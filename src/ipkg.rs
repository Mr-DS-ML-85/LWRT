//! ipkg — LWRT's own tiny package manager. Since we own both the repo and
//! the client, packages use a deliberately trivial format: an uncompressed
//! POSIX ustar archive (`<name>.ipk`) whose first member is `./control` and
//! whose remaining members are extracted relative to /. No ar/gzip/tar libs.
//!
//!   ipkg update           refresh the package index
//!   ipkg list             show available packages
//!   ipkg install <name>   download + extract a package
//!   ipkg remove <name>    delete a package's installed files

use crate::config::Config;
use crate::sha256;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;

const STATE: &str = "/var/ipkg";

pub fn run(args: &[String]) -> i32 {
    let cfg = Config::load();
    let repo = cfg.get_or("ipkg", "repo", "http://downloads.lwrt.local/packages").to_string();
    let _ = fs::create_dir_all(format!("{STATE}/installed"));

    match args.first().map(|s| s.as_str()) {
        Some("update") => update(&repo),
        Some("list") => list(),
        Some("install") => match args.get(1) {
            Some(name) => install(&repo, name),
            None => {
                eprintln!("ipkg: install <name>");
                1
            }
        },
        Some("remove") => match args.get(1) {
            Some(name) => remove(name),
            None => {
                eprintln!("ipkg: remove <name>");
                1
            }
        },
        _ => {
            eprintln!("ipkg: update|list|install <name>|remove <name>");
            1
        }
    }
}

fn update(repo: &str) -> i32 {
    match http_get(&format!("{repo}/Packages")) {
        Ok(body) => {
            let _ = fs::write(format!("{STATE}/Packages"), &body);
            println!("ipkg: index updated ({} bytes)", body.len());
            0
        }
        Err(e) => {
            eprintln!("ipkg: update failed: {e}");
            1
        }
    }
}

fn list() -> i32 {
    match fs::read_to_string(format!("{STATE}/Packages")) {
        Ok(t) => {
            print!("{t}");
            0
        }
        Err(_) => {
            eprintln!("ipkg: no index; run `ipkg update`");
            1
        }
    }
}

fn install(repo: &str, name: &str) -> i32 {
    // Integrity is anchored in the index: it names the file and its SHA-256.
    // Without an index entry we refuse to install — never fetch an unverified
    // blob by guessing the URL.
    let index = match fs::read_to_string(format!("{STATE}/Packages")) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("ipkg: no index; run `ipkg update`");
            return 1;
        }
    };
    let entry = match find_entry(&index, name) {
        Some(e) => e,
        None => {
            eprintln!("ipkg: {name}: not in index");
            return 1;
        }
    };

    let url = format!("{repo}/{}", entry.filename);
    let blob = match http_get(&url) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ipkg: download {url}: {e}");
            return 1;
        }
    };

    // Size then digest: cheap check first, then the cryptographic one.
    if let Some(sz) = entry.size {
        if blob.len() != sz {
            eprintln!("ipkg: {name}: size mismatch ({} != {sz})", blob.len());
            return 1;
        }
    }
    if let Some(want) = &entry.sha256 {
        let got = sha256::hex(&sha256::digest(&blob));
        if !got.eq_ignore_ascii_case(want) {
            eprintln!("ipkg: {name}: SHA256 mismatch\n  want {want}\n  got  {got}");
            return 1;
        }
    } else {
        eprintln!("ipkg: {name}: index has no SHA256sum; refusing");
        return 1;
    }

    match extract_ustar(&blob) {
        Ok(ex) => {
            let manifest = ex.files.join("\n");
            let _ = fs::write(format!("{STATE}/installed/{name}.list"), manifest);
            if let Some(ctrl) = ex.control {
                let _ = fs::write(format!("{STATE}/installed/{name}.control"), ctrl);
            }
            println!("ipkg: installed {name} ({} files, sha256 ok)", ex.files.len());
            0
        }
        Err(e) => {
            eprintln!("ipkg: extract {name}: {e}");
            1
        }
    }
}

/// One package's metadata from the `Packages` index.
struct Entry {
    filename: String,
    size: Option<usize>,
    sha256: Option<String>,
}

/// Find the stanza for `name` in an opkg-style index (blank-line-separated
/// `Key: value` blocks) and pull the fields we verify against.
fn find_entry(index: &str, name: &str) -> Option<Entry> {
    for stanza in index.split("\n\n") {
        let mut is_match = false;
        let mut filename = None;
        let mut size = None;
        let mut sha256 = None;
        for line in stanza.lines() {
            let Some((key, val)) = line.split_once(':') else { continue };
            let val = val.trim();
            match key.trim() {
                "Package" => is_match = val == name,
                "Filename" => filename = Some(val.to_string()),
                "Size" => size = val.parse().ok(),
                "SHA256sum" => sha256 = Some(val.to_string()),
                _ => {}
            }
        }
        if is_match {
            // A package with no Filename defaults to `<name>.ipk`.
            return Some(Entry {
                filename: filename.unwrap_or_else(|| format!("{name}.ipk")),
                size,
                sha256,
            });
        }
    }
    None
}

fn remove(name: &str) -> i32 {
    let list = format!("{STATE}/installed/{name}.list");
    let manifest = match fs::read_to_string(&list) {
        Ok(m) => m,
        Err(_) => {
            eprintln!("ipkg: {name} not installed");
            return 1;
        }
    };
    for f in manifest.lines() {
        if !f.is_empty() && f != "./control" {
            let _ = fs::remove_file(f);
        }
    }
    let _ = fs::remove_file(&list);
    println!("ipkg: removed {name}");
    0
}

// ---- minimal HTTP/1.0 GET ---------------------------------------------------

fn http_get(url: &str) -> std::io::Result<Vec<u8>> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| err("only http:// supported"))?;
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let host = hostport.split(':').next().unwrap_or(hostport);
    let addr = if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:80")
    };

    let mut stream = TcpStream::connect(addr)?;
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: ipkg\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;

    // Split headers/body on the first CRLFCRLF.
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| err("no http header terminator"))?;
    let headers = String::from_utf8_lossy(&raw[..sep]);
    let status_ok = headers
        .lines()
        .next()
        .map(|l| l.contains(" 200"))
        .unwrap_or(false);
    if !status_ok {
        return Err(err("http status not 200"));
    }
    Ok(raw[sep + 4..].to_vec())
}

fn err(msg: &str) -> std::io::Error {
    std::io::Error::other(msg)
}

// ---- ustar extraction -------------------------------------------------------

/// The result of unpacking a `.ipk`: the package's `./control` metadata (held
/// in memory, never written under /) and the list of real files installed.
struct Extracted {
    control: Option<Vec<u8>>,
    files: Vec<String>,
}

/// Extract a plain (uncompressed) POSIX ustar archive into /. The `./control`
/// member is captured rather than written; everything else lands relative to
/// /. Returns the captured control blob and the list of paths written.
fn extract_ustar(data: &[u8]) -> std::io::Result<Extracted> {
    let mut control = None;
    let mut written = Vec::new();
    let mut off = 0usize;
    while off + 512 <= data.len() {
        let hdr = &data[off..off + 512];
        // Two zero blocks mark end of archive.
        if hdr.iter().all(|&b| b == 0) {
            break;
        }
        let name = cstr(&hdr[0..100]);
        let size = octal(&hdr[124..136]);
        let typeflag = hdr[156];
        off += 512;

        let file_data = &data[off..(off + size).min(data.len())];
        off += align512(size);

        if name.is_empty() {
            continue;
        }
        // The control member is metadata, not an installed file: capture it
        // in memory and never let it touch the filesystem.
        if is_control(&name) {
            control = Some(file_data.to_vec());
            continue;
        }
        let path = sanitize(&name);
        match typeflag {
            b'5' => {
                // directory
                let _ = fs::create_dir_all(&path);
            }
            b'0' | 0 => {
                if let Some(parent) = std::path::Path::new(&path).parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let mut f = fs::File::create(&path)?;
                f.write_all(file_data)?;
                written.push(name.clone());
            }
            _ => {} // ignore symlinks/devices for now
        }
    }
    Ok(Extracted { control, files: written })
}

/// Does this archive member name the package's control file?
fn is_control(name: &str) -> bool {
    matches!(name.trim_start_matches("./"), "control")
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).to_string()
}

fn octal(b: &[u8]) -> usize {
    let s = cstr(b);
    let s = s.trim();
    usize::from_str_radix(if s.is_empty() { "0" } else { s }, 8).unwrap_or(0)
}

fn align512(n: usize) -> usize {
    (n + 511) & !511
}

/// Map an archive member name to an absolute install path, refusing escapes.
fn sanitize(name: &str) -> String {
    let trimmed = name.trim_start_matches("./").trim_start_matches('/');
    // Drop any ".." components defensively.
    let safe: Vec<&str> = trimmed.split('/').filter(|c| *c != ".." && !c.is_empty()).collect();
    format!("/{}", safe.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX: &str = "\
Package: hello
Version: 1.0
Filename: hello_1.0_mipsel.ipk
Size: 2048
SHA256sum: abc123

Package: world
Version: 2.1
Filename: world_2.1_mipsel.ipk
Size: 99
SHA256sum: deadbeef
";

    #[test]
    fn find_entry_pulls_the_right_stanza() {
        let e = find_entry(INDEX, "world").expect("found");
        assert_eq!(e.filename, "world_2.1_mipsel.ipk");
        assert_eq!(e.size, Some(99));
        assert_eq!(e.sha256.as_deref(), Some("deadbeef"));
        assert!(find_entry(INDEX, "missing").is_none());
    }

    #[test]
    fn sanitize_refuses_escapes() {
        assert_eq!(sanitize("./etc/lwrt/config"), "/etc/lwrt/config");
        assert_eq!(sanitize("../../etc/shadow"), "/etc/shadow");
        assert_eq!(sanitize("/usr/bin/foo"), "/usr/bin/foo");
    }
}
