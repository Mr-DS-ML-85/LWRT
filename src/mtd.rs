//! `mtd` — raw flash partition tool, the muscle behind firmware upgrades.
//!
//! OpenWrt's `mtd` writes a new image straight onto a `/dev/mtdN` character
//! device: unlock, erase a block at a time, then stream the payload back in.
//! That is exactly what `sysupgrade` does under the hood, so a faithful `mtd`
//! gives us field-upgradeable firmware without dragging in mtd-utils.
//!
//! Subcommands:
//!   mtd                     list partitions (pretty-print /proc/mtd)
//!   mtd write <img> <part>  erase enough blocks for <img>, then write it
//!   mtd erase <part>        erase the whole partition
//!   mtd verify <img> <part> read the partition back and compare against <img>
//!
//! <part> is either a `/dev/mtdN` path or a partition *name* (e.g. `firmware`),
//! which we resolve through /proc/mtd just like the real tool.
//!
//! The ioctl numbers are computed from the kernel `_IOC` macros at compile time
//! so the encoding is correct on both the mipsel target (DIRBITS=3) and the
//! x86_64 host used for tests (asm-generic, DIRBITS=2).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;

// ---- _IOC encoding ----------------------------------------------------------
//
// The MTD ioctls are `_IOR('M', 1, ..)` etc. The bit layout of `_IOC` is
// architecture specific: MIPS carves out 3 direction bits at the top (NONE=1,
// READ=2, WRITE=4) and 13 size bits, whereas the asm-generic ABI used by x86
// uses 2 direction bits (NONE=0, WRITE=1, READ=2) and 14 size bits.

#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
mod ioc {
    pub const DIRSHIFT: u32 = 29;
    pub const SIZESHIFT: u32 = 16;
    pub const READ: u32 = 2;
    pub const WRITE: u32 = 4;
}

#[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
mod ioc {
    pub const DIRSHIFT: u32 = 30;
    pub const SIZESHIFT: u32 = 16;
    pub const READ: u32 = 2;
    pub const WRITE: u32 = 1;
}

const TYPESHIFT: u32 = 8;
const NRSHIFT: u32 = 0;

// The result is the raw 32-bit ioctl request. We keep it as `u32` and cast
// with `as _` at the call site: `libc::ioctl`'s request type is `c_ulong` on
// x86 but `c_int` on MIPS, and only a bit-preserving `as` cast (never
// `try_into`, which would reject the WRITE patterns whose top bit is set)
// works on both.
const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u32 {
    (dir << ioc::DIRSHIFT) | (ty << TYPESHIFT) | (nr << NRSHIFT) | (size << ioc::SIZESHIFT)
}

const M: u32 = b'M' as u32;
// struct mtd_info_user is 32 bytes (u8 type + u32 x5 + u64 padding, aligned).
const MEMGETINFO: u32 = ioc(ioc::READ, M, 1, 32);
// struct erase_info_user is two u32s = 8 bytes.
const MEMERASE: u32 = ioc(ioc::WRITE, M, 2, 8);
const MEMUNLOCK: u32 = ioc(ioc::WRITE, M, 6, 8);

// ---- mtd_info ---------------------------------------------------------------

#[derive(Clone, Copy)]
struct MtdInfo {
    size: u32,
    erasesize: u32,
}

fn get_info(f: &File) -> io::Result<MtdInfo> {
    // mtd_info_user: type@0(u8) flags@4 size@8 erasesize@12 writesize@16 ...
    let mut buf = [0u8; 32];
    let r = unsafe { libc::ioctl(f.as_raw_fd(), MEMGETINFO as _, buf.as_mut_ptr()) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let rd = |off: usize| u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
    Ok(MtdInfo {
        size: rd(8),
        erasesize: rd(12),
    })
}

/// Unlock + erase the half-open range `[start, start+len)`, one block at a time.
/// `len` is rounded up to the erase-block size; `start` must be block-aligned.
fn erase_range(f: &File, info: &MtdInfo, start: u32, len: u32) -> io::Result<()> {
    let bs = info.erasesize.max(1);
    let end = start.saturating_add(len);
    let end = end.div_ceil(bs) * bs;
    let end = end.min(info.size);
    let mut off = start - (start % bs);
    while off < end {
        let mut ei = [0u8; 8];
        ei[0..4].copy_from_slice(&off.to_ne_bytes());
        ei[4..8].copy_from_slice(&bs.to_ne_bytes());
        // MEMUNLOCK is advisory; ignore failures (many chips are always unlocked).
        unsafe { libc::ioctl(f.as_raw_fd(), MEMUNLOCK as _, ei.as_ptr()) };
        let r = unsafe { libc::ioctl(f.as_raw_fd(), MEMERASE as _, ei.as_ptr()) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        off += bs;
    }
    Ok(())
}

// ---- partition resolution ---------------------------------------------------

/// Map a partition argument to a `/dev/mtdN` path. Accepts an explicit
/// `/dev/...` path, an `mtdN` shorthand, or a partition name from /proc/mtd.
pub fn resolve(part: &str) -> io::Result<String> {
    if part.starts_with("/dev/") {
        return Ok(part.to_string());
    }
    if let Some(n) = part.strip_prefix("mtd") {
        if n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty() {
            return Ok(format!("/dev/mtd{n}"));
        }
    }
    // Look the name up in /proc/mtd. Lines look like:
    //   mtd5: 00fa0000 00010000 "firmware"
    let table = std::fs::read_to_string("/proc/mtd")?;
    for line in table.lines() {
        let Some((dev, rest)) = line.split_once(':') else {
            continue;
        };
        if let Some(name) = rest.split('"').nth(1) {
            if name == part {
                return Ok(format!("/dev/{}", dev.trim()));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no mtd partition named '{part}'"),
    ))
}

// ---- subcommands ------------------------------------------------------------

fn list() -> i32 {
    match std::fs::read_to_string("/proc/mtd") {
        Ok(t) => {
            print!("{t}");
            0
        }
        Err(e) => {
            eprintln!("mtd: /proc/mtd: {e}");
            1
        }
    }
}

/// Open the resolved partition device read/write with O_SYNC so each write is
/// committed before we move on — important when we may be erasing flash we are
/// also booting from.
fn open_part(part: &str) -> io::Result<(File, MtdInfo)> {
    let path = resolve(part)?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_SYNC)
        .open(&path)?;
    let info = get_info(&f)?;
    Ok((f, info))
}

// O_SYNC lives behind the OpenOptionsExt trait.
use std::os::unix::fs::OpenOptionsExt;

fn read_image(src: &str) -> io::Result<Vec<u8>> {
    if src == "-" {
        let mut v = Vec::new();
        io::stdin().read_to_end(&mut v)?;
        Ok(v)
    } else {
        std::fs::read(src)
    }
}

/// Flash `img` onto the named partition. Exposed so `sysupgrade` can reuse the
/// exact erase-then-write path instead of duplicating the ioctl dance.
pub fn write_image(img: &str, part: &str) -> i32 {
    write(img, part)
}

fn write(img: &str, part: &str) -> i32 {
    let data = match read_image(img) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("mtd: read {img}: {e}");
            return 1;
        }
    };
    let (mut f, info) = match open_part(part) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("mtd: open {part}: {e}");
            return 1;
        }
    };
    if data.len() as u64 > info.size as u64 {
        eprintln!(
            "mtd: image is {} bytes but {part} holds only {}",
            data.len(),
            info.size
        );
        return 1;
    }
    if let Err(e) = erase_range(&f, &info, 0, data.len() as u32) {
        eprintln!("mtd: erase {part}: {e}");
        return 1;
    }
    if let Err(e) = f.seek(SeekFrom::Start(0)).and_then(|_| f.write_all(&data)) {
        eprintln!("mtd: write {part}: {e}");
        return 1;
    }
    if let Err(e) = f.flush() {
        eprintln!("mtd: flush {part}: {e}");
        return 1;
    }
    println!("mtd: wrote {} bytes to {part}", data.len());
    0
}

fn erase(part: &str) -> i32 {
    let (f, info) = match open_part(part) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("mtd: open {part}: {e}");
            return 1;
        }
    };
    match erase_range(&f, &info, 0, info.size) {
        Ok(()) => {
            println!("mtd: erased {part} ({} bytes)", info.size);
            0
        }
        Err(e) => {
            eprintln!("mtd: erase {part}: {e}");
            1
        }
    }
}

fn verify(img: &str, part: &str) -> i32 {
    let data = match read_image(img) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("mtd: read {img}: {e}");
            return 1;
        }
    };
    let (mut f, _info) = match open_part(part) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("mtd: open {part}: {e}");
            return 1;
        }
    };
    let mut on_flash = vec![0u8; data.len()];
    if let Err(e) = f
        .seek(SeekFrom::Start(0))
        .and_then(|_| f.read_exact(&mut on_flash))
    {
        eprintln!("mtd: read {part}: {e}");
        return 1;
    }
    if on_flash == data {
        println!("mtd: {part} matches {img}");
        0
    } else {
        eprintln!("mtd: {part} DOES NOT match {img}");
        2
    }
}

pub fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        None | Some("list") => list(),
        Some("write") => match (args.get(1), args.get(2)) {
            (Some(img), Some(part)) => write(img, part),
            _ => {
                eprintln!("usage: mtd write <image|-> <partition>");
                2
            }
        },
        Some("erase") => match args.get(1) {
            Some(part) => erase(part),
            None => {
                eprintln!("usage: mtd erase <partition>");
                2
            }
        },
        Some("verify") => match (args.get(1), args.get(2)) {
            (Some(img), Some(part)) => verify(img, part),
            _ => {
                eprintln!("usage: mtd verify <image> <partition>");
                2
            }
        },
        Some(other) => {
            eprintln!("mtd: unknown subcommand '{other}'");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_numbers_match_asm_generic() {
        // On the x86_64 host these must equal the canonical mtd-utils values.
        #[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
        {
            assert_eq!(MEMGETINFO, 0x80204d01);
            assert_eq!(MEMERASE, 0x40084d02);
            assert_eq!(MEMUNLOCK, 0x40084d06);
        }
        // On MIPS the direction bits shift to 29 and READ/WRITE swap meaning.
        #[cfg(any(target_arch = "mips", target_arch = "mips64"))]
        {
            assert_eq!(MEMGETINFO, 0x40204d01);
            assert_eq!(MEMERASE, 0x80084d02);
            assert_eq!(MEMUNLOCK, 0x80084d06);
        }
    }

    #[test]
    fn resolve_accepts_dev_paths_and_shorthand() {
        assert_eq!(resolve("/dev/mtd3").unwrap(), "/dev/mtd3");
        assert_eq!(resolve("mtd7").unwrap(), "/dev/mtd7");
    }

    #[test]
    fn resolve_rejects_unknown_name() {
        // A bogus name with no /proc/mtd match (or no /proc/mtd at all on the
        // host) must surface as an error, never a silent wrong device.
        assert!(resolve("definitely-not-a-partition-xyz").is_err());
    }
}
