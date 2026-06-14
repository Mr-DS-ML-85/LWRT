//! log — LWRT's logd/syslogd. A daemon that owns the `/dev/log` datagram
//! socket (where libc `syslog(3)` and our own applets write) and also drains
//! the kernel ring via `/dev/kmsg`, funnelling both into one size-capped file
//! that survives with a single rotation. No ubus, no in-memory query protocol:
//! `log read` just prints the file.
//!
//!   log            run the logging daemon (foreground; init supervises it)
//!   log read       print the current log
//!   log <text...>  inject one message (the `logger` role)

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::time::{SystemTime, UNIX_EPOCH};

const SOCK: &str = "/dev/log";
const FILE: &str = "/var/log/messages";
const OLD: &str = "/var/log/messages.0";
const MAX: u64 = 64 * 1024;

pub fn run(args: &[String]) -> i32 {
    match args.first().map(|s| s.as_str()) {
        Some("read") => read(),
        None => daemon(),
        Some(_) => logger(&args.join(" ")),
    }
}

/// Print the rotated-then-current log, oldest first.
fn read() -> i32 {
    let mut out = String::new();
    if let Ok(s) = fs::read_to_string(OLD) {
        out.push_str(&s);
    }
    if let Ok(s) = fs::read_to_string(FILE) {
        out.push_str(&s);
    }
    print!("{out}");
    0
}

/// One-shot logger: try the running daemon's socket, else append directly.
fn logger(msg: &str) -> i32 {
    let line = format!("{} user: {msg}", stamp());
    if let Ok(sock) = UnixDatagram::unbound() {
        if sock.send_to(line.as_bytes(), SOCK).is_ok() {
            return 0;
        }
    }
    append(&line);
    0
}

/// The daemon: poll the `/dev/log` socket and `/dev/kmsg`, append every line.
fn daemon() -> i32 {
    let _ = fs::create_dir_all("/var/log");
    let _ = fs::remove_file(SOCK); // stale socket from a previous run
    let sock = match UnixDatagram::bind(SOCK) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("log: bind {SOCK}: {e}");
            return 1;
        }
    };
    // Kernel ring; non-blocking so poll drives it. Optional — a kernel without
    // /dev/kmsg just means we only carry userspace logs.
    let kmsg = OpenOptions::new().read(true).open("/dev/kmsg").ok();
    if let Some(k) = &kmsg {
        let _ = set_nonblock(k.as_raw_fd());
    }

    println!("log: syslogd on {SOCK}");
    let mut buf = [0u8; 4096];
    loop {
        let mut fds = [
            libc::pollfd { fd: sock.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd {
                fd: kmsg.as_ref().map(|k| k.as_raw_fd()).unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("log: poll: {e}");
            return 1;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            if let Ok(len) = sock.recv(&mut buf) {
                ingest_userspace(&buf[..len]);
            }
        }
        if fds[1].revents & libc::POLLIN != 0 {
            if let Some(mut k) = kmsg.as_ref() {
                // Drain all currently-available records.
                while let Ok(len) = k.read(&mut buf) {
                    if len == 0 {
                        break;
                    }
                    ingest_kernel(&buf[..len]);
                }
            }
        }
    }
}

/// A `/dev/log` datagram is one message, possibly with a trailing newline.
fn ingest_userspace(bytes: &[u8]) {
    let msg = String::from_utf8_lossy(bytes);
    let msg = msg.trim_end_matches(['\n', '\0']);
    if !msg.is_empty() {
        append(&format!("{} {msg}", stamp()));
    }
}

/// A `/dev/kmsg` record is `prio,seq,ts,flag;message`. Keep the message.
fn ingest_kernel(bytes: &[u8]) {
    let rec = String::from_utf8_lossy(bytes);
    let body = rec.split_once(';').map(|(_, m)| m).unwrap_or(&rec);
    let body = body.trim_end_matches('\n');
    if !body.is_empty() {
        append(&format!("{} kernel: {body}", stamp()));
    }
}

/// Append one line, rotating once when the file crosses [`MAX`].
fn append(line: &str) {
    if fs::metadata(FILE).map(|m| m.len()).unwrap_or(0) >= MAX {
        let _ = fs::rename(FILE, OLD);
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(FILE) {
        let _ = writeln!(f, "{line}");
    }
}

/// Seconds since the Unix epoch as a bare timestamp. No timezone math — the
/// reader can format; we just need monotone, sortable, cheap.
fn stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("[{secs}]")
}

fn set_nonblock(fd: libc::c_int) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
