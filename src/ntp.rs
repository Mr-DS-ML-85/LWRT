//! ntp — a tiny SNTP (RFC 4330) client, the role OpenWrt's sysntpd plays.
//! Routers boot with no battery-backed clock; a wrong date breaks TLS and
//! package signatures. This sends one mode-3 query, reads the transmit
//! timestamp, and sets the system clock. No drift discipline — just "make the
//! wall clock approximately right," which is all a SoHo router needs.
//!
//!   ntp            sync once against the configured server(s)
//!   ntp <host>     sync once against a specific server

use crate::config::Config;
use std::io;
use std::net::UdpSocket;
use std::time::Duration;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

pub fn run(args: &[String]) -> i32 {
    let cfg = Config::load();
    // Explicit host argument wins; otherwise take the comma/space list from
    // config, falling back to a sensible public pool.
    let servers: Vec<String> = match args.first() {
        Some(h) => vec![h.clone()],
        None => cfg
            .get_or("ntp", "server", "pool.ntp.org")
            .split([',', ' '])
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
    };

    for server in &servers {
        match sync_once(server) {
            Ok(unix_secs) => {
                println!("ntp: {server} -> {unix_secs} (clock set)");
                return 0;
            }
            Err(e) => eprintln!("ntp: {server}: {e}"),
        }
    }
    eprintln!("ntp: all servers failed");
    1
}

/// Query one server and set the system clock from its transmit timestamp.
fn sync_once(server: &str) -> io::Result<u64> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    // Resolve "host" -> "host:123" via getaddrinfo (musl) and connect.
    sock.connect((server, 123u16))?;

    // 48-byte SNTP request: LI=0, VN=4, Mode=3 (client) in the first octet.
    let mut req = [0u8; 48];
    req[0] = 0x23;
    sock.send(&req)?;

    let mut resp = [0u8; 48];
    let n = sock.recv(&mut resp)?;
    if n < 48 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short reply"));
    }

    // Transmit timestamp: 64-bit fixed point at offset 40 (secs:frac, big-endian).
    let secs = u32::from_be_bytes([resp[40], resp[41], resp[42], resp[43]]) as u64;
    let frac = u32::from_be_bytes([resp[44], resp[45], resp[46], resp[47]]) as u64;
    if secs == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "null timestamp"));
    }
    let unix = secs
        .checked_sub(NTP_UNIX_OFFSET)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "pre-1970 timestamp"))?;
    // Fraction is in units of 1/2^32 s; convert to nanoseconds.
    let nanos = (frac * 1_000_000_000) >> 32;

    set_clock(unix, nanos as i64)?;
    Ok(unix)
}

/// CLOCK_REALTIME := unix.nanos.
fn set_clock(secs: u64, nanos: i64) -> io::Result<()> {
    // Let inference pick the field types (tv_sec/tv_nsec widths vary by libc
    // version — musl 1.2 made tv_sec 64-bit), so we avoid naming the
    // deprecated `time_t`/`c_long` aliases directly.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    ts.tv_sec = secs as _;
    ts.tv_nsec = nanos as _;
    let r = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
