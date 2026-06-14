//! Tiny forwarding DNS resolver on UDP :53. Answers local lease hostnames
//! itself; everything else is relayed to the upstream learned from the WAN
//! DHCP lease (falling back to a public resolver). A small TTL cache keeps
//! repeat lookups off the WAN link.

use crate::config::Config;
use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

pub fn run(_args: &[String]) -> i32 {
    let cfg = Config::load();
    let lan_ip = cfg.get_or("lan", "ipaddr", "192.168.1.1");
    let bind = format!("{lan_ip}:53");

    let sock = match UdpSocket::bind(&bind) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("dns: bind {bind}: {e}");
            return 1;
        }
    };
    println!("dns: listening on {bind}");

    let mut cache: HashMap<Vec<u8>, (Vec<u8>, Instant)> = HashMap::new();
    let mut buf = [0u8; 1500];

    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => continue,
        };
        let query = &buf[..n];
        if query.len() < 12 {
            continue;
        }

        // Try a local answer for leased hostnames first.
        if let Some(reply) = local_answer(query) {
            let _ = sock.send_to(&reply, from);
            continue;
        }

        // Cache key = question section (everything after the 12-byte header).
        let key = query[12..].to_vec();
        if let Some((resp, when)) = cache.get(&key) {
            if when.elapsed() < Duration::from_secs(60) {
                let mut out = resp.clone();
                out[0] = query[0]; // restore the client's transaction id
                out[1] = query[1];
                let _ = sock.send_to(&out, from);
                continue;
            }
        }

        if let Some(resp) = forward(query) {
            let mut store = resp.clone();
            store[0] = 0;
            store[1] = 0;
            cache.insert(key, (store, Instant::now()));
            let _ = sock.send_to(&resp, from);
        }
    }
}

fn upstream() -> Ipv4Addr {
    std::fs::read_to_string("/run/wan.dns")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(Ipv4Addr::new(1, 1, 1, 1))
}

fn forward(query: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    sock.send_to(query, (upstream(), 53)).ok()?;
    let mut buf = [0u8; 1500];
    let n = sock.recv(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

/// If the query is a single A question for a leased hostname, synthesise the
/// answer. Returns None to fall through to forwarding.
fn local_answer(query: &[u8]) -> Option<Vec<u8>> {
    // Only handle a standard single-question query.
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount != 1 {
        return None;
    }
    let (name, after) = read_name(query, 12)?;
    if after + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[after], query[after + 1]]);
    if qtype != 1 {
        return None; // only A records
    }

    let host = name.trim_end_matches(".lan").to_ascii_lowercase();
    let ip = lookup_lease(&host)?;

    // Build a response: copy question, add one answer with a pointer to the name.
    let mut r = Vec::with_capacity(after + 4 + 16);
    r.extend_from_slice(&query[..after + 4]);
    r[2] = 0x81; // QR=1, RD=1
    r[3] = 0x80; // RA=1
    r[6] = 0;
    r[7] = 1; // ancount = 1
    // answer: name pointer to offset 12
    r.extend_from_slice(&[0xc0, 0x0c]);
    r.extend_from_slice(&1u16.to_be_bytes()); // type A
    r.extend_from_slice(&1u16.to_be_bytes()); // class IN
    r.extend_from_slice(&120u32.to_be_bytes()); // ttl
    r.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    r.extend_from_slice(&ip.octets());
    Some(r)
}

/// Decode a DNS name starting at `pos` into "label.label". No compression in
/// questions, so we don't follow pointers here.
fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len >= 0xc0 {
            return None; // pointer; bail to forwarding
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&buf[pos..pos + len]).to_string());
        pos += len;
    }
    Some((parts.join("."), pos))
}

fn lookup_lease(host: &str) -> Option<Ipv4Addr> {
    let text = std::fs::read_to_string("/run/dhcp.leases").ok()?;
    for line in text.lines() {
        // format: expiry mac ip name
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 4 && f[3].eq_ignore_ascii_case(host) {
            return f[2].parse().ok();
        }
    }
    None
}
