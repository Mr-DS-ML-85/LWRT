//! DHCPv4. One applet, two roles:
//!   `dhcp server`  — hands out leases on the LAN bridge.
//!   `dhcp client`  — obtains the WAN lease and configures eth/route/dns.
//!
//! Pure BOOTP/DHCP over UDP, no external deps. The packet layout is the
//! classic 236-byte fixed header + magic cookie + TLV options.

use crate::{config::Config, net};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: [u8; 4] = [99, 130, 83, 99];
const OP_REQUEST: u8 = 1;
const OP_REPLY: u8 = 2;

// Option codes
const OPT_SUBNET: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_LEASE: u8 = 51;
const OPT_MSGTYPE: u8 = 53;
const OPT_SERVERID: u8 = 54;
const OPT_REQIP: u8 = 50;
const OPT_END: u8 = 255;

// DHCP message types
const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;

const LEASES_PATH: &str = "/run/dhcp.leases";

struct Packet {
    op: u8,
    xid: [u8; 4],
    chaddr: [u8; 6],
    yiaddr: Ipv4Addr,
    msg_type: u8,
    req_ip: Option<Ipv4Addr>,
    hostname: Option<String>,
}

/// Iterate the DHCP options that follow the magic cookie at offset 240,
/// yielding `(code, value)` for each TLV. Pads (code 0) are skipped and the
/// walk stops at OPT_END or a truncated option — so callers never touch raw
/// offsets. One walker, shared by both the server (`parse`) and client
/// (`parse_ack`) paths.
fn options(buf: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut i = 240;
    std::iter::from_fn(move || {
        while i < buf.len() {
            let code = buf[i];
            if code == OPT_END {
                return None;
            }
            if code == 0 {
                i += 1; // pad
                continue;
            }
            let len = *buf.get(i + 1)? as usize;
            let start = i + 2;
            let end = (start + len).min(buf.len());
            i = start + len;
            return Some((code, &buf[start..end]));
        }
        None
    })
}

fn ipv4(val: &[u8]) -> Option<Ipv4Addr> {
    let o: [u8; 4] = val.get(..4)?.try_into().ok()?;
    Some(Ipv4Addr::from(o))
}

fn parse(buf: &[u8]) -> Option<Packet> {
    if buf.len() < 240 || buf[236..240] != MAGIC {
        return None;
    }
    let mut p = Packet {
        op: buf[0],
        xid: buf[4..8].try_into().ok()?,
        chaddr: buf[28..34].try_into().ok()?,
        yiaddr: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
        msg_type: 0,
        req_ip: None,
        hostname: None,
    };
    for (code, val) in options(buf) {
        match code {
            OPT_MSGTYPE => p.msg_type = *val.first().unwrap_or(&0),
            OPT_REQIP => p.req_ip = ipv4(val),
            12 => p.hostname = String::from_utf8(val.to_vec()).ok(), // host name
            _ => {}
        }
    }
    Some(p)
}

/// Build a reply with the given yiaddr/type and server options.
#[allow(clippy::too_many_arguments)]
fn build_reply(
    req: &Packet,
    msg_type: u8,
    yiaddr: Ipv4Addr,
    server: Ipv4Addr,
    mask: Ipv4Addr,
    dns: Ipv4Addr,
    lease: u32,
) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[0] = OP_REPLY;
    b[1] = 1; // htype ethernet
    b[2] = 6; // hlen
    b[4..8].copy_from_slice(&req.xid);
    b[16..20].copy_from_slice(&yiaddr.octets()); // yiaddr
    b[20..24].copy_from_slice(&server.octets()); // siaddr
    b[28..34].copy_from_slice(&req.chaddr);
    b[236..240].copy_from_slice(&MAGIC);

    let opt = |code: u8, val: &[u8], b: &mut Vec<u8>| {
        b.push(code);
        b.push(val.len() as u8);
        b.extend_from_slice(val);
    };
    opt(OPT_MSGTYPE, &[msg_type], &mut b);
    opt(OPT_SERVERID, &server.octets(), &mut b);
    opt(OPT_LEASE, &lease.to_be_bytes(), &mut b);
    opt(OPT_SUBNET, &mask.octets(), &mut b);
    opt(OPT_ROUTER, &server.octets(), &mut b);
    opt(OPT_DNS, &dns.octets(), &mut b);
    b.push(OPT_END);
    b
}

fn bind_to_device(sock: &UdpSocket, ifname: &str) -> std::io::Result<()> {
    let cname = std::ffi::CString::new(ifname)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "interior NUL"))?;
    let r = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            cname.as_ptr() as *const libc::c_void,
            (ifname.len() + 1) as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn run(args: &[String]) -> i32 {
    let cfg = Config::load();
    match args.first().map(|s| s.as_str()) {
        Some("client") => client(&cfg),
        _ => server(&cfg),
    }
}

// ---- server ----------------------------------------------------------------

struct Pool {
    start: u32,
    count: u32,
    mask: Ipv4Addr,
    server: Ipv4Addr,
    lease: u32,
    by_mac: BTreeMap<[u8; 6], u32>,
    used: std::collections::BTreeSet<u32>,
    names: BTreeMap<u32, String>,
}

impl Pool {
    fn lease_for(&mut self, mac: [u8; 6], requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        if let Some(&ip) = self.by_mac.get(&mac) {
            return Some(Ipv4Addr::from(ip));
        }
        // honour a sane request inside the pool
        if let Some(r) = requested {
            let v = u32::from(r);
            if v >= self.start && v < self.start + self.count && !self.used.contains(&v) {
                self.assign(mac, v);
                return Some(r);
            }
        }
        for off in 0..self.count {
            let v = self.start + off;
            if !self.used.contains(&v) {
                self.assign(mac, v);
                return Some(Ipv4Addr::from(v));
            }
        }
        None
    }
    fn assign(&mut self, mac: [u8; 6], v: u32) {
        self.by_mac.insert(mac, v);
        self.used.insert(v);
    }
    fn persist(&self) {
        if let Ok(mut f) = std::fs::File::create(LEASES_PATH) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            for (mac, &ip) in &self.by_mac {
                let name = self.names.get(&ip).map(|s| s.as_str()).unwrap_or("*");
                let _ = writeln!(
                    f,
                    "{} {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} {} {}",
                    now + self.lease as u64,
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                    Ipv4Addr::from(ip),
                    name
                );
            }
        }
    }
}

fn server(cfg: &Config) -> i32 {
    if cfg.get_or("dhcp", "enabled", "1") != "1" {
        println!("dhcp: server disabled");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
    let lan_if = cfg.get_or("lan", "ifname", "br-lan");
    // A typo in /etc/lwrt/config must not panic a supervised service into a
    // respawn loop — report it and exit cleanly instead.
    let addr = |sect, key, def| net::parse_v4(cfg.get_or(sect, key, def));
    let (server_ip, mask, start) = match (
        addr("lan", "ipaddr", "192.168.1.1"),
        addr("lan", "netmask", "255.255.255.0"),
        addr("dhcp", "start", "192.168.1.100"),
    ) {
        (Ok(s), Ok(m), Ok(st)) => (s, m, st),
        _ => {
            eprintln!("dhcp: bad lan/dhcp address in config");
            return 1;
        }
    };
    let count: u32 = cfg.get_or("dhcp", "limit", "100").parse().unwrap_or(100);
    let lease: u32 = cfg.get_or("dhcp", "leasetime", "43200").parse().unwrap_or(43200);

    let sock = match UdpSocket::bind(("0.0.0.0", 67)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("dhcp: bind :67: {e}");
            return 1;
        }
    };
    let _ = sock.set_broadcast(true);
    if let Err(e) = bind_to_device(&sock, lan_if) {
        eprintln!("dhcp: bind {lan_if}: {e}");
    }

    let mut pool = Pool {
        start: u32::from(start),
        count,
        mask,
        server: server_ip,
        lease,
        by_mac: BTreeMap::new(),
        used: std::collections::BTreeSet::new(),
        names: BTreeMap::new(),
    };

    println!("dhcp: serving {lan_if} pool {start}+{count}");
    let mut buf = [0u8; 1024];
    loop {
        let n = match sock.recv_from(&mut buf) {
            Ok((n, _)) => n,
            Err(_) => continue,
        };
        let req = match parse(&buf[..n]) {
            Some(p) if p.op == OP_REQUEST => p,
            _ => continue,
        };
        let bcast: SocketAddr = "255.255.255.255:68".parse().unwrap();
        match req.msg_type {
            DISCOVER => {
                if let Some(ip) = pool.lease_for(req.chaddr, req.req_ip) {
                    if let Some(h) = &req.hostname {
                        pool.names.insert(u32::from(ip), h.clone());
                    }
                    let reply =
                        build_reply(&req, OFFER, ip, pool.server, pool.mask, pool.server, pool.lease);
                    let _ = sock.send_to(&reply, bcast);
                }
            }
            REQUEST => {
                let granted = pool
                    .by_mac
                    .get(&req.chaddr)
                    .map(|&v| Ipv4Addr::from(v))
                    .or_else(|| pool.lease_for(req.chaddr, req.req_ip));
                match granted {
                    Some(ip) => {
                        if let Some(h) = &req.hostname {
                            pool.names.insert(u32::from(ip), h.clone());
                        }
                        let reply = build_reply(
                            &req, ACK, ip, pool.server, pool.mask, pool.server, pool.lease,
                        );
                        let _ = sock.send_to(&reply, bcast);
                        pool.persist();
                    }
                    None => {
                        let reply = build_reply(
                            &req, NAK, Ipv4Addr::UNSPECIFIED, pool.server, pool.mask,
                            pool.server, 0,
                        );
                        let _ = sock.send_to(&reply, bcast);
                    }
                }
            }
            _ => {}
        }
    }
}

// ---- client ----------------------------------------------------------------

fn client(cfg: &Config) -> i32 {
    let wan_if = cfg.get_or("wan", "ifname", "eth0.2");
    // The interface must be up (link) before we can send.
    let _ = net::up(wan_if);

    let sock = match UdpSocket::bind(("0.0.0.0", 68)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("dhcp client: bind :68: {e}");
            return 1;
        }
    };
    let _ = sock.set_broadcast(true);
    let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    if let Err(e) = bind_to_device(&sock, wan_if) {
        eprintln!("dhcp client: bind {wan_if}: {e}");
    }

    let xid = rand_xid();
    let mac = if_mac(wan_if).unwrap_or([0x02, 0, 0, 0, 0, 1]);
    let server_bcast: SocketAddr = "255.255.255.255:67".parse().unwrap();

    // DISCOVER
    let disc = build_client(xid, mac, DISCOVER, None, None);
    if let Err(e) = sock.send_to(&disc, server_bcast) {
        eprintln!("dhcp client: send discover: {e}");
        return 1;
    }

    let mut buf = [0u8; 1024];
    let offer = loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(p) = parse(&buf[..n]) {
                    if p.op == OP_REPLY && p.msg_type == OFFER && p.xid == xid {
                        break p;
                    }
                }
            }
            Err(_) => {
                eprintln!("dhcp client: no offer (timeout)");
                return 1;
            }
        }
    };

    // REQUEST the offered address
    let req = build_client(xid, mac, REQUEST, Some(offer.yiaddr), Some(offer.yiaddr));
    let _ = sock.send_to(&req, server_bcast);

    let (addr, mask, gw, dns) = loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some((mask, gw, dns)) = parse_ack(&buf[..n], xid) {
                    break (offer.yiaddr, mask, gw, dns);
                }
            }
            Err(_) => {
                eprintln!("dhcp client: no ack (timeout)");
                return 1;
            }
        }
    };

    if let Err(e) = net::configure(wan_if, addr, mask) {
        eprintln!("dhcp client: configure {wan_if}: {e}");
        return 1;
    }
    if let Some(gw) = gw {
        let _ = net::default_route(gw);
    }
    if let Some(dns) = dns {
        let _ = std::fs::write("/run/wan.dns", format!("{dns}\n"));
    }
    println!("dhcp client: {wan_if} = {addr}, gw {gw:?}, dns {dns:?}");
    0
}

fn build_client(
    xid: [u8; 4],
    mac: [u8; 6],
    msg_type: u8,
    req_ip: Option<Ipv4Addr>,
    server: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[0] = OP_REQUEST;
    b[1] = 1;
    b[2] = 6;
    b[4..8].copy_from_slice(&xid);
    b[10] = 0x80; // broadcast flag
    b[28..34].copy_from_slice(&mac);
    b[236..240].copy_from_slice(&MAGIC);
    b.push(OPT_MSGTYPE);
    b.push(1);
    b.push(msg_type);
    if let Some(ip) = req_ip {
        b.push(OPT_REQIP);
        b.push(4);
        b.extend_from_slice(&ip.octets());
    }
    if let Some(s) = server {
        b.push(OPT_SERVERID);
        b.push(4);
        b.extend_from_slice(&s.octets());
    }
    // parameter request list: mask, router, dns
    b.push(55);
    b.push(3);
    b.extend_from_slice(&[OPT_SUBNET, OPT_ROUTER, OPT_DNS]);
    b.push(OPT_END);
    b
}

fn parse_ack(buf: &[u8], xid: [u8; 4]) -> Option<(Ipv4Addr, Option<Ipv4Addr>, Option<Ipv4Addr>)> {
    if buf.len() < 240 || buf[236..240] != MAGIC || buf[4..8] != xid || buf[0] != OP_REPLY {
        return None;
    }
    let mut is_ack = false;
    let mut mask = Ipv4Addr::new(255, 255, 255, 0);
    let mut gw = None;
    let mut dns = None;
    for (code, val) in options(buf) {
        match code {
            OPT_MSGTYPE if val.first() == Some(&ACK) => is_ack = true,
            OPT_SUBNET => mask = ipv4(val).unwrap_or(mask),
            OPT_ROUTER => gw = ipv4(val).or(gw),
            OPT_DNS => dns = ipv4(val).or(dns),
            _ => {}
        }
    }
    is_ack.then_some((mask, gw, dns))
}

fn rand_xid() -> [u8; 4] {
    // No RNG crate; mix pid + time. Good enough for a transaction id.
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let v = (std::process::id() as u64).wrapping_mul(2654435761)
        ^ t.as_nanos() as u64;
    (v as u32).to_be_bytes()
}

/// Read an interface's MAC via SIOCGIFHWADDR.
fn if_mac(ifname: &str) -> Option<[u8; 6]> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return None;
    }
    let mut req = [0u8; 32];
    let b = ifname.as_bytes();
    let n = b.len().min(15);
    req[..n].copy_from_slice(&b[..n]);
    let r = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as _, req.as_mut_ptr()) };
    unsafe { libc::close(fd) };
    if r < 0 {
        return None;
    }
    // sa_family (2 bytes) then 6 bytes of MAC at offset 16+2.
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&req[18..24]);
    Some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_walker_yields_each_tlv_and_stops_at_end() {
        // 240-byte header (only the cookie matters here) + msgtype + reqip + END.
        let mut buf = vec![0u8; 240];
        buf[236..240].copy_from_slice(&MAGIC);
        buf.extend_from_slice(&[OPT_MSGTYPE, 1, DISCOVER]);
        buf.extend_from_slice(&[OPT_REQIP, 4, 192, 168, 1, 50]);
        buf.push(OPT_END);
        buf.extend_from_slice(&[0xff, 0xff]); // trailing junk past END must be ignored

        let opts: Vec<_> = options(&buf).collect();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0], (OPT_MSGTYPE, &[DISCOVER][..]));
        assert_eq!(opts[1], (OPT_REQIP, &[192, 168, 1, 50][..]));
    }

    #[test]
    fn parse_reads_a_built_client_packet() {
        let xid = [0xde, 0xad, 0xbe, 0xef];
        let mac = [0x02, 0, 0, 0, 0, 1];
        let pkt = build_client(xid, mac, REQUEST, Some(Ipv4Addr::new(10, 0, 0, 5)), None);
        let p = parse(&pkt).expect("valid packet");
        assert_eq!(p.op, OP_REQUEST);
        assert_eq!(p.xid, xid);
        assert_eq!(p.chaddr, mac);
        assert_eq!(p.msg_type, REQUEST);
        assert_eq!(p.req_ip, Some(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn truncated_option_does_not_panic() {
        let mut buf = vec![0u8; 240];
        buf[236..240].copy_from_slice(&MAGIC);
        buf.extend_from_slice(&[OPT_REQIP, 4, 1, 2]); // claims len 4, only 2 present
        // ipv4() must reject the short value rather than index out of bounds.
        let p = parse(&buf).expect("header is valid");
        assert_eq!(p.req_ip, None);
    }
}
