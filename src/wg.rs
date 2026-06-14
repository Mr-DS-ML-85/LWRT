//! WireGuard front end — the WireGuard lesson embodied: the crypto, the
//! transport, the routing all live in ~4k lines of kernel code; this applet is
//! the thin tool that creates the `wg0` interface (rtnetlink) and pushes the
//! key/port/peers into it (genetlink WG_CMD_SET_DEVICE). No userspace crypto.

use crate::{config::Config, net, nl, nl::NlBuf, util};
use std::net::Ipv4Addr;

const NETLINK_ROUTE: libc::c_int = 0;
const NETLINK_GENERIC: libc::c_int = 16;
const GENL_ID_CTRL: u16 = 16;

// rtnetlink
const RTM_NEWLINK: u16 = 16;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;

// genl ctrl
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

// wireguard genl
const WG_CMD_SET_DEVICE: u8 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_PEERS: u16 = 8;
const WGDEVICE_F_REPLACE_PEERS: u32 = 1;
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

pub fn run(args: &[String]) -> i32 {
    let cfg = Config::load();
    match args.first().map(|s| s.as_str()) {
        Some("down") => {
            eprintln!("wg: down not implemented (delete link)");
            0
        }
        _ => up(&cfg),
    }
}

fn up(cfg: &Config) -> i32 {
    if cfg.get_or("wireguard", "enabled", "0") != "1" {
        println!("wg: disabled");
        return 0;
    }
    let ifname = "wg0";
    if let Err(e) = ensure_link(ifname) {
        eprintln!("wg: create {ifname}: {e}");
        // Continue: it may already exist.
    }

    let privk = match cfg.get("wireguard", "private_key").and_then(util::b64_decode) {
        Some(k) if k.len() == 32 => k,
        _ => {
            eprintln!("wg: missing/invalid private_key");
            return 1;
        }
    };
    let port: u16 = cfg.get_or("wireguard", "listen_port", "51820").parse().unwrap_or(51820);

    if let Err(e) = set_device(ifname, &privk, port, cfg) {
        eprintln!("wg: set_device: {e}");
        return 1;
    }

    // Address the tunnel and bring it up.
    if let Some(addr) = cfg.get("wireguard", "address") {
        let (ip, _cidr) = split_cidr(addr);
        if let Ok(ip) = net::parse_v4(&ip) {
            let _ = net::configure(ifname, ip, Ipv4Addr::new(255, 255, 255, 0));
        }
    }
    let _ = net::up(ifname);
    println!("wg: {ifname} up on :{port}");
    0
}

/// Create a `wireguard`-kind link via rtnetlink.
fn ensure_link(ifname: &str) -> std::io::Result<()> {
    let fd = nl::open(NETLINK_ROUTE)?;

    let mut b = NlBuf::new();
    let m = b.begin_message(
        RTM_NEWLINK,
        nl::NLM_F_REQUEST | nl::NLM_F_CREATE | nl::NLM_F_EXCL | nl::NLM_F_ACK,
        1,
    );
    // ifinfomsg: family,pad,type(u16),index(i32),flags(u32),change(u32) = 16 zero
    // bytes (AF_UNSPEC = 0).
    b.bytes(&[0u8; 16]);
    b.attr_str(IFLA_IFNAME, ifname);
    let info = b.begin_nested(IFLA_LINKINFO);
    b.attr_str(IFLA_INFO_KIND, "wireguard");
    b.end_nested(info);
    b.end_message(m);

    nl::send(fd, b.as_slice())?;
    let res = nl::recv_ack(fd);
    nl::close(fd);
    // EEXIST means the link is already there — fine.
    match res {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        other => other,
    }
}

/// Resolve a genl family id by name (CTRL_CMD_GETFAMILY).
fn genl_family_id(name: &str) -> std::io::Result<u16> {
    let fd = nl::open(NETLINK_GENERIC)?;

    let mut b = NlBuf::new();
    let m = b.begin_message(GENL_ID_CTRL, nl::NLM_F_REQUEST | nl::NLM_F_ACK, 1);
    genlmsghdr(&mut b, CTRL_CMD_GETFAMILY, 1);
    b.attr_str(CTRL_ATTR_FAMILY_NAME, name);
    b.end_message(m);

    nl::send(fd, b.as_slice())?;
    let reply = nl::recv_msg(fd)?;
    nl::close(fd);

    if reply.len() < 20 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "wg: short genl reply",
        ));
    }
    // skip nlmsghdr(16) + genlmsghdr(4)
    let attrs = &reply[20..];
    let mut id = 0u16;
    nl::for_each_attr(attrs, |typ, val| {
        if typ == CTRL_ATTR_FAMILY_ID && val.len() >= 2 {
            id = u16::from_le_bytes([val[0], val[1]]);
        }
    });
    if id == 0 {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "wg: kernel module not loaded?",
        ))
    } else {
        Ok(id)
    }
}

fn set_device(ifname: &str, privk: &[u8], port: u16, cfg: &Config) -> std::io::Result<()> {
    let family = genl_family_id("wireguard")?;
    let fd = nl::open(NETLINK_GENERIC)?;

    let mut b = NlBuf::new();
    let m = b.begin_message(family, nl::NLM_F_REQUEST | nl::NLM_F_ACK, 1);
    genlmsghdr(&mut b, WG_CMD_SET_DEVICE, 1);
    b.attr_str(WGDEVICE_A_IFNAME, ifname);
    b.attr_u32_le(WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);
    b.attr(WGDEVICE_A_PRIVATE_KEY, privk);
    b.attr_u16_ne(WGDEVICE_A_LISTEN_PORT, port);

    // Peers: any [peerN] section with a public_key. The WGDEVICE_A_PEERS list
    // is only opened once we have a valid peer; each peer is a nested attr
    // whose type is its running index.
    let mut peers_scope: Option<nl::Scope> = None;
    let mut peer_idx: u16 = 0;
    for (name, sect) in &cfg.sections {
        if !name.starts_with("peer") {
            continue;
        }
        let pubk = match sect.get("public_key").map(|s| s.as_str()).and_then(util::b64_decode) {
            Some(k) if k.len() == 32 => k,
            _ => continue,
        };
        peers_scope.get_or_insert_with(|| b.begin_nested(WGDEVICE_A_PEERS));

        let peer = b.begin_nested(peer_idx);
        b.attr(WGPEER_A_PUBLIC_KEY, &pubk);
        if let Some(ka) = sect.get("keepalive").and_then(|s| s.parse::<u16>().ok()) {
            b.attr_u16_ne(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, ka);
        }
        if let Some(sa) = sect.get("endpoint").and_then(|ep| sockaddr_in(ep)) {
            b.attr(WGPEER_A_ENDPOINT, &sa);
        }
        if let Some(aips) = sect.get("allowed_ips") {
            let list = b.begin_nested(WGPEER_A_ALLOWEDIPS);
            for (idx, cidr) in aips.split(',').enumerate() {
                allowedip(&mut b, idx as u16, cidr.trim());
            }
            b.end_nested(list);
        }
        b.end_nested(peer);
        peer_idx += 1;
    }
    if let Some(scope) = peers_scope {
        b.end_nested(scope);
    }
    b.end_message(m);

    nl::send(fd, b.as_slice())?;
    let res = nl::recv_ack(fd);
    nl::close(fd);
    res
}

/// Append one WGALLOWEDIP nested attr (indexed by `idx`) to `b`. Parses the
/// CIDR first so a malformed entry writes nothing.
fn allowedip(b: &mut NlBuf, idx: u16, cidr: &str) {
    let (ip, mask) = split_cidr(cidr);
    let addr: Ipv4Addr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return,
    };
    let mask: u8 = mask.parse().unwrap_or(32);
    let s = b.begin_nested(idx);
    b.attr_u16_ne(WGALLOWEDIP_A_FAMILY, libc::AF_INET as u16);
    b.attr(WGALLOWEDIP_A_IPADDR, &addr.octets());
    b.attr(WGALLOWEDIP_A_CIDR_MASK, &[mask]);
    b.end_nested(s);
}

/// "host:port" -> sockaddr_in bytes (sin_family ne, sin_port be, sin_addr be).
fn sockaddr_in(ep: &str) -> Option<Vec<u8>> {
    let (host, port) = ep.rsplit_once(':')?;
    let addr: Ipv4Addr = host.parse().ok()?;
    let port: u16 = port.parse().ok()?;
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v.extend_from_slice(&addr.octets());
    v.extend_from_slice(&[0u8; 8]); // sin_zero
    Some(v)
}

fn split_cidr(s: &str) -> (String, String) {
    match s.split_once('/') {
        Some((a, m)) => (a.to_string(), m.to_string()),
        None => (s.to_string(), "32".to_string()),
    }
}

fn genlmsghdr(b: &mut NlBuf, cmd: u8, version: u8) {
    b.bytes(&[cmd, version, 0, 0]);
}
