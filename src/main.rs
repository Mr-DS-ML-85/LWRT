//! LWRT — one static binary that is the entire router userspace.
//!
//! WireGuard's lesson: keep the hard work in the kernel (nftables, NAT,
//! bridge/DSA, WireGuard, mt76) and ship a tiny userspace tool. This binary
//! is that tool. It dispatches on its applet name (argv[0] basename, like
//! busybox) or the first argument, so a single static binary back ends init,
//! networking, dhcp/dns, firewall, the wg VPN front end, the web UI and ipkg.

mod config;
mod dhcp;
mod dns;
mod fw;
mod httpd;
mod init;
mod ipkg;
// Dependency-free JSON value/parser/serializer, shared by `ubus` and `httpd`.
mod json;
mod log;
mod mtd;
mod net;
mod nl;
mod ntp;
mod sha256;
mod sys;
mod sysupgrade;
mod ubus;
mod util;
mod wg;

use std::env;
use std::net::Ipv4Addr;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = env::args().collect();

    // Applet selection: prefer argv[0] basename (busybox-style symlinks),
    // fall back to argv[1] when invoked as the bare `lwrt` binary.
    let arg0 = args
        .first()
        .map(|s| s.rsplit('/').next().unwrap_or(s))
        .unwrap_or("lwrt");

    let (applet, rest): (&str, &[String]) = match arg0 {
        "lwrt" | "" => match args.get(1) {
            Some(a) => (a.as_str(), &args[2..]),
            None => ("help", &[]),
        },
        other => (other, &args[1..]),
    };

    let code = match applet {
        "init" => init::run(rest),
        "ifup" => applet_ifup(rest),
        "dhcp" => dhcp::run(rest),
        "dns" => dns::run(rest),
        "fw" => fw::run(rest),
        "wg" => wg::run(rest),
        "httpd" => httpd::run(rest),
        "ipkg" => ipkg::run(rest),
        "ntp" => ntp::run(rest),
        "log" => log::run(rest),
        "ubus" => ubus::run(rest),
        "mtd" => mtd::run(rest),
        "sysupgrade" => sysupgrade::run(rest),
        "version" => {
            println!("LWRT {VERSION}");
            0
        }
        "help" | "--help" | "-h" => {
            usage();
            0
        }
        other => {
            eprintln!("lwrt: unknown applet '{other}'");
            usage();
            1
        }
    };
    std::process::exit(code);
}

fn usage() {
    eprintln!(
        "LWRT {VERSION} — compact router userspace\n\
         usage: lwrt <applet> [args]\n\
         applets:\n\
         \x20 init      PID 1: mount, bring up net, supervise services\n\
         \x20 ifup      configure an interface: ifup <name> <ip> <mask> [gw]\n\
         \x20 dhcp      DHCP server|client (dhcp server / dhcp client)\n\
         \x20 dns       DNS forwarder + lease resolver\n\
         \x20 fw        load nftables NAT+filter ruleset\n\
         \x20 wg        WireGuard VPN: wg up / wg down\n\
         \x20 httpd     admin web UI\n\
         \x20 ipkg      package manager: update|list|install|remove\n\
         \x20 ntp       SNTP client: set the clock from a time server\n\
         \x20 log       syslogd (log) / read log (log read) / logger (log <msg>)\n\
         \x20 ubus      message bus: broker (ubus) / list / call / send / listen\n\
         \x20 mtd       flash tool: list / write <img> <part> / erase / verify\n\
         \x20 sysupgrade flash a firmware image and reboot: sysupgrade [-n] <img>\n\
         \x20 version   print version"
    );
}

/// Manual interface config helper: `ifup <name> <ip> <mask> [gateway]`.
fn applet_ifup(args: &[String]) -> i32 {
    if args.len() < 3 {
        eprintln!("usage: ifup <name> <ip> <netmask> [gateway]");
        return 1;
    }
    let (ip, mask) = match (net::parse_v4(&args[1]), net::parse_v4(&args[2])) {
        (Ok(a), Ok(m)) => (a, m),
        _ => {
            eprintln!("ifup: bad address/netmask");
            return 1;
        }
    };
    if let Err(e) = net::configure(&args[0], ip, mask) {
        eprintln!("ifup: {}: {e}", args[0]);
        return 1;
    }
    if let Some(gw) = args.get(3) {
        match gw.parse::<Ipv4Addr>() {
            Ok(gw) => {
                if let Err(e) = net::default_route(gw) {
                    eprintln!("ifup: route: {e}");
                }
            }
            Err(_) => eprintln!("ifup: bad gateway {gw}"),
        }
    }
    println!("ifup: {} = {ip}/{mask}", args[0]);
    0
}
