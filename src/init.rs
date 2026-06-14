//! PID 1. Mounts the virtual filesystems, brings up the network from
//! /etc/lwrt/config, then supervises the long-running service applets
//! (dhcp server, dns, httpd) — respawning any that die. WireGuard and the
//! firewall live in the kernel; we just push their config in once at boot.

use crate::{config::Config, net, sys};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Long-running services init keeps alive. Each is just this binary re-exec'd
/// with the applet name (busybox-style multicall).
const SERVICES: &[&[&str]] = &[
    &["log"],
    &["ubus"],
    &["dhcp", "server"],
    &["dns"],
    &["httpd"],
];

pub fn run(_args: &[String]) -> i32 {
    println!("LWRT init: PID {} starting", std::process::id());
    sys::signal(libc::SIGTERM, on_term);

    mount_all();
    let cfg = Config::load();
    bring_up_network(&cfg);

    // One-shot kernel config: firewall ruleset + WireGuard (if enabled).
    run_oneshot(&["fw"]);
    if cfg.get_or("wireguard", "enabled", "0") == "1" {
        run_oneshot(&["wg", "up"]);
    }

    supervise();
    0
}

fn mount_all() {
    // (source, target, fstype, flags, data)
    let mounts: &[(&str, &str, &str, u64, &str)] = &[
        ("proc", "/proc", "proc", 0, ""),
        ("sysfs", "/sys", "sysfs", 0, ""),
        ("devtmpfs", "/dev", "devtmpfs", 0, ""),
        ("tmpfs", "/tmp", "tmpfs", 0, "mode=1777"),
        ("tmpfs", "/run", "tmpfs", 0, "mode=0755"),
    ];
    for (src, tgt, fs, flags, data) in mounts {
        let _ = sys::mkdir(tgt, 0o755);
        if let Err(e) = sys::mount(src, tgt, fs, *flags, data) {
            // EBUSY just means it's already mounted — harmless.
            if e.raw_os_error() != Some(libc::EBUSY) {
                eprintln!("init: mount {tgt}: {e}");
            }
        }
    }
}

fn bring_up_network(cfg: &Config) {
    let _ = net::up("lo");

    let lan_if = cfg.get_or("lan", "ifname", "br-lan");
    let ip = cfg.get_or("lan", "ipaddr", "192.168.1.1");
    let mask = cfg.get_or("lan", "netmask", "255.255.255.0");
    match (net::parse_v4(ip), net::parse_v4(mask)) {
        (Ok(a), Ok(m)) => {
            if let Err(e) = net::configure(lan_if, a, m) {
                eprintln!("init: lan {lan_if}: {e}");
            } else {
                println!("init: {lan_if} = {ip}/{mask}");
            }
        }
        _ => eprintln!("init: bad lan address {ip}/{mask}"),
    }

    // WAN: dhcp client runs as a one-shot to obtain the initial lease;
    // for static, configure directly.
    match cfg.get_or("wan", "proto", "dhcp") {
        "dhcp" => run_oneshot(&["dhcp", "client"]),
        "static" => {
            let wan_if = cfg.get_or("wan", "ifname", "eth0.2");
            if let (Some(a), Some(m)) = (cfg.get("wan", "ipaddr"), cfg.get("wan", "netmask")) {
                if let (Ok(a), Ok(m)) = (net::parse_v4(a), net::parse_v4(m)) {
                    let _ = net::configure(wan_if, a, m);
                }
            }
            if let Some(gw) = cfg.get("wan", "gateway") {
                if let Ok(gw) = net::parse_v4(gw) {
                    let _ = net::default_route(gw);
                }
            }
        }
        other => eprintln!("init: unknown wan proto {other}"),
    }
}

/// Run an applet to completion as a child (fork+exec self).
fn run_oneshot(argv: &[&str]) {
    match sys::fork() {
        Ok(Some(pid)) => {
            // Parent: wait for this specific child.
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }
        Ok(None) => exec_self(argv),
        Err(e) => eprintln!("init: fork {argv:?}: {e}"),
    }
}

/// Supervise the SERVICES: spawn each, then on any child exit respawn it.
fn supervise() {
    let mut pids: Vec<(libc::pid_t, usize)> = Vec::new();
    for (idx, svc) in SERVICES.iter().enumerate() {
        if let Some(pid) = spawn(svc) {
            pids.push((pid, idx));
        }
    }

    loop {
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        let mut status = 0;
        let dead = unsafe { libc::waitpid(-1, &mut status, 0) };
        if dead <= 0 {
            continue;
        }
        if let Some(slot) = pids.iter().position(|(p, _)| *p == dead) {
            let (_, idx) = pids.remove(slot);
            eprintln!("init: service {:?} died, respawning", SERVICES[idx]);
            if let Some(pid) = spawn(SERVICES[idx]) {
                pids.push((pid, idx));
            }
        }
    }

    // Graceful-ish shutdown: tell everyone to go, then reboot.
    unsafe { libc::kill(-1, libc::SIGTERM) };
    let _ = sys::reboot(libc::LINUX_REBOOT_CMD_RESTART);
}

fn spawn(argv: &[&str]) -> Option<libc::pid_t> {
    match sys::fork() {
        Ok(Some(pid)) => Some(pid),
        Ok(None) => exec_self(argv),
        Err(e) => {
            eprintln!("init: spawn {argv:?}: {e}");
            None
        }
    }
}

/// Replace the current (forked) process image with this binary running
/// `argv`. Never returns on success.
///
/// We try `/proc/self/exe` first (works regardless of where the binary lives)
/// but fall back to the canonical install path so supervision still works on
/// kernels built without procfs. Both are attempted before giving up.
fn exec_self(argv: &[&str]) -> ! {
    // argv[0] = applet name so multicall dispatch picks it up.
    let cargs: Vec<CString> = std::iter::once(argv[0])
        .chain(argv[1..].iter().copied())
        .map(|a| CString::new(a).unwrap_or_else(|_| CString::new("").unwrap()))
        .collect();
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    for prog in ["/proc/self/exe", "/sbin/lwrt"] {
        if let Ok(p) = CString::new(prog) {
            unsafe {
                libc::execv(p.as_ptr(), ptrs.as_ptr());
            }
            // execv only returns on failure; try the next candidate.
        }
    }
    eprintln!("init: execv {argv:?} failed: {}", std::io::Error::last_os_error());
    std::process::exit(127);
}
