# incomplete.md

All known issues, gaps, and incomplete functionality in c54-os.

## Critical

- **No web UI authentication** (`src/httpd.rs:67-91`) — anyone on LAN can read/write config including WireGuard private keys, reboot the router
- **XSS in web UI** (`src/httpd.rs:149-203`) — lease hostnames and status values injected into innerHTML without escaping
- **ipkg path traversal** (`src/ipkg.rs:166-204`) — packages extract to `/`; a malicious package can overwrite any file on the system
- **No ipkg checksum/signature verification** (`src/ipkg.rs:47-58`) — HTTP-only downloads with no integrity checks, trivial MITM

## High

- **WiFi completely unimplemented** — `[wifi]` config section is parsed but no code acts on it (no hostapd/iw/wpa_supplicant)
- **`wg down` unimplemented** (`src/wg.rs:44-47`) — prints "not implemented", returns success, interface stays up
- **`fw flush` unimplemented** (`src/fw.rs:90-94`) — no-op, cannot tear down nftables ruleset
- **No port forwarding / DNAT** (`src/fw.rs:89-111`) — firewall only does masquerade + stateful forward, no way to forward ports to internal servers
- **No INPUT chain** (`src/fw.rs:175-183`) — router itself is unprotected from inbound WAN connections; httpd accessible from internet
- **IP forwarding enable silently discarded** (`src/fw.rs:114-117`) — if `/proc/sys/net/ipv4/ip_forward` write fails, no error reported, routing silently broken
- **No DHCP lease expiry** (`src/dhcp.rs:1-488`) — leases never reclaimed, offline clients hold IPs forever
- **DHCP server continues if device bind fails** (`src/dhcp.rs:230-240`) — responds to DHCP from any interface including WAN, hands out LAN IPs to WAN clients
- **Socket FD leak in net::configure** (`src/net.rs:46-64`) — if SIOCSIFADDR succeeds but SIOCSIFNETMASK fails, socket never closed
- **No respawn rate limiting** (`src/init.rs:113-143`) — crash-looping services respawn infinitely, consuming CPU
- **Hardcoded toolchain paths** (`.cargo/config.toml:8,20`) — breaks on any machine other than the original developer's
- **No logging framework** — all output is println!/eprintln!, no log levels, no timestamps, no persistence
- **No IPv6 support anywhere** — entire codebase is IPv4-only
- **No NTP / time synchronization** — system clock starts at epoch on devices without RTC, affects WireGuard handshakes, DHCP leases, any future TLS

## Medium

- **Web UI is HTTP only** (`src/httpd.rs:15`) — config changes including private keys sent in plaintext
- **Serial HTTP server** (`src/httpd.rs:24-29`) — one connection at a time, slow client blocks all admin access
- **No CSRF protection on reboot** (`src/httpd.rs:84-88`)
- **Hardcoded WireGuard interface name "wg0"** (`src/wg.rs:57`)
- **WireGuard CIDR mask discarded** (`src/wg.rs:77-83`) — always hardcoded to /24 regardless of config
- **`ensure_link` failure swallowed** (`src/wg.rs:58-61`) — errors from creating WG interface not propagated
- **ipkg HTTP only, no HTTPS** (`src/ipkg.rs:116-160`)
- **ipkg ignores symlinks/special files** (`src/ipkg.rs:200`)
- **ipkg no `upgrade` subcommand** (`src/ipkg.rs:18-45`)
- **ipkg no reference counting** (`src/ipkg.rs:97-113`) — shared files deleted for all packages
- **DNS cache TTL hardcoded to 60s** (`src/dns.rs:47`)
- **DNS cache grows without bound** (`src/dns.rs:25-63`) — no eviction, OOM risk on busy networks
- **DNS single upstream, no fallback** (`src/dns.rs:66-71`) — falls back to hardcoded 1.1.1.1
- **DHCP unwrap() panics before UNIX epoch** (`src/dhcp.rs:196`) — real risk on boot without RTC
- **DHCP 1024-byte receive buffers** (`src/dhcp.rs:256,340`) — too small for full DHCP packets with options
- **DHCP no lease persistence across restarts** (`src/dhcp.rs:156-214`)
- **`[system] hostname` cosmetic only** — displayed in web UI but never set on the system (no sethostname syscall)
- **No unmount on shutdown** (`src/init.rs:42-59`) — filesystems not unmounted before reboot
- **Config load failure silent** (`src/config.rs:40-45`) — defaults used with no warning
- **cpio/gzip errors suppressed in mkrootfs.sh** (`scripts/mkrootfs.sh:32`) — can produce zero-byte initramfs
- **CString::new().unwrap() panics** (`src/init.rs:158-173`, `src/sys.rs:9-12`) — NUL bytes in config crash PID 1
- **Interface name silently truncated** (`src/net.rs:20-26`) — names >15 bytes truncated without error
- **Fixed 8192-byte netlink buffer** (`src/nl.rs:135-142`)
- **Service list hardcoded at compile time** (`src/init.rs:18-22`) — cannot add services without recompilation

## Not implemented

- Port forwarding / DNAT rules
- Custom firewall rules (entire ruleset is hardcoded)
- IPv6 (DHCPv6, NDP, NAT66)
- NTP client
- Persistent logging / syslog
- Hardware watchdog integration
- HTTPS (web UI or ipkg)
- WiFi management (hostapd/iw/wpa_supplicant)
- `wg down`
- `fw flush`
- `ipkg upgrade`
- Config validation


