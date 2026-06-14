# LWRT — Lightweight Wireless Router

**OpenWrt's userspace, reimagined as one compact static Rust binary, riding
inside an execute-in-place (XIP) Linux kernel — small enough for a 4 MB / 4 MB
router.**

LWRT keeps the hard parts where they belong (the mainline Linux kernel: the
nftables VM, conntrack/NAT, the bridge/DSA datapath, WireGuard, mac80211/mt76)
and replaces the sprawling OpenWrt userspace — procd, netifd, ubus, uci,
dnsmasq, fw4, opkg, uhttpd/LuCI, dropbear, wpad — with a **single ~0.6 MB
multicall binary**. One static executable *is* the entire userspace: PID 1,
the network bring-up, DHCP, DNS, the firewall loader, the WireGuard front end,
the package manager, and the admin web UI, dispatched busybox-style on the
applet name.

> Status: early but real. The userspace cross-compiles and the XIP kernel
> boots it as PID 1 in QEMU. See [`incomplete.md`](old_bugs/incomplete.md) and
> [`bugs.md`](old_bugs/bugs.md) for the honest list of gaps and hardening still in
> flight.

📖 **Documentation:** a full guide — architecture, every applet, the netlink
builder, the config format, building, porting and an OpenWrt→LWRT parity map —
lives in [`docs/`](docs/) as a static site (open `docs/index.html`, or serve it
with `python3 -m http.server` from that directory).

---

## Why

A typical SoHo router (e.g. the TP-Link Archer C54: MT7628, 16 MB RAM but only
**4 MB SPI flash**) cannot hold a modern OpenWrt image. Two ideas buy the room
back:

1. **XIP kernel** — on MIPS, KSEG0/KSEG1 are *unmapped* segments, so the
   kernel's `.text`/`.rodata`/`.init.text` can run directly from the flash
   window with no page tables and no copy to RAM. That frees ~2.3 MB of RAM
   that stock Linux spends on a decompressed kernel image.
2. **One tiny userspace binary** — instead of dozens of C daemons + shared
   libraries + an interpreter stack, a single statically-linked Rust binary
   with musl. No `libubus`, no Lua, no shell.

---

## OpenWrt → LWRT parity map

Clean-room reimplementation (not a machine translation of GPL sources) of the
behaviour that matters, compacted. This maps the *whole* OpenWrt default
userspace — every base-system daemon, not just the headline ones — onto LWRT
applets, so the gaps are honest and complete.

| OpenWrt component         | What it does                          | LWRT applet   | Status |
|---------------------------|---------------------------------------|---------------|--------|
| procd                     | PID 1: init, supervise, reap          | `init`        | done — mounts, net bring-up, respawn |
| ubusd / libubus           | system IPC message/object bus         | `ubus`        | done — unix-socket newline-JSON bus, `system` object + provider routing |
| rpcd (+rrdns)             | ubus-over-JSON-RPC, ACLs              | `httpd`/`ubus`| partial — JSON API in `httpd` |
| uci / libuci              | config store                          | `config`      | done — INI at `/etc/lwrt/config` |
| netifd                    | interface daemon + proto handlers     | `net`/`ifup`  | done — ioctl/netlink interface config |
| fstools / mtd / fwtool    | overlay mount, sysupgrade, flash I/O  | `mtd`/`sysupgrade` | partial — `mtd` write/erase/verify (MTD ioctls) + `sysupgrade` validate/flash/reboot; overlay mount planned |
| logd                      | syslog ring + `/dev/log`              | `log`         | done — `/dev/log` + `/dev/kmsg` syslogd |
| libubox / blobmsg / ubox  | utility libraries (json, lists)       | internal Rust | n/a — std + own `nl`/`sha256` |
| dnsmasq (DHCP)            | LAN DHCP server + WAN client          | `dhcp`        | done — server (LAN) + client (WAN) |
| dnsmasq (DNS)             | forwarding cache + `.lan` leases      | `dns`         | done — forwarding cache + lease names |
| odhcpd / odhcp6c          | IPv6 RA/DHCPv6 server + client        | `dhcp6`       | planned |
| ppp / ppp-mod-pppoe       | PPPoE WAN dial                        | `pppoe`       | planned |
| firewall4 (fw4)           | nftables NAT + filter                 | `fw`          | done — inet table: input policy-drop, stateful forward, masquerade, DNAT port-forwards |
| wireguard-tools           | WG link + peers                       | `wg`          | done — via rtnetlink/genetlink |
| wpad / hostapd            | AP + WPA/EAPOL over nl80211           | `wifi`        | planned (hard) |
| iw / iwinfo               | wireless status / scan                | `wifi`        | planned |
| uhttpd                    | web server                            | `httpd`       | done — threaded server, embedded SPA + JSON API, session auth + CSRF |
| LuCI                      | web admin UI                          | `httpd`       | done — single-page app, XSS-safe rendering, secret redaction |
| dropbear                  | SSH server                            | `sshd`        | planned (hard) |
| sysntpd                   | SNTP client                           | `ntp`         | done — sets the clock |
| opkg                      | package manager                       | `ipkg`        | done — ustar `.ipk`, SHA-256 verified |
| usign                     | signed-feed verification              | `ipkg`        | planned — ed25519 signed index |

---

## Repository layout

```
src/            the multicall userspace (one binary, one applet per module)
rootfs/         default on-device files (etc/lwrt/config)
scripts/
  build.sh      portable cross-build of the mipsel-musl binary
  mkrootfs.sh   stage the rootfs + emit a cpio.gz initramfs
  mkimage.sh    bake LWRT into the XIP kernel -> bootable flash image
.cargo/         tier-3 target + build-std settings (machine-neutral)
vendor/         libunwind.a shim (regenerated by build.sh; git-ignored)
incomplete.md   known gaps / not-yet-implemented
bugs.md         per-file audit (severity + line numbers)
```

The XIP kernel lives in its **own** repository (`mips-xip-kernel`); LWRT points
at it at build time and does not vendor it.

---

## Building

**Prerequisites**

- Rust nightly with `rust-src` (`rust-toolchain.toml` pins this).
- An OpenWrt musl cross toolchain for `mipsel_24kc` (provides the musl gcc that
  drives the final link — the tier-3 target ships no self-contained CRT).
- For the kernel image: `clang`, a `mipsel-linux-gnu-` binutils, `cpio`,
  `qemu-system-mipsel`.

**The userspace binary**

```sh
scripts/build.sh
```

`build.sh` auto-detects your OpenWrt `staging_dir`, wires the linker and
`STAGING_DIR` via environment (so `.cargo/config.toml` stays machine-neutral),
regenerates `vendor/libunwind.a`, and produces
`target/mipsel-unknown-linux-musl/release/lwrt`. Override paths with
`LWRT_OPENWRT`, `LWRT_TOOLCHAIN`, `LWRT_TARGET`.

**The bootable XIP image**

```sh
scripts/mkimage.sh            # builds binary -> stages rootfs -> kernel image
```

Point it at your kernel tree with `LWRT_KERNEL=/path/to/mips-xip-kernel`. The
result is `<kernel>/build/out/xip-bios.bin`. Boot it:

```sh
qemu-system-mipsel -M malta -cpu 24Kf -m 256 -bios xip-bios.bin -nographic
```

You should see `LWRT init: PID 1 starting`.

---

## Porting to another router

LWRT itself is board-agnostic — it talks to the kernel through standard ioctls
and netlink. Porting is really *kernel* porting:

1. **Pick the flash XIP window.** Set `CONFIG_XIP_PHYS_ADDR` to the SoC's
   memory-mapped SPI/NOR flash base. On MT7628 that is `0x1c000000`
   (KSEG0 `0x9c000000`).
2. **Mind the R_MIPS_26 boundary.** MIPS `jal` can only jump within a
   256 MB-aligned segment. Keep the kernel's flash-resident text below the next
   `0x_0000000` boundary above the window. The QEMU malta `-bios` window at
   `0x1fc01000` leaves only ~4 MB before `0xa0000000`, which is why the malta
   defconfig omits the netfilter stack; the MT7628 window at `0x9c000000` has
   64 MB of headroom and fits the full firewall.
3. **Write a defconfig** for the board (NIC driver, DSA/switch, WiFi) modeled on
   `configs/lwrt_qemu_malta_defconfig`.
4. **Adjust `rootfs/etc/lwrt/config`** — interface names (`lan.ifname`,
   `wan.ifname`), addresses, radios.

---

## Debugging on real hardware

- **Serial console early.** Keep `earlycon=ttyS0` (or the board's UART) on the
  kernel command line. Rust init's kernel-ABI mismatches then surface as
  syscall errors on the console before anything else is up — e.g.
  `mount /proc: No such device` means `CONFIG_PROC_FS` is off,
  `Function not implemented` means the matching kernel subsystem is missing.
- **Netlink, not strace.** There is no strace on the device. To debug firewall
  rule application, read the kernel's netlink/netfilter logs — the `fw` applet
  programs nftables over `NETLINK_NETFILTER` and the kernel reports rejections.
- **Binary integrity.** Make sure the musl library the toolchain links against
  is compatible with the kernel version you boot; a mismatch shows up as
  syscall ENOSYS/EINVAL from otherwise-correct code.

---

## License

GPL-2.0-or-later. See [`LICENSE`](LICENSE).
