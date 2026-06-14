# COMPREHENSIVE CODE AUDIT: C54-OS

## FILE: `/home/irfan/Desktop/tools/c54-os/src/wg.rs`

### 1. Unimplemented Stubs / TODOs / No-ops

| Line | Issue | Severity |
|------|-------|----------|
| **44-47** | **`wg down` is a no-op stub.** Prints "not implemented" and returns 0 (success). Any user or script calling `wg down` will believe the interface was torn down when it was not. The WireGuard interface, peers, and keys remain active in the kernel. This is explicitly documented as incomplete. | HIGH |
| **57** | **Hardcoded WireGuard interface name `"wg0"`.** Unlike LAN/WAN ifnames which come from config, the WG interface name is hardcoded to `"wg0"`. Cannot run multiple tunnels or use a custom interface name. | MEDIUM |
| **70** | **`listen_port` parsing uses `unwrap_or(51820)`.** If the config value is malformed (e.g., `port = abc`), it silently falls back to 51820 with no warning. | LOW |

### 2. Missing Error Handling / Silent Failures

| Line | Issue | Severity |
|------|-------|----------|
| **58-61** | **`ensure_link` failure is swallowed.** If creating the WG interface fails (and it is not EEXIST), the code logs it but continues to `set_device`, which will then fail with a confusing error. The comment says "it may already exist" but other errors (permission denied, module not loaded) are not handled. | MEDIUM |
| **79-82** | **`net::configure` result is ignored** (`let _ = net::configure(...)`). If addressing the WG interface fails, no error is reported. | MEDIUM |
| **84** | **`net::up(ifname)` result is ignored** (`let _ = net::up(ifname)`). | LOW |
| **159-168** | **Peer configuration silently skips invalid peers.** If a `[peerN]` section has a malformed `public_key` or no `public_key`, it is silently skipped with no warning. | LOW |
| **173-176** | **`sockaddr_in` endpoint parsing silently skips on failure.** If the endpoint format is invalid, no error or warning is emitted; the peer is created without an endpoint. | LOW |
| **180-184** | **`allowedip` silently skips invalid CIDRs.** No warning for malformed allowed_ips entries. | LOW |
| **213** | **`peers_index` returns `n | NLA_F_NESTED`.** This ORs the nested flag into the index count, which happens to work because the WireGuard genetlink protocol uses the index as the nla_type, and nested attributes need the flag. However, if there are more than ~32K peers, this would overflow. Not a practical concern, but semantically confusing. | LOW |

### 3. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **63-68** | **Private key validation is minimal.** Only checks length == 32 bytes after base64 decode. Does not validate that the key is not all zeros (which is an invalid WireGuard key that the kernel would reject). | LOW |
| **77-83** | **WireGuard address CIDR is extracted but the CIDR mask is discarded** (`let (ip, _cidr) = split_cidr(addr)`). The netmask is always hardcoded to `/24` (`255.255.255.0`). If the user configures `address = 10.7.0.1/32`, the netmask will still be /24, which is incorrect. | MEDIUM |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/ipkg.rs`

### 1. Unimplemented Stubs / Missing Functionality

| Line | Issue | Severity |
|------|-------|----------|
| **200** | **Symlinks, devices, and other special files are ignored.** The `extract_ustar` function only handles regular files (`b'0'` or 0) and directories (`b'5'`). All other ustar typeflags (symlinks `b'2'`, hardlinks `b'1'`, character/block devices `b'3'`/`b'4'`) are silently skipped. | MEDIUM |
| **116-160** | **HTTP only, no HTTPS.** The `http_get` function only supports plain HTTP. No TLS support. Packages are downloaded in plaintext, vulnerable to MITM attacks. This is documented as known. | HIGH |
| **47-58** | **No checksum/signature verification.** Downloaded packages are not verified against any checksum or signature. A corrupted or tampered package would be extracted as-is. | HIGH |
| **18-45** | **No `upgrade` subcommand.** Cannot upgrade installed packages; only install/remove/update-list are supported. | MEDIUM |
| **97-113** | **`remove` does not handle shared files.** If two packages install the same file, removing one deletes the file for both. No reference counting. | MEDIUM |
| **97-113** | **`remove` does not remove empty directories left behind.** After removing files, empty parent directories remain. | LOW |

### 2. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **166-204** | **Path traversal in `extract_ustar`.** While `sanitize()` (line 222-226) strips leading `./` and `/` and removes `..` components, it always prepends `/`. This means every file in the package is extracted relative to `/`. A malicious package could overwrite any file on the system (e.g., `/etc/shadow`, `/etc/c54/config`). The `sanitize` function is a defense but the entire model of extracting to `/` is inherently dangerous. | CRITICAL |
| **166-204** | **No size limit on extracted files.** A malicious package could contain an extremely large file that fills up the flash/RAM. | HIGH |
| **118-156** | **No HTTP timeout or connection timeout.** `TcpStream::connect` uses OS defaults; `read_to_end` has no limit. A slow or malicious server could cause the client to hang or exhaust memory. | MEDIUM |
| **146-151** | **HTTP response parsing is fragile.** Checks for `" 200"` substring in the status line. Would match `HTTP/1.1 200 OK` but also `HTTP/1.1 2000 Bad` or any response containing `" 200"` anywhere. | LOW |
| **134-136** | **No `Host` header validation.** The `Host` header is sent but responses are not validated against it. | LOW |

### 3. Missing Error Handling

| Line | Issue | Severity |
|------|-------|----------|
| **50** | **`fs::write` result is discarded** (`let _ = fs::write(...)`). If writing the package index fails, no error is reported. | LOW |
| **86** | **`fs::write` for manifest is discarded** (`let _ = fs::write(...)`). | LOW |
| **106-109** | **`fs::remove_file` results are discarded** (`let _ = fs::remove_file(f)`). Failed file deletions are silently ignored. | LOW |
| **180** | **Slice bounds not checked against data length.** `file_data = &data[off..(off + size).min(data.len())]` -- if `off + size` overflows `usize` (extremely unlikely but possible with malicious input), this could panic. | LOW |

### 4. Hardcoded Values

| Line | Issue | Severity |
|------|-------|----------|
| **16** | **`STATE` path hardcoded to `/var/ipkg`.** Cannot be changed without recompilation. | LOW |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/httpd.rs`

### 1. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **149-203** | **XSS vulnerability in the embedded HTML/JS.** The `loadLeases` function injects lease data directly into HTML via template literals without escaping: `` `<tr><td>${x.name}<td>${x.ip}<td>${x.mac}</tr>` ``. A hostname containing `<script>` or HTML tags would execute arbitrary JavaScript in the admin browser. The `loadStatus` function similarly injects `${s.hostname}`, `${s.lan}`, etc. into innerHTML without escaping. | CRITICAL |
| **67-91** | **No authentication on any API endpoint.** Anyone on the LAN can read the config (including WireGuard private keys), modify config, and reboot the router. The `/api/config` GET endpoint exposes `config::PATH` which includes `private_key = ...` in the wireguard section. | CRITICAL |
| **77-83** | **`POST /api/config` accepts arbitrary config.** Any client can overwrite the entire `/etc/c54/config` file with arbitrary content, including injecting malicious settings (e.g., changing the DHCP server range, DNS settings, firewall rules, or WireGuard keys). No validation of the submitted config. | CRITICAL |
| **84-88** | **`POST /api/reboot` has no CSRF protection.** A malicious page open in a LAN browser could force the router to reboot via a form submission or fetch. | MEDIUM |
| **15** | **Listens only on port 80.** No HTTPS. Config changes and the admin UI are transmitted in plaintext. | MEDIUM |
| **24-29** | **Single-threaded, serial request handling.** Only one connection is served at a time. A single slow client (slowloris-style) can block all other admin access. | MEDIUM |

### 2. Missing Error Handling

| Line | Issue | Severity |
|------|-------|----------|
| **36** | **`reader.read_line` result is checked for `== 0` later (line 45) but the first `read_line` on line 36 does not handle EOF gracefully.** If the client disconnects before sending a request, `read_line` returns `Ok(0)` but `method` and `path` will be empty strings, leading to a 404 response -- acceptable but sloppy. | LOW |
| **54** | **`reader.read_exact` could fail** if the client sends a Content-Length header but disconnects before sending the body. The error propagates up and the connection is dropped. | LOW |
| **75** | **`fs::read(config::PATH)` failure falls back to DEFAULT.** If the config file is corrupted or missing, the web UI silently shows the default config, not the actual file content. This is inconsistent with the intent of "edit the config file". | LOW |
| **112-115** | **`/proc/uptime` parsing is fragile.** If the format changes or the file is missing, uptime shows "0" with no error. | LOW |

### 3. Hardcoded Values

| Line | Issue | Severity |
|------|-------|----------|
| **15** | **HTTP port 80 is hardcoded.** Cannot be configured via config file. | MEDIUM |
| **189-202** | **Status auto-refresh interval is hardcoded to 5000ms** in JavaScript. | LOW |
| **201** | **`confirm()` dialog text is hardcoded** in English. No i18n. | LOW |

### 4. Architectural Limitations

| Line | Issue | Severity |
|------|-------|----------|
| **24-29** | **No keep-alive / persistent connections.** Uses HTTP/1.0 with `Connection: close`. Every page load requires a new TCP connection. | LOW |
| **58-64** | **No CORS headers.** The API cannot be accessed from other origins (could be a feature, but limits future extensibility). | LOW |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/dns.rs`

### 1. Missing Functionality

| Line | Issue | Severity |
|------|-------|----------|
| **84-117** | **Only handles A records.** AAAA (IPv6), MX, CNAME, TXT, SOA, and all other record types are not supported locally. Queries for non-A types are forwarded upstream, but local lease answers only work for A records. | MEDIUM |
| **86-87** | **Only handles single-question queries.** Queries with `qdcount != 1` are silently forwarded. Most real-world clients send one question, but the spec allows multiple. | LOW |
| **47** | **Cache TTL is hardcoded to 60 seconds** regardless of the upstream record's actual TTL. This is wasteful for long-lived records and potentially stale for short-lived ones. | MEDIUM |
| **25-63** | **No cache eviction.** The HashMap grows without bound. On a busy network with many unique queries, this will consume increasing memory until the process is OOM-killed. | MEDIUM |
| **66-71** | **Only one upstream DNS server.** Reads from `/run/wan.dns` which contains a single IP. No fallback if that server is unreachable. Falls back to `1.1.1.1` if the file is missing. | MEDIUM |

### 2. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **73-79** | **DNS amplification potential.** The forwarder creates a new UDP socket per query and sends the full query upstream. The response from upstream is forwarded back verbatim, which could be larger than the query. This is standard DNS behavior, but without rate limiting, the server could be used as an amplifier. | LOW |
| **99-100** | **Local answer uses `.lan` suffix stripping.** `name.trim_end_matches(".lan")` only handles the `.lan` TLD. If a client queries for `host.local` or `host`, the local lookup will fail. Inconsistent naming. | LOW |
| **113** | **Hardcoded TTL of 120 seconds** for local lease answers. This is independent of the actual DHCP lease time. | LOW |

### 3. Missing Error Handling

| Line | Issue | Severity |
|------|-------|----------|
| **40** | **`sock.send_to` result is discarded** (`let _ = sock.send_to(...)`). Failed responses are silently dropped. | LOW |
| **51** | **Same issue on cached response send.** | LOW |
| **61** | **Same issue on forwarded response send.** | LOW |
| **146** | **`read_to_string` for leases uses `.ok()` which silently returns None.** If the leases file is missing or unreadable, local resolution simply returns None with no error. | LOW |

### 4. Hardcoded Values

| Line | Issue | Severity |
|------|-------|----------|
| **47** | **Cache TTL hardcoded to 60 seconds.** | MEDIUM |
| **70** | **Fallback DNS hardcoded to `1.1.1.1`.** | LOW |
| **113** | **Local answer TTL hardcoded to 120.** | LOW |
| **14** | **DNS port 53 is hardcoded.** Cannot run on an alternative port. | LOW |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/dhcp.rs`

### 1. Missing Functionality

| Line | Issue | Severity |
|------|-------|----------|
| **1-488** | **No DHCP lease expiry.** Leases are written to `/run/dhcp.leases` with an expiry timestamp, but the server never checks or reclaims expired leases. A client that goes offline permanently holds its IP forever until the server restarts. | HIGH |
| **218-222** | **When DHCP is disabled, the server enters an infinite sleep loop.** It does not exit or return; it sleeps forever in 1-hour increments. This means init's supervisor will never see it die, and it occupies a process slot doing nothing. | MEDIUM |
| **461-467** | **`rand_xid` is not cryptographically random.** Uses PID XOR timestamp. A sophisticated attacker could predict transaction IDs and spoof DHCP responses. | LOW |
| **425-459** | **`parse_ack` only extracts one DNS server.** If the DHCP server provides multiple DNS servers (which is common), only the first is used. | LOW |
| **448-449** | **Only one router/gateway is extracted** from the DHCP ACK, even though the DHCP option can contain multiple. | LOW |
| **389-423** | **Client DISCOVER uses broadcast flag** (`b[10] = 0x80`). This is correct for initial discovery, but the client should handle unicast responses too (some servers respond unicast after the initial handshake). | LOW |
| **156-214** | **`Pool` struct has no persistence across restarts.** If the DHCP server restarts, all in-memory leases are lost. Clients will continue using their IPs until their leases expire, but the server doesn't know about them and may reassign the same IPs to new clients, causing conflicts. | MEDIUM |

### 2. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **230** | **DHCP server binds to `0.0.0.0:67`** before binding to the device. If `SO_BINDTODEVICE` fails (line 238-240), the server continues running and will respond to DHCP requests from ANY interface, including the WAN. This could hand out LAN IPs to WAN clients. | HIGH |
| **316** | **DHCP client binds to `0.0.0.0:68`** -- same device-binding issue as the server. If the device bind fails, the client could receive responses from the wrong interface. | MEDIUM |
| **266** | **Broadcast address `255.255.255.255:68` is hardcoded.** This is correct for BOOTP/DHCP but doesn't handle unicast responses. | LOW |

### 3. Missing Error Handling

| Line | Issue | Severity |
|------|-------|----------|
| **196** | **`SystemTime::now().duration_since(UNIX_EPOCH).unwrap()` will panic** if the system clock is before UNIX epoch. On an embedded device without RTC, this is a real concern at boot. | MEDIUM |
| **275** | **`sock.send_to` for OFFER is discarded** (`let _ = sock.send_to(...)`). Failed offers are silently dropped. | LOW |
| **292** | **`sock.send_to` for ACK is discarded.** | LOW |
| **300** | **`sock.send_to` for NAK is discarded.** | LOW |
| **359** | **`sock.send_to` for REQUEST is discarded** (`let _ = sock.send_to(...)`). If this fails, the client will wait for an ACK that never comes and timeout. | LOW |
| **380** | **`net::default_route` result is discarded** (`let _ = net::default_route(gw)`). | LOW |
| **383** | **DNS file write result is discarded** (`let _ = std::fs::write(...)`). | LOW |

### 4. Hardcoded Values

| Line | Issue | Severity |
|------|-------|----------|
| **36** | **`LEASES_PATH` hardcoded to `/run/dhcp.leases`.** | LOW |
| **256** | **Receive buffer hardcoded to 1024 bytes.** DHCP packets can be up to ~1500 bytes (with options). A packet with options beyond 1024 bytes would be truncated. | MEDIUM |
| **340** | **Client receive buffer also 1024 bytes.** | MEDIUM |
| **324** | **Client timeout hardcoded to 5 seconds.** Not configurable. | LOW |
| **330** | **Fallback MAC `[0x02, 0, 0, 0, 0, 1]`** when `if_mac` fails. This is a locally-administered, unicast MAC which is correct, but it means all clients without a readable MAC will share the same MAC, causing lease conflicts. | LOW |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/fw.rs`

### 1. Unimplemented Stubs / TODOs

| Line | Issue | Severity |
|------|-------|----------|
| **90-94** | **`fw flush` is explicitly not implemented.** Prints a warning and continues to reprogram. A true flush should send `NFT_MSG_DELTABLE`. | MEDIUM |
| **89-111** | **No port forwarding / DNAT rules.** The firewall only supports NAT masquerade and stateful forwarding. There is no way to configure port forwarding (e.g., forward port 80 on WAN to an internal server). | HIGH |
| **89-111** | **No custom firewall rules.** The ruleset is entirely hardcoded. Users cannot add their own filtering rules, port blocks, or traffic shaping. | HIGH |
| **89-111** | **No IPv6 support.** The entire firewall is IPv4-only (NFPROTO_INET is used but the rules only handle IPv4 concepts). | MEDIUM |

### 2. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **114-117** | **`enable_forwarding` writes to `/proc/sys/net/ipv4/ip_forward`** but discards the result (`let _ =`). If this write fails (permission denied, read-only filesystem), IP forwarding is silently not enabled, and the router will not route traffic. No error is reported. | HIGH |
| **116** | **Reverse path filtering is enabled** (`rp_filter = 1`) which is good, but the write result is also discarded. | LOW |
| **175-183** | **Forward chain policy is DROP** which is correct, but there is no INPUT chain. The router itself is unprotected from inbound connections on the WAN interface. Any service listening on the router (e.g., httpd) is accessible from the WAN if the WAN has a public IP. | HIGH |

### 3. Missing Error Handling

| Line | Issue | Severity |
|------|-------|----------|
| **115** | **`fs::write` to `/proc/sys/net/ipv4/ip_forward` result is discarded.** | HIGH |
| **116** | **`fs::write` to `/proc/sys/net/ipv4/conf/all/rp_filter` result is discarded.** | MEDIUM |
| **253-265** | **ACK draining loop runs only 8 times.** If the kernel sends more than 8 responses (unlikely but possible with complex rulesets), remaining ACKs are not drained, potentially leaving the netlink socket in a bad state. | LOW |

### 4. Hardcoded Values

| Line | Issue | Severity |
|------|-------|----------|
| **87** | **Table name `"c54"` is hardcoded.** Cannot be configured. | LOW |
| **180-182** | **Forward chain hook priority `0`** is hardcoded. | LOW |
| **189-191** | **Postrouting chain hook priority `100`** is hardcoded. | LOW |
| **194-218** | **The entire ruleset structure is hardcoded.** No flexibility for users to add rules. | HIGH |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/init.rs`

### 1. Missing Functionality

| Line | Issue | Severity |
|------|-------|----------|
| **18-22** | **Only 3 services are supervised:** dhcp, dns, httpd. WireGuard runs as a one-shot at boot. There is no mechanism to add new services or supervise additional processes. | MEDIUM |
| **113-143** | **No rate limiting on respawns.** If a service crashes in a loop, the supervisor will respawn it无限次, consuming CPU and filling logs. A proper init should have a respawn limit (e.g., max 5 restarts per minute). | HIGH |
| **42-59** | **No unmount on shutdown.** The supervisor sends SIGTERM and reboots, but never unmounts filesystems. This could lead to data corruption on flash storage. | MEDIUM |
| **24** | **`run` ignores `_args`.** The init applet does not accept any command-line arguments (e.g., for single-user mode, kernel command line parsing). | LOW |

### 2. Missing Error Handling

| Line | Issue | Severity |
|------|-------|----------|
| **52** | **`sys::mkdir` result is discarded** (`let _ = sys::mkdir(tgt, 0o755)`). If mkdir fails for a reason other than EEXIST, mount will then fail with a confusing "mount point does not exist" error. | LOW |
| **63** | **`net::up("lo")` result is discarded** (`let _ = net::up("lo")`). If the loopback interface cannot be brought up, no error is reported. | LOW |
| **87** | **`net::configure` result for WAN static is discarded** (`let _ = net::configure(...)`). | LOW |
| **92** | **`net::default_route` result for WAN static gateway is discarded** (`let _ = net::default_route(...)`). | LOW |
| **106** | **`waitpid` return value is not checked.** The status code of oneshot children is not inspected. | LOW |
| **141-142** | **`libc::kill(-1, SIGTERM)` sends SIGTERM to all processes** including init itself (PID 1). Since init is running `supervise()` at this point, it could receive SIGTERM and the handler would set `STOP = true`, causing a clean exit. However, the subsequent `reboot()` call might race with the signal handler. | MEDIUM |

### 3. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **158-173** | **`exec_self` uses `CString::new(...).unwrap()`** which will panic if any argument contains a NUL byte. A malicious or buggy caller could cause PID 1 to panic and reboot the system. | MEDIUM |
| **29** | **Config is loaded once at boot and never reloaded.** Live config changes from the web UI require a full reboot. This is by design but means any config error requires a reboot to fix (or a serial console). | LOW |

### 4. Hardcoded Values

| Line | Issue | Severity |
|------|-------|----------|
| **18-22** | **Service list is hardcoded** at compile time. Cannot add/remove services without recompilation. | MEDIUM |
| **44-50** | **Mount table is hardcoded.** No `/dev/pts`, no `/proc/bus`, no `/sys/fs/cgroup`, etc. | LOW |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/config.rs`

### 1. Missing Functionality

| Line | Issue | Severity |
|------|-------|----------|
| **17-38** | **INI parser is extremely minimal.** Does not support: quoted values, multi-line values, variable interpolation, include directives, or config validation. | LOW |
| **21** | **Comment handling splits on `#` only.** Values containing `#` are truncated. For example, `key = value#notcomment` would be parsed as `key = value`. This is a common INI limitation. | LOW |
| **40-45** | **Config load failure silently uses defaults.** If the config file is missing or unreadable, the error is completely swallowed. No log message, no warning. The router boots with defaults which may not match what the user expects. | MEDIUM |
| **30-35** | **Duplicate keys within a section are silently overwritten.** The last `key = value` wins. No warning for duplicates. | LOW |

### 2. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **8** | **Config path hardcoded to `/etc/c54/config`.** Cannot be overridden via environment variable or command line. | LOW |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/net.rs`

### 1. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **20-26** | **Interface name is truncated at 15 bytes** (IFNAMSIZ - 1). If a longer name is passed, it is silently truncated. No error is returned. A truncated name could accidentally configure the wrong interface. | MEDIUM |
| **35-42** | **`ioctl_ifreq` takes a fixed 32-byte buffer.** This matches the Linux `ifreq` struct size for most cases, but some ioctls (e.g., `SIOCGIFADDR`) may write more data. The 32-byte limit is correct for the ioctls used here, but there is no assertion or compile-time check. | LOW |

### 2. Missing Error Handling

| Line | Issue | Severity |
|------|-------|----------|
| **46-64** | **`configure` does not close the socket on partial failure.** If `SIOCSIFADDR` succeeds but `SIOCSIFNETMASK` fails, the socket is closed by the `?` operator via the `ioctl_ifreq` call on line 59, but `up(ifname)` on line 61 might use a different socket. Actually, looking more carefully, the `?` on line 53 and 59 will return early, and the `close(fd)` on line 62 will never be reached. **The socket leaks on error.** | HIGH |
| **67-83** | **Same socket leak issue in `up()`.** If `SIOCGIFFLAGS` succeeds but `SIOCSIFFLAGS` fails, the socket is closed by the `res` assignment on line 80, so this one is actually fine -- the `close(fd)` on line 81 runs regardless. | OK |
| **86-112** | **`default_route` closes the fd correctly** on both success and error paths. | OK |

### 3. Hardcoded Values

| Line | Issue | Severity |
|------|-------|----------|
| **9** | **`IFNAMSIZ` hardcoded to 16.** This matches Linux, but is platform-specific. | LOW |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/nl.rs`

### 1. Missing Error Handling

| Line | Issue | Severity |
|------|-------|----------|
| **113-132** | **`recv_ack` returns `Ok(())` for messages shorter than 16 bytes.** A truncated or malformed message is treated as success. | LOW |
| **135-142** | **`recv_msg` uses a fixed 8192-byte buffer.** Netlink messages larger than 8192 bytes (possible with large dumps) would be truncated. The caller has no way to know. | MEDIUM |

### 2. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **146-157** | **`for_each_attr` has no protection against infinite loops.** If `len` is 0 (which is checked: `len < 4` causes break) or if `align4(len)` returns 0 (impossible since len >= 4), this could loop forever. The check `len < 4` on line 151 prevents this. | OK |
| **68-88** | **Netlink socket has no credential checking.** Any process on the system can send netlink messages. This is standard Linux behavior but means any compromised process can manipulate firewall rules, network interfaces, etc. | LOW |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/util.rs`

### 1. Missing Error Handling

| Line | Issue | Severity |
|------|-------|----------|
| **5-32** | **`b64_decode` always returns `Some`.** The function signature says `Option<Vec<u8>>` but the only early return is `val(c)?` on line 23, which returns `None` for invalid characters. However, after the loop, it unconditionally returns `Some(out)`. This means partially decoded data is returned even after encountering invalid characters (the invalid character causes the function to return `None` immediately, which is correct). Actually, the `?` operator on line 23 will cause the function to return `None` if any character is invalid. This is correct behavior. | OK |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/sys.rs`

### 1. Security Issues

| Line | Issue | Severity |
|------|-------|----------|
| **70-73** | **`signal` handler uses `libc::signal` instead of `sigaction`.** `signal()` has undefined behavior for signal re-entrancy on some platforms. `sigaction` is the POSIX-correct way. On Linux/musl this works, but it is not portable. | LOW |
| **9-12** | **`CString::new(...).unwrap()` will panic** if any mount source, target, fstype, or data string contains a NUL byte. Since these come from the config file, a malicious config could crash PID 1. | MEDIUM |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/.cargo/config.toml`

### 1. Hardcoded Paths

| Line | Issue | Severity |
|------|-------|----------|
| **8** | **`STAGING_DIR` hardcoded to `/home/irfan/Desktop/tools/mips-xip-kernel/openwrt/staging_dir`.** This will fail on any other machine. Should be an environment variable or documented as a setup requirement. | HIGH |
| **20** | **Linker path hardcoded to `/home/irfan/Desktop/tools/mips-xip-kernel/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin/mipsel-openwrt-linux-musl-gcc`.** Same issue -- breaks on any other machine. | HIGH |
| **26** | **`-L` path hardcoded to `/home/irfan/c54-os/vendor`.** This is a different base path than the OpenWrt toolchain, and uses a non-relative path. Should be relative to the project root. | MEDIUM |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/rootfs/etc/c54/config`

### 1. Config Sections That No Code Acts On

| Section/Key | Issue | Severity |
|-------------|-------|----------|
| **`[wifi]` (lines 21-25)** | **Entirely dead config.** The `ssid`, `encryption`, `key`, and `channel` keys are parsed by the INI parser but NO code anywhere in the codebase reads or acts on them. There is no hostapd, iw, or wpa_supplicant integration. WiFi configuration is completely non-functional. This is the most significant dead config section. | HIGH |
| **`[system] hostname`** (line 4) | **Only read by `httpd.rs:110`** for display in the status JSON. Never used to actually set the system hostname (no `sethostname()` syscall, no writing to `/proc/sys/kernel/hostname`). The hostname is cosmetic only in the web UI. | MEDIUM |
| **`[wireguard] address`** | **Read by `wg.rs:78-83`** but the CIDR mask is discarded and hardcoded to /24. | MEDIUM |
| **`[wireguard] private_key`** (line 35) | **Shipped as empty string in the default config.** If a user enables WireGuard without setting a key, the error message is generic ("missing/invalid private_key"). | LOW |
| **`[firewall] masq`** | **Only two values recognized: "1" (enable) and anything else (disable).** No granular control. | LOW |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/scripts/mkrootfs.sh`

### 1. Missing Functionality / Incomplete

| Line | Issue | Severity |
|------|-------|----------|
| **28-29** | **Device nodes are created with `2>/dev/null || true`.** If `mknod` fails (e.g., not running as root), the rootfs has no console or null device. The kernel will still boot if using devtmpfs, but the brief window before devtmpfs mounts will have no devices. | LOW |
| **32** | **`cpio` output is piped through `gzip -9`** with stderr redirected to `/dev/null`. If `cpio` or `gzip` fail, the error is hidden and a zero-byte or truncated initramfs is produced. The build will "succeed" silently. | MEDIUM |
| **1** | **Script uses `#!/bin/sh`** but does not check for required tools (cpio, gzip, mknod, install). | LOW |
| **19** | **Config is copied from source tree, not the build directory.** If the user has modified `build/rootfs/etc/c54/config` (via the web UI), running `mkrootfs.sh` will overwrite it with the source tree version. This is correct behavior (rebuild from source) but could surprise users. | LOW |

---

## FILE: `/home/irfan/Desktop/tools/c54-os/src/main.rs`

### 1. Missing Functionality

| Line | Issue | Severity |
|------|-------|----------|
| **62-66** | **Unknown applet prints usage and returns 1.** No support for applet aliases (e.g., `ifconfig` -> `ifup`, `iptables` -> `fw`). | LOW |
| **88-117** | **`ifup` applet is defined in `main.rs`** rather than its own module. This breaks the pattern of one module per applet and makes the code harder to navigate. | LOW |

---

## CROSS-CUTTING ISSUES (Architecture-wide)

| Issue | Severity |
|-------|----------|
| **No logging framework.** All output goes to stdout/stderr via `println!`/`eprintln!`. No log levels, no timestamps, no log rotation, no remote syslog. Debugging a production router is extremely difficult. | HIGH |
| **No graceful degradation.** If any subsystem fails (e.g., netlink for firewall), the router continues running but may be in an insecure state (no firewall rules, no NAT). There is no health monitoring or alerting. | HIGH |
| **No configuration validation.** The config parser accepts any key/value pair without validation. Malformed IPs, negative numbers, out-of-range values, etc. are only caught at the point of use, if at all. | MEDIUM |
| **No IPv6 support anywhere.** The entire codebase is IPv4-only. Modern router OSes must support IPv6 (DHCPv6, NDP, NAT66, etc.). | HIGH |
| **No NTP / time synchronization.** The system clock is whatever the hardware provides. On an embedded device without RTC, time starts at epoch (1970) and is never corrected. This affects: WireGuard handshake timestamps, DHCP lease expiry, certificate validation (if HTTPS were added), log timestamps. | HIGH |
| **No syslog or persistent logging.** All logs go to stdout/stderr which is lost on reboot (no `/var/log`). Debugging boot issues requires a serial console. | MEDIUM |
| **No watchdog.** If the init supervisor hangs, there is no hardware watchdog to reboot the device. The router becomes a brick until manual intervention. | MEDIUM |
| **No package integrity.** The `ipkg` package manager has no checksum or signature verification. Packages can be tampered with in transit (HTTP-only) or on disk. | HIGH |
| **Single-threaded HTTP server.** A slow or malicious client can block all admin access indefinitely. | MEDIUM |
| **No HTTPS anywhere.** The web UI and package downloads are all plaintext HTTP. Config changes (including WireGuard private keys) are transmitted in the clear on the LAN. | HIGH |
| **No authentication on the web UI.** Anyone on the LAN can view/modify config and reboot the router. | CRITICAL |

---

## SUMMARY BY SEVERITY

### CRITICAL (3)
1. **`httpd.rs:67-91`** -- No authentication on web UI; anyone on LAN can read/write config including WireGuard private keys.
2. **`httpd.rs:149-203`** -- XSS in embedded HTML/JS via unsanitized lease data injection into innerHTML.
3. **`ipkg.rs:166-204`** -- Path traversal risk in ustar extraction; packages can overwrite any file on the system.

### HIGH (14)
1. **`wg.rs:44-47`** -- `wg down` is a no-op stub.
2. **`ipkg.rs:116-160`** -- HTTP only, no HTTPS for package downloads.
3. **`ipkg.rs:47-58`** -- No checksum/signature verification on packages.
4. **`dhcp.rs:1-488`** -- No DHCP lease expiry mechanism.
5. **`fw.rs:89-111`** -- No port forwarding / DNAT rules; no INPUT chain for router protection.
6. **`fw.rs:114-117`** -- IP forwarding enable result silently discarded.
7. **`init.rs:113-143`** -- No respawn rate limiting; crash loops consume resources.
8. **`net.rs:46-64`** -- Socket file descriptor leak on partial failure in `configure()`.
9. **`.cargo/config.toml:8,20`** -- Hardcoded absolute paths to developer-specific toolchain.
10. **No logging framework** -- impossible to debug production issues.
11. **No IPv6 support** -- modern routers require it.
12. **No NTP/time sync** -- affects WireGuard, DHCP leases, certificates.
13. **No package integrity** -- HTTP + no checksums = trivial MITM.
14. **No web UI authentication** -- listed above as CRITICAL but also architectural.

### MEDIUM (22)
1. **`wg.rs:57`** -- Hardcoded WireGuard interface name.
2. **`wg.rs:77-83`** -- WireGuard CIDR mask discarded, hardcoded to /24.
3. **`wg.rs:58-61`** -- `ensure_link` failure swallowed.
4. **`ipkg.rs:200`** -- Symlinks/special files silently ignored.
5. **`ipkg.rs:18-45`** -- No `upgrade` subcommand.
6. **`ipkg.rs:97-113`** -- No reference counting for shared files.
7. **`httpd.rs:84-88`** -- No CSRF protection on reboot endpoint.
8. **`httpd.rs:15`** -- HTTP only, no HTTPS.
9. **`httpd.rs:24-29`** -- Single-threaded, serial request handling.
10. **`dns.rs:47`** -- Cache TTL hardcoded to 60s.
11. **`dns.rs:25-63`** -- No cache eviction (unbounded memory growth).
12. **`dns.rs:66-71`** -- Single upstream DNS server, no fallback.
13. **`dhcp.rs:196`** -- `unwrap()` on system time panics before UNIX epoch.
14. **`dhcp.rs:256,340`** -- 1024-byte receive buffers too small for full DHCP packets.
15. **`dhcp.rs:156-214`** -- No lease persistence across server restarts.
16. **`dhcp.rs:230`** -- Server continues if device bind fails (security risk).
17. **`fw.rs:90-94`** -- `fw flush` not implemented.
18. **`init.rs:113-143`** -- No service respawn rate limiting.
19. **`init.rs:158-173`** -- `CString::new().unwrap()` panics on NUL bytes in PID 1.
20. **`config.rs:40-45`** -- Config load failure silently uses defaults.
21. **`net.rs:20-26`** -- Interface name silently truncated.
22. **`nl.rs:135-142`** -- Fixed 8192-byte netlink receive buffer.
23. **`scripts/mkrootfs.sh:32`** -- cpio/gzip errors suppressed.
24. **`sys.rs:9-12`** -- `CString::new().unwrap()` panics on NUL in mount args.
25. **`[wifi]` config section** -- completely dead, no code acts on it.
26. **`[system] hostname`** -- cosmetic only, never set on the system.

### LOW (30+)
Multiple instances of: discarded `let _ =` error returns, hardcoded ports/values, missing edge case handling, non-portable signal handling, fragile HTTP parsing, no log levels, no config validation, missing i18n, hardcoded English strings, and more as detailed in the per-file sections above.
