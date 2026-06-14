//! The admin web UI — a lightweight, clean-room take on LuCI's UX (not its
//! code). A small thread-per-connection HTTP/1.0 server renders server-side
//! HTML *fragments*; a tiny embedded HTMX-compatible shim swaps them into the
//! page on click/submit/load. Three sections: Status, Clients, Settings.
//!
//! Hypermedia, not a JSON SPA: every endpoint returns ready-to-display HTML, so
//! there is no client-side templating and nothing to keep in sync. The whole
//! thing is baked into the binary — no asset files, no framework, no tokio.
//!
//! Settings are edited through a friendly form, never a raw config blob. Secret
//! fields (Wi-Fi key) are left blank meaning "keep current", so they never
//! leave the device. All dynamic text is HTML-escaped server-side (stored-XSS
//! guard against e.g. a hostile DHCP hostname).
//!
//! Security (plain HTTP on the LAN, no TLS in a static musl binary): if an admin
//! password is configured, every UI/data endpoint needs a session cookie from
//! the login form, and state-changing POSTs need a matching X-CSRF-Token.

use crate::config::{self, Config};
use crate::sha256;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SESSION_TTL: Duration = Duration::from_secs(3600);

/// Config keys whose values must never leave the device in cleartext.
const SECRET_KEYS: &[&str] = &["key", "password", "password_sha256", "private_key", "psk"];

/// In-memory session store: token -> issue time, shared across conn threads.
#[derive(Default)]
struct Sessions {
    tokens: HashMap<String, Instant>,
}

impl Sessions {
    fn gc(&mut self) {
        let now = Instant::now();
        self.tokens
            .retain(|_, t| now.duration_since(*t) < SESSION_TTL);
    }
    fn insert(&mut self, token: String) {
        self.gc();
        self.tokens.insert(token, Instant::now());
    }
    fn valid(&self, token: &str) -> bool {
        match self.tokens.get(token) {
            Some(t) => Instant::now().duration_since(*t) < SESSION_TTL,
            None => false,
        }
    }
}

pub fn run(_args: &[String]) -> i32 {
    let cfg = Config::load();
    let lan_ip = cfg.get_or("lan", "ipaddr", "192.168.1.1");
    // Default to the LAN address on :80; `LWRT_HTTPD_BIND` overrides it, which
    // keeps the board default while letting tests/dev bind a loopback port.
    let bind = std::env::var("LWRT_HTTPD_BIND").unwrap_or_else(|_| format!("{lan_ip}:80"));
    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("httpd: bind {bind}: {e}");
            return 1;
        }
    };
    println!("httpd: admin UI on http://{bind}/");
    let sessions = Arc::new(Mutex::new(Sessions::default()));
    for conn in listener.incoming() {
        if let Ok(stream) = conn {
            let s = sessions.clone();
            std::thread::spawn(move || {
                let _ = handle(stream, &s);
            });
        }
    }
    0
}

/// Parsed view of the request line + the headers we care about.
struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
    cookie_token: Option<String>,
    csrf: Option<String>,
}

/// Pull `session=<token>` out of a Cookie header value.
fn cookie_token(value: &str) -> Option<String> {
    value
        .split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix("session=").map(|t| t.to_string()))
}

fn read_request(reader: &mut impl BufRead) -> std::io::Result<Request> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut clen = 0usize;
    let mut cookie = None;
    let mut csrf = None;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        let lower = h.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            clen = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = lower.strip_prefix("cookie:") {
            cookie = cookie_token(v.trim());
        } else if lower.starts_with("x-csrf-token:") {
            csrf = h["x-csrf-token:".len()..].trim().to_string().into();
        }
    }
    clen = clen.min(256 * 1024); // cap body so a hostile length can't OOM us
    let mut body = vec![0u8; clen];
    if clen > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok(Request {
        method,
        path,
        body,
        cookie_token: cookie,
        csrf,
    })
}

fn handle(mut stream: TcpStream, sessions: &Mutex<Sessions>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let req = read_request(&mut reader)?;
    let cfg = Config::load();

    let (status, ctype, payload, set_cookie) = route(&req, &cfg, sessions);
    let cookie_hdr = match set_cookie {
        Some(tok) => format!("Set-Cookie: session={tok}; HttpOnly; SameSite=Strict; Path=/\r\n"),
        None => String::new(),
    };
    let head = format!(
        "HTTP/1.0 {status}\r\nContent-Type: {ctype}\r\n{cookie_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&payload)?;
    Ok(())
}

// ---- auth -------------------------------------------------------------------

fn auth_required(cfg: &Config) -> bool {
    cfg.get("admin", "password").is_some() || cfg.get("admin", "password_sha256").is_some()
}

fn verify_password(cfg: &Config, supplied: &str) -> bool {
    if let Some(h) = cfg.get("admin", "password_sha256") {
        return sha256::hex(&sha256::digest(supplied.as_bytes())).eq_ignore_ascii_case(h.trim());
    }
    if let Some(p) = cfg.get("admin", "password") {
        return p == supplied;
    }
    false
}

fn is_authed(req: &Request, cfg: &Config, sessions: &Mutex<Sessions>) -> bool {
    if !auth_required(cfg) {
        return true; // open mode
    }
    match &req.cookie_token {
        Some(tok) => sessions.lock().unwrap().valid(tok),
        None => false,
    }
}

/// State-changing requests need cookie and X-CSRF-Token to match (skipped in
/// open mode, where there is no session to bind to).
fn csrf_ok(req: &Request, cfg: &Config) -> bool {
    if !auth_required(cfg) {
        return true;
    }
    match (&req.cookie_token, &req.csrf) {
        (Some(c), Some(h)) => c == h,
        _ => false,
    }
}

fn new_token() -> String {
    let mut buf = [0u8; 16];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    sha256::hex(&buf)
}

// ---- routing ----------------------------------------------------------------

type Resp = (&'static str, &'static str, Vec<u8>, Option<String>);

const HTML: &str = "text/html; charset=utf-8";

fn html(status: &'static str, body: String) -> Resp {
    (status, HTML, body.into_bytes(), None)
}

fn route(req: &Request, cfg: &Config, sessions: &Mutex<Sessions>) -> Resp {
    let m = req.method.as_str();
    let p = req.path.as_str();
    let host = cfg.get_or("system", "hostname", "lwrt").to_string();

    // Public: the page shell and the login handler.
    if m == "GET" && p == "/" {
        if auth_required(cfg) && !is_authed(req, cfg, sessions) {
            return html("200 OK", full_page(login_inner(None)));
        }
        let csrf = if auth_required(cfg) {
            req.cookie_token.as_deref()
        } else {
            None
        };
        return html("200 OK", full_page(shell_inner(csrf, &host)));
    }
    if m == "POST" && p == "/ui/login" {
        return login(req, cfg, sessions, &host);
    }

    // Everything below needs a valid session when auth is configured.
    if !is_authed(req, cfg, sessions) {
        return html("401 Unauthorized", login_inner(Some("Session expired — sign in again")));
    }

    match (m, p) {
        ("GET", "/ui/status") => html("200 OK", frag_status()),
        ("GET", "/ui/clients") => html("200 OK", frag_clients()),
        ("GET", "/ui/settings") => html("200 OK", frag_settings()),
        ("POST", "/ui/settings") => {
            if !csrf_ok(req, cfg) {
                return html("403 Forbidden", note("Session check failed — reload the page.", true));
            }
            save_settings(&req.body)
        }
        ("POST", "/ui/reboot") => {
            if !csrf_ok(req, cfg) {
                return html("403 Forbidden", note("Session check failed — reload the page.", true));
            }
            unsafe { libc::kill(1, libc::SIGTERM) };
            html("200 OK", note("Rebooting… this page will stop responding for a moment.", false))
        }
        _ => ("404 Not Found", "text/plain", b"not found".to_vec(), None),
    }
}

/// `POST /ui/login` with a urlencoded `password` field. Returns the app shell on
/// success (HTMX swaps it into #root) or the login form with an error.
fn login(req: &Request, cfg: &Config, sessions: &Mutex<Sessions>, host: &str) -> Resp {
    let form = parse_form(&req.body);
    let supplied = field(&form, "password").unwrap_or_default();
    if !auth_required(cfg) || verify_password(cfg, &supplied) {
        let token = new_token();
        sessions.lock().unwrap().insert(token.clone());
        // CSRF token == session token; the shim echoes it in X-CSRF-Token.
        return (
            "200 OK",
            HTML,
            shell_inner(Some(&token), host).into_bytes(),
            Some(token),
        );
    }
    html("401 Unauthorized", login_inner(Some("Wrong password")))
}

// ---- settings persistence ---------------------------------------------------

/// Apply the settings form to the stored config, preserving comments, ordering
/// and any keys the form does not manage (e.g. wireguard, firewall forwards).
fn save_settings(body: &[u8]) -> Resp {
    let form = parse_form(body);
    let mut updates: Vec<(String, String, String)> = Vec::new();
    let mut put = |section: &str, key: &str, name: &str| {
        if let Some(v) = field(&form, name) {
            updates.push((section.to_string(), key.to_string(), v));
        }
    };
    put("system", "hostname", "hostname");
    put("lan", "ipaddr", "lan_ipaddr");
    put("wifi", "ssid", "wifi_ssid");
    put("wifi", "key", "wifi_key"); // blank => kept (secret rule below)
    put("wan", "proto", "wan_proto");
    // Checkbox: present means enabled.
    let dhcp = if form.iter().any(|(k, _)| k == "dhcp_enabled") {
        "1"
    } else {
        "0"
    };
    updates.push(("dhcp".into(), "enabled".into(), dhcp.into()));

    let old = fs::read_to_string(config::PATH).unwrap_or_else(|_| config::DEFAULT.to_string());
    let merged = apply_settings(&old, updates);
    let _ = fs::create_dir_all("/etc/lwrt");
    match fs::write(config::PATH, merged) {
        Ok(()) => html(
            "200 OK",
            note("Saved. Reboot to apply network changes.", false),
        ),
        Err(_) => html("500 Error", note("Could not write config.", true)),
    }
}

/// True if `key` (trimmed) names a secret value.
fn is_secret_key(key: &str) -> bool {
    SECRET_KEYS.contains(&key)
}

/// Split a `key = value` line (ignoring comments/blank/section lines).
fn split_kv(raw: &str) -> Option<(&str, &str)> {
    let line = raw.split('#').next().unwrap_or("").trim();
    if line.is_empty() || line.starts_with('[') {
        return None;
    }
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim()))
}

/// Emit (and drain) any pending updates that belong to `section`.
fn flush_section(out: &mut String, section: &str, updates: &mut Vec<(String, String, String)>) {
    let mut i = 0;
    while i < updates.len() {
        if updates[i].0 == section {
            let (_, k, v) = updates.remove(i);
            out.push_str(&format!("{k} = {v}\n"));
        } else {
            i += 1;
        }
    }
}

/// Line-preserving config update. Replaces values for `(section, key)` pairs in
/// place, appends ones whose section exists but key doesn't, and creates whole
/// sections at the end if needed. Empty secret values are dropped (= keep old).
fn apply_settings(old: &str, mut updates: Vec<(String, String, String)>) -> String {
    updates.retain(|(_, k, v)| !(is_secret_key(k) && v.trim().is_empty()));

    let mut out = String::with_capacity(old.len() + 64);
    let mut section = String::new();
    for raw in old.lines() {
        let trimmed = raw.trim();
        if let Some(name) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // Leaving a section: append any of its keys that weren't present.
            flush_section(&mut out, &section, &mut updates);
            section = name.trim().to_string();
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        if let Some((k, _)) = split_kv(raw) {
            if let Some(pos) = updates.iter().position(|(s, uk, _)| *s == section && uk == k) {
                let (_, _, v) = updates.remove(pos);
                let indent = &raw[..raw.len() - raw.trim_start().len()];
                out.push_str(&format!("{indent}{k} = {v}\n"));
                continue;
            }
        }
        out.push_str(raw);
        out.push('\n');
    }
    flush_section(&mut out, &section, &mut updates);

    // Updates for sections that never appeared: create them.
    let mut seen: Vec<String> = Vec::new();
    for (s, _, _) in &updates {
        if !seen.contains(s) {
            seen.push(s.clone());
        }
    }
    for s in seen {
        out.push_str(&format!("\n[{s}]\n"));
        flush_section(&mut out, &s, &mut updates);
    }
    out
}

// ---- form / escaping helpers ------------------------------------------------

fn field(form: &[(String, String)], name: &str) -> Option<String> {
    form.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
}

fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((urldecode(k), urldecode(v)))
        })
        .collect()
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => match (hexval(b[i + 1]), hexval(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// HTML-escape untrusted text before it enters a fragment (stored-XSS guard).
fn hesc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

fn fmt_uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else {
        format!("{h}h {m}m")
    }
}

// ---- fragments --------------------------------------------------------------

fn row(k: &str, v: &str) -> String {
    format!("<div class=row><span class=k>{}</span><span>{}</span></div>", hesc(k), hesc(v))
}

fn frag_status() -> String {
    let cfg = Config::load();
    let host = cfg.get_or("system", "hostname", "lwrt");
    let lan = cfg.get_or("lan", "ipaddr", "192.168.1.1");
    let uptime = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split('.').next().and_then(|n| n.parse::<u64>().ok()))
        .unwrap_or(0);
    let dns = fs::read_to_string("/run/wan.dns").unwrap_or_default();
    let clients = fs::read_to_string("/run/dhcp.leases")
        .map(|t| t.lines().count())
        .unwrap_or(0);
    let wg = cfg.get_or("wireguard", "enabled", "0") == "1";
    format!(
        "<div class=card>{}{}{}{}{}{}</div>\
         <div class=card><button class=act hx-post=/ui/reboot hx-target=#content \
         hx-confirm=\"Reboot the router?\">Reboot router</button></div>",
        row("Hostname", host),
        row("LAN address", lan),
        row("Uptime", &fmt_uptime(uptime)),
        row("DHCP clients", &clients.to_string()),
        row("Upstream DNS", if dns.trim().is_empty() { "—" } else { dns.trim() }),
        row("WireGuard VPN", if wg { "enabled" } else { "off" }),
    )
}

fn frag_clients() -> String {
    let text = fs::read_to_string("/run/dhcp.leases").unwrap_or_default();
    let mut rows = String::from("<tr><th>Name<th>IP<th>MAC</tr>");
    let mut n = 0;
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 4 {
            n += 1;
            rows.push_str(&format!(
                "<tr><td>{}<td>{}<td>{}</tr>",
                hesc(f[3]),
                hesc(f[2]),
                hesc(f[1])
            ));
        }
    }
    if n == 0 {
        return "<div class=card><p class=k>No active DHCP leases.</p></div>".into();
    }
    format!("<div class=card><table>{rows}</table></div>")
}

fn opt(value: &str, current: &str, label: &str) -> String {
    let sel = if value == current { " selected" } else { "" };
    format!("<option value={value}{sel}>{label}</option>")
}

fn frag_settings() -> String {
    let cfg = Config::load();
    let host = hesc(cfg.get_or("system", "hostname", "lwrt"));
    let lan = hesc(cfg.get_or("lan", "ipaddr", "192.168.1.1"));
    let ssid = hesc(cfg.get_or("wifi", "ssid", "LWRT"));
    let proto = cfg.get_or("wan", "proto", "dhcp");
    let dhcp_on = cfg.get_or("dhcp", "enabled", "1") == "1";
    let checked = if dhcp_on { " checked" } else { "" };
    format!(
        "<div class=card><form hx-post=/ui/settings hx-target=#content>\
         <label>Hostname<input name=hostname value=\"{host}\"></label>\
         <label>LAN IP address<input name=lan_ipaddr value=\"{lan}\"></label>\
         <label>Wi-Fi network name (SSID)<input name=wifi_ssid value=\"{ssid}\"></label>\
         <label>Wi-Fi password<input name=wifi_key type=password placeholder=\"leave blank to keep current\"></label>\
         <label>WAN protocol<select name=wan_proto>{}{}{}</select></label>\
         <label class=chk><input type=checkbox name=dhcp_enabled{checked}> Run DHCP server on LAN</label>\
         <p><button class=act type=submit>Save</button></p>\
         </form></div>",
        opt("dhcp", proto, "DHCP (automatic)"),
        opt("static", proto, "Static IP"),
        opt("pppoe", proto, "PPPoE"),
    )
}

/// A small inline result/notice fragment.
fn note(msg: &str, err: bool) -> String {
    let cls = if err { "note err" } else { "note ok" };
    format!("<div class=card><p class={cls}>{}</p></div>", hesc(msg))
}

// ---- page shell -------------------------------------------------------------

fn shell_inner(csrf: Option<&str>, host: &str) -> String {
    let meta = csrf
        .map(|t| format!("<meta name=csrf content=\"{}\">", hesc(t)))
        .unwrap_or_default();
    format!(
        "{meta}\
         <header><span class=dot></span><b>LWRT</b><span>{}</span></header>\
         <nav>\
         <button class=on hx-get=/ui/status hx-target=#content>Status</button>\
         <button hx-get=/ui/clients hx-target=#content>Clients</button>\
         <button hx-get=/ui/settings hx-target=#content>Settings</button>\
         </nav>\
         <main><div id=content hx-get=/ui/status hx-trigger=load>loading…</div></main>",
        hesc(host)
    )
}

fn login_inner(err: Option<&str>) -> String {
    let msg = err
        .map(|e| format!("<p class=err>{}</p>", hesc(e)))
        .unwrap_or_default();
    format!(
        "<header><span class=dot></span><b>LWRT</b></header>\
         <main><div class=card><h3>Sign in</h3>\
         <p class=k>Enter the admin password.</p>\
         <form hx-post=/ui/login hx-target=#root>\
         <input name=password type=password placeholder=Password autofocus>\
         <p><button class=act type=submit>Log in</button></p>{msg}\
         </form></div></main>"
    )
}

fn full_page(root_inner: String) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
         <meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>LWRT</title><style>{CSS}</style></head>\
         <body><div id=root>{root_inner}</div><script>{SHIM}</script></body></html>"
    )
}

const CSS: &str = "\
:root{--bg:#0f1419;--card:#1a212b;--fg:#e6edf3;--mut:#7d8590;--acc:#2f81f7;--ok:#3fb950;--err:#f85149}\
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}\
header{background:var(--card);padding:14px 20px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #30363d}\
header b{font-size:18px}header span{color:var(--mut)}\
nav{display:flex;gap:4px;padding:10px 20px;flex-wrap:wrap;background:var(--card);border-bottom:1px solid #30363d}\
nav button{background:none;border:1px solid #30363d;color:var(--fg);padding:6px 14px;border-radius:6px;cursor:pointer}\
nav button.on{background:var(--acc);border-color:var(--acc);color:#fff}\
main{padding:20px;max-width:760px;margin:0 auto}\
.card{background:var(--card);border:1px solid #30363d;border-radius:10px;padding:18px;margin-bottom:16px}\
.row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #21262d}\
.row:last-child{border:0}.k{color:var(--mut)}\
label{display:block;margin:12px 0;color:var(--mut)}label.chk{display:flex;align-items:center;gap:8px;color:var(--fg)}\
input,select{width:100%;background:#0d1117;color:var(--fg);border:1px solid #30363d;border-radius:8px;padding:9px;font:14px system-ui;margin-top:4px}\
input[type=checkbox]{width:auto;margin:0}\
button.act{background:var(--acc);border:0;color:#fff;padding:9px 18px;border-radius:6px;cursor:pointer;font-size:14px}\
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px;border-bottom:1px solid #21262d}\
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);display:inline-block;margin-right:6px}\
.note{margin:0}.ok{color:var(--ok)}.err{color:var(--err)}h3{margin-top:0}";

// Minimal HTMX-compatible shim (clean-room): supports hx-get/hx-post,
// hx-target, hx-trigger (load|click|submit), hx-confirm, and form serialisation.
// Sends the CSRF token from <meta name=csrf> on POSTs. ~30 lines, no deps.
const SHIM: &str = r#"(function(){
function tgt(el){var t=el.getAttribute('hx-target');return t?document.querySelector(t):el;}
function proc(root){root.querySelectorAll('[hx-get],[hx-post]').forEach(function(el){
if(el._hx)return;el._hx=1;
var verb=el.hasAttribute('hx-post')?'POST':'GET';
var url=el.getAttribute('hx-'+verb.toLowerCase());
var trig=el.getAttribute('hx-trigger')||(el.tagName==='FORM'?'submit':'click');
if(trig==='load'){req(el,verb,url);return;}
if(el.tagName==='FORM'){el.addEventListener('submit',function(e){e.preventDefault();
req(el,'POST',url,new URLSearchParams(new FormData(el)).toString());});return;}
el.addEventListener(trig,function(e){e.preventDefault();
if(el.parentElement&&el.parentElement.tagName==='NAV'){
Array.prototype.forEach.call(el.parentElement.children,function(c){c.classList.remove('on');});
el.classList.add('on');}
req(el,verb,url);});});}
function req(el,verb,url,body){
var c=el.getAttribute('hx-confirm');if(c&&!confirm(c))return;
var o={method:verb,headers:{}};
var m=document.querySelector('meta[name=csrf]');
if(verb==='POST'&&m)o.headers['X-CSRF-Token']=m.content;
if(body){o.body=body;o.headers['Content-Type']='application/x-www-form-urlencoded';}
fetch(url,o).then(function(r){return r.text();}).then(function(h){var t=tgt(el);t.innerHTML=h;proc(t);});}
window.addEventListener('DOMContentLoaded',function(){proc(document);});
})();"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(text: &str) -> Config {
        Config::parse(text)
    }

    #[test]
    fn cookie_token_extracts_session() {
        assert_eq!(
            cookie_token("foo=1; session=abc123; bar=2"),
            Some("abc123".to_string())
        );
        assert_eq!(cookie_token("nothing=here"), None);
    }

    #[test]
    fn auth_required_only_when_password_set() {
        assert!(!auth_required(&cfg("[lan]\nipaddr = 1.1.1.1\n")));
        assert!(auth_required(&cfg("[admin]\npassword = hunter2\n")));
        assert!(auth_required(&cfg("[admin]\npassword_sha256 = deadbeef\n")));
    }

    #[test]
    fn verify_password_plaintext_and_hash() {
        let c = cfg("[admin]\npassword = hunter2\n");
        assert!(verify_password(&c, "hunter2"));
        assert!(!verify_password(&c, "nope"));
        let h = sha256::hex(&sha256::digest(b"hunter2"));
        let c2 = cfg(&format!("[admin]\npassword_sha256 = {h}\n"));
        assert!(verify_password(&c2, "hunter2"));
        assert!(!verify_password(&c2, "Hunter2"));
    }

    #[test]
    fn sessions_validate_membership() {
        let mut s = Sessions::default();
        s.insert("tok".into());
        assert!(s.valid("tok"));
        assert!(!s.valid("other"));
    }

    #[test]
    fn csrf_requires_matching_cookie_and_header_when_locked() {
        let locked = cfg("[admin]\npassword = x\n");
        let open = cfg("[lan]\nx = 1\n");
        let mk = |c: Option<&str>, h: Option<&str>| Request {
            method: "POST".into(),
            path: "/ui/reboot".into(),
            body: vec![],
            cookie_token: c.map(str::to_string),
            csrf: h.map(str::to_string),
        };
        assert!(csrf_ok(&mk(Some("t"), Some("t")), &locked));
        assert!(!csrf_ok(&mk(Some("t"), Some("u")), &locked));
        assert!(!csrf_ok(&mk(Some("t"), None), &locked));
        assert!(csrf_ok(&mk(None, None), &open));
    }

    #[test]
    fn urldecode_handles_plus_and_percent() {
        assert_eq!(urldecode("a+b%20c"), "a b c");
        assert_eq!(urldecode("%2Fetc%2Flwrt"), "/etc/lwrt");
        assert_eq!(urldecode("plain"), "plain");
        assert_eq!(urldecode("bad%2"), "bad%2"); // truncated escape left as-is
    }

    #[test]
    fn parse_form_splits_pairs() {
        let f = parse_form(b"hostname=router1&wan_proto=pppoe&wifi_key=");
        assert_eq!(field(&f, "hostname").as_deref(), Some("router1"));
        assert_eq!(field(&f, "wan_proto").as_deref(), Some("pppoe"));
        assert_eq!(field(&f, "wifi_key").as_deref(), Some(""));
        assert_eq!(field(&f, "missing"), None);
    }

    #[test]
    fn hesc_blocks_script_injection() {
        assert_eq!(hesc("<script>x</script>"), "&lt;script&gt;x&lt;/script&gt;");
        assert_eq!(hesc("a&\"b'"), "a&amp;&quot;b&#39;");
    }

    #[test]
    fn apply_settings_replaces_existing_value_in_place() {
        let old = "[system]\nhostname = old\n[lan]\nipaddr = 192.168.1.1\n";
        let upd = vec![("system".into(), "hostname".into(), "new".into())];
        let out = apply_settings(old, upd);
        assert!(out.contains("hostname = new"));
        assert!(out.contains("ipaddr = 192.168.1.1")); // untouched
        assert!(!out.contains("hostname = old"));
    }

    #[test]
    fn apply_settings_keeps_blank_secret_but_writes_new_one() {
        let old = "[wifi]\nssid = Net\nkey = realkey\n";
        // blank wifi key -> keep; new ssid -> change
        let upd = vec![
            ("wifi".into(), "ssid".into(), "NewNet".into()),
            ("wifi".into(), "key".into(), "".into()),
        ];
        let out = apply_settings(old, upd);
        assert!(out.contains("ssid = NewNet"));
        assert!(out.contains("key = realkey"));

        let upd2 = vec![("wifi".into(), "key".into(), "brandnew".into())];
        let out2 = apply_settings(old, upd2);
        assert!(out2.contains("key = brandnew"));
    }

    #[test]
    fn apply_settings_appends_missing_key_and_section() {
        // key missing in existing section
        let old = "[lan]\nipaddr = 1.1.1.1\n";
        let upd = vec![("lan".into(), "netmask".into(), "255.255.255.0".into())];
        let out = apply_settings(old, upd);
        assert!(out.contains("netmask = 255.255.255.0"));

        // whole section missing
        let upd2 = vec![("dhcp".into(), "enabled".into(), "1".into())];
        let out2 = apply_settings(old, upd2);
        assert!(out2.contains("[dhcp]"));
        assert!(out2.contains("enabled = 1"));
    }
}
