//! ubus — LWRT's micro message bus. OpenWrt's `ubusd` is a broker that other
//! daemons register objects on and that clients call methods through; LWRT
//! ships a deliberately tiny, clean-room equivalent. The wire format is *not*
//! libubox's binary blobmsg — it is one JSON object per line over a
//! `SOCK_STREAM` unix socket, which is all a monolithic userspace needs and
//! costs no extra parser (we already carry [`crate::json`]).
//!
//!   ubus               run the broker (foreground; init supervises it)
//!   ubus list [path]   list registered objects and their methods
//!   ubus call P M [J]  call method M on object P with JSON args J
//!   ubus send E [J]    broadcast event E with JSON payload J
//!   ubus listen [E..]  subscribe to events, print them as they arrive
//!
//! Protocol (each frame is one line of JSON):
//!   client→broker  {"op":"list"}
//!                  {"op":"call","path":..,"method":..,"args":{..}}
//!                  {"op":"add","path":..,"methods":[..]}   (provider registers)
//!                  {"op":"reply","id":N,"data":{..}}       (provider answers)
//!                  {"op":"send","event":..,"data":{..}}
//!                  {"op":"listen"}
//!   broker→client  {"status":0,"data":{..}} | {"status":N,"error":".."}
//!                  {"invoke":N,"method":..,"args":{..}}     (to a provider)
//!                  {"event":..,"data":{..}}                 (to a listener)

use crate::json::{self, Value};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const SOCK: &str = "/var/run/ubus.sock";

/// Objects the broker answers itself, so a fresh system has something to call.
const BUILTINS: &[(&str, &[&str])] = &[("system", &["board", "info"])];

/// Broker socket path. Defaults to [`SOCK`]; `LWRT_UBUS_SOCK` overrides it,
/// which keeps the default board-standard while letting tests use a temp path.
fn sock_path() -> String {
    std::env::var("LWRT_UBUS_SOCK").unwrap_or_else(|_| SOCK.to_string())
}

pub fn run(args: &[String]) -> i32 {
    match args.first().map(|s| s.as_str()) {
        None | Some("daemon") => daemon(),
        Some("list") => cli_list(args.get(1).map(|s| s.as_str())),
        Some("call") => match (args.get(1), args.get(2)) {
            (Some(path), Some(method)) => cli_call(path, method, args.get(3).map(|s| s.as_str())),
            _ => {
                eprintln!("ubus: call <path> <method> [json-args]");
                1
            }
        },
        Some("send") => match args.get(1) {
            Some(event) => cli_send(event, args.get(2).map(|s| s.as_str())),
            None => {
                eprintln!("ubus: send <event> [json-data]");
                1
            }
        },
        Some("listen") => cli_listen(),
        Some(other) => {
            eprintln!("ubus: unknown subcommand '{other}'");
            1
        }
    }
}

// ---- broker -----------------------------------------------------------------

/// One externally-registered object and the connection that owns it.
struct Object {
    path: String,
    methods: Vec<String>,
    owner: u64,
}

#[derive(Default)]
struct Bus {
    objects: Vec<Object>,
    conns: HashMap<u64, UnixStream>, // id -> write handle
    listeners: HashSet<u64>,
    pending: HashMap<u64, u64>, // in-flight call id -> caller conn id
    next_conn: u64,
    next_req: u64,
}

impl Bus {
    /// Push one JSON frame (newline-terminated) to a connection.
    fn send_to(&self, conn: u64, v: &Value) {
        if let Some(stream) = self.conns.get(&conn) {
            let mut w: &UnixStream = stream;
            let mut line = v.to_string();
            line.push('\n');
            let _ = w.write_all(line.as_bytes());
        }
    }
}

fn daemon() -> i32 {
    let sock = sock_path();
    if let Some(dir) = std::path::Path::new(&sock).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::remove_file(&sock); // clear a stale socket from a prior run
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ubus: bind {sock}: {e}");
            return 1;
        }
    };
    println!("ubus: broker on {sock}");

    let bus = Arc::new(Mutex::new(Bus::default()));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let bus = Arc::clone(&bus);
        thread::spawn(move || handle_conn(bus, stream));
    }
    0
}

fn handle_conn(bus: Arc<Mutex<Bus>>, stream: UnixStream) {
    let Ok(write_half) = stream.try_clone() else { return };
    let id = {
        let mut b = bus.lock().unwrap();
        b.next_conn += 1;
        let id = b.next_conn;
        b.conns.insert(id, write_half);
        id
    };

    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        match Value::parse(&line) {
            Ok(req) => handle_request(&bus, id, &req),
            Err(e) => {
                let b = bus.lock().unwrap();
                b.send_to(id, &err(-1, &format!("bad json: {e}")));
            }
        }
    }

    // Connection closed: drop everything it owned.
    let mut b = bus.lock().unwrap();
    b.conns.remove(&id);
    b.listeners.remove(&id);
    b.objects.retain(|o| o.owner != id);
}

fn handle_request(bus: &Arc<Mutex<Bus>>, id: u64, req: &Value) {
    let op = req.get("op").and_then(Value::as_str).unwrap_or("");
    match op {
        "list" => {
            let b = bus.lock().unwrap();
            b.send_to(id, &list_objects(&b));
        }
        "call" => {
            let path = req.get("path").and_then(Value::as_str).unwrap_or("");
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            let args = req.get("args").cloned().unwrap_or_else(|| Value::Object(vec![]));

            // Built-ins are answered synchronously by the broker.
            if let Some(data) = builtin_call(path, method, &args) {
                let b = bus.lock().unwrap();
                b.send_to(id, &ok(data));
                return;
            }
            // Otherwise route to a registered provider and wait for its reply.
            let mut b = bus.lock().unwrap();
            let owner = b
                .objects
                .iter()
                .find(|o| o.path == path && o.methods.iter().any(|m| m == method))
                .map(|o| o.owner);
            match owner {
                Some(owner) => {
                    b.next_req += 1;
                    let reqid = b.next_req;
                    b.pending.insert(reqid, id);
                    let invoke = json::obj([
                        ("invoke", Value::Num(reqid as f64)),
                        ("method", json::s(method)),
                        ("args", args),
                    ]);
                    b.send_to(owner, &invoke);
                }
                None => b.send_to(id, &err(-2, "object/method not found")),
            }
        }
        "reply" => {
            // A provider returning the result of an earlier invoke.
            let reqid = req.get("id").and_then(Value::as_u64).unwrap_or(0);
            let data = req.get("data").cloned().unwrap_or(Value::Null);
            let mut b = bus.lock().unwrap();
            if let Some(caller) = b.pending.remove(&reqid) {
                b.send_to(caller, &ok(data));
            }
        }
        "add" => {
            let path = req.get("path").and_then(Value::as_str).unwrap_or("").to_string();
            let methods = req
                .get("methods")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|m| m.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let mut b = bus.lock().unwrap();
            if path.is_empty() {
                b.send_to(id, &err(-1, "add: empty path"));
            } else {
                b.objects.retain(|o| o.path != path); // last registration wins
                b.objects.push(Object { path, methods, owner: id });
                b.send_to(id, &status(0));
            }
        }
        "send" => {
            let event = req.get("event").and_then(Value::as_str).unwrap_or("").to_string();
            let data = req.get("data").cloned().unwrap_or(Value::Null);
            let msg = json::obj([("event", json::s(event)), ("data", data)]);
            let b = bus.lock().unwrap();
            let targets: Vec<u64> = b.listeners.iter().copied().collect();
            for t in targets {
                b.send_to(t, &msg);
            }
            b.send_to(id, &status(0));
        }
        "listen" => {
            let mut b = bus.lock().unwrap();
            b.listeners.insert(id);
            b.send_to(id, &status(0));
        }
        _ => {
            let b = bus.lock().unwrap();
            b.send_to(id, &err(-1, "unknown op"));
        }
    }
}

fn list_objects(b: &Bus) -> Value {
    let mut objs: Vec<Value> = BUILTINS
        .iter()
        .map(|(p, ms)| {
            json::obj([
                ("path", json::s(*p)),
                ("methods", Value::Array(ms.iter().map(|m| json::s(*m)).collect())),
            ])
        })
        .collect();
    for o in &b.objects {
        objs.push(json::obj([
            ("path", json::s(o.path.clone())),
            ("methods", Value::Array(o.methods.iter().map(|m| json::s(m.clone())).collect())),
        ]));
    }
    json::obj([("status", Value::Num(0.0)), ("objects", Value::Array(objs))])
}

// ---- built-in `system` object ----------------------------------------------

fn builtin_call(path: &str, method: &str, _args: &Value) -> Option<Value> {
    match (path, method) {
        ("system", "board") => Some(board()),
        ("system", "info") => Some(info()),
        _ => None,
    }
}

fn board() -> Value {
    json::obj([
        ("kernel", json::s(kernel_release())),
        ("hostname", json::s(hostname())),
        ("system", json::s("LWRT")),
        ("model", json::s("LWRT router")),
        ("board_name", json::s("lwrt")),
        (
            "release",
            json::obj([
                ("distribution", json::s("LWRT")),
                ("version", json::s(crate::VERSION)),
            ]),
        ),
    ])
}

fn info() -> Value {
    let (total, free) = meminfo();
    json::obj([
        ("uptime", Value::Num(uptime() as f64)),
        ("localtime", Value::Num(now_secs() as f64)),
        (
            "memory",
            json::obj([
                ("total", Value::Num(total as f64)),
                ("free", Value::Num(free as f64)),
            ]),
        ),
    ])
}

// ---- client -----------------------------------------------------------------

fn connect() -> Result<UnixStream, String> {
    let sock = sock_path();
    UnixStream::connect(&sock).map_err(|e| format!("connect {sock}: {e} (is the broker running?)"))
}

/// Send one request, read exactly one response line, parse it.
fn request(req: &Value) -> Result<Value, String> {
    let stream = connect()?;
    let mut w: &UnixStream = &stream;
    let mut line = req.to_string();
    line.push('\n');
    w.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(&stream);
    let mut resp = String::new();
    reader.read_line(&mut resp).map_err(|e| e.to_string())?;
    Value::parse(resp.trim()).map_err(|e| format!("bad response: {e}"))
}

fn cli_list(filter: Option<&str>) -> i32 {
    let resp = match request(&json::obj([("op", json::s("list"))])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ubus: {e}");
            return 1;
        }
    };
    let Some(objs) = resp.get("objects").and_then(Value::as_array) else {
        eprintln!("ubus: malformed list response");
        return 1;
    };
    for o in objs {
        let path = o.get("path").and_then(Value::as_str).unwrap_or("");
        if filter.is_some_and(|f| f != path) {
            continue;
        }
        let methods: Vec<&str> =
            o.get("methods").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        println!("{path}\t[{}]", methods.join(", "));
    }
    0
}

fn cli_call(path: &str, method: &str, args_json: Option<&str>) -> i32 {
    let args = match args_json {
        Some(t) => match Value::parse(t) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ubus: bad json args: {e}");
                return 1;
            }
        },
        None => Value::Object(vec![]),
    };
    let req = json::obj([
        ("op", json::s("call")),
        ("path", json::s(path)),
        ("method", json::s(method)),
        ("args", args),
    ]);
    match request(&req) {
        Ok(resp) => match resp.get("data") {
            Some(data) => {
                println!("{}", data.to_string());
                0
            }
            None => {
                let msg = resp.get("error").and_then(Value::as_str).unwrap_or("call failed");
                eprintln!("ubus: {msg}");
                1
            }
        },
        Err(e) => {
            eprintln!("ubus: {e}");
            1
        }
    }
}

fn cli_send(event: &str, data_json: Option<&str>) -> i32 {
    let data = match data_json {
        Some(t) => match Value::parse(t) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ubus: bad json data: {e}");
                return 1;
            }
        },
        None => Value::Null,
    };
    let req = json::obj([("op", json::s("send")), ("event", json::s(event)), ("data", data)]);
    match request(&req) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("ubus: {e}");
            1
        }
    }
}

fn cli_listen() -> i32 {
    let stream = match connect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ubus: {e}");
            return 1;
        }
    };
    let mut w: &UnixStream = &stream;
    if w.write_all(b"{\"op\":\"listen\"}\n").is_err() {
        eprintln!("ubus: listen: write failed");
        return 1;
    }
    let reader = BufReader::new(&stream);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        // Skip the initial {"status":0} ack; print event frames.
        if let Ok(v) = Value::parse(&line) {
            if v.get("event").is_some() {
                println!("{}", v.to_string());
            }
        }
    }
    0
}

// ---- reply helpers ----------------------------------------------------------

fn ok(data: Value) -> Value {
    json::obj([("status", Value::Num(0.0)), ("data", data)])
}

fn status(code: i64) -> Value {
    json::obj([("status", Value::Num(code as f64))])
}

fn err(code: i64, msg: &str) -> Value {
    json::obj([("status", Value::Num(code as f64)), ("error", json::s(msg))])
}

// ---- system probes ----------------------------------------------------------

fn kernel_release() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } == 0 {
        cbuf(&u.release)
    } else {
        String::new()
    }
}

/// Convert a NUL-terminated C char buffer to a String. `c_char` is `i8` on some
/// targets and `u8` on others (MIPS), so cast through `u8`.
fn cbuf(buf: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "lwrt".to_string())
}

fn uptime() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|f| f.parse::<f64>().ok()))
        .map(|f| f as u64)
        .unwrap_or(0)
}

/// (MemTotal, MemFree) in kB from /proc/meminfo.
fn meminfo() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total = 0;
    let mut free = 0;
    for line in text.lines() {
        let kb = || line.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        if line.starts_with("MemTotal:") {
            total = kb();
        } else if line.starts_with("MemFree:") {
            free = kb();
        }
    }
    (total, free)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn board_has_expected_shape() {
        let b = board();
        assert_eq!(b.get("system").and_then(Value::as_str), Some("LWRT"));
        assert_eq!(
            b.get("release").and_then(|r| r.get("distribution")).and_then(Value::as_str),
            Some("LWRT")
        );
        // version comes from the crate and must be non-empty.
        assert!(!b
            .get("release")
            .and_then(|r| r.get("version"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty());
    }

    #[test]
    fn builtin_dispatch_and_misses() {
        assert!(builtin_call("system", "board", &Value::Null).is_some());
        assert!(builtin_call("system", "info", &Value::Null).is_some());
        assert!(builtin_call("system", "nope", &Value::Null).is_none());
        assert!(builtin_call("other", "board", &Value::Null).is_none());
    }

    #[test]
    fn reply_helpers_are_well_formed() {
        assert_eq!(ok(Value::Null).get("status"), Some(&Value::Num(0.0)));
        assert_eq!(err(-2, "x").get("status"), Some(&Value::Num(-2.0)));
        assert_eq!(err(-2, "x").get("error").and_then(Value::as_str), Some("x"));
    }

    #[test]
    fn list_includes_builtin_system() {
        let b = Bus::default();
        let listed = list_objects(&b);
        let objs = listed.get("objects").and_then(Value::as_array).unwrap();
        assert!(objs.iter().any(|o| o.get("path").and_then(Value::as_str) == Some("system")));
    }
}
