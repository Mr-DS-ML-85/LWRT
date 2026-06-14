//! The whole router is driven by one small INI-style file: /etc/lwrt/config.
//! Sections in [brackets], `key = value` lines, `#` comments. We deliberately
//! keep the model flat and string-typed — applets pull what they need.

use std::collections::BTreeMap;
use std::fs;

pub const PATH: &str = "/etc/lwrt/config";

/// A parsed config: section name -> (key -> value).
#[derive(Debug, Default)]
pub struct Config {
    pub sections: BTreeMap<String, BTreeMap<String, String>>,
}

impl Config {
    pub fn parse(text: &str) -> Config {
        let mut cfg = Config::default();
        let mut cur = String::from("");
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                cur = name.trim().to_string();
                cfg.sections.entry(cur.clone()).or_default();
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                cfg.sections
                    .entry(cur.clone())
                    .or_default()
                    .insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        cfg
    }

    pub fn load() -> Config {
        match fs::read_to_string(PATH) {
            Ok(t) => Config::parse(&t),
            Err(_) => Config::with_defaults(),
        }
    }

    /// Sensible router defaults so a blank device still boots usefully.
    pub fn with_defaults() -> Config {
        Config::parse(DEFAULT)
    }

    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections.get(section)?.get(key).map(|s| s.as_str())
    }

    pub fn get_or<'a>(&'a self, section: &str, key: &str, default: &'a str) -> &'a str {
        self.get(section, key).unwrap_or(default)
    }
}

pub const DEFAULT: &str = "\
# LWRT default configuration
[system]
hostname = lwrt

[admin]
# Web UI password. Set this to require login (recommended). You may instead
# store password_sha256 = <hex of sha256(password)> to avoid a cleartext pw.
# password = changeme

[lan]
ifname = br-lan
ipaddr = 192.168.1.1
netmask = 255.255.255.0

[dhcp]
enabled = 1
start = 192.168.1.100
limit = 100
leasetime = 43200

[wan]
ifname = eth0.2
proto = dhcp

[wifi]
ssid = LWRT
encryption = psk2
key = changeme0
channel = auto

[wireguard]
enabled = 0
listen_port = 51820
address = 10.7.0.1/24

[firewall]
masq = 1
# port forwards: comma-separated proto:wan_dport:dest_ip:dest_port
# forward = tcp:8080:192.168.1.10:80, udp:5000:192.168.1.20:5000
";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_sections_keys_and_comments() {
        let c = Config::parse("# top\n[a]\nx = 1 # inline\n\n[b]\ny=hello world\n");
        assert_eq!(c.get("a", "x"), Some("1"));
        assert_eq!(c.get("b", "y"), Some("hello world"));
        assert_eq!(c.get_or("b", "z", "def"), "def");
    }
    #[test]
    fn defaults_are_valid() {
        let c = Config::with_defaults();
        assert_eq!(c.get("lan", "ipaddr"), Some("192.168.1.1"));
        assert_eq!(c.get("dhcp", "enabled"), Some("1"));
    }
}
