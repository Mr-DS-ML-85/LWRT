//! json — a tiny, dependency-free JSON value type, parser and serializer.
//!
//! LWRT speaks JSON in two places: the `httpd` admin API and the `ubus` message
//! bus. Rather than pull in `serde`/`serde_json` (and the compile-time + binary
//! cost on a 4 MB target), we carry a compact recursive-descent parser over a
//! small [`Value`] enum. It implements the JSON grammar (RFC 8259) closely
//! enough for config-sized documents: objects, arrays, strings with the
//! standard escapes (including `\uXXXX`), numbers, and the three literals.
//! Object key order is preserved (a `Vec` of pairs, not a map) so round-trips
//! and signatures are stable.

use std::fmt::Write as _;

/// A parsed JSON value. Numbers are kept as `f64` (JSON has one number type);
/// callers that want integers use [`Value::as_u64`] / [`Value::as_i64`].
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Vec<Value>),
    /// Insertion order preserved.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Parse one JSON document. Trailing whitespace is allowed; trailing
    /// non-whitespace is an error.
    pub fn parse(input: &str) -> Result<Value, String> {
        let mut p = Parser { b: input.as_bytes(), i: 0 };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != p.b.len() {
            return Err(format!("trailing data at byte {}", p.i));
        }
        Ok(v)
    }

    // --- ergonomic accessors -------------------------------------------------

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Num(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    // --- serialization -------------------------------------------------------

    /// Serialize to a compact (no-whitespace) JSON string.
    pub fn to_string(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }

    fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Num(n) => {
                // Emit integers without a trailing `.0`; finite check keeps us
                // from writing `NaN`/`inf`, which are not valid JSON.
                if n.is_finite() && n.fract() == 0.0 && n.abs() < 1e15 {
                    let _ = write!(out, "{}", *n as i64);
                } else if n.is_finite() {
                    let _ = write!(out, "{n}");
                } else {
                    out.push_str("null");
                }
            }
            Value::Str(s) => write_str(s, out),
            Value::Array(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Value::Object(pairs) => {
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Build a `Value::Object` from an ordered list of key/value pairs.
pub fn obj<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Convenience: a string value.
pub fn s(v: impl Into<String>) -> Value {
    Value::Str(v.into())
}

/// Write a JSON string literal with the mandatory escapes.
fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.i) {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') | Some(b'f') => self.boolean(),
            Some(b'n') => self.null(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(format!("unexpected byte {:?} at {}", c as char, self.i)),
            None => Err("unexpected end of input".into()),
        }
    }

    fn expect(&mut self, c: u8) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected {:?} at byte {}", c as char, self.i))
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.expect(b'{')?;
        let mut pairs = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(pairs));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            self.expect(b':')?;
            self.ws();
            let val = self.value()?;
            pairs.push((key, val));
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.i)),
            }
        }
        Ok(Value::Object(pairs))
    }

    fn array(&mut self) -> Result<Value, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.i)),
            }
        }
        Ok(Value::Array(items))
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or("unterminated escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\x08'),
                        b'f' => out.push('\x0c'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => return Err(format!("bad escape \\{}", other as char)),
                    }
                }
                // A raw UTF-8 byte: copy it through. We collect the bytes of a
                // multibyte sequence by reading until we have a valid char.
                _ => {
                    // Reconstruct the full UTF-8 code point starting at c.
                    let start = self.i - 1;
                    let extra = utf8_extra(c);
                    let end = start + 1 + extra;
                    if end > self.b.len() {
                        return Err("truncated UTF-8 in string".into());
                    }
                    let chunk = &self.b[start..end];
                    match std::str::from_utf8(chunk) {
                        Ok(part) => out.push_str(part),
                        Err(_) => return Err("invalid UTF-8 in string".into()),
                    }
                    self.i = end;
                }
            }
        }
        Ok(out)
    }

    /// Parse the four hex digits of a `\u` escape into a `char`, handling
    /// UTF-16 surrogate pairs (`😀`).
    fn unicode_escape(&mut self) -> Result<char, String> {
        let hi = self.hex4()?;
        let cp = if (0xD800..=0xDBFF).contains(&hi) {
            // High surrogate: must be followed by \uXXXX low surrogate.
            if self.peek() == Some(b'\\') {
                self.i += 1;
                self.expect(b'u')?;
            } else {
                return Err("lone high surrogate".into());
            }
            let lo = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return Err("bad low surrogate".into());
            }
            0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
        } else {
            hi
        };
        char::from_u32(cp).ok_or_else(|| "invalid code point".into())
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.peek().ok_or("truncated \\u escape")?;
            self.i += 1;
            let d = (c as char).to_digit(16).ok_or("non-hex in \\u escape")?;
            v = v * 16 + d;
        }
        Ok(v)
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-') {
                self.i += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad number")?;
        text.parse::<f64>()
            .map(Value::Num)
            .map_err(|_| format!("invalid number {text:?}"))
    }

    fn boolean(&mut self) -> Result<Value, String> {
        if self.b[self.i..].starts_with(b"true") {
            self.i += 4;
            Ok(Value::Bool(true))
        } else if self.b[self.i..].starts_with(b"false") {
            self.i += 5;
            Ok(Value::Bool(false))
        } else {
            Err(format!("invalid literal at byte {}", self.i))
        }
    }

    fn null(&mut self) -> Result<Value, String> {
        if self.b[self.i..].starts_with(b"null") {
            self.i += 4;
            Ok(Value::Null)
        } else {
            Err(format!("invalid literal at byte {}", self.i))
        }
    }
}

/// Number of *continuation* bytes that follow a UTF-8 lead byte.
fn utf8_extra(lead: u8) -> usize {
    match lead {
        0x00..=0x7f => 0,
        0xc0..=0xdf => 1,
        0xe0..=0xef => 2,
        0xf0..=0xf7 => 3,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scalars_and_literals() {
        assert_eq!(Value::parse("null").unwrap(), Value::Null);
        assert_eq!(Value::parse("true").unwrap(), Value::Bool(true));
        assert_eq!(Value::parse("false").unwrap(), Value::Bool(false));
        assert_eq!(Value::parse("  42 ").unwrap(), Value::Num(42.0));
        assert_eq!(Value::parse("-3.5e2").unwrap(), Value::Num(-350.0));
        assert_eq!(Value::parse(r#""hi""#).unwrap(), Value::Str("hi".into()));
    }

    #[test]
    fn parses_nested_object_and_array() {
        let v = Value::parse(r#"{"a":1,"b":[true,null,"x"],"c":{"d":2}}"#).unwrap();
        assert_eq!(v.get("a").unwrap().as_u64(), Some(1));
        assert_eq!(v.get("b").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(v.get("c").unwrap().get("d").unwrap().as_u64(), Some(2));
        assert!(v.get("missing").is_none());
    }

    #[test]
    fn string_escapes_roundtrip() {
        let v = Value::parse(r#""line\ntab\tquote\"slash\\end""#).unwrap();
        assert_eq!(v.as_str().unwrap(), "line\ntab\tquote\"slash\\end");
        // Re-serialize and re-parse: must be stable.
        let again = Value::parse(&v.to_string()).unwrap();
        assert_eq!(v, again);
    }

    #[test]
    fn unicode_and_surrogate_pairs() {
        assert_eq!(Value::parse(r#""A""#).unwrap().as_str(), Some("A"));
        // U+1F600 GRINNING FACE as a surrogate pair.
        assert_eq!(
            Value::parse(r#""😀""#).unwrap().as_str(),
            Some("\u{1F600}")
        );
    }

    #[test]
    fn compact_serialization_drops_integer_point() {
        let v = obj([("n", Value::Num(5.0)), ("s", s("hi"))]);
        assert_eq!(v.to_string(), r#"{"n":5,"s":"hi"}"#);
    }

    #[test]
    fn rejects_trailing_and_malformed() {
        assert!(Value::parse("1 2").is_err());
        assert!(Value::parse("{").is_err());
        assert!(Value::parse("[1,]").is_err());
        assert!(Value::parse(r#"{"k":}"#).is_err());
        assert!(Value::parse("").is_err());
    }
}
