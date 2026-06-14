//! Tiny helpers with no obvious home. Kept dependency-free on purpose.

/// Decode standard base64 (with optional padding). WireGuard keys are 32-byte
/// values encoded this way. Returns None on malformed input.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in s.trim().as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn b64_roundtrip_known() {
        // "hello" -> aGVsbG8=
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        // 32-byte WireGuard-style key decodes to 32 bytes.
        let k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=";
        assert_eq!(b64_decode(k).unwrap().len(), 32);
    }
}
