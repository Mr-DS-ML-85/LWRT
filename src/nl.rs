//! Minimal netlink plumbing shared by the firewall (NETLINK_NETFILTER /
//! nf_tables) and WireGuard (NETLINK_GENERIC / genetlink). Just enough to
//! build attribute-encoded messages and read back the kernel's ACK/error.
//! This is the "thin userspace over an in-kernel feature" pattern.
//!
//! Encoding goes through [`NlBuf`], a single growable buffer that appends
//! every header and attribute *in place* and backpatches the length fields of
//! nested attributes / messages when their scope closes. The naive approach —
//! returning a fresh `Vec<u8>` per attribute and `extend`-ing them together —
//! allocates dozens of short-lived buffers to emit one ruleset; this allocates
//! once and grows.

use std::io;
use std::os::unix::io::RawFd;

pub const NLMSG_ERROR: u16 = 0x2;
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_EXCL: u16 = 0x200;
const NLA_F_NESTED: u16 = 0x8000;

pub fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// A marker for an open nested attribute or message, returned by `begin_*`
/// and consumed by the matching `end_*`. `#[must_use]` so a forgotten close
/// (which would leave a zero length field on the wire) is a compile warning.
#[must_use = "an opened netlink scope must be closed with end_nested/end_message"]
pub struct Scope(usize);

/// Append-only netlink message builder over one backing buffer.
#[derive(Default)]
pub struct NlBuf {
    buf: Vec<u8>,
}

impl NlBuf {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(256) }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    fn pad(&mut self) {
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
    }

    /// Append raw bytes with no attribute header. For the fixed structs that
    /// precede the attribute stream in a message body — `nfgenmsg` (nf_tables)
    /// and `genlmsghdr` (genetlink). Callers pass already-aligned chunks.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Append one attribute `(type, raw payload)`, 4-byte aligned. The length
    /// field counts the 4-byte header + payload but not the trailing pad,
    /// matching the kernel's `nla_put`.
    pub fn attr(&mut self, typ: u16, payload: &[u8]) -> &mut Self {
        let len = (4 + payload.len()) as u16;
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(&typ.to_le_bytes());
        self.buf.extend_from_slice(payload);
        self.pad();
        self
    }

    pub fn attr_u16_ne(&mut self, typ: u16, v: u16) -> &mut Self {
        self.attr(typ, &v.to_ne_bytes())
    }
    pub fn attr_u32_be(&mut self, typ: u16, v: u32) -> &mut Self {
        self.attr(typ, &v.to_be_bytes())
    }
    pub fn attr_u32_le(&mut self, typ: u16, v: u32) -> &mut Self {
        self.attr(typ, &v.to_le_bytes())
    }

    /// A NUL-terminated string attribute.
    pub fn attr_str(&mut self, typ: u16, s: &str) -> &mut Self {
        let len = (4 + s.len() + 1) as u16;
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(&typ.to_le_bytes());
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        self.pad();
        self
    }

    /// Open a nested attribute. Write children with the normal `attr*` calls,
    /// then close it with [`end_nested`](Self::end_nested).
    pub fn begin_nested(&mut self, typ: u16) -> Scope {
        let off = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]); // length backpatched on close
        self.buf.extend_from_slice(&(typ | NLA_F_NESTED).to_le_bytes());
        Scope(off)
    }

    pub fn end_nested(&mut self, scope: Scope) -> &mut Self {
        let len = (self.buf.len() - scope.0) as u16;
        self.buf[scope.0..scope.0 + 2].copy_from_slice(&len.to_le_bytes());
        self.pad();
        self
    }

    /// Open a netlink message (16-byte `nlmsghdr`). Write the body, then close
    /// with [`end_message`](Self::end_message). Several messages may be opened
    /// back-to-back in the same buffer (e.g. an nf_tables batch).
    pub fn begin_message(&mut self, msg_type: u16, flags: u16, seq: u32) -> Scope {
        let off = self.buf.len();
        self.buf.extend_from_slice(&[0, 0, 0, 0]); // nlmsg_len, backpatched
        self.buf.extend_from_slice(&msg_type.to_le_bytes());
        self.buf.extend_from_slice(&flags.to_le_bytes());
        self.buf.extend_from_slice(&seq.to_le_bytes());
        self.buf.extend_from_slice(&0u32.to_le_bytes()); // pid 0: kernel assigns
        Scope(off)
    }

    pub fn end_message(&mut self, scope: Scope) -> &mut Self {
        let len = (self.buf.len() - scope.0) as u32;
        self.buf[scope.0..scope.0 + 4].copy_from_slice(&len.to_le_bytes());
        self.pad();
        self
    }
}

pub fn open(protocol: libc::c_int) -> io::Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let r = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// Send raw bytes to the kernel (portid 0).
pub fn send(fd: RawFd, data: &[u8]) -> io::Result<()> {
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let n = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Read one datagram and, if it is an NLMSG_ERROR, surface its errno
/// (0 = ACK success).
pub fn recv_ack(fd: RawFd) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    if n < 16 {
        return Ok(());
    }
    let msg_type = u16::from_le_bytes([buf[4], buf[5]]);
    if msg_type == NLMSG_ERROR {
        // body: int error, then original header
        let err = i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if err != 0 {
            return Err(io::Error::from_raw_os_error(-err));
        }
    }
    Ok(())
}

/// Read one datagram and return its raw bytes (caller parses).
pub fn recv_msg(fd: RawFd) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 8192];
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf[..n as usize].to_vec())
}

/// Walk the top-level attributes in a netlink message body, invoking `f`
/// with (nla_type without flags, payload) for each.
pub fn for_each_attr(body: &[u8], mut f: impl FnMut(u16, &[u8])) {
    let mut i = 0;
    while i + 4 <= body.len() {
        let len = u16::from_le_bytes([body[i], body[i + 1]]) as usize;
        let typ = u16::from_le_bytes([body[i + 2], body[i + 3]]) & 0x3fff;
        if len < 4 || i + len > body.len() {
            break;
        }
        f(typ, &body[i + 4..i + len]);
        i += align4(len);
    }
}

pub fn close(fd: RawFd) {
    unsafe { libc::close(fd) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_is_4byte_aligned_with_correct_len_field() {
        // 3-byte payload -> len field 7, total padded to 8.
        let mut b = NlBuf::new();
        b.attr(5, &[1, 2, 3]);
        let a = b.as_slice();
        assert_eq!(a.len(), 8);
        assert_eq!(u16::from_le_bytes([a[0], a[1]]), 7);
        assert_eq!(u16::from_le_bytes([a[2], a[3]]), 5);
        assert_eq!(&a[4..7], &[1, 2, 3]);
        assert_eq!(a[7], 0); // pad
    }

    #[test]
    fn nested_sets_flag_and_backpatches_length() {
        let mut b = NlBuf::new();
        let s = b.begin_nested(2);
        b.attr(1, &[9]); // one 8-byte child (len 5 -> padded to 8)
        b.end_nested(s);
        let n = b.as_slice();
        // outer: 4-byte header + 8-byte child = 12
        assert_eq!(u16::from_le_bytes([n[0], n[1]]), 12);
        let typ = u16::from_le_bytes([n[2], n[3]]);
        assert_eq!(typ & NLA_F_NESTED, NLA_F_NESTED);
        assert_eq!(typ & !NLA_F_NESTED, 2);
        assert_eq!(n.len(), 12);
    }

    #[test]
    fn message_header_length_is_total_including_body() {
        let mut b = NlBuf::new();
        let m = b.begin_message(0x10, NLM_F_REQUEST, 42);
        b.attr_u32_le(1, 0xdeadbeef);
        b.end_message(m);
        let msg = b.as_slice();
        // 16-byte header + one 8-byte attr.
        assert_eq!(u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]), 24);
        assert_eq!(u16::from_le_bytes([msg[4], msg[5]]), 0x10);
        assert_eq!(u16::from_le_bytes([msg[6], msg[7]]), NLM_F_REQUEST);
        assert_eq!(u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]), 42);
        assert_eq!(msg.len(), 24);
    }

    #[test]
    fn for_each_attr_walks_back_what_we_wrote() {
        let mut b = NlBuf::new();
        b.attr(1, &[0xaa]);
        b.attr_u32_le(2, 0xdeadbeef);
        let mut seen = Vec::new();
        for_each_attr(b.as_slice(), |t, v| seen.push((t, v.to_vec())));
        assert_eq!(seen[0].0, 1);
        assert_eq!(seen[0].1, vec![0xaa]);
        assert_eq!(seen[1].0, 2);
        assert_eq!(
            u32::from_le_bytes([seen[1].1[0], seen[1].1[1], seen[1].1[2], seen[1].1[3]]),
            0xdeadbeef
        );
    }
}
