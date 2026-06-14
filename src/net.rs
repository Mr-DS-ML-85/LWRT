//! Interface configuration without an `ip`/`ifconfig` binary on the device.
//! We talk to the kernel directly: ioctl() on an AF_INET socket for address,
//! netmask and flags; SIOCADDRT for the default route. This covers everything
//! a home router needs (bridge + DSA switch ports already exist in-kernel).

use std::io;
use std::net::Ipv4Addr;

const IFNAMSIZ: usize = 16;

fn ctl_socket() -> io::Result<libc::c_int> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn name_buf(ifname: &str) -> [u8; IFNAMSIZ] {
    let mut buf = [0u8; IFNAMSIZ];
    let b = ifname.as_bytes();
    let n = b.len().min(IFNAMSIZ - 1);
    buf[..n].copy_from_slice(&b[..n]);
    buf
}

/// Lay an Ipv4Addr into a sockaddr_in at the start of `out` (16 bytes).
fn put_sockaddr_in(out: &mut [u8], addr: Ipv4Addr) {
    out[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    // sin_port = 0 at [2..4]
    out[4..8].copy_from_slice(&addr.octets()); // sin_addr, network order
}

fn ioctl_ifreq(fd: libc::c_int, req: libc::c_ulong, ifreq: &mut [u8; 32]) -> io::Result<()> {
    let r = unsafe { libc::ioctl(fd, req as _, ifreq.as_mut_ptr()) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Assign an IPv4 address + netmask to an interface and bring it up.
pub fn configure(ifname: &str, addr: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let fd = ctl_socket()?;
    let name = name_buf(ifname);

    // SIOCSIFADDR
    let mut req = [0u8; 32];
    req[..IFNAMSIZ].copy_from_slice(&name);
    put_sockaddr_in(&mut req[IFNAMSIZ..], addr);
    ioctl_ifreq(fd, libc::SIOCSIFADDR, &mut req)?;

    // SIOCSIFNETMASK
    let mut req = [0u8; 32];
    req[..IFNAMSIZ].copy_from_slice(&name);
    put_sockaddr_in(&mut req[IFNAMSIZ..], netmask);
    ioctl_ifreq(fd, libc::SIOCSIFNETMASK, &mut req)?;

    let r = up(ifname);
    unsafe { libc::close(fd) };
    r
}

/// Set IFF_UP | IFF_RUNNING on an interface (read-modify-write the flags).
pub fn up(ifname: &str) -> io::Result<()> {
    let fd = ctl_socket()?;
    let name = name_buf(ifname);

    let mut req = [0u8; 32];
    req[..IFNAMSIZ].copy_from_slice(&name);
    ioctl_ifreq(fd, libc::SIOCGIFFLAGS, &mut req)?;

    // ifr_flags is a c_short at offset IFNAMSIZ.
    let mut flags = i16::from_ne_bytes([req[IFNAMSIZ], req[IFNAMSIZ + 1]]);
    flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
    req[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());

    let res = ioctl_ifreq(fd, libc::SIOCSIFFLAGS, &mut req);
    unsafe { libc::close(fd) };
    res
}

/// Add a default route via `gateway`.
pub fn default_route(gateway: Ipv4Addr) -> io::Result<()> {
    let fd = ctl_socket()?;
    // struct rtentry, built field-by-field so we don't depend on its layout
    // being identical across libc versions.
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };

    // rt_dst = 0.0.0.0 (default), rt_genmask = 0.0.0.0
    set_rt_addr(&mut rt.rt_dst, Ipv4Addr::UNSPECIFIED);
    set_rt_addr(&mut rt.rt_genmask, Ipv4Addr::UNSPECIFIED);
    set_rt_addr(&mut rt.rt_gateway, gateway);
    rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as u16;

    let r = unsafe { libc::ioctl(fd, libc::SIOCADDRT as _, &rt) };
    let res = if r < 0 {
        let e = io::Error::last_os_error();
        // An existing identical route is fine.
        if e.raw_os_error() == Some(libc::EEXIST) {
            Ok(())
        } else {
            Err(e)
        }
    } else {
        Ok(())
    };
    unsafe { libc::close(fd) };
    res
}

fn set_rt_addr(sa: &mut libc::sockaddr, addr: Ipv4Addr) {
    sa.sa_family = libc::AF_INET as libc::sa_family_t;
    // sa_data: [0..2] port, [2..6] addr
    let oct = addr.octets();
    sa.sa_data[2] = oct[0] as libc::c_char;
    sa.sa_data[3] = oct[1] as libc::c_char;
    sa.sa_data[4] = oct[2] as libc::c_char;
    sa.sa_data[5] = oct[3] as libc::c_char;
}

/// Convenience: parse "a.b.c.d" or return a clear error.
pub fn parse_v4(s: &str) -> io::Result<Ipv4Addr> {
    s.parse::<Ipv4Addr>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("bad IPv4: {s}")))
}
