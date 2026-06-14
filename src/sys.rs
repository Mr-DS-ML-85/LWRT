//! Thin wrappers over the handful of raw syscalls the userspace needs.
//! Keeping them in one place means the rest of the tree stays `unsafe`-free.

use std::ffi::CString;
use std::io;

/// Build a NUL-terminated C string, mapping an interior NUL to an `io` error
/// instead of panicking. These wrappers run inside PID 1, so a bad string must
/// surface as a recoverable error — never abort the whole router.
fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interior NUL"))
}

/// mount(2) with the common flags. `fstype`/`data` may be empty.
pub fn mount(src: &str, target: &str, fstype: &str, flags: u64, data: &str) -> io::Result<()> {
    let c_src = cstr(src)?;
    let c_tgt = cstr(target)?;
    let c_fs = cstr(fstype)?;
    let c_data = cstr(data)?;
    let data_ptr = if data.is_empty() {
        std::ptr::null()
    } else {
        c_data.as_ptr() as *const libc::c_void
    };
    let r = unsafe {
        libc::mount(
            c_src.as_ptr(),
            c_tgt.as_ptr(),
            c_fs.as_ptr(),
            flags as libc::c_ulong,
            data_ptr,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// mkdir(2), ignoring EEXIST so it is idempotent.
pub fn mkdir(path: &str, mode: u32) -> io::Result<()> {
    let c = cstr(path)?;
    let r = unsafe { libc::mkdir(c.as_ptr(), mode as libc::mode_t) };
    if r == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(e)
    }
}

/// fork(2). Returns Some(child_pid) in the parent, None in the child.
pub fn fork() -> io::Result<Option<libc::pid_t>> {
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(None),
        n => Ok(Some(n)),
    }
}

/// reboot(2). action is one of libc::LINUX_REBOOT_CMD_*.
pub fn reboot(action: libc::c_int) -> io::Result<()> {
    let r = unsafe { libc::reboot(action) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Install a simple signal handler (sa_handler form).
pub fn signal(sig: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    unsafe {
        libc::signal(sig, handler as libc::sighandler_t);
    }
}
