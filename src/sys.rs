//! Raw kernel ABI not covered (or not covered stably) by the `libc` crate:
//! the seccomp user-notification structures and ioctls, plus small helpers.
//!
//! Layouts are the x86_64 ones from `linux/seccomp.h`; they were checked
//! against the C compiler before being written down here.
#![allow(dead_code)]

/// `errno`-style error: a positive errno value.
pub type Errno = i32;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Errno>;

/// Returns the calling thread's current `errno`.
pub fn errno() -> Errno {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Converts a raw syscall return value into a [`Result`].
///
/// # Arguments
/// * `rc` - Return value of a libc call or raw syscall.
pub fn check(rc: i64) -> Result<i64> {
    if rc < 0 { Err(errno()) } else { Ok(rc) }
}

/// Mirror of `struct seccomp_data`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// Mirror of `struct seccomp_notif` (80 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// Mirror of `struct seccomp_notif_resp` (24 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// Mirror of `struct seccomp_notif_addfd` (24 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

pub const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0xc050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xc018_2101;
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = 0x4008_2102;
pub const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = 0x4018_2103;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 1 << 3;
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1;
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_SET_MODE_FILTER: i64 = 1;
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
pub const AUDIT_ARCH_ARM: u32 = 0x4000_0028;

/// Maximum path length we read out of a tracee.
pub const PATH_MAX: usize = 4096;

/// Bytes a 64-bit ABI guarantees below the stack pointer (the red zone).
pub const RED_ZONE_SIZE: u64 = 128;

/// Formats an errno for log messages.
pub fn strerror(e: Errno) -> String {
    std::io::Error::from_raw_os_error(e).to_string()
}

/// Logs to stderr when `verbose` is at least `level`.
#[macro_export]
macro_rules! note {
    ($ctx:expr, $level:expr, $($arg:tt)*) => {
        if $ctx.config.verbose >= $level { eprintln!("proot: {}", format!($($arg)*)); }
    };
}
