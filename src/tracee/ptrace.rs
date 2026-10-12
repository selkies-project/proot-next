//! Thin ptrace wrappers.  All requests must come from the tracer thread.

use crate::sys::{Result, check};

/// Options the tracer sets on every tracee.
pub const DEFAULT_OPTIONS: i64 = (libc::PTRACE_O_TRACESYSGOOD
    | libc::PTRACE_O_TRACEFORK
    | libc::PTRACE_O_TRACEVFORK
    | libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_TRACEEXEC
    | libc::PTRACE_O_TRACESECCOMP) as i64;

/// `PTRACE_O_EXITKILL`, added when `--kill-on-exit` is set.
pub const OPTION_EXITKILL: i64 = libc::PTRACE_O_EXITKILL as i64;

/// Attaches to `pid` with `PTRACE_SEIZE`, setting `options` at the same time.
///
/// Unlike `PTRACE_ATTACH`/`PTRACE_TRACEME`, seizing does not stop the tracee
/// and makes group-stops and new-child stops arrive as `PTRACE_EVENT_STOP`,
/// which is what lets the tracer tell them apart from signal delivery.
///
/// # Arguments
/// * `pid` - Process to seize; must be our child or otherwise ptrace-accessible.
/// * `options` - Bitwise or of `PTRACE_O_*`.
pub fn seize(pid: i32, options: i64) -> Result<()> {
    check(unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0, options) }).map(|_| ())
}

/// Leaves a group-stopped tracee stopped but able to report further events.
pub fn listen(pid: i32) -> Result<()> {
    check(unsafe { libc::ptrace(libc::PTRACE_LISTEN, pid, 0, 0) }).map(|_| ())
}

#[allow(dead_code)]
/// Sets ptrace options on a stopped tracee.
///
/// # Arguments
/// * `pid` - Tracee thread id.
/// * `options` - Bitwise or of `PTRACE_O_*`.
pub fn setoptions(pid: i32, options: i64) -> Result<()> {
    check(unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, options) }).map(|_| ())
}

/// Resumes a stopped tracee, delivering `sig` (0 for none).
pub fn cont(pid: i32, sig: i32) -> Result<()> {
    check(unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, sig as i64) }).map(|_| ())
}

/// Reads the `siginfo` of the signal a tracee is stopped for.
pub fn getsiginfo(pid: i32) -> Result<libc::siginfo_t> {
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    check(unsafe { libc::ptrace(libc::PTRACE_GETSIGINFO, pid, 0, &mut si as *mut _) })?;
    Ok(si)
}

/// Reads the event message of the current stop (new child pid, exit status...).
pub fn geteventmsg(pid: i32) -> Result<u64> {
    let mut msg: u64 = 0;
    check(unsafe { libc::ptrace(libc::PTRACE_GETEVENTMSG, pid, 0, &mut msg as *mut u64) })?;
    Ok(msg)
}

/// Fetches the general purpose registers of a stopped tracee (x86 only).
#[cfg(target_arch = "x86_64")]
pub fn getregs(pid: i32) -> Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    check(unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs as *mut _) })?;
    Ok(regs)
}

/// Stores the general purpose registers of a stopped tracee (x86 only).
#[cfg(target_arch = "x86_64")]
pub fn setregs(pid: i32, regs: &libc::user_regs_struct) -> Result<()> {
    check(unsafe { libc::ptrace(libc::PTRACE_SETREGS, pid, 0, regs as *const _) }).map(|_| ())
}

/// Reads a register set (`PTRACE_GETREGSET`), the only register interface on aarch64.
///
/// # Arguments
/// * `pid` - Tracee thread id.
/// * `nt` - Note type, e.g. `NT_PRSTATUS`.
/// * `buf` - Destination of `len` bytes.
///
/// # Returns
/// The number of bytes the kernel filled: a 32-bit tracee's `NT_PRSTATUS` is
/// smaller than a 64-bit one, which is how the ABI is told apart.
#[allow(dead_code)]
pub fn getregset(pid: i32, nt: u32, buf: *mut u8, len: usize) -> Result<usize> {
    let mut iov = libc::iovec {
        iov_base: buf as *mut _,
        iov_len: len,
    };
    check(unsafe { libc::ptrace(libc::PTRACE_GETREGSET, pid, nt as usize, &mut iov as *mut _) })?;
    Ok(iov.iov_len)
}

/// Writes a register set (`PTRACE_SETREGSET`).
///
/// # Arguments
/// * `pid` - Tracee thread id.
/// * `nt` - Note type, e.g. `NT_PRSTATUS` or `NT_ARM_SYSTEM_CALL`.
/// * `buf` - Source of `len` bytes.
#[allow(dead_code)]
pub fn setregset(pid: i32, nt: u32, buf: *mut u8, len: usize) -> Result<()> {
    let mut iov = libc::iovec {
        iov_base: buf as *mut _,
        iov_len: len,
    };
    check(unsafe { libc::ptrace(libc::PTRACE_SETREGSET, pid, nt as usize, &mut iov as *mut _) }).map(|_| ())
}
