//! How the supervisor gets the right to reach its tracees.
//!
//! Both modes need the kernel's ptrace access check to pass towards every
//! tracee: the tracer for `PTRACE_SEIZE`, the no-ptrace mode for
//! `process_vm_readv` and `/proc/<pid>/mem`.  Yama's `ptrace_scope` of 2
//! grants that only to a holder of `CAP_SYS_PTRACE` in the tracee's user
//! namespace, so where the plain check is refused the first tracee is moved
//! into a user namespace of its own, which the supervisor owns from outside
//! and therefore holds every capability in.  The namespace maps the caller's
//! own uid and gid onto themselves and nothing else.
//!
//! Where neither ptrace nor a user namespace works (the common Kubernetes
//! case), the guest-stub restricted mode (see `guest_stub`) needs no access
//! to a guest's memory at all: a stub inside each guest process moves the
//! memory a served syscall uses into a mailbox both sides map.  It is the
//! fallback on x86_64 and aarch64, ruled out by `PROOT_GUEST_STUB=0`.
//!
//! The choice is made empirically: a child is forked and the supervisor
//! tries the accesses it will need on it, first as it is, then inside a user
//! namespace.  A host where neither works (Yama 3, an LSM policy, a profile
//! that also filters `unshare`) falls back to the guest stub, or where that
//! is unavailable or ruled out gets an error instead of a guest that hangs.

use crate::sys::{errno, strerror};
use std::ffi::CString;

/// What the probe settled on.
#[derive(Clone, Debug)]
pub struct Access {
    /// Whether the trace tier runs on ptrace.
    pub ptrace: bool,
    /// The user namespace the first tracee enters, if one is needed.
    pub userns: Option<UserNs>,
    /// Whether the guest-stub restricted mode is used: the supervisor does
    /// not reach the guests' memory, a stub inside each moves it to a mailbox.
    pub trap_mode: bool,
}

/// Everything the first tracee needs to enter its user namespace, prepared
/// before `fork` so the child does not allocate.
#[derive(Clone, Debug)]
pub struct UserNs {
    /// The line written to `/proc/self/uid_map`.
    uid_map: CString,
    /// The line written to `/proc/self/gid_map`.
    gid_map: CString,
}

/// A value the probe reads back from the child's copy of the supervisor's
/// memory, proving the read reached it.
static MARKER: u64 = 0x7072_6f6f_745f_6e78;

impl UserNs {
    /// Prepares an identity mapping of the caller's uid and gid.
    ///
    /// # Returns
    /// The prepared mapping.
    pub fn identity() -> UserNs {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        UserNs {
            uid_map: CString::new(format!("{uid} {uid} 1")).unwrap(),
            gid_map: CString::new(format!("{gid} {gid} 1")).unwrap(),
        }
    }

    /// Moves the calling process into a new user namespace with the prepared
    /// mapping.  Allocation free, for use between `fork` and `execve`.
    ///
    /// # Returns
    /// `Ok` once the namespace is entered and mapped.
    ///
    /// # Errors
    /// The errno of the step that failed.
    pub fn enter(&self) -> Result<(), i32> {
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } < 0 {
            return Err(errno());
        }
        write_file(c"/proc/self/setgroups", c"deny")?;
        write_file(c"/proc/self/uid_map", &self.uid_map)?;
        write_file(c"/proc/self/gid_map", &self.gid_map)
    }
}

/// Writes `text` to the file at `path`.  Allocation free.
///
/// # Arguments
/// * `path` - File to open for writing.
/// * `text` - Bytes to write in one call.
///
/// # Errors
/// The errno of `open` or `write`.
fn write_file(path: &std::ffi::CStr, text: &std::ffi::CStr) -> Result<(), i32> {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(errno());
    }
    let bytes = text.to_bytes();
    let n = unsafe { libc::write(fd, bytes.as_ptr() as *const _, bytes.len()) };
    let e = errno();
    unsafe { libc::close(fd) };
    if n == bytes.len() as isize { Ok(()) } else { Err(e) }
}

/// Outcome of one probe child.
struct Trial {
    /// Whether the supervisor could read the child's memory, or the errno.
    memory: Result<(), i32>,
    /// Whether the child could be ptraced, or its errno.
    ptrace: Result<(), i32>,
}

/// Decides how the supervisor reaches its tracees.
///
/// `PROOT_USERNS` forces the user namespace (`1`) or rules it out (`0`).
///
/// # Arguments
/// * `ptrace_wanted` - Whether the ptrace tier is available as far as the
///   syscall filter is concerned; a host that refuses it only through the
///   access check falls back to the no-ptrace mode when a user namespace
///   does not help.
/// * `stub` - Whether the guest-stub restricted mode may be used: `Some(false)`
///   as the fallback when no combination reaches a child, `Some(true)` in
///   any case, `None` never.  Ignored where the stub does not exist
///   (neither x86_64 nor aarch64).
///
/// # Returns
/// The mode and, when needed, the user namespace to enter.
///
/// # Errors
/// A message naming what was refused, when no combination reaches a child
/// and the guest-stub restricted mode is unavailable or ruled out.
pub fn probe(ptrace_wanted: bool, stub: Option<bool>) -> Result<Access, String> {
    let stub = stub.filter(|_| cfg!(any(target_arch = "x86_64", target_arch = "aarch64")));
    let trapped = Access {
        ptrace: false,
        userns: None,
        trap_mode: true,
    };
    if stub == Some(true) {
        return Ok(trapped);
    }
    let forced = std::env::var_os("PROOT_USERNS").map(|v| v != "0");
    let userns = UserNs::identity();
    let mut plans: Vec<(bool, bool)> = Vec::new();
    for ptrace in [ptrace_wanted, false] {
        for ns in [false, true] {
            if forced.is_some_and(|f| f != ns) || plans.contains(&(ptrace, ns)) {
                continue;
            }
            plans.push((ptrace, ns));
        }
    }
    let mut plain: Option<Trial> = None;
    let mut namespaced: Option<Trial> = None;
    for (ptrace, ns) in plans {
        let slot = if ns { &mut namespaced } else { &mut plain };
        if slot.is_none() {
            *slot = Some(trial(ns.then_some(&userns), ptrace_wanted));
        }
        let t = slot.as_ref().unwrap();
        if t.memory.is_ok() && (!ptrace || t.ptrace.is_ok()) {
            return Ok(Access {
                ptrace,
                userns: ns.then_some(userns),
                trap_mode: false,
            });
        }
    }
    if stub.is_some() {
        return Ok(trapped);
    }
    Err(refusal(plain.as_ref(), namespaced.as_ref()))
}

/// Forks a child that waits, tries the supervisor's accesses on it, and
/// kills it.
///
/// # Arguments
/// * `userns` - User namespace the child enters first, if any.
/// * `try_ptrace` - Whether to try `PTRACE_SEIZE` too.
///
/// # Returns
/// The result of each access; a child that could not enter its namespace
/// reports that errno for both.
fn trial(userns: Option<&UserNs>, try_ptrace: bool) -> Trial {
    let mut ready = [0i32; 2];
    let mut go = [0i32; 2];
    if unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        let e = errno();
        return Trial {
            memory: Err(e),
            ptrace: Err(e),
        };
    }
    if unsafe { libc::pipe2(go.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        let e = errno();
        unsafe {
            libc::close(ready[0]);
            libc::close(ready[1]);
        }
        return Trial {
            memory: Err(e),
            ptrace: Err(e),
        };
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(ready[0]);
            libc::close(go[1]);
            let status: i32 = match userns.map(UserNs::enter) {
                Some(Err(e)) => e,
                _ => 0,
            };
            libc::write(ready[1], &status as *const i32 as *const _, 4);
            let mut byte = 0u8;
            libc::read(go[0], &mut byte as *mut u8 as *mut _, 1);
            libc::_exit(0);
        }
    }
    unsafe {
        libc::close(ready[1]);
        libc::close(go[0]);
    }
    let result = if pid < 0 {
        let e = errno();
        Trial {
            memory: Err(e),
            ptrace: Err(e),
        }
    } else {
        let mut status = 0i32;
        let n = unsafe { libc::read(ready[0], &mut status as *mut i32 as *mut _, 4) };
        if n != 4 || status != 0 {
            let e = if n == 4 { status } else { libc::ECHILD };
            Trial {
                memory: Err(e),
                ptrace: Err(e),
            }
        } else {
            Trial {
                memory: read_marker(pid),
                ptrace: if try_ptrace { seize(pid) } else { Err(libc::ENOSYS) },
            }
        }
    };
    unsafe {
        libc::close(ready[0]);
        libc::close(go[1]);
        if pid > 0 {
            libc::kill(pid, libc::SIGKILL);
            let mut st = 0;
            while libc::waitpid(pid, &mut st, libc::__WALL) < 0 && errno() == libc::EINTR {}
        }
    }
    result
}

/// Reads [`MARKER`] from the child the way the notification handlers will:
/// `process_vm_readv`, or `/proc/<pid>/mem` where that is filtered.
///
/// # Arguments
/// * `pid` - The probe child, a copy of this address space.
///
/// # Errors
/// The errno of `/proc/<pid>/mem` when both refuse.
fn read_marker(pid: i32) -> Result<(), i32> {
    let mut value = 0u64;
    let addr = &MARKER as *const u64 as u64;
    let local = libc::iovec {
        iov_base: &mut value as *mut u64 as *mut _,
        iov_len: 8,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut _,
        iov_len: 8,
    };
    if unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) } == 8 && value == MARKER {
        return Ok(());
    }
    let path = CString::new(format!("/proc/{pid}/mem")).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(errno());
    }
    value = 0;
    let n = unsafe { libc::pread64(fd, &mut value as *mut u64 as *mut _, 8, addr as i64) };
    let e = errno();
    unsafe { libc::close(fd) };
    if n == 8 && value == MARKER { Ok(()) } else { Err(e) }
}

/// Seizes the probe child; it is killed right after, which ends the trace.
///
/// # Arguments
/// * `pid` - The probe child.
///
/// # Errors
/// The errno of `PTRACE_SEIZE`.
fn seize(pid: i32) -> Result<(), i32> {
    if unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0usize, 0usize) } < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

/// Builds the message for a host where no plan reaches a child.
///
/// # Arguments
/// * `plain` - The trial without a user namespace, if it ran.
/// * `namespaced` - The trial inside a user namespace, if it ran.
///
/// # Returns
/// A message naming the refusals and the Yama setting.
fn refusal(plain: Option<&Trial>, namespaced: Option<&Trial>) -> String {
    let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| format!("kernel.yama.ptrace_scope is {}", s.trim()))
        .unwrap_or_else(|_| "Yama is not present".into());
    let mut msg = String::from("cannot reach the guest's memory: ");
    if let Some(t) = plain {
        let e = t.memory.err().unwrap_or(libc::EPERM);
        msg.push_str(&format!(
            "process_vm_readv and /proc/<pid>/mem are refused for a child ({})",
            strerror(e)
        ));
    }
    match namespaced {
        Some(t) => {
            let e = t.memory.err().unwrap_or(libc::EPERM);
            msg.push_str(&format!(
                "{}a user namespace did not help ({})",
                if plain.is_some() { ", and " } else { "" },
                strerror(e)
            ));
        }
        None if std::env::var_os("PROOT_USERNS").is_some_and(|v| v == "0") => {
            msg.push_str(", and PROOT_USERNS=0 rules out a user namespace")
        }
        None => {}
    }
    msg.push_str(&format!(
        "; {scope}, and proot-next needs either CAP_SYS_PTRACE, a ptrace_scope of 0 or 1, or unprivileged user namespaces"
    ));
    if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        msg.push_str(" (PROOT_GUEST_STUB=0 rules out the guest-stub mode, which needs none of them)");
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_reaches_a_child_or_explains_why_not() {
        match probe(true, None) {
            Ok(a) => {
                assert!(!a.trap_mode);
                if a.userns.is_none() {
                    assert!(read_marker(std::process::id() as i32).is_ok());
                }
            }
            Err(msg) => assert!(msg.contains("ptrace_scope") || msg.contains("Yama")),
        }
    }

    /// The guest stub is taken where nothing else reaches a child, anywhere
    /// when forced, and never when ruled out.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn the_guest_stub_is_the_last_resort_when_asked_for() {
        let a = probe(true, Some(false)).expect("the guest stub needs no access");
        assert_eq!(a.trap_mode, probe(true, None).is_err());
        assert!(probe(true, Some(true)).unwrap().trap_mode);
    }

    #[test]
    fn identity_mapping_names_the_callers_ids() {
        let ns = UserNs::identity();
        let uid = unsafe { libc::getuid() };
        assert_eq!(ns.uid_map.to_bytes(), format!("{uid} {uid} 1").as_bytes());
    }
}
