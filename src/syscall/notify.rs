//! Handlers for syscalls answered through seccomp user notification.
//!
//! Each handler reads its path arguments out of the tracee, translates them
//! into the guest filesystem view, performs the real syscall in the
//! supervisor, and answers with a value, an error, or an injected
//! descriptor.  The kernel never sees an untranslated guest path for the
//! syscalls routed here.
//!
//! Every notification is answered exactly once.  After tracee memory has been
//! read and before anything irreversible happens, the notification id is
//! re-validated; a stale id (the tracee died or was interrupted by a signal)
//! is dropped silently.

use crate::abi::{Abi, Variant};
use crate::fs::Fs;
use crate::fs::translate::{detranslate_path, guest_cwd, read_link, translate_path};
use crate::note;
use crate::seccomp::notify::{reply, reply_continue, reply_fd, still_valid};
use crate::state::{Ctx, View};
use crate::sys::{Errno, Result, SeccompNotif, check};
use crate::syscall::direct;
use crate::syscall::nr::*;
use std::cell::OnceCell;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

/// Sentinel errno meaning "the notification is stale, do not answer".
const DROPPED: Errno = -1;

/// Largest extended attribute value or list we shuttle through.
const XATTR_MAX: usize = 65536;

/// `open(2)` flags that imply the caller intends to modify the file.
///
/// `O_TMPFILE` is deliberately absent: its value includes the `O_DIRECTORY`
/// bit, so testing for it would flag every `opendir`, and it always comes
/// with `O_WRONLY` or `O_RDWR` anyway.
const WRITE_INTENT: i64 =
    (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as i64;

/// `fchmodat2(2)` is 452 on every architecture; the libc crate lacks it for aarch64.
const SYS_FCHMODAT2_HOST: libc::c_long = 452;

/// `IN_DONT_FOLLOW` for `inotify_add_watch(2)`.
const IN_DONT_FOLLOW: u64 = 0x0200_0000;

/// How a handler wants the notification answered.
pub(crate) enum Outcome {
    /// Plain return value or errno.
    Value(Result<i64>),
    /// Install this supervisor descriptor into the tracee and return its number.
    Fd { fd: i32, cloexec: bool },
    /// Let the kernel run the syscall untouched.
    Continue,
    /// The handler answered the notification itself.
    Replied,
}

/// One notification plus the shared state needed to serve it.
pub(crate) struct Req<'a> {
    pub ctx: &'a Ctx,
    pub listener: i32,
    pub id: u64,
    pub pid: u32,
    pub args: [u64; 6],
    /// Syscall number as the tracee issued it, in its own ABI.
    pub raw_nr: i32,
    /// ABI the request came through; 32-bit pointers are already zero-extended.
    pub abi: Abi,
    /// How an i386 request differs from the x86_64 number it was mapped to.
    pub variant: Variant,
    /// The caller's view, looked up once per request.
    view: OnceCell<Arc<View>>,
}

impl<'a> Req<'a> {
    pub fn arg(&self, i: usize) -> u64 {
        self.args[i]
    }

    /// The view the calling process lives in.
    pub fn view(&self) -> &View {
        self.view.get_or_init(|| self.ctx.view(self.pid as i32))
    }

    /// The calling process's filesystem view.
    pub fn fs(&self) -> &Fs {
        &self.view().fs
    }

    fn arg_i64(&self, i: usize) -> i64 {
        self.args[i] as i64
    }

    fn dirfd(&self, i: usize) -> i32 {
        self.args[i] as i32
    }

    /// Thread-group id of the calling thread.
    pub fn tgid(&self) -> i32 {
        self.ctx.tgid(self.pid as i32)
    }

    /// Reads the NUL-terminated path in argument `i`, rewriting `/proc/self`
    /// and `/proc/thread-self` to the tracee's own entries since the
    /// supervisor would otherwise see its own.
    pub fn path(&self, i: usize) -> Result<Vec<u8>> {
        let raw = self.ctx.mem.read_cstr(self.pid, self.arg(i))?;
        Ok(rewrite_proc_self(&raw, self.pid))
    }

    /// Translates `path` relative to `dirfd` into a host path.
    pub fn translate(&self, dirfd: i32, path: &[u8], deref_final: bool) -> Result<Vec<u8>> {
        let host = translate_path(self.fs(), self.pid, dirfd, path, deref_final)?;
        note!(
            self.ctx,
            2,
            "pid {} {} -> {}",
            self.pid,
            String::from_utf8_lossy(path),
            String::from_utf8_lossy(&host)
        );
        Ok(host)
    }

    /// Re-validates the notification; `Err(DROPPED)` when the tracee is gone.
    pub fn valid(&self) -> Result<()> {
        if still_valid(self.listener, self.id) {
            Ok(())
        } else {
            Err(DROPPED)
        }
    }

    /// Refuses with `EROFS` when `host` lies under a read-only binding.
    pub fn check_writable(&self, host: &[u8]) -> Result<()> {
        let guest = detranslate_path(self.fs(), host);
        match self.fs().binding_for_guest(&guest) {
            Some(b) if b.read_only => Err(libc::EROFS),
            _ => Ok(()),
        }
    }

    pub fn write(&self, addr: u64, data: &[u8]) -> Result<()> {
        self.ctx.mem.write(self.pid, addr, data)
    }

    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.ctx.mem.read(self.pid, addr, &mut buf)?;
        if n != len {
            return Err(libc::EFAULT);
        }
        Ok(buf)
    }
}

/// Serves one notification.  Always answers exactly once, unless the
/// notification turned out to be stale.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `listener` - Listener descriptor to answer on.
/// * `req` - The notification as received.
pub fn handle(ctx: &Ctx, listener: i32, req: &SeccompNotif) {
    let Some(abi) = Abi::from_audit(req.data.arch) else {
        reply(listener, req.id, Err(libc::ENOSYS));
        return;
    };
    let raw_nr = req.data.nr as i64;
    let hello = match abi {
        Abi::X86_64 | Abi::Aarch64 => crate::guest_stub::layout::HELLO64,
        Abi::I386 | Abi::Arm => crate::guest_stub::layout::HELLO32,
    };
    if ctx.trap_mode() && raw_nr == hello && req.data.args[0] == crate::guest_stub::layout::HELLO_MARK {
        direct::hello(ctx, req.pid);
        reply(listener, req.id, Ok(0));
        return;
    }
    let (nr, variant) = if ctx.no_ptrace && abi.socketcall_nr() == Some(raw_nr) {
        (SOCKETCALL, Variant::Same)
    } else {
        match abi.to_canonical(raw_nr) {
            Some(x) => x,
            None => {
                // Not a syscall we serve for this ABI: let the kernel run it.
                reply_continue(listener, req.id);
                return;
            }
        }
    };
    let r = Req {
        ctx,
        listener,
        id: req.id,
        pid: req.pid,
        args: req.data.args,
        raw_nr: req.data.nr,
        abi,
        variant,
        view: OnceCell::new(),
    };
    match dispatch(&r, nr) {
        Ok(Outcome::Value(v)) => reply(listener, req.id, v),
        Ok(Outcome::Fd { fd, cloexec }) => reply_fd(listener, req.id, fd, cloexec),
        Ok(Outcome::Continue) => reply_continue(listener, req.id),
        Ok(Outcome::Replied) => {}
        Err(DROPPED) => {}
        Err(e) => {
            note!(
                ctx,
                2,
                "pid {} {}: {}",
                req.pid,
                name(nr),
                crate::sys::strerror(e)
            );
            reply(listener, req.id, Err(e));
        }
    }
}

/// Routes a syscall number to its handler.
fn dispatch(r: &Req, nr: i64) -> Result<Outcome> {
    if let Some(o) = direct::shim_passthrough(r, nr) {
        return Ok(o);
    }
    if r.ctx.no_ptrace {
        if nr == SOCKETCALL {
            return direct::do_socketcall(r);
        }
        if let Some(o) = direct::dispatch(r, nr) {
            return o;
        }
    }
    match nr {
        OPEN => do_open(
            r,
            libc::AT_FDCWD,
            &r.path(0)?,
            r.arg(0),
            r.arg_i64(1),
            r.arg_i64(2),
        ),
        CREAT => {
            let flags = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as i64;
            do_open(r, libc::AT_FDCWD, &r.path(0)?, r.arg(0), flags, r.arg_i64(1))
        }
        OPENAT => do_open(r, r.dirfd(0), &r.path(1)?, r.arg(1), r.arg_i64(2), r.arg_i64(3)),
        OPENAT2 => do_openat2(r),
        STAT => do_stat(r, libc::AT_FDCWD, &r.path(0)?, r.arg(1), 0),
        LSTAT => do_stat(
            r,
            libc::AT_FDCWD,
            &r.path(0)?,
            r.arg(1),
            libc::AT_SYMLINK_NOFOLLOW as i64,
        ),
        NEWFSTATAT => do_stat(r, r.dirfd(0), &r.path(1)?, r.arg(2), r.arg_i64(3)),
        STATX => do_statx(r),
        STATFS => do_statfs(r),
        ACCESS => do_access(r, libc::AT_FDCWD, &r.path(0)?, r.arg_i64(1), 0),
        FACCESSAT => do_access(r, r.dirfd(0), &r.path(1)?, r.arg_i64(2), 0),
        FACCESSAT2 => do_access(r, r.dirfd(0), &r.path(1)?, r.arg_i64(2), r.arg_i64(3)),
        READLINK => do_readlink(r, libc::AT_FDCWD, &r.path(0)?, r.arg(1), r.arg(2) as usize),
        READLINKAT => do_readlink(r, r.dirfd(0), &r.path(1)?, r.arg(2), r.arg(3) as usize),
        GETCWD => do_getcwd(r),
        UNAME => do_uname(r),
        // -0: the tracee is root as far as it can tell, with a virtual identity it can drop.
        // A nested view without -0 inside a launch with it is left to the kernel.
        GETUID | GETGID | GETEUID | GETEGID | GETRESUID | GETRESGID | SETUID | SETGID | SETREUID
        | SETREGID | SETRESUID | SETRESGID | SETFSUID | SETFSGID | SETGROUPS | GETGROUPS | CAPSET
        | FCHOWN
            if !r.view().fake_root =>
        {
            Ok(Outcome::Continue)
        }
        GETUID | GETGID | GETEUID | GETEGID | GETRESUID | GETRESGID | SETUID | SETGID | SETREUID
        | SETREGID | SETRESUID | SETRESGID | SETFSUID | SETFSGID => do_identity(r, nr),
        SETGROUPS => do_setgroups(r),
        GETGROUPS => do_getgroups(r),
        CAPSET => Ok(Outcome::Value(Ok(0))),
        FCHOWN => do_fchown(r),
        MKDIR => do_mkdir(r, libc::AT_FDCWD, &r.path(0)?, r.arg_i64(1)),
        MKDIRAT => do_mkdir(r, r.dirfd(0), &r.path(1)?, r.arg_i64(2)),
        RMDIR => do_unlink(r, libc::AT_FDCWD, &r.path(0)?, libc::AT_REMOVEDIR as i64),
        UNLINK => do_unlink(r, libc::AT_FDCWD, &r.path(0)?, 0),
        UNLINKAT => do_unlink(r, r.dirfd(0), &r.path(1)?, r.arg_i64(2)),
        RENAME => do_rename(r, libc::AT_FDCWD, &r.path(0)?, libc::AT_FDCWD, &r.path(1)?, 0),
        RENAMEAT => do_rename(r, r.dirfd(0), &r.path(1)?, r.dirfd(2), &r.path(3)?, 0),
        RENAMEAT2 => do_rename(r, r.dirfd(0), &r.path(1)?, r.dirfd(2), &r.path(3)?, r.arg_i64(4)),
        LINK => do_link(r, libc::AT_FDCWD, &r.path(0)?, libc::AT_FDCWD, &r.path(1)?, 0),
        LINKAT => do_link(r, r.dirfd(0), &r.path(1)?, r.dirfd(2), &r.path(3)?, r.arg_i64(4)),
        SYMLINK => do_symlink(r, &r.path(0)?, libc::AT_FDCWD, &r.path(1)?),
        SYMLINKAT => do_symlink(r, &r.path(0)?, r.dirfd(1), &r.path(2)?),
        CHMOD => do_chmod(r, libc::AT_FDCWD, &r.path(0)?, r.arg_i64(1), 0),
        FCHMODAT => do_chmod(r, r.dirfd(0), &r.path(1)?, r.arg_i64(2), 0),
        FCHMODAT2 => do_chmod(r, r.dirfd(0), &r.path(1)?, r.arg_i64(2), r.arg_i64(3)),
        CHOWN => do_chown(r, libc::AT_FDCWD, &r.path(0)?, r.arg_i64(1), r.arg_i64(2), 0),
        LCHOWN => {
            let flags = libc::AT_SYMLINK_NOFOLLOW as i64;
            do_chown(r, libc::AT_FDCWD, &r.path(0)?, r.arg_i64(1), r.arg_i64(2), flags)
        }
        FCHOWNAT => do_chown(
            r,
            r.dirfd(0),
            &r.path(1)?,
            r.arg_i64(2),
            r.arg_i64(3),
            r.arg_i64(4),
        ),
        TRUNCATE => do_truncate(r),
        MKNOD => do_mknod(r, libc::AT_FDCWD, &r.path(0)?, r.arg_i64(1), r.arg_i64(2)),
        MKNODAT => do_mknod(r, r.dirfd(0), &r.path(1)?, r.arg_i64(2), r.arg_i64(3)),
        UTIME => do_utime(r),
        UTIMES => do_utimes(r, libc::AT_FDCWD, 0, 1),
        FUTIMESAT => do_utimes(r, r.dirfd(0), 1, 2),
        UTIMENSAT => do_utimensat(r),
        SETXATTR | LSETXATTR => do_setxattr(r, nr == LSETXATTR),
        GETXATTR | LGETXATTR => do_getxattr(r, nr == LGETXATTR),
        LISTXATTR | LLISTXATTR => do_listxattr(r, nr == LLISTXATTR),
        REMOVEXATTR | LREMOVEXATTR => do_removexattr(r, nr == LREMOVEXATTR),
        INOTIFY_ADD_WATCH => do_inotify_add_watch(r),
        CLONE3 => direct::do_clone(r, CLONE3),
        NAME_TO_HANDLE_AT => Ok(Outcome::Value(Err(libc::EOPNOTSUPP))),
        _ => Ok(Outcome::Continue),
    }
}

// ---- helpers ---------------------------------------------------------------

/// Builds a C string from path bytes.
fn cstr(path: &[u8]) -> Result<CString> {
    CString::new(path.to_vec()).map_err(|_| libc::EINVAL)
}

/// Replaces a leading `/proc/self` or `/proc/thread-self` with the tracee's pid.
fn rewrite_proc_self(path: &[u8], pid: u32) -> Vec<u8> {
    let rules: [(&[u8], String); 2] = [
        (b"/proc/thread-self", format!("/proc/{pid}/task/{pid}")),
        (b"/proc/self", format!("/proc/{pid}")),
    ];
    for (prefix, repl) in rules {
        if path.starts_with(prefix) && (path.len() == prefix.len() || path[prefix.len()] == b'/') {
            let mut out = repl.into_bytes();
            out.extend_from_slice(&path[prefix.len()..]);
            return out;
        }
    }
    path.to_vec()
}

/// Lexically cleans an absolute path (no symlink resolution).
fn lexical_clean(path: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for comp in path.split(|&c| c == b'/') {
        match comp {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let mut out = Vec::with_capacity(path.len() + 1);
    for p in &parts {
        out.push(b'/');
        out.extend_from_slice(p);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

/// Classifies a guest path as a `/proc/<pid>/...` magic link.
///
/// # Returns
/// `Some((pid, true))` for an `exe` link, `Some((pid, false))` for `cwd`,
/// `root`, `fd/N` or `map_files/X`, `None` for anything else.
fn proc_magic_link(guest: &[u8]) -> Option<(i32, bool)> {
    let rest = guest.strip_prefix(b"/proc/")?;
    let mut parts = rest.split(|&c| c == b'/');
    let pid: i32 = std::str::from_utf8(parts.next()?).ok()?.parse().ok()?;
    let mut tail: Vec<&[u8]> = parts.collect();
    if tail.len() >= 3 && tail[0] == b"task" {
        tail.drain(0..2);
    }
    match tail.as_slice() {
        [b"exe"] => Some((pid, true)),
        [b"cwd"] | [b"root"] => Some((pid, false)),
        [b"fd", _] | [b"map_files", _] => Some((pid, false)),
        _ => None,
    }
}

/// Whether `host` names a FIFO; opening one may block the supervisor.
fn is_fifo(host: &CString) -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(host.as_ptr(), &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFIFO }
}

/// Reads a `struct timeval[2]` from the tracee and converts it to 64-bit timespecs.
///
/// An i386 caller (`Variant::Time32`) supplies 32-bit seconds and microseconds.
fn timevals_to_timespecs(r: &Req, addr: u64) -> Result<Option<[u8; 32]>> {
    if addr == 0 {
        return Ok(None);
    }
    let (word, read_word): (usize, fn(&[u8]) -> i64) = match r.variant {
        Variant::Time32 => (4, |b| i32::from_ne_bytes(b.try_into().unwrap()) as i64),
        _ => (8, |b| i64::from_ne_bytes(b.try_into().unwrap())),
    };
    let tv = r.read(addr, 4 * word)?;
    let mut ts = [0u8; 32];
    for i in 0..2 {
        let sec = read_word(&tv[i * 2 * word..i * 2 * word + word]);
        let usec = read_word(&tv[i * 2 * word + word..i * 2 * word + 2 * word]);
        ts[i * 16..i * 16 + 8].copy_from_slice(&sec.to_ne_bytes());
        ts[i * 16 + 8..i * 16 + 16].copy_from_slice(&(usec * 1000).to_ne_bytes());
    }
    Ok(Some(ts))
}

/// Reads a `struct timespec[2]` from the tracee, widening 32-bit fields for i386 `utimensat`.
///
/// `UTIME_NOW`/`UTIME_OMIT` are positive values below 2^30 and survive the widening.
fn timespecs_from_tracee(r: &Req, addr: u64) -> Result<Option<[u8; 32]>> {
    if addr == 0 {
        return Ok(None);
    }
    if r.variant != Variant::Timespec32 {
        return Ok(Some(r.read(addr, 32)?.try_into().map_err(|_| libc::EFAULT)?));
    }
    let raw = r.read(addr, 16)?;
    let mut ts = [0u8; 32];
    for i in 0..4 {
        let v = i32::from_ne_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap()) as i64;
        ts[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
    }
    Ok(Some(ts))
}

/// Runs `utimensat(2)` on a host path with an optional timespec pair.
fn host_utimensat(host: &[u8], times: Option<&[u8; 32]>, flags: i64) -> Result<i64> {
    let c = cstr(host)?;
    let tp = times.map(|t| t.as_ptr()).unwrap_or(std::ptr::null());
    check(unsafe { libc::syscall(libc::SYS_utimensat, libc::AT_FDCWD, c.as_ptr(), tp, flags) })
}

/// Deref policy derived from `AT_SYMLINK_NOFOLLOW`.
fn follow(flags: i64) -> bool {
    flags & libc::AT_SYMLINK_NOFOLLOW as i64 == 0
}

/// Whether a path argument is empty with `AT_EMPTY_PATH`, i.e. targets the fd itself.
fn targets_fd(path: &[u8], flags: i64) -> bool {
    path.is_empty() && flags & libc::AT_EMPTY_PATH as i64 != 0
}

// ---- open family -----------------------------------------------------------

/// `open`/`creat`/`openat`: open in the supervisor and inject the descriptor.
///
/// `path_addr` is where the path string lives in the tracee, for the
/// in-place rewrite an `O_PATH` open needs without ptrace.
fn do_open(r: &Req, dirfd: i32, path: &[u8], path_addr: u64, flags: i64, mode: i64) -> Result<Outcome> {
    let flags = r.abi.open_flags_to_host(flags);
    if flags & libc::O_PATH as i64 != 0 && r.ctx.no_ptrace {
        return direct::do_open_path(r, dirfd, path, path_addr, flags);
    }
    let o_excl_create = flags & libc::O_CREAT as i64 != 0 && flags & libc::O_EXCL as i64 != 0;
    let deref = flags & libc::O_NOFOLLOW as i64 == 0 && !o_excl_create;
    let host = r.translate(dirfd, path, deref)?;
    r.valid()?;
    if flags & WRITE_INTENT != 0 {
        r.check_writable(&host)?;
    }
    let c = cstr(&host)?;
    if host == path && is_fifo(&c) {
        // Identity path: let the tracee block on the FIFO itself rather than us.
        return Ok(Outcome::Continue);
    }
    if flags & WRITE_INTENT == 0
        && let Some(fd) =
            fake_proc_status(&host, fake_ids_for_status(r, &host))?.or(fake_proc_cmdline(r.ctx, &host)?)
    {
        return Ok(Outcome::Fd {
            fd,
            cloexec: flags & libc::O_CLOEXEC as i64 != 0,
        });
    }
    let fd = check(unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            c.as_ptr(),
            flags | libc::O_CLOEXEC as i64,
            mode,
        )
    })?;
    Ok(Outcome::Fd {
        fd: fd as i32,
        cloexec: flags & libc::O_CLOEXEC as i64 != 0,
    })
}

/// Serves `/proc/<pid>/status` with our own pid hidden from `TracerPid` and,
/// under `-0`, root in the `Uid`/`Gid` lines.
///
/// Programs read that field to decide whether a debugger is attached and may
/// change behaviour or trap when it is.  A transparent supervisor must not
/// show up there, so the file is copied into a memfd with the field zeroed.
///
/// # Arguments
/// * `host` - Translated host path about to be opened.
///
/// # Returns
/// A descriptor on the rewritten copy, or `None` when the path is not a status file.
fn fake_proc_status(host: &[u8], fake_root: Option<crate::procs::Ids>) -> Result<Option<i32>> {
    let Some(rest) = host.strip_prefix(b"/proc/") else {
        return Ok(None);
    };
    let Some(rest) = rest.strip_suffix(b"/status") else {
        return Ok(None);
    };
    let is_num = |b: &[u8]| !b.is_empty() && b.iter().all(|c| c.is_ascii_digit());
    let ok = match rest.splitn(3, |&c| c == b'/').collect::<Vec<_>>().as_slice() {
        [pid] => is_num(pid),
        [pid, b"task", tid] => is_num(pid) && is_num(tid),
        _ => false,
    };
    if !ok {
        return Ok(None);
    }
    let text = std::fs::read(std::ffi::OsStr::from_bytes(host))
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    let me = format!("TracerPid:\t{}\n", std::process::id()).into_bytes();
    let mut out = Vec::with_capacity(text.len());
    for line in text.split_inclusive(|&c| c == b'\n') {
        if line == me.as_slice() {
            out.extend_from_slice(b"TracerPid:\t0\n");
        } else if let Some(ids) = fake_root
            && (line.starts_with(b"Uid:") || line.starts_with(b"Gid:"))
        {
            let (a, b, c, d) = if line.starts_with(b"Uid:") {
                (ids.ruid, ids.euid, ids.suid, ids.fsuid)
            } else {
                (ids.rgid, ids.egid, ids.sgid, ids.fsgid)
            };
            out.extend_from_slice(&line[..4]);
            out.extend_from_slice(format!("\t{a}\t{b}\t{c}\t{d}\n").as_bytes());
        } else {
            out.extend_from_slice(line);
        }
    }
    Ok(Some(readonly_memfd("proc-status", &out)?))
}

/// Serves `/proc/<pid>/cmdline` as the process was started, without the
/// loader the exec was retargeted at.
///
/// The kernel's file names the loader alias, `--argv0`, the name and the
/// program before the real arguments; `ps`, `pgrep -f` and programs reading
/// their own command line expect the argv the tracee passed.  A process in
/// the no-ptrace trampoline, or one that rewrote its own argv, is left as is.
///
/// In the guest-stub restricted mode no loader is exec'd, so the kernel's
/// file is the vector the program was exec'd with, which is right but for a
/// `#!` script: there the interpreter, its argument and the script recorded
/// at the exec take the place of `argv[0]`, as the kernel would show them.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `host` - Translated host path about to be opened.
///
/// # Returns
/// A descriptor on the rewritten copy, or `None` when the path is not a
/// cmdline file or the file carries no loader prefix.
///
/// # Errors
/// An errno when the file cannot be read or the copy made.
fn fake_proc_cmdline(ctx: &Ctx, host: &[u8]) -> Result<Option<i32>> {
    let Some(rest) = host.strip_prefix(b"/proc/") else {
        return Ok(None);
    };
    let Some(rest) = rest.strip_suffix(b"/cmdline") else {
        return Ok(None);
    };
    let is_num = |b: &[u8]| !b.is_empty() && b.iter().all(|c| c.is_ascii_digit());
    let ok = match rest.splitn(3, |&c| c == b'/').collect::<Vec<_>>().as_slice() {
        [pid] => is_num(pid),
        [pid, b"task", tid] => is_num(pid) && is_num(tid),
        _ => false,
    };
    if !ok {
        return Ok(None);
    }
    let text = std::fs::read(std::ffi::OsStr::from_bytes(host))
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    let args: Vec<&[u8]> = text.split(|&c| c == 0).collect();
    if ctx.trap_mode() {
        let pid: i32 = std::str::from_utf8(rest.split(|&c| c == b'/').next().unwrap_or_default())
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let Some(prefix) = ctx.procs.info(pid).cmdline_prefix.filter(|_| !text.is_empty()) else {
            return Ok(None);
        };
        let out: Vec<u8> = prefix
            .iter()
            .map(|a| a.as_slice())
            .chain(args.iter().skip(1).copied())
            .collect::<Vec<_>>()
            .join(&0u8);
        return Ok(Some(readonly_memfd("proc-cmdline", &out)?));
    }
    let alias_dir = crate::exec::alias_dir();
    let in_alias = args
        .first()
        .is_some_and(|a| crate::fs::binding::is_prefix(alias_dir.as_os_str().as_bytes(), a));
    if !in_alias {
        return Ok(None);
    }
    let tail: Vec<&[u8]> = match args.as_slice() {
        [_, b"--argv0", argv0, _, rest @ ..] => std::iter::once(*argv0).chain(rest.iter().copied()).collect(),
        [_, prog, rest @ ..] => std::iter::once(*prog).chain(rest.iter().copied()).collect(),
        _ => return Ok(None),
    };
    let out: Vec<u8> = tail.join(&0u8);
    Ok(Some(readonly_memfd("proc-cmdline", &out)?))
}

/// A read-only descriptor on a memfd holding `content`.
///
/// The caller asked for a read-only file and a memfd is read-write, so the
/// writable descriptor is re-opened read-only through `/proc/self/fd` and
/// dropped, which keeps `F_GETFL` truthful.
///
/// # Arguments
/// * `name` - Name of the memfd, for diagnostics.
/// * `content` - Bytes the file holds.
fn readonly_memfd(name: &str, content: &[u8]) -> Result<i32> {
    let name = CString::new(name).unwrap();
    let fd =
        check(unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), libc::MFD_CLOEXEC) })? as i32;
    let mut off = 0;
    while off < content.len() {
        let n = unsafe { libc::write(fd, content[off..].as_ptr() as *const _, content.len() - off) };
        if n <= 0 {
            unsafe { libc::close(fd) };
            return Err(crate::sys::errno());
        }
        off += n as usize;
    }
    let link = CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let ro = unsafe { libc::open(link.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    unsafe { libc::close(fd) };
    if ro < 0 {
        return Err(crate::sys::errno());
    }
    Ok(ro)
}

/// `openat2`: like `openat` with a `struct open_how`.
fn do_openat2(r: &Req) -> Result<Outcome> {
    let path = r.path(1)?;
    let size = (r.arg(3) as usize).min(24);
    let mut how = [0u8; 24];
    if size > 0 {
        how[..size].copy_from_slice(&r.read(r.arg(2), size)?);
    }
    let flags = r
        .abi
        .open_flags_to_host(u64::from_ne_bytes(how[0..8].try_into().unwrap()) as i64);
    how[0..8].copy_from_slice(&(flags as u64).to_ne_bytes());
    if flags & libc::O_PATH as i64 != 0 {
        // An O_PATH descriptor cannot be injected; ENOSYS makes callers fall
        // back to openat(2), which the filter routes to the ptrace tier.
        return Err(libc::ENOSYS);
    }
    let o_excl_create = flags & libc::O_CREAT as i64 != 0 && flags & libc::O_EXCL as i64 != 0;
    let deref = flags & libc::O_NOFOLLOW as i64 == 0 && !o_excl_create;
    let host = r.translate(r.dirfd(0), &path, deref)?;
    r.valid()?;
    if flags & WRITE_INTENT != 0 {
        r.check_writable(&host)?;
    }
    let c = cstr(&host)?;
    let fd = check(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c.as_ptr(),
            how.as_ptr(),
            24usize,
        )
    })?;
    Ok(Outcome::Fd {
        fd: fd as i32,
        cloexec: flags & libc::O_CLOEXEC as i64 != 0,
    })
}

// ---- stat family -----------------------------------------------------------

/// `stat`/`lstat`/`newfstatat`: fill the host's `struct stat` in the tracee
/// (144 bytes on x86_64, 128 on aarch64), converted for i386 callers.
fn do_stat(r: &Req, dirfd: i32, path: &[u8], buf: u64, flags: i64) -> Result<Outcome> {
    if targets_fd(path, flags) {
        return Ok(Outcome::Continue);
    }
    let host = r.translate(dirfd, path, follow(flags))?;
    r.valid()?;
    let c = cstr(&host)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let host_flags = flags & (libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT) as i64;
    check(unsafe {
        libc::syscall(
            libc::SYS_newfstatat,
            libc::AT_FDCWD,
            c.as_ptr(),
            &mut st as *mut libc::stat,
            host_flags,
        )
    })?;
    fake_owner(r, &mut st.st_uid, &mut st.st_gid);
    match r.variant {
        Variant::Stat64 => r.write(buf, &crate::abi::stat_to_stat64(&st))?,
        Variant::ArmStat64 => r.write(buf, &crate::abi::stat_to_arm_stat64(&st))?,
        Variant::OldStat => r.write(buf, &crate::abi::stat_to_old_stat(&st)?)?,
        _ => r.write(buf, unsafe {
            std::slice::from_raw_parts(
                &st as *const libc::stat as *const u8,
                std::mem::size_of::<libc::stat>(),
            )
        })?,
    }
    Ok(Outcome::Value(Ok(0)))
}

/// `statx`: fill a 256-byte `struct statx` in the tracee.
fn do_statx(r: &Req) -> Result<Outcome> {
    let flags = r.arg_i64(2);
    if r.arg(1) == 0 {
        return Ok(Outcome::Continue);
    }
    let path = r.path(1)?;
    if targets_fd(&path, flags) {
        return Ok(Outcome::Continue);
    }
    let host = r.translate(r.dirfd(0), &path, follow(flags))?;
    r.valid()?;
    let c = cstr(&host)?;
    let mut st = [0u8; 256];
    let host_flags = flags & !(libc::AT_EMPTY_PATH as i64);
    check(unsafe {
        libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            c.as_ptr(),
            host_flags,
            r.arg(3) as u32,
            st.as_mut_ptr(),
        )
    })?;
    let (mut uid, mut gid) = (
        u32::from_ne_bytes(st[20..24].try_into().unwrap()),
        u32::from_ne_bytes(st[24..28].try_into().unwrap()),
    );
    fake_owner(r, &mut uid, &mut gid);
    st[20..24].copy_from_slice(&uid.to_ne_bytes());
    st[24..28].copy_from_slice(&gid.to_ne_bytes());
    r.write(r.arg(4), &st)?;
    Ok(Outcome::Value(Ok(0)))
}

/// `statfs`: fill a 120-byte `struct statfs` in the tracee.
fn do_statfs(r: &Req) -> Result<Outcome> {
    let host = r.translate(libc::AT_FDCWD, &r.path(0)?, true)?;
    r.valid()?;
    let c = cstr(&host)?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    check(unsafe { libc::syscall(libc::SYS_statfs, c.as_ptr(), &mut st as *mut libc::statfs) })?;
    match r.variant {
        // statfs64(path, size, buf)
        Variant::Statfs64 => r.write(r.arg(2), &crate::abi::statfs_to_statfs64(&st))?,
        Variant::OldStatfs => r.write(r.arg(1), &crate::abi::statfs_to_old_statfs(&st))?,
        _ => r.write(r.arg(1), unsafe {
            std::slice::from_raw_parts(
                &st as *const libc::statfs as *const u8,
                std::mem::size_of::<libc::statfs>(),
            )
        })?,
    }
    Ok(Outcome::Value(Ok(0)))
}

/// `access`/`faccessat`/`faccessat2`.
fn do_access(r: &Req, dirfd: i32, path: &[u8], mode: i64, flags: i64) -> Result<Outcome> {
    let host = r.translate(dirfd, path, follow(flags))?;
    r.valid()?;
    let c = cstr(&host)?;
    let rc = check(unsafe { libc::syscall(libc::SYS_faccessat2, libc::AT_FDCWD, c.as_ptr(), mode, flags) });
    Ok(Outcome::Value(rc))
}

// ---- links and names ---------------------------------------------------------

/// `readlink`/`readlinkat`: raw target, except `/proc` magic links are detranslated.
fn do_readlink(r: &Req, dirfd: i32, path: &[u8], buf: u64, bufsiz: usize) -> Result<Outcome> {
    let host = r.translate(dirfd, path, false)?;
    r.valid()?;
    let guest = lexical_clean(&detranslate_path(r.fs(), &host));
    let target = match proc_magic_link(&guest) {
        Some((pid, true)) => match r.ctx.tracee(pid).exe_guest {
            Some(exe) => exe,
            None => detranslate_path(r.fs(), &read_link(&host)?),
        },
        Some((pid, false)) => match r.fs().virtual_cwd(pid).filter(|_| guest.ends_with(b"/cwd")) {
            Some(cwd) => cwd,
            None => detranslate_path(r.fs(), &read_link(&host)?),
        },
        None => read_link(&host)?,
    };
    let len = target.len().min(bufsiz);
    if len > 0 {
        r.write(buf, &target[..len])?;
    }
    Ok(Outcome::Value(Ok(len as i64)))
}

/// `getcwd`: the tracee's cwd as a guest path, NUL-terminated.
fn do_getcwd(r: &Req) -> Result<Outcome> {
    let mut cwd = guest_cwd(r.fs(), r.pid)?;
    r.valid()?;
    cwd.push(0);
    if cwd.len() > r.arg(1) as usize {
        return Err(libc::ERANGE);
    }
    r.write(r.arg(0), &cwd)?;
    Ok(Outcome::Value(Ok(cwd.len() as i64)))
}

/// `uname`: the host's answer with `release` and/or `nodename` replaced.
fn do_uname(r: &Req) -> Result<Outcome> {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    check(unsafe { libc::uname(&mut u) } as i64)?;
    let mut bytes = [0u8; 390];
    let src = unsafe { std::slice::from_raw_parts(&u as *const _ as *const u8, 390) };
    bytes.copy_from_slice(src);
    if let Some(rel) = &r.view().kernel_release {
        let n = rel.len().min(64);
        bytes[130..195].fill(0);
        bytes[130..130 + n].copy_from_slice(&rel[..n]);
    }
    if let Some(host) = &r.view().hostname {
        // utsname.nodename sits at offset 65.
        let n = host.len().min(64);
        bytes[65..130].fill(0);
        bytes[65..65 + n].copy_from_slice(&host[..n]);
    }
    r.valid()?;
    r.write(r.arg(0), &bytes)?;
    Ok(Outcome::Value(Ok(0)))
}

/// The identity syscalls under `-0`, over the process's virtual [`crate::procs::Ids`].
///
/// Getters report the virtual ids.  Setters follow the kernel's rules: with a
/// virtual effective id of 0 any value is accepted, otherwise only the real,
/// effective and saved ids may be chosen; a 32-bit `-1` leaves a field alone.
fn do_identity(r: &Req, nr: i64) -> Result<Outcome> {
    let tgid = r.tgid();
    let mut ids = r.ctx.ids(tgid);
    let id16 = r.variant == Variant::Id16;
    let write_three = |a: u32, b: u32, c: u32| -> Result<()> {
        for (i, v) in [a, b, c].into_iter().enumerate() {
            if r.arg(i) != 0 {
                if id16 {
                    r.write(r.arg(i), &(v as u16).to_ne_bytes())?
                } else {
                    r.write(r.arg(i), &v.to_ne_bytes())?
                }
            }
        }
        Ok(())
    };
    let arg = |i: usize| r.arg(i) as u32;
    let keep = |v: u32| v == u32::MAX;
    let allowed = |v: u32, (a, b, c): (u32, u32, u32)| v == a || v == b || v == c;
    let uids = (ids.ruid, ids.euid, ids.suid);
    let gids = (ids.rgid, ids.egid, ids.sgid);
    let root = ids.euid == 0;
    let rc: i64 = match nr {
        GETUID => ids.ruid as i64,
        GETEUID => ids.euid as i64,
        GETGID => ids.rgid as i64,
        GETEGID => ids.egid as i64,
        GETRESUID => {
            write_three(ids.ruid, ids.euid, ids.suid)?;
            0
        }
        GETRESGID => {
            write_three(ids.rgid, ids.egid, ids.sgid)?;
            0
        }
        SETUID => {
            let v = arg(0);
            if root {
                (ids.ruid, ids.euid, ids.suid) = (v, v, v);
            } else if allowed(v, uids) {
                ids.euid = v;
            } else {
                return Err(libc::EPERM);
            }
            ids.fsuid = ids.euid;
            0
        }
        SETGID => {
            let v = arg(0);
            if root {
                (ids.rgid, ids.egid, ids.sgid) = (v, v, v);
            } else if allowed(v, gids) {
                ids.egid = v;
            } else {
                return Err(libc::EPERM);
            }
            ids.fsgid = ids.egid;
            0
        }
        SETREUID | SETRESUID => {
            let (nr_, ne, ns) = if nr == SETREUID {
                (arg(0), arg(1), u32::MAX)
            } else {
                (arg(0), arg(1), arg(2))
            };
            for v in [nr_, ne, ns] {
                if !keep(v) && !root && !allowed(v, uids) {
                    return Err(libc::EPERM);
                }
            }
            if !keep(nr_) {
                ids.ruid = nr_;
            }
            if !keep(ne) {
                ids.euid = ne;
            }
            if !keep(ns) {
                ids.suid = ns;
            } else if nr == SETREUID && (!keep(nr_) || (!keep(ne) && ne != uids.0)) {
                ids.suid = ids.euid;
            }
            ids.fsuid = ids.euid;
            0
        }
        SETREGID | SETRESGID => {
            let (ng, ne, ns) = if nr == SETREGID {
                (arg(0), arg(1), u32::MAX)
            } else {
                (arg(0), arg(1), arg(2))
            };
            for v in [ng, ne, ns] {
                if !keep(v) && !root && !allowed(v, gids) {
                    return Err(libc::EPERM);
                }
            }
            if !keep(ng) {
                ids.rgid = ng;
            }
            if !keep(ne) {
                ids.egid = ne;
            }
            if !keep(ns) {
                ids.sgid = ns;
            } else if nr == SETREGID && (!keep(ng) || (!keep(ne) && ne != gids.0)) {
                ids.sgid = ids.egid;
            }
            ids.fsgid = ids.egid;
            0
        }
        SETFSUID => {
            let prev = ids.fsuid;
            let v = arg(0);
            if root || allowed(v, uids) || v == ids.fsuid {
                ids.fsuid = v;
            }
            prev as i64
        }
        SETFSGID => {
            let prev = ids.fsgid;
            let v = arg(0);
            if root || allowed(v, gids) || v == ids.fsgid {
                ids.fsgid = v;
            }
            prev as i64
        }
        _ => return Ok(Outcome::Continue),
    };
    r.ctx.set_ids(tgid, ids);
    Ok(Outcome::Value(Ok(rc)))
}

/// `setgroups(size, list)` under `-0`: recorded for `getgroups`, never applied.
fn do_setgroups(r: &Req) -> Result<Outcome> {
    let tgid = r.tgid();
    if r.ctx.ids(tgid).euid != 0 {
        return Err(libc::EPERM);
    }
    let n = (r.arg(0) as usize).min(65536);
    let width = if r.variant == Variant::Id16 { 2 } else { 4 };
    let raw = if n > 0 {
        r.read(r.arg(1), n * width)?
    } else {
        Vec::new()
    };
    let groups: Vec<u32> = raw
        .chunks_exact(width)
        .map(|c| {
            if width == 2 {
                u16::from_ne_bytes([c[0], c[1]]) as u32
            } else {
                u32::from_ne_bytes(c.try_into().unwrap())
            }
        })
        .collect();
    r.ctx.set_groups(tgid, groups);
    Ok(Outcome::Value(Ok(0)))
}

/// `getgroups(size, list)` under `-0`: the recorded list, or the kernel's when none was set.
fn do_getgroups(r: &Req) -> Result<Outcome> {
    let tgid = r.tgid();
    let Some(groups) = r.ctx.groups(tgid) else {
        return Ok(Outcome::Continue);
    };
    let size = r.arg(0) as usize;
    if size == 0 {
        return Ok(Outcome::Value(Ok(groups.len() as i64)));
    }
    if size < groups.len() {
        return Err(libc::EINVAL);
    }
    let mut out = Vec::with_capacity(groups.len() * 4);
    for g in &groups {
        if r.variant == Variant::Id16 {
            out.extend_from_slice(&(*g as u16).to_ne_bytes())
        } else {
            out.extend_from_slice(&g.to_ne_bytes())
        }
    }
    if !out.is_empty() {
        r.write(r.arg(1), &out)?;
    }
    Ok(Outcome::Value(Ok(groups.len() as i64)))
}

/// `fchown` under `-0`: through the descriptor's `/proc` link; a refusal is forgiven.
fn do_fchown(r: &Req) -> Result<Outcome> {
    let c = cstr(format!("/proc/{}/fd/{}", r.pid, r.arg(0) as i32).as_bytes())?;
    let rc = check(unsafe {
        libc::syscall(
            libc::SYS_fchownat,
            libc::AT_FDCWD,
            c.as_ptr(),
            r.arg_i64(1),
            r.arg_i64(2),
            0,
        )
    });
    Ok(Outcome::Value(forgive_as_root(r, rc)))
}

/// Under `-0`, an ownership or device-node refusal reads as success, like PRoot's fake_id0.
fn forgive_as_root(r: &Req, rc: Result<i64>) -> Result<i64> {
    match rc {
        Err(libc::EPERM) | Err(libc::EACCES) if r.view().fake_root => Ok(0),
        other => other,
    }
}

/// Under `-0`, files owned by the supervisor's own ids belong to root.
fn fake_owner(r: &Req, uid: &mut u32, gid: &mut u32) {
    if r.view().fake_root {
        if *uid == unsafe { libc::getuid() } {
            *uid = 0;
        }
        if *gid == unsafe { libc::getgid() } {
            *gid = 0;
        }
    }
}

/// Under `-0`, the virtual identity to show in a `/proc/<pid>/status` being opened.
fn fake_ids_for_status(r: &Req, host: &[u8]) -> Option<crate::procs::Ids> {
    if !r.view().fake_root {
        return None;
    }
    let pid: i32 = host
        .strip_prefix(b"/proc/")?
        .split(|&c| c == b'/')
        .next()
        .and_then(|p| std::str::from_utf8(p).ok()?.parse().ok())?;
    Some(r.ctx.ids(pid))
}

/// `mkdir`/`mkdirat`.
fn do_mkdir(r: &Req, dirfd: i32, path: &[u8], mode: i64) -> Result<Outcome> {
    let host = r.translate(dirfd, path, false)?;
    r.valid()?;
    r.check_writable(&host)?;
    let c = cstr(&host)?;
    let rc = check(unsafe { libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, c.as_ptr(), mode) });
    r.fs().flush_cache();
    Ok(Outcome::Value(rc))
}

/// `unlink`/`unlinkat`/`rmdir`.
fn do_unlink(r: &Req, dirfd: i32, path: &[u8], flags: i64) -> Result<Outcome> {
    let host = r.translate(dirfd, path, false)?;
    r.valid()?;
    r.check_writable(&host)?;
    let c = cstr(&host)?;
    let rc = check(unsafe { libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, c.as_ptr(), flags) });
    r.fs().flush_cache();
    Ok(Outcome::Value(rc))
}

/// `rename`/`renameat`/`renameat2`.
fn do_rename(r: &Req, olddirfd: i32, old: &[u8], newdirfd: i32, new: &[u8], flags: i64) -> Result<Outcome> {
    let host_old = r.translate(olddirfd, old, false)?;
    let host_new = r.translate(newdirfd, new, false)?;
    r.valid()?;
    r.check_writable(&host_old)?;
    r.check_writable(&host_new)?;
    let (co, cn) = (cstr(&host_old)?, cstr(&host_new)?);
    let rc = check(unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            co.as_ptr(),
            libc::AT_FDCWD,
            cn.as_ptr(),
            flags,
        )
    });
    r.fs().flush_cache();
    Ok(Outcome::Value(rc))
}

/// `link`/`linkat`.  An empty old path with `AT_EMPTY_PATH` links the tracee's
/// descriptor via its `/proc` entry.
fn do_link(r: &Req, olddirfd: i32, old: &[u8], newdirfd: i32, new: &[u8], flags: i64) -> Result<Outcome> {
    let (host_old, host_flags) = if targets_fd(old, flags) {
        (
            format!("/proc/{}/fd/{}", r.pid, olddirfd).into_bytes(),
            libc::AT_SYMLINK_FOLLOW as i64,
        )
    } else {
        let deref = flags & libc::AT_SYMLINK_FOLLOW as i64 != 0;
        (
            r.translate(olddirfd, old, deref)?,
            flags & libc::AT_SYMLINK_FOLLOW as i64,
        )
    };
    let host_new = r.translate(newdirfd, new, false)?;
    r.valid()?;
    r.check_writable(&host_new)?;
    let (co, cn) = (cstr(&host_old)?, cstr(&host_new)?);
    let rc = check(unsafe {
        libc::syscall(
            libc::SYS_linkat,
            libc::AT_FDCWD,
            co.as_ptr(),
            libc::AT_FDCWD,
            cn.as_ptr(),
            host_flags,
        )
    });
    r.fs().flush_cache();
    Ok(Outcome::Value(rc))
}

/// `symlink`/`symlinkat`: the target is stored verbatim, only the link path is translated.
fn do_symlink(r: &Req, target: &[u8], newdirfd: i32, linkpath: &[u8]) -> Result<Outcome> {
    let host = r.translate(newdirfd, linkpath, false)?;
    r.valid()?;
    r.check_writable(&host)?;
    let (ct, cl) = (cstr(target)?, cstr(&host)?);
    let rc = check(unsafe { libc::syscall(libc::SYS_symlinkat, ct.as_ptr(), libc::AT_FDCWD, cl.as_ptr()) });
    r.fs().flush_cache();
    Ok(Outcome::Value(rc))
}

// ---- attributes --------------------------------------------------------------

/// `chmod`/`fchmodat`/`fchmodat2`.
fn do_chmod(r: &Req, dirfd: i32, path: &[u8], mode: i64, flags: i64) -> Result<Outcome> {
    let host = r.translate(dirfd, path, follow(flags))?;
    r.valid()?;
    r.check_writable(&host)?;
    let c = cstr(&host)?;
    let rc = check(unsafe { libc::syscall(SYS_FCHMODAT2_HOST, libc::AT_FDCWD, c.as_ptr(), mode, flags) });
    Ok(Outcome::Value(rc))
}

/// `chown`/`lchown`/`fchownat`.
fn do_chown(r: &Req, dirfd: i32, path: &[u8], uid: i64, gid: i64, flags: i64) -> Result<Outcome> {
    if targets_fd(path, flags) {
        return Ok(Outcome::Continue);
    }
    let host = r.translate(dirfd, path, follow(flags))?;
    r.valid()?;
    r.check_writable(&host)?;
    let c = cstr(&host)?;
    let host_flags = flags & libc::AT_SYMLINK_NOFOLLOW as i64;
    let rc = check(unsafe {
        libc::syscall(
            libc::SYS_fchownat,
            libc::AT_FDCWD,
            c.as_ptr(),
            uid,
            gid,
            host_flags,
        )
    });
    Ok(Outcome::Value(forgive_as_root(r, rc)))
}

/// `truncate`.
fn do_truncate(r: &Req) -> Result<Outcome> {
    let host = r.translate(libc::AT_FDCWD, &r.path(0)?, true)?;
    r.valid()?;
    r.check_writable(&host)?;
    let c = cstr(&host)?;
    // truncate64(path, len_lo, len_hi) on i386; ARM pads to an even register pair.
    let len = match r.variant {
        Variant::Truncate64 => (r.arg(1) | (r.arg(2) << 32)) as i64,
        Variant::Truncate64Arm => (r.arg(2) | (r.arg(3) << 32)) as i64,
        _ => r.arg_i64(1),
    };
    let rc = check(unsafe { libc::syscall(libc::SYS_truncate, c.as_ptr(), len) });
    Ok(Outcome::Value(rc))
}

/// `mknod`/`mknodat`.
fn do_mknod(r: &Req, dirfd: i32, path: &[u8], mode: i64, dev: i64) -> Result<Outcome> {
    let host = r.translate(dirfd, path, false)?;
    r.valid()?;
    r.check_writable(&host)?;
    let c = cstr(&host)?;
    let rc = check(unsafe { libc::syscall(libc::SYS_mknodat, libc::AT_FDCWD, c.as_ptr(), mode, dev) });
    Ok(Outcome::Value(forgive_as_root(r, rc)))
}

/// `utime`: `struct utimbuf` (two seconds fields) to timespecs.
fn do_utime(r: &Req) -> Result<Outcome> {
    let path = r.path(0)?;
    let times = if r.arg(1) == 0 {
        None
    } else {
        let mut ts = [0u8; 32];
        if r.variant == Variant::Time32 {
            let ub = r.read(r.arg(1), 8)?;
            for (dst, src) in [(0usize, 0usize), (16, 4)] {
                let v = i32::from_ne_bytes(ub[src..src + 4].try_into().unwrap()) as i64;
                ts[dst..dst + 8].copy_from_slice(&v.to_ne_bytes());
            }
        } else {
            let ub = r.read(r.arg(1), 16)?;
            ts[0..8].copy_from_slice(&ub[0..8]);
            ts[16..24].copy_from_slice(&ub[8..16]);
        }
        Some(ts)
    };
    let host = r.translate(libc::AT_FDCWD, &path, true)?;
    r.valid()?;
    r.check_writable(&host)?;
    Ok(Outcome::Value(host_utimensat(&host, times.as_ref(), 0)))
}

/// `utimes`/`futimesat`: `struct timeval[2]` to timespecs.
fn do_utimes(r: &Req, dirfd: i32, path_idx: usize, times_idx: usize) -> Result<Outcome> {
    let path = r.path(path_idx)?;
    let times = timevals_to_timespecs(r, r.arg(times_idx))?;
    let host = r.translate(dirfd, &path, true)?;
    r.valid()?;
    r.check_writable(&host)?;
    Ok(Outcome::Value(host_utimensat(&host, times.as_ref(), 0)))
}

/// `utimensat`.  A NULL path targets the descriptor itself and is passed through.
fn do_utimensat(r: &Req) -> Result<Outcome> {
    if r.arg(1) == 0 {
        return Ok(Outcome::Continue);
    }
    let flags = r.arg_i64(3);
    let path = r.path(1)?;
    if targets_fd(&path, flags) {
        return Ok(Outcome::Continue);
    }
    let times = timespecs_from_tracee(r, r.arg(2))?;
    let host = r.translate(r.dirfd(0), &path, follow(flags))?;
    r.valid()?;
    r.check_writable(&host)?;
    let host_flags = flags & libc::AT_SYMLINK_NOFOLLOW as i64;
    Ok(Outcome::Value(host_utimensat(&host, times.as_ref(), host_flags)))
}

/// `setxattr`/`lsetxattr`.
fn do_setxattr(r: &Req, nofollow: bool) -> Result<Outcome> {
    let path = r.path(0)?;
    let name = cstr(&r.ctx.mem.read_cstr(r.pid, r.arg(1))?)?;
    let size = r.arg(3) as usize;
    if size > XATTR_MAX {
        return Err(libc::E2BIG);
    }
    let value = r.read(r.arg(2), size)?;
    let host = r.translate(libc::AT_FDCWD, &path, !nofollow)?;
    r.valid()?;
    r.check_writable(&host)?;
    let c = cstr(&host)?;
    let nr = if nofollow {
        libc::SYS_lsetxattr
    } else {
        libc::SYS_setxattr
    };
    let rc =
        check(unsafe { libc::syscall(nr, c.as_ptr(), name.as_ptr(), value.as_ptr(), size, r.arg_i64(4)) });
    Ok(Outcome::Value(rc))
}

/// `getxattr`/`lgetxattr`.
fn do_getxattr(r: &Req, nofollow: bool) -> Result<Outcome> {
    let path = r.path(0)?;
    let name = cstr(&r.ctx.mem.read_cstr(r.pid, r.arg(1))?)?;
    let size = (r.arg(3) as usize).min(XATTR_MAX);
    let host = r.translate(libc::AT_FDCWD, &path, !nofollow)?;
    r.valid()?;
    let c = cstr(&host)?;
    let mut buf = vec![0u8; size];
    let nr = if nofollow {
        libc::SYS_lgetxattr
    } else {
        libc::SYS_getxattr
    };
    let rc = check(unsafe { libc::syscall(nr, c.as_ptr(), name.as_ptr(), buf.as_mut_ptr(), size) })?;
    if size > 0 && rc > 0 {
        r.write(r.arg(2), &buf[..rc as usize])?;
    }
    Ok(Outcome::Value(Ok(rc)))
}

/// `listxattr`/`llistxattr`.
fn do_listxattr(r: &Req, nofollow: bool) -> Result<Outcome> {
    let path = r.path(0)?;
    let size = (r.arg(2) as usize).min(XATTR_MAX);
    let host = r.translate(libc::AT_FDCWD, &path, !nofollow)?;
    r.valid()?;
    let c = cstr(&host)?;
    let mut buf = vec![0u8; size];
    let nr = if nofollow {
        libc::SYS_llistxattr
    } else {
        libc::SYS_listxattr
    };
    let rc = check(unsafe { libc::syscall(nr, c.as_ptr(), buf.as_mut_ptr(), size) })?;
    if size > 0 && rc > 0 {
        r.write(r.arg(1), &buf[..rc as usize])?;
    }
    Ok(Outcome::Value(Ok(rc)))
}

/// `removexattr`/`lremovexattr`.
fn do_removexattr(r: &Req, nofollow: bool) -> Result<Outcome> {
    let path = r.path(0)?;
    let name = cstr(&r.ctx.mem.read_cstr(r.pid, r.arg(1))?)?;
    let host = r.translate(libc::AT_FDCWD, &path, !nofollow)?;
    r.valid()?;
    r.check_writable(&host)?;
    let c = cstr(&host)?;
    let nr = if nofollow {
        libc::SYS_lremovexattr
    } else {
        libc::SYS_removexattr
    };
    let rc = check(unsafe { libc::syscall(nr, c.as_ptr(), name.as_ptr()) });
    Ok(Outcome::Value(rc))
}

/// `inotify_add_watch`.
///
/// The watch must be added to the tracee's own inotify descriptor, which the
/// supervisor cannot reach without `pidfd_getfd`.  Paths that translate to
/// themselves are passed through; translated paths fail with `ENOENT` so
/// watchers fall back to polling.  Moving this to the ptrace tier would fix it.
fn do_inotify_add_watch(r: &Req) -> Result<Outcome> {
    let path = r.path(1)?;
    let deref = r.arg(2) & IN_DONT_FOLLOW == 0;
    let host = r.translate(libc::AT_FDCWD, &path, deref)?;
    r.valid()?;
    if host == path {
        return Ok(Outcome::Continue);
    }
    note!(
        r.ctx,
        1,
        "pid {} inotify_add_watch on translated path {} unsupported",
        r.pid,
        String::from_utf8_lossy(&path)
    );
    Ok(Outcome::Value(Err(libc::ENOENT)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_proc_self() {
        assert_eq!(rewrite_proc_self(b"/proc/self/exe", 42), b"/proc/42/exe".to_vec());
        assert_eq!(rewrite_proc_self(b"/proc/selfish", 42), b"/proc/selfish".to_vec());
        assert_eq!(
            rewrite_proc_self(b"/proc/thread-self/stat", 7),
            b"/proc/7/task/7/stat".to_vec()
        );
    }

    #[test]
    fn classifies_magic_links() {
        assert_eq!(proc_magic_link(b"/proc/12/exe"), Some((12, true)));
        assert_eq!(proc_magic_link(b"/proc/12/task/13/exe"), Some((12, true)));
        assert_eq!(proc_magic_link(b"/proc/12/fd/3"), Some((12, false)));
        assert_eq!(proc_magic_link(b"/proc/12/cwd"), Some((12, false)));
        assert_eq!(proc_magic_link(b"/proc/12/status"), None);
        assert_eq!(proc_magic_link(b"/etc/passwd"), None);
    }

    #[test]
    fn cleans_lexically() {
        assert_eq!(lexical_clean(b"/a//b/./../c"), b"/a/c".to_vec());
        assert_eq!(lexical_clean(b"/.."), b"/".to_vec());
    }
}
