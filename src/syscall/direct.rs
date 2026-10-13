//! Handlers for the syscalls that take a ptrace stop when ptrace is
//! available, served through user notification when it is not.
//!
//! A notification cannot change registers, only answer the syscall, let it
//! continue, or install a descriptor into the tracee.  Three tricks cover
//! the former ptrace tier:
//!
//! * `chdir`, `fchdir` and `chroot` are answered without running: the
//!   working directory is virtual (`procs`), every path handler resolves
//!   relative paths against it, and the kernel's own cwd of every tracee
//!   stays pinned to the alias directory.
//! * `connect` and `bind` are performed by the supervisor on a socket of
//!   the same type and flags, which then replaces the tracee's descriptor
//!   through `ADDFD` with `SETFD`.
//! * `execve`, `inotify_add_watch` and `O_PATH` opens must run in the tracee
//!   with a different path.  The path string is overwritten in place,
//!   through `/proc/<pid>/mem`, with a name of one or two bytes that
//!   resolves inside the alias directory, which the kernel cwd makes
//!   reachable from any process: `e` is the exec trampoline (see
//!   `exec::shim`) and a transient one-character symlink stands for any
//!   other host path.  The syscall then continues.  Once the task has
//!   consumed the argument, the original bytes are put back, but only when
//!   the memory still holds exactly what was written: a buffer may have
//!   been freed or reused by then, and must not be touched if so.
//!
//! `clone` and its relatives are notified only to snapshot the parent's
//! state for the child, see `procs`.

use crate::exec::{self, shim};
use crate::fs::translate::{detranslate_path, guest_fd_path, read_link};
use crate::note;
use crate::procs::PendingExec;
use crate::seccomp::notify::{addfd_at, reply_continue};
use crate::sys::{Result, errno};
use crate::syscall::notify::{Outcome, Req};
use crate::syscall::nr::*;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `CLONE_VFORK`: the child shares the parent's memory until it execs.
const CLONE_VFORK: u64 = 0x4000;
/// `CLONE_THREAD`: the new task shares the process, nothing to inherit.
const CLONE_THREAD: u64 = 0x10000;
/// Longest wait for a continued syscall to return before restoring anyway.
const RESTORE_TIMEOUT: Duration = Duration::from_secs(2);
/// CPU time a resumed task must have run for its syscall to be past the
/// argument copy and the path walk, with a wide margin over the microseconds
/// those take.
const SETTLED_CPU: u64 = 100_000;

/// Characters available for transient alias names; `e` and `r` are the
/// trampoline and its records.
const ALIAS_CHARS: &[u8] = b"0123456789abcdfghijklmnopqstuvwxyzABCDFGHIJKLMNOPQSTUVWXYZ";

/// Which names are in use, and where the next search starts: names are
/// handed out round-robin so a name just released is not re-pointed while
/// the kernel may still be walking through it.
static ALIASES: Mutex<([bool; ALIAS_CHARS.len()], usize)> = Mutex::new(([false; ALIAS_CHARS.len()], 0));

/// Routes a former trace-tier syscall to its handler; `None` for any other.
///
/// # Arguments
/// * `r` - The notification.
/// * `nr` - Canonical syscall number.
pub fn dispatch(r: &Req, nr: i64) -> Option<Result<Outcome>> {
    Some(match nr {
        EXECVE => do_execve(r, false),
        EXECVEAT => do_execve(r, true),
        CHDIR => r.path(0).and_then(|p| set_cwd(r, libc::AT_FDCWD, &p)),
        FCHDIR => {
            guest_fd_path(&r.ctx.fs, r.pid, r.arg(0) as i32).and_then(|p| set_cwd(r, libc::AT_FDCWD, &p))
        }
        CHROOT => do_chroot(r),
        CONNECT => do_sockaddr(r, r.arg(0) as i32, r.arg(1), r.arg(2) as usize, true),
        BIND => do_sockaddr(r, r.arg(0) as i32, r.arg(1), r.arg(2) as usize, false),
        INOTIFY_ADD_WATCH => do_inotify_add_watch(r),
        CLONE | FORK | VFORK | CLONE3 => do_clone(r, nr),
        _ => return None,
    })
}

/// Lets the trampoline's own syscalls through untranslated.
///
/// Between the rewritten exec and the trampoline's exec of the real target,
/// the process opens and unlinks its record relative to the kernel cwd.  The
/// mark is verified against `/proc/<pid>/exe` so a program whose rewritten
/// exec failed is not left untranslated.
///
/// # Arguments
/// * `r` - The notification.
/// * `nr` - Canonical syscall number.
///
/// # Returns
/// `Some(Continue)` for the trampoline, `None` otherwise.
pub fn shim_passthrough(r: &Req, nr: i64) -> Option<Outcome> {
    if matches!(nr, EXECVE | EXECVEAT) {
        return None;
    }
    let tgid = r.tgid();
    r.ctx.procs.shim_pending(tgid)?;
    if shim::running(r.pid) {
        return Some(Outcome::Continue);
    }
    r.ctx.procs.shim_leave(tgid);
    None
}

/// `socketcall(call, args)` from an i386 tracee: `bind` (2) and `connect` (3).
///
/// # Arguments
/// * `r` - The notification.
pub fn do_socketcall(r: &Req) -> Result<Outcome> {
    let call = r.arg(0);
    if call != 2 && call != 3 {
        return Ok(Outcome::Continue);
    }
    let raw = r.read(r.arg(1), 12)?;
    let word = |i: usize| u32::from_ne_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap()) as u64;
    do_sockaddr(r, word(0) as i32, word(1), word(2) as usize, call == 3)
}

/// `execve`/`execveat` through the trampoline.
///
/// The plan is checked the way the kernel would check it, so a program the
/// kernel would refuse is refused here and the caller survives with the
/// errno.  The record is written, the process marked, and the path string
/// replaced by `e`.  An `execveat` of a descriptor (`AT_EMPTY_PATH`) has
/// that descriptor replaced by one on the trampoline instead; a relative
/// `execveat` path has its `dirfd` replaced by the alias directory so `e`
/// resolves there.  A `vfork` child's path string belongs to its parent and
/// is restored there later.
///
/// A notification from a process already marked, and verified to be running
/// the trampoline, is the trampoline's exec of the real target: a host path
/// the kernel resolves as is, let through once the program is recorded.
///
/// # Arguments
/// * `r` - The notification.
/// * `is_at` - `execveat` rather than `execve`.
fn do_execve(r: &Req, is_at: bool) -> Result<Outcome> {
    let tgid = r.tgid();
    if let Some(p) = r.ctx.procs.shim_pending(tgid) {
        r.ctx.procs.shim_leave(tgid);
        if shim::running(r.pid) {
            r.ctx.set_exe(tgid, p.guest, p.host);
            if let Some((parent, addr, orig, written)) = p.restore {
                restore_if_intact(r, parent as u32, addr, &orig, &written);
            }
            return Ok(Outcome::Continue);
        }
    }
    let (dirfd, path_idx, argv_idx, at_flags) = if is_at {
        (r.arg(0) as i32, 1, 2, r.arg(4) as i32)
    } else {
        (libc::AT_FDCWD, 0, 1, 0)
    };
    let user_path = r.path(path_idx)?;
    let argv = exec::read_argv(r.ctx, r.pid, r.arg(argv_idx), r.abi.ptr_size())?;
    let empty_path = is_at && user_path.is_empty();
    let plan = if empty_path {
        if at_flags & libc::AT_EMPTY_PATH == 0 {
            return Err(libc::ENOENT);
        }
        let guest = guest_fd_path(&r.ctx.fs, r.pid, dirfd)?;
        exec::plan(r.ctx, r.pid, libc::AT_FDCWD, &guest, argv, true)?
    } else {
        let deref = at_flags & libc::AT_SYMLINK_NOFOLLOW == 0;
        exec::plan(r.ctx, r.pid, dirfd, &user_path, argv, deref)?
    };
    if !is_at && !plan.changed {
        r.ctx.set_exe(tgid, plan.guest_prog, plan.host_prog);
        return Ok(Outcome::Continue);
    }
    check_executable(&plan)?;
    r.valid()?;
    exec::debug_exec(r.pid, &plan);
    shim::write_record(tgid, &plan)?;
    let vfork_parent = r.ctx.tracee(tgid).vfork_parent;
    let mut orig = user_path.clone();
    orig.push(0);
    let restore = vfork_parent
        .filter(|_| !empty_path)
        .map(|parent| (parent, r.arg(path_idx), orig, b"e\0".to_vec()));
    r.ctx.procs.shim_enter(
        tgid,
        PendingExec {
            guest: plan.guest_prog.clone(),
            host: plan.host_prog.clone(),
            restore,
        },
    );
    let undo = |e: i32| {
        r.ctx.procs.shim_leave(tgid);
        if let Some(p) = shim::record_path(tgid) {
            let _ = std::fs::remove_file(p);
        }
        e
    };
    let Some(shim_path) = shim::path() else {
        return Err(undo(libc::ENOENT));
    };
    if empty_path {
        let fd =
            open_host(shim_path.as_os_str().as_bytes(), libc::O_RDONLY | libc::O_CLOEXEC).map_err(undo)?;
        addfd_at(r.listener, r.id, fd, dirfd, true).map_err(undo)?;
        return Ok(Outcome::Continue);
    }
    r.ctx
        .mem
        .write_force(r.pid, r.arg(path_idx), b"e\0")
        .map_err(undo)?;
    if is_at && dirfd != libc::AT_FDCWD && user_path.first() != Some(&b'/') {
        let dir = shim_path
            .parent()
            .map(|d| d.as_os_str().as_bytes().to_vec())
            .unwrap_or_default();
        let fd = open_host(&dir, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC).map_err(undo)?;
        addfd_at(r.listener, r.id, fd, dirfd, true).map_err(undo)?;
    }
    Ok(Outcome::Continue)
}

/// Refuses a plan the kernel would refuse, with the kernel's errno.
///
/// A shell relies on `ENOEXEC` to run a script without `#!` itself; a
/// trampoline that died instead would take the shell with it.
fn check_executable(plan: &exec::ExecPlan) -> Result<()> {
    let c = CString::new(plan.host_prog.clone()).map_err(|_| libc::ENOENT)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c.as_ptr(), &mut st) } < 0 {
        return Err(errno());
    }
    if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
        return Err(libc::EACCES);
    }
    if unsafe { libc::access(c.as_ptr(), libc::X_OK) } < 0 {
        return Err(errno());
    }
    if !plan.understood && !binfmt_misc_matches(&plan.host_prog) {
        return Err(libc::ENOEXEC);
    }
    Ok(())
}

/// Whether a registered `binfmt_misc` handler would run a file we do not
/// recognize, by the same magic or extension test the kernel applies.
///
/// # Arguments
/// * `host` - Host path of the file.
fn binfmt_misc_matches(host: &[u8]) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc/sys/fs/binfmt_misc") else {
        return false;
    };
    let head = std::fs::read(std::ffi::OsStr::from_bytes(host))
        .map(|mut d| {
            d.truncate(256);
            d
        })
        .unwrap_or_default();
    let name = host.rsplit(|&b| b == b'/').next().unwrap_or(host);
    for entry in entries.flatten() {
        if entry.file_name() == "register" || entry.file_name() == "status" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        if !text.starts_with("enabled") {
            continue;
        }
        let field = |key: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(key))
                .map(|v| v.trim().to_string())
        };
        if let Some(ext) = field("extension ") {
            if name.ends_with(format!(".{ext}").as_bytes()) {
                return true;
            }
            continue;
        }
        let (Some(magic), offset) = (
            field("magic "),
            field("offset ")
                .and_then(|o| o.parse::<usize>().ok())
                .unwrap_or(0),
        ) else {
            continue;
        };
        let unhex = |h: &str| -> Vec<u8> {
            h.as_bytes()
                .chunks(2)
                .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
                .collect()
        };
        let magic = unhex(&magic);
        let mask = field("mask ")
            .map(|m| unhex(&m))
            .unwrap_or_else(|| vec![0xff; magic.len()]);
        if head.len() < offset + magic.len() {
            continue;
        }
        if magic
            .iter()
            .zip(mask.iter().chain(std::iter::repeat(&0xff)))
            .zip(&head[offset..])
            .all(|((m, k), b)| b & k == m & k)
        {
            return true;
        }
    }
    false
}

/// Opens a host path for injection.
fn open_host(host: &[u8], flags: i32) -> Result<i32> {
    let c = CString::new(host.to_vec()).map_err(|_| libc::EINVAL)?;
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    if fd < 0 { Err(errno()) } else { Ok(fd) }
}

/// Moves the virtual working directory to `path`, with `chdir`'s own checks.
fn set_cwd(r: &Req, dirfd: i32, path: &[u8]) -> Result<Outcome> {
    let host = r.translate(dirfd, path, true)?;
    let c = CString::new(host.clone()).map_err(|_| libc::ENOENT)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c.as_ptr(), &mut st) } < 0 {
        return Err(errno());
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(libc::ENOTDIR);
    }
    if unsafe { libc::access(c.as_ptr(), libc::X_OK) } < 0 {
        return Err(errno());
    }
    let guest = detranslate_path(&r.ctx.fs, &host);
    r.valid()?;
    r.ctx.procs.set_cwd(r.pid as i32, guest);
    Ok(Outcome::Value(Ok(0)))
}

/// `chroot`: the guest root is a no-op, anything else is refused as it would
/// be for an unprivileged process.
fn do_chroot(r: &Req) -> Result<Outcome> {
    let host = r.translate(libc::AT_FDCWD, &r.path(0)?, true)?;
    if detranslate_path(&r.ctx.fs, &host) == b"/" {
        return Ok(Outcome::Value(Ok(0)));
    }
    Err(libc::EPERM)
}

/// `connect`/`bind` on an `AF_UNIX` path, done on a replacement socket.
///
/// The tracee's socket cannot be reached (`pidfd_getfd` is not allowed in a
/// default container), so a new socket of the same type, with the same
/// `O_NONBLOCK` and `O_CLOEXEC`, is connected or bound to the host path by
/// the supervisor and installed over the tracee's descriptor number.
/// Options set on the old socket before this call, and a `bind` made before
/// a `connect`, do not carry over.  A descriptor that is not a unix socket
/// is left to the kernel, which reports the mismatch.
///
/// # Arguments
/// * `r` - The notification.
/// * `sockfd` - The tracee's socket.
/// * `addr` - Address of the `sockaddr` in the tracee.
/// * `len` - Its length.
/// * `connect` - `connect` (follow a final symlink) rather than `bind`.
fn do_sockaddr(r: &Req, sockfd: i32, addr: u64, len: usize, connect: bool) -> Result<Outcome> {
    if addr == 0 || len <= 2 || len > 110 {
        return Ok(Outcome::Continue);
    }
    let sa = r.read(addr, len)?;
    if u16::from_ne_bytes([sa[0], sa[1]]) != libc::AF_UNIX as u16 || sa[2] == 0 {
        return Ok(Outcome::Continue);
    }
    let end = sa[2..].iter().position(|&b| b == 0).map(|p| p + 2).unwrap_or(len);
    let path = sa[2..end].to_vec();
    let host = r.translate(libc::AT_FDCWD, &path, connect)?;
    if host == path {
        return Ok(Outcome::Continue);
    }
    if !connect {
        r.check_writable(&host)?;
    }
    if host.len() >= 108 {
        return Err(libc::ENAMETOOLONG);
    }
    let Some((kind, flags)) = socket_description(r.pid, sockfd) else {
        return Ok(Outcome::Continue);
    };
    let nonblock = flags & libc::O_NONBLOCK != 0;
    let cloexec = flags & libc::O_CLOEXEC != 0;
    let new = unsafe {
        libc::socket(
            libc::AF_UNIX,
            kind | libc::SOCK_CLOEXEC | if nonblock { libc::SOCK_NONBLOCK } else { 0 },
            0,
        )
    };
    if new < 0 {
        return Err(errno());
    }
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sun.sun_family = libc::AF_UNIX as u16;
    for (i, b) in host.iter().enumerate() {
        sun.sun_path[i] = *b as libc::c_char;
    }
    let sun_len = (2 + host.len() + 1) as libc::socklen_t;
    let sun_ptr = &sun as *const libc::sockaddr_un as *const libc::sockaddr;
    let rc = unsafe {
        if connect {
            libc::connect(new, sun_ptr, sun_len)
        } else {
            libc::bind(new, sun_ptr, sun_len)
        }
    };
    if rc < 0 {
        let e = errno();
        unsafe { libc::close(new) };
        return Err(e);
    }
    note!(
        r.ctx,
        2,
        "pid {} {} fd {} -> {}",
        r.pid,
        if connect { "connect" } else { "bind" },
        sockfd,
        String::from_utf8_lossy(&host)
    );
    r.valid().inspect_err(|_| unsafe {
        libc::close(new);
    })?;
    addfd_at(r.listener, r.id, new, sockfd, cloexec)?;
    Ok(Outcome::Value(Ok(0)))
}

/// Type and descriptor flags of a tracee's unix socket.
///
/// The inode from `/proc/<pid>/fd/N` is looked up in `/proc/net/unix` for
/// the socket type; `/proc/<pid>/fdinfo/N` gives the flags.
///
/// # Arguments
/// * `tid` - Tracee thread id.
/// * `fd` - Descriptor number in the tracee.
///
/// # Returns
/// `(SOCK_* type, O_* flags)`, or `None` when it is not a unix socket.
fn socket_description(tid: u32, fd: i32) -> Option<(i32, i32)> {
    let link = read_link(format!("/proc/{tid}/fd/{fd}").as_bytes()).ok()?;
    let inode = link.strip_prefix(b"socket:[")?.strip_suffix(b"]")?;
    let inode = std::str::from_utf8(inode).ok()?;
    let table = std::fs::read_to_string("/proc/net/unix").ok()?;
    let kind = table.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 7 && f[6] == inode {
            i32::from_str_radix(f[4], 16).ok()
        } else {
            None
        }
    })?;
    let info = std::fs::read_to_string(format!("/proc/{tid}/fdinfo/{fd}")).ok()?;
    let flags = info
        .lines()
        .find_map(|l| l.strip_prefix("flags:"))
        .and_then(|v| i32::from_str_radix(v.trim(), 8).ok())?;
    Some((kind, flags))
}

/// `inotify_add_watch`: the watch goes on the tracee's own descriptor, so the
/// path is rewritten to a transient alias.
fn do_inotify_add_watch(r: &Req) -> Result<Outcome> {
    const IN_DONT_FOLLOW: u64 = 0x0200_0000;
    let path = r.path(1)?;
    let dont_follow = r.arg(2) & IN_DONT_FOLLOW != 0;
    let host = r.translate(libc::AT_FDCWD, &path, !dont_follow)?;
    if host == path {
        return Ok(Outcome::Continue);
    }
    let form = if dont_follow && is_symlink(&host) {
        Form::Dir
    } else {
        Form::File
    };
    let mut orig = path.clone();
    orig.push(0);
    transient_rewrite(r, r.arg(1), &orig, &host, form)
}

/// An `O_PATH` open without ptrace.
///
/// Such descriptors cannot be injected, so directories and readable files
/// are opened read-only instead, which serves the same purposes (`openat`
/// relative to it, `fstat`, `/proc/self/fd/N`).  Anything else, a socket, a
/// device, an unreadable file or a symlink opened with `O_NOFOLLOW`, goes
/// through a transient alias so the kernel opens it in the tracee.
///
/// # Arguments
/// * `r` - The notification.
/// * `dirfd` - Base of a relative `path`.
/// * `path` - Path as the tracee passed it.
/// * `path_addr` - Where that string lives in the tracee.
/// * `flags` - Host-form open flags, `O_PATH` included.
pub fn do_open_path(r: &Req, dirfd: i32, path: &[u8], path_addr: u64, flags: i64) -> Result<Outcome> {
    let nofollow = flags & libc::O_NOFOLLOW as i64 != 0;
    let host = r.translate(dirfd, path, !nofollow)?;
    let cloexec = flags & libc::O_CLOEXEC as i64 != 0;
    let c = CString::new(host.clone()).map_err(|_| libc::ENOENT)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } < 0 {
        return Err(errno());
    }
    let kind = st.st_mode & libc::S_IFMT;
    let base = libc::O_RDONLY | libc::O_CLOEXEC | if nofollow { libc::O_NOFOLLOW } else { 0 };
    let direct = match kind {
        libc::S_IFDIR => Some(base | libc::O_DIRECTORY),
        libc::S_IFREG => Some(base),
        _ => None,
    };
    if let Some(open_flags) = direct {
        r.valid()?;
        match open_host(&host, open_flags) {
            Ok(fd) => return Ok(Outcome::Fd { fd, cloexec }),
            Err(libc::EACCES) => {}
            Err(e) => return Err(e),
        }
    }
    if dirfd != libc::AT_FDCWD && path.first() != Some(&b'/') {
        return Err(libc::EACCES);
    }
    let form = if kind == libc::S_IFLNK {
        Form::Dir
    } else {
        Form::File
    };
    let mut orig = path.to_vec();
    orig.push(0);
    transient_rewrite(r, path_addr, &orig, &host, form)
}

/// `clone`/`fork`/`vfork`/`clone3`: refuse a new namespace, snapshot the
/// parent for the child without ptrace, then continue.
///
/// `clone3` arrives here in both modes, since its flags live in memory where
/// the filter cannot see them.
///
/// # Arguments
/// * `r` - The notification.
/// * `nr` - Canonical syscall number.
pub fn do_clone(r: &Req, nr: i64) -> Result<Outcome> {
    let flags = match nr {
        CLONE => r.arg(0),
        CLONE3 => {
            let raw = r.read(r.arg(0), 8)?;
            u64::from_ne_bytes(raw.try_into().unwrap())
        }
        VFORK => CLONE_VFORK,
        _ => 0,
    };
    if flags & crate::syscall::CLONE_NEWNS_FLAGS != 0 {
        return Err(libc::EPERM);
    }
    if r.ctx.no_ptrace && flags & CLONE_THREAD == 0 {
        r.ctx.procs.forked(r.pid as i32, flags & CLONE_VFORK != 0);
    }
    Ok(Outcome::Continue)
}

/// How a transient alias stands for its target.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    /// The alias is a symlink to the target; the rewritten path is the alias name.
    File,
    /// The alias is a symlink to the target's parent directory; the rewritten
    /// path is `<alias>/<basename>`, for syscalls that must not follow a
    /// final symlink or that create the final component.
    Dir,
}

/// Rewrites a path string in the tracee to a transient alias, continues the
/// syscall, and puts the string back once the syscall has consumed it.
///
/// # Arguments
/// * `r` - The notification.
/// * `addr` - Address of the string in the tracee.
/// * `orig` - The bytes at `addr` that may be overwritten (the string and its NUL).
/// * `host` - Host path the alias stands for.
/// * `form` - Alias form.
///
/// # Returns
/// `Outcome::Replied`: the notification was answered here.
///
/// # Errors
/// `ENAMETOOLONG` when even the alias does not fit, or the errno of creating it.
fn transient_rewrite(r: &Req, addr: u64, orig: &[u8], host: &[u8], form: Form) -> Result<Outcome> {
    let dir = shim::dir_bytes().ok_or(libc::ENOENT)?;
    let name = acquire_alias().ok_or(libc::EAGAIN)?;
    let release = |e: i32| {
        release_alias(name);
        e
    };
    let (target, repl): (Vec<u8>, Vec<u8>) = match form {
        Form::File => (host.to_vec(), vec![name]),
        Form::Dir => {
            let cut = host.iter().rposition(|&b| b == b'/').unwrap_or(0);
            let parent = if cut == 0 {
                b"/".to_vec()
            } else {
                host[..cut].to_vec()
            };
            let mut p = vec![name, b'/'];
            p.extend_from_slice(&host[cut + 1..]);
            (parent, p)
        }
    };
    if repl.len() + 1 > orig.len() {
        return Err(release(libc::ENAMETOOLONG));
    }
    let mut link = dir.clone();
    link.push(b'/');
    link.push(name);
    let (lt, ll) = (
        CString::new(target).map_err(|_| release(libc::EINVAL))?,
        CString::new(link.clone()).map_err(|_| release(libc::EINVAL))?,
    );
    unsafe { libc::unlink(ll.as_ptr()) };
    if unsafe { libc::symlink(lt.as_ptr(), ll.as_ptr()) } < 0 {
        return Err(release(errno()));
    }
    let mut written = repl.clone();
    written.push(0);
    r.valid().map_err(release)?;
    let cpu_before = cpu_time(r.pid);
    r.ctx.mem.write_force(r.pid, addr, &written).map_err(release)?;
    note!(
        r.ctx,
        2,
        "pid {} rewrote {} -> {} for {}",
        r.pid,
        String::from_utf8_lossy(&orig[..orig.len().saturating_sub(1)]),
        String::from_utf8_lossy(&repl),
        String::from_utf8_lossy(host)
    );
    reply_continue(r.listener, r.id);
    wait_syscall_consumed(r, cpu_before);
    restore_if_intact(r, r.pid, addr, orig, &written);
    release_alias(name);
    Ok(Outcome::Replied)
}

/// Puts `orig` back at `addr` in process `pid` if the memory still holds
/// exactly the rewrite, i.e. `written` followed by the rest of `orig`.
///
/// A buffer that was freed or reused since the rewrite no longer matches
/// and is left alone: writing into it would corrupt whatever lives there
/// now (a reused stack frame, an allocator's free list).
///
/// # Arguments
/// * `r` - The notification, for logging.
/// * `pid` - Process whose memory holds the string.
/// * `addr` - Address of the string.
/// * `orig` - The original bytes.
/// * `written` - The bytes written over the front of them.
fn restore_if_intact(r: &Req, pid: u32, addr: u64, orig: &[u8], written: &[u8]) {
    let mut cur = vec![0u8; orig.len()];
    let intact = r.ctx.mem.read(pid, addr, &mut cur) == Ok(orig.len())
        && cur[..written.len()] == *written
        && cur[written.len()..] == orig[written.len()..];
    if intact {
        let _ = r.ctx.mem.write_force(pid, addr, orig);
    } else {
        note!(
            r.ctx,
            2,
            "pid {pid} rewritten string at {addr:#x} not restored: memory reused"
        );
    }
}

/// Waits until the continued syscall has consumed its rewritten argument.
///
/// The kernel copies a path in, and walks it, as the first thing it does
/// after the task resumes, so the string may be restored once the task has
/// spent [`SETTLED_CPU`] of CPU time since the reply (`/proc/<tid>/schedstat`),
/// or sooner when it is seen blocked in a different syscall, or outside any
/// syscall, or gone.  `/proc/<tid>/syscall` alone cannot tell: it reads
/// `running` for a task on a CPU whether it is about to copy the argument or
/// long past it.  A syscall that blocks inside itself has consumed the
/// argument too, so the wait gives up after [`RESTORE_TIMEOUT`].  Without
/// scheduler statistics the wait is a fixed two milliseconds.
///
/// # Arguments
/// * `r` - The notification, for the thread id and the syscall to look for.
/// * `cpu_before` - The task's run time before the reply, from [`cpu_time`].
fn wait_syscall_consumed(r: &Req, cpu_before: Option<u64>) {
    let path = format!("/proc/{}/syscall", r.pid);
    let start = Instant::now();
    let mut polls = 0u32;
    while start.elapsed() < RESTORE_TIMEOUT {
        match (cpu_before, cpu_time(r.pid)) {
            (Some(before), Some(now)) if now.saturating_sub(before) >= SETTLED_CPU => return,
            (Some(_), None) => return,
            (None, _) => {
                std::thread::sleep(Duration::from_millis(2));
                return;
            }
            _ => {}
        }
        let Ok(s) = std::fs::read_to_string(&path) else {
            return;
        };
        let mut it = s.split_whitespace();
        let first = it.next().unwrap_or("");
        if first != "running" {
            let in_it = first.parse::<i64>().ok() == Some(r.raw_nr as i64)
                && (0..6).all(|i| {
                    it.next()
                        .and_then(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
                        == Some(r.args[i])
                });
            if !in_it {
                return;
            }
        }
        polls += 1;
        if polls < 50 {
            std::thread::yield_now();
        } else {
            std::thread::sleep(Duration::from_micros(200.min(50 * polls as u64)));
        }
    }
}

/// CPU time thread `tid` has run, in nanoseconds, from `/proc/<tid>/schedstat`.
///
/// # Arguments
/// * `tid` - Thread id.
fn cpu_time(tid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{tid}/schedstat")).ok()?;
    s.split_whitespace().next()?.parse().ok()
}

/// Takes a free one-character alias name, the least recently handed out.
fn acquire_alias() -> Option<u8> {
    let mut g = ALIASES.lock().unwrap();
    let (used, next) = &mut *g;
    let n = ALIAS_CHARS.len();
    let i = (0..n).map(|k| (*next + k) % n).find(|&i| !used[i])?;
    used[i] = true;
    *next = (i + 1) % n;
    Some(ALIAS_CHARS[i])
}

/// Returns an alias name to the pool.  The symlink stays until the name
/// comes round again.
fn release_alias(name: u8) {
    if let Some(i) = ALIAS_CHARS.iter().position(|&c| c == name) {
        ALIASES.lock().unwrap().0[i] = false;
    }
}

/// Whether a host path is a symlink.
fn is_symlink(host: &[u8]) -> bool {
    let Ok(c) = CString::new(host.to_vec()) else {
        return false;
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::lstat(c.as_ptr(), &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFLNK }
}

/// Whether ptrace can be used from here.
///
/// `PTRACE_PEEKUSER` on a process that is not a tracee fails with `ESRCH`
/// once the kernel reaches the request; a seccomp policy that filters the
/// syscall answers with its own errno before that.
pub fn ptrace_usable() -> bool {
    let rc = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, std::process::id() as i32, 0usize, 0usize) };
    rc < 0 && errno() == libc::ESRCH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_names_are_short_and_rotate() {
        let a = acquire_alias().unwrap();
        let b = acquire_alias().unwrap();
        assert_ne!(a, b);
        assert!(a != b'e' && a != b'r' && b != b'e' && b != b'r');
        release_alias(a);
        release_alias(b);
        let c = acquire_alias().unwrap();
        assert_ne!(c, a);
        assert_ne!(c, b);
        release_alias(c);
    }

    #[test]
    fn describes_own_unix_socket() {
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
        assert!(fd >= 0);
        let (kind, flags) = socket_description(std::process::id(), fd).expect("own socket is described");
        assert_eq!(kind, libc::SOCK_DGRAM);
        assert!(flags & libc::O_NONBLOCK != 0);
        assert!(flags & libc::O_CLOEXEC == 0);
        unsafe { libc::close(fd) };
        assert!(socket_description(std::process::id(), fd).is_none());
    }

    #[test]
    fn ptrace_probe_does_not_panic() {
        let _ = ptrace_usable();
    }
}
