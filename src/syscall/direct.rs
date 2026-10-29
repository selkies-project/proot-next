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
//!   other host path.  A symlink to be reached by a bare name, which no
//!   `<alias>/<name>` fits, is reached through a hard link to it instead,
//!   the same inode.  The syscall then continues.  Once the task has
//!   consumed the argument, the original bytes are put back, but only when
//!   the memory still holds exactly what was written: a buffer may have
//!   been freed or reused by then, and must not be touched if so.
//!
//! `clone` and its relatives are notified only to snapshot the parent's
//! state for the child, see `procs`.
//!
//! In the guest-stub restricted mode (see `guest_stub`) the strings these
//! handlers rewrite are the stub's copies in the mailbox, with room for any
//! host path, so the full host path is written and nothing is put back.  An
//! exec is planned from the staged copy and answered with the mailbox
//! descriptor installed for the trampoline, which the stub then execs itself.

use crate::exec::nested::EnvSource;
use crate::exec::shim::Trapped;
use crate::exec::{self, ExecPlan, shim};
use crate::fs::canon::RETRY;
use crate::fs::translate::{guest_dirfd_path, guest_fd_path, read_link, strip_deleted};
use crate::guest_stub::layout;
use crate::note;
use crate::seccomp::notify::{addfd, addfd_at, reply_continue};
use crate::state::Ctx;
use crate::sys::{Result, errno};
use crate::syscall::notify::{Outcome, Req};
use crate::syscall::nr::*;
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
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

/// Directories holding hard links to symlinks, one per mount reached so far.
///
/// `linkat` refuses a link across mounts, and the alias directory usually
/// sits on a tmpfs of its own, so a symlink elsewhere is linked from a
/// directory created on its mount.
static STAGING: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Routes a former trace-tier syscall to its handler; `None` for any other.
///
/// # Arguments
/// * `r` - The notification.
/// * `nr` - Canonical syscall number.
pub fn dispatch(r: &Req, nr: i64) -> Option<Result<Outcome>> {
    Some(match nr {
        EXECVE | EXECVEAT if r.ctx.trap_mode() => do_execve_trapped(r, nr == EXECVEAT),
        EXECVE => do_execve(r, false),
        EXECVEAT => do_execve(r, true),
        CHDIR => r.path(0).and_then(|p| set_cwd(r, libc::AT_FDCWD, &p)),
        FCHDIR => guest_fd_path(r.fs(), r.pid, r.arg(0) as i32).and_then(|p| set_cwd(r, libc::AT_FDCWD, &p)),
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
/// the process opens and unlinks its record, and carries out the setup of a
/// nested launch, with host paths.  The mark is verified against
/// `/proc/<pid>/exe` so a program whose rewritten exec failed is not left
/// untranslated.  Serves both modes: with ptrace the trampoline's notified
/// syscalls come here and its traced ones to `syscall::traced`.
///
/// # Arguments
/// * `r` - The notification.
/// * `nr` - Canonical syscall number.
///
/// # Returns
/// `Some(Continue)` for the trampoline, `None` otherwise.
pub fn shim_passthrough(r: &Req, nr: i64) -> Option<Outcome> {
    if matches!(nr, EXECVE | EXECVEAT) || r.ctx.trap_mode() {
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
            if let Some((parent, addr, orig, written)) = &p.restore {
                restore_if_intact(r, *parent as u32, *addr, orig, written);
            }
            exec::finish_pending(r.ctx, tgid, p);
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
    let env = EnvSource::Address {
        envp: r.arg(argv_idx + 1),
        ptr_size: r.abi.ptr_size(),
    };
    let empty_path = is_at && user_path.is_empty();
    let plan = if empty_path {
        if at_flags & libc::AT_EMPTY_PATH == 0 {
            return Err(libc::ENOENT);
        }
        let guest = guest_dirfd_path(r.fs(), r.pid, dirfd)?;
        exec::plan(r.ctx, r.pid, libc::AT_FDCWD, &guest, argv, true, env)?
    } else {
        let deref = at_flags & libc::AT_SYMLINK_NOFOLLOW == 0;
        exec::plan(r.ctx, r.pid, dirfd, &user_path, argv, deref, env)?
    };
    if !is_at && !plan.changed {
        r.ctx.set_exe(tgid, plan.guest_prog, plan.host_prog);
        return Ok(Outcome::Continue);
    }
    if plan.trampoline.is_none() {
        check_executable(&plan)?;
    }
    r.valid()?;
    exec::debug_exec(r.pid, &plan);
    shim::write_record(tgid, &plan, None)?;
    let vfork_parent = r.ctx.tracee(tgid).vfork_parent;
    let mut orig = user_path.clone();
    orig.push(0);
    let mut pending = exec::pending_of(&plan);
    pending.restore = vfork_parent
        .filter(|_| !empty_path)
        .map(|parent| (parent, r.arg(path_idx), orig, b"e\0".to_vec()));
    r.ctx.procs.shim_enter(tgid, pending);
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

/// `execve`/`execveat` in the guest-stub restricted mode.
///
/// The stub staged the path and the vectors, or only `argv[0]` when they
/// did not fit, which is enough for anything but a nested launch.  The plan
/// is checked as [`do_execve`] checks it, plus what the trampoline's loader
/// cannot run; the mailbox is installed into the caller, the record
/// written, and the answer is the mailbox's descriptor number, on which
/// the stub execs the trampoline.
///
/// # Arguments
/// * `r` - The notification.
/// * `is_at` - `execveat` rather than `execve`.
///
/// # Returns
/// The mailbox's descriptor number in the caller, as the call's result.
///
/// # Errors
/// The errno the kernel would refuse the exec with, `E2BIG` for vectors too
/// large to stage when the plan needs them, or the error of reading the
/// arguments or installing the mailbox.
fn do_execve_trapped(r: &Req, is_at: bool) -> Result<Outcome> {
    let (dirfd, path_idx, argv_idx, at_flags) = if is_at {
        (r.arg(0) as i32, 1, 2, r.arg(4) as i32)
    } else {
        (libc::AT_FDCWD, 0, 1, 0)
    };
    let truncated = r.arg(layout::EXEC_TRUNCATED_ARG) != 0;
    let user_path = r.path(path_idx)?;
    let argv = exec::read_argv(r.ctx, r.pid, r.arg(argv_idx), r.abi.ptr_size())?;
    let env = EnvSource::Address {
        envp: r.arg(argv_idx + 1),
        ptr_size: r.abi.ptr_size(),
    };
    let plan = if is_at && user_path.is_empty() {
        if at_flags & libc::AT_EMPTY_PATH == 0 {
            return Err(libc::ENOENT);
        }
        let guest = guest_dirfd_path(r.fs(), r.pid, dirfd)?;
        exec::plan(r.ctx, r.pid, libc::AT_FDCWD, &guest, argv, true, env)?
    } else {
        let deref = at_flags & libc::AT_SYMLINK_NOFOLLOW == 0;
        exec::plan(r.ctx, r.pid, dirfd, &user_path, argv, deref, env)?
    };
    if truncated && plan.trampoline.is_some() {
        return Err(libc::E2BIG);
    }
    let narrow = check_loadable(r.ctx, &plan)?;
    r.valid()?;
    exec::debug_exec(r.pid, &plan);
    let mailbox = r.ctx.mailbox.ok_or(libc::ENOSYS)?;
    let copy = unsafe { libc::fcntl(mailbox, libc::F_DUPFD_CLOEXEC, 0) };
    if copy < 0 {
        return Err(errno());
    }
    let fd = addfd(r.listener, r.id, copy, false)?;
    commit_trapped(r.ctx, r.tgid(), &plan, fd, narrow)?;
    Ok(Outcome::Value(Ok(fd as i64)))
}

/// Plans the first tracee's exec in the guest-stub restricted mode, which
/// the supervisor itself sets up rather than a stub: the tracee execs the
/// trampoline through the allow gate with the mailbox it inherited.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `pid` - The first tracee, registered in the process table.
/// * `path` - The command as given.
/// * `argv` - Its argument vector.
/// * `env` - Its environment, as names and values.
///
/// # Errors
/// The errno the exec would have failed with.
pub fn plan_first_trapped(
    ctx: &Ctx,
    pid: i32,
    path: &[u8],
    argv: Vec<Vec<u8>>,
    env: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<()> {
    let plan = exec::plan(
        ctx,
        pid as u32,
        libc::AT_FDCWD,
        path,
        argv,
        true,
        EnvSource::Given(env),
    )?;
    let narrow = check_loadable(ctx, &plan)?;
    exec::debug_exec(pid as u32, &plan);
    commit_trapped(ctx, pid, &plan, ctx.mailbox.ok_or(libc::ENOSYS)?, narrow)
}

/// Writes the trampoline's record for a planned exec in the guest-stub mode
/// and marks the process as about to run it.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `tgid` - The process.
/// * `plan` - Its exec; its `user_path` becomes `AT_EXECFN` and the name.
/// * `mailbox` - The mailbox's descriptor number in the process.
/// * `narrow` - The program is 32-bit, for the 32-bit trampoline.
///
/// # Errors
/// Errno from writing the record.
fn commit_trapped(ctx: &Ctx, tgid: i32, plan: &ExecPlan, mailbox: i32, narrow: bool) -> Result<()> {
    let execfn = if plan.user_path.is_empty() {
        plan.guest_prog.clone()
    } else {
        plan.user_path.clone()
    };
    let mut name = exec::exec_name(&plan.user_path, &plan.guest_prog).to_vec();
    name.truncate(15);
    let trapped = Trapped {
        mailbox,
        execfn,
        name,
        narrow,
    };
    shim::write_record(tgid, plan, Some(&trapped))?;
    let mut pending = exec::pending_of(plan);
    if plan.trampoline.is_none() && plan.prefix > 1 {
        pending.cmdline_prefix = Some(plan.argv[..plan.prefix].to_vec());
    }
    ctx.procs.shim_enter(tgid, pending);
    Ok(())
}

/// Refuses, in the guest-stub mode, a plan the trampolines' loaders cannot
/// carry out, and tells which trampoline loads the rest.  Besides what the
/// kernel refuses (see [`check_executable`]) that is a format only
/// `binfmt_misc` would run, and a 32-bit program where the i386 trampoline
/// cannot run (a kernel without ia32 emulation).  A nested launch, which
/// the trampoline sets up first, is only classified.
///
/// # Arguments
/// * `ctx` - Shared supervisor state, for the diagnostic.
/// * `plan` - The exec.
///
/// # Returns
/// Whether the program is 32-bit, to be loaded by the i386 trampoline.
///
/// # Errors
/// The kernel's errno, `ENOEXEC` for an unknown format, `EOPNOTSUPP` for a
/// 32-bit program without the i386 trampoline.
fn check_loadable(ctx: &Ctx, plan: &ExecPlan) -> Result<bool> {
    if plan.trampoline.is_some() {
        return Ok(!plan.exec_path.is_empty()
            && matches!(
                exec::elf::classify_file(&plan.exec_path),
                Ok(exec::elf::FileKind::Elf32(_))
            ));
    }
    check_executable(plan)?;
    match exec::elf::classify_file(&plan.exec_path) {
        Ok(exec::elf::FileKind::Elf64(_)) => Ok(false),
        Ok(exec::elf::FileKind::Elf32(_)) if shim::has_32bit() => Ok(true),
        Ok(exec::elf::FileKind::Elf32(_)) => {
            note!(
                ctx,
                1,
                "{}: 32-bit programs cannot run here (no i386 trampoline)",
                String::from_utf8_lossy(&plan.guest_prog)
            );
            Err(libc::EOPNOTSUPP)
        }
        _ => Err(libc::ENOEXEC),
    }
}

/// Answers the trampoline's [`layout::HELLO`]: the exec planned for the
/// process has happened, so it now runs the program, in the view the plan
/// named.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `tid` - The calling thread.
pub fn hello(ctx: &Ctx, tid: u32) {
    let tgid = ctx.tgid(tid as i32);
    if let Some(p) = ctx.procs.shim_pending(tgid) {
        ctx.procs.shim_leave(tgid);
        exec::finish_pending(ctx, tgid, p);
    }
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
    let guest = retry(|| {
        let resolved = r.translate(dirfd, path, true)?;
        let mode = resolved.mode_nofollow()?;
        if mode & libc::S_IFMT == libc::S_IFLNK && resolved.pinned() {
            return Err(RETRY);
        }
        if mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(libc::ENOTDIR);
        }
        let (dfd, c, nofollow) = resolved.at(false)?;
        let flags = if nofollow { libc::AT_SYMLINK_NOFOLLOW } else { 0 };
        if unsafe { libc::syscall(libc::SYS_faccessat2, dfd, c.as_ptr(), libc::X_OK, flags) } < 0 {
            return Err(errno());
        }
        Ok(resolved.guest)
    })?;
    r.valid()?;
    r.ctx.procs.set_cwd(r.pid as i32, guest);
    Ok(Outcome::Value(Ok(0)))
}

/// Runs a lookup again while it finds a symlink swapped in since the walk.
fn retry<T>(mut f: impl FnMut() -> Result<T>) -> Result<T> {
    for _ in 0..3 {
        match f() {
            Err(RETRY) => continue,
            r => return r,
        }
    }
    Err(libc::ELOOP)
}

/// `chroot`: the guest root is a no-op, anything else is refused as it would
/// be for an unprivileged process.
fn do_chroot(r: &Req) -> Result<Outcome> {
    let resolved = r.translate(libc::AT_FDCWD, &r.path(0)?, true)?;
    if resolved.guest == b"/" {
        return Ok(Outcome::Value(Ok(0)));
    }
    Err(libc::EPERM)
}

/// `connect`/`bind` on an `AF_UNIX` path, done on a replacement socket.
///
/// The tracee's socket cannot be reached (`pidfd_getfd` is not allowed in a
/// default container), so a new socket of the same type, with the same
/// `O_NONBLOCK` and `O_CLOEXEC`, is connected or bound by the supervisor
/// and installed over the tracee's descriptor number.  The address names
/// the socket through its pinned parent, `/proc/self/fd/<parent>/<name>`,
/// since the socket calls have no `dirfd` form: the parents cannot be
/// redirected, while the kernel resolves the final name itself, so a
/// symlink the guest swaps in there during a `connect` is followed.
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
    let resolved = r.translate(libc::AT_FDCWD, &path, connect)?;
    if resolved.host == path {
        return Ok(Outcome::Continue);
    }
    if !connect {
        r.check_writable(&resolved)?;
    }
    let host = resolved.parent_path()?.into_bytes();
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
        String::from_utf8_lossy(&resolved.host)
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
/// path is rewritten to a transient alias, which the tracee then walks.
fn do_inotify_add_watch(r: &Req) -> Result<Outcome> {
    const IN_DONT_FOLLOW: u64 = 0x0200_0000;
    let path = r.path(1)?;
    let dont_follow = r.arg(2) & IN_DONT_FOLLOW != 0;
    let resolved = r.translate(libc::AT_FDCWD, &path, !dont_follow)?;
    if resolved.host == path {
        return Ok(Outcome::Continue);
    }
    let form = if dont_follow
        && resolved
            .mode_nofollow()
            .is_ok_and(|m| m & libc::S_IFMT == libc::S_IFLNK)
    {
        Form::Dir
    } else {
        Form::File
    };
    let mut orig = path.clone();
    orig.push(0);
    transient_rewrite(r, r.arg(1), &orig, &resolved.host, form)
}

/// An `O_PATH` open without ptrace.
///
/// Such descriptors cannot be injected, so directories and readable files
/// are opened read-only instead, which serves the same purposes (`openat`
/// relative to it, `fstat`, `/proc/self/fd/N`), through the pinned parent.
/// `O_DIRECTORY` on anything but a directory is refused with `ENOTDIR`
/// first, as the kernel does: `mv` probes its destination that way and
/// takes a descriptor for a directory to move into.
/// Anything else, a socket, a device, an unreadable file or a symlink opened
/// with `O_NOFOLLOW`, goes through a transient alias so the kernel opens it
/// in the tracee, which walks the host path itself.
///
/// # Arguments
/// * `r` - The notification.
/// * `dirfd` - Base of a relative `path`.
/// * `path` - Path as the tracee passed it.
/// * `path_addr` - Where that string lives in the tracee.
/// * `flags` - Host-form open flags, `O_PATH` included.
pub fn do_open_path(r: &Req, dirfd: i32, path: &[u8], path_addr: u64, flags: i64) -> Result<Outcome> {
    let nofollow = flags & libc::O_NOFOLLOW as i64 != 0;
    let resolved = r.translate(dirfd, path, !nofollow)?;
    if r.ctx.trap_mode() {
        return rewrite_staged(r, path_addr, &resolved.host);
    }
    let cloexec = flags & libc::O_CLOEXEC as i64 != 0;
    let kind = resolved.mode_nofollow()? & libc::S_IFMT;
    if flags & libc::O_DIRECTORY as i64 != 0 && kind != libc::S_IFDIR {
        return Err(libc::ENOTDIR);
    }
    let (dfd, c, nofollow) = resolved.at(true)?;
    let base = libc::O_RDONLY | libc::O_CLOEXEC | if nofollow { libc::O_NOFOLLOW } else { 0 };
    let direct = match kind {
        libc::S_IFDIR => Some(base | libc::O_DIRECTORY),
        libc::S_IFREG => Some(base),
        _ => None,
    };
    if let Some(open_flags) = direct {
        r.valid()?;
        let fd = unsafe { libc::openat(dfd, c.as_ptr(), open_flags) };
        if fd >= 0 {
            return Ok(Outcome::Fd { fd, cloexec });
        }
        if errno() != libc::EACCES {
            return Err(errno());
        }
    }
    if dirfd != libc::AT_FDCWD && path.first() != Some(&b'/') {
        if kernel_walks_alike(r.pid, dirfd, path, &resolved.host) {
            return Ok(Outcome::Continue);
        }
        return Err(libc::EACCES);
    }
    let form = if nofollow { Form::Dir } else { Form::File };
    let mut orig = path.to_vec();
    orig.push(0);
    transient_rewrite(r, path_addr, &orig, &resolved.host, form)
}

/// Whether the kernel, walking `path` from the tracee's `dirfd` by itself,
/// reaches `host`.
///
/// The descriptor is a host directory already, so a path that joins onto it
/// with nothing to translate on the way (no symlink among its components,
/// which canonicalization would have resolved) needs no rewrite.
///
/// # Arguments
/// * `pid` - Tracee thread id.
/// * `dirfd` - A directory descriptor of the tracee.
/// * `path` - Path relative to it, as the tracee passed it.
/// * `host` - What translation resolved it to.
fn kernel_walks_alike(pid: u32, dirfd: i32, path: &[u8], host: &[u8]) -> bool {
    let Ok(dir) = read_link(format!("/proc/{pid}/fd/{dirfd}").as_bytes()) else {
        return false;
    };
    let mut joined = strip_deleted(dir);
    if joined.first() != Some(&b'/') {
        return false;
    }
    if joined != b"/" {
        joined.push(b'/');
    }
    joined.extend_from_slice(path);
    joined == host
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
    /// path is `<alias>/<basename>`, for syscalls that must not follow the
    /// final component.  When that does not fit, a hard link to the target
    /// stands in, see [`place_alias`].
    Dir,
}

/// A transient alias in place: the bytes that replace the tracee's string,
/// and the hard link to remove once the syscall has consumed them.
struct Placed {
    repl: Vec<u8>,
    staged: Option<PathBuf>,
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
/// `ENAMETOOLONG` when no alias fits, or the errno of creating it.
fn transient_rewrite(r: &Req, addr: u64, orig: &[u8], host: &[u8], form: Form) -> Result<Outcome> {
    if r.ctx.trap_mode() {
        return rewrite_staged(r, addr, host);
    }
    let dir = shim::dir_bytes().ok_or(libc::ENOENT)?;
    let name = acquire_alias().ok_or(libc::EAGAIN)?;
    let placed = match place_alias(&dir, name, orig.len(), host, form, &staging_candidates(r.ctx)) {
        Ok(placed) => placed,
        Err(e) => {
            release_alias(name);
            return Err(e);
        }
    };
    let fail = |e: i32| {
        unstage(&placed);
        release_alias(name);
        e
    };
    let mut written = placed.repl.clone();
    written.push(0);
    r.valid().map_err(fail)?;
    let cpu_before = cpu_time(r.pid);
    r.ctx.mem.write_force(r.pid, addr, &written).map_err(fail)?;
    note!(
        r.ctx,
        2,
        "pid {} rewrote {} -> {} for {}",
        r.pid,
        String::from_utf8_lossy(&orig[..orig.len().saturating_sub(1)]),
        String::from_utf8_lossy(&placed.repl),
        String::from_utf8_lossy(host)
    );
    reply_continue(r.listener, r.id);
    wait_syscall_consumed(r, cpu_before);
    restore_if_intact(r, r.pid, addr, orig, &written);
    unstage(&placed);
    release_alias(name);
    Ok(Outcome::Replied)
}

/// Places the alias `name` for `host` so that its path fits in `room` bytes,
/// the tracee's string and its NUL.
///
/// A symlink in the alias directory comes first: to the target itself, or
/// to its parent with `<name>/<basename>` for a final component that must
/// be reached without following it.  When that does not fit, the final
/// component is reached through a hard link to it, which is the same inode:
/// as `<name>` in the alias directory when that is on the target's mount,
/// else as `<name>/<name>` through a staging directory on that mount.
///
/// # Arguments
/// * `dir` - The alias directory.
/// * `name` - The alias name held by the caller.
/// * `room` - Bytes available in the tracee for the path and its NUL.
/// * `host` - Host path the alias stands for.
/// * `form` - Alias form.
/// * `candidates` - Where a staging directory may be created, in order.
///
/// # Errors
/// `ENAMETOOLONG` when no placement fits, or the errno of creating the symlink.
fn place_alias(
    dir: &[u8],
    name: u8,
    room: usize,
    host: &[u8],
    form: Form,
    candidates: &[PathBuf],
) -> Result<Placed> {
    let link = Path::new(OsStr::from_bytes(dir)).join(OsStr::from_bytes(&[name]));
    let _ = std::fs::remove_file(&link);
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
    if repl.len() < room {
        std::os::unix::fs::symlink(OsStr::from_bytes(&target), &link).map_err(io_errno)?;
        return Ok(Placed { repl, staged: None });
    }
    if form != Form::Dir || room < 2 {
        return Err(libc::ENAMETOOLONG);
    }
    if link_nofollow(host, &link).is_ok() {
        return Ok(Placed {
            repl: vec![name],
            staged: Some(link),
        });
    }
    if room < 4 {
        return Err(libc::ENAMETOOLONG);
    }
    let staged = stage_hard_link(host, name, candidates).ok_or(libc::ENAMETOOLONG)?;
    let stage_dir = staged.parent().ok_or(libc::ENAMETOOLONG)?;
    if let Err(e) = std::os::unix::fs::symlink(stage_dir, &link) {
        let _ = std::fs::remove_file(&staged);
        return Err(io_errno(e));
    }
    Ok(Placed {
        repl: vec![name, b'/', name],
        staged: Some(staged),
    })
}

/// Removes the hard link an alias was placed through, once the syscall has
/// consumed the rewritten path; a descriptor opened through it keeps the inode.
///
/// # Arguments
/// * `placed` - The alias.
fn unstage(placed: &Placed) {
    if let Some(p) = &placed.staged {
        let _ = std::fs::remove_file(p);
    }
}

/// The errno of an I/O error, `EIO` for one without.
///
/// # Arguments
/// * `e` - The error.
fn io_errno(e: std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

/// `linkat` without `AT_SYMLINK_FOLLOW`: a hard link to `host` itself, a
/// symlink included.
///
/// # Arguments
/// * `host` - Existing path.
/// * `at` - Path of the new link.
///
/// # Errors
/// The errno of `linkat`.
fn link_nofollow(host: &[u8], at: &Path) -> Result<()> {
    let src = CString::new(host.to_vec()).map_err(|_| libc::EINVAL)?;
    let dst = CString::new(at.as_os_str().as_bytes().to_vec()).map_err(|_| libc::EINVAL)?;
    if unsafe { libc::linkat(libc::AT_FDCWD, src.as_ptr(), libc::AT_FDCWD, dst.as_ptr(), 0) } < 0 {
        return Err(errno());
    }
    Ok(())
}

/// Makes a hard link named `name` to `host` in a staging directory on its
/// mount, creating one under the first of `candidates` that allows it.
///
/// # Arguments
/// * `host` - Existing path.
/// * `name` - The alias name held by the caller.
/// * `candidates` - Where a staging directory may be created, in order.
///
/// # Returns
/// The hard link's path, or `None` when no directory on that mount can hold
/// one: a read-only mount, no writable candidate on it, or a symlink of
/// another owner under `fs.protected_hardlinks`.
fn stage_hard_link(host: &[u8], name: u8, candidates: &[PathBuf]) -> Option<PathBuf> {
    let link_in = |d: &Path| {
        let p = d.join(OsStr::from_bytes(&[name]));
        let _ = std::fs::remove_file(&p);
        link_nofollow(host, &p).ok().map(|()| p)
    };
    let mut staging = STAGING.lock().unwrap();
    if let Some(p) = staging.iter().find_map(|d| link_in(d)) {
        return Some(p);
    }
    for base in candidates {
        let d = base.join(format!("proot-next-{}-stage", std::process::id()));
        if std::fs::DirBuilder::new().mode(0o700).create(&d).is_err() {
            continue;
        }
        if let Some(p) = link_in(&d) {
            staging.push(d);
            return Some(p);
        }
        let _ = std::fs::remove_dir(&d);
    }
    None
}

/// Where a staging directory may be created, in order: the user's cache
/// directory, beside the rootfs, and the temporary directory.
///
/// # Arguments
/// * `ctx` - Supervisor state.
fn staging_candidates(ctx: &Ctx) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(c) = std::env::var_os("XDG_CACHE_HOME").filter(|c| !c.is_empty()) {
        v.push(PathBuf::from(c));
    } else if let Some(h) = std::env::var_os("HOME") {
        v.push(PathBuf::from(h).join(".cache"));
    }
    if let Some(parent) = Path::new(OsStr::from_bytes(&ctx.config.root)).parent() {
        v.push(parent.to_path_buf());
    }
    v.push(std::env::temp_dir());
    v
}

/// Removes the staging directories, at exit.
pub fn remove_staging() {
    for d in STAGING.lock().unwrap().drain(..) {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// Whether `host` lies in the alias directory or a staging directory.
///
/// # Arguments
/// * `host` - A host path.
fn under_alias(host: &[u8]) -> bool {
    let within = |d: &[u8]| host.len() > d.len() && host.starts_with(d) && host[d.len()] == b'/';
    shim::dir_bytes().is_some_and(|d| within(&d))
        || STAGING
            .lock()
            .unwrap()
            .iter()
            .any(|d| within(d.as_os_str().as_bytes()))
}

/// `readlinkat` with an empty path on a descriptor opened through a hard
/// link alias: the answer comes from the descriptor's own inode, reopened
/// through `/proc`, since the link it was opened by is gone by then and its
/// name may stand for something else.
///
/// # Arguments
/// * `r` - The notification.
/// * `dirfd` - The descriptor.
/// * `path` - The path argument.
///
/// # Returns
/// `None` when the call is not such a read, which the caller serves by path.
pub fn readlink_alias_fd(r: &Req, dirfd: i32, path: &[u8]) -> Option<Result<Vec<u8>>> {
    if !r.ctx.no_ptrace || !path.is_empty() || dirfd < 0 {
        return None;
    }
    let proc_link = format!("/proc/{}/fd/{}", r.pid, dirfd);
    let host = strip_deleted(read_link(proc_link.as_bytes()).ok()?);
    if !under_alias(&host) {
        return None;
    }
    Some(readlink_reopened(&proc_link))
}

/// Reads the target of the symlink a `/proc/<pid>/fd/N` link leads to, by
/// reopening it `O_PATH` here, which lands on that inode whether or not its
/// name still exists.
///
/// # Arguments
/// * `proc_link` - The `/proc` link.
///
/// # Errors
/// The errno of the reopen, or `ENOENT` where the inode is no symlink, as
/// the kernel answers an empty path on such a descriptor.
fn readlink_reopened(proc_link: &str) -> Result<Vec<u8>> {
    let c = CString::new(proc_link).map_err(|_| libc::EINVAL)?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(errno());
    }
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let n = unsafe { libc::readlinkat(fd, c"".as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    let e = errno();
    unsafe { libc::close(fd) };
    if n < 0 {
        return Err(if e == libc::EINVAL { libc::ENOENT } else { e });
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// Replaces a path the guest stub staged with its host path and lets the
/// syscall continue on it.
///
/// # Arguments
/// * `r` - The notification.
/// * `addr` - Address of the staged path, a [`layout::PATH_AREA`] of the mailbox.
/// * `host` - The host path.
///
/// # Errors
/// `ENAMETOOLONG` for a host path that does not fit, `EFAULT` for an
/// address outside the mailbox.
fn rewrite_staged(r: &Req, addr: u64, host: &[u8]) -> Result<Outcome> {
    if host.len() >= layout::PATH_AREA {
        return Err(libc::ENAMETOOLONG);
    }
    let mut bytes = host.to_vec();
    bytes.push(0);
    r.valid()?;
    r.ctx.mem.write(r.pid, addr, &bytes)?;
    note!(
        r.ctx,
        2,
        "pid {} rewrote the staged path to {}",
        r.pid,
        String::from_utf8_lossy(host)
    );
    Ok(Outcome::Continue)
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

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("proot-direct-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn hard_link_alias_is_the_symlink_itself() {
        use std::os::unix::fs::MetadataExt;
        let d = scratch("hardlink");
        let link = d.join("link");
        std::os::unix::fs::symlink("target", &link).unwrap();
        let alias_dir = d.join("alias");
        std::fs::create_dir(&alias_dir).unwrap();
        let (dir, host) = (alias_dir.as_os_str().as_bytes(), link.as_os_str().as_bytes());
        let name = acquire_alias().unwrap();
        let want = std::fs::symlink_metadata(&link).unwrap();
        let placed = place_alias(dir, name, b"link\0".len(), host, Form::Dir, &[]).unwrap();
        assert_eq!(placed.repl, vec![name]);
        let got = std::fs::symlink_metadata(alias_dir.join(OsStr::from_bytes(&[name]))).unwrap();
        assert!(got.file_type().is_symlink());
        assert_eq!((got.dev(), got.ino()), (want.dev(), want.ino()));
        assert_eq!(std::fs::symlink_metadata(&link).unwrap().nlink(), 2);
        unstage(&placed);
        assert_eq!(std::fs::symlink_metadata(&link).unwrap().nlink(), 1);
        assert_eq!(
            place_alias(dir, name, b"\0".len(), host, Form::Dir, &[]).err(),
            Some(libc::ENAMETOOLONG)
        );
        let fits = place_alias(dir, name, b"./link\0".len(), host, Form::Dir, &[]).unwrap();
        assert!(fits.staged.is_none());
        assert_eq!(fits.repl, [&[name, b'/'][..], b"link"].concat());
        release_alias(name);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn staging_directory_holds_a_link_on_the_symlinks_mount() {
        use std::os::unix::fs::MetadataExt;
        let d = scratch("staging");
        let link = d.join("link");
        std::os::unix::fs::symlink("target", &link).unwrap();
        let host = link.as_os_str().as_bytes();
        let name = acquire_alias().unwrap();
        let staged =
            stage_hard_link(host, name, &[d.join("missing"), d.clone()]).expect("a staging directory");
        let stage_dir = staged.parent().unwrap().to_path_buf();
        assert_eq!(stage_dir.parent(), Some(d.as_path()));
        let (want, got) = (
            std::fs::symlink_metadata(&link).unwrap(),
            std::fs::symlink_metadata(&staged).unwrap(),
        );
        assert_eq!((got.dev(), got.ino()), (want.dev(), want.ino()));
        assert!(under_alias(staged.as_os_str().as_bytes()));
        assert!(!under_alias(host));
        assert_eq!(stage_hard_link(host, name, &[]), Some(staged.clone()));
        remove_staging();
        assert!(!stage_dir.exists());
        release_alias(name);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn kernel_walks_a_single_component_from_a_directory_descriptor() {
        let d = scratch("walk");
        std::os::unix::fs::symlink("target", d.join("link")).unwrap();
        let c = CString::new(d.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        let host = d.join("link");
        let host = host.as_os_str().as_bytes();
        let pid = std::process::id();
        assert!(kernel_walks_alike(pid, fd, b"link", host));
        assert!(!kernel_walks_alike(pid, fd, b"./link", host));
        assert!(!kernel_walks_alike(pid, fd, b"link", b"/elsewhere/link"));
        assert!(!kernel_walks_alike(pid, -1, b"link", host));
        unsafe { libc::close(fd) };
        std::fs::remove_dir_all(d).unwrap();
    }
}
