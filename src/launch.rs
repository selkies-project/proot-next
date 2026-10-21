//! Starting the first tracee and wiring supervisor, listener and tracer.
//!
//! The child installs the seccomp filter and hands the listener back over a
//! socketpair, then waits for one byte.  The parent seizes it with ptrace,
//! starts the notification pool and sends the byte, so the child's first
//! traced syscall already has a tracer and no `SIGSTOP` handshake is needed.
//!
//! Where the ptrace syscall is filtered out (a hardened container profile),
//! or when `PROOT_NO_PTRACE` is set, there is no tracer: the filter sends the
//! trace tier to the listener as well, the child's kernel working directory
//! is pinned to the alias directory holding the exec shim, and the handlers
//! in `syscall::direct` do the rest.  The process table is then lazy and a
//! reaper thread watches pidfds for exits.
//!
//! Where the kernel's ptrace access check refuses the supervisor even
//! towards its own child (Yama's `ptrace_scope` of 2), the first tracee
//! enters a user namespace of its own before installing the filter; see
//! `access`.  Where that is refused too, the guest-stub restricted mode
//! (see `guest_stub`) traps the served syscalls into a stub inside each
//! guest, and the first tracee execs the trampoline that arms it, with a
//! plan the supervisor wrote before letting it go.

use crate::access;
use crate::cli::bwrap;
use crate::config::Config;
use crate::exec::shim;
use crate::fs::translate::{detranslate_path, translate_path};
use crate::guest_stub::{self, layout};
use crate::note;
use crate::procs::{ProcTable, TraceeInfo};
use crate::seccomp::{filter, notify};
use crate::state::Ctx;
use crate::sys::{errno, strerror};
use crate::syscall::{
    DUMPABLE_SYSCALLS, NAMESPACE_FLAG_SYSCALLS, NO_PTRACE_SYSCALLS, NOTIFY_SYSCALLS, REFUSED_SYSCALLS,
    TRACE_SYSCALLS, direct, nr,
};
use crate::tracee::ptrace;
use crate::tracer;
use std::ffi::CString;
use std::os::unix::ffi::OsStringExt;
use std::sync::Arc;

unsafe extern "C" {
    static environ: *const *const libc::c_char;
}

/// Runs the configured command under supervision and returns its exit code.
///
/// The child installs the seccomp filter and hands the listener back over a
/// socketpair before stopping itself; the parent then becomes the tracer and
/// starts the notification pool.
///
/// # Arguments
/// * `config` - Fully parsed configuration.
///
/// # Errors
/// A message describing why the command could not be started.
pub fn run(config: Config) -> Result<i32, String> {
    if config.command.is_empty() {
        return Err("no command given".into());
    }
    let mut config = config;
    resolve_command_in_path(&mut config);
    let access = match access::probe(
        !no_ptrace_forced() && direct::ptrace_usable(),
        guest_stub_choice(),
    ) {
        Ok(a) => a,
        Err(e) if config.bwrap_mode => exit_like_bwrap_without_namespaces(&e),
        Err(e) => return Err(e),
    };
    let no_ptrace = !access.ptrace;
    let mut ctx = Ctx::new(config, no_ptrace);
    if access.trap_mode {
        ctx.mailbox = Some(guest_stub::Mailbox::create()?.fd);
    }
    let ctx = Arc::new(ctx);
    let trap_mode = ctx.trap_mode();
    if no_ptrace {
        note!(
            ctx,
            1,
            "running without ptrace: the trace tier is served through notifications"
        );
    }
    if trap_mode {
        note!(
            ctx,
            1,
            "running in the guest-stub mode: a stub in each guest stages syscall memory through a shared mailbox"
        );
    }
    if access.userns.is_some() {
        note!(
            ctx,
            1,
            "the guest runs in a user namespace of its own: the ptrace access check refuses a plain child"
        );
    }
    let mut notify_list: Vec<i64> = NOTIFY_SYSCALLS.to_vec();
    notify_list.push(nr::CLONE3);
    let trace_list: &[i64] = if no_ptrace {
        notify_list.extend_from_slice(NO_PTRACE_SYSCALLS);
        &[]
    } else {
        TRACE_SYSCALLS
    };
    if ctx.config.kernel_release.is_some() || ctx.config.hostname.is_some() {
        notify_list.push(nr::UNAME);
    }
    if ctx.config.fake_root {
        notify_list.extend_from_slice(crate::syscall::FAKE_ROOT_SYSCALLS);
    }
    let (native, compat) = (crate::abi::Abi::native(), crate::abi::Abi::compat());
    let (notify64, trace64) = (native.numbers_for(&notify_list), native.numbers_for(trace_list));
    let (notify32, trace32) = (compat.numbers_for(&notify_list), compat.numbers_for(trace_list));
    let ns_list: Vec<i64> = NAMESPACE_FLAG_SYSCALLS
        .iter()
        .copied()
        .filter(|nr| !notify_list.contains(nr))
        .collect();
    let (ns64, ns32) = (native.numbers_for(&ns_list), compat.numbers_for(&ns_list));
    let (dumpable64, dumpable32) = (
        native.numbers_for(DUMPABLE_SYSCALLS),
        compat.numbers_for(DUMPABLE_SYSCALLS),
    );
    let (refused64, refused32) = (
        native.numbers_for(REFUSED_SYSCALLS),
        compat.numbers_for(REFUSED_SYSCALLS),
    );
    let program = if trap_mode {
        let (mut trapped64, direct64): (Vec<i64>, Vec<i64>) =
            notify64.iter().partition(|nr| layout::trapped64(**nr));
        let (mut trapped32, direct32): (Vec<i64>, Vec<i64>) =
            notify32.iter().partition(|nr| layout::trapped32(**nr));
        trapped64.extend(layout::SIGNAL_CALLS64);
        trapped32.extend(layout::SIGNAL_CALLS32);
        filter::build_trapped(
            &filter::Table {
                abi: native,
                notify: &direct64,
                trace: &trapped64,
                ns_flags: &ns64,
                refused: &refused64,
                dumpable: &dumpable64,
            },
            &filter::Table {
                abi: compat,
                notify: &direct32,
                trace: &trapped32,
                ns_flags: &ns32,
                refused: &refused32,
                dumpable: &dumpable32,
            },
        )
    } else {
        filter::build(
            &filter::Table {
                abi: native,
                notify: &notify64,
                trace: &trace64,
                ns_flags: &ns64,
                refused: &refused64,
                dumpable: &dumpable64,
            },
            &filter::Table {
                abi: compat,
                notify: &notify32,
                trace: &trace32,
                ns_flags: &ns32,
                refused: &refused32,
                dumpable: &dumpable32,
            },
            no_ptrace,
        )
    };

    // argv[0] may be overridden (bwrap --argv0); the program path is always command[0].
    let program_path = ctx.config.command[0].as_ptr();
    let argv: Vec<*const libc::c_char> = std::iter::once(
        ctx.config
            .argv0
            .as_ref()
            .unwrap_or(&ctx.config.command[0])
            .as_ptr(),
    )
    .chain(ctx.config.command.iter().skip(1).map(|c| c.as_ptr()))
    .chain(std::iter::once(std::ptr::null()))
    .collect();
    // The initial cwd is a guest path; the child's chdir(2) is a traced syscall
    // so the tracer translates it like any other.
    let is_dir = |guest: &[u8]| {
        translate_path(&ctx.root.fs, std::process::id(), libc::AT_FDCWD, guest, true)
            .map(|h| {
                std::fs::metadata(std::ffi::OsStr::from_bytes_hack(&h))
                    .map(|m| m.is_dir())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    };
    let start = bwrap::start_dir(&ctx.config, is_dir);
    let host_cwd_exists = start.is_some();
    if !(host_cwd_exists || (ctx.config.bwrap_mode && ctx.config.cwd_default)) {
        eprintln!(
            "proot: can't chdir to {} in the guest rootfs, using /",
            String::from_utf8_lossy(&ctx.config.cwd)
        );
    }
    let start = start.unwrap_or_else(|| b"/".to_vec());
    let cwd = CString::new(start.clone()).map_err(|_| "cwd contains NUL")?;
    let env = ctx.config.env.as_ref().map(|e| {
        if ctx.config.bwrap_mode {
            bwrap::with_pwd(e, &start)
        } else {
            e.clone()
        }
    });
    let env_storage: Option<Vec<*const libc::c_char>> = env.as_ref().map(|e| {
        e.iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect()
    });
    let envp: *const *const libc::c_char = match &env_storage {
        Some(v) => v.as_ptr(),
        None => unsafe { environ },
    };
    let slash = CString::new("/").unwrap();
    let mailbox = ctx.mailbox;
    let pinned_cwd: Option<CString> = if no_ptrace {
        let dir = shim::install()?;
        become_subreaper();
        Some(CString::new(dir.into_os_string().into_vec()).map_err(|_| "alias directory contains NUL")?)
    } else {
        None
    };
    let initial_cwd: Vec<u8> = if host_cwd_exists {
        translate_path(&ctx.root.fs, std::process::id(), libc::AT_FDCWD, &start, true)
            .map(|h| detranslate_path(&ctx.root.fs, &h))
            .unwrap_or_else(|_| b"/".to_vec())
    } else {
        b"/".to_vec()
    };
    // Caller-supplied seccomp programs (bwrap --seccomp): converted before fork so the child does not allocate.
    let extra_programs: Vec<Vec<filter::SockFilter>> = ctx
        .config
        .seccomp_programs
        .iter()
        .map(|bytes| filter::from_bytes(bytes))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| format!("--seccomp program: {e}"))?;

    let mut sv = [0i32; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } < 0
    {
        return Err(format!("socketpair: {}", strerror(errno())));
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", strerror(errno())));
    }
    if pid == 0 {
        // Child: nothing here may allocate.
        unsafe {
            libc::close(sv[0]);
            if let Some(dir) = &pinned_cwd {
                if libc::chdir(dir.as_ptr()) < 0 {
                    libc::_exit(121);
                }
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            }
            if let Some(ns) = &access.userns
                && ns.enter().is_err()
            {
                libc::_exit(118);
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                libc::_exit(120);
            }
            let fd = match filter::install(&program) {
                Ok(fd) => fd,
                Err(libc::EBUSY) => libc::_exit(119),
                Err(_) => libc::_exit(122),
            };
            if !send_fd(sv[1], fd) {
                libc::_exit(123);
            }
            libc::close(fd);
            if ctx.config.new_session {
                libc::setsid();
            }
            for prog in &extra_programs {
                if filter::install_plain(prog).is_err() {
                    libc::_exit(124);
                }
            }
            // Wait for the parent to seize us before the first traced syscall.
            let mut go = 0u8;
            if libc::read(sv[1], &mut go as *mut u8 as *mut _, 1) != 1 {
                libc::_exit(125);
            }
            libc::close(sv[1]);
            if go != 0 {
                libc::_exit(go as i32);
            }
            // From here on every traced syscall is served by the parent.
            if pinned_cwd.is_none() && (!host_cwd_exists || libc::chdir(cwd.as_ptr()) < 0) {
                libc::chdir(slash.as_ptr());
            }
            if let Some(mail) = mailbox {
                guest_stub::exec_trampoline(
                    mail,
                    guest_stub::layout::SHIM_PATH.as_ptr().cast(),
                    argv.as_ptr(),
                    envp,
                );
            }
            libc::execve(program_path, argv.as_ptr(), envp);
            let e = *libc::__errno_location();
            libc::_exit(if e == libc::ENOENT { 127 } else { 126 });
        }
    }
    unsafe { libc::close(sv[1]) };
    let listener = match recv_fd(sv[0]) {
        Some(fd) => fd,
        None => {
            unsafe { libc::close(sv[0]) };
            let mut st = 0;
            unsafe { libc::waitpid(pid, &mut st, libc::__WALL) };
            return Err(match libc::WEXITSTATUS(st) {
                119 if ctx.config.bwrap_mode => {
                    exit_like_bwrap_without_namespaces("proot-next cannot run under another supervisor")
                }
                118 => "cannot enter the user namespace the probe entered".into(),
                119 => "the seccomp filter chain already has a listener (a supervisor other than proot-next)"
                    .into(),
                120 => "PR_SET_NO_NEW_PRIVS refused".into(),
                121 => "cannot enter the alias directory".into(),
                124 => "the caller's --seccomp program was refused by the kernel".into(),
                122 => "seccomp user notification is not available on this kernel or is filtered".into(),
                _ => "child failed before handing over the seccomp listener".into(),
            });
        }
    };
    if no_ptrace {
        ctx.procs.register_root(
            pid,
            TraceeInfo {
                cwd: Some(initial_cwd),
                ..Default::default()
            },
        );
        if let Err(e) = ProcTable::start_reaper(&ctx.procs) {
            eprintln!("proot: cannot watch process exits: {}", strerror(e));
        }
    } else if let Err(e) = ptrace::seize(pid, tracer::options(&ctx)) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::close(sv[0]);
            libc::close(listener);
            let mut st = 0;
            libc::waitpid(pid, &mut st, libc::__WALL);
        }
        if e == libc::EPERM && ctx.config.bwrap_mode {
            exit_like_bwrap_without_namespaces("proot-next cannot run under another supervisor");
        }
        return Err(match e {
            libc::EPERM => "ptrace(PTRACE_SEIZE) refused: this process is already traced (a debugger, or a supervisor other than proot-next) or ptrace is disallowed here".into(),
            e => format!("ptrace(PTRACE_SEIZE): {}", strerror(e)),
        });
    }
    report_status(&ctx.config.info_fds, &format!("{{\"child-pid\": {pid}}}\n"));
    report_status(
        &ctx.config.json_status_fds,
        &format!("{{\"child-pid\": {pid}}}\n"),
    );
    let go = if trap_mode {
        match plan_first_trapped(&ctx, pid, env.as_deref()) {
            Ok(()) => 0u8,
            Err(libc::ENOENT) => 127,
            Err(_) => 126,
        }
    } else {
        0
    };
    let pool = notify::start(listener, ctx.clone());
    if unsafe { libc::write(sv[0], &go as *const u8 as *const _, 1) } != 1 {
        return Err("could not release the first tracee".into());
    }
    unsafe { libc::close(sv[0]) };
    let code = if no_ptrace {
        let code = wait_root(pid);
        pool.wait_closed();
        code
    } else {
        tracer::run(&ctx, pid)
    };
    unsafe { libc::close(listener) };
    report_status(
        &ctx.config.json_status_fds,
        &format!("{{\"exit-code\": {code}}}\n"),
    );
    // PROOT_BWRAP_KEEP=1 leaves the materialized root behind for inspection.
    let keep = std::env::var_os("PROOT_BWRAP_KEEP").is_some();
    ctx.root.remove_placeholders();
    let _ = std::fs::remove_dir_all(crate::exec::alias_dir());
    if let Some(dir) = shim::path().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
        let _ = std::fs::remove_dir_all(dir);
    }
    for dir in ctx.config.cleanup_dirs.iter().filter(|_| !keep) {
        let _ = std::fs::remove_dir_all(std::ffi::OsStr::from_bytes_hack(dir));
    }
    Ok(code)
}

/// Plans the first tracee's exec in the guest-stub restricted mode: its
/// command, argument vector and environment as the child will exec them.
///
/// # Arguments
/// * `ctx` - Shared supervisor state, with the first tracee registered.
/// * `pid` - The first tracee.
/// * `env` - The environment the child execs with, `None` for the supervisor's.
///
/// # Errors
/// The errno the exec would have failed with.
fn plan_first_trapped(ctx: &Ctx, pid: i32, env: Option<&[CString]>) -> crate::sys::Result<()> {
    let argv: Vec<Vec<u8>> = std::iter::once(ctx.config.argv0.as_ref().unwrap_or(&ctx.config.command[0]))
        .chain(ctx.config.command.iter().skip(1))
        .map(|c| c.as_bytes().to_vec())
        .collect();
    let split = |e: &[u8]| match e.iter().position(|&b| b == b'=') {
        Some(i) => (e[..i].to_vec(), e[i + 1..].to_vec()),
        None => (e.to_vec(), Vec::new()),
    };
    let env: Vec<(Vec<u8>, Vec<u8>)> = match env {
        Some(e) => e.iter().map(|c| split(c.as_bytes())).collect(),
        None => std::env::vars_os()
            .map(|(k, v)| (k.into_vec(), v.into_vec()))
            .collect(),
    };
    direct::plan_first_trapped(ctx, pid, ctx.config.command[0].as_bytes(), argv, env)
}

/// When the guest-stub restricted mode may be used, from `PROOT_GUEST_STUB`:
/// as the fallback where nothing else reaches the guest's memory (unset, or
/// any other value), anywhere (`force`), or never (`0`).
///
/// # Returns
/// `Some(false)` for the fallback, `Some(true)` for `force`, `None` for `0`.
fn guest_stub_choice() -> Option<bool> {
    match std::env::var_os("PROOT_GUEST_STUB") {
        Some(v) if v == "0" => None,
        Some(v) => Some(v == "force"),
        None => Some(false),
    }
}

/// Whether `PROOT_NO_PTRACE` forces the mode without a ptrace tier (any
/// value but `0`).
///
/// # Returns
/// `true` when the mode is forced.
fn no_ptrace_forced() -> bool {
    std::env::var_os("PROOT_NO_PTRACE").is_some_and(|v| v != "0")
}

/// Exits the way bubblewrap exits when it cannot create its namespaces.
///
/// A supervisor cannot start under another tracer or another listener, nor
/// on a host that refuses it access to its own child.  Inside proot-next
/// the first never happens, since an exec of bwrap is served as a nested
/// launch (see `exec::nested`); otherwise the caller is a program that
/// started us as bubblewrap, and those programs know this message (GTK's
/// glycin runs its image loaders unsandboxed on seeing it).
///
/// # Arguments
/// * `reason` - Why proot-next cannot start, appended to the message.
fn exit_like_bwrap_without_namespaces(reason: &str) -> ! {
    eprintln!("bwrap: No permissions to create a new namespace: {reason}");
    std::process::exit(1);
}

/// Makes the supervisor the parent of every orphan among its descendants.
///
/// Without ptrace the supervisor reads and writes tracee memory on its own
/// authority, which Yama's default `ptrace_scope` of 1 grants only towards
/// descendants.  A daemon that double-forks would be reparented to init and
/// lose that standing; as a child subreaper the supervisor adopts it
/// instead, and [`wait_root`] reaps it.
fn become_subreaper() {
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
}

/// Waits for the first tracee and returns the exit code to report, reaping
/// every other child along the way.
///
/// Without ptrace the first tracee is the supervisor's own child and, with
/// [`become_subreaper`], so is every orphaned descendant.  Once the first
/// tracee is gone a thread keeps reaping until the process exits; the pool
/// closes when no process uses the filter any more, the point at which the
/// tracer loop would have run out of tracees.
///
/// # Arguments
/// * `pid` - The first tracee.
fn wait_root(pid: i32) -> i32 {
    let code = loop {
        let mut status = 0;
        let got = unsafe { libc::waitpid(-1, &mut status, 0) };
        if got < 0 {
            match errno() {
                libc::EINTR => continue,
                _ => break 1,
            }
        }
        if got != pid {
            continue;
        }
        if libc::WIFEXITED(status) {
            break libc::WEXITSTATUS(status);
        }
        if libc::WIFSIGNALED(status) {
            break 128 + libc::WTERMSIG(status);
        }
    };
    std::thread::Builder::new()
        .name("subreaper".into())
        .spawn(|| {
            loop {
                let mut status = 0;
                if unsafe { libc::waitpid(-1, &mut status, 0) } < 0 && errno() == libc::ECHILD {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        })
        .expect("spawn subreaper thread");
    code
}

/// Writes one status line to each of bubblewrap's `--info-fd`/`--json-status-fd` descriptors.
///
/// # Arguments
/// * `fds` - Descriptor numbers inherited from the caller; write errors are ignored.
/// * `line` - Text to write, newline included.
fn report_status(fds: &[i32], line: &str) {
    for &fd in fds {
        unsafe { libc::write(fd, line.as_ptr() as *const _, line.len()) };
    }
}

/// Resolves a bare command name through `PATH`, as seen from inside the guest.
///
/// bubblewrap and the shells exec with PATH search; the kernel does not.  The
/// search uses the `PATH` of the environment the command will receive and
/// checks each candidate on the host side of the translation.  An unresolved
/// name is left alone so the kernel reports `ENOENT`.
///
/// # Arguments
/// * `config` - Configuration whose `command[0]` may be a bare name.
fn resolve_command_in_path(config: &mut Config) {
    let Some(first) = config.command.first() else {
        return;
    };
    let name = first.as_bytes().to_vec();
    if name.is_empty() || name.contains(&b'/') {
        return;
    }
    let path_var: Vec<u8> = match &config.env {
        Some(env) => env
            .iter()
            .find_map(|e| e.as_bytes().strip_prefix(b"PATH=").map(|v| v.to_vec()))
            .unwrap_or_default(),
        None => std::env::var_os("PATH")
            .map(|p| std::os::unix::ffi::OsStrExt::as_bytes(p.as_os_str()).to_vec())
            .unwrap_or_default(),
    };
    let fs = crate::fs::Fs::new(config);
    for dir in path_var.split(|&c| c == b':').filter(|d| !d.is_empty()) {
        let mut guest = dir.to_vec();
        if !guest.ends_with(b"/") {
            guest.push(b'/');
        }
        guest.extend_from_slice(&name);
        let Ok(host) = translate_path(&fs, std::process::id(), libc::AT_FDCWD, &guest, true) else {
            continue;
        };
        let Ok(c) = CString::new(host) else { continue };
        if unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0 {
            if let Ok(g) = CString::new(guest) {
                // execvp semantics: argv[0] stays the name as typed.
                if config.argv0.is_none() {
                    config.argv0 = Some(config.command[0].clone());
                }
                config.command[0] = g;
            }
            return;
        }
    }
}

/// Sends a descriptor over a unix socket with `SCM_RIGHTS`.  Allocation free.
fn send_fd(sock: i32, fd: i32) -> bool {
    let mut byte = 1u8;
    let mut iov = libc::iovec {
        iov_base: &mut byte as *mut u8 as *mut _,
        iov_len: 1,
    };
    let mut cbuf = [0u8; 24];
    cbuf[0..8].copy_from_slice(&20u64.to_ne_bytes());
    cbuf[8..12].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
    cbuf[12..16].copy_from_slice(&libc::SCM_RIGHTS.to_ne_bytes());
    cbuf[16..20].copy_from_slice(&fd.to_ne_bytes());
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = 24;
    unsafe { libc::sendmsg(sock, &msg, 0) == 1 }
}

/// Receives a descriptor sent by [`send_fd`].
fn recv_fd(sock: i32) -> Option<i32> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: &mut byte as *mut u8 as *mut _,
        iov_len: 1,
    };
    let mut cbuf = [0u8; 24];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = 24;
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n != 1 || msg.msg_controllen < 20 {
        return None;
    }
    Some(i32::from_ne_bytes(cbuf[16..20].try_into().unwrap()))
}

/// Byte-slice to `OsStr` helper kept local to avoid a trait import at call sites.
trait FromBytesHack {
    fn from_bytes_hack(b: &[u8]) -> &std::ffi::OsStr;
}
impl FromBytesHack for std::ffi::OsStr {
    fn from_bytes_hack(b: &[u8]) -> &std::ffi::OsStr {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(b)
    }
}
