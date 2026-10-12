//! Starting the first tracee and wiring supervisor, listener and tracer.
//!
//! The child installs the seccomp filter and hands the listener back over a
//! socketpair, then waits for one byte.  The parent seizes it with ptrace,
//! starts the notification pool and sends the byte, so the child's first
//! traced syscall already has a tracer and no `SIGSTOP` handshake is needed.

use crate::config::Config;
use crate::fs::translate::translate_path;
use crate::seccomp::{filter, notify};
use crate::state::Ctx;
use crate::sys::{errno, strerror};
use crate::syscall::{NOTIFY_SYSCALLS, TRACE_SYSCALLS, nr};
use crate::tracee::ptrace;
use crate::tracer;
use std::ffi::CString;
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
    let ctx = Arc::new(Ctx::new(config));
    let mut notify_list: Vec<i64> = NOTIFY_SYSCALLS.to_vec();
    if ctx.config.kernel_release.is_some() || ctx.config.hostname.is_some() {
        notify_list.push(nr::UNAME);
    }
    if ctx.config.fake_root {
        notify_list.extend_from_slice(crate::syscall::FAKE_ROOT_SYSCALLS);
    }
    let (native, compat) = (crate::abi::Abi::native(), crate::abi::Abi::compat());
    let (notify64, trace64) = (
        native.numbers_for(&notify_list),
        native.numbers_for(TRACE_SYSCALLS),
    );
    let (notify32, trace32) = (
        compat.numbers_for(&notify_list),
        compat.numbers_for(TRACE_SYSCALLS),
    );
    let program = filter::build(
        &filter::Table {
            abi: native,
            notify: &notify64,
            trace: &trace64,
        },
        &filter::Table {
            abi: compat,
            notify: &notify32,
            trace: &trace32,
        },
    );

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
    let env_storage: Option<Vec<*const libc::c_char>> = ctx.config.env.as_ref().map(|e| {
        e.iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect()
    });
    let envp: *const *const libc::c_char = match &env_storage {
        Some(v) => v.as_ptr(),
        None => unsafe { environ },
    };
    // The initial cwd is a guest path; the child's chdir(2) is a traced syscall
    // so the tracer translates it like any other.
    let cwd = CString::new(ctx.config.cwd.clone()).map_err(|_| "cwd contains NUL")?;
    let host_cwd_exists = translate_path(&ctx.fs, std::process::id(), libc::AT_FDCWD, &ctx.config.cwd, true)
        .map(|h| {
            std::fs::metadata(std::ffi::OsStr::from_bytes_hack(&h))
                .map(|m| m.is_dir())
                .unwrap_or(false)
        })
        .unwrap_or(false);
    if !host_cwd_exists {
        eprintln!(
            "proot: can't chdir to {} in the guest rootfs, using /",
            String::from_utf8_lossy(&ctx.config.cwd)
        );
    }
    let slash = CString::new("/").unwrap();
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
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                libc::_exit(120);
            }
            let fd = match filter::install(&program) {
                Ok(fd) => fd,
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
            // From here on every traced syscall is served by the parent.
            if !host_cwd_exists || libc::chdir(cwd.as_ptr()) < 0 {
                libc::chdir(slash.as_ptr());
            }
            libc::execve(program_path, argv.as_ptr(), envp);
            let e = *libc::__errno_location();
            libc::_exit(if e == libc::ENOENT { 127 } else { 126 });
        }
    }
    unsafe { libc::close(sv[1]) };
    // Seize first: the child blocks on the handshake byte until we have.
    if let Err(e) = ptrace::seize(pid, tracer::options(&ctx)) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::close(sv[0]);
            let mut st = 0;
            libc::waitpid(pid, &mut st, libc::__WALL);
        }
        return Err(match e {
            libc::EPERM => "ptrace(PTRACE_SEIZE) refused: this process is already traced (proot inside proot, or a debugger) or ptrace is disallowed here; nested proot is not supported yet".into(),
            e => format!("ptrace(PTRACE_SEIZE): {}", strerror(e)),
        });
    }
    let listener = match recv_fd(sv[0]) {
        Some(fd) => fd,
        None => {
            unsafe { libc::close(sv[0]) };
            let mut st = 0;
            unsafe { libc::waitpid(pid, &mut st, libc::__WALL) };
            return Err(match libc::WEXITSTATUS(st) {
                120 => "PR_SET_NO_NEW_PRIVS refused".into(),
                124 => "the caller's --seccomp program was refused by the kernel".into(),
                122 => "seccomp user notification is not available on this kernel or is filtered".into(),
                _ => "child failed before handing over the seccomp listener".into(),
            });
        }
    };
    report_status(&ctx.config.info_fds, &format!("{{\"child-pid\": {pid}}}\n"));
    report_status(
        &ctx.config.json_status_fds,
        &format!("{{\"child-pid\": {pid}}}\n"),
    );
    notify::start(listener, ctx.clone());
    let go = 1u8;
    if unsafe { libc::write(sv[0], &go as *const u8 as *const _, 1) } != 1 {
        return Err("could not release the first tracee".into());
    }
    unsafe { libc::close(sv[0]) };
    let code = tracer::run(&ctx, pid);
    unsafe { libc::close(listener) };
    report_status(
        &ctx.config.json_status_fds,
        &format!("{{\"exit-code\": {code}}}\n"),
    );
    // PROOT_BWRAP_KEEP=1 leaves the materialized root behind for inspection.
    let keep = std::env::var_os("PROOT_BWRAP_KEEP").is_some();
    let _ = std::fs::remove_dir_all(crate::exec::alias_dir());
    for dir in ctx.config.cleanup_dirs.iter().filter(|_| !keep) {
        let _ = std::fs::remove_dir_all(std::ffi::OsStr::from_bytes_hack(dir));
    }
    Ok(code)
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
