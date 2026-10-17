//! Nested proot and bwrap: a view of their own instead of a supervisor of
//! their own.
//!
//! The kernel allows one tracer per process and one seccomp listener per
//! filter chain, so a proot started inside the guest could never supervise
//! anything.  It does not have to: the supervisor already serves every
//! descendant, and all a nested launch needs is a different translation
//! table for one subtree.  So an `execve` of the supervisor's own binary, or
//! of any ELF named `proot` or `bwrap` (the latter unless `PROOT_NEST=0`),
//! is not carried out.  The command line is parsed here, on the tracee's
//! behalf, with the tracee's view, working directory, environment and
//! descriptors; every path in it is composed through that view into a
//! [`View`] in host terms, which the process enters at the exec of the
//! real command and its descendants inherit.  The process that called
//! `proot` becomes the command, so the caller's child, exit status and
//! signals are the kernel's own.
//!
//! What only the process itself can do (`chdir`, `setsid`, the death signal,
//! the caller's seccomp programs, the status descriptors, a replaced
//! environment, a usage message on its own stderr) is handed to the exec
//! trampoline through its record, see [`super::shim`].
//!
//! A nested view can see no more than the view it was asked from: `-r /`
//! inside a guest is that guest's root.  Options that would change which
//! syscalls the filter notifies (`-0`, `-k`) cannot be served unless the
//! outer launch already notifies them, and are refused with a message.

use super::{ExecPlan, Trampoline};
use crate::cli::{self, CliError, host::Host};
use crate::config::{Binding, Config};
use crate::fs::Fs;
use crate::fs::binding::{is_prefix, join_prefix, rest_after};
use crate::fs::translate::{detranslate_path, guest_cwd, read_link, translate_path};
use crate::note;
use crate::state::{Ctx, View};
use crate::sys::Result;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::sync::{Arc, OnceLock};

/// Upper bound on environment entries read from the tracee.
const MAX_ENV: usize = 1 << 16;

/// Which command-line dialect a nested launch speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontEnd {
    Proot,
    Bwrap,
}

/// Program names intercepted by name (the supervisor's own binary is
/// intercepted by inode, whatever it is called).
const NAMES: &[&[u8]] = &[b"proot", b"proot-next", b"bwrap"];

/// Decides whether an exec is a nested launch, and in which dialect.
///
/// # Arguments
/// * `host_prog` - Host path of the ELF about to run (after `#!` expansion).
/// * `user_path` - Program path as the tracee passed it.
/// * `guest_prog` - Canonical guest path of the program.
/// * `argv0` - The tracee's `argv[0]`, which selects the dialect as `main` does.
/// * `is_elf` - The program is an ELF the tracee named directly, not a script.
///
/// # Returns
/// The dialect, or `None` for an ordinary exec.
pub fn detect(
    host_prog: &[u8],
    user_path: &[u8],
    guest_prog: &[u8],
    argv0: &[u8],
    is_elf: bool,
) -> Option<FrontEnd> {
    let name = super::exec_name(user_path, guest_prog);
    let ours = is_elf && same_file_as_us(host_prog);
    let by_name = is_elf && by_name_enabled() && NAMES.contains(&name);
    if !ours && !by_name {
        return None;
    }
    let argv0_name = argv0.rsplit(|&b| b == b'/').next().unwrap_or(argv0);
    Some(if argv0_name.ends_with(b"bwrap") || name.ends_with(b"bwrap") {
        FrontEnd::Bwrap
    } else {
        FrontEnd::Proot
    })
}

/// Whether programs named `proot` or `bwrap` are intercepted; `PROOT_NEST=0` turns it off.
fn by_name_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("PROOT_NEST").is_none_or(|v| v != "0"))
}

/// Whether `host` is the file the supervisor itself is running from.
fn same_file_as_us(host: &[u8]) -> bool {
    static US: OnceLock<Option<(u64, u64)>> = OnceLock::new();
    let us = US.get_or_init(|| dev_ino(b"/proc/self/exe"));
    us.is_some() && *us == dev_ino(host)
}

/// Device and inode of a host path, symlinks followed.
fn dev_ino(host: &[u8]) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(std::ffi::OsStr::from_bytes(host)).ok()?;
    Some((m.dev(), m.ino()))
}

/// Where a nested launch takes its environment from.
pub enum EnvSource {
    /// The `envp` the tracee passed to `execve`: its address (0 for none)
    /// and the pointer width of the tracee's ABI.
    Address { envp: u64, ptr_size: usize },
    /// An environment already in hand (a launch nested inside a nested one).
    Given(Vec<(Vec<u8>, Vec<u8>)>),
}

/// The requesting tracee, as the command-line parsers see it.
struct Tracee<'a> {
    view: &'a View,
    pid: u32,
    env: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Host for Tracee<'_> {
    fn exists(&self, path: &[u8]) -> bool {
        translate_path(&self.view.fs, self.pid, libc::AT_FDCWD, path, true)
            .map(|h| std::fs::metadata(std::ffi::OsStr::from_bytes(&h)).is_ok())
            .unwrap_or(false)
    }

    fn is_dir(&self, path: &[u8]) -> bool {
        translate_path(&self.view.fs, self.pid, libc::AT_FDCWD, path, true)
            .map(|h| std::fs::metadata(std::ffi::OsStr::from_bytes(&h)).is_ok_and(|m| m.is_dir()))
            .unwrap_or(false)
    }

    fn host_path(&self, path: &[u8]) -> Vec<u8> {
        if let Ok(h) = translate_path(&self.view.fs, self.pid, libc::AT_FDCWD, path, true) {
            return h;
        }
        let mut guest = if path.first() == Some(&b'/') {
            Vec::new()
        } else {
            self.cwd()
        };
        if guest != b"/" && !guest.is_empty() {
            guest.push(b'/');
        }
        guest.extend_from_slice(path);
        self.view.fs.substitute_guest_to_host(&guest)
    }

    fn cwd(&self) -> Vec<u8> {
        guest_cwd(&self.view.fs, self.pid).unwrap_or_else(|_| b"/".to_vec())
    }

    fn var(&self, name: &[u8]) -> Option<Vec<u8>> {
        self.env.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }

    fn vars(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.env.clone()
    }

    fn read_fd(&self, fd: i32) -> std::io::Result<Vec<u8>> {
        if fd < 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EBADF));
        }
        std::fs::read(format!("/proc/{}/fd/{fd}", self.pid))
    }

    fn fd_path(&self, fd: i32) -> std::io::Result<Vec<u8>> {
        let link = read_link(format!("/proc/{}/fd/{fd}", self.pid).as_bytes())
            .map_err(std::io::Error::from_raw_os_error)?;
        if link.first() != Some(&b'/') {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        Ok(link)
    }
}

/// Plans a nested launch: the command of the nested command line, run in a
/// view composed from the requester's.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `view` - The requester's view.
/// * `pid` - Requesting tracee thread id.
/// * `front` - Dialect of the command line.
/// * `argv` - The tracee's full argument vector (`argv[0]` is the program).
/// * `env` - The tracee's environment.
///
/// # Returns
/// A plan that always goes through the trampoline: for the real command,
/// or to print a message on the tracee's own stdout or stderr and exit.
///
/// # Errors
/// Errno from reading the tracee.
pub fn plan(
    ctx: &Ctx,
    view: &View,
    pid: u32,
    front: FrontEnd,
    argv: Vec<Vec<u8>>,
    env: EnvSource,
) -> Result<ExecPlan> {
    let env = match env {
        EnvSource::Address { envp, ptr_size } => read_env(ctx, pid, envp, ptr_size)?,
        EnvSource::Given(e) => e,
    };
    let tracee = Tracee { view, pid, env };
    let args: Vec<OsString> = argv
        .iter()
        .skip(1)
        .map(|a| OsString::from_vec(a.clone()))
        .collect();
    let parsed = match front {
        FrontEnd::Proot => cli::parse(args, &tracee),
        FrontEnd::Bwrap => cli::bwrap::parse(args, &tracee),
    };
    let message = |code: i32, text: String, to_stdout: bool| -> Result<ExecPlan> {
        note!(ctx, 1, "pid {pid} nested launch: {}", text.trim_end());
        Ok(ExecPlan::message(Trampoline {
            exit: Some((code, text.into_bytes(), to_stdout)),
            ..Trampoline::default()
        }))
    };
    let config = match parsed {
        Ok(c) => c,
        Err(CliError::Exit { code, text }) => return message(code, text, true),
        Err(CliError::Usage(msg)) => return message(125, format!("proot: {msg}\n"), false),
    };
    let uname_served = ctx.config.kernel_release.is_some() || ctx.config.hostname.is_some();
    if config.fake_root && !ctx.root.fake_root {
        return message(
            1,
            "proot: -0 inside proot-next needs the outer proot started with -0\n".into(),
            false,
        );
    }
    if config.kernel_release.is_some() && !uname_served {
        return message(
            1,
            "proot: -k inside proot-next needs the outer proot started with -k\n".into(),
            false,
        );
    }
    let mut config = config;
    if !uname_served {
        config.hostname = None;
    }
    compose_sub_bindings(&view.fs, &mut config);
    let keep = std::env::var_os("PROOT_BWRAP_KEEP").is_some();
    let nested = Arc::new(View::new(&config, ctx.procs.clone(), ctx.cache.clone(), !keep));
    note!(
        ctx,
        1,
        "pid {pid} nested {:?} launch: root {} with {} bindings",
        front,
        String::from_utf8_lossy(&nested.fs.root),
        nested.fs.bindings.len()
    );
    let (cwd, warning) = nested_cwd(&tracee, &nested, &config);
    let cwd_host = translate_path(&nested.fs, pid, libc::AT_FDCWD, &cwd, true)
        .unwrap_or_else(|_| nested.fs.root.clone());
    let command = match resolve_command(&nested, pid, &config, &tracee, &cwd) {
        Ok(c) => c,
        Err(e) => {
            let name = config
                .command
                .first()
                .map(|c| c.as_bytes().to_vec())
                .unwrap_or_default();
            let reason = std::io::Error::from_raw_os_error(e);
            let reason = reason.to_string();
            let reason = reason.split(" (os error").next().unwrap_or(&reason).to_string();
            let text = if config.bwrap_mode {
                format!("bwrap: execvp {}: {reason}\n", String::from_utf8_lossy(&name))
            } else {
                format!(
                    "proot: cannot execute {}: {reason}\n",
                    String::from_utf8_lossy(&name)
                )
            };
            return message(if e == libc::ENOENT { 127 } else { 126 }, text, false);
        }
    };
    let mut cmd_argv: Vec<Vec<u8>> = config.command.iter().map(|c| c.as_bytes().to_vec()).collect();
    if let Some(a0) = &config.argv0 {
        cmd_argv[0] = a0.as_bytes().to_vec();
    }
    let inner_env = match &config.env {
        Some(e) => e
            .iter()
            .map(|c| {
                let b = c.as_bytes();
                match b.iter().position(|&x| x == b'=') {
                    Some(i) => (b[..i].to_vec(), b[i + 1..].to_vec()),
                    None => (b.to_vec(), Vec::new()),
                }
            })
            .collect(),
        None => tracee.env.clone(),
    };
    let mut plan = super::plan_in(
        ctx,
        &nested,
        pid,
        libc::AT_FDCWD,
        &command,
        cmd_argv,
        true,
        EnvSource::Given(inner_env),
    )?;
    if let Some(t) = plan.trampoline.as_mut() {
        if t.exit.is_some() {
            return Ok(plan);
        }
        merge_setup(t, &config, warning);
        return Ok(plan);
    }
    let mut setup = Trampoline {
        enter: Some((nested, cwd)),
        chdir: if ctx.no_ptrace { None } else { Some(cwd_host) },
        ..Trampoline::default()
    };
    merge_setup(&mut setup, &config, warning);
    plan.trampoline = Some(setup);
    plan.prefix = plan.argv.len();
    plan.changed = true;
    Ok(plan)
}

/// Adds what the nested command line asks the trampoline to do before the exec.
///
/// Carries the requester's bindings beneath a nested bind along with it, the
/// way a recursive bind mount carries the submounts under its source.
///
/// The front ends translate the host side of every nested binding through
/// the requester's view, which flattens the table to one host path per entry
/// and drops whatever the requester had bound further down.  pressure-vessel
/// binds the host `/` at `/run/host` and, finding a 32-bit loader at the
/// host's `/usr/lib/ld-linux.so.2` (one the outer launch bound there),
/// symlinks the container's `/lib/ld-linux.so.2` to it; without the outer
/// binding carried under `/run/host` that link dangles and no 32-bit program
/// in the container can execute.  The nested root is left alone: it is a
/// plain directory, as PRoot's rootfs is, not a bind of the requester's `/`.
///
/// # Arguments
/// * `outer` - The requester's view.
/// * `config` - The parsed nested launch, whose bindings already name host
///   paths; bindings found beneath them are appended.
fn compose_sub_bindings(outer: &Fs, config: &mut Config) {
    let targets: Vec<(Vec<u8>, Vec<u8>, bool)> = config
        .bindings
        .iter()
        .map(|b| (b.host.clone(), b.guest.clone(), b.read_only))
        .collect();
    for (host, guest, read_only) in targets {
        let source = detranslate_path(outer, &host);
        for b in &outer.bindings {
            if b.guest != source && is_prefix(&source, &b.guest) {
                config.bindings.push(Binding {
                    host: b.host.clone(),
                    guest: join_prefix(&guest, rest_after(&source, &b.guest)),
                    read_only: read_only || b.read_only,
                });
            }
        }
    }
}

/// A plan that already carries a trampoline (a launch nested inside the
/// nested one) keeps the innermost view and gets the outer launch's
/// process setup on top; the innermost environment wins when both set one.
fn merge_setup(t: &mut Trampoline, config: &Config, warning: Option<String>) {
    if t.env.is_none() {
        t.env = config
            .env
            .as_ref()
            .map(|e| e.iter().map(|c| c.as_bytes().to_vec()).collect());
    }
    t.new_session |= config.new_session;
    t.die_with_parent |= config.kill_on_exit && config.bwrap_mode;
    t.seccomp_programs.extend(config.seccomp_programs.iter().cloned());
    t.info_fds.extend(config.info_fds.iter().copied());
    t.json_status_fds.extend(config.json_status_fds.iter().copied());
    if let Some(w) = warning {
        t.warnings.push(w.into_bytes());
    }
}

/// The working directory the nested command starts in, as a guest path of
/// the nested view, and a warning when it is not the one asked for.
///
/// A directory given on the command line is a path of the nested view.
/// Without one, PRoot starts in the caller's working directory when it is
/// visible in the new view, else in `/`.
fn nested_cwd(tracee: &Tracee, nested: &View, config: &Config) -> (Vec<u8>, Option<String>) {
    let wanted: Vec<u8> = if config.cwd_default {
        let host = tracee.host_path(&tracee.cwd());
        match nested.fs.substitute_host_to_guest(&host) {
            Some(g) => g,
            None => return (b"/".to_vec(), None),
        }
    } else if config.cwd.first() == Some(&b'/') {
        config.cwd.clone()
    } else {
        let mut p = b"/".to_vec();
        p.extend_from_slice(&config.cwd);
        p
    };
    let ok = translate_path(&nested.fs, tracee.pid, libc::AT_FDCWD, &wanted, true)
        .map(|h| std::fs::metadata(std::ffi::OsStr::from_bytes(&h)).is_ok_and(|m| m.is_dir()))
        .unwrap_or(false);
    if ok {
        let canonical = translate_path(&nested.fs, tracee.pid, libc::AT_FDCWD, &wanted, true)
            .map(|h| detranslate_path(&nested.fs, &h))
            .unwrap_or(wanted);
        return (canonical, None);
    }
    if config.cwd_default {
        return (b"/".to_vec(), None);
    }
    (
        b"/".to_vec(),
        Some(format!(
            "proot: can't chdir to {} in the guest rootfs, using /\n",
            String::from_utf8_lossy(&wanted)
        )),
    )
}

/// The guest path of the nested command: as given when it has a slash
/// (relative to the nested working directory), else found in `PATH`.
///
/// # Errors
/// `ENOENT` when nothing by that name is executable, or the errno of what was found.
fn resolve_command(nested: &View, pid: u32, config: &Config, tracee: &Tracee, cwd: &[u8]) -> Result<Vec<u8>> {
    let name = config
        .command
        .first()
        .map(|c| c.as_bytes().to_vec())
        .ok_or(libc::ENOENT)?;
    if name.is_empty() {
        return Err(libc::ENOENT);
    }
    let candidates: Vec<Vec<u8>> = if name.contains(&b'/') {
        if name.first() == Some(&b'/') {
            vec![name]
        } else {
            let mut p = cwd.to_vec();
            if p != b"/" {
                p.push(b'/');
            }
            p.extend_from_slice(&name);
            vec![p]
        }
    } else {
        let path_var = config
            .env
            .as_ref()
            .and_then(|e| {
                e.iter()
                    .find_map(|c| c.as_bytes().strip_prefix(b"PATH=").map(|v| v.to_vec()))
            })
            .or_else(|| tracee.var(b"PATH"))
            .unwrap_or_else(|| b"/usr/local/bin:/usr/bin:/bin".to_vec());
        path_var
            .split(|&c| c == b':')
            .filter(|d| d.first() == Some(&b'/'))
            .map(|d| {
                let mut p = d.to_vec();
                if !p.ends_with(b"/") {
                    p.push(b'/');
                }
                p.extend_from_slice(&name);
                p
            })
            .collect()
    };
    let mut last = libc::ENOENT;
    for guest in candidates {
        let Ok(host) = translate_path(&nested.fs, pid, libc::AT_FDCWD, &guest, true) else {
            continue;
        };
        match executable(&host) {
            Ok(()) => return Ok(guest),
            Err(e) => {
                if e != libc::ENOENT {
                    last = e;
                }
            }
        }
    }
    Err(last)
}

/// `execve`'s own checks on a host path: it exists, is not a directory, and
/// is executable.
fn executable(host: &[u8]) -> Result<()> {
    let c = std::ffi::CString::new(host.to_vec()).map_err(|_| libc::ENOENT)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c.as_ptr(), &mut st) } < 0 {
        return Err(crate::sys::errno());
    }
    if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
        return Err(libc::EACCES);
    }
    if unsafe { libc::access(c.as_ptr(), libc::X_OK) } < 0 {
        return Err(crate::sys::errno());
    }
    Ok(())
}

/// Reads the tracee's environment as `(name, value)` pairs.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `pid` - Tracee thread id.
/// * `envp` - Address of the pointer array, or 0 for an empty environment.
/// * `ptr_size` - Pointer width of the tracee's ABI.
fn read_env(ctx: &Ctx, pid: u32, envp: u64, ptr_size: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    if envp == 0 {
        return Ok(Vec::new());
    }
    let ptrs = ctx.mem.read_ptr_array_sized(pid, envp, MAX_ENV, ptr_size)?;
    let mut out = Vec::with_capacity(ptrs.len());
    for p in ptrs {
        let entry = ctx.mem.read_cstr(pid, p)?;
        match entry.iter().position(|&b| b == b'=') {
            Some(i) => out.push((entry[..i].to_vec(), entry[i + 1..].to_vec())),
            None => out.push((entry, Vec::new())),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_our_binary_by_inode_and_others_by_name() {
        let us = std::fs::read_link("/proc/self/exe").unwrap();
        let us = us.as_os_str().as_bytes();
        assert_eq!(
            detect(us, b"/x/anything", b"/x/anything", b"anything", true),
            Some(FrontEnd::Proot)
        );
        assert_eq!(
            detect(us, b"/x/anything", b"/x/anything", b"bwrap", true),
            Some(FrontEnd::Bwrap)
        );
        assert_eq!(
            detect(us, b"/x/anything", b"/x/anything", b"anything", false),
            None
        );
        assert_eq!(
            detect(b"/bin/true", b"/usr/bin/bwrap", b"/usr/bin/bwrap", b"bwrap", true),
            Some(FrontEnd::Bwrap)
        );
        assert_eq!(
            detect(b"/bin/true", b"proot", b"/usr/bin/proot", b"proot", true),
            Some(FrontEnd::Proot)
        );
        assert_eq!(
            detect(b"/bin/true", b"/usr/bin/true", b"/usr/bin/true", b"true", true),
            None
        );
        assert_eq!(
            detect(
                b"/bin/true",
                b"/usr/bin/bwrap",
                b"/usr/bin/bwrap",
                b"bwrap",
                false
            ),
            None
        );
    }
}
