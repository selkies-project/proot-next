//! `execve` handling at the ptrace stop.
//!
//! The kernel resolves the program path and its `PT_INTERP` on the host, so
//! both must be rewritten before the syscall proceeds:
//!
//! 1. the program path is translated, and `#!` scripts are expanded into
//!    interpreter plus argument, repeatedly, until an ELF is reached;
//! 2. a dynamically linked ELF is not executed directly: the exec is
//!    re-targeted at the host copy of its dynamic loader, with the program's
//!    guest path as the loader's argument.  The loader then opens the program
//!    and its libraries through `openat`, which the notify handlers translate;
//! 3. the new argv is written on the tracee's stack and the registers point
//!    at it.  `envp` is untouched.
//!
//! Set `PROOT_EXEC_DEBUG=1` to print every rewritten exec on stderr.
//!
//! Without ptrace the same plan is carried out by a trampoline inside the
//! tracee instead of a register rewrite, see [`shim`].
//!
//! Known gaps: at the kernel level `/proc/<pid>/exe` and `AT_EXECFN` name the
//! loader; the supervisor answers `readlink` on `/proc/self/exe` from the
//! record kept here, but a program reading `AT_EXECFN` from its auxv sees the
//! loader.
//!
//! Both ABIs are handled: argv is read and written with the *caller's* pointer
//! width (the kernel interprets `execve` arguments in the caller's ABI), and a
//! 32-bit ELF is re-targeted at its own 32-bit loader.

pub mod elf;
pub mod shebang;
pub mod shim;

use crate::fs::translate::{detranslate_path, translate_path};
use crate::state::Ctx;
use crate::sys::Result;
use crate::syscall::nr::EXECVEAT;
use crate::tracee::regs::Regs;
use elf::FileKind;
use std::collections::HashMap;
use std::sync::Mutex;

/// Upper bound on argv entries read from the tracee.
const MAX_ARGV: usize = 1 << 18;
/// Maximum nesting of `#!` interpreters (the kernel allows 4).
const MAX_SHEBANG_DEPTH: usize = 4;

/// What the kernel should load in place of what the tracee asked for.
#[derive(Clone, Debug)]
pub struct ExecPlan {
    /// Host path to exec.
    pub exec_path: Vec<u8>,
    /// The complete argument vector to exec it with.
    pub argv: Vec<Vec<u8>>,
    /// Entries at the front of `argv` that did not come from the caller's
    /// `argv[1..]`; the rest is the caller's tail, unchanged.
    pub prefix: usize,
    /// Whether `exec_path` or `argv` differ from what the tracee asked.
    pub changed: bool,
    /// Canonical guest path of the program (after `#!` expansion).
    pub guest_prog: Vec<u8>,
    /// Host path of the program (after `#!` expansion).
    pub host_prog: Vec<u8>,
    /// Whether the program's format was recognized (ELF or `#!`).
    pub understood: bool,
}

/// Works out what to exec for a program the tracee named.
///
/// `#!` scripts are expanded into interpreter plus argument, repeatedly,
/// until an ELF is reached; a dynamically linked ELF is re-targeted at the
/// host copy of its loader with the program's guest path as the loader's
/// argument.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `pid` - Tracee thread id.
/// * `dirfd` - Base of a relative `user_path`.
/// * `user_path` - Program path as the tracee passed it.
/// * `argv` - The tracee's argument vector (empty when it passed NULL).
/// * `deref_final` - Follow a symlink in the final component of the program path.
///
/// # Errors
/// `ELOOP` for too many nested `#!`, otherwise the errno of translating a
/// path.  A missing or unreadable program is not an error here: the plan
/// names its translated path and `understood` is false.
pub fn plan(
    ctx: &Ctx,
    pid: u32,
    dirfd: i32,
    user_path: &[u8],
    mut argv: Vec<Vec<u8>>,
    deref_final: bool,
) -> Result<ExecPlan> {
    let argv_was_null = argv.is_empty();
    if argv.is_empty() {
        // The kernel runs a program with an empty argv as if argv[0] were "".
        argv.push(Vec::new());
    }
    let tail = argv.len() - 1;

    // 1. Program path, then #! expansion.
    let mut host_prog = translate_path(&ctx.fs, pid, dirfd, user_path, deref_final)?;
    let mut argv0_user = user_path.to_vec();
    let mut kind = elf::classify_file(&host_prog);
    let mut depth = 0;
    while let Ok(FileKind::Shebang(line)) = &kind {
        if depth == MAX_SHEBANG_DEPTH {
            return Err(libc::ELOOP);
        }
        depth += 1;
        let sb = shebang::parse(line).ok_or(libc::ENOEXEC)?;
        // argv becomes: interp [arg] script argv[1..]
        let mut new_argv = vec![sb.interp.clone()];
        if let Some(a) = &sb.arg {
            new_argv.push(a.clone());
        }
        new_argv.push(argv0_user.clone());
        new_argv.extend(argv.drain(1..));
        argv = new_argv;
        argv0_user = sb.interp.clone();
        host_prog = translate_path(&ctx.fs, pid, libc::AT_FDCWD, &sb.interp, true)?;
        kind = elf::classify_file(&host_prog);
    }

    // 2. Decide what the kernel should load.
    let guest_prog = detranslate_path(&ctx.fs, &host_prog);
    let mut changed = depth > 0 || argv_was_null;
    let understood = matches!(kind, Ok(FileKind::Elf64(_)) | Ok(FileKind::Elf32(_)));
    let (exec_path, new_argv): (Vec<u8>, Vec<Vec<u8>>) = match kind {
        Ok(FileKind::Elf64(info)) | Ok(FileKind::Elf32(info)) => match info.interp {
            Some(interp) if !ctx.fs.identity => {
                let host_interp = translate_path(&ctx.fs, pid, libc::AT_FDCWD, &interp, true)?;
                let mut v = vec![host_interp.clone()];
                let argv0_supported = loader_supports_argv0(&host_interp);
                if argv0_supported {
                    v.push(b"--argv0".to_vec());
                    v.push(argv[0].clone());
                }
                // The loader takes the program's `$ORIGIN` from the path it is
                // given, where the kernel would take it from the resolved
                // executable, so the canonical path goes to a loader that
                // takes argv[0] separately.  A loader without --argv0 uses the
                // path as argv[0], on which multi-call binaries (busybox)
                // dispatch, so it gets the name as typed, unless that name is
                // dirfd-relative and meaningless after the rewrite.
                v.push(
                    if !argv0_supported && (dirfd == libc::AT_FDCWD || argv0_user.first() == Some(&b'/')) {
                        argv0_user.clone()
                    } else {
                        guest_prog.clone()
                    },
                );
                v.extend(argv[1..].iter().cloned());
                changed = true;
                // Exec the loader through an alias named as the tracee named the
                // program, which is where the kernel takes comm and AT_EXECFN from
                // (a script keeps its own name, not its interpreter's).
                let exec_as = loader_alias(&host_interp, exec_name(user_path, &guest_prog))
                    .unwrap_or_else(|| host_interp.clone());
                v[0] = exec_as.clone();
                (exec_as, v)
            }
            // Static, or identity translation where the interpreter resolves as is.
            _ => (host_prog.clone(), argv),
        },
        // Not something we understand (or unreadable): let the kernel decide.
        _ => (host_prog.clone(), argv),
    };
    if exec_path != user_path {
        changed = true;
    }
    Ok(ExecPlan {
        prefix: new_argv.len() - tail,
        exec_path,
        argv: new_argv,
        changed,
        guest_prog,
        host_prog,
        understood,
    })
}

/// Rewrites an `execve`/`execveat` so the kernel loads host-side files only.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `regs` - Registers at the stop; edits are committed by the caller.
///
/// # Errors
/// `ELOOP` for too many nested `#!`, otherwise the errno of reading the tracee
/// or translating a path.  A missing or unreadable program is not an error:
/// the translated path is left for the kernel to judge.
pub fn handle_execve(ctx: &Ctx, regs: &mut Regs) -> Result<()> {
    let pid = regs.pid() as u32;
    let abi = regs.abi();
    let is_at = matches!(abi.to_canonical(regs.sysnum()), Some((EXECVEAT, _)));
    let ptr_size = abi.ptr_size();
    let (dirfd, path_idx, argv_idx) = if is_at {
        (regs.arg(0) as i32, 1, 2)
    } else {
        (libc::AT_FDCWD, 0, 1)
    };
    let at_flags = if is_at { regs.arg(4) as i32 } else { 0 };
    let deref_final = at_flags & libc::AT_SYMLINK_NOFOLLOW == 0;

    let user_path = ctx.mem.read_cstr(pid, regs.arg(path_idx))?;
    let argv = read_argv(ctx, pid, regs.arg(argv_idx), ptr_size)?;
    let plan = plan(ctx, pid, dirfd, &user_path, argv, deref_final)?;
    ctx.set_exe(pid as i32, plan.guest_prog.clone(), plan.host_prog.clone());

    // 3. Materialize path and argv in the tracee, unless nothing changed.
    if !is_at && !plan.changed {
        return Ok(());
    }
    debug_exec(pid, &plan);
    let (path_addr, argv_addr) = push_argv(ctx, regs, &plan.exec_path, &plan.argv, ptr_size)?;
    if is_at {
        regs.set_arg(0, libc::AT_FDCWD as i64 as u64);
        regs.set_arg(1, path_addr);
        regs.set_arg(2, argv_addr);
        regs.set_arg(
            4,
            (at_flags & !(libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW)) as u64,
        );
    } else {
        regs.set_arg(0, path_addr);
        regs.set_arg(1, argv_addr);
    }
    Ok(())
}

/// Reads the tracee's argument vector.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `pid` - Tracee thread id.
/// * `argv_ptr` - Address of the pointer array, or 0.
/// * `ptr_size` - Pointer width of the tracee's ABI.
///
/// # Returns
/// The strings; empty for a NULL `argv`.
pub fn read_argv(ctx: &Ctx, pid: u32, argv_ptr: u64, ptr_size: usize) -> Result<Vec<Vec<u8>>> {
    if argv_ptr == 0 {
        return Ok(Vec::new());
    }
    let ptrs = ctx.mem.read_ptr_array_sized(pid, argv_ptr, MAX_ARGV, ptr_size)?;
    ptrs.iter().map(|&p| ctx.mem.read_cstr(pid, p)).collect()
}

/// Prints the rewritten exec when `PROOT_EXEC_DEBUG` is set.
///
/// # Arguments
/// * `pid` - Tracee thread id.
/// * `plan` - The exec about to happen.
pub fn debug_exec(pid: u32, plan: &ExecPlan) {
    if std::env::var_os("PROOT_EXEC_DEBUG").is_some() {
        eprintln!(
            "proot: exec pid {pid}: {} argv={:?}",
            String::from_utf8_lossy(&plan.exec_path),
            plan.argv
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>()
        );
    }
}

/// The name the kernel would give a process exec'd as `user_path`: the last
/// component of that path, or of `guest_prog` when the path is empty
/// (`execveat` of a descriptor) or ends in a slash.
///
/// # Arguments
/// * `user_path` - Program path as the tracee passed it.
/// * `guest_prog` - Canonical guest path of what will run.
fn exec_name<'a>(user_path: &'a [u8], guest_prog: &'a [u8]) -> &'a [u8] {
    let base = |p: &'a [u8]| p.rsplit(|&b| b == b'/').next().unwrap_or(p);
    match base(user_path) {
        b"" => guest_prog,
        name => name,
    }
}

/// Writes a path and an argv array onto the tracee's stack.
///
/// Layout, from the returned base upwards: the NUL-terminated pointer array
/// (entries `ptr_size` bytes wide, base 16-byte aligned), then every string,
/// then the path.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `regs` - Registers whose stack pointer locates the scratch area.
/// * `path` - Program path for the kernel.
/// * `argv` - Argument strings, without NULs.
/// * `ptr_size` - Pointer width of the calling process's ABI (4 or 8).
///
/// # Returns
/// `(path address, argv address)` in the tracee.
fn push_argv(
    ctx: &Ctx,
    regs: &mut Regs,
    path: &[u8],
    argv: &[Vec<u8>],
    ptr_size: usize,
) -> Result<(u64, u64)> {
    let table = (argv.len() + 1) * ptr_size;
    let strings: usize = argv.iter().map(|a| a.len() + 1).sum::<usize>() + path.len() + 1;
    let total = table + strings;
    // Below the red zone, without moving the stack pointer: no exit stop is
    // taken, so a lowered rsp would survive a failed execve and crash the tracee.
    let base = regs.sp().saturating_sub(crate::sys::RED_ZONE_SIZE + total as u64) & !0xf;
    let mut buf = vec![0u8; total];
    let mut off = table;
    for (i, a) in argv.iter().enumerate() {
        let addr = base + off as u64;
        if ptr_size == 8 {
            buf[i * 8..i * 8 + 8].copy_from_slice(&addr.to_le_bytes());
        } else {
            buf[i * 4..i * 4 + 4].copy_from_slice(&(addr as u32).to_le_bytes());
        }
        buf[off..off + a.len()].copy_from_slice(a);
        off += a.len() + 1;
    }
    let path_addr = base + off as u64;
    buf[off..off + path.len()].copy_from_slice(path);
    ctx.mem.write(regs.pid() as u32, base, &buf)?;
    Ok((path_addr, base))
}

/// A symlink to `host_interp` whose basename is the program's, for `execve`.
///
/// The kernel names a process after the basename of the path it exec'd and
/// exposes that path as `AT_EXECFN`.  Exec'ing the loader directly would make
/// every dynamic program show up as `ld-linux-x86-64.so.2`, so the loader is
/// reached through `<alias dir>/<hash of loader>/<program name>` instead.  One
/// alias per (loader, name), created on first use; the directory lives for
/// the supervisor's life (see [`alias_dir`]).
///
/// # Arguments
/// * `host_interp` - Host path of the dynamic loader.
/// * `name` - Name to give the alias, or a path whose last component is taken.
///
/// # Returns
/// The alias path, or `None` when the directory or link cannot be created.
fn loader_alias(host_interp: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::os::unix::ffi::OsStrExt;
    let name = name.rsplit(|&b| b == b'/').next().filter(|n| !n.is_empty())?;
    let mut h = DefaultHasher::new();
    host_interp.hash(&mut h);
    let dir = alias_dir().join(format!("{:016x}", h.finish()));
    let link = dir.join(std::ffi::OsStr::from_bytes(name));
    match std::fs::read_link(&link) {
        Ok(target) if target.as_os_str().as_bytes() == host_interp => {}
        Ok(_) => {
            let _ = std::fs::remove_file(&link);
            std::fs::create_dir_all(&dir).ok()?;
            std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(host_interp), &link).ok()?;
        }
        Err(_) => {
            std::fs::create_dir_all(&dir).ok()?;
            if let Err(e) = std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(host_interp), &link)
                && e.kind() != std::io::ErrorKind::AlreadyExists
            {
                return None;
            }
        }
    }
    Some(link.as_os_str().as_bytes().to_vec())
}

static ALIAS_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Directory holding the loader aliases, private to this supervisor.
///
/// Created under `$XDG_RUNTIME_DIR` or the temp dir, named by our pid, and
/// removed by the launcher when the supervisor exits.  Without ptrace the
/// same directory holds the exec shim and is every tracee's kernel cwd, see
/// [`shim`].
pub fn alias_dir() -> std::path::PathBuf {
    ALIAS_DIR
        .get_or_init(|| {
            let base = std::env::var_os("XDG_RUNTIME_DIR")
                .map(std::path::PathBuf::from)
                .filter(|p| p.is_dir())
                .unwrap_or_else(std::env::temp_dir);
            base.join(format!("proot-next-{}", std::process::id()))
        })
        .clone()
}

/// Fixes the alias directory before anything used it (the shim installer).
///
/// # Arguments
/// * `dir` - The directory to use from now on.
pub fn set_alias_dir(dir: std::path::PathBuf) {
    let _ = ALIAS_DIR.set(dir);
}

/// Whether the loader at `host_interp` understands `--argv0`.
///
/// glibc (>= 2.33) stores the option as `--argv0`; musl parses the leading
/// dashes itself and stores `argv0`.  Probed once per loader by scanning the
/// file; the result is cached for the life of the supervisor.
///
/// # Arguments
/// * `host_interp` - Host path of the dynamic loader.
fn loader_supports_argv0(host_interp: &[u8]) -> bool {
    static CACHE: Mutex<Option<HashMap<Vec<u8>, bool>>> = Mutex::new(None);
    let mut guard = CACHE.lock().unwrap();
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some(&v) = cache.get(host_interp) {
        return v;
    }
    use std::os::unix::ffi::OsStrExt;
    let data = std::fs::read(std::ffi::OsStr::from_bytes(host_interp)).unwrap_or_default();
    let supported = data.windows(8).any(|w| w == b"--argv0\0") || data.windows(7).any(|w| w == b"\0argv0\0");
    cache.insert(host_interp.to_vec(), supported);
    supported
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_loader_argv0_probe_is_cached() {
        let ld = b"/lib64/ld-linux-x86-64.so.2";
        if std::path::Path::new("/lib64/ld-linux-x86-64.so.2").exists() {
            let a = loader_supports_argv0(ld);
            let b = loader_supports_argv0(ld);
            assert_eq!(a, b);
        }
    }
}
