//! bubblewrap-compatible front end, selected when `argv[0]` ends in `bwrap`.
//!
//! bubblewrap describes a container as an ordered list of operations: bind
//! mounts, directories, symlinks, generated files, environment edits, and
//! namespace or capability changes.  Without namespaces the description is
//! materialized instead: a fresh private root directory receives every
//! `--dir`, `--symlink`, `--tmpfs` and data-file entry, each bind becomes a
//! [`Binding`] (read-only ones flagged), and the options that only make sense
//! with namespaces are accepted and ignored.  The result is an ordinary
//! [`Config`] that the launcher runs like any PRoot invocation.
//!
//! Known no-ops: every `--unshare-*`, `--share-net`, `--disable-userns`,
//! `--assert-userns-disabled`, `--userns*`, `--pidns`, `--uid`, `--gid`,
//! `--cap-add`, `--cap-drop`, `--as-pid-1`, `--lock-file`, `--sync-fd`,
//! `--block-fd`, `--userns-block-fd`, `--exec-label`, `--file-label`,
//! `--mqueue` (created as a plain directory), `--size`, `--level-prefix`,
//! `--not-a-security-boundary`.  `--hostname` is recorded for a future
//! `uname` handler.  Overlay options are refused.

use super::CliError;
use crate::config::{Binding, Config, trim_slashes};
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Version string pressure-vessel and flatpak parse from `bwrap --version`.
pub const BWRAP_VERSION: &str = "bubblewrap 0.9.0 (proot-next)";

const FLAGS: &[&str] = &[
    "--unshare-all",
    "--share-net",
    "--unshare-user",
    "--unshare-user-try",
    "--unshare-ipc",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-uts",
    "--unshare-cgroup",
    "--unshare-cgroup-try",
    "--disable-userns",
    "--assert-userns-disabled",
    "--clearenv",
    "--new-session",
    "--die-with-parent",
    "--as-pid-1",
    "--level-prefix",
    "--not-a-security-boundary",
    "--help",
    "--version",
];
const ONE_ARG: &[&str] = &[
    "--args",
    "--argv0",
    "--userns",
    "--userns2",
    "--pidns",
    "--uid",
    "--gid",
    "--hostname",
    "--chdir",
    "--unsetenv",
    "--lock-file",
    "--sync-fd",
    "--remount-ro",
    "--exec-label",
    "--file-label",
    "--proc",
    "--dev",
    "--tmpfs",
    "--mqueue",
    "--dir",
    "--seccomp",
    "--add-seccomp-fd",
    "--block-fd",
    "--userns-block-fd",
    "--info-fd",
    "--json-status-fd",
    "--cap-add",
    "--cap-drop",
    "--perms",
    "--size",
    "--tmp-overlay",
    "--ro-overlay",
    "--overlay-src",
];
const TWO_ARGS: &[&str] = &[
    "--setenv",
    "--bind",
    "--bind-try",
    "--dev-bind",
    "--dev-bind-try",
    "--ro-bind",
    "--ro-bind-try",
    "--bind-fd",
    "--ro-bind-fd",
    "--file",
    "--bind-data",
    "--ro-bind-data",
    "--symlink",
    "--chmod",
];
const THREE_ARGS: &[&str] = &["--overlay"];

/// One parsed operation: the option, its arguments, and the `--perms` mode
/// that applied to it (only for options that create an entry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub option: String,
    pub args: Vec<Vec<u8>>,
    pub perms: Option<u32>,
}

/// Parses bubblewrap-style arguments (without `argv[0]`) into a launchable config.
///
/// # Arguments
/// * `args` - Command-line arguments as bubblewrap would receive them.
///
/// # Returns
/// A [`Config`] whose root is a freshly materialized directory.
///
/// # Errors
/// [`CliError::Exit`] after `--help`/`--version`, [`CliError::Usage`] for
/// unknown options, missing arguments, unreadable descriptors or overlays.
pub fn parse(args: Vec<OsString>) -> Result<Config, CliError> {
    let (ops, command) = parse_ops(args.into_iter().map(|a| a.into_vec()).collect())?;
    for op in &ops {
        match op.option.as_str() {
            "--help" => {
                print!(
                    "{BWRAP_VERSION}\n\nusage: bwrap [OPTIONS...] [--] COMMAND [ARGS...]\n\nbubblewrap-compatible front end of proot-next: binds and generated entries are\nmaterialized in a private root and the command runs under ptrace/seccomp\ntranslation instead of namespaces.\n"
                );
                return Err(CliError::Exit(0));
            }
            "--version" => {
                println!("{BWRAP_VERSION}");
                return Err(CliError::Exit(0));
            }
            _ => {}
        }
    }
    if command.is_empty() {
        return Err(CliError::Usage("bwrap: COMMAND is required".into()));
    }
    let root = make_root()?;
    let root_bytes = root.as_os_str().as_bytes().to_vec();
    let mut cfg = Config {
        root: root_bytes.clone(),
        cleanup_dirs: vec![root_bytes],
        cwd: b"/".to_vec(),
        ..Config::default()
    };
    let mut env: BTreeMap<Vec<u8>, Vec<u8>> = std::env::vars_os()
        .map(|(k, v)| (k.into_vec(), v.into_vec()))
        .collect();
    let mut argv0: Option<Vec<u8>> = None;
    if let Err(e) = apply_ops(&ops, &root, &mut cfg, &mut env, &mut argv0) {
        let _ = fs::remove_dir_all(&root);
        return Err(e);
    }
    cfg.env = Some(
        env.into_iter()
            .map(|(mut k, v)| {
                k.push(b'=');
                k.extend_from_slice(&v);
                CString::new(k).unwrap_or_default()
            })
            .collect(),
    );
    cfg.command = command
        .into_iter()
        .map(|a| CString::new(a).unwrap_or_default())
        .collect();
    cfg.argv0 = argv0.map(|a| CString::new(a).unwrap_or_default());
    cfg.bwrap_mode = true;
    Ok(cfg)
}

/// Splits the command line into operations and the command.
///
/// `--args FD` is spliced in place as bubblewrap does, and `--perms` is
/// attached to the next entry-creating option.
///
/// # Arguments
/// * `args` - Raw argument bytes, `argv[0]` excluded.
///
/// # Returns
/// The operations in order and the command (possibly empty).
///
/// # Errors
/// [`CliError::Usage`] on an unknown option or a missing argument.
pub fn parse_ops(mut args: Vec<Vec<u8>>) -> Result<(Vec<Op>, Vec<Vec<u8>>), CliError> {
    let mut ops = Vec::new();
    let mut perms: Option<u32> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].clone();
        if arg == b"--" {
            i += 1;
            break;
        }
        if !arg.starts_with(b"--") {
            break;
        }
        let name = String::from_utf8_lossy(&arg).into_owned();
        if name == "--args" {
            let fd = parse_fd(args.get(i + 1).map(|v| v.as_slice()), "--args")?;
            let data =
                read_fd(fd).map_err(|e| CliError::Usage(format!("--args: cannot read fd {fd}: {e}")))?;
            unsafe { libc::close(fd) };
            let spliced: Vec<Vec<u8>> = data
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_vec())
                .collect();
            args.splice(i..i + 2, spliced);
            continue;
        }
        let count = if FLAGS.contains(&name.as_str()) {
            0
        } else if ONE_ARG.contains(&name.as_str()) {
            1
        } else if TWO_ARGS.contains(&name.as_str()) {
            2
        } else if THREE_ARGS.contains(&name.as_str()) {
            3
        } else {
            return Err(CliError::Usage(format!("bwrap: Unknown option {name}")));
        };
        if i + count >= args.len() {
            return Err(CliError::Usage(format!(
                "bwrap: {name} takes {count} argument(s)"
            )));
        }
        let values: Vec<Vec<u8>> = args[i + 1..i + 1 + count].to_vec();
        i += 1 + count;
        if name == "--perms" {
            let s = String::from_utf8_lossy(&values[0]).into_owned();
            perms = Some(
                u32::from_str_radix(&s, 8).map_err(|_| CliError::Usage(format!("bwrap: bad --perms {s}")))?,
            );
            continue;
        }
        let creates = matches!(
            name.as_str(),
            "--dir" | "--tmpfs" | "--symlink" | "--file" | "--bind-data" | "--ro-bind-data" | "--mqueue"
        );
        ops.push(Op {
            option: name,
            args: values,
            perms: if creates { perms.take() } else { None },
        });
    }
    Ok((ops, args[i..].to_vec()))
}

/// Applies the operations: creates entries under `root`, fills bindings and
/// environment.  Pure mapping lives in [`map_op`]; this does the filesystem work.
fn apply_ops(
    ops: &[Op],
    root: &Path,
    cfg: &mut Config,
    env: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    argv0: &mut Option<Vec<u8>>,
) -> Result<(), CliError> {
    for op in ops {
        let a = |n: usize| -> &[u8] { &op.args[n] };
        match op.option.as_str() {
            "--bind" | "--dev-bind" | "--ro-bind" | "--bind-try" | "--dev-bind-try" | "--ro-bind-try" => {
                let src = a(0);
                let dest = a(1);
                if !Path::new(os(src)).exists() {
                    if op.option.ends_with("-try") {
                        continue;
                    }
                    return Err(CliError::Usage(format!(
                        "bwrap: Can't find source path {}: No such file or directory",
                        String::from_utf8_lossy(src)
                    )));
                }
                let src_abs = absolutize(src);
                ensure_mount_point(root, dest, Path::new(os(&src_abs)).is_dir());
                cfg.bindings
                    .push(bind(&src_abs, dest, op.option.starts_with("--ro-bind")));
            }
            "--bind-fd" | "--ro-bind-fd" => {
                let fd = parse_fd(Some(a(0)), &op.option)?;
                let src = fs::read_link(format!("/proc/self/fd/{fd}"))
                    .map_err(|e| CliError::Usage(format!("bwrap: {}: fd {fd}: {e}", op.option)))?;
                let src = src.as_os_str().as_bytes().to_vec();
                ensure_mount_point(root, a(1), Path::new(os(&src)).is_dir());
                cfg.bindings.push(bind(&src, a(1), op.option == "--ro-bind-fd"));
            }
            "--remount-ro" => {
                let dest = trim_slashes(a(0).to_vec());
                match cfg.bindings.iter_mut().rev().find(|b| b.guest == dest) {
                    Some(b) => b.read_only = true,
                    None => {
                        let host = under_root(root, &dest);
                        cfg.bindings.push(Binding {
                            host,
                            guest: dest,
                            read_only: true,
                        });
                    }
                }
            }
            "--proc" => {
                ensure_mount_point(root, a(0), true);
                cfg.bindings.push(bind(b"/proc", a(0), false));
            }
            "--dev" => {
                ensure_mount_point(root, a(0), true);
                cfg.bindings.push(bind(b"/dev", a(0), false));
            }
            "--dir" | "--tmpfs" | "--mqueue" => {
                let p = under_root_path(root, a(0));
                fs::create_dir_all(&p).map_err(|e| usage(&op.option, a(0), e))?;
                set_mode(&p, op.perms.unwrap_or(0o755));
            }
            "--symlink" => {
                let link = under_root_path(root, a(1));
                if let Some(parent) = link.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                match fs::symlink_metadata(&link) {
                    Ok(m)
                        if m.file_type().is_symlink()
                            && fs::read_link(&link).ok().as_deref() == Some(Path::new(os(a(0)))) => {}
                    Ok(_) => {
                        return Err(CliError::Usage(format!(
                            "bwrap: Can't make symlink at {}: File exists",
                            String::from_utf8_lossy(a(1))
                        )));
                    }
                    Err(_) => std::os::unix::fs::symlink(os(a(0)), &link)
                        .map_err(|e| usage("--symlink", a(1), e))?,
                }
            }
            "--file" | "--bind-data" | "--ro-bind-data" => {
                let fd = parse_fd(Some(a(0)), &op.option)?;
                let data = read_fd(fd)
                    .map_err(|e| CliError::Usage(format!("bwrap: {}: fd {fd}: {e}", op.option)))?;
                unsafe { libc::close(fd) };
                let p = under_root_path(root, a(1));
                if let Some(parent) = p.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let mode = op.perms.unwrap_or(0o666 & !umask());
                fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(mode)
                    .open(&p)
                    .and_then(|mut f| std::io::Write::write_all(&mut f, &data))
                    .map_err(|e| usage(&op.option, a(1), e))?;
                set_mode(&p, mode);
                if op.option == "--ro-bind-data" {
                    let dest = trim_slashes(a(1).to_vec());
                    cfg.bindings.push(Binding {
                        host: p.as_os_str().as_bytes().to_vec(),
                        guest: dest,
                        read_only: true,
                    });
                }
            }
            "--chmod" => {
                let s = String::from_utf8_lossy(a(0)).into_owned();
                let mode = u32::from_str_radix(&s, 8)
                    .map_err(|_| CliError::Usage(format!("bwrap: bad --chmod {s}")))?;
                set_mode(&under_root_path(root, a(1)), mode);
            }
            _ => map_op(op, cfg, env, argv0)?,
        }
    }
    Ok(())
}

/// Applies an operation that touches only the configuration (no filesystem work).
///
/// # Arguments
/// * `op` - Parsed operation.
/// * `cfg` - Configuration being built.
/// * `env` - Environment being built for the command.
/// * `argv0` - Receives `--argv0`.
///
/// # Errors
/// [`CliError::Usage`] for unreadable descriptors and unsupported overlays.
pub fn map_op(
    op: &Op,
    cfg: &mut Config,
    env: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    argv0: &mut Option<Vec<u8>>,
) -> Result<(), CliError> {
    let a = |n: usize| -> &[u8] { &op.args[n] };
    match op.option.as_str() {
        "--chdir" => cfg.cwd = a(0).to_vec(),
        "--setenv" => {
            env.insert(a(0).to_vec(), a(1).to_vec());
        }
        "--unsetenv" => {
            env.remove(a(0));
        }
        "--clearenv" => env.clear(),
        "--argv0" => *argv0 = Some(a(0).to_vec()),
        "--die-with-parent" => cfg.kill_on_exit = true,
        "--new-session" => cfg.new_session = true,
        "--hostname" => cfg.hostname = Some(a(0).to_vec()),
        "--seccomp" | "--add-seccomp-fd" => {
            let fd = parse_fd(Some(a(0)), &op.option)?;
            let data =
                read_fd(fd).map_err(|e| CliError::Usage(format!("bwrap: {}: fd {fd}: {e}", op.option)))?;
            unsafe { libc::close(fd) };
            if op.option == "--seccomp" {
                cfg.seccomp_programs.clear();
            }
            cfg.seccomp_programs.push(data);
        }
        "--info-fd" => cfg.info_fds.push(parse_fd(Some(a(0)), "--info-fd")?),
        "--json-status-fd" => cfg
            .json_status_fds
            .push(parse_fd(Some(a(0)), "--json-status-fd")?),
        "--overlay" | "--tmp-overlay" | "--ro-overlay" | "--overlay-src" => {
            return Err(CliError::Usage(format!(
                "bwrap: {} is not supported without namespaces",
                op.option
            )));
        }
        // Namespaces, capabilities, ids, labels and synchronisation: nothing to do here.
        _ => {}
    }
    Ok(())
}

/// Creates the private root for this launch.
///
/// Lives under `$XDG_RUNTIME_DIR` when writable, else under a `0700`
/// per-user directory in the temporary directory.
///
/// # Errors
/// [`CliError::Usage`] when no suitable directory can be created.
fn make_root() -> Result<PathBuf, CliError> {
    let mut base = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d)
            if Path::new(&d).is_dir()
                && fs::metadata(&d)
                    .map(|m| m.permissions().mode() & 0o200 != 0)
                    .unwrap_or(false) =>
        {
            PathBuf::from(d)
        }
        _ => {
            let d = std::env::temp_dir().join(format!("proot-next-{}", unsafe { libc::getuid() }));
            let _ = fs::DirBuilder::new().mode(0o700).create(&d);
            d
        }
    };
    base.push("bwrap");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&base)
        .map_err(|e| CliError::Usage(format!("bwrap: cannot create {}: {e}", base.display())))?;
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ (std::process::id() as u64).rotate_left(32);
    for _ in 0..64 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let root = base.join(format!("{}-{:08x}", std::process::id(), seed as u32));
        match fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => return Ok(root),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(CliError::Usage(format!(
                    "bwrap: cannot create {}: {e}",
                    root.display()
                )));
            }
        }
    }
    Err(CliError::Usage(
        "bwrap: cannot find a free root directory name".into(),
    ))
}

/// Creates the mount point for `dest` inside the fresh root, so listings of
/// the parent show it and lexical path walks find a directory there.
fn ensure_mount_point(root: &Path, dest: &[u8], is_dir: bool) {
    let p = under_root_path(root, dest);
    if p == root {
        return;
    }
    if is_dir {
        let _ = fs::create_dir_all(&p);
    } else {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&p);
    }
}

fn under_root_path(root: &Path, guest: &[u8]) -> PathBuf {
    let g = trim_slashes(guest.to_vec());
    if g == b"/" {
        return root.to_path_buf();
    }
    root.join(os(&g[1..]))
}

fn under_root(root: &Path, guest: &[u8]) -> Vec<u8> {
    under_root_path(root, guest).as_os_str().as_bytes().to_vec()
}

fn bind(host: &[u8], guest: &[u8], read_only: bool) -> Binding {
    Binding {
        host: trim_slashes(host.to_vec()),
        guest: trim_slashes(guest.to_vec()),
        read_only,
    }
}

fn absolutize(p: &[u8]) -> Vec<u8> {
    if p.first() == Some(&b'/') {
        return p.to_vec();
    }
    let mut cwd = std::env::current_dir()
        .map(|c| c.as_os_str().as_bytes().to_vec())
        .unwrap_or_else(|_| b"/".to_vec());
    if cwd != b"/" {
        cwd.push(b'/');
    }
    cwd.extend_from_slice(p);
    cwd
}

fn os(b: &[u8]) -> &std::ffi::OsStr {
    std::ffi::OsStr::from_bytes(b)
}

fn set_mode(p: &Path, mode: u32) {
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(mode));
}

fn umask() -> u32 {
    let m = unsafe { libc::umask(0) };
    unsafe { libc::umask(m) };
    m as u32
}

fn usage(option: &str, path: &[u8], e: std::io::Error) -> CliError {
    CliError::Usage(format!("bwrap: {option} {}: {e}", String::from_utf8_lossy(path)))
}

fn parse_fd(v: Option<&[u8]>, option: &str) -> Result<i32, CliError> {
    let v = v.ok_or_else(|| CliError::Usage(format!("bwrap: {option} takes an argument")))?;
    String::from_utf8_lossy(v).parse::<i32>().map_err(|_| {
        CliError::Usage(format!(
            "bwrap: {option}: not a descriptor: {}",
            String::from_utf8_lossy(v)
        ))
    })
}

/// Reads an inherited descriptor to its end from its current position.
fn read_fd(fd: i32) -> std::io::Result<Vec<u8>> {
    use std::os::unix::io::FromRawFd;
    if fd < 0 {
        return Err(std::io::Error::from_raw_os_error(libc::EBADF));
    }
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut f = unsafe { fs::File::from_raw_fd(dup) };
    let mut out = Vec::new();
    f.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<Vec<u8>> {
        s.iter().map(|x| x.as_bytes().to_vec()).collect()
    }

    #[test]
    fn splits_ops_and_command_with_perms() {
        let (ops, cmd) = parse_ops(v(&[
            "--perms",
            "0700",
            "--dir",
            "/x",
            "--ro-bind",
            "/usr",
            "/usr",
            "--",
            "/bin/sh",
            "-c",
            "--die-with-parent",
        ]))
        .unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[0],
            Op {
                option: "--dir".into(),
                args: v(&["/x"]),
                perms: Some(0o700)
            }
        );
        assert_eq!(ops[1].perms, None);
        assert_eq!(cmd, v(&["/bin/sh", "-c", "--die-with-parent"]));
    }

    #[test]
    fn maps_config_only_options() {
        let mut cfg = Config::default();
        let mut env = BTreeMap::new();
        let mut argv0 = None;
        for op in [
            Op {
                option: "--die-with-parent".into(),
                args: vec![],
                perms: None,
            },
            Op {
                option: "--new-session".into(),
                args: vec![],
                perms: None,
            },
            Op {
                option: "--chdir".into(),
                args: v(&["/app"]),
                perms: None,
            },
            Op {
                option: "--setenv".into(),
                args: v(&["FOO", "bar"]),
                perms: None,
            },
            Op {
                option: "--unshare-all".into(),
                args: vec![],
                perms: None,
            },
            Op {
                option: "--hostname".into(),
                args: v(&["box"]),
                perms: None,
            },
        ] {
            map_op(&op, &mut cfg, &mut env, &mut argv0).unwrap();
        }
        assert!(cfg.kill_on_exit && cfg.new_session);
        assert_eq!(cfg.cwd, b"/app".to_vec());
        assert_eq!(env.get(b"FOO".as_slice()), Some(&b"bar".to_vec()));
        assert_eq!(cfg.hostname, Some(b"box".to_vec()));
    }

    #[test]
    fn ro_bind_is_read_only_and_root_is_private() {
        let cfg = parse(vec![
            "--ro-bind".into(),
            "/usr".into(),
            "/usr".into(),
            "--symlink".into(),
            "usr/lib".into(),
            "/lib".into(),
            "--".into(),
            "/bin/true".into(),
        ])
        .unwrap();
        let b = cfg.bindings.iter().find(|b| b.guest == b"/usr").unwrap();
        assert!(b.read_only && b.host == b"/usr");
        let root = Path::new(os(&cfg.root));
        assert!(root.join("usr").is_dir());
        assert_eq!(fs::read_link(root.join("lib")).unwrap(), Path::new("usr/lib"));
        assert_eq!(cfg.cleanup_dirs, vec![cfg.root.clone()]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_option_is_an_error() {
        assert!(matches!(parse_ops(v(&["--bogus", "x"])), Err(CliError::Usage(_))));
    }
}
