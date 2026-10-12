//! PRoot command-line front end (the subset proot-apps and users rely on).

pub mod bwrap;

use crate::config::{Binding, Config, trim_slashes};
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;

/// Why parsing stopped.
#[derive(Debug)]
pub enum CliError {
    /// Print nothing more and exit with this code (`--help`, `--version`).
    Exit(i32),
    /// A usage error with its message.
    Usage(String),
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage:
  proot [option] ... [command]

Regular options:
  -r *path*, --rootfs=*path*    Use *path* as the new guest root file-system, default is /.
  -b *path*, --bind=*path*      Make the content of *path* accessible in the guest rootfs (host:guest).
  -w *path*, --cwd=*path*       Set the initial working directory to *path*.
  --kill-on-exit                Kill all processes on command exit (always on; accepted for compatibility).
  -v *value*, --verbose=*value* Set the level of debug information to *value*.
  -V, --version                 Print version, copyright, license and contact, then exit.
  -h, --help                    Print the version and the command-line usage, then exit.

Extension options:
  -k *string*, --kernel-release=*string*  Make current kernel appear as kernel release *string*.
  -0, --root-id                 Make current user appear as \"root\": ids read as 0, ownership changes succeed.
  -l, --link2symlink            Accepted and ignored.

Alias options:
  -R *path*                     Alias: -r *path* + a couple of recommended -b.
  -S *path*                     Alias: -0 -r *path* + a couple of recommended -b.

Environment: PROOT_THREADS (default 4) and PROOT_SPIN_US (default 200) tune the supervisor pool.
";

/// Host paths bound into the guest by `-R` and `-S`, when they exist.
const RECOMMENDED_R: &[&str] = &[
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/hosts.equiv",
    "/etc/mtab",
    "/etc/netgroup",
    "/etc/networks",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/dev/",
    "/sys/",
    "/proc/",
    "/tmp/",
    "/run/",
    "/var/run/dbus/system_bus_socket",
];
const RECOMMENDED_S: &[&str] = &[
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/dev/",
    "/sys/",
    "/proc/",
    "/tmp/",
    "/run/shm",
];

/// Parses PRoot-style arguments (without `argv[0]`).
///
/// # Arguments
/// * `args` - Command-line arguments.
///
/// # Returns
/// The configuration to launch.
///
/// # Errors
/// [`CliError::Exit`] after `--help`/`--version`, [`CliError::Usage`] otherwise.
pub fn parse(args: Vec<OsString>) -> Result<Config, CliError> {
    let mut cfg = Config::default();
    let mut it = args.into_iter().peekable();
    let mut cwd_set = false;
    while let Some(a) = it.peek().cloned() {
        let s = a.as_bytes();
        if s.is_empty() || s[0] != b'-' || s == b"-" {
            break;
        }
        it.next();
        if s == b"--" {
            break;
        }
        // Split "--opt=value" and recognise "--opt value" / "-o value".
        let (opt, inline): (Vec<u8>, Option<Vec<u8>>) = match s.iter().position(|&c| c == b'=') {
            Some(i) if s.starts_with(b"--") => (s[..i].to_vec(), Some(s[i + 1..].to_vec())),
            _ => (s.to_vec(), None),
        };
        let value =
            |it: &mut std::iter::Peekable<std::vec::IntoIter<OsString>>| -> Result<Vec<u8>, CliError> {
                if let Some(v) = inline.clone() {
                    return Ok(v);
                }
                it.next().map(|v| v.as_bytes().to_vec()).ok_or_else(|| {
                    CliError::Usage(format!("missing value for {}", String::from_utf8_lossy(&opt)))
                })
            };
        match &opt[..] {
            b"-r" | b"--rootfs" => cfg.root = value(&mut it)?,
            b"-R" | b"-S" => {
                cfg.root = value(&mut it)?;
                let list = if opt == b"-R" {
                    RECOMMENDED_R
                } else {
                    RECOMMENDED_S
                };
                for p in list {
                    if std::path::Path::new(p).exists() {
                        cfg.bindings.push(bind(p.as_bytes(), None));
                    }
                }
                if let Some(home) = std::env::var_os("HOME") {
                    cfg.bindings.push(bind(home.as_bytes(), None));
                }
                if opt == b"-S" {
                    cfg.fake_root = true;
                }
            }
            b"-b" | b"--bind" | b"-m" | b"--mount" => {
                let v = value(&mut it)?;
                match v.iter().position(|&c| c == b':') {
                    Some(i) => cfg.bindings.push(bind(&v[..i], Some(&v[i + 1..]))),
                    None => cfg.bindings.push(bind(&v, None)),
                }
            }
            b"-w" | b"--cwd" | b"--pwd" => {
                cfg.cwd = value(&mut it)?;
                cwd_set = true;
            }
            b"--kill-on-exit" => cfg.kill_on_exit = true,
            b"-v" | b"--verbose" => {
                let v = value(&mut it)?;
                cfg.verbose = String::from_utf8_lossy(&v)
                    .parse()
                    .map_err(|_| CliError::Usage("bad verbosity".into()))?;
            }
            b"-k" | b"--kernel-release" => cfg.kernel_release = Some(value(&mut it)?),
            b"-0" | b"--root-id" => cfg.fake_root = true,
            b"-l" | b"--link2symlink" | b"-i" | b"--change-id" | b"-p" | b"--port" => {
                if matches!(&opt[..], b"-i" | b"--change-id" | b"-p" | b"--port") {
                    value(&mut it)?;
                }
                eprintln!(
                    "proot: option {} is accepted but not implemented yet",
                    String::from_utf8_lossy(&opt)
                );
            }
            b"-q" | b"--qemu" => return Err(CliError::Usage("qemu support is not implemented".into())),
            b"-V" | b"--version" => {
                println!(
                    "proot-next {VERSION}\nA Rust reimplementation of PRoot (seccomp user notification + ptrace)."
                );
                return Err(CliError::Exit(0));
            }
            b"-h" | b"--help" | b"--usage" => {
                print!("proot-next {VERSION}\n\n{USAGE}");
                return Err(CliError::Exit(0));
            }
            _ => {
                return Err(CliError::Usage(format!(
                    "unknown option {}",
                    String::from_utf8_lossy(&opt)
                )));
            }
        }
    }
    cfg.command = it
        .map(|a| CString::new(a.as_bytes()).unwrap_or_default())
        .collect();
    if cfg.command.is_empty() {
        let shell = std::env::var_os("SHELL").unwrap_or_else(|| "/bin/sh".into());
        cfg.command = vec![CString::new(shell.as_bytes()).unwrap()];
    }
    if !cwd_set {
        // PRoot: the initial cwd is the host cwd, as a guest path, when it is visible there.
        cfg.cwd = std::env::current_dir()
            .map(|p| p.as_os_str().as_bytes().to_vec())
            .unwrap_or_else(|_| b"/".to_vec());
    }
    Ok(cfg)
}

fn bind(host: &[u8], guest: Option<&[u8]>) -> Binding {
    let host = trim_slashes(host.to_vec());
    let guest = trim_slashes(guest.map(|g| g.to_vec()).unwrap_or_else(|| host.clone()));
    Binding {
        host,
        guest,
        read_only: false,
    }
}
