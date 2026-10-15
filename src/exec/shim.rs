//! The exec trampoline: a static binary installed in the alias directory as
//! `e`, and the record files that tell it what to run.
//!
//! Without ptrace every tracee has the alias directory as its kernel working
//! directory, so the two-byte path `e` names the trampoline from any
//! process, whatever length the original path string had.  The supervisor
//! writes `r<pid>` next to it with the plan (see [`write_record`]), rewrites
//! the path string to `e`, lets the exec proceed, and the trampoline execs
//! the real target with the arguments rebuilt from the record and its own,
//! untouched, `argv[1..]`.  A nested launch (see [`super::nested`]) takes
//! the trampoline in both modes, exec'd by its full path with ptrace, and
//! its record carries the process setup as well: a complete argument vector,
//! an environment, a directory to enter, session and death-signal flags,
//! seccomp programs, status descriptors, or a message to print and exit with.
//!
//! The binaries under `shim/bin/` are built by `shim/build.sh` from the
//! `no_std` crate in `shim/` and embedded here; one per host architecture.

use crate::exec::ExecPlan;
use crate::sys::Result;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[cfg(target_arch = "x86_64")]
const SHIM: &[u8] = include_bytes!("shim/bin/shim-x86_64");
#[cfg(target_arch = "aarch64")]
const SHIM: &[u8] = include_bytes!("shim/bin/shim-aarch64");

/// Name of the trampoline inside the alias directory.
pub const SHIM_NAME: &str = "e";

static INSTALLED: OnceLock<PathBuf> = OnceLock::new();

/// Installs the trampoline and returns the directory holding it.
///
/// The directory becomes every tracee's kernel working directory.  A base
/// where the trampoline cannot be executed (a `noexec` mount) is skipped for
/// the next candidate.
///
/// # Errors
/// A message when no candidate directory can hold an executable file.
pub fn install() -> std::result::Result<PathBuf, String> {
    if let Some(dir) = INSTALLED.get() {
        return Ok(dir.clone());
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        candidates.push(p);
    }
    candidates.push(std::env::temp_dir());
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".cache"));
    }
    let mut last = String::from("no candidate directory");
    for base in candidates.iter().filter(|b| b.is_dir()) {
        let dir = base.join(format!("proot-next-{}", std::process::id()));
        match install_in(&dir) {
            Ok(()) => {
                let _ = INSTALLED.set(dir.clone());
                crate::exec::set_alias_dir(dir.clone());
                return Ok(dir);
            }
            Err(e) => {
                last = format!("{}: {e}", dir.display());
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
    Err(format!("cannot install the exec shim ({last})"))
}

/// Writes the trampoline into `dir` and checks it runs there.
///
/// Run without a record the trampoline exits 126 after one line on stderr;
/// any other outcome means it did not run at all (a `noexec` mount, the
/// wrong architecture).
///
/// # Arguments
/// * `dir` - Directory to install into, created if needed.
fn install_in(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(SHIM_NAME);
    std::fs::write(&path, SHIM)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    let out = std::process::Command::new(&path)
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .output()?;
    if out.status.code() != Some(126) {
        return Err(std::io::Error::other(format!("trampoline did not run: {out:?}")));
    }
    Ok(())
}

/// Path of the installed trampoline.
pub fn path() -> Option<PathBuf> {
    INSTALLED.get().map(|d| d.join(SHIM_NAME))
}

/// Whether thread `tid` is currently executing the trampoline.
///
/// # Arguments
/// * `tid` - Thread id.
pub fn running(tid: u32) -> bool {
    let Some(me) = path() else { return false };
    std::fs::read_link(format!("/proc/{tid}/exe"))
        .map(|p| p == me)
        .unwrap_or(false)
}

/// Writes the record the trampoline will read for process `tgid`.
///
/// The record is a sequence of netstrings (`<length>:<bytes>,`), each
/// holding a one-byte tag and its value; text values carry their
/// terminating NUL so the trampoline can hand them to `execve` in place.
/// The first field is `v2`.  Then either `A<n>` (leading arguments, the
/// trampoline's own `argv[1..]` follow) or `a<n>` (the complete vector),
/// each followed by `n` fields tagged `-`; `p<path>` to exec; optionally
/// `e<n>` and `n` environment entries tagged `-`; `c<dir>` to enter; `s`
/// for a new session; `d` to die with the parent; `S<program>` (binary,
/// repeatable); `I<fd>` and `J<fd>` status descriptors; `W<text>` lines to
/// print; or, instead of all of the above, `E<code>:<text>` or
/// `O<code>:<text>` to print on stderr or stdout and exit.
///
/// # Arguments
/// * `tgid` - Process about to exec the trampoline.
/// * `plan` - What it should exec.
///
/// # Errors
/// Errno from writing the file.
pub fn write_record(tgid: i32, plan: &ExecPlan) -> Result<()> {
    let Some(dir) = INSTALLED.get() else {
        return Err(libc::ENOENT);
    };
    let mut rec = Record::default();
    rec.text(b'v', b"2");
    match &plan.trampoline {
        Some(t) => {
            for w in &t.warnings {
                rec.text(b'W', w);
            }
            if let Some((code, text, to_stdout)) = &t.exit {
                let mut v = format!("{code}:").into_bytes();
                v.extend_from_slice(text);
                rec.text(if *to_stdout { b'O' } else { b'E' }, &v);
            } else {
                rec.text(b'a', plan.argv.len().to_string().as_bytes());
                for a in &plan.argv {
                    rec.text(b'-', a);
                }
                rec.text(b'p', &plan.exec_path);
                if let Some(env) = &t.env {
                    rec.text(b'e', env.len().to_string().as_bytes());
                    for e in env {
                        rec.text(b'-', e);
                    }
                }
                if let Some(dir) = &t.chdir {
                    rec.text(b'c', dir);
                }
                if t.new_session {
                    rec.text(b's', b"");
                }
                if t.die_with_parent {
                    rec.text(b'd', b"");
                }
                for prog in &t.seccomp_programs {
                    rec.binary(b'S', prog);
                }
                for fd in &t.info_fds {
                    rec.text(b'I', fd.to_string().as_bytes());
                }
                for fd in &t.json_status_fds {
                    rec.text(b'J', fd.to_string().as_bytes());
                }
            }
        }
        None => {
            rec.text(b'A', plan.prefix.to_string().as_bytes());
            for a in &plan.argv[..plan.prefix] {
                rec.text(b'-', a);
            }
            rec.text(b'p', &plan.exec_path);
        }
    }
    std::fs::write(dir.join(format!("r{tgid}")), rec.bytes).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

/// A record under construction.
#[derive(Default)]
struct Record {
    bytes: Vec<u8>,
}

impl Record {
    /// Appends a text field: the tag, the text and a NUL.
    fn text(&mut self, tag: u8, value: &[u8]) {
        self.field(tag, value, true);
    }

    /// Appends a binary field: the tag and the bytes.
    fn binary(&mut self, tag: u8, value: &[u8]) {
        self.field(tag, value, false);
    }

    fn field(&mut self, tag: u8, value: &[u8], nul: bool) {
        let len = 1 + value.len() + usize::from(nul);
        self.bytes.extend_from_slice(len.to_string().as_bytes());
        self.bytes.push(b':');
        self.bytes.push(tag);
        self.bytes.extend_from_slice(value);
        if nul {
            self.bytes.push(0);
        }
        self.bytes.push(b',');
    }
}

/// Path of the record file of process `tgid`.
pub fn record_path(tgid: i32) -> Option<PathBuf> {
    INSTALLED.get().map(|d| d.join(format!("r{tgid}")))
}

/// The alias directory as bytes, for building rewritten paths.
pub fn dir_bytes() -> Option<Vec<u8>> {
    INSTALLED.get().map(|d| d.as_os_str().as_bytes().to_vec())
}
