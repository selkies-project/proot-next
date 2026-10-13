//! The exec trampoline of the no-ptrace mode: a static binary installed in
//! the alias directory as `e`, and the record files that tell it what to run.
//!
//! Every tracee has the alias directory as its kernel working directory, so
//! the two-byte path `e` names the trampoline from any process, whatever
//! length the original path string had.  The supervisor writes `r<pid>` next
//! to it with the plan (see [`write_record`]), rewrites the path string to
//! `e`, lets the exec proceed, and the trampoline execs the real target with
//! the arguments rebuilt from the record and its own, untouched, `argv[1..]`.
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
/// Format: NUL-separated fields, the count of leading arguments as decimal
/// text, the path to exec, then those arguments.
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
    let mut rec = Vec::with_capacity(256);
    rec.extend_from_slice(plan.prefix.to_string().as_bytes());
    rec.push(0);
    rec.extend_from_slice(&plan.exec_path);
    rec.push(0);
    for a in &plan.argv[..plan.prefix] {
        rec.extend_from_slice(a);
        rec.push(0);
    }
    std::fs::write(dir.join(format!("r{tgid}")), rec).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

/// Path of the record file of process `tgid`.
pub fn record_path(tgid: i32) -> Option<PathBuf> {
    INSTALLED.get().map(|d| d.join(format!("r{tgid}")))
}

/// The alias directory as bytes, for building rewritten paths.
pub fn dir_bytes() -> Option<Vec<u8>> {
    INSTALLED.get().map(|d| d.as_os_str().as_bytes().to_vec())
}
