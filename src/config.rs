//! Runtime configuration shared by both command-line front ends.

use std::ffi::CString;

/// One bind mount: the host path visible at `guest` inside the guest root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Absolute host path, without a trailing slash (except for `/`).
    pub host: Vec<u8>,
    /// Absolute guest path, without a trailing slash (except for `/`).
    pub guest: Vec<u8>,
    /// Whether writes through this binding are refused with `EROFS`.
    pub read_only: bool,
}

/// Everything the launcher needs to start the traced command.
#[derive(Clone, Debug)]
pub struct Config {
    /// Host directory used as the guest `/`.
    pub root: Vec<u8>,
    /// Bind mounts, in command-line order; later entries win on equal prefix.
    pub bindings: Vec<Binding>,
    /// Initial working directory, as a guest path.
    pub cwd: Vec<u8>,
    /// `cwd` was not given on the command line: it is the caller's working
    /// directory, to be kept only where the guest can see it.
    pub cwd_default: bool,
    /// Kill every tracee when the supervisor exits.
    pub kill_on_exit: bool,
    /// Verbosity, 0 is quiet.
    pub verbose: i32,
    /// Command and arguments to run inside the guest; `argv[0]` first.
    pub command: Vec<CString>,
    /// Environment for the command, or `None` to inherit the supervisor's.
    pub env: Option<Vec<CString>>,
    /// Value reported by `uname(2)` in the `release` field, if faked.
    pub kernel_release: Option<Vec<u8>>,
    /// Pretend to be root (fake_id0).  Accepted but not implemented yet.
    pub fake_root: bool,
    /// Number of supervisor threads answering seccomp notifications.
    pub threads: usize,
    /// Microseconds a supervisor thread spins before parking.
    pub spin_us: u64,
    /// Directories to remove recursively once the tracer returns (bwrap mode).
    pub cleanup_dirs: Vec<Vec<u8>>,
    /// Extra classic-BPF seccomp programs (raw `sock_filter` bytes) the first
    /// tracee installs after ours (bwrap `--seccomp`/`--add-seccomp-fd`).
    pub seccomp_programs: Vec<Vec<u8>>,
    /// Descriptors that receive `{"child-pid": N}` once the child is forked
    /// (bwrap `--info-fd`).
    pub info_fds: Vec<i32>,
    /// Descriptors that receive `{"child-pid": N}` and later `{"exit-code": N}`
    /// (bwrap `--json-status-fd`).
    pub json_status_fds: Vec<i32>,
    /// Run the command in a new session (bwrap `--new-session`).
    pub new_session: bool,
    /// Hostname to report (bwrap `--hostname`).  Not applied yet.
    pub hostname: Option<Vec<u8>>,
    /// `argv[0]` to give the command when it differs from `command[0]` (bwrap `--argv0`).
    pub argv0: Option<CString>,
    /// Invoked through the bubblewrap front end: failures are worded as bwrap words them.
    pub bwrap_mode: bool,
}

impl Default for Config {
    /// Builds the configuration equivalent to running `proot` with no option.
    fn default() -> Self {
        let threads = std::env::var("PROOT_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4);
        let spin_us = std::env::var("PROOT_SPIN_US")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200);
        // bwrap mode has no verbosity flag of its own; the environment serves both front ends.
        let verbose = std::env::var("PROOT_VERBOSE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        Config {
            root: b"/".to_vec(),
            bindings: Vec::new(),
            cwd: b".".to_vec(),
            cwd_default: false,
            kill_on_exit: false,
            verbose,
            command: Vec::new(),
            env: None,
            kernel_release: None,
            fake_root: false,
            threads,
            spin_us,
            cleanup_dirs: Vec::new(),
            seccomp_programs: Vec::new(),
            info_fds: Vec::new(),
            json_status_fds: Vec::new(),
            new_session: false,
            hostname: None,
            argv0: None,
            bwrap_mode: false,
        }
    }
}

/// Strips trailing slashes from a path, keeping a lone `/`.
///
/// # Arguments
/// * `path` - Any path.
///
/// # Returns
/// The same path without trailing slashes.
pub fn trim_slashes(mut path: Vec<u8>) -> Vec<u8> {
    while path.len() > 1 && path.ends_with(b"/") {
        path.pop();
    }
    if path.is_empty() {
        path.push(b'/');
    }
    path
}
