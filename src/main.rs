//! PRoot reimplemented in Rust.
//!
//! The program runs a command inside a guest root filesystem without any
//! privilege.  Path-taking syscalls are routed through seccomp user
//! notification and answered by a small pool of supervisor threads; only the
//! syscalls that must change the tracee's own state in place (`execve`,
//! `chdir`, unix socket `bind`/`connect`) take a ptrace stop.  Everything else
//! runs untraced at native speed.  Where ptrace is filtered out, those few
//! syscalls are served through notifications too, with in-place rewrites
//! (`syscall::direct`).
//!
//! The binary behaves like bubblewrap when invoked through a name ending in
//! `bwrap`, busybox style, so a symlink is enough to make it a drop-in.

mod abi;
mod cli;
mod config;
mod exec;
mod fs;
mod launch;
mod procs;
mod seccomp;
mod state;
mod sys;
mod syscall;
mod tracee;
mod tracer;

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

/// Program entry point.
///
/// Dispatches on the basename of `argv[0]`: a name ending in `bwrap` selects
/// the bubblewrap-compatible front end, anything else the PRoot front end.
/// Exits with the traced command's exit status, or 1 on internal error.
fn main() {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    let argv0 = args.remove(0);
    let base = std::path::Path::new(&argv0)
        .file_name()
        .map(|f| f.as_bytes().to_vec())
        .unwrap_or_default();
    let parsed = if base.ends_with(b"bwrap") {
        cli::bwrap::parse(args, &cli::host::Local)
    } else {
        cli::parse(args, &cli::host::Local)
    };
    let config = match parsed {
        Ok(c) => c,
        Err(cli::CliError::Exit { code, text }) => {
            print!("{text}");
            std::process::exit(code)
        }
        Err(cli::CliError::Usage(msg)) => {
            eprintln!("proot: {msg}");
            std::process::exit(125);
        }
    };
    match launch::run(config) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("proot: {e}");
            std::process::exit(1);
        }
    }
}
