//! Where a command line is interpreted: the parsers ask this for everything
//! that depends on the process that typed it.
//!
//! A top-level launch is parsed in the supervisor's own process.  A nested
//! launch (a tracee exec'ing proot or bwrap, see `exec::nested`) is parsed by
//! the supervisor on the tracee's behalf: paths are the tracee's guest paths,
//! the working directory and environment are the tracee's, and descriptors
//! named on the command line are open in the tracee.

use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The process a command line is interpreted for.
pub trait Host {
    /// Whether `path`, as this process names it, exists.
    fn exists(&self, path: &[u8]) -> bool;

    /// Whether `path`, as this process names it, is a directory (symlinks followed).
    fn is_dir(&self, path: &[u8]) -> bool;

    /// The absolute host path behind `path` as this process names it.
    ///
    /// A path that does not exist is still mapped, so a binding may name a
    /// mount point that appears later.
    fn host_path(&self, path: &[u8]) -> Vec<u8>;

    /// The working directory, as this process names it.
    fn cwd(&self) -> Vec<u8>;

    /// One environment variable.
    fn var(&self, name: &[u8]) -> Option<Vec<u8>>;

    /// The whole environment.
    fn vars(&self) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// Reads descriptor `fd` of this process to its end.
    fn read_fd(&self, fd: i32) -> std::io::Result<Vec<u8>>;

    /// The host path descriptor `fd` of this process is open on.
    fn fd_path(&self, fd: i32) -> std::io::Result<Vec<u8>>;
}

/// The supervisor's own process.
pub struct Local;

impl Host for Local {
    fn exists(&self, path: &[u8]) -> bool {
        Path::new(std::ffi::OsStr::from_bytes(path)).exists()
    }

    fn is_dir(&self, path: &[u8]) -> bool {
        Path::new(std::ffi::OsStr::from_bytes(path)).is_dir()
    }

    fn host_path(&self, path: &[u8]) -> Vec<u8> {
        if path.first() == Some(&b'/') {
            return path.to_vec();
        }
        let mut cwd = self.cwd();
        if cwd != b"/" {
            cwd.push(b'/');
        }
        cwd.extend_from_slice(path);
        cwd
    }

    fn cwd(&self) -> Vec<u8> {
        std::env::current_dir()
            .map(|c| c.as_os_str().as_bytes().to_vec())
            .unwrap_or_else(|_| b"/".to_vec())
    }

    fn var(&self, name: &[u8]) -> Option<Vec<u8>> {
        std::env::var_os(std::ffi::OsStr::from_bytes(name)).map(|v| v.as_bytes().to_vec())
    }

    fn vars(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        std::env::vars_os()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect()
    }

    fn read_fd(&self, fd: i32) -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        use std::os::unix::io::FromRawFd;
        if fd < 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EBADF));
        }
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut f = unsafe { std::fs::File::from_raw_fd(dup) };
        let mut out = Vec::new();
        f.read_to_end(&mut out)?;
        Ok(out)
    }

    fn fd_path(&self, fd: i32) -> std::io::Result<Vec<u8>> {
        std::fs::read_link(format!("/proc/self/fd/{fd}")).map(|p| p.as_os_str().as_bytes().to_vec())
    }
}
