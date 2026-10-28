//! Translating a tracee's `(dirfd, path)` into the object to act on, or
//! into a host path, and back.

use super::Fs;
use super::canon::{Resolved, resolve};
use crate::sys::{PATH_MAX, Result};

/// The guest path of a tracee's working directory.
///
/// Without ptrace the kernel's cwd of every tracee is pinned to the alias
/// directory and the real one is kept in the process table; otherwise it is
/// read from `/proc`.
///
/// # Arguments
/// * `fs` - Guest filesystem view.
/// * `pid` - Tracee thread id.
pub fn guest_cwd(fs: &Fs, pid: u32) -> Result<Vec<u8>> {
    if let Some(cwd) = fs.virtual_cwd(pid as i32) {
        return Ok(cwd);
    }
    let host = strip_deleted(read_link(format!("/proc/{pid}/cwd").as_bytes())?);
    Ok(detranslate_path(fs, &host))
}

/// Drops the ` (deleted)` marker `/proc` appends to links of unlinked targets.
pub fn strip_deleted(mut host: Vec<u8>) -> Vec<u8> {
    const MARK: &[u8] = b" (deleted)";
    if host.len() > MARK.len() + 1 && host.ends_with(MARK) {
        host.truncate(host.len() - MARK.len());
    }
    host
}

/// Reads the guest path of a tracee's open directory descriptor.
///
/// # Arguments
/// * `fs` - Guest filesystem view.
/// * `pid` - Tracee thread id.
/// * `fd` - Descriptor number in the tracee.
pub fn guest_fd_path(fs: &Fs, pid: u32, fd: i32) -> Result<Vec<u8>> {
    if fd < 0 {
        return Err(libc::EBADF);
    }
    let host = strip_deleted(read_link(format!("/proc/{pid}/fd/{fd}").as_bytes())?);
    if host.first() != Some(&b'/') {
        // Pipes, sockets and anonymous inodes read like `pipe:[123]`.
        return Err(libc::ENOTDIR);
    }
    Ok(detranslate_path(fs, &host))
}

/// The guest path of `dirfd` itself, or of the tracee's cwd for `AT_FDCWD`:
/// what an empty path names in the calls that allow one (`AT_EMPTY_PATH`,
/// and `readlinkat` always).
///
/// # Arguments
/// * `fs` - Guest filesystem view.
/// * `pid` - Tracee thread id.
/// * `dirfd` - Descriptor number in the tracee, or `libc::AT_FDCWD`.
pub fn guest_dirfd_path(fs: &Fs, pid: u32, dirfd: i32) -> Result<Vec<u8>> {
    if dirfd == libc::AT_FDCWD {
        guest_cwd(fs, pid)
    } else {
        guest_fd_path(fs, pid, dirfd)
    }
}

/// Translates a path as seen by a tracee into the object to operate on.
///
/// Relative paths are resolved against `dirfd` (`AT_FDCWD` means the tracee's
/// cwd) by reading the descriptor's own path from `/proc`, so the whole path
/// is canonicalized inside the guest namespace, on the descriptors the view
/// holds open (see [`resolve`]).  An empty path fails with `ENOENT`, as the
/// kernel's lookup fails it; a call that lets it name `dirfd` itself
/// resolves [`guest_dirfd_path`] instead.
///
/// # Arguments
/// * `fs` - Guest filesystem view.
/// * `pid` - Tracee thread id.
/// * `dirfd` - Base descriptor for relative paths, or `libc::AT_FDCWD`.
/// * `path` - Path bytes as read from the tracee, without NUL.
/// * `deref_final` - Follow a symlink in the final component.
///
/// # Returns
/// The canonical guest path, its host path, and the pinned directory and
/// name to act on.
///
/// # Errors
/// `ENOENT` for an empty path, errno from the walk, or `EBADF` when `dirfd`
/// cannot be resolved.
pub fn translate(fs: &Fs, pid: u32, dirfd: i32, path: &[u8], deref_final: bool) -> Result<Resolved> {
    if path.is_empty() {
        return Err(libc::ENOENT);
    }
    let guest = if path.first() == Some(&b'/') {
        path.to_vec()
    } else {
        let mut base = guest_dirfd_path(fs, pid, dirfd)?;
        if base != b"/" {
            base.push(b'/');
        }
        base.extend_from_slice(path);
        base
    };
    let resolved = resolve(fs, pid, &guest, deref_final)?;
    if resolved.guest.len() >= PATH_MAX {
        return Err(libc::ENAMETOOLONG);
    }
    Ok(resolved)
}

/// Translates a path as seen by a tracee into a textual host path, for the
/// callers that hand the path to a program or to the tracee itself (the
/// exec plan, the ptrace tier's in-place rewrites): the kernel then resolves
/// it again on the host.
///
/// # Arguments
/// As [`translate`].
///
/// # Returns
/// An absolute host path.
pub fn translate_path(fs: &Fs, pid: u32, dirfd: i32, path: &[u8], deref_final: bool) -> Result<Vec<u8>> {
    translate(fs, pid, dirfd, path, deref_final).map(|r| r.host)
}

/// Translates a host path back into the guest's view (for `readlink` on
/// `/proc` magic links and `getcwd`).
///
/// # Arguments
/// * `fs` - Guest filesystem view.
/// * `host` - Absolute host path.
///
/// # Returns
/// The guest path; a host path outside every binding is returned unchanged.
pub fn detranslate_path(fs: &Fs, host: &[u8]) -> Vec<u8> {
    fs.substitute_host_to_guest(host).unwrap_or_else(|| host.to_vec())
}

/// `readlink(2)` on a host path, as bytes.
///
/// # Arguments
/// * `host` - Host path to read.
pub fn read_link(host: &[u8]) -> Result<Vec<u8>> {
    let c = std::ffi::CString::new(host.to_vec()).map_err(|_| libc::EINVAL)?;
    let mut buf = vec![0u8; PATH_MAX];
    let n = unsafe { libc::readlink(c.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if n < 0 {
        return Err(crate::sys::errno());
    }
    buf.truncate(n as usize);
    Ok(buf)
}
