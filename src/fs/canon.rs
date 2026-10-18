//! Component-wise canonicalization of guest paths (port of PRoot's `canon.c`),
//! walked on descriptors.
//!
//! Every component of a guest path is looked up on the host side of its
//! binding, relative to an `O_PATH` descriptor of the directory walked so
//! far, never through a textual host path: a symlink found there is read and
//! re-interpreted *in the guest namespace*, so a link to `/usr/lib` inside
//! the rootfs lands in the rootfs's `/usr/lib`, never the host's.  The walk
//! starts from the descriptors [`Fs`] holds open on the root and on every
//! binding, and ends on a [`Resolved`]: the pinned parent directory and the
//! final name, which the handlers act on with the `*at` syscalls and
//! `O_NOFOLLOW`.  A directory the guest renames away and replaces by a
//! symlink while a call is in flight is then seen as the symlink it is, and
//! resolved inside the guest on a retry, instead of followed on the host by
//! the kernel's own walk of a stale string.  Directories already resolved are
//! kept in [`Fs`]'s cache to skip the `openat` next time.

use super::Fs;
use crate::sys::{Errno, PATH_MAX, Result, errno};
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

/// Symlink hops allowed before giving up with `ELOOP` (Linux's `MAXSYMLINKS`).
const MAX_SYMLINKS: u32 = 40;

/// Walks started over, after a component changed under the walk, before
/// giving up with `ELOOP`.
const MAX_RESTARTS: u32 = 3;

/// Sentinel errno: the object changed between two steps of a lookup or
/// between the lookup and the call; start over from the guest path.  Never
/// reaches a tracee: [`resolve`] and the handlers turn it into `ELOOP` once
/// the restarts are used up.
pub const RETRY: Errno = -2;

/// Where the object a guest path names is, for the `*at` syscalls.
#[derive(Debug)]
pub enum At {
    /// `name` inside the pinned directory `parent`.  Acted on with
    /// `O_NOFOLLOW`/`AT_SYMLINK_NOFOLLOW`: the walk already followed the
    /// name when asked to, so a symlink there now was swapped in since.
    Child { parent: Arc<OwnedFd>, name: Vec<u8> },
    /// The pinned object itself: the root or a binding, reached through
    /// `/proc/self/fd/<n>`, which the kernel resolves to the open inode.
    Object(Arc<OwnedFd>),
    /// Only the textual host path: a `/proc` magic link the kernel must
    /// re-open itself, or a mount point whose host side does not exist yet.
    Path,
}

/// A guest path resolved inside the guest namespace.
#[derive(Debug)]
pub struct Resolved {
    /// The canonical absolute guest path.
    pub guest: Vec<u8>,
    /// Its textual host path, for logging, identity checks and the `/proc`
    /// fakes; not what the syscall acts on when `at` is pinned.
    pub host: Vec<u8>,
    /// What the syscall acts on.
    pub at: At,
}

impl Resolved {
    /// The `(dirfd, path, nofollow)` triple for a `*at` syscall.
    ///
    /// # Arguments
    /// * `nofollow` - Whether the caller asked not to follow a final symlink.
    ///
    /// # Returns
    /// The descriptor and path to pass, and whether to pass the no-follow
    /// flag: always for a pinned name, never through a `/proc/self/fd` link
    /// (the object behind it is never a symlink), as asked otherwise.
    pub fn at(&self, nofollow: bool) -> Result<(RawFd, CString, bool)> {
        match &self.at {
            At::Child { parent, name } => Ok((parent.as_raw_fd(), cstr(name)?, true)),
            At::Object(fd) => Ok((libc::AT_FDCWD, fd_path(fd), false)),
            At::Path => Ok((libc::AT_FDCWD, cstr(&self.host)?, nofollow)),
        }
    }

    /// Whether the syscall acts through a pinned parent or object.
    pub fn pinned(&self) -> bool {
        !matches!(self.at, At::Path)
    }

    /// Whether the path names a mount point of the view itself.
    pub fn is_mount_point(&self) -> bool {
        matches!(self.at, At::Object(_))
    }

    /// `st_mode` of the object, without following a final symlink.
    pub fn mode_nofollow(&self) -> Result<u32> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let (dfd, c, nofollow) = self.at(true)?;
        let flags = if nofollow { libc::AT_SYMLINK_NOFOLLOW } else { 0 };
        if unsafe { libc::fstatat(dfd, c.as_ptr(), &mut st, flags) } < 0 {
            return Err(errno());
        }
        Ok(st.st_mode)
    }

    /// An `O_PATH` descriptor of the object itself, for the syscalls without
    /// a `dirfd` form, which then act on `/proc/self/fd/<n>`.
    ///
    /// # Arguments
    /// * `deref` - Whether the caller asked to follow a final symlink.  The
    ///   walk did so already, so a symlink found here was swapped in since
    ///   and the lookup is retried; without `deref` a symlink is returned as
    ///   the object, with its mode, for the caller to refuse or to act on
    ///   through its parent.
    ///
    /// # Returns
    /// The descriptor and the object's `st_mode`.
    pub fn object(&self, deref: bool) -> Result<(Arc<OwnedFd>, u32)> {
        let fd = match &self.at {
            At::Object(fd) => fd.clone(),
            At::Child { parent, name } => Arc::new(open_at(parent, name, libc::O_NOFOLLOW)?),
            At::Path => {
                let c = cstr(&self.host)?;
                let flags = libc::O_PATH | libc::O_CLOEXEC | if deref { 0 } else { libc::O_NOFOLLOW };
                let fd = unsafe { libc::open(c.as_ptr(), flags) };
                if fd < 0 {
                    return Err(errno());
                }
                Arc::new(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        };
        let mode = fstat_mode(&fd)?;
        if deref && self.pinned() && mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(RETRY);
        }
        Ok((fd, mode))
    }

    /// The path of the object with only its parents pinned,
    /// `/proc/self/fd/<parent>/<name>`, for a syscall that must see the
    /// name as it is now (the `l*xattr` family, a socket address).
    pub fn parent_path(&self) -> Result<CString> {
        match &self.at {
            At::Child { parent, name } => {
                let mut p = format!("/proc/self/fd/{}/", parent.as_raw_fd()).into_bytes();
                p.extend_from_slice(name);
                cstr(&p)
            }
            At::Object(fd) => Ok(fd_path(fd)),
            At::Path => cstr(&self.host),
        }
    }
}

/// `/proc/self/fd/<n>` of a descriptor, as a C string.
pub fn fd_path(fd: &OwnedFd) -> CString {
    CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap()
}

/// What becomes of the components after a missing intermediate one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Missing {
    /// They are appended lexically: the path a binding table or a mount
    /// point needs names where the object would be.
    Lexical,
    /// The lookup fails with `ENOENT`, as the kernel's would.
    Errno,
}

/// Canonicalizes an absolute guest path inside the guest namespace.
///
/// Unlike [`resolve`], a path whose intermediate component is missing stays
/// lexical from there on, as the binding table needs it.
///
/// # Arguments
/// * `fs` - Guest filesystem view.
/// * `pid` - Tracee thread id the path belongs to (for `/proc/self`).
/// * `guest` - Absolute guest path, may contain `.`/`..`/double slashes.
/// * `deref_final` - Follow a symlink in the last component.
///
/// # Returns
/// The canonical absolute guest path (no `.`/`..`/symlinks in the walked part).
///
/// # Errors
/// As [`resolve`], except for a missing intermediate component.
pub fn canonicalize(fs: &Fs, pid: u32, guest: &[u8], deref_final: bool) -> Result<Vec<u8>> {
    resolve_with(fs, pid, guest, deref_final, Missing::Lexical).map(|r| r.guest)
}

/// Resolves an absolute guest path inside the guest namespace to the pinned
/// directory and name to act on.
///
/// Walks `guest` one component at a time.  Each intermediate component is
/// opened `O_PATH` relative to the directory walked so far; a symlink is
/// read and its target re-entered into the walk as a guest path (absolute
/// targets restart from guest `/`).  The final component is dereferenced
/// only when `deref_final` is true.  A final component that does not exist
/// is returned as a name in its parent, so the kernel produces the real
/// error, or creates it, through the pinned parent; a missing or non-directory
/// intermediate component fails here with the errno the kernel would give.
///
/// `/proc` magic links are special: `/proc/self` and `/proc/thread-self`
/// become the tracee's own entries (not the supervisor's), and the targets of
/// `/proc/<pid>/{exe,cwd,root,fd/N,map_files/*}` are host paths, so they are
/// detranslated instead of being re-walked as guest paths.
///
/// # Arguments
/// * `fs` - Guest filesystem view.
/// * `pid` - Tracee thread id the path belongs to (for `/proc/self`).
/// * `guest` - Absolute guest path, may contain `.`/`..`/double slashes.
/// * `deref_final` - Follow a symlink in the last component.
///
/// # Errors
/// `ELOOP` after too many symlinks, or when a component kept changing under
/// the walk; `ENAMETOOLONG` for an overlong result; `ENOTDIR` when an
/// intermediate component is not a directory; `ENOENT` when one is missing;
/// `EINVAL` for a relative input.
pub fn resolve(fs: &Fs, pid: u32, guest: &[u8], deref_final: bool) -> Result<Resolved> {
    resolve_with(fs, pid, guest, deref_final, Missing::Errno)
}

fn resolve_with(fs: &Fs, pid: u32, guest: &[u8], deref_final: bool, missing: Missing) -> Result<Resolved> {
    if guest.first() != Some(&b'/') {
        return Err(libc::EINVAL);
    }
    if guest.len() >= PATH_MAX {
        return Err(libc::ENAMETOOLONG);
    }
    for _ in 0..MAX_RESTARTS {
        match walk(fs, pid, guest, deref_final, missing) {
            Err(RETRY) => continue,
            Ok(r) if r.guest.len() >= PATH_MAX => return Err(libc::ENAMETOOLONG),
            r => return r,
        }
    }
    Err(libc::ELOOP)
}

/// One pass of [`resolve`]; `Err(RETRY)` when a component changed under it.
fn walk(fs: &Fs, pid: u32, path: &[u8], deref_final: bool, missing: Missing) -> Result<Resolved> {
    // The canonical guest directory walked so far, and its pinned descriptor:
    // `None` while textual (a mount point whose host side is missing), and
    // stale when `seated` is false (after `..` or a `/proc` rewrite), to be
    // reopened from the mount point before the next lookup.
    let mut result: Vec<u8> = b"/".to_vec();
    let mut cur: Option<Arc<OwnedFd>> = fs.mount_pin(b"/").flatten();
    let mut seated = true;
    let mut queue: VecDeque<Vec<u8>> = components(path);
    let mut hops = 0u32;
    while let Some(comp) = queue.pop_front() {
        let is_final = queue.is_empty();
        match comp.as_slice() {
            b"." => continue,
            b".." => {
                pop_component(&mut result);
                seated = false;
                continue;
            }
            _ => {}
        }
        let candidate = join(&result, &comp);
        // The tracee's own /proc entries, never the supervisor's.
        if candidate == b"/proc/self" {
            result = format!("/proc/{pid}").into_bytes();
            seated = false;
            continue;
        }
        if candidate == b"/proc/thread-self" {
            result = format!("/proc/{pid}/task/{pid}").into_bytes();
            seated = false;
            continue;
        }
        if (!is_final || deref_final) && is_proc_magic_link(&candidate) {
            // `/proc/<n>/exe` is answered from our own record: the kernel's link
            // names the dynamic loader after an exec rewrite.  Without ptrace
            // `/proc/<n>/cwd` is too, since the kernel's is pinned elsewhere.
            if candidate.ends_with(b"/exe")
                && let Some(exe) = proc_pid(&candidate).and_then(|n| fs.exe_of(n))
            {
                result = exe;
                seated = false;
                continue;
            }
            if candidate.ends_with(b"/cwd")
                && let Some(cwd) = proc_pid(&candidate).and_then(|n| fs.virtual_cwd(n))
            {
                result = cwd;
                seated = false;
                continue;
            }
            if fs.proc_is_host {
                // `fd/N` and `map_files/X` name open objects, not paths: a memfd,
                // a pipe, a deleted file.  Opening one re-opens the object, which
                // only the kernel can do, so a final one is left to the kernel
                // (the link itself is not under the guest's control).  Followed
                // by more components it must be a directory, whose path the link
                // names; that is re-entered as a guest path.
                if is_final && is_proc_fd_link(&candidate) {
                    return Ok(textual(fs, candidate));
                }
                // The link content is a host path (or "pipe:[n]"-style for non-files).
                let host = fs.substitute_guest_to_host(&candidate);
                match read_link(&host) {
                    Ok(target) if target.first() == Some(&b'/') => {
                        let target = super::translate::strip_deleted(target);
                        result = fs.substitute_host_to_guest(&target).unwrap_or(target);
                        if candidate.ends_with(b"/root") {
                            result = b"/".to_vec();
                        }
                        seated = false;
                        continue;
                    }
                    Ok(_) if is_proc_fd_link(&candidate) => return Err(libc::ENOTDIR),
                    Ok(_) => return Ok(textual(fs, append_rest(candidate, queue.make_contiguous()))),
                    Err(e) => return Err(e),
                }
            }
        }
        // A mount point of the view: its own pinned host side, whatever lies
        // under the name in the directory above.
        if let Some(pin) = fs.mount_pin(&candidate) {
            if is_final {
                return Ok(match pin {
                    Some(fd) => object(fs, candidate, fd),
                    None => textual(fs, candidate),
                });
            }
            result = candidate;
            cur = pin;
            seated = true;
            continue;
        }
        if !is_final && let Some(fd) = fs.cache_get(&candidate) {
            result = candidate;
            cur = Some(fd);
            seated = true;
            continue;
        }
        if !seated {
            cur = match open_dir(fs, &result) {
                Err(libc::ENOENT) if fs.binding_below(&result) => None,
                Err(libc::ENOENT) if missing == Missing::Lexical => {
                    return Ok(textual(fs, append_rest(candidate, queue.make_contiguous())));
                }
                r => r?,
            };
            seated = true;
        }
        let Some(dir) = cur.clone() else {
            // Textual: the mount point this lies under has no host side yet.
            let host = fs.substitute_guest_to_host(&candidate);
            let mode = match lstat_mode(&host) {
                Ok(m) => m,
                Err(_) if !is_final && fs.binding_below(&candidate) => {
                    result = candidate;
                    continue;
                }
                Err(_) if is_final => return Ok(textual(fs, candidate)),
                Err(_) => return Ok(textual(fs, append_rest(candidate, queue.make_contiguous()))),
            };
            let is_link = mode & libc::S_IFMT == libc::S_IFLNK;
            if is_link && (!is_final || deref_final) {
                let target = read_link(&host)?;
                follow(&mut hops, &mut result, &mut seated, &mut queue, target)?;
                continue;
            }
            if !is_final && mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(libc::ENOTDIR);
            }
            result = candidate;
            continue;
        };
        if is_final {
            if !deref_final {
                return Ok(child(fs, candidate, dir, comp));
            }
            match fstatat_mode(&dir, &comp) {
                Ok(mode) if mode & libc::S_IFMT == libc::S_IFLNK => {
                    // The link may have been swapped for something else since the
                    // stat; then this walk is stale.
                    let target = readlinkat(&dir, &comp).map_err(|_| RETRY)?;
                    follow(&mut hops, &mut result, &mut seated, &mut queue, target)?;
                    continue;
                }
                // Missing or unreadable: the kernel reports it through the parent.
                _ => return Ok(child(fs, candidate, dir, comp)),
            }
        }
        match open_dir_component(&dir, &comp) {
            Ok(fd) => {
                let fd = Arc::new(fd);
                fs.cache_put(&candidate, fd.clone());
                result = candidate;
                cur = Some(fd);
            }
            Err(libc::ELOOP) => {
                let target = readlinkat(&dir, &comp).map_err(|_| RETRY)?;
                follow(&mut hops, &mut result, &mut seated, &mut queue, target)?;
            }
            // A directory of the view only for the binding below it: on from
            // its name, to that binding's pin.
            Err(libc::ENOENT) if fs.binding_below(&candidate) => {
                result = candidate;
                cur = None;
            }
            Err(libc::ENOENT) if missing == Missing::Lexical => {
                return Ok(textual(fs, append_rest(candidate, queue.make_contiguous())));
            }
            // Missing or not a directory, as the kernel would say of the component.
            Err(e) => return Err(e),
        }
    }
    // The path names the directory walked to itself: `/`, a mount point, or
    // a directory reached through `..` or a `/proc` rewrite.
    if let Some(pin) = fs.mount_pin(&result) {
        return Ok(match pin {
            Some(fd) => object(fs, result, fd),
            None => textual(fs, result),
        });
    }
    let mut parent = result.clone();
    pop_component(&mut parent);
    let name = result.rsplit(|&c| c == b'/').next().unwrap_or_default().to_vec();
    match open_dir(fs, &parent)? {
        Some(dir) => Ok(child(fs, result, dir, name)),
        None => Ok(textual(fs, result)),
    }
}

/// Re-enters a symlink target into the walk, interpreted in the guest
/// namespace relative to the canonical directory that holds the link.
fn follow(
    hops: &mut u32,
    result: &mut Vec<u8>,
    seated: &mut bool,
    queue: &mut VecDeque<Vec<u8>>,
    target: Vec<u8>,
) -> Result<()> {
    *hops += 1;
    if *hops > MAX_SYMLINKS {
        return Err(libc::ELOOP);
    }
    if target.first() == Some(&b'/') {
        *result = b"/".to_vec();
        *seated = false;
    }
    for comp in components(&target).into_iter().rev() {
        queue.push_front(comp);
    }
    Ok(())
}

/// Opens the canonical guest directory `guest` from the mount point it lies under.
///
/// Each component below the mount point is a directory the walk already
/// resolved, so one that is a symlink now was swapped in since: that is a
/// [`RETRY`], as the walk must resolve it in the guest namespace.
///
/// # Returns
/// `None` when the mount point has no host side yet (textual lookups).
fn open_dir(fs: &Fs, guest: &[u8]) -> Result<Option<Arc<OwnedFd>>> {
    if let Some(fd) = fs.cache_get(guest) {
        return Ok(Some(fd));
    }
    let (pin, rest) = fs.pin_for_guest(guest);
    let Some(mut dir) = pin else {
        return Ok(None);
    };
    let mut prefix = guest[..guest.len() - rest.len()].to_vec();
    for comp in rest.split(|&c| c == b'/').filter(|c| !c.is_empty()) {
        prefix = join(&prefix, comp);
        if let Some(fd) = fs.cache_get(&prefix) {
            dir = fd;
            continue;
        }
        dir = Arc::new(open_dir_component(&dir, comp).map_err(|e| if e == libc::ELOOP { RETRY } else { e })?);
        fs.cache_put(&prefix, dir.clone());
    }
    Ok(Some(dir))
}

/// Opens the directory `comp` inside `dir` as an `O_PATH` descriptor.
///
/// # Errors
/// `ELOOP` when it is a symlink, `ENOTDIR` when it is anything else,
/// `ENOENT` when it is missing, as `openat2` reports them.
fn open_dir_component(dir: &OwnedFd, comp: &[u8]) -> Result<OwnedFd> {
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS,
    };
    let c = cstr(comp)?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(errno());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Opens `name` inside `dir` as an `O_PATH|O_CLOEXEC` descriptor with extra `flags`.
fn open_at(dir: &OwnedFd, name: &[u8], flags: i32) -> Result<OwnedFd> {
    let c = cstr(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | flags,
        )
    };
    if fd < 0 {
        return Err(errno());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A [`Resolved`] for `name` inside the pinned directory `parent`.
fn child(fs: &Fs, guest: Vec<u8>, parent: Arc<OwnedFd>, name: Vec<u8>) -> Resolved {
    Resolved {
        host: fs.substitute_guest_to_host(&guest),
        guest,
        at: At::Child { parent, name },
    }
}

/// A [`Resolved`] for a pinned mount point itself.
fn object(fs: &Fs, guest: Vec<u8>, fd: Arc<OwnedFd>) -> Resolved {
    Resolved {
        host: fs.substitute_guest_to_host(&guest),
        guest,
        at: At::Object(fd),
    }
}

/// A [`Resolved`] the kernel resolves from the textual host path.
fn textual(fs: &Fs, guest: Vec<u8>) -> Resolved {
    Resolved {
        host: fs.substitute_guest_to_host(&guest),
        guest,
        at: At::Path,
    }
}

/// Whether a canonical guest path names a `/proc/<pid>[/task/<tid>]/{exe,cwd,root,fd/N,map_files/X}` link.
///
/// # Arguments
/// * `path` - Canonical absolute guest path.
fn is_proc_magic_link(path: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(b"/proc/") else {
        return false;
    };
    let mut parts = rest.split(|&c| c == b'/');
    let Some(pid) = parts.next() else { return false };
    if pid.is_empty() || !pid.iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let mut parts: Vec<&[u8]> = parts.collect();
    if parts.len() >= 2 && parts[0] == b"task" && parts[1].iter().all(|c| c.is_ascii_digit()) {
        parts.drain(0..2);
    }
    match parts.as_slice() {
        [b"exe"] | [b"cwd"] | [b"root"] => true,
        [b"fd", n] => !n.is_empty() && n.iter().all(|c| c.is_ascii_digit()),
        [b"map_files", _] => true,
        _ => false,
    }
}

/// Whether a canonical guest path is a `/proc/<pid>[/task/<tid>]/fd/N` or `map_files/X` link.
fn is_proc_fd_link(path: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(b"/proc/") else {
        return false;
    };
    let mut parts: Vec<&[u8]> = rest.split(|&c| c == b'/').collect();
    if parts.len() >= 3 && parts[1] == b"task" {
        parts.drain(0..2);
    } else if !parts.is_empty() {
        parts.remove(0);
    }
    matches!(parts.as_slice(), [b"fd", _] | [b"map_files", _])
}

/// The `<n>` of a `/proc/<n>/...` path, or of `/proc/<n>/task/<t>/...` (then `t`).
fn proc_pid(path: &[u8]) -> Option<i32> {
    let rest = path.strip_prefix(b"/proc/")?;
    let parts: Vec<&[u8]> = rest.split(|&c| c == b'/').collect();
    let pick = if parts.len() >= 3 && parts[1] == b"task" {
        parts[2]
    } else {
        parts[0]
    };
    std::str::from_utf8(pick).ok()?.parse().ok()
}

/// The non-empty components of a path, in order.
fn components(path: &[u8]) -> VecDeque<Vec<u8>> {
    path.split(|&c| c == b'/')
        .filter(|c| !c.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

/// Appends the remaining components to a path without touching the host.
fn append_rest(mut path: Vec<u8>, rest: &[Vec<u8>]) -> Vec<u8> {
    for comp in rest {
        match comp.as_slice() {
            b"." => {}
            b".." => pop_component(&mut path),
            c => path = join(&path, c),
        }
    }
    path
}

/// Joins a canonical directory and one component.
fn join(dir: &[u8], comp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(dir.len() + comp.len() + 1);
    out.extend_from_slice(dir);
    if dir != b"/" {
        out.push(b'/');
    }
    out.extend_from_slice(comp);
    out
}

/// Removes the last component of a canonical path; `/` stays `/`.
fn pop_component(path: &mut Vec<u8>) {
    if let Some(i) = path.iter().rposition(|&c| c == b'/') {
        path.truncate(i.max(1));
    }
}

/// Builds a C string from path bytes.
fn cstr(path: &[u8]) -> Result<CString> {
    CString::new(path.to_vec()).map_err(|_| libc::EINVAL)
}

/// `st_mode` of a host path without following a final symlink.
fn lstat_mode(host: &[u8]) -> Result<u32> {
    let c = cstr(host)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } < 0 {
        return Err(errno());
    }
    Ok(st.st_mode)
}

/// `st_mode` of `name` inside `dir` without following a final symlink.
fn fstatat_mode(dir: &OwnedFd, name: &[u8]) -> Result<u32> {
    let c = cstr(name)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
        return Err(errno());
    }
    Ok(st.st_mode)
}

/// `st_mode` of an open descriptor.
fn fstat_mode(fd: &OwnedFd) -> Result<u32> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err(errno());
    }
    Ok(st.st_mode)
}

/// `readlinkat(2)` of `name` inside `dir`, as bytes.
pub fn readlinkat(dir: &OwnedFd, name: &[u8]) -> Result<Vec<u8>> {
    let c = cstr(name)?;
    let mut buf = vec![0u8; PATH_MAX];
    let n = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if n < 0 {
        return Err(errno());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// `readlink(2)` on a host path, as bytes.
fn read_link(host: &[u8]) -> Result<Vec<u8>> {
    super::translate::read_link(host)
}

/// Removes `.` components, resolves `..` lexically and collapses slashes.
///
/// # Arguments
/// * `path` - Absolute path.
///
/// # Returns
/// The cleaned absolute path.
#[allow(dead_code)]
pub fn lexical_clean(path: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for comp in path.split(|&c| c == b'/') {
        match comp {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let mut out = Vec::with_capacity(path.len() + 1);
    for p in &parts {
        out.push(b'/');
        out.extend_from_slice(p);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Binding, Config};
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn me() -> u32 {
        std::process::id()
    }

    /// Builds a throwaway rootfs with a few symlinks and one binding.
    fn fixture() -> (Fs, PathBuf, PathBuf) {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("proot-next-canon-{}-{}", std::process::id(), n));
        let root = base.join("root");
        let bind = base.join("bind");
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(&bind).unwrap();
        std::fs::write(root.join("usr/bin/sh"), b"#!").unwrap();
        std::fs::write(root.join("etc/passwd"), b"root").unwrap();
        std::fs::write(bind.join("file"), b"bound").unwrap();
        symlink("usr/bin", root.join("bin")).unwrap(); // relative
        symlink("/usr/bin", root.join("abs")).unwrap(); // absolute, must stay in the guest
        symlink("loop", root.join("loop")).unwrap(); // self loop
        symlink("../../..", root.join("escape")).unwrap(); // clamps at guest /
        symlink("/mnt/file", root.join("tobind")).unwrap(); // into a binding
        symlink("/etc/passwd", root.join("usr/bin/pw")).unwrap();
        let mut c = Config {
            root: root.as_os_str().as_encoded_bytes().to_vec(),
            ..Config::default()
        };
        c.bindings.push(Binding {
            host: bind.as_os_str().as_encoded_bytes().to_vec(),
            guest: b"/mnt".to_vec(),
            read_only: false,
        });
        (Fs::new(&c), root, bind)
    }

    /// The inode a resolved path's parent and name lead to, read through the pin.
    fn pinned_inode(r: &Resolved) -> u64 {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let (dfd, c, nofollow) = r.at(false).unwrap();
        let flags = if nofollow { libc::AT_SYMLINK_NOFOLLOW } else { 0 };
        assert_eq!(unsafe { libc::fstatat(dfd, c.as_ptr(), &mut st, flags) }, 0);
        st.st_ino
    }

    fn inode(p: &std::path::Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(p).unwrap().ino()
    }

    #[test]
    fn follows_links_inside_the_guest() {
        let (fs, _root, _bind) = fixture();
        assert_eq!(
            canonicalize(&fs, me(), b"/bin/sh", true).unwrap(),
            b"/usr/bin/sh".to_vec()
        );
        assert_eq!(
            canonicalize(&fs, me(), b"/abs/sh", true).unwrap(),
            b"/usr/bin/sh".to_vec()
        );
        assert_eq!(canonicalize(&fs, me(), b"/abs", false).unwrap(), b"/abs".to_vec());
        assert_eq!(
            canonicalize(&fs, me(), b"/abs", true).unwrap(),
            b"/usr/bin".to_vec()
        );
        assert_eq!(
            canonicalize(&fs, me(), b"//usr/./bin/../bin/pw", true).unwrap(),
            b"/etc/passwd".to_vec()
        );
        assert_eq!(
            canonicalize(&fs, me(), b"/usr/bin/pw", false).unwrap(),
            b"/usr/bin/pw".to_vec()
        );
    }

    #[test]
    fn cannot_escape_and_detects_loops() {
        let (fs, _root, _bind) = fixture();
        assert_eq!(
            canonicalize(&fs, me(), b"/escape/etc/passwd", true).unwrap(),
            b"/etc/passwd".to_vec()
        );
        assert_eq!(
            canonicalize(&fs, me(), b"/../../etc", true).unwrap(),
            b"/etc".to_vec()
        );
        assert_eq!(canonicalize(&fs, me(), b"/loop", true), Err(libc::ELOOP));
        assert_eq!(canonicalize(&fs, me(), b"/loop/x", true), Err(libc::ELOOP));
        assert_eq!(
            canonicalize(&fs, me(), b"/etc/passwd/x", true),
            Err(libc::ENOTDIR)
        );
        assert_eq!(canonicalize(&fs, me(), b"relative", true), Err(libc::EINVAL));
    }

    #[test]
    fn missing_components_get_the_kernels_errors() {
        let (fs, _root, _bind) = fixture();
        // A missing final component is the parent's business.
        assert_eq!(
            canonicalize(&fs, me(), b"/etc/new", true).unwrap(),
            b"/etc/new".to_vec()
        );
        let r = resolve(&fs, me(), b"/etc/new", false).unwrap();
        assert!(matches!(&r.at, At::Child { name, .. } if name == b"new"));
        // A missing intermediate one is ENOENT, whatever follows it, for a
        // lookup; the binding table keeps the rest lexically.
        assert_eq!(
            resolve(&fs, me(), b"/nope/a/../b/./c", true).err(),
            Some(libc::ENOENT)
        );
        assert_eq!(resolve(&fs, me(), b"/nope/..", true).err(), Some(libc::ENOENT));
        assert_eq!(
            canonicalize(&fs, me(), b"/nope/a/../b/./c", true).unwrap(),
            b"/nope/b/c".to_vec()
        );
    }

    #[test]
    fn links_into_bindings_resolve_on_the_binding_host() {
        let (fs, _root, bind) = fixture();
        assert_eq!(
            canonicalize(&fs, me(), b"/tobind", true).unwrap(),
            b"/mnt/file".to_vec()
        );
        let r = resolve(&fs, me(), b"/tobind", true).unwrap();
        assert_eq!(r.host, bind.join("file").as_os_str().as_encoded_bytes().to_vec());
        assert_eq!(pinned_inode(&r), inode(&bind.join("file")));
        assert_eq!(
            canonicalize(&fs, me(), b"/mnt/../etc", true).unwrap(),
            b"/etc".to_vec()
        );
    }

    #[test]
    fn roots_and_mount_points_are_the_pinned_objects() {
        let (fs, root, bind) = fixture();
        let r = resolve(&fs, me(), b"/", true).unwrap();
        assert!(r.is_mount_point());
        assert_eq!(pinned_inode(&r), inode(&root));
        let r = resolve(&fs, me(), b"/mnt", false).unwrap();
        assert!(r.is_mount_point());
        assert_eq!(pinned_inode(&r), inode(&bind));
        let r = resolve(&fs, me(), b"/usr/bin/..", true).unwrap();
        assert!(matches!(&r.at, At::Child { name, .. } if name == b"usr"));
        assert_eq!(pinned_inode(&r), inode(&root.join("usr")));
    }

    #[test]
    fn directory_cache_is_used_and_flushed() {
        let (fs, root, _bind) = fixture();
        canonicalize(&fs, me(), b"/usr/bin/sh", true).unwrap();
        assert!(fs.cache_has_dir(b"/usr/bin") || std::env::var_os("PROOT_NO_PATH_CACHE").is_some());
        // Replace the directory by a symlink behind the cache's back, then flush.
        std::fs::rename(root.join("usr/bin"), root.join("usr/realbin")).unwrap();
        symlink("realbin", root.join("usr/bin")).unwrap();
        fs.flush_cache();
        assert!(!fs.cache_has_dir(b"/usr/bin"));
        assert_eq!(
            canonicalize(&fs, me(), b"/usr/bin/sh", true).unwrap(),
            b"/usr/realbin/sh".to_vec()
        );
    }

    #[test]
    fn a_swapped_in_symlink_is_seen_not_followed() {
        let (fs, root, _bind) = fixture();
        let outside = root.parent().unwrap().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("sh"), b"host").unwrap();
        // The walk pins usr/bin; the guest then renames it away and plants a
        // link to a host directory in its place.
        let r = resolve(&fs, me(), b"/usr/bin/sh", true).unwrap();
        std::fs::rename(root.join("usr/bin"), root.join("usr/realbin")).unwrap();
        symlink(&outside, root.join("usr/bin")).unwrap();
        assert_eq!(pinned_inode(&r), inode(&root.join("usr/realbin/sh")));
        let (dfd, c, nofollow) = r.at(false).unwrap();
        assert!(nofollow);
        let fd = unsafe { libc::openat(dfd, c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW) };
        assert!(fd >= 0);
        let mut buf = [0u8; 2];
        assert_eq!(unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, 2) }, 2);
        assert_eq!(&buf, b"#!");
        unsafe { libc::close(fd) };
        // Walked afresh, the link is interpreted in the guest, where its target is missing.
        fs.flush_cache();
        assert_eq!(resolve(&fs, me(), b"/usr/bin/sh", true).err(), Some(libc::ENOENT));
    }

    #[test]
    fn a_binding_below_a_missing_directory_is_reached() {
        // A rootfs glue could not make the placeholders in has nothing at /opt.
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("proot-next-canon-below-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(base.join("root")).unwrap();
        std::fs::write(base.join("file"), b"bound").unwrap();
        let mut c = Config {
            root: base.join("root").as_os_str().as_encoded_bytes().to_vec(),
            ..Config::default()
        };
        c.bindings.push(Binding {
            host: base.join("file").as_os_str().as_encoded_bytes().to_vec(),
            guest: b"/opt/x/y/file".to_vec(),
            read_only: false,
        });
        let fs = Fs::new(&c);
        for path in [&b"/opt/x/y/file"[..], b"/opt/x/../x/y/./file"] {
            let r = resolve(&fs, me(), path, true).unwrap();
            assert_eq!(r.guest, b"/opt/x/y/file".to_vec());
            assert_eq!(pinned_inode(&r), inode(&base.join("file")));
        }
        assert_eq!(resolve(&fs, me(), b"/nope/x", true).err(), Some(libc::ENOENT));
    }
}
