//! Component-wise canonicalization of guest paths (port of PRoot's `canon.c`).
//!
//! Every component of a guest path is checked on the host side of its
//! binding: a symlink found there is read and re-interpreted *in the guest
//! namespace*, so a link to `/usr/lib` inside the rootfs lands in the
//! rootfs's `/usr/lib`, never the host's.  Directories already resolved are
//! remembered in [`Fs`]'s cache to skip the `lstat` next time.

use super::Fs;
use crate::sys::{PATH_MAX, Result, errno};
use std::ffi::CString;

/// Symlink hops allowed before giving up with `ELOOP` (Linux's `MAXSYMLINKS`).
const MAX_SYMLINKS: u32 = 40;

/// Canonicalizes an absolute guest path inside the guest namespace.
///
/// Walks `guest` one component at a time.  For each intermediate component
/// the host counterpart (via [`Fs::substitute_guest_to_host`]) is `lstat`ed;
/// a symlink is read and its target re-entered into the walk as a guest path
/// (absolute targets restart from guest `/`).  The final component is
/// dereferenced only when `deref_final` is true.  Components that do not
/// exist stop the walk and the remainder is appended verbatim so the kernel
/// produces the real error later.
///
/// # Arguments
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
/// # Returns
/// The canonical absolute guest path (no `.`/`..`/symlinks in the walked part).
///
/// # Errors
/// `ELOOP` after too many symlinks, `ENAMETOOLONG` for an overlong result,
/// `ENOTDIR` when an intermediate component is a regular file, `EINVAL` for a
/// relative input.
pub fn canonicalize(fs: &Fs, pid: u32, guest: &[u8], deref_final: bool) -> Result<Vec<u8>> {
    if guest.first() != Some(&b'/') {
        return Err(libc::EINVAL);
    }
    if guest.len() >= PATH_MAX {
        return Err(libc::ENAMETOOLONG);
    }
    let mut hops = 0u32;
    let result = walk(fs, pid, b"/", guest, deref_final, &mut hops)?;
    if result.len() >= PATH_MAX {
        return Err(libc::ENAMETOOLONG);
    }
    Ok(result)
}

/// Resolves `path` (absolute or relative) against the canonical directory `base`.
///
/// # Arguments
/// * `fs` - Guest filesystem view.
/// * `pid` - Tracee thread id, for `/proc/self`.
/// * `base` - Canonical guest directory a relative `path` starts from.
/// * `path` - Path to walk.
/// * `deref_final` - Follow a symlink in the last component.
/// * `hops` - Symlinks followed so far, shared across recursion.
fn walk(fs: &Fs, pid: u32, base: &[u8], path: &[u8], deref_final: bool, hops: &mut u32) -> Result<Vec<u8>> {
    let mut result: Vec<u8> = if path.first() == Some(&b'/') {
        b"/".to_vec()
    } else {
        base.to_vec()
    };
    let comps: Vec<&[u8]> = path.split(|&c| c == b'/').filter(|c| !c.is_empty()).collect();
    let last = comps.len().saturating_sub(1);
    for (idx, comp) in comps.iter().enumerate() {
        let is_final = idx == last;
        match *comp {
            b"." => continue,
            b".." => {
                pop_component(&mut result);
                continue;
            }
            _ => {}
        }
        let candidate = join(&result, comp);
        // The tracee's own /proc entries, never the supervisor's.
        if candidate == b"/proc/self" {
            result = format!("/proc/{pid}").into_bytes();
            continue;
        }
        if candidate == b"/proc/thread-self" {
            result = format!("/proc/{pid}/task/{pid}").into_bytes();
            continue;
        }
        if (!is_final || deref_final) && is_proc_magic_link(&candidate) {
            // `fd/N` and `map_files/X` name open objects, not paths: a memfd, a
            // pipe, a deleted file.  Opening them through the link re-opens the
            // object, which only the kernel can do, so the walk stops here and
            // the kernel resolves the rest on the host side (/proc is identity).
            if is_proc_fd_link(&candidate) {
                return Ok(append_rest(candidate, &comps[idx + 1..]));
            }
            // `/proc/<n>/exe` is answered from our own record: the kernel's link
            // names the dynamic loader after an exec rewrite.
            if candidate.ends_with(b"/exe")
                && let Some(exe) = proc_pid(&candidate).and_then(|n| fs.exe_of(n))
            {
                result = exe;
                continue;
            }
            // The link content is a host path (or "pipe:[n]"-style for non-files).
            let host = fs.substitute_guest_to_host(&candidate);
            match read_link(&host) {
                Ok(target) if target.first() == Some(&b'/') => {
                    result = fs.substitute_host_to_guest(&target).unwrap_or(target);
                    if candidate.ends_with(b"/root") {
                        result = b"/".to_vec();
                    }
                    continue;
                }
                _ => return Ok(append_rest(candidate, &comps[idx + 1..])),
            }
        }
        if !is_final && fs.cache_has_dir(&candidate) {
            result = candidate;
            continue;
        }
        let host = fs.substitute_guest_to_host(&candidate);
        let mode = match lstat_mode(&host) {
            Ok(m) => m,
            Err(_) if is_final => {
                // Missing or unreadable final component: the kernel reports it.
                return Ok(candidate);
            }
            Err(_) => {
                // Missing intermediate: stop here, keep the rest lexically.
                return Ok(append_rest(candidate, &comps[idx + 1..]));
            }
        };
        let is_link = mode & libc::S_IFMT == libc::S_IFLNK;
        let is_dir = mode & libc::S_IFMT == libc::S_IFDIR;
        if is_link && (!is_final || deref_final) {
            *hops += 1;
            if *hops > MAX_SYMLINKS {
                return Err(libc::ELOOP);
            }
            let target = read_link(&host)?;
            // The link is interpreted in the guest namespace, relative to the
            // canonical directory that holds it.
            result = walk(fs, pid, &result, &target, true, hops)?;
            if result.len() >= PATH_MAX {
                return Err(libc::ENAMETOOLONG);
            }
            continue;
        }
        if !is_final && !is_dir {
            return Err(libc::ENOTDIR);
        }
        if !is_final {
            fs.cache_add_dir(&candidate);
        }
        result = candidate;
    }
    Ok(result)
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

/// Appends the remaining components to a path without touching the host.
fn append_rest(mut path: Vec<u8>, rest: &[&[u8]]) -> Vec<u8> {
    for comp in rest {
        match *comp {
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

/// `st_mode` of a host path without following a final symlink.
fn lstat_mode(host: &[u8]) -> Result<u32> {
    let c = CString::new(host.to_vec()).map_err(|_| libc::EINVAL)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } < 0 {
        return Err(errno());
    }
    Ok(st.st_mode)
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
    fn missing_components_are_kept_for_the_kernel() {
        let (fs, _root, _bind) = fixture();
        assert_eq!(
            canonicalize(&fs, me(), b"/nope/a/../b/./c", true).unwrap(),
            b"/nope/b/c".to_vec()
        );
        assert_eq!(
            canonicalize(&fs, me(), b"/etc/new", true).unwrap(),
            b"/etc/new".to_vec()
        );
    }

    #[test]
    fn links_into_bindings_resolve_on_the_binding_host() {
        let (fs, _root, bind) = fixture();
        assert_eq!(
            canonicalize(&fs, me(), b"/tobind", true).unwrap(),
            b"/mnt/file".to_vec()
        );
        let host = fs.substitute_guest_to_host(&canonicalize(&fs, me(), b"/tobind", true).unwrap());
        assert_eq!(host, bind.join("file").as_os_str().as_encoded_bytes().to_vec());
        assert_eq!(
            canonicalize(&fs, me(), b"/mnt/../etc", true).unwrap(),
            b"/etc".to_vec()
        );
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
}
