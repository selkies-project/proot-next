//! Binding tables: longest-prefix substitution between guest and host paths,
//! and the descriptors the path walk starts from.

use crate::config::{Binding, Config, trim_slashes};
use crate::procs::ProcTable;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// A cache entry's key: the view's id and the canonical guest directory.
type CacheKey = (u64, Vec<u8>);

/// Directory descriptors kept in the cache before it is cleared wholesale.
///
/// Each entry holds an open descriptor, so the cap bounds the supervisor's
/// descriptor table rather than its memory.
const DIR_CACHE_MAX: usize = 512;

/// `O_PATH` descriptors of canonical guest directories already walked,
/// shared by every view of one supervisor.
///
/// Lets the walk skip the `openat` of an intermediate component, and pins
/// the directory the component named when it was walked: a later lookup
/// through the entry lands in that directory whatever the name now points
/// to.  Entries are keyed by the view they were resolved in, since the same
/// guest path names different host directories in different views, and the
/// whole cache is flushed by [`DirCache::flush`] after any syscall that may
/// replace a directory, whichever view made it: the host directories are
/// shared.
#[derive(Debug)]
pub struct DirCache {
    entries: RwLock<HashMap<CacheKey, Arc<OwnedFd>>>,
    /// False when `PROOT_NO_PATH_CACHE` is set.
    enabled: bool,
}

impl DirCache {
    /// Creates an empty cache, disabled when `PROOT_NO_PATH_CACHE` is set.
    pub fn new() -> DirCache {
        DirCache {
            entries: RwLock::new(HashMap::new()),
            enabled: std::env::var_os("PROOT_NO_PATH_CACHE").is_none(),
        }
    }

    /// Forgets every cached directory of every view.
    ///
    /// Call after `mkdir`, `rmdir`, `rename`, `unlink`, `symlink`, `link`,
    /// `mknod` or any other syscall that can turn a directory into something
    /// else (or the reverse); changes made from outside PRoot are not seen
    /// until then, and a lookup through a stale entry stays in the directory
    /// it pinned.
    pub fn flush(&self) {
        if let Ok(mut c) = self.entries.write() {
            c.clear();
        }
    }
}

/// The host side of the root or of a binding, held open once.
///
/// Every walk starts from one of these descriptors rather than from the
/// textual host prefix, so a rename of the prefix's parents on the host (the
/// rootfs under a bound `$HOME`, say) cannot redirect it.  A host that does
/// not exist yet is opened on the first lookup that finds it there.
#[derive(Debug)]
pub struct Pin {
    host: Vec<u8>,
    fd: OnceLock<Arc<OwnedFd>>,
}

impl Pin {
    fn new(host: Vec<u8>) -> Pin {
        Pin {
            host,
            fd: OnceLock::new(),
        }
    }

    /// The descriptor, opening the host side on first use; `None` while it
    /// does not exist (a symlink is never a host side: `resolve_host` ran).
    pub fn get(&self) -> Option<Arc<OwnedFd>> {
        if let Some(fd) = self.fd.get() {
            return Some(fd.clone());
        }
        let fd = open_path(&self.host, libc::O_NOFOLLOW)?;
        let _ = self.fd.set(Arc::new(fd));
        self.fd.get().cloned()
    }
}

/// Opens a host path as an `O_PATH|O_CLOEXEC` descriptor with extra `flags`.
fn open_path(host: &[u8], flags: i32) -> Option<OwnedFd> {
    let c = CString::new(host.to_vec()).ok()?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC | flags) };
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

impl Default for DirCache {
    fn default() -> Self {
        DirCache::new()
    }
}

/// Source of view identifiers, unique for the life of the supervisor.
static NEXT_VIEW_ID: AtomicU64 = AtomicU64::new(1);

/// The guest filesystem view: a root directory plus bind mounts.
#[derive(Debug)]
pub struct Fs {
    /// Host directory serving as guest `/`, no trailing slash.
    pub root: Vec<u8>,
    /// Bindings sorted so that longer guest prefixes come first.
    pub bindings: Vec<Binding>,
    /// True when root is `/` and there are no bindings: translation is a no-op.
    pub identity: bool,
    /// True when guest `/proc` is the host's: its magic links mean what they
    /// mean on the host.
    pub proc_is_host: bool,
    /// The root's host side, held open.
    root_pin: Pin,
    /// Each binding's host side, held open; same order as `bindings`.
    pins: Vec<Pin>,
    /// Identifies this view's entries in the shared directory cache.
    id: u64,
    /// Directory cache shared with every other view of the supervisor.
    cache: Arc<DirCache>,
    /// Per-process records: the program each process runs, since the kernel's
    /// own `/proc/<pid>/exe` names the dynamic loader after an exec rewrite,
    /// and without ptrace the working directory too.
    pub procs: Arc<ProcTable>,
}

impl Fs {
    /// Builds the view from the parsed configuration with its own process
    /// table and directory cache.
    ///
    /// # Arguments
    /// * `config` - Parsed command line.  Bindings are normalized and sorted.
    pub fn new(config: &Config) -> Fs {
        Fs::with_procs(config, Arc::new(ProcTable::new(false)))
    }

    /// Builds the view from the parsed configuration over a shared process
    /// table, with a directory cache of its own.
    ///
    /// # Arguments
    /// * `config` - Parsed command line.  Bindings are normalized and sorted.
    /// * `procs` - Process table shared with the supervisor.
    pub fn with_procs(config: &Config, procs: Arc<ProcTable>) -> Fs {
        Fs::with_cache(config, procs, Arc::new(DirCache::new()))
    }

    /// Builds the view from the parsed configuration over a shared process
    /// table and a shared directory cache.
    ///
    /// The root is made absolute, since it is used from the alias directory
    /// as well (loader aliases, the exec shim's records).
    ///
    /// # Arguments
    /// * `config` - Parsed command line.  Bindings are normalized and sorted.
    /// * `procs` - Process table shared with the supervisor.
    /// * `cache` - Directory cache shared with the supervisor's other views.
    pub fn with_cache(config: &Config, procs: Arc<ProcTable>, cache: Arc<DirCache>) -> Fs {
        let root = resolve_host(&config.root);
        let mut bindings: Vec<Binding> = config
            .bindings
            .iter()
            .map(|b| Binding {
                host: resolve_host(&b.host),
                guest: trim_slashes(b.guest.clone()),
                read_only: b.read_only,
            })
            .collect();
        // Stable sort: longer guest prefix first, later command-line entries first on ties.
        bindings.reverse();
        bindings.sort_by_key(|b| std::cmp::Reverse(b.guest.len()));
        let identity = root == b"/" && bindings.iter().all(|b| b.host == b.guest);
        let pins = bindings.iter().map(|b| Pin::new(b.host.clone())).collect();
        let mut fs = Fs {
            root_pin: Pin::new(root.clone()),
            root,
            bindings,
            identity,
            proc_is_host: false,
            pins,
            id: NEXT_VIEW_ID.fetch_add(1, Ordering::Relaxed),
            cache,
            procs,
        };
        fs.canonicalize_bindings();
        fs.proc_is_host = fs.substitute_guest_to_host(b"/proc") == b"/proc";
        fs
    }

    /// Rewrites every binding's guest path to the canonical form lookups use.
    ///
    /// A lookup is canonicalized through the view before the binding table is
    /// consulted, so a guest path given through a symlink of the rootfs, such
    /// as `/lib/ld-linux.so.2` on a merged-usr host where `/lib` points to
    /// `usr/lib`, would never match unless the table holds the
    /// `/usr/lib/ld-linux.so.2` the lookup resolves to.  The final component
    /// is kept as given, and a path whose intermediate components are missing
    /// stays lexical, as the walk stops there.  The table is re-sorted and the
    /// identity flag recomputed when anything changed.
    fn canonicalize_bindings(&mut self) {
        let canonical: Vec<Vec<u8>> = self
            .bindings
            .iter()
            .map(|b| match super::canon::canonicalize(self, 0, &b.guest, false) {
                Ok(c) => trim_slashes(c),
                Err(_) => b.guest.clone(),
            })
            .collect();
        if self.bindings.iter().zip(&canonical).all(|(b, c)| b.guest == *c) {
            return;
        }
        for (b, c) in self.bindings.iter_mut().zip(canonical) {
            b.guest = c;
        }
        let mut pairs: Vec<(Binding, Pin)> = std::mem::take(&mut self.bindings)
            .into_iter()
            .zip(std::mem::take(&mut self.pins))
            .collect();
        pairs.sort_by_key(|(b, _)| std::cmp::Reverse(b.guest.len()));
        (self.bindings, self.pins) = pairs.into_iter().unzip();
        self.identity = self.root == b"/" && self.bindings.iter().all(|b| b.host == b.guest);
    }

    /// The pinned directory of a canonical guest directory the cache has seen in this view.
    ///
    /// # Arguments
    /// * `guest` - Canonical absolute guest path.
    pub fn cache_get(&self, guest: &[u8]) -> Option<Arc<OwnedFd>> {
        if !self.cache.enabled {
            return None;
        }
        self.cache
            .entries
            .read()
            .ok()
            .and_then(|c| c.get(&(self.id, guest.to_vec())).cloned())
    }

    /// Records the directory `guest` resolved to in this view.
    ///
    /// # Arguments
    /// * `guest` - Canonical absolute guest path.
    /// * `fd` - Its `O_PATH` descriptor.
    pub fn cache_put(&self, guest: &[u8], fd: Arc<OwnedFd>) {
        if !self.cache.enabled {
            return;
        }
        if let Ok(mut c) = self.cache.entries.write() {
            if c.len() >= DIR_CACHE_MAX {
                c.clear();
            }
            c.insert((self.id, guest.to_vec()), fd);
        }
    }

    /// Whether `guest` is a canonical directory the cache has seen in this view.
    #[cfg(test)]
    pub fn cache_has_dir(&self, guest: &[u8]) -> bool {
        self.cache_get(guest).is_some()
    }

    /// The pinned host side of the binding whose guest path is exactly
    /// `guest`, or of the root for `/`.
    ///
    /// # Returns
    /// `None` when `guest` is no mount point of this view; `Some(None)` when
    /// it is one whose host side does not exist.
    pub fn mount_pin(&self, guest: &[u8]) -> Option<Option<Arc<OwnedFd>>> {
        if let Some(i) = self.bindings.iter().position(|b| b.guest == guest) {
            return Some(self.pins[i].get());
        }
        (guest == b"/").then(|| self.root_pin.get())
    }

    /// Whether a binding lies below `guest`, which then stands in the view as a
    /// directory even where the host side has nothing under the name: in a
    /// rootfs the placeholders of `glue` could not be made in, say.
    ///
    /// # Arguments
    /// * `guest` - Canonical absolute guest path.
    pub fn binding_below(&self, guest: &[u8]) -> bool {
        self.bindings
            .iter()
            .any(|b| b.guest.len() > guest.len() && is_prefix(guest, &b.guest))
    }

    /// The pinned mount point under which `guest` lies, and the path from there.
    ///
    /// # Arguments
    /// * `guest` - Canonical absolute guest path.
    ///
    /// # Returns
    /// The binding's (or root's) descriptor, `None` when its host side does
    /// not exist, and the remainder of `guest` below it with its leading
    /// slash (empty for the mount point itself).
    pub fn pin_for_guest<'a>(&self, guest: &'a [u8]) -> (Option<Arc<OwnedFd>>, &'a [u8]) {
        match self.bindings.iter().position(|b| is_prefix(&b.guest, guest)) {
            Some(i) => (self.pins[i].get(), rest_after(&self.bindings[i].guest, guest)),
            None => (self.root_pin.get(), rest_after(b"/", guest)),
        }
    }

    /// Forgets every cached directory of every view sharing the cache.
    pub fn flush_cache(&self) {
        self.cache.flush();
    }

    /// The recorded guest program of thread `tid`, if any.
    ///
    /// # Arguments
    /// * `tid` - Thread or process id as it appears in a `/proc/<n>` path.
    pub fn exe_of(&self, tid: i32) -> Option<Vec<u8>> {
        self.procs.exe_of(tid)
    }

    /// The virtual working directory of thread `tid`, when cwd is virtual (no ptrace).
    ///
    /// # Arguments
    /// * `tid` - Thread or process id.
    pub fn virtual_cwd(&self, tid: i32) -> Option<Vec<u8>> {
        if self.procs.lazy {
            self.procs.cwd_of(tid)
        } else {
            None
        }
    }

    /// Finds the binding whose guest prefix covers `guest`, if any.
    ///
    /// # Arguments
    /// * `guest` - Absolute, lexically clean guest path.
    pub fn binding_for_guest(&self, guest: &[u8]) -> Option<&Binding> {
        self.bindings.iter().find(|b| is_prefix(&b.guest, guest))
    }

    /// Finds the binding whose host prefix covers `host`, preferring the longest.
    ///
    /// # Arguments
    /// * `host` - Absolute host path.
    pub fn binding_for_host(&self, host: &[u8]) -> Option<&Binding> {
        self.bindings
            .iter()
            .filter(|b| is_prefix(&b.host, host))
            .max_by_key(|b| b.host.len())
    }

    /// Substitutes the guest prefix of an absolute guest path with its host prefix.
    ///
    /// This is purely lexical: no symlink is followed.  Use
    /// [`crate::fs::translate::translate_path`] for a real translation.
    ///
    /// # Arguments
    /// * `guest` - Absolute guest path.
    ///
    /// # Returns
    /// The host path the guest path maps to.
    pub fn substitute_guest_to_host(&self, guest: &[u8]) -> Vec<u8> {
        if self.identity {
            return guest.to_vec();
        }
        match self.binding_for_guest(guest) {
            Some(b) => join_prefix(&b.host, rest_after(&b.guest, guest)),
            None => join_prefix(&self.root, rest_after(b"/", guest)),
        }
    }

    /// Substitutes the host prefix of a host path with its guest prefix.
    ///
    /// # Arguments
    /// * `host` - Absolute host path.
    ///
    /// # Returns
    /// The guest path, or `None` when the host path is not visible in the guest.
    pub fn substitute_host_to_guest(&self, host: &[u8]) -> Option<Vec<u8>> {
        if self.identity {
            return Some(host.to_vec());
        }
        // The root is just the lowest-priority binding of `/`: the longest host
        // prefix wins, and a binding beats the root on equal length.  This matters
        // when the rootfs itself lives under a bound directory (e.g. $HOME).
        let binding = self.binding_for_host(host);
        let root_hit = is_prefix(&self.root, host);
        match binding {
            Some(b) if !root_hit || b.host.len() >= self.root.len() => {
                Some(join_prefix(&b.guest, rest_after(&b.host, host)))
            }
            _ if root_hit => Some(join_prefix(b"/", rest_after(&self.root, host))),
            _ => None,
        }
    }
}

/// The real host path behind a binding or the root, symlinks resolved.
///
/// A binding names a host object, not a symlink to it: `/etc/resolv.conf`
/// pointing into `/run/systemd/resolve/` must bind the resolver file itself,
/// or the guest would follow the link inside its own rootfs and find nothing.
/// Same as PRoot's `realpath` on every binding.  A relative path becomes
/// absolute the same way.  A path that does not exist (yet) is kept as given.
fn resolve_host(host: &[u8]) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let trimmed = trim_slashes(host.to_vec());
    match std::fs::canonicalize(std::ffi::OsStr::from_bytes(&trimmed)) {
        Ok(real) => trim_slashes(real.as_os_str().as_bytes().to_vec()),
        Err(_) => trimmed,
    }
}

/// Whether `prefix` is `path` itself or a directory ancestor of it.
///
/// A prefix of `/` matches every absolute path.
pub fn is_prefix(prefix: &[u8], path: &[u8]) -> bool {
    if prefix == b"/" {
        return path.first() == Some(&b'/');
    }
    path.starts_with(prefix) && (path.len() == prefix.len() || path[prefix.len()] == b'/')
}

/// The part of `path` after `prefix`, keeping its leading slash.
///
/// A prefix of `/` consumes nothing, so the whole path is the remainder.
pub fn rest_after<'a>(prefix: &[u8], path: &'a [u8]) -> &'a [u8] {
    if prefix == b"/" {
        path
    } else {
        &path[prefix.len()..]
    }
}

/// Concatenates a prefix and a `/`-leading (or empty) remainder without doubling slashes.
pub fn join_prefix(prefix: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut out = if prefix == b"/" {
        Vec::new()
    } else {
        prefix.to_vec()
    };
    out.extend_from_slice(rest);
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs(root: &str, binds: &[(&str, &str)]) -> Fs {
        let mut c = Config {
            root: root.as_bytes().to_vec(),
            ..Config::default()
        };
        for (h, g) in binds {
            c.bindings.push(Binding {
                host: h.as_bytes().to_vec(),
                guest: g.as_bytes().to_vec(),
                read_only: false,
            });
        }
        Fs::new(&c)
    }

    #[test]
    fn substitutes_longest_prefix() {
        let f = fs("/rootfs", &[("/tmp", "/tmp"), ("/host/pulse", "/var/run/pulse")]);
        assert_eq!(
            f.substitute_guest_to_host(b"/usr/bin/ls"),
            b"/rootfs/usr/bin/ls".to_vec()
        );
        assert_eq!(f.substitute_guest_to_host(b"/tmp/x"), b"/tmp/x".to_vec());
        assert_eq!(
            f.substitute_guest_to_host(b"/var/run/pulse/native"),
            b"/host/pulse/native".to_vec()
        );
        assert_eq!(
            f.substitute_guest_to_host(b"/var/run/pulsex"),
            b"/rootfs/var/run/pulsex".to_vec()
        );
        assert_eq!(f.substitute_host_to_guest(b"/rootfs/etc"), Some(b"/etc".to_vec()));
        assert_eq!(
            f.substitute_host_to_guest(b"/host/pulse/native"),
            Some(b"/var/run/pulse/native".to_vec())
        );
        assert_eq!(f.substitute_host_to_guest(b"/elsewhere"), None);
        assert_eq!(f.substitute_host_to_guest(b"/rootfs"), Some(b"/".to_vec()));
    }

    #[test]
    fn slash_root_with_bindings_keeps_leading_slash() {
        let f = fs("/", &[("/data/x", "/pn-bind")]);
        assert!(!f.identity);
        assert_eq!(
            f.substitute_host_to_guest(b"/usr/bin/cat"),
            Some(b"/usr/bin/cat".to_vec())
        );
        assert_eq!(
            f.substitute_guest_to_host(b"/usr/bin/cat"),
            b"/usr/bin/cat".to_vec()
        );
        assert_eq!(f.substitute_guest_to_host(b"/pn-bind/f"), b"/data/x/f".to_vec());
        assert_eq!(
            f.substitute_host_to_guest(b"/data/x/f"),
            Some(b"/pn-bind/f".to_vec())
        );
        let g = fs("/rootfs", &[("/", "/host")]);
        assert_eq!(g.substitute_guest_to_host(b"/host/etc"), b"/etc".to_vec());
    }

    #[test]
    fn binding_host_side_is_the_real_path() {
        let d = std::env::temp_dir().join(format!("pn-bind-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("real")).unwrap();
        std::fs::write(d.join("real/conf"), "x").unwrap();
        std::os::unix::fs::symlink("real/conf", d.join("link")).unwrap();
        let link = d.join("link").as_os_str().as_encoded_bytes().to_vec();
        let f = fs("/rootfs", &[(std::str::from_utf8(&link).unwrap(), "/etc/conf")]);
        let real = std::fs::canonicalize(d.join("real/conf")).unwrap();
        assert_eq!(
            f.substitute_guest_to_host(b"/etc/conf"),
            real.as_os_str().as_encoded_bytes().to_vec()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rootfs_under_a_bound_directory_detranslates_to_root() {
        // proot-apps: the rootfs lives in $HOME and -R binds $HOME.
        let f = fs(
            "/home/me/proot-apps/app",
            &[("/home/me", "/home/me"), ("/tmp", "/tmp")],
        );
        assert_eq!(
            f.substitute_host_to_guest(b"/home/me/proot-apps/app/usr/share"),
            Some(b"/usr/share".to_vec())
        );
        assert_eq!(
            f.substitute_host_to_guest(b"/home/me/Documents"),
            Some(b"/home/me/Documents".to_vec())
        );
        assert_eq!(
            f.substitute_host_to_guest(b"/home/me/proot-apps/app"),
            Some(b"/".to_vec())
        );
        assert_eq!(f.substitute_host_to_guest(b"/tmp/x"), Some(b"/tmp/x".to_vec()));
    }
}
