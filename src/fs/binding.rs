//! Binding tables: longest-prefix substitution between guest and host paths.

use crate::config::{Binding, Config, trim_slashes};
use crate::procs::ProcTable;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Entries kept in the directory cache before it is cleared wholesale.
const DIR_CACHE_MAX: usize = 65_536;

/// Canonical guest directories known to exist and not be symlinks, shared
/// by every view of one supervisor.
///
/// Lets the walk skip one `lstat` per intermediate component.  Entries are
/// keyed by the view they were resolved in, since the same guest path names
/// different host directories in different views, and the whole cache is
/// flushed by [`DirCache::flush`] after any syscall that may replace a
/// directory, whichever view made it: the host directories are shared.
#[derive(Debug)]
pub struct DirCache {
    entries: RwLock<HashSet<(u64, Vec<u8>)>>,
    /// False when `PROOT_NO_PATH_CACHE` is set.
    enabled: bool,
}

impl DirCache {
    /// Creates an empty cache, disabled when `PROOT_NO_PATH_CACHE` is set.
    pub fn new() -> DirCache {
        DirCache {
            entries: RwLock::new(HashSet::new()),
            enabled: std::env::var_os("PROOT_NO_PATH_CACHE").is_none(),
        }
    }

    /// Forgets every cached directory of every view.
    ///
    /// Call after `mkdir`, `rmdir`, `rename`, `unlink`, `symlink`, `link`,
    /// `mknod` or any other syscall that can turn a directory into something
    /// else (or the reverse); changes made from outside PRoot are not seen.
    pub fn flush(&self) {
        if let Ok(mut c) = self.entries.write() {
            c.clear();
        }
    }
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
        let mut fs = Fs {
            root,
            bindings,
            identity,
            id: NEXT_VIEW_ID.fetch_add(1, Ordering::Relaxed),
            cache,
            procs,
        };
        fs.canonicalize_bindings();
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
        self.bindings.sort_by_key(|b| std::cmp::Reverse(b.guest.len()));
        self.identity = self.root == b"/" && self.bindings.iter().all(|b| b.host == b.guest);
    }

    /// Whether `guest` is a canonical directory the cache has seen in this view.
    ///
    /// # Arguments
    /// * `guest` - Canonical absolute guest path.
    pub fn cache_has_dir(&self, guest: &[u8]) -> bool {
        self.cache.enabled
            && self
                .cache
                .entries
                .read()
                .map(|c| c.contains(&(self.id, guest.to_vec())))
                .unwrap_or(false)
    }

    /// Records that `guest` resolved to a real directory in this view.
    ///
    /// # Arguments
    /// * `guest` - Canonical absolute guest path.
    pub fn cache_add_dir(&self, guest: &[u8]) {
        if !self.cache.enabled {
            return;
        }
        if let Ok(mut c) = self.cache.entries.write() {
            if c.len() >= DIR_CACHE_MAX {
                c.clear();
            }
            c.insert((self.id, guest.to_vec()));
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
