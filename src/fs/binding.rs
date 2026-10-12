//! Binding tables: longest-prefix substitution between guest and host paths.

use crate::config::{Binding, Config, trim_slashes};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Entries kept in the directory cache before it is cleared wholesale.
const DIR_CACHE_MAX: usize = 65_536;

/// The guest filesystem view: a root directory plus bind mounts.
#[derive(Debug)]
pub struct Fs {
    /// Host directory serving as guest `/`, no trailing slash.
    pub root: Vec<u8>,
    /// Bindings sorted so that longer guest prefixes come first.
    pub bindings: Vec<Binding>,
    /// True when root is `/` and there are no bindings: translation is a no-op.
    pub identity: bool,
    /// Canonical guest directories known to exist and not be symlinks.
    ///
    /// Lets the walk skip one `lstat` per intermediate component.  Flushed by
    /// [`Fs::flush_cache`] after any syscall that may replace a directory.
    dir_cache: RwLock<HashSet<Vec<u8>>>,
    /// Canonical guest path of the program each process runs, keyed by tgid.
    ///
    /// The kernel's own `/proc/<pid>/exe` names the dynamic loader after an
    /// exec rewrite, so every path through that link resolves here instead.
    exes: RwLock<HashMap<i32, Vec<u8>>>,
    /// False when `PROOT_NO_PATH_CACHE` is set.
    cache_enabled: bool,
}

impl Fs {
    /// Builds the view from the parsed configuration.
    ///
    /// # Arguments
    /// * `config` - Parsed command line.  Bindings are normalized and sorted.
    pub fn new(config: &Config) -> Fs {
        let root = trim_slashes(config.root.clone());
        let mut bindings: Vec<Binding> = config
            .bindings
            .iter()
            .map(|b| Binding {
                host: trim_slashes(b.host.clone()),
                guest: trim_slashes(b.guest.clone()),
                read_only: b.read_only,
            })
            .collect();
        // Stable sort: longer guest prefix first, later command-line entries first on ties.
        bindings.reverse();
        bindings.sort_by(|a, b| b.guest.len().cmp(&a.guest.len()));
        let identity = root == b"/" && bindings.iter().all(|b| b.host == b.guest);
        let cache_enabled = std::env::var_os("PROOT_NO_PATH_CACHE").is_none();
        Fs {
            root,
            bindings,
            identity,
            dir_cache: RwLock::new(HashSet::new()),
            exes: RwLock::new(HashMap::new()),
            cache_enabled,
        }
    }

    /// Whether `guest` is a canonical directory the cache has seen.
    ///
    /// # Arguments
    /// * `guest` - Canonical absolute guest path.
    pub fn cache_has_dir(&self, guest: &[u8]) -> bool {
        self.cache_enabled && self.dir_cache.read().map(|c| c.contains(guest)).unwrap_or(false)
    }

    /// Records that `guest` resolved to a real directory.
    ///
    /// # Arguments
    /// * `guest` - Canonical absolute guest path.
    pub fn cache_add_dir(&self, guest: &[u8]) {
        if !self.cache_enabled {
            return;
        }
        if let Ok(mut c) = self.dir_cache.write() {
            if c.len() >= DIR_CACHE_MAX {
                c.clear();
            }
            c.insert(guest.to_vec());
        }
    }

    /// Forgets every cached directory.
    ///
    /// Call after `mkdir`, `rmdir`, `rename`, `unlink`, `symlink`, `link`,
    /// `mknod` or any other syscall that can turn a directory into something
    /// else (or the reverse); changes made from outside PRoot are not seen.
    pub fn flush_cache(&self) {
        if let Ok(mut c) = self.dir_cache.write() {
            c.clear();
        }
    }

    /// Records the guest path of the program process `tgid` now runs.
    ///
    /// # Arguments
    /// * `tgid` - Thread-group id of the process.
    /// * `guest` - Canonical guest path of the executable.
    pub fn set_exe(&self, tgid: i32, guest: Vec<u8>) {
        if let Ok(mut m) = self.exes.write() {
            m.insert(tgid, guest);
        }
    }

    /// Copies the recorded program from `parent` to a forked `child`.
    pub fn fork_exe(&self, parent: i32, child: i32) {
        if let Ok(mut m) = self.exes.write()
            && let Some(e) = m.get(&parent).cloned()
        {
            m.insert(child, e);
        }
    }

    /// Forgets a process that exited.
    pub fn forget_exe(&self, tgid: i32) {
        if let Ok(mut m) = self.exes.write() {
            m.remove(&tgid);
        }
    }

    /// The recorded guest program of thread `tid`, trying its thread group too.
    ///
    /// # Arguments
    /// * `tid` - Thread or process id as it appears in a `/proc/<n>` path.
    pub fn exe_of(&self, tid: i32) -> Option<Vec<u8>> {
        let m = self.exes.read().ok()?;
        if let Some(e) = m.get(&tid) {
            return Some(e.clone());
        }
        let tgid = tgid_of(tid)?;
        m.get(&tgid).cloned()
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

/// Thread-group id of a thread, read from `/proc`.
fn tgid_of(tid: i32) -> Option<i32> {
    let s = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
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
