//! Supervisor-wide shared state.

use crate::config::Config;
use crate::fs::Fs;
use crate::fs::binding::DirCache;
use crate::procs::{Ids, ProcTable, TraceeInfo};
use crate::tracee::mem::Mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// One guest: a filesystem view and the launch options that go with it.
///
/// The first tracee gets the view the command line describes.  A tracee
/// that execs proot or bwrap gets a view of its own, composed through the
/// one it asked from, which its descendants inherit (see `exec::nested`).
#[derive(Debug)]
pub struct View {
    /// Root and bindings, in host terms.
    pub fs: Fs,
    /// Value reported by `uname(2)` in the `release` field, if faked.
    pub kernel_release: Option<Vec<u8>>,
    /// Value reported by `uname(2)` in the `nodename` field, if faked.
    pub hostname: Option<Vec<u8>>,
    /// Pretend to be root (`-0`).
    pub fake_root: bool,
    /// Directories removed once the last process of the view is gone (a
    /// nested bwrap's materialized root).
    cleanup_dirs: Vec<Vec<u8>>,
}

impl View {
    /// Builds a view from a configuration whose paths are host paths.
    ///
    /// # Arguments
    /// * `config` - Root, bindings and flags.
    /// * `procs` - Process table shared with the supervisor.
    /// * `cache` - Directory cache shared with the supervisor's other views.
    /// * `cleanup` - Remove `config.cleanup_dirs` when the view is dropped.
    pub fn new(config: &Config, procs: Arc<ProcTable>, cache: Arc<DirCache>, cleanup: bool) -> View {
        View {
            fs: Fs::with_cache(config, procs, cache),
            kernel_release: config.kernel_release.clone(),
            hostname: config.hostname.clone(),
            fake_root: config.fake_root,
            cleanup_dirs: if cleanup {
                config.cleanup_dirs.clone()
            } else {
                Vec::new()
            },
        }
    }
}

impl Drop for View {
    fn drop(&mut self) {
        use std::os::unix::ffi::OsStrExt;
        for dir in &self.cleanup_dirs {
            let _ = std::fs::remove_dir_all(std::ffi::OsStr::from_bytes(dir));
        }
    }
}

/// Everything handlers need, shared read-mostly between all threads.
pub struct Ctx {
    pub config: Config,
    /// The view of the first tracee, and of every process without one of its own.
    pub root: Arc<View>,
    /// Directory cache shared by every view.
    pub cache: Arc<DirCache>,
    pub mem: Mem,
    /// Per-process bookkeeping, shared with `fs` for `/proc` magic links.
    pub procs: Arc<ProcTable>,
    /// True when running without ptrace: the former ptrace tier is served
    /// through notifications with in-place rewrites (see `syscall::direct`).
    pub no_ptrace: bool,
    /// The mailbox descriptor of the guest-stub restricted mode, installed
    /// into every process that execs (see `guest_stub`); `None` elsewhere.
    pub mailbox: Option<i32>,
    /// Set once any process has a view of its own; until then every lookup
    /// answers the root view without touching the process table.
    nested: AtomicBool,
}

impl Ctx {
    /// Builds the shared state from a configuration.
    ///
    /// # Arguments
    /// * `config` - Parsed command line.
    /// * `no_ptrace` - Run without a ptrace tier.
    pub fn new(config: Config, no_ptrace: bool) -> Ctx {
        let procs = Arc::new(ProcTable::new(no_ptrace));
        let cache = Arc::new(DirCache::new());
        let root = Arc::new(View::new(&config, procs.clone(), cache.clone(), false));
        Ctx {
            config,
            root,
            cache,
            mem: Mem,
            procs,
            no_ptrace,
            mailbox: None,
            nested: AtomicBool::new(false),
        }
    }

    /// Whether guests run the stub of the guest-stub restricted mode.
    ///
    /// # Returns
    /// `true` when a mailbox was set up.
    pub fn trap_mode(&self) -> bool {
        self.mailbox.is_some()
    }

    /// The view the process of thread `tid` lives in.
    ///
    /// # Arguments
    /// * `tid` - Thread or process id.
    pub fn view(&self, tid: i32) -> Arc<View> {
        if !self.nested.load(Ordering::Relaxed) {
            return self.root.clone();
        }
        self.procs.view_of(tid).unwrap_or_else(|| self.root.clone())
    }

    /// Moves the process of thread `tid` into `view`, with `cwd` as its
    /// working directory there when the working directory is virtual.
    ///
    /// # Arguments
    /// * `tid` - Thread or process id.
    /// * `view` - The view to enter.
    /// * `cwd` - Working directory as a guest path of `view`.
    pub fn enter_view(&self, tid: i32, view: Arc<View>, cwd: Vec<u8>) {
        self.nested.store(true, Ordering::Relaxed);
        self.procs.update(tid, |t| {
            t.view = Some(view);
            if t.cwd.is_some() {
                t.cwd = Some(cwd);
            }
        });
    }

    /// Returns a copy of what is known about the process of thread `tid`.
    pub fn tracee(&self, tid: i32) -> TraceeInfo {
        self.procs.info(tid)
    }

    /// Records the executable the process of thread `tid` is now running.
    pub fn set_exe(&self, tid: i32, guest: Vec<u8>, host: Vec<u8>) {
        self.procs.set_exe(tid, guest, host);
    }

    /// The virtual identity of the process of thread `tid` (root until changed).
    pub fn ids(&self, tid: i32) -> Ids {
        self.procs.ids(tid)
    }

    /// Replaces the virtual identity of the process of thread `tid`.
    pub fn set_ids(&self, tid: i32, ids: Ids) {
        self.procs.set_ids(tid, ids);
    }

    /// Supplementary groups of the process of thread `tid`, if `setgroups` was called.
    pub fn groups(&self, tid: i32) -> Option<Vec<u32>> {
        self.procs.groups(tid)
    }

    /// Records the supplementary groups of the process of thread `tid`.
    pub fn set_groups(&self, tid: i32, groups: Vec<u32>) {
        self.procs.set_groups(tid, groups);
    }

    /// Copies the bookkeeping of the process of `parent` to a newly forked `child`.
    pub fn fork(&self, parent: i32, child: i32) {
        self.procs.fork(parent, child);
    }

    /// Forgets a process or thread that exited.
    pub fn forget(&self, pid: i32) {
        self.procs.forget(pid);
    }

    /// Thread-group id of a thread.
    pub fn tgid(&self, tid: i32) -> i32 {
        self.procs.tgid(tid)
    }
}
