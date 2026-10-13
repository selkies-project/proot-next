//! Supervisor-wide shared state.

use crate::config::Config;
use crate::fs::Fs;
use crate::procs::{Ids, ProcTable, TraceeInfo};
use crate::tracee::mem::Mem;
use std::sync::Arc;

/// Everything handlers need, shared read-mostly between all threads.
pub struct Ctx {
    pub config: Config,
    pub fs: Fs,
    pub mem: Mem,
    /// Per-process bookkeeping, shared with `fs` for `/proc` magic links.
    pub procs: Arc<ProcTable>,
    /// True when running without ptrace: the former ptrace tier is served
    /// through notifications with in-place rewrites (see `syscall::direct`).
    pub no_ptrace: bool,
}

impl Ctx {
    /// Builds the shared state from a configuration.
    ///
    /// # Arguments
    /// * `config` - Parsed command line.
    /// * `no_ptrace` - Run without a ptrace tier.
    pub fn new(config: Config, no_ptrace: bool) -> Ctx {
        let procs = Arc::new(ProcTable::new(no_ptrace));
        let fs = Fs::with_procs(&config, procs.clone());
        Ctx {
            config,
            fs,
            mem: Mem,
            procs,
            no_ptrace,
        }
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
