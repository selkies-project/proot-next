//! Supervisor-wide shared state.

use crate::config::Config;
use crate::fs::Fs;
use crate::tracee::mem::Mem;
use std::collections::HashMap;
use std::sync::RwLock;

/// The identity a process believes it has under `-0`.
///
/// Starts as root; `setuid` and friends move it with the kernel's rules
/// (anything goes while the effective id is 0, otherwise only among the
/// real, effective and saved ids).  Inherited across fork, kept across exec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Ids {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
}

/// What the supervisor remembers about one tracee process.
#[derive(Clone, Debug, Default)]
pub struct TraceeInfo {
    /// Virtual identity under `-0`; `None` until the process changes it.
    pub ids: Option<Ids>,
    /// Supplementary groups set with `setgroups` under `-0`.
    pub groups: Option<Vec<u32>>,
    /// Canonical guest path of the running executable, for `/proc/self/exe`.
    pub exe_guest: Option<Vec<u8>>,
    /// Host path actually executed, for diagnostics.
    pub exe_host: Option<Vec<u8>>,
}

/// Everything handlers need, shared read-mostly between all threads.
pub struct Ctx {
    pub config: Config,
    pub fs: Fs,
    pub mem: Mem,
    /// Per-process bookkeeping, keyed by thread-group id.
    pub tracees: RwLock<HashMap<i32, TraceeInfo>>,
}

impl Ctx {
    /// Builds the shared state from a configuration.
    pub fn new(config: Config) -> Ctx {
        let fs = Fs::new(&config);
        Ctx {
            config,
            fs,
            mem: Mem,
            tracees: RwLock::new(HashMap::new()),
        }
    }

    /// Returns a copy of what is known about process `pid`.
    pub fn tracee(&self, pid: i32) -> TraceeInfo {
        self.tracees
            .read()
            .unwrap()
            .get(&pid)
            .cloned()
            .unwrap_or_default()
    }

    /// Records the executable a process is now running.
    pub fn set_exe(&self, pid: i32, guest: Vec<u8>, host: Vec<u8>) {
        self.fs.set_exe(pid, guest.clone());
        let mut t = self.tracees.write().unwrap();
        let e = t.entry(pid).or_default();
        e.exe_guest = Some(guest);
        e.exe_host = Some(host);
    }

    /// The virtual identity of process `tgid` (root until changed).
    pub fn ids(&self, tgid: i32) -> Ids {
        self.tracees
            .read()
            .unwrap()
            .get(&tgid)
            .and_then(|t| t.ids)
            .unwrap_or_default()
    }

    /// Replaces the virtual identity of process `tgid`.
    pub fn set_ids(&self, tgid: i32, ids: Ids) {
        self.tracees.write().unwrap().entry(tgid).or_default().ids = Some(ids);
    }

    /// Supplementary groups of process `tgid`, if `setgroups` was called.
    pub fn groups(&self, tgid: i32) -> Option<Vec<u32>> {
        self.tracees
            .read()
            .unwrap()
            .get(&tgid)
            .and_then(|t| t.groups.clone())
    }

    /// Records the supplementary groups of process `tgid`.
    pub fn set_groups(&self, tgid: i32, groups: Vec<u32>) {
        self.tracees.write().unwrap().entry(tgid).or_default().groups = Some(groups);
    }

    /// Copies the bookkeeping of `parent` to a newly forked `child`.
    pub fn fork(&self, parent: i32, child: i32) {
        self.fs.fork_exe(parent, child);
        let mut t = self.tracees.write().unwrap();
        let info = t.get(&parent).cloned().unwrap_or_default();
        t.insert(child, info);
    }

    /// Forgets a process that exited.
    pub fn forget(&self, pid: i32) {
        self.fs.forget_exe(pid);
        self.tracees.write().unwrap().remove(&pid);
    }

    /// Thread-group id of a thread, from `/proc`, falling back to the tid.
    pub fn tgid(tid: i32) -> i32 {
        if let Ok(s) = std::fs::read_to_string(format!("/proc/{tid}/status")) {
            for line in s.lines() {
                if let Some(v) = line.strip_prefix("Tgid:") {
                    return v.trim().parse().unwrap_or(tid);
                }
            }
        }
        tid
    }
}
