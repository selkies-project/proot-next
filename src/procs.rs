//! Per-process bookkeeping shared by every handler: the program a process
//! runs, the identity it believes it has under `-0` and, without ptrace, the
//! working directory it believes it is in.
//!
//! With ptrace the tracer registers every child at its fork event and
//! forgets it at exit.  Without ptrace (see `launch`) nothing announces a new
//! process, so the table is lazy: a process is discovered at its first
//! notification and inherits the state of its parent, read from `/proc`.  To
//! make that inheritance exact when the parent changed state between the
//! fork and the child's first syscall, `clone` is notified too and a snapshot
//! of the parent is queued for the child; a parent that exits first leaves
//! its snapshots on an orphan list.  Exits are observed through pidfds by a
//! reaper thread so the table does not grow without bound.
//!
//! Notifications carry thread ids; the thread-to-process map is cached and
//! re-read from `/proc` once a second, which keeps a reused id from naming
//! the wrong process for longer than that.

use crate::state::View;
use crate::sys::{Result, errno};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// How long a cached thread-to-process mapping is trusted.
const TID_TTL: Duration = Duration::from_secs(1);
/// How long an orphaned fork snapshot stays claimable.
const ORPHAN_TTL: Duration = Duration::from_secs(10);
/// Longest parent chain walked when discovering a process.
const MAX_ANCESTRY: usize = 64;

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
    /// Working directory as a canonical guest path, kept here without ptrace
    /// (the kernel's own cwd is then pinned to the supervisor's alias directory).
    pub cwd: Option<Vec<u8>>,
    /// The process this one was `vfork`ed from and still shares memory with,
    /// until it execs; a rewritten exec path then has to be restored there.
    pub vfork_parent: Option<i32>,
    /// The view this process lives in; `None` for the root view.
    pub view: Option<Arc<View>>,
    /// Arguments that stand in `/proc/<pid>/cmdline` before the kernel's
    /// `argv[1..]`: the interpreter, its argument and the script of a `#!`
    /// program the guest-stub trampoline loaded, where the kernel's file
    /// keeps the vector the script was exec'd with.
    pub cmdline_prefix: Option<Vec<Vec<u8>>>,
    /// Set between a rewritten exec and the trampoline's exec of the real
    /// target.  Inherited by a child the trampoline forks, which then carries
    /// out the exec itself.
    pub pending: Option<PendingExec>,
}

/// The program a process is about to run through the exec shim.
#[derive(Clone, Debug)]
pub struct PendingExec {
    /// Canonical guest path of the program.
    pub guest: Vec<u8>,
    /// Host path handed to the kernel.
    pub host: Vec<u8>,
    /// The path string rewritten in a `vfork` parent's memory: its address,
    /// the original bytes and the bytes written over them.
    pub restore: Option<(i32, u64, Vec<u8>, Vec<u8>)>,
    /// The view the process enters at the real exec, with its working
    /// directory there (a nested proot or bwrap launch).
    pub enter: Option<(Arc<View>, Vec<u8>)>,
    /// What becomes [`TraceeInfo::cmdline_prefix`].
    pub cmdline_prefix: Option<Vec<Vec<u8>>>,
}

/// The reaper's epoll descriptor and the pidfd it watches for each process.
#[derive(Debug)]
struct Reaper {
    epoll: i32,
    pidfds: HashMap<i32, i32>,
}

/// The process table.
#[derive(Debug)]
pub struct ProcTable {
    /// True without ptrace: processes are discovered at their first syscall.
    pub lazy: bool,
    procs: RwLock<HashMap<i32, TraceeInfo>>,
    tids: RwLock<HashMap<i32, (i32, Instant)>>,
    /// State given to a process whose ancestry leads nowhere known.
    defaults: RwLock<TraceeInfo>,
    /// Snapshots taken at `clone`, waiting for the child, keyed by parent.
    forks: Mutex<HashMap<i32, VecDeque<TraceeInfo>>>,
    /// Snapshots whose parent exited before the child was seen.
    orphans: Mutex<VecDeque<(Instant, TraceeInfo)>>,
    /// At least the number of processes with a pending exec, so the check
    /// on every notification costs nothing while there is none.
    shim: AtomicUsize,
    reaper: Mutex<Option<Reaper>>,
}

impl ProcTable {
    /// Creates an empty table.
    ///
    /// # Arguments
    /// * `lazy` - Discover processes at their first syscall (no ptrace).
    pub fn new(lazy: bool) -> ProcTable {
        ProcTable {
            lazy,
            procs: RwLock::new(HashMap::new()),
            tids: RwLock::new(HashMap::new()),
            defaults: RwLock::new(TraceeInfo::default()),
            forks: Mutex::new(HashMap::new()),
            orphans: Mutex::new(VecDeque::new()),
            shim: AtomicUsize::new(0),
            reaper: Mutex::new(None),
        }
    }

    /// Sets the state handed to processes with no known ancestor, and
    /// registers `root` with it.
    ///
    /// # Arguments
    /// * `root` - Pid of the first tracee.
    /// * `info` - Its initial state.
    pub fn register_root(&self, root: i32, info: TraceeInfo) {
        *self.defaults.write().unwrap() = info.clone();
        self.procs.write().unwrap().insert(root, info);
        self.watch(root);
    }

    /// Thread-group id of thread `tid`, cached for [`TID_TTL`].
    ///
    /// A thread that is gone, or not visible, maps to itself.
    ///
    /// # Arguments
    /// * `tid` - Thread id as a notification reports it.
    pub fn tgid(&self, tid: i32) -> i32 {
        if let Some((tgid, at)) = self.tids.read().unwrap().get(&tid)
            && at.elapsed() < TID_TTL
        {
            return *tgid;
        }
        let tgid = read_status(tid).map(|(t, _)| t).unwrap_or(tid);
        self.tids.write().unwrap().insert(tid, (tgid, Instant::now()));
        tgid
    }

    /// A copy of what is known about the process of thread `tid`.
    ///
    /// # Arguments
    /// * `tid` - Thread or process id.
    pub fn info(&self, tid: i32) -> TraceeInfo {
        let tgid = self.tgid(tid);
        self.ensure(tgid);
        self.procs.read().unwrap().get(&tgid).cloned().unwrap_or_default()
    }

    /// Changes the state of the process of thread `tid` in place.
    ///
    /// Without ptrace, children forked since the last change are registered
    /// first, with the state the parent had when it forked them.
    ///
    /// # Arguments
    /// * `tid` - Thread or process id.
    /// * `f` - The change.
    pub fn update(&self, tid: i32, f: impl FnOnce(&mut TraceeInfo)) {
        let tgid = self.tgid(tid);
        self.ensure(tgid);
        if self.lazy {
            self.adopt_children(tgid);
        }
        let mut p = self.procs.write().unwrap();
        f(p.entry(tgid).or_default());
    }

    /// Registers `child` with a copy of `parent`'s state (ptrace fork event).
    ///
    /// # Arguments
    /// * `parent` - Thread id of the forking thread.
    /// * `child` - New process (or thread) id.
    pub fn fork(&self, parent: i32, child: i32) {
        let tgid = self.tgid(parent);
        let mut p = self.procs.write().unwrap();
        let info = p.get(&tgid).cloned().unwrap_or_default();
        if info.pending.is_some() {
            self.shim.fetch_add(1, Ordering::Relaxed);
        }
        p.insert(child, info);
    }

    /// The view of the process of thread `tid`, if it has one of its own.
    ///
    /// # Arguments
    /// * `tid` - Thread or process id.
    pub fn view_of(&self, tid: i32) -> Option<Arc<View>> {
        let tgid = self.tgid(tid);
        self.ensure(tgid);
        self.procs.read().unwrap().get(&tgid).and_then(|t| t.view.clone())
    }

    /// Takes a snapshot of the forking process for the child to inherit (no ptrace).
    ///
    /// # Arguments
    /// * `tid` - Thread calling `clone`, `fork` or `vfork`.
    /// * `vfork` - The child shares the parent's memory until it execs.
    pub fn forked(&self, tid: i32, vfork: bool) {
        let tgid = self.tgid(tid);
        let mut info = self.info(tgid);
        info.vfork_parent = if vfork { Some(tgid) } else { None };
        self.forks
            .lock()
            .unwrap()
            .entry(tgid)
            .or_default()
            .push_back(info);
    }

    /// Forgets a process or thread that exited.
    ///
    /// Snapshots it left for unborn children move to the orphan list.
    ///
    /// # Arguments
    /// * `pid` - Thread or process id.
    pub fn forget(&self, pid: i32) {
        self.tids
            .write()
            .unwrap()
            .retain(|t, (g, _)| *t != pid && *g != pid);
        let Some(gone) = self.procs.write().unwrap().remove(&pid) else {
            return;
        };
        if gone.pending.is_some() {
            self.shim.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(q) = self.forks.lock().unwrap().remove(&pid) {
            let now = Instant::now();
            let mut orphans = self.orphans.lock().unwrap();
            orphans.extend(q.into_iter().map(|s| (now, s)));
        }
        let mut r = self.reaper.lock().unwrap();
        if let Some(r) = r.as_mut()
            && let Some(fd) = r.pidfds.remove(&pid)
        {
            unsafe { libc::close(fd) };
        }
    }

    /// Records the executable the process of `tid` now runs.
    pub fn set_exe(&self, tid: i32, guest: Vec<u8>, host: Vec<u8>) {
        self.update(tid, |t| {
            t.exe_guest = Some(guest);
            t.exe_host = Some(host);
        });
    }

    /// The recorded guest program of thread `tid`, if any.
    pub fn exe_of(&self, tid: i32) -> Option<Vec<u8>> {
        self.info(tid).exe_guest
    }

    /// The virtual working directory of the process of `tid` (no ptrace).
    pub fn cwd_of(&self, tid: i32) -> Option<Vec<u8>> {
        self.info(tid).cwd
    }

    /// Replaces the virtual working directory of the process of `tid`.
    pub fn set_cwd(&self, tid: i32, cwd: Vec<u8>) {
        self.update(tid, |t| t.cwd = Some(cwd));
    }

    /// The virtual identity of the process of `tid` (root until changed).
    pub fn ids(&self, tid: i32) -> Ids {
        self.info(tid).ids.unwrap_or_default()
    }

    /// Replaces the virtual identity of the process of `tid`.
    pub fn set_ids(&self, tid: i32, ids: Ids) {
        self.update(tid, |t| t.ids = Some(ids));
    }

    /// Supplementary groups of the process of `tid`, if `setgroups` was called.
    pub fn groups(&self, tid: i32) -> Option<Vec<u32>> {
        self.info(tid).groups
    }

    /// Records the supplementary groups of the process of `tid`.
    pub fn set_groups(&self, tid: i32, groups: Vec<u32>) {
        self.update(tid, |t| t.groups = Some(groups));
    }

    /// Marks process `tgid` as about to run the exec shim for `pending`.
    pub fn shim_enter(&self, tgid: i32, pending: PendingExec) {
        self.shim.fetch_add(1, Ordering::Relaxed);
        self.update(tgid, |t| {
            t.pending = Some(pending);
        });
    }

    /// The pending exec of process `tgid`, if it is in the shim.
    pub fn shim_pending(&self, tgid: i32) -> Option<PendingExec> {
        if self.shim.load(Ordering::Relaxed) == 0 {
            return None;
        }
        self.ensure(tgid);
        self.procs
            .read()
            .unwrap()
            .get(&tgid)
            .and_then(|t| t.pending.clone())
    }

    /// Clears the shim mark of process `tgid`.
    pub fn shim_leave(&self, tgid: i32) {
        let mut p = self.procs.write().unwrap();
        if let Some(t) = p.get_mut(&tgid)
            && t.pending.take().is_some()
        {
            self.shim.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Makes sure process `tgid` has an entry, discovering its ancestry if needed.
    fn ensure(&self, tgid: i32) {
        if !self.lazy || self.procs.read().unwrap().contains_key(&tgid) {
            return;
        }
        self.discover(tgid, 0);
    }

    /// Registers `tgid` with the state of its parent, walking up as needed.
    ///
    /// A parent that is still known contributes the snapshot it took at the
    /// fork, or its current state.  A process whose parent is gone (reparented
    /// to init or to the supervisor) takes the oldest orphaned snapshot, or
    /// the defaults.
    fn discover(&self, tgid: i32, depth: usize) {
        let me = std::process::id() as i32;
        let ppid = read_status(tgid).map(|(_, p)| p).unwrap_or(0);
        let state = if ppid > 1 && ppid != me && depth < MAX_ANCESTRY {
            if !self.procs.read().unwrap().contains_key(&ppid) {
                self.discover(ppid, depth + 1);
            }
            let snapshot = self
                .forks
                .lock()
                .unwrap()
                .get_mut(&ppid)
                .and_then(|q| q.pop_front());
            match snapshot {
                Some(s) => s,
                None => {
                    let mut s = self.procs.read().unwrap().get(&ppid).cloned().unwrap_or_default();
                    s.vfork_parent = None;
                    s
                }
            }
        } else {
            let mut orphans = self.orphans.lock().unwrap();
            while let Some((at, _)) = orphans.front()
                && at.elapsed() > ORPHAN_TTL
            {
                orphans.pop_front();
            }
            match orphans.pop_front() {
                Some((_, s)) => s,
                None => self.defaults.read().unwrap().clone(),
            }
        };
        let pending = state.pending.is_some();
        let inserted = self.procs.write().unwrap().try_insert_entry(tgid, state);
        if inserted {
            if pending {
                self.shim.fetch_add(1, Ordering::Relaxed);
            }
            self.watch(tgid);
        }
    }

    /// Registers the children `tgid` forked since its last state change.
    ///
    /// Only done while snapshots are pending, since finding children means
    /// scanning `/proc`.
    fn adopt_children(&self, tgid: i32) {
        if self.forks.lock().unwrap().get(&tgid).is_none_or(|q| q.is_empty()) {
            return;
        }
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return;
        };
        for entry in dir.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
                continue;
            };
            if self.procs.read().unwrap().contains_key(&pid) {
                continue;
            }
            if read_status(pid).map(|(_, p)| p) != Some(tgid) {
                continue;
            }
            let snapshot = self
                .forks
                .lock()
                .unwrap()
                .get_mut(&tgid)
                .and_then(|q| q.pop_front());
            let Some(state) = snapshot else { break };
            let pending = state.pending.is_some();
            if self.procs.write().unwrap().try_insert_entry(pid, state) {
                if pending {
                    self.shim.fetch_add(1, Ordering::Relaxed);
                }
                self.watch(pid);
            }
        }
    }

    /// Starts watching `tgid` for exit, if a reaper is running.
    fn watch(&self, tgid: i32) {
        let mut r = self.reaper.lock().unwrap();
        let Some(r) = r.as_mut() else { return };
        if r.pidfds.contains_key(&tgid) {
            return;
        }
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, tgid, 0) } as i32;
        if pidfd < 0 {
            return;
        }
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: tgid as u32 as u64,
        };
        if unsafe { libc::epoll_ctl(r.epoll, libc::EPOLL_CTL_ADD, pidfd, &mut ev) } < 0 {
            unsafe { libc::close(pidfd) };
            return;
        }
        r.pidfds.insert(tgid, pidfd);
    }

    /// Starts the reaper thread, which forgets processes as they exit.
    ///
    /// Processes registered before the reaper started are watched from here on.
    ///
    /// # Arguments
    /// * `table` - The table to reap; the thread holds a reference for its life.
    ///
    /// # Errors
    /// Errno from `epoll_create1`.
    pub fn start_reaper(table: &Arc<ProcTable>) -> Result<()> {
        let epoll = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll < 0 {
            return Err(errno());
        }
        *table.reaper.lock().unwrap() = Some(Reaper {
            epoll,
            pidfds: HashMap::new(),
        });
        let known: Vec<i32> = table.procs.read().unwrap().keys().copied().collect();
        for pid in known {
            table.watch(pid);
        }
        let t = table.clone();
        std::thread::Builder::new()
            .name("reaper".into())
            .spawn(move || {
                let mut events = [libc::epoll_event { events: 0, u64: 0 }; 64];
                loop {
                    let n = unsafe { libc::epoll_wait(epoll, events.as_mut_ptr(), 64, -1) };
                    if n < 0 {
                        if errno() == libc::EINTR {
                            continue;
                        }
                        return;
                    }
                    for ev in &events[..n as usize] {
                        t.forget(ev.u64 as u32 as i32);
                    }
                }
            })
            .map_err(|_| libc::EAGAIN)?;
        Ok(())
    }
}

/// Inserts only when the key is absent; true when inserted.
trait TryInsert {
    fn try_insert_entry(&mut self, key: i32, value: TraceeInfo) -> bool;
}

impl TryInsert for HashMap<i32, TraceeInfo> {
    fn try_insert_entry(&mut self, key: i32, value: TraceeInfo) -> bool {
        if self.contains_key(&key) {
            return false;
        }
        self.insert(key, value);
        true
    }
}

/// `(Tgid, PPid)` of a thread from `/proc/<tid>/status`.
///
/// # Arguments
/// * `tid` - Thread id.
pub fn read_status(tid: i32) -> Option<(i32, i32)> {
    let s = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    let (mut tgid, mut ppid) = (None, None);
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("Tgid:") {
            tgid = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("PPid:") {
            ppid = v.trim().parse().ok();
        }
        if tgid.is_some() && ppid.is_some() {
            break;
        }
    }
    Some((tgid?, ppid?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eager_table_copies_on_fork_and_forgets() {
        let me = std::process::id() as i32;
        let t = ProcTable::new(false);
        t.set_exe(me, b"/bin/x".to_vec(), b"/host/x".to_vec());
        t.fork(me, 4_000_001);
        assert_eq!(t.exe_of(4_000_001), Some(b"/bin/x".to_vec()));
        t.forget(4_000_001);
        assert_eq!(t.exe_of(4_000_001), None);
        assert_eq!(t.tgid(me), me);
    }

    #[test]
    fn lazy_table_inherits_from_the_parent_and_takes_snapshots() {
        let me = std::process::id() as i32;
        let (_, parent) = read_status(me).unwrap();
        let t = ProcTable::new(true);
        t.register_root(
            parent,
            TraceeInfo {
                cwd: Some(b"/start".to_vec()),
                ..Default::default()
            },
        );
        assert_eq!(t.cwd_of(me), Some(b"/start".to_vec()));
        t.forked(me, false);
        t.set_cwd(me, b"/later".to_vec());
        let snapshot = t.forks.lock().unwrap().get(&me).and_then(|q| q.front().cloned());
        assert_eq!(snapshot.and_then(|s| s.cwd), Some(b"/start".to_vec()));
        assert_eq!(t.cwd_of(me), Some(b"/later".to_vec()));
        t.forget(me);
        let orphan = t.orphans.lock().unwrap().front().cloned();
        assert_eq!(orphan.and_then(|(_, s)| s.cwd), Some(b"/start".to_vec()));
    }

    #[test]
    fn shim_marks_are_per_process() {
        let t = ProcTable::new(false);
        assert!(t.shim_pending(7).is_none());
        t.shim_enter(
            7,
            PendingExec {
                guest: b"/bin/true".to_vec(),
                host: b"/r/bin/true".to_vec(),
                restore: None,
                enter: None,
                cmdline_prefix: None,
            },
        );
        assert_eq!(t.shim_pending(7).map(|p| p.guest), Some(b"/bin/true".to_vec()));
        t.fork(7, 8);
        assert_eq!(t.shim_pending(8).map(|p| p.host), Some(b"/r/bin/true".to_vec()));
        t.shim_leave(7);
        assert!(t.shim_pending(7).is_none());
        assert!(t.shim_pending(8).is_some());
        t.forget(8);
        assert_eq!(t.shim.load(Ordering::Relaxed), 0);
    }
}
