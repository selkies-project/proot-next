//! The listener pool: leader/followers over one seccomp listener descriptor.
//!
//! The kernel hands a notification to the longest-waiting receiver, which on
//! an idle host means a cold core.  So exactly one thread (the leader) waits
//! at a time, spinning on `poll` for a short while before sleeping.  When it
//! receives it releases the token and serves the request itself; whichever
//! spinning follower grabs the token becomes the next leader.  Idle threads
//! park after `spin_us`.

use crate::state::Ctx;
use crate::sys::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

struct Pool {
    token: Mutex<()>,
    park: Mutex<()>,
    cv: Condvar,
    parked: AtomicUsize,
    closed: AtomicBool,
    /// Current spin budget in microseconds, 0..=spin_us.
    budget: AtomicU64,
}

/// Longest a follower spins for the token before parking, in microseconds.
const FOLLOWER_SPIN_US: u64 = 20;

/// Blocking receive; `None` once the listener is closed.
fn recv(listener: i32) -> Option<SeccompNotif> {
    loop {
        let mut req = SeccompNotif::default();
        if unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV as _, &mut req as *mut _) } == 0 {
            return Some(req);
        }
        match errno() {
            libc::EINTR => continue,
            // ENOENT from RECV means no task uses the filter any more: every
            // tracee is gone, so the pool is done.  (For SEND it would mean a
            // stale id, but that is answered elsewhere.)
            _ => return None,
        }
    }
}

/// Spins on `poll(0)` for up to `budget` microseconds, then blocks until readable.
///
/// # Returns
/// True when a request was found while spinning, false when we had to block.
fn wait_ready(listener: i32, budget: u64) -> bool {
    let mut pfd = libc::pollfd {
        fd: listener,
        events: libc::POLLIN,
        revents: 0,
    };
    if budget > 0 {
        let start = Instant::now();
        loop {
            pfd.revents = 0;
            if unsafe { libc::poll(&mut pfd, 1, 0) } > 0 {
                return true;
            }
            if start.elapsed().as_micros() >= budget as u128 {
                break;
            }
            std::hint::spin_loop();
        }
    }
    unsafe { libc::poll(&mut pfd, 1, -1) };
    false
}

fn thread_main(listener: i32, pool: Arc<Pool>, ctx: Arc<Ctx>, spin_us: u64) {
    loop {
        if pool.closed.load(Ordering::Acquire) {
            return;
        }
        let guard = 'tok: loop {
            let start = Instant::now();
            let follower_spin = FOLLOWER_SPIN_US.min(pool.budget.load(Ordering::Relaxed));
            loop {
                if let Ok(g) = pool.token.try_lock() {
                    break 'tok g;
                }
                if start.elapsed().as_micros() >= follower_spin as u128 {
                    break;
                }
                std::hint::spin_loop();
            }
            // Park until the leader steps down.  Re-check the token under the
            // park lock so a notify sent just before we parked is not lost.
            let pg = pool.park.lock().unwrap();
            if let Ok(g) = pool.token.try_lock() {
                break 'tok g;
            }
            pool.parked.fetch_add(1, Ordering::AcqRel);
            let _ = pool.cv.wait_timeout(pg, Duration::from_secs(1)).unwrap();
            pool.parked.fetch_sub(1, Ordering::AcqRel);
            if pool.closed.load(Ordering::Acquire) {
                return;
            }
        };
        let budget = pool.budget.load(Ordering::Relaxed);
        let hit = wait_ready(listener, budget);
        pool.budget
            .store(if hit { spin_us } else { budget / 2 }, Ordering::Relaxed);
        let req = recv(listener);
        drop(guard);
        if pool.parked.load(Ordering::Acquire) > 0 {
            let _pg = pool.park.lock().unwrap();
            pool.cv.notify_one();
        }
        match req {
            Some(r) => crate::syscall::notify::handle(&ctx, listener, &r),
            None => {
                pool.closed.store(true, Ordering::Release);
                pool.cv.notify_all();
                return;
            }
        }
    }
}

/// Starts the supervisor threads.  They run until the listener closes.
///
/// # Arguments
/// * `listener` - Seccomp listener descriptor received from the first tracee.
/// * `ctx` - Shared supervisor state.
pub fn start(listener: i32, ctx: Arc<Ctx>) {
    let pool = Arc::new(Pool {
        token: Mutex::new(()),
        park: Mutex::new(()),
        cv: Condvar::new(),
        parked: AtomicUsize::new(0),
        closed: AtomicBool::new(false),
        budget: AtomicU64::new(ctx.config.spin_us),
    });
    let threads = ctx.config.threads.max(1);
    let spin_us = ctx.config.spin_us;
    for i in 0..threads {
        let (pool, ctx) = (pool.clone(), ctx.clone());
        std::thread::Builder::new()
            .name(format!("notify-{i}"))
            .spawn(move || thread_main(listener, pool, ctx, spin_us))
            .expect("spawn supervisor thread");
    }
}

/// Answers a notification with a plain result or an error.
///
/// # Arguments
/// * `listener` - Listener descriptor.
/// * `id` - Notification id.
/// * `result` - `Ok(value)` becomes the syscall's return value, `Err(errno)` its error.
pub fn reply(listener: i32, id: u64, result: Result<i64>) {
    let resp = match result {
        Ok(v) => SeccompNotifResp {
            id,
            val: v,
            error: 0,
            flags: 0,
        },
        Err(e) => SeccompNotifResp {
            id,
            val: 0,
            error: -e,
            flags: 0,
        },
    };
    unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND as _, &resp as *const _) };
}

/// Lets the kernel execute the syscall unchanged.
pub fn reply_continue(listener: i32, id: u64) {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND as _, &resp as *const _) };
}

/// Installs `fd` into the tracee and completes the syscall with its number.
///
/// Closes the supervisor's copy of `fd` afterwards.
///
/// # Arguments
/// * `listener` - Listener descriptor.
/// * `id` - Notification id.
/// * `fd` - Supervisor-side descriptor to hand over.
/// * `cloexec` - Set `O_CLOEXEC` on the tracee's copy.
pub fn reply_fd(listener: i32, id: u64, fd: i32, cloexec: bool) {
    let add = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: fd as u32,
        newfd: 0,
        newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
    };
    let rc = unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD as _, &add as *const _) };
    if rc < 0 {
        let e = errno();
        if e == libc::EINVAL {
            // Kernel older than 5.14: install first, then answer with the number.
            let add2 = SeccompNotifAddfd { flags: 0, ..add };
            let newfd = unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD as _, &add2 as *const _) };
            reply(
                listener,
                id,
                if newfd < 0 { Err(errno()) } else { Ok(newfd as i64) },
            );
        } else if e != libc::ENOENT {
            // The tracee must never be left waiting: EBADF here means the
            // descriptor cannot be injected (e.g. O_PATH), report it as such.
            reply(
                listener,
                id,
                Err(if e == libc::EBADF { libc::EOPNOTSUPP } else { e }),
            );
        }
    }
    unsafe { libc::close(fd) };
}

/// Checks that the tracee is still blocked in this notification.
///
/// Call after reading tracee memory and before acting on it.
pub fn still_valid(listener: i32, id: u64) -> bool {
    unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID as _, &id as *const _) == 0 }
}
