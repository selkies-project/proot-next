//! The ptrace event loop.  Runs on the thread that forked the first tracee.
//!
//! Tracees are seized, so stops are unambiguous: seccomp-trace stops for the
//! tier-two syscalls, exec events (to keep `/proc/self/exe` bookkeeping
//! honest), clone/fork events (to copy bookkeeping to the child), and
//! `PTRACE_EVENT_STOP` for group-stops and freshly attached children.  A
//! group-stop gets `PTRACE_LISTEN` so job control keeps working; every other
//! stop is resumed.  Signal-delivery stops are forwarded unchanged.

use crate::note;
use crate::state::Ctx;
use crate::sys::{errno, strerror};
use crate::syscall::traced;
use crate::tracee::ptrace;
use crate::tracee::regs::Regs;
use std::sync::Arc;

/// Runs the loop until every tracee has exited.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `root` - Pid of the first tracee, whose exit status becomes ours.
///
/// # Returns
/// The exit code to report: the root tracee's status, or 128 plus the signal.
pub fn run(ctx: &Arc<Ctx>, root: i32) -> i32 {
    let mut exit_code = 0;
    // Live tracees.  The loop ends when this empties, not when waitpid runs out
    // of children: a non-tracee child (an inherited helper, a pipe reader)
    // must not keep the supervisor alive.
    let mut tracees: std::collections::HashSet<i32> = std::collections::HashSet::new();
    tracees.insert(root);
    loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if pid < 0 {
            match errno() {
                libc::EINTR => continue,
                libc::ECHILD => break,
                e => {
                    eprintln!("proot: waitpid: {}", strerror(e));
                    break;
                }
            }
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            if pid == root {
                exit_code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                };
            }
            ctx.forget(pid);
            tracees.remove(&pid);
            if tracees.is_empty() {
                break;
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xff;
        let mut deliver = 0;
        note!(
            ctx,
            3,
            "pid {pid}: stop sig={sig} event={event} status={status:#x}"
        );
        match event {
            libc::PTRACE_EVENT_SECCOMP => match Regs::fetch(pid) {
                Ok(mut regs) => {
                    traced::handle(ctx, &mut regs);
                    if let Err(e) = regs.commit() {
                        note!(ctx, 1, "pid {pid}: setregs: {}", strerror(e));
                    }
                }
                Err(e) => note!(ctx, 1, "pid {pid}: getregs: {}", strerror(e)),
            },
            libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
                if let Ok(child) = ptrace::geteventmsg(pid) {
                    tracees.insert(child as i32);
                    ctx.fork(pid, child as i32);
                }
            }
            libc::PTRACE_EVENT_EXEC => {
                // Threads other than the leader vanish on exec; the leader keeps
                // the record set by the execve handler.
            }
            libc::PTRACE_EVENT_STOP => {
                // A new child may report its first stop before the parent's clone event.
                tracees.insert(pid);
                // Group-stop: keep the tracee stopped (job control, SIGSTOP from
                // outside) but stay able to hear about it.  Anything else here is
                // a freshly attached child or a PTRACE_INTERRUPT: just resume.
                if matches!(sig, libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU) {
                    if let Err(e) = ptrace::listen(pid)
                        && e != libc::ESRCH
                    {
                        note!(ctx, 1, "pid {pid}: listen: {}", strerror(e));
                    }
                    continue;
                }
            }
            0 => {
                // Signal-delivery stop: the tracee gets exactly what it was sent.
                deliver = sig;
                let mut si_code = 0;
                if matches!(
                    sig,
                    libc::SIGTRAP
                        | libc::SIGSEGV
                        | libc::SIGILL
                        | libc::SIGABRT
                        | libc::SIGBUS
                        | libc::SIGSYS
                ) {
                    if let Ok(si) = ptrace::getsiginfo(pid) {
                        si_code = si.si_code;
                        // si_pid/si_addr share a union; both are printed since the
                        // meaning depends on si_code (SI_USER/SI_TKILL: sender pid).
                        let (spid, addr) = unsafe { (si.si_pid(), si.si_addr() as usize) };
                        note!(
                            ctx,
                            1,
                            "pid {pid}: fatal signal {sig} si_code={} si_pid={spid} si_addr={addr:#x}",
                            si.si_code
                        );
                    }
                    // An `int3` breakpoint is what a program executes when it believes a
                    // debugger is attached and wants it to take over.  Behave like that
                    // debugger: resume past it.  A real crash sequence (`int3; ud2`)
                    // still dies on the `ud2`.
                    if sig == libc::SIGTRAP
                        && si_code == 0x80
                        && let Ok(regs) = Regs::fetch(pid)
                    {
                        let mut byte = [0u8; 1];
                        if ctx
                            .mem
                            .read(pid as u32, regs.ip().wrapping_sub(1), &mut byte)
                            .is_ok()
                            && byte[0] == 0xcc
                        {
                            note!(ctx, 1, "pid {pid}: breakpoint at {:#x} swallowed", regs.ip() - 1);
                            deliver = 0;
                        }
                    }
                    if let Ok(regs) = Regs::fetch(pid) {
                        let ip = regs.ip();
                        let where_ = std::fs::read_to_string(format!("/proc/{pid}/maps"))
                            .ok()
                            .and_then(|m| {
                                m.lines().find_map(|l| {
                                    let mut f = l.split_whitespace();
                                    let range = f.next()?;
                                    let (lo, hi) = range.split_once('-')?;
                                    let (lo, hi) = (
                                        u64::from_str_radix(lo, 16).ok()?,
                                        u64::from_str_radix(hi, 16).ok()?,
                                    );
                                    if ip < lo || ip >= hi {
                                        return None;
                                    }
                                    let _perms = f.next()?;
                                    let off = u64::from_str_radix(f.next()?, 16).ok()?;
                                    let path = f.nth(2).unwrap_or("[anon]");
                                    Some(format!("{path}+{:#x}", ip - lo + off))
                                })
                            })
                            .unwrap_or_else(|| "?".into());
                        note!(ctx, 1, "pid {pid}: ip={ip:#x} in {where_}");
                        note!(ctx, 1, "pid {pid}: {}", address_space_summary(pid));
                    }
                }
            }
            _ => {}
        }
        if let Err(e) = ptrace::cont(pid, deliver)
            && e != libc::ESRCH
        {
            note!(ctx, 1, "pid {pid}: cont: {}", strerror(e));
        }
    }
    exit_code
}

/// One line describing a tracee's address space, for fatal-signal reports:
/// where the heap and stack are, how much is mapped, and the largest free gap
/// below 4 GiB (what a 32-bit process has left to allocate from).
///
/// # Arguments
/// * `pid` - Tracee thread id.
fn address_space_summary(pid: i32) -> String {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return "maps unavailable".into();
    };
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let (mut heap, mut stack, mut total) = (String::from("none"), String::from("none"), 0u64);
    for line in maps.lines() {
        let mut f = line.split_whitespace();
        let Some(range) = f.next() else { continue };
        let Some((lo, hi)) = range.split_once('-') else {
            continue;
        };
        let (Ok(lo), Ok(hi)) = (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16)) else {
            continue;
        };
        total += hi - lo;
        ranges.push((lo, hi));
        match f.nth(4) {
            Some("[heap]") => heap = format!("{lo:#x}-{hi:#x} ({} MiB)", (hi - lo) >> 20),
            Some("[stack]") => stack = format!("{lo:#x}-{hi:#x}"),
            _ => {}
        }
    }
    ranges.sort_unstable();
    let mut gap = 0u64;
    let mut cursor = 0x10000u64;
    for (lo, hi) in &ranges {
        if *lo >= 0xffff_f000 {
            break;
        }
        gap = gap.max(lo.saturating_sub(cursor));
        cursor = cursor.max(*hi);
    }
    gap = gap.max(0xffff_f000u64.saturating_sub(cursor));
    format!(
        "{} mappings, {} MiB mapped, heap {heap}, stack {stack}, largest free gap below 4G {} MiB",
        ranges.len(),
        total >> 20,
        gap >> 20
    )
}

/// Ptrace options for every tracee.
///
/// Tracees always die with the supervisor: once the listener is gone every
/// translated syscall would fail with `ENOSYS`, so an orphaned tracee is
/// never useful.  `--kill-on-exit` is therefore accepted but implied.
pub fn options(ctx: &Ctx) -> i64 {
    let _ = ctx;
    ptrace::DEFAULT_OPTIONS | ptrace::OPTION_EXITKILL
}
