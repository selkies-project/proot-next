//! Builds and installs the classic-BPF seccomp filter.
//!
//! Three tiers: syscalls answered by the supervisor (`USER_NOTIF`), syscalls
//! that need a ptrace stop to edit the tracee in place (`TRACE`), and
//! everything else (`ALLOW`).  Namespace creation is refused with `EPERM`,
//! as a default container refuses it, because a tracee in a mount namespace
//! of its own cannot be served from the supervisor's.  The host's 64-bit ABI
//! and its 32-bit compat ABI each get a number table; any other audit arch
//! (x32) is refused with `ENOSYS`.  A compat table may be empty, which
//! refuses that ABI too.

use crate::abi::Abi;
use crate::sys::*;

/// Mirror of `struct sock_filter`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Mirror of `struct sock_fprog`.
#[repr(C)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JSET_K: u16 = 0x45;
const BPF_JA: u16 = 0x05;
const BPF_RET_K: u16 = 0x06;

/// Offset of the low 32 bits of `seccomp_data.args[i]`.
fn arg_offset(i: usize) -> u32 {
    16 + 8 * i as u32
}

/// One ABI's share of the filter: its audit arch and its number lists.
pub struct Table<'a> {
    pub abi: Abi,
    pub notify: &'a [i64],
    pub trace: &'a [i64],
    /// Syscalls whose first argument is refused with `EPERM` when it carries
    /// a `CLONE_NEW*` bit (`clone`, `unshare`).
    pub ns_flags: &'a [i64],
    /// Syscalls refused with `EPERM` outright (`setns`).
    pub refused: &'a [i64],
}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
fn jump(k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: BPF_JEQ_K,
        jt,
        jf,
        k,
    }
}

/// A table entry that needs to look at an argument before deciding.
#[derive(Clone, Copy)]
enum Sub {
    /// `open`-family: flags argument `arg` with `O_PATH` set goes to the tracer.
    OPath { arg: usize },
    /// `socketcall`: calls 2 (`bind`) and 3 (`connect`) go to the tracer, the rest are allowed.
    Socketcall,
    /// `clone`/`unshare`: a `CLONE_NEW*` bit in the first argument is refused.
    NsFlags,
}

impl Sub {
    fn len(self) -> usize {
        match self {
            Sub::OPath { .. } => 3,
            Sub::Socketcall => 4,
            Sub::NsFlags => 3,
        }
    }
}

/// Builds the filter program.
///
/// `O_PATH` opens are routed to the tracer by inspecting the flags argument,
/// because such descriptors cannot be injected with ADDFD; an i386
/// `socketcall` is routed there for `bind` and `connect` only.  Without a
/// tracer (`no_trace`) both go to the listener instead, like every entry of
/// the trace lists.
///
/// # Arguments
/// * `t64` - The host's 64-bit ABI and its syscall lists.
/// * `t32` - The host's 32-bit compat ABI and its lists (may be empty).
/// * `no_trace` - Serve the trace tier through user notification.
///
/// # Returns
/// The instruction list, ready for `seccomp(2)`.
pub fn build(t64: &Table, t32: &Table, no_trace: bool) -> Vec<SockFilter> {
    // Per table: the (nr, sub) entries placed after the plain notify/trace lists.
    let subs_for = |t: &Table| -> Vec<(i64, Sub)> {
        let mut v: Vec<(i64, Sub)> = t
            .notify
            .iter()
            .filter_map(|nr| t.abi.open_flags_arg(*nr).map(|arg| (*nr, Sub::OPath { arg })))
            .collect();
        if let Some(nr) = t.abi.socketcall_nr() {
            v.push((nr, Sub::Socketcall));
        }
        v.extend(t.ns_flags.iter().map(|nr| (*nr, Sub::NsFlags)));
        v
    };
    let (subs64, subs32) = (subs_for(t64), subs_for(t32));
    // A notify entry that has a sub-block is routed through it, not straight to NOTIF.
    let plain64: Vec<i64> = t64
        .notify
        .iter()
        .copied()
        .filter(|nr| t64.abi.open_flags_arg(*nr).is_none())
        .collect();
    let plain32: Vec<i64> = t32
        .notify
        .iter()
        .copied()
        .filter(|nr| t32.abi.open_flags_arg(*nr).is_none())
        .collect();
    let n64 = plain64.len() + t64.trace.len() + t64.refused.len() + subs64.len();
    let n32 = plain32.len() + t32.trace.len() + t32.refused.len() + subs32.len();
    let sub_len: usize = subs64.iter().chain(subs32.iter()).map(|(_, s)| s.len()).sum();
    let total = 4 + n64 + 2 + n32 + 1 + sub_len + 5;
    assert!(total < 255, "filter too large for 8-bit jump offsets");
    // Layout (indices):
    //   0      ld arch
    //   1      jeq arch64 -> 3 ; else -> 2
    //   2      jeq arch32 -> T32 ; else -> E
    //   3      ld nr
    //   4..    64-bit table: plain notify, trace, refused, sub entries
    //   A      ret ALLOW
    //   T32    ld nr
    //   T32+1.. 32-bit table
    //   A2     ret ALLOW
    //   S..    sub-blocks
    //   N      ret NOTIF
    //   T      ret TRACE
    //   E      ret ERRNO(ENOSYS)
    //   P      ret ERRNO(EPERM)
    //   A3     ret ALLOW (for sub-blocks, which cannot jump backwards)
    let a = 4 + n64;
    let t32_idx = a + 1;
    let a2 = t32_idx + 1 + n32;
    let sub_base = a2 + 1;
    let n_idx = sub_base + sub_len;
    let t_idx = if no_trace { n_idx } else { n_idx + 1 };
    let e_idx = n_idx + 2;
    let p_idx = e_idx + 1;
    let a3_idx = e_idx + 2;
    let off = |from: usize, to: usize| (to - from - 1) as u8;
    // Start index of sub-block k (over the concatenation of subs64 and subs32).
    let sub_index = |k: usize| -> usize {
        sub_base
            + subs64
                .iter()
                .chain(subs32.iter())
                .take(k)
                .map(|(_, s)| s.len())
                .sum::<usize>()
    };
    let mut f = Vec::with_capacity(total);
    f.push(stmt(BPF_LD_W_ABS, 4));
    f.push(jump(t64.abi.audit(), 1, 0));
    if n32 == 0 {
        f.push(jump(t32.abi.audit(), off(2, e_idx), off(2, e_idx)));
    } else {
        f.push(jump(t32.abi.audit(), off(2, t32_idx), off(2, e_idx)));
    }
    f.push(stmt(BPF_LD_W_ABS, 0));
    let emit_table = |f: &mut Vec<SockFilter>,
                      start: usize,
                      plain: &[i64],
                      trace: &[i64],
                      refused: &[i64],
                      subs: &[(i64, Sub)],
                      k0: usize| {
        let mut i = start;
        for nr in plain {
            f.push(jump(*nr as u32, off(i, n_idx), 0));
            i += 1;
        }
        for nr in trace {
            f.push(jump(*nr as u32, off(i, t_idx), 0));
            i += 1;
        }
        for nr in refused {
            f.push(jump(*nr as u32, off(i, p_idx), 0));
            i += 1;
        }
        for (k, (nr, _)) in subs.iter().enumerate() {
            f.push(jump(*nr as u32, off(i, sub_index(k0 + k)), 0));
            i += 1;
        }
    };
    emit_table(&mut f, 4, &plain64, t64.trace, t64.refused, &subs64, 0);
    f.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    f.push(stmt(BPF_LD_W_ABS, 0));
    emit_table(
        &mut f,
        t32_idx + 1,
        &plain32,
        t32.trace,
        t32.refused,
        &subs32,
        subs64.len(),
    );
    f.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    for (k, (_, sub)) in subs64.iter().chain(subs32.iter()).enumerate() {
        let here = sub_index(k);
        match *sub {
            Sub::OPath { arg } => {
                f.push(stmt(BPF_LD_W_ABS, arg_offset(arg)));
                f.push(SockFilter {
                    code: BPF_JSET_K,
                    jt: off(here + 1, t_idx),
                    jf: 0,
                    k: libc::O_PATH as u32,
                });
                f.push(SockFilter {
                    code: BPF_JA,
                    jt: 0,
                    jf: 0,
                    k: off(here + 2, n_idx) as u32,
                });
            }
            Sub::Socketcall => {
                f.push(stmt(BPF_LD_W_ABS, arg_offset(0)));
                f.push(jump(2, off(here + 1, t_idx), 0)); // SYS_BIND
                f.push(jump(3, off(here + 2, t_idx), 0)); // SYS_CONNECT
                // BPF cannot jump backwards to the table's ALLOW, so the other
                // calls go forward to the trailing ALLOW.
                f.push(SockFilter {
                    code: BPF_JA,
                    jt: 0,
                    jf: 0,
                    k: off(here + 3, a3_idx) as u32,
                });
            }
            Sub::NsFlags => {
                f.push(stmt(BPF_LD_W_ABS, arg_offset(0)));
                f.push(SockFilter {
                    code: BPF_JSET_K,
                    jt: off(here + 1, p_idx),
                    jf: 0,
                    k: crate::syscall::CLONE_NEWNS_FLAGS as u32,
                });
                f.push(SockFilter {
                    code: BPF_JA,
                    jt: 0,
                    jf: 0,
                    k: off(here + 2, a3_idx) as u32,
                });
            }
        }
    }
    f.push(stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF));
    f.push(stmt(BPF_RET_K, SECCOMP_RET_TRACE));
    f.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
    f.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    // Trailing ALLOW for sub-blocks that fall through.
    f.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    debug_assert_eq!(f.len(), a3_idx + 1);
    f
}

/// Installs `program` in the calling thread and returns the listener fd.
///
/// Must run in the child, after `PR_SET_NO_NEW_PRIVS` and `PTRACE_TRACEME`,
/// before `execve`.  Async-signal-safe: no allocation.
///
/// # Arguments
/// * `program` - Filter from [`build`].
///
/// # Errors
/// Errno from `seccomp(2)`; `EINVAL` on a kernel without user notification.
pub fn install(program: &[SockFilter]) -> Result<i32> {
    let prog = SockFprog {
        len: program.len() as u16,
        filter: program.as_ptr(),
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const _,
        )
    };
    check(fd).map(|fd| fd as i32)
}

/// Decodes a raw classic-BPF program as bubblewrap receives it on `--seccomp FD`.
///
/// # Arguments
/// * `bytes` - Concatenated `struct sock_filter` records (8 bytes each).
///
/// # Errors
/// A message when the length is not a multiple of 8, empty, or too long.
pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Vec<SockFilter>, String> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) {
        return Err(format!(
            "{} bytes is not a whole number of BPF instructions",
            bytes.len()
        ));
    }
    if bytes.len() / 8 > 4096 {
        return Err("program longer than BPF_MAXINSNS".into());
    }
    Ok(bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| SockFilter {
            code: u16::from_ne_bytes([c[0], c[1]]),
            jt: c[2],
            jf: c[3],
            k: u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
        })
        .collect())
}

/// Installs a caller-supplied program without a listener (stacks on ours).
///
/// Must run in the child before `execve`.  Async-signal-safe.
///
/// # Arguments
/// * `program` - Decoded filter.
pub fn install_plain(program: &[SockFilter]) -> Result<()> {
    let prog = SockFprog {
        len: program.len() as u16,
        filter: program.as_ptr(),
    };
    check(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0u64,
            &prog as *const _,
        )
    })
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Interprets the subset of BPF we emit, returning the action for (arch, nr, args).
    fn run_args(prog: &[SockFilter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let mut pc = 0usize;
        let mut acc = 0u32;
        loop {
            let i = prog[pc];
            match i.code {
                BPF_LD_W_ABS => {
                    acc = match i.k {
                        0 => nr,
                        4 => arch,
                        k => args[((k - 16) / 8) as usize] as u32,
                    }
                }
                BPF_JEQ_K => pc += if acc == i.k { i.jt as usize } else { i.jf as usize },
                BPF_JSET_K => {
                    pc += if acc & i.k != 0 {
                        i.jt as usize
                    } else {
                        i.jf as usize
                    }
                }
                BPF_JA => pc += i.k as usize,
                BPF_RET_K => return i.k,
                _ => panic!("unknown op"),
            }
            pc += 1;
        }
    }

    fn run(prog: &[SockFilter], arch: u32, nr: u32) -> u32 {
        run_args(prog, arch, nr, [0; 6])
    }

    #[test]
    fn routes_each_tier() {
        let p = build(
            &Table {
                abi: Abi::X86_64,
                notify: &[2, 257],
                trace: &[59, 80],
                ns_flags: &[56, 272],
                refused: &[308],
            },
            &Table {
                abi: Abi::I386,
                notify: &[5, 295],
                trace: &[11, 12],
                ns_flags: &[120, 310],
                refused: &[346],
            },
            false,
        );
        let eperm = SECCOMP_RET_ERRNO | libc::EPERM as u32;
        assert_eq!(
            run_args(&p, AUDIT_ARCH_X86_64, 56, [0x1200011, 0, 0, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            run_args(&p, AUDIT_ARCH_X86_64, 56, [0x10000011, 0, 0, 0, 0, 0]),
            eperm
        );
        assert_eq!(
            run_args(&p, AUDIT_ARCH_X86_64, 272, [0x20000, 0, 0, 0, 0, 0]),
            eperm
        );
        assert_eq!(
            run_args(&p, AUDIT_ARCH_X86_64, 272, [0x200, 0, 0, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(run_args(&p, AUDIT_ARCH_X86_64, 308, [0; 6]), eperm);
        assert_eq!(
            run_args(&p, AUDIT_ARCH_I386, 120, [0x10000011, 0, 0, 0, 0, 0]),
            eperm
        );
        assert_eq!(
            run_args(&p, AUDIT_ARCH_I386, 102, [1, 0, 0, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(run(&p, AUDIT_ARCH_X86_64, 2), SECCOMP_RET_USER_NOTIF);
        assert_eq!(run(&p, AUDIT_ARCH_X86_64, 257), SECCOMP_RET_USER_NOTIF);
        assert_eq!(run(&p, AUDIT_ARCH_X86_64, 59), SECCOMP_RET_TRACE);
        assert_eq!(run(&p, AUDIT_ARCH_X86_64, 80), SECCOMP_RET_TRACE);
        assert_eq!(run(&p, AUDIT_ARCH_X86_64, 39), SECCOMP_RET_ALLOW);
        assert_eq!(run(&p, AUDIT_ARCH_I386, 5), SECCOMP_RET_USER_NOTIF);
        assert_eq!(run(&p, AUDIT_ARCH_I386, 295), SECCOMP_RET_USER_NOTIF);
        assert_eq!(run(&p, AUDIT_ARCH_I386, 11), SECCOMP_RET_TRACE);
        assert_eq!(run(&p, AUDIT_ARCH_I386, 12), SECCOMP_RET_TRACE);
        assert_eq!(run(&p, AUDIT_ARCH_I386, 2), SECCOMP_RET_ALLOW);
        assert_eq!(run(&p, 0xc000_00b7, 5), SECCOMP_RET_ERRNO | libc::ENOSYS as u32);
        // O_PATH opens are traced, plain opens notified, on both ABIs.
        let opath = libc::O_PATH as u64;
        assert_eq!(
            run_args(&p, AUDIT_ARCH_X86_64, 257, [0, 0, opath | 2, 0, 0, 0]),
            SECCOMP_RET_TRACE
        );
        assert_eq!(
            run_args(&p, AUDIT_ARCH_X86_64, 257, [0, 0, 2, 0, 0, 0]),
            SECCOMP_RET_USER_NOTIF
        );
        assert_eq!(
            run_args(&p, AUDIT_ARCH_X86_64, 2, [0, opath, 0, 0, 0, 0]),
            SECCOMP_RET_TRACE
        );
        assert_eq!(
            run_args(&p, AUDIT_ARCH_I386, 295, [0, 0, opath, 0, 0, 0]),
            SECCOMP_RET_TRACE
        );
        assert_eq!(
            run_args(&p, AUDIT_ARCH_I386, 5, [0, 0, 0, 0, 0, 0]),
            SECCOMP_RET_USER_NOTIF
        );
        // aarch64 host: generic numbers, empty compat table refuses 32-bit ARM.
        let q = build(
            &Table {
                abi: Abi::Aarch64,
                notify: &[56, 79],
                trace: &[221],
                ns_flags: &[],
                refused: &[],
            },
            &Table {
                abi: Abi::Arm,
                notify: &[],
                trace: &[],
                ns_flags: &[],
                refused: &[],
            },
            false,
        );
        assert_eq!(
            run_args(&q, AUDIT_ARCH_AARCH64, 56, [0, 0, 0, 0, 0, 0]),
            SECCOMP_RET_USER_NOTIF
        );
        assert_eq!(
            run_args(&q, AUDIT_ARCH_AARCH64, 56, [0, 0, opath, 0, 0, 0]),
            SECCOMP_RET_TRACE
        );
        assert_eq!(run_args(&q, AUDIT_ARCH_AARCH64, 221, [0; 6]), SECCOMP_RET_TRACE);
        assert_eq!(run_args(&q, AUDIT_ARCH_AARCH64, 63, [0; 6]), SECCOMP_RET_ALLOW);
        assert_eq!(
            run(&q, AUDIT_ARCH_ARM, 5),
            SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
    }

    #[test]
    fn without_a_tracer_everything_is_notified() {
        let p = build(
            &Table {
                abi: Abi::X86_64,
                notify: &[2, 59, 257],
                trace: &[],
                ns_flags: &[272],
                refused: &[],
            },
            &Table {
                abi: Abi::I386,
                notify: &[5, 11, 295],
                trace: &[],
                ns_flags: &[],
                refused: &[],
            },
            true,
        );
        let opath = libc::O_PATH as u64;
        assert_eq!(run(&p, AUDIT_ARCH_X86_64, 59), SECCOMP_RET_USER_NOTIF);
        assert_eq!(
            run_args(&p, AUDIT_ARCH_X86_64, 257, [0, 0, opath, 0, 0, 0]),
            SECCOMP_RET_USER_NOTIF
        );
        assert_eq!(
            run_args(&p, AUDIT_ARCH_I386, 102, [3, 0, 0, 0, 0, 0]),
            SECCOMP_RET_USER_NOTIF
        );
        assert_eq!(
            run_args(&p, AUDIT_ARCH_I386, 102, [1, 0, 0, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(run(&p, AUDIT_ARCH_I386, 11), SECCOMP_RET_USER_NOTIF);
    }
}
