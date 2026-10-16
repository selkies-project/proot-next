//! The guest stub: a `SIGSYS` handler that serves the syscalls the filter
//! traps in the guest-stub restricted mode, where the supervisor cannot
//! reach a guest's memory.  One source for the x86_64, i386, aarch64 and
//! 32-bit ARM builds of the shim; what differs between them is in [`arch`].
//!
//! The handler copies the memory a trapped syscall reads into a mailbox slot
//! (see [`layout`]), makes the call from the notify gate so the supervisor
//! answers it from the copy, copies what it wrote back to the caller's
//! buffers, and stores the result in the saved result register.  The
//! caller's other registers are never touched, so the call returns exactly
//! as a syscall does.  Four cases never reach the supervisor's ordinary
//! handlers:
//!
//! * `execve` and `execveat` are planned by the supervisor from a staged
//!   copy of the path and vectors, which answers with a mailbox descriptor
//!   it installed; the stub then execs the shim (`e` in the alias directory,
//!   the kernel working directory of every guest, by [`layout::SHIM_PATH`])
//!   through the allow gate with the caller's own vectors.  The new shim maps
//!   the mailbox again and loads the program itself, so the stub is in place
//!   from its first instruction.
//! * `rt_sigprocmask` is emulated on the mask saved in the signal frame,
//!   which `rt_sigreturn` restores, with `SIGSYS` kept unblocked: the kernel
//!   kills a process whose trap finds `SIGSYS` blocked.
//! * `rt_sigaction` strips `SIGSYS` from every handler's mask for the same
//!   reason, and for `SIGSYS` itself records the program's handler instead
//!   of installing it; a `SIGSYS` that is not one of the filter's traps is
//!   passed on to it.
//! * i386 `socketcall` carries `bind` and `connect` in an argument array
//!   that points to the address, both of which are staged.
//!
//! The handler runs with `SA_NODEFER` so a signal handler that interrupts it
//! can make trapped syscalls of its own, each in a slot of its own.  It
//! makes every syscall of its own through the allow gate and uses no libc,
//! since the thread pointer belongs to the program.

use crate::layout::{self, Len, Produced, Stage};
use core::sync::atomic::{AtomicU32, Ordering};

/// `si_code` of a `SIGSYS` raised by a seccomp filter.
const SYS_SECCOMP: i32 = 1;
/// The signal the filter's traps raise.
const SIGSYS: usize = 31;
/// `sa_flags` bit naming `sa_restorer`.
const SA_RESTORER: usize = 0x0400_0000;
/// `SIG_DFL`.
const SIG_DFL: usize = 0;
/// `SIG_IGN`.
const SIG_IGN: usize = 1;
/// Mask bit of `SIGSYS`.
const SIGSYS_BIT: u64 = 1 << (SIGSYS - 1);
/// Mask bits the kernel never lets a thread block.
const UNBLOCKABLE: u64 = (1 << (libc::SIGKILL - 1)) | (1 << (libc::SIGSTOP - 1));
/// Size of the alternate signal stack given to the main thread.
const ALT_STACK_SIZE: usize = 64 * 1024;
/// Size of the kernel's signal set.
const SIGSET_SIZE: usize = 8;

/// What differs between the x86_64 and the i386 stub.
#[cfg(target_arch = "x86_64")]
mod arch {
    /// Offset of the general registers in a signal frame's `ucontext`.
    pub const UC_GREGS: usize = 40;
    /// Offset of the saved signal mask in a signal frame's `ucontext`.
    pub const UC_SIGMASK: usize = 296;
    /// Saved registers of the syscall arguments, in argument order: `rdi`,
    /// `rsi`, `rdx`, `r10`, `r8`, `r9`.
    pub const ARG_REGS: [usize; 6] = [8, 9, 12, 2, 0, 1];
    /// Saved register of the result, `rax`.
    pub const RET_REG: usize = 13;
    /// Offset of the syscall number in a `SIGSYS` `siginfo_t`.
    pub const SI_SYSCALL: usize = 24;
    /// `mmap`, whose offset is in bytes.
    pub const SYS_MMAP: isize = libc::SYS_mmap as isize;

    core::arch::global_asm!(
        ".globl proot_stub_restore",
        ".type proot_stub_restore, @function",
        "proot_stub_restore:",
        "mov eax, 15",
        "syscall",
    );

    /// Makes a syscall from the gate at `at`.
    ///
    /// # Arguments
    /// * `at` - [`super::layout::ALLOW_GATE`] or [`super::layout::NOTIFY_GATE`].
    /// * `nr` - Syscall number.
    /// * `a` - Its six arguments.
    ///
    /// # Returns
    /// The raw result, a negative errno on failure.
    ///
    /// # Safety
    /// The gates must be mapped, and the arguments valid for the syscall.
    #[inline(always)]
    pub unsafe fn gate(at: usize, nr: isize, a: [usize; 6]) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
                "lea r12, [rip + 2f]",
                "jmp {at}",
                "2:",
                at = in(reg) at,
                inlateout("rax") nr => ret,
                in("rdi") a[0],
                in("rsi") a[1],
                in("rdx") a[2],
                in("r10") a[3],
                in("r8") a[4],
                in("r9") a[5],
                out("r12") _,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }
}

/// What differs between the x86_64 and the i386 stub.
#[cfg(target_arch = "x86")]
mod arch {
    /// Offset of the general registers in a signal frame's `ucontext`.
    pub const UC_GREGS: usize = 20;
    /// Offset of the saved signal mask in a signal frame's `ucontext`.
    pub const UC_SIGMASK: usize = 108;
    /// Saved registers of the syscall arguments, in argument order: `ebx`,
    /// `ecx`, `edx`, `esi`, `edi`, `ebp`.
    pub const ARG_REGS: [usize; 6] = [8, 10, 9, 5, 4, 6];
    /// Saved register of the result, `eax`.
    pub const RET_REG: usize = 11;
    /// Offset of the syscall number in a `SIGSYS` `siginfo_t`.
    pub const SI_SYSCALL: usize = 16;
    /// `mmap2`, whose offset is in pages.
    pub const SYS_MMAP: isize = libc::SYS_mmap2 as isize;

    core::arch::global_asm!(
        ".globl proot_stub_restore",
        ".type proot_stub_restore, @function",
        "proot_stub_restore:",
        "mov eax, 173",
        "int 0x80",
        ".globl proot_stub_gate",
        ".type proot_stub_gate, @function",
        "proot_stub_gate:",
        "push ebp",
        "push ebx",
        "push esi",
        "push edi",
        "mov eax, [esp + 28]",
        "mov ebx, [eax]",
        "mov ecx, [eax + 4]",
        "mov edx, [eax + 8]",
        "mov esi, [eax + 12]",
        "mov edi, [eax + 16]",
        "mov ebp, [eax + 20]",
        "mov eax, [esp + 24]",
        "call dword ptr [esp + 20]",
        "pop edi",
        "pop esi",
        "pop ebx",
        "pop ebp",
        "ret",
    );

    unsafe extern "C" {
        /// Loads the six arguments from `a` and `nr`, calls the gate at `at`
        /// and returns its result, saving the registers the C ABI preserves.
        ///
        /// # Arguments
        /// * `at` - The gate.
        /// * `nr` - Syscall number.
        /// * `a` - Its six arguments.
        ///
        /// # Returns
        /// The raw result, a negative errno on failure.
        fn proot_stub_gate(at: usize, nr: isize, a: *const usize) -> isize;
    }

    /// Makes a syscall from the gate at `at`.
    ///
    /// # Arguments
    /// * `at` - [`super::layout::ALLOW_GATE`] or [`super::layout::NOTIFY_GATE`].
    /// * `nr` - Syscall number.
    /// * `a` - Its six arguments.
    ///
    /// # Returns
    /// The raw result, a negative errno on failure.
    ///
    /// # Safety
    /// The gates must be mapped, and the arguments valid for the syscall.
    #[inline(always)]
    pub unsafe fn gate(at: usize, nr: isize, a: [usize; 6]) -> isize {
        unsafe { proot_stub_gate(at, nr, a.as_ptr()) }
    }
}

/// What differs between the aarch64 stub and the others.
#[cfg(target_arch = "aarch64")]
mod arch {
    /// Offset of `x0` in a signal frame's `ucontext`: after `uc_flags`,
    /// `uc_link`, `uc_stack`, a 128-byte `uc_sigmask` and, 16-byte aligned,
    /// `fault_address`.
    pub const UC_GREGS: usize = 184;
    /// Offset of the saved signal mask in a signal frame's `ucontext`.
    pub const UC_SIGMASK: usize = 40;
    /// Saved registers of the syscall arguments, `x0` to `x5`.
    pub const ARG_REGS: [usize; 6] = [0, 1, 2, 3, 4, 5];
    /// Saved register of the result, `x0`.
    pub const RET_REG: usize = 0;
    /// Offset of the syscall number in a `SIGSYS` `siginfo_t`.
    pub const SI_SYSCALL: usize = 24;
    /// `mmap`, whose offset is in bytes.
    pub const SYS_MMAP: isize = libc::SYS_mmap as isize;

    core::arch::global_asm!(
        ".globl proot_stub_restore",
        ".type proot_stub_restore, %function",
        "proot_stub_restore:",
        "mov x8, #139",
        "svc #0",
    );

    /// Makes a syscall from the gate at `at`.
    ///
    /// # Arguments
    /// * `at` - [`super::layout::ALLOW_GATE`] or [`super::layout::NOTIFY_GATE`].
    /// * `nr` - Syscall number.
    /// * `a` - Its six arguments.
    ///
    /// # Returns
    /// The raw result, a negative errno on failure.
    ///
    /// # Safety
    /// The gates must be mapped, and the arguments valid for the syscall.
    #[inline(always)]
    pub unsafe fn gate(at: usize, nr: isize, a: [usize; 6]) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
                "adr x16, 2f",
                "br {at}",
                "2:",
                at = in(reg) at,
                inlateout("x0") a[0] => ret,
                in("x1") a[1],
                in("x2") a[2],
                in("x3") a[3],
                in("x4") a[4],
                in("x5") a[5],
                in("x8") nr,
                out("x16") _,
                options(nostack),
            );
        }
        ret
    }

    /// Makes code just written at `start` visible to instruction fetch:
    /// cleans the data cache and invalidates the instruction cache over it,
    /// line by line, as `__clear_cache` does.
    ///
    /// # Arguments
    /// * `start` - First byte written.
    /// * `len` - Bytes written.
    pub fn sync_code(start: usize, len: usize) {
        let ctr: usize;
        unsafe { core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
        let dline = 4 << ((ctr >> 16) & 0xf);
        let iline = 4 << (ctr & 0xf);
        let mut a = start & !(dline - 1);
        while a < start + len {
            unsafe { core::arch::asm!("dc cvau, {}", in(reg) a, options(nostack)) };
            a += dline;
        }
        unsafe { core::arch::asm!("dsb ish", options(nostack)) };
        let mut a = start & !(iline - 1);
        while a < start + len {
            unsafe { core::arch::asm!("ic ivau, {}", in(reg) a, options(nostack)) };
            a += iline;
        }
        unsafe { core::arch::asm!("dsb ish", "isb", options(nostack)) };
    }
}

/// What differs between the 32-bit ARM stub and the others.
#[cfg(target_arch = "arm")]
mod arch {
    /// Offset of `r0` in a signal frame's `ucontext`: after `uc_flags`,
    /// `uc_link`, `uc_stack` and the `trap_no`, `error_code` and `oldmask`
    /// words that start `struct sigcontext`.
    pub const UC_GREGS: usize = 32;
    /// Offset of the saved signal mask in a signal frame's `ucontext`.
    pub const UC_SIGMASK: usize = 104;
    /// Saved registers of the syscall arguments, `r0` to `r5`.
    pub const ARG_REGS: [usize; 6] = [0, 1, 2, 3, 4, 5];
    /// Saved register of the result, `r0`.
    pub const RET_REG: usize = 0;
    /// Offset of the syscall number in a `SIGSYS` `siginfo_t`.
    pub const SI_SYSCALL: usize = 16;
    /// `mmap2`, whose offset is in pages.
    pub const SYS_MMAP: isize = libc::SYS_mmap2 as isize;
    /// The ARM private `cacheflush` call.
    const SYS_CACHEFLUSH: isize = 0x0f_0002;

    core::arch::global_asm!(
        ".arm",
        ".globl proot_stub_restore",
        ".type proot_stub_restore, %function",
        "proot_stub_restore:",
        "mov r7, #173",
        "svc #0",
        ".globl proot_stub_gate",
        ".type proot_stub_gate, %function",
        "proot_stub_gate:",
        "push {{r4, r5, r7, lr}}",
        "mov r12, r0",
        "mov r7, r1",
        "ldr r0, [r2]",
        "ldr r1, [r2, #4]",
        "ldr r3, [r2, #12]",
        "ldr r4, [r2, #16]",
        "ldr r5, [r2, #20]",
        "ldr r2, [r2, #8]",
        "blx r12",
        "pop {{r4, r5, r7, pc}}",
    );

    unsafe extern "C" {
        /// Loads the six arguments from `a` and `nr`, calls the gate at `at`
        /// and returns its result, saving the registers the C ABI preserves.
        ///
        /// # Arguments
        /// * `at` - The gate.
        /// * `nr` - Syscall number.
        /// * `a` - Its six arguments.
        ///
        /// # Returns
        /// The raw result, a negative errno on failure.
        fn proot_stub_gate(at: usize, nr: isize, a: *const usize) -> isize;
    }

    /// Makes a syscall from the gate at `at`.
    ///
    /// # Arguments
    /// * `at` - [`super::layout::ALLOW_GATE`] or [`super::layout::NOTIFY_GATE`].
    /// * `nr` - Syscall number.
    /// * `a` - Its six arguments.
    ///
    /// # Returns
    /// The raw result, a negative errno on failure.
    ///
    /// # Safety
    /// The gates must be mapped, and the arguments valid for the syscall.
    #[inline(always)]
    pub unsafe fn gate(at: usize, nr: isize, a: [usize; 6]) -> isize {
        unsafe { proot_stub_gate(at, nr, a.as_ptr()) }
    }

    /// Makes code just written at `start` visible to instruction fetch,
    /// through the kernel's `cacheflush`.
    ///
    /// # Arguments
    /// * `start` - First byte written.
    /// * `len` - Bytes written.
    pub fn sync_code(start: usize, len: usize) {
        unsafe { libc::syscall(SYS_CACHEFLUSH as libc::c_long, start, start + len, 0) };
    }
}

/// Makes code just written at `start` visible to instruction fetch; x86
/// keeps its caches coherent itself.
///
/// # Arguments
/// * `_start` - First byte written.
/// * `_len` - Bytes written.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn sync_code(_start: usize, _len: usize) {}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
use arch::sync_code;

unsafe extern "C" {
    /// Calls `rt_sigreturn`; the restorer of the stub's handler.
    fn proot_stub_restore();
}

/// The kernel's `struct sigaction` as `rt_sigaction` reads it: handler,
/// flags, restorer, then the 64-bit mask as two words, which keeps it at
/// `3 * sizeof(long)` on both ABIs.
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelAction {
    /// The handler, or `SIG_DFL`, `SIG_IGN`.
    handler: usize,
    /// `SA_*` flags.
    flags: usize,
    /// Where the handler returns to, with `SA_RESTORER`.
    restorer: usize,
    /// Signals blocked while the handler runs, low word first.
    mask: [u32; 2],
}

impl KernelAction {
    /// The default action.
    const DEFAULT: KernelAction = KernelAction {
        handler: SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: [0, 0],
    };

    /// The signal mask.
    ///
    /// # Returns
    /// The mask as one 64-bit set.
    fn mask(&self) -> u64 {
        self.mask[0] as u64 | ((self.mask[1] as u64) << 32)
    }

    /// Replaces the signal mask.
    ///
    /// # Arguments
    /// * `m` - The new mask as one 64-bit set.
    fn set_mask(&mut self, m: u64) {
        self.mask = [m as u32, (m >> 32) as u32];
    }
}

/// The program's own `SIGSYS` action.
static mut CHAINED: KernelAction = KernelAction::DEFAULT;

/// Alternate signal stack of the main thread.
static mut ALT_STACK: [u8; ALT_STACK_SIZE] = [0; ALT_STACK_SIZE];

/// Makes a syscall the filter lets through untouched.
///
/// # Arguments
/// * `nr` - Syscall number.
/// * `a` - Its six arguments.
///
/// # Returns
/// The raw result, a negative errno on failure.
pub fn sys(nr: isize, a: [usize; 6]) -> isize {
    unsafe { arch::gate(layout::ALLOW_GATE, nr, a) }
}

/// Makes a syscall the filter sends to the supervisor.
///
/// # Arguments
/// * `nr` - Syscall number.
/// * `a` - Its six arguments.
///
/// # Returns
/// The raw result, a negative errno on failure.
fn notify(nr: isize, a: [usize; 6]) -> isize {
    unsafe { arch::gate(layout::NOTIFY_GATE, nr, a) }
}

/// A negative errno as a syscall result.
///
/// # Arguments
/// * `e` - The errno.
///
/// # Returns
/// `-e`.
fn err(e: i32) -> isize {
    -(e as isize)
}

/// Whether a raw syscall result is an error: -4095 to -1.  On i386 an
/// address above 2 GiB is negative as a signed word too.
///
/// # Arguments
/// * `r` - The raw result.
///
/// # Returns
/// `true` for an error.
pub fn failed(r: isize) -> bool {
    (-4095..0).contains(&r)
}

/// Maps the gate page.
///
/// Harmless where the filter knows no gates: a syscall made from one is
/// then an ordinary syscall.
///
/// # Returns
/// `true` once the gates can be called.
pub fn map_gates() -> bool {
    unsafe {
        let page = libc::mmap(
            layout::GATE_ADDR as *mut libc::c_void,
            layout::PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        if page == libc::MAP_FAILED {
            return false;
        }
        if page as usize != layout::GATE_ADDR {
            libc::munmap(page, layout::PAGE);
            return false;
        }
        for at in [layout::ALLOW_GATE, layout::NOTIFY_GATE] {
            core::ptr::copy_nonoverlapping(
                layout::GATE_CODE.as_ptr(),
                at as *mut u8,
                layout::GATE_CODE.len(),
            );
        }
        sync_code(layout::GATE_ADDR, layout::PAGE);
        libc::mprotect(page, layout::PAGE, libc::PROT_READ | libc::PROT_EXEC) == 0
    }
}

/// Maps the mailbox from `mail_fd`, which it closes, and arms the handler.
///
/// The main thread gets an alternate signal stack; other threads take the
/// trap on their own stack unless they set one.  A `SIG_IGN` inherited
/// across the exec is kept as the program's action, and `SIGSYS` is
/// unblocked.
///
/// # Arguments
/// * `mail_fd` - Descriptor of the mailbox memfd, installed by the supervisor.
///
/// # Returns
/// `Ok` once armed.
///
/// # Errors
/// The errno of the step that failed.
pub fn install(mail_fd: i32) -> Result<(), i32> {
    let mail = sys(
        arch::SYS_MMAP,
        [
            layout::MAIL_ADDR,
            layout::MAIL_SIZE,
            (libc::PROT_READ | libc::PROT_WRITE) as usize,
            (libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE) as usize,
            mail_fd as usize,
            0,
        ],
    );
    sys(libc::SYS_close as isize, [mail_fd as usize, 0, 0, 0, 0, 0]);
    if failed(mail) {
        return Err(-mail as i32);
    }
    if mail as usize != layout::MAIL_ADDR {
        sys(
            libc::SYS_munmap as isize,
            [mail as usize, layout::MAIL_SIZE, 0, 0, 0, 0],
        );
        return Err(libc::EEXIST);
    }
    let stack = [core::ptr::addr_of_mut!(ALT_STACK) as usize, 0, ALT_STACK_SIZE];
    sys(
        libc::SYS_sigaltstack as isize,
        [stack.as_ptr() as usize, 0, 0, 0, 0, 0],
    );
    let act = KernelAction {
        handler: handler as usize,
        flags: (libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER | libc::SA_RESTART) as usize
            | SA_RESTORER,
        restorer: proot_stub_restore as usize,
        mask: [0, 0],
    };
    let mut old = KernelAction::DEFAULT;
    let rc = sys(
        libc::SYS_rt_sigaction as isize,
        [
            SIGSYS,
            &act as *const KernelAction as usize,
            &mut old as *mut KernelAction as usize,
            SIGSET_SIZE,
            0,
            0,
        ],
    );
    if rc < 0 {
        return Err(-rc as i32);
    }
    if old.handler == SIG_IGN {
        unsafe { core::ptr::addr_of_mut!(CHAINED).write(old) };
    }
    let unblock = SIGSYS_BIT;
    sys(
        libc::SYS_rt_sigprocmask as isize,
        [
            libc::SIG_UNBLOCK as usize,
            &unblock as *const u64 as usize,
            0,
            SIGSET_SIZE,
            0,
            0,
        ],
    );
    Ok(())
}

/// Tells the supervisor that the exec it planned for this process happened.
pub fn hello() {
    notify(
        layout::HELLO as isize,
        [layout::HELLO_MARK as usize, 0, 0, 0, 0, 0],
    );
}

/// The mailbox's slot owners.
///
/// # Returns
/// One thread id or 0 per slot, in the mailbox's first page.
fn owners() -> &'static [AtomicU32; layout::SLOTS] {
    unsafe { &*(layout::MAIL_ADDR as *const [AtomicU32; layout::SLOTS]) }
}

/// Claims a free slot for the calling thread, waiting for one if none is.
///
/// A slot whose owner thread no longer exists is taken back.
///
/// # Returns
/// The slot number.
fn claim() -> usize {
    let tid = sys(libc::SYS_gettid as isize, [0; 6]) as u32;
    let owners = owners();
    let start = tid as usize % layout::SLOTS;
    loop {
        for k in 0..layout::SLOTS {
            let i = (start + k) % layout::SLOTS;
            if owners[i].load(Ordering::Relaxed) == 0
                && owners[i]
                    .compare_exchange(0, tid, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return i;
            }
        }
        for owner in owners.iter() {
            let o = owner.load(Ordering::Relaxed);
            if o != 0 && sys(libc::SYS_kill as isize, [o as usize, 0, 0, 0, 0, 0]) == err(libc::ESRCH) {
                let _ = owner.compare_exchange(o, 0, Ordering::Relaxed, Ordering::Relaxed);
            }
        }
        sys(libc::SYS_sched_yield as isize, [0; 6]);
    }
}

/// Gives a slot back.
///
/// # Arguments
/// * `slot` - A slot from [`claim`].
fn release(slot: usize) {
    owners()[slot].store(0, Ordering::Release);
}

/// Hands out the space of one slot.
struct Bump {
    /// The next free byte.
    cur: usize,
    /// The end of the slot.
    end: usize,
}

impl Bump {
    /// The whole of a slot.
    ///
    /// # Arguments
    /// * `slot` - A slot from [`claim`].
    ///
    /// # Returns
    /// The slot's space, all of it free.
    fn new(slot: usize) -> Bump {
        let cur = layout::slot_addr(slot);
        Bump {
            cur,
            end: cur + layout::SLOT_SIZE,
        }
    }

    /// Bytes still free.
    ///
    /// # Returns
    /// The room left in the slot.
    fn room(&self) -> usize {
        self.end - self.cur
    }

    /// Takes `len` bytes, 16-byte aligned.
    ///
    /// # Arguments
    /// * `len` - Bytes to take.
    ///
    /// # Returns
    /// Their address, or `None` when the slot is full.
    fn take(&mut self, len: usize) -> Option<usize> {
        if len > self.room() {
            return None;
        }
        let at = self.cur;
        self.cur = ((self.cur + len + 15) & !15).min(self.end);
        Some(at)
    }
}

/// Copies the NUL-terminated string at `src` to `dst`.
///
/// # Arguments
/// * `src` - The string in the caller's memory.
/// * `dst` - Where to copy it.
/// * `max` - Room at `dst`, terminating NUL included.
///
/// # Returns
/// The bytes copied, NUL included, or `None` when no NUL came within `max`.
unsafe fn copy_str(src: usize, dst: usize, max: usize) -> Option<usize> {
    let (s, d) = (src as *const u8, dst as *mut u8);
    for i in 0..max {
        let b = unsafe { s.add(i).read_volatile() };
        unsafe { d.add(i).write(b) };
        if b == 0 {
            return Some(i + 1);
        }
    }
    None
}

/// Length of a NUL-terminated string.
///
/// # Arguments
/// * `s` - Address of the string.
///
/// # Returns
/// Its length without the NUL.
unsafe fn strlen(s: usize) -> usize {
    let mut n = 0;
    while unsafe { (s as *const u8).add(n).read_volatile() } != 0 {
        n += 1;
    }
    n
}

/// Copies bytes.
///
/// # Arguments
/// * `src` - Where from.
/// * `dst` - Where to.
/// * `len` - How many.
unsafe fn copy(src: usize, dst: usize, len: usize) {
    for i in 0..len {
        unsafe {
            (dst as *mut u8)
                .add(i)
                .write((src as *const u8).add(i).read_volatile())
        };
    }
}

/// The length a [`Len`] names.
///
/// # Arguments
/// * `len` - The length's description.
/// * `a` - The syscall's arguments.
///
/// # Returns
/// The length in bytes.
fn length(len: Len, a: &[usize; 6]) -> usize {
    match len {
        Len::Fixed(n) => n,
        Len::Arg(i) => a[i],
        Len::Elems(i, size) => a[i].saturating_mul(size),
    }
}

/// The handler installed for `SIGSYS`.
///
/// # Arguments
/// * `sig` - The signal number.
/// * `si` - The kernel's `siginfo_t`.
/// * `uc` - The kernel's `ucontext_t`, whose saved registers and mask take effect on return.
unsafe extern "C" fn handler(sig: i32, si: *mut u8, uc: *mut u8) {
    unsafe {
        let data = (si.add(4) as *const i32).read();
        let code = (si.add(8) as *const i32).read();
        if code != SYS_SECCOMP || data != layout::TAG as i32 {
            chain(sig, si, uc);
            return;
        }
        let nr = (si.add(arch::SI_SYSCALL) as *const i32).read() as isize;
        let g = uc.add(arch::UC_GREGS) as *mut usize;
        let mut a = [0usize; 6];
        for (i, r) in arch::ARG_REGS.iter().enumerate() {
            a[i] = g.add(*r).read();
        }
        let ret = match nr {
            n if n == libc::SYS_rt_sigprocmask as isize => sigprocmask(uc.add(arch::UC_SIGMASK), a),
            n if n == libc::SYS_rt_sigaction as isize => sigaction(a),
            n if n == libc::SYS_execve as isize || n == libc::SYS_execveat as isize => exec(nr, a),
            #[cfg(target_arch = "x86")]
            n if n as i64 == layout::SOCKETCALL_I386 => socketcall(a),
            _ => match layout::staging(nr as i64) {
                Some(spec) => forward(nr, a, spec),
                None => sys(nr, a),
            },
        };
        g.add(arch::RET_REG).write(ret as usize);
    }
}

/// Stages a syscall's memory, has the supervisor serve it, and copies its
/// output back.
///
/// # Arguments
/// * `nr` - Syscall number.
/// * `a` - Its arguments as the caller passed them.
/// * `spec` - Its memory, from [`layout::staging`].
///
/// # Returns
/// The syscall's result.
unsafe fn forward(nr: isize, mut a: [usize; 6], spec: &[(usize, Stage)]) -> isize {
    let slot = claim();
    let mut room = Bump::new(slot);
    let mut outs = [(0usize, 0usize, 0usize, Produced::Whole); 3];
    let mut nouts = 0;
    let mut ret = 0isize;
    for &(i, stage) in spec {
        let p = a[i];
        if p == 0 {
            continue;
        }
        match stage {
            Stage::Path => {
                let Some(dst) = room.take(layout::PATH_AREA) else {
                    ret = err(libc::ENAMETOOLONG);
                    break;
                };
                if unsafe { copy_str(p, dst, layout::PATH_AREA) }.is_none() {
                    ret = err(libc::ENAMETOOLONG);
                    break;
                }
                a[i] = dst;
            }
            Stage::In { len, max, too_big } => {
                let n = length(len, &a);
                if n > max {
                    ret = err(too_big);
                    break;
                }
                let Some(dst) = room.take(n) else {
                    ret = err(too_big);
                    break;
                };
                unsafe { copy(p, dst, n) };
                a[i] = dst;
            }
            Stage::Out(len, produced) => {
                let want = length(len, &a);
                let unit = match len {
                    Len::Elems(_, size) => size,
                    _ => 1,
                };
                let n = want.min(room.room() / unit * unit);
                if n < want {
                    match len {
                        Len::Arg(k) => a[k] = n,
                        Len::Elems(k, size) => a[k] = n / size,
                        Len::Fixed(_) => {}
                    }
                }
                let dst = room.take(n).unwrap_or(p);
                a[i] = dst;
                outs[nouts] = (p, dst, n, produced);
                nouts += 1;
            }
        }
    }
    if ret == 0 {
        ret = notify(nr, a);
        if ret >= 0 {
            for &(to, from, n, produced) in &outs[..nouts] {
                let done = match produced {
                    Produced::Whole if ret == 0 => n,
                    Produced::Whole => 0,
                    Produced::Ret => (ret as usize).min(n),
                    Produced::RetElems(size) => (ret as usize).saturating_mul(size).min(n),
                };
                if from != to {
                    unsafe { copy(from, to, done) };
                }
            }
        }
    }
    release(slot);
    ret
}

/// i386 `socketcall`: `bind` and `connect` have their argument array and
/// the address it points to staged; other calls are not trapped.
///
/// # Arguments
/// * `a` - The call number and the address of its argument array.
///
/// # Returns
/// The call's result.
#[cfg(target_arch = "x86")]
unsafe fn socketcall(a: [usize; 6]) -> isize {
    const BIND: usize = 2;
    const CONNECT: usize = 3;
    let (call, args) = (a[0], a[1]);
    if (call != BIND && call != CONNECT) || args == 0 {
        return sys(layout::SOCKETCALL_I386 as isize, a);
    }
    let v = args as *const usize;
    let (fd, addr, len) = unsafe {
        (
            v.read_volatile(),
            v.add(1).read_volatile(),
            v.add(2).read_volatile(),
        )
    };
    if len > layout::SOCKADDR_MAX {
        return err(libc::EINVAL);
    }
    let slot = claim();
    let mut room = Bump::new(slot);
    let staged = match (addr, room.take(len)) {
        (0, _) | (_, None) => addr,
        (_, Some(dst)) => {
            unsafe { copy(addr, dst, len) };
            dst
        }
    };
    let ret = match room.take(3 * core::mem::size_of::<usize>()) {
        Some(arr) => {
            let w = arr as *mut usize;
            unsafe {
                w.write(fd);
                w.add(1).write(staged);
                w.add(2).write(len);
            }
            notify(layout::SOCKETCALL_I386 as isize, [call, arr, 0, 0, 0, 0])
        }
        None => err(libc::EINVAL),
    };
    release(slot);
    ret
}

/// Stages a vector of strings (`argv`, `envp`).
///
/// # Arguments
/// * `room` - The slot's space.
/// * `vec` - The caller's NULL-terminated pointer array, or 0.
/// * `first` - Stage only its first entry.
///
/// # Returns
/// Address of the staged array (0 for a NULL vector), or `None` when it
/// does not fit.
unsafe fn stage_vector(room: &mut Bump, vec: usize, first: bool) -> Option<usize> {
    if vec == 0 {
        return Some(0);
    }
    let src = vec as *const usize;
    let mut n = 0;
    while unsafe { src.add(n).read_volatile() } != 0 && !(first && n == 1) {
        n += 1;
    }
    let arr = room.take((n + 1) * core::mem::size_of::<usize>())? as *mut usize;
    for i in 0..n {
        let s = unsafe { src.add(i).read_volatile() };
        let len = unsafe { strlen(s) } + 1;
        let dst = room.take(len)?;
        unsafe {
            copy(s, dst, len);
            arr.add(i).write(dst);
        }
    }
    unsafe { arr.add(n).write(0) };
    Some(arr as usize)
}

/// `execve`/`execveat`: the supervisor plans the exec from a staged copy,
/// then the stub execs the shim with the caller's own vectors.
///
/// Vectors too large for the slot are staged as `argv[0]` alone with
/// [`layout::EXEC_TRUNCATED_ARG`] set, which is enough for an ordinary exec
/// since the shim receives the vectors from the kernel.
///
/// # Arguments
/// * `nr` - The `execve` or `execveat` number.
/// * `a` - The caller's arguments.
///
/// # Returns
/// The error of a refused or failed exec; a successful one does not return.
unsafe fn exec(nr: isize, a: [usize; 6]) -> isize {
    let (path, argv, envp) = if nr == libc::SYS_execveat as isize {
        (1, 2, 3)
    } else {
        (0, 1, 2)
    };
    let slot = claim();
    let mut room = Bump::new(slot);
    let mut b = a;
    b[layout::EXEC_TRUNCATED_ARG] = 0;
    if a[path] != 0 {
        let dst = room.take(layout::PATH_AREA).unwrap_or(0);
        if unsafe { copy_str(a[path], dst, layout::PATH_AREA) }.is_none() {
            release(slot);
            return err(libc::ENAMETOOLONG);
        }
        b[path] = dst;
    }
    let mark = room.cur;
    let full = unsafe {
        stage_vector(&mut room, a[argv], false)
            .and_then(|v| stage_vector(&mut room, a[envp], false).map(|e| (v, e)))
    };
    let staged = full.or_else(|| {
        room.cur = mark;
        b[layout::EXEC_TRUNCATED_ARG] = 1;
        let v = unsafe { stage_vector(&mut room, a[argv], true) }?;
        let e = room.take(core::mem::size_of::<usize>())?;
        unsafe { (e as *mut usize).write(0) };
        Some((v, e))
    });
    let Some((v, e)) = staged else {
        release(slot);
        return err(libc::E2BIG);
    };
    b[argv] = v;
    b[envp] = e;
    let mail = notify(nr, b);
    release(slot);
    if mail < 0 {
        return mail;
    }
    let rc = sys(
        libc::SYS_execve as isize,
        [layout::SHIM_PATH.as_ptr() as usize, a[argv], a[envp], 0, 0, 0],
    );
    sys(libc::SYS_close as isize, [mail as usize, 0, 0, 0, 0, 0]);
    rc
}

/// `rt_sigprocmask`, applied to the mask the signal frame restores.
///
/// # Arguments
/// * `mask` - The saved mask in the frame.
/// * `a` - `how`, `set`, `oldset`, `sigsetsize`.
///
/// # Returns
/// 0, or `-EINVAL` as the kernel would answer.
unsafe fn sigprocmask(mask: *mut u8, a: [usize; 6]) -> isize {
    let [how, set, old, size, ..] = a;
    if size != SIGSET_SIZE {
        return err(libc::EINVAL);
    }
    let mask = mask as *mut u64;
    let cur = unsafe { mask.read_unaligned() };
    if set != 0 {
        let s = unsafe { (set as *const u64).read_unaligned() };
        let new = match how as i32 {
            libc::SIG_BLOCK => cur | s,
            libc::SIG_UNBLOCK => cur & !s,
            libc::SIG_SETMASK => s,
            _ => return err(libc::EINVAL),
        };
        if old != 0 {
            unsafe { (old as *mut u64).write_unaligned(cur) };
        }
        unsafe { mask.write_unaligned(new & !(UNBLOCKABLE | SIGSYS_BIT)) };
    } else if old != 0 {
        unsafe { (old as *mut u64).write_unaligned(cur) };
    }
    0
}

/// `rt_sigaction`, keeping `SIGSYS` out of every handler's mask and the
/// stub's handler in place for `SIGSYS`.
///
/// # Arguments
/// * `a` - `signum`, `act`, `oldact`, `sigsetsize`.
///
/// # Returns
/// The kernel's answer, or 0 for `SIGSYS`.
unsafe fn sigaction(a: [usize; 6]) -> isize {
    let [sig, act, old, size, ..] = a;
    if size != SIGSET_SIZE {
        return err(libc::EINVAL);
    }
    if sig == SIGSYS {
        let chained = core::ptr::addr_of_mut!(CHAINED);
        let new = (act != 0).then(|| unsafe { (act as *const KernelAction).read_unaligned() });
        if old != 0 {
            unsafe { (old as *mut KernelAction).write_unaligned(chained.read()) };
        }
        if let Some(new) = new {
            unsafe { chained.write(new) };
        }
        return 0;
    }
    if act == 0 {
        return sys(libc::SYS_rt_sigaction as isize, a);
    }
    let mut own = unsafe { (act as *const KernelAction).read_unaligned() };
    own.set_mask(own.mask() & !SIGSYS_BIT);
    sys(
        libc::SYS_rt_sigaction as isize,
        [sig, &own as *const KernelAction as usize, old, size, 0, 0],
    )
}

/// Passes a `SIGSYS` that is not one of the filter's traps to the program's
/// own action: its handler, nothing for `SIG_IGN`, or death by the signal
/// for `SIG_DFL`.
///
/// # Arguments
/// * `sig` - The signal number.
/// * `si` - The kernel's `siginfo_t`.
/// * `uc` - The kernel's `ucontext_t`.
unsafe fn chain(sig: i32, si: *mut u8, uc: *mut u8) {
    let chained = core::ptr::addr_of_mut!(CHAINED);
    let act = unsafe { chained.read() };
    match act.handler {
        SIG_IGN => {}
        SIG_DFL => {
            let dfl = KernelAction {
                flags: SA_RESTORER,
                restorer: proot_stub_restore as usize,
                ..KernelAction::DEFAULT
            };
            sys(
                libc::SYS_rt_sigaction as isize,
                [SIGSYS, &dfl as *const KernelAction as usize, 0, SIGSET_SIZE, 0, 0],
            );
            let mask = unsafe { uc.add(arch::UC_SIGMASK) } as *mut u64;
            unsafe { mask.write_unaligned(mask.read_unaligned() & !SIGSYS_BIT) };
            let pid = sys(libc::SYS_getpid as isize, [0; 6]) as usize;
            let tid = sys(libc::SYS_gettid as isize, [0; 6]) as usize;
            sys(libc::SYS_tgkill as isize, [pid, tid, SIGSYS, 0, 0, 0]);
        }
        h => {
            if act.flags & libc::SA_RESETHAND as usize != 0 {
                unsafe { chained.write(KernelAction::DEFAULT) };
            }
            if act.flags & libc::SA_SIGINFO as usize != 0 {
                let f: unsafe extern "C" fn(i32, *mut u8, *mut u8) = unsafe { core::mem::transmute(h) };
                unsafe { f(sig, si, uc) };
            } else {
                let f: unsafe extern "C" fn(i32) = unsafe { core::mem::transmute(h) };
                unsafe { f(sig) };
            }
        }
    }
}
