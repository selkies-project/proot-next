//! The supervisor's side of the guest-stub restricted mode.
//!
//! Where neither ptrace nor a user namespace lets the supervisor reach a
//! guest's memory (see `access`), a stub inside every guest process moves
//! the memory each served syscall uses into a mailbox both sides map.  The
//! stub is part of the exec shim (`exec/shim/src/stub.rs`), which loads
//! every program in place instead of exec'ing it so the stub stays armed;
//! [`layout`] is the contract between the two, compiled into both.
//!
//! Here the mailbox is created and mapped into the supervisor, where
//! `tracee::mem` serves guest addresses inside it and refuses every other,
//! so the handlers in `syscall::notify` and `syscall::direct` read and write
//! the staged copies as if they were the guest's memory.  The first tracee
//! maps the gate page and execs the shim through the allow gate, the one
//! exec the filter lets through without the stub.

#[path = "exec/shim/src/layout.rs"]
#[allow(dead_code)]
pub mod layout;

use crate::sys::errno;

/// The mailbox memfd.  The supervisor's mapping lives as long as the process.
#[derive(Debug)]
pub struct Mailbox {
    /// The memfd, close-on-exec in the supervisor.
    pub fd: i32,
}

impl Mailbox {
    /// Creates the mailbox and maps it into the supervisor, registering the
    /// mapping with `tracee::mem`.
    ///
    /// # Returns
    /// The mailbox.
    ///
    /// # Errors
    /// A message naming the step that failed.
    pub fn create() -> Result<Mailbox, String> {
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"proot-mailbox".as_ptr(),
                libc::MFD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!("memfd_create: {}", crate::sys::strerror(errno())));
        }
        let fd = fd as i32;
        if unsafe { libc::ftruncate(fd, layout::MAIL_SIZE as libc::off_t) } < 0 {
            let e = errno();
            unsafe { libc::close(fd) };
            return Err(format!("sizing the mailbox: {}", crate::sys::strerror(e)));
        }
        let local = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                layout::MAIL_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if local == libc::MAP_FAILED {
            let e = errno();
            unsafe { libc::close(fd) };
            return Err(format!("mapping the mailbox: {}", crate::sys::strerror(e)));
        }
        crate::tracee::mem::set_window(
            &[layout::MAIL64, layout::MAIL32],
            layout::MAIL_SIZE,
            local as *mut u8,
        );
        Ok(Mailbox { fd })
    }
}

/// Execs the trampoline in the first tracee, through the allow gate, with
/// the mailbox descriptor it inherited kept open for it.  Allocation free,
/// for use between `fork` and `execve`.
///
/// # Arguments
/// * `mail` - The mailbox descriptor.
/// * `shim` - Path of the trampoline from the kernel working directory.
/// * `argv` - The command's argument vector.
/// * `envp` - Its environment.
///
/// # Safety
/// The pointers must be valid for `execve`.  Exits the process, with 127
/// when the trampoline is missing and 126 for any other failure.
pub unsafe fn exec_trampoline(
    mail: i32,
    shim: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> ! {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    unsafe {
        libc::fcntl(mail, libc::F_SETFD, 0);
        if map_gates() && exec_through_gate(shim, argv, envp) == -(libc::ENOENT as i64) {
            libc::_exit(127);
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = (mail, shim, argv, envp);
    unsafe { libc::_exit(126) }
}

/// Maps the gate page in the calling process.  Allocation free, for the
/// first tracee between `fork` and its exec of the shim.
///
/// # Returns
/// `true` once the gates can be called.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn map_gates() -> bool {
    unsafe {
        let page = libc::mmap(
            layout::GATE_ADDR as *mut libc::c_void,
            layout::PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        if page as usize != layout::GATE_ADDR {
            return false;
        }
        for at in [layout::ALLOW_GATE, layout::NOTIFY_GATE] {
            std::ptr::copy_nonoverlapping(layout::GATE_CODE.as_ptr(), at as *mut u8, layout::GATE_CODE.len());
        }
        #[cfg(target_arch = "aarch64")]
        sync_code(layout::GATE_ADDR, layout::PAGE);
        libc::mprotect(page, layout::PAGE, libc::PROT_READ | libc::PROT_EXEC) == 0
    }
}

/// Makes code just written at `start` visible to instruction fetch: cleans
/// the data cache and invalidates the instruction cache over it, line by
/// line, as `__clear_cache` does.  Allocation free.
///
/// # Arguments
/// * `start` - First byte written.
/// * `len` - Bytes written.
#[cfg(target_arch = "aarch64")]
fn sync_code(start: usize, len: usize) {
    let ctr: usize;
    unsafe { std::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    let dline = 4 << ((ctr >> 16) & 0xf);
    let iline = 4 << (ctr & 0xf);
    let mut a = start & !(dline - 1);
    while a < start + len {
        unsafe { std::arch::asm!("dc cvau, {}", in(reg) a, options(nostack)) };
        a += dline;
    }
    unsafe { std::arch::asm!("dsb ish", options(nostack)) };
    let mut a = start & !(iline - 1);
    while a < start + len {
        unsafe { std::arch::asm!("ic ivau, {}", in(reg) a, options(nostack)) };
        a += iline;
    }
    unsafe { std::arch::asm!("dsb ish", "isb", options(nostack)) };
}

/// `execve` through the allow gate.  Allocation free.
///
/// # Arguments
/// * `path` - Program to exec.
/// * `argv` - Its argument vector.
/// * `envp` - Its environment.
///
/// # Returns
/// The negative errno of a failed exec; a successful one does not return.
///
/// # Safety
/// [`map_gates`] must have succeeded, and the pointers be valid for `execve`.
#[cfg(target_arch = "x86_64")]
unsafe fn exec_through_gate(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "lea r12, [rip + 2f]",
            "jmp {at}",
            "2:",
            at = in(reg) layout::ALLOW_GATE,
            inlateout("rax") libc::SYS_execve => ret,
            in("rdi") path,
            in("rsi") argv,
            in("rdx") envp,
            out("r12") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// `execve` through the allow gate.  Allocation free.
///
/// # Arguments
/// * `path` - Program to exec.
/// * `argv` - Its argument vector.
/// * `envp` - Its environment.
///
/// # Returns
/// The negative errno of a failed exec; a successful one does not return.
///
/// # Safety
/// [`map_gates`] must have succeeded, and the pointers be valid for `execve`.
#[cfg(target_arch = "aarch64")]
unsafe fn exec_through_gate(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "adr x16, 2f",
            "br {at}",
            "2:",
            at = in(reg) layout::ALLOW_GATE,
            inlateout("x0") path => ret,
            in("x1") argv,
            in("x2") envp,
            in("x8") libc::SYS_execve,
            out("x16") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::layout::*;

    /// The last slot ends where the mailbox does.
    #[test]
    fn slots_fill_the_mailbox() {
        assert_eq!(slot_addr(0), MAIL_ADDR + PAGE);
        assert_eq!(slot_addr(SLOTS - 1) + SLOT_SIZE, MAIL_ADDR + MAIL_SIZE);
    }

    /// Every path syscall the supervisor serves is staged or handled by the
    /// stub, on all four ABIs, and the calls that need only registers are
    /// not trapped.
    #[test]
    fn served_path_syscalls_are_trapped() {
        use crate::abi::Abi;
        use crate::syscall::{NO_PTRACE_SYSCALLS, NOTIFY_SYSCALLS, nr};
        let registers_only = [nr::CLONE, nr::FORK, nr::VFORK, nr::FCHDIR, nr::CLONE3];
        type Trapped = fn(i64) -> bool;
        let tables: [(Abi, Trapped); 4] = [
            (Abi::X86_64, trapped_x86_64),
            (Abi::I386, trapped_i386),
            (Abi::Aarch64, trapped_aarch64),
            (Abi::Arm, trapped_arm),
        ];
        for (abi, trapped) in tables {
            for nr in abi.numbers_for(NOTIFY_SYSCALLS) {
                assert!(trapped(nr), "{abi:?} {nr} is served but not staged");
            }
            for nr in abi.numbers_for(NO_PTRACE_SYSCALLS) {
                let canonical = abi.to_canonical(nr).unwrap().0;
                assert_eq!(trapped(nr), !registers_only.contains(&canonical), "{abi:?} {nr}");
            }
        }
        for nr in [nr::GETUID, nr::FCHOWN, nr::SETUID] {
            assert!(!trapped_x86_64(nr), "{nr}");
        }
    }

    /// Paths and outputs are staged at the arguments the kernel reads them
    /// from, in each ABI's layout.
    #[test]
    fn staging_names_the_right_arguments() {
        assert_eq!(staging_x86_64(262).unwrap()[0], (1, Stage::Path));
        assert_eq!(
            staging_x86_64(262).unwrap()[1],
            (2, Stage::Out(Len::Fixed(144), Produced::Whole))
        );
        assert_eq!(
            staging_x86_64(332).unwrap()[1],
            (4, Stage::Out(Len::Fixed(256), Produced::Whole))
        );
        assert_eq!(
            staging_x86_64(266).unwrap(),
            &[(0, Stage::Path), (2, Stage::Path)]
        );
        assert_eq!(
            staging_x86_64(267).unwrap()[1],
            (2, Stage::Out(Len::Arg(3), Produced::Ret))
        );
        assert_eq!(
            staging_x86_64(79).unwrap()[0],
            (0, Stage::Out(Len::Arg(1), Produced::Ret))
        );
        assert!(staging_x86_64(0).is_none());
        assert_eq!(
            staging_i386(195).unwrap()[1],
            (1, Stage::Out(Len::Fixed(96), Produced::Whole))
        );
        assert_eq!(
            staging_i386(106).unwrap()[1],
            (1, Stage::Out(Len::Fixed(64), Produced::Whole))
        );
        assert_eq!(
            staging_i386(268).unwrap()[1],
            (2, Stage::Out(Len::Fixed(84), Produced::Whole))
        );
        assert_eq!(
            staging_i386(80).unwrap()[0],
            (1, Stage::Out(Len::Elems(0, 2), Produced::RetElems(2)))
        );
        assert_eq!(staging_i386(304).unwrap(), &[(0, Stage::Path), (2, Stage::Path)]);
        assert!(trapped_i386(11) && trapped_i386(174) && !trapped_i386(120));
        assert_eq!(
            staging_aarch64(79).unwrap()[1],
            (2, Stage::Out(Len::Fixed(128), Produced::Whole))
        );
        assert_eq!(
            staging_aarch64(36).unwrap(),
            &[(0, Stage::Path), (2, Stage::Path)]
        );
        assert!(trapped_aarch64(221) && trapped_aarch64(134) && !trapped_aarch64(220));
        assert_eq!(
            staging_arm(327).unwrap()[1],
            (2, Stage::Out(Len::Fixed(104), Produced::Whole))
        );
        assert_eq!(
            staging_arm(266).unwrap()[1],
            (2, Stage::Out(Len::Fixed(84), Produced::Whole))
        );
        assert!(trapped_arm(387) && trapped_arm(174) && !trapped_arm(120));
    }
}
