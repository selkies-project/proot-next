//! Architecture view of a tracee's registers at a syscall-entry stop.
//!
//! Two hosts are supported: x86_64 (also serving i386 tracees) and aarch64.
//! Both expose the same [`Regs`] API; the differences are confined to the
//! `arch` module selected at compile time.

use crate::abi::Abi;
use crate::sys::{RED_ZONE_SIZE, Result};

#[cfg(target_arch = "x86_64")]
mod arch {
    use super::super::ptrace;
    use crate::abi::Abi;
    use crate::sys::Result;

    pub type Raw = libc::user_regs_struct;

    pub fn fetch(pid: i32) -> Result<Raw> {
        ptrace::getregs(pid)
    }

    pub fn store(pid: i32, cur: &Raw, _orig: &Raw) -> Result<()> {
        ptrace::setregs(pid, cur)
    }

    /// `0x23` is the 32-bit compat code segment, `0x33` the 64-bit one.
    pub fn abi(r: &Raw) -> Abi {
        if r.cs == 0x23 { Abi::I386 } else { Abi::X86_64 }
    }

    pub fn sysnum(r: &Raw) -> i64 {
        r.orig_rax as i64
    }

    pub fn set_sysnum(r: &mut Raw, nr: i64) {
        r.orig_rax = nr as u64;
    }

    /// The result a skipped syscall returns: `rax`, `eax` for i386.
    pub fn set_ret(r: &mut Raw, v: i64) {
        r.rax = v as u64;
    }

    pub fn arg(r: &Raw, i: usize) -> u64 {
        match abi(r) {
            Abi::I386 => {
                (match i {
                    0 => r.rbx,
                    1 => r.rcx,
                    2 => r.rdx,
                    3 => r.rsi,
                    4 => r.rdi,
                    _ => r.rbp,
                }) & 0xffff_ffff
            }
            _ => match i {
                0 => r.rdi,
                1 => r.rsi,
                2 => r.rdx,
                3 => r.r10,
                4 => r.r8,
                _ => r.r9,
            },
        }
    }

    pub fn set_arg(r: &mut Raw, i: usize, v: u64) {
        match abi(r) {
            Abi::I386 => {
                let v = v & 0xffff_ffff;
                match i {
                    0 => r.rbx = v,
                    1 => r.rcx = v,
                    2 => r.rdx = v,
                    3 => r.rsi = v,
                    4 => r.rdi = v,
                    _ => r.rbp = v,
                }
            }
            _ => match i {
                0 => r.rdi = v,
                1 => r.rsi = v,
                2 => r.rdx = v,
                3 => r.r10 = v,
                4 => r.r8 = v,
                _ => r.r9 = v,
            },
        }
    }

    pub fn sp(r: &Raw) -> u64 {
        r.rsp
    }

    pub fn ip(r: &Raw) -> u64 {
        r.rip
    }

    pub fn same(a: &Raw, b: &Raw) -> bool {
        let n = std::mem::size_of::<Raw>();
        unsafe {
            std::slice::from_raw_parts(a as *const _ as *const u8, n)
                == std::slice::from_raw_parts(b as *const _ as *const u8, n)
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arch {
    use super::super::ptrace;
    use crate::abi::Abi;
    use crate::sys::Result;

    /// `struct user_pt_regs` for a 64-bit tracee, or the 18-word `struct
    /// user_regs` (r0..r15, cpsr, orig_r0) the kernel reports for a 32-bit one.
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq)]
    pub struct Raw {
        pub regs: [u64; 31],
        pub sp: u64,
        pub pc: u64,
        pub pstate: u64,
        /// The tracee is AArch32: `regs[0..18]` hold the 32-bit view instead.
        pub compat: bool,
        /// Syscall number override, written through `NT_ARM_SYSTEM_CALL` on store.
        pub sysnum_override: Option<i32>,
    }

    const NT_PRSTATUS: u32 = 1;
    const NT_ARM_SYSTEM_CALL: u32 = 0x404;
    const REGS64_LEN: usize = 34 * 8;
    const REGS32_LEN: usize = 18 * 4;

    pub fn fetch(pid: i32) -> Result<Raw> {
        let mut r = Raw {
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
            compat: false,
            sysnum_override: None,
        };
        let mut buf = [0u8; REGS64_LEN];
        let n = ptrace::getregset(pid, NT_PRSTATUS, buf.as_mut_ptr(), REGS64_LEN)?;
        if n == REGS32_LEN {
            r.compat = true;
            for (i, w) in buf[..REGS32_LEN].as_chunks::<4>().0.iter().enumerate() {
                r.regs[i] = u32::from_ne_bytes(*w) as u64;
            }
            r.sp = r.regs[13];
            r.pc = r.regs[15];
            r.pstate = r.regs[16];
        } else {
            for (i, w) in buf[..31 * 8].as_chunks::<8>().0.iter().enumerate() {
                r.regs[i] = u64::from_ne_bytes(*w);
            }
            r.sp = u64::from_ne_bytes(buf[248..256].try_into().unwrap());
            r.pc = u64::from_ne_bytes(buf[256..264].try_into().unwrap());
            r.pstate = u64::from_ne_bytes(buf[264..272].try_into().unwrap());
        }
        Ok(r)
    }

    pub fn store(pid: i32, cur: &Raw, orig: &Raw) -> Result<()> {
        if let Some(nr) = cur.sysnum_override {
            let mut v = nr;
            ptrace::setregset(pid, NT_ARM_SYSTEM_CALL, &mut v as *mut i32 as *mut u8, 4)?;
        }
        if cur.regs != orig.regs || cur.sp != orig.sp || cur.pc != orig.pc {
            if cur.compat {
                let mut buf = [0u8; REGS32_LEN];
                for i in 0..18 {
                    buf[i * 4..i * 4 + 4].copy_from_slice(&(cur.regs[i] as u32).to_ne_bytes());
                }
                ptrace::setregset(pid, NT_PRSTATUS, buf.as_mut_ptr(), REGS32_LEN)?;
            } else {
                let mut buf = [0u8; REGS64_LEN];
                for i in 0..31 {
                    buf[i * 8..i * 8 + 8].copy_from_slice(&cur.regs[i].to_ne_bytes());
                }
                buf[248..256].copy_from_slice(&cur.sp.to_ne_bytes());
                buf[256..264].copy_from_slice(&cur.pc.to_ne_bytes());
                buf[264..272].copy_from_slice(&cur.pstate.to_ne_bytes());
                ptrace::setregset(pid, NT_PRSTATUS, buf.as_mut_ptr(), REGS64_LEN)?;
            }
        }
        Ok(())
    }

    pub fn abi(r: &Raw) -> Abi {
        if r.compat { Abi::Arm } else { Abi::Aarch64 }
    }

    /// The syscall number lives in x8 (AArch64) or r7 (AArch32) at entry.
    pub fn sysnum(r: &Raw) -> i64 {
        if let Some(n) = r.sysnum_override {
            return n as i64;
        }
        if r.compat {
            r.regs[7] as i64
        } else {
            r.regs[8] as i64
        }
    }

    pub fn set_sysnum(r: &mut Raw, nr: i64) {
        r.sysnum_override = Some(nr as i32);
    }

    /// The result a skipped syscall returns: `x0`, `r0` for a compat tracee.
    pub fn set_ret(r: &mut Raw, v: i64) {
        r.regs[0] = if r.compat {
            v as u64 & 0xffff_ffff
        } else {
            v as u64
        };
    }

    /// Arguments are x0..x5 or r0..r5 on both ABIs.
    pub fn arg(r: &Raw, i: usize) -> u64 {
        let v = r.regs[i.min(5)];
        if r.compat { v & 0xffff_ffff } else { v }
    }

    pub fn set_arg(r: &mut Raw, i: usize, v: u64) {
        r.regs[i.min(5)] = if r.compat { v & 0xffff_ffff } else { v };
        if r.compat && i == 0 {
            // orig_r0 is what the kernel re-reads for a restarted syscall.
            r.regs[17] = v & 0xffff_ffff;
        }
    }

    pub fn sp(r: &Raw) -> u64 {
        r.sp
    }

    pub fn ip(r: &Raw) -> u64 {
        r.pc
    }

    pub fn same(a: &Raw, b: &Raw) -> bool {
        a == b
    }
}

/// Registers of a tracee stopped at syscall entry, with pending edits.
#[derive(Clone)]
pub struct Regs {
    pid: i32,
    orig: arch::Raw,
    cur: arch::Raw,
    /// Bytes already handed out below the red zone by [`Regs::alloc_stack`].
    scratch_used: u64,
}

impl Regs {
    /// Fetches the registers of `pid`.
    pub fn fetch(pid: i32) -> Result<Regs> {
        let r = arch::fetch(pid)?;
        Ok(Regs {
            pid,
            orig: r,
            cur: r,
            scratch_used: 0,
        })
    }

    /// Thread id these registers belong to.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// ABI the tracee made this syscall through.
    pub fn abi(&self) -> Abi {
        arch::abi(&self.cur)
    }

    /// Syscall number being entered, in the tracee's own ABI numbering.
    pub fn sysnum(&self) -> i64 {
        arch::sysnum(&self.cur)
    }

    /// Skips the syscall and makes it fail with `errno`: a tracer that sets the
    /// number to `-1` at the entry or seccomp stop has the tracee see whatever
    /// it put in the result register (seccomp(2), `SECCOMP_RET_TRACE`), which
    /// is `ENOSYS` left alone.
    pub fn fail(&mut self, errno: i32) {
        arch::set_sysnum(&mut self.cur, -1);
        arch::set_ret(&mut self.cur, -i64::from(errno));
    }

    /// Syscall argument `i` (0..6), in the register order of the tracee's ABI.
    pub fn arg(&self, i: usize) -> u64 {
        arch::arg(&self.cur, i)
    }

    /// Sets syscall argument `i` (0..6) in the register the tracee's ABI uses.
    pub fn set_arg(&mut self, i: usize, v: u64) {
        arch::set_arg(&mut self.cur, i, v);
    }

    /// Current stack pointer.
    pub fn sp(&self) -> u64 {
        arch::sp(&self.cur)
    }

    /// Current instruction pointer.
    pub fn ip(&self) -> u64 {
        arch::ip(&self.cur)
    }

    /// Reserves `size` bytes of scratch space below the tracee's stack pointer.
    ///
    /// The stack pointer itself is left untouched: we take no exit stop that
    /// could restore it, and the memory below `sp` minus the red zone is
    /// unused while the thread sits in the syscall instruction.  (aarch64 has
    /// no red zone; skipping one is harmless.)  Successive reservations stack
    /// downwards.  For `execve` the kernel discards the whole stack anyway.
    ///
    /// # Arguments
    /// * `size` - Bytes to reserve; the result is 16-byte aligned.
    ///
    /// # Returns
    /// The address of the reserved block in the tracee.
    pub fn alloc_stack(&mut self, size: u64) -> u64 {
        let sp = self.sp();
        let base = sp.saturating_sub(RED_ZONE_SIZE + self.scratch_used);
        let addr = base.saturating_sub(size) & !0xf;
        self.scratch_used = sp - addr;
        addr
    }

    /// Writes the modified registers back if anything changed.
    pub fn commit(&self) -> Result<()> {
        if arch::same(&self.cur, &self.orig) {
            return Ok(());
        }
        arch::store(self.pid, &self.cur, &self.orig)
    }
}
