//! What the supervisor and the guest stub agree on in the guest-stub
//! restricted mode: fixed addresses, the mailbox format, and which memory
//! each trapped syscall reads or writes, for the x86_64 and i386 ABIs of an
//! x86_64 host and the aarch64 and 32-bit ARM ABIs of an aarch64 host.
//!
//! Compiled into the supervisor and into every build of the `no_std` exec
//! shim, so it uses `core` only, with syscall numbers written out: the
//! supervisor needs its compat ABI's table as well as its own.
//!
//! # Gates
//!
//! One page at a fixed address holds two gates, [`GATE_NOTIFY_OFFSET`]
//! apart.  The filter lets a syscall made from the first (allow) through
//! untouched and sends one made from the second (notify) to the supervisor,
//! telling them apart by the instruction pointer the kernel reports, which
//! is the address right after the syscall instruction.  On x86_64 a gate is
//! `syscall; jmp *%r12` and on aarch64 `svc #0; br x16`, the caller putting
//! its return address in a register the kernel preserves and that carries
//! no argument, so the gate needs no stack; i386 uses all six free
//! registers for arguments, so there a gate is `int $0x80; ret`, called,
//! and on 32-bit ARM `svc #0; bx lr`, called.
//!
//! # Mailbox
//!
//! A memfd of [`MAIL_SIZE`] bytes mapped at a fixed address in every guest
//! process, a different one in 64-bit and 32-bit processes, and anywhere in
//! the supervisor.  The first page holds one `u32` owner per slot, the
//! thread id of the stub that claimed it or 0; the slots follow,
//! [`SLOT_SIZE`] bytes each.  A stub copies the memory a syscall reads into
//! its slot, points the arguments there, makes the call from the notify
//! gate, and copies what the call wrote back to the caller's buffers.  Path
//! strings get [`PATH_AREA`] bytes each so the supervisor can replace one
//! with a host path of any length before letting the call continue.

/// Size of a page.
pub const PAGE: usize = 4096;

/// Whether this build serves the ARM family (aarch64 and 32-bit ARM).
const ARM: bool = cfg!(any(target_arch = "aarch64", target_arch = "arm"));

/// Address of the gate page in a 64-bit guest.  On x86_64, below the
/// region `mmap` hands out top-down from near the stack and above where
/// position-independent executables and their heaps are placed, and above
/// `0x7000_ffff_ffff`: the seccomp filter Proton's Wine installs for some
/// games traps every syscall made from there or lower as a Windows
/// program's.  On aarch64 below where position-independent executables are
/// placed even with 39-bit addresses (2/3 of 512 GiB), far from the `mmap`
/// region.
pub const GATE64: u64 = if ARM { 0x40_0000_0000 } else { 0x7100_0000_0000 };

/// Address of the mailbox in a 64-bit guest, one megabyte above its gates.
pub const MAIL64: u64 = GATE64 + 0x10_0000;

/// Address of the gate page in a 32-bit guest: below where `mmap` starts
/// handing out memory top-down under the stack, above where executables,
/// their heaps and Wine's reserved ranges lie.
pub const GATE32: u64 = 0xe000_0000;

/// Address of the mailbox in a 32-bit guest, one megabyte above its gates.
pub const MAIL32: u64 = GATE32 + 0x10_0000;

/// Distance from the allow gate to the notify gate.
pub const GATE_NOTIFY_OFFSET: usize = 16;

/// Length of the syscall instruction (`syscall`, `int $0x80`; `svc #0` on
/// ARM), by which the instruction pointer the kernel reports for a gate's
/// syscall lies past it.
pub const SYSCALL_LEN: usize = if ARM { 4 } else { 2 };

/// Address of the gate page in this build's guests.
#[cfg(target_pointer_width = "64")]
pub const GATE_ADDR: usize = GATE64 as usize;

/// Address of the gate page in this build's guests.
#[cfg(target_pointer_width = "32")]
pub const GATE_ADDR: usize = GATE32 as usize;

/// Address of the mailbox in this build's guests.
#[cfg(target_pointer_width = "64")]
pub const MAIL_ADDR: usize = MAIL64 as usize;

/// Address of the mailbox in this build's guests.
#[cfg(target_pointer_width = "32")]
pub const MAIL_ADDR: usize = MAIL32 as usize;

/// Gate whose syscalls the filter allows untouched.
pub const ALLOW_GATE: usize = GATE_ADDR;

/// Gate whose syscalls the filter sends to the supervisor.
pub const NOTIFY_GATE: usize = GATE_ADDR + GATE_NOTIFY_OFFSET;

/// Machine code of each gate: `syscall; jmp *%r12`.
#[cfg(target_arch = "x86_64")]
pub const GATE_CODE: &[u8] = &[0x0f, 0x05, 0x41, 0xff, 0xe4];

/// Machine code of each gate: `int $0x80; ret`.
#[cfg(target_arch = "x86")]
pub const GATE_CODE: &[u8] = &[0xcd, 0x80, 0xc3];

/// Machine code of each gate: `svc #0; br x16`.
#[cfg(target_arch = "aarch64")]
pub const GATE_CODE: &[u8] = &[0x01, 0x00, 0x00, 0xd4, 0x00, 0x02, 0x1f, 0xd6];

/// Machine code of each gate, in the A32 instruction set: `svc #0; bx lr`.
#[cfg(target_arch = "arm")]
pub const GATE_CODE: &[u8] = &[0x00, 0x00, 0x00, 0xef, 0x1e, 0xff, 0x2f, 0xe1];

/// Number of slots, the most trapped syscalls in flight at once across every
/// guest process; a stub that finds none free waits for one.
pub const SLOTS: usize = 128;

/// Size of one slot.
pub const SLOT_SIZE: usize = 128 * 1024;

/// Size of the mailbox: the owner page and the slots.
pub const MAIL_SIZE: usize = PAGE + SLOTS * SLOT_SIZE;

/// Room given to each staged path string, terminating NUL included, so the
/// supervisor can write any host path over it.
pub const PATH_AREA: usize = 4096;

/// `SECCOMP_RET_DATA` of the filter's traps, reported in `si_errno`, which
/// tells the stub's traps from those of a filter the program installed.
pub const TAG: u32 = 0x7e57;

/// `getpid` on the host's 64-bit ABI (x86_64 39, aarch64 172).  The exec
/// shim makes it from the notify gate once it runs, with [`HELLO_MARK`] as
/// its argument, telling the supervisor that the exec it planned has
/// happened.  A real syscall that every seccomp profile allows: a container
/// runtime's filter refuses unknown numbers, and its refusal outranks the
/// notification.
pub const HELLO64: i64 = if ARM { 172 } else { 39 };

/// `getpid` on i386 and 32-bit ARM, the 32-bit shim's [`HELLO64`].
pub const HELLO32: i64 = 20;

/// Argument 0 of the hello, small enough for a 32-bit register.
pub const HELLO_MARK: u64 = 0x7072_6e68;

/// This build's hello syscall.
#[cfg(target_pointer_width = "64")]
pub const HELLO: i64 = HELLO64;

/// This build's hello syscall.
#[cfg(target_pointer_width = "32")]
pub const HELLO: i64 = HELLO32;

/// Argument of a staged `execve` or `execveat` that is 1 when the argument
/// and environment vectors did not fit in the slot and only `argv[0]` was
/// staged.
pub const EXEC_TRUNCATED_ARG: usize = 5;

/// Name of the 32-bit trampoline in the alias directory, next to `e`.
pub const SHIM32_NAME: &str = "e32";

const _: () = {
    assert!(GATE64.is_multiple_of(PAGE as u64) && MAIL64.is_multiple_of(PAGE as u64));
    assert!(GATE32.is_multiple_of(PAGE as u64) && MAIL32.is_multiple_of(PAGE as u64));
    assert!(GATE64 + PAGE as u64 <= MAIL64 && GATE32 + PAGE as u64 <= MAIL32);
    assert!(MAIL64 + (MAIL_SIZE as u64) < if ARM { 1 << 39 } else { 1 << 47 });
    assert!(MAIL32 + (MAIL_SIZE as u64) < 0xf000_0000);
    assert!(SLOTS * 4 <= PAGE);
    assert!(2 * PATH_AREA + XATTR_MAX <= SLOT_SIZE);
};

/// Address of slot `i`.
///
/// # Arguments
/// * `i` - Slot number, below [`SLOTS`].
///
/// # Returns
/// The address of the slot's first byte in a guest of this build.
pub const fn slot_addr(i: usize) -> usize {
    MAIL_ADDR + PAGE + i * SLOT_SIZE
}

/// Length of a buffer argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Len {
    /// A fixed number of bytes.
    Fixed(usize),
    /// The value of argument `.0`, in bytes.
    Arg(usize),
    /// The value of argument `.0` times an element size `.1`.
    Elems(usize, usize),
}

/// The part of an output buffer a successful call wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Produced {
    /// All of it, when the call returned 0.
    Whole,
    /// As many bytes as the call returned.
    Ret,
    /// As many elements of `.0` bytes as the call returned.
    RetElems(usize),
}

/// How one argument is staged in the mailbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// A NUL-terminated string, copied into a [`PATH_AREA`].
    Path,
    /// A buffer the call reads, copied in.  Longer than `max` bytes, the call
    /// fails with `too_big` without being made, as the kernel would fail it.
    In {
        /// Its length.
        len: Len,
        /// The most staged.
        max: usize,
        /// The errno of a longer buffer.
        too_big: i32,
    },
    /// A buffer the call writes, copied back once it returns.
    Out(Len, Produced),
}

/// Largest socket address, `sizeof(struct sockaddr_storage)`.
pub const SOCKADDR_MAX: usize = 128;

/// Largest `struct open_how` staged.
pub const OPEN_HOW_MAX: usize = 256;

/// Largest extended attribute value, `XATTR_SIZE_MAX`.
pub const XATTR_MAX: usize = 65536;

/// Most supplementary groups staged for `setgroups`.
pub const GROUPS_MAX: usize = 16384;

/// `EINVAL`.
const EINVAL: i32 = 22;
/// `E2BIG`.
const E2BIG: i32 = 7;

/// A fixed-size input that always fits.
///
/// # Arguments
/// * `len` - Its length.
///
/// # Returns
/// The staging.
const fn input(len: usize) -> Stage {
    Stage::In {
        len: Len::Fixed(len),
        max: SLOT_SIZE,
        too_big: EINVAL,
    }
}

/// A fixed-size output, written whole on success.
///
/// # Arguments
/// * `len` - Its length.
///
/// # Returns
/// The staging.
const fn output(len: usize) -> Stage {
    Stage::Out(Len::Fixed(len), Produced::Whole)
}

/// An output holding as many bytes as the call returned, sized by an argument.
///
/// # Arguments
/// * `arg` - The argument that holds the buffer's size.
///
/// # Returns
/// The staging.
const fn ret_bytes(arg: usize) -> Stage {
    Stage::Out(Len::Arg(arg), Produced::Ret)
}

/// A socket address whose length is argument 2.
const SOCKADDR: Stage = Stage::In {
    len: Len::Arg(2),
    max: SOCKADDR_MAX,
    too_big: EINVAL,
};

/// A `struct open_how` whose size is argument 3.
const OPEN_HOW: Stage = Stage::In {
    len: Len::Arg(3),
    max: OPEN_HOW_MAX,
    too_big: E2BIG,
};

/// An extended attribute value whose size is argument 3.
const XATTR_VALUE: Stage = Stage::In {
    len: Len::Arg(3),
    max: XATTR_MAX,
    too_big: E2BIG,
};

/// A group list of argument 0 entries of `size` bytes.
///
/// # Arguments
/// * `size` - Bytes per group id.
///
/// # Returns
/// The staging.
const fn groups_in(size: usize) -> Stage {
    Stage::In {
        len: Len::Elems(0, size),
        max: GROUPS_MAX * size,
        too_big: EINVAL,
    }
}

/// A group list output of argument 0 entries of `size` bytes.
///
/// # Arguments
/// * `size` - Bytes per group id.
///
/// # Returns
/// The staging.
const fn groups_out(size: usize) -> Stage {
    Stage::Out(Len::Elems(0, size), Produced::RetElems(size))
}

/// One path in argument 0.
const P0: &[(usize, Stage)] = &[(0, Stage::Path)];
/// One path in argument 1.
const P1: &[(usize, Stage)] = &[(1, Stage::Path)];
/// Paths in arguments 0 and 1.
const P0P1: &[(usize, Stage)] = &[(0, Stage::Path), (1, Stage::Path)];
/// Paths in arguments 1 and 3.
const P1P3: &[(usize, Stage)] = &[(1, Stage::Path), (3, Stage::Path)];
/// Paths in arguments 0 and 2.
const P0P2: &[(usize, Stage)] = &[(0, Stage::Path), (2, Stage::Path)];

/// The memory an x86_64 syscall uses, as (argument index, staging) pairs.
///
/// `execve`, `execveat`, `rt_sigaction` and `rt_sigprocmask` are trapped too
/// but handled by the stub itself, see [`trapped_x86_64`].
///
/// # Arguments
/// * `nr` - x86_64 syscall number.
///
/// # Returns
/// The arguments to stage, or `None` when the syscall carries no memory the
/// supervisor reads or writes.
pub fn staging_x86_64(nr: i64) -> Option<&'static [(usize, Stage)]> {
    use Stage::Path;
    const STAT: &[(usize, Stage)] = &[(0, Path), (1, output(144))];
    const FSTATAT: &[(usize, Stage)] = &[(1, Path), (2, output(144))];
    const STATX: &[(usize, Stage)] = &[(1, Path), (4, output(256))];
    const STATFS: &[(usize, Stage)] = &[(0, Path), (1, output(120))];
    const READLINK: &[(usize, Stage)] = &[(0, Path), (1, ret_bytes(2))];
    const READLINKAT: &[(usize, Stage)] = &[(1, Path), (2, ret_bytes(3))];
    const GETCWD: &[(usize, Stage)] = &[(0, ret_bytes(1))];
    const UNAME: &[(usize, Stage)] = &[(0, output(390))];
    const UTIME: &[(usize, Stage)] = &[(0, Path), (1, input(16))];
    const UTIMES: &[(usize, Stage)] = &[(0, Path), (1, input(32))];
    const UTIMESAT: &[(usize, Stage)] = &[(1, Path), (2, input(32))];
    const OPENAT2: &[(usize, Stage)] = &[(1, Path), (2, OPEN_HOW)];
    const SETXATTR: &[(usize, Stage)] = &[(0, Path), (1, Path), (2, XATTR_VALUE)];
    const GETXATTR: &[(usize, Stage)] = &[(0, Path), (1, Path), (2, ret_bytes(3))];
    const LISTXATTR: &[(usize, Stage)] = &[(0, Path), (1, ret_bytes(2))];
    const SOCK: &[(usize, Stage)] = &[(1, SOCKADDR)];
    const RESIDS: &[(usize, Stage)] = &[(0, output(4)), (1, output(4)), (2, output(4))];
    const GETGROUPS: &[(usize, Stage)] = &[(1, groups_out(4))];
    const SETGROUPS: &[(usize, Stage)] = &[(1, groups_in(4))];
    Some(match nr {
        2 | 85 | 21 | 90 | 92 | 94 | 76 | 87 | 83 | 84 | 133 | 80 | 161 => P0,
        257 | 269 | 439 | 268 | 452 | 260 | 263 | 258 | 259 | 254 | 303 => P1,
        82 | 86 | 88 | 197 | 198 => P0P1,
        264 | 316 | 265 => P1P3,
        266 => P0P2,
        437 => OPENAT2,
        4 | 6 => STAT,
        262 => FSTATAT,
        332 => STATX,
        137 => STATFS,
        89 => READLINK,
        267 => READLINKAT,
        79 => GETCWD,
        63 => UNAME,
        132 => UTIME,
        235 => UTIMES,
        261 | 280 => UTIMESAT,
        188 | 189 => SETXATTR,
        191 | 192 => GETXATTR,
        194 | 195 => LISTXATTR,
        42 | 49 => SOCK,
        118 | 120 => RESIDS,
        115 => GETGROUPS,
        116 => SETGROUPS,
        _ => return None,
    })
}

/// Whether the filter traps x86_64 syscall `nr` into the stub rather than
/// notifying the supervisor directly: it has memory to stage, or the stub
/// handles it (`execve`, `execveat`, `rt_sigaction`, `rt_sigprocmask`).
///
/// # Arguments
/// * `nr` - x86_64 syscall number.
///
/// # Returns
/// `true` for a trapped syscall.
pub fn trapped_x86_64(nr: i64) -> bool {
    staging_x86_64(nr).is_some() || matches!(nr, 59 | 322 | 13 | 14)
}

/// The memory an i386 syscall uses, as (argument index, staging) pairs.
///
/// The structures are the i386 ones: the old and the 64-bit `struct stat`,
/// 32-bit time values, 16-bit ids in the calls without a `32` form.
/// `execve`, `execveat`, `rt_sigaction`, `rt_sigprocmask` and the `bind`
/// and `connect` of `socketcall` are trapped too but handled by the stub
/// itself, see [`trapped_i386`].
///
/// # Arguments
/// * `nr` - i386 syscall number.
///
/// # Returns
/// The arguments to stage, or `None` when the syscall carries no memory the
/// supervisor reads or writes.
pub fn staging_i386(nr: i64) -> Option<&'static [(usize, Stage)]> {
    use Stage::Path;
    const OLD_STAT: &[(usize, Stage)] = &[(0, Path), (1, output(64))];
    const STAT64: &[(usize, Stage)] = &[(0, Path), (1, output(96))];
    const FSTATAT64: &[(usize, Stage)] = &[(1, Path), (2, output(96))];
    const STATX: &[(usize, Stage)] = &[(1, Path), (4, output(256))];
    const STATFS: &[(usize, Stage)] = &[(0, Path), (1, output(64))];
    const STATFS64: &[(usize, Stage)] = &[(0, Path), (2, output(84))];
    const READLINK: &[(usize, Stage)] = &[(0, Path), (1, ret_bytes(2))];
    const READLINKAT: &[(usize, Stage)] = &[(1, Path), (2, ret_bytes(3))];
    const GETCWD: &[(usize, Stage)] = &[(0, ret_bytes(1))];
    const UNAME: &[(usize, Stage)] = &[(0, output(390))];
    const UTIME: &[(usize, Stage)] = &[(0, Path), (1, input(8))];
    const UTIMES: &[(usize, Stage)] = &[(0, Path), (1, input(16))];
    const UTIMESAT32: &[(usize, Stage)] = &[(1, Path), (2, input(16))];
    const UTIMESAT64: &[(usize, Stage)] = &[(1, Path), (2, input(32))];
    const OPENAT2: &[(usize, Stage)] = &[(1, Path), (2, OPEN_HOW)];
    const SETXATTR: &[(usize, Stage)] = &[(0, Path), (1, Path), (2, XATTR_VALUE)];
    const GETXATTR: &[(usize, Stage)] = &[(0, Path), (1, Path), (2, ret_bytes(3))];
    const LISTXATTR: &[(usize, Stage)] = &[(0, Path), (1, ret_bytes(2))];
    const SOCK: &[(usize, Stage)] = &[(1, SOCKADDR)];
    const RESIDS16: &[(usize, Stage)] = &[(0, output(2)), (1, output(2)), (2, output(2))];
    const RESIDS32: &[(usize, Stage)] = &[(0, output(4)), (1, output(4)), (2, output(4))];
    const GETGROUPS16: &[(usize, Stage)] = &[(1, groups_out(2))];
    const GETGROUPS32: &[(usize, Stage)] = &[(1, groups_out(4))];
    const SETGROUPS16: &[(usize, Stage)] = &[(1, groups_in(2))];
    const SETGROUPS32: &[(usize, Stage)] = &[(1, groups_in(4))];
    Some(match nr {
        5 | 8 | 10 | 12 | 14 | 15 | 16 | 33 | 39 | 40 | 61 | 92 | 193 | 182 | 198 | 212 => P0,
        295 | 296 | 297 | 298 | 301 | 306 | 307 | 439 | 452 | 292 | 341 => P1,
        9 | 38 | 83 | 235 | 236 => P0P1,
        302 | 303 | 353 => P1P3,
        304 => P0P2,
        437 => OPENAT2,
        106 | 107 => OLD_STAT,
        195 | 196 => STAT64,
        300 => FSTATAT64,
        383 => STATX,
        99 => STATFS,
        268 => STATFS64,
        85 => READLINK,
        305 => READLINKAT,
        183 => GETCWD,
        122 => UNAME,
        30 => UTIME,
        271 => UTIMES,
        299 | 320 => UTIMESAT32,
        412 => UTIMESAT64,
        226 | 227 => SETXATTR,
        229 | 230 => GETXATTR,
        232 | 233 => LISTXATTR,
        361 | 362 => SOCK,
        165 | 171 => RESIDS16,
        209 | 211 => RESIDS32,
        80 => GETGROUPS16,
        205 => GETGROUPS32,
        81 => SETGROUPS16,
        206 => SETGROUPS32,
        _ => return None,
    })
}

/// i386 `socketcall`, whose `bind` and `connect` the filter traps.
pub const SOCKETCALL_I386: i64 = 102;

/// Whether the filter traps i386 syscall `nr` into the stub rather than
/// notifying the supervisor directly: it has memory to stage, or the stub
/// handles it (`execve`, `execveat`, `rt_sigaction`, `rt_sigprocmask`).
/// `socketcall` is trapped by its call number, apart from this list.
///
/// # Arguments
/// * `nr` - i386 syscall number.
///
/// # Returns
/// `true` for a trapped syscall.
pub fn trapped_i386(nr: i64) -> bool {
    staging_i386(nr).is_some() || matches!(nr, 11 | 358 | 174 | 175)
}

/// The memory an aarch64 syscall uses, as (argument index, staging) pairs.
///
/// The generic syscall table has only the `*at` forms and the 64-bit
/// layouts, with a 128-byte `struct stat`.  `execve`, `execveat`,
/// `rt_sigaction` and `rt_sigprocmask` are trapped too but handled by the
/// stub itself, see [`trapped_aarch64`].
///
/// # Arguments
/// * `nr` - aarch64 syscall number.
///
/// # Returns
/// The arguments to stage, or `None` when the syscall carries no memory the
/// supervisor reads or writes.
pub fn staging_aarch64(nr: i64) -> Option<&'static [(usize, Stage)]> {
    use Stage::Path;
    const FSTATAT: &[(usize, Stage)] = &[(1, Path), (2, output(128))];
    const STATX: &[(usize, Stage)] = &[(1, Path), (4, output(256))];
    const STATFS: &[(usize, Stage)] = &[(0, Path), (1, output(120))];
    const READLINKAT: &[(usize, Stage)] = &[(1, Path), (2, ret_bytes(3))];
    const GETCWD: &[(usize, Stage)] = &[(0, ret_bytes(1))];
    const UNAME: &[(usize, Stage)] = &[(0, output(390))];
    const UTIMESAT: &[(usize, Stage)] = &[(1, Path), (2, input(32))];
    const OPENAT2: &[(usize, Stage)] = &[(1, Path), (2, OPEN_HOW)];
    const SETXATTR: &[(usize, Stage)] = &[(0, Path), (1, Path), (2, XATTR_VALUE)];
    const GETXATTR: &[(usize, Stage)] = &[(0, Path), (1, Path), (2, ret_bytes(3))];
    const LISTXATTR: &[(usize, Stage)] = &[(0, Path), (1, ret_bytes(2))];
    const SOCK: &[(usize, Stage)] = &[(1, SOCKADDR)];
    const RESIDS: &[(usize, Stage)] = &[(0, output(4)), (1, output(4)), (2, output(4))];
    const GETGROUPS: &[(usize, Stage)] = &[(1, groups_out(4))];
    const SETGROUPS: &[(usize, Stage)] = &[(1, groups_in(4))];
    Some(match nr {
        49 | 51 | 45 => P0,
        56 | 34 | 33 | 54 | 35 | 53 | 48 | 439 | 452 | 27 | 264 => P1,
        14 | 15 => P0P1,
        38 | 276 | 37 => P1P3,
        36 => P0P2,
        437 => OPENAT2,
        79 => FSTATAT,
        291 => STATX,
        43 => STATFS,
        78 => READLINKAT,
        17 => GETCWD,
        160 => UNAME,
        88 => UTIMESAT,
        5 | 6 => SETXATTR,
        8 | 9 => GETXATTR,
        11 | 12 => LISTXATTR,
        200 | 203 => SOCK,
        148 | 150 => RESIDS,
        158 => GETGROUPS,
        159 => SETGROUPS,
        _ => return None,
    })
}

/// Whether the filter traps aarch64 syscall `nr` into the stub rather than
/// notifying the supervisor directly: it has memory to stage, or the stub
/// handles it (`execve`, `execveat`, `rt_sigaction`, `rt_sigprocmask`).
///
/// # Arguments
/// * `nr` - aarch64 syscall number.
///
/// # Returns
/// `true` for a trapped syscall.
pub fn trapped_aarch64(nr: i64) -> bool {
    staging_aarch64(nr).is_some() || matches!(nr, 221 | 281 | 134 | 135)
}

/// The memory a 32-bit ARM (EABI) syscall uses, as (argument index,
/// staging) pairs.
///
/// The structures are the ARM ones: the old `struct stat`, the 104-byte
/// `struct stat64`, 32-bit time values, 16-bit ids in the calls without a
/// `32` form.  `execve`, `execveat`, `rt_sigaction` and `rt_sigprocmask` are
/// trapped too but handled by the stub itself, see [`trapped_arm`].
///
/// # Arguments
/// * `nr` - ARM EABI syscall number.
///
/// # Returns
/// The arguments to stage, or `None` when the syscall carries no memory the
/// supervisor reads or writes.
pub fn staging_arm(nr: i64) -> Option<&'static [(usize, Stage)]> {
    use Stage::Path;
    const OLD_STAT: &[(usize, Stage)] = &[(0, Path), (1, output(64))];
    const STAT64: &[(usize, Stage)] = &[(0, Path), (1, output(104))];
    const FSTATAT64: &[(usize, Stage)] = &[(1, Path), (2, output(104))];
    const STATX: &[(usize, Stage)] = &[(1, Path), (4, output(256))];
    const STATFS: &[(usize, Stage)] = &[(0, Path), (1, output(64))];
    const STATFS64: &[(usize, Stage)] = &[(0, Path), (2, output(84))];
    const READLINK: &[(usize, Stage)] = &[(0, Path), (1, ret_bytes(2))];
    const READLINKAT: &[(usize, Stage)] = &[(1, Path), (2, ret_bytes(3))];
    const GETCWD: &[(usize, Stage)] = &[(0, ret_bytes(1))];
    const UNAME: &[(usize, Stage)] = &[(0, output(390))];
    const UTIMES: &[(usize, Stage)] = &[(0, Path), (1, input(16))];
    const UTIMESAT32: &[(usize, Stage)] = &[(1, Path), (2, input(16))];
    const UTIMESAT64: &[(usize, Stage)] = &[(1, Path), (2, input(32))];
    const OPENAT2: &[(usize, Stage)] = &[(1, Path), (2, OPEN_HOW)];
    const SETXATTR: &[(usize, Stage)] = &[(0, Path), (1, Path), (2, XATTR_VALUE)];
    const GETXATTR: &[(usize, Stage)] = &[(0, Path), (1, Path), (2, ret_bytes(3))];
    const LISTXATTR: &[(usize, Stage)] = &[(0, Path), (1, ret_bytes(2))];
    const SOCK: &[(usize, Stage)] = &[(1, SOCKADDR)];
    const RESIDS16: &[(usize, Stage)] = &[(0, output(2)), (1, output(2)), (2, output(2))];
    const RESIDS32: &[(usize, Stage)] = &[(0, output(4)), (1, output(4)), (2, output(4))];
    const GETGROUPS16: &[(usize, Stage)] = &[(1, groups_out(2))];
    const GETGROUPS32: &[(usize, Stage)] = &[(1, groups_out(4))];
    const SETGROUPS16: &[(usize, Stage)] = &[(1, groups_in(2))];
    const SETGROUPS32: &[(usize, Stage)] = &[(1, groups_in(4))];
    Some(match nr {
        5 | 8 | 10 | 12 | 14 | 15 | 16 | 33 | 39 | 40 | 61 | 92 | 193 | 182 | 198 | 212 => P0,
        322 | 323 | 324 | 325 | 328 | 333 | 334 | 439 | 452 | 317 | 370 => P1,
        9 | 38 | 83 | 235 | 236 => P0P1,
        329 | 330 | 382 => P1P3,
        331 => P0P2,
        437 => OPENAT2,
        106 | 107 => OLD_STAT,
        195 | 196 => STAT64,
        327 => FSTATAT64,
        397 => STATX,
        99 => STATFS,
        266 => STATFS64,
        85 => READLINK,
        332 => READLINKAT,
        183 => GETCWD,
        122 => UNAME,
        269 => UTIMES,
        326 | 348 => UTIMESAT32,
        412 => UTIMESAT64,
        226 | 227 => SETXATTR,
        229 | 230 => GETXATTR,
        232 | 233 => LISTXATTR,
        282 | 283 => SOCK,
        165 | 171 => RESIDS16,
        209 | 211 => RESIDS32,
        80 => GETGROUPS16,
        205 => GETGROUPS32,
        81 => SETGROUPS16,
        206 => SETGROUPS32,
        _ => return None,
    })
}

/// Whether the filter traps 32-bit ARM syscall `nr` into the stub rather
/// than notifying the supervisor directly: it has memory to stage, or the
/// stub handles it (`execve`, `execveat`, `rt_sigaction`, `rt_sigprocmask`).
///
/// # Arguments
/// * `nr` - ARM EABI syscall number.
///
/// # Returns
/// `true` for a trapped syscall.
pub fn trapped_arm(nr: i64) -> bool {
    staging_arm(nr).is_some() || matches!(nr, 11 | 387 | 174 | 175)
}

/// Whether the filter traps syscall `nr` of the host's 64-bit ABI.
///
/// # Arguments
/// * `nr` - Syscall number.
///
/// # Returns
/// As [`trapped_x86_64`] or [`trapped_aarch64`].
pub fn trapped64(nr: i64) -> bool {
    if ARM {
        trapped_aarch64(nr)
    } else {
        trapped_x86_64(nr)
    }
}

/// Whether the filter traps syscall `nr` of the host's 32-bit compat ABI.
///
/// # Arguments
/// * `nr` - Syscall number.
///
/// # Returns
/// As [`trapped_i386`] or [`trapped_arm`].
pub fn trapped32(nr: i64) -> bool {
    if ARM { trapped_arm(nr) } else { trapped_i386(nr) }
}

/// `rt_sigaction` and `rt_sigprocmask` of the host's 64-bit ABI, which the
/// stub handles and the filter traps although the supervisor serves neither.
pub const SIGNAL_CALLS64: [i64; 2] = if ARM { [134, 135] } else { [13, 14] };

/// `rt_sigaction` and `rt_sigprocmask` of the host's 32-bit compat ABI.
pub const SIGNAL_CALLS32: [i64; 2] = [174, 175];

/// The staging of this build's ABI.
///
/// # Arguments
/// * `nr` - Native syscall number.
///
/// # Returns
/// As [`staging_x86_64`].
#[cfg(target_arch = "x86_64")]
pub fn staging(nr: i64) -> Option<&'static [(usize, Stage)]> {
    staging_x86_64(nr)
}

/// The staging of this build's ABI.
///
/// # Arguments
/// * `nr` - Native syscall number.
///
/// # Returns
/// As [`staging_i386`].
#[cfg(target_arch = "x86")]
pub fn staging(nr: i64) -> Option<&'static [(usize, Stage)]> {
    staging_i386(nr)
}

/// The staging of this build's ABI.
///
/// # Arguments
/// * `nr` - Native syscall number.
///
/// # Returns
/// As [`staging_aarch64`].
#[cfg(target_arch = "aarch64")]
pub fn staging(nr: i64) -> Option<&'static [(usize, Stage)]> {
    staging_aarch64(nr)
}

/// The staging of this build's ABI.
///
/// # Arguments
/// * `nr` - Native syscall number.
///
/// # Returns
/// As [`staging_arm`].
#[cfg(target_arch = "arm")]
pub fn staging(nr: i64) -> Option<&'static [(usize, Stage)]> {
    staging_arm(nr)
}
