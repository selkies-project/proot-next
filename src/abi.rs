//! Syscall ABIs a tracee may use.
//!
//! Handlers work in x86_64 terms: the numbers in `syscall::nr` are the
//! canonical names of the operations.  Every other ABI is mapped onto them
//! here, together with a [`Variant`] describing how its arguments or
//! structure layouts differ.  A 32-bit i386 process on an x86_64 kernel has
//! different numbers, `ebx..ebp` argument registers, 4-byte pointers and a
//! few 32-bit structures; aarch64 shares the layouts of x86_64 but uses the
//! generic syscall table, which has no legacy `open`/`stat`/`access` family.

use crate::sys::{AUDIT_ARCH_AARCH64, AUDIT_ARCH_ARM, AUDIT_ARCH_I386, AUDIT_ARCH_X86_64};
use crate::syscall::nr::*;

/// The ABI a request came through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abi {
    X86_64,
    I386,
    Aarch64,
    /// 32-bit ARM (EABI) compat on an aarch64 kernel.
    Arm,
}

impl Abi {
    /// ABI from a seccomp `arch` field; `None` for x32 and anything else.
    pub fn from_audit(arch: u32) -> Option<Abi> {
        match arch {
            AUDIT_ARCH_X86_64 => Some(Abi::X86_64),
            AUDIT_ARCH_I386 => Some(Abi::I386),
            AUDIT_ARCH_AARCH64 => Some(Abi::Aarch64),
            AUDIT_ARCH_ARM => Some(Abi::Arm),
            _ => None,
        }
    }

    /// The 64-bit ABI of the host this binary was built for.
    pub fn native() -> Abi {
        if cfg!(target_arch = "aarch64") {
            Abi::Aarch64
        } else {
            Abi::X86_64
        }
    }

    /// The 32-bit compat ABI of the host, if any.
    pub fn compat() -> Abi {
        if cfg!(target_arch = "aarch64") {
            Abi::Arm
        } else {
            Abi::I386
        }
    }

    /// Audit arch value the kernel reports for this ABI.
    pub fn audit(self) -> u32 {
        match self {
            Abi::X86_64 => AUDIT_ARCH_X86_64,
            Abi::I386 => AUDIT_ARCH_I386,
            Abi::Aarch64 => AUDIT_ARCH_AARCH64,
            Abi::Arm => AUDIT_ARCH_ARM,
        }
    }

    /// Size of a pointer in the tracee.
    pub fn ptr_size(self) -> usize {
        match self {
            Abi::X86_64 | Abi::Aarch64 => 8,
            Abi::I386 | Abi::Arm => 4,
        }
    }

    /// Maps a syscall number of this ABI onto the canonical (x86_64) number.
    ///
    /// # Arguments
    /// * `nr` - Syscall number as the tracee issued it.
    ///
    /// # Returns
    /// The canonical number and the argument variant, or `None` when the
    /// syscall is not one we filter (or the ABI is not served).
    pub fn to_canonical(self, nr: i64) -> Option<(i64, Variant)> {
        match self {
            Abi::X86_64 => Some((nr, Variant::Same)),
            Abi::I386 => i386_to_x86_64(nr),
            Abi::Aarch64 => aarch64_to_x86_64(nr).map(|n| (n, Variant::Same)),
            Abi::Arm => arm_to_x86_64(nr),
        }
    }

    /// This ABI's number for a canonical `open`-family syscall, with the index
    /// of its flags argument (for the filter's `O_PATH` routing).
    pub fn open_flags_arg(self, nr: i64) -> Option<usize> {
        match (self, nr) {
            (Abi::X86_64, OPEN) | (Abi::I386, 5) | (Abi::Arm, 5) => Some(1),
            (Abi::X86_64, OPENAT) | (Abi::I386, 295) | (Abi::Aarch64, 56) | (Abi::Arm, 322) => Some(2),
            _ => None,
        }
    }

    /// Converts this ABI's `open(2)` flag bits into the host's.
    ///
    /// The generic values are shared by x86 and aarch64; ARM differs in
    /// `O_DIRECTORY`, `O_NOFOLLOW`, `O_DIRECT` and `O_LARGEFILE`, so a 32-bit
    /// ARM caller's flags are remapped before any handler interprets them.
    ///
    /// # Arguments
    /// * `flags` - Flags as the tracee passed them.
    pub fn open_flags_to_host(self, flags: i64) -> i64 {
        match self {
            Abi::Arm => {
                const ARM_O_DIRECTORY: i64 = 0o40000;
                const ARM_O_NOFOLLOW: i64 = 0o100000;
                const ARM_O_DIRECT: i64 = 0o200000;
                const ARM_O_LARGEFILE: i64 = 0o400000;
                let mut out = flags & !(ARM_O_DIRECTORY | ARM_O_NOFOLLOW | ARM_O_DIRECT | ARM_O_LARGEFILE);
                if flags & ARM_O_DIRECTORY != 0 {
                    out |= libc::O_DIRECTORY as i64;
                }
                if flags & ARM_O_NOFOLLOW != 0 {
                    out |= libc::O_NOFOLLOW as i64;
                }
                if flags & ARM_O_DIRECT != 0 {
                    out |= libc::O_DIRECT as i64;
                }
                out
            }
            _ => flags,
        }
    }

    /// The legacy `socketcall` multiplexer of this ABI, if it has one.
    ///
    /// i386 glibc issues every socket operation through it, so a 32-bit
    /// program's `bind` and `connect` arrive here rather than as syscalls.
    pub fn socketcall_nr(self) -> Option<i64> {
        match self {
            Abi::I386 => Some(102),
            _ => None,
        }
    }

    /// This ABI's numbers for every canonical syscall in `canonical`.
    ///
    /// # Arguments
    /// * `canonical` - x86_64 numbers (the lists in `syscall`).
    pub fn numbers_for(self, canonical: &[i64]) -> Vec<i64> {
        match self {
            Abi::X86_64 => canonical.to_vec(),
            _ => (0..512)
                .filter(|n| {
                    self.to_canonical(*n)
                        .map(|(x, _)| canonical.contains(&x))
                        .unwrap_or(false)
                })
                .collect(),
        }
    }
}

/// Maps an aarch64 (generic table) syscall number onto the x86_64 number.
///
/// The generic table has only the `*at` forms; layouts match x86_64 except
/// `struct stat`, which the handlers size from the host's `libc::stat`.
pub fn aarch64_to_x86_64(nr: i64) -> Option<i64> {
    Some(match nr {
        5 => SETXATTR,
        6 => LSETXATTR,
        8 => GETXATTR,
        9 => LGETXATTR,
        11 => LISTXATTR,
        12 => LLISTXATTR,
        14 => REMOVEXATTR,
        15 => LREMOVEXATTR,
        17 => GETCWD,
        27 => INOTIFY_ADD_WATCH,
        33 => MKNODAT,
        34 => MKDIRAT,
        35 => UNLINKAT,
        36 => SYMLINKAT,
        37 => LINKAT,
        38 => RENAMEAT,
        43 => STATFS,
        45 => TRUNCATE,
        48 => FACCESSAT,
        49 => CHDIR,
        51 => CHROOT,
        53 => FCHMODAT,
        54 => FCHOWNAT,
        56 => OPENAT,
        78 => READLINKAT,
        79 => NEWFSTATAT,
        88 => UTIMENSAT,
        160 => UNAME,
        200 => BIND,
        203 => CONNECT,
        221 => EXECVE,
        264 => NAME_TO_HANDLE_AT,
        276 => RENAMEAT2,
        281 => EXECVEAT,
        291 => STATX,
        437 => OPENAT2,
        439 => FACCESSAT2,
        452 => FCHMODAT2,
        55 => FCHOWN,
        91 => CAPSET,
        143 => SETREGID,
        144 => SETGID,
        145 => SETREUID,
        146 => SETUID,
        147 => SETRESUID,
        148 => GETRESUID,
        149 => SETRESGID,
        150 => GETRESGID,
        151 => SETFSUID,
        152 => SETFSGID,
        158 => GETGROUPS,
        159 => SETGROUPS,
        174 => GETUID,
        175 => GETEUID,
        176 => GETGID,
        177 => GETEGID,
        _ => return None,
    })
}

/// How a syscall's arguments differ from the x86_64 form it maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Same arguments and layouts as the x86_64 number.
    Same,
    /// `stat`/`lstat`/`fstatat` writing the i386 `struct stat64` (96 bytes).
    Stat64,
    /// `stat`/`lstat` writing the old i386 `struct stat` (64 bytes).
    OldStat,
    /// `statfs64(path, size, buf)` writing the i386 `struct statfs64` (84 bytes).
    Statfs64,
    /// `statfs(path, buf)` writing the old i386 `struct statfs` (64 bytes).
    OldStatfs,
    /// `truncate64(path, len_lo, len_hi)` (i386).
    Truncate64,
    /// `truncate64(path, pad, len_lo, len_hi)`: ARM EABI pairs 64-bit arguments on even registers.
    Truncate64Arm,
    /// `stat64`/`lstat64`/`fstatat64` writing the ARM EABI `struct stat64` (104 bytes).
    ArmStat64,
    /// `getresuid`/`getresgid` with 16-bit ids (the pre-`32` i386 and ARM forms).
    Id16,
    /// `utimensat` with 32-bit `struct timespec` pairs.
    Timespec32,
    /// `utime`/`utimes` with 32-bit `time_t` structures.
    Time32,
}

/// Maps an i386 syscall number onto the x86_64 number handlers understand.
///
/// # Arguments
/// * `nr` - i386 syscall number.
///
/// # Returns
/// The x86_64 number plus how its arguments differ, or `None` when the
/// syscall is not one we filter.
pub fn i386_to_x86_64(nr: i64) -> Option<(i64, Variant)> {
    use Variant::*;
    Some(match nr {
        5 => (OPEN, Same),
        8 => (CREAT, Same),
        9 => (LINK, Same),
        10 => (UNLINK, Same),
        11 => (EXECVE, Same),
        12 => (CHDIR, Same),
        14 => (MKNOD, Same),
        15 => (CHMOD, Same),
        16 => (LCHOWN, Same),
        30 => (UTIME, Time32),
        33 => (ACCESS, Same),
        38 => (RENAME, Same),
        39 => (MKDIR, Same),
        40 => (RMDIR, Same),
        61 => (CHROOT, Same),
        83 => (SYMLINK, Same),
        85 => (READLINK, Same),
        92 => (TRUNCATE, Same),
        99 => (STATFS, OldStatfs),
        106 => (STAT, OldStat),
        107 => (LSTAT, OldStat),
        122 => (UNAME, Same),
        182 => (CHOWN, Same),
        183 => (GETCWD, Same),
        193 => (TRUNCATE, Truncate64),
        195 => (STAT, Stat64),
        196 => (LSTAT, Stat64),
        198 => (LCHOWN, Same),
        212 => (CHOWN, Same),
        226 => (SETXATTR, Same),
        227 => (LSETXATTR, Same),
        229 => (GETXATTR, Same),
        230 => (LGETXATTR, Same),
        232 => (LISTXATTR, Same),
        233 => (LLISTXATTR, Same),
        235 => (REMOVEXATTR, Same),
        236 => (LREMOVEXATTR, Same),
        268 => (STATFS, Statfs64),
        271 => (UTIMES, Time32),
        292 => (INOTIFY_ADD_WATCH, Same),
        295 => (OPENAT, Same),
        296 => (MKDIRAT, Same),
        297 => (MKNODAT, Same),
        298 => (FCHOWNAT, Same),
        299 => (FUTIMESAT, Time32),
        300 => (NEWFSTATAT, Stat64),
        301 => (UNLINKAT, Same),
        302 => (RENAMEAT, Same),
        303 => (LINKAT, Same),
        304 => (SYMLINKAT, Same),
        305 => (READLINKAT, Same),
        306 => (FCHMODAT, Same),
        307 => (FACCESSAT, Same),
        320 => (UTIMENSAT, Timespec32),
        341 => (NAME_TO_HANDLE_AT, Same),
        353 => (RENAMEAT2, Same),
        358 => (EXECVEAT, Same),
        361 => (BIND, Same),
        362 => (CONNECT, Same),
        383 => (STATX, Same),
        412 => (UTIMENSAT, Same),
        437 => (OPENAT2, Same),
        439 => (FACCESSAT2, Same),
        452 => (FCHMODAT2, Same),
        23 => (SETUID, Same),
        24 => (GETUID, Same),
        46 => (SETGID, Same),
        47 => (GETGID, Same),
        49 => (GETEUID, Same),
        50 => (GETEGID, Same),
        70 => (SETREUID, Same),
        71 => (SETREGID, Same),
        80 => (GETGROUPS, Id16),
        81 => (SETGROUPS, Same),
        95 => (FCHOWN, Same),
        138 => (SETFSUID, Same),
        139 => (SETFSGID, Same),
        164 => (SETRESUID, Same),
        165 => (GETRESUID, Id16),
        170 => (SETRESGID, Same),
        171 => (GETRESGID, Id16),
        185 => (CAPSET, Same),
        199 => (GETUID, Same),
        200 => (GETGID, Same),
        201 => (GETEUID, Same),
        202 => (GETEGID, Same),
        203 => (SETREUID, Same),
        204 => (SETREGID, Same),
        205 => (GETGROUPS, Same),
        206 => (SETGROUPS, Same),
        207 => (FCHOWN, Same),
        208 => (SETRESUID, Same),
        209 => (GETRESUID, Same),
        210 => (SETRESGID, Same),
        211 => (GETRESGID, Same),
        213 => (SETUID, Same),
        214 => (SETGID, Same),
        215 => (SETFSUID, Same),
        216 => (SETFSGID, Same),
        _ => return None,
    })
}

/// Maps an ARM EABI syscall number onto the x86_64 number.
///
/// Like i386 it keeps the legacy non-`at` calls and the 32-bit structure
/// variants, but its `stat64` layout and 64-bit argument pairing are its own.
pub fn arm_to_x86_64(nr: i64) -> Option<(i64, Variant)> {
    use Variant::*;
    Some(match nr {
        5 => (OPEN, Same),
        8 => (CREAT, Same),
        9 => (LINK, Same),
        10 => (UNLINK, Same),
        11 => (EXECVE, Same),
        12 => (CHDIR, Same),
        14 => (MKNOD, Same),
        15 => (CHMOD, Same),
        16 => (LCHOWN, Same),
        33 => (ACCESS, Same),
        38 => (RENAME, Same),
        39 => (MKDIR, Same),
        40 => (RMDIR, Same),
        61 => (CHROOT, Same),
        83 => (SYMLINK, Same),
        85 => (READLINK, Same),
        92 => (TRUNCATE, Same),
        99 => (STATFS, OldStatfs),
        106 => (STAT, OldStat),
        107 => (LSTAT, OldStat),
        122 => (UNAME, Same),
        182 => (CHOWN, Same),
        183 => (GETCWD, Same),
        193 => (TRUNCATE, Truncate64Arm),
        195 => (STAT, ArmStat64),
        196 => (LSTAT, ArmStat64),
        198 => (LCHOWN, Same),
        212 => (CHOWN, Same),
        226 => (SETXATTR, Same),
        227 => (LSETXATTR, Same),
        229 => (GETXATTR, Same),
        230 => (LGETXATTR, Same),
        232 => (LISTXATTR, Same),
        233 => (LLISTXATTR, Same),
        235 => (REMOVEXATTR, Same),
        236 => (LREMOVEXATTR, Same),
        266 => (STATFS, Statfs64),
        269 => (UTIMES, Time32),
        282 => (BIND, Same),
        283 => (CONNECT, Same),
        317 => (INOTIFY_ADD_WATCH, Same),
        322 => (OPENAT, Same),
        323 => (MKDIRAT, Same),
        324 => (MKNODAT, Same),
        325 => (FCHOWNAT, Same),
        326 => (FUTIMESAT, Time32),
        327 => (NEWFSTATAT, ArmStat64),
        328 => (UNLINKAT, Same),
        329 => (RENAMEAT, Same),
        330 => (LINKAT, Same),
        331 => (SYMLINKAT, Same),
        332 => (READLINKAT, Same),
        333 => (FCHMODAT, Same),
        334 => (FACCESSAT, Same),
        348 => (UTIMENSAT, Timespec32),
        370 => (NAME_TO_HANDLE_AT, Same),
        382 => (RENAMEAT2, Same),
        387 => (EXECVEAT, Same),
        397 => (STATX, Same),
        412 => (UTIMENSAT, Same),
        437 => (OPENAT2, Same),
        439 => (FACCESSAT2, Same),
        452 => (FCHMODAT2, Same),
        23 => (SETUID, Same),
        24 => (GETUID, Same),
        46 => (SETGID, Same),
        47 => (GETGID, Same),
        49 => (GETEUID, Same),
        50 => (GETEGID, Same),
        70 => (SETREUID, Same),
        71 => (SETREGID, Same),
        80 => (GETGROUPS, Id16),
        81 => (SETGROUPS, Same),
        95 => (FCHOWN, Same),
        138 => (SETFSUID, Same),
        139 => (SETFSGID, Same),
        164 => (SETRESUID, Same),
        165 => (GETRESUID, Id16),
        170 => (SETRESGID, Same),
        171 => (GETRESGID, Id16),
        185 => (CAPSET, Same),
        199 => (GETUID, Same),
        200 => (GETGID, Same),
        201 => (GETEUID, Same),
        202 => (GETEGID, Same),
        203 => (SETREUID, Same),
        204 => (SETREGID, Same),
        205 => (GETGROUPS, Same),
        206 => (SETGROUPS, Same),
        207 => (FCHOWN, Same),
        208 => (SETRESUID, Same),
        209 => (GETRESUID, Same),
        210 => (SETRESGID, Same),
        211 => (GETRESGID, Same),
        213 => (SETUID, Same),
        214 => (SETGID, Same),
        215 => (SETFSUID, Same),
        216 => (SETFSGID, Same),
        _ => return None,
    })
}

/// Little-endian field writer for the 32-bit structure layouts.
struct Out<const N: usize>([u8; N]);

impl<const N: usize> Out<N> {
    fn new() -> Self {
        Out([0u8; N])
    }
    fn u64(&mut self, off: usize, v: u64) {
        self.0[off..off + 8].copy_from_slice(&v.to_ne_bytes());
    }
    fn u32(&mut self, off: usize, v: u64) {
        self.0[off..off + 4].copy_from_slice(&(v as u32).to_ne_bytes());
    }
    fn u16(&mut self, off: usize, v: u64) {
        self.0[off..off + 2].copy_from_slice(&(v as u16).to_ne_bytes());
    }
}

/// Converts the host's `struct stat` into the i386 `struct stat64` (96 bytes).
///
/// Layout: st_dev 0 (8), __pad0 8 (4), __st_ino 12 (4), st_mode 16, st_nlink 20,
/// st_uid 24, st_gid 28, st_rdev 32 (8), __pad3 40 (4), st_size 44 (8),
/// st_blksize 52 (4), st_blocks 56 (8), times 64..88 (6 x 4), st_ino 88 (8).
// Field types differ between hosts (u32 on aarch64 where x86_64 has u64), so the casts stay.
#[allow(clippy::unnecessary_cast)]
pub fn stat_to_stat64(st: &libc::stat) -> [u8; 96] {
    let mut o = Out::<96>::new();
    o.u64(0, st.st_dev as u64);
    o.u32(12, st.st_ino as u64);
    o.u32(16, st.st_mode as u64);
    o.u32(20, st.st_nlink as u64);
    o.u32(24, st.st_uid as u64);
    o.u32(28, st.st_gid as u64);
    o.u64(32, st.st_rdev as u64);
    o.u64(44, st.st_size as u64);
    o.u32(52, st.st_blksize as u64);
    o.u64(56, st.st_blocks as u64);
    for (off, v) in [
        (64usize, st.st_atime),
        (68, st.st_atime_nsec),
        (72, st.st_mtime),
        (76, st.st_mtime_nsec),
        (80, st.st_ctime),
        (84, st.st_ctime_nsec),
    ] {
        o.u32(off, v as u64);
    }
    o.u64(88, st.st_ino as u64);
    o.0
}

/// Converts the host's `struct stat` into the ARM EABI `struct stat64` (104 bytes).
///
/// Same fields as the i386 layout, but every 64-bit field sits on an 8-byte
/// boundary: st_size 48, st_blksize 56, st_blocks 64, times 72..96, st_ino 96.
// Field types differ between hosts (u32 on aarch64 where x86_64 has u64), so the casts stay.
#[allow(clippy::unnecessary_cast)]
pub fn stat_to_arm_stat64(st: &libc::stat) -> [u8; 104] {
    let mut o = Out::<104>::new();
    o.u64(0, st.st_dev as u64);
    o.u32(12, st.st_ino as u64);
    o.u32(16, st.st_mode as u64);
    o.u32(20, st.st_nlink as u64);
    o.u32(24, st.st_uid as u64);
    o.u32(28, st.st_gid as u64);
    o.u64(32, st.st_rdev as u64);
    o.u64(48, st.st_size as u64);
    o.u32(56, st.st_blksize as u64);
    o.u64(64, st.st_blocks as u64);
    for (off, v) in [
        (72usize, st.st_atime),
        (76, st.st_atime_nsec),
        (80, st.st_mtime),
        (84, st.st_mtime_nsec),
        (88, st.st_ctime),
        (92, st.st_ctime_nsec),
    ] {
        o.u32(off, v as u64);
    }
    o.u64(96, st.st_ino as u64);
    o.0
}

/// Converts the host's `struct stat` into the old 32-bit `struct stat` (64 bytes), shared by i386 and ARM.
///
/// Fields that do not fit yield `EOVERFLOW`, as the kernel does.
// Field types differ between hosts (u32 on aarch64 where x86_64 has u64), so the casts stay.
#[allow(clippy::unnecessary_cast)]
pub fn stat_to_old_stat(st: &libc::stat) -> Result<[u8; 64], i32> {
    let (ino, size) = (st.st_ino as u64, st.st_size as i64);
    if ino > u32::MAX as u64 || size > i32::MAX as i64 || size < i32::MIN as i64 {
        return Err(libc::EOVERFLOW);
    }
    // st_dev 0 (4), st_ino 4 (4), st_mode 8 (2), st_nlink 10 (2), st_uid 12 (2),
    // st_gid 14 (2), st_rdev 16 (4), st_size 20 (4), st_blksize 24 (4), st_blocks 28 (4),
    // times 32..56 (6 x 4), unused 56..64.
    let mut o = Out::<64>::new();
    o.u32(0, old_encode_dev(st.st_dev as u64) as u64);
    o.u32(4, ino);
    o.u16(8, st.st_mode as u64);
    o.u16(10, st.st_nlink as u64);
    o.u16(12, st.st_uid as u64);
    o.u16(14, st.st_gid as u64);
    o.u32(16, old_encode_dev(st.st_rdev as u64) as u64);
    o.u32(20, size as u64);
    o.u32(24, st.st_blksize as u64);
    o.u32(28, st.st_blocks as u64);
    for (off, v) in [
        (32usize, st.st_atime),
        (36, st.st_atime_nsec),
        (40, st.st_mtime),
        (44, st.st_mtime_nsec),
        (48, st.st_ctime),
        (52, st.st_ctime_nsec),
    ] {
        o.u32(off, v as u64);
    }
    Ok(o.0)
}

/// Kernel `old_encode_dev`: 8-bit major and minor packed into 16 bits.
fn old_encode_dev(dev: u64) -> u32 {
    let major = ((dev >> 8) & 0xfff) as u32;
    let minor = ((dev & 0xff) | ((dev >> 12) & 0xfff00)) as u32;
    ((major & 0xff) << 8) | (minor & 0xff)
}

/// The host's `f_flags`, which the libc crate leaves inside `f_spare`.
///
/// Both 64-bit hosts lay `struct statfs` out identically: `f_flags` is the
/// word at offset 80.
fn statfs_flags(sf: &libc::statfs) -> u64 {
    let p = sf as *const _ as *const u8;
    let b = unsafe { std::slice::from_raw_parts(p.add(80), 8) };
    u64::from_ne_bytes(b.try_into().unwrap())
}

/// Bytes of the host's `struct statfs` `f_fsid` field.
fn fsid_bytes(sf: &libc::statfs) -> [u8; 8] {
    let p = &sf.f_fsid as *const _ as *const u8;
    let mut b = [0u8; 8];
    b.copy_from_slice(unsafe { std::slice::from_raw_parts(p, 8) });
    b
}

/// Converts the host's `struct statfs` into the 32-bit `struct statfs64` (84 bytes, i386 and ARM).
///
/// Layout: f_type 0 (4), f_bsize 4 (4), f_blocks 8 (8), f_bfree 16, f_bavail 24, f_files 32,
/// f_ffree 40, f_fsid 48 (8), f_namelen 56 (4), f_frsize 60 (4), f_flags 64 (4), spare 68..84.
// Field types differ between hosts (u32 on aarch64 where x86_64 has u64), so the casts stay.
#[allow(clippy::unnecessary_cast)]
pub fn statfs_to_statfs64(sf: &libc::statfs) -> [u8; 84] {
    let mut o = Out::<84>::new();
    o.u32(0, sf.f_type as u64);
    o.u32(4, sf.f_bsize as u64);
    o.u64(8, sf.f_blocks as u64);
    o.u64(16, sf.f_bfree as u64);
    o.u64(24, sf.f_bavail as u64);
    o.u64(32, sf.f_files as u64);
    o.u64(40, sf.f_ffree as u64);
    o.0[48..56].copy_from_slice(&fsid_bytes(sf));
    o.u32(56, sf.f_namelen as u64);
    o.u32(60, sf.f_frsize as u64);
    o.u32(64, statfs_flags(sf));
    o.0
}

/// Converts the host's `struct statfs` into the old 32-bit `struct statfs` (64 bytes, all 32-bit fields).
// Field types differ between hosts (u32 on aarch64 where x86_64 has u64), so the casts stay.
#[allow(clippy::unnecessary_cast)]
pub fn statfs_to_old_statfs(sf: &libc::statfs) -> [u8; 64] {
    let mut o = Out::<64>::new();
    for (i, v) in [
        sf.f_type as u64,
        sf.f_bsize as u64,
        sf.f_blocks as u64,
        sf.f_bfree as u64,
        sf.f_bavail as u64,
        sf.f_files as u64,
        sf.f_ffree as u64,
    ]
    .into_iter()
    .enumerate()
    {
        o.u32(i * 4, v);
    }
    o.0[28..36].copy_from_slice(&fsid_bytes(sf));
    o.u32(36, sf.f_namelen as u64);
    o.u32(40, sf.f_frsize as u64);
    o.u32(44, statfs_flags(sf));
    o.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_common_numbers() {
        assert_eq!(i386_to_x86_64(5), Some((OPEN, Variant::Same)));
        assert_eq!(i386_to_x86_64(195), Some((STAT, Variant::Stat64)));
        assert_eq!(i386_to_x86_64(300), Some((NEWFSTATAT, Variant::Stat64)));
        assert_eq!(i386_to_x86_64(11), Some((EXECVE, Variant::Same)));
        assert_eq!(i386_to_x86_64(1), None);
        assert!(Abi::I386.numbers_for(&[OPEN, OPENAT]).contains(&295));
        assert_eq!(
            Abi::Aarch64.numbers_for(&[OPENAT, NEWFSTATAT, OPEN]),
            vec![56, 79]
        );
        assert_eq!(Abi::Aarch64.to_canonical(221), Some((EXECVE, Variant::Same)));
        assert_eq!(Abi::Arm.to_canonical(5), Some((OPEN, Variant::Same)));
    }

    #[test]
    fn stat64_layouts_carry_key_fields() {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_ino = 0x1122334455u64 as _;
        st.st_mode = 0o100644;
        st.st_size = 5_000_000_000i64 as _;
        st.st_atime = 1_700_000_000 as _;
        let s = stat_to_stat64(&st);
        assert_eq!(u64::from_ne_bytes(s[88..96].try_into().unwrap()), 0x1122334455);
        assert_eq!(u32::from_ne_bytes(s[16..20].try_into().unwrap()), 0o100644);
        assert_eq!(u64::from_ne_bytes(s[44..52].try_into().unwrap()), 5_000_000_000);
        assert_eq!(u32::from_ne_bytes(s[64..68].try_into().unwrap()), 1_700_000_000);
        let a = stat_to_arm_stat64(&st);
        assert_eq!(u64::from_ne_bytes(a[96..104].try_into().unwrap()), 0x1122334455);
        assert_eq!(u64::from_ne_bytes(a[48..56].try_into().unwrap()), 5_000_000_000);
        assert_eq!(u32::from_ne_bytes(a[72..76].try_into().unwrap()), 1_700_000_000);
        assert_eq!(stat_to_old_stat(&st), Err(libc::EOVERFLOW));
    }

    #[test]
    fn arm_numbers_and_flags() {
        assert_eq!(Abi::Arm.to_canonical(322), Some((OPENAT, Variant::Same)));
        assert_eq!(Abi::Arm.to_canonical(327), Some((NEWFSTATAT, Variant::ArmStat64)));
        assert_eq!(Abi::Arm.to_canonical(283), Some((CONNECT, Variant::Same)));
        assert!(Abi::Arm.numbers_for(&[OPENAT, STAT]).contains(&195));
        let arm_nofollow_dir = 0o100000 | 0o40000 | 0o2;
        let host = Abi::Arm.open_flags_to_host(arm_nofollow_dir);
        assert_eq!(host & libc::O_NOFOLLOW as i64, libc::O_NOFOLLOW as i64);
        assert_eq!(host & libc::O_DIRECTORY as i64, libc::O_DIRECTORY as i64);
        assert_eq!(host & 0o2, 0o2);
        assert_eq!(
            Abi::X86_64.open_flags_to_host(libc::O_NOFOLLOW as i64),
            libc::O_NOFOLLOW as i64
        );
    }
}
