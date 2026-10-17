//! Syscall routing: which numbers go where, and the handlers for each tier.

pub mod direct;
pub mod notify;
pub mod nr;
pub mod traced;

use nr::*;

/// Syscalls answered by the supervisor through user notification.
///
/// `uname` is appended at runtime only when a kernel release is faked.
pub const NOTIFY_SYSCALLS: &[i64] = &[
    OPEN,
    STAT,
    LSTAT,
    ACCESS,
    GETCWD,
    RENAME,
    MKDIR,
    RMDIR,
    CREAT,
    LINK,
    UNLINK,
    SYMLINK,
    READLINK,
    CHMOD,
    CHOWN,
    LCHOWN,
    TRUNCATE,
    STATFS,
    MKNOD,
    UTIME,
    UTIMES,
    SETXATTR,
    LSETXATTR,
    GETXATTR,
    LGETXATTR,
    LISTXATTR,
    LLISTXATTR,
    REMOVEXATTR,
    LREMOVEXATTR,
    OPENAT,
    MKDIRAT,
    MKNODAT,
    FCHOWNAT,
    FUTIMESAT,
    NEWFSTATAT,
    UNLINKAT,
    RENAMEAT,
    LINKAT,
    SYMLINKAT,
    READLINKAT,
    FCHMODAT,
    FACCESSAT,
    UTIMENSAT,
    NAME_TO_HANDLE_AT,
    RENAMEAT2,
    STATX,
    FACCESSAT2,
    OPENAT2,
    FCHMODAT2,
];

/// Syscalls added to the notify tier by `-0`: identity queries answered as root,
/// identity changes accepted, descriptor ownership changes forgiven.
pub const FAKE_ROOT_SYSCALLS: &[i64] = &[
    GETUID, GETGID, GETEUID, GETEGID, GETRESUID, GETRESGID, SETUID, SETGID, SETREUID, SETREGID, SETRESUID,
    SETRESGID, SETFSUID, SETFSGID, SETGROUPS, GETGROUPS, CAPSET, FCHOWN,
];

/// Syscalls served through notification instead of a ptrace stop when
/// there is no ptrace: the trace tier plus `fchdir` (the working directory
/// is virtual then) and the `clone` family (the child's state is snapshotted
/// at the fork).
pub const NO_PTRACE_SYSCALLS: &[i64] = &[
    EXECVE,
    EXECVEAT,
    CHDIR,
    FCHDIR,
    CHROOT,
    CONNECT,
    BIND,
    INOTIFY_ADD_WATCH,
    CLONE,
    FORK,
    VFORK,
    CLONE3,
];

/// Syscalls whose namespace flags are refused with `EPERM` by the filter
/// itself, as a default container refuses them: a tracee in a mount
/// namespace of its own could not be served by a supervisor that does the
/// filesystem work in its own.  `clone3` carries its flags in memory and is
/// inspected by a handler instead; `setns` is refused outright.
pub const NAMESPACE_FLAG_SYSCALLS: &[i64] = &[CLONE, UNSHARE];

/// Syscalls whose dumpable-flag operations go to the listener.
///
/// A process that clears its dumpable flag closes `process_vm_readv`,
/// `/proc/<pid>/mem` and `/proc/<pid>/fd` to everyone without
/// `CAP_SYS_PTRACE`, the supervisor included, and every later path syscall
/// would fail with `EACCES`.  The filter routes `prctl(PR_SET_DUMPABLE)` and
/// `PR_GET_DUMPABLE` here, where the flag is remembered instead of changed;
/// every other `prctl` runs natively.
pub const DUMPABLE_SYSCALLS: &[i64] = &[PRCTL];

/// Syscalls refused with `EPERM` unconditionally.
pub const REFUSED_SYSCALLS: &[i64] = &[SETNS];

/// `CLONE_NEW*` bits of `clone`, `clone3` and `unshare` flags.
pub const CLONE_NEWNS_FLAGS: u64 = 0x7e02_0080;

/// Syscalls that take a ptrace stop so their arguments can be edited in place.
///
/// `inotify_add_watch` is here because a watch can only be added to the
/// tracee's own inotify descriptor, so the path is rewritten in place.
pub const TRACE_SYSCALLS: &[i64] = &[EXECVE, EXECVEAT, CHDIR, CHROOT, CONNECT, BIND, INOTIFY_ADD_WATCH];
