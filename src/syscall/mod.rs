//! Syscall routing: which numbers go where, and the handlers for each tier.

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

/// Syscalls that take a ptrace stop so their arguments can be edited in place.
///
/// `inotify_add_watch` is here because a watch can only be added to the
/// tracee's own inotify descriptor, so the path is rewritten in place.
pub const TRACE_SYSCALLS: &[i64] = &[EXECVE, EXECVEAT, CHDIR, CHROOT, CONNECT, BIND, INOTIFY_ADD_WATCH];
