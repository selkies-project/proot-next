# Architecture

## Process model

```
proot (supervisor)
 ├─ main thread ........ ptrace tracer (tracer.rs): seccomp-trace stops for
 │                        execve/chdir/chroot/bind/connect, fork/exec events
 └─ notify-N threads ... leader/followers pool (seccomp/notify.rs) answering
                          user notifications for every other path syscall
tracee tree ............ inherits one seccomp filter (seccomp/filter.rs)
                          installed by the first child before execve
```

The first child does `PR_SET_NO_NEW_PRIVS`, `PTRACE_TRACEME`, installs the
filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, passes the listener fd back
over a socketpair with `SCM_RIGHTS`, raises `SIGSTOP`, then `chdir`s and
`execve`s.  Both of those last calls are already traced.

## ABIs

Two hosts: x86_64 (serving x86_64 and i386 tracees) and aarch64 (serving
aarch64 and 32-bit ARM tracees).  A 32-bit ARM thread reports an 18-word
register set through `NT_PRSTATUS`, which is how it is told apart; its
syscall number is r7, its `stat64` has 8-byte-aligned 64-bit fields (104
bytes), 64-bit arguments arrive on even register pairs, and its
`O_DIRECTORY`/`O_NOFOLLOW` values differ from x86's, so open flags are
remapped per ABI before any handler reads them.  `src/abi.rs` maps every ABI's numbers onto the canonical x86_64
ones the handlers use; `tracee/regs.rs` has one backend per host, and on
aarch64 the syscall number is changed through the `NT_ARM_SYSTEM_CALL`
regset.  Handlers size `struct stat` from the host's libc, since it is 128
bytes on aarch64 and 144 on x86_64.

A 32-bit process uses the i386 ABI: different numbers, arguments in
`ebx..ebp`, 4-byte pointers and a few 32-bit structure layouts.  The filter
has one jump table per ABI, both landing on the same actions.  Notifications
carry the arch, so `syscall/notify.rs` maps an i386 number to the x86_64
handler plus a `Variant` describing the layout differences; at ptrace stops the
code segment selector tells the ABI and `Regs` maps registers accordingly.  The
exec handler reads argv in the caller's pointer width and retargets ELF32
programs at the 32-bit loader.

## Syscall tiers

| tier | mechanism | syscalls | why |
|---|---|---|---|
| notify | listener pool | open/stat/access/readlink/getcwd/mkdir/unlink/rename/link/symlink/chmod/chown/utimensat/truncate/statfs/xattr/inotify/openat2/statx... | result can be produced by the supervisor and written back or injected with ADDFD |
| trace | ptrace stop | execve, execveat, chdir, chroot, connect, bind | must change the tracee's own state; args rewritten on its stack |
| allow | none | everything else | no path involved |

`uname` joins the notify tier only when `-k` fakes a kernel release.

## Why a small warm pool

The kernel hands a notification to the longest-waiting receiver.  On an idle
host that is a cold core in a deep C-state, which costs more than the round
trip itself.  `seccomp/notify.rs` therefore lets exactly one thread wait at a
time, spinning on `poll` for `PROOT_SPIN_US` before sleeping, and hands the
token to a spinning follower when it receives.  Four threads was the sweet
spot on a 32-core powersave host; 32 threads was 3x slower than one.

## Path translation

`fs/binding.rs` holds the longest-prefix tables both ways.  `fs/canon.rs`
walks a guest path component by component, lstat-ing the host side and
re-entering symlink targets as guest paths, so a link inside the rootfs can
never escape it.  `fs/translate.rs` resolves `dirfd`-relative paths by reading
the descriptor's path from `/proc/<pid>/fd` and detranslating it, then
canonicalizes the joined guest path.

## execve

The kernel resolves `PT_INTERP` itself, which would escape the guest.  The
exec handler translates the program, expands `#!` interpreters, reads
`PT_INTERP`, and re-targets the exec at the host path of the guest's dynamic
loader with the program as its argument (`--argv0` on glibc).  The guest path
of the program is remembered per process so `readlink(/proc/self/exe)` is
answered truthfully.  Known gap: `AT_EXECFN` and the kernel's own notion of
the exe point at the loader.

## Looking like nothing is there

A ptrace supervisor is indistinguishable from a debugger unless it works at
it.  Three things learned from Steam's webhelper:

* `/proc/<pid>/status` is served from a read-only memfd with `TracerPid`
  zeroed.  Valve's assert macro checks that field and executes `int3` when a
  debugger seems present; Chromium's crash reporter also keys off it.
* An `int3` breakpoint (SIGTRAP with `si_code == SI_KERNEL`, `0xCC` at
  `rip-1`) is resumed past, as an attached debugger would.  A genuine crash
  sequence is `int3; ud2` and still dies on the `ud2`.
* `/proc/<pid>/fd/N` and `map_files/*` links are not canonicalized: they name
  open objects (memfds, pipes, deleted files) that only the kernel can re-open,
  so the walk stops at the link and the host resolves it.

Tracees are `PTRACE_SEIZE`d so group-stops arrive as `PTRACE_EVENT_STOP` and
get `PTRACE_LISTEN`; forwarding them as signals re-stops the whole thread
group and storms a multithreaded tracee.

## Fake root

`-0` adds the identity syscalls to the notify tier.  Each process carries a
virtual `Ids` (real, effective, saved and filesystem uid and gid, root to
start) and an optional `setgroups` list; the getters report them and the
setters apply the kernel's rules, so a daemon that drops to an unprivileged
user and verifies the drop, as apt's methods do, sees what it expects.
`chown`, `fchown` and `mknod` refusals read as success, files owned by the
supervisor's ids stat as root's, and the served `/proc/<pid>/status` shows
the virtual ids.

## Tracee memory

`process_vm_readv/writev` when permitted (Docker's default profile allows
them), `/proc/<pid>/mem` otherwise, opened per access so a stale descriptor
never reads a pre-exec address space.

## Measurements

`bench/run.sh` builds `bench/sysbench.c`, runs it natively and under one or
two proot binaries, and prints ns per operation with the slowdown against
native.  The table is one run on an x86_64 host (Linux 6.12), both binaries
with `-R` on the proot-apps debian-trixie rootfs, PRoot 5.5.0 being the
static x86_64 release from proot-me.  Figures are slowdown over native, so
lower is better.

| test | proot-next | PRoot 5.5.0 |
|---|---|---|
| stat deep path | 18.5x | 24.8x |
| access deep path | 18.3x | 29.6x |
| open+close deep path | 9.1x | 14.3x |
| stat ENOENT | 35.2x | 31.9x |
| readlink | 22.6x | 39.2x |
| readlink /proc/self/exe | 8.9x | 22.3x |
| getcwd | 29.9x | 82.2x |
| unix socket connect | 4.1x | 6.7x |
| uname | 1.3x | 69.2x |
| prctl | 1.5x | 61.7x |
| stat x4 threads | 23.1x | 47.3x |
| stat x16 threads | 53.8x | 110.6x |
| fork+exec /bin/true | 1.5x | 1.6x |

Lookups that fail with `ENOENT` are the one place PRoot is ahead: it lets the
kernel fail the call on the tracee's behalf after a ptrace stop, where
proot-next pays a full notify round trip to learn the same thing.  Exec is
within noise of PRoot, since both have to stop the tracee for it.  Every path
component does a linear prefix scan over the binding table (`-R` installs
about fifteen bindings), and the read-only check detranslates once more per
call; identity (`-r /`) runs at about 6x, so that is the headroom left in
lookups.

## Known gaps

* Hosts: x86_64 (x86_64 + i386 tracees) and aarch64 (aarch64 + 32-bit ARM
  tracees).  x32 gets `ENOSYS`.  Of the i386 `socketcall` multiplexer only
  `bind` and `connect` are translated; `sendto`/`sendmsg` with a unix
  address are not.
* No link2symlink, no qemu, no sysvipc/ashmem extensions.
* Errors from the trace tier surface as `ENOSYS` (no exit stop to set errno);
  missing files are passed through so the kernel reports `ENOENT` itself.
* `AT_EMPTY_PATH` operations pass through to the kernel on the host fd (correct
  by construction, but untranslated).
* Mount points for bindings are not "glued" into the rootfs listing: `ls /`
  only shows entries that physically exist in the rootfs.
* Kernel-level `/proc/<pid>/exe`, `/proc/<pid>/comm` and `AT_EXECFN` name the
  dynamic loader; `readlink` is answered from our own record.  A glibc older
  than 2.33 in a rootfs loses `--argv0`.
* bwrap: `--dev` binds the host `/dev`; `--uid/--gid`, `--unshare-*` and the
  capability options are no-ops; `--hostname` only affects `uname`.
* Opening a FIFO through a non-identity binding blocks a supervisor thread.
* `name_to_handle_at` returns `EOPNOTSUPP`.
