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
| refuse | `EPERM` from the filter | `clone`/`unshare` with a `CLONE_NEW*` flag, `setns`; `clone3` via a handler | see below |

`uname` joins the notify tier only when `-k` fakes a kernel release.

## No namespaces inside the guest

The supervisor does the filesystem work in its own mount namespace.  A
tracee that created one of its own (bubblewrap run by glycin for GTK's image
loaders, Firefox's content sandbox, a nested bwrap) would get its `mkdir`s
and `open`s served from the wrong namespace: bwrap's `newroot` landed in the
host's `/tmp` and its loaders then failed.  So namespace creation is refused
with `EPERM`, which is what a default Docker container answers too and what
every such helper already handles: bwrap prints "No permissions to create a
new namespace" and glycin falls back to running its loaders unsandboxed.
`clone` and `unshare` are checked in BPF on their flags argument; `clone3`
keeps its flags in memory, so it is notified in both modes and checked by
`syscall::direct::do_clone`; `setns` is refused outright.

## Nested proot and bwrap

The kernel allows one tracer per process and one listener per seccomp
filter chain, so a proot started inside the guest can never be a second
supervisor (PRoot gets around the first limit by emulating ptrace for its
tracees, at about ten times the cost of a single PRoot, and would still hit
the second).  It does not need to be one: the supervisor already serves
every descendant, and a nested launch only needs a different translation
table for one subtree.  So an `execve` of the supervisor's own binary
(matched by inode), or of any ELF named `proot`, `proot-next` or `bwrap`
(matched by name, unless `PROOT_NEST=0`), is not carried out.
`exec/nested.rs` parses the command line with the same front ends as
`main`, on the tracee's behalf: paths are looked up in the tracee's view,
the working directory and environment are the tracee's (its `envp` is read
from the exec), and `--args`, `--file` and `--seccomp` descriptors are read
through `/proc/<pid>/fd`.  The root and the host side of every binding are
translated through the requester's view, so the result is a flat table in
host terms: a nested view can see no more than the view it was asked from,
and a third level composes the same way.  The table, with the launch's
`-k`/`-0`/`--hostname` values, is a `View` (`state.rs`); each process record
holds an `Arc` to its view, inherited at fork, and the directory cache is
shared across views and keyed by view.

The process that called `proot` becomes the command, so the caller's child,
its exit status and its signals are the kernel's own.  The exec is
retargeted at the trampoline in both modes, exec'd by its full path with
ptrace, and the record carries what only the process itself can do: the
complete argument vector, a replaced environment, the `chdir` (with ptrace;
without it the view's virtual cwd is set), `setsid`, the death signal, the
caller's seccomp programs, the status descriptors, and for
`--json-status-fd` a fork whose parent waits and reports the exit code,
which is bubblewrap's own process shape in the one case a caller depends on
it.  A usage error, `--help` or `--version` is also carried out by the
trampoline, on the caller's own stderr or stdout.  The process enters its
view at the trampoline's exec of the real target, where the pending record
is completed (`exec::finish_pending`); until then its syscalls pass
through untranslated, as they do for every trampoline.

The filter is fixed at launch, so a nested `-0` or `-k` is refused with a
message unless the outer launch already notifies those syscalls; a nested
`--hostname` is dropped in that case.  bwrap's materialized root is removed
when the last process of the view is gone.

## Without ptrace

A container profile that filters the `ptrace` syscall still allows the
listener, `process_vm_readv` and `/proc/<pid>/mem` (the kernel's access check
for those is separate from the syscall), so the trace tier is served through
notifications instead.  `launch.rs` probes with `PTRACE_PEEKUSER` on itself,
which a working ptrace answers with `ESRCH` and a filter with its own errno;
`PROOT_NO_PTRACE=1` forces the mode for testing.  A notification cannot
change registers, only answer, continue, or install a descriptor, so
(`syscall/direct.rs`):

* `chdir`, `fchdir` and `chroot` are answered without running.  Each process
  has a virtual cwd in `procs.rs`, path translation resolves relative paths
  against it, and the kernel's own cwd of every tracee is pinned to the alias
  directory under `$XDG_RUNTIME_DIR`.
* `connect` and `bind` are done by the supervisor on a socket of the same
  type and `O_NONBLOCK`/`O_CLOEXEC` (read from `/proc/net/unix` and
  `fdinfo`), which replaces the tracee's descriptor through `ADDFD` with
  `SETFD`.  Options set before the call and a `bind` before a `connect` are
  lost; `SO_PEERCRED` names the supervisor.
* `execve` cannot be retargeted from outside, so the path string is
  overwritten in place through `/proc/<pid>/mem` (which, unlike
  `process_vm_writev`, writes read-only pages) with `e`, a two-byte name that
  resolves in the pinned cwd to a static trampoline (`exec/shim/`, embedded).
  The supervisor writes `r<pid>` next to it with the planned exec path and
  leading arguments, lets the exec continue, passes the trampoline's own
  syscalls through untranslated while `/proc/<pid>/exe` is the trampoline,
  and records the program at the trampoline's exec of the real target.  A
  program the kernel would refuse is refused before the rewrite with the
  kernel's errno (a shell depends on `ENOEXEC` to run `#!`-less scripts
  itself; `binfmt_misc` entries are matched the kernel's way).  `execveat`
  with `AT_EMPTY_PATH` replaces the descriptor with one on the trampoline;
  a dirfd-relative path also replaces the dirfd with the alias directory.
* `inotify_add_watch` and the `O_PATH` opens that cannot be served with a
  read-only descriptor (sockets, devices, unreadable files, symlinks with
  `O_NOFOLLOW`) get the same in-place rewrite to a transient one-character
  symlink.  The original bytes are put back once the task has consumed the
  argument, judged by CPU time from `/proc/<pid>/schedstat`
  (`/proc/<pid>/syscall` reads `running` both before and after the copy), and
  only if the memory still holds exactly what was written: a freed or reused
  buffer is left alone.  A `vfork`/`posix_spawn` child's exec path lives in
  the parent and is restored there under the same rule.
* The supervisor reads and writes tracee memory on its own authority, which
  Yama's default `ptrace_scope` of 1 (Ubuntu) grants only towards
  descendants, so it makes itself a child subreaper: a double-forked daemon
  is adopted rather than handed to init, and reaped by the launcher.
* Without fork events, `procs.rs` discovers a process at its first
  notification and copies its parent's state from `/proc`.  `clone` and
  relatives are notified only to queue a snapshot of the parent for the
  child, and a parent that exits first leaves its snapshots to an orphan
  list, so a daemon's double fork inherits the right cwd.  Exits come from
  pidfds polled by a reaper thread.  Thread-to-process mappings are cached
  for a second.

Nothing of the "looking like nothing is there" work applies: there is no
tracer to hide, breakpoints and fatal signals are the kernel's business, and
a guest can be debugged again.

The cost is confined to the former trace tier.  One `bench/run.sh` run on
the host above, same rootfs, ptrace mode against the no-ptrace mode: path
lookups identical within noise, unix socket connect 3.2x against 2.3x,
fork+wait 1.2x against 0.9x, fork+exec 1.4x against 1.9x (two execs per
exec), `getcwd` 29x against 40x.

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
loader with the program as its argument (`--argv0` on glibc).  Three things
the kernel would have taken from the program are taken care of: the loader is
given the resolved program path, since that is where it takes `$ORIGIN`
from (Electron apps started through a `/usr/bin` symlink find their bundled
libraries that way); it is reached through an alias named as the tracee
named the program, so `comm` reads as the kernel would set it, a script
keeping its own name (glibc's loader reports the program path in
`AT_EXECFN` by itself); and `/proc/<pid>/cmdline` is served
with the loader prefix removed, so `ps` and `pgrep -f` see the argv the
tracee passed.  The guest path of the program is remembered per process so
`readlink(/proc/self/exe)` is answered truthfully.  Known gap: the kernel's
own notion of the exe, seen from outside the guest, is the alias.

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
* Kernel-level `/proc/<pid>/exe` names the loader alias; `readlink` is
  answered from our own record and `cmdline` is served, but a tool outside
  the guest sees the alias.  A glibc older than 2.33 in a rootfs loses
  `--argv0`, and with it the resolved `$ORIGIN`.
* `execveat` of a memfd (`AT_EMPTY_PATH` on a descriptor without a path)
  fails; PRoot refuses it too.
* bwrap: `--dev` binds the host `/dev`; `--uid/--gid`, `--unshare-*` and the
  capability options are no-ops; `--hostname` only affects `uname`, and not
  at all in a nested launch under an outer launch without `-k` or
  `--hostname`.
* Nested `-0` and `-k` need the outer launch to have them.  A debugger inside
  a ptrace-mode guest still gets `EPERM`: ptrace is not emulated.
* Opening a FIFO through a non-identity binding blocks a supervisor thread.
* `name_to_handle_at` returns `EOPNOTSUPP`.
* Without ptrace: a buffer refilled by the program between a rewrite and its
  restore is not restored, and one read back in the microseconds before the
  restore shows the alias; `connect` after a `bind` on the same socket loses
  the bind; a failed `execve` whose failure the kernel reported (not one
  refused here) leaves `e` in the caller's path string.
