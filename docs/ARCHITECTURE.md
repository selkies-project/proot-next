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
and a third level composes the same way.  The requester's bindings beneath a
nested bind are carried along under it, as a recursive bind mount carries
submounts, while a nested root stays the plain directory it names: pressure-vessel binds the host `/` at `/run/host` and
points the container's 32-bit loader at the one it finds there.  The table, with the launch's
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

## Yama scope 2

Both modes rest on the kernel's ptrace access check towards every tracee.
Yama's `ptrace_scope` of 2 refuses it to anyone without `CAP_SYS_PTRACE`,
even towards a child, and checks that capability in the tracee's user
namespace.  So `access.rs` forks a probe child before anything else and
tries `PTRACE_SEIZE` (when the filter allows ptrace) and a read of a known
static through `process_vm_readv` or `/proc/<pid>/mem`, first plainly and
then with the child in a fresh user namespace.  The first plan that works
wins: ptrace, ptrace in a namespace, no-ptrace, no-ptrace in a namespace.
In a namespace the first tracee calls `unshare(CLONE_NEWUSER)` and writes
an identity map of its own uid and gid before installing the filter; the
supervisor stays in the initial namespace and owns the new one, which gives
it every capability there.  The tracer seizes the child after receiving the
listener, by which time the child is inside.  `PTRACE_SEIZE` on itself is
no use as a probe: it answers `ESRCH` at scope 2 as everywhere else.  When
no plan works the guest-stub mode below takes over; where it cannot (not
x86_64 or aarch64, or `PROOT_GUEST_STUB=0`) the launch fails with exit 1 rather than
serving a guest whose memory it cannot read (a no-ptrace guest hung at the
first notification).

The default Docker and Kubernetes `RuntimeDefault` profiles refuse
`unshare` without `CAP_SYS_ADMIN`, and an added `CAP_SYS_PTRACE` is not
effective for a non-root user, so a typical pod on a scope 2 node ends up
in the guest-stub mode.

## Guest stub restricted mode

Where `unshare` is also refused (the common Kubernetes case, and Docker's
default profile for a user without `CAP_SYS_ADMIN`), neither ptrace nor a
user namespace is available, so the supervisor cannot read or write guest
memory at all.  Nearly every syscall it serves has its important argument
in guest memory (the path of `open`, the buffer of `stat`).  This mode puts
a stub inside each guest process that moves that memory where the
supervisor can see it.  `guest_stub.rs` is the supervisor's side, the
trampoline's `stub.rs` and `loader.rs` the guest's, and `layout.rs` (in the
trampoline's crate, compiled into both) the contract between them.

### Gates and the filter

One page at a fixed address holds two gates, the allow gate and the
notify gate.  The filter reads the instruction pointer of every syscall
before anything else: one made from the allow gate is allowed, one from
the notify gate goes to the listener, whatever its number.  64-bit and
32-bit processes have their gate page, and their mailbox, at addresses of
their own: `0x7100_0000_0000` on x86_64, `0x40_0000_0000` on aarch64 (inside
a 39-bit address space too, under where position-independent programs
load), `0xe0000000` for both 32-bit ABIs.  A 64-bit gate is `syscall; jmp
*%r12` or `svc #0; br x16`, the caller passing its return address in a
register the kernel preserves and no syscall reads, so it needs no stack;
i386 uses every free register for arguments, so a 32-bit gate is `int
$0x80; ret`, called, and on 32-bit ARM `svc #0; bx lr`, called.  On ARM the
gate code is written and then pushed through the caches (`dc cvau`/`ic
ivau`, the `cacheflush` call) before it runs.  Everything else meets the
usual tiers, except that the trace list
is every served syscall with memory to stage, returned as
`SECCOMP_RET_TRAP` with a tag, plus `rt_sigaction` and `rt_sigprocmask`.
Served syscalls that need only registers (`clone`, `fork`, `vfork`,
`fchdir`, the `-0` identity calls) are notified directly.  `clone3`, whose
flags are in memory, gets `ENOSYS`, on which every C library falls back to
`clone`.  The compat tiers are built the same way from the i386 or ARM
numbers, i386 `bind` and `connect` of `socketcall` trapped by their call
number.

Telling the stub's syscalls apart by the address they are made from means
no register value a program might happen to pass can make the filter take
its call for the stub's, as a marker in an argument register could.

The x86_64 address has to clear another program's filter too.  For games
that make Windows syscalls directly, Proton's Wine installs a filter
(`install_bpf` in `dlls/ntdll/unix/signal_x86_64.c`) that traps every
syscall made from an address whose high word is `0x7000` or lower as the
game's, native libraries being mapped above that.  Its trap outranks our
filter's allow, the stub passes the `SIGSYS` on to Wine's handler as it
should, and Wine crashed on the stub's own `gettid` (a Windows DOSBox
build under Proton Experimental) while the gates were at `0x6e70_0000_0000`.

### Mailbox

A 16 MiB memfd, mapped `MAP_SHARED` at a fixed address in every guest and
anywhere in the supervisor.  Its first page holds one owner per slot; then
come 128 slots of 128 KiB.  A thread claims a slot by writing its thread id
into the owner with a compare-and-swap and frees it by writing 0; a thread
that finds every slot taken takes back those whose owner no longer exists
(`kill(tid, 0)` answers `ESRCH`) and otherwise yields until one frees.
Each invocation of the handler claims its own slot, so a signal handler
that interrupts it can make trapped syscalls of its own.

`tracee::mem` serves guest addresses inside the mailbox from the
supervisor's mapping and answers `EFAULT` for every other address, so the
handlers in `syscall::notify` and `syscall::direct` run unchanged on the
staged copies, and a handler that reads memory the stub did not stage
fails visibly instead of reading the guest by accident on a host where it
could.

### The handler

On a tagged `SIGSYS` the handler reads the syscall's number and arguments
from the signal frame, then, by the table in `layout.rs`:

1. copies every path into a 4 KiB area of its slot (a NULL path stays
   NULL, one without a NUL in 4096 bytes fails with `ENAMETOOLONG`), every
   input buffer (`struct open_how`, a socket address, a `timespec` pair,
   an extended attribute value) after them, and reserves room for every
   output buffer, pointing those arguments at the copies;
2. makes the syscall itself from the notify gate.  The supervisor answers
   it from the copies, injects a descriptor, or lets it continue, in which
   case the kernel runs it on the copies, which are valid memory in the
   process; a path the kernel must open in the caller (`O_PATH`,
   `inotify_add_watch`) is replaced in place by its host path, which the
   4 KiB area always has room for;
3. copies back what the call wrote (the whole `struct stat`, or as many
   bytes as `readlink` returned), frees the slot and stores the result in
   the saved result register (`rax`, `eax`, `x0`, `r0`).

The other saved registers are never touched, so the program finds them as
a syscall leaves them.  The handler runs with `SA_NODEFER` and makes its
own syscalls through the allow gate with inline assembly: the thread
pointer belongs to the program, so no libc.

`SIGSYS` must never be blocked when a trap fires: the kernel then resets
the handler and kills the process.  Programs block every signal routinely
(`posix_spawn`'s child, a thread created with a full mask, a handler
registered with `sigfillset`), so `rt_sigprocmask` is emulated on the mask
saved in the signal frame, which `rt_sigreturn` installs, with `SIGSYS`
left out, and `rt_sigaction` strips `SIGSYS` from every handler's mask.
For `SIGSYS` itself `rt_sigaction` records the program's action without
installing it, and a `SIGSYS` that is not one of the filter's traps (a
filter of the program's own, `kill`) goes to that action.

### Exec, and the first program

Signal handlers are reset by `execve` and `ld.so` opens libraries before
any preloaded code runs, so a stub loaded with `LD_PRELOAD` would arrive
too late.  Every exec goes through the trampoline instead, which loads the
program in place.

On `execve` the handler stages the path, `argv` and `envp` (only `argv[0]`
when they do not fit in a slot, which is enough for anything but a nested
launch, then refused with `E2BIG`).  The supervisor plans the exec from the
copy as in the no-ptrace mode, refuses what the trampolines cannot load
(a format only `binfmt_misc` knows with `ENOEXEC`, a 32-bit program on a
kernel without ia32 emulation with `EOPNOTSUPP`), installs a descriptor of
the mailbox into the caller with `ADDFD`, writes the record and answers
with that descriptor's number.  The handler frees its slot and execs `e`
through the allow gate with the caller's own vectors.  For a 32-bit
program the record says so, and `e` execs `e32`, the i386 or 32-bit ARM
build of the same trampoline, with its own vectors, leaving the record for
it; the other way round, a 32-bit process's stub execs `e` like any other.
rustc links i686, armv7 and aarch64 musl statically but not
position-independent, so those trampolines are linked at `0xd0000000`,
above where fixed-address programs load and far below position-independent
ones (the aarch64 startup code also needs to be within 4 GiB of address
0); the x86_64 one is position-independent.

The trampoline maps the gates first and makes its own syscalls through the
allow gate until the stub is armed, maps the mailbox from the descriptor
named in the record, arms the handler, and tells the supervisor with a
`getpid` from the notify gate carrying a mark, at which the pending exec is
completed (the program recorded for `/proc/self/exe`, a nested view
entered).  That has to be a real syscall: container runtimes' profiles
refuse unknown numbers, and their refusal outranks the notification.  Then
it maps the program the way `binfmt_elf` would: a position-independent
file wherever `mmap` finds room, aligned to its segments, a fixed-address
one only where nothing is mapped, in pages of the size the kernel reports,
the bss past the last file page anonymous.  The
rest of the last file page of a segment with a bss is zeroed to the end of
the page, not only of the segment, as the kernel does: glibc's `ld.so`
allocates its first link map from that tail without clearing it, and
Ubuntu's i386 `ld.so` crashed on the file data a shorter clearing left
there.  The
interpreter is opened through an ordinary, trapped `open`, so the
supervisor translates it, and loaded the same way.  The new stack goes
below the trampoline's frames, with the trampoline's own auxiliary vector
(vDSO, `AT_RANDOM`, ids, hardware capabilities) and the entries that
describe the program replaced; the argument and environment pointers point
at the strings the kernel already holds, so `/proc/self/cmdline` and a
program that rewrites its title see what they would.  The vector the
kernel keeps, which `PR_GET_AUXV` and `/proc/self/auxv` return (rustix
reads it, and uutils' multi-call binary picks its applet by the name in
its `AT_EXECFN`), points at the path `e` was exec'd by, which is padded
with slashes to the longest a staged path can be (`./…/e`) so the
trampoline can write the program's path over it.  `comm` is set from the
record.  A 32-bit ARM entry point with the Thumb bit is entered in Thumb.

The first program is planned by the supervisor before it lets the child
go, and the child execs the trampoline through the allow gate with the
mailbox descriptor it inherited.

### Costs and limits

- No dearer than the other modes: best of five on this host, `ls -lR /usr`
  in the test rootfs took 50 ms against 57 ms without ptrace and 55 ms with
  it, and 300 execs of `/bin/true` 130 ms against 168 ms and 119 ms.  The
  trap and the copies cost about what `process_vm_readv` and
  `/proc/<pid>/mem` do.
- 32-bit programs run where the kernel has ia32 emulation, or on aarch64
  where the CPU and kernel run AArch32.
- A 32-bit process gives up 16 MiB of its address space at `0xe0100000`
  to the mailbox, and `e32` sits at `0xd0000000`.
- On aarch64 the loader maps programs without `PROT_BTI`, so a program
  built for branch target identification runs without it on CPUs that
  have it.
- `/proc/<pid>/exe` and the first line of `/proc/<pid>/maps` name the
  trampoline at the kernel level; the supervisor answers for `exe`.  The
  auxiliary vector the kernel keeps describes the trampoline but for
  `AT_EXECFN`.
- An executable the guest may run but not read cannot be loaded.
- A vfork child that changes the `SIGSYS` action changes it for its parent
  too, since the recorded action lives in shared memory.
- A program that passes an invalid non-NULL pointer to a trapped syscall
  faults in the handler rather than getting `EFAULT`.
- A program that longjmps out of a signal handler that interrupted the
  stub leaves a slot claimed until the thread exits.

### Status

The fallback: `access::probe` selects the mode when neither ptrace nor a
user namespace reaches the guest's memory, unless `PROOT_GUEST_STUB=0`
rules it out; `PROOT_GUEST_STUB=force` selects it anywhere, which is how
the e2e suite covers it on any host.  x86_64 and aarch64 hosts, for their
64-bit and 32-bit programs.
Checked with Firefox and a Chromium build rendering pages headless and the
GTK4 proot-apps installer (glycin's nested bwrap loaders included) on a
desktop host, with Firefox through proot-apps inside a selkies container
under Docker's default profile at Yama scope 2, and on i386 with a Debian
trixie rootfs (shell, apt under `-0`, gcc) and the stub probe built for
i386, run under proot and under its `bwrap` front end in a locked-down
selkies container with Ubuntu 26.04's i386 libraries.  Steam in a selkies
container under Docker's default profile with every capability but the six
its init needs dropped and `no-new-privileges`, at Yama scope 2, took the
mode as the fallback for pressure-vessel's `bwrap` and ran games through
every runtime path Steam uses: native 64-bit and native 32-bit programs in
the Steam Linux Runtime, and Windows programs, 32-bit ones included, under
Proton 11 and Proton Experimental.  On aarch64
(Neoverse-N1, 4K pages, 48-bit addresses), in a locked-down selkies
container with the mode forced: the e2e suite in all three modes, the stub
probe for aarch64 and for 32-bit ARM, and an armhf Debian rootfs running
apt and gcc under `-0`.

## Why a small warm pool

The kernel hands a notification to the longest-waiting receiver.  On an idle
host that is a cold core in a deep C-state, which costs more than the round
trip itself.  `seccomp/notify.rs` therefore lets exactly one thread wait at a
time, spinning on `poll` for `PROOT_SPIN_US` before sleeping, and hands the
token to a spinning follower when it receives.  Four threads was the sweet
spot on a 32-core powersave host; 32 threads was 3x slower than one.

## Path translation

`fs/binding.rs` holds the longest-prefix tables both ways, and keeps the
host side of the root and of every binding open as an `O_PATH` descriptor.
`fs/canon.rs` walks a guest path component by component from those
descriptors: each intermediate component is opened `O_PATH` relative to the
directory walked so far (`openat2` with `RESOLVE_NO_SYMLINKS`, so a symlink
reports itself), a symlink's target is re-entered as a guest path, and a
component that is a mount point of the view switches to that binding's own
descriptor.  The walk never touches a textual host path, so neither a
symlink inside the rootfs nor a rename of the rootfs's own parents on the
host (the rootfs under a bound `$HOME`) leads it out.  Its result is the
canonical guest path plus the pinned parent directory and the final name,
and the handlers in `syscall/notify.rs` act on that pair with the `*at`
syscalls and `O_NOFOLLOW`/`AT_SYMLINK_NOFOLLOW`, since the walk already
followed a final symlink when asked to.  A symlink found there was swapped
in by the guest after the walk: the call is walked again, three times at
most, so the link is resolved inside the guest, then fails with `ELOOP`.
Syscalls without a `dirfd` form (`truncate`, `statfs`, `chmod`, the xattr
family) act on the object's `/proc/self/fd/<n>`, which the kernel resolves
to the open inode once the object is seen not to be a symlink; the
`l*xattr` variants act on `/proc/self/fd/<parent>/<name>`, since the name as
it is now is what they are for.  A mount point itself (`/`, a binding) is
acted on through its own descriptor the same way, and is busy to `unlink`,
`rmdir` and `rename` as a mount point is.  A `/proc/<pid>/fd/N` link as the
last component is left to the kernel, which re-opens the object behind it
(a memfd, a pipe); followed by more components it must be a directory,
whose path is re-entered as a guest path.

An empty path fails with `ENOENT` before any walk, as the kernel's lookup
fails it, rather than naming the working directory: CUDA's driver unlinks
`""` before it binds an abstract socket, and gives up on `EISDIR`.  The calls
that let an empty path name `dirfd` itself, `AT_EMPTY_PATH` and `readlinkat`,
resolve the descriptor's own path, or the working directory's for
`AT_FDCWD`, and the ptrace tier leaves an empty path to the kernel.

A missing final component is returned as a name in its parent, so the
kernel creates it or reports `ENOENT` through the pinned directory.  A
missing intermediate component fails the lookup with `ENOENT`, as the
kernel's would: `stat("/missing/..")` is `ENOENT`, where PRoot resolves it
lexically to `/`.  The binding table is the exception: a binding's guest
path is canonicalized when the view is built with the rest kept lexical and
the final component as given, so a binding named through a symlink of the
rootfs (`/lib/ld-linux.so.2` on a merged-usr host) lands on the entry
lookups resolve to.  A binding whose host side does not exist yet is walked
textually, and pinned by the first lookup that finds it there.  So is a
directory the view has only because a binding lies below it, where `glue`
could not make a placeholder (a rootfs the user cannot write): the walk goes
on by name to the binding's own descriptor, as PRoot resolves it lexically.

The directory cache (`DirCache`) holds the `O_PATH` descriptors of canonical
guest directories already walked, keyed by view, capped at 512 descriptors
and flushed on every syscall that may replace a directory.  A lookup through
a cached entry lands in the directory the entry pinned, whatever the name
points to now, so the stale answer a change made outside proot-next can give
is that directory, never a path the kernel walks.  Without the cache
(`PROOT_NO_PATH_CACHE=1`) every component costs one `openat2`, about a
quarter more on a `stat` loop.

What stays textual is what the tracee must walk itself.  The ptrace tier
rewrites the paths of `execve`, `chdir`, `chroot`, `connect`, `bind`,
`inotify_add_watch` and `O_PATH` opens in the tracee's memory
(`syscall/traced.rs`); without ptrace the exec trampoline runs the host path
of the program and the loader, and the alias directory's transient symlinks
stand for the host paths of `inotify_add_watch` and of `O_PATH` opens of
special files.  A unix socket address names the socket as
`/proc/self/fd/<parent>/<name>`, so its parents are pinned while a swap of
the final name during a `connect` is followed.  There a guest racing its own
call lands where its symlink points, which reaches nothing its user cannot
reach already, and the README says so: proot-next confines paths, as PRoot
does, and is no boundary against a guest working against it.
`fs/translate.rs` resolves `dirfd`-relative paths by reading the
descriptor's path from `/proc/<pid>/fd` and detranslating it, then walks the
joined guest path.

## Mount points

A directory listing is the kernel's: `getdents` runs untranslated on a
descriptor of the host directory, so a binding whose guest path has nothing
behind it on disk is found by name and missing from its parent's listing.
Loaders that discover drivers by listing a directory (libglvnd's
`egl_vendor.d`, the Vulkan loader's `icd.d`, the OpenCL ICD loader) then
never see a vendor file bound in one by one, which is how proot-apps hands
the NVIDIA driver to its guests.  `fs/glue.rs` does what PRoot does: when a
view is built, every missing component of a binding's guest path is
created in the directory under it, an empty file or a directory after the
binding's host side, and removed when the view ends.  The walk never
follows a symlink and never creates under a read-only binding.  Each
placeholder carries the `user.proot-next.placeholder` attribute, so one
left by a supervisor that was killed is adopted and removed by the next
launch.  `PROOT_DONT_POLLUTE_ROOTFS` turns this off.  Emulating `getdents`
instead would need the tracee's directory position, which only
`pidfd_getfd` reaches and a default container profile refuses.

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
* `/proc/<pid>/fd/N`, `map_files/*` and `ns/*` links are not canonicalized:
  they name objects (memfds, pipes, deleted files, namespaces) that only the
  kernel can reach, so the walk stops at the link and the host resolves it.
  An `ns/*` link reads as `pid:[n]` and the like, not a path, so a `stat`
  through one only works this way.

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

Both, and the `/proc/<pid>/fd` links the handlers resolve descriptors
through, pass the kernel's ptrace access check, which a tracee closes to
everyone without `CAP_SYS_PTRACE` by clearing its dumpable flag
(`prctl(PR_SET_DUMPABLE, 0)`, what Bitwarden's process isolation and
Chromium's sandbox do): every path syscall after it got `EACCES`, Bitwarden
could not open its log or create a thread.  The filter sends that `prctl`
and `PR_GET_DUMPABLE` to the listener, which records the value per process
and answers without clearing anything; an exec resets the record as the
kernel resets the flag.  Every other `prctl` option runs natively.

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
* A mount point left by a supervisor that was killed stays on a filesystem
  without user extended attributes; elsewhere the next launch removes it.
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
* In the user namespace used at Yama scope 2, only the caller's uid and gid
  are mapped: other owners read as `nobody` through calls the kernel answers
  (`fstat`), supplementary groups as `nogroup`, and
  `setgroups` is refused without `-0`.
* Without ptrace: a buffer refilled by the program between a rewrite and its
  restore is not restored, and one read back in the microseconds before the
  restore shows the alias; `connect` after a `bind` on the same socket loses
  the bind; a failed `execve` whose failure the kernel reported (not one
  refused here) leaves `e` in the caller's path string.
