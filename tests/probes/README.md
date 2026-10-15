# Test probes

Small programs the integration tests (`tests/e2e.rs`) run under proot-next.
They reproduce the failures found while bringing up real applications, so a
regression shows up here before it shows up in a browser or a game.

| Probe | Built for | What it proves |
|---|---|---|
| `socketcall32` | i686, static musl | A 32-bit `connect()` issued through the i386 `socketcall` multiplexer is translated through a binding (what gave Half-Life its sound). |
| `armtest` | armv7, static musl | readlink, getcwd, stat64, open, O_PATH, chdir and uname from a 32-bit ARM tracee on an aarch64 host. |
| `gpprobe.c` | host, needs `libudev-dev` | Chromium's gamepad discovery: libudev enumeration, the O_PATH opens it does, device node access and the udev monitor. Built and run by the test when the header is present. |
| `stubprobe.c` | x86_64 or aarch64 host, `cc` (and `-m32 -no-pie` on x86_64); its 32-bit ARM checks are built by hand with an armhf compiler, the suite does not | What a program takes for granted about its syscalls, under the guest stub: preserved registers, NULL and over-long paths, output buffers, 48 threads at once, every signal blocked, a handler with a full mask, a `SIGSYS` handler of its own, spawn, vfork, and an exec whose environment does not fit a mailbox slot. Built by the test, checked natively first. |
| `bsstail.c` | x86_64 or aarch64 host, `cc` (and `-m32` on x86_64) | The page after a program's bss reads zero once the guest stub's loader has mapped it, as the kernel leaves it; Ubuntu's i386 `ld.so` allocates its first link map there. |
| `winefilter.c` | x86_64 host, `cc` | Installs the seccomp filter Proton's Wine uses for some games, which traps syscalls made from low addresses as Windows code; the guest stub's gates must lie above its line. |
| `denyunknown.c` | x86_64 or aarch64 host, `cc` | Runs a command under a seccomp filter that refuses unknown syscall numbers, as container runtimes' default profiles do. |

`build.sh` builds the two Rust probes into `tests/probes/bin/`, which the
tests look for; a missing probe makes its test skip with a message rather
than fail, so `cargo test` works on a tree that never ran `build.sh`.
