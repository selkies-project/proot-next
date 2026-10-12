# Test probes

Small programs the integration tests (`tests/e2e.rs`) run under proot-next.
They reproduce the failures found while bringing up real applications, so a
regression shows up here before it shows up in a browser or a game.

| Probe | Built for | What it proves |
|---|---|---|
| `socketcall32` | i686, static musl | A 32-bit `connect()` issued through the i386 `socketcall` multiplexer is translated through a binding (what gave Half-Life its sound). |
| `armtest` | armv7, static musl | readlink, getcwd, stat64, open, O_PATH, chdir and uname from a 32-bit ARM tracee on an aarch64 host. |
| `gpprobe.c` | host, needs `libudev-dev` | Chromium's gamepad discovery: libudev enumeration, the O_PATH opens it does, device node access and the udev monitor. Built and run by the test when the header is present. |

`build.sh` builds the two Rust probes into `tests/probes/bin/`, which the
tests look for; a missing probe makes its test skip with a message rather
than fail, so `cargo test` works on a tree that never ran `build.sh`.
