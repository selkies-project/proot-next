# bench

Syscall micro benchmark used for the numbers in `docs/ARCHITECTURE.md`.

`sysbench.c` runs the syscalls a desktop application hammers (path lookups,
descriptor churn, ioctl, unix socket traffic, process creation) plus a few
untraced controls, and prints ns per operation. `run.sh` builds it, runs it
natively and under one or two proot binaries, and prints the slowdown of each
against native so two implementations can be compared on the same host.

```bash
cargo build --release
scripts/fetch-rootfs.sh ghcr.io/linuxserver/proot-apps:debian-trixie rootfs
curl -LO https://github.com/proot-me/proot/releases/download/v5.5.0/proot && chmod +x proot
bench/run.sh target/release/proot ./proot -- -R rootfs
```

`SYSBENCH_ARGS="-n 20000 -t 8"` tunes iterations and threads. Results depend
on the host and kernel; compare binaries in the same run, not across runs.
