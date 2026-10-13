<p align="center">
  <img src="assets/logo.svg" alt="P#-next" width="160" height="160">
</p>

# proot-next

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0) [![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://selkies-project.github.io/proot-next/) [![Tests](https://github.com/selkies-project/proot-next/actions/workflows/tests.yml/badge.svg)](https://github.com/selkies-project/proot-next/actions/workflows/tests.yml) [![Release](https://img.shields.io/github/v/release/selkies-project/proot-next?display_name=tag)](https://github.com/selkies-project/proot-next/releases/latest)

PRoot reimplemented in Rust: `chroot`, `mount --bind` and a bubblewrap front
end without any privilege, for containers where user namespaces and FUSE are
off the table.  Built for [proot-apps](https://github.com/linuxserver/proot-apps)
and for standing in for `bwrap` under pressure-vessel.

## How it differs from PRoot

PRoot stops every traced syscall twice with ptrace.  proot-next routes
path-taking syscalls through **seccomp user notification**: a small pool of
supervisor threads reads the path out of the tracee, translates it, performs
the real syscall itself and hands the result (or an injected descriptor) back.
Only `execve`, `chdir`, `chroot` and unix-socket `bind`/`connect` take a
ptrace stop, because they must change the tracee's own state in place.
Everything else runs untraced at native speed.

Measured against PRoot 5.5.0 on the same host with `-R` on the same rootfs
(`bench/` has the harness and `docs/ARCHITECTURE.md` the table): path lookups
1.1x to 1.6x faster, `readlink`/`getcwd` 1.7x to 2.8x faster, `stat` from 16
threads 2x faster, and `uname`/`prctl` at native speed where PRoot
stops them.

## Install

Static binaries for x86_64 and aarch64, no runtime dependencies. The latest
release for your architecture, into `~/.local/bin`, with the `bwrap` name
beside it:

```bash
mkdir -p ~/.local/bin && cd ~/.local/bin \
  && curl -fsSL -o proot "https://github.com/selkies-project/proot-next/releases/latest/download/proot-$(uname -m)" \
  && chmod +x proot && ln -sf proot bwrap && ./proot --version
```

Full documentation: https://selkies-project.github.io/proot-next/

## Usage

```
proot -R ./rootfs /entrypoint arg...          # proot-apps style
proot -S ./rootfs apt-get install hello       # fake root: package managers work
proot -r ./rootfs -b /tmp -b /home/me:/home/me -w / /bin/sh
PROOT_THREADS=4 PROOT_SPIN_US=200 proot ...   # supervisor pool tuning
ln -s proot bwrap && ./bwrap --ro-bind /usr /usr --proc /proc -- /bin/sh   # bwrap mode
```

The binary switches to the bubblewrap command line when its `argv[0]` ends in
`bwrap`, busybox style.  Steam's pressure-vessel honours `$BWRAP`, so pointing
that at the symlink is enough.

## Building

```
cargo build --release          # target/release/proot
cargo test
```

Static builds for distribution: `cargo build --release --target x86_64-unknown-linux-musl`.
aarch64: `cargo build --release --target aarch64-unknown-linux-gnu` (needs an
aarch64 linker, or build natively on the aarch64 host).

## Platforms

x86_64 hosts run x86_64 and i386 programs; aarch64 hosts run aarch64 and
32-bit ARM programs.
Works wherever Docker's default seccomp profile and AppArmor policy apply, with
no capabilities and no user namespaces.

## License

This project is licensed under the **Mozilla Public License Version 2.0**.
See [LICENSE](LICENSE).
