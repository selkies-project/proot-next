<p align="center">
  <img src="assets/logo.svg" alt="P#-next" width="160" height="160">
</p>

<h1 align="center">proot-next</h1>

<p align="center">Part of <a href="https://www.linuxserver.io"><img src="https://raw.githubusercontent.com/selkies-project/proot-next/main/assets/linuxserver.svg" alt="LinuxServer.io" title="LinuxServer.io" width="32" height="32" align="middle"></a></p>

[![Tests](https://github.com/selkies-project/proot-next/actions/workflows/tests.yml/badge.svg)](https://github.com/selkies-project/proot-next/actions/workflows/tests.yml) [![Release](https://img.shields.io/github/v/release/selkies-project/proot-next?display_name=tag)](https://github.com/selkies-project/proot-next/releases/latest) [![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0) [![Docs](https://img.shields.io/badge/docs-proot.selkies.io-blue)](https://proot.selkies.io/) [![Discord](https://img.shields.io/badge/dynamic/json?logo=discord&label=Discord%20Members&query=approximate_member_count&url=https%3A%2F%2Fdiscordapp.com%2Fapi%2Finvites%2FwDNGDeSW5F%3Fwith_counts%3Dtrue)](https://discord.gg/wDNGDeSW5F) [![Ask DeepWiki](https://img.shields.io/badge/Ask-DeepWiki-blue)](https://deepwiki.com/selkies-project/proot-next)

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
Everything else runs untraced at native speed.  Where a container's seccomp
profile filters ptrace out, those few are served through notifications as
well, with an exec trampoline and a virtual working directory.

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

Full documentation: https://proot.selkies.io/

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

## Steam

Steam, Proton and Wine in a Debian-based amd64 container that has no user
namespaces, where a stock Steam stops at "Steam now requires user namespaces
to be enabled":

```bash
curl -fsSL https://raw.githubusercontent.com/selkies-project/proot-next/main/install-steam.sh | sudo sh
```

That installs Steam with the 32-bit libraries it needs, puts the latest
release's binary in `/usr/local/lib/proot-next` with the `bwrap` name beside
it, and points Steam's own launcher at it (`PROOT_NEXT_VERSION` picks another
release). Start Steam as usual. The Steam Linux Runtime is used exactly as
Valve ships it, and the client's browser helper, native games and Proton all
run through bwrap mode. `tests/steam/check.sh` exercises it the way Steam does.

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

## Security

proot-next confines paths, not privileges: the guest runs as the user who
started it, and nothing it reaches is beyond what that user can reach
already.  A symlink in the rootfs is resolved as the guest's, so it never
leads a lookup out.  The syscalls the supervisor serves act through directory
descriptors its walk pinned, not on a host path the kernel would walk again,
so a guest that renames a directory of its own and puts a symlink in its
place during its own call gets the directory it had, or the link resolved
inside the guest, never the host directory the link names.  The few syscalls
the tracee must run itself (an exec, and under ptrace `chdir`, `connect`,
`bind`, `inotify_add_watch` and `O_PATH` opens) still walk a host path, so
there such a swap lands where the link points.  Like PRoot, it is no boundary
against a guest working against it; run untrusted code in a container, which
is.

## License

This project is licensed under the **Mozilla Public License Version 2.0**.
See [LICENSE](LICENSE).
