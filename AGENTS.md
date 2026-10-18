# Working on this repository

proot-next is the PRoot reimplementation behind
[proot-apps](https://github.com/linuxserver/proot-apps) and the bwrap stand-in the
[selkies baseimages](https://github.com/linuxserver/docker-baseimage-selkies) hand to Steam's pressure-vessel.
A change here is usually tested through one of those two.

Rust, edition 2024. Rustdoc on every public item in Google style: a one-line summary, then `# Arguments`
(`* name - description`), `# Returns`, `# Errors` as applicable; types are always explicit in signatures. Usage
documentation lives in `docs/` (fumadocs, published to GitHub Pages with the rustdoc under `/rustdoc/`). Comments
describe the current code for a reader, not the change that produced it; no inline comments, no issue numbers.
American English.

The floor before reporting a change: `cargo test` (unit tests plus `tests/e2e.rs`, which drives the built binary;
build the 32-bit probes first with `tests/probes/build.sh` and point `PROOT_TEST_ROOTFS` at a rootfs from
`scripts/fetch-rootfs.sh ghcr.io/linuxserver/proot-apps:debian-trixie rootfs`, or those cases skip),
`cargo clippy --all-targets -- -D warnings` and `pre-commit run --all-files`. Every failure found in a real
application becomes a case in `tests/e2e.rs` or a probe under `tests/probes/`; a change to translation, exec or the
tracer is also run against a desktop app through proot-apps and, when it touches bwrap mode, against Steam's
webhelper in a selkies container. Everything here can be tested
empirically on the host, so every claim in a report has been run, and anything that could not be run says so.

CodeQL's code scanning alerts are at least stylistic recommendations: each is fixed in the code and closed by the
next scan, never dismissed or closed by hand, a case that is so by design included. Code that is safe through a check
CodeQL cannot follow (a validator in another function, a bound set elsewhere) is rewritten so the check sits where
the query recognizes it (its `*Customizations.qll` in github/codeql lists the forms), so the scan keeps watching
that path.

Architecture and the lessons that cost the most time are in `docs/ARCHITECTURE.md`; read it before changing the
tracer, the filter or canonicalization. A supervisor must stay invisible to its tracees (no `TracerPid`, breakpoints
resumed, no translation of `/proc/<pid>/fd` links) and must never leave a tracee blocked in a notification: every
request is answered exactly once.

Releases: a push to `main` publishes the static binaries to a pre-release named by the short commit hash; a
`MAJOR.MINOR.PATCH` tag releases with `release-notes/<tag>.md` as its body, so the notes are written with the
change, and `Cargo.toml` carries the same version as the tag.
