#!/bin/bash
# Build the 32-bit probe binaries the integration tests use.  Static musl, so
# they run on any host of the right architecture without an armhf or i386
# userland.  Output: tests/probes/bin/{socketcall32,armtest}.
#
#   tests/probes/build.sh            # both
#   tests/probes/build.sh armtest    # one
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/bin"
build() { # crate target
  local crate=$1 target=$2
  rustup target add "$target" >/dev/null 2>&1 || true
  mkdir -p "$here/$crate/.cargo" && cp "$here/.cargo-config.toml" "$here/$crate/.cargo/config.toml"
  (cd "$here/$crate" && cargo build --release --target "$target" --quiet)
  cp "$here/$crate/target/$target/release/$crate" "$here/bin/$crate"
  echo "built $here/bin/$crate ($target)"
}
for crate in ${@:-socketcall32 armtest}; do
  case $crate in
    socketcall32) build socketcall32 i686-unknown-linux-musl ;;
    armtest) build armtest armv7-unknown-linux-musleabihf ;;
    *) echo "unknown probe $crate" >&2; exit 1 ;;
  esac
done
