#!/bin/bash
# Builds the static exec shim for both hosts, and the 32-bit one each host
# also installs for its compat guests (i686 on x86_64, armv7 on aarch64), and
# stores the binaries under bin/.
# Self-contained musl linking through rustup targets, so no cross toolchain is
# needed; the results are committed and embedded into proot with include_bytes!.
#
#   src/exec/shim/build.sh              # x86_64, i686, aarch64 and armv7
#   src/exec/shim/build.sh aarch64      # one
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/bin" "$here/.cargo"
cp "$here/.cargo-config.toml" "$here/.cargo/config.toml"
for arch in ${@:-x86_64 i686 aarch64 armv7}; do
  case $arch in
    armv7) target=armv7-unknown-linux-musleabihf ;;
    *) target="$arch-unknown-linux-musl" ;;
  esac
  rustup target add "$target" >/dev/null 2>&1 || true
  (cd "$here" && cargo build --release --target "$target" --quiet)
  cp "$here/target/$target/release/proot-shim" "$here/bin/shim-$arch"
  echo "built $here/bin/shim-$arch ($(stat -c %s "$here/bin/shim-$arch") bytes)"
done
