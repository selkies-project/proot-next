#!/bin/bash
# Builds the static exec shim for both hosts and stores the binaries under bin/.
# Self-contained musl linking through rustup targets, so no cross toolchain is
# needed; the results are committed and embedded into proot with include_bytes!.
#
#   src/exec/shim/build.sh              # x86_64 and aarch64
#   src/exec/shim/build.sh aarch64      # one
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/bin" "$here/.cargo"
cp "$here/.cargo-config.toml" "$here/.cargo/config.toml"
for arch in ${@:-x86_64 aarch64}; do
  target="$arch-unknown-linux-musl"
  rustup target add "$target" >/dev/null 2>&1 || true
  (cd "$here" && cargo build --release --target "$target" --quiet)
  cp "$here/target/$target/release/proot-shim" "$here/bin/shim-$arch"
  echo "built $here/bin/shim-$arch ($(stat -c %s "$here/bin/shim-$arch") bytes)"
done
