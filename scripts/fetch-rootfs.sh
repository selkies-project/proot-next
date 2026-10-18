#!/bin/bash
# Pull a single-layer proot-apps image from a registry into a directory, the
# way proot-apps does, for tests.  Usage: scripts/fetch-rootfs.sh IMAGE DIR
#
# Every request is retried on any error, including an HTTP error status and
# a connection reset, so one registry hiccup does not fail a whole CI matrix.
set -euo pipefail
IMAGE=$1; DIR=$2
REG=${IMAGE%%/*}; REST=${IMAGE#*/}; REPO=${REST%%:*}; TAG=${REST##*:}
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
curl() { command curl -sf --retry 5 --retry-all-errors --retry-delay 5 --connect-timeout 20 "$@"; }
TOKEN=$(curl "https://${REG}/token?scope=repository:${REPO}:pull" | jq -re .token)
auth=(-H "Authorization: Bearer ${TOKEN}")
accept=(-H "Accept: application/vnd.oci.image.index.v1+json" -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" -H "Accept: application/vnd.docker.distribution.manifest.v2+json" -H "Accept: application/vnd.oci.image.manifest.v1+json")
M=$(curl "${auth[@]}" "${accept[@]}" "https://${REG}/v2/${REPO}/manifests/${TAG}")
D=$(echo "$M" | jq -r --arg a "$ARCH" '(.manifests[]? | select(.platform.architecture==$a) | .digest) // .layers[0].digest')
L=$(curl "${auth[@]}" "${accept[@]}" "https://${REG}/v2/${REPO}/manifests/${D}" | jq -r '.layers[0].digest // empty')
[ -n "$L" ] || L=$D
mkdir -p "$DIR"
curl -L "${auth[@]}" "https://${REG}/v2/${REPO}/blobs/${L}" | tar -xzf - -C "$DIR"
echo "extracted ${IMAGE} (${ARCH}) into ${DIR}"
