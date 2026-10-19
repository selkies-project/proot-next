#!/bin/bash
# Pull a single-layer proot-apps image from a registry into a directory, the
# way proot-apps does, for tests.  Usage: scripts/fetch-rootfs.sh IMAGE DIR
#
# Every request is retried on any error, including an HTTP error status and
# a connection reset, so one registry hiccup does not fail a whole CI matrix.
# The tag floats; the platform's manifest and its layer are content-addressed,
# and each has to hash to the digest it is fetched by.
set -euo pipefail
IMAGE=$1; DIR=$2
REG=${IMAGE%%/*}; REST=${IMAGE#*/}; REPO=${REST%%:*}; TAG=${REST##*:}
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
curl() { command curl -sf --retry 5 --retry-all-errors --retry-delay 5 --connect-timeout 20 "$@"; }
TOKEN=$(curl "https://${REG}/token?scope=repository:${REPO}:pull" | jq -re .token)
auth=(-H "Authorization: Bearer ${TOKEN}")
accept=(-H "Accept: application/vnd.oci.image.index.v1+json" -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" -H "Accept: application/vnd.docker.distribution.manifest.v2+json" -H "Accept: application/vnd.oci.image.manifest.v1+json")
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
verify() { [ "sha256:$(sha256sum "$1" | cut -d' ' -f1)" = "$2" ] || { echo "${IMAGE}: $2 does not hash to its digest" >&2; exit 1; }; }
M=$(curl "${auth[@]}" "${accept[@]}" "https://${REG}/v2/${REPO}/manifests/${TAG}")
if echo "$M" | jq -e '.manifests' > /dev/null; then
    D=$(echo "$M" | jq -re --arg a "$ARCH" '.manifests[] | select(.platform.architecture==$a) | .digest')
    curl "${auth[@]}" "${accept[@]}" -o "$WORK/manifest" "https://${REG}/v2/${REPO}/manifests/${D}"
    verify "$WORK/manifest" "$D"
    L=$(jq -re '.layers[0].digest' "$WORK/manifest")
else
    L=$(echo "$M" | jq -re '.layers[0].digest')
fi
mkdir -p "$DIR"
curl -L "${auth[@]}" -o "$WORK/layer" "https://${REG}/v2/${REPO}/blobs/${L}"
verify "$WORK/layer" "$L"
tar -xzf "$WORK/layer" -C "$DIR"
echo "extracted ${IMAGE} (${ARCH}) into ${DIR}"
