#!/bin/sh

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Installs Steam with proot-next as its bubblewrap into a Debian-based amd64
# image or system, for containers that have no user namespaces.
#
# Steam's launcher package comes from Valve's repository, registered here with
# its signing keys checked against their fingerprints, together with the 32-bit
# host libraries the 32-bit client and games need and the libraries Steam's
# metapackages only recommend but games reach for (Vulkan, EGL, video
# acceleration, and XKB of both architectures). proot-next is the release
# binary for this architecture, checked against the SHA-256 its release
# publishes, at PROOT_NEXT_VERSION or else the latest release, with the
# `bwrap` name beside it. steamdeps, the client's dependency check, would
# drive apt through pkexec at every start; the system carries what it checks
# for, so it is diverted to a stub that answers that everything is there.
# Steam's own launcher is diverted so that every way of starting Steam -- the
# menu entry, a steam:// link, a shell -- names proot-next as BWRAP. Without
# that, Steam's requirements check finds no working bubblewrap and refuses to
# start with "Steam now requires user namespaces to be enabled".
#
# Run as root, or under fakeroot in a rootless image build. Running it again
# over an earlier install, this script's or proot-bwrap's, rewires Steam to the
# proot-next it installs.

set -eu

prefix="${PREFIX:-/usr/local}"
version="${PROOT_NEXT_VERSION:-latest}"
# Off PATH on purpose: a bwrap on PATH is what GTK's glycin and other
# sandboxing callers pick up, and only Steam is meant to get this one.
libexec="${prefix}/lib/proot-next"
repo="https://github.com/selkies-project/proot-next"
# Valve signs its repository with both of these keys, and its key file carries
# both: the long-standing one and the 2025 one, which the launcher package
# signed into the repository by the first ships in its keyring.
steam_keys="BA1816EF8E75005FCF5E27A1F24AEA9FB05498B7 DB23C56BF0F377FD02970A2A84706F31879D59CB"
export DEBIAN_FRONTEND=noninteractive

case "$(dpkg --print-architecture)" in
    amd64) ;;
    *) echo "Steam's client is x86 only; nothing to install on $(dpkg --print-architecture)" >&2; exit 1 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

apt_install() {
    apt-get install --no-install-recommends -y "$@"
}

fetch() {  # fetch URL OUT
    curl -o "$2" -fsSL --retry 5 --retry-all-errors --retry-delay 3 --retry-connrefused --retry-max-time 180 "$1"
}

missing=""
command -v curl > /dev/null 2>&1 || missing="curl ca-certificates"
command -v gpg > /dev/null 2>&1 || missing="${missing} gpg"
# shellcheck disable=SC2086  # the package list is meant to split
[ -z "${missing}" ] || { apt-get update && apt_install ${missing}; }

# Every primary key in the file has to be one of Valve's; a subkey follows its
# primary and is vouched for by it.
fetch "https://repo.steampowered.com/steam/archive/stable/steam.gpg" "${work}/steam.gpg"
found="$(gpg --show-keys --with-colons "${work}/steam.gpg" 2> /dev/null |
    awk -F: '$1 == "pub" { primary = 1; next } $1 == "fpr" && primary { print $10; primary = 0 }')"
[ -n "${found}" ] || { echo "steam.gpg holds no OpenPGP key" >&2; exit 1; }
for fingerprint in ${found}; do
    case " ${steam_keys} " in
        *" ${fingerprint} "*) ;;
        *) echo "steam.gpg holds key ${fingerprint}, which is not Valve's" >&2; exit 1 ;;
    esac
done

if ! dpkg --print-foreign-architectures | grep -qx i386; then
    dpkg --add-architecture i386
fi

# The entry is the one the launcher package carries as its own, so installing
# the package leaves it as it is; should a later package's differ, dpkg keeps
# this one rather than asking.
mkdir -p /usr/share/keyrings /etc/apt/sources.list.d
install -m 644 "${work}/steam.gpg" /usr/share/keyrings/steam.gpg
printf 'deb [arch=amd64,i386 signed-by=/usr/share/keyrings/steam.gpg] https://repo.steampowered.com/steam/ stable steam\ndeb-src [arch=amd64,i386 signed-by=/usr/share/keyrings/steam.gpg] https://repo.steampowered.com/steam/ stable steam\n' \
    > /etc/apt/sources.list.d/steam-stable.list
apt-get update
apt_install -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold steam-launcher
apt_install \
    steam-libs-amd64 \
    steam-libs-i386 \
    libvulkan1 \
    libvulkan1:i386 \
    mesa-vulkan-drivers \
    mesa-vulkan-drivers:i386 \
    libegl1:i386 \
    libgles2:i386 \
    libglx-mesa0:i386 \
    libva2:i386 \
    libva-drm2:i386 \
    libva-x11-2:i386 \
    libxkbcommon-x11-0:i386 \
    libfontconfig1:i386 \
    libxss1:i386 \
    libasound2-plugins:i386

# The release's own SHA-256 file names the binary as it was built; the check
# is made against its digest, whatever name it gives.
if [ "${version}" = latest ]; then
    url="${repo}/releases/latest/download"
else
    url="${repo}/releases/download/${version}"
fi
fetch "${url}/proot-x86_64" "${work}/proot"
fetch "${url}/proot-x86_64.sha256" "${work}/proot.sha256"
expected="$(cut -d' ' -f1 "${work}/proot.sha256")"
actual="$(sha256sum "${work}/proot" | cut -d' ' -f1)"
[ -n "${expected}" ] && [ "${actual}" = "${expected}" ] ||
    { echo "proot-x86_64 is ${actual}, the release says ${expected:-nothing}" >&2; exit 1; }
mkdir -p "${libexec}"
install -m 755 "${work}/proot" "${libexec}/proot"
ln -sfn proot "${libexec}/bwrap"

if [ ! -e /usr/bin/steamdeps.distrib ]; then
    dpkg-divert --rename --divert /usr/bin/steamdeps.distrib /usr/bin/steamdeps
fi
printf '#!/bin/sh\nexit 0\n' > /usr/bin/steamdeps
chmod 755 /usr/bin/steamdeps

# The launcher is a symbolic link to the client's own script; diverting it
# leaves the package free to update that script, and an already-set BWRAP wins
# so that a session can still choose another one. The client takes its package
# name from the name it was started as and refuses to run under any other, and
# a shell script cannot be given a different one -- the kernel hands the
# interpreter the script's own path -- so the replacement starts it through a
# link that is still called `steam`.
ln -sfn bin_steam.sh /usr/lib/steam/steam
if [ ! -e /usr/bin/steam.distrib ]; then
    dpkg-divert --rename --divert /usr/bin/steam.distrib /usr/bin/steam
fi
cat > /usr/bin/steam <<EOF
#!/bin/sh
# Start Steam with a bubblewrap that works without user namespaces.
BWRAP="\${BWRAP:-${libexec}/bwrap}"
export BWRAP
exec /usr/lib/steam/steam "\$@"
EOF
chmod 755 /usr/bin/steam

apt-get clean
rm -rf /var/lib/apt/lists/*
echo "proot-next $("${libexec}/proot" --version 2>&1 | head -1) installed at ${libexec} and wired into /usr/bin/steam"
