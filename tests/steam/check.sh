#!/bin/bash
# Exercises bwrap mode through the Steam Linux Runtime tools the way Steam
# does: soldier, sniper, and scout-on-soldier containers, OpenGL and Vulkan for
# both architectures, an X11 client, a native GL benchmark, and a Windows GL
# program through GE-Proton. Optionally the Steam client itself.
#
# usage: check.sh --home DIR [--proot PROOT] [--force] [--display :N]
#        [--games ROOT] [--wgltri EXE] [--client BIN_STEAM_SH]
#
# ROOT holds usr/bin/glmark2 and usr/bin/vkcube where the containers see it,
# under the home.
#
# The bwrap is $BWRAP, or the one install-steam.sh puts in
# /usr/local/lib/proot-next, or --proot names a proot-next binary to use under
# that name. --force makes pressure-vessel use it even where its own bubblewrap
# works, which is how a host with user namespaces tests it at all.
set -u

display="${DISPLAY:-:96}"
home=""
games=""
wgltri=""
client=""
force=""
proot=""
while [ $# -gt 0 ]; do
    case "$1" in
        --proot) proot="$2"; shift 2 ;;
        --force) force=yes; shift ;;
        --display) display="$2"; shift 2 ;;
        --home) home="$2"; shift 2 ;;
        --games) games="$2"; shift 2 ;;
        --wgltri) wgltri="$2"; shift 2 ;;
        --client) client="$2"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done
[ -n "$home" ] || { echo "--home is required" >&2; exit 2; }
export HOME="$home" DISPLAY="$display"
if [ -n "$proot" ]; then
    # The name is what selects bwrap mode, so the binary gets a link of its own.
    links="$(mktemp -d)"
    trap 'rm -rf "$links"' EXIT
    ln -s "$(readlink -f "$proot")" "$links/bwrap"
    export BWRAP="$links/bwrap"
fi
export BWRAP="${BWRAP:-/usr/local/lib/proot-next/bwrap}"
[ -z "$force" ] || export PRESSURE_VESSEL_BWRAP="$BWRAP"
common="$HOME/Steam/steamapps/common"
soldier="$common/SteamLinuxRuntime_soldier/run"
sniper="$common/SteamLinuxRuntime_sniper/run"
scout="$common/SteamLinuxRuntime/run-in-scout-on-soldier"
helpers=/usr/lib/pressure-vessel/from-host/libexec/steam-runtime-tools-0
host_helpers="$common/SteamLinuxRuntime_sniper/pressure-vessel/libexec/steam-runtime-tools-0"
pass=0
fail=0
skip=0
quiet='capsule-capture-libs|libdl tokens|libidentify|^\)$|VDPAU|Developer script'

report() {
    if [ "$1" = 0 ]; then pass=$((pass + 1)); echo "PASS $2: $3"; else fail=$((fail + 1)); echo "FAIL $2: $3"; fi
}

# A host program the runtime cannot satisfy is a library mismatch, not a
# container defect: real bubblewrap gives the same result, so say so and
# move on rather than counting it against bwrap mode.
report_workload() {
    case "$3" in
        *"error while loading shared libraries"*)
            skip=$((skip + 1)); echo "SKIP $2: ${3#*: }" ;;
        *) report "$1" "$2" "$3" ;;
    esac
}

# in_runtime RUN COMMAND: run a shell command in that runtime, stripping the
# host-side pressure-vessel noise, with a 10 minute budget.
in_runtime() {
    timeout 600 "$1" -- /bin/sh -c "$2" 2>&1 | grep -vE "$quiet"
}

echo "== bwrap"
out="$("$BWRAP" --version 2>&1)"
case "$out" in *proot-next*) report 0 version "$out" ;; *) report 1 version "$BWRAP is not proot-next: $out" ;; esac

# The command line Steam's own requirements check probes with, which has to
# work or the client refuses to start at all.
"$BWRAP" --bind / / true
report $? probe "steam-runtime-check-requirements probe"

echo "== containers"
# Each runtime is told apart by its os-release, the name and the release both.
release='head -1 /etc/os-release; grep "^VERSION_ID=" /etc/os-release'
out="$(in_runtime "$soldier" "$release")"
case "$out" in *soldier*VERSION_ID=*) report 0 soldier "$(echo "$out" | tr '\n' ' ')" ;; *) report 1 soldier "$out" ;; esac
out="$(in_runtime "$sniper" "$release")"
case "$out" in *sniper*VERSION_ID=*) report 0 sniper "$(echo "$out" | tr '\n' ' ')" ;; *) report 1 sniper "$out" ;; esac
# shellcheck disable=SC2016  # expanded by the shell inside the container
out="$(in_runtime "$scout" 'head -1 /etc/os-release; echo "STEAM_RUNTIME=$STEAM_RUNTIME"; ls "$STEAM_RUNTIME/pinned_libs_32" | head -1')"
case "$out" in *soldier*STEAM_RUNTIME=/*pinned*|*soldier*STEAM_RUNTIME=/*lib*) report 0 scout "$(echo "$out" | tr '\n' ' ' | cut -c1-160)" ;; *) report 1 scout "$out" ;; esac

echo "== path semantics"
# A helper the runtime reaches through the host's tree, a symlink chain the
# runtime's alternatives make, and the account file pressure-vessel generates.
out="$(in_runtime "$sniper" "readlink -f $helpers/pv-locale-gen; readlink -f /usr/bin/awk; echo container=\$container; grep -c \"^$(id -un):\" /etc/passwd")"
case "$out" in *pv-locale-gen*awk*container=pressure-vessel*1) report 0 paths "readlink -f, generated /etc/passwd" ;; *) report 1 paths "$out" ;; esac

echo "== graphics"
# A renderer string on its own proves nothing: llvmpipe answers too, and a
# container that has quietly fallen back to it is exactly what a native game
# reports as running on the CPU. So every check here is against what the same
# helper says outside the container, per architecture. A host that is itself
# software cannot show more than that the container matches it, and a host
# whose 32-bit graphics stack is missing -- an NVIDIA container runtime
# installs none today -- says so rather than counting against bwrap mode.
renderer() {  # renderer HELPERS ARCH
    "$1/$2-linux-gnu-wflinfo" --platform glx --api gl 2>/dev/null |
        sed -n 's/^OpenGL renderer string: //p' | tail -1
}

vulkan_gpus() {  # vulkan_gpus HELPERS ARCH: the non-software devices, one per line
    "$1/$2-linux-gnu-check-vulkan" 2>/dev/null |
        sed -n 's/.*"device-name":"\([^"]*\)".*/\1/p' |
        grep -vE 'llvmpipe|lavapipe|SwiftShader' | sort -u
}

software() {
    case "$1" in llvmpipe*|softpipe*|swrast*|"Software Rasterizer"*) return 0 ;; *) return 1 ;; esac
}

check_gl() {  # check_gl NAME RUN ARCH
    host="$(renderer "$host_helpers" "$3")"
    guest="$(in_runtime "$2" "$helpers/$3-linux-gnu-wflinfo --platform glx --api gl 2>&1 | grep 'renderer string'" |
        sed -n 's/.*renderer string: //p' | tail -1)"
    if [ -z "$host" ]; then
        skip=$((skip + 1)); echo "SKIP $1: no $3 OpenGL on the host to compare with"
    elif [ "$guest" != "$host" ]; then
        report 1 "$1" "container has $guest, host has $host"
    elif software "$host"; then
        skip=$((skip + 1)); echo "SKIP $1: $guest on both sides, so this host has no GPU OpenGL for $3"
    else
        report 0 "$1" "$guest"
    fi
}

check_vulkan() {  # check_vulkan NAME RUN ARCH
    host="$(vulkan_gpus "$host_helpers" "$3")"
    guest="$(in_runtime "$2" "$helpers/$3-linux-gnu-check-vulkan 2>&1" |
        sed -n 's/.*"device-name":"\([^"]*\)".*/\1/p' | grep -vE 'llvmpipe|lavapipe|SwiftShader' | sort -u)"
    if [ -z "$host" ]; then
        skip=$((skip + 1)); echo "SKIP $1: no $3 Vulkan device on the host to compare with"
        return
    fi
    if [ -z "$guest" ]; then
        report 1 "$1" "container has no GPU, host has $(echo "$host" | tr '\n' ' ')"
        return
    fi
    missing="$(echo "$host" | grep -vxF "$guest" | tr '\n' ' ')"
    if [ -n "$missing" ]; then
        report 1 "$1" "container is missing $missing"
    else
        report 0 "$1" "$(echo "$guest" | tr '\n' ' ')"
    fi
}

# sniper is what Proton runs in and scout-on-soldier is what a native game runs
# in, and they capture the graphics stack separately.
for arch in x86_64 i386; do
    check_gl "gl-$arch" "$sniper" "$arch"
    check_gl "gl-scout-$arch" "$scout" "$arch"
    check_vulkan "vulkan-$arch" "$sniper" "$arch"
done
# shellcheck disable=SC2016  # expanded by the shell inside the container
out="$(in_runtime "$sniper" 'xterm -e /bin/true; echo rc=$?')"
case "$out" in *rc=0*) report 0 x11 "xterm ran" ;; *) report 1 x11 "$out" ;; esac

if [ -n "$games" ]; then
    echo "== native workloads"
    out="$(in_runtime "$sniper" "timeout 180 $games/usr/bin/glmark2 --data-path $games/usr/share/glmark2 -b build -b texture --size 640x480 2>&1 | grep -E 'GL_RENDERER|Score|error while loading'")"
    case "$out" in *Score*) report_workload 0 glmark2 "$(echo "$out" | tr -s ' \n' ' ')" ;; *) report_workload 1 glmark2 "$out" ;; esac
    out="$(in_runtime "$sniper" "timeout 120 $games/usr/bin/vkcube --c 200 > /tmp/vkcube.out 2>&1; echo rc=\$?; head -2 /tmp/vkcube.out")"
    case "$out" in *rc=0*"Selected GPU"*) report_workload 0 vkcube "$(echo "$out" | tail -1)" ;; *) report_workload 1 vkcube "$out" ;; esac
fi

if [ -n "$wgltri" ]; then
    echo "== proton"
    proton="$(find "$HOME/Steam/compatibilitytools.d" -maxdepth 2 -name proton -path '*/GE-Proton*' 2>/dev/null | sort | head -1)"
    if [ -z "$proton" ]; then
        report 1 proton "no GE-Proton under $HOME/Steam/compatibilitytools.d"
    else
        game_dir="$(dirname "$wgltri")"
        tool_dir="$(dirname "$proton")"
        # The runtime Steam runs the tool in is the one its manifest asks for.
        appid="$(sed -n 's/.*"require_tool_appid"[[:space:]]*"\([0-9]*\)".*/\1/p' "$tool_dir/toolmanifest.vdf" 2>/dev/null)"
        case "$appid" in
            1391110) runtime=SteamLinuxRuntime_soldier ;;
            4183110) runtime=SteamLinuxRuntime_4 ;;
            *) runtime=SteamLinuxRuntime_sniper ;;
        esac
        export STEAM_COMPAT_DATA_PATH="$HOME/Steam/steamapps/compatdata/999999"
        export STEAM_COMPAT_CLIENT_INSTALL_PATH="$HOME/Steam"
        export STEAM_COMPAT_INSTALL_PATH="$game_dir"
        export STEAM_COMPAT_TOOL_PATHS="$tool_dir:$common/$runtime"
        export STEAM_COMPAT_LIBRARY_PATHS="$HOME/Steam"
        export STEAM_COMPAT_MOUNTS="$game_dir"
        mkdir -p "$STEAM_COMPAT_DATA_PATH"
        cd "$(dirname "$wgltri")" || exit 2
        result="${wgltri%.exe}.txt"
        rm -f "$result"
        if [ ! -x "$common/$runtime/_v2-entry-point" ]; then
            report 1 proton "$(basename "$tool_dir") runs in $runtime, which is not under $common"
            cd - > /dev/null || true
        else
            timeout 900 "$common/$runtime/_v2-entry-point" --verb=waitforexitandrun -- "$proton" waitforexitandrun "$wgltri" 300 > "$HOME/proton-check.log" 2>&1
            out="$(tr '\n' ' ' < "$result" 2>/dev/null)"
            case "$out" in *GL_RENDERER*frames:*) report 0 proton "$out" ;; *) report 1 proton "${out:-$(grep -E 'wine: |Error|error' "$HOME/proton-check.log" | grep -vE "$quiet" | head -2 | tr '\n' ' ')}" ;; esac
            cd - > /dev/null || true
        fi
    fi
fi

if [ -n "$client" ]; then
    echo "== steam client"
    setsid "$client" > "$HOME/steam-client-check.log" 2>&1 &
    found=""
    # A cold client downloads and unpacks itself before the browser helper
    # draws anything, which takes minutes on a slow host.
    for _ in $(seq 1 180); do
        tree="$(xwininfo -root -tree 2>/dev/null)"
        case "$tree" in
            *"Sign in to Steam"*) found="sign-in window"; break ;;
            *"not responding"*) found=""; break ;;
        esac
        sleep 2
    done
    signed_in=1; [ -z "$found" ] || signed_in=0
    report "$signed_in" client "${found:-no sign-in window}"
    "$client" -shutdown > /dev/null 2>&1
    for _ in $(seq 1 30); do pgrep -f 'ubuntu12_32/steam ' > /dev/null || break; sleep 2; done
fi

echo "== $pass passed, $fail failed, $skip skipped"
[ "$fail" = 0 ]
