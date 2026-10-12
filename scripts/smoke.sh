#!/bin/bash
# Quick functional pass for proot-next.  Usage: scripts/smoke.sh [path/to/proot] [rootfs]
# With a rootfs argument, also runs the guest-root checks against it.
set -u
PROOT=${1:-$(dirname "$0")/../target/debug/proot}
ROOTFS=${2:-}
fail=0
check() { # name, expected, actual
  if [ "$2" == "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected [$2] got [$3]"; fail=1; fi
}
check "exit status"        3 "$($PROOT -r / /bin/sh -c 'exit 3'; echo $?)"
check "pwd via -w"         /tmp "$($PROOT -r / -w /tmp /bin/sh -c pwd)"
check "pipe + fork"        hi "$($PROOT -r / /bin/sh -c 'echo hi | cat')"
check "readlink self/exe"  "$(readlink -f "$(command -v readlink)")" "$($PROOT -r / /bin/sh -c 'readlink /proc/self/exe')"
check "kernel release"     4.4.0-fake "$($PROOT -r / -k 4.4.0-fake /bin/uname -r)"
d=$(mktemp -d); echo data > "$d/f"
check "file bind"          data "$($PROOT -r / -b "$d:/pn-bind" /bin/cat /pn-bind/f)"
check "mkdir/rename/rm"    ok "$($PROOT -r / /bin/sh -c "mkdir $d/a && mv $d/a $d/b && rmdir $d/b && echo ok")"
rm -rf "$d"
if [ -n "$ROOTFS" ]; then
  check "rootfs ls"        0 "$($PROOT -R "$ROOTFS" /bin/ls / >/dev/null; echo $?)"
  check "rootfs sh"        guest "$($PROOT -R "$ROOTFS" /bin/sh -c 'echo guest')"
  check "rootfs script"    script "$($PROOT -R "$ROOTFS" /bin/sh -c 'printf "#!/bin/sh\necho script\n" > /tmp/pn-s; chmod +x /tmp/pn-s; /tmp/pn-s; rm -f /tmp/pn-s')"
fi
exit $fail
