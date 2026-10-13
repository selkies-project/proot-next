#!/bin/sh
# Run sysbench natively and under one or two proot binaries, print the ns per
# operation side by side and the slowdown against native.
#
#   bench/run.sh PROOT [OTHER_PROOT] -- [proot flags...]
#
#   bench/run.sh target/release/proot -- -R rootfs
#   bench/run.sh target/release/proot /path/to/proot-5.5.0 -- -R rootfs
#
# SYSBENCH_ARGS passes options through to sysbench (e.g. "-n 20000 -t 8").
set -e
here=$(dirname "$(readlink -f "$0")")
proot=$1; shift
other=
if [ "$1" != "--" ]; then other=$1; shift; fi
[ "$1" = "--" ] && shift

cc -O2 -pthread -o "$here/sysbench" "$here/sysbench.c"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$here/sysbench" $SYSBENCH_ARGS | grep -v '^#' > "$tmp/native"
"$proot" "$@" "$here/sysbench" $SYSBENCH_ARGS | grep -v '^#' > "$tmp/a"
if [ -n "$other" ]; then
  "$other" "$@" "$here/sysbench" $SYSBENCH_ARGS | grep -v '^#' > "$tmp/b"
else
  : > "$tmp/b"
fi

printf '%-28s %9s %9s %9s   %7s %7s\n' test native "$(basename "$proot")" "${other:+$(basename "$other")}" "" ""
paste -d '\t' "$tmp/native" "$tmp/a" "$tmp/b" | awk -F'\t' '
{
  split($1, n, "  +"); split($2, a, "  +"); split($3, b, "  +")
  nn = n[2] + 0; na = a[2] + 0; nb = b[2] + 0
  line = sprintf("%-28s %9d %9d", n[1], nn, na)
  if (nb > 0) line = line sprintf(" %9d", nb); else line = line sprintf(" %9s", "")
  line = line sprintf("   %6.1fx", nn ? na / nn : 0)
  if (nb > 0) line = line sprintf(" %6.1fx", nn ? nb / nn : 0)
  print line
}'
