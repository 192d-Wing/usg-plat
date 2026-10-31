#!/bin/sh
# Runs inside the virtme-ng guest as root (started by vng-run.sh). Prints
# XDP-GUEST-OK as its last line when every step passed or was skipped for a
# stated reason; vng-run.sh requires that line.
#
#   1. the guest runs the expected kernel; bpffs is mounted;
#   2. kernel smoke: XDP load + BPF_PROG_TEST_RUN (xdp-smoke.py);
#   3. the level-2 netns topology comes up (netns.sh);
#   4. level 2: the plat-xdp test_run suite inside that netns, when its test
#      binary is passed (WU3 adds it; skipped until then);
#   5. level 4: the e2e topology, then e2e.sh run (skips, exit 77, until
#      platd and plat-xdp-loader with the xdp feature exist, WU5/WU6).
#
# Usage: guest.sh KVER [LEVEL2_TEST_BIN]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
fail() { echo "XDP-GUEST-FAIL: $*"; exit 1; }

[ $# -ge 1 ] || fail "usage: guest.sh KVER [LEVEL2_TEST_BIN]"
want=$1
level2=${2:-}

echo "GUEST: $(uname -r) $(uname -m)"
[ "$(uname -r)" = "$want" ] || fail "booted $(uname -r), expected $want"
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
echo "kernel.unprivileged_bpf_disabled = $(cat /proc/sys/kernel/unprivileged_bpf_disabled)"
if [ -e /sys/kernel/btf/vmlinux ]; then echo "BTF: yes"; else echo "BTF: no"; fi

python3 -I "$here/xdp-smoke.py" || fail "kernel smoke test"

"$here/netns.sh" up platxdp || fail "netns topology"
if [ -n "$level2" ]; then
    [ -x "$level2" ] || fail "level-2 test binary not executable: $level2"
    nsenter --net=/run/netns/platxdp "$level2" --ignored --test-threads=1 || fail "level 2 test_run suite"
else
    echo "SKIP: level 2 (no plat-xdp test_run binary; WU3)"
fi
"$here/netns.sh" down platxdp

"$here/e2e.sh" topology || fail "e2e topology"
rc=0
"$here/e2e.sh" run || rc=$?
case "$rc" in
    0) ;;
    77) echo "SKIP: level 4 e2e (see message above)" ;;
    *) fail "level 4 e2e (exit $rc)" ;;
esac

echo "XDP-GUEST-OK $(uname -r)"
