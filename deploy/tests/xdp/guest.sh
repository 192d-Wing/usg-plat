#!/bin/sh
# Runs inside the virtme-ng guest as root (started by vng-run.sh). Prints
# XDP-GUEST-OK as its last line when every step passed or was skipped for a
# stated reason; vng-run.sh requires that line.
#
#   1. the guest runs the expected kernel; bpffs is mounted;
#   2. kernel smoke: XDP load + BPF_PROG_TEST_RUN (xdp-smoke.py);
#   3. with -o OBJECT: the stack and instruction gate on the plat-xdp-ebpf
#      object (obj-gate.py stats: verifier statistics, ≤ 384 B deepest call
#      chain, processed-instruction budget; fails closed), run once as
#      root and once with only CAP_BPF CAP_NET_ADMIN (no CAP_PERFMON;
#      fatal on every kernel; the [xdp] minimum is 6.6);
#   4. the level-2 netns topology comes up (netns.sh);
#   5. with -o OBJECT: the level-2 smoke vectors on the object inside that
#      netns (obj-gate.py testrun, level2-vectors.txt);
#   6. level 2: the plat-xdp test_run suite inside that netns, when its test
#      binary is passed (make test-xdp builds it; vng-run.sh -l);
#   7. level 4: the e2e topology, then e2e.sh run (skips, exit 77, unless
#      PLATD and PLAT_XDP_LOADER name the binaries; it runs on the host VM
#      today, WU5; the units come with WU6).
#
# Usage: guest.sh [-o OBJECT] KVER [LEVEL2_TEST_BIN]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
fail() { echo "XDP-GUEST-FAIL: $*"; exit 1; }

object=
while getopts o: opt; do
    case "$opt" in
        o) object=$OPTARG ;;
        *) fail "usage: guest.sh [-o OBJECT] KVER [LEVEL2_TEST_BIN]" ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || fail "usage: guest.sh [-o OBJECT] KVER [LEVEL2_TEST_BIN]"
want=$1
level2=${2:-}

echo "GUEST: $(uname -r) $(uname -m)"
[ "$(uname -r)" = "$want" ] || fail "booted $(uname -r), expected $want"
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
echo "kernel.unprivileged_bpf_disabled = $(cat /proc/sys/kernel/unprivileged_bpf_disabled)"
if [ -e /sys/kernel/btf/vmlinux ]; then echo "BTF: yes"; else echo "BTF: no"; fi

python3 -I "$here/xdp-smoke.py" || fail "kernel smoke test"

if [ -n "$object" ]; then
    [ -f "$object" ] || fail "no object $object"
    python3 -I "$here/obj-gate.py" stats "$object" || fail "stack and instruction gate"
    # SEC-001 (AC-6): the loader runs with CAP_BPF and CAP_NET_ADMIN only
    # (plan §7). Without CAP_PERFMON the verifier is stricter (no pointer
    # arithmetic leaks, Spectre v1/v4 sanitation, partial stack writes), so
    # the object must also load with exactly those capabilities.
    # Without CAP_DAC_OVERRIDE root may not read the shared home tree, so
    # the gate and the object are copied to a root-owned directory first.
    echo "least-privilege load (CAP_BPF CAP_NET_ADMIN):"
    lp=$(mktemp -d)
    cp "$here/obj-gate.py" "$object" "$lp/"
    setpriv --bounding-set=-all,+bpf,+net_admin --inh-caps=-all -- \
        python3 -I "$lp/obj-gate.py" stats "$lp/$(basename "$object")" ||
        fail "load with CAP_BPF CAP_NET_ADMIN only (no CAP_PERFMON)"
    rm -rf "$lp"
else
    echo "SKIP: eBPF object gates (no -o OBJECT)"
fi

"$here/netns.sh" up platxdp || fail "netns topology"
if [ -n "$object" ]; then
    nsenter --net=/run/netns/platxdp python3 -I "$here/obj-gate.py" testrun "$object" "$here/level2-vectors.txt" ||
        fail "level-2 smoke vectors"
fi
if [ -n "$level2" ]; then
    [ -x "$level2" ] || fail "level-2 test binary not executable: $level2"
    nsenter --net=/run/netns/platxdp "$level2" --ignored --test-threads=1 || fail "level 2 test_run suite"
else
    echo "SKIP: level 2 (no plat-xdp test_run binary passed)"
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
