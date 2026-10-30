#!/bin/sh
# F2: VM loss (`limactl stop -f plat-linux`). Pass criteria as F1.
set -eu
CASE=f02-vm-loss
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
a_slices=$(active_slices "$A")
info "A owns $a_slices slices"
# The audit log of A is read after the VM is back (it is on A's disk).
capture_start
traffic_start 60
sleep 15
limactl stop -f "$A" >/dev/null 2>&1
if ms=$(wait_until 15000 slices_eq "$B" 16) && [ "$ms" -le "$TAKEOVER_BUDGET_MS" ]; then
    pass "B active on all slices after $ms ms"
else
    fail "takeover took $ms ms (budget $TAKEOVER_BUDGET_MS ms)"
fi
traffic_wait 120
capture_stop
check_flows 95 -
acq=$(audit_grep "$B" cluster_slice_acquire | grep -cF '"cluster.reason":"takeover"' || true)
if [ "$acq" -ge "$a_slices" ]; then pass "$acq acquire(takeover) records on B"; else fail "only $acq acquire(takeover) records on B"; fi
if [ "$(audit_count "$B" nat_port_block_adopt)" -gt 0 ]; then pass "adopt records on B"; else fail "no adopt records on B"; fi
limactl start "$A" >/dev/null
attrib
restore
finish
