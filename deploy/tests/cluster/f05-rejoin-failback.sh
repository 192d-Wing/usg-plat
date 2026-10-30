#!/bin/sh
# F5: rejoin of A after a crash.
# Pass: A syncs as backup and fails back after failback_delay_secs by
# handover with no flow loss beyond 1 s; release(handover) records on B.
set -eu
CASE=f05-rejoin-failback
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
a_slices=$(active_slices "$A")
platd_kill9 "$A"
wait_until 15000 slices_eq "$B" 16 >/dev/null || fail "B did not take over"
mark=$(audit_mark "$B")
platd_start "$A"
if ms=$(wait_until 60000 metric_gt "$A" 'plat_cluster_slices{state="backup_in_sync"' 0); then
    pass "A in sync as backup after $ms ms"
else
    fail "A never reached backup_in_sync"
fi
traffic_start $((FAILBACK_SECS + 45))
if ms=$(wait_until $(((FAILBACK_SECS + 40) * 1000)) slices_eq "$A" "$a_slices"); then
    pass "A failed back to $a_slices slices after $ms ms"
else
    fail "A did not fail back"
fi
traffic_wait 180
check_flows 100 1000
new=$(vm "$B" "$AUDIT_CAT | tail -n +$((mark + 1))")
h=$(printf '%s\n' "$new" | grep -cF '"plat.release_reason":"handover"' || true)
if [ "$h" -gt 0 ]; then pass "$h release(handover) records on B"; else fail "no release(handover) records on B"; fi
attrib
restore
finish
