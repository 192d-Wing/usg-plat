#!/bin/sh
# F4: full isolation of A (cut from B and from the witness; data plane and
# BGP stay up).
# Pass: A fences within lease - margin and runs the withdraw hook; B takes
# over after lease + margin; the edge sees no slice packets from A after A's
# fence time.
set -eu
CASE=f04-isolate-node
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
a_slices=$(active_slices "$A")
mark=$(audit_mark "$A")
mac_a=$(overlay_mac "$A")
capture_start
traffic_start 45
sleep 10
block_peer "$A" "$B_IP"
block_peer "$A" "$E_IP"
fence_budget=$((LEASE_MS * (100 - DRIFT_PCT) / 100 + 500))
if ms=$(wait_until 10000 slices_eq "$A" 0) && [ "$ms" -le "$fence_budget" ]; then
    pass "A fenced all slices after $ms ms (<= lease - margin + poll)"
else
    fail "A fenced after $ms ms (budget $fence_budget ms)"
fi
if ms=$(wait_until 10000 slices_eq "$B" 16); then pass "B active on all slices after $ms ms"; else fail "B did not take over"; fi
traffic_wait 120
capture_stop
new=$(vm "$A" "$AUDIT_CAT | tail -n +$((mark + 1))")
wd=$(printf '%s\n' "$new" | grep -F '"event.action":"cluster_hook"' | grep -cF '"cluster.hook":"withdraw"' || true)
if [ "$wd" -ge "$a_slices" ]; then pass "withdraw hook ran $wd times on A"; else fail "withdraw hook ran $wd times on A (want $a_slices)"; fi
fence_ts=$(printf '%s\n' "$new" | grep -F '"event.action":"cluster_slice_release"' | tail -n 1 |
    sed -n 's/^{"@timestamp":"\([^"]*\)".*/\1/p')
if [ -z "$fence_ts" ]; then
    fail "no cluster_slice_release record on A"
else
    n=$(pkts_from_after "$mac_a" "$fence_ts")
    if [ "$n" -eq 0 ]; then pass "no pool-sourced packets from A after its fence ($fence_ts)"; else fail "$n packets from A after its fence ($fence_ts)"; fi
fi
attrib
restore
finish
