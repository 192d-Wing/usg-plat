#!/bin/sh
# F1: `kill -9 platd` on node A (plan §8.2).
# Pass: B acquires A's slices within lease + margin + BFD (<= 5 s); >= 95 % of
# TCP flows survive; acquire(takeover) and adopt records present; zero
# attribution overlap.
set -eu
CASE=f01-kill-platd
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
a_slices=$(active_slices "$A")
info "A owns $a_slices slices"
mark=$(audit_mark "$B")
capture_start
traffic_start 60
sleep 15
platd_kill9 "$A"
if ms=$(wait_until 15000 slices_eq "$B" 16) && [ "$ms" -le "$TAKEOVER_BUDGET_MS" ]; then
    pass "B active on all slices after $ms ms"
else
    fail "takeover took $ms ms (budget $TAKEOVER_BUDGET_MS ms)"
fi
traffic_wait 120
capture_stop
check_flows 95 -
new=$(vm "$B" "$AUDIT_CAT | tail -n +$((mark + 1))")
acq=$(printf '%s\n' "$new" | grep -F '"event.action":"cluster_slice_acquire"' | grep -cF '"cluster.reason":"takeover"' || true)
adopt=$(printf '%s\n' "$new" | grep -cF '"event.action":"nat_port_block_adopt"' || true)
if [ "$acq" -ge "$a_slices" ]; then pass "$acq acquire(takeover) records on B"; else fail "only $acq acquire(takeover) records on B (want $a_slices)"; fi
if [ "$adopt" -gt 0 ]; then pass "$adopt adopt records on B"; else fail "no adopt records on B"; fi
attrib
restore
finish
