#!/bin/sh
# F12: grow from one to two members (rolling).
# A runs alone (B stopped: A + witness keep quorum and A serves all 16
# slices); B then joins. Pass: about half of the slices are handed over to B,
# at most max_concurrent_handovers (4) in flight at a time; flows survive.
set -eu
CASE=f12-grow
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
platd_stop "$B"
wait_until 15000 slices_eq "$A" 16 >/dev/null || fail "A did not take all slices"
# Fresh member: state dir wiped; the audit files are archived, not deleted,
# so earlier records stay closed by their service_start (lib.sh AUDIT_CAT).
vm "$B" "rm -rf /var/lib/plat/cluster/*; install -d -m 0750 /var/lib/plat-audit-archive
    for f in /var/log/plat/nat64-audit.jsonl.[0-9]*; do [ -e \"\$f\" ] && mv \"\$f\" /var/lib/plat-audit-archive/; done
    [ -e /var/log/plat/nat64-audit.jsonl ] && mv /var/log/plat/nat64-audit.jsonl /var/lib/plat-audit-archive/nat64-audit.jsonl.\$(date +%s%6N); true"
ma=$(audit_mark "$A")
t_start=$(iso_now "$B")
traffic_start $((FAILBACK_SECS + 60))
sleep 5
platd_start "$B"
if ms=$(wait_until $(((FAILBACK_SECS + 50) * 1000)) rebalanced_to "$B" 6); then
    pass "B serves $(active_slices "$B") of 16 slices after $ms ms"
else
    fail "slices not rebalanced (A $(active_slices "$A"), B $(active_slices "$B"))"
fi
traffic_wait 240
check_flows 95 -
# In-flight handovers: +1 at A's release(handover), -1 at B's acquire(handover).
{
    vm "$A" "$AUDIT_CAT | tail -n +$((ma + 1))" | grep -F '"event.action":"cluster_slice_release"' |
        grep -F handover | sed -n 's/^{"@timestamp":"\([^"]*\)".*/\1 1/p'
    audit_grep "$B" cluster_slice_acquire | grep -E '"cluster.reason":"(handover|failback)"' | sed -n 's/^{"@timestamp":"\([^"]*\)".*/\1 -1/p' |
        awk -v t="$t_start" '$1 >= t'
} | sort >"$OUT/handovers.txt"
peak=$(awk '{ c += $2; if (c > m) m = c } END { print m + 0 }' "$OUT/handovers.txt")
n=$(grep -c ' -1$' "$OUT/handovers.txt" || true)
if [ "$n" -ge 6 ] && [ "$n" -le 10 ]; then pass "$n slices handed over (about half)"; else fail "$n slices handed over (want 6..10)"; fi
if [ "$peak" -le 4 ]; then pass "at most $peak handovers in flight"; else fail "$peak handovers in flight (> 4)"; fi
attrib
restore
finish
