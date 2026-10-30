#!/bin/sh
# F8: slow and lossy peer link (netem 200 ms, 5 % loss, 1 Mbit on A->B)
# under a flow storm.
# Pass: worker packet rate on A within noise of the unimpaired rate; any
# replication loss is counted (repl_dropped on A, gaps on B) and repaired by
# resync after the impairment is lifted; no attribution violation.
# Round 4 (B-4): the impairment need not cause loss. TCP retransmits on the
# lossy link, and the flow storm's replication stream (about 200 new
# connections/s x 2 records x ~60 bytes, ~200 kbit/s) fits in 1 Mbit, so the
# bounded peer queue does not overflow and the connection does not reset.
# Without loss nothing is dropped and B stays in sync: the case then checks
# that no gap was hidden (B's gap counter and A's resyncs unchanged).
set -eu
CASE=f08-slow-peer-link
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

rx() { metric "$A" plat_worker_rx_packets_total; }
rate() {
    r0=$(rx)
    sleep 10
    echo $((($(rx) - r0) / 10))
}
ensure_cluster
traffic_start 120 200 500 200
sleep 10
base=$(rate)
d0=$(metric "$A" plat_cluster_repl_dropped_total)
g0=$(metric "$B" 'plat_cluster_repl_dropped_total{reason="gap"')
r0=$(metric "$A" plat_cluster_resync_total)
vm "$A" "tc qdisc add dev plha0 root handle 1: prio
tc qdisc add dev plha0 parent 1:3 handle 30: netem delay 200ms loss 5% rate 1mbit
tc filter add dev plha0 parent 1: protocol ip u32 match ip dst $B_IP/32 flowid 1:3"
sleep 10
imp=$(rate)
info "A rx pps unimpaired $base, impaired $imp"
if [ "$imp" -ge $((base * 85 / 100)) ]; then pass "worker rate within noise ($imp vs $base pps)"; else fail "worker rate dropped ($imp vs $base pps)"; fi
sleep 20
d1=$(metric "$A" plat_cluster_repl_dropped_total)
g1=$(metric "$B" 'plat_cluster_repl_dropped_total{reason="gap"')
r1=$(metric "$A" plat_cluster_resync_total)
if [ "$d1" -gt "$d0" ] || [ "$g1" -gt "$g0" ]; then
    pass "replication loss counted (A dropped $((d1 - d0)), B gaps $((g1 - g0)))"
elif [ "$r1" -eq "$r0" ] && backup_resynced "$B"; then
    pass "no replication loss under the impairment: nothing dropped, no gap, no resync, B in sync"
else
    fail "resync without counted loss (A resyncs $((r1 - r0)), B gaps $((g1 - g0)))"
fi
s0=$(metric "$A" plat_cluster_resync_total)
vm "$A" "tc qdisc del dev plha0 root"
if ms=$(wait_until 60000 backup_resynced "$B"); then
    pass "resync complete $ms ms after the impairment was lifted ($(($(metric "$A" plat_cluster_resync_total) - s0)) resyncs)"
else
    fail "B still syncing 60 s after the impairment was lifted"
fi
traffic_wait 180
attrib
restore
finish
