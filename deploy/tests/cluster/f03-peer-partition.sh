#!/bin/sh
# F3: peer-link partition only (port 7946 dropped between A and B; both still
# reach the witness).
# Pass: exactly one view wins; no slice swap churn (only one side takes
# over); no dual-active slice at the edge.
set -eu
CASE=f03-peer-partition
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
ta0=$(metric "$A" plat_cluster_takeovers_total)
tb0=$(metric "$B" plat_cluster_takeovers_total)
capture_start
traffic_start 45
sleep 10
block_peer "$A" "$B_IP"
block_peer "$B" "$A_IP"
t_cut=$(iso_now "$E")
sleep 20
ta=$(($(metric "$A" plat_cluster_takeovers_total) - ta0))
tb=$(($(metric "$B" plat_cluster_takeovers_total) - tb0))
aa=$(active_slices "$A")
ab=$(active_slices "$B")
info "after partition: A active $aa takeovers $ta; B active $ab takeovers $tb"
if [ $((aa + ab)) -eq 16 ]; then pass "every slice active exactly once"; else fail "active slices A $aa + B $ab != 16"; fi
if [ "$ta" -eq 0 ] || [ "$tb" -eq 0 ]; then pass "one view won (takeovers A $ta, B $tb)"; else fail "both sides took over (A $ta, B $tb): swap churn"; fi
traffic_wait 120
capture_stop
# Allow lease + margin for the loser to fence before judging the capture.
settle=$(vm "$E" "date -u -d '$t_cut + $((LEASE_MS / 1000 + 2)) seconds' +%Y-%m-%dT%H:%M:%S.%6NZ")
d=$(dual_active_after "$settle")
if [ "$d" -eq 0 ]; then pass "no dual-active slice at the edge after $settle"; else fail "$d slice-seconds sourced from both nodes"; fi
attrib
restore
finish
