#!/bin/sh
# F9: witness down.
# Pass: no view change and no disruption; with a subsequent crash of A, no
# takeover (two of three voters lost: documented behaviour; recovery is the
# operator's `platd cluster takeover` on B, see README).
set -eu
CASE=f09-witness-down
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
e0=$(metric "$A" plat_cluster_epoch)
tb0=$(metric "$B" plat_cluster_takeovers_total)
b_slices=$(active_slices "$B")
traffic_start 30
vm "$E" "systemctl stop plat-witness"
sleep 15
if [ "$(metric "$A" plat_cluster_epoch)" -eq "$e0" ]; then pass "no view change with the witness down"; else fail "epoch changed ($e0 -> $(metric "$A" plat_cluster_epoch))"; fi
traffic_wait 120
check_flows 100 1000
platd_kill9 "$A"
sleep 15
tb=$(($(metric "$B" plat_cluster_takeovers_total) - tb0))
if [ "$tb" -eq 0 ]; then pass "no takeover by B without quorum"; else fail "B took over $tb slices without quorum"; fi
info "B active slices after A crash without witness: $(active_slices "$B") (was $b_slices)"
attrib
restore
finish
