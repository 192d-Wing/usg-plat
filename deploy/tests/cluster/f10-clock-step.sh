#!/bin/sh
# F10: wall-clock step of +-1 h on A (leases use the monotonic clock).
# Pass: no lease effect (no fence, no takeover, no view change).
set -eu
CASE=f10-clock-step
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
e0=$(metric "$A" plat_cluster_epoch)
t0=$(($(metric "$A" plat_cluster_takeovers_total) + $(metric "$B" plat_cluster_takeovers_total)))
# Slices already fenced before the step (e.g. left by an earlier case) are
# not caused by it; judge the change.
fz=$(fenced_slices "$A")
vm "$A" "systemctl stop chrony"
for step in '+1 hour' '-2 hours' '+1 hour'; do
    vm "$A" "date -s '$step' >/dev/null"
    sleep $((LEASE_MS * 2 / 1000 + 1))
    f=$(($(fenced_slices "$A") - fz))
    if [ "$f" -le 0 ]; then pass "no fence after step $step"; else fail "$f slices fenced after step $step"; fi
done
vm "$A" "systemctl start chrony && chronyc -a makestep >/dev/null"
t1=$(($(metric "$A" plat_cluster_takeovers_total) + $(metric "$B" plat_cluster_takeovers_total)))
if [ "$t1" -eq "$t0" ]; then pass "no takeover"; else fail "$((t1 - t0)) takeovers"; fi
if [ "$(metric "$A" plat_cluster_epoch)" -eq "$e0" ]; then pass "no view change"; else fail "epoch changed"; fi
restore
finish
