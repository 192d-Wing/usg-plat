#!/bin/sh
# Leader-crash takeover timing (open item: ~6.2 s vs 5 s target).
# Usage: takeover-trials.sh [trials]  (default 7). For each trial: healthy
# baseline, find the view leader, SIGKILL its platd, and measure
#   poll_ms : host poll until the survivor reports all 16 slices Active
#   audit_ms: survivor's last takeover cluster_slice_acquire @timestamp minus
#             the kill time taken on the victim (both chrony-synced)
# then restart the victim and wait for failback. Results: $OUT/trials.txt
set -eu
CASE=takeover-trials
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"
n=${1:-7}
fast_poll() {
    limit=$1
    shift
    t0=$(now_ms)
    until "$@" >/dev/null 2>&1; do
        [ $(($(now_ms) - t0)) -lt "$limit" ] || { echo $(($(now_ms) - t0)); return 1; }
        sleep 0.1
    done
    echo $(($(now_ms) - t0))
}
i=1
while [ "$i" -le "$n" ]; do
    ensure_cluster
    leader=$(cluster_json "$A" | sed -n 's/.*"leader":\([0-9]*\).*/\1/p')
    if [ "$leader" = 0 ]; then victim=$A; surv=$B; else victim=$B; surv=$A; fi
    vslices=$(active_slices "$victim")
    mark=$(audit_mark "$surv")
    t_kill=$(vm "$victim" "date -u +%s%6N; systemctl kill --kill-whom=main -s KILL platd; systemctl stop platd" | head -n 1)
    ms=$(fast_poll 20000 slices_eq "$surv" 16) || ms="timeout($ms)"
    sleep 1
    last=$(vm "$surv" "$AUDIT_CAT | tail -n +$((mark + 1))" | grep -F '"event.action":"cluster_slice_acquire"' |
        grep -F '"cluster.reason":"takeover"' | tail -n 1 | sed -n 's/^{"@timestamp":"\([^"]*\)".*/\1/p')
    if [ -n "$last" ]; then
        t_acq=$(vm "$surv" "date -u -d '$last' +%s%6N")
        audit_ms=$(((t_acq - t_kill) / 1000))
    else
        audit_ms=none
    fi
    line="trial $i leader=$leader victim_slices=$vslices poll_ms=$ms audit_ms=$audit_ms"
    info "$line"
    echo "$line" >>"$OUT/trials.txt"
    platd_start "$victim"
    i=$((i + 1))
done
finish
