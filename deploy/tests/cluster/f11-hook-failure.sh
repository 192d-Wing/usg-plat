#!/bin/sh
# F11: hook failure and hook timeout.
# Pass: cluster_hook outcome failure audited and counted; the slice stays
# Active (routing is the operator's concern, alerted).
set -eu
CASE=f11-hook-failure
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
# 1. failure: FRR down on B, so vtysh fails (exit 75) on takeover.
f0=$(metric "$B" plat_cluster_hook_failures_total)
mark=$(audit_mark "$B")
vm "$B" "systemctl stop frr"
platd_kill9 "$A"
if wait_until 15000 slices_eq "$B" 16 >/dev/null; then pass "slices Active on B despite failing announce hook"; else fail "B did not activate all slices"; fi
sleep 2
new=$(vm "$B" "$AUDIT_CAT | tail -n +$((mark + 1))")
n=$(printf '%s\n' "$new" | grep -F '"event.action":"cluster_hook"' | grep -cF '"event.outcome":"failure"' || true)
if [ "$n" -gt 0 ]; then pass "$n cluster_hook failure records"; else fail "no cluster_hook failure record"; fi
f1=$(metric "$B" plat_cluster_hook_failures_total)
if [ "$f1" -gt "$f0" ]; then pass "hook failures counted ($((f1 - f0)))"; else fail "hook failures not counted"; fi
vm "$B" "systemctl start frr"

# 2. timeout: the withdraw hook on B hangs past hook_timeout_ms during failback.
vm "$B" "cp -p /usr/libexec/plat/frr-withdraw.sh /root/frr-withdraw.sh.orig
printf '#!/bin/sh\nexec sleep 30\n' >/usr/libexec/plat/frr-withdraw.sh"
f0=$(metric "$B" plat_cluster_hook_failures_total)
platd_start "$A"
if wait_until $(((FAILBACK_SECS + 60) * 1000)) metric_gt "$B" plat_cluster_hook_failures_total "$f0" >/dev/null; then
    pass "withdraw hook timeout counted"
else
    fail "withdraw hook timeout not counted"
fi
vm "$B" "install -m 0755 -o root -g root /root/frr-withdraw.sh.orig /usr/libexec/plat/frr-withdraw.sh"
attrib
restore
finish
