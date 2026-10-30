#!/bin/sh
# Crash route check (D-3): edge routes before `kill -9 platd` on A, after
# the kill, after A restarts as a standby, and after failback.
# Usage: deploy/tests/cluster/route-check.sh
set -eu
CASE=route-check
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

# Announcers (overlay host numbers) of an IPv4 slice at the edge.
from_of() {
    vm "$E" "vtysh -c 'show bgp ipv4 unicast $1'" | grep -oE "from 192\.168\.205\.[0-9]+" |
        sed 's/from 192\.168\.205\.//' | paste -sd+ -
}
rt() {
    v6=$(vm "$E" "ip -6 route show 64:ff9b:1::/96" | grep -c via || true)
    echo "v6_paths=$v6 v4_16_from=$(from_of 192.0.2.16/28) v4_0_from=$(from_of 192.0.2.0/28)"
}

ensure_cluster
info "before kill: $(rt)"
platd_kill9 "$A"
sleep 8
info "8 s after kill -9 A: $(rt)"
ann=$(vm "$A" "ls /var/lib/plat/cluster/announce.d | wc -l" | tr -d ' ')
nets=$(vm "$A" "vtysh -c 'show running-config'" | grep -c "network 192\.0\.2" || true)
info "A announce.d entries $ann, A IPv4 networks $nets"
if [ "$ann" -eq 0 ] && [ "$nets" -eq 0 ]; then pass "crashed node withdrew its slices"; else fail "stale route state on A"; fi
platd_start "$A"
sleep 10
r=$(rt)
info "10 s after restart (standby, A active $(active_slices "$A")): $r"
case $r in v6_paths=1\ *) pass "standby does not announce the NAT64 prefix" ;; *) fail "standby announces the NAT64 prefix" ;; esac
m0=$(metric "$A" 'plat_drops_total{reason="missteered"')
vm "$E" "ip netns exec cli python3 /opt/plat-test/flows.py client --target $SERVER6 --duration 10 --flows 40 \
    --udp-pps 50 --cps 5 --sources 8 --out /tmp/route-check.json; cat /tmp/route-check.json"
echo
d=$(($(metric "$A" 'plat_drops_total{reason="missteered"') - m0))
if [ "$d" -eq 0 ]; then pass "no missteered drops on the standby"; else fail "$d missteered drops on the standby"; fi
wait_until $(((FAILBACK_SECS + 60) * 1000)) both_serving >/dev/null || fail "no failback"
sleep 3
info "after failback (A $(active_slices "$A"), B $(active_slices "$B")): $(rt)"
finish
