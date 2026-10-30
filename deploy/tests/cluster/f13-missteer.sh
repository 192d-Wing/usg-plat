#!/bin/sh
# F13: mis-steer: the edge sends one subscriber to a node that holds none of
# its port blocks while its peer does (README "Subscriber home").
#
# A subscriber's home is every node that holds one of its blocks. After
# takeover/failback churn a long-lived subscriber can legitimately be homed
# on both nodes (blocks in slices of both owners); such a subscriber is not
# mis-steered anywhere. The case therefore uses a fresh subscriber /64 (one
# per run, never used by other cases) whose only block is on one node.
#
# Pass: on the non-home node the steered packets are counted
# (`plat_cluster_steer_missteered_total`) and dropped
# (`plat_drops_total{reason="missteered"}`) and no block is allocated there;
# the same holds after the non-home node restarts with an empty directory
# (B-9: homes are re-announced on link up / acquisition).
set -eu
CASE=f13-missteer
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
# Fresh /64 inside the edge's 2001:db8:100::/40 (groups 0x100-0xffff; the
# traffic generator only uses 1-8).
SUB=2001:db8:100:$(printf '%x' $(($(now_ms) % 0xfe00 + 0x100)))
info "fresh subscriber $SUB::/64"
vm "$E" "ip -6 addr add $SUB::1/64 dev cli0 nodad && ip -6 -n cli addr add $SUB::10/64 dev cli1 nodad"
cleanup_sub() {
    vm "$E" "systemctl stop plat-f13-ka 2>/dev/null; ip -6 rule del pref 207 2>/dev/null; ip -6 route flush table 207 2>/dev/null
        ip -6 -n cli addr del $SUB::10/64 dev cli1 2>/dev/null; ip -6 addr del $SUB::1/64 dev cli0 2>/dev/null; true"
}
# Keepalive (normal ECMP path): the block must not be released for idleness
# while the non-home node restarts.
vm "$E" "systemctl stop plat-f13-ka 2>/dev/null; systemctl reset-failed plat-f13-ka 2>/dev/null
    systemd-run --unit plat-f13-ka --collect ip netns exec cli ping -6 -q -i 1 -I $SUB::10 $SERVER6" >/dev/null
sleep 5

# newest <vm> <action>: timestamp of <vm>'s newest <action> record for $SUB.
newest() {
    audit_grep "$1" "$2" | grep -F "\"$SUB::/64\"" | sed -n 's/^{"@timestamp":"\([^"]*\)".*/\1/p' | sort | tail -n 1
}
# held <vm>: true when <vm> holds a block of $SUB (its newest allocate/adopt
# for the subscriber is newer than its newest release).
held() {
    got=$({
        newest "$1" nat_port_block_allocate
        newest "$1" nat_port_block_adopt
    } | sort | tail -n 1)
    rel=$(newest "$1" nat_port_block_release)
    [ -n "$got" ] && { [ -z "$rel" ] || [ "$(printf '%s\n%s\n' "$got" "$rel" | sort | tail -n 1)" = "$got" ]; }
}
# Sets home/other/other6 from the current holders; fails unless exactly one
# node holds the subscriber.
find_home() {
    ha=1 hb=1
    held "$A" || ha=0
    held "$B" || hb=0
    case $ha$hb in
    10) home=$A other=$B other6=$B6 ;;
    01) home=$B other=$A other6=$A6 ;;
    11)
        fail "$SUB::/64 holds blocks on both nodes (not single-homed)"
        return 1
        ;;
    *)
        fail "$SUB::/64 not homed anywhere"
        return 1
        ;;
    esac
    info "$SUB::/64 homed on $home; steering it to $other"
}

# steer_check <label>: steer $SUB to $other, ping, check the counters and
# that nothing was allocated for it there.
steer_check() {
    m0=$(metric "$other" plat_cluster_steer_missteered_total)
    d0=$(metric "$other" 'plat_drops_total{reason="missteered"}')
    mark=$(audit_mark "$other")
    vm "$E" "ip -6 route replace 64:ff9b:1::/96 via $other6 table 207 && { ip -6 rule del pref 207 2>/dev/null; true; } &&
        ip -6 rule add pref 207 from $SUB::/64 lookup 207"
    vm "$E" "ip netns exec cli ping -6 -q -c 10 -i 0.2 -W 1 -I $SUB::10 $SERVER6" >/dev/null 2>&1 || true
    m1=$(metric "$other" plat_cluster_steer_missteered_total)
    d1=$(metric "$other" 'plat_drops_total{reason="missteered"}')
    if [ "$m1" -gt "$m0" ]; then pass "$1: missteered counted on $other ($((m1 - m0)))"; else fail "$1: missteered not counted on $other"; fi
    if [ "$d1" -gt "$d0" ]; then pass "$1: missteered packets dropped ($((d1 - d0)))"; else fail "$1: no missteered drops"; fi
    if vm "$other" "$AUDIT_CAT | tail -n +$((mark + 1))" | grep -F '"event.action":"nat_port_block_allocate"' | grep -qF "\"$SUB::/64\""; then
        fail "$1: block allocated for $SUB::/64 on $other"
    else
        pass "$1: no block for $SUB::/64 on $other"
    fi
    vm "$E" "ip -6 rule del pref 207 2>/dev/null; true"
}

if find_home; then
    steer_check "steady state"
    # B-9: the non-home node restarts with an empty directory and must
    # relearn the home from its peer's re-announcement.
    info "restarting platd on $other (B-9)"
    vm "$other" "systemctl restart platd"
    wait_until $(((FAILBACK_SECS + 90) * 1000)) both_serving >/dev/null || fail "not both serving after restart"
    sleep 5
    # Failback may have handed the subscriber's slice to the restarted node.
    if find_home; then steer_check "after restart"; fi
fi
cleanup_sub
attrib
restore
finish
