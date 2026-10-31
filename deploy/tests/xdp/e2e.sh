#!/bin/sh
# Level 4 end-to-end test for the XDP fast path (plan §11 level 4). Skeleton:
# the topology is real and checked now; the cases arrive with WU5 (platd [xdp])
# and WU6 (loader unit) and skip until then.
#
#   xc (client, IPv6 only)        xp (PLAT: platd + plat-xdp-loader)        xs (server, IPv4)
#   c0 2001:db8:c::2/64  <--veth-->  p6 2001:db8:c::1/64
#                                    p4 198.51.100.1/24  <--veth-->  s0 198.51.100.2/24
#   client default route via xp (covers the RFC 6052 well-known prefix
#   64:ff9b::/96); server routes the test pool 192.0.2.0/24 via xp.
# Documentation ranges only (RFC 3849, RFC 5737). The cases will set
# allow_non_global_destinations = true in the test config for that reason.
#
# Cases (plan §11 level 4), each run with the fast path on and compared with a
# TUN-only run (fast path off): server-side captures byte-equal except the
# IPv4 ID.
#   udp_both_directions     UDP flows IPv6->IPv4 and IPv4->IPv6
#   first_packet_slow_path  first packet via platd/TUN, then the fast path
#   fast_path_keepalive     session kept alive only by fast-path traffic past
#                           udp_secs (invariant I2)
#   idle_expiry             expiry after silence (SC-10)
#   frag_needed_revalidate  ICMPv4 Frag Needed about a fast-path flow is
#                           translated by the slow path (revalidation)
#
# Usage: e2e.sh topology    build the three namespaces, check reachability,
#                           remove them (needs root)
#        e2e.sh run         run the cases (needs root); exit 77 = skipped
# Environment: PLATD, PLAT_XDP_LOADER (default target/release/...).
# Exit: 0 pass; 1 failure; 2 usage; 77 skipped (prerequisites missing).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
NS_C=xc NS_P=xp NS_S=xs

die() { echo "e2e: $1" >&2; exit "${2:-1}"; }
nsx() { n=$1; shift; nsenter --net="/run/netns/$n" "$@"; }

down() {
    for n in "$NS_C" "$NS_P" "$NS_S"; do
        ip netns del "$n" 2>/dev/null || true
    done
}

up() {
    [ "$(id -u)" -eq 0 ] || die "needs root" 2
    modprobe veth 2>/dev/null || true
    down
    for n in "$NS_C" "$NS_P" "$NS_S"; do
        ip netns add "$n"
        ip -n "$n" link set lo up
    done
    ip -n "$NS_C" link add c0 type veth peer name p6 netns "$NS_P"
    ip -n "$NS_P" link add p4 type veth peer name s0 netns "$NS_S"
    ip -n "$NS_C" link set c0 up
    ip -n "$NS_P" link set p6 up
    ip -n "$NS_P" link set p4 up
    ip -n "$NS_S" link set s0 up

    ip -n "$NS_C" addr add 2001:db8:c::2/64 dev c0 nodad
    ip -n "$NS_C" -6 route add default via 2001:db8:c::1 dev c0
    ip -n "$NS_P" addr add 2001:db8:c::1/64 dev p6 nodad
    ip -n "$NS_P" addr add 198.51.100.1/24 dev p4
    ip -n "$NS_S" addr add 198.51.100.2/24 dev s0
    ip -n "$NS_S" route add 192.0.2.0/24 via 198.51.100.1 dev s0
    nsx "$NS_P" sysctl -qw net.ipv4.conf.all.forwarding=1
    nsx "$NS_P" sysctl -qw net.ipv6.conf.all.forwarding=1
}

check_topology() {
    nsx "$NS_C" ping -6 -c 1 -W 2 2001:db8:c::1 >/dev/null || die "client cannot reach the PLAT"
    nsx "$NS_S" ping -c 1 -W 2 198.51.100.1 >/dev/null || die "server cannot reach the PLAT"
    nsx "$NS_C" ip -6 route get 64:ff9b::c633:6402 | grep -q 'dev c0' || die "client has no route to 64:ff9b::/96"
    echo "e2e: topology ok" >&2
}

skip() { echo "e2e: SKIP: $*" >&2; exit 77; }

run() {
    platd=${PLATD:-$repo/target/release/platd}
    loader=${PLAT_XDP_LOADER:-$repo/target/release/plat-xdp-loader}
    [ -x "$platd" ] || skip "no platd at $platd (build with --features xdp, WU5)"
    [ -x "$loader" ] || skip "no plat-xdp-loader at $loader (WU3)"
    # The cases listed in the header land with WU5/WU6 (config with [xdp],
    # loader unit, captures on s0). Until they do, report a skip rather than a
    # pass so a green job never claims level 4 coverage.
    skip "level 4 cases not implemented yet (WU5/WU6)"
}

case "${1:-}" in
    topology)
        up
        trap down EXIT
        check_topology
        ;;
    run) run ;;
    *) die "usage: e2e.sh topology|run" 2 ;;
esac
