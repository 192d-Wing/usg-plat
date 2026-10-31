#!/bin/sh
# Network namespace topology for BPF_PROG_TEST_RUN with bpf_fib_lookup (plan
# §11 level 2; the WU0 spike's netns.sh). bpf_fib_lookup resolves against the
# caller's namespace, so the level-2 harness runs inside this one:
#
#   nsenter --net=/run/netns/platxdp <harness>
#
# Use nsenter --net, not `ip netns exec`: the latter remounts /sys, which hides
# bpffs, so BPF_OBJ_PIN fails with ENOENT in a process that both pins and test
# runs. Resolve interfaces with if_nametoindex(), not /sys/class/net.
#
#   tun0   dummy, forwarding 1 (stands in for the TUN, the fib_lookup ifindex)
#   up0    veth 02:00:00:00:01:01, 192.0.2.1/24; 203.0.113.0/24 via
#          192.0.2.254 (permanent neighbour 02:00:00:00:01:fe on up0p)
#   acc0   veth 02:00:00:00:02:01, 2001:db8:a::1/64; 2001:db8:b::/64 and
#          2001:db8::/64 (the plat-xdp-core vectors' subscriber 2001:db8::10)
#          via 2001:db8:a::fe (permanent neighbour 02:00:00:00:02:fe on acc0p)
# The fixed vectors (plat-xdp-core tests/vectors) depend on these MACs and
# addresses. Documentation ranges only (RFC 5737, RFC 3849).
#
# Usage: netns.sh [up|down] [NETNS]      (default: up platxdp; needs root)
set -eu

action=${1:-up}
ns=${2:-platxdp}
nsx() { nsenter --net="/run/netns/$ns" "$@"; }

case "$action" in
    down)
        ip netns del "$ns" 2>/dev/null || true
        exit 0
        ;;
    up) ;;
    *)
        echo "usage: netns.sh [up|down] [NETNS]" >&2
        exit 2
        ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "netns.sh: needs root" >&2; exit 2; }
modprobe veth 2>/dev/null || true
modprobe dummy 2>/dev/null || true

ip netns del "$ns" 2>/dev/null || true
ip netns add "$ns"
ip -n "$ns" link set lo up

ip -n "$ns" link add tun0 type dummy
ip -n "$ns" link add up0 address 02:00:00:00:01:01 type veth peer name up0p address 02:00:00:00:01:fe
ip -n "$ns" link add acc0 address 02:00:00:00:02:01 type veth peer name acc0p address 02:00:00:00:02:fe
for l in tun0 up0 up0p acc0 acc0p; do
    ip -n "$ns" link set "$l" up
done

ip -n "$ns" addr add 192.0.2.1/24 dev up0
ip -n "$ns" route add 203.0.113.0/24 via 192.0.2.254 dev up0
ip -n "$ns" neigh add 192.0.2.254 lladdr 02:00:00:00:01:fe dev up0 nud permanent

ip -n "$ns" addr add 2001:db8:a::1/64 dev acc0 nodad
ip -n "$ns" route add 2001:db8:b::/64 via 2001:db8:a::fe dev acc0
ip -n "$ns" route add 2001:db8::/64 via 2001:db8:a::fe dev acc0
ip -n "$ns" neigh add 2001:db8:a::fe lladdr 02:00:00:00:02:fe dev acc0 nud permanent

nsx sysctl -qw net.ipv4.conf.all.forwarding=1
nsx sysctl -qw net.ipv4.conf.tun0.forwarding=1
nsx sysctl -qw net.ipv6.conf.all.forwarding=1

# Self-check: both routes resolve through the expected device.
nsx ip route get 203.0.113.5 | grep -q 'dev up0' || { echo "netns.sh: IPv4 route check failed" >&2; exit 1; }
nsx ip -6 route get 2001:db8:b::5 | grep -q 'dev acc0' || { echo "netns.sh: IPv6 route check failed" >&2; exit 1; }
nsx ip -6 route get 2001:db8::10 | grep -q 'dev acc0' || { echo "netns.sh: IPv6 subscriber route check failed" >&2; exit 1; }
echo "netns.sh: $ns ready" >&2
