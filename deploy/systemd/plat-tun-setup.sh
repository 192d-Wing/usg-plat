#!/bin/sh
# Creates and routes the persistent multiqueue TUN interface and installs the
# host forward policy before platd starts. Runs as root via ExecStartPre=+ ;
# the device is owned by plat:plat, so platd itself needs no capabilities
# (NIST 800-53 AC-6).
#
# Usage: plat-tun-setup.sh /etc/plat/platd.toml
#
# Everything is derived from that configuration through
# `platd check-config --format env` (NIST 800-53 CM-6): the TUN interface,
# the NAT64 prefix, the client prefixes and this node's slice of the pool.
# Nothing is edited by hand, and any failure or mismatch aborts the start.
#
# NIST 800-53: SC-7 (Boundary Protection), CM-7 (Least Functionality) - the
# host forwards only translator traffic: client prefixes -> NAT64 prefix into
# the TUN, translated IPv6 back to the clients, this node's pool slice out of
# the TUN and traffic to it back in. Everything else that would be forwarded
# (native IPv6 from clients, transit traffic, other nodes' pool slices) hits
# the default-drop forward chain, so nothing bypasses the client allow-list
# or audit attribution. The policy is installed before forwarding is enabled.
set -eu

die() {
    echo "plat-tun-setup: $*" >&2
    exit 1
}

CONFIG=${1:-}
[ -n "$CONFIG" ] || die "usage: plat-tun-setup.sh /etc/plat/platd.toml"
[ -r "$CONFIG" ] || die "cannot read $CONFIG"
PLATD=${PLATD:-/usr/bin/platd}
MTU=${PLAT_MTU:-1500}
SVC_USER=${PLAT_USER:-plat}
SVC_GROUP=${PLAT_GROUP:-plat}

command -v nft >/dev/null 2>&1 || die "nft (nftables) is required for the forward policy"

# Machine-readable view of the validated config (parsed, never eval'd).
env_out=$("$PLATD" check-config --config "$CONFIG" --format env) || die "check-config failed for $CONFIG"
IF=
PREFIX=
CLIENTS=
POOL=
while IFS='=' read -r key value; do
    case "$key" in
        PLAT_IF) IF=$value ;;
        PLAT_NAT64_PREFIX) PREFIX=$value ;;
        PLAT_CLIENT_PREFIXES) CLIENTS=$value ;;
        PLAT_OWNED_POOL) POOL=$value ;;
        PLAT_NODE_ID | '') ;;
        *) die "unexpected check-config output: $key" ;;
    esac
done <<EOF
$env_out
EOF

# Belt and braces: only plain names and CIDRs reach ip(8) and nft(8).
check() {
    printf '%s\n' "$2" | grep -Eqx "$3" || die "check-config returned a malformed $1: '$2'"
}
V6='[0-9a-fA-F:]+/[0-9]{1,3}'
V4='[0-9.]+/[0-9]{1,2}'
check interface "$IF" '[A-Za-z0-9_.-]{1,15}'
check nat64_prefix "$PREFIX" "$V6"
check client_prefixes "$CLIENTS" "$V6( $V6)*"
check owned_pool "$POOL" "$V4( $V4)*"

if ! ip link show dev "$IF" >/dev/null 2>&1; then
    ip tuntap add dev "$IF" mode tun multi_queue user "$SVC_USER" group "$SVC_GROUP"
fi
# An existing device must be a multiqueue TUN owned by the service account,
# or platd could not attach (or someone else could).
uid=$(id -u "$SVC_USER")
gid=$(getent group "$SVC_GROUP" | cut -d: -f3)
owner=$(cat "/sys/class/net/$IF/owner" 2>/dev/null || echo missing)
group=$(cat "/sys/class/net/$IF/group" 2>/dev/null || echo missing)
flags=$(cat "/sys/class/net/$IF/tun_flags" 2>/dev/null || echo 0)
if [ "$owner" != "$uid" ] || [ "$group" != "$gid" ]; then
    die "$IF is owned by $owner:$group, expected $uid:$gid"
fi
if [ $((flags & 0x100)) -eq 0 ]; then
    die "$IF is not a multi_queue TUN (tun_flags $flags)"
fi

# Forward policy first, atomically replacing any previous version of the
# table (one nft transaction), then routes, then forwarding.
clients_set=$(printf '%s' "$CLIENTS" | sed 's/ /, /g')
pool_set=$(printf '%s' "$POOL" | sed 's/ /, /g')
nft -f - <<EOF
table inet plat
delete table inet plat
table inet plat {
    chain forward {
        type filter hook forward priority 0; policy drop;
        # IPv6 clients to the NAT64 prefix, into the translator.
        oifname "$IF" ip6 saddr { $clients_set } ip6 daddr $PREFIX accept
        # Translated IPv6 from the translator back to the clients.
        iifname "$IF" ip6 saddr $PREFIX ip6 daddr { $clients_set } accept
        # ICMPv6 errors from IPv6-side routers about translated flows
        # (platd validates them against live sessions).
        oifname "$IF" ip6 daddr $PREFIX icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
        # Translated IPv4 from this node's pool slice, and traffic to it.
        iifname "$IF" ip saddr { $pool_set } accept
        oifname "$IF" ip daddr { $pool_set } accept
        counter drop
    }
}
EOF
nft list chain inet plat forward >/dev/null || die "forward policy not installed"

ip link set dev "$IF" mtu "$MTU" up
# Only this node's routes on the TUN: drop stale ones (an old prefix, the
# whole pool, another node's slice), then add the configured ones.
ip -4 route flush dev "$IF" proto boot 2>/dev/null || true
ip -6 route flush dev "$IF" proto boot 2>/dev/null || true
ip -6 route replace "$PREFIX" dev "$IF" proto boot
for p in $POOL; do
    ip -4 route replace "$p" dev "$IF" proto boot
done

# Verify the kernel now routes exactly the configured prefixes to the TUN
# (ip(8) prints host routes without /32 or /128).
norm() { sed -e 's#/32$##' -e 's#/128$##' | sort; }
want4=$(for p in $POOL; do echo "$p"; done | norm)
got4=$(ip -4 route show dev "$IF" proto boot | awk '{print $1}' | norm)
[ "$got4" = "$want4" ] || die "IPv4 routes on $IF [$got4] do not match this node's pool [$want4]"
want6=$(printf '%s\n' "$PREFIX" | norm)
got6=$(ip -6 route show dev "$IF" proto boot | awk '{print $1}' | norm)
[ "$got6" = "$want6" ] || die "IPv6 routes on $IF [$got6] do not match the NAT64 prefix [$want6]"

sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
