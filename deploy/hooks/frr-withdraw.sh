#!/bin/sh
# Example `cluster.ha.hooks.withdraw` hook: withdraw one IPv4 pool slice this
# node no longer owns (handover, fence, shutdown) from FRR (`no network
# <cidr>`) and remove it from <state_dir>/announce.d/.
#
# Usage (exec'd by platd's plat-cluster-hook thread with argv, never a shell):
#   frr-withdraw.sh <slice-cidr> <epoch> <reason>
#
# platd calls it before the slice is fenced. Idempotent: a slice that is not
# announced is not an error (exit 0). Both steps are attempted even if one
# fails, so a watcher daemon and FRR never disagree longer than necessary.
#
# Install like frr-announce.sh (root-owned, 0755, not group/world-writable).
#
# Exit codes (sysexits): 0 withdrawn or not announced; 64 bad arguments;
# 69 vtysh missing or no `router bgp`; 73 cannot remove the announce file;
# 75 vtysh refused the change (or plat-v6-announce.sh failed).
#
# Environment: PLAT_STATE_DIR (default /var/lib/plat/cluster). VTYSH is
# honoured only with PLAT_TEST_MODE=1 (deploy/tests/deploy-scripts-test.sh).
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SC-7 (Boundary Protection) - a fenced node stops attracting slice traffic
# - NIST 800-53: CP-10 (System Recovery)
# - RFC 4271 - withdrawal by the external BGP speaker (FRR)
set -eu

die() {
    echo "frr-withdraw: $2" >&2
    exit "$1"
}

[ $# -eq 3 ] || die 64 "usage: frr-withdraw.sh <slice-cidr> <epoch> <reason>"
CIDR=$1
EPOCH=$2
REASON=$3

printf '%s\n' "$CIDR" | grep -Eqx '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' || die 64 "bad slice cidr '$CIDR'"
printf '%s\n' "$CIDR" | awk -F'[./]' '$1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255 && $5 >= 1 && $5 <= 32 { ok = 1 } END { exit !ok }' ||
    die 64 "bad slice cidr '$CIDR'"
printf '%s\n' "$EPOCH" | grep -Eqx '[0-9]{1,20}' || die 64 "bad epoch '$EPOCH'"
printf '%s\n' "$REASON" | grep -Eqx '[a-z_]{1,32}' || die 64 "bad reason '$REASON'"

if [ "${PLAT_TEST_MODE:-0}" = 1 ]; then
    VTYSH=${VTYSH:-vtysh}
else
    VTYSH=vtysh
fi
STATE_DIR=${PLAT_STATE_DIR:-/var/lib/plat/cluster}
case "$STATE_DIR" in /*) ;; *) die 64 "PLAT_STATE_DIR must be absolute" ;; esac

rc=0
# 1. Announce directory.
f=$STATE_DIR/announce.d/$(printf '%s' "$CIDR" | tr / _)
if [ -e "$f" ] || [ -L "$f" ]; then
    rm -f "$f" 2>/dev/null || {
        echo "frr-withdraw: cannot remove $f" >&2
        rc=73
    }
fi

# 2. FRR.
command -v "$VTYSH" >/dev/null 2>&1 || die 69 "vtysh not found"
running=$("$VTYSH" -c "show running-config") || die 75 "vtysh show running-config failed"
ASN=$(printf '%s\n' "$running" | awk '$1 == "router" && $2 == "bgp" { print $3; exit }')
printf '%s\n' "$ASN" | grep -Eqx '[0-9]{1,10}' || die 69 "no 'router bgp <asn>' in the FRR configuration"
if printf '%s\n' "$running" | grep -Eq "^[[:space:]]+network $CIDR\$"; then
    "$VTYSH" -c "configure terminal" -c "router bgp $ASN" -c "address-family ipv4 unicast" \
        -c "no network $CIDR" -c "end" >/dev/null || die 75 "vtysh rejected 'no network $CIDR' (epoch $EPOCH)"
fi

# 3. IPv6 NAT64 prefix (D-2): withdrawn with the last slice (announce.d
#    empty), through plat-v6-announce.sh `slices` (a no-op without
#    /etc/default/plat-v6-announce or in standalone mode).
V6=/usr/libexec/plat/plat-v6-announce.sh
if [ "${PLAT_TEST_MODE:-0}" = 1 ]; then V6=${PLAT_V6_ANNOUNCE:-$V6}; fi
if [ -x "$V6" ]; then
    PLAT_STATE_DIR=$STATE_DIR "$V6" slices >/dev/null || {
        echo "frr-withdraw: plat-v6-announce.sh slices failed (epoch $EPOCH)" >&2
        rc=75
    }
fi
exit "$rc"
