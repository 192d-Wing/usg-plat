#!/bin/sh
# Example `cluster.ha.hooks.announce` hook: announce one IPv4 pool slice this
# node now owns, through FRR (`network <cidr>` under `router bgp`), and record
# it in <state_dir>/announce.d/ for routing daemons that watch files
# (bird, exabgp).
#
# Usage (exec'd by platd's plat-cluster-hook thread with argv, never a shell):
#   frr-announce.sh <slice-cidr> <epoch> <reason>
#
# platd calls it after the slice is Active (epoch committed, audit records
# queued), serialized and under `cluster.ha.hook_timeout_ms`. Idempotent: an
# already-announced slice is left as is (exit 0).
#
# Install root-owned and not group/world-writable (platd refuses otherwise):
#   sudo install -D -m 0755 -o root -g root deploy/hooks/frr-announce.sh /usr/libexec/plat/frr-announce.sh
# platd runs as `plat`; vtysh needs it in the `frrvty` group. FRR must have
# exactly one `router bgp <asn>` and `no bgp network import-check` (the TUN
# only carries the whole-pool route, not each slice).
#
# Exit codes (sysexits): 0 announced or already announced; 64 bad arguments;
# 69 vtysh missing or no `router bgp`; 73 cannot write the announce file;
# 75 vtysh refused the change (or plat-v6-announce.sh failed).
#
# Environment: PLAT_STATE_DIR (default /var/lib/plat/cluster). VTYSH is
# honoured only with PLAT_TEST_MODE=1 (deploy/tests/deploy-scripts-test.sh).
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SC-7 (Boundary Protection) - only owned slices are routed here
# - NIST 800-53: CP-10 (System Recovery) - routes follow ownership on takeover
# - RFC 4271 - announcement by the external BGP speaker (FRR)
set -eu

die() {
    echo "frr-announce: $2" >&2
    exit "$1"
}

[ $# -eq 3 ] || die 64 "usage: frr-announce.sh <slice-cidr> <epoch> <reason>"
CIDR=$1
EPOCH=$2
REASON=$3

# Strict argument checks: only a canonical IPv4 CIDR, a decimal epoch and a
# short lower-case word reach vtysh and the file system.
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

# 1. Announce directory (atomic rename; '/' in the CIDR becomes '_').
ANN=$STATE_DIR/announce.d
[ -L "$ANN" ] && die 73 "$ANN is a symbolic link"
mkdir -p "$ANN" 2>/dev/null || die 73 "cannot create $ANN"
f=$ANN/$(printf '%s' "$CIDR" | tr / _)
printf '%s %s\n' "$EPOCH" "$REASON" >"$f.tmp.$$" 2>/dev/null || die 73 "cannot write $f"
mv -f "$f.tmp.$$" "$f" || {
    rm -f "$f.tmp.$$"
    die 73 "cannot rename $f"
}

# 2. FRR.
command -v "$VTYSH" >/dev/null 2>&1 || die 69 "vtysh not found"
running=$("$VTYSH" -c "show running-config") || die 75 "vtysh show running-config failed"
ASN=$(printf '%s\n' "$running" | awk '$1 == "router" && $2 == "bgp" { print $3; exit }')
printf '%s\n' "$ASN" | grep -Eqx '[0-9]{1,10}' || die 69 "no 'router bgp <asn>' in the FRR configuration"
if ! printf '%s\n' "$running" | grep -Eq "^[[:space:]]+network $CIDR\$"; then
    "$VTYSH" -c "configure terminal" -c "router bgp $ASN" -c "address-family ipv4 unicast" \
        -c "network $CIDR" -c "end" >/dev/null || die 75 "vtysh rejected 'network $CIDR' (epoch $EPOCH)"
fi

# 3. IPv6 NAT64 prefix (D-2): announced only while this node owns at least
#    one slice (announce.d non-empty), through plat-v6-announce.sh `slices`
#    (a no-op without /etc/default/plat-v6-announce or in standalone mode).
V6=/usr/libexec/plat/plat-v6-announce.sh
if [ "${PLAT_TEST_MODE:-0}" = 1 ]; then V6=${PLAT_V6_ANNOUNCE:-$V6}; fi
if [ -x "$V6" ]; then
    PLAT_STATE_DIR=$STATE_DIR "$V6" slices >/dev/null || die 75 "plat-v6-announce.sh slices failed (epoch $EPOCH)"
fi
exit 0
