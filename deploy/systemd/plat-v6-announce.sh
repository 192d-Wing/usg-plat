#!/bin/sh
# usage: plat-v6-announce.sh prestart|on|off|sync|slices
#
# Ties the BGP announcements of this node to platd: the NAT64 IPv6 prefix
# (D-1, D-2) and, in cluster mode, the cleanup of the IPv4 pool slices the
# slice hooks announced (D-3).
#
#   prestart platd.service ExecStartPre=: start from a clean state. Withdraws
#           every slice `network` this node may still announce (the files in
#           <state_dir>/announce.d/ and, with PLAT_V4_POOL, every IPv4
#           `network` inside the pool), empties announce.d, withdraws the
#           IPv6 prefix and records the new platd lifetime (INVOCATION_ID)
#           in the owner file. Only slice files written during this
#           lifetime count afterwards.
#   on      platd.service ExecStartPost=. standalone: announce. cluster:
#           apply the slice state (nothing is owned at start, so this
#           withdraws; the first slice hook announces).
#   off     platd.service ExecStopPost=: the prestart cleanup (all slices,
#           announce.d, IPv6 prefix) plus removal of the owner file. systemd
#           runs it after every exit, including a crash or SIGKILL, when no
#           withdraw hook ran.
#   sync    frr.service ExecStartPost=: re-applies the current state after
#           an FRR restart: everything withdrawn unless platd runs; in
#           cluster mode only the slices announced during the current platd
#           lifetime (owner file matches platd's InvocationID) are
#           re-announced, and the IPv6 prefix only while one exists.
#   slices  run by the shipped cluster hooks (deploy/hooks) after every
#           slice announce/withdraw: in cluster mode announce while
#           announce.d holds at least one slice of the current lifetime,
#           withdraw when it holds none; a no-op in standalone mode or
#           without the settings file.
#
# FRR down (vtysh fails) is not an error for prestart/off: the files are
# still cleared (FRR loses vtysh changes on restart anyway). All modes are
# idempotent: FRR is changed only where its running config differs.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CP-10 / SC-5 - a node whose translator is down, or that
#   owns no pool slice (a rejoining standby), does not attract IPv4 or IPv6
#   traffic (no ECMP blackhole of its share of subscribers)
# - NIST 800-53: SC-7 - a prefix is routed here only while this node can
#   translate it
#
# Settings: /etc/default/plat-v6-announce (shell; optional for prestart, off
# and sync, which then only clean up the IPv4 slices):
#   PLAT_BGP_ASN=64513                  (required)
#   PLAT_NAT64_PREFIX=64:ff9b:1::/96    (required)
#   PLAT_V6_MODE=cluster                (standalone (default) or cluster;
#                                        set cluster with [cluster.ha])
#   PLAT_STATE_DIR=/var/lib/plat/cluster (cluster.ha.state_dir; the hooks'
#                                        environment takes precedence)
#   PLAT_V4_POOL="192.0.2.0/24"         (optional: the cluster IPv4 pool(s);
#                                        prestart/off/sync also withdraw any
#                                        FRR `network` inside them)
set -eu
MODE_ARG=${1:-}
ENV_STATE_DIR=${PLAT_STATE_DIR:-}
CONF=${PLAT_V6_ANNOUNCE_CONF:-/etc/default/plat-v6-announce}
OWNER=/run/plat-announce.owner
if [ "${PLAT_TEST_MODE:-0}" = 1 ]; then OWNER=${PLAT_V6_OWNER_FILE:-$OWNER}; fi
HAVE_CONF=0
if [ -r "$CONF" ]; then
    HAVE_CONF=1
    # shellcheck source=/dev/null
    . "$CONF"
else
    case $MODE_ARG in
    # The hooks call `slices` on every node; the IPv6 announcement is optional.
    slices) exit 0 ;;
    prestart | off | sync) ;;
    *)
        echo "plat-v6-announce: $CONF missing" >&2
        exit 78
        ;;
    esac
fi
if [ "$HAVE_CONF" = 1 ]; then
    : "${PLAT_BGP_ASN:?}" "${PLAT_NAT64_PREFIX:?}"
    case $PLAT_BGP_ASN in *[!0-9]* | '') echo "plat-v6-announce: bad PLAT_BGP_ASN" >&2; exit 78 ;; esac
    case $PLAT_NAT64_PREFIX in *[!0-9a-fA-F:/]* | '') echo "plat-v6-announce: bad PLAT_NAT64_PREFIX" >&2; exit 78 ;; esac
fi
V6_MODE=${PLAT_V6_MODE:-standalone}
case $V6_MODE in standalone | cluster) ;; *) echo "plat-v6-announce: bad PLAT_V6_MODE" >&2; exit 78 ;; esac
V4_POOL=${PLAT_V4_POOL:-}
case $V4_POOL in *[!0-9./\ ]*) echo "plat-v6-announce: bad PLAT_V4_POOL" >&2; exit 78 ;; esac
STATE_DIR=${ENV_STATE_DIR:-${PLAT_STATE_DIR:-/var/lib/plat/cluster}}
case $STATE_DIR in /*) ;; *) echo "plat-v6-announce: PLAT_STATE_DIR must be absolute" >&2; exit 78 ;; esac
ANN=$STATE_DIR/announce.d
CIDR4_RE='([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}'

vty() {
    vtysh -c 'configure terminal' -c "router bgp $PLAT_BGP_ASN" -c 'address-family ipv6 unicast' -c "$1"
}

# lifetime: platd's current InvocationID ("" without systemd). prestart
# runs inside the new invocation, so systemd's INVOCATION_ID is preferred.
lifetime() {
    if [ "$MODE_ARG" = prestart ] && [ -n "${INVOCATION_ID:-}" ]; then
        printf '%s\n' "$INVOCATION_ID"
        return
    fi
    systemctl show -p InvocationID --value platd 2>/dev/null || true
}

# current_lifetime: true when the owner file was written by prestart of the
# platd that runs now (D-3: files from an earlier, crashed platd never
# count). `off` removes the file on every exit and /run is cleared at boot,
# so from the hooks (`slices`, inside platd's sandbox, where systemctl may
# be unavailable) its presence is enough; sync (root, FRR restart) also
# compares it with platd's InvocationID.
current_lifetime() {
    [ -f "$OWNER" ] || return 1
    [ "$MODE_ARG" = slices ] && return 0
    want=$(lifetime)
    have=$(cat "$OWNER" 2>/dev/null || true)
    [ "$have" = "$want" ]
}

ann_ok() { [ -d "$ANN" ] && [ ! -L "$ANN" ]; }

# owned_slices: the slice CIDRs in announce.d (temp files ignored), one per line.
owned_slices() {
    ann_ok || return 0
    for f in "$ANN"/*; do
        [ -f "$f" ] || continue
        n=${f##*/}
        case $n in *.tmp*) continue ;; esac
        c=$(printf '%s' "$n" | tr _ /)
        printf '%s\n' "$c" | grep -Eqx "$CIDR4_RE" && printf '%s\n' "$c"
    done
    return 0
}

# owns_slice: true while announce.d holds at least one slice of this lifetime.
owns_slice() {
    current_lifetime || return 1
    [ -n "$(owned_slices)" ]
}

platd_running() {
    case $(systemctl is-active platd 2>/dev/null || true) in active | activating | reloading) return 0 ;; esac
    return 1
}

# pool_networks <running-config>: IPv4 `network` statements inside PLAT_V4_POOL.
pool_networks() {
    [ -n "$V4_POOL" ] || return 0
    printf '%s\n' "$1" | awk -v pool="$V4_POOL" '
        function n(a,  p) { split(a, p, "."); return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }
        function inside(c, pc,  x, y, s, b) {
            split(c, x, "/"); split(pc, y, "/")
            if (x[2] + 0 < y[2] + 0) return 0
            s = 2 ^ (32 - y[2]); b = n(y[1]) - n(y[1]) % s
            return n(x[1]) >= b && n(x[1]) < b + s
        }
        BEGIN { np = split(pool, P, " ") }
        $1 == "network" && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ {
            for (i = 1; i <= np; i++) if (inside($2, P[i])) { print $2; break }
        }'
}

# v4 <running-config> <cidr> <want 0|1>: changes FRR only when it differs.
v4() {
    if printf '%s\n' "$1" | grep -Eq "^[[:space:]]+network $2\$"; then h=1; else h=0; fi
    [ "$3" = "$h" ] && return 0
    asn=$(printf '%s\n' "$1" | awk '$1 == "router" && $2 == "bgp" { print $3; exit }')
    printf '%s\n' "$asn" | grep -Eqx '[0-9]{1,10}' || return 1
    if [ "$3" = 1 ]; then cmd="network $2"; else cmd="no network $2"; fi
    vtysh -c 'configure terminal' -c "router bgp $asn" -c 'address-family ipv4 unicast' -c "$cmd" -c end >/dev/null
}

# reconcile_v4 <keep 0|1>: withdraws every candidate slice (announce.d plus
# PLAT_V4_POOL networks); with keep=1 the slices of the current lifetime are
# (re-)announced instead. Returns 1 when FRR could not be read or changed.
reconcile_v4() {
    running=$(vtysh -c 'show running-config' 2>/dev/null) || return 1
    keep=
    if [ "$1" = 1 ] && current_lifetime; then keep=$(owned_slices); fi
    rc=0
    for c in $(
        owned_slices
        pool_networks "$running"
    ); do
        if printf '%s\n' "$keep" | grep -qx "$c"; then w=1; else w=0; fi
        v4 "$running" "$c" "$w" || rc=1
    done
    return "$rc"
}

# apply <want 0|1>: changes FRR only when its configuration differs, so
# repeated hook runs stay quiet.
apply() {
    running=$(vtysh -c 'show running-config') || { echo "plat-v6-announce: vtysh failed" >&2; exit 75; }
    if printf '%s\n' "$running" | grep -Eq "^[[:space:]]+network $PLAT_NAT64_PREFIX\$"; then have=1; else have=0; fi
    [ "$1" = "$have" ] && return 0
    if [ "$1" = 1 ]; then vty "network $PLAT_NAT64_PREFIX"; else vty "no network $PLAT_NAT64_PREFIX"; fi
}

# Serializes the slice-driven modes (hooks, FRR sync, start, stop) so the
# last writer has read the newest announce.d state. util-linux flock(1) on
# the directory; both root and the daemon user can open it.
lock() {
    if command -v flock >/dev/null 2>&1 && ann_ok; then
        exec 9<"$ANN"
        flock -w 10 9 || true
    fi
}

want_slices() { if owns_slice; then echo 1; else echo 0; fi; }

# cleanup: D-3 crash recovery, shared by prestart and off. Never fails.
cleanup() {
    lock
    reconcile_v4 0 || echo "plat-v6-announce: FRR unavailable; IPv4 slices not withdrawn there" >&2
    if ann_ok; then
        for f in "$ANN"/* "$ANN"/.[!.]*; do
            if [ -f "$f" ] || [ -L "$f" ]; then rm -f "$f" || echo "plat-v6-announce: cannot remove $f" >&2; fi
        done
    fi
    if [ "$HAVE_CONF" = 1 ]; then
        ( apply 0 ) || echo "plat-v6-announce: FRR unavailable; IPv6 prefix not withdrawn there" >&2
    fi
}

case $MODE_ARG in
prestart)
    cleanup
    rm -f "$OWNER"
    lt=$(lifetime)
    (umask 022 && printf '%s\n' "$lt" >"$OWNER.tmp.$$" && mv -f "$OWNER.tmp.$$" "$OWNER") ||
        echo "plat-v6-announce: cannot write $OWNER (no slice will count until the next start)" >&2
    exit 0
    ;;
on)
    if [ "$V6_MODE" = standalone ]; then
        vty "network $PLAT_NAT64_PREFIX"
        exit
    fi
    lock
    apply "$(want_slices)"
    ;;
off)
    cleanup
    rm -f "$OWNER"
    exit 0
    ;;
sync)
    if ! platd_running; then
        lock
        reconcile_v4 0 || true
        [ "$HAVE_CONF" = 0 ] || apply 0
    else
        lock
        reconcile_v4 1 || true
        [ "$HAVE_CONF" = 0 ] && exit 0
        if [ "$V6_MODE" = standalone ]; then apply 1; else apply "$(want_slices)"; fi
    fi
    ;;
slices)
    [ "$V6_MODE" = cluster ] || exit 0
    lock
    apply "$(want_slices)"
    ;;
*)
    echo "usage: $0 prestart|on|off|sync|slices" >&2
    exit 64
    ;;
esac
