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
# or audit attribution. The policy is installed before forwarding is enabled,
# persisted in /etc/nftables.d/plat.nft and included (glob include of
# /etc/nftables.d/*.nft) from /etc/nftables.conf so an nftables reload
# restores it; plat-fwguard disables forwarding if the live table is missing
# or differs from the snapshot saved here (SC-24, fail closed).
#
# Test hooks (deploy/tests/deploy-scripts-test.sh), honoured only with
# PLAT_TEST_MODE=1: PLATD, PLAT_SYSFS, PLAT_NFT_RULES, PLAT_NFT_CONF,
# PLAT_LOG_DIR, PLAT_LOG_GROUP, PLAT_TMPFILES_CONF. Outside test mode the fixed paths are used.
set -eu

die() {
    echo "plat-tun-setup: $*" >&2
    exit 1
}

CONFIG=${1:-}
[ -n "$CONFIG" ] || die "usage: plat-tun-setup.sh /etc/plat/platd.toml"
[ -r "$CONFIG" ] || die "cannot read $CONFIG"
MTU=${PLAT_MTU:-1500}
SVC_USER=${PLAT_USER:-plat}
SVC_GROUP=${PLAT_GROUP:-plat}
# Persistent copy of the forward policy (NFT_RULES), included from the
# nftables service configuration (NFT_CONF) so `systemctl reload/restart
# nftables` restores it (POAM-019).
if [ "${PLAT_TEST_MODE:-0}" = 1 ]; then
    PLATD=${PLATD:-/usr/bin/platd}
    LOG_GROUP=${PLAT_LOG_GROUP:-plat-log}
    LOG_DIR=${PLAT_LOG_DIR:-/var/log/plat}
    TMPFILES_CONF=${PLAT_TMPFILES_CONF:-/usr/lib/tmpfiles.d/plat.conf}
    SYSFS=${PLAT_SYSFS:-/sys/class/net}
    NFT_RULES=${PLAT_NFT_RULES:-/etc/nftables.d/plat.nft}
    NFT_CONF=${PLAT_NFT_CONF:-/etc/nftables.conf}
else
    PLATD=/usr/bin/platd
    LOG_GROUP=plat-log
    LOG_DIR=/var/log/plat
    TMPFILES_CONF=/usr/lib/tmpfiles.d/plat.conf
    SYSFS=/sys/class/net
    NFT_RULES=/etc/nftables.d/plat.nft
    NFT_CONF=/etc/nftables.conf
fi
# What plat-fwguard.sh compares the live table with (not matched by the
# *.nft include glob).
NFT_EXPECTED=$NFT_RULES.expected

command -v nft >/dev/null 2>&1 || die "nft (nftables) is required for the forward policy"

# Machine-readable view of the validated config (parsed, never eval'd).
# Every line must be a PLAT_* assignment; keys this script does not use
# (PLAT_NODE_ID, PLAT_FIPS, PLAT_MGMT_TLS, future additions) are ignored, and
# each key it needs is required below.
env_out=$("$PLATD" check-config --config "$CONFIG" --format env) || die "check-config failed for $CONFIG"
IF=
PREFIX=
CLIENTS=
POOL=
while IFS= read -r line; do
    [ -n "$line" ] || continue
    printf '%s\n' "$line" | grep -Eq '^PLAT_[A-Z0-9_]+=' ||
        die "unexpected check-config output: $line"
    key=${line%%=*}
    value=${line#*=}
    case "$key" in
        PLAT_IF) IF=$value ;;
        PLAT_NAT64_PREFIX) PREFIX=$value ;;
        PLAT_CLIENT_PREFIXES) CLIENTS=$value ;;
        PLAT_OWNED_POOL) POOL=$value ;;
        *) ;;
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

# Audit log directory (AU-9, AC-6): plat:plat-log 2750 - the dedicated
# read-only group plat-log (log shippers and verify-log operators join it,
# never the plat group), setgid so files platd creates (0640) inherit it.
# The unit has no LogsDirectory= (systemd would re-apply plat:plat 0750 after
# this script, L13); the directory comes from tmpfiles.d, applied here once
# the group exists, with chgrp/chmod as the backstop when systemd-tmpfiles or
# the tmpfiles.d file is absent. Existing files and subdirectories (rotated
# logs) are re-grouped too, within the log volume (-xdev), at bounded depth,
# only if owned by the service account, and for files only with a single
# link (a hard link planted to a file elsewhere is never re-grouped).
if ! getent group "$LOG_GROUP" >/dev/null 2>&1; then
    groupadd --system "$LOG_GROUP" || die "cannot create group $LOG_GROUP"
fi
# Refuse a symlinked log directory before systemd-tmpfiles touches it (SEC-306).
[ -L "$LOG_DIR" ] && die "$LOG_DIR is a symbolic link"
if [ -f "$TMPFILES_CONF" ] && command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create "$TMPFILES_CONF" || die "systemd-tmpfiles failed for $TMPFILES_CONF (create it before the first start: systemd-tmpfiles --create /usr/lib/tmpfiles.d/plat.conf)"
fi
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR" || die "cannot create $LOG_DIR (create it before the first start: systemd-tmpfiles --create /usr/lib/tmpfiles.d/plat.conf)"
    chown "$SVC_USER" "$LOG_DIR" || die "cannot chown $LOG_DIR"
fi
chgrp "$LOG_GROUP" "$LOG_DIR"
chmod 2750 "$LOG_DIR"
find "$LOG_DIR" -xdev -mindepth 1 -maxdepth 4 -type d -user "$SVC_USER" -exec chgrp -h "$LOG_GROUP" {} +
find "$LOG_DIR" -xdev -mindepth 1 -maxdepth 4 -type f -user "$SVC_USER" -links 1 -exec chgrp -h "$LOG_GROUP" {} +

if ! ip link show dev "$IF" >/dev/null 2>&1; then
    ip tuntap add dev "$IF" mode tun multi_queue user "$SVC_USER" group "$SVC_GROUP"
fi
# An existing device must be a multiqueue TUN owned by the service account,
# or platd could not attach (or someone else could).
uid=$(id -u "$SVC_USER")
gid=$(getent group "$SVC_GROUP" | cut -d: -f3)
owner=$(cat "$SYSFS/$IF/owner" 2>/dev/null || echo missing)
group=$(cat "$SYSFS/$IF/group" 2>/dev/null || echo missing)
flags=$(cat "$SYSFS/$IF/tun_flags" 2>/dev/null || echo 0)
if [ "$owner" != "$uid" ] || [ "$group" != "$gid" ]; then
    die "$IF is owned by $owner:$group, expected $uid:$gid"
fi
if [ $((flags & 0x100)) -eq 0 ]; then
    die "$IF is not a multi_queue TUN (tun_flags $flags)"
fi

# Forward policy first, atomically replacing any previous version of the
# table (one nft transaction), then routes, then forwarding. The rules are
# written to $NFT_RULES (atomic rename) and loaded from there, so the live
# policy and the copy the nftables service restores are the same file.
clients_set=$(printf '%s' "$CLIENTS" | sed 's/ /, /g')
pool_set=$(printf '%s' "$POOL" | sed 's/ /, /g')
mkdir -p "$(dirname "$NFT_RULES")"
tmp_rules="$NFT_RULES.tmp.$$"
trap 'rm -f "$tmp_rules"' EXIT
cat >"$tmp_rules" <<EOF
# Generated by plat-tun-setup.sh from $CONFIG - do not edit; it is
# rewritten at every platd start (NIST 800-53 SC-7, CM-7).
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
chmod 0644 "$tmp_rules"
nft -c -f "$tmp_rules" || die "generated forward policy does not parse"
mv -f "$tmp_rules" "$NFT_RULES"
trap - EXIT
nft -f "$NFT_RULES" || die "cannot load $NFT_RULES"
# Snapshot of the table as loaded, for plat-fwguard.sh (SC-24: a changed
# policy, not only a missing one, closes forwarding).
nft list table inet plat >"$NFT_EXPECTED.tmp.$$" || die "forward policy not installed"
chmod 0644 "$NFT_EXPECTED.tmp.$$"
mv -f "$NFT_EXPECTED.tmp.$$" "$NFT_EXPECTED"

# Make the nftables service restore the policy after its own flush: one
# glob include of the drop-in directory in its configuration. A glob include
# matching no file is not an error, so removing plat.nft can never break the
# host ruleset. Idempotent; an exact include of plat.nft written by an
# earlier version is replaced by the glob. Hosts without that file (other
# distributions) rely on plat-fwguard, which disables forwarding when the
# table is missing.
old_include="include \"$NFT_RULES\""
include_line="include \"$(dirname "$NFT_RULES")/*.nft\""
if [ -f "$NFT_CONF" ]; then
    if grep -Fqx "$old_include" "$NFT_CONF"; then
        conf_tmp="$NFT_CONF.tmp.$$"
        if grep -Fqx "$include_line" "$NFT_CONF"; then
            grep -Fvx "$old_include" "$NFT_CONF" >"$conf_tmp" || true
        else
            awk -v old="$old_include" -v new="$include_line" '$0 == old { print new; next } { print }' \
                "$NFT_CONF" >"$conf_tmp"
        fi
        # Rewrite in place (keeps the file's owner and mode).
        cat "$conf_tmp" >"$NFT_CONF"
        rm -f "$conf_tmp"
    elif ! grep -Fqx "$include_line" "$NFT_CONF"; then
        printf '\n# usg-plat forward policy (plat-tun-setup.sh)\n%s\n' "$include_line" >>"$NFT_CONF"
    fi
else
    echo "plat-tun-setup: warning: $NFT_CONF not found; add '$include_line' to your nftables configuration" >&2
fi

ip link set dev "$IF" mtu "$MTU" up
# Only this node's routes on the TUN, whatever their protocol: drop every
# route (an old prefix, the whole pool, another node's slice, a static route
# someone added), then add the configured ones.
ip -4 route flush dev "$IF" 2>/dev/null || true
ip -6 route flush dev "$IF" 2>/dev/null || true
ip -6 route replace "$PREFIX" dev "$IF" proto boot
for p in $POOL; do
    ip -4 route replace "$p" dev "$IF" proto boot
done

# Verify the main table now holds exactly the configured prefixes on the TUN,
# of any protocol (ip(8) prints host routes without /32 or /128; the IPv6
# link-local route is ignored).
# POAM: POAM-019 residual - routes in other routing tables (policy routing)
# are not verified.
norm() { sed -e 's#/32$##' -e 's#/128$##' | sort; }
want4=$(for p in $POOL; do echo "$p"; done | norm)
got4=$(ip -4 route show dev "$IF" | awk '{print $1}' | norm)
[ "$got4" = "$want4" ] || die "IPv4 routes on $IF [$got4] do not match this node's pool [$want4]"
want6=$(printf '%s\n' "$PREFIX" | norm)
got6=$(ip -6 route show dev "$IF" | awk '$1 !~ /^fe80:/ {print $1}' | norm)
[ "$got6" = "$want6" ] || die "IPv6 routes on $IF [$got6] do not match the NAT64 prefix [$want6]"

sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
