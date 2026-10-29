#!/bin/sh
# Fail-closed guard for the host forward policy, run as root every 2 s by
# plat-fwguard.timer and right after the nftables service starts, reloads or
# stops (drop-in nftables.service.d/plat-fwguard.conf).
#
# The live `table inet plat` must be exactly what plat-tun-setup.sh loaded:
# the setup script saves `nft list table inet plat` right after loading the
# policy to /etc/nftables.d/plat.nft.expected, and the guard compares the
# live listing with it (counter values ignored). Without that snapshot (setup
# never ran, or it was removed) the guard still requires a forward-hook
# chain with policy drop. If the table is missing, modified or not default
# drop - a `flush ruleset`, an nftables reload without the include, a
# configuration-management run, a hand edit - the host would forward client
# traffic around the translator, its allow-list and audit attribution. The
# guard then turns IPv4 and IPv6 forwarding off and logs an error to the
# journal. Forwarding is re-enabled only by plat-tun-setup.sh (restart
# platd), after the policy is back.
#
# Test hook (deploy/tests/deploy-scripts-test.sh; honoured only with
# PLAT_TEST_MODE=1): PLAT_NFT_RULES.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SC-7 (Boundary Protection), SC-24 (Fail in Known State),
#   CM-7 (Least Functionality), AU-12 (journal record of the event)
set -u

NFT_RULES=/etc/nftables.d/plat.nft
if [ "${PLAT_TEST_MODE:-0}" = 1 ]; then
    NFT_RULES=${PLAT_NFT_RULES:-$NFT_RULES}
fi
EXPECTED=$NFT_RULES.expected

# Counter values change with traffic; indentation and blank lines carry no
# meaning.
norm() {
    sed -e 's/counter packets [0-9]* bytes [0-9]*/counter/g' -e 's/^[[:space:]]*//' -e '/^$/d'
}

state=
if ! command -v nft >/dev/null 2>&1; then
    state=missing-nft
elif ! live=$(nft list table inet plat 2>/dev/null); then
    state=missing-table
else
    live=$(printf '%s\n' "$live" | norm)
    if ! printf '%s\n' "$live" | grep -Eq '^type filter hook forward priority [^;]*; policy drop;'; then
        state=forward-not-default-drop
    elif [ -r "$EXPECTED" ] && [ "$live" != "$(norm <"$EXPECTED")" ]; then
        state=policy-modified
    fi
fi
[ -n "$state" ] || exit 0

v4=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)
v6=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo unknown)
if [ "$v4" = 0 ] && [ "$v6" = 0 ]; then
    # Already closed; nothing to report on every tick.
    exit 0
fi
# sd-daemon priority prefixes: the journal records <3> as err.
if sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0; then
    echo "<3>plat-fwguard: forward policy table inet plat not as installed ($state); IP forwarding disabled (was ipv4=$v4 ipv6=$v6). Restore with: systemctl restart platd" >&2
    exit 0
fi
echo "<3>plat-fwguard: forward policy table inet plat not as installed ($state) and forwarding could NOT be disabled" >&2
exit 1
