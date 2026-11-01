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
# XDP fast path (POAM-016, plan §6): XDP runs before netfilter, so the
# table above does not see fast-path traffic. While the loader's state file
# /run/plat/xdp.state exists, every interface it lists must run exactly the
# program the loader attached: the XDP program id the kernel reports for
# the interface (`ip -d link`, IFLA_XDP_PROG_ID) must equal the state
# file's prog_id, and the tag, when ip(8) can show it (that needs
# CAP_SYS_ADMIN, which the guard does not have), its prog_tag. Program ids
# are allocated cyclically and never reused while a program exists, so an
# equal id is the same loaded program. An interface without a program
# (detached) is no bypass and is not reported. Another program
# (xdp-program-swapped), a state file the guard cannot parse
# (xdp-state-malformed) or interfaces it cannot list (xdp-unverifiable)
# fail closed: the guard unpins the listed interfaces' link pins
# (/run/plat/bpf/link_<ifindex>, which detaches the loader's links),
# detaches any program attached through netlink (`ip link set ... xdp...
# off`), turns forwarding off as above (which also stops a FIB-based
# program: bpf_fib_lookup returns FWD_DISABLED) and logs an error. The
# loader writes the state file right after it replaces a program, so a
# mismatch is checked again after a second before the guard acts. Restore
# with `systemctl restart platd` (which re-runs plat-xdp.service).
# POAM: (POAM-037 residual) a foreign program attached through a bpf_link
# pinned outside /run/plat/bpf or held open by a process cannot be detached
# from a shell without CAP_SYS_ADMIN (BPF_LINK_GET_FD_BY_ID); the guard then
# reports "could NOT be detached", exits 1 and keeps forwarding off, which
# stops only programs that use bpf_fib_lookup.
#
# Test hooks (deploy/tests/deploy-scripts-test.sh; honoured only with
# PLAT_TEST_MODE=1): PLAT_NFT_RULES, PLAT_XDP_STATE, PLAT_XDP_PIN_DIR,
# PLAT_XDP_RECHECK_SECS.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SC-7 (Boundary Protection), SC-24 (Fail in Known State),
#   CM-7 (Least Functionality), AU-12 (journal record of the event)
# - NIST 800-53: SI-7 (Software Integrity) - the attached XDP program is
#   the one the loader recorded
set -u

NFT_RULES=/etc/nftables.d/plat.nft
XDP_STATE=/run/plat/xdp.state
XDP_PINS=/run/plat/bpf
XDP_RECHECK=1
if [ "${PLAT_TEST_MODE:-0}" = 1 ]; then
    NFT_RULES=${PLAT_NFT_RULES:-$NFT_RULES}
    XDP_STATE=${PLAT_XDP_STATE:-$XDP_STATE}
    XDP_PINS=${PLAT_XDP_PIN_DIR:-$XDP_PINS}
    XDP_RECHECK=${PLAT_XDP_RECHECK_SECS:-$XDP_RECHECK}
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

# Sets xstate (empty: as attached, or no state file), xdetail and xdp_ifs
# ("ifindex name" lines of the state file's interfaces).
xdp_check() {
    xstate=
    xdetail=
    xdp_ifs=
    [ -e "$XDP_STATE" ] || return 0
    if ! st=$(cat "$XDP_STATE" 2>/dev/null); then
        xstate=xdp-state-malformed
        xdetail="$XDP_STATE unreadable"
        return 0
    fi
    want_id=$(printf '%s\n' "$st" | sed -n 's/^prog_id=\([0-9][0-9]*\)$/\1/p')
    want_tag=$(printf '%s\n' "$st" | sed -n 's/^prog_tag=\([0-9a-f][0-9a-f]*\)$/\1/p')
    xdp_ifs=$(printf '%s\n' "$st" | sed -n 's/^interface=\([^ ][^ ]*\) \([0-9][0-9]*\) [a-z][a-z]*$/\2 \1/p')
    if [ -z "$want_id" ] || [ -z "$want_tag" ] || [ -z "$xdp_ifs" ]; then
        xstate=xdp-state-malformed
        xdetail="$XDP_STATE has no prog_id, prog_tag or interface"
        return 0
    fi
    if ! command -v ip >/dev/null 2>&1 || ! links=$(ip -o -d link show 2>/dev/null); then
        xstate=xdp-unverifiable
        xdetail="cannot list the interfaces (ip -o -d link show)"
        return 0
    fi
    while read -r ifx ifn; do
        line=$(printf '%s\n' "$links" | grep "^$ifx: " | head -n 1)
        [ -n "$line" ] || continue
        # Details form "prog/xdp id N [name X] [tag T]", short form
        # "xdp[generic|drv|offload]/id:N".
        id=$(printf '%s\n' "$line" | sed -n 's|.*prog/xdp id \([0-9][0-9]*\).*|\1|p')
        [ -n "$id" ] || id=$(printf '%s\n' "$line" | sed -n 's|.*xdp[a-z]*/id:\([0-9][0-9]*\).*|\1|p')
        [ -n "$id" ] || continue
        tag=$(printf '%s\n' "$line" | sed -n 's|.*prog/xdp id [0-9]*.* tag \([0-9a-f][0-9a-f]*\).*|\1|p')
        if [ "$id" != "$want_id" ] || { [ -n "$tag" ] && [ "$tag" != "$want_tag" ]; }; then
            xstate=xdp-program-swapped
            xdetail="$ifn (ifindex $ifx) runs program id $id${tag:+ tag $tag}, the loader attached id $want_id tag $want_tag"
            return 0
        fi
    done <<EOF
$xdp_ifs
EOF
}

xdp_check
if [ -n "$xstate" ] && [ "$XDP_RECHECK" != 0 ]; then
    sleep "$XDP_RECHECK"
    xdp_check
fi
[ -n "$state$xstate" ] || exit 0

xfail=0
removed=
xmsg=
if [ -n "$xstate" ]; then
    # Detach: the loader's own link pins only, then any program attached
    # through netlink, in both modes. The state file stays (it names what
    # the loader attached; plat-xdp.service removes it on stop).
    while read -r ifx ifn; do
        [ -n "$ifx" ] || continue
        if [ -e "$XDP_PINS/link_$ifx" ] && rm -f "$XDP_PINS/link_$ifx" 2>/dev/null; then
            removed=1
        fi
        ip link set dev "$ifn" xdpgeneric off 2>/dev/null
        ip link set dev "$ifn" xdpdrv off 2>/dev/null
    done <<EOF
$xdp_ifs
EOF
    reason=$xstate
    detail=$xdetail
    xdp_check
    if [ "$xstate" = xdp-program-swapped ]; then
        xmsg="<3>plat-fwguard: XDP fast path not as attached ($reason): $detail; the program could NOT be detached"
        xfail=1
    elif [ "$reason" = xdp-program-swapped ]; then
        xmsg="<3>plat-fwguard: XDP fast path not as attached ($reason): $detail; fast path detached. Restore with: systemctl restart platd"
    else
        xmsg="<3>plat-fwguard: XDP fast path cannot be verified ($reason): $detail; the listed interfaces' links were unpinned. Restore with: systemctl restart platd"
    fi
fi
what="forward policy table inet plat not as installed ($state)"
[ -n "$state" ] || what="XDP fast path not as attached ($reason)"

v4=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)
v6=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo unknown)
if [ "$v4" = 0 ] && [ "$v6" = 0 ]; then
    # Already closed; nothing to report on every tick unless a program was
    # (or could not be) detached just now.
    if [ -n "$xmsg" ] && { [ -n "$removed" ] || [ "$xfail" = 1 ]; }; then
        echo "$xmsg" >&2
    fi
    exit "$xfail"
fi
[ -z "$xmsg" ] || echo "$xmsg" >&2
# sd-daemon priority prefixes: the journal records <3> as err.
if sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0; then
    echo "<3>plat-fwguard: $what; IP forwarding disabled (was ipv4=$v4 ipv6=$v6). Restore with: systemctl restart platd" >&2
    exit "$xfail"
fi
echo "<3>plat-fwguard: $what and forwarding could NOT be disabled" >&2
exit 1
