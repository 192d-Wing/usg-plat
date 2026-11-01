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
# file's prog_id. In the shipped sandbox the program is matched by id
# only: ip(8) shows the tag only with CAP_SYS_ADMIN, which the guard does
# not have, and the tag is compared only when ip(8) shows it. Program ids
# are allocated cyclically and never reused while a program exists, so an
# equal id is the same loaded program. Interfaces are matched by ifindex;
# the name used to detach is the one the live listing shows for that
# ifindex, never the state file's. An interface without a program
# (detached) is no bypass and is not reported. Another program
# (xdp-program-swapped), a state file the guard cannot parse
# (xdp-state-malformed) or interfaces it cannot list (xdp-unverifiable)
# fail closed: the guard unpins the listed interfaces' link pins
# (/run/plat/bpf/link_<ifindex>, which detaches the loader's links; every
# link_* pin when the state file names no interface), detaches any program
# attached through netlink (`ip link set ... xdp... off`), turns forwarding
# off as above (which also stops a FIB-based program: bpf_fib_lookup
# returns FWD_DISABLED) and logs an error.
# Without a state file nothing of the fast path may be left (xdp-orphan,
# SEC-W68-001): any entry under /run/plat/bpf, or an XDP program on an
# interface named in [[xdp.interfaces]] of /etc/plat/platd.toml while
# [xdp] enabled = true, fails closed the same way (every link_* pin and
# those interfaces). Only the `[[xdp.interfaces]]` + `name = "..."` form
# is read; the pin check covers everything the loader creates.
# The loader writes the state file after it pins and attaches, and removes
# it last on detach, so a mismatch or orphan is checked again after
# PLAT_FWGUARD_XDP_RECHECK_SECS seconds (integer 0..=30, default 1; set it
# with a plat-fwguard.service drop-in `Environment=`; 0 acts at once)
# before the guard acts. Restore with `systemctl restart platd` (which
# re-runs plat-xdp.service).
# POAM: (POAM-037 residual) a foreign program attached through a bpf_link
# pinned outside /run/plat/bpf or held open by a process cannot be detached
# from a shell without CAP_SYS_ADMIN (BPF_LINK_GET_FD_BY_ID); the guard then
# reports "could NOT be detached", exits 1 and keeps forwarding off, which
# stops only programs that use bpf_fib_lookup.
#
# Test hooks (deploy/tests/deploy-scripts-test.sh; honoured only with
# PLAT_TEST_MODE=1): PLAT_NFT_RULES, PLAT_XDP_STATE, PLAT_XDP_PIN_DIR,
# PLAT_XDP_CONFIG, PLAT_XDP_RECHECK_SECS.
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
XDP_CONFIG=/etc/plat/platd.toml
XDP_RECHECK=1
case "${PLAT_FWGUARD_XDP_RECHECK_SECS:-}" in
    [0-9] | [12][0-9] | 30) XDP_RECHECK=$PLAT_FWGUARD_XDP_RECHECK_SECS ;;
    *) ;;
esac
if [ "${PLAT_TEST_MODE:-0}" = 1 ]; then
    NFT_RULES=${PLAT_NFT_RULES:-$NFT_RULES}
    XDP_STATE=${PLAT_XDP_STATE:-$XDP_STATE}
    XDP_PINS=${PLAT_XDP_PIN_DIR:-$XDP_PINS}
    XDP_CONFIG=${PLAT_XDP_CONFIG:-$XDP_CONFIG}
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

# The [[xdp.interfaces]] names of the config while [xdp] enabled = true
# (platd allows 1..=15 of [A-Za-z0-9_.-]; anything else is ignored).
xdp_conf_ifaces() {
    [ -r "$XDP_CONFIG" ] || return 0
    awk '
        { sub(/#.*/, "") }
        /^[[:space:]]*\[/ { sec = $0; gsub(/[[:space:]]/, "", sec); next }
        sec == "[xdp]" && /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true[[:space:]]*$/ { en = 1 }
        sec == "[[xdp.interfaces]]" && match($0, /^[[:space:]]*name[[:space:]]*=[[:space:]]*"[A-Za-z0-9_.-]+"/) {
            v = substr($0, RSTART, RLENGTH); sub(/^[^"]*"/, "", v); sub(/"$/, "", v)
            if (length(v) <= 15) n[++c] = v
        }
        END { if (en) for (i = 1; i <= c; i++) print n[i] }
    ' "$XDP_CONFIG" 2>/dev/null
}

# From the listing in $links: the line and the name (without @peer) of an
# ifindex, the ifindex of a name, and a line's XDP program id (details form
# "prog/xdp id N [name X] [tag T]", short form "xdp[generic|drv|offload]/id:N").
if_line() {
    il_ifx=$1
    printf '%s\n' "$links" | grep "^$il_ifx: " | head -n 1
}
if_name() {
    in_ifx=$1
    if_line "$in_ifx" | sed -n 's/^[0-9][0-9]*: \([^:@ ][^:@ ]*\)[@:].*/\1/p'
}
if_index() {
    re=$(printf '%s' "$1" | sed 's/\./\\./g')
    printf '%s\n' "$links" | sed -n "s/^\([0-9][0-9]*\): ${re}[@:].*/\1/p" | head -n 1
}
line_id() {
    i=$(printf '%s\n' "$1" | sed -n 's|.*prog/xdp id \([0-9][0-9]*\).*|\1|p')
    [ -n "$i" ] || i=$(printf '%s\n' "$1" | sed -n 's|.*xdp[a-z]*/id:\([0-9][0-9]*\).*|\1|p')
    printf '%s' "$i"
}
list_links() { command -v ip >/dev/null 2>&1 && links=$(ip -o -d link show 2>/dev/null); }

# No state file: anything left of the fast path is an orphan.
xdp_orphan() {
    pins=$(ls -A "$XDP_PINS" 2>/dev/null)
    cifs=$(xdp_conf_ifaces)
    [ -n "$pins$cifs" ] || return 0
    xall=1
    if [ -n "$cifs" ]; then
        if ! list_links; then
            xstate=xdp-unverifiable
            xdetail="no $XDP_STATE and cannot list the [xdp] interfaces (ip -o -d link show)"
            return 0
        fi
        for n in $cifs; do
            ifx=$(if_index "$n")
            [ -n "$ifx" ] || continue
            id=$(line_id "$(if_line "$ifx")")
            [ -n "$id" ] || continue
            xstate=xdp-orphan
            xprog=1
            xdetail="$n (ifindex $ifx) runs XDP program id $id without $XDP_STATE"
            return 0
        done
    fi
    if [ -n "$pins" ]; then
        xstate=xdp-orphan
        xdetail="pins under $XDP_PINS without $XDP_STATE: $(printf '%s\n' "$pins" | head -n 4 | tr '\n' ' ')"
    fi
}

# Sets xstate (empty: as attached, or nothing of the fast path left without
# a state file), xdetail, xdp_ifs ("ifindex name" lines of the state
# file's interfaces), xall (act on every link pin and [xdp] interface:
# no interface known) and xprog (a wrong program was seen running).
xdp_check() {
    xstate=
    xdetail=
    xdp_ifs=
    xall=
    xprog=
    links=
    if [ ! -e "$XDP_STATE" ]; then
        xdp_orphan
        return 0
    fi
    if ! st=$(cat "$XDP_STATE" 2>/dev/null); then
        xstate=xdp-state-malformed
        xdetail="$XDP_STATE unreadable"
        xall=1
        return 0
    fi
    want_id=$(printf '%s\n' "$st" | sed -n 's/^prog_id=\([0-9][0-9]*\)$/\1/p')
    want_tag=$(printf '%s\n' "$st" | sed -n 's/^prog_tag=\([0-9a-f][0-9a-f]*\)$/\1/p')
    xdp_ifs=$(printf '%s\n' "$st" | sed -n 's/^interface=\([^ ][^ ]*\) \([0-9][0-9]*\) [a-z][a-z]*$/\2 \1/p')
    if [ -z "$want_id" ] || [ -z "$want_tag" ] || [ -z "$xdp_ifs" ]; then
        xstate=xdp-state-malformed
        xdetail="$XDP_STATE has no prog_id, prog_tag or interface"
        [ -n "$xdp_ifs" ] || xall=1
        return 0
    fi
    if ! list_links; then
        xstate=xdp-unverifiable
        xdetail="cannot list the interfaces (ip -o -d link show)"
        return 0
    fi
    while read -r ifx _; do
        line=$(if_line "$ifx")
        [ -n "$line" ] || continue
        id=$(line_id "$line")
        [ -n "$id" ] || continue
        tag=$(printf '%s\n' "$line" | sed -n 's|.*prog/xdp id [0-9]*.* tag \([0-9a-f][0-9a-f]*\).*|\1|p')
        if [ "$id" != "$want_id" ] || { [ -n "$tag" ] && [ "$tag" != "$want_tag" ]; }; then
            xstate=xdp-program-swapped
            xprog=1
            xdetail="$(if_name "$ifx") (ifindex $ifx) runs program id $id${tag:+ tag $tag}, the loader attached id $want_id tag $want_tag"
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
nunpinned=0
xmsg=
if [ -n "$xstate" ]; then
    reason=$xstate
    detail=$xdetail
    all=$xall
    # Targets ("ifindex state-file-name" lines): the state file's
    # interfaces, or (all) every link pin and every [xdp] interface.
    # Detach: the loader's own link pins, then any program attached through
    # netlink, in both modes, by the name the live listing shows for the
    # ifindex (SEC-W68-002; the state file's name only when nothing can be
    # listed). The state file stays (it names what the loader attached;
    # plat-xdp.service removes it on stop).
    list_links || links=
    targets=$xdp_ifs
    if [ -n "$all" ]; then
        targets=
        for p in "$XDP_PINS"/link_*; do
            [ -e "$p" ] || continue
            targets="$targets${p##*/link_} -
"
        done
        for n in $(xdp_conf_ifaces); do
            ifx=$(if_index "$n")
            [ -z "$ifx" ] || targets="$targets$ifx -
"
        done
    fi
    while read -r ifx ifn; do
        [ -n "$ifx" ] || continue
        if [ -e "$XDP_PINS/link_$ifx" ] && rm -f "$XDP_PINS/link_$ifx" 2>/dev/null; then
            removed=1
            nunpinned=$((nunpinned + 1))
        fi
        case "$ifx" in *[!0-9]*) continue ;; *) ;; esac
        name=
        if [ -n "$links" ]; then
            name=$(if_name "$ifx")
        elif [ "$ifn" != - ]; then
            name=$ifn
        fi
        [ -n "$name" ] || continue
        ip link set dev "$name" xdpgeneric off 2>/dev/null
        ip link set dev "$name" xdpdrv off 2>/dev/null
    done <<EOF
$targets
EOF
    xdp_check
    if [ -n "$xprog" ]; then
        xmsg="<3>plat-fwguard: XDP fast path not as attached ($reason): $detail; the program could NOT be detached"
        xfail=1
    elif [ "$reason" = xdp-program-swapped ] || [ "$reason" = xdp-orphan ]; then
        xmsg="<3>plat-fwguard: XDP fast path not as attached ($reason): $detail; fast path detached ($nunpinned link pins unpinned). Restore with: systemctl restart platd"
    elif [ -n "$all" ] && [ "$nunpinned" -gt 0 ]; then
        xmsg="<3>plat-fwguard: XDP fast path cannot be verified ($reason): $detail; no interface known, so every link pin under $XDP_PINS was unpinned ($nunpinned). Restore with: systemctl restart platd"
    elif [ -n "$all" ]; then
        xmsg="<3>plat-fwguard: XDP fast path cannot be verified ($reason): $detail; no interface known and no link pin under $XDP_PINS to unpin. Restore with: systemctl restart platd"
    else
        xmsg="<3>plat-fwguard: XDP fast path cannot be verified ($reason): $detail; the listed interfaces' links were unpinned ($nunpinned). Restore with: systemctl restart platd"
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
