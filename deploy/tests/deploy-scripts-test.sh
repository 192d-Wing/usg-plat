#!/bin/sh
# Drives deploy/systemd/plat-tun-setup.sh and plat-fwguard.sh against the
# REAL `platd check-config --format env` output of config/platd.example.toml,
# with ip(8), nft(8), sysctl(8) and the account tools replaced by stubs that
# record their calls. Catches regressions such as the setup script rejecting
# a new check-config key (LINUX_VERIFICATION.md L4). Real kernel behaviour
# is checked on Linux (L3-L6, L13, L15).
#
# Usage: deploy-scripts-test.sh [path/to/platd]   (default: cargo run)
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SETUP=$ROOT/deploy/systemd/plat-tun-setup.sh
GUARD=$ROOT/deploy/systemd/plat-fwguard.sh
CONFIG=$ROOT/config/platd.example.toml

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
BIN=$WORK/bin
STATE=$WORK/state
mkdir -p "$BIN" "$STATE"

if [ $# -ge 1 ]; then
    REAL_PLATD=$1
    [ -x "$REAL_PLATD" ] || { echo "no platd binary at $REAL_PLATD" >&2; exit 1; }
else
    # Through cargo run, which also sets the dynamic library path the FIPS
    # crypto build needs on macOS.
    cargo build -q -p platd --manifest-path "$ROOT/Cargo.toml"
    REAL_PLATD=$WORK/platd
    cat >"$REAL_PLATD" <<WRAP
#!/bin/sh
exec cargo run -q -p platd --manifest-path "$ROOT/Cargo.toml" -- "\$@"
WRAP
    chmod 0755 "$REAL_PLATD"
fi

fails=0
pass() { echo "ok - $1"; }
fail() { echo "FAIL - $1" >&2; fails=$((fails + 1)); }

# --- stubs -----------------------------------------------------------------
cat >"$BIN/ip" <<'STUB'
#!/bin/sh
# Minimal ip(8): one TUN, main-table routes kept in $STATE/routes{4,6}.
echo "ip $*" >>"$STATE/calls"
case "$*" in
    # plat-fwguard's XDP check: $STATE/links (or $STATE/links.N for the
    # N-th listing) in `ip -o -d link show` form; detaching removes the
    # device's program unless $STATE/xdp.sticky exists.
    "-o -d link show")
        [ -f "$STATE/links.fail" ] && exit 1
        n=$(($(cat "$STATE/links.calls" 2>/dev/null || echo 0) + 1))
        echo "$n" >"$STATE/links.calls"
        if [ -f "$STATE/links.$n" ]; then cat "$STATE/links.$n"; else cat "$STATE/links" 2>/dev/null; fi
        exit 0 ;;
    "link set dev "*" xdpgeneric off" | "link set dev "*" xdpdrv off")
        [ -f "$STATE/xdp.sticky" ] && exit 1
        sed -e "/^[0-9]*: $4[@:]/s| prog/xdp id [0-9][^\\\\]*||" -e "/^[0-9]*: $4[@:]/s| xdp[a-z]*/id:[0-9]*||" \
            "$STATE/links" >"$STATE/l.tmp" && mv "$STATE/l.tmp" "$STATE/links"
        exit 0 ;;
esac
fam=4
case "$1" in -4) shift ;; -6) fam=6; shift ;; esac
case "$1 $2" in
    "link show") [ -d "$PLAT_SYSFS/$4" ] ;;
    "tuntap add")
        mkdir -p "$PLAT_SYSFS/$4"
        echo 999 >"$PLAT_SYSFS/$4/owner"
        echo 988 >"$PLAT_SYSFS/$4/group"
        echo 0x1901 >"$PLAT_SYSFS/$4/tun_flags" ;;
    "link set") : ;;
    "route flush") : >"$STATE/routes$fam" ;;
    "route replace")
        grep -v "^$3 " "$STATE/routes$fam" >"$STATE/r.tmp" 2>/dev/null || true
        echo "$3 proto $7 scope link" >>"$STATE/r.tmp"
        mv "$STATE/r.tmp" "$STATE/routes$fam" ;;
    "route show") cat "$STATE/routes$fam" 2>/dev/null || true ;;
    *) echo "ip stub: unsupported: $*" >&2; exit 2 ;;
esac
STUB
cat >"$BIN/nft" <<'STUB'
#!/bin/sh
# Live ruleset = $STATE/loaded.nft; `list table` prints it the way nft(8)
# does: no comments or delete/add preamble, symbolic priority, live counters.
echo "nft $*" >>"$STATE/calls"
case "$*" in
    "-c -f "*) [ -s "$3" ] ;;
    "-f "*) cp "$2" "$STATE/loaded.nft" ;;
    "list chain inet plat forward") [ -f "$STATE/loaded.nft" ] ;;
    "list table inet plat")
        [ -f "$STATE/loaded.nft" ] || exit 1
        n=$(cat "$STATE/pkts" 2>/dev/null || echo 0)
        sed -e '/^#/d' -e '/^table inet plat$/d' -e '/^delete table/d' -e '/^[[:space:]]*#/d' \
            -e 's/priority 0;/priority filter;/' \
            -e "s/counter drop/counter packets $n bytes $((n * 60)) drop/" "$STATE/loaded.nft" ;;
    *) exit 2 ;;
esac
STUB
cat >"$BIN/sysctl" <<'STUB'
#!/bin/sh
echo "sysctl $*" >>"$STATE/calls"
case "$1" in
    -n) cat "$STATE/sysctl.$2" 2>/dev/null || echo 1 ;;
    -qw) [ -f "$STATE/sysctl.fail" ] && exit 1; shift; for kv; do echo "${kv#*=}" >"$STATE/sysctl.${kv%%=*}"; done ;;
esac
STUB
cat >"$BIN/id" <<'STUB'
#!/bin/sh
echo 999
STUB
cat >"$BIN/getent" <<'STUB'
#!/bin/sh
case "$2" in
    plat) echo "plat:x:988:" ;;
    plat-log) [ -f "$STATE/group.plat-log" ] && echo "plat-log:x:987:" ;;
    *) exit 2 ;;
esac
STUB
cat >"$BIN/groupadd" <<'STUB'
#!/bin/sh
echo "groupadd $*" >>"$STATE/calls"
: >"$STATE/group.plat-log"
STUB
cat >"$BIN/chgrp" <<'STUB'
#!/bin/sh
# One line per target (find -exec ... {} + batches them).
h=
if [ "$1" = -h ]; then h="-h "; shift; fi
g=$1
shift
for f; do echo "chgrp $h$g $f" >>"$STATE/calls"; done
STUB
cat >"$BIN/systemd-tmpfiles" <<'STUB'
#!/bin/sh
# Records the call and the group the directory would get; the group must
# already exist (tmpfiles fails on an unknown group).
echo "systemd-tmpfiles $*" >>"$STATE/calls"
[ -f "$STATE/group.plat-log" ] || { echo "unknown group plat-log" >&2; exit 1; }
grep -q '^d  *[^ ]*/log/plat  *2750  *plat  *plat-log ' "$2" || exit 1
STUB
cat >"$BIN/chown" <<'STUB'
#!/bin/sh
echo "chown $*" >>"$STATE/calls"
STUB
cat >"$BIN/chmod" <<'STUB'
#!/bin/sh
echo "chmod $*" >>"$STATE/calls"
STUB
/bin/chmod 0755 "$BIN"/*

# The log files below are owned by whoever runs the test; find -user needs a
# real account name.
ME=$(id -un)
RULES=$WORK/etc/nftables.d/plat.nft
TMPFILES=$ROOT/deploy/systemd/plat.tmpfiles.conf
run_setup() {
    PATH="$BIN:$PATH" STATE=$STATE PLAT_TEST_MODE=1 PLATD=$1 PLAT_SYSFS=$WORK/sys PLAT_USER=$ME \
        PLAT_NFT_RULES=$RULES PLAT_NFT_CONF=$WORK/etc/nftables.conf \
        PLAT_LOG_DIR=$WORK/log PLAT_TMPFILES_CONF=$TMPFILES sh "$SETUP" "$CONFIG"
}

mkdir -p "$WORK/etc" "$WORK/log/rotated" "$WORK/sys"
printf '#!/usr/sbin/nft -f\nflush ruleset\n' >"$WORK/etc/nftables.conf"
: >"$WORK/log/nat64-audit.jsonl"
: >"$WORK/log/rotated/nat64-audit.jsonl.1"
# A hard link planted in the log dir to a file elsewhere must not be re-grouped.
: >"$WORK/elsewhere"
ln "$WORK/elsewhere" "$WORK/log/planted.jsonl"
# A stale whole-pool static route on the TUN must not survive (L15).
echo "192.0.2.0/23 proto static scope link" >"$STATE/routes4"

# --- 1. real check-config output (incl. PLAT_FIPS, PLAT_MGMT_TLS) -----------
env_out=$("$REAL_PLATD" check-config --config "$CONFIG" --format env)
echo "$env_out" | grep -q '^PLAT_IF=' || fail "check-config env output lacks PLAT_IF"
if run_setup "$REAL_PLATD" >"$WORK/out" 2>&1; then
    pass "setup accepts real check-config output"
else
    fail "setup rejected real check-config output: $(cat "$WORK/out")"
fi
if grep -q 'ip6 saddr { 2001:db8:100::/40 } ip6 daddr 64:ff9b:1::/96 accept' "$WORK/etc/nftables.d/plat.nft"; then pass "persistent rules file written from config"; else fail "rules file content"; fi
if cmp -s "$WORK/etc/nftables.d/plat.nft" "$STATE/loaded.nft"; then pass "live policy loaded from the persistent file"; else fail "live policy differs from persistent file"; fi
routes4=$(cat "$STATE/routes4")
if [ "$routes4" = "192.0.2.0/24 proto boot scope link" ]; then pass "stale static route removed, only the pool slice routed"; else fail "IPv4 routes: $routes4"; fi
if grep -q 'sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1' "$STATE/calls"; then pass "forwarding enabled last"; else fail "forwarding not enabled"; fi
if grep -q '^groupadd --system plat-log' "$STATE/calls" && grep -q "^chgrp plat-log $WORK/log\$" "$STATE/calls" && grep -q "^chgrp -h plat-log $WORK/log/nat64-audit.jsonl\$" "$STATE/calls"; then pass "log dir and files handed to plat-log"; else fail "plat-log group handling"; fi
if grep -q "^chgrp -h plat-log $WORK/log/rotated\$" "$STATE/calls" && grep -q "^chgrp -h plat-log $WORK/log/rotated/nat64-audit.jsonl.1\$" "$STATE/calls"; then pass "rotated files in subdirectories re-grouped"; else fail "rotated subdirectory not re-grouped"; fi
if grep -q "planted.jsonl" "$STATE/calls"; then fail "hard-linked file re-grouped"; else pass "hard-linked file left alone"; fi
if grep -q 'hook forward priority filter; policy drop;' "$RULES.expected" 2>/dev/null; then pass "guard snapshot of the loaded table written"; else fail "no guard snapshot"; fi
if grep -Fqx "include \"$WORK/etc/nftables.d/*.nft\"" "$WORK/etc/nftables.conf"; then pass "nftables.conf has the glob include"; else fail "glob include missing"; fi
if grep -q "^chmod 2750 $WORK/log\$" "$STATE/calls"; then pass "log dir mode 2750"; else fail "log dir mode"; fi
# L13: tmpfiles.d applied after the group exists; the unit must not use
# LogsDirectory= (systemd would re-apply plat:plat 0750 after the script).
if awk '/^groupadd/{g=NR} /^systemd-tmpfiles --create /{t=NR} END{exit !(g && t && g < t)}' "$STATE/calls"; then pass "tmpfiles.d applied after plat-log is created"; else fail "tmpfiles.d not applied (or before groupadd)"; fi
if grep -Eq '^d[[:space:]]+/var/log/plat[[:space:]]+2750[[:space:]]+plat[[:space:]]+plat-log[[:space:]]' "$TMPFILES"; then pass "tmpfiles.d entry plat:plat-log 2750"; else fail "tmpfiles.d entry"; fi
if grep -Eq '^Logs?Directory' "$ROOT/deploy/systemd/platd.service"; then fail "unit still uses LogsDirectory="; elif grep -qx 'ReadWritePaths=/var/log/plat' "$ROOT/deploy/systemd/platd.service"; then pass "unit has no LogsDirectory=, keeps ReadWritePaths"; else fail "ReadWritePaths=/var/log/plat missing"; fi
# L5: ReadWritePaths= is resolved before ExecStartPre=, so the README install
# must create plat, plat-log, then apply tmpfiles.d before the first start.
if awk '/^getent passwd plat .*useradd/{u=NR} /^getent group plat-log .*groupadd/{g=NR}
    /install .*plat.tmpfiles.conf \/usr\/lib\/tmpfiles.d\/plat.conf/{i=NR}
    /^sudo systemd-tmpfiles --create \/usr\/lib\/tmpfiles.d\/plat.conf/{t=NR}
    /^sudo systemctl enable --now platd/{e=NR}
    END{exit !(u && g && i && t && e && u < t && g < t && i < t && t < e)}' "$ROOT/README.md"; then
    pass "README creates plat/plat-log and applies tmpfiles.d before starting platd"
else fail "README install order for /var/log/plat (L5)"; fi
# L5 (run 4): platd runs as User=plat, so the config is root:plat 0640 and is
# installed only after the plat user/group and plat-log exist.
if awk '/^getent passwd plat .*useradd/{u=NR} /^getent group plat-log .*groupadd/{g=NR}
    /install .*-m 0640 -o root -g plat config\/platd.example.toml \/etc\/plat\/platd.toml/{c=NR}
    /install .*platd.example.toml/{n++}
    END{exit !(u && g && c && n == 1 && u < c && g < c)}' "$ROOT/README.md"; then
    pass "README installs platd.toml root:plat 0640 after creating plat/plat-log"
else fail "README config install order/ownership (L5)"; fi

# --- 1b. log dir absent and no tmpfiles.d file: created by the script --------
rm -rf "$WORK/log2"
mv "$STATE/calls" "$STATE/calls.main"
if PATH="$BIN:$PATH" STATE=$STATE PLAT_TEST_MODE=1 PLATD=$REAL_PLATD PLAT_SYSFS=$WORK/sys PLAT_USER=$ME \
    PLAT_NFT_RULES=$RULES PLAT_NFT_CONF=$WORK/etc/nftables.conf PLAT_LOG_DIR=$WORK/log2 \
    PLAT_TMPFILES_CONF=$WORK/absent.conf sh "$SETUP" "$CONFIG" >"$WORK/out" 2>&1 &&
    [ -d "$WORK/log2" ] && grep -q "^chown $ME $WORK/log2\$" "$STATE/calls" &&
    grep -q "^chgrp plat-log $WORK/log2\$" "$STATE/calls" && grep -q "^chmod 2750 $WORK/log2\$" "$STATE/calls" &&
    ! grep -q '^systemd-tmpfiles' "$STATE/calls"; then
    pass "log dir created plat:plat-log 2750 without tmpfiles.d"
else
    fail "log dir fallback: $(cat "$WORK/out")"
fi
mv "$STATE/calls.main" "$STATE/calls"

# --- 2. idempotent re-run ---------------------------------------------------
run_setup "$REAL_PLATD" >"$WORK/out" 2>&1 || fail "second run failed: $(cat "$WORK/out")"
if [ "$(grep -c '^include ' "$WORK/etc/nftables.conf")" = 1 ]; then pass "nftables.conf include added exactly once"; else fail "include count in nftables.conf"; fi

# --- 2b. migration from the exact plat.nft include of earlier versions ------
printf '#!/usr/sbin/nft -f\nflush ruleset\ninclude "%s"\n' "$RULES" >"$WORK/etc/nftables.conf"
run_setup "$REAL_PLATD" >"$WORK/out" 2>&1 || fail "migration run failed: $(cat "$WORK/out")"
if ! grep -Fq "plat.nft\"" "$WORK/etc/nftables.conf" && [ "$(grep -c '^include ' "$WORK/etc/nftables.conf")" = 1 ] && grep -Fqx "include \"$WORK/etc/nftables.d/*.nft\"" "$WORK/etc/nftables.conf"; then pass "exact include replaced by the glob"; else fail "include migration: $(cat "$WORK/etc/nftables.conf")"; fi
printf 'include "%s"\ninclude "%s/*.nft"\n' "$RULES" "$WORK/etc/nftables.d" >"$WORK/etc/nftables.conf"
run_setup "$REAL_PLATD" >"$WORK/out" 2>&1 || fail "migration run failed: $(cat "$WORK/out")"
if [ "$(cat "$WORK/etc/nftables.conf")" = "include \"$WORK/etc/nftables.d/*.nft\"" ]; then pass "exact include dropped when the glob is present"; else fail "double include: $(cat "$WORK/etc/nftables.conf")"; fi
if [ "$(grep -c '^groupadd' "$STATE/calls")" = 1 ]; then pass "group created once"; else fail "groupadd repeated"; fi

# --- 3. malformed / incomplete check-config output --------------------------
fake() {
    cat >"$WORK/fake-platd" <<FAKE
#!/bin/sh
printf '%s\n' "$1"
FAKE
    chmod 0755 "$WORK/fake-platd"
}
fake "$env_out
PLAT_FUTURE_KEY=whatever"
if run_setup "$WORK/fake-platd" >/dev/null 2>&1; then pass "unknown PLAT_* key ignored"; else fail "unknown PLAT_* key rejected"; fi
fake "$env_out
rm -rf /"
if run_setup "$WORK/fake-platd" >/dev/null 2>&1; then fail "non-PLAT line accepted"; else pass "non-PLAT line rejected"; fi
fake "$(echo "$env_out" | grep -v '^PLAT_OWNED_POOL=')"
if run_setup "$WORK/fake-platd" >/dev/null 2>&1; then fail "missing PLAT_OWNED_POOL accepted"; else pass "missing required key rejected"; fi
fake "$(echo "$env_out" | sed 's#^PLAT_IF=.*#PLAT_IF=plat0;reboot#')"
if run_setup "$WORK/fake-platd" >/dev/null 2>&1; then fail "malformed interface accepted"; else pass "malformed interface rejected"; fi

# --- 3a. cluster HA: the whole pool is routed to the TUN (plan §1.5) ---------
# The real output now carries PLAT_CLUSTER_HA / PLAT_POOL_ALL; each case sets its own.
base=$(echo "$env_out" | grep -Ev '^PLAT_(OWNED_POOL|CLUSTER_HA|POOL_ALL)=')
if echo "$env_out" | grep -qx 'PLAT_CLUSTER_HA=0' && echo "$env_out" | grep -q '^PLAT_POOL_ALL='; then
    pass "check-config env output has PLAT_CLUSTER_HA and PLAT_POOL_ALL"
else
    fail "check-config env output lacks PLAT_CLUSTER_HA / PLAT_POOL_ALL"
fi
fake "$base
PLAT_OWNED_POOL=192.0.2.0/25
PLAT_CLUSTER_HA=1
PLAT_POOL_ALL=192.0.2.0/24"
if run_setup "$WORK/fake-platd" >"$WORK/out" 2>&1 && [ "$(cat "$STATE/routes4")" = "192.0.2.0/24 proto boot scope link" ] &&
    grep -q 'iifname "plat0" ip saddr { 192.0.2.0/24 } accept' "$RULES"; then
    pass "HA: whole pool routed and admitted, not only the owned slices"
else
    fail "HA whole-pool route: $(cat "$WORK/out") routes [$(cat "$STATE/routes4")]"
fi
fake "$base
PLAT_OWNED_POOL=192.0.2.0/25
PLAT_CLUSTER_HA=0
PLAT_POOL_ALL=192.0.2.0/24"
if run_setup "$WORK/fake-platd" >/dev/null 2>&1 && [ "$(cat "$STATE/routes4")" = "192.0.2.0/25 proto boot scope link" ]; then
    pass "HA off: only the owned pool routed"
else
    fail "HA off routes [$(cat "$STATE/routes4")]"
fi
fake "$base
PLAT_OWNED_POOL=192.0.2.0/25
PLAT_CLUSTER_HA=1"
if run_setup "$WORK/fake-platd" >/dev/null 2>&1; then fail "HA without PLAT_POOL_ALL accepted"; else pass "HA without PLAT_POOL_ALL rejected"; fi
fake "$base
PLAT_OWNED_POOL=192.0.2.0/25
PLAT_CLUSTER_HA=1
PLAT_POOL_ALL=192.0.2.0/24;reboot"
if run_setup "$WORK/fake-platd" >/dev/null 2>&1; then fail "malformed PLAT_POOL_ALL accepted"; else pass "malformed PLAT_POOL_ALL rejected"; fi
fake "$base
PLAT_OWNED_POOL=192.0.2.0/25
PLAT_CLUSTER_HA=yes
PLAT_POOL_ALL=192.0.2.0/24"
if run_setup "$WORK/fake-platd" >/dev/null 2>&1; then fail "malformed PLAT_CLUSTER_HA accepted"; else pass "malformed PLAT_CLUSTER_HA rejected"; fi

# --- 3c. pool-source guard (POAM-024) ----------------------------------------
if echo "$env_out" | grep -qx 'PLAT_CROSS_NODE_HAIRPIN=0' && echo "$env_out" | grep -qx 'PLAT_CLUSTER_IFACES='; then
    pass "check-config env output has PLAT_CROSS_NODE_HAIRPIN=0 and empty PLAT_CLUSTER_IFACES"
else
    fail "check-config env output lacks PLAT_CROSS_NODE_HAIRPIN / PLAT_CLUSTER_IFACES"
fi
guard_default='oifname "plat0" ip saddr { 192.0.2.0/24 } counter drop comment "plat-pool-source-guard"'
fake "$env_out"
if run_setup "$WORK/fake-platd" >"$WORK/out" 2>&1 && grep -Fq "$guard_default" "$RULES" &&
    [ "$(grep -n 'plat-pool-source-guard' "$RULES" | cut -d: -f1)" -lt "$(grep -n 'iifname "plat0" ip saddr' "$RULES" | cut -d: -f1)" ]; then
    pass "default: every pool source towards the TUN is dropped before the pool accepts"
else
    fail "default pool-source guard: $(cat "$WORK/out")"
fi
xbase=$(echo "$env_out" | grep -Ev '^PLAT_(OWNED_POOL|CLUSTER_HA|POOL_ALL|CROSS_NODE_HAIRPIN|CLUSTER_IFACES)=')
fake "$xbase
PLAT_OWNED_POOL=192.0.2.0/25
PLAT_CLUSTER_HA=0
PLAT_POOL_ALL=192.0.2.0/24
PLAT_CROSS_NODE_HAIRPIN=1
PLAT_CLUSTER_IFACES=eth1 bond0.20"
guard_x='oifname "plat0" iifname != { "eth1", "bond0.20" } ip saddr { 192.0.2.0/24 } counter drop comment "plat-pool-source-guard"'
if run_setup "$WORK/fake-platd" >"$WORK/out" 2>&1 && grep -Fq "$guard_x" "$RULES" &&
    grep -F 'plat-pool-source-guard' "$RULES.expected" | grep -Fq ' drop comment'; then
    pass "cross-node hairpin: whole-pool sources admitted only from the cluster interfaces"
else
    fail "cross-node pool-source guard: $(cat "$WORK/out")"
fi
for bad in "PLAT_CROSS_NODE_HAIRPIN=1
PLAT_CLUSTER_IFACES=" "PLAT_CROSS_NODE_HAIRPIN=1
PLAT_CLUSTER_IFACES=eth1;reboot" "PLAT_CROSS_NODE_HAIRPIN=1
PLAT_CLUSTER_IFACES=eth1\" }" "PLAT_CROSS_NODE_HAIRPIN=0
PLAT_CLUSTER_IFACES=eth1" "PLAT_CROSS_NODE_HAIRPIN=yes
PLAT_CLUSTER_IFACES="; do
    fake "$xbase
PLAT_OWNED_POOL=192.0.2.0/25
PLAT_CLUSTER_HA=0
PLAT_POOL_ALL=192.0.2.0/24
$bad"
    if run_setup "$WORK/fake-platd" >/dev/null 2>&1; then fail "guard input accepted: $bad"; else pass "guard input rejected: $(echo "$bad" | tr '\n' ' ')"; fi
done

# --- 3b. test hooks are ignored outside test mode ----------------------------
# Only where the real path is absent, so the run stops before touching the
# host (it dies at the missing /usr/bin/platd).
if [ ! -e /usr/bin/platd ]; then
    cat >"$WORK/marker-platd" <<FAKE
#!/bin/sh
: >"$STATE/fake-called"
FAKE
    chmod 0755 "$WORK/marker-platd"
    if PATH="$BIN:$PATH" STATE=$STATE PLATD=$WORK/marker-platd sh "$SETUP" "$CONFIG" >/dev/null 2>&1 || [ -e "$STATE/fake-called" ]; then
        fail "PLATD hook honoured without PLAT_TEST_MODE=1"
    else
        pass "test hooks ignored without PLAT_TEST_MODE=1"
    fi
fi

# --- 4. forward guard ---------------------------------------------------------
run_setup "$REAL_PLATD" >"$WORK/out" 2>&1 || fail "setup before guard tests failed: $(cat "$WORK/out")"
cp "$STATE/loaded.nft" "$WORK/good.nft"
guard_env() { PATH="$BIN:$PATH" STATE=$STATE PLAT_TEST_MODE=1 PLAT_NFT_RULES=$RULES "$@"; }
run_guard() { guard_env sh "$GUARD" 2>"$WORK/guard.err"; }
fwd_on() { echo 1 >"$STATE/sysctl.net.ipv4.ip_forward"; echo 1 >"$STATE/sysctl.net.ipv6.conf.all.forwarding"; : >"$STATE/calls"; }
closed() { grep -q 'sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0' "$STATE/calls" && grep -q "^<3>plat-fwguard.*($1)" "$WORK/guard.err"; }
fwd_on
if run_guard && ! grep -q 'sysctl -qw' "$STATE/calls"; then pass "guard leaves forwarding on while the policy is as installed"; else fail "guard with policy present: $(cat "$WORK/guard.err")"; fi
echo 12345 >"$STATE/pkts"
if run_guard && ! grep -q 'sysctl -qw' "$STATE/calls"; then pass "guard ignores counter values"; else fail "guard tripped on counters: $(cat "$WORK/guard.err")"; fi
# An extra accept rule: table and default-drop chain still exist.
sed 's/^\( *\)counter drop/\1iifname "eth0" accept\
\1counter drop/' "$WORK/good.nft" >"$STATE/loaded.nft"
if run_guard && closed policy-modified; then pass "guard disables forwarding when the policy was modified"; else fail "modified policy not detected: $(cat "$WORK/guard.err")"; fi
fwd_on
# Outside test mode the snapshot hook is ignored: the guard reads the fixed
# path (absent here), so the modified (still default-drop) table passes.
if [ ! -e /etc/nftables.d/plat.nft.expected ]; then
    if PLAT_NFT_RULES=$RULES PATH="$BIN:$PATH" STATE=$STATE sh "$GUARD" 2>/dev/null && ! grep -q 'sysctl -qw' "$STATE/calls"; then pass "guard hook ignored without PLAT_TEST_MODE=1"; else fail "guard honoured hook outside test mode"; fi
fi
# Without a snapshot the forward chain must still be default drop.
sed 's/policy drop;/policy accept;/' "$WORK/good.nft" >"$STATE/loaded.nft"
mv "$RULES.expected" "$WORK/expected.saved"
fwd_on
if run_guard && closed forward-not-default-drop; then pass "guard requires policy drop without a snapshot"; else fail "accept policy not detected: $(cat "$WORK/guard.err")"; fi
cp "$WORK/good.nft" "$STATE/loaded.nft"
fwd_on
if run_guard && ! grep -q 'sysctl -qw' "$STATE/calls"; then pass "guard accepts a default-drop table without a snapshot"; else fail "guard without snapshot: $(cat "$WORK/guard.err")"; fi
mv "$WORK/expected.saved" "$RULES.expected"
rm -f "$STATE/loaded.nft"
fwd_on
if run_guard && closed missing-table; then pass "guard disables forwarding when the table is gone"; else fail "guard did not fail closed"; fi
: >"$STATE/calls"
if run_guard && ! grep -q 'sysctl -qw' "$STATE/calls" && [ ! -s "$WORK/guard.err" ]; then pass "guard quiet once forwarding is off"; else fail "guard repeated action"; fi

# --- 4b. XDP fast path integrity in the guard (plan §6, §11 deploy tests) -----
# State file as plat-xdp-loader writes it; links as `ip -o -d link show`
# prints them (with -d as root the tag too, without CAP_SYS_ADMIN only the id).
XST=$WORK/run/plat/xdp.state
XPINS=$WORK/run/plat/bpf
mkdir -p "$XPINS"
cp "$WORK/good.nft" "$STATE/loaded.nft"
xdp_state() {
    printf 'object_sha256=%s\nprog_id=%s\nprog_tag=%s\nmode=native\nnonce=%s\ninterface=p6 2 access\ninterface=p4 3 upstream\n' \
        "$(printf '%064d' 0 | tr 0 a)" "$1" 0123456789abcdef "$(printf '%032d' 0)" >"$XST"
}
# $1, $2: the program parts of p6 and p4 ("" = none).
xdp_links() {
    rm -f "$STATE"/links.[0-9]* "$STATE/links.calls" "$STATE/xdp.sticky"
    {
        echo '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0'
        echo "2: p6@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc noqueue state UP mode DEFAULT group default qlen 1000\\    link/ether 02:00:00:00:02:01 brd ff:ff:ff:ff:ff:ff link-netns xc promiscuity 0 \\    veth $1\\    addrgenmode eui64 numtxqueues 6"
        echo "3: p4@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc noqueue state UP mode DEFAULT group default qlen 1000\\    link/ether 02:00:00:00:01:01 brd ff:ff:ff:ff:ff:ff link-netns xs promiscuity 0 \\    veth $2\\    addrgenmode eui64 numtxqueues 6"
    } >"$STATE/links"
    : >"$XPINS/link_2"
    : >"$XPINS/link_3"
    : >"$XPINS/OUT6"
}
xguard() {
    guard_env env PLAT_XDP_STATE="$XST" PLAT_XDP_PIN_DIR="$XPINS" PLAT_XDP_CONFIG="${XCONF:-$WORK/absent.toml}" PLAT_XDP_RECHECK_SECS="${RECHECK:-0}" sh "$GUARD" 2>"$WORK/guard.err"
}
quiet() { ! grep -q 'sysctl -qw' "$STATE/calls" && [ ! -s "$WORK/guard.err" ]; }
detached() { [ ! -e "$XPINS/link_2" ] && [ ! -e "$XPINS/link_3" ] && [ -e "$XPINS/OUT6" ] && grep -q 'ip link set dev p6 xdpgeneric off' "$STATE/calls"; }

# SEC-W68-001: no state file, nothing of the fast path may be left (xdp-orphan).
XCONF=$WORK/xdp.toml
xdp_conf() { printf '[dataplane]\ninterface = "plat0"\n\n[xdp]\nenabled = %s # comment\n\n[[xdp.interfaces]]\nname = "p6"\nrole = "access"\n\n[[xdp.interfaces]]\nname = "p4"  # upstream\nrole = "upstream"\n' "$1" >"$XCONF"; }
no_pins() { rm -f "$XPINS"/*; }
fwd_on
xdp_links "prog/xdp id 42 " "prog/xdp id 42 "
no_pins
if xguard && quiet; then pass "guard without an XDP state file, pins or [xdp] interfaces ignores XDP"; else fail "guard acted without a state file: $(cat "$WORK/guard.err")"; fi
xdp_links "" ""
if xguard && closed xdp-orphan && [ ! -e "$XPINS/link_2" ] && [ ! -e "$XPINS/link_3" ] && [ -e "$XPINS/OUT6" ] &&
    grep -q 'ip link set dev p6 xdpgeneric off' "$STATE/calls" && grep -q '2 link pins unpinned' "$WORK/guard.err"; then
    pass "guard fails closed on pins without a state file (xdp-orphan) and unpins every link"
else fail "orphan pins not detected: $(cat "$WORK/guard.err")"; fi
fwd_on
xdp_links "" "prog/xdp id 42 "
no_pins
xdp_conf true
if XCONF=$XCONF xguard && closed xdp-orphan && grep -q 'p4 (ifindex 3) runs XDP program id 42 without' "$WORK/guard.err" &&
    grep -q 'ip link set dev p4 xdpdrv off' "$STATE/calls"; then
    pass "guard fails closed on a program on an [xdp] interface without a state file"
else fail "orphan program not detected: $(cat "$WORK/guard.err")"; fi
fwd_on
xdp_links "" "prog/xdp id 42 "
no_pins
xdp_conf false
if XCONF=$XCONF xguard && quiet; then pass "guard ignores XDP programs while [xdp] is disabled"; else fail "orphan with [xdp] off: $(cat "$WORK/guard.err")"; fi
xdp_conf true
xdp_links "" ""
no_pins
if XCONF=$XCONF xguard && quiet; then pass "guard quiet with [xdp] interfaces, no program, no pins and no state file"; else fail "clean stop tripped: $(cat "$WORK/guard.err")"; fi
# A transient orphan (the loader pins before it writes the state file) is re-checked.
xdp_links "" ""
no_pins
: >"$XPINS/link_2"
printf '#!/bin/sh\nrm -f "%s" && exec %s "$@"\n' "$XPINS/link_2" "$(command -v sleep)" >"$BIN/sleep"
chmod +x "$BIN/sleep"
if RECHECK=1 xguard && quiet; then pass "guard re-checks a transient orphan before it acts"; else fail "transient orphan acted on: $(cat "$WORK/guard.err")"; fi
rm -f "$BIN/sleep"
fwd_on
xdp_links "prog/xdp id 42 " "prog/xdp id 42 "
xdp_state 42
if xguard && quiet; then pass "guard accepts the attached program (id only, as without CAP_SYS_ADMIN)"; else fail "guard tripped on the attached program: $(cat "$WORK/guard.err")"; fi
xdp_links "prog/xdp id 42 name plat_xdp tag 0123456789abcdef jited " "xdpgeneric/id:42 "
if xguard && quiet; then pass "guard accepts id and tag (details form) and the short form"; else fail "guard tripped on id and tag: $(cat "$WORK/guard.err")"; fi
xdp_links "" ""
if xguard && quiet; then pass "guard ignores interfaces without a program (detached)"; else fail "guard tripped on a detached interface: $(cat "$WORK/guard.err")"; fi
xdp_links "prog/xdp id 77 " "prog/xdp id 42 "
if xguard && closed xdp-program-swapped && detached && grep -q 'p6 (ifindex 2) runs program id 77' "$WORK/guard.err" &&
    grep -q 'fast path detached' "$WORK/guard.err"; then
    pass "guard detaches a swapped program and disables forwarding"
else fail "swapped program not handled: $(cat "$WORK/guard.err")"; fi
: >"$STATE/calls"
if xguard && quiet; then pass "guard quiet once the swapped program is detached and forwarding is off"; else fail "guard repeated XDP action: $(cat "$WORK/guard.err")"; fi
fwd_on
xdp_links "prog/xdp id 42 name plat_xdp tag fedcba9876543210 jited " "prog/xdp id 42 "
if xguard && closed xdp-program-swapped && detached; then pass "guard detects a wrong tag with the same id"; else fail "wrong tag not detected: $(cat "$WORK/guard.err")"; fi
fwd_on
xdp_links "prog/xdp id 77 " ""
: >"$STATE/xdp.sticky"
if ! xguard && closed xdp-program-swapped && grep -q 'could NOT be detached' "$WORK/guard.err"; then
    pass "guard fails (exit 1) when the swapped program cannot be detached, forwarding off"
else fail "undetachable program not reported: $(cat "$WORK/guard.err")"; fi
fwd_on
xdp_links "prog/xdp id 77 " ""
printf 'prog_id=42\nprog_tag=0123456789abcdef\n' >"$XST"
if xguard && closed xdp-state-malformed; then pass "guard fails closed on a malformed state file"; else fail "malformed state file not detected: $(cat "$WORK/guard.err")"; fi
fwd_on
# A loader replacing the program writes the state file right after the links:
# the guard checks again after PLAT_XDP_RECHECK_SECS before it acts.
xdp_state 42
xdp_links "prog/xdp id 42 " "prog/xdp id 42 "
sed 's|prog/xdp id 42 |prog/xdp id 77 |' "$STATE/links" >"$STATE/links.1"
if RECHECK=1 xguard && quiet; then pass "guard re-checks a mismatch before acting"; else fail "guard acted on a transient mismatch: $(cat "$WORK/guard.err")"; fi
# QA WU6/8 additions: persistent mismatch across the re-check, more malformed
# state files, ip(8) failure and output variants, exit codes when closed.
fwd_on
xdp_links "prog/xdp id 77 " "prog/xdp id 42 "
cp "$STATE/links" "$STATE/links.1"
cp "$STATE/links" "$STATE/links.2"
if RECHECK=1 xguard && closed xdp-program-swapped && detached && [ "$(cat "$STATE/links.calls")" -ge 2 ]; then
    pass "guard acts when the mismatch persists across the 1 s re-check"
else fail "persistent mismatch after re-check: $(cat "$WORK/guard.err")"; fi
fwd_on
xdp_links "prog/xdp id 42 " "prog/xdp id 77 name evil tag 0123456789abcdef "
if xguard && closed xdp-program-swapped && grep -q 'p4 (ifindex 3) runs program id 77' "$WORK/guard.err"; then
    pass "guard detects a swap on the second (upstream) interface"
else fail "upstream swap not detected: $(cat "$WORK/guard.err")"; fi
fwd_on
xdp_links "prog/xdp id 42 " "xdpdrv/id:77 "
if xguard && closed xdp-program-swapped && grep -q 'runs program id 77,' "$WORK/guard.err"; then
    pass "guard detects a swap in the short form (xdpdrv/id:N)"
else fail "short-form swap not detected: $(cat "$WORK/guard.err")"; fi
fwd_on
xdp_links "prog/xdp id 420 " "prog/xdp id 42 "
if xguard && closed xdp-program-swapped; then pass "guard does not prefix-match program ids (420 vs 42)"; else fail "id 420 accepted for 42: $(cat "$WORK/guard.err")"; fi
# Malformed with parseable interface lines: closed and the listed links unpinned.
for bad in "prog_id=42\nprog_tag=ZZ\ninterface=p6 2 access" "prog_tag=0123456789abcdef\ninterface=p6 2 access"; do
    fwd_on
    xdp_links "prog/xdp id 42 " "prog/xdp id 42 "
    printf '%b\n' "$bad" >"$XST"
    if xguard && closed xdp-state-malformed && [ ! -e "$XPINS/link_2" ]; then :; else fail "malformed state '$bad' not failed closed: $(cat "$WORK/guard.err")"; fi
done
# Malformed without a parseable interface: forwarding off (the guard cannot
# know which links to unpin; QA WU6/8 finding: the message still says the
# listed interfaces' links were unpinned).
for bad in "" "prog_id=4x2" "prog_id=42\nprog_tag=0123456789abcdef\ninterface=p6 two access"; do
    fwd_on
    xdp_links "prog/xdp id 42 " "prog/xdp id 42 "
    printf '%b\n' "$bad" >"$XST"
    if xguard && closed xdp-state-malformed && [ ! -e "$XPINS/link_2" ] && [ ! -e "$XPINS/link_3" ] && [ -e "$XPINS/OUT6" ] &&
        grep -q 'every link pin under .* was unpinned (2)' "$WORK/guard.err" && ! grep -q "listed interfaces" "$WORK/guard.err"; then :
    else fail "malformed state '$bad' not failed closed: $(cat "$WORK/guard.err")"; fi
done
# QA-1: no interface in the state file and no link pin: says so.
fwd_on
xdp_links "prog/xdp id 42 " "prog/xdp id 42 "
rm -f "$XPINS"/link_*
: >"$XST"
if xguard && closed xdp-state-malformed && grep -q 'no link pin under .* to unpin' "$WORK/guard.err"; then
    pass "guard unpins every link pin when the state file names no interface, and reports what it did"
else fail "no-interface message: $(cat "$WORK/guard.err")"; fi
# SEC-W68-002: detach by the live name of the ifindex, not the state file's.
fwd_on
xdp_links "prog/xdp id 77 " "prog/xdp id 42 "
xdp_state 42
sed -i.bak 's/^interface=p6 2 /interface=renamed0 2 /' "$XST"
if xguard && closed xdp-program-swapped && grep -q 'ip link set dev p6 xdpgeneric off' "$STATE/calls" &&
    ! grep -q 'renamed0' "$STATE/calls" && grep -q 'p6 (ifindex 2) runs program id 77' "$WORK/guard.err" &&
    grep -q 'fast path detached' "$WORK/guard.err"; then
    pass "guard detaches by the listed name of the ifindex, not the state file's name"
else fail "detach by state-file name: $(grep 'ip link set' "$STATE/calls"; cat "$WORK/guard.err")"; fi
pass "guard fails closed on empty, non-numeric id, bad ifindex, bad tag and missing id state files"
fwd_on
xdp_state 42
xdp_links "prog/xdp id 42 " "prog/xdp id 42 "
: >"$STATE/links.fail"
if xguard && closed xdp-unverifiable && [ ! -e "$XPINS/link_2" ] && [ ! -e "$XPINS/link_3" ]; then
    pass "guard fails closed (xdp-unverifiable) when ip -o -d link show fails"
else fail "unverifiable not handled: $(cat "$WORK/guard.err")"; fi
rm -f "$STATE/links.fail"
fwd_on
xdp_links "" ""
sed -i.bak '/^3: /d' "$STATE/links"
if xguard && quiet; then pass "guard ignores a state-file interface absent from the listing"; else fail "absent interface: $(cat "$WORK/guard.err")"; fi
# Forwarding already off: an undetachable swap still exits 1 and is reported.
fwd_on
echo 0 >"$STATE/sysctl.net.ipv4.ip_forward"; echo 0 >"$STATE/sysctl.net.ipv6.conf.all.forwarding"
xdp_links "prog/xdp id 77 " ""
: >"$STATE/xdp.sticky"
if ! xguard && ! grep -q 'sysctl -qw' "$STATE/calls" && grep -q 'could NOT be detached' "$WORK/guard.err"; then
    pass "guard exits 1 on an undetachable swap even with forwarding already off"
else fail "undetachable swap with forwarding off: $(cat "$WORK/guard.err")"; fi
fwd_on
xdp_links "prog/xdp id 77 " ""
: >"$STATE/sysctl.fail"
if ! xguard && grep -q 'forwarding could NOT be disabled' "$WORK/guard.err"; then
    pass "guard exits 1 when forwarding cannot be disabled after a swap"
else fail "sysctl failure not reported: $(cat "$WORK/guard.err")"; fi
rm -f "$STATE/sysctl.fail"
xdp_state 42
fwd_on
: >"$WORK/guard.err"
if [ ! -e /run/plat/xdp.state ]; then
    xdp_links "prog/xdp id 77 " ""
    if PLAT_XDP_STATE=$XST PLAT_NFT_RULES=$RULES PATH="$BIN:$PATH" STATE=$STATE sh "$GUARD" 2>/dev/null && quiet; then
        pass "XDP test hooks ignored without PLAT_TEST_MODE=1"
    else fail "guard honoured PLAT_XDP_STATE outside test mode"; fi
fi

# --- 4c. XDP units and tmpfiles (static; real behaviour: e2e.sh E2E_UNITS=1) --
SD=$ROOT/deploy/systemd
XTMP=$SD/plat-xdp.tmpfiles.conf
if grep -Eq '^d +/run/plat +0755 +root +root ' "$XTMP" && grep -Eq '^z +/run/plat/bpf +2750 +root +plat ' "$XTMP"; then
    pass "plat-xdp.tmpfiles.conf: /run/plat 0755 root:root, /run/plat/bpf 2750 root:plat"
else fail "plat-xdp.tmpfiles.conf entries"; fi
unit_val() { sed -n "s/^$2=//p" "$SD/$1"; }
if [ "$(unit_val plat-xdp.service CapabilityBoundingSet)" = "CAP_BPF CAP_NET_ADMIN" ] &&
    [ "$(unit_val plat-xdp.service AmbientCapabilities)" = "CAP_BPF CAP_NET_ADMIN" ] &&
    [ "$(unit_val plat-xdp.service Group)" = plat ] && [ "$(unit_val plat-xdp.service User)" = root ] &&
    [ "$(unit_val plat-xdp.service RemainAfterExit)" = yes ] &&
    unit_val plat-xdp.service ExecStart | grep -q ' attach --config /etc/plat/platd.toml$' &&
    unit_val plat-xdp.service ExecStop | grep -q ' detach$' &&
    unit_val plat-xdp.service ExecStopPost | grep -qx '/usr/libexec/plat/plat-xdp-loader detach' &&
    unit_val plat-xdp.service ExecStartPre | grep -q '^+/usr/bin/systemd-tmpfiles --create /usr/lib/tmpfiles.d/plat-xdp.conf$' &&
    [ "$(unit_val plat-xdp.service ReadWritePaths)" = /run/plat ]; then
    pass "plat-xdp.service: CAP_BPF + CAP_NET_ADMIN only, root:plat, attach/detach, tmpfiles"
else fail "plat-xdp.service privileges or commands"; fi
if unit_val plat-xdp.service PartOf | grep -qx platd.service && unit_val plat-xdp.service BindsTo | grep -qx platd.service &&
    unit_val plat-xdp.service Before | grep -qx platd.service &&
    unit_val platd.service.d.example/xdp.conf Requires | grep -qx plat-xdp.service &&
    unit_val platd.service.d.example/xdp.conf After | grep -qx plat-xdp.service; then
    pass "plat-xdp.service bound to platd both ways (fresh attach on every platd start)"
else fail "plat-xdp.service / platd binding"; fi
if [ "$(unit_val platd.service.d.example/xdp.conf SystemCallFilter)" = bpf ] &&
    ! grep -Eq '^(CapabilityBoundingSet|AmbientCapabilities|ProcSubset|ProtectProc|ReadWritePaths)=' "$SD/platd.service.d.example/xdp.conf"; then
    pass "platd xdp drop-in adds only the bpf syscall (no capability, /proc/self kept)"
else fail "platd xdp drop-in"; fi
if [ "$(unit_val run-plat-bpf.mount Where)" = /run/plat/bpf ] && [ "$(unit_val run-plat-bpf.mount Type)" = bpf ] &&
    unit_val run-plat-bpf.mount Options | grep -q '^mode=0750,nosuid,nodev,noexec$'; then
    pass "run-plat-bpf.mount: dedicated bpffs at /run/plat/bpf"
else fail "run-plat-bpf.mount"; fi
if unit_val plat-fwguard.service ReadWritePaths | grep -qx -- '-/run/plat/bpf' &&
    [ "$(unit_val plat-fwguard.service CapabilityBoundingSet)" = CAP_NET_ADMIN ]; then
    pass "plat-fwguard.service can unpin XDP links with CAP_NET_ADMIN only"
else fail "plat-fwguard.service XDP paths"; fi
if [ "$(unit_val plat-xdp.service Type)" = oneshot ] && [ "$(unit_val plat-xdp.service NoNewPrivileges)" = yes ] &&
    [ "$(unit_val plat-xdp.service IPAddressDeny)" = any ] &&
    [ "$(unit_val plat-xdp.service RestrictAddressFamilies)" = "AF_UNIX AF_NETLINK" ] &&
    unit_val plat-xdp.service SecureBits | grep -q noroot-locked &&
    unit_val plat-xdp.service ProtectSystem | grep -qx strict &&
    unit_val platd.service.d.example/xdp.conf RequiresMountsFor | grep -qx /run/plat/bpf &&
    unit_val platd.service.d.example/xdp.conf ReadOnlyPaths | grep -qx /run/plat; then
    pass "plat-xdp.service sandbox (oneshot, NNP, noroot-locked, no IP) and drop-in mount/read-only paths"
else fail "plat-xdp.service sandbox or drop-in mount dependency"; fi
PKG=$ROOT/services/platd/Cargo.toml
pkg_ok=1
for f in deploy/systemd/plat-xdp.service deploy/systemd/run-plat-bpf.mount deploy/systemd/plat-xdp.tmpfiles.conf \
    deploy/systemd/platd.service.d.example/xdp.conf target/release/plat-xdp-loader; do
    [ "$(grep -c "$f\"" "$PKG")" -eq 2 ] || { fail "packaging: $f not in both the deb and the rpm assets"; pkg_ok=0; }
done
[ "$pkg_ok" = 0 ] || pass "packaging lists the loader and the XDP units (deb and rpm)"

# --- 5. cluster announce/withdraw hooks (deploy/hooks) ------------------------
ANNOUNCE=$ROOT/deploy/hooks/frr-announce.sh
WITHDRAW=$ROOT/deploy/hooks/frr-withdraw.sh
cat >"$BIN/vtysh" <<'STUB'
#!/bin/sh
# vtysh(1): running config in $STATE/frr.conf; argv as the hooks pass it:
# -c "configure terminal" -c "router bgp N" -c "address-family ..." -c "<cmd>" -c end
echo "vtysh $*" >>"$STATE/vtysh.calls"
case "$2" in
    "show running-config") cat "$STATE/frr.conf" ;;
    "configure terminal")
        [ -f "$STATE/vtysh.fail" ] && exit 1
        case "$8" in
            "no network "*) grep -vx "  network ${8#no network }" "$STATE/frr.conf" >"$STATE/frr.tmp" || true
                mv "$STATE/frr.tmp" "$STATE/frr.conf" ;;
            "network "*) echo "  $8" >>"$STATE/frr.conf" ;;
            *) exit 2 ;;
        esac ;;
    *) exit 2 ;;
esac
STUB
/bin/chmod 0755 "$BIN/vtysh"
HSTATE=$WORK/cluster
hook() { PATH="$BIN:$PATH" STATE=$STATE PLAT_TEST_MODE=1 VTYSH="$BIN/vtysh" PLAT_STATE_DIR=$HSTATE sh "$@" 2>>"$WORK/hook.err"; }
printf 'router bgp 64513\n address-family ipv4 unicast\n exit-address-family\n' >"$STATE/frr.conf"
: >"$STATE/vtysh.calls"
if hook "$ANNOUNCE" 192.0.2.16/28 7 takeover && [ "$(cat "$HSTATE/announce.d/192.0.2.16_28")" = "7 takeover" ] &&
    grep -qx '  network 192.0.2.16/28' "$STATE/frr.conf" &&
    grep -q 'router bgp 64513 -c address-family ipv4 unicast -c network 192.0.2.16/28' "$STATE/vtysh.calls"; then
    pass "announce hook: network statement and announce.d file"
else fail "announce hook: $(cat "$WORK/hook.err")"; fi
n0=$(grep -c 'configure terminal' "$STATE/vtysh.calls")
if hook "$ANNOUNCE" 192.0.2.16/28 8 handover && [ "$(grep -c 'configure terminal' "$STATE/vtysh.calls")" = "$n0" ] &&
    [ "$(grep -c 'network 192.0.2.16/28' "$STATE/frr.conf")" = 1 ] && [ "$(cat "$HSTATE/announce.d/192.0.2.16_28")" = "8 handover" ]; then
    pass "announce hook idempotent"
else fail "announce hook repeated the change"; fi
if hook "$WITHDRAW" 192.0.2.16/28 9 fenced && [ ! -e "$HSTATE/announce.d/192.0.2.16_28" ] &&
    ! grep -q 'network 192.0.2.16/28' "$STATE/frr.conf"; then
    pass "withdraw hook: no network and file removed"
else fail "withdraw hook: $(cat "$WORK/hook.err")"; fi
n0=$(grep -c 'configure terminal' "$STATE/vtysh.calls")
if hook "$WITHDRAW" 192.0.2.16/28 9 fenced && [ "$(grep -c 'configure terminal' "$STATE/vtysh.calls")" = "$n0" ]; then
    pass "withdraw hook idempotent"
else fail "withdraw hook not idempotent"; fi
rc() { set +e; hook "$@"; r=$?; set -e; echo "$r"; }
rejects() {
    r=$(rc "$ANNOUNCE" "$@")
    if [ "$r" = 64 ]; then pass "announce rejects '$*' (64)"; else fail "announce '$*' exit $r"; fi
}
rejects 192.0.2.16/28 7
rejects 300.0.2.16/28 7 takeover
rejects '192.0.2.16/28;reboot' 7 takeover
rejects 192.0.2.16/33 7 takeover
rejects 2001:db8::/64 7 takeover
rejects 192.0.2.16/28 x takeover
rejects 192.0.2.16/28 7 Take-over
rejects 192.0.2.16/28 7 "\$(reboot)"
printf 'hostname x\n' >"$STATE/frr.conf"
if [ "$(rc "$ANNOUNCE" 192.0.2.32/28 1 startup)" = 69 ]; then pass "announce without router bgp exits 69"; else fail "no router bgp not detected"; fi
printf 'router bgp 64513\n' >"$STATE/frr.conf"
: >"$STATE/vtysh.fail"
if [ "$(rc "$ANNOUNCE" 192.0.2.32/28 1 startup)" = 75 ]; then pass "announce: vtysh refusal exits 75"; else fail "vtysh refusal not reported"; fi
printf 'router bgp 64513\n  network 192.0.2.32/28\n' >"$STATE/frr.conf"
if [ "$(rc "$WITHDRAW" 192.0.2.32/28 2 shutdown)" = 75 ]; then pass "withdraw: vtysh refusal exits 75"; else fail "withdraw vtysh refusal not reported"; fi
rm -f "$STATE/vtysh.fail"
set +e
PATH="$BIN:$PATH" STATE=$STATE PLAT_TEST_MODE=1 VTYSH="$BIN/vtysh" PLAT_STATE_DIR=relative sh "$ANNOUNCE" 192.0.2.32/28 1 startup 2>/dev/null
r=$?
set -e
if [ "$r" = 64 ]; then pass "relative PLAT_STATE_DIR rejected"; else fail "relative PLAT_STATE_DIR accepted ($r)"; fi
if ! command -v vtysh >/dev/null 2>&1; then
    set +e
    PATH="/usr/bin:/bin" VTYSH="$BIN/vtysh" PLAT_STATE_DIR=$HSTATE sh "$ANNOUNCE" 192.0.2.32/28 1 startup 2>/dev/null
    r=$?
    set -e
    if [ "$r" = 69 ]; then pass "VTYSH hook ignored without PLAT_TEST_MODE=1"; else fail "VTYSH honoured outside test mode ($r)"; fi
fi
for h in "$ANNOUNCE" "$WITHDRAW"; do
    if grep -q 'COMPLIANCE MAPPING' "$h"; then pass "$(basename "$h") has a compliance mapping"; else fail "$(basename "$h") lacks COMPLIANCE MAPPING"; fi
done

# --- 6. attribution checker (deploy/tests/cluster/attrib-check.sh) ------------
CHECK=$ROOT/deploy/tests/cluster/attrib-check.sh
ev() {
    printf '{"@timestamp":"%s","plat.schema":7,"event.sequence":%s,"event.action":"%s","observer.type":"nat64","observer.name":"%s","plat.node_id":0,"event.outcome":"success"%s}\n' "$@"
}
blk() {
    printf ',"source.ip":"%s","plat.subscriber.prefix":"%s/64","source.nat.ip":"%s","plat.nat.port_start":%s,"plat.nat.port_end":%s' "$1" "$1" "$2" "$3" "$4"
}
A1=$WORK/a.jsonl
B1=$WORK/b.jsonl
{
    ev 2026-10-29T10:00:00.000001Z 1 cluster_slice_acquire plat-1 ',"cluster.slice":"192.0.2.16/28","cluster.epoch":1,"cluster.reason":"startup"'
    ev 2026-10-29T10:00:01.000000Z 2 nat_port_block_allocate plat-1 "$(blk 2001:db8:100:1:: 192.0.2.17 1024 1535)"
    ev 2026-10-29T10:00:01.500000Z 3 nat_port_block_allocate plat-1 "$(blk 2001:db8:100:2:: 192.0.2.17 1536 2047)"
    ev 2026-10-29T10:00:02.000000Z 4 nat_port_block_release plat-1 "$(blk 2001:db8:100:2:: 192.0.2.17 1536 2047)"
} >"$A1"
{
    ev 2026-10-29T10:00:05.000000Z 1 cluster_slice_acquire plat-2 ',"cluster.slice":"192.0.2.16/28","cluster.epoch":2,"cluster.reason":"takeover","cluster.prev_owner":0'
    ev 2026-10-29T10:00:05.000100Z 2 nat_port_block_adopt plat-2 "$(blk 2001:db8:100:1:: 192.0.2.17 1024 1535)"
    ev 2026-10-29T10:00:06.000000Z 3 nat_port_block_allocate plat-2 "$(blk 2001:db8:100:3:: 192.0.2.17 1536 2047)"
} >"$B1"
printf '2026-10-29T10:00:01.200000Z 192.0.2.17 1100\n2026-10-29T10:00:05.000200Z 192.0.2.17 1100\n' >"$WORK/pk.txt"
cat "$A1" "$B1" >"$WORK/siem.jsonl"
if sh "$CHECK" -p "$WORK/pk.txt" "$A1" "$B1" "$WORK/siem.jsonl" >"$WORK/ac.out" 2>&1 &&
    grep -q '2 allocate\|3 allocate' "$WORK/ac.out" && grep -q ' 0 violation' "$WORK/ac.out"; then
    pass "attrib-check: clean takeover passes, SIEM duplicates collapsed"
else fail "attrib-check clean case: $(cat "$WORK/ac.out")"; fi
cp "$A1" "$WORK/a2.jsonl"
ev 2026-10-29T10:00:07.000000Z 5 nat_port_block_allocate plat-1 "$(blk 2001:db8:100:4:: 192.0.2.17 1536 2047)" >>"$WORK/a2.jsonl"
if sh "$CHECK" "$WORK/a2.jsonl" "$B1" >"$WORK/ac.out" 2>&1; then fail "attrib-check missed a block on two nodes"
elif grep -q 'held by plat-2 for 2001:db8:100:3::/64' "$WORK/ac.out"; then pass "attrib-check: block on two observers detected"
else fail "attrib-check overlap output: $(cat "$WORK/ac.out")"; fi
cp "$A1" "$WORK/a3.jsonl"
ev 2026-10-29T10:00:01.700000Z 9 nat_port_block_allocate plat-1 "$(blk 2001:db8:100:9:: 192.0.2.17 1024 1535)" >>"$WORK/a3.jsonl"
if sh "$CHECK" "$WORK/a3.jsonl" >"$WORK/ac.out" 2>&1; then fail "attrib-check missed two subscribers on one block"
elif grep -q 'attributed to 2001:db8:100:1::/64 and 2001:db8:100:9::/64' "$WORK/ac.out"; then pass "attrib-check: two subscribers on one block detected"
else fail "attrib-check two-subscriber output: $(cat "$WORK/ac.out")"; fi
printf '2026-10-29T10:00:00.500000Z 192.0.2.17 1100\n' >"$WORK/pk2.txt"
if sh "$CHECK" -p "$WORK/pk2.txt" "$A1" "$B1" >"$WORK/ac.out" 2>&1; then fail "attrib-check missed a packet before allocate"
elif grep -q 'before any allocate/adopt' "$WORK/ac.out"; then pass "attrib-check: packet before allocate/adopt detected"
else fail "attrib-check packet output: $(cat "$WORK/ac.out")"; fi
set +e
sh "$CHECK" >/dev/null 2>&1
r=$?
set -e
if [ "$r" = 2 ]; then pass "attrib-check usage error exits 2"; else fail "attrib-check usage exit $r"; fi

# --- plat-v6-announce.sh (D-1, D-2): prefix follows platd and slice ownership
V6=$ROOT/deploy/systemd/plat-v6-announce.sh
cat >"$BIN/vtysh" <<'STUB'
#!/bin/sh
# Same model as the hook stub: running config in $STATE/frr.conf.
echo "vtysh $*" >>"$STATE/vtysh.calls"
case "$2" in
    "show running-config") cat "$STATE/frr.conf" ;;
    "configure terminal")
        case "$8" in
            "no network "*) grep -vx "  network ${8#no network }" "$STATE/frr.conf" >"$STATE/frr.tmp" || true
                mv "$STATE/frr.tmp" "$STATE/frr.conf" ;;
            "network "*) grep -qx "  $8" "$STATE/frr.conf" || echo "  $8" >>"$STATE/frr.conf" ;;
            *) exit 2 ;;
        esac ;;
    *) exit 2 ;;
esac
STUB
cat >"$BIN/systemctl" <<'STUB'
#!/bin/sh
if [ "$1" = show ]; then echo "${PLAT_INV:-}"; exit 0; fi
if [ "${PLAT_ACTIVE:-0}" = 1 ]; then echo active; else echo inactive; exit 3; fi
STUB
chmod +x "$BIN/vtysh" "$BIN/systemctl"
V6NET='  network 64:ff9b:1::/96'
v6up() { grep -qx "$V6NET" "$STATE/frr.conf"; }
OWNERF=$WORK/announce.owner
export PLAT_INV=inv-1
v6() { PATH="$BIN:$PATH" STATE=$STATE PLAT_TEST_MODE=1 PLAT_V6_OWNER_FILE=$OWNERF PLAT_V6_ANNOUNCE_CONF="$WORK/v6.conf" sh "$V6" "$@" 2>>"$WORK/v6.err"; }
printf 'router bgp 64513\n' >"$STATE/frr.conf"
: >"$STATE/vtysh.calls"
printf 'PLAT_BGP_ASN=64513\nPLAT_NAT64_PREFIX=64:ff9b:1::/96\n' >"$WORK/v6.conf"
if v6 on && v6up && v6 off && ! v6up && v6 on && PLAT_ACTIVE=0 v6 sync && ! v6up && PLAT_ACTIVE=1 v6 sync && v6up &&
    grep -q 'router bgp 64513 -c address-family ipv6 unicast -c network 64:ff9b:1::/96' "$STATE/vtysh.calls"; then
    pass "plat-v6-announce standalone: on/off/sync follow platd"
else fail "plat-v6-announce standalone: $(cat "$WORK/v6.err") $(cat "$STATE/vtysh.calls")"; fi
v6 off
n0=$(grep -c 'configure terminal' "$STATE/vtysh.calls")
if v6 slices && [ "$(grep -c 'configure terminal' "$STATE/vtysh.calls")" = "$n0" ]; then
    pass "plat-v6-announce standalone: slices is a no-op"
else fail "plat-v6-announce standalone slices changed FRR"; fi
# D-2: cluster mode.
V6STATE=$WORK/v6cluster
mkdir -p "$V6STATE/announce.d"
printf 'PLAT_BGP_ASN=64513\nPLAT_NAT64_PREFIX=64:ff9b:1::/96\nPLAT_V6_MODE=cluster\nPLAT_STATE_DIR=%s\n' "$V6STATE" >"$WORK/v6.conf"
INVOCATION_ID=inv-1 v6 prestart
if [ "$(cat "$OWNERF")" = inv-1 ] && v6 on && ! v6up; then pass "D-2: start with no slice does not announce"; else fail "D-2: announced at start without a slice"; fi
echo "3 takeover" >"$V6STATE/announce.d/192.0.2.16_28"
echo "3 takeover" >"$V6STATE/announce.d/192.0.2.32_28.tmp"
if v6 slices && v6up; then pass "D-2: first slice announces the prefix"; else fail "D-2: first slice did not announce"; fi
n0=$(grep -c 'configure terminal' "$STATE/vtysh.calls")
if v6 slices && [ "$(grep -c 'configure terminal' "$STATE/vtysh.calls")" = "$n0" ]; then
    pass "D-2: slices idempotent"
else fail "D-2: slices repeated the change"; fi
if PLAT_ACTIVE=1 v6 sync && v6up && PLAT_ACTIVE=0 v6 sync && ! v6up && PLAT_ACTIVE=1 v6 sync && v6up; then
    pass "D-2: FRR resync follows platd and announce.d"
else fail "D-2: FRR resync wrong"; fi
rm -f "$V6STATE/announce.d/192.0.2.16_28"
if v6 slices && ! v6up; then pass "D-2: last slice released withdraws the prefix (temp files ignored)"; else fail "D-2: prefix kept without a slice"; fi
if PLAT_ACTIVE=1 v6 sync && ! v6up; then pass "D-2: FRR resync without a slice withdraws"; else fail "D-2: resync announced without a slice"; fi
rm -f "$V6STATE/announce.d/192.0.2.32_28.tmp"
# Through the shipped hooks (PLAT_V6_ANNOUNCE honoured in test mode only).
printf '#!/bin/sh\nexec sh "%s" "$@"\n' "$V6" >"$BIN/v6wrap"
chmod +x "$BIN/v6wrap"
printf 'router bgp 64513\n' >"$STATE/frr.conf"
v6hook() {
    PATH="$BIN:$PATH" STATE=$STATE PLAT_TEST_MODE=1 VTYSH="$BIN/vtysh" PLAT_STATE_DIR=$V6STATE \
        PLAT_V6_OWNER_FILE=$OWNERF PLAT_V6_ANNOUNCE="$BIN/v6wrap" PLAT_V6_ANNOUNCE_CONF="$WORK/v6.conf" sh "$@" 2>>"$WORK/hook.err"
}
if v6hook "$ANNOUNCE" 192.0.2.16/28 4 takeover && v6up && v6hook "$ANNOUNCE" 192.0.2.48/28 4 takeover &&
    v6hook "$WITHDRAW" 192.0.2.16/28 5 handover && v6up && v6hook "$WITHDRAW" 192.0.2.48/28 5 handover && ! v6up; then
    pass "D-2: hooks announce with the first slice and withdraw with the last"
else fail "D-2 hooks: $(cat "$WORK/hook.err")"; fi
# --- D-3: route state after a platd crash ------------------------------------
printf 'PLAT_BGP_ASN=64513\nPLAT_NAT64_PREFIX=64:ff9b:1::/96\nPLAT_V6_MODE=cluster\nPLAT_STATE_DIR=%s\nPLAT_V4_POOL="192.0.2.0/24"\n' "$V6STATE" >"$WORK/v6.conf"
printf 'router bgp 64513\n' >"$STATE/frr.conf"
v6hook "$ANNOUNCE" 192.0.2.16/28 4 takeover && v6hook "$ANNOUNCE" 192.0.2.48/28 4 takeover
# A slice whose file was lost, an operator route outside the pool.
printf '  network 192.0.2.64/28\n  network 198.51.100.0/24\n' >>"$STATE/frr.conf"
# kill -9: no withdraw hook, files and routes stay; ExecStopPost runs `off`.
if v6up && v6 off && ! v6up && ! grep -q 'network 192.0.2.' "$STATE/frr.conf" &&
    grep -qx '  network 198.51.100.0/24' "$STATE/frr.conf" && [ -z "$(ls -A "$V6STATE/announce.d")" ] && [ ! -e "$OWNERF" ]; then
    pass "D-3: stop-post after a crash withdraws all slices and the prefix, clears announce.d"
else fail "D-3 stop-post: $(cat "$STATE/frr.conf") $(ls -A "$V6STATE/announce.d") $(cat "$WORK/v6.err")"; fi
n0=$(grep -c 'configure terminal' "$STATE/vtysh.calls")
if v6 off && [ "$(grep -c 'configure terminal' "$STATE/vtysh.calls")" = "$n0" ]; then
    pass "D-3: stop-post idempotent"
else fail "D-3: stop-post repeated changes"; fi
# FRR down: still clears the files.
echo "4 takeover" >"$V6STATE/announce.d/192.0.2.16_28"
mv "$BIN/vtysh" "$BIN/vtysh.real"
printf '#!/bin/sh\nexit 1\n' >"$BIN/vtysh"
chmod +x "$BIN/vtysh"
if v6 off && [ -z "$(ls -A "$V6STATE/announce.d")" ]; then pass "D-3: stop-post with FRR down clears announce.d"
else fail "D-3: stop-post failed with FRR down"; fi
mv -f "$BIN/vtysh.real" "$BIN/vtysh"
# Restart with stale files (stop-post skipped): prestart cleans, nothing announced.
printf '  network 192.0.2.16/28\n' >>"$STATE/frr.conf"
echo "4 takeover" >"$V6STATE/announce.d/192.0.2.16_28"
echo "inv-0" >"$OWNERF"
PLAT_INV=inv-2
if INVOCATION_ID=inv-2 v6 prestart && v6 on && PLAT_ACTIVE=1 v6 sync && ! v6up &&
    ! grep -q 'network 192.0.2.16/28' "$STATE/frr.conf" && [ "$(cat "$OWNERF")" = inv-2 ]; then
    pass "D-3: restart with stale files announces nothing"
else fail "D-3: restart with stale files announced: $(cat "$STATE/frr.conf")"; fi
# FRR restart with files from an earlier lifetime: sync announces nothing.
echo "4 takeover" >"$V6STATE/announce.d/192.0.2.16_28"
printf 'router bgp 64513\n' >"$STATE/frr.conf"
PLAT_INV=inv-3
if PLAT_ACTIVE=1 v6 sync && ! v6up && ! grep -q 'network 192.0.2.16/28' "$STATE/frr.conf"; then
    pass "D-3: FRR sync ignores stale-lifetime files"
else fail "D-3: sync announced stale files: $(cat "$STATE/frr.conf")"; fi
PLAT_INV=inv-2
if PLAT_ACTIVE=1 v6 sync && v6up && grep -qx '  network 192.0.2.16/28' "$STATE/frr.conf"; then
    pass "D-3: FRR sync re-announces the current lifetime's slices"
else fail "D-3: sync lost current slices: $(cat "$STATE/frr.conf")"; fi
if PLAT_ACTIVE=0 v6 sync && ! v6up && ! grep -q 'network 192.0.2.16/28' "$STATE/frr.conf"; then
    pass "D-3: FRR sync with platd down withdraws slices and prefix"
else fail "D-3: sync with platd down kept routes"; fi
v6 off
if PLAT_V6_ANNOUNCE_CONF=$WORK/none PATH="$BIN:$PATH" sh "$V6" slices; then
    pass "plat-v6-announce slices without settings is a no-op"
else fail "plat-v6-announce slices failed without settings"; fi
printf 'PLAT_BGP_ASN=1;reboot\nPLAT_NAT64_PREFIX=64:ff9b:1::/96\n' >"$WORK/v6bad.conf"
if PATH="$BIN:$PATH" PLAT_V6_ANNOUNCE_CONF="$WORK/v6bad.conf" sh "$V6" on 2>/dev/null; then
    fail "plat-v6-announce accepted a bad ASN"
else pass "plat-v6-announce refuses a bad ASN"; fi
printf 'PLAT_BGP_ASN=1\nPLAT_NAT64_PREFIX=64:ff9b:1::/96\nPLAT_V6_MODE=both\n' >"$WORK/v6bad.conf"
if PATH="$BIN:$PATH" PLAT_V6_ANNOUNCE_CONF="$WORK/v6bad.conf" sh "$V6" on 2>/dev/null; then
    fail "plat-v6-announce accepted a bad PLAT_V6_MODE"
else pass "plat-v6-announce refuses a bad PLAT_V6_MODE"; fi

[ "$fails" -eq 0 ] || { echo "$fails deploy test(s) failed" >&2; exit 1; }
echo "all deploy script tests passed"
