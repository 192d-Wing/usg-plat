#!/bin/sh
# Shared helpers for the cluster/HA failure-injection tests (plan §8.2).
# Sourced by deploy/tests/cluster/f*.sh and setup.sh; runs on the macOS (or
# Linux) host and drives the Lima VMs with `limactl shell`.
#
# Topology (VXLAN overlay `plha0`, VNI 205, over the Lima user-v2 network):
#   plat-linux    node A  id 0  192.168.205.11  fd00:205::11
#   plat-linux-2  node B  id 1  192.168.205.12  fd00:205::12
#   plat-edge     edge + witness 192.168.205.20  fd00:205::20
#     netns cli : 2001:db8:100:<n>::10/64 (IPv6 clients), via the edge
#     netns inet: 203.0.113.10/24 (IPv4 server), via the edge
# Pool 192.0.2.0/24, slices /28 (16 slices), NAT64 prefix 64:ff9b:1::/96.
# All addresses are documentation/ULA ranges; nothing here is routable.

# Caller sets CASE before sourcing.
: "${CASE:=adhoc}"
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
HERE=$ROOT/deploy/tests/cluster

A=${PLAT_A:-plat-linux}
B=${PLAT_B:-plat-linux-2}
E=${PLAT_EDGE:-plat-edge}
A_IP=192.168.205.11
B_IP=192.168.205.12
E_IP=192.168.205.20
A6=fd00:205::11
B6=fd00:205::12
E6=fd00:205::20
PEER_PORT=7946
POOL=192.0.2.0/24
SERVER4=203.0.113.10
SERVER6=64:ff9b:1::cb00:710a
# Must match the generated configs (setup.sh).
LEASE_MS=3000
DRIFT_PCT=10
FAILBACK_SECS=60
# Takeover budget: lease + margin + BFD (plan F1, target <= 5 s).
TAKEOVER_BUDGET_MS=5000
# Used by the sourcing scripts (setup.sh, f*.sh).
export A6 B6 E6 SERVER4 TAKEOVER_BUDGET_MS

OUT=${PLAT_CLUSTER_OUT:-$ROOT/target/cluster-ha-test}/$CASE-$(date +%Y%m%dT%H%M%S)
mkdir -p "$OUT"

FAILS=0
pass() { echo "ok - $CASE: $1" | tee -a "$OUT/result"; }
fail() {
    echo "FAIL - $CASE: $1" | tee -a "$OUT/result" >&2
    FAILS=$((FAILS + 1))
}
info() { echo "# $CASE: $*" | tee -a "$OUT/result"; }
finish() {
    if [ "$FAILS" -eq 0 ]; then
        echo "PASS $CASE (artifacts: $OUT)"
        exit 0
    fi
    echo "FAIL $CASE: $FAILS check(s) failed (artifacts: $OUT)" >&2
    exit 1
}

# Run a root shell command in a VM. limactl shell quotes each argument.
vm() {
    v=$1
    shift
    limactl shell --workdir / "$v" sudo sh -c "$*"
}
vm_up() { [ "$(limactl list --format '{{.Status}}' "$1" 2>/dev/null)" = Running ]; }

now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000'; }

# wait_until <timeout-ms> <command> [args...]: polls the command (usually a
# predicate below) every 200 ms; prints the elapsed ms, fails on timeout.
wait_until() {
    limit=$1
    shift
    t0=$(now_ms)
    while :; do
        if "$@" >/dev/null 2>&1; then
            echo $(($(now_ms) - t0))
            return 0
        fi
        [ $(($(now_ms) - t0)) -lt "$limit" ] || {
            echo $(($(now_ms) - t0))
            return 1
        }
        sleep 0.2
    done
}

# Prometheus value (summed over matching series) from a node's /metrics.
metric() {
    vm "$1" "curl -s --max-time 2 127.0.0.1:9464/metrics" 2>/dev/null |
        awk -v m="$2" 'index($0, m) == 1 { s += $NF } END { print s + 0 }'
}
active_slices() { metric "$1" 'plat_cluster_slices{state="active"'; }
fenced_slices() { metric "$1" 'plat_cluster_slices{state="fenced"'; }
# Predicates for wait_until.
slices_eq() { [ "$(active_slices "$1")" -eq "$2" ]; }
all_active_once() { [ $(($(active_slices "$A") + $(active_slices "$B"))) -eq 16 ]; }
pool_free() { metric "$1" plat_pool_blocks_free; }
both_serving() { all_active_once && [ "$(active_slices "$A")" -gt 0 ] && [ "$(active_slices "$B")" -gt 0 ]; }
metric_gt() { [ "$(metric "$1" "$2")" -gt "$3" ]; }
metric_eq() { [ "$(metric "$1" "$2")" -eq "$3" ]; }
# Backup <vm> has no slice still syncing and at least one in sync.
backup_resynced() {
    metric_eq "$1" 'plat_cluster_slices{state="backup_syncing"' 0 &&
        metric_gt "$1" 'plat_cluster_slices{state="backup_in_sync"' 0
}
# <vm> serves at least <n> slices and every slice is active exactly once.
rebalanced_to() { [ "$(active_slices "$1")" -ge "$2" ] && all_active_once; }
# Audit files in chronological order (platd rotates on every start to
# nat64-audit.jsonl.<µs epoch>; the plain glob lists the current file first).
# Files archived by f12 (fresh member) come first.
AUDIT_CAT="cat \$(ls /var/lib/plat-audit-archive/nat64-audit.jsonl.[0-9]* 2>/dev/null | sort) \$(ls /var/log/plat/nat64-audit.jsonl.[0-9]* 2>/dev/null | sort) /var/log/plat/nat64-audit.jsonl 2>/dev/null"
cluster_json() { vm "$1" "curl -s --max-time 2 127.0.0.1:9464/cluster"; }

platd_start() { vm "$1" "systemctl start platd"; }
platd_stop() { vm "$1" "systemctl stop platd"; }
# SIGKILL to the main process only (the cgroup-wide kill fails with EINVAL
# on the Lima kernels and makes systemctl exit non-zero), then cancel the
# Restart=on-failure job so the node stays down as the cases expect.
platd_kill9() { vm "$1" "systemctl kill --kill-whom=main -s KILL platd && systemctl stop platd"; }
platd_running() { vm "$1" "systemctl is-active --quiet platd"; }

# Healthy baseline: both nodes up, all 16 slices active exactly once.
ensure_cluster() {
    for v in "$A" "$B" "$E"; do vm_up "$v" || limactl start "$v" >/dev/null; done
    vm "$E" "systemctl start plat-witness" || true
    platd_running "$A" || platd_start "$A"
    platd_running "$B" || platd_start "$B"
    # Both nodes serving (failback after a restart takes failback_delay_secs).
    wait_until $(((FAILBACK_SECS + 90) * 1000)) both_serving >/dev/null ||
        { fail "baseline: slices not all active once on both nodes"; finish; }
    # Product bug (three-VM report, B-2): after a restart/handover the backup
    # can stay backup_syncing and the pool reports 0 free blocks, so every new
    # subscriber is dropped (port_exhausted). Record it and cold-start both
    # nodes so the case starts from a usable baseline.
    if [ "$(pool_free "$A")" -eq 0 ] || [ "$(pool_free "$B")" -eq 0 ]; then
        info "BASELINE-STARVED: pool free A $(pool_free "$A") B $(pool_free "$B"); cold restart of both nodes"
        echo "$CASE $(date -u +%FT%TZ)" >>"${PLAT_CLUSTER_OUT:-$ROOT/target/cluster-ha-test}/starved-baselines.txt"
        for v in "$A" "$B"; do vm "$v" "systemctl kill --kill-whom=main -s KILL platd; systemctl stop platd" || true; done
        sleep 4
        platd_start "$A"
        platd_start "$B"
        wait_until $(((FAILBACK_SECS + 90) * 1000)) both_serving >/dev/null || { fail "baseline after cold restart"; finish; }
        wait_until 60000 backup_resynced "$A" >/dev/null || true
    fi
}

# Event lines with a given action from a node's audit log.
audit_grep() { vm "$1" "$AUDIT_CAT | grep -F '\"event.action\":\"$2\"'" || true; }
audit_count() { audit_grep "$1" "$2" | grep -c . || true; }
audit_mark() { vm "$1" "$AUDIT_CAT | wc -l" | tr -d ' '; }

# Copies both nodes' audit logs and the edge SIEM copy to $OUT and runs the
# attribution checker (with the edge packet capture when present).
attrib() {
    vm "$A" "$AUDIT_CAT" >"$OUT/audit-a.jsonl" || true
    vm "$B" "$AUDIT_CAT" >"$OUT/audit-b.jsonl" || true
    vm "$E" "cat /var/log/plat-siem/siem.jsonl 2>/dev/null" >"$OUT/audit-siem.jsonl" || true
    set -- "$OUT/audit-a.jsonl" "$OUT/audit-b.jsonl" "$OUT/audit-siem.jsonl"
    # 5 ms: edge capture clock vs node audit clock (chrony, separate VMs).
    if [ -s "$OUT/pkts.txt" ]; then set -- -p "$OUT/pkts.txt" -t 5 "$@"; fi
    if sh "$HERE/attrib-check.sh" "$@" >"$OUT/attrib.txt" 2>&1; then
        pass "zero attribution overlap ($(tail -n 1 "$OUT/attrib.txt"))"
    else
        fail "attribution overlap: $(grep -c VIOLATION "$OUT/attrib.txt") violation(s), see $OUT/attrib.txt"
    fi
}

# --- traffic (deploy/tests/cluster/flows.py on the edge) --------------------
# traffic_start <seconds> [flows] [udp-pps] [new-conn/s]
traffic_start() {
    vm "$E" "systemctl stop plat-flows 2>/dev/null; systemctl reset-failed plat-flows 2>/dev/null; rm -f /run/plat-flows.json
        systemd-run --unit plat-flows --collect ip netns exec cli python3 /opt/plat-test/flows.py client \
            --target $SERVER6 --duration $1 --flows ${2:-200} --udp-pps ${3:-200} --cps ${4:-20} \
            --sources 8 --out /run/plat-flows.json" >/dev/null
}
traffic_wait() {
    wait_until $((${1:-600} * 1000)) vm "$E" "test -s /run/plat-flows.json" >/dev/null ||
        fail "traffic generator produced no result"
    vm "$E" "cat /run/plat-flows.json" >"$OUT/flows.json" 2>/dev/null || true
}
flows_field() { vm "$E" "jq -r '.$1' /run/plat-flows.json"; }
# check_flows <min-tcp-survival-%> <max-gap-ms or -> [min-new-conn-%]
check_flows() {
    total=$(flows_field tcp_flows)
    alive=$(flows_field tcp_survived)
    gap=$(flows_field tcp_max_gap_ms)
    [ "${total:-0}" -gt 0 ] || { fail "no TCP flows were established"; return; }
    pct=$((alive * 100 / total))
    if [ "$pct" -ge "$1" ]; then pass "TCP survival $alive/$total ($pct% >= $1%)"; else fail "TCP survival $alive/$total ($pct% < $1%)"; fi
    if [ "$2" != - ]; then
        if [ "$gap" -le "$2" ]; then pass "max flow gap ${gap} ms <= $2 ms"; else fail "max flow gap ${gap} ms > $2 ms"; fi
    fi
    if [ -n "${3:-}" ]; then
        ok=$(flows_field new_ok)
        bad=$(flows_field new_fail)
        npct=$((ok * 100 / (ok + bad + 1)))
        if [ "$npct" -ge "$3" ]; then pass "new connections $ok ok / $bad failed"; else fail "new connections $ok ok / $bad failed (< $3%)"; fi
    fi
}

# --- edge capture: translated IPv4 leaving the nodes towards the edge --------
capture_start() {
    vm "$E" "systemctl stop plat-cap 2>/dev/null; systemctl reset-failed plat-cap 2>/dev/null; rm -f /run/plat-cap.txt
        systemd-run --unit plat-cap --collect --setenv=TZ=UTC sh -c \
            'exec tcpdump -l -n -e -tttt -i plha0 \"ip src net $POOL\" >/run/plat-cap.txt 2>/dev/null'" >/dev/null
    sleep 1
}
capture_stop() {
    vm "$E" "systemctl stop plat-cap" || true
    vm "$E" "cat /run/plat-cap.txt" >"$OUT/cap.txt" 2>/dev/null || true
    # "<date> <time> <src-mac> > ... <src-ip>.<port> > ..." -> pkts.txt for
    # attrib-check (ISO-8601 UTC, microseconds) and macs.txt (epoch-free).
    awk '{
        ts = $1 "T" $2 "Z"; mac = $3
        for (i = 4; i <= NF; i++) if ($i == ">" && $(i - 1) ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
            n = split($(i - 1), o, "."); print ts, o[1] "." o[2] "." o[3] "." o[4], o[5] > "'"$OUT"'/pkts.txt"
            print ts, mac, o[1] "." o[2] "." o[3] "." o[4] > "'"$OUT"'/macs.txt"; break
        }
    }' "$OUT/cap.txt"
}
overlay_mac() { vm "$1" "cat /sys/class/net/plha0/address"; }
# Packets sourced from <mac> at or after <ISO ts> in the capture.
pkts_from_after() {
    [ -f "$OUT/macs.txt" ] || { echo 0; return; }
    awk -v m="$1" -v t="$2" '$2 == m && $1 >= t' "$OUT/macs.txt" | grep -c . || true
}
# Slices (/28) sourced by both MACs within the same second after <ISO ts>.
dual_active_after() {
    [ -f "$OUT/macs.txt" ] || { echo 0; return; }
    awk -v t="$1" '$1 >= t {
        split($3, o, "."); s = o[1] "." o[2] "." o[3] "." int(o[4] / 16) * 16 "/28"
        sec = substr($1, 1, 19); seen[s, sec, $2] = 1; macs[s, sec] = macs[s, sec] (index(macs[s, sec], $2) ? "" : " " $2)
    } END { for (k in macs) if (split(macs[k], x, " ") > 1) n++; print n + 0 }' "$OUT/macs.txt"
}

# --- impairment of the peer link (overlay, port 7946) -----------------------
# Drops cluster traffic between this VM and the given peer address.
block_peer() {
    vm "$1" "nft add table inet plat_test 2>/dev/null; nft 'add chain inet plat_test cut { type filter hook input priority -10; }' 2>/dev/null
        nft 'add chain inet plat_test cuto { type filter hook output priority -10; }' 2>/dev/null
        nft add rule inet plat_test cut ip saddr $2 tcp dport $PEER_PORT drop
        nft add rule inet plat_test cut ip saddr $2 tcp sport $PEER_PORT drop
        nft add rule inet plat_test cuto ip daddr $2 tcp dport $PEER_PORT drop
        nft add rule inet plat_test cuto ip daddr $2 tcp sport $PEER_PORT drop"
}
unblock_all() { vm "$1" "nft delete table inet plat_test 2>/dev/null || true"; }
iso_now() { vm "$1" "date -u +%Y-%m-%dT%H:%M:%S.%6NZ"; }

# --- configuration ------------------------------------------------------------
# gen_config <node-id> <listen-ip> <member ids, e.g. "0 1"> [port_block_size]
# Prints a platd.toml derived from config/platd.example.toml (the shipped
# example stays the single source of the non-cluster settings).
gen_config() {
    gid=$1
    gip=$2
    gmembers=$3
    gpbs=${4:-512}
    gn=$(echo "$gmembers" | wc -w | tr -d ' ')
    awk -v id="$gid" -v name="plat-$((gid + 1))" -v n="$gn" -v pbs="$gpbs" -v syslog="$E_IP:514" '
        /^\[/ { sec = $0 }
        sec == "[node]" && /^id = / { print "id = " id; next }
        sec == "[node]" && /^name = / { print "name = \"" name "\""; next }
        sec == "[cluster]" && /^node_count = / {
            print "node_count = " n; print "partition = \"slices\""; print "slice_prefix_len = 28"; next
        }
        sec == "[nat64]" && /^port_block_size = / { print "port_block_size = " pbs; next }
        sec == "[[audit.syslog]]" && /^address = / { print "address = \"" syslog "\""; next }
        # The test server 203.0.113.10 is TEST-NET-3 (non-global, SC-7 default deny).
        sec == "[translation]" && /^allow_non_global_destinations = / { print "allow_non_global_destinations = true   # test bed: TEST-NET-3 server"; next }
        sec == "[tls.revocation]" && /^mode = / { print "mode = \"off\"   # test PKI without CRL/OCSP"; next }
        { print }' "$ROOT/config/platd.example.toml"
    for m in $gmembers; do
        printf '\n[[cluster.members]]\nid = %s\nname = "plat-%s"\npeer_addr = "192.168.205.%s:%s"\nidentity = "dns:plat-%s.cluster.example"\n' \
            "$m" "$((m + 1))" "$((11 + m))" "$PEER_PORT" "$((m + 1))"
    done
    printf '\n[cluster.ha]\nenabled = true\nlisten = "%s:%s"\n' "$gip" "$PEER_PORT"
    if [ "$gn" -eq 2 ]; then
        printf 'witness = { addr = "%s:%s", identity = "dns:witness.cluster.example" }\n' "$E_IP" "$PEER_PORT"
    fi
    cat <<CFG
auto_failover = true
lease_ms = $LEASE_MS
heartbeat_ms = 500
drift_margin_pct = $DRIFT_PCT
failback_delay_secs = $FAILBACK_SECS
state_dir = "/var/lib/plat/cluster"
hook_timeout_ms = 5000

[cluster.ha.hooks]
announce = "/usr/libexec/plat/frr-announce.sh"
withdraw = "/usr/libexec/plat/frr-withdraw.sh"

[cluster.ha.tls]
cert_file = "/etc/plat/tls/cluster.crt"
key_file = "/etc/plat/tls/cluster.key"
ca_file = "/etc/plat/tls/ca.crt"

[cluster.steering]
mode = "drop"
CFG
}

# install_config <vm> <file>: root:plat 0640 as in the README.
install_config() {
    limactl copy "$2" "$1:/tmp/platd.toml.new" &&
        vm "$1" "install -m 0640 -o root -g plat /tmp/platd.toml.new /etc/plat/platd.toml && rm -f /tmp/platd.toml.new"
}
# Default configs: A = id 0, B = id 1, both members.
restore_configs() {
    gen_config 0 "$A_IP" "0 1" >"$OUT/a.toml"
    gen_config 1 "$B_IP" "0 1" >"$OUT/b.toml"
    install_config "$A" "$OUT/a.toml"
    install_config "$B" "$OUT/b.toml"
}

# Back to the healthy baseline after a case (impairments removed, default
# configs, everything running, every slice active exactly once).
restore() {
    for v in "$A" "$B" "$E"; do vm_up "$v" || limactl start "$v" >/dev/null; done
    for v in "$A" "$B"; do
        unblock_all "$v"
        vm "$v" "tc qdisc del dev plha0 root 2>/dev/null; systemctl start chrony frr; true"
    done
    vm "$E" "systemctl stop plat-f13-ka 2>/dev/null; ip -6 rule del pref 207 2>/dev/null; ip -6 route flush table 207 2>/dev/null; systemctl start plat-witness; true"
    restore_configs
    # Cases that installed another config set CONFIG_CHANGED=1.
    if [ "${CONFIG_CHANGED:-0}" = 1 ]; then
        vm "$A" "systemctl restart platd"
        vm "$B" "systemctl restart platd"
    fi
    ensure_cluster
}
