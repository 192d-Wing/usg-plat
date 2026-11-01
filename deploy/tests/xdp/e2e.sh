#!/bin/sh
# Level 4 end-to-end test for the XDP fast path (plan §11 level 4). WU5 adds
# the platd [xdp] cases udp_both_directions, first_packet_slow_path,
# fast_path_keepalive and idle_expiry (run as root with the loader and platd
# started by hand, not by their units: the units are WU6); the capture
# comparison and frag_needed_revalidate are still to come (WU6/WU8).
#
#   xc (client, IPv6 only)        xp (PLAT: platd + plat-xdp-loader)        xs (server, IPv4)
#   c0 2001:db8:c::2/64  <--veth-->  p6 2001:db8:c::1/64
#                                    p4 198.51.100.1/24  <--veth-->  s0 198.51.100.2/24
#   client default route via xp (covers the RFC 6052 well-known prefix
#   64:ff9b::/96); server routes the test pool 192.0.2.0/24 via xp.
# Documentation ranges only (RFC 3849, RFC 5737). The cases will set
# allow_non_global_destinations = true in the test config for that reason.
#
# Cases (plan §11 level 4), each run with the fast path on and compared with a
# TUN-only run (fast path off): server-side captures byte-equal except the
# IPv4 ID.
#   udp_both_directions     UDP flows IPv6->IPv4 and IPv4->IPv6
#   first_packet_slow_path  first packet via platd/TUN, then the fast path
#   fast_path_keepalive     session kept alive only by fast-path traffic past
#                           udp_secs (invariant I2)
#   idle_expiry             expiry after silence (SC-10)
#   frag_needed_revalidate  ICMPv4 Frag Needed about a fast-path flow is
#                           translated by the slow path (revalidation)
#
# Usage: e2e.sh topology    build the three namespaces, check reachability,
#                           remove them (needs root)
#        e2e.sh run         run the cases (needs root); exit 77 = skipped
# Environment: PLATD, PLAT_XDP_LOADER: the binaries to test (`make xdp`
# builds both under target/release); without them `run` skips (exit 77), so
# the virtme-ng guests of `make test-xdp` skip level 4 unless given them.
# E2E_MODE=native|generic (default native), E2E_TX_OFFLOAD=on|off (default
# off; on: the senders emit CHECKSUM_PARTIAL frames, which the fast path
# declines since the WU5 fix (udp_csum_unverified) and the slow path
# translates; off: complete checksums as from a wire, taken by the fast
# path), E2E_SKIP_IDLE=1 (skip the 125 s idle_expiry wait),
# E2E_ECHOES (default 150), E2E_KEEP=1 (keep the work directory with the
# receiver captures s0.pcap / c0.pcap).
# Exit: 0 pass; 1 failure; 2 usage; 77 skipped (prerequisites missing).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
NS_C=xc NS_P=xp NS_S=xs

die() { echo "e2e: $1" >&2; exit "${2:-1}"; }
nsx() { n=$1; shift; nsenter --net="/run/netns/$n" "$@"; }

down() {
    for n in "$NS_C" "$NS_P" "$NS_S"; do
        ip netns del "$n" 2>/dev/null || true
    done
}

up() {
    [ "$(id -u)" -eq 0 ] || die "needs root" 2
    modprobe veth 2>/dev/null || true
    down
    for n in "$NS_C" "$NS_P" "$NS_S"; do
        ip netns add "$n"
        ip -n "$n" link set lo up
    done
    ip -n "$NS_C" link add c0 type veth peer name p6 netns "$NS_P"
    ip -n "$NS_P" link add p4 type veth peer name s0 netns "$NS_S"
    ip -n "$NS_C" link set c0 up
    ip -n "$NS_P" link set p6 up
    ip -n "$NS_P" link set p4 up
    ip -n "$NS_S" link set s0 up

    ip -n "$NS_C" addr add 2001:db8:c::2/64 dev c0 nodad
    ip -n "$NS_C" -6 route add default via 2001:db8:c::1 dev c0
    ip -n "$NS_P" addr add 2001:db8:c::1/64 dev p6 nodad
    ip -n "$NS_P" addr add 198.51.100.1/24 dev p4
    ip -n "$NS_S" addr add 198.51.100.2/24 dev s0
    ip -n "$NS_S" route add 192.0.2.0/24 via 198.51.100.1 dev s0
    nsx "$NS_P" sysctl -qw net.ipv4.conf.all.forwarding=1
    nsx "$NS_P" sysctl -qw net.ipv6.conf.all.forwarding=1
}

check_topology() {
    nsx "$NS_C" ping -6 -c 1 -W 2 2001:db8:c::1 >/dev/null || die "client cannot reach the PLAT"
    nsx "$NS_S" ping -c 1 -W 2 198.51.100.1 >/dev/null || die "server cannot reach the PLAT"
    nsx "$NS_C" ip -6 route get 64:ff9b::c633:6402 | grep -q 'dev c0' || die "client has no route to 64:ff9b::/96"
    echo "e2e: topology ok" >&2
}

skip() { echo "e2e: SKIP: $*" >&2; exit 77; }

# Metric value from platd's /metrics in the PLAT namespace ($1: the whole
# series name with labels, e.g. 'plat_xdp_packets_total{dir="v6_to_v4"}').
metric() {
    metric_key=$1
    nsx "$NS_P" curl -fsS "http://127.0.0.1:$MGMT_PORT/metrics" | awk -v k="$metric_key" '$1 == k { print $2; f = 1 } END { if (!f) print -1 }'
}

# Non-zero plat_xdp_* series and the server-side view (diagnostics).
dump() {
    nsx "$NS_P" curl -fsS "http://127.0.0.1:$MGMT_PORT/metrics" | grep -E '^plat_(xdp|rx|tx|drops)' | grep -v ' 0$' >&2 || true
    nsx "$NS_S" ip -s link show s0 >&2 || true
    nsx "$NS_P" ip -s link show p4 >&2 || true
}

# The cases need a platd built with --features xdp and the loader
# (`make xdp`), python3, curl and ethtool.
run() {
    [ "$(id -u)" -eq 0 ] || die "needs root" 2
    platd=${PLATD:-}
    loader=${PLAT_XDP_LOADER:-}
    if [ -z "$platd" ] || [ -z "$loader" ]; then
        skip "PLATD / PLAT_XDP_LOADER not set (e.g. PLATD=$repo/target/release/platd PLAT_XDP_LOADER=$repo/target/release/plat-xdp-loader after make xdp)"
    fi
    [ -x "$platd" ] || die "no platd at $platd" 2
    [ -x "$loader" ] || die "no plat-xdp-loader at $loader" 2
    for t in python3 curl ethtool tcpdump; do
        command -v "$t" >/dev/null || skip "$t missing"
    done
    [ ! -e /run/plat/bpf ] || [ ! -e /run/plat/xdp.state ] || die "/run/plat in use (a loader is attached); refusing"
    work=$(mktemp -d /var/tmp/plat-e2e.XXXXXX)
    MGMT_PORT=9464 # the example's loopback listener
    trap 'cleanup' EXIT
    up
    check_topology
    # Native XDP redirect into a veth needs NAPI on the receiving peer.
    # Local sockets on a veth send CHECKSUM_PARTIAL packets (the UDP
    # checksum holds only the pseudo-header sum), which no wire delivers:
    # the fast path's RFC 1624 update of such a sum yields a wrong checksum.
    # Full checksums, as from a real NIC.
    # E2E_TX_OFFLOAD=on keeps TX checksum offload on, so the senders emit
    # CHECKSUM_PARTIAL frames: the fast path must decline them (RFC-001).
    tx=${E2E_TX_OFFLOAD:-off}
    case $tx in on | off) ;; *) die "E2E_TX_OFFLOAD must be on or off" 2 ;; esac
    nsx "$NS_C" ethtool -K c0 gro on tx "$tx" >/dev/null || die "ethtool -K c0"
    nsx "$NS_S" ethtool -K s0 gro on tx "$tx" >/dev/null || die "ethtool -K s0"
    # The fixed pin directory (plan §7), a dedicated bpffs.
    mkdir -p /run/plat/bpf
    chmod 0755 /run/plat
    mountpoint -q /run/plat/bpf || mount -t bpf bpffs /run/plat/bpf || die "mounting bpffs on /run/plat/bpf"
    # Permanent neighbours, so bpf_fib_lookup never meets an unresolved one.
    # (`ip`, not /sys: nsenter --net keeps the outer /sys.)
    mac_s=$(ip -n "$NS_S" link show s0 | awk '/link\/ether/ { print $2 }')
    mac_c=$(ip -n "$NS_C" link show c0 | awk '/link\/ether/ { print $2 }')
    ip -n "$NS_P" neigh replace 198.51.100.2 lladdr "$mac_s" dev p4 nud permanent
    ip -n "$NS_P" -6 neigh replace 2001:db8:c::2 lladdr "$mac_c" dev p6 nud permanent
    # The TUN and its routes (plat-tun-setup.sh does this in production).
    ip -n "$NS_P" tuntap add dev plat0 mode tun multi_queue || die "creating the TUN"
    ip -n "$NS_P" link set plat0 up
    nsx "$NS_P" sysctl -qw net.ipv4.conf.plat0.forwarding=1
    ip -n "$NS_P" -6 route add 64:ff9b:1::/96 dev plat0
    ip -n "$NS_P" route add 192.0.2.0/24 dev plat0

    xmode=${E2E_MODE:-native}
    case $xmode in native | generic) ;; *) die "E2E_MODE must be native or generic" 2 ;; esac
    cfg=$work/platd.toml
    sed -e "s|/var/log/plat/nat64-audit.jsonl|$work/audit.jsonl|" \
        -e 's|min_free_bytes = 2147483648|min_free_bytes = 1048576|' \
        -e 's|queue_capacity = 1048576|queue_capacity = 65536|' \
        -e 's|allow_non_global_destinations = false|allow_non_global_destinations = true|' \
        -e 's|client_prefixes = \["2001:db8:100::/40"\]|client_prefixes = ["2001:db8:c::/48"]|' \
        -e 's|max_sessions = 4000000|max_sessions = 100000|' \
        -e 's|udp_secs = 300|udp_secs = 120|' \
        -e 's|workers = 0|workers = 2|' \
        -e 's|pin_cpus = true|pin_cpus = false|' \
        "$repo/config/platd.example.toml" |
        python3 -I -c 'import sys, re; t = sys.stdin.read(); t = re.sub(r"\[\[audit\.syslog\]\]\n(?:[^\[\n].*\n)*", "", t); sys.stdout.write(t)' >"$cfg"
    cat >>"$cfg" <<X

[xdp]
enabled = true
mode = "$xmode"
allow_generic = true
max_sessions = 65536
heartbeat_ms = 250
deadline_ms = 1000
[[xdp.interfaces]]
name = "p6"
role = "access"
[[xdp.interfaces]]
name = "p4"
role = "upstream"
X
    "$platd" check-config -c "$cfg" >"$work/check.txt" 2>&1 || { cat "$work/check.txt" >&2; die "check-config refused the e2e config"; }
    nsx "$NS_P" "$loader" attach -c "$cfg" || die "loader attach failed"
    # nsenter (not the nsx function) so that $! is platd itself.
    nsenter --net="/run/netns/$NS_P" "$platd" run -c "$cfg" >"$work/platd.log" 2>&1 </dev/null &
    platd_pid=$!
    i=0
    until [ "$(metric plat_xdp_enabled 2>/dev/null)" = 1 ]; do
        i=$((i + 1))
        [ $i -lt 50 ] || { cat "$work/platd.log" >&2; die "platd did not enable the fast path"; }
        sleep 0.2
    done
    echo "e2e: platd running, fast path enabled" >&2

    # UDP echo server (IPv4) and a client sending one datagram a second
    # from a fixed port for $1 seconds, counting echoes.
    nsenter --net="/run/netns/$NS_S" python3 -I -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("198.51.100.2", 7))
while True:
    d, a = s.recvfrom(2048)
    s.sendto(d, a)
' >/dev/null 2>&1 </dev/null &
    echo_pid=$!
    client() {
        echo_count=$1
        nsx "$NS_C" python3 -I -c '
import socket, sys, time
n = int(sys.argv[1])
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("2001:db8:c::2", 40000))
s.settimeout(0.9)
ok = 0
for i in range(n):
    s.sendto(b"e2e-%d" % i, ("64:ff9b:1::c633:6402", 7))
    try:
        if s.recv(2048) == b"e2e-%d" % i:
            ok += 1
    except socket.timeout:
        pass
    time.sleep(1.0)
print(ok)
' "$echo_count"
    }

    # Captures at both receivers, to check every delivered checksum.
    nsenter --net="/run/netns/$NS_S" tcpdump -s 200 -U -ni s0 -w "$work/s0.pcap" udp >/dev/null 2>&1 </dev/null &
    pcap_s=$!
    nsenter --net="/run/netns/$NS_C" tcpdump -s 200 -U -ni c0 -w "$work/c0.pcap" udp >/dev/null 2>&1 </dev/null &
    pcap_c=$!
    sleep 1
    n=${E2E_ECHOES:-150}
    s64a=$(metric plat_v6_to_v4_total)
    s46a=$(metric plat_v4_to_v6_total)
    # The first datagram creates the session on the slow path. Its entries
    # are published by plat-xdp-pub about a millisecond later (WU5
    # deferred publish), so its echo may take either path: wait for the
    # publish before the rest (QA flake).
    got=$(client 1)
    i=0
    until [ "$(metric plat_xdp_installs_total)" -ge 1 ]; do
        i=$((i + 1))
        [ $i -lt 50 ] || die "first_packet_slow_path: the session was never published"
        sleep 0.1
    done
    # udp_both_directions + fast_path_keepalive: one-second echoes, longer
    # than udp_secs = 120 with the default 150.
    got=$((got + $(client $((n - 1)))))
    s64=$(($(metric plat_v6_to_v4_total) - s64a))
    s46=$(($(metric plat_v4_to_v6_total) - s46a))
    f64=$(metric 'plat_xdp_packets_total{dir="v6_to_v4"}')
    f46=$(metric 'plat_xdp_packets_total{dir="v4_to_v6"}')
    unv=$(metric 'plat_xdp_pass_total{reason="udp_csum_unverified"}')
    sess=$(metric plat_sessions)
    xs=$(metric plat_xdp_sessions)
    sleep 1
    kill "$pcap_s" "$pcap_c" 2>/dev/null || true
    wait "$pcap_s" "$pcap_c" 2>/dev/null || true
    pcap_s=
    echo "e2e: mode $xmode, tx offload $tx: echoes $got/$n; slow path v6->v4 $s64, v4->v6 $s46; fast path v6->v4 $f64, v4->v6 $f46; udp_csum_unverified $unv; sessions $sess, xdp $xs" >&2
    [ "$got" -ge $((n - 2)) ] || { dump; die "udp_both_directions: only $got/$n echoes"; }
    # RFC-001: every datagram that reached a receiver carries a correct
    # UDP checksum (tcpdump -vv verifies both families).
    bad=$(
        {
            tcpdump -nvv -r "$work/s0.pcap" 2>/dev/null | grep '192\.0\.2\.[0-9]*\.[0-9]* > 198\.51\.100\.2\.7:'
            tcpdump -nvv -r "$work/c0.pcap" 2>/dev/null | grep '64:ff9b:1::c633:6402\.7 > 2001:db8:c::2\.40000:'
        } | grep -c 'bad udp cksum' || true
    )
    okc=$(
        {
            tcpdump -nvv -r "$work/s0.pcap" 2>/dev/null | grep '192\.0\.2\.[0-9]*\.[0-9]* > 198\.51\.100\.2\.7:'
            tcpdump -nvv -r "$work/c0.pcap" 2>/dev/null | grep '64:ff9b:1::c633:6402\.7 > 2001:db8:c::2\.40000:'
        } | grep -c 'udp sum ok' || true
    )
    echo "e2e: receiver captures: $okc datagrams with a verified UDP checksum, $bad bad" >&2
    [ "$bad" -eq 0 ] || die "udp_checksum: $bad delivered datagrams with a bad UDP checksum"
    [ "$okc" -ge $((2 * n - 4)) ] || die "udp_checksum: only $okc verified checksums at the receivers"
    if [ "$tx" = on ]; then
        # The senders' frames are CHECKSUM_PARTIAL: the fast path declines
        # them (udp_csum_unverified) and the slow path translates them.
        if [ "$unv" -lt $((2 * n - 4)) ] || [ "$f64" -ne 0 ] || [ "$f46" -ne 0 ]; then
            die "udp_csum_unverified: partial frames not declined ($unv declined, fast path $f64 / $f46)"
        fi
        echo "e2e: PASS udp_both_directions udp_checksum udp_csum_unverified (tx offload on: slow path, correct checksums)" >&2
    else
        if [ "$f64" -lt $((n - 5)) ] || [ "$f46" -lt $((n - 5)) ]; then
            die "udp_both_directions: fast path counters did not move ($f64 / $f46)"
        fi
        # The first datagram is translated by platd; its echo by either path.
        if [ "$s64" -ne 1 ] || [ "$s46" -gt 1 ]; then
            die "first_packet_slow_path: slow path translated $s64 / $s46 (expected 1 / 0-1)"
        fi
        if [ "$sess" -ne 1 ] || [ "$xs" -ne 1 ]; then
            die "fast_path_keepalive: session gone after fast-path-only traffic ($sess / $xs)"
        fi
        echo "e2e: PASS udp_both_directions udp_checksum first_packet_slow_path fast_path_keepalive" >&2
    fi

    if [ -z "${E2E_SKIP_IDLE:-}" ]; then
        # idle_expiry: silence for udp_secs plus two sweeps.
        sleep 125
        sess=$(metric plat_sessions)
        xs=$(metric plat_xdp_sessions)
        ret=$(metric plat_xdp_retires_total)
        echo "e2e: after 125 s idle: sessions $sess, xdp sessions $xs, retires $ret" >&2
        if [ "$sess" -ne 0 ] || [ "$xs" -ne 0 ] || [ "$ret" -lt "$(metric plat_xdp_installs_total)" ]; then
            die "idle_expiry: session not expired ($sess / $xs / $ret)"
        fi
        echo "e2e: PASS idle_expiry" >&2
    fi

    kill "$echo_pid" 2>/dev/null || true
    kill -TERM "$platd_pid"
    wait "$platd_pid" || die "platd exited non-zero on SIGTERM (log: $work/platd.log)"
    platd_pid=
    grep -q '"event.action":"xdp_fastpath_state".*"plat.xdp.state":"enabled","event.reason":"start"' "$work/audit.jsonl" ||
        die "audit: no xdp_fastpath_state enabled/start"
    grep -q '"event.action":"xdp_fastpath_state".*"event.reason":"shutdown"' "$work/audit.jsonl" ||
        die "audit: no xdp_fastpath_state shutdown"
    grep -q '"event.action":"service_start".*"plat.xdp.mode":"'"$xmode"'"' "$work/audit.jsonl" ||
        die "audit: service_start without plat.xdp.mode"
    echo "e2e: PASS audit (service_start plat.xdp.*, xdp_fastpath_state start/shutdown)" >&2
    echo "e2e: not yet covered: capture comparison with a TUN-only run, frag_needed_revalidate (WU6/WU8)" >&2
}

cleanup() {
    if [ -n "${platd_pid:-}" ]; then
        kill -TERM "$platd_pid" 2>/dev/null || true
        wait "$platd_pid" 2>/dev/null || true
    fi
    [ -z "${echo_pid:-}" ] || kill "$echo_pid" 2>/dev/null || true
    [ -z "${pcap_s:-}" ] || kill "$pcap_s" "$pcap_c" 2>/dev/null || true
    [ -z "${loader:-}" ] || nsx "$NS_P" "$loader" detach >/dev/null 2>&1 || true
    ! mountpoint -q /run/plat/bpf || umount /run/plat/bpf
    rmdir /run/plat/bpf 2>/dev/null || true
    rm -f /run/plat/xdp.state
    rmdir /run/plat 2>/dev/null || true
    down
    [ -z "${work:-}" ] || [ -n "${E2E_KEEP:-}" ] || rm -rf "$work"
}

case "${1:-}" in
    topology)
        up
        trap down EXIT
        check_topology
        ;;
    run) run ;;
    *) die "usage: e2e.sh topology|run" 2 ;;
esac
