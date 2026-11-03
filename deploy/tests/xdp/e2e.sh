#!/bin/sh
# Level 4 end-to-end test for the XDP fast path (plan §11 level 4). WU5 adds
# the platd [xdp] cases udp_both_directions, first_packet_slow_path,
# fast_path_keepalive and idle_expiry (the loader and platd started by hand);
# WU6 runs the same cases through the installed systemd units
# (E2E_UNITS=1) and adds the unit cases below. The VM verification run
# (2026-11-03) adds frag_needed_revalidate, deadman_stop, deadman_kill9,
# capture_compare and the separate map_full run (E2E_MAPFULL=1).
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
#   frag_needed_revalidate  ICMPv4 Frag Needed about a fast-path-only flow
#                           (older than udp_secs) is translated by the slow
#                           path into an ICMPv6 Packet Too Big (seen
#                           read-back, plan §5), not refused as filtered
#   deadman_stop            L29: `kill -STOP platd`: the fast path stops
#                           forwarding within deadline_ms (the packets then
#                           pass to the stopped TUN reader); after
#                           `kill -CONT` it forwards again
#   deadman_kill9           L29: `kill -9 platd` (by hand, program left
#                           attached): the fast path stops within
#                           deadline_ms; then detach, attach, start again
#                           (no stale_maps). With E2E_UNITS=1 the
#                           measurement is part of auto_restart_reattach.
#   capture_compare         the same datagrams (payloads 1..1300 B, DF and
#                           not) through the fast path and through a
#                           TUN-only platd (no [xdp]): receiver frames
#                           byte-equal except IPv4 ID and header checksum
#                           when DF = 0 (not with E2E_UNITS=1)
# With E2E_MAPFULL=1 (L32) only:
#   map_full                xdp.max_sessions = 4096, 5000 flows: every flow
#                           echoed with correct checksums, at most 4096 on
#                           the fast path, install failures counted; after
#                           expiry new flows get fast-path entries again
# With E2E_UNITS=1 (plan §7, LINUX_VERIFICATION L25/L27):
#   loader_privileges       plat-xdp.service runs as uid 0, gid plat, with
#                           exactly CAP_BPF + CAP_NET_ADMIN, no_new_privs,
#                           a seccomp filter
#   pins_root_plat          mount root 2750 root:plat, pins root:plat (maps
#                           0660 / 0640, program and links 0600), /run/plat
#                           0755 root, state file 0644 root
#   restart_reattach        `systemctl restart platd` re-runs the loader
#                           (fresh maps, no stale_maps)
#   auto_restart_reattach   the same after SIGKILL (Restart=on-failure)
#   fwguard_swapped         plat-fwguard.service detects and detaches another
#                           program on an interface, forwarding off
#   stop_detaches           `systemctl stop platd` stops the loader unit: no
#                           pins, no state file, no program attached
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
# receiver captures s0.pcap / c0.pcap), E2E_MAPFULL=1 (run only map_full,
# about 3 minutes).
# E2E_UNITS=1: use the installed units (platd.service with the
# platd.service.d/xdp.conf drop-in, plat-xdp.service, run-plat-bpf.mount,
# plat-fwguard.service) and binaries (/usr/bin/platd,
# /usr/libexec/plat/plat-xdp-loader) instead of PLATD / PLAT_XDP_LOADER;
# test-only runtime drop-ins in /run/systemd/system put them in the PLAT
# namespace with the test config (removed at exit). platd.service must not
# be active.
# Exit: 0 pass; 1 failure; 2 usage; 77 skipped (prerequisites missing).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
NS_C=xc NS_P=xp NS_S=xs

die() { echo "e2e: $1" >&2; exit "${2:-1}"; }
nsx() { nsx_ns=$1; shift; nsenter --net="/run/netns/$nsx_ns" "$@"; }

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
    [ "${units:-0}" != 1 ] || journal
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
    units=${E2E_UNITS:-0}
    if [ "$units" = 1 ]; then
        # The installed units and binaries (deploy/systemd, README).
        command -v systemctl >/dev/null || skip "systemctl missing"
        for u in platd.service plat-xdp.service run-plat-bpf.mount plat-fwguard.service; do
            systemctl cat "$u" >/dev/null 2>&1 || skip "$u not installed"
        done
        systemctl show -p Requires --value platd.service | grep -qw plat-xdp.service ||
            skip "platd.service.d/xdp.conf not installed"
        ! systemctl is-active -q platd.service || die "platd.service is active; refusing" 2
        ! mountpoint -q /run/plat/bpf || die "/run/plat/bpf is mounted; refusing" 2
        platd=/usr/bin/platd
        loader=/usr/libexec/plat/plat-xdp-loader
    elif [ -z "$platd" ] || [ -z "$loader" ]; then
        skip "PLATD / PLAT_XDP_LOADER not set (e.g. PLATD=$repo/target/release/platd PLAT_XDP_LOADER=$repo/target/release/plat-xdp-loader after make xdp)"
    fi
    [ -x "$platd" ] || die "no platd at $platd" 2
    [ -x "$loader" ] || die "no plat-xdp-loader at $loader" 2
    for t in python3 curl ethtool tcpdump; do
        command -v "$t" >/dev/null || skip "$t missing"
    done
    [ ! -e /run/plat/bpf ] || [ ! -e /run/plat/xdp.state ] || die "/run/plat in use (a loader is attached); refusing"
    work=$(mktemp -d /var/tmp/plat-e2e.XXXXXX)
    t0=$(date +%s)
    audit=$work/audit.jsonl
    cfg=$work/platd.toml
    if [ "$units" = 1 ]; then
        # platd runs as plat in its sandbox: the config where it can read
        # it, the audit file in the unit's ReadWritePaths.
        audit=/var/log/plat/e2e-audit.jsonl
        install -d -m 0750 -o root -g plat /run/plat-e2e
        cfg=/run/plat-e2e/platd.toml
    fi
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
    # The fixed pin directory (plan §7), a dedicated bpffs (with the units:
    # run-plat-bpf.mount and plat-xdp.tmpfiles.conf).
    if [ "$units" != 1 ]; then
        mkdir -p /run/plat/bpf
        chmod 0755 /run/plat
        mountpoint -q /run/plat/bpf || mount -t bpf bpffs /run/plat/bpf || die "mounting bpffs on /run/plat/bpf"
    fi
    # Permanent neighbours, so bpf_fib_lookup never meets an unresolved one.
    # (`ip`, not /sys: nsenter --net keeps the outer /sys.)
    mac_s=$(ip -n "$NS_S" link show s0 | awk '/link\/ether/ { print $2 }')
    mac_c=$(ip -n "$NS_C" link show c0 | awk '/link\/ether/ { print $2 }')
    ip -n "$NS_P" neigh replace 198.51.100.2 lladdr "$mac_s" dev p4 nud permanent
    ip -n "$NS_P" -6 neigh replace 2001:db8:c::2 lladdr "$mac_c" dev p6 nud permanent
    # The TUN and its routes (plat-tun-setup.sh does this in production; the
    # units run skips it, as it writes the host's nftables files; there the
    # TUN is owned by plat, so platd needs no capability).
    if [ "$units" = 1 ]; then
        ip -n "$NS_P" tuntap add dev plat0 mode tun multi_queue user plat group plat || die "creating the TUN"
    else
        ip -n "$NS_P" tuntap add dev plat0 mode tun multi_queue || die "creating the TUN"
    fi
    ip -n "$NS_P" link set plat0 up
    nsx "$NS_P" sysctl -qw net.ipv4.conf.plat0.forwarding=1
    ip -n "$NS_P" -6 route add 64:ff9b:1::/96 dev plat0
    ip -n "$NS_P" route add 192.0.2.0/24 dev plat0

    xmode=${E2E_MODE:-native}
    case $xmode in native | generic) ;; *) die "E2E_MODE must be native or generic" 2 ;; esac
    sed -e "s|/var/log/plat/nat64-audit.jsonl|$audit|" \
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
    mapfull=${E2E_MAPFULL:-0}
    xmax=65536
    if [ "$mapfull" = 1 ]; then
        # map_full: 5000 flows from one subscriber (10 port blocks of 512)
        # against a 4096-entry fast path (the [xdp] minimum).
        sed -i -e 's|^max_blocks_per_subscriber = 4$|max_blocks_per_subscriber = 16|' \
            -e 's|^max_sessions_per_subscriber = 4000$|max_sessions_per_subscriber = 8000|' "$cfg"
        xmax=4096
    fi
    # capture_compare: the same config without [xdp] (TUN only).
    cp "$cfg" "$work/platd-tun.toml"
    cat >>"$cfg" <<X

[xdp]
enabled = true
mode = "$xmode"
allow_generic = true
max_sessions = $xmax
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
    if [ "$units" = 1 ]; then
        chown root:plat "$cfg"
        chmod 0640 "$cfg"
        units_dropins
        systemctl start platd.service || { journal; die "systemctl start platd.service failed"; }
    else
        nsx "$NS_P" "$loader" attach -c "$cfg" || die "loader attach failed"
        # nsenter (not the nsx function) so that $! is platd itself.
        nsenter --net="/run/netns/$NS_P" "$platd" run -c "$cfg" >"$work/platd.log" 2>&1 </dev/null &
        platd_pid=$!
    fi
    wait_enabled
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
    pcap_tool >"$work/pcap.py"

    if [ "$mapfull" = 1 ]; then
        map_full
        kill "$echo_pid" 2>/dev/null || true
        [ "$units" != 1 ] || die "E2E_MAPFULL=1 runs without E2E_UNITS" 2
        kill -TERM "$platd_pid"
        wait "$platd_pid" || die "platd exited non-zero on SIGTERM (log: $work/platd.log)"
        platd_pid=
        echo "e2e: PASS map_full" >&2
        return 0
    fi

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
        [ $i -lt 50 ] || { dump; die "first_packet_slow_path: the session was never published"; }
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
        frag_needed_revalidate
        deadman_stop
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

    cmp=0
    if [ "$units" != 1 ] && [ "$tx" = off ]; then
        cmp=1
        cmp_traffic xdp
    fi
    if [ "$units" = 1 ]; then
        units_cases
    else
        [ "$tx" = on ] || deadman_kill9
        kill -TERM "$platd_pid"
        wait "$platd_pid" || die "platd exited non-zero on SIGTERM (log: $work/platd.log)"
        platd_pid=
        [ "$cmp" = 0 ] || capture_compare
    fi
    kill "$echo_pid" 2>/dev/null || true
    audit_all | grep -q '"event.action":"xdp_fastpath_state".*"plat.xdp.state":"enabled","event.reason":"start"' ||
        die "audit: no xdp_fastpath_state enabled/start"
    audit_all | grep -q '"event.action":"xdp_fastpath_state".*"event.reason":"shutdown"' ||
        die "audit: no xdp_fastpath_state shutdown"
    audit_all | grep -q '"event.action":"service_start".*"plat.xdp.mode":"'"$xmode"'"' ||
        die "audit: service_start without plat.xdp.mode"
    ! audit_all | grep -q '"event.reason":"stale_maps"' || die "audit: a platd start was refused stale_maps"
    echo "e2e: PASS audit (service_start plat.xdp.*, xdp_fastpath_state start/shutdown, no stale_maps)" >&2
    echo "e2e: xdp_fastpath_state records: $(xdp_states)" >&2
}

# Every audit file of the run (platd rotates the file it finds at start).
audit_all() { cat "$audit" "$audit".* 2>/dev/null || true; }
# The xdp_fastpath_state records so far, as state:reason.
xdp_states() {
    audit_all | sed -n 's/.*"event.action":"xdp_fastpath_state".*"plat.xdp.state":"\([a-z]*\)","event.reason":"\([a-z_]*\)".*/\1:\2/p' | tr '\n' ' '
}

# --- VM verification cases (2026-11-03) --------------------------------------

# A small pcap reader (classic pcap, Ethernet, as tcpdump -w writes it).
#   pcap.py times FILE SRC4 SPORT          arrival times (s) of IPv4 UDP
#                                          datagrams from SRC4:SPORT to port 7
#   pcap.py map FILE CPORT                 "addr port" the PLAT used for the
#                                          client port CPORT (first datagram)
#   pcap.py cmp A B                        frames equal except, for IPv4 with
#                                          DF = 0, the ID and header checksum
#                                          (B's pool address and port are
#                                          replaced by A's, its checksums
#                                          recomputed)
#   pcap.py icmp6 FILE TYPE                ICMPv6 messages of TYPE: "mtu src"
pcap_tool() {
    cat <<'PY'
import struct, sys

def frames(path):
    with open(path, "rb") as f:
        d = f.read()
    if len(d) < 24:
        return
    magic = struct.unpack_from("<I", d, 0)[0]
    e = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
    o = 24
    while o + 16 <= len(d):
        sec, frac, incl, _ = struct.unpack_from(e + "IIII", d, o)
        o += 16
        yield sec + frac / (1e9 if nano else 1e6), d[o:o + incl]
        o += incl

def udp4(fr):
    if len(fr) < 42 or fr[12:14] != b"\x08\x00" or fr[23] != 17:
        return None
    ihl = (fr[14] & 15) * 4
    u = 14 + ihl
    return fr[26:30], struct.unpack_from(">HH", fr, u)

cmd = sys.argv[1]
if cmd == "times":
    src = bytes(int(x) for x in sys.argv[3].split("."))
    sport = int(sys.argv[4])
    for t, fr in frames(sys.argv[2]):
        u = udp4(fr)
        if u and u[0] == src and u[1] == (sport, 7):
            print("%.6f" % t)
elif cmd == "map":
    want = int(sys.argv[3])
    for t, fr in frames(sys.argv[2]):
        u = udp4(fr)
        if u and u[1][1] == 7:
            print(".".join(str(b) for b in u[0]), u[1][0])
            break
elif cmd == "cmp":
    a = [fr for _, fr in frames(sys.argv[2])]
    b = [fr for _, fr in frames(sys.argv[3])]
    def csum(d):
        if len(d) % 2:
            d += b"\0"
        t = sum(struct.unpack("!%dH" % (len(d) // 2), d))
        while t >> 16:
            t = (t & 0xFFFF) + (t >> 16)
        return ~t & 0xFFFF
    # The pool address and port are chosen afresh by each platd: put a's
    # mapping into b's IPv4 datagrams to port 7, with both checksums
    # recomputed for b (a keeps the bytes as delivered).
    m = next((x[26:30] + x[34:36] for x in a if udp4(x) and udp4(x)[1][1] == 7), None)
    def remap(fr):
        fr = bytearray(fr)
        if m and udp4(bytes(fr)) and udp4(bytes(fr))[1][1] == 7:
            ihl = (fr[14] & 15) * 4
            u = 14 + ihl
            fr[26:30] = m[:4]
            fr[u:u + 2] = m[4:]
            fr[24:26] = b"\0\0"
            fr[24:26] = struct.pack("!H", csum(bytes(fr[14:u])))
            ul = struct.unpack_from("!H", fr, u + 4)[0]
            fr[u + 6:u + 8] = b"\0\0"
            ph = bytes(fr[26:34]) + struct.pack("!BBH", 0, 17, ul)
            c = csum(ph + bytes(fr[u:u + ul])) or 0xFFFF
            fr[u + 6:u + 8] = struct.pack("!H", c)
        return bytes(fr)
    b = [remap(x) for x in b]
    def norm(fr):
        fr = bytearray(fr)
        if len(fr) >= 34 and fr[12:14] == b"\x08\x00" and not fr[20] & 0x40:
            fr[18:20] = b"\0\0"
            fr[24:26] = b"\0\0"
        return bytes(fr)
    same = sum(1 for x, y in zip(a, b) if norm(x) == norm(y))
    df = sum(1 for x in a if len(x) >= 34 and x[12:14] == b"\x08\x00" and x[20] & 0x40)
    print(len(a), len(b), same, df)
    for i, (x, y) in enumerate(zip(a, b)):
        if norm(x) != norm(y):
            j = next((k for k in range(min(len(x), len(y))) if x[k] != y[k]), min(len(x), len(y)))
            print("frame %d differs at byte %d (len %d / %d)" % (i, j, len(x), len(y)), file=sys.stderr)
            print("  a: " + x[max(0, j - 8):j + 16].hex(), file=sys.stderr)
            print("  b: " + y[max(0, j - 8):j + 16].hex(), file=sys.stderr)
            break
    if m:
        print("pool mapping of the fast-path run: %s:%d" % (".".join(str(x) for x in m[:4]), struct.unpack("!H", m[4:])[0]), file=sys.stderr)
elif cmd == "icmp6":
    ty = int(sys.argv[3])
    for t, fr in frames(sys.argv[2]):
        if len(fr) >= 62 and fr[12:14] == b"\x86\xdd" and fr[20] == 58 and fr[54] == ty:
            src = ":".join(fr[22:38][i:i + 2].hex() for i in range(0, 16, 2))
            print(struct.unpack_from(">I", fr, 58)[0], src)
PY
}

# The PLAT's IPv4 address and port for client port $1, from s0 capture $2.
mapping() { python3 -I "$work/pcap.py" map "$2" "$1"; }

# Creates (or refreshes) the session on client port 40000 and sets lm_a /
# lm_p to its mapping, waiting for the fast-path publish.
live_mapping() {
    lm_i0=$(metric plat_xdp_installs_total)
    nsenter --net="/run/netns/$NS_S" tcpdump -s 96 -U -ni s0 -w "$work/map.pcap" udp dst port 7 >/dev/null 2>&1 </dev/null &
    pcap_s=$! pcap_c=
    sleep 1
    client 1 >/dev/null
    i=0
    until [ "$(metric plat_xdp_installs_total)" -gt "$lm_i0" ] || [ $i -ge 30 ]; do
        i=$((i + 1))
        sleep 0.1
    done
    client 1 >/dev/null
    dm_stop_capture
    read -r lm_a lm_p <<X
$(mapping 40000 "$work/map.pcap")
X
    [ -n "$lm_p" ] || die "no mapping for client port 40000"
}

# frag_needed_revalidate: the session on port 40000 was created by the first
# datagram on the slow path and then kept alive by the fast path only for
# longer than udp_secs (fast_path_keepalive). An ICMPv4 Frag Needed from the
# server about it is validated by platd against that session (filtering:
# the seen read-back of plan §5 counts the fast-path use) and translated to
# an ICMPv6 Packet Too Big at the client.
#
# COMPLIANCE MAPPING:
# - RFC 7915 §4.2 - ICMPv4 Frag Needed -> ICMPv6 Packet Too Big
# - RFC 6146 §3.5.1 - the session is refreshed by fast-path packets
frag_needed_revalidate() {
    read -r fn_a fn_p <<X
$(mapping 40000 "$work/s0.pcap")
X
    [ -n "$fn_p" ] || die "frag_needed_revalidate: no mapping for port 40000 in the capture"
    nsenter --net="/run/netns/$NS_C" tcpdump -s 0 -U -ni c0 -w "$work/ptb.pcap" icmp6 >/dev/null 2>&1 </dev/null &
    pcap_s=$!
    # Diagnostics: the TUN side in the PLAT namespace.
    nsenter --net="/run/netns/$NS_P" tcpdump -s 0 -U -ni plat0 -w "$work/ptb-tun.pcap" icmp or icmp6 >/dev/null 2>&1 </dev/null &
    pcap_c=$!
    sleep 1
    rv0=$(metric plat_xdp_revalidated_total)
    # ICMPv4 type 3 code 4, next-hop MTU 1400, quoting the translated
    # datagram (IPv4 header with a valid checksum + 8 bytes of UDP).
    nsx "$NS_S" python3 -I -c '
import socket, struct, sys
src, sport = sys.argv[1], int(sys.argv[2])
def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + 1372, 0, 0x4000, 62, 17, 0,
                 socket.inet_aton(src), socket.inet_aton("198.51.100.2"))
ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
quote = ip + struct.pack("!HHHH", sport, 7, 8 + 1372, 0x1234)
icmp = struct.pack("!BBHHH", 3, 4, 0, 0, 1400) + quote
icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.sendto(icmp, (src, 0))
' "$fn_a" "$fn_p" || die "frag_needed_revalidate: sending the Frag Needed failed"
    sleep 1
    kill "$pcap_s" "$pcap_c" 2>/dev/null || true
    wait "$pcap_s" "$pcap_c" 2>/dev/null || true
    pcap_s=
    ptb=$(python3 -I "$work/pcap.py" icmp6 "$work/ptb.pcap" 2)
    [ -n "$ptb" ] || tcpdump -nv -r "$work/ptb-tun.pcap" >&2 2>/dev/null || true
    echo "e2e: Frag Needed (MTU 1400) about $fn_a:$fn_p -> 198.51.100.2:7; client got Packet Too Big: ${ptb:-none}; revalidated $rv0 -> $(metric plat_xdp_revalidated_total)" >&2
    [ -n "$ptb" ] || { dump; die "frag_needed_revalidate: no ICMPv6 Packet Too Big at the client"; }
    # RFC 7915 §4.2: MTU + 20 (1420), and the source the server's embed.
    printf '%s\n' "$ptb" | grep -q '^1420 0064:ff9b:0001:0000:0000:0000:c633:6402$' ||
        die "frag_needed_revalidate: unexpected Packet Too Big: $ptb"
    echo "e2e: PASS frag_needed_revalidate (session older than udp_secs, fast-path only)" >&2
}

# Fast-path stop measurement around a signal to platd (L29). Sends 200
# datagrams a second from port 40000 (the established session) while
# capturing at the server; $1 = STOP or KILL. Sets dm_t (signal time),
# dm_last (last arrival from the old mapping before dm_t + 3 s) and
# dm_after (arrivals after dm_t + 3 s).
dm_sender() {
    nsx "$NS_C" python3 -I -c '
import socket, sys, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("2001:db8:c::2", 40000))
s.setblocking(False)
end = time.time() + float(sys.argv[1])
i = 0
while time.time() < end:
    s.sendto(b"dm-%d" % i, ("64:ff9b:1::c633:6402", 7))
    i += 1
    try:
        while s.recv(2048):
            pass
    except BlockingIOError:
        pass
    time.sleep(0.005)
' "$1" >/dev/null 2>&1 </dev/null &
    dm_pid=$!
}

dm_capture() {
    nsenter --net="/run/netns/$NS_S" tcpdump -s 96 -U -ni s0 -w "$1" udp dst port 7 >/dev/null 2>&1 </dev/null &
    pcap_s=$! pcap_c=
    sleep 1
}

dm_stop_capture() {
    kill "$pcap_s" 2>/dev/null || true
    wait "$pcap_s" 2>/dev/null || true
    pcap_s=
}

# Arrival summary of capture $1 for mapping $2 $3 relative to time $4 and
# $5: "<last before $5 - $4 in ms> <arrivals in [$4, $4 + 0.5 s)>
# <arrivals at or after $5>".
dm_summary() {
    python3 -I "$work/pcap.py" times "$1" "$2" "$3" | awk -v t="$4" -v c="$5" '
        $1 >= t && $1 < c { last = $1; if ($1 < t + 0.5) early++ }
        $1 >= c { after++ }
        END { printf "%d %d %d\n", (last ? (last - t) * 1000 : -1), early + 0, after + 0 }'
}

# deadman_stop (L29): SIGSTOP freezes every platd thread, so plat-xdp-ctl
# stops storing heartbeats: the program keeps forwarding until
# CONTROL.deadline_ns (at most deadline_ms after the last heartbeat), then
# passes every packet (reason deadline) to the kernel and the TUN, where
# nobody reads them. SIGCONT: heartbeats resume and so does the fast path.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SC-24 (Fail in Known State) - dead-man deadline
deadman_stop() {
    if [ "$units" = 1 ]; then dm_target=$(systemctl show -p MainPID --value platd.service); else dm_target=$platd_pid; fi
    read -r dm_a dm_p <<X
$(mapping 40000 "$work/s0.pcap")
X
    dl0=$(metric 'plat_xdp_pass_total{reason="deadline"}')
    st0=$(metric plat_xdp_heartbeat_stalls_total)
    dm_capture "$work/dm-stop.pcap"
    dm_sender 12
    sleep 2
    dm_t=$(date +%s.%N)
    kill -STOP "$dm_target"
    sleep 5
    dm_c=$(date +%s.%N)
    kill -CONT "$dm_target"
    sleep 2
    f0=$(metric 'plat_xdp_packets_total{dir="v6_to_v4"}')
    wait "$dm_pid" 2>/dev/null || true
    f1=$(metric 'plat_xdp_packets_total{dir="v6_to_v4"}')
    dm_stop_capture
    dl1=$(metric 'plat_xdp_pass_total{reason="deadline"}')
    st1=$(metric plat_xdp_heartbeat_stalls_total)
    read -r dm_last dm_early dm_after <<X
$(dm_summary "$work/dm-stop.pcap" "$dm_a" "$dm_p" "$dm_t" "$dm_c")
X
    set -- "$dm_last" "$dm_early" "$dm_after"
    echo "e2e: SIGSTOP: last arrival $1 ms after the signal ($2 in the first 500 ms), $3 arrivals after SIGCONT; pass deadline $dl0 -> $dl1; fast path v6->v4 +$((f1 - f0)) in the 3 s after SIGCONT + 2 s; heartbeat stalls $st0 -> $st1" >&2
    sleep 1
    dm_states=$(xdp_states)
    echo "e2e: xdp_fastpath_state since start: $dm_states" >&2
    # The freeze stops plat-xdp-ctl too, so the deadline runs out without a
    # heartbeat_stalled record, and after SIGCONT the first health check
    # passes (no heartbeat_resumed): reported, not failed (verification run
    # finding, LINUX_VERIFICATION L29).
    case $dm_states in
        *heartbeat_stalled*heartbeat_resumed*) ;;
        *) echo "e2e: FINDING deadman_stop: no heartbeat_stalled / heartbeat_resumed record for the deadline expiry" >&2 ;;
    esac
    # deadline_ms = 1000; heartbeat_ms = 250, so the deadline is 750..1000
    # ms after the signal; 60 ms for the coarse clock and capture latency.
    [ "$1" -ge 0 ] && [ "$1" -le 1060 ] || die "deadman_stop: forwarding $1 ms after SIGSTOP (deadline_ms 1000)"
    [ "$2" -gt 0 ] || die "deadman_stop: nothing forwarded right after SIGSTOP (fast path not in use?)"
    [ "$((dl1 - dl0))" -gt 100 ] || die "deadman_stop: pass deadline did not move ($dl0 -> $dl1)"
    [ "$3" -gt 100 ] || die "deadman_stop: $3 arrivals after SIGCONT"
    [ "$((f1 - f0))" -gt 100 ] || die "deadman_stop: fast path did not resume after SIGCONT (+$((f1 - f0)))"
    echo "e2e: PASS deadman_stop" >&2
}

# deadman_kill9 (L29, by hand): platd SIGKILLed, the program stays attached
# with the maps; it forwards until the deadline, then passes. Then the
# restart the units do: detach, attach (fresh maps), platd again.
deadman_kill9() {
    # The session on port 40000 expired in idle_expiry: a new one.
    live_mapping
    dm_a=$lm_a dm_p=$lm_p
    dm_capture "$work/dm-kill.pcap"
    dm_sender 5
    sleep 2
    dm_t=$(date +%s.%N)
    kill -KILL "$platd_pid"
    wait "$platd_pid" 2>/dev/null || true
    platd_pid=
    wait "$dm_pid" 2>/dev/null || true
    dm_stop_capture
    attached=$(xdp_prog_on p6)
    read -r dm_last dm_early dm_after <<X
$(dm_summary "$work/dm-kill.pcap" "$dm_a" "$dm_p" "$dm_t" 9999999999)
X
    set -- "$dm_last" "$dm_early" "$dm_after"
    echo "e2e: SIGKILL: last arrival $1 ms after the signal ($2 in the first 500 ms); program still attached: ${attached:-none}" >&2
    [ -n "$attached" ] || die "deadman_kill9: program detached (the case needs it left attached)"
    [ "$1" -ge 0 ] && [ "$1" -le 1060 ] || die "deadman_kill9: forwarding $1 ms after SIGKILL (deadline_ms 1000)"
    [ "$2" -gt 0 ] || die "deadman_kill9: nothing forwarded right after SIGKILL"
    nsx "$NS_P" "$loader" detach || die "deadman_kill9: detach failed"
    nsx "$NS_P" "$loader" attach -c "$cfg" || die "deadman_kill9: re-attach failed"
    nsenter --net="/run/netns/$NS_P" "$platd" run -c "$cfg" >>"$work/platd.log" 2>&1 </dev/null &
    platd_pid=$!
    wait_enabled
    echo "e2e: PASS deadman_kill9 (re-attached: program $(xdp_prog_on p6))" >&2
}

# capture_compare: datagrams of fixed payloads from client port 40002
# (payload sizes around the RFC 1624 edge, odd lengths, and above the DF
# threshold of 1260 B total), each echoed; captures at both receivers.
# $1 = label.
cmp_traffic() {
    nsenter --net="/run/netns/$NS_S" tcpdump -s 0 -U -ni s0 -w "$work/cmp-$1-s0.pcap" udp dst port 7 >/dev/null 2>&1 </dev/null &
    pcap_s=$!
    nsenter --net="/run/netns/$NS_C" tcpdump -s 0 -U -ni c0 -w "$work/cmp-$1-c0.pcap" udp dst port 40002 >/dev/null 2>&1 </dev/null &
    pcap_c=$!
    sleep 1
    cf0=$(metric 'plat_xdp_packets_total{dir="v6_to_v4"}')
    ok=$(nsx "$NS_C" python3 -I -c '
import socket, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("2001:db8:c::2", 40002))
s.settimeout(0.9)
ok = 0
sizes = [1, 2, 3, 4, 5, 63, 64, 100, 511, 1000, 1231, 1232, 1233, 1300, 1400]
for r in range(3):
    for n in sizes:
        d = bytes((r * 7 + n + i) & 0xFF for i in range(n))
        s.sendto(d, ("64:ff9b:1::c633:6402", 7))
        try:
            if s.recv(2048) == d:
                ok += 1
        except socket.timeout:
            pass
        time.sleep(0.2 if r == 0 and n == 1 else 0.05)
print(ok)
')
    sleep 1
    kill "$pcap_s" "$pcap_c" 2>/dev/null || true
    wait "$pcap_s" "$pcap_c" 2>/dev/null || true
    pcap_s=
    cf1=$(metric 'plat_xdp_packets_total{dir="v6_to_v4"}')
    echo "e2e: capture_compare ($1): $ok/45 echoes, fast path v6->v4 +$((cf1 - cf0))" >&2
    [ "$ok" -eq 45 ] || die "capture_compare: $ok/45 echoes ($1)"
    # The xdp run: all but the first datagram on the fast path; the TUN
    # run: none (no [xdp]: the series is absent or 0).
    if [ "$1" = xdp ]; then
        [ $((cf1 - cf0)) -ge 44 ] || die "capture_compare: only $((cf1 - cf0)) of 45 on the fast path"
    else
        [ "$cf1" -le 0 ] || die "capture_compare: TUN-only run reports fast-path packets ($cf1)"
    fi
}

capture_compare() {
    # TUN only: the loader detached, platd without [xdp]; the same
    # namespaces, neighbours and routes.
    nsx "$NS_P" "$loader" detach >/dev/null 2>&1 || true
    nsenter --net="/run/netns/$NS_P" "$platd" run -c "$work/platd-tun.toml" >"$work/platd-tun.log" 2>&1 </dev/null &
    platd_pid=$!
    i=0
    until nsx "$NS_P" curl -fsS "http://127.0.0.1:$MGMT_PORT/metrics" >/dev/null 2>&1; do
        i=$((i + 1))
        [ $i -lt 100 ] || { cat "$work/platd-tun.log" >&2; die "capture_compare: TUN-only platd did not start"; }
        sleep 0.2
    done
    [ -z "$(xdp_prog_on p6)$(xdp_prog_on p4)" ] || die "capture_compare: a program is attached in the TUN-only run"
    cmp_traffic tun
    kill -TERM "$platd_pid"
    wait "$platd_pid" || die "TUN-only platd exited non-zero on SIGTERM"
    platd_pid=
    for side in s0 c0; do
        read -r c1 c2 c3 c4 <<X
$(python3 -I "$work/pcap.py" cmp "$work/cmp-xdp-$side.pcap" "$work/cmp-tun-$side.pcap")
X
        set -- "$c1" "$c2" "$c3" "$c4"
        echo "e2e: capture_compare $side: fast path $1 frames, TUN only $2, equal $3 (DF set: $4, compared with the ID)" >&2
        [ "$1" -eq 45 ] && [ "$2" -eq 45 ] && [ "$3" -eq 45 ] || die "capture_compare: $side frames differ"
    done
    echo "e2e: PASS capture_compare (receiver frames byte-equal except the IPv4 ID / header checksum when DF = 0; pool port of the TUN run mapped onto the fast-path run's)" >&2
}

# map_full (L32): 5000 flows (one socket each) against xdp.max_sessions =
# 4096. Round 1 creates the sessions (slow path), round 2 a second later
# uses them: every flow echoed (correct payload) and every delivered UDP
# checksum correct, at most 4096 on the fast path, install failures
# counted. After udp_secs + sweeps the sessions are gone, and 100 new
# flows get fast-path entries again.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SC-5 (Denial-of-Service Protection) - bounded fast-path
#   maps, overflow stays on the slow path
mf_flows() {
    nsx "$NS_C" python3 -I -c '
import resource, select, socket, sys, time
resource.setrlimit(resource.RLIMIT_NOFILE, (16384, 16384))
n, rounds = int(sys.argv[1]), int(sys.argv[2])
socks = []
for i in range(n):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind(("2001:db8:c::2", 0))
    s.setblocking(False)
    socks.append(s)
res = []
for r in range(rounds):
    pend = {}
    for i, s in enumerate(socks):
        d = b"mf-%d-%d" % (r, i)
        s.sendto(d, ("64:ff9b:1::c633:6402", 7))
        pend[s.fileno()] = (s, d)
        if i % 200 == 199:
            time.sleep(0.02)
    ok = 0
    end = time.time() + 5
    p = select.epoll()
    for fd in pend:
        p.register(fd, select.EPOLLIN)
    while pend and time.time() < end:
        for fd, _ in p.poll(0.5):
            s, d = pend[fd]
            if s.recv(2048) == d:
                ok += 1
            del pend[fd]
            p.unregister(fd)
    res.append(ok)
    time.sleep(2)
print(" ".join(map(str, res)))
' "$1" "$2"
}

mf_counters() {
    echo "sessions $(metric plat_sessions), xdp sessions $(metric plat_xdp_sessions), installs $(metric plat_xdp_installs_total), install failures map_full $(metric 'plat_xdp_install_failures_total{reason="map_full"}') slots $(metric 'plat_xdp_install_failures_total{reason="slots"}') error $(metric 'plat_xdp_install_failures_total{reason="error"}'), fast path v6->v4 $(metric 'plat_xdp_packets_total{dir="v6_to_v4"}') v4->v6 $(metric 'plat_xdp_packets_total{dir="v4_to_v6"}'), slow path v6->v4 $(metric plat_v6_to_v4_total) v4->v6 $(metric plat_v4_to_v6_total), pass no_session $(metric 'plat_xdp_pass_total{reason="no_session"}')"
}

map_full() {
    nsenter --net="/run/netns/$NS_S" tcpdump -s 200 -U -ni s0 -w "$work/mf-s0.pcap" udp dst port 7 >/dev/null 2>&1 </dev/null &
    pcap_s=$!
    nsenter --net="/run/netns/$NS_C" tcpdump -s 200 -U -ni c0 -w "$work/mf-c0.pcap" udp src port 7 >/dev/null 2>&1 </dev/null &
    pcap_c=$!
    sleep 1
    read -r r1 r2 r3 <<X
$(mf_flows 5000 3)
X
    set -- "$r1" "$r2" "$r3"
    echo "e2e: map_full: 5000 flows, echoes per round: $*" >&2
    echo "e2e: map_full after the burst: $(mf_counters)" >&2
    for r in "$@"; do [ "$r" -eq 5000 ] || { dump; die "map_full: only $r/5000 echoes in a round"; }; done
    xs=$(metric plat_xdp_sessions)
    fl=$(($(metric 'plat_xdp_install_failures_total{reason="map_full"}') + $(metric 'plat_xdp_install_failures_total{reason="slots"}')))
    f64=$(metric 'plat_xdp_packets_total{dir="v6_to_v4"}')
    s64=$(metric plat_v6_to_v4_total)
    [ "$(metric plat_sessions)" -eq 5000 ] || die "map_full: $(metric plat_sessions) sessions, want 5000"
    [ "$xs" -le 4096 ] && [ "$xs" -ge 3000 ] || die "map_full: $xs fast-path sessions (want 3000..4096)"
    [ "$fl" -gt 0 ] || die "map_full: no install failure counted"
    # Rounds 2 and 3: fast-path flows on the fast path, the rest on the
    # slow path.
    [ "$f64" -ge $((2 * xs - 100)) ] || die "map_full: fast path carried only $f64"
    [ "$s64" -ge $((5000 + 2 * (5000 - xs))) ] || die "map_full: slow path carried only $s64"
    kill "$pcap_s" "$pcap_c" 2>/dev/null || true
    wait "$pcap_s" "$pcap_c" 2>/dev/null || true
    pcap_s=
    bad=$({ tcpdump -nvv -r "$work/mf-s0.pcap" 2>/dev/null; tcpdump -nvv -r "$work/mf-c0.pcap" 2>/dev/null; } | grep -c 'bad udp cksum' || true)
    okc=$({ tcpdump -nvv -r "$work/mf-s0.pcap" 2>/dev/null; tcpdump -nvv -r "$work/mf-c0.pcap" 2>/dev/null; } | grep -c 'udp sum ok' || true)
    echo "e2e: map_full receiver captures: $okc verified UDP checksums, $bad bad" >&2
    [ "$bad" -eq 0 ] && [ "$okc" -ge 30000 ] || die "map_full: checksums ($okc ok, $bad bad)"
    echo "e2e: PASS map_full overflow (every flow served, overflow on the slow path)" >&2
    sleep 125
    echo "e2e: map_full after 125 s idle: $(mf_counters)" >&2
    [ "$(metric plat_sessions)" -eq 0 ] && [ "$(metric plat_xdp_sessions)" -eq 0 ] || die "map_full: sessions not expired"
    i0=$(metric plat_xdp_installs_total)
    f0=$(metric 'plat_xdp_packets_total{dir="v6_to_v4"}')
    read -r r1 r2 r3 <<X
$(mf_flows 100 3)
X
    set -- "$r1" "$r2" "$r3"
    echo "e2e: map_full recovery: 100 new flows, echoes per round: $*; $(mf_counters)" >&2
    for r in "$@"; do [ "$r" -eq 100 ] || die "map_full: recovery round $r/100"; done
    [ $(($(metric plat_xdp_installs_total) - i0)) -eq 100 ] || die "map_full: recovery installs $(($(metric plat_xdp_installs_total) - i0))/100"
    [ $(($(metric 'plat_xdp_packets_total{dir="v6_to_v4"}') - f0)) -ge 200 ] || die "map_full: recovery flows not on the fast path"
    echo "e2e: PASS map_full recovery (new flows installed after expiry)" >&2
}

# --- E2E_UNITS=1: the installed systemd units (WU6) -------------------------

# Test-only runtime drop-ins (/run/systemd/system, gone at reboot): the units
# run in the PLAT namespace with the e2e config. platd's ExecStartPre/Post
# (plat-tun-setup.sh, route announcement) are cleared: they write the host's
# nftables files; the TUN is created above. The extra loader ExecStartPre
# runs with the loader's exact credentials and sandbox and logs them, so the
# capabilities can be checked after the one-shot exits.
units_dropins() {
    for u in platd plat-xdp; do
        mkdir -p "/run/systemd/system/$u.service.d"
    done
    cat >/run/systemd/system/platd.service.d/zz-e2e.conf <<X
[Service]
NetworkNamespacePath=/run/netns/$NS_P
ExecStartPre=
ExecStartPost=
ExecStopPost=
ExecStart=
ExecStart=/usr/bin/platd run --config $cfg
X
    cat >/run/systemd/system/plat-xdp.service.d/zz-e2e.conf <<X
[Service]
NetworkNamespacePath=/run/netns/$NS_P
ExecStartPre=/usr/bin/id
ExecStartPre=/bin/grep -E ^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp): /proc/self/status
ExecStart=
ExecStart=/usr/libexec/plat/plat-xdp-loader attach --config $cfg
X
    systemctl daemon-reload
}

# plat-fwguard.service in the PLAT namespace ($1 = on) or back on the host
# (off). Only for fwguard_swapped: platd.service pulls in
# plat-fwguard.timer (Wants=), and the guard must not check the PLAT
# namespace, which has no forward policy table, during the other cases.
fwguard_in_ns() {
    fg_mode=$1
    if [ "$fg_mode" = on ]; then
        mkdir -p /run/systemd/system/plat-fwguard.service.d
        printf '[Service]\nNetworkNamespacePath=/run/netns/%s\n' "$NS_P" >/run/systemd/system/plat-fwguard.service.d/zz-e2e.conf
    else
        rm -f /run/systemd/system/plat-fwguard.service.d/zz-e2e.conf
        rmdir /run/systemd/system/plat-fwguard.service.d 2>/dev/null || true
    fi
    systemctl daemon-reload
}

units_cleanup() {
    systemctl stop platd.service plat-xdp.service plat-fwguard.service 2>/dev/null || true
    systemctl stop run-plat-bpf.mount 2>/dev/null || true
    rm -f /run/systemd/system/platd.service.d/zz-e2e.conf /run/systemd/system/plat-xdp.service.d/zz-e2e.conf \
        /run/systemd/system/plat-fwguard.service.d/zz-e2e.conf
    rmdir /run/systemd/system/platd.service.d /run/systemd/system/plat-xdp.service.d \
        /run/systemd/system/plat-fwguard.service.d 2>/dev/null || true
    systemctl daemon-reload
    systemctl reset-failed platd.service plat-xdp.service plat-fwguard.service run-plat-bpf.mount 2>/dev/null || true
    rm -rf /run/plat-e2e
    [ -n "${E2E_KEEP:-}" ] || rm -f /var/log/plat/e2e-audit.jsonl*
}

journal() {
    journalctl -u plat-xdp.service -u platd.service -u plat-fwguard.service --since "@$t0" --no-pager -o cat 2>/dev/null |
        tail -n 60 >&2 || true
}

wait_enabled() {
    i=0
    until [ "$(metric plat_xdp_enabled 2>/dev/null)" = 1 ]; do
        i=$((i + 1))
        if [ $i -ge 150 ]; then
            [ "$units" = 1 ] && journal
            [ "$units" = 1 ] || cat "$work/platd.log" >&2
            die "platd did not enable the fast path"
        fi
        sleep 0.2
    done
}

state_id() { sed -n 's/^prog_id=//p' /run/plat/xdp.state 2>/dev/null; }

# Waits up to $1 s for a fast path enabled by an attach other than prog id $2.
wait_reattached() {
    wr_secs=$1 wr_old=$2
    i=0
    while [ "$(state_id)" = "$wr_old" ] || [ -z "$(state_id)" ] || [ "$(metric plat_xdp_enabled 2>/dev/null)" != 1 ]; do
        i=$((i + 1))
        [ $i -lt $((wr_secs * 5)) ] || return 1
        sleep 0.2
    done
}

xdp_prog_on() {
    xp_dev=$1
    ip -n "$NS_P" -o -d link show dev "$xp_dev" | sed -n 's|.*prog/xdp id \([0-9]*\).*|\1|p'
}

units_cases() {
    # loader_privileges: exactly CAP_BPF (39) + CAP_NET_ADMIN (12), group
    # plat, no_new_privs, seccomp filter.
    creds=$(journalctl -u plat-xdp.service --since "@$t0" --no-pager -o cat |
        grep -E '^(uid=|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp)' | head -n 8 | tr -s '\t\n' '  ')
    echo "e2e: loader credentials: $creds" >&2
    for want in 'uid=0(root)' 'gid=[0-9]*(plat)' 'CapEff: 0000008000001000' 'CapPrm: 0000008000001000' \
        'CapBnd: 0000008000001000' 'CapAmb: 0000008000001000' 'NoNewPrivs: 1' 'Seccomp: 2'; do
        printf '%s\n' "$creds" | grep -q "$want" || die "loader_privileges: no '$want' in: $creds"
    done
    echo "e2e: PASS loader_privileges (CapEff = CAP_BPF + CAP_NET_ADMIN, gid plat)" >&2

    # pins_root_plat: setgid mount root, every pin root:plat with the mode of
    # plat_xdp::maps::MAPS (read-write 0660, read-only 0640; TX, program
    # and links 0600; IDENT, IDENT_KEY and SCRATCH never pinned); /run/plat
    # root-owned, not group- or other-writable; state file 0644 root.
    gid=$(getent group plat | cut -d: -f3)
    [ "$(stat -c '%a %u %g' /run/plat/bpf)" = "2750 0 $gid" ] || die "pins_root_plat: mount root $(stat -c '%a %u %g' /run/plat/bpf)"
    [ "$(stat -c '%a %u' /run/plat)" = "755 0" ] || die "pins_root_plat: /run/plat $(stat -c '%a %u' /run/plat)"
    [ "$(stat -c '%a %u' /run/plat/xdp.state)" = "644 0" ] || die "pins_root_plat: state file $(stat -c '%a %u' /run/plat/xdp.state)"
    npins=0
    for p in /run/plat/bpf/*; do
        name=${p##*/}
        case $name in
            OUT6 | IN4 | SLOT | SLICE | CONTROL) want=660 ;;
            CONFIG | STATS | FWD | IFACES | EGRESS) want=640 ;;
            TX | prog | link_*) want=600 ;;
            *) die "pins_root_plat: unexpected pin $name" ;;
        esac
        got=$(stat -c '%a %u %g' "$p")
        [ "$got" = "$want 0 $gid" ] || die "pins_root_plat: $name is $got, want $want 0 $gid"
        npins=$((npins + 1))
    done
    [ "$npins" -eq 14 ] || die "pins_root_plat: $npins pins, want 14 (11 maps, prog, 2 links)"
    echo "e2e: PASS pins_root_plat" >&2

    # restart_reattach: `systemctl restart platd` re-runs the loader first
    # (PartOf=), so the new platd gets fresh maps (no stale_maps).
    id=$(state_id)
    systemctl restart platd.service || { journal; die "restart_reattach: systemctl restart failed"; }
    wait_reattached 30 "$id" || { journal; die "restart_reattach: the loader did not re-run (prog id $id)"; }
    echo "e2e: PASS restart_reattach (prog id $id -> $(state_id))" >&2

    # auto_restart_reattach: platd killed, Restart=on-failure brings it back
    # through a fresh attach too (BindsTo= / PartOf=).
    # L29 under the units: the fast path of the old program stops within
    # deadline_ms of the SIGKILL. Arrivals are counted up to 1.9 s after it:
    # the restart (RestartSec=2s) may reuse the same mapping.
    id=$(state_id)
    # The session on port 40000 died with the first platd: a new one.
    live_mapping
    ar_a=$lm_a ar_p=$lm_p
    dm_capture "$work/dm-kill.pcap"
    dm_sender 6
    sleep 2
    dm_t=$(date +%s.%N)
    kill -KILL "$(systemctl show -p MainPID --value platd.service)"
    wait "$dm_pid" 2>/dev/null || true
    dm_stop_capture
    read -r dm_last dm_early dm_after <<X
$(dm_summary "$work/dm-kill.pcap" "$ar_a" "$ar_p" "$dm_t" "$(awk -v t="$dm_t" 'BEGIN { printf "%.6f", t + 1.9 }')")
X
    wait_reattached 40 "$id" || { journal; die "auto_restart_reattach: no fresh attach after SIGKILL (prog id $id)"; }
    echo "e2e: SIGKILL under the units: last arrival from $ar_a:$ar_p within 1.9 s: $dm_last ms after the signal ($dm_early in the first 500 ms; $dm_after later, after the restart)" >&2
    [ "$dm_last" -ge 0 ] && [ "$dm_last" -le 1060 ] || die "auto_restart_reattach: forwarding $dm_last ms after SIGKILL (deadline_ms 1000)"
    [ "$dm_early" -gt 0 ] || die "auto_restart_reattach: nothing forwarded right after SIGKILL"
    echo "e2e: PASS auto_restart_reattach deadman_kill9 (prog id $id -> $(state_id))" >&2

    # fwguard_swapped: another program on p6 than the one the state file
    # names is detected and detached by plat-fwguard.service (its own
    # sandbox, CAP_NET_ADMIN only); forwarding goes off. The other program:
    # a second attach by the loader into a scratch bpffs, whose links are
    # unpinned again, attached to p6 through netlink. (The PLAT namespace
    # has no `inet plat` table, so the guard also reports missing-table;
    # the XDP line is checked here.)
    p6=$(ip -n "$NS_P" -o link show dev p6 | cut -d: -f1)
    p4=$(ip -n "$NS_P" -o link show dev p4 | cut -d: -f1)
    rm -f "/run/plat/bpf/link_$p6" "/run/plat/bpf/link_$p4"
    mkdir -p "$work/bpf"
    mount -t bpf bpffs "$work/bpf"
    nsx "$NS_P" "$loader" --pin-dir "$work/bpf" --state-file "$work/other.state" attach -c "$cfg" >/dev/null 2>&1 ||
        die "fwguard_swapped: second attach failed"
    rm -f "$work/bpf/link_$p6" "$work/bpf/link_$p4"
    ip -n "$NS_P" link set dev p6 xdpgeneric pinned "$work/bpf/prog" || die "fwguard_swapped: netlink attach"
    other=$(xdp_prog_on p6)
    if [ -z "$other" ] || [ "$other" = "$(state_id)" ]; then die "fwguard_swapped: no other program on p6"; fi
    # The timer (pulled in by platd.service) must not run the host's guard
    # in place of this one.
    fwtimer=$(systemctl is-active plat-fwguard.timer || true)
    systemctl stop plat-fwguard.timer
    while [ "$(systemctl is-active plat-fwguard.service)" = activating ]; do sleep 0.2; done
    fwguard_in_ns on
    systemctl start plat-fwguard.service || true
    fwguard_in_ns off
    [ "$fwtimer" != active ] || systemctl start plat-fwguard.timer
    msg=$(journalctl -u plat-fwguard.service --since "@$t0" --no-pager -o cat | grep 'xdp-program-swapped' | tail -n 1)
    [ -n "$msg" ] || { journal; die "fwguard_swapped: not reported"; }
    [ -z "$(xdp_prog_on p6)" ] || die "fwguard_swapped: program $other still attached"
    [ "$(nsx "$NS_P" sysctl -n net.ipv4.ip_forward)" = 0 ] || die "fwguard_swapped: forwarding still on"
    nsx "$NS_P" "$loader" --pin-dir "$work/bpf" --state-file "$work/other.state" detach >/dev/null 2>&1 || true
    umount "$work/bpf"
    nsx "$NS_P" sysctl -qw net.ipv4.conf.all.forwarding=1 net.ipv6.conf.all.forwarding=1
    echo "e2e: PASS fwguard_swapped: $msg" >&2

    # stop_detaches: stopping platd stops the loader unit (detach): no pin,
    # no state file, no program on the interfaces.
    systemctl stop platd.service
    # systemctl returns once platd is stopped; the loader unit's stop job
    # (ordered after it) may still be running.
    i=0
    until [ "$(systemctl is-active plat-xdp.service)" = inactive ]; do
        i=$((i + 1))
        [ $i -lt 50 ] || die "stop_detaches: plat-xdp.service is $(systemctl is-active plat-xdp.service)"
        sleep 0.2
    done
    [ -z "$(ls -A /run/plat/bpf 2>/dev/null)" ] || die "stop_detaches: pins left: $(ls /run/plat/bpf)"
    [ ! -e /run/plat/xdp.state ] || die "stop_detaches: state file left"
    [ -z "$(xdp_prog_on p6)$(xdp_prog_on p4)" ] || die "stop_detaches: a program is still attached"
    echo "e2e: PASS stop_detaches" >&2
}

cleanup() {
    if [ -n "${platd_pid:-}" ]; then
        kill -TERM "$platd_pid" 2>/dev/null || true
        wait "$platd_pid" 2>/dev/null || true
    fi
    [ -z "${echo_pid:-}" ] || kill "$echo_pid" 2>/dev/null || true
    [ -z "${pcap_s:-}" ] || kill "$pcap_s" "$pcap_c" 2>/dev/null || true
    if [ "${units:-0}" = 1 ]; then
        units_cleanup
        ! mountpoint -q "${work:-/nonexistent}/bpf" 2>/dev/null || umount "$work/bpf"
    else
        [ -z "${loader:-}" ] || nsx "$NS_P" "$loader" detach >/dev/null 2>&1 || true
        ! mountpoint -q /run/plat/bpf || umount /run/plat/bpf
    fi
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
