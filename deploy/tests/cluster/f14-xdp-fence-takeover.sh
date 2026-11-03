#!/bin/sh
# F14 (LINUX_VERIFICATION L30): HA fence and takeover with the XDP fast path
# on both nodes (xdp-setup.sh first; generic mode on the plha0 overlay).
#   1. Both nodes forward UDP on the fast path.
#   2. A crashes (SIGKILL): the units stop its loader (no program, no pins
#      on A); B takes A's slices over (cluster_slice_acquire takeover,
#      nat_port_block_adopt), its SLICE words turn Active, and B's fast
#      path carries the flows again (new sessions, POAM-028).
#   3. A restarts and fails back by handover: B fences each slice it hands
#      back (SLICE word no longer Active, so none of its records for the
#      slice can match), A acquires them under a new generation, and the
#      edge sees no packet of those slices from B after the release.
# Pass: as above, plus zero attribution overlap (attrib-check.sh).
set -eu
CASE=f14-xdp-fence-takeover
PLAT_XDP=1
export PLAT_XDP
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

# "<slice> <state> <generation>" per SLICE entry (plat_xdp_core::abi:
# state 0 inactive, 1 active, 2 fenced, 3 adopting).
slice_dump() {
    vm "$1" "bpftool -j map dump pinned /run/plat/bpf/SLICE" 2>/dev/null | python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
for e in d:
    k = int.from_bytes(bytes(int(x, 16) for x in e["key"]), "little")
    v = bytes(int(x, 16) for x in e["value"])
    if k < 16:
        print(k, v[0], int.from_bytes(v[4:8], "little"))
'
}
# Slices with state 1 in a dump, space separated.
active_in() { awk '$2 == 1 { printf "%s ", $1 }' "$1"; }
fp_packets() { metric "$1" plat_xdp_packets_total; }

# UDP load for the fast path: flows.py sends one UDP stream (one subscriber,
# one slice), so 32 more flows from the 8 subscriber /64s (4 ports each),
# 25 datagrams a second each, echoed by the flows.py server; per-flow
# counts and the longest gap go to /run/plat-f14-udp.json on the edge.
udp_start() {
    cat >"$OUT/udp.py" <<'PY'
import json, select, socket, sys, time
dur = float(sys.argv[1])
socks = []
for i in range(8):
    for _ in range(4):
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind(("2001:db8:100:%x::10" % (i + 1), 0))
        s.connect(("64:ff9b:1::cb00:710a", 5201))
        s.setblocking(False)
        socks.append(s)
st = {s.fileno(): {"src": s.getsockname()[0], "port": s.getsockname()[1], "sent": 0, "recv": 0, "last": 0.0, "gap": 0.0} for s in socks}
p = select.epoll()
for s in socks:
    p.register(s.fileno(), select.EPOLLIN)
by = {s.fileno(): s for s in socks}
t0 = time.monotonic()
for f in st.values():
    f["last"] = t0
nxt = t0
while time.monotonic() < t0 + dur:
    now = time.monotonic()
    if now >= nxt:
        for s in socks:
            try:
                s.send(b"f14")
                st[s.fileno()]["sent"] += 1
            except OSError:
                pass
        nxt = now + 0.04
    for fd, _ in p.poll(0.01):
        try:
            while by[fd].recv(64):
                f = st[fd]
                t = time.monotonic()
                f["gap"] = max(f["gap"], t - f["last"])
                f["last"] = t
                f["recv"] += 1
        except OSError:
            pass
out = list(st.values())
for f in out:
    f["gap"] = max(f["gap"], time.monotonic() - f["last"])
    f["gap_ms"] = int(f.pop("gap") * 1000)
    f.pop("last")
json.dump({"flows": out}, open("/run/plat-f14-udp.json", "w"))
PY
    limactl copy "$OUT/udp.py" "$E:/tmp/plat-f14-udp.py"
    vm "$E" "systemctl stop plat-f14-udp 2>/dev/null; systemctl reset-failed plat-f14-udp 2>/dev/null; rm -f /run/plat-f14-udp.json
        systemd-run --unit plat-f14-udp --collect ip netns exec cli python3 /tmp/plat-f14-udp.py $1" >/dev/null
}
udp_wait() {
    wait_until $((${1:-600} * 1000)) vm "$E" "test -s /run/plat-f14-udp.json" >/dev/null || fail "UDP generator produced no result"
    vm "$E" "cat /run/plat-f14-udp.json; rm -f /run/plat-f14-udp.json /tmp/plat-f14-udp.py" >"$OUT/udp.json" 2>/dev/null || true
}
xdp_attached() { vm "$1" "ip -d link show dev plha0 | grep -q 'prog/xdp'"; }

ensure_cluster
for v in "$A" "$B"; do
    [ "$(metric "$v" plat_xdp_enabled)" -eq 1 ] || { fail "$v: fast path not enabled (run xdp-setup.sh)"; finish; }
done
a_slices=$(active_slices "$A")
info "baseline: A $a_slices, B $(active_slices "$B") active slices"
capture_start
traffic_start 240 200 200 5
udp_start 240
sleep 15
fa0=$(fp_packets "$A")
fb0=$(fp_packets "$B")
sleep 5
fa1=$(fp_packets "$A")
fb1=$(fp_packets "$B")
if [ $((fa1 - fa0)) -gt 0 ] && [ $((fb1 - fb0)) -gt 0 ]; then
    pass "fast path forwards on both nodes (+$((fa1 - fa0)) A, +$((fb1 - fb0)) B in 5 s)"
else
    fail "fast path idle: +$((fa1 - fa0)) A, +$((fb1 - fb0)) B in 5 s"
fi
slice_dump "$A" >"$OUT/slice-a-0.txt"
slice_dump "$B" >"$OUT/slice-b-0.txt"
a_set=$(active_in "$OUT/slice-a-0.txt")
info "A's slices (SLICE map): $a_set; B: $(active_in "$OUT/slice-b-0.txt")"

# --- 2. crash of A, takeover by B ---------------------------------------------
mark=$(audit_mark "$B")
platd_kill9 "$A"
if ms=$(wait_until 15000 slices_eq "$B" 16); then pass "B took over all slices after $ms ms"; else fail "B did not take over"; fi
if xdp_attached "$A"; then fail "A: a program is still attached to plha0"; else pass "A: no program on plha0 after the crash"; fi
pins=$(vm "$A" "ls -A /run/plat/bpf 2>/dev/null | wc -l" | tr -d ' ')
if [ "$pins" -eq 0 ]; then pass "A: no pins left (loader unit stopped with platd)"; else fail "A: $pins pins left"; fi
new=$(vm "$B" "$AUDIT_CAT | tail -n +$((mark + 1))")
acq=$(printf '%s\n' "$new" | grep -F '"event.action":"cluster_slice_acquire"' | grep -cF '"cluster.reason":"takeover"' || true)
adopt=$(printf '%s\n' "$new" | grep -cF '"event.action":"nat_port_block_adopt"' || true)
if [ "$acq" -eq "$a_slices" ]; then pass "B: $acq cluster_slice_acquire(takeover) records"; else fail "B: $acq cluster_slice_acquire(takeover), want $a_slices"; fi
if [ "$adopt" -gt 0 ]; then pass "B: $adopt nat_port_block_adopt records"; else fail "B: no nat_port_block_adopt record"; fi
slice_dump "$B" >"$OUT/slice-b-1.txt"
n=$(awk '$2 == 1' "$OUT/slice-b-1.txt" | grep -c . || true)
if [ "$n" -eq 16 ]; then pass "B: SLICE map has all 16 slices Active"; else fail "B: $n Active SLICE entries"; fi
for s in $a_set; do
    info "slice $s on B: before $(awk -v s="$s" '$1 == s { print $2 "/" $3 }' "$OUT/slice-b-0.txt"), after takeover $(awk -v s="$s" '$1 == s { print $2 "/" $3 }' "$OUT/slice-b-1.txt") (state/generation)"
done
fb2=$(fp_packets "$B")
sleep 10
fb3=$(fp_packets "$B")
xb=$(metric "$B" plat_xdp_sessions)
if [ $((fb3 - fb2)) -gt 0 ]; then pass "B: fast path forwards after the takeover (+$((fb3 - fb2)) in 10 s, $xb fast-path sessions)"; else fail "B: fast path idle after takeover"; fi

# --- 3. A back, failback by handover: B fences, A acquires ---------------------
mark_a=$(audit_mark "$A")
mark_b=$(audit_mark "$B")
si0=$(metric "$B" 'plat_xdp_pass_total{reason="slice_inactive"}')
platd_start "$A"
if ms=$(wait_until $(((FAILBACK_SECS + 60) * 1000)) slices_eq "$A" "$a_slices"); then
    pass "A failed back to $a_slices slices after $ms ms"
else
    fail "A did not fail back"
fi
sleep 5
slice_dump "$A" >"$OUT/slice-a-2.txt"
slice_dump "$B" >"$OUT/slice-b-2.txt"
a2_set=$(active_in "$OUT/slice-a-2.txt")
for s in $a2_set; do
    sb=$(awk -v s="$s" '$1 == s { print $2 }' "$OUT/slice-b-2.txt")
    info "slice $s: A $(awk -v s="$s" '$1 == s { print $2 "/" $3 }' "$OUT/slice-a-2.txt"), B $(awk -v s="$s" '$1 == s { print $2 "/" $3 }' "$OUT/slice-b-2.txt") (state/generation)"
    [ "$sb" != 1 ] || fail "slice $s Active in both SLICE maps"
done
both=$(for s in $a2_set; do awk -v s="$s" '$1 == s && $2 == 1' "$OUT/slice-b-2.txt"; done | grep -c . || true)
[ "$both" -ne 0 ] || pass "no slice Active in both SLICE maps (B's records of A's slices cannot match)"
new_b=$(vm "$B" "$AUDIT_CAT | tail -n +$((mark_b + 1))")
new_a=$(vm "$A" "$AUDIT_CAT | tail -n +$((mark_a + 1))")
rel=$(printf '%s\n' "$new_b" | grep -F '"event.action":"cluster_slice_release"' | grep -cF '"cluster.reason":"handover"' || true)
acq=$(printf '%s\n' "$new_a" | grep -F '"event.action":"cluster_slice_acquire"' | grep -c . || true)
adopt=$(printf '%s\n' "$new_a" | grep -cF '"event.action":"nat_port_block_adopt"' || true)
info "B: $rel cluster_slice_release(handover); A: $acq cluster_slice_acquire, $adopt nat_port_block_adopt"
if [ "$rel" -gt 0 ]; then pass "B: $rel release(handover) records"; else fail "B: no release(handover) record"; fi
if [ "$acq" -gt 0 ]; then pass "A: $acq cluster_slice_acquire records"; else fail "A: no cluster_slice_acquire record"; fi
# The last release on B (ISO time), then no packet of a handed-back slice
# from B's MAC after it (200 ms for the edge capture vs audit clocks).
t_rel=$(printf '%s\n' "$new_b" | grep -F '"event.action":"cluster_slice_release"' | tail -n 1 | sed -n 's/^{"@timestamp":"\([^"]*\)".*/\1/p')
sleep 10
si1=$(metric "$B" 'plat_xdp_pass_total{reason="slice_inactive"}')
info "B: plat_xdp_pass_total{reason=slice_inactive} $si0 -> $si1; fast-path sessions $(metric "$B" plat_xdp_sessions)"
traffic_wait 300
capture_stop
mac_b=$(overlay_mac "$B")
mac_a=$(overlay_mac "$A")
if [ -n "$t_rel" ] && [ -f "$OUT/macs.txt" ]; then
    t_cut=$(python3 -I -c 'import sys, datetime as d; t = d.datetime.strptime(sys.argv[1], "%Y-%m-%dT%H:%M:%S.%fZ") + d.timedelta(milliseconds=200); print(t.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))' "$t_rel")
    stale=$(awk -v m="$mac_b" -v t="$t_cut" -v set=" $a2_set" '$2 == m && $1 >= t {
        split($3, o, "."); if (index(set, " " int(o[4] / 16) " ")) n++ } END { print n + 0 }' "$OUT/macs.txt")
    served=$(awk -v m="$mac_a" -v t="$t_cut" -v set=" $a2_set" '$2 == m && $1 >= t {
        split($3, o, "."); if (index(set, " " int(o[4] / 16) " ")) n++ } END { print n + 0 }' "$OUT/macs.txt")
    info "edge capture after the last release ($t_rel + 200 ms): packets of A's slices from B $stale, from A $served"
    if [ "$stale" -eq 0 ]; then pass "B sent no packet of a fenced slice after the release"; else fail "B sent $stale packets of fenced slices after the release"; fi
    if [ "$served" -gt 0 ]; then pass "A serves its slices after the handover ($served packets)"; else fail "A sent no packet of its slices after the handover"; fi
else
    fail "no release timestamp or no edge capture"
fi
info "flows: $(vm "$E" "cat /run/plat-flows.json" 2>/dev/null | tr -d '\n' | cut -c1-400)"
udp_wait 300
info "UDP flows (src sent/recv max-gap-ms): $(python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))["flows"]
print(" ".join("%s:%d %d/%d %d" % (f["src"].split(":")[3], f["port"], f["sent"], f["recv"], f["gap_ms"]) for f in d))
' "$OUT/udp.json" 2>/dev/null)"
attrib
restore
finish
