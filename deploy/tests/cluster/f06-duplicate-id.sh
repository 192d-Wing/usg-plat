#!/bin/sh
# F6: duplicate node id (B started with id 0, A's id).
# Pass: refused as duplicate_id and audited; no slice served by the
# impostor; health degraded where the refusing node has /healthz.
#
# Where the refusal lands: the impostor (id 0, B's certificate, B's
# address) dials only higher ids, so its claim reaches the witness, where
# id 0 (A) is connected: refused `duplicate_id` (S-1). A never sees the
# impostor's Hello: A's dial to id 1 fails in TLS (the impostor's peer
# allow-list does not contain A's identity, which it believes is its own),
# so A records `handshake`. A's /healthz is degraded only if A itself
# refused a duplicate; otherwise the check is informational.
set -eu
CASE=f06-duplicate-id
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
platd_stop "$B"
gen_config 0 "$B_IP" "0 1" >"$OUT/b-dup.toml"
CONFIG_CHANGED=1
install_config "$B" "$OUT/b-dup.toml"
mark=$(audit_mark "$A")
wmark=$(vm "$E" "wc -l </var/log/plat/witness-audit.jsonl" | tr -d ' ')
platd_start "$B" || true
sleep 15
new=$(vm "$A" "$AUDIT_CAT | tail -n +$((mark + 1))")
wnew=$(vm "$E" "tail -n +$((wmark + 1)) /var/log/plat/witness-audit.jsonl")
dup_a=0
if printf '%s\n' "$new" | grep -F '"event.action":"cluster_peer_rejected"' | grep -qF 'duplicate_id'; then dup_a=1; fi
if [ "$dup_a" -eq 1 ] || printf '%s\n' "$wnew" | grep -F '"event.action":"cluster_peer_rejected"' | grep -qF 'duplicate_id'; then
    pass "duplicate_id refusal audited (A: $dup_a, else the witness)"
else
    fail "no cluster_peer_rejected duplicate_id record on A or the witness"
fi
if [ "$(active_slices "$B")" -eq 0 ]; then pass "impostor serves no slice"; else fail "impostor serves $(active_slices "$B") slices"; fi
health=$(vm "$A" "curl -s --max-time 2 -o /dev/null -w '%{http_code}' 127.0.0.1:9464/healthz" || true)
body=$(vm "$A" "curl -s --max-time 2 127.0.0.1:9464/healthz" || true)
if [ "$health" != 200 ] || printf '%s' "$body" | grep -qi degraded; then
    pass "health degraded on A ($health)"
elif [ "$dup_a" -eq 1 ]; then
    fail "A refused a duplicate id but health is not degraded ($health $body)"
else
    info "A did not see the impostor's Hello (refused at the witness); A health $health"
fi
attrib
restore
finish
