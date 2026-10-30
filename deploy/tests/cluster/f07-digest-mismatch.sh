#!/bin/sh
# F7: config digest mismatch (B with a different port_block_size).
# Pass: digest_mismatch refused and audited; no replication; the
# service_start digests differ.
set -eu
CASE=f07-digest-mismatch
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

ensure_cluster
platd_stop "$B"
gen_config 1 "$B_IP" "0 1" 1024 >"$OUT/b-mismatch.toml"
CONFIG_CHANGED=1
install_config "$B" "$OUT/b-mismatch.toml"
platd_start "$B" || true
sleep 15
if { audit_grep "$A" cluster_peer_rejected; audit_grep "$B" cluster_peer_rejected; } | grep -qF digest_mismatch; then
    pass "digest_mismatch audited"
else
    fail "no digest_mismatch record"
fi
r0=$(metric "$B" plat_cluster_repl_events_total)
sleep 5
r1=$(metric "$B" plat_cluster_repl_events_total)
if [ "$r0" -eq 0 ] && [ "$r1" -eq 0 ]; then pass "no replication to/from B"; else fail "replication events on B ($r0 -> $r1)"; fi
dig() { audit_grep "$1" service_start | tail -n 1 | sed -n 's/.*"cluster.config_digest":"\([^"]*\)".*/\1/p'; }
da=$(dig "$A")
db=$(dig "$B")
if [ -n "$da" ] && [ -n "$db" ] && [ "$da" != "$db" ]; then pass "service_start digests differ"; else fail "digests A '$da' B '$db'"; fi
restore
finish
