#!/bin/sh
# LINUX_VERIFICATION L33: OCSP name resolution through the built-in
# resolver (`plat-dns`) with platd running under the shipped systemd unit.
#
# Cases (docs/compliance/LINUX_VERIFICATION.md, L33):
#   a  resolv.conf -> local dnsmasq that answers: handshake passes
#   b  udp/tcp 53 dropped by nft on the input hook (silent): handshake
#      fails within budget_ms and
#      plat_revocation_resolve_failures_total{reason="timeout"} increments;
#      b0 records the output-hook rule of the procedure (fails fast, EPERM)
#   c  resolv.conf -> systemd-resolved stub 127.0.0.53: handshake passes
#   d  a name only in /etc/hosts resolves (with DNS blackholed)
#   e  resolv.conf edited while running: picked up within 30 s; a file
#      without `nameserver` keeps the last good configuration
#   f  no seccomp EPERM / SIGSYS for plat-dns (journal, plus a re-run of
#      a/b/reload with SystemCallErrorNumber=kill, so any denied call kills
#      platd with SIGSYS instead of failing quietly)
#
# Every client certificate carries its own OCSP AIA host name (a fresh name
# per handshake), so no result or OCSP cache hides a lookup. The OCSP
# responder is `openssl ocsp` (CA-signed responses); dnsmasq answers
# *.l33.test with 127.0.0.1 on 127.0.0.1 (server A) and 127.0.0.2 (server B).
#
# Usage (as root, on a disposable Linux test host with systemd-resolved,
# dnsmasq-base, openssl, curl and nft):
#   l33-resolver.sh run PLATD_BINARY REPO_DIR
# Every installed file the run replaces is backed up (content, mode, owner)
# and restored on exit; resolv.conf, /etc/hosts, the unit, resolved and nft
# state are restored too. Work dir: $L33_WORK (default /root/l33-work),
# removed on success unless L33_KEEP=1.
# Exit: 0 all cases pass; 1 a case failed; 2 usage or environment.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SC-5 (Denial-of-Service Protection) - lookup bounded by
#   budget_ms; IA-5(2)(b)(1) (path/status validation) - OCSP by name under
#   hard_fail; SC-7 (Boundary Protection), SC-39/AC-6 - shipped sandbox
set -eu

die() { echo "l33: $1" >&2; exit "${2:-1}"; }
log() { echo "l33: $*"; }

if ! { [ $# -eq 3 ] && [ "$1" = run ]; }; then die "usage: l33-resolver.sh run PLATD_BINARY REPO_DIR" 2; fi
bin=$2
repo=$3
[ "$(id -u)" = 0 ] || die "must run as root" 2
for t in dnsmasq openssl curl nft systemctl journalctl resolvectl sha256sum stat; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t" 2
done
[ -x "$bin" ] || die "not executable: $bin" 2
[ -f "$repo/deploy/systemd/platd.service" ] || die "not a repo: $repo" 2
systemctl is-active --quiet platd && die "platd is running; stop it first" 2

work=${L33_WORK:-/root/l33-work}
[ -e "$work" ] && die "$work exists" 2
mkdir -m 0700 "$work"
bk=$work/backup
mkdir "$bk"
fails=0
start=$(date '+%Y-%m-%d %H:%M:%S')
budget_ms=4000

# --- backup / restore ------------------------------------------------------
# Manifest lines: <path> <saved-name> (saved-name "-" = did not exist).
backup() {
    bpath=$1
    n=$(printf '%s' "$bpath" | tr '/' '_')
    if [ -e "$bpath" ] || [ -L "$bpath" ]; then
        cp -a "$bpath" "$bk/$n"
        if [ -L "$bpath" ]; then
            echo "$bpath symlink $(readlink "$bpath")" >>"$bk/state"
        else
            echo "$bpath $(sha256sum <"$bpath" | cut -d' ' -f1) $(stat -c '%a %U %G' "$bpath")" >>"$bk/state"
        fi
        echo "$bpath $n" >>"$bk/manifest"
    else
        echo "$bpath -" >>"$bk/manifest"
    fi
}
restore() {
    [ -f "$bk/manifest" ] || return 0
    while read -r p n; do
        rm -f "$p"
        [ "$n" = - ] || cp -a "$bk/$n" "$p"
    done <"$bk/manifest"
    : >"$bk/manifest.done"
}
verify_restore() {
    [ -f "$bk/state" ] || return 0
    while read -r p a b c d; do
        if [ "$a" = symlink ]; then
            [ "$(readlink "$p")" = "$b" ] || { echo "l33: RESTORE MISMATCH $p" >&2; return 1; }
        else
            now="$(sha256sum <"$p" | cut -d' ' -f1) $(stat -c '%a %U %G' "$p")"
            [ "$now" = "$a $b $c $d" ] || { echo "l33: RESTORE MISMATCH $p" >&2; return 1; }
        fi
    done <"$bk/state"
    log "restore verified: $(wc -l <"$bk/state") files byte-identical, same mode/owner"
}

nft_before=$(nft list tables)
tun_before=$(ip -o link show plat0 2>/dev/null | wc -l)
resolved_before=$(systemctl is-active systemd-resolved || true)

cleanup() {
    rc=$?
    set +e
    systemctl stop platd 2>/dev/null
    rm -rf /run/systemd/system/platd.service.d/l33-kill.conf
    rmdir /run/systemd/system/platd.service.d 2>/dev/null
    nft delete table inet l33 2>/dev/null
    [ -f "$work/dns.pids" ] && xargs kill <"$work/dns.pids" 2>/dev/null
    [ -f "$work/ocsp.pid" ] && kill "$(cat "$work/ocsp.pid")" 2>/dev/null
    restore
    rm -rf /etc/plat/l33 /var/log/plat/l33-audit.jsonl*
    systemctl daemon-reload
    [ "$resolved_before" = active ] && systemctl restart systemd-resolved
    # plat-tun-setup.sh leaves the TUN and its nft table; remove them only
    # if this run created them.
    if [ "$tun_before" = 0 ]; then ip link delete plat0 2>/dev/null; fi
    for t in $(nft list tables | awk '{print $2 " " $3}' | tr ' ' ':'); do
        echo "$nft_before" | grep -q "^table $(echo "$t" | tr ':' ' ')$" || nft delete table "$(echo "$t" | tr ':' ' ')"
    done
    verify_restore || rc=1
    [ "$(nft list tables)" = "$nft_before" ] || { echo "l33: nft tables differ from before" >&2; rc=1; }
    if [ "$rc" = 0 ] && [ "${L33_KEEP:-0}" != 1 ]; then rm -rf "$work"; else log "work dir kept: $work"; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# --- test PKI (P-256, 1 day) -----------------------------------------------
pki=$work/pki
mkdir "$pki"
cd "$pki"
: >index.txt
echo 1000 >serial
cat >ca.cnf <<EOF
[ca]
default_ca = l33
[l33]
dir = $pki
database = $pki/index.txt
serial = $pki/serial
new_certs_dir = $pki
certificate = $pki/ca.crt
private_key = $pki/ca.key
default_md = sha256
default_days = 1
policy = any
unique_subject = no
copy_extensions = none
[any]
commonName = supplied
EOF
openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
openssl req -x509 -new -key ca.key -sha256 -days 1 -subj "/CN=usg-plat L33 test CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out ca.crt
issue() { # name ext-lines
    openssl ecparam -name prime256v1 -genkey -noout -out "$1.key" 2>/dev/null
    openssl req -new -key "$1.key" -subj "/CN=$1" -out "$1.csr"
    printf '%s\n' "$2" >"$1.ext"
    openssl ca -batch -config ca.cnf -extfile "$1.ext" -in "$1.csr" -out "$1.crt" 2>/dev/null
}
issue mgmt "subjectAltName=IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature"
client() { # name aia-host
    issue "$1" "subjectAltName=DNS:l33-client.test
extendedKeyUsage=clientAuth
keyUsage=critical,digitalSignature
authorityInfoAccess=OCSP;URI:http://$2:8888/"
}
client metrics a.l33.test
client b b.l33.test
client b0 b0.l33.test
client d ocsp.l33hosts.test
i=1
while [ $i -le 30 ]; do
    client "e$i" "e$i.l33.test"
    client "g$i" "g$i.l33.test"
    client "c$i" "c$i.l33.test"
    i=$((i + 1))
done
for n in f1 f2 f2b f3 f4; do client "$n" "$n.l33.test"; done
openssl ocsp -index index.txt -port 8888 -rsigner ca.crt -rkey ca.key -CA ca.crt -nmin 60 \
    -ignore_err >"$work/ocsp.log" 2>&1 &
echo $! >"$work/ocsp.pid"

# --- DNS servers -----------------------------------------------------------
: >"$work/dns.pids"
for s in A:127.0.0.1 B:127.0.0.2; do
    dnsmasq -k --conf-file=/dev/null --no-resolv --no-hosts --bind-interfaces \
        --listen-address="${s#*:}" --port=53 --address=/l33.test/127.0.0.1 --local-ttl=0 \
        --log-queries --log-facility=- --user=nobody --pid-file= >"$work/dns${s%%:*}.log" 2>&1 &
    echo $! >>"$work/dns.pids"
done
sleep 1
xargs kill -0 <"$work/dns.pids" || die "dnsmasq did not start" 2

# --- install -----------------------------------------------------------------
for f in /usr/bin/platd /etc/plat/platd.toml /etc/systemd/system/platd.service \
    /usr/libexec/plat/plat-tun-setup.sh /etc/systemd/system/platd.service.d/v6-announce.conf \
    /etc/hosts /etc/resolv.conf /etc/systemd/resolved.conf.d/l33.conf; do
    backup "$f"
done
install -m 0755 -o root -g root "$bin" /usr/bin/platd
install -m 0644 -o root -g root "$repo/deploy/systemd/platd.service" /etc/systemd/system/platd.service
install -m 0755 -o root -g root "$repo/deploy/systemd/plat-tun-setup.sh" /usr/libexec/plat/plat-tun-setup.sh
# Not part of the sandbox; it would touch FRR route state.
rm -f /etc/systemd/system/platd.service.d/v6-announce.conf
install -d -m 0750 -o root -g plat /etc/plat/l33
install -m 0644 "$pki/mgmt.crt" "$pki/ca.crt" /etc/plat/l33/
install -m 0640 -o root -g plat "$pki/mgmt.key" /etc/plat/l33/
printf '127.0.0.1 ocsp.l33hosts.test\n' >>/etc/hosts
rm -f /etc/resolv.conf
printf 'nameserver 127.0.0.1\n' >/etc/resolv.conf
cat >/etc/plat/platd.toml <<'EOF'
# L33 test configuration (deploy/tests/resolver/l33-resolver.sh).
[node]
id = 0
name = "l33"

[translation]
nat64_prefix = "64:ff9b:1::/96"
client_prefixes = ["2001:db8:100::/40"]
ipv6_mtu = 1500
ipv4_mtu = 1500
lowest_ipv6_mtu = 1280
icmp_errors_per_sec = 100
copy_tos = true
wkp_non_global_icmp_errors = false
allow_non_global_destinations = true

[nat64]
pool = ["192.0.2.0/24"]
port_min = 1024
port_max = 65535
port_block_size = 512
max_blocks_per_subscriber = 4
subscriber_prefix_len = 64
paired_pooling = true
filtering = "address_dependent"
max_sessions = 100000
max_sessions_per_subscriber = 4000
max_subscribers = 10000
table_shards = 64
block_cooldown_secs = 120

[timeouts]
udp_secs = 300
tcp_established_secs = 7440
tcp_transitory_secs = 240
icmp_secs = 60

[dataplane]
interface = "plat0"
workers = 1
pin_cpus = false
sweep_interval_ms = 1000

[audit]
mode = "port_block"
queue_capacity = 65536
on_overflow = "refuse_new_bindings"
batch_max = 4096
flush_interval_ms = 100
summary_interval_secs = 60

[audit.file]
path = "/var/log/plat/l33-audit.jsonl"
max_bytes = 67108864
max_files = 0
min_free_bytes = 1073741824

[management]
listen = "127.0.0.1:9464"

[management.tls]
cert_file = "/etc/plat/l33/mgmt.crt"
key_file = "/etc/plat/l33/mgmt.key"
client_ca_file = "/etc/plat/l33/ca.crt"
allowed_clients = ["dns:l33-client.test"]
max_connections = 4
max_connections_per_ip = 2
handshake_timeout_ms = 5000

[tls]
require_fips = true
pq_hybrid = true

[tls.revocation]
mode = "hard_fail"
clock_skew_secs = 300
budget_ms = 4000

[tls.revocation.ocsp]
enabled = true
use_aia = true
method = "post"
cert_id_hash = "sha256"
nonce = true
require_nonce = false
timeout_ms = 2000
max_age_secs = 3600
cache_entries = 1024

[tls.revocation.crl]
enabled = false
use_cdp = true
urls = []
files = []
timeout_ms = 5000
max_bytes = 10485760
cache_bytes = 67108864
max_crls = 64
refresh_margin_secs = 3600
EOF
chmod 0644 /etc/plat/platd.toml
/usr/bin/platd check-config -c /etc/plat/platd.toml >/dev/null || die "check-config failed" 2
systemctl daemon-reload
systemctl start platd
sleep 3
systemctl is-active --quiet platd || die "platd did not start" 2

# --- helpers -----------------------------------------------------------------
now_ms() { date +%s%3N; }
# hs NAME: one mTLS handshake + GET /metrics; prints "<http code> <ms>".
hs() {
    t0=$(now_ms)
    code=$(curl -s -o "$work/hs.out" -w '%{http_code}' --max-time 10 --cacert "$pki/ca.crt" \
        --cert "$pki/$1.crt" --key "$pki/$1.key" https://127.0.0.1:9464/metrics || true)
    echo "$code $(($(now_ms) - t0))"
}
metric() { # name with labels; read through the cached metrics client
    curl -s --max-time 10 --cacert "$pki/ca.crt" --cert "$pki/metrics.crt" --key "$pki/metrics.key" \
        https://127.0.0.1:9464/metrics | awk -v m="$1" '$1 == m {print $2}'
}
verdict() { # case result evidence
    echo "L33($1) $2: $3" | tee -a "$work/results"
    [ "$2" = PASS ] || fails=$((fails + 1))
}
# blackhole HOOK: drop udp/tcp 53. On the output hook the local stack
# reports the drop to the sender at once (sendto/connect fail with EPERM),
# so the lookup fails fast; on the input hook the queries vanish silently,
# which is what an unreachable resolver looks like (timeout).
blackhole() {
    nft add table inet l33
    nft add chain inet l33 c "{ type filter hook $1 priority 0; policy accept; }"
    nft add rule inet l33 c udp dport 53 drop
    nft add rule inet l33 c tcp dport 53 drop
}
failures() { # all resolve failure counters, one line
    curl -s --max-time 10 --cacert "$pki/ca.crt" --cert "$pki/metrics.crt" --key "$pki/metrics.key" \
        https://127.0.0.1:9464/metrics | awk '/^plat_revocation_resolve_failures_total/ {printf "%s=%s ", $1, $2}'
}
queried() { grep -ic "query\[[A-Z]*\] $1 from" "$work/dns$2.log" || true; }
timeout_metric='plat_revocation_resolve_failures_total{reason="timeout"}'

# --- (a) dnsmasq answers ---------------------------------------------------------
r=$(hs metrics)
if [ "${r% *}" = 200 ] && [ "$(queried a.l33.test A)" -ge 1 ]; then
    verdict a PASS "handshake 200 in ${r#* } ms, dnsmasq A answered a.l33.test ($(queried a.l33.test A) queries)"
else
    verdict a FAIL "handshake $r, A queries $(queried a.l33.test A)"
fi

# --- (d) /etc/hosts only, DNS blackholed ---------------------------------------
blackhole output
r=$(hs d)
if [ "${r% *}" = 200 ] && [ "$(queried ocsp.l33hosts.test A)$(queried ocsp.l33hosts.test B)" = 00 ]; then
    verdict d PASS "handshake 200 in ${r#* } ms with udp/tcp 53 dropped, no DNS query for ocsp.l33hosts.test"
else
    verdict d FAIL "handshake $r"
fi

# --- (b) DNS blackholed ----------------------------------------------------------
# b0: the procedure's output-hook rule (still in place from (d)).
f0=$(failures)
r=$(hs b0)
nft delete table inet l33
log "b0 (output hook drop): handshake ${r% *} after ${r#* } ms; counters before: $f0; after: $(failures)"
echo "L33(b0) INFO: output-hook drop: handshake ${r% *} after ${r#* } ms; counters $f0 -> $(failures)" >>"$work/results"
# b: silent blackhole (input hook).
blackhole input
before=$(metric "$timeout_metric")
r=$(hs b)
after=$(metric "$timeout_metric")
nft delete table inet l33
if [ "${r% *}" != 200 ] && [ "${r#* }" -le $((budget_ms + 1000)) ] && [ "${after:-0}" -gt "${before:-0}" ]; then
    verdict b PASS "handshake refused (code ${r% *}) after ${r#* } ms (budget_ms $budget_ms), timeout counter $before -> $after"
else
    verdict b FAIL "handshake $r, timeout counter $before -> $after"
fi

# --- (e) resolv.conf edited while running ---------------------------------------
printf 'nameserver 127.0.0.2\n' >/etc/resolv.conf.l33 && mv /etc/resolv.conf.l33 /etc/resolv.conf
t0=$(date +%s)
picked=
i=1
while [ $i -le 30 ]; do
    r=$(hs "e$i")
    if [ "${r% *}" = 200 ] && [ "$(queried "e$i.l33.test" B)" -ge 1 ]; then picked=$(($(date +%s) - t0)); break; fi
    i=$((i + 1))
    sleep 2
done
# Now a file without nameserver: B must stay in use.
printf '# no nameserver (L33)\noptions ndots:1\n' >/etc/resolv.conf.l33 && mv /etc/resolv.conf.l33 /etc/resolv.conf
t1=$(date +%s)
kept=0
j=1
while [ $(($(date +%s) - t1)) -lt 45 ] && [ $j -le 30 ]; do
    r=$(hs "g$j")
    if [ "${r% *}" = 200 ] && [ "$(queried "g$j.l33.test" B)" -ge 1 ]; then kept=$((kept + 1)); else kept=-999; fi
    j=$((j + 1))
    sleep 3
done
rejected=$(journalctl -u platd --since "$start" -o cat | grep -c 'new resolver configuration rejected' || true)
if [ -n "$picked" ] && [ "$picked" -le 35 ] && [ "$kept" -gt 0 ] && [ "$rejected" -ge 1 ]; then
    verdict e PASS "new nameserver used ${picked} s after the edit (attempt $i); file without nameserver: $kept/$((j - 1)) handshakes over 45 s still via B, $rejected 'rejected' warning(s)"
else
    verdict e FAIL "picked='$picked' kept=$kept rejected=$rejected"
fi

# --- (c) systemd-resolved stub ------------------------------------------------------
mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNS=127.0.0.1\nDomains=~l33.test\n' >/etc/systemd/resolved.conf.d/l33.conf
systemctl restart systemd-resolved
rm -f /etc/resolv.conf
cp -P "$bk/_etc_resolv.conf" /etc/resolv.conf
grep -q '^nameserver 127.0.0.53' /etc/resolv.conf || die "resolv.conf is not the resolved stub" 2
t0=$(date +%s)
ok=
i=1
while [ $i -le 30 ]; do
    r=$(hs "c$i")
    if [ "${r% *}" = 200 ] && [ "$(queried "c$i.l33.test" A)" -ge 1 ]; then ok=$(($(date +%s) - t0)); break; fi
    i=$((i + 1))
    sleep 2
done
if [ -n "$ok" ]; then
    verdict c PASS "via 127.0.0.53 after ${ok} s (attempt $i; resolved forwards ~l33.test to dnsmasq A, which logged c$i.l33.test)"
else
    verdict c FAIL "no handshake via the stub in 30 attempts"
fi

# --- (f) seccomp ---------------------------------------------------------------------
mkdir -p /run/systemd/system/platd.service.d
printf '[Service]\nSystemCallErrorNumber=kill\n' >/run/systemd/system/platd.service.d/l33-kill.conf
systemctl daemon-reload
systemctl restart platd
sleep 3
fstart=$(date '+%Y-%m-%d %H:%M:%S')
r1=$(hs f1)
blackhole output
r2=$(hs f2)
nft delete table inet l33
blackhole input
r2b=$(hs f2b)
nft delete table inet l33
touch /etc/hosts
sleep 32
r3=$(hs f3)
sleep 1
r4=$(hs f4)
reloaded=$(journalctl -u platd --since "$fstart" -o cat | grep -c 'resolver configuration reloaded' || true)
active=$(systemctl is-active platd || true)
restarts=$(systemctl show -p NRestarts --value platd)
rm -f /run/systemd/system/platd.service.d/l33-kill.conf
systemctl daemon-reload
sys=$( (journalctl -u platd --since "$start" -o cat | grep -Ei 'SIGSYS|status=31'
    journalctl -k --since "$start" -o cat | grep -E 'type=1326') | grep -c . || true)
eperm=$(journalctl -u platd --since "$start" -o cat | grep -Eic 'plat-dns.*(EPERM|Operation not permitted|os error 1\))' || true)
if [ "${r1% *}" = 200 ] && [ "${r2% *}" != 200 ] && [ "${r2b% *}" != 200 ] && [ "${r3% *}" = 200 ] && [ "${r4% *}" = 200 ] &&
    [ "$active" = active ] && [ "$restarts" = 0 ] && [ "$sys" = 0 ] && [ "$eperm" = 0 ]; then
    verdict f PASS "SystemCallErrorNumber=kill: lookup 200, blackholed lookups refused (output hook ${r2#* } ms, input hook ${r2b#* } ms), reload ($reloaded) + lookups 200, platd active, NRestarts 0; journal: 0 SIGSYS/seccomp, 0 plat-dns EPERM"
else
    verdict f FAIL "r1=$r1 r2=$r2 r2b=$r2b r3=$r3 r4=$r4 active=$active restarts=$restarts sigsys=$sys eperm=$eperm"
fi

journalctl -u platd --since "$start" -o short-iso >"$work/platd.journal"
log "summary:"
cat "$work/results"
[ "$fails" = 0 ] || exit 1
