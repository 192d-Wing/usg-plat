#!/bin/sh
# Install-time gate tests (POAM-044 (c)): real apt / dnf in containers against
# a throwaway local HTTPS repository (fixtures.sh) with dummy usg-plat
# packages and the stand-in cosign. One function per case; case ids are
# stable (E00-E22) and cited by docs/compliance/LINUX_VERIFICATION.md.
#
#   run.sh [--engine podman|docker] [--work DIR] [DISTRO...]
#   run.sh --inside        (in the test container; used by the above)
#
# DISTRO: debian12 ubuntu2404 rocky9 rocky10 (default: all). Images are pinned
# by multi-arch index digest and run on the host CPU (x86_64 or aarch64).
# Needs the usg-plat-verify packages from `make verify-pkg` (target/verify, or
# USG_PLAT_VERIFY_PKG_DIR) and network access in the containers for the
# distro prerequisites (python3, curl, ca-certificates, unattended-upgrades /
# dnf-automatic); the distro repositories are disabled before the tests run.
# APT_OPTS is passed through to apt-get. The work directory (default a new
# target/verify-install.XXXXXX) keeps the fixtures, per-case logs and
# results.txt per distro; nothing is deleted.
#
# Cases marked GAP assert a recorded residual on purpose (they pass when the
# gap is still there): E06 transaction-wide refusal (POAM-044 (g)), E16
# dpkg -i / rpm -U bypass, E17 apt `pkg=ver` with a foreign name (apt only;
# on dnf includepkgs holds and E17 asserts that).
#
# Exit: 0 all cases passed; 1 a case failed; 2 usage or environment.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-7(15) (Code
#   Authentication), CM-14 (Signed Components), SR-11 (Component
#   Authenticity), CM-7 (pin / includepkgs), AU-12 (refusals are logged)
# POAM: POAM-044 (c), (g) - the GAP cases document the residuals
set -u

# Images pinned by the multi-arch index digest (same pins as real-release.sh).
image_of() {
    case $1 in
        debian12) echo docker.io/library/debian@sha256:268fb24c39bca92d326dd83ea3abebe4a3f7751c804ffef23bb6d857dd343ff8 ;;
        ubuntu2404) echo docker.io/library/ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852 ;;
        rocky9) echo docker.io/rockylinux/rockylinux@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f ;;
        rocky10) echo docker.io/rockylinux/rockylinux@sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834 ;;
        *) die "unknown distro $1" ;;
    esac
}
BUILDER=debian12

HOST=usg-plat.test
BASE=https://$HOST/usg-plat-packages
STATE=/var/lib/usg-plat-verify
SYSLOG=/var/log/usgtest-syslog
COSIGN_BIN=/usr/local/bin/cosign

die() { echo "install-test: $1" >&2; exit "${2:-2}"; }

# ---------------------------------------------------------------------------------
# Framework (inside the container).
# ---------------------------------------------------------------------------------
OUT=/out
RES=$OUT/results.txt
npass=0 nfail=0

rec() { # PASS|FAIL|GAP id detail
    printf '%s %s %s\n' "$1" "$2" "$3" | tee -a "$RES"
    case $1 in FAIL) nfail=$((nfail + 1)) ;; *) npass=$((npass + 1)) ;; esac
}

# run ID CMD...: output to $OUT/ID.log, status in $rc.
run() {
    id=$1
    shift
    printf '+ %s\n' "$*" >>"$OUT/$id.log"
    "$@" >>"$OUT/$id.log" 2>&1
    rc=$?
}
# want ID 0|nz: check $rc of the last run.
# shellcheck disable=SC2329 # called through run or check
want() {
    case $2 in
        nz) [ "$rc" -ne 0 ] ;;
        *) [ "$rc" -eq "$2" ] ;;
    esac && return 0
    note="exit $rc, want $2: $(tail -n 1 "$OUT/$1.log")"
    return 1
}
# has ID PATTERN: the case log matches an extended regexp.
# shellcheck disable=SC2329 # called through run or check
has() {
    grep -Eq -- "$2" "$OUT/$1.log" && return 0
    note="no /$2/ in $1.log"
    return 1
}
# verdict ID KIND(PASS|GAP) DETAIL: record $ok from the case body.
verdict() {
    if [ "$ok" -eq 1 ]; then rec "$2" "$1" "$3"; else rec FAIL "$1" "$note"; fi
}
# check COND...: fold a condition into $ok (keeps the first failure note).
check() {
    if [ "$ok" -eq 1 ] && ! "$@"; then
        ok=0
        [ -n "${note:-}" ] || note="failed: $*"
    fi
}
start() { ok=1 note=''; : >"$OUT/$1.log"; }

syslog_errs() { grep -c '^<83>.*usg-plat-verify' "$SYSLOG" 2>/dev/null || echo 0; }
cosign_off() { [ -f "$COSIGN_BIN" ] && mv -f "$COSIGN_BIN" /root/cosign.off; }
cosign_on() { install -m 0755 /fx/stub/cosign "$COSIGN_BIN"; }

# Background services: a syslog sink on /dev/log (records keep the <PRI>
# prefix: authpriv.err is <83>) and the HTTPS repository on 127.0.0.1:443.
services() {
    cat >/root/usgtest-syslog.py <<'PY'
import os, socket, sys
path, out = sys.argv[1], sys.argv[2]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(path)
os.chmod(path, 0o666)
with open(out, "ab", buffering=0) as f:
    while True:
        f.write(s.recv(65536).rstrip(b"\0\n") + b"\n")
PY
    cat >/root/usgtest-https.py <<'PY'
import functools, http.server, ssl, sys
root, cert, key = sys.argv[1:4]
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s\n" % (fmt % args))
h = functools.partial(H, directory=root)
s = http.server.ThreadingHTTPServer(("127.0.0.1", 443), h)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
c.load_cert_chain(cert, key)
s.socket = c.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
    python3 -I /root/usgtest-syslog.py /dev/log "$SYSLOG" >"$OUT/syslog-sink.log" 2>&1 &
    python3 -I /root/usgtest-https.py /fx/www /fx/tls/server.pem /fx/tls/server.key >"$OUT/https.log" 2>&1 &
    i=0
    while [ $i -lt 40 ]; do
        if [ -S /dev/log ] && curl -fsS -o /dev/null "$BASE/releases/v$P1/SHA256SUMS" 2>/dev/null; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.25
    done
    die "test services did not start (see $OUT/https.log)"
}

# Point the shipped configuration at the test repository (an operator of a
# mirror edits the same conffiles).
point_conf() {
    sed -i -e "s|^REPO_HOST=.*|REPO_HOST=$HOST|" -e "s|^REPO_BASE=.*|REPO_BASE=$BASE|" \
        /etc/usg-plat-verify/verify.conf
}

# ---------------------------------------------------------------------------------
# apt (Debian 12, Ubuntu 24.04).
# ---------------------------------------------------------------------------------
apt_ver() { dpkg-query -W -f '${db:Status-Abbrev}${Version}' "$1" 2>/dev/null | sed -n 's/^ii *//p'; }
# shellcheck disable=SC2329 # called through run or check
AG() { apt-get -y -o Dpkg::Use-Pty=0 "$@"; }

apt_setup() {
    export DEBIAN_FRONTEND=noninteractive
    # shellcheck disable=SC2086 # APT_OPTS is a list of options
    { apt-get ${APT_OPTS:-} update && apt-get ${APT_OPTS:-} install -y --no-install-recommends \
        ca-certificates curl python3 unattended-upgrades; } >"$OUT/setup.log" 2>&1 ||
        die "prerequisites failed (see $OUT/setup.log)"
    mkdir -p /root/usgtest-disabled
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
        if [ -f "$f" ]; then mv -f "$f" /root/usgtest-disabled/; fi
    done
    printf 'Types: deb\nURIs: file:/fx/distro/apt\nSuites: ./\nTrusted: yes\n' \
        >/etc/apt/sources.list.d/usgtest-distro.sources
    install -m 0644 /fx/tls/ca.pem /usr/local/share/ca-certificates/usgtest-ca.crt
    update-ca-certificates >>"$OUT/setup.log" 2>&1
    DA=$(dpkg --print-architecture)
    services
}

apt_cases() {
    deb=/fx/verify/usg-plat-verify_${VV}-1_all.deb

    start E01-bootstrap-dpkg-i
    run E01-bootstrap-dpkg-i dpkg -i "$deb"
    check want E01-bootstrap-dpkg-i 0
    check has E01-bootstrap-dpkg-i 'WARNING: cosign not found'
    verdict E01-bootstrap-dpkg-i PASS "gate installed, warns without cosign"
    # E22: fetch-sums needs an https client; a minimal image has none, so the
    # package must pull one in (found on the live v0.4.0 install).
    start E22-depends-https-client
    # shellcheck disable=SC2016 # dpkg-query format, not a shell expansion
    run E22-depends-https-client dpkg-query -W -f '${Depends}\n' usg-plat-verify
    check has E22-depends-https-client 'curl [|] wget'
    check has E22-depends-https-client 'ca-certificates'
    verdict E22-depends-https-client PASS "Depends names curl | wget and ca-certificates"
    point_conf
    sed -i "s|^URIs:.*|URIs: $BASE/apt|" /etc/apt/sources.list.d/usg-plat.sources
    sed -i "s|^Pin: origin .*|Pin: origin \"$HOST\"|" /etc/apt/preferences.d/usg-plat
    cosign_on

    start E02-update-selftest
    run E02-update-selftest AG update
    check want E02-update-selftest 0
    check test -f "$STATE/releases/v$P2/SHA256SUMS"
    run E02-update-selftest usg-plat-verify selftest
    check want E02-update-selftest 0
    verdict E02-update-selftest PASS "apt-get update runs fetch-sums and selftest --apt; selftest --full passes"

    start E03-canary-uninstallable
    run E03-canary-uninstallable apt-cache policy usg-plat-pin-canary
    check has E03-canary-uninstallable 'Candidate: \(none\)'
    run E03-canary-uninstallable AG install usg-plat-pin-canary
    check want E03-canary-uninstallable nz
    verdict E03-canary-uninstallable PASS "pin -1 holds"

    start E04-foreign-name-hidden
    run E04-foreign-name-hidden AG install usg-test-foreign
    check want E04-foreign-name-hidden nz
    check test -z "$(apt_ver usg-test-foreign)"
    verdict E04-foreign-name-hidden PASS "foreign name from the repo has no candidate"

    cosign_off
    start E05-missing-cosign-refused
    run E05-missing-cosign-refused AG install "platd=$P1-1"
    check want E05-missing-cosign-refused nz
    check has E05-missing-cosign-refused 'cosign not found'
    check test -z "$(apt_ver platd)"
    verdict E05-missing-cosign-refused PASS "platd refused, not installed"

    start E06-mixed-transaction-refused
    run E06-mixed-transaction-refused AG install "platd=$P1-1" usg-test-extra
    check want E06-mixed-transaction-refused nz
    check test -z "$(apt_ver platd)"
    check test -z "$(apt_ver usg-test-extra)"
    verdict E06-mixed-transaction-refused GAP "whole transaction refused, usg-test-extra not installed (residual g)"

    start E07-unrelated-installs-alone
    run E07-unrelated-installs-alone AG install usg-test-hello
    check want E07-unrelated-installs-alone 0
    check test "$(apt_ver usg-test-hello)" = 1.0
    verdict E07-unrelated-installs-alone PASS "installs with cosign missing"
    cosign_on

    start E08-repo-install
    run E08-repo-install AG install "platd=$P1-1"
    check want E08-repo-install 0
    check has E08-repo-install "accepted platd_$P1-1_$DA.deb"
    check test "$(apt_ver platd)" = "$P1-1"
    verdict E08-repo-install PASS "platd $P1-1 from the HTTPS repo"

    start E09-unattended-refusal-logged
    printf 'Unattended-Upgrade::Origins-Pattern { "origin=usg-plat"; };\n' >/etc/apt/apt.conf.d/52usgtest
    cosign_off
    before=$(syslog_errs)
    run E09-unattended-refusal-logged unattended-upgrade -v
    after=$(syslog_errs)
    check test "$(apt_ver platd)" = "$P1-1"
    check test "$after" -gt "$before"
    check has E09-unattended-refusal-logged 'cosign not found|failed'
    cosign_on
    verdict E09-unattended-refusal-logged PASS "unattended-upgrade refused, authpriv.err record ($before -> $after)"

    start E10-repo-upgrade
    run E10-repo-upgrade AG install --only-upgrade platd
    check want E10-repo-upgrade 0
    check test "$(apt_ver platd)" = "$P2-1"
    verdict E10-repo-upgrade PASS "$P1-1 -> $P2-1"

    start E11-downgrade-refused
    run E11-downgrade-refused AG install --allow-downgrades "platd=$P1-1"
    check want E11-downgrade-refused nz
    check has E11-downgrade-refused 'downgrade from'
    check test "$(apt_ver platd)" = "$P2-1"
    verdict E11-downgrade-refused PASS "stays $P2-1"

    start E12-downgrade-override
    run E12-downgrade-override env USG_PLAT_ALLOW_DOWNGRADE=1 \
        apt-get -y -o Dpkg::Use-Pty=0 install --allow-downgrades "platd=$P1-1"
    check want E12-downgrade-override 0
    check test "$(apt_ver platd)" = "$P1-1"
    run E12-downgrade-override AG install --only-upgrade platd
    check test "$(apt_ver platd)" = "$P2-1"
    verdict E12-downgrade-override PASS "USG_PLAT_ALLOW_DOWNGRADE=1 accepted"

    dpkg -r platd >/dev/null 2>&1
    start E13-local-install
    run E13-local-install sh -c "cd /fx/local && apt-get -y -o Dpkg::Use-Pty=0 install ./platd_$P4-1_$DA.deb"
    check want E13-local-install 0
    check has E13-local-install "accepted platd_$P4-1_$DA.deb"
    check test "$(apt_ver platd)" = "$P4-1"
    verdict E13-local-install PASS "apt install ./x.deb with sibling SHA256SUMS"

    dpkg -r platd >/dev/null 2>&1
    start E14-tampered-byte-refused
    run E14-tampered-byte-refused sh -c "cd /fx/tamper && apt-get -y -o Dpkg::Use-Pty=0 install ./platd_$P4-1_$DA.deb"
    check want E14-tampered-byte-refused nz
    check has E14-tampered-byte-refused 'not in the verified SHA256SUMS'
    check test -z "$(apt_ver platd)"
    verdict E14-tampered-byte-refused PASS "one payload byte flipped"

    start E15-tampered-sums-refused
    run E15-tampered-sums-refused AG install "/fx/badsums/platd_$P4-1_$DA.deb"
    check want E15-tampered-sums-refused nz
    check has E15-tampered-sums-refused 'does not verify'
    check test -z "$(apt_ver platd)"
    verdict E15-tampered-sums-refused PASS "SHA256SUMS changed after signing"

    # E21: a local .deb staged in a world-writable (sticky) directory could be
    # swapped after the hash; the gate refuses it (stage in a root-only dir).
    start E21-world-writable-dir-refused
    mkdir -p /tmp/usgtest-ww && chmod 1777 /tmp/usgtest-ww  # NOSONAR S2612: negative test, the gate must refuse this dir
    cp /fx/local/platd_"$P4"-1_"$DA".deb /fx/local/SHA256SUMS /fx/local/SHA256SUMS.sigstore.json /tmp/usgtest-ww/
    run E21-world-writable-dir-refused sh -c "cd /tmp/usgtest-ww && apt-get -y -o Dpkg::Use-Pty=0 install ./platd_$P4-1_$DA.deb"
    check want E21-world-writable-dir-refused nz
    check has E21-world-writable-dir-refused 'root-only directory'
    check test -z "$(apt_ver platd)"
    verdict E21-world-writable-dir-refused PASS "local .deb in a sticky world-writable directory refused"

    start E16-bypass-dpkg-i
    run E16-bypass-dpkg-i dpkg -i "/fx/unlisted/platd_$P3-1_$DA.deb"
    check want E16-bypass-dpkg-i 0
    check test "$(apt_ver platd)" = "$P3-1"
    verdict E16-bypass-dpkg-i GAP "dpkg -i installs an unlisted platd (POAM-044 (c))"

    start E17-foreign-pkg-eq-ver
    run E17-foreign-pkg-eq-ver AG install usg-test-foreign=99.0
    check want E17-foreign-pkg-eq-ver 0
    check test "$(apt_ver usg-test-foreign)" = 99.0
    verdict E17-foreign-pkg-eq-ver GAP "explicit foreign pkg=ver from the Trusted repo installs (POAM-044 (c))"

    start E18-selftest-bad-origin
    sed -i "s|^Pin: origin .*|Pin: origin \"https://$HOST\"|" /etc/apt/preferences.d/usg-plat
    run E18-selftest-bad-origin AG update
    check want E18-selftest-bad-origin nz
    check has E18-selftest-bad-origin 'FAIL: .*Pin: origin'
    sed -i "s|^Pin: origin .*|Pin: origin \"$HOST\"|" /etc/apt/preferences.d/usg-plat
    run E18-selftest-bad-origin AG update
    check want E18-selftest-bad-origin 0
    verdict E18-selftest-bad-origin PASS "origin with a scheme fails apt-get update (exit $rc after restore)"
}

# ---------------------------------------------------------------------------------
# dnf4 (Rocky 9, Rocky 10).
# ---------------------------------------------------------------------------------
rpm_ver() { rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null | grep -Ev 'not installed'; }
# shellcheck disable=SC2329 # called through run or check
DNF() { dnf -y "$@"; }

dnf_setup() {
    dnf -y --setopt=retries=5 install dnf-automatic >"$OUT/setup.log" 2>&1 ||
        die "prerequisites failed (see $OUT/setup.log)"
    mkdir -p /root/usgtest-disabled
    for f in /etc/yum.repos.d/*.repo; do
        if [ -f "$f" ]; then mv -f "$f" /root/usgtest-disabled/; fi
    done
    printf '[usgtest-distro]\nname=usgtest-distro\nbaseurl=file:///fx/distro/rpm\ngpgcheck=0\nenabled=1\n' \
        >/etc/yum.repos.d/usgtest-distro.repo
    install -m 0644 /fx/tls/ca.pem /etc/pki/ca-trust/source/anchors/usgtest-ca.pem
    update-ca-trust >>"$OUT/setup.log" 2>&1
    RA=$(uname -m)
    services
}

dnf_cases() {
    vrpm=/fx/verify/usg-plat-verify-${VV}-1.noarch.rpm

    # E00: %pre refuses a dnf whose PLUGINPATH is not EL9/EL10's (unit C).
    start E00-pre-refuses-pluginpath
    const=$(python3 -I -c 'import dnf.const, sys; sys.stdout.write(dnf.const.__file__)')
    cp -p "$const" /root/dnf-const.py.orig
    sed -i "s|^PLUGINPATH = .*|PLUGINPATH = '/usr/lib/python3.99/site-packages/dnf-plugins'|" "$const"
    run E00-pre-refuses-pluginpath python3 -I -c 'import dnf.const; print(dnf.const.PLUGINPATH)'
    check has E00-pre-refuses-pluginpath 'python3\.99'
    run E00-pre-refuses-pluginpath rpm -i --nodeps "$vrpm"
    check want E00-pre-refuses-pluginpath nz
    check has E00-pre-refuses-pluginpath "dnf plugin path '/usr/lib/python3.99/site-packages/dnf-plugins' is not supported"
    check test -z "$(rpm_ver usg-plat-verify)"
    cp -p /root/dnf-const.py.orig "$const"
    run E00-pre-refuses-pluginpath python3 -I -c 'import dnf.const; print(dnf.const.PLUGINPATH)'
    check has E00-pre-refuses-pluginpath '^/usr/lib/python3\.(9|12)/site-packages/dnf-plugins$'
    verdict E00-pre-refuses-pluginpath PASS "%pre exit 1 with an unexpected PLUGINPATH (rpm -i --nodeps)"

    start E01-bootstrap-rpm-i
    run E01-bootstrap-rpm-i rpm -i "$vrpm"
    check want E01-bootstrap-rpm-i 0
    check has E01-bootstrap-rpm-i 'WARNING: cosign not found'
    verdict E01-bootstrap-rpm-i PASS "gate installed, warns without cosign"
    start E22-depends-https-client
    run E22-depends-https-client rpm -q --requires usg-plat-verify
    check has E22-depends-https-client 'curl'
    check has E22-depends-https-client 'ca-certificates'
    verdict E22-depends-https-client PASS "Requires names curl and ca-certificates"
    if [ -z "$(rpm_ver usg-plat-verify)" ]; then
        # E01 stays FAILED; continue without the dependency check so the
        # remaining cases still run.
        rpm -i --nodeps "$vrpm" >"$OUT/E01-nodeps.log" 2>&1 || die "rpm -i --nodeps failed too" 1
    fi
    point_conf
    # shellcheck disable=SC2016 # $basearch is a dnf variable
    sed -i "s|^baseurl=.*|baseurl=$BASE/rpm/\$basearch|" /etc/yum.repos.d/usg-plat.repo
    cosign_on

    start E02-plugin-loaded-selftest
    run E02-plugin-loaded-selftest DNF makecache
    check want E02-plugin-loaded-selftest 0
    run E02-plugin-loaded-selftest dnf -v --cacheonly repolist
    check has E02-plugin-loaded-selftest '^Loaded plugins:.*usg_plat_verify'
    run E02-plugin-loaded-selftest usg-plat-verify selftest
    check want E02-plugin-loaded-selftest 0
    verdict E02-plugin-loaded-selftest PASS "dnf reports usg_plat_verify loaded; selftest --full passes"

    start E03-includepkgs-holds
    run E03-includepkgs-holds dnf -q --cacheonly repoquery --repo usg-plat --qf '%{name}'
    check want E03-includepkgs-holds 0
    names=$(grep -Ev '^\+ ' "$OUT/E03-includepkgs-holds.log" | sort -u | tr '\n' ' ')
    check test "$names" = "platd usg-plat-verify "
    run E03-includepkgs-holds DNF install usg-plat-pin-canary
    check want E03-includepkgs-holds nz
    verdict E03-includepkgs-holds PASS "repo exposes only: $names; canary uninstallable"

    start E04-foreign-name-hidden
    run E04-foreign-name-hidden DNF install usg-test-foreign
    check want E04-foreign-name-hidden nz
    check test -z "$(rpm_ver usg-test-foreign)"
    verdict E04-foreign-name-hidden PASS "includepkgs hides the foreign name"

    cosign_off
    start E05-missing-cosign-refused
    run E05-missing-cosign-refused DNF install "platd-$P1-1"
    check want E05-missing-cosign-refused nz
    check has E05-missing-cosign-refused 'cosign not found'
    check has E05-missing-cosign-refused 'usg-plat-verify: refusing platd'
    check test -z "$(rpm_ver platd)"
    verdict E05-missing-cosign-refused PASS "platd refused, not installed"

    start E06-mixed-transaction-refused
    run E06-mixed-transaction-refused DNF install "platd-$P1-1" usg-test-extra
    check want E06-mixed-transaction-refused nz
    check test -z "$(rpm_ver platd)"
    check test -z "$(rpm_ver usg-test-extra)"
    verdict E06-mixed-transaction-refused GAP "whole transaction refused, usg-test-extra not installed (residual g)"

    start E07-unrelated-installs-alone
    run E07-unrelated-installs-alone DNF install usg-test-hello
    check want E07-unrelated-installs-alone 0
    check test "$(rpm_ver usg-test-hello)" = 1.0-1
    verdict E07-unrelated-installs-alone PASS "installs with cosign missing"
    cosign_on

    start E08-repo-install
    run E08-repo-install DNF install "platd-$P1-1"
    check want E08-repo-install 0
    check has E08-repo-install "accepted platd-$P1-1.$RA.rpm"
    check test "$(rpm_ver platd)" = "$P1-1"
    verdict E08-repo-install PASS "platd $P1-1 from the HTTPS repo (sums fetched by resolved())"

    start E09-automatic-refusal-logged
    sed -i -e 's/^apply_updates.*/apply_updates = yes/' -e 's/^upgrade_type.*/upgrade_type = default/' \
        -e 's/^random_sleep.*/random_sleep = 0/' /etc/dnf/automatic.conf
    cosign_off
    before=$(syslog_errs)
    run E09-automatic-refusal-logged dnf-automatic /etc/dnf/automatic.conf
    after=$(syslog_errs)
    check want E09-automatic-refusal-logged nz
    check has E09-automatic-refusal-logged 'usg-plat-verify: refusing platd'
    check test "$(rpm_ver platd)" = "$P1-1"
    check test "$after" -gt "$before"
    cosign_on
    verdict E09-automatic-refusal-logged PASS "dnf-automatic refused, authpriv.err record ($before -> $after)"

    start E10-repo-upgrade
    run E10-repo-upgrade DNF upgrade platd
    check want E10-repo-upgrade 0
    check test "$(rpm_ver platd)" = "$P2-1"
    verdict E10-repo-upgrade PASS "$P1-1 -> $P2-1"

    start E11-downgrade-refused
    run E11-downgrade-refused DNF downgrade platd
    check want E11-downgrade-refused nz
    check has E11-downgrade-refused 'usg-plat-verify: refusing platd'
    check test "$(rpm_ver platd)" = "$P2-1"
    verdict E11-downgrade-refused PASS "stays $P2-1"

    start E12-downgrade-override
    run E12-downgrade-override env USG_PLAT_ALLOW_DOWNGRADE=1 dnf -y downgrade platd
    check want E12-downgrade-override 0
    check test "$(rpm_ver platd)" = "$P1-1"
    run E12-downgrade-override DNF upgrade platd
    check test "$(rpm_ver platd)" = "$P2-1"
    verdict E12-downgrade-override PASS "USG_PLAT_ALLOW_DOWNGRADE=1 accepted"

    rpm -e platd >/dev/null 2>&1
    start E13-local-install
    run E13-local-install sh -c "cd /fx/local && dnf -y install ./platd-$P4-1.$RA.rpm"
    check want E13-local-install 0
    check has E13-local-install "accepted platd-$P4-1.$RA.rpm"
    check test "$(rpm_ver platd)" = "$P4-1"
    verdict E13-local-install PASS "dnf install ./x.rpm (@commandline) with sibling SHA256SUMS"

    rpm -e platd >/dev/null 2>&1
    start E14-tampered-byte-refused
    run E14-tampered-byte-refused sh -c "cd /fx && dnf -y install ./tamper/platd-$P4-1.$RA.rpm"
    check want E14-tampered-byte-refused nz
    check has E14-tampered-byte-refused 'not in the verified SHA256SUMS'
    check test -z "$(rpm_ver platd)"
    verdict E14-tampered-byte-refused PASS "one payload byte flipped"

    start E15-tampered-sums-refused
    run E15-tampered-sums-refused DNF install "/fx/badsums/platd-$P4-1.$RA.rpm"
    check want E15-tampered-sums-refused nz
    check has E15-tampered-sums-refused 'does not verify'
    check test -z "$(rpm_ver platd)"
    verdict E15-tampered-sums-refused PASS "SHA256SUMS changed after signing"

    # E21: as for apt, a local .rpm in a world-writable directory is refused.
    start E21-world-writable-dir-refused
    mkdir -p /tmp/usgtest-ww && chmod 1777 /tmp/usgtest-ww  # NOSONAR S2612: negative test, the gate must refuse this dir
    cp /fx/local/platd-"$P4"-1."$RA".rpm /fx/local/SHA256SUMS /fx/local/SHA256SUMS.sigstore.json /tmp/usgtest-ww/
    run E21-world-writable-dir-refused sh -c "cd /tmp/usgtest-ww && dnf -y install ./platd-$P4-1.$RA.rpm"
    check want E21-world-writable-dir-refused nz
    check has E21-world-writable-dir-refused 'root-only directory'
    check test -z "$(rpm_ver platd)"
    verdict E21-world-writable-dir-refused PASS "local .rpm in a sticky world-writable directory refused"

    start E16-bypass-rpm-U
    run E16-bypass-rpm-U rpm -U "/fx/unlisted/platd-$P3-1.$RA.rpm"
    check want E16-bypass-rpm-U 0
    check test "$(rpm_ver platd)" = "$P3-1"
    verdict E16-bypass-rpm-U GAP "rpm -U installs an unlisted platd (POAM-044 (c))"

    start E17-foreign-pkg-eq-ver
    run E17-foreign-pkg-eq-ver DNF install usg-test-foreign-99.0
    check want E17-foreign-pkg-eq-ver nz
    check test -z "$(rpm_ver usg-test-foreign)"
    verdict E17-foreign-pkg-eq-ver PASS "includepkgs also hides an explicit foreign name-version"
}

# Common to both: the refusals above were logged and recorded.
log_cases() {
    start E19-refusals-logged
    check test "$(syslog_errs)" -gt 0
    check test -s "$STATE/last-refusal"
    check grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z platd ' "$STATE/last-refusal"
    n=$(cat "$STATE/refusals_total" 2>/dev/null || echo 0)
    check test "$n" -gt 0
    cp "$SYSLOG" "$OUT/syslog.txt" 2>/dev/null
    verdict E19-refusals-logged PASS "$(syslog_errs) authpriv.err records, last-refusal written, refusals_total $n"

    start E20-stub-argv
    # The gate never passed the regexp identity or the offline flag.
    check test -s /var/log/usgtest-cosign.argv
    check sh -c '! grep -Eq -- "--certificate-identity-regexp|--offline" /var/log/usgtest-cosign.argv'
    check grep -q -- '--trusted-root /usr/share/usg-plat-verify/trusted_root.json' /var/log/usgtest-cosign.argv
    cp /var/log/usgtest-cosign.argv "$OUT/cosign-argv.txt" 2>/dev/null
    verdict E20-stub-argv PASS "exact identity and --trusted-root on every call"
}

inside() {
    [ -d /fx ] && [ -d "$OUT" ] || die "run inside the test container (see run.sh)"
    : >"$RES"
    # shellcheck source=/dev/null # written by fixtures.sh
    . /fx/versions.env
    if command -v apt-get >/dev/null 2>&1; then
        apt_setup
        apt_cases
    elif command -v dnf >/dev/null 2>&1; then
        dnf_setup
        dnf_cases
    else
        die "neither apt-get nor dnf found"
    fi
    log_cases
    echo "install-test: $npass passed, $nfail failed" | tee -a "$RES"
    [ $nfail -eq 0 ]
}

# ---------------------------------------------------------------------------------
# Host driver.
# ---------------------------------------------------------------------------------
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
engine='' work='' distros=''
while [ $# -gt 0 ]; do
    case $1 in
        --inside) inside; exit $? ;;
        --engine) [ $# -ge 2 ] || die "--engine needs a value"; engine=$2; shift ;;
        --work) [ $# -ge 2 ] || die "--work needs a directory"; work=$2; shift ;;
        debian12 | ubuntu2404 | rocky9 | rocky10) distros="$distros $1" ;;
        -h | --help) sed -n '2,30p' "$0"; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done
[ -n "$distros" ] || distros="debian12 ubuntu2404 rocky9 rocky10"
if [ -z "$engine" ]; then
    if command -v podman >/dev/null 2>&1; then engine=podman
    elif command -v docker >/dev/null 2>&1; then engine=docker
    else die "neither podman nor docker found"; fi
fi
vdir=${USG_PLAT_VERIFY_PKG_DIR:-$repo/target/verify}
if ! ls "$vdir"/usg-plat-verify_*-1_all.deb >/dev/null 2>&1 ||
    ! ls "$vdir"/usg-plat-verify-*-1.noarch.rpm >/dev/null 2>&1; then
    die "no usg-plat-verify packages in $vdir (run make verify-pkg)"
fi
vdir=$(cd "$vdir" && pwd)
mkdir -p "$repo/target"
[ -n "$work" ] || work=$(mktemp -d "$repo/target/verify-install.XXXXXX") || die "mktemp failed"
mkdir -p "$work" || die "cannot create $work"
work=$(cd "$work" && pwd)

if [ ! -f "$work/fx/versions.env" ]; then
    echo "install-test: building fixtures in $work/fx"
    "$engine" run --rm -e APT_OPTS -v "$repo:/src:ro" -v "$vdir:/verify:ro" -v "$work:/work" \
        "$(image_of "$BUILDER")" \
        sh /src/deploy/tests/verify/install/fixtures.sh --deps --out /work/fx --verify-dir /verify ||
        die "fixtures failed" 1
fi

status=0
summary=''
for d in $distros; do
    img=$(image_of "$d")
    mkdir -p "$work/out-$d"
    echo "install-test: === $d ($img)"
    "$engine" run --rm -e APT_OPTS --add-host "$HOST:127.0.0.1" \
        -v "$repo:/src:ro" -v "$work/fx:/fx:ro" -v "$work/out-$d:/out" \
        "$img" sh /src/deploy/tests/verify/install/run.sh --inside
    rc=$?
    [ $rc -eq 0 ] || status=1
    summary="$summary
$d: $(tail -n 1 "$work/out-$d/results.txt" 2>/dev/null || echo 'no results') (exit $rc)"
done
echo "install-test: results in $work$summary"
exit $status
