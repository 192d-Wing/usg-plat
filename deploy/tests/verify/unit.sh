#!/bin/sh
# Unit tests of the usg-plat install-time gate (deploy/verify): verify-pkg,
# apt-hook, fetch-sums, selftest and usg-plat-verify, with stand-in cosign,
# logger, dpkg-deb and apt-cache on PATH. The cosign stand-in records every
# argument it gets, so the tests check the exact command line.
#
# Usage: deploy/tests/verify/unit.sh        (from anywhere; Linux or any host
#        with sha256sum and timeout(1))
# Exit:  0 all passed; 1 a case failed; 2 missing tool.
# The scratch directory is printed and left in $TMPDIR (nothing is removed
# recursively).
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SI-7(15) (Code Authentication), CM-14 (Signed Components),
#   SR-11 (Component Authenticity) - the gate refuses on every failure and
#   passes cosign the exact identity and the pinned trust root
# - NIST 800-53: SA-11 (Developer Testing and Evaluation)
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
src="$root/deploy/verify"
for t in sha256sum timeout awk sed; do
    command -v "$t" >/dev/null 2>&1 || {
        echo "unit.sh: missing tool $t (run on Linux or in a container)" >&2
        exit 2
    }
done

umask 022
W=$(mktemp -d "${TMPDIR:-/tmp}/usg-plat-verify-unit.XXXXXX") || exit 2
echo "unit.sh: scratch $W"
mkdir -p "$W/stub" "$W/libexec" "$W/state/releases" "$W/arch" "$W/local" "$W/rel/v0.3.0" "$W/rel/v0.2.1" "$W/tf" "$W/apt" "$W/pol"
cp "$src/libexec/verify-pkg" "$src/libexec/apt-hook" "$src/libexec/fetch-sums" "$src/libexec/selftest" "$W/libexec/"
echo '{"mediaType":"stub"}' >"$W/trusted_root.json"

# --- stand-ins -------------------------------------------------------------------
cat >"$W/stub/cosign" <<'EOF'
#!/bin/sh
# Stand-in cosign: records argv (one per line) and GODEBUG, acts per $STUB_MODE.
rec=${STUB_REC:?}
{ echo "--call--"; echo "GODEBUG=${GODEBUG:-}"; for a in "$@"; do printf '%s\n' "$a"; done; } >>"$rec"
case ${STUB_MODE:-ok} in exit127) exit 127 ;; *) ;; esac
if [ "$1" = version ]; then
    echo "GitVersion:    v${STUB_VERSION:-3.1.4}"
    exit 0
fi
case ${STUB_MODE:-ok} in
    sleep) sleep 5 ;;
    fail) echo "Error: none of the expected identities matched" >&2; exit 1 ;;
    stderr-error) echo "Error: something odd" >&2; echo "Verified OK" >&2; exit 0 ;;
    near-ok) echo "Verified OK? no" >&2; echo "not Verified OK" >&2; exit 0 ;;
    silent) exit 0 ;;
    *) ;;
esac
# Simulated signature: the bundle was made for $STUB_SIGNED_TAG.
want="https://github.com/192d-Wing/usg-plat/.github/workflows/packages.yml@refs/tags/${STUB_SIGNED_TAG:-v0.3.0}"
prev=''
for a in "$@"; do
    if [ "$prev" = --certificate-identity ] && [ "$a" != "$want" ]; then
        echo "Error: expected SAN value \"$a\", got \"$want\"" >&2
        exit 1
    fi
    prev=$a
done
echo "Verified OK" >&2
exit 0
EOF
cat >"$W/stub/logger" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"${STUB_LOG:?}"
EOF
cat >"$W/stub/dpkg-deb" <<'EOF'
#!/bin/sh
# Stand-in dpkg-deb -f FILE FIELD...: the fake .deb is its own control text.
[ "$1" = -f ] || exit 2
f=$2
shift 2
[ -f "$f" ] || exit 2
if [ $# -eq 1 ]; then
    sed -n "s/^$1: //p" "$f"
else
    for k in "$@"; do grep "^$k: " "$f"; done
fi
EOF
cat >"$W/stub/apt-cache" <<'EOF'
#!/bin/sh
# Stand-in apt-cache policy NAME: prints $STUB_POLICY/NAME when present.
[ "$1" = policy ] || exit 0
shift
for n in "$@"; do
    [ -f "${STUB_POLICY:?}/$n" ] && cat "$STUB_POLICY/$n"
done
exit 0
EOF
chmod 0755 "$W/stub/cosign" "$W/stub/logger" "$W/stub/dpkg-deb" "$W/stub/apt-cache" "$W"/libexec/*

write_conf() { # extra lines
    {
        echo 'NAMES="platd usg-plat-verify"'
        echo 'REPO_HOST=192d-wing.github.io'
        echo "REPO_BASE=file://$W/pub"
        echo "COSIGN=$W/stub/cosign"
        echo 'COSIGN_MIN=3.0.3'
        echo 'COSIGN_GODEBUG=fips140=only'
        echo 'ALLOW_DOWNGRADE=0'
        printf '%s\n' "$@"
    } >"$W/verify.conf"
}
write_conf

# Test mode: the path overrides below are honoured, the invoking uid counts
# as an owner for root_only() and its walk stops at $W (mktemp under /tmp).
export USG_PLAT_VERIFY_TEST=1 USG_PLAT_VERIFY_TEST_TOP="$W"
export USG_PLAT_VERIFY_CONF="$W/verify.conf"
export USG_PLAT_VERIFY_STATE="$W/state"
export USG_PLAT_VERIFY_TRUSTED_ROOT="$W/trusted_root.json"
export USG_PLAT_VERIFY_TEXTFILE_DIR="$W/tf/collector"
export USG_PLAT_VERIFY_LIBEXEC="$W/libexec"
export USG_PLAT_VERIFY_PATH="$W/stub:$PATH"
export USG_PLAT_VERIFY_APT_SOURCES="$W/apt/usg-plat.sources"
export USG_PLAT_VERIFY_APT_PREF="$W/apt/usg-plat.pref"
export STUB_REC="$W/cosign.rec" STUB_LOG="$W/logger.rec" STUB_POLICY="$W/pol"
export USG_PLAT_VERIFY_TIMEOUT=10
unset USG_PLAT_VERIFY_SUMS_DIR USG_PLAT_ALLOW_DOWNGRADE STUB_MODE STUB_VERSION STUB_SIGNED_TAG

# Fake packages: the file is its control text, so dpkg-deb (stub) and
# sha256sum (real) both work on it.
mkdeb() { # path package version arch
    printf 'Package: %s\nVersion: %s\nArchitecture: %s\n' "$2" "$3" "$4" >"$1"
}
digest() { h=$(sha256sum "$1"); echo "${h%% *}"; }

mkdeb "$W/arch/platd_0.3.0-1_amd64.deb" platd 0.3.0-1 amd64
mkdeb "$W/arch/platd_0.3.0-1_arm64.deb" platd 0.3.0-1 arm64
mkdeb "$W/arch/platd_0.2.1-1_amd64.deb" platd 0.2.1-1 amd64
mkdeb "$W/arch/libfoo_1.0_amd64.deb" libfoo 1.0 amd64
mkdeb "$W/arch/evil_1.0_amd64.deb" platd 0.3.0-1 amd64
printf "Evil: yes\n" >>"$W/arch/evil_1.0_amd64.deb"
mkdeb "$W/arch/platd_0.3.0-1_amd64.wrongver.deb" platd 0.3.0-2 amd64
mkdeb "$W/local/platd_0.3.0-1_arm64.deb" platd 0.3.0-1 arm64
printf 'x' >>"$W/local/platd_0.3.0-1_arm64.deb" # differs from the archives copy
H_AMD=$(digest "$W/arch/platd_0.3.0-1_amd64.deb")
H_ARM=$(digest "$W/arch/platd_0.3.0-1_arm64.deb")
H_OLD=$(digest "$W/arch/platd_0.2.1-1_amd64.deb")
H_LOCAL=$(digest "$W/local/platd_0.3.0-1_arm64.deb")
H_RPM=$(printf 'rpm' | sha256sum)
H_RPM=${H_RPM%% *}
H_NONE=0000000000000000000000000000000000000000000000000000000000000000
{
    echo "$H_AMD  platd_0.3.0-1_amd64.deb"
    echo "$H_ARM  platd_0.3.0-1_arm64.deb"
    echo "$H_RPM  platd-0.3.0-1.x86_64.rpm"
} >"$W/rel/v0.3.0/SHA256SUMS"
echo "$H_OLD  platd_0.2.1-1_amd64.deb" >"$W/rel/v0.2.1/SHA256SUMS"
echo '{}' >"$W/rel/v0.3.0/SHA256SUMS.sigstore.json"
echo '{}' >"$W/rel/v0.2.1/SHA256SUMS.sigstore.json"
mkdir -p "$W/pub"
ln -s "$W/rel" "$W/pub/releases"
mkdir -p "$W/state/releases/v0.3.0" "$W/state/releases/v0.2.1"
cp "$W/rel/v0.3.0/SHA256SUMS" "$W/rel/v0.3.0/SHA256SUMS.sigstore.json" "$W/state/releases/v0.3.0/"
cp "$W/rel/v0.2.1/SHA256SUMS" "$W/rel/v0.2.1/SHA256SUMS.sigstore.json" "$W/state/releases/v0.2.1/"
# Local install: sibling sums list the local file.
echo "$H_LOCAL  platd_0.3.0-1_arm64.deb" >"$W/local/SHA256SUMS"
echo '{}' >"$W/local/SHA256SUMS.sigstore.json"

# --- harness -------------------------------------------------------------------
pass=0 failn=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1" >&2; }
reset() {
    : >"$STUB_REC"
    : >"$STUB_LOG"
    rm -f "$W/state/last-refusal" "$W/state/refusals_total" "$W/tf/collector/usg-plat-verify.prom"
    unset USG_PLAT_VERIFY_SUMS_DIR USG_PLAT_ALLOW_DOWNGRADE STUB_MODE STUB_VERSION STUB_SIGNED_TAG
    write_conf
}
# expect NAME CODE CMD...: run CMD (stdout/stderr to $W/out), compare exit code.
expect() {
    n=$1 want=$2
    shift 2
    "$@" >"$W/out" 2>&1
    got=$?
    if [ "$got" -eq "$want" ]; then ok "$n"; else bad "$n (exit $got, want $want): $(tr '\n' ' ' <"$W/out")"; fi
}
check() { # NAME CMD...: CMD must succeed
    n=$1
    shift
    if "$@"; then ok "$n"; else bad "$n"; fi
}
vp() { "$W/libexec/verify-pkg" "$@"; }
absent() { ! grep -Eq -- "$@"; }             # absent ERE FILE...
absent_r() { ! grep -rq -- "$@"; }           # absent_r STRING DIR...
reason() { # NAME TEXT: the last output contains TEXT
    if grep -q -- "$2" "$W/out"; then ok "$1"; else bad "$1"; fi
}
sc_clean() { (cd "$root" && shellcheck -x -s sh "$@"); }
# argv of the verify-blob call, one per line
blob_argv() { awk '/^--call--$/ { c = 0; next } $0 == "verify-blob" { c = 1 } c' "$STUB_REC"; }
after() { # FLAG: the argument following FLAG in the verify-blob call
    blob_argv | awk -v f="$1" 'p { print; exit } $0 == f { p = 1 }'
}
no_cosign_call() { [ ! -s "$STUB_REC" ]; }
IDENT=https://github.com/192d-Wing/usg-plat/.github/workflows/packages.yml@refs/tags/v0.3.0

# --- verify-pkg: accept and command line ---------------------------------------
reset
expect "accept platd amd64 from the cache" 0 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
check "exact --certificate-identity" [ "$(after --certificate-identity)" = "$IDENT" ]
check "--certificate-oidc-issuer" [ "$(after --certificate-oidc-issuer)" = https://token.actions.githubusercontent.com ]
check "--trusted-root is the pinned root" [ "$(after --trusted-root)" = "$W/trusted_root.json" ]
check "--bundle passed" [ -n "$(after --bundle)" ]
check "no regexp identity, no offline flag" absent '^--certificate-identity-regexp|^--offline' "$STUB_REC"
check "GODEBUG=fips140=only passed through" grep -qx 'GODEBUG=fips140=only' "$STUB_REC"
check "accept logged at authpriv.info" grep -q 'authpriv.info.*accepted platd_0.3.0-1_amd64.deb' "$STUB_LOG"
check "accept writes no last-refusal" [ ! -e "$W/state/last-refusal" ]
reset
expect "accept rpm name grammar" 0 vp --name platd --version 0.3.0-1 --arch x86_64 --sha256 "$H_RPM"
reset
write_conf 'COSIGN_GODEBUG='
expect "empty COSIGN_GODEBUG accepted" 0 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
check "no GODEBUG when empty" grep -qx 'GODEBUG=' "$STUB_REC"

# --- verify-pkg: usage and inputs (exit 2) -------------------------------------
reset
expect "missing arguments" 2 vp --name platd
expect "unknown option" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD" --offline x
expect "bad name" 2 vp --name openssl --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
expect "bad version (two parts)" 2 vp --name platd --version 0.3 --arch amd64 --sha256 "$H_AMD"
expect "bad version (epoch)" 2 vp --name platd --version 1:0.3.0-1 --arch amd64 --sha256 "$H_AMD"
expect "bad version (suffix)" 2 vp --name platd --version 0.3.0-1~rc1 --arch amd64 --sha256 "$H_AMD"
expect "bad version (newline)" 2 vp --name platd --version "0.3.0-1
x" --arch amd64 --sha256 "$H_AMD"
expect "bad arch" 2 vp --name platd --version 0.3.0-1 --arch i386 --sha256 "$H_AMD"
expect "bad sha256" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 ABC
expect "relative sums dir" 2 env USG_PLAT_VERIFY_SUMS_DIR=rel "$W/libexec/verify-pkg" --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
check "usage errors never call cosign" no_cosign_call
write_conf 'COSIGN_MIN=2.5.0'
expect "COSIGN_MIN below the 3.0.3 floor" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reset
expect "missing configuration" 2 env USG_PLAT_VERIFY_CONF="$W/nope.conf" "$W/libexec/verify-pkg" --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
expect "missing trusted root" 2 env USG_PLAT_VERIFY_TRUSTED_ROOT="$W/nope.json" "$W/libexec/verify-pkg" --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"

# --- verify-pkg: refusals (exit 1) ---------------------------------------------
reset
expect "digest not in sums" 1 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_NONE"
expect "digest listed under another file name" 1 vp --name platd --version 0.3.0-1 --arch arm64 --sha256 "$H_AMD"
reason "other-name reason" 'under another file name'
reset
STUB_SIGNED_TAG=v0.2.1
export STUB_SIGNED_TAG
expect "sums for another tag (identity mismatch)" 1 env USG_PLAT_VERIFY_SUMS_DIR="$W/rel/v0.2.1" "$W/libexec/verify-pkg" --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_OLD"
reset
expect "no sums for the tag" 1 vp --name platd --version 0.4.0-1 --arch amd64 --sha256 "$H_AMD"
check "missing sums never call cosign" no_cosign_call
reset
write_conf "COSIGN=$W/stub/no-such-cosign"
expect "cosign missing" 1 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
# cosign itself must be root-only (SEC-010): file, target and ancestors.
reset
expect "test mode is announced" 0 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reason "test mode on stderr" 'test mode enabled: overrides honoured'
check "test mode logged at authpriv.warning" grep -q 'authpriv.warning.*test mode enabled: overrides honoured' "$STUB_LOG"
mkdir -p "$W/cos/gw" "$W/cos/lnk" "$W/cos/own"
cp "$W/stub/cosign" "$W/cos/gw/cosign"
chmod 0775 "$W/cos/gw"
reset
write_conf "COSIGN=$W/cos/gw/cosign"
expect "cosign in a group-writable directory refused" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reason "cosign refusal reason" 'cosign .* is not root-owned'
check "untrusted cosign never ran" no_cosign_call
reset
ln -s "$W/stub/cosign" "$W/cos/lnk/cosign"
write_conf "COSIGN=$W/cos/lnk/cosign"
expect "symlink to a root-only cosign accepted" 0 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reset
ln -s "$W/cos/gw/cosign" "$W/cos/lnk/cosign-gw"
write_conf "COSIGN=$W/cos/lnk/cosign-gw"
expect "symlink to a cosign in a group-writable directory refused" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reset
ln -s "$W/stub/cosign" "$W/cos/gw/cosign-ln"
write_conf "COSIGN=$W/cos/gw/cosign-ln"
expect "symlink in a group-writable directory refused" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reset
cp "$W/stub/cosign" "$W/cos/own/cosign"
chmod 0775 "$W/cos/own/cosign"
write_conf "COSIGN=$W/cos/own/cosign"
expect "group-writable cosign file refused" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
chmod 0755 "$W/cos/own/cosign"
if [ "$(id -u)" = 0 ]; then
    chown 65534 "$W/cos/own/cosign"
    reset
    write_conf "COSIGN=$W/cos/own/cosign"
    expect "cosign owned by another uid refused" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
    chown 0 "$W/cos/own/cosign"
elif [ "${CI:-}" = true ]; then
    bad "the non-root-owner cosign case needs root in CI"
else
    echo "skip cosign owned by another uid (not root)"
fi
reset
write_conf "COSIGN=$W/cos/gw/cosign"
expect "selftest --full flags an untrusted cosign" 1 "$W/libexec/selftest" --full
reason "selftest names the cosign problem" 'cosign .* is not root-owned'
reset
STUB_MODE=exit127
export STUB_MODE
expect "cosign exits 127" 1 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reset
STUB_VERSION=3.0.2
export STUB_VERSION
expect "cosign 3.0.2 below 3.0.3" 1 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
STUB_VERSION=2.5.0
expect "cosign 2.5.0 below 3.0.3" 1 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
check "old cosign never runs verify-blob" absent '^verify-blob$' "$STUB_REC"
STUB_VERSION=3.0.3
expect "cosign 3.0.3 accepted" 0 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
STUB_VERSION=3.10.0
expect "cosign 3.10.0 accepted (numeric compare)" 0 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reset
STUB_MODE='sleep'
export STUB_MODE
expect "cosign timeout" 1 env USG_PLAT_VERIFY_TIMEOUT=1 "$W/libexec/verify-pkg" --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reason "timeout reason" 'timed out'
reset
STUB_MODE=fail
export STUB_MODE
expect "cosign verification failure" 1 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
STUB_MODE=stderr-error
expect "cosign exit 0, exact Verified OK line, other noise accepted" 0 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
STUB_MODE=near-ok
expect "cosign exit 0 with only near-miss Verified OK lines refused" 1 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
STUB_MODE=silent
expect "cosign exit 0 without Verified OK" 1 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"

# --- logging -------------------------------------------------------------------
reset
expect "refusal for logging" 1 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_NONE"
check "refusal logged at authpriv.err with tag" grep -q -- '-t usg-plat-verify -p authpriv.err' "$STUB_LOG"
check "last-refusal written" grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z platd 0.3.0-1 digest is not' "$W/state/last-refusal"
check "refusals_total is 1" grep -qx 1 "$W/state/refusals_total"
check "no textfile without the collector directory" [ ! -e "$W/tf/collector/usg-plat-verify.prom" ]
mkdir -p "$W/tf/collector"
expect "second refusal" 1 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_NONE"
check "textfile written when the directory exists" grep -qx 'usg_plat_verify_refusals_total 2' "$W/tf/collector/usg-plat-verify.prom"
check "textfile has the timestamp gauge" grep -Eq '^usg_plat_verify_last_refusal_timestamp_seconds [0-9]+$' "$W/tf/collector/usg-plat-verify.prom"
rmdir "$W/tf/collector" 2>/dev/null || { rm -f "$W/tf/collector/usg-plat-verify.prom"; rmdir "$W/tf/collector"; }

# --- apt-hook ------------------------------------------------------------------
hook_in() { # action lines...
    echo "VERSION 3"
    echo "APT::Architecture=amd64"
    echo "Dir=/"
    echo "Dir::Cache=$W/"
    echo "Dir::Cache::archives=arch/"
    echo "DPkg::Tools::Options::/usr/libexec/usg-plat-verify/apt-hook::Version=3"
    echo ""
    printf '%s\n' "$@"
}
hook() { hook_in "$@" | "$W/libexec/apt-hook"; }

reset
expect "distro lines only pass" 0 hook \
    "libfoo - - none < 1.0 amd64 same $W/arch/libfoo_1.0_amd64.deb" \
    "bash 5.1 amd64 none < 5.2 amd64 none /var/cache/apt/archives/bash_5.2_amd64.deb" \
    "libfoo - - none < 1.0 amd64 same **CONFIGURE**"
check "distro lines never call cosign" no_cosign_call
reset
expect "REMOVE and CONFIGURE pass for our names" 0 hook \
    "platd 0.3.0-1 amd64 none > - - none **REMOVE**" \
    "platd - - none < 0.3.0-1 amd64 none **CONFIGURE**"
check "REMOVE/CONFIGURE never call cosign" no_cosign_call
reset
expect "install from the archives (cached sums)" 0 hook \
    "platd - - none < 0.3.0-1 amd64 none $W/arch/platd_0.3.0-1_amd64.deb"
reset
expect "upgrade from the archives" 0 hook \
    "platd 0.2.1-1 amd64 none < 0.3.0-1 amd64 none $W/arch/platd_0.3.0-1_amd64.deb"
reset
expect "local ./x.deb uses the sibling sums" 0 hook \
    "platd - - none < 0.3.0-1 arm64 none $W/local/platd_0.3.0-1_arm64.deb"
reset
expect "relative path refused" 1 hook "platd - - none < 0.3.0-1 amd64 none arch/platd_0.3.0-1_amd64.deb"
check "relative path never calls cosign" no_cosign_call
expect "non-.deb action refused" 1 hook "platd - - none < 0.3.0-1 amd64 none $W/arch/platd_0.3.0-1_amd64.tar"
expect "missing file refused" 1 hook "platd - - none < 0.3.0-1 amd64 none $W/arch/nope_0.3.0-1_amd64.deb"
ln -s "$W/arch/platd_0.3.0-1_amd64.deb" "$W/arch/link_0.3.0-1_amd64.deb"
expect "symlink refused" 1 hook "platd - - none < 0.3.0-1 amd64 none $W/arch/link_0.3.0-1_amd64.deb"
rm -f "$W/arch/link_0.3.0-1_amd64.deb"
expect "control Version mismatch refused" 1 hook \
    "platd - - none < 0.3.0-1 amd64 none $W/arch/platd_0.3.0-1_amd64.wrongver.deb"
expect "control Architecture mismatch refused" 1 hook \
    "platd - - none < 0.3.0-1 arm64 none $W/arch/platd_0.3.0-1_amd64.deb"
expect "control Package mismatch refused" 1 hook \
    "usg-plat-verify - - none < 0.3.0-1 amd64 none $W/arch/platd_0.3.0-1_amd64.deb"
expect "foreign name carrying our package refused" 1 hook \
    "evil - - none < 1.0 amd64 none $W/arch/evil_1.0_amd64.deb"
check "hook refusals never call cosign" no_cosign_call
check "hook refusal writes last-refusal" grep -q 'evil' "$W/state/last-refusal"
check "hook refusal logged at authpriv.err" grep -q -- '-p authpriv.err' "$STUB_LOG"
reset
expect "downgrade refused" 1 hook \
    "platd 0.3.0-1 amd64 none > 0.2.1-1 amd64 none $W/arch/platd_0.2.1-1_amd64.deb"
reason "downgrade reason" downgrade
reset
USG_PLAT_ALLOW_DOWNGRADE=1
export USG_PLAT_ALLOW_DOWNGRADE
expect "downgrade allowed with USG_PLAT_ALLOW_DOWNGRADE=1" 0 env STUB_SIGNED_TAG=v0.2.1 "$W/libexec/apt-hook" <<EOF
$(hook_in "platd 0.3.0-1 amd64 none > 0.2.1-1 amd64 none $W/arch/platd_0.2.1-1_amd64.deb")
EOF
reset
write_conf 'ALLOW_DOWNGRADE=1'
expect "downgrade allowed with ALLOW_DOWNGRADE=1" 0 env STUB_SIGNED_TAG=v0.2.1 "$W/libexec/apt-hook" <<EOF
$(hook_in "platd 0.3.0-1 amd64 none > 0.2.1-1 amd64 none $W/arch/platd_0.2.1-1_amd64.deb")
EOF
reset
mkdir -p "$W/tamper"
cp "$W/arch/platd_0.3.0-1_arm64.deb" "$W/rel/v0.3.0/SHA256SUMS" "$W/rel/v0.3.0/SHA256SUMS.sigstore.json" "$W/tamper/"
printf 'y' >>"$W/tamper/platd_0.3.0-1_arm64.deb"
expect "tampered byte refused" 1 hook \
    "platd - - none < 0.3.0-1 arm64 none $W/tamper/platd_0.3.0-1_arm64.deb"
reset
printf 'VERSION 2\n\nplatd - - none < 0.3.0-1 amd64 none %s\n' "$W/arch/platd_0.3.0-1_amd64.deb" >"$W/v2.in"
expect "protocol VERSION 2 refused" 1 "$W/libexec/apt-hook" <"$W/v2.in"
reset
expect "verify-pkg refusal aborts the transaction" 1 env STUB_MODE=fail "$W/libexec/apt-hook" <<EOF
$(hook_in "libfoo - - none < 1.0 amd64 same $W/arch/libfoo_1.0_amd64.deb" "platd - - none < 0.3.0-1 amd64 none $W/arch/platd_0.3.0-1_amd64.deb")
EOF

# --- apt-hook: root-only package paths (SEC-001) ----------------------------------
for d in ww sticky gw; do
    mkdir -p "$W/$d"
    cp "$W/local/platd_0.3.0-1_arm64.deb" "$W/local/SHA256SUMS" "$W/local/SHA256SUMS.sigstore.json" "$W/$d/"
done
chmod 0777 "$W/ww"
chmod 1777 "$W/sticky"
chmod g+w "$W/gw/platd_0.3.0-1_arm64.deb"
reset
expect "local .deb in a world-writable directory refused" 1 hook \
    "platd - - none < 0.3.0-1 arm64 none $W/ww/platd_0.3.0-1_arm64.deb"
reason "world-writable reason" 'root-only directory'
expect "local .deb in a sticky world-writable directory refused" 1 hook \
    "platd - - none < 0.3.0-1 arm64 none $W/sticky/platd_0.3.0-1_arm64.deb"
expect "group-writable local .deb refused" 1 hook \
    "platd - - none < 0.3.0-1 arm64 none $W/gw/platd_0.3.0-1_arm64.deb"
mkdir -p "$W/ww/sub"
chmod 0755 "$W/ww/sub"
cp "$W/local/platd_0.3.0-1_arm64.deb" "$W/local/SHA256SUMS" "$W/local/SHA256SUMS.sigstore.json" "$W/ww/sub/"
expect "local .deb below a world-writable ancestor refused" 1 hook \
    "platd - - none < 0.3.0-1 arm64 none $W/ww/sub/platd_0.3.0-1_arm64.deb"
expect "dot-dot path refused" 1 hook \
    "platd - - none < 0.3.0-1 arm64 none $W/ww/../local/platd_0.3.0-1_arm64.deb"
check "root-only refusals never call cosign" no_cosign_call
chmod 0777 "$W/arch"
expect "archives directory that is world-writable refused" 1 hook \
    "platd - - none < 0.3.0-1 amd64 none $W/arch/platd_0.3.0-1_amd64.deb"
chmod 0755 "$W/arch"
chmod 0755 "$W/ww" "$W/sticky"

# --- apt-hook: paths with spaces (SEC-005) ------------------------------------------
mkdir -p "$W/sp ace"
cp "$W/arch/evil_1.0_amd64.deb" "$W/sp ace/evil_1.0_amd64.deb"
cp "$W/arch/platd_0.3.0-1_amd64.deb" "$W/sp ace/platd_0.3.0-1_amd64.deb"
reset
expect "foreign name, path with spaces, carrying our package refused" 1 hook \
    "evil - - none < 1.0 amd64 none $W/sp ace/evil_1.0_amd64.deb"
reason "shadow found through the space" 'contains platd'
expect "foreign name, unparseable path with spaces refused" 1 hook \
    "libfoo - - none < 1.0 amd64 none $W/no such/libfoo_1.0_amd64.deb"
expect "our name, path with spaces refused" 1 hook \
    "platd - - none < 0.3.0-1 amd64 none $W/sp ace/platd_0.3.0-1_amd64.deb"
cp "$W/arch/libfoo_1.0_amd64.deb" "$W/sp ace/libfoo_1.0_amd64.deb"
expect "foreign name, path with spaces, foreign package passes" 0 hook \
    "libfoo - - none < 1.0 amd64 none $W/sp ace/libfoo_1.0_amd64.deb"
no_newline_hook() { printf 'VERSION 3\n\nevil - - none < 1.0 amd64 none %s' "$W/arch/evil_1.0_amd64.deb" | "$W/libexec/apt-hook"; }
expect "last line without a newline is still checked" 1 no_newline_hook

# --- configuration and trust root ownership (SEC-008) --------------------------------
reset
chmod g+w "$W/verify.conf"
expect "group-writable verify.conf: verify-pkg exit 2" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
expect "group-writable verify.conf: apt-hook refuses" 1 hook \
    "platd - - none < 0.3.0-1 amd64 none $W/arch/platd_0.3.0-1_amd64.deb"
expect "group-writable verify.conf: fetch-sums exit 2" 2 env USG_PLAT_VERIFY_STATE="$W/fs" "$W/libexec/fetch-sums" v0.3.0
expect "group-writable verify.conf: selftest exit 2" 2 "$W/libexec/selftest" --apt
check "conf refusals never call cosign" no_cosign_call
chmod 0644 "$W/verify.conf"
mkdir -p "$W/cdir"
chmod 0777 "$W/cdir"
cp "$W/verify.conf" "$W/cdir/verify.conf"
expect "verify.conf in a world-writable directory: exit 2" 2 env USG_PLAT_VERIFY_CONF="$W/cdir/verify.conf" "$W/libexec/verify-pkg" --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
chmod 0755 "$W/cdir"
chmod o+w "$W/trusted_root.json"
expect "other-writable trusted root: exit 2" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
chmod 0644 "$W/trusted_root.json"
if [ "$(id -u)" = 0 ]; then
    chown 65534 "$W/verify.conf"
    expect "verify.conf owned by another uid: exit 2" 2 vp --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
    chown 0 "$W/verify.conf"
else
    echo "skip foreign-owner verify.conf case (not root)"
fi

# --- test hooks only in test mode (SEC-003) ------------------------------------------
reset
expect "overrides ignored without USG_PLAT_VERIFY_TEST=1" 2 env -u USG_PLAT_VERIFY_TEST \
    TMPDIR=/tmp USG_PLAT_VERIFY_CONF=/nonexistent/verify.conf "$W/libexec/verify-pkg" --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reason "ignored overrides are named" 'ignoring test-only environment.*USG_PLAT_VERIFY_CONF'
reason "TMPDIR is named too" 'ignoring test-only environment.*TMPDIR'
reason "the shipped configuration path is used" '/etc/usg-plat-verify/verify.conf'
check "overrides ignored: stand-in cosign never ran" no_cosign_call
expect "USG_PLAT_VERIFY_TEST=0 is not test mode" 2 env USG_PLAT_VERIFY_TEST=0 "$W/libexec/verify-pkg" --name platd --version 0.3.0-1 --arch amd64 --sha256 "$H_AMD"
reason "TEST=0 ignores overrides" 'ignoring test-only environment'
reset
expect "USG_PLAT_ALLOW_DOWNGRADE=1 is logged" 0 env USG_PLAT_ALLOW_DOWNGRADE=1 STUB_SIGNED_TAG=v0.2.1 "$W/libexec/apt-hook" <<EOF
$(hook_in "platd 0.3.0-1 amd64 none > 0.2.1-1 amd64 none $W/arch/platd_0.2.1-1_amd64.deb")
EOF
check "override logged at authpriv.warning" grep -q 'authpriv.warning.*USG_PLAT_ALLOW_DOWNGRADE=1' "$STUB_LOG"
check "allowed downgrade logged" grep -q 'authpriv.warning.*downgrade of platd' "$STUB_LOG"
# The common block is byte-identical in every script.
common_of() { sed -n '/^# >>> common:/,/^# <<< common$/p' "$1"; }
common_same() {
    ref=$(common_of "$src/libexec/verify-pkg")
    [ -n "$ref" ] || return 1
    for f in "$src/libexec/apt-hook" "$src/libexec/fetch-sums" "$src/libexec/selftest" "$src/bin/usg-plat-verify"; do
        [ "$(common_of "$f")" = "$ref" ] || { echo "common block differs in $f" >&2; return 1; }
    done
}
# The package scripts carry the same block (the spec doubles each % for rpm).
common_pkg() {
    ref=$(common_of "$src/libexec/verify-pkg")
    [ "$(common_of "$src/debian/postinst")" = "$ref" ] || { echo "common block differs in debian/postinst" >&2; return 1; }
    [ "$(common_of "$src/rpm/usg-plat-verify.spec" | sed 's/%%/%/g')" = "$ref" ] ||
        { echo "common block differs in rpm/usg-plat-verify.spec" >&2; return 1; }
}
check "common block identical in postinst and %post" common_pkg
exec_of() { sed -n '/^# >>> common-exec/,/^# <<< common-exec/p' "$1"; }
exec_same() {
    ref=$(exec_of "$src/libexec/verify-pkg")
    [ -n "$ref" ] || return 1
    for f in "$src/libexec/selftest" "$src/debian/postinst"; do
        [ "$(exec_of "$f")" = "$ref" ] || { echo "common-exec block differs in $f" >&2; return 1; }
    done
    [ "$(exec_of "$src/rpm/usg-plat-verify.spec" | sed 's/%%/%/g')" = "$ref" ] ||
        { echo "common-exec block differs in the spec" >&2; return 1; }
}
check "common-exec block identical where cosign is checked" exec_same
check "common block identical in all gate scripts" common_same

# --- selftest --apt --------------------------------------------------------------
good_sources() {
    printf 'Types: deb\nURIs: %s\nSuites: stable\nComponents: main\nTrusted: yes\n' \
        "${1:-https://192d-wing.github.io/usg-plat-packages/apt}" >"$W/apt/usg-plat.sources"
}
good_pref() {
    o=${1-192d-wing.github.io}
    printf 'Package: *\nPin: origin "%s"\nPin-Priority: -1\n\nPackage: platd usg-plat-verify\nPin: origin "%s"\nPin-Priority: 500\n' \
        "$o" "$o" >"$W/apt/usg-plat.pref"
}
canary() { # candidate
    printf 'usg-plat-pin-canary:\n  Installed: (none)\n  Candidate: %s\n  Version table:\n     0.0.0 -1\n        -1 https://192d-wing.github.io/usg-plat-packages/apt stable/main all Packages\n' \
        "$1" >"$W/pol/usg-plat-pin-canary"
}
platd_policy() { # prio [source-uri]
    printf 'platd:\n  Installed: 0.2.1-1\n  Candidate: 0.3.0-1\n  Version table:\n     0.3.0-1 %s\n        -1 %s stable/main amd64 Packages\n *** 0.2.1-1 100\n        100 /var/lib/dpkg/status\n' \
        "$1" "${2:-https://192d-wing.github.io/usg-plat-packages/apt}" >"$W/pol/platd"
}
st() { "$W/libexec/selftest" --apt; }
reset
good_sources
good_pref
canary '(none)'
platd_policy 500
expect "selftest passes with the shipped layout" 0 st
cp "$src/apt/usg-plat.sources" "$W/apt/usg-plat.sources"
cp "$src/apt/usg-plat.pref" "$W/apt/usg-plat.pref"
expect "selftest passes on the shipped files" 0 st
good_sources
good_pref 'https://192d-wing.github.io'
expect "origin with a scheme fails" 1 st
good_pref '192d-wing.github.io:443'
expect "origin with a port fails" 1 st
good_pref '192D-Wing.github.io'
expect "origin in upper case fails" 1 st
good_pref
good_sources https://example.invalid/apt
expect "sources host differs from REPO_HOST" 1 st
good_sources http://192d-wing.github.io/usg-plat-packages/apt  # NOSONAR S5332: negative test, clear-text URL must be refused
expect "sources not https" 1 st
good_sources https://192D-WING.github.io:443/usg-plat-packages/apt
expect "sources host compared lowercased, port ignored" 0 st
good_sources https://192d-wing.github.io.example.invalid/apt
expect "sources host with REPO_HOST as a prefix fails" 1 st
# Offline mirror on file: (apt gives it an empty origin).
good_sources file:/srv/usg-plat/apt
good_pref ''
platd_policy 500 file:/srv/usg-plat/apt
expect "file: source with origin \"\" passes" 0 st
good_sources file:///srv/usg-plat/apt
expect "file:/// source with origin \"\" passes" 0 st
good_pref
expect "file: source with origin REPO_HOST fails" 1 st
good_pref ''
platd_policy -1 file:/srv/usg-plat/apt
expect "file: source with platd at -1 fails" 1 st
platd_policy 500
expect "file: source, platd only from https in the indexes, fails" 1 st
platd_policy 500 file:/srv/usg-plat/apt
good_sources file://mirror.example.invalid/apt
expect "file: URI with a host fails" 1 st
good_sources http://192d-wing.github.io/usg-plat-packages/apt  # NOSONAR S5332: negative test, clear-text URL must be refused
expect "http: source with origin \"\" fails" 1 st
good_sources 'https://192d-wing.github.io/usg-plat-packages/apt file:/srv/usg-plat/apt'
expect "mixed https and file: sources fail" 1 st
good_pref
expect "mixed https and file: sources fail (REPO_HOST origin)" 1 st
platd_policy 500
good_sources https://mirror.example.invalid/usg-plat/apt
expect "https mirror on a host other than REPO_HOST fails" 1 st
good_sources
canary '0.0.0'
expect "canary with a candidate fails" 1 st
rm -f "$W/pol/usg-plat-pin-canary"
expect "canary absent from the indexes fails" 1 st
canary '(none)'
platd_policy -1
expect "platd pinned at -1 fails" 1 st
rm -f "$W/pol/platd"
expect "platd absent from the indexes fails" 1 st
platd_policy 500
check "selftest failure logged at authpriv.err" grep -q -- '-p authpriv.err' "$STUB_LOG"
reset
write_conf 'REPO_HOST=https://192d-wing.github.io'
expect "REPO_HOST with a scheme is a config error" 2 st
reset
expect "selftest usage" 2 "$W/libexec/selftest"

# --- selftest --dnf --------------------------------------------------------------
reset
cat >"$W/apt/usg-plat.repo" <<'EOF'
[usg-plat]
baseurl=https://192d-wing.github.io/usg-plat-packages/rpm/$basearch
includepkgs=platd usg-plat-verify
EOF
printf '[main]\nenabled=1\n' >"$W/apt/plugin.conf"
cat >"$W/stub/dnf" <<'EOF'
#!/bin/sh
echo "Loaded plugins: builddep, ${STUB_DNF_PLUGINS:-usg_plat_verify}"
EOF
chmod 0755 "$W/stub/dnf"
std() { USG_PLAT_VERIFY_DNF_REPO="$W/apt/usg-plat.repo" USG_PLAT_VERIFY_DNF_PLUGIN_CONF="$W/apt/plugin.conf" "$W/libexec/selftest" --dnf; }
expect "selftest --dnf passes with the plugin loaded" 0 std
sed -i.bak "s|^baseurl=.*|baseurl=file:///srv/usg-plat/rpm/\$basearch|" "$W/apt/usg-plat.repo"
expect "selftest --dnf accepts a file:/// mirror" 0 std
sed -i.bak 's|^baseurl=.*|baseurl=file://mirror.example.invalid/rpm|' "$W/apt/usg-plat.repo"
expect "selftest --dnf refuses file://host" 1 std
sed -i.bak 's|^baseurl=.*|baseurl=http://192d-wing.github.io/usg-plat-packages/rpm|' "$W/apt/usg-plat.repo"  # NOSONAR S5332: negative test, clear-text URL must be refused
expect "selftest --dnf refuses http:" 1 std
sed -i.bak 's|^baseurl=.*|baseurl=https://example.invalid/rpm|' "$W/apt/usg-plat.repo"
expect "selftest --dnf refuses https on another host" 1 std
sed -i.bak "s|^baseurl=.*|baseurl=https://192d-wing.github.io/usg-plat-packages/rpm/\$basearch|" "$W/apt/usg-plat.repo"
STUB_DNF_PLUGINS=copr
export STUB_DNF_PLUGINS
expect "selftest --dnf fails when dnf did not load the plugin" 1 std
unset STUB_DNF_PLUGINS
rm -f "$W/stub/dnf"

# --- fetch-sums ----------------------------------------------------------------
reset
mkdir -p "$W/fs"
expect "fetch-sums from a file:// base" 0 env USG_PLAT_VERIFY_STATE="$W/fs" "$W/libexec/fetch-sums" 0.3.0-1 v0.2.1 junk
check "fetched v0.3.0 sums" cmp -s "$W/fs/releases/v0.3.0/SHA256SUMS" "$W/rel/v0.3.0/SHA256SUMS"
check "fetched v0.2.1 bundle" [ -f "$W/fs/releases/v0.2.1/SHA256SUMS.sigstore.json" ]
expect "fetch-sums missing release fails" 1 env USG_PLAT_VERIFY_STATE="$W/fs" "$W/libexec/fetch-sums" v9.9.9
ls -a "$W/fs/releases" >"$W/ls.out"
check "no partial directory left" absent part "$W/ls.out"
check "no v9.9.9 directory" [ ! -e "$W/fs/releases/v9.9.9" ]
write_conf 'REPO_BASE=http://192d-wing.github.io/usg-plat-packages'  # NOSONAR S5332: negative test, clear-text URL must be refused
expect "fetch-sums refuses http" 2 env USG_PLAT_VERIFY_STATE="$W/fs" "$W/libexec/fetch-sums" v0.3.0
reset
expect "fetch-sums with no args uses apt policy" 0 env USG_PLAT_VERIFY_STATE="$W/fs" "$W/libexec/fetch-sums"

# --- usg-plat-verify -----------------------------------------------------------
reset
expect "usg-plat-verify verify FILE (cache)" 0 "$src/bin/usg-plat-verify" verify "$W/arch/platd_0.3.0-1_amd64.deb"
expect "usg-plat-verify verify FILE (sibling sums)" 0 "$src/bin/usg-plat-verify" verify "$W/local/platd_0.3.0-1_arm64.deb"
expect "usg-plat-verify verify tampered FILE" 1 "$src/bin/usg-plat-verify" verify "$W/arch/evil_1.0_amd64.deb"
expect "usg-plat-verify status" 0 "$src/bin/usg-plat-verify" status
expect "usg-plat-verify usage" 2 "$src/bin/usg-plat-verify" frobnicate

# --- source checks -------------------------------------------------------------
check "no regexp identity flag in the gate" absent_r certificate-identity-regexp "$src/libexec" "$src/bin"
check "no offline flag in the gate" absent_r --offline "$src/libexec" "$src/bin"
if command -v shellcheck >/dev/null 2>&1; then
    check "shellcheck clean" sc_clean deploy/verify/libexec/verify-pkg deploy/verify/libexec/apt-hook \
        deploy/verify/libexec/fetch-sums deploy/verify/libexec/selftest deploy/verify/bin/usg-plat-verify \
        deploy/tests/verify/unit.sh
elif [ "${CI:-}" = true ]; then
    bad "shellcheck is required in CI"
else
    echo "skip shellcheck (not installed)"
fi

echo "unit.sh: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
