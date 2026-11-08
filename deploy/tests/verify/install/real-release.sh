#!/bin/sh
# Real-cosign leg of the install-time gate tests: upstream cosign v3.1.4
# (SHA-256 pinned) verifies the real published v0.3.0 release through the
# installed usg-plat-verify (verify-pkg and `usg-plat-verify verify`) with
# the shipped, pinned trusted_root.json, in a container with --network none.
#
#   real-release.sh [--engine podman|docker] [--assets DIR] [--work DIR] [DISTRO...]
#   real-release.sh --fetch-cosign DIR     download + check cosign, print its path
#   real-release.sh --inside               (in the container; used by the above)
#
# DISTRO: debian12 ubuntu2404 rocky9 rocky10 (default: all). Only the gate
# decision is tested (accept / refuse): the v0.3.0 platd packages need
# glibc 2.38/2.39 and do not install on Debian 12 or EL9 until the separate
# glibc-floor change lands, so no platd package is installed here.
#
# Inputs: target/verify/usg-plat-verify_<v>-1_all.deb and .noarch.rpm
# (`make verify-pkg`, or USG_PLAT_VERIFY_PKG_DIR); the release assets are
# downloaded from GitHub unless --assets names a directory that has them.
# PLAT_TOOL_CACHE=DIR reuses a verified cosign download (CI actions/cache).
#
# Exit: 0 all cases passed; 1 a case failed; 2 usage or environment.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-11 (Developer Testing), SI-7(15) (Code Authentication),
#   CM-14 (Signed Components), SR-11 (Component Authenticity) - the shipped
#   gate accepts the real signed release offline and refuses tampering, a
#   wrong identity, a wrong trust root and a missing cosign (POAM-044 (c))
set -u

COSIGN_VERSION=v3.1.4
COSIGN_SHA256_AMD64=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
COSIGN_SHA256_ARM64=ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2
TAG=v0.3.0
REL=0.3.0-1
RELEASE_URL=https://github.com/192d-Wing/usg-plat/releases/download/$TAG
ASSETS="SHA256SUMS SHA256SUMS.sigstore.json platd_${REL}_amd64.deb platd_${REL}_arm64.deb platd-${REL}.x86_64.rpm platd-${REL}.aarch64.rpm"

# Images pinned by the multi-arch index digest (same pins as run.sh).
image_of() {
    case $1 in
        debian12) echo docker.io/library/debian@sha256:268fb24c39bca92d326dd83ea3abebe4a3f7751c804ffef23bb6d857dd343ff8 ;;
        ubuntu2404) echo docker.io/library/ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852 ;;
        rocky9) echo docker.io/rockylinux/rockylinux@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f ;;
        rocky10) echo docker.io/rockylinux/rockylinux@sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834 ;;
        *) die "unknown distro $1" ;;
    esac
}

die() { echo "real-release: $1" >&2; exit "${2:-2}"; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | cut -d' ' -f1
    else
        shasum -a 256 -- "$1" | cut -d' ' -f1
    fi
}

# The container engine runs Linux on the host CPU (podman machine on macOS too).
host_arch() {
    case $(uname -m) in
        arm64 | aarch64) echo arm64 ;;
        x86_64 | amd64) echo amd64 ;;
        *) die "unsupported CPU $(uname -m)" ;;
    esac
}

# fetch_cosign DIR: DIR/cosign-linux-<arch>, SHA-256 checked (cache first).
fetch_cosign() {
    a=$(host_arch)
    if [ "$a" = arm64 ]; then want=$COSIGN_SHA256_ARM64; else want=$COSIGN_SHA256_AMD64; fi
    asset=cosign-linux-$a
    mkdir -p "$1" || die "cannot create $1"
    dst=$1/$asset
    if [ -f "$dst" ] && [ "$(sha256_of "$dst")" = "$want" ]; then
        echo "$dst"
        return 0
    fi
    cache=${PLAT_TOOL_CACHE:-}
    cached=$cache/cosign-$COSIGN_VERSION-$a
    if [ -n "$cache" ] && [ -f "$cached" ] && [ "$(sha256_of "$cached")" = "$want" ]; then
        cp -- "$cached" "$dst.part" && mv -f -- "$dst.part" "$dst"
        echo "real-release: cosign cache hit $cached" >&2
    else
        echo "real-release: fetching cosign $COSIGN_VERSION $asset" >&2
        curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 30 --retry 6 --retry-delay 10 \
            --retry-all-errors -o "$dst.part" \
            "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/$asset" ||
            die "cosign download failed" 1
        got=$(sha256_of "$dst.part")
        [ "$got" = "$want" ] || { rm -f -- "$dst.part"; die "cosign sha256 mismatch: got $got, want $want" 1; }
        mv -f -- "$dst.part" "$dst"
        if [ -n "$cache" ]; then
            mkdir -p "$cache" && cp -- "$dst" "$cached.tmp" && mv -f -- "$cached.tmp" "$cached"
        fi
    fi
    [ "$(sha256_of "$dst")" = "$want" ] || die "cosign sha256 mismatch after copy" 1
    chmod 0755 "$dst"
    echo "$dst"
}

# ---------------------------------------------------------------------------------
# Inside the container.
# ---------------------------------------------------------------------------------
inside() {
    OUT=/out
    RES=$OUT/results.txt
    : >"$RES"
    npass=0 nfail=0
    rec() { # PASS|FAIL id detail
        printf '%s %s %s\n' "$1" "$2" "$3" | tee -a "$RES"
        if [ "$1" = PASS ]; then npass=$((npass + 1)); else nfail=$((nfail + 1)); fi
    }
    # expect ID WANT(0|1|nz) GREP CMD...: exit status and an output pattern.
    expect() {
        id=$1 want=$2 pat=$3
        shift 3
        "$@" >"$OUT/$id.log" 2>&1
        rc=$?
        case $want in
            nz) [ $rc -ne 0 ] ;;
            *) [ $rc -eq "$want" ] ;;
        esac || { rec FAIL "$id" "exit $rc, want $want: $(tail -n 1 "$OUT/$id.log")"; return 1; }
        if [ -n "$pat" ] && ! grep -Eq -- "$pat" "$OUT/$id.log"; then
            rec FAIL "$id" "exit $rc but no /$pat/: $(tail -n 1 "$OUT/$id.log")"
            return 1
        fi
        rec PASS "$id" "exit $rc"
    }
    vp=/usr/libexec/usg-plat-verify/verify-pkg
    h() { sha256sum -- "$1" | cut -d' ' -f1; }

    # R00: no network in this container.
    if getent hosts github.com >/dev/null 2>&1; then
        rec FAIL R00-no-network "github.com resolves"
    else
        rec PASS R00-no-network "--network none"
    fi
    # Install the gate as shipped (bootstrap path: dpkg -i / rpm -i).
    if command -v dpkg >/dev/null 2>&1; then
        expect R01-install-gate 0 '' dpkg -i /verify/usg-plat-verify_*-1_all.deb
        own=/assets/platd_${REL}_$(dpkg --print-architecture).deb
    else
        if ! expect R01-install-gate 0 '' rpm -i /verify/usg-plat-verify-*-1.noarch.rpm; then
            # R01 stays FAILED; install without the dependency check so the
            # gate decisions below are still exercised.
            rpm -i --nodeps /verify/usg-plat-verify-*-1.noarch.rpm >"$OUT/R01-nodeps.log" 2>&1
        fi
        own=/assets/platd-${REL}.$(uname -m).rpm
    fi
    install -m 0755 /cosign/cosign /usr/local/bin/cosign
    expect R02-cosign-version 0 'GitVersion: +v3\.1\.4' /usr/local/bin/cosign version
    if grep -qx 'COSIGN_GODEBUG=fips140=only' /etc/usg-plat-verify/verify.conf; then
        rec PASS R03-godebug-fips140-only "default verify.conf"
    else
        rec FAIL R03-godebug-fips140-only "COSIGN_GODEBUG is not fips140=only"
    fi

    export USG_PLAT_VERIFY_SUMS_DIR=/assets
    expect R04-accept-deb-amd64 0 'accepted platd_' $vp --name platd --version $REL --arch amd64 \
        --sha256 "$(h "/assets/platd_${REL}_amd64.deb")"
    expect R05-accept-deb-arm64 0 'accepted platd_' $vp --name platd --version $REL --arch arm64 \
        --sha256 "$(h "/assets/platd_${REL}_arm64.deb")"
    expect R06-accept-rpm-x86_64 0 'accepted platd-' $vp --name platd --version $REL --arch x86_64 \
        --sha256 "$(h "/assets/platd-${REL}.x86_64.rpm")"
    expect R07-accept-rpm-aarch64 0 'accepted platd-' $vp --name platd --version $REL --arch aarch64 \
        --sha256 "$(h "/assets/platd-${REL}.aarch64.rpm")"
    unset USG_PLAT_VERIFY_SUMS_DIR
    expect R08-usg-plat-verify-verify 0 'accepted platd' /usr/sbin/usg-plat-verify verify "$own"

    # Refusals. Each works on private copies in /tmp (the assets are read-only).
    mkdir -p /tmp/r-sums /tmp/r-tag
    cp /assets/SHA256SUMS /assets/SHA256SUMS.sigstore.json /tmp/r-sums/
    printf '%064d  platd_%s_amd64.deb\n' 0 "$REL" >>/tmp/r-sums/SHA256SUMS
    expect R09-refuse-tampered-sums 1 'does not verify' env USG_PLAT_VERIFY_SUMS_DIR=/tmp/r-sums \
        $vp --name platd --version $REL --arch arm64 --sha256 "$(h "/assets/platd_${REL}_arm64.deb")"
    tampered=$({ cat "/assets/platd_${REL}_arm64.deb"; printf x; } | sha256sum | cut -d' ' -f1)
    expect R10-refuse-tampered-package 1 'not in the verified SHA256SUMS' env USG_PLAT_VERIFY_SUMS_DIR=/assets \
        $vp --name platd --version $REL --arch arm64 --sha256 "$tampered"
    expect R11-refuse-other-file-name 1 'under another file name' env USG_PLAT_VERIFY_SUMS_DIR=/assets \
        $vp --name platd --version $REL --arch amd64 --sha256 "$(h "/assets/platd_${REL}_arm64.deb")"
    cp /assets/SHA256SUMS /assets/SHA256SUMS.sigstore.json /tmp/r-tag/
    expect R12-refuse-wrong-tag-identity 1 'does not verify' env USG_PLAT_VERIFY_SUMS_DIR=/tmp/r-tag \
        $vp --name platd --version 0.2.1-1 --arch arm64 --sha256 "$(h "/assets/platd_${REL}_arm64.deb")"
    # The USG_PLAT_VERIFY_TRUSTED_ROOT override is test-only (ignored without
    # USG_PLAT_VERIFY_TEST=1, POAM044-SEC-003), so swap the installed,
    # root-owned trust root itself and put it back afterwards.
    tr=/usr/share/usg-plat-verify/trusted_root.json
    cp -p "$tr" /root/trusted_root.json.orig
    printf '{}\n' >"$tr"
    expect R13-refuse-wrong-trust-root 1 'does not verify' env USG_PLAT_VERIFY_SUMS_DIR=/assets \
        $vp --name platd --version $REL --arch arm64 --sha256 "$(h "/assets/platd_${REL}_arm64.deb")"
    cp -p /root/trusted_root.json.orig "$tr"
    mv /usr/local/bin/cosign /usr/local/bin/cosign.off
    expect R14-refuse-missing-cosign 1 'cosign not found' env USG_PLAT_VERIFY_SUMS_DIR=/assets \
        $vp --name platd --version $REL --arch arm64 --sha256 "$(h "/assets/platd_${REL}_arm64.deb")"
    mv /usr/local/bin/cosign.off /usr/local/bin/cosign
    if grep -q 'cosign not found' /var/lib/usg-plat-verify/last-refusal; then
        rec PASS R15-last-refusal "written"
    else
        rec FAIL R15-last-refusal "not written"
    fi

    echo "real-release: $npass passed, $nfail failed" | tee -a "$RES"
    [ $nfail -eq 0 ]
}

# ---------------------------------------------------------------------------------
# Host driver.
# ---------------------------------------------------------------------------------
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
engine='' assets='' work=''
distros=''
while [ $# -gt 0 ]; do
    case $1 in
        --inside) inside; exit $? ;;
        --fetch-cosign) [ $# -eq 2 ] || die "usage: real-release.sh --fetch-cosign DIR"; fetch_cosign "$2"; exit $? ;;
        --engine) [ $# -ge 2 ] || die "--engine needs a value"; engine=$2; shift ;;
        --assets) [ $# -ge 2 ] || die "--assets needs a directory"; assets=$2; shift ;;
        --work) [ $# -ge 2 ] || die "--work needs a directory"; work=$2; shift ;;
        debian12 | ubuntu2404 | rocky9 | rocky10) distros="$distros $1" ;;
        -h | --help) sed -n '2,22p' "$0"; exit 0 ;;
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
if ! ls "$vdir"/usg-plat-verify_*-1_all.deb >/dev/null 2>&1 || ! ls "$vdir"/usg-plat-verify-*-1.noarch.rpm >/dev/null 2>&1; then
    die "no usg-plat-verify packages in $vdir (run make verify-pkg)"
fi
vdir=$(cd "$vdir" && pwd)
mkdir -p "$repo/target"
[ -n "$work" ] || work=$(mktemp -d "$repo/target/verify-real.XXXXXX") || die "mktemp failed"
mkdir -p "$work/cosign" || die "cannot create $work"
work=$(cd "$work" && pwd)

cos=$(fetch_cosign "$work/cosign") || exit $?
cp -- "$cos" "$work/cosign/cosign" && chmod 0755 "$work/cosign/cosign"

if [ -z "$assets" ]; then
    assets=$work/assets
    mkdir -p "$assets"
    for f in $ASSETS; do
        [ -f "$assets/$f" ] && continue
        curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 30 --retry 6 --retry-delay 10 \
            --retry-all-errors -o "$assets/$f.part" "$RELEASE_URL/$f" || die "download of $f failed" 1
        mv -f -- "$assets/$f.part" "$assets/$f"
    done
fi
for f in $ASSETS; do [ -f "$assets/$f" ] || die "$assets/$f missing"; done
assets=$(cd "$assets" && pwd)

status=0
summary=''
for d in $distros; do
    img=$(image_of "$d")
    mkdir -p "$work/out-$d"
    echo "real-release: === $d ($img)"
    # usg-plat-verify depends on an https client (curl | wget) and
    # ca-certificates, which the apt base images lack: add them with network
    # in a prep container, then run the cases from that image without network.
    prep=usg-plat-real-prep-$d-$$
    # shellcheck disable=SC2016 # expanded by sh -c inside the container
    case $d in
        debian*|ubuntu*) pcmd='apt-get ${APT_OPTS:-} update && apt-get ${APT_OPTS:-} install -y --no-install-recommends curl ca-certificates' ;;
        *) pcmd='command -v curl >/dev/null' ;;
    esac
    if ! "$engine" run --name "$prep" -e APT_OPTS="${APT_OPTS:-}" -e DEBIAN_FRONTEND=noninteractive \
        "$img" sh -c "$pcmd" >"$work/out-$d/prep.log" 2>&1 ||
        ! "$engine" commit "$prep" "localhost/$prep:latest" >>"$work/out-$d/prep.log" 2>&1; then
        "$engine" rm -f "$prep" >/dev/null 2>&1
        die "prerequisites for $d failed (see $work/out-$d/prep.log)"
    fi
    "$engine" rm -f "$prep" >/dev/null 2>&1
    "$engine" run --rm --network none \
        -v "$repo:/src:ro" -v "$vdir:/verify:ro" -v "$assets:/assets:ro" \
        -v "$work/cosign:/cosign:ro" -v "$work/out-$d:/out" \
        "localhost/$prep:latest" sh /src/deploy/tests/verify/install/real-release.sh --inside
    rc=$?
    "$engine" rmi -f "localhost/$prep:latest" >/dev/null 2>&1
    [ $rc -eq 0 ] || status=1
    summary="$summary
$d: $(tail -n 1 "$work/out-$d/results.txt" 2>/dev/null || echo 'no results') (exit $rc)"
done
echo "real-release: results in $work$summary"
exit $status
