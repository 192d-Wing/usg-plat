#!/bin/sh
# Build the usg-plat-verify packages (install-time signature gate):
#
#   target/verify/usg-plat-verify_<ver>-1_all.deb   (dpkg-deb --root-owner-group)
#   target/verify/usg-plat-verify-<ver>-1.noarch.rpm (rpmbuild -bb)
#
#   build.sh [--deb|--rpm] [--src DIR] [--out DIR] [--trusted-root FILE]
#   build.sh --self-test       builds from placeholder files in a temp dir
#
# <ver> is the workspace version (Cargo.toml [workspace.package]). The
# trusted root (default target/verify/trusted_root.json, written by
# trusted-root.sh) is refused unless its SHA-256 equals trusted_root.sha256.
# Every package is inspected after the build (dpkg-deb -c / rpm -qlpv): its
# regular files, modes, owners and conffiles must equal the plan-v3 §2 table.
# The package holds only shell, python and data: no binary and no crypto, so
# it is outside the cargo graph, the SBOM's Rust components and the CBOM.
#
# Exit: 0 ok, 1 build or inspection failure, 2 usage or missing input.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SI-7(15) (Code Authentication), CM-14 (Signed Components) -
#   packages the gate; SR-11 - the bundled trust root is the reviewed pin
# - NIST 800-53: CM-2 (Baseline Configuration) - contents checked against a
#   fixed manifest on every build
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
SRC=$here
OUT=$repo/target/verify
TROOT=
PIN=$here/trusted_root.sha256
do_deb=1
do_rpm=1

die() { echo "verify-build: $*" >&2; exit 2; }
fail() { echo "verify-build: FAILED: $*" >&2; exit 1; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | cut -d' ' -f1
    else
        shasum -a 256 -- "$1" | cut -d' ' -f1
    fi
}

workspace_version() {
    v=$(awk '/^\[workspace\.package\]/ { s = 1; next } /^\[/ { s = 0 }
        s && /^version *= *"/ { gsub(/^version *= *"|".*$/, ""); print; exit }' "$repo/Cargo.toml")
    printf '%s\n' "$v" | grep -qx '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' ||
        die "cannot read the workspace version from $repo/Cargo.toml (got '$v')"
    printf '%s\n' "$v"
}

# Manifest: "<mode> <source under SRC> <installed path>", one per line.
# Units A (libexec, bin, etc, apt) and B (dnf) own the sources; this script
# only packages them. Plan-v3 §2 is the authority for the installed paths.
COMMON='755 libexec/verify-pkg /usr/libexec/usg-plat-verify/verify-pkg
755 libexec/fetch-sums /usr/libexec/usg-plat-verify/fetch-sums
755 libexec/selftest /usr/libexec/usg-plat-verify/selftest
755 bin/usg-plat-verify /usr/sbin/usg-plat-verify
644 etc/verify.conf /etc/usg-plat-verify/verify.conf
644 trusted_root.json /usr/share/usg-plat-verify/trusted_root.json'
DEB_ONLY='755 libexec/apt-hook /usr/libexec/usg-plat-verify/apt-hook
644 apt/50usg-plat-verify /etc/apt/apt.conf.d/50usg-plat-verify
644 apt/usg-plat.sources /etc/apt/sources.list.d/usg-plat.sources
644 apt/usg-plat.pref /etc/apt/preferences.d/usg-plat'
# The rpm installs the plugin once per supported platform python (see spec).
RPM_ONLY='644 dnf/usg_plat_verify.py /usr/lib/python3.9/site-packages/dnf-plugins/usg_plat_verify.py
644 dnf/usg_plat_verify.py /usr/lib/python3.12/site-packages/dnf-plugins/usg_plat_verify.py
644 dnf/usg_plat_verify.conf /etc/dnf/plugins/usg_plat_verify.conf
644 dnf/usg-plat.repo /etc/yum.repos.d/usg-plat.repo'
RPM_CONF='/etc/dnf/plugins/usg_plat_verify.conf
/etc/usg-plat-verify/verify.conf
/etc/yum.repos.d/usg-plat.repo'

perm_string() {
    case $1 in
        755) echo '-rwxr-xr-x' ;;
        644) echo '-rw-r--r--' ;;
        *) die "manifest mode $1 not supported" ;;
    esac
}

# Fail clearly when a unit's file is not in the tree yet.
check_sources() { # check_sources MANIFEST
    missing=
    while read -r _ src _; do
        [ "$src" = trusted_root.json ] && continue
        [ -f "$SRC/$src" ] || missing="$missing $SRC/$src"
    done <<EOF
$1
EOF
    [ -z "$missing" ] || die "missing package sources (units A/B):$missing"
}

expected_listing() { # expected_listing MANIFEST -> "perm owner path", sorted
    while read -r mode _ dst; do
        printf '%s root/root %s\n' "$(perm_string "$mode")" "$dst"
    done <<EOF
$1
EOF
}

compare() { # compare WHAT EXPECTED_FILE GOT_FILE
    if ! diff -u "$2" "$3" >&2; then
        fail "$1 differs from the manifest (- expected, + package)"
    fi
}

stage() { # stage MANIFEST ROOT
    while read -r mode src dst; do
        if [ "$src" = trusted_root.json ]; then from=$TROOT; else from=$SRC/$src; fi
        mkdir -p "$2$(dirname "$dst")"
        cp -- "$from" "$2$dst"
        chmod "0$mode" "$2$dst"
    done <<EOF
$1
EOF
}

build_deb() {
    manifest="$COMMON
$DEB_ONLY"
    check_sources "$manifest"
    command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb not found (apt-get install dpkg-dev)"
    root="$work/deb"
    mkdir -p "$root/DEBIAN"
    stage "$manifest" "$root"
    sed "s/@VERSION@/$version/" "$here/debian/control.in" >"$root/DEBIAN/control"
    cp -- "$here/debian/conffiles" "$root/DEBIAN/conffiles"
    for s in postinst prerm; do
        cp -- "$here/debian/$s" "$root/DEBIAN/$s"
        chmod 0755 "$root/DEBIAN/$s"
    done
    chmod 0644 "$root/DEBIAN/control" "$root/DEBIAN/conffiles"
    find "$root" -type d -exec chmod 0755 {} +
    find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} + 2>/dev/null || true
    deb="$OUT/usg-plat-verify_${version}-1_all.deb"
    dpkg-deb --root-owner-group -Zxz -b "$root" "$deb" >/dev/null

    # Inspect what was built, not what was staged.
    [ "$(dpkg-deb -f "$deb" Package)" = usg-plat-verify ] || fail "deb Package field"
    [ "$(dpkg-deb -f "$deb" Version)" = "$version-1" ] || fail "deb Version field"
    [ "$(dpkg-deb -f "$deb" Architecture)" = all ] || fail "deb Architecture field"
    expected_listing "$manifest" | LC_ALL=C sort >"$work/deb.want"
    dpkg-deb -c "$deb" | awk '$1 !~ /^d/ { p = $6; sub(/^\./, "", p); print $1, $2, p }' |
        LC_ALL=C sort >"$work/deb.got"
    compare "deb contents" "$work/deb.want" "$work/deb.got"
    LC_ALL=C sort "$here/debian/conffiles" >"$work/deb.cwant"
    dpkg-deb -I "$deb" conffiles | LC_ALL=C sort >"$work/deb.cgot"
    compare "deb conffiles" "$work/deb.cwant" "$work/deb.cgot"
    echo "verify-build: $deb"
}

build_rpm() {
    manifest="$COMMON
$RPM_ONLY"
    check_sources "$manifest"
    command -v rpmbuild >/dev/null 2>&1 || die "rpmbuild not found (apt-get install rpm)"
    top="$work/rpm"
    mkdir -p "$top/SOURCES/libexec" "$top/SOURCES/bin" "$top/SOURCES/etc" "$top/SOURCES/dnf"
    while read -r _ src _; do
        if [ "$src" = trusted_root.json ]; then from=$TROOT; else from=$SRC/$src; fi
        cp -- "$from" "$top/SOURCES/$src"
    done <<EOF
$manifest
EOF
    rpmbuild -bb --quiet \
        --define "_topdir $top" \
        --define "_sourcedir $top/SOURCES" \
        --define "_rpmdir $top/RPMS" \
        --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
        --define "pkgversion $version" \
        --define "use_source_date_epoch_as_buildtime 1" \
        --define "clamp_mtime_to_source_date_epoch 1" \
        "$here/rpm/usg-plat-verify.spec" >&2
    rpm="$OUT/usg-plat-verify-${version}-1.noarch.rpm"
    [ -f "$top/RPMS/usg-plat-verify-${version}-1.noarch.rpm" ] || fail "rpmbuild did not produce usg-plat-verify-${version}-1.noarch.rpm"
    cp -- "$top/RPMS/usg-plat-verify-${version}-1.noarch.rpm" "$rpm"

    [ "$(rpm -qp --qf '%{NAME} %{VERSION} %{RELEASE} %{ARCH}' "$rpm")" = "usg-plat-verify $version 1 noarch" ] ||
        fail "rpm NAME/VERSION/RELEASE/ARCH"
    expected_listing "$manifest" | LC_ALL=C sort >"$work/rpm.want"
    rpm -qlpv "$rpm" | awk '$1 !~ /^d/ { print $1, $3 "/" $4, $NF }' | LC_ALL=C sort >"$work/rpm.got"
    compare "rpm contents" "$work/rpm.want" "$work/rpm.got"
    printf '%s\n' "$RPM_CONF" | LC_ALL=C sort >"$work/rpm.cwant"
    rpm -qcp "$rpm" | LC_ALL=C sort >"$work/rpm.cgot"
    compare "rpm config files" "$work/rpm.cwant" "$work/rpm.cgot"
    echo "verify-build: $rpm"
}

self_test() {
    t=$(mktemp -d)
    trap 'rm -rf -- "$t"' EXIT INT TERM
    rc=0
    # Placeholder sources for units A and B.
    for f in libexec/verify-pkg libexec/apt-hook libexec/fetch-sums libexec/selftest bin/usg-plat-verify \
        etc/verify.conf apt/50usg-plat-verify apt/usg-plat.sources apt/usg-plat.pref \
        dnf/usg_plat_verify.py dnf/usg_plat_verify.conf dnf/usg-plat.repo; do
        mkdir -p "$t/src/$(dirname "$f")"
        printf '# placeholder %s\n' "$f" >"$t/src/$f"
    done
    printf '{"mediaType": "fixture"}\n' >"$t/root.json"
    printf '%s  trusted_root.json\n' "$(sha256_of "$t/root.json")" >"$t/pin"

    # Missing unit files fail clearly (exit 2, names the file).
    mkdir -p "$t/empty"
    r=0
    VERIFY_PIN="$t/pin" sh "$here/build.sh" --src "$t/empty" --out "$t/out0" --trusted-root "$t/root.json" \
        >"$t/log0" 2>&1 || r=$?
    if [ "$r" = 2 ] && grep -q 'missing package sources' "$t/log0"; then
        echo "ok   missing unit files refused"
    else
        echo "FAIL missing unit files (rc $r)"; cat "$t/log0"; rc=1
    fi
    # A trust root that is not the pin is refused.
    printf 'other\n' >"$t/bad.json"
    r=0
    VERIFY_PIN="$t/pin" sh "$here/build.sh" --src "$t/src" --out "$t/out1" --trusted-root "$t/bad.json" \
        >"$t/log1" 2>&1 || r=$?
    if [ "$r" = 1 ] && grep -q 'trusted root digest' "$t/log1"; then
        echo "ok   unpinned trusted root refused"
    else
        echo "FAIL unpinned trusted root (rc $r)"; cat "$t/log1"; rc=1
    fi
    # Full build and inspection, when the tools exist (required in CI).
    for kind in deb rpm; do
        tool=dpkg-deb
        [ "$kind" = rpm ] && tool=rpmbuild
        if ! command -v "$tool" >/dev/null 2>&1; then
            if [ "${CI:-}" = true ]; then echo "FAIL $tool missing in CI"; rc=1; continue; fi
            echo "skip $kind build ($tool not installed)"
            continue
        fi
        r=0
        VERIFY_PIN="$t/pin" sh "$here/build.sh" "--$kind" --src "$t/src" --out "$t/out" \
            --trusted-root "$t/root.json" >"$t/log-$kind" 2>&1 || r=$?
        if [ "$r" = 0 ]; then
            echo "ok   $kind built and matches the manifest"
        else
            echo "FAIL $kind build (rc $r)"; cat "$t/log-$kind"; rc=1
        fi
    done
    rm -rf -- "$t"
    trap - EXIT INT TERM
    return "$rc"
}

while [ $# -gt 0 ]; do
    case $1 in
        --deb) do_deb=1; do_rpm=0 ;;
        --rpm) do_deb=0; do_rpm=1 ;;
        --src) [ $# -ge 2 ] || die "--src needs a directory"; SRC=$(cd "$2" && pwd); shift ;;
        --out) [ $# -ge 2 ] || die "--out needs a directory"; OUT=$2; shift ;;
        --trusted-root) [ $# -ge 2 ] || die "--trusted-root needs a file"; TROOT=$2; shift ;;
        --self-test) self_test; exit $? ;;
        -h | --help) sed -n '2,18p' "$0"; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done

PIN=${VERIFY_PIN:-$PIN}
[ -n "$TROOT" ] || TROOT=$repo/target/verify/trusted_root.json
[ -f "$TROOT" ] || die "no trusted root at $TROOT (run deploy/verify/trusted-root.sh or make verify-pkg)"
want=$(sed -n 's/^\([0-9a-f]\{64\}\)  trusted_root\.json$/\1/p' "$PIN")
[ -n "$want" ] || die "malformed pin file $PIN"
got=$(sha256_of "$TROOT")
[ "$got" = "$want" ] || fail "trusted root digest $got != pinned $want ($TROOT)"

version=$(workspace_version)
: "${SOURCE_DATE_EPOCH:=$(git -C "$repo" log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT INT TERM
if [ "$do_deb" = 1 ]; then build_deb; fi
if [ "$do_rpm" = 1 ]; then build_rpm; fi
rm -rf -- "$work"
trap - EXIT INT TERM
