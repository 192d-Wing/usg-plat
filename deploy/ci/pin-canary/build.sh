#!/bin/sh
# Build the empty usg-plat-pin-canary packages:
#
#   <out>/usg-plat-pin-canary_0.0.0_all.deb       (dpkg-deb --root-owner-group)
#   <out>/usg-plat-pin-canary-0.0.0-1.noarch.rpm  (rpmbuild -bb)
#
#   build.sh [--out DIR]      default target/verify
#
# The canary must be in every published usg-plat repository, starting with
# the first publish: `usg-plat-verify selftest --apt` requires apt to report
# `Candidate: (none)` for it, so `apt-get update` exits 100 on a repository
# without it (by design). deploy/ci/publish-packages.sh refuses such a tree.
#
# Exit: 0 ok, 1 build or inspection failure, 2 usage or missing tool.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-7 (Least Functionality), CM-14 (Signed Components) -
#   lets the host prove the -1 pin for foreign names matches the origin
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
OUT=$repo/target/verify

die() { echo "pin-canary: $*" >&2; exit 2; }
fail() { echo "pin-canary: FAILED: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case $1 in
        --out) [ $# -ge 2 ] || die "--out needs a directory"; OUT=$2; shift ;;
        -h | --help) sed -n '2,14p' "$0"; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done

command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb not found"
command -v rpmbuild >/dev/null 2>&1 || die "rpmbuild not found (apt-get install rpm)"
# Fixed timestamps: the canary has no content worth dating.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
export SOURCE_DATE_EPOCH
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT INT TERM

mkdir -p "$work/deb/DEBIAN"
cp -- "$here/control" "$work/deb/DEBIAN/control"
chmod 0644 "$work/deb/DEBIAN/control"
find "$work/deb" -type d -exec chmod 0755 {} +
deb=$OUT/usg-plat-pin-canary_0.0.0_all.deb
dpkg-deb --root-owner-group -Zxz -b "$work/deb" "$deb" >/dev/null
[ "$(dpkg-deb -f "$deb" Package)" = usg-plat-pin-canary ] || fail "deb Package field"
[ -z "$(dpkg-deb -c "$deb" | awk '$1 !~ /^d/')" ] || fail "deb is not empty"
echo "pin-canary: $deb"

rpmbuild -bb --quiet \
    --define "_topdir $work/rpm" \
    --define "_rpmdir $work/rpm/RPMS" \
    --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "_buildhost usg-plat-pin-canary" \
    "$here/usg-plat-pin-canary.spec" >&2
rpm=$OUT/usg-plat-pin-canary-0.0.0-1.noarch.rpm
cp -- "$work/rpm/RPMS/usg-plat-pin-canary-0.0.0-1.noarch.rpm" "$rpm"
[ "$(rpm -qp --qf '%{NAME} %{ARCH}' "$rpm")" = "usg-plat-pin-canary noarch" ] || fail "rpm NAME/ARCH"
[ -z "$(rpm -qlp "$rpm" | grep -v '^(contains no files)$' || true)" ] || fail "rpm is not empty"
echo "pin-canary: $rpm"
