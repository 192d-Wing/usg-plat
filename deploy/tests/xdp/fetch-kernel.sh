#!/bin/sh
# Fetch and unpack one matrix kernel (kernels.conf) for the virtme-ng tests
# (plan §11 level 3, §3 WU7 criterion 4). Debian packages only, verified as a
# chain, failing closed at each link:
#   1. dists/SUITE/InRelease signature: gpgv against debian-archive-keyring;
#      at least one GOODSIG (unexpired, unrevoked key), no BADSIG/REVKEYSIG;
#      signatures by keys the keyring lacks are ignored. Only the signed text is
#      parsed. Valid-Until is enforced except for snapshot.debian.org.
#   2. main/binary-ARCH/Packages.xz: size and sha256 from the signed Release.
#   3. each .deb (the unsigned image, plus linux-modules for the split
#      layout): sha256 from Packages, and the kernels.conf pin if one exists
#      (snapshot sources must be pinned).
#
# Usage: fetch-kernel.sh [-a amd64|arm64] [-o OUTDIR] [-k KEYRING] NAME
#   NAME     a `kernel` entry in kernels.conf (6.1, 6.6, 6.12, latest)
#   -a       Debian architecture (default: from uname -m)
#   -o       output directory (default: target/xdp-kernels in the repo; not
#            under /tmp, which virtme-ng hides from the guest)
#   -k       keyring (default $XDP_DEBIAN_KEYRING, else
#            /usr/share/keyrings/debian-archive-keyring.gpg)
# Output: stdout is the path of the unpacked vmlinuz (one line); OUTDIR/NAME-ARCH
# holds boot/, lib/modules/KVER and kernel.env (what was fetched and verified).
# Exit: 0 ok; 1 download or verification failure; 2 usage or missing tool.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SR-3 (Supply Chain Controls), SR-4 (Provenance), SI-7
#   (Software, Firmware, and Information Integrity) - test kernels are
#   signature- and hash-verified before they are booted
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
conf=$here/kernels.conf

die() { echo "fetch-kernel: $1" >&2; exit "${2:-1}"; }
log() { echo "fetch-kernel: $*" >&2; }
usage() { die "usage: fetch-kernel.sh [-a amd64|arm64] [-o OUTDIR] [-k KEYRING] NAME" 2; }

arch=
out=$repo/target/xdp-kernels
keyring=${XDP_DEBIAN_KEYRING:-/usr/share/keyrings/debian-archive-keyring.gpg}
while getopts a:o:k: opt; do
    case "$opt" in
        a) arch=$OPTARG ;;
        o) out=$OPTARG ;;
        k) keyring=$OPTARG ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || usage
name=$1

if [ -z "$arch" ]; then
    case "$(uname -m)" in
        x86_64 | amd64) arch=amd64 ;;
        aarch64 | arm64) arch=arm64 ;;
        *) die "unsupported host $(uname -m); pass -a" 2 ;;
    esac
fi
case "$arch" in amd64 | arm64) ;; *) die "unsupported architecture $arch" 2 ;; esac

for t in curl gpgv xz sha256sum dpkg-deb awk sort date; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t" 2
done
[ -f "$keyring" ] || die "keyring not found: $keyring (install debian-archive-keyring)" 2

entry=$(awk -v n="$name" '$1 == "kernel" && $2 == n { print $3, $4, $5; exit }' "$conf")
[ -n "$entry" ] || die "no kernel '$name' in $conf" 2
set -f
# shellcheck disable=SC2086 # split the three fields
set -- $entry
set +f
base=$1 suite=$2 vglob=$3
case "$base" in https://*) ;; *) die "base URL must be https: $base" 2 ;; esac
snapshot=no
case "$base" in https://snapshot.debian.org/*) snapshot=yes ;; esac

dest=$out/$name-$arch
work=$out/.dl-$name-$arch
rm -rf "$work"
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT INT TERM

fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --max-time 900 -o "$2" "$1" || die "download failed: $1"; }

# 1. Signed Release.
fetch "$base/dists/$suite/InRelease" "$work/InRelease"
gpgv --keyring "$keyring" --status-fd 3 --output "$work/Release" "$work/InRelease" \
    3>"$work/gpgv.status" 2>"$work/gpgv.err" || true
# gpgv exits non-zero when one of several signatures uses a key the keyring
# lacks; apt accepts that if another signature is good, and so do we.
if grep -Eq '^\[GNUPG:\] (BADSIG|REVKEYSIG) ' "$work/gpgv.status"; then
    cat "$work/gpgv.err" >&2
    die "bad or revoked signature on $base/dists/$suite/InRelease"
fi
# GOODSIG is emitted only for a good signature by a key that is neither
# expired nor revoked (EXPKEYSIG/REVKEYSIG replace it); VALIDSIG names it.
signers=$(awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3 }' "$work/gpgv.status" | sort -u | tr '\n' ' ')
if ! grep -q '^\[GNUPG:\] GOODSIG ' "$work/gpgv.status" || [ -z "$signers" ] || [ ! -s "$work/Release" ]; then
    cat "$work/gpgv.err" >&2
    die "no valid signature on $base/dists/$suite/InRelease"
fi
log "InRelease $suite signed by: $signers"

valid_until=$(sed -n 's/^Valid-Until: //p' "$work/Release")
if [ -n "$valid_until" ] && [ "$snapshot" = no ]; then
    vu=$(date -u -d "$valid_until" +%s) || die "unparsable Valid-Until: $valid_until"
    [ "$(date -u +%s)" -lt "$vu" ] || die "Release for $suite expired at $valid_until (stale mirror?)"
fi

# 2. Packages.xz, hashed by the signed Release (SHA256 section only).
idx=main/binary-$arch/Packages.xz
line=$(awk -v f="$idx" '
    /^SHA256:/ { s = 1; next }
    /^[^ ]/ { s = 0 }
    s && $3 == f { print $1, $2; exit }' "$work/Release")
[ -n "$line" ] || die "$idx not listed in the signed Release"
want_sha=${line% *} want_size=${line#* }
fetch "$base/dists/$suite/$idx" "$work/Packages.xz"
got_size=$(wc -c <"$work/Packages.xz" | tr -d ' ')
got_sha=$(sha256sum "$work/Packages.xz" | cut -d' ' -f1)
if [ "$got_size" != "$want_size" ] || [ "$got_sha" != "$want_sha" ]; then
    die "$idx mismatch: got $got_sha/$got_size, want $want_sha/$want_size"
fi
xz -dc "$work/Packages.xz" >"$work/Packages"

# 3. Select the newest matching unsigned image from source `linux`, in either
# layout (no cloud/rt/16k/dbg flavours):
#   classic  linux-image-<abi>-<arch>-unsigned       (image + modules)
#   split    linux-binary-unsigned-<abi>-<arch>      (image; sid since 7.x)
#            + linux-modules-<abi>-<arch>, same Version
# Columns: package, version, filename, sha256, abi.
awk '
    /^Package: / { p = $2; v = f = h = "" }
    /^Version: / { v = $2 }
    /^Filename: / { f = $2 }
    /^SHA256: / { h = $2 }
    /^$/ { if (p != "" && v != "" && f != "" && h != "") print p "\t" v "\t" f "\t" h; p = "" }
    END { if (p != "" && v != "" && f != "" && h != "") print p "\t" v "\t" f "\t" h }
' "$work/Packages" >"$work/index"

abi_re='[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9]+)?(\+deb[0-9]+)?'
tab=$(printf '\t')
: >"$work/matching"
while IFS=$tab read -r p v f h; do
    abi=$(printf '%s\n' "$p" | sed -nE "s/^linux-image-($abi_re)-$arch-unsigned\$/\\1/p; s/^linux-binary-unsigned-($abi_re)-$arch\$/\\1/p")
    [ -n "$abi" ] || continue
    # shellcheck disable=SC2254 # vglob is a pattern by design
    case "$v" in $vglob) printf '%s\t%s\t%s\t%s\t%s\n' "$p" "$v" "$f" "$h" "$abi" >>"$work/matching" ;; esac
done <<EOF
$(grep -E "^linux-(image|binary-unsigned)-[0-9]" "$work/index")
EOF
pick=$(sort -t "$tab" -k2,2V "$work/matching" | tail -n 1)
[ -n "$pick" ] || die "no unsigned kernel image for $arch matching '$vglob' in $suite"
IFS=$tab read -r package version _ _ abi <<EOF
$pick
EOF
log "selected $package $version"
debs=$package
mods=linux-modules-$abi-$arch
case "$package" in
    linux-binary-unsigned-*)
        awk -F "$tab" -v p="$mods" -v v="$version" '$1 == p && $2 == v { found = 1 } END { exit !found }' "$work/index" ||
            die "split layout without $mods $version in $suite"
        debs="$package $mods"
        ;;
esac

# Download and verify each .deb against Packages and its pin.
rm -rf "$dest"
mkdir -p "$dest"
pinned=yes
shas=
for p in $debs; do
    line=$(awk -F "$tab" -v p="$p" -v v="$version" '$1 == p && $2 == v { print $3 "\t" $4; exit }' "$work/index")
    filename=${line%"$tab"*} deb_sha=${line#*"$tab"}
    case "$filename" in
        *..* | /*) die "refusing Filename $filename" ;;
        pool/main/l/linux/*.deb) ;;
        *) die "unexpected Filename $filename (want pool/main/l/linux/)" ;;
    esac
    debname=${filename##*/}
    pin=$(awk -v d="$debname" '$1 == "pin" && $2 == d { print $3; exit }' "$conf")
    if [ "$snapshot" = yes ] && [ -z "$pin" ]; then
        die "snapshot source without a pin for $debname (add it to kernels.conf)"
    fi
    fetch "$base/$filename" "$work/$debname"
    got=$(sha256sum "$work/$debname" | cut -d' ' -f1)
    [ "$got" = "$deb_sha" ] || die "$debname sha256 $got does not match Packages ($deb_sha)"
    if [ -n "$pin" ]; then
        [ "$got" = "$pin" ] || die "$debname sha256 $got does not match the kernels.conf pin ($pin)"
    else
        pinned=no
        log "no pin for $debname (verified by the signed index; record: pin $debname $got)"
    fi
    log "verified $debname sha256 $got"
    shas="$shas$debname=$got "
    # dpkg-deb -x needs no root and runs no maintainer scripts.
    dpkg-deb -x "$work/$debname" "$dest"
done

# The split layout keeps the image in usr/lib/modules/KVER/vmlinuz[.unsigned]
# and has no boot/; give it the classic name so vng-run.sh sees one layout.
if [ ! -d "$dest/boot" ]; then
    set -- "$dest"/usr/lib/modules/*/vmlinuz.unsigned "$dest"/usr/lib/modules/*/vmlinuz
    for img do
        [ -f "$img" ] || continue
        k=${img%/*}
        mkdir -p "$dest/boot"
        ln "$img" "$dest/boot/vmlinuz-${k##*/}"
        break
    done
fi
set -- "$dest"/boot/vmlinuz-*
if [ $# -ne 1 ] || [ ! -f "$1" ]; then die "expected exactly one kernel image in $debs"; fi
kimg=$1
kver=${kimg##*/vmlinuz-}
# usr-merged packages ship usr/lib/modules; virtme-ng looks for lib/modules
# next to the image's root.
if [ ! -d "$dest/lib/modules/$kver" ] && [ -d "$dest/usr/lib/modules/$kver" ] && [ ! -e "$dest/lib" ]; then
    ln -s usr/lib "$dest/lib"
fi
[ -d "$dest/lib/modules/$kver" ] || die "no lib/modules/$kver in $debs"

cat >"$dest/kernel.env" <<EOF
XDP_KERNEL_NAME=$name
XDP_KERNEL_ARCH=$arch
XDP_KERNEL_SUITE=$suite
XDP_KERNEL_PACKAGES="$debs"
XDP_KERNEL_VERSION=$version
XDP_KERNEL_KVER=$kver
XDP_KERNEL_SHA256="${shas% }"
XDP_KERNEL_PINNED=$pinned
XDP_KERNEL_SIGNERS="${signers% }"
EOF
log "ok: $kver ($version, pinned=$pinned)"
echo "$kimg"
