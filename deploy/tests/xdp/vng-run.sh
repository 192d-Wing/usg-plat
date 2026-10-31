#!/bin/sh
# Boot a kernel image with virtme-ng and run the XDP guest checks in it (plan
# §11 levels 2-4, §3 WU7 criterion 5). The guest shares the host filesystem
# read-only and runs as root.
#
# With a usable /dev/kvm the guest boots under KVM. Without it, TCG: on
# aarch64 through qemu-tcg.sh (vng 1.22 passes KVM-only options with
# --disable-kvm), on x86_64 with --disable-microvm (microvm wants KVM).
# Expect about 15 s per kernel under TCG (spike: 6.1.176, 15.5 s).
#
# Usage: vng-run.sh [-m] [-c CPUS] [-M MEMORY] KERNEL_IMAGE [-- GUEST_CMD [ARG...]]
#   KERNEL_IMAGE  .../boot/vmlinuz-KVER as printed by fetch-kernel.sh
#   -m            install the image's lib/modules/KVER into /lib/modules when
#                 absent (root or sudo; CI runners only). The guest sees the
#                 host's /lib/modules when vng cannot read the version from a
#                 compressed image, so this makes modprobe work either way.
#   GUEST_CMD     default: guest.sh KVER (same directory). Arguments are limited
#                 to [A-Za-z0-9_./:=,+@%-] (they become one vng --exec string).
# Environment: XDP_VNG_TIMEOUT (seconds, default 900), XDP_LOG_DIR (default
# target/xdp-vm in the repo).
# Exit: 0 when vng exits 0 and the guest printed XDP-GUEST-OK; 1 otherwise;
#       2 usage or missing tool.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)

die() { echo "vng-run: $1" >&2; exit "${2:-1}"; }
usage() { die "usage: vng-run.sh [-m] [-c CPUS] [-M MEMORY] KERNEL_IMAGE [-- GUEST_CMD [ARG...]]" 2; }

install_mods=no
cpus=4
mem=2G
while getopts mc:M: opt; do
    case "$opt" in
        m) install_mods=yes ;;
        c) cpus=$OPTARG ;;
        M) mem=$OPTARG ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || usage
kimg=$1
shift
if [ $# -gt 0 ]; then
    [ "$1" = -- ] || usage
    shift
fi

[ "$(uname -s)" = Linux ] || die "needs Linux" 2
for t in vng timeout; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t" 2
done
[ -f "$kimg" ] || die "no kernel image $kimg" 2
case "$kimg" in /tmp/*) die "kernel under /tmp is hidden from the guest; use fetch-kernel.sh -o" 2 ;; *) ;; esac
kimg=$(cd "$(dirname "$kimg")" && pwd)/$(basename "$kimg")
kver=${kimg##*/vmlinuz-}
[ "$kver" != "$kimg" ] || die "image name must be vmlinuz-KVER: $kimg" 2
root=${kimg%/boot/vmlinuz-*}

if [ "$install_mods" = yes ] && [ ! -d "/lib/modules/$kver" ]; then
    [ -d "$root/lib/modules/$kver" ] || die "no $root/lib/modules/$kver to install"
    sudo=
    [ "$(id -u)" -eq 0 ] || sudo=sudo
    $sudo cp -a "$root/lib/modules/$kver" "/lib/modules/$kver"
    $sudo depmod -a "$kver"
    echo "vng-run: installed modules for $kver into /lib/modules" >&2
fi

[ $# -gt 0 ] || set -- "$here/guest.sh" "$kver"
for a do
    case "$a" in
        *[!A-Za-z0-9_./:=,+@%-]* | '') die "guest argument outside [A-Za-z0-9_./:=,+@%-]: '$a'" 2 ;;
    esac
done
cmd=$*

if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    accel=kvm
    set -- --run "$kimg"
else
    accel=tcg
    set -- --run "$kimg" --disable-kvm
    case "$(uname -m)" in
        aarch64 | arm64) set -- "$@" --qemu "$here/qemu-tcg.sh" ;;
        x86_64 | amd64) set -- "$@" --disable-microvm ;;
    esac
fi

logdir=${XDP_LOG_DIR:-$repo/target/xdp-vm}
mkdir -p "$logdir"
log=$logdir/$kver.log
echo "vng-run: booting $kver ($accel, $cpus CPUs, $mem) -> $log" >&2
start=$(date +%s)
rc=0
timeout "${XDP_VNG_TIMEOUT:-900}" vng "$@" --cpus "$cpus" --memory "$mem" --user root \
    --exec "$cmd" </dev/null >"$log" 2>&1 || rc=$?
elapsed=$(($(date +%s) - start))
cat "$log"
if [ "$rc" -ne 0 ]; then
    die "vng exited $rc after ${elapsed}s ($kver, $accel)"
fi
grep -q '^XDP-GUEST-OK' "$log" || die "guest did not report XDP-GUEST-OK ($kver, $accel, ${elapsed}s)"
echo "vng-run: ok $kver ($accel, ${elapsed}s)" >&2
