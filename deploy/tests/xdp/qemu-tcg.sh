#!/bin/sh
# QEMU wrapper for virtme-ng on aarch64 hosts without KVM (plan §11 level 3).
# vng 1.22 passes `-M virt,gic-version=host -cpu host` even with --disable-kvm
# on aarch64; both need KVM. Rewrite them for TCG and force the TCG
# accelerator. vng-run.sh selects this wrapper through `vng --qemu`; drop it
# once a vng release fixes --disable-kvm on aarch64.
#
# Environment: QEMU_SYSTEM_AARCH64 (default: qemu-system-aarch64 on PATH).
set -eu

qemu=${QEMU_SYSTEM_AARCH64:-$(command -v qemu-system-aarch64 || true)}
[ -n "$qemu" ] || { echo "qemu-tcg: qemu-system-aarch64 not found" >&2; exit 2; }

# Rotate the argument list once, rewriting the value that follows -M/-machine
# or -cpu. pauth-impdef makes pointer authentication cheap under TCG.
prev=
for a do
    shift
    case "$prev" in
        -M | -machine) [ "$a" = virt,gic-version=host ] && a=virt,gic-version=3 ;;
        -cpu) [ "$a" = host ] && a=max,pauth-impdef=on ;;
    esac
    set -- "$@" "$a"
    prev=$a
done
exec "$qemu" -accel tcg,thread=multi "$@"
