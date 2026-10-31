#!/bin/sh
# Fail unless rustc and bpf-linker use the same LLVM major (plan §15). rustc
# emits LLVM bitcode for bpfel-unknown-none and bpf-linker links it with its
# embedded LLVM; bitcode is only compatible within one major (23 today).
#
# Usage: check-llvm-major.sh [BPF_LINKER]   (default: bpf-linker on PATH)
# Environment: RUSTC (default rustc).
# Exit: 0 majors equal; 1 mismatch or version not found; 2 usage.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-15 (Development Process, Standards, and Tools), CM-2
#   (Baseline Configuration) - the two pinned tools must move together
set -eu

die() { echo "check-llvm-major: $1" >&2; exit "${2:-1}"; }

[ $# -le 1 ] || die "usage: check-llvm-major.sh [BPF_LINKER]" 2
linker=${1:-$(command -v bpf-linker || true)}
if [ -z "$linker" ] || [ ! -f "$linker" ]; then die "bpf-linker not found (run install-bpf-linker.sh)"; fi
rustc=${RUSTC:-rustc}

rust_llvm=$("$rustc" -vV | sed -n 's/^LLVM version: //p')
[ -n "$rust_llvm" ] || die "no 'LLVM version' line in '$rustc -vV'"

# The release binary carries the string "LLVM version X.Y.Z" (spike: 23.1.3).
# grep -a instead of strings(1): no binutils dependency.
linker_llvm=$(LC_ALL=C grep -aoE 'LLVM version [0-9]+(\.[0-9]+)*' "$linker" | sed 's/^LLVM version //' | sort -u)
[ -n "$linker_llvm" ] || die "no 'LLVM version' string in $linker"
[ "$(printf '%s\n' "$linker_llvm" | wc -l)" -eq 1 ] || die "several LLVM versions in $linker: $linker_llvm"

rust_major=${rust_llvm%%.*}
linker_major=${linker_llvm%%.*}
echo "check-llvm-major: rustc LLVM $rust_llvm, bpf-linker LLVM $linker_llvm" >&2
[ "$rust_major" = "$linker_major" ] || die "LLVM major mismatch: rustc $rust_major, bpf-linker $linker_major (move both in one change)"
echo "check-llvm-major: ok (LLVM $rust_major)" >&2
