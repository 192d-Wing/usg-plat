#!/bin/sh
# Install the pinned bpf-linker from its prebuilt musl release tarball (XDP
# fast path, POAM-016 Phase 1, plan §15). No `cargo install`, no system LLVM:
# the binary embeds LLVM 23.1.3, matching rustc 1.99.1's LLVM 23.
#
# Usage: install-bpf-linker.sh [BINDIR]     (default: $HOME/.local/bin)
# Exit: 0 installed (or already the pinned build); 1 download or sha256 mismatch;
#       2 usage or unsupported host.
#
# Bumping the version: change BPF_LINKER_VERSION and both sha256 values in one
# change (the release asset digests on GitHub), and run check-llvm-major.sh. An
# LLVM-major move in rustc requires moving bpf-linker in the same PR.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-15 (Development Process, Standards, and Tools), CM-2
#   (Baseline Configuration), SR-3 (Supply Chain Controls) - pinned tool,
#   verified by sha256 before it is executed
set -eu

BPF_LINKER_VERSION=0.12.0
SHA256_AARCH64=5e201e69dafac7af98f9788f1c68edd5ccc8fa0805093f899bf02bd2947b3935
SHA256_X86_64=6789717c8cb6a2a5d920f3b6bfac2bd7efc00f6228ecd149108a99699a75c679

die() { echo "install-bpf-linker: $1" >&2; exit "${2:-1}"; }

[ $# -le 1 ] || die "usage: install-bpf-linker.sh [BINDIR]" 2
bindir=${1:-$HOME/.local/bin}

case "$(uname -s)/$(uname -m)" in
    Linux/aarch64 | Linux/arm64) triple=aarch64-unknown-linux-musl want=$SHA256_AARCH64 ;;
    Linux/x86_64 | Linux/amd64) triple=x86_64-unknown-linux-musl want=$SHA256_X86_64 ;;
    *) die "unsupported host $(uname -s)/$(uname -m) (Linux aarch64 or x86_64 only)" 2 ;;
esac
for t in curl sha256sum tar zstd; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t" 2
done

asset=bpf-linker-$triple.tar.zst
url=https://github.com/aya-rs/bpf-linker/releases/download/v$BPF_LINKER_VERSION/$asset

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
echo "install-bpf-linker: fetching $url" >&2
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$work/$asset" "$url" || die "download failed: $url"

got=$(sha256sum "$work/$asset" | cut -d' ' -f1)
[ "$got" = "$want" ] || die "sha256 mismatch for $asset: got $got, want $want"
echo "install-bpf-linker: sha256 ok $got" >&2

# The tarball holds a single regular file named bpf-linker; refuse anything else.
listing=$(tar --zstd -tf "$work/$asset")
[ "$listing" = bpf-linker ] || die "unexpected tarball contents: $listing"
mkdir -p "$work/x"
tar --zstd -xf "$work/$asset" -C "$work/x" --no-same-owner bpf-linker
if [ ! -f "$work/x/bpf-linker" ] || [ -L "$work/x/bpf-linker" ]; then die "bpf-linker is not a regular file"; fi

mkdir -p "$bindir"
install -m 0755 "$work/x/bpf-linker" "$bindir/bpf-linker"
echo "install-bpf-linker: installed bpf-linker $BPF_LINKER_VERSION ($triple) to $bindir/bpf-linker" >&2
