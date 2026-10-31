#!/bin/sh
# Build the plat-xdp-ebpf object (plan §15): the nested bpfel-unknown-none
# build that aya-build 0.2.1 runs, with the same flags (`--cfg
# bpf_target_arch`, `-Cdebuginfo=2`, `-Clink-arg=--btf`, `--release`,
# `-Z build-std=core`), plus path remapping so the object does not depend on
# where the tree, CARGO_HOME or the toolchain live. The link options of the
# object itself are in crates/plat-xdp-ebpf/build.rs, so every build of the
# crate gets them.
#
# RUSTC_BOOTSTRAP=1 is set for this one cargo command only (the -Z flag on
# stable 1.99.1); the workspace build never sees it (Makefile xdp-env).
#
# Usage: build-object.sh [OUTDIR]     (default: target/xdp in the repo)
# Output: OUTDIR/plat-xdp-ebpf and OUTDIR/plat-xdp-ebpf.sha256
# Exit: 0 built; 1 build failed; 2 usage or missing tool.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-15 (Development Process, Standards, and Tools), CM-2
#   (Baseline Configuration), SI-7 (Software, Firmware, and Information
#   Integrity) - pinned toolchain and linker, fixed flags, path-independent
#   output, recorded SHA-256
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)

die() { echo "build-object: $1" >&2; exit "${2:-1}"; }

[ $# -le 1 ] || die "usage: build-object.sh [OUTDIR]" 2
out=${1:-$repo/target/xdp}
for t in cargo rustc bpf-linker sha256sum; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t (bpf-linker: deploy/tests/xdp/install-bpf-linker.sh)" 2
done

case "$(uname -m)" in
    aarch64 | arm64) arch=aarch64 ;;
    x86_64 | amd64) arch=x86_64 ;;
    *) die "unsupported host $(uname -m)" 2 ;;
esac

cd "$repo"
sysroot=$(rustc --print sysroot)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
cargo_home=$(cd "$cargo_home" && pwd)
us=$(printf '\037')
flags="--cfg=bpf_target_arch=\"$arch\"${us}-Cdebuginfo=2${us}-Clink-arg=--btf"
flags="$flags${us}--remap-path-prefix=$repo=/usg-plat${us}--remap-path-prefix=$cargo_home=/cargo"
flags="$flags${us}--remap-path-prefix=$sysroot=/rustc"

RUSTC_BOOTSTRAP=1 CARGO_ENCODED_RUSTFLAGS=$flags cargo build --package plat-xdp-ebpf --bins --release \
    --target bpfel-unknown-none -Z build-std=core --locked --target-dir "$repo/target/xdp-ebpf" ||
    die "cargo build failed"

mkdir -p "$out"
cp "$repo/target/xdp-ebpf/bpfel-unknown-none/release/plat-xdp-ebpf" "$out/plat-xdp-ebpf"
(cd "$out" && sha256sum plat-xdp-ebpf >plat-xdp-ebpf.sha256)
echo "build-object: $(cat "$out/plat-xdp-ebpf.sha256") ($arch host, $(rustc -V))" >&2
