#!/bin/sh
# Install the pinned shellcheck from its prebuilt release tarball, so CI and
# local `make check` lint with the same version (Ubuntu 24.04's apt package
# is 0.9.0 and flagged SC2015 where 0.11.0 does not).
#
# Usage: install-shellcheck.sh [BINDIR]     (default: $HOME/.local/bin)
# Exit: 0 installed; 1 download or sha256 mismatch; 2 usage or unsupported host.
#
# Bumping the version: change SHELLCHECK_VERSION here and in the Makefile and
# both sha256 values (the release asset digests on GitHub) in one change.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-15 (Development Process, Standards, and Tools), CM-2
#   (Baseline Configuration), SR-3 (Supply Chain Controls) - pinned tool,
#   verified by sha256 before it is executed
set -eu

SHELLCHECK_VERSION=0.11.0
SHA256_AARCH64=68a8133197a50beb8803f8d42f9908d1af1c5540d4bb05fdfca8c1fa47decefc
SHA256_X86_64=b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6

die() { echo "install-shellcheck: $1" >&2; exit "${2:-1}"; }

[ $# -le 1 ] || die "usage: install-shellcheck.sh [BINDIR]" 2
bindir=${1:-$HOME/.local/bin}

case "$(uname -s)/$(uname -m)" in
    Linux/aarch64 | Linux/arm64) arch=aarch64 want=$SHA256_AARCH64 ;;
    Linux/x86_64 | Linux/amd64) arch=x86_64 want=$SHA256_X86_64 ;;
    *) die "unsupported host $(uname -s)/$(uname -m) (Linux aarch64 or x86_64 only)" 2 ;;
esac
for t in curl sha256sum tar; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t" 2
done

dir=shellcheck-v$SHELLCHECK_VERSION
asset=$dir.linux.$arch.tar.gz
url=https://github.com/koalaman/shellcheck/releases/download/v$SHELLCHECK_VERSION/$asset

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
echo "install-shellcheck: fetching $url" >&2
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$work/$asset" "$url" || die "download failed: $url"

got=$(sha256sum "$work/$asset" | cut -d' ' -f1)
[ "$got" = "$want" ] || die "sha256 mismatch for $asset: got $got, want $want"
echo "install-shellcheck: sha256 ok $got" >&2

mkdir -p "$work/x"
tar -xzf "$work/$asset" -C "$work/x" --no-same-owner "$dir/shellcheck"
if [ ! -f "$work/x/$dir/shellcheck" ] || [ -L "$work/x/$dir/shellcheck" ]; then die "shellcheck is not a regular file"; fi

mkdir -p "$bindir"
install -m 0755 "$work/x/$dir/shellcheck" "$bindir/shellcheck"
echo "install-shellcheck: installed shellcheck $SHELLCHECK_VERSION ($arch) to $bindir/shellcheck" >&2
