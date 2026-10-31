#!/bin/sh
# Reproducibility check of the plat-xdp-ebpf object (SEC-001, NIST-004):
# builds the committed tree a second time in another directory with
# build-object.sh, requires the same SHA-256 as OBJECT, and fails if either
# object contains a host path (/home/, /Users/, .cargo, rustup), which
# would mean the --remap-path-prefix set in build-object.sh no longer covers
# a source location.
#
# Usage: check-repro.sh OBJECT [WORKDIR]   (WORKDIR default: a mktemp dir)
# Exit: 0 identical and path-free; 1 differs or leaks a path; 2 usage.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity),
#   SA-15, CM-2 - the shipped object is reproducible from the tree
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
die() { echo "check-repro: $1" >&2; exit "${2:-1}"; }

if [ $# -lt 1 ] || [ $# -gt 2 ]; then die "usage: check-repro.sh OBJECT [WORKDIR]" 2; fi
obj=$1
[ -f "$obj" ] || die "no object $obj (make xdp)" 2
work=${2:-$(mktemp -d)}
mkdir -p "$work/tree"

# The tracked tree only (what CI checked out), not target/.
(cd "$repo" && git ls-files -z | xargs -0 tar cf -) | (cd "$work/tree" && tar xf -)
"$work/tree/deploy/tests/xdp/build-object.sh" "$work/out" >/dev/null

a=$(sha256sum "$obj" | cut -d' ' -f1)
b=$(sha256sum "$work/out/plat-xdp-ebpf" | cut -d' ' -f1)
[ "$a" = "$b" ] || die "object differs between $repo and $work/tree: $a vs $b"
for o in "$obj" "$work/out/plat-xdp-ebpf"; do
    if LC_ALL=C grep -a -o -E '/home/|/Users/|\.cargo|rustup' "$o" | sort -u | grep -q .; then
        die "$o contains a host path: $(LC_ALL=C grep -a -o -E '/home/|/Users/|\.cargo|rustup' "$o" | sort -u | tr '\n' ' ')"
    fi
done
echo "check-repro: ok ($a, rebuilt in $work/tree, no host paths)"
