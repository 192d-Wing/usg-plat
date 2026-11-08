#!/bin/sh
# Check that every `container: image:` pin of an image in a workflow uses the
# same digest (the Rocky 9 build floor in packages.yml: jobs `packages` and
# `sbom-xdp`; `container:` cannot read `env`, so the pin is repeated).
#
# Usage: deploy/ci/check-container-pins.sh [WORKFLOW...]
#        (default .github/workflows/packages.yml)
# Exit:  0 consistent; 1 pins differ, an image is not pinned by digest, or
#        packages.yml has fewer than two Rocky 9 pins; 2 file missing.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-2 (Baseline Configuration), SR-3 (Supply Chain Controls) -
#   both release build jobs run on the same pinned base image
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
[ $# -gt 0 ] || set -- "$root/.github/workflows/packages.yml"
status=0
for wf in "$@"; do
    [ -f "$wf" ] || { echo "check-container-pins: $wf missing" >&2; exit 2; }
    # Image references on the line after `container:`.
    imgs=$(awk '/^[[:space:]]*container:[[:space:]]*$/ { c = 1; next }
        c && /^[[:space:]]*image:/ { sub(/^[[:space:]]*image:[[:space:]]*/, ""); print; c = 0; next }
        { c = 0 }' "$wf")
    for i in $imgs; do
        case $i in
            *@sha256:????????????????????????????????????????????????????????????????) ;;
            *) echo "check-container-pins: $wf: $i is not pinned by sha256 digest" >&2; status=1 ;;
        esac
    done
    for name in $(printf '%s\n' "$imgs" | sed 's/@.*//' | sort -u); do
        n=$(printf '%s\n' "$imgs" | grep -c "^$name@")
        d=$(printf '%s\n' "$imgs" | grep "^$name@" | sort -u | grep -c .)
        if [ "$d" -ne 1 ]; then
            echo "check-container-pins: $wf: $name is pinned to $d different digests:" >&2
            printf '%s\n' "$imgs" | grep "^$name@" | sort -u | sed 's/^/  /' >&2
            status=1
        else
            echo "check-container-pins: $wf: $name x$n, one digest"
        fi
    done
    case $wf in
        */packages.yml)
            r=$(printf '%s\n' "$imgs" | grep -c '^rockylinux/rockylinux:9@')
            [ "$r" -ge 2 ] || {
                echo "check-container-pins: $wf: expected the Rocky 9 pin in packages and sbom-xdp, found $r" >&2
                status=1
            }
            ;;
        *) ;;
    esac
done
exit $status
