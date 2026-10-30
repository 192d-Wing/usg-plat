#!/bin/sh
# Runs the cluster/HA failure-injection cases F1-F13 (plan §8.2) in order
# against the Lima test bed prepared by setup.sh, from the host.
# Usage: run-all.sh [case ...]   e.g. run-all.sh f01 f04
# Each case restores the baseline when it ends; artifacts go to
# target/cluster-ha-test/<case>-<time>/ (override with PLAT_CLUSTER_OUT).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
[ $# -gt 0 ] || set -- f01 f02 f03 f04 f05 f06 f07 f08 f09 f10 f11 f12 f13
failed=
for c in "$@"; do
    for f in "$HERE/$c"-*.sh; do
        [ -f "$f" ] || { echo "no such case: $c" >&2; exit 2; }
        sh "$f" || failed="$failed $c"
    done
done
[ -z "$failed" ] || { echo "FAILED:$failed" >&2; exit 1; }
echo "all cluster cases passed"
