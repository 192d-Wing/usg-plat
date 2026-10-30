#!/bin/bash
# startcheck.sh <cfg.toml> <snapshot-file> <label>: run `platd run` in ng-plat
# with /etc/nftables.d bind-mounted (private mount namespace) to a directory
# holding only the snapshot. rc 124: still running at the timeout (the gate
# passed); rc 1: the gate refused to start. Env as in run-case.sh.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
W=${NFTGUARD_WORK:-$HERE}
SRC=${PLAT_SRC:-$(cd "$HERE/../../.." && pwd)}
D=$W/mnt-$3
rm -rf "$D"; mkdir -p "$D"
cp "$2" "$D/plat.nft.expected"
echo "### [$3] cfg=$(basename "$1") snapshot guard line:"
grep -n 'guard' "$D/plat.nft.expected" || echo "(no guard line)"
ip netns exec ng-plat unshare -m sh -c "mount --make-rprivate / && mount --bind \"\$1\" /etc/nftables.d && timeout 4 \"\$2\" run -c \"\$3\"" \
  sh "$D" "$SRC/target/release/platd" "$1" > "$W/out-$3.txt" 2>&1
rc=$?
grep -E 'FIPS status|cross_node_hairpin|ERROR|audit|worker|listening' "$W/out-$3.txt" | head -6 | cut -c1-400
echo "[$3] rc=$rc (124 = still running when timeout killed it, i.e. gate passed)"
