#!/bin/bash
# run-case.sh <A|B|C|D>: build the three-namespace topology, run
# plat-tun-setup.sh in ng-plat with cfg<case>.toml, send probes, show counters.
# Env: NFTGUARD_WORK (work dir holding cfg*.toml; default this directory),
# PLAT_SRC (repository with target/release/platd; default ../../..),
# PLAT_RUN_USER (owner for the test log dir; default $SUDO_USER).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
W=${NFTGUARD_WORK:-$HERE}
SRC=${PLAT_SRC:-$(cd "$HERE/../../.." && pwd)}
U=${PLAT_RUN_USER:-${SUDO_USER:-root}}
C=$1
ST=$W/state$C
rm -rf "$ST"; mkdir -p "$ST/nftd" "$ST/log"
for n in ng-plat ng-ext ng-cl; do ip netns del "$n" 2>/dev/null; ip netns add "$n"; done
ip link add ext0 netns ng-plat type veth peer name ext0p netns ng-ext
ip link add cl0 netns ng-plat type veth peer name cl0p netns ng-cl
X=(ip netns exec ng-plat)
"${X[@]}" ip addr add 10.10.1.1/24 dev ext0; "${X[@]}" ip link set ext0 up
"${X[@]}" ip addr add 10.10.2.1/24 dev cl0; "${X[@]}" ip link set cl0 up; "${X[@]}" ip link set lo up
ip netns exec ng-ext ip addr add 10.10.1.2/24 dev ext0p; ip netns exec ng-ext ip link set ext0p up
ip netns exec ng-ext ip route add default via 10.10.1.1
ip netns exec ng-cl ip addr add 10.10.2.2/24 dev cl0p; ip netns exec ng-cl ip link set cl0p up
ip netns exec ng-cl ip route add default via 10.10.2.1
# rp_filter off so the nft guard (not reverse-path filtering) is what is tested
"${X[@]}" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
  net.ipv4.conf.ext0.rp_filter=0 net.ipv4.conf.cl0.rp_filter=0
echo "### plat-tun-setup.sh cfg$C"
"${X[@]}" env PLAT_TEST_MODE=1 PLATD="$SRC/target/release/platd" PLAT_USER="$U" PLAT_GROUP="$U" \
  PLAT_LOG_GROUP="$U" PLAT_LOG_DIR="$ST/log" PLAT_TMPFILES_CONF="$ST/none" PLAT_NFT_RULES="$ST/nftd/plat.nft" \
  PLAT_NFT_CONF="$ST/none.conf" sh "$SRC/deploy/systemd/plat-tun-setup.sh" "$W/cfg$C.toml"
echo "setup rc=$?"
echo "### generated plat.nft (guard line)"; grep -n guard "$ST/nftd/plat.nft"
echo "### plat.nft.expected"; cat "$ST/nftd/plat.nft.expected"
"${X[@]}" ip -4 route show; "${X[@]}" sysctl net.ipv4.ip_forward
"${X[@]}" timeout 6 python3 -I "$HERE/tunread.py" plat0 6 > "$ST/tun.txt" 2>&1 &
"${X[@]}" timeout 6 tcpdump -lni plat0 -c 20 ip > "$ST/tcpdump.txt" 2>&1 &
sleep 1.5
echo "### probes"
probe() {
  echo "probe $1: ns=$2 src=$3 dst=$4"
  ip netns exec "$2" python3 -I "$HERE/send.py" "$3" "$4" "$1"
  sleep 0.3
}
probe P1-pool-from-ext ng-ext 192.0.2.50 192.0.2.10
probe P1b-pool32-from-ext ng-ext 203.0.113.7 192.0.2.10
probe P2-pool-from-cl ng-cl 192.0.2.50 192.0.2.10
probe P3-nonpool-from-ext ng-ext 198.51.100.9 192.0.2.10
probe P4-nonpool-from-cl ng-cl 198.51.100.9 192.0.2.10
wait
echo "### TUN reader"; cat "$ST/tun.txt"
echo "### tcpdump plat0"; cat "$ST/tcpdump.txt"
echo "### counters"; "${X[@]}" nft -a list chain inet plat forward | grep -E 'counter'
