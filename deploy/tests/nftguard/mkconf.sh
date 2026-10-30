#!/bin/sh
# mkconf.sh <example.toml> <outdir>: writes cfgA.toml (hairpin off) and
# cfgB.toml (hairpin on, cluster interface cl0), then cfgC.toml (pool that
# nft merges into one range) and cfgD.toml (two cluster interfaces).
set -eu
EX=$1
D=$2
base() {
  sed -e 's#^pool = .*#pool = ["192.0.2.0/25", "192.0.2.128/25", "203.0.113.7/32"]#' \
      -e "s#^path = \"/var/log/plat/nat64-audit.jsonl\"#path = \"$D/log/nat64-audit.jsonl\"#" \
      -e 's#^min_free_bytes = .*#min_free_bytes = 1048576#' \
      -e 's#^listen = "127.0.0.1:9464"#listen = "127.0.0.1:19464"#' \
      -e 's#^address = "198.51.100.10:514"#address = "127.0.0.1:15514"#' "$EX"
}
base > "$D/cfgA.toml"
base | sed -e 's#^cross_node_hairpin = false#cross_node_hairpin = true\ncluster_interfaces = ["cl0"]#' > "$D/cfgB.toml"
sed -e 's#^pool = .*#pool = ["192.0.2.0/24", "192.0.3.0/25"]#' "$D/cfgB.toml" > "$D/cfgC.toml"
sed -e 's#^cluster_interfaces = .*#cluster_interfaces = ["cl0", "bond1.40"]#' "$D/cfgB.toml" > "$D/cfgD.toml"
