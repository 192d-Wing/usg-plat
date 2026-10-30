# POAM-024 residual (b): live check of `plat-pool-source-guard`

- Source: branch at f74f53d (fix/poams-020-024-013, PR #16). Clean tree, copied with `git archive HEAD`. No files in the worktree were edited.
- VM: Lima `plat-linux`, kernel 6.8.0-147-generic aarch64, nftables v1.0.9, scapy 2.5.0.
- Build: `cargo build --release -p platd` (default features, TLS/FIPS on), finished in 1m09s.
- Scripts (now in `deploy/tests/nftguard/`): mkconf.sh (mkconf2.sh folded in), run-case.sh, startcheck.sh, tunread.py, send.py.

## Setup
Three network namespaces: `ng-plat` (the translator host: ext0 10.10.1.1/24, cl0 10.10.2.1/24, TUN plat0 created by the script), `ng-ext` (ext0p 10.10.1.2) and `ng-cl` (cl0p 10.10.2.2), connected by veth pairs.
I set rp_filter=0 in ng-plat so the nft rule, not reverse-path filtering, decides the result.
I ran plat-tun-setup.sh in ng-plat with PLAT_TEST_MODE=1 and the PLATD/PLAT_NFT_RULES/PLAT_LOG_DIR/... hooks pointing at the scratch dir. The rules were loaded with the real nft.
A Python reader attached a queue to the multiqueue TUN (tunread.py), and `tcpdump -ni plat0` ran alongside it.
The probes were scapy UDP packets to 192.0.2.10 (a pool address routed to plat0).

The configs are the example config with these changes:
- cfgA: pool ["192.0.2.0/25","192.0.2.128/25","203.0.113.7/32"], cross_node_hairpin=false.
- cfgB: cfgA plus hairpin=true and cluster_interfaces=["cl0"].
- cfgC: cfgB with pool ["192.0.2.0/24","192.0.3.0/25"] (adjacent, so nft merges them).
- cfgD: cfgB with cluster_interfaces ["cl0","bond1.40"].

`check-config --format env` (cfgB): PLAT_OWNED_POOL=PLAT_POOL_ALL=`192.0.2.0/24 203.0.113.7/32`, PLAT_CROSS_NODE_HAIRPIN=1, PLAT_CLUSTER_IFACES=cl0. For cfgA: HAIRPIN=0 and CLUSTER_IFACES is empty. The two /25s are merged into a /24.

Command: `sudo bash run-case.sh <A|B|C|D>`

## Rendering: what was generated and what `nft list` printed
| case | generated rule | nft rendering (plat.nft.expected) |
|---|---|---|
| A | `oifname "plat0" ip saddr { 192.0.2.0/24, 203.0.113.7/32 } counter drop comment "plat-pool-source-guard"` | `oifname "plat0" ip saddr { 192.0.2.0/24, 203.0.113.7 } counter packets 0 bytes 0 drop comment "plat-pool-source-guard"` |
| B | `... iifname != { "cl0" } ip saddr {...}` | `oifname "plat0" iifname != "cl0" ip saddr { 192.0.2.0/24, 203.0.113.7 } counter packets 0 bytes 0 drop comment ...` (a one-element set loses its braces; a /32 loses its prefix length) |
| C | `ip saddr { 192.0.2.0/24, 192.0.3.0/25 }` | `ip saddr { 192.0.2.0-192.0.3.127 }` (merged into one range) |
| D | `iifname != { "cl0", "bond1.40" }` | `iifname != { "cl0", "bond1.40" }` |

## Packet results (TUN reader / tcpdump on plat0 / guard counter)
| probe | A (hairpin off) | B (hairpin on, cl0) |
|---|---|---|
| P1 pool src 192.0.2.50 from ext0 | dropped | dropped |
| P1b pool src 203.0.113.7 from ext0 | dropped | dropped |
| P2 pool src 192.0.2.50 from cl0 | dropped | **reached TUN** |
| P3 non-pool 198.51.100.9 from ext0 | reached TUN | reached TUN |
| P4 non-pool 198.51.100.9 from cl0 | reached TUN | reached TUN |
| guard counter | `packets 3 bytes 134` | `packets 2 bytes 91` |
| final `counter drop` | 0 | 0 |

C: the guard counter was 1 (P1, inside the merged range, was dropped). P2 from cl0 reached the TUN. 203.0.113.7 is not in pool C, so it was correctly forwarded.
D: guard counter 2 (P1 and P1b dropped). P2 from cl0 reached the TUN.

Excerpt for case B:
```
### TUN reader
TUN-RX v4 src=192.0.2.50 dst=192.0.2.10 len=43
TUN-RX v4 src=198.51.100.9 dst=192.0.2.10 len=47
TUN-RX v4 src=198.51.100.9 dst=192.0.2.10 len=46
### counters
oifname "plat0" iifname != "cl0" ip saddr { 192.0.2.0/24, 203.0.113.7 } counter packets 2 bytes 91 drop comment "plat-pool-source-guard" # handle 7
counter packets 0 bytes 0 drop # handle 12
```

## platd start gate (`hairpin_guard::check`) against the real nft output
`startcheck.sh <cfg> <snapshot> <label>` runs `platd run -c <cfg>` under `timeout 4` in ng-plat. It uses a private mount namespace that bind-mounts a directory holding only the snapshot over /etc/nftables.d, because SNAPSHOT is a hardcoded path.
rc=124 means platd was still running when the timeout killed it, so it got past the gate and logged `platd running`. rc=1 means the gate refused to start.

| label | cfg | snapshot | result |
|---|---|---|---|
| B-snapshot | B | setup's plat.nft.expected | PASS (rc=124, "platd running") |
| B-live-with-counters | B | `nft list table inet plat` after traffic (counter packets 2) | PASS (124) |
| C-snapshot | C | merged range `192.0.2.0-192.0.3.127` | PASS (124) |
| D-snapshot | D | `iifname != { "cl0", "bond1.40" }` | PASS (124) |
| B-guard-removed | B | guard line deleted | REFUSED (rc=1) |
| B-wrong-iface | B | `iifname != "ext0"` | REFUSED (1) |
| B-pool-not-covered | B | 203.0.113.7 replaced by 198.51.100.1 | REFUSED (1) |
| B-with-A-snapshot | B | hairpin-off rule (no iifname) | REFUSED (1) |
| A-hairpin-off-no-guard | A | guard removed | PASS (124; the gate does not apply) |

In every refused case the error was the same (misleading; fixed after this run, see Findings):
```
ERROR translation.cross_node_hairpin = true but /etc/nftables.d/plat.nft.expected accepts IPv4 before the pool-source guard: iifname "plat0" ip saddr { 192.0.2.0/24, 203.0.113.7 } accept; the host must drop pool-sourced IPv4 arriving outside translation.cluster_interfaces (run plat-tun-setup.sh, POAM-024)
```

## Findings
- No security bug. The rule enforces the policy on a real kernel. The gate parses everything real nft produced: a /32 without its prefix length, a one-element set without braces, merged ranges, a multi-interface set, and non-zero counters. It refuses to start when the guard is removed or does not match.
- Diagnostic issue (low): the "has no matching pool-source guard rule" error can never appear with the generated layout. When the guard is missing or does not match, the next rule (`iifname "plat0" ip saddr {pool} accept`) counts as "accepts IPv4 before the guard", so the operator gets a misleading message. That accept rule is outbound from the TUN and cannot shadow a rule for traffic going into the TUN. The gate still fails closed; only the message is wrong. Fixed on the same branch: only accepts that can match traffic towards the TUN count as shadowing, so these cases now report "has no matching pool-source guard rule" (`hairpin_guard.rs::missing_guard_is_reported_as_missing_not_shadowed`).
- Not in scope: this verified the snapshot plus the live rule, not plat-fwguard's sync between them. The run was in network namespaces, not with the systemd unit.

## Cleanup
`ip netns del ng-plat ng-ext ng-cl; rm -rf $NFTGUARD_WORK`. Afterwards `ip netns list` was empty. The host already had `table inet plat`, `table ip nat` and `plat0` before this run; they were untouched, because all my nft and links were inside the namespaces. Other VMs were not touched.
