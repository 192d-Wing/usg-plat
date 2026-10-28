# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and SemVer.

## [Unreleased]

### Added

- Stateful NAT64 / 464XLAT PLAT engine: RFC 6052 mapping, RFC 7915 in-place
  translation, ICMP error translation, RFC 6146 BIB/session tables with
  endpoint-independent mapping, address-dependent filtering, TCP state
  machine, hairpinning.
- Bulk port-block allocation with paired pooling and per-subscriber limits.
- High-speed SIEM attribution logging (log schema v4, see Changed): non-blocking queue,
  JSON/CEF, RFC 5424 syslog over UDP/TCP, SHA-256 chained local file,
  `platd verify-log`.
- Multithreaded `platd` daemon on Linux multiqueue TUN with CPU pinning,
  sweeper, loopback Prometheus metrics, `check-config`.
- Cluster pool partitioning with route-announcement prefixes.
- `/plat-workflow` multi-agent development skill and subagents.
- GitHub Actions CI (`.github/workflows/ci.yml`): `make fmt`, `make clippy`,
  `make check-linux`, `make test` (native Linux), `make security`; actions
  pinned to commit SHAs, `contents: read`, toolchain from `rust-toolchain.toml`.
  `Swatinem/rust-cache` (cache saved only on `main`); Dependabot
  (`.github/dependabot.yml`) checks GitHub Actions and Cargo weekly.
- Supply-chain gate: `cargo-deny` (`deny.toml`) alongside `cargo-audit`.
- IPv4 fragmentation of DF=0 packets whose IPv6 form exceeds
  `translation.lowest_ipv6_mtu`; locally generated ICMPv4/ICMPv6 errors
  (Packet Too Big / Fragmentation Needed), rate-limited by
  `translation.icmp_errors_per_sec`.
- Audit pipeline fails closed: on queue overflow, disk-full or I/O error the
  logger enters a degraded state and new bindings are refused until recovery
  (`audit.on_overflow = "refuse_new_bindings"`, the default).
- Audit hash chain v2+: each file opens with an `audit_chain_continue` header
  linking to its predecessor; checkpoints carry node id and schema;
  `platd verify-log` verifies chain continuity across files.
- `platd check-config --format text|env`.
- `deploy/systemd/plat-tun-setup.sh`: TUN, routing and nftables setup run
  before the unprivileged daemon.

### Changed

- **Breaking (config behaviour):** `translation.allow_non_global_destinations`
  defaults to `false`; RFC 6890 non-global IPv4 space (RFC 1918, 100.64/10,
  documentation ranges, ...) is refused as a destination and as an inbound
  source under every prefix. Set it to `true` for NSP deployments that must
  reach such space.
- **Breaking (config validation):** the Well-Known Prefix cannot be combined
  with a non-global pool; `audit.on_overflow = "refuse_new_bindings"` (the
  default) requires `[audit.file]` (syslog-only configs must set
  `"drop_and_alert"`).
- New config keys (all defaulted): `translation.lowest_ipv6_mtu`,
  `icmp_errors_per_sec`, `copy_tos`, `wkp_non_global_icmp_errors`,
  `allow_non_global_destinations`; `nat64.max_subscribers`;
  `audit.file.max_files`, `audit.file.min_free_bytes`.
- **SIEM log schema v4** (`LOG_SCHEMA_VERSION` 1 -> 4): chain-continue header,
  two-phase prune records, CEF `cn4`/nodeId, `cs6`/schema and `outcome`.
  SIEM parser owners must update. Audit files from schema 1 (chain v1) no
  longer verify.
- systemd unit runs with no capabilities (empty `AmbientCapabilities` and
  `CapabilityBoundingSet`); TUN/routing set up beforehand by the setup script.
- Hairpinning works under the default policy with a non-global pool.

### Security

- Per-subscriber and subscriber-table limits (`nat64.max_subscribers`).
- Expired sessions no longer match on the data path.
- SEC-301: wire IPv4 packets sourced from this node's own pool slice are
  refused (`src_not_allowed`); other nodes' slices are still accepted for
  cross-node hairpin, so the cluster edge must filter the pool prefix as an
  ingress source (POAM-024).
- SEC-302: a deferred port-block release that meets a disconnected audit
  sink is counted once in `plat_audit_lost_total`; new counter
  `plat_pool_releases_deferred_total`.
- `// POAM:` code markers added for POAM-010, 011, 012, 013, 018, 020, 023.
