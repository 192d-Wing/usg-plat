# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and SemVer.

## [Unreleased]

### Added

- Revocation metrics (SI-4): `plat_ocsp_fetch_seconds` and
  `plat_crl_fetch_seconds` histograms (`outcome` = `ok`/`error`, HTTP exchange
  only), `plat_crl_next_update_seconds{issuer}` gauge and
  `plat_crl_state_dir_sync_failures_total` counter.
- FIPS TLS (POAM-004, POAM-005): rustls with the aws-lc-rs FIPS crypto provider
  (TLS 1.3 only; FIPS cipher suites; kx X25519MLKEM768/P-256/P-384, hybrid off via
  `tls.pq_hybrid = false`). New `audit.syslog[].transport = "tls"` (RFC 5425
  octet-counted framing, CA-pinned server verification, optional client cert)
  and mTLS remote management (non-loopback `management.listen` requires a TLS
  block; client cert required; subject/SAN allow-list; every connection audited).
  Full-chain revocation checking (OCSP first, CRL fallback, `hard_fail` default).
  Key-file permission checks and zeroized key buffers. `check-config` prints a TLS summary.
- `make check-notls` CI step keeps the TLS-off (`--no-default-features`) build compiling.
- New crate `plat-tls` (FIPS init, TLS policy, key/cert loading, identity,
  verifiers, deadline-bound TLS I/O, OCSP/CRL revocation checker and the
  `plat-revocation` refresher thread).
- OCSP client (RFC 6960): stapling for the syslog collector leaf, SHA-256
  CertID (`cert_id_hash = "sha1"` option for RFC 5019), RFC 8954 nonce,
  delegated-responder checks, bounded cache with single-flight fetches.
- CRL support (RFC 5280): `crl.files`, `crl.urls` and HTTP CDPs; named
  IssuingDistributionPoint enforced (URI and directoryName); delta/indirect
  CRLs unusable; duplicate extensions rejected; reason `not_yet_valid` for a
  future thisUpdate; cRLNumber high-water mark per issuer and scope,
  persisted to `cache_dir/crl-numbers` (serialised atomic writes, retried on
  failure).
- Management mTLS listener (`plat-mgmt`, `plat-mgmt-conn` threads):
  `max_connections` (default 4), `management.tls.max_connections_per_ip`
  (default 2; IPv4 per address, IPv6 per /64, IPv4-mapped = IPv4), 2 s
  ClientHello deadline, `handshake_timeout_ms` (default 5000).
- Log schema v5 records: `management_connection` (incl.
  `plat.mgmt.allow_entry`, `tls.client.x509.alternative_names`; CEF
  `cs2`/`cs3`), `management_connection_suppressed`, `tls_revocation_check`,
  `revocation_source_refresh` (transitions `failing`, `recovered`,
  `stale_dropped`, `rollback_rejected`, `state_rejected`,
  `state_persist_failed`); `service_start` `plat.fips`/`plat.fips_provider`;
  `audit_remote_loss` `plat.reason` (`io`, `tls_handshake`, `tls_verify`,
  `tls_revocation`; TCP losses now report `io`).
- Metrics: `plat_fips_mode`, `plat_mgmt_connections_total`,
  `plat_mgmt_rejections_total`, `plat_revocation_checks_total`,
  `plat_revocation_refresh_failures_total`, `plat_ocsp_cache_entries`,
  `plat_crl_cache_entries`, `plat_crl_cache_bytes`,
  `plat_crl_state_errors_total`, `plat_tls_cert_expiry_seconds`,
  `plat_audit_remote_tls_handshakes_total`,
  `plat_audit_remote_tls_failures_total`.
- `check-config --format env` adds `PLAT_FIPS` and `PLAT_MGMT_TLS`.
- systemd unit: `StateDirectory=plat/revocation` (mode 0700) for the
  optional CRL cache.

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
- Zensical documentation site (`zensical.toml`, `make docs`, `make docs-serve`)
  with a GitHub Pages workflow (`.github/workflows/docs.yml`).

### Changed

- `aws-lc-fips-sys` pinned to `~0.14.4` (AWS-LC-FIPS 4.2.0) in `plat-tls`.
- SC-13 status corrected to Partial: AWS-LC-FIPS 4.x is CMVP Modules In
  Process, not validated; certificates #5298/#5314 (v3.1) do not cover this
  build (POAM-026).
- **Breaking (log schema v5):** `LOG_SCHEMA_VERSION` 4 -> 5; `service_start` gains
  FIPS status, new management-connection and revocation records. SIEM parser
  owners must update.
- **Breaking (config):** new `tls`/revocation/management TLS settings; `require_fips`
  defaults to `true` - `platd` refuses to start if the FIPS module is not active.
- **Breaking (build):** the crypto boundary is no longer pure Rust. Building now
  requires CMake, Go (>= 1.18) and a C compiler (plus `gcc-aarch64-linux-gnu`
  for aarch64 cross-checks; `make check-linux` falls back to TLS-off without it).
- `deny.toml`: allow `ISC`; `OpenSSL` permitted only for `aws-lc-fips-sys`.
- Version: minor bump at release (pre-1.0, config + log schema breaking).
- **Breaking (config):** `management.tls.allowed_clients` entries must be typed
  (`cn:`, `dns:`, `uri:`, `sha256:<hex>`); bare entries are a validation error.
- **Breaking (config):** a non-loopback `management.listen` requires
  `[management.tls]`; with it the single listener is mTLS only.
- `tls.pq_hybrid` defaults to `true`; NIAP NDcPP evaluated configurations must
  set it to `false`.
- `check-config` (text and env) loads all TLS files and checks key permissions;
  exit 2 on failure.
- Key files with setuid/setgid/sticky bits are rejected; FIFOs and devices at
  any configured TLS/CRL path are rejected instead of blocking.
- Revocation HTTP fetcher rejects non-token header names, whitespace before
  the colon and obs-fold lines (documented deviation from RFC 9112 §5.2).
- `Event` is no longer `Copy` (TLS records carry text behind `Arc`);
  data-plane events are unchanged.
- Workspace builds `plat-audit` without TLS by default for data-plane crates;
  `platd`'s `tls` feature enables it.
- Docs: NIST mapping (AC-17, SC-8, IA-3, IA-5(2), SC-12, SC-13; CM-3 and SA-11
  now Implemented), POA&M (POAM-004/005 closed, POAM-025 added), SIEM schema
  v5, RFC compliance TLS/revocation section, architecture and README.
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

- SEC-201: the CRL disk cache fsyncs the directory after the atomic rename;
  failures are counted in the new `plat_crl_state_dir_sync_failures_total`.
- SEC-202: a rejected regular `crl-numbers` file is moved aside as
  `crl-numbers.rejected.<ts>` (exclusive name, fchmod 0600 via O_NOFOLLOW;
  just-moved plus 2 newest others kept); non-regular entries are left in
  place; a failed move-aside counts in `plat_crl_state_errors_total`. Own
  stale temporary files older than start − 60 s are removed at start.
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
