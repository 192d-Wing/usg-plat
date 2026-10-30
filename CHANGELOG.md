# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and SemVer.

## [Unreleased]

### Cluster high availability (branch `feat/cluster-ha`)

HA is off unless `[cluster.ha] enabled = true`. The peer wire protocol is
unreleased and unversioned across builds: **all members and the witness must
run the same build.** Linux three-VM items L19–L23 are not fully re-run.

#### Breaking

- SIEM schema **6 → 7** (`plat_audit::LOG_SCHEMA_VERSION = 7`). SIEM parser
  owners must update: new `cluster_*` records and `service_start` fields
  `cluster.mode`, `cluster.config_digest`, owned slices. See
  `docs/compliance/SIEM_LOGGING.md`.
- Released port blocks now cool down for `nat64.block_cooldown_secs`
  (default 120, range 120..=3600) before reuse (POAM-010 closed).

#### Added

- `plat-cluster`: `membership` (leases, quorum, leader election), `view`,
  `slices` (fixed /28 slices, weighted rendezvous), `codec` (peer wire
  format), `digest` (config digest); simulation tests `tests/sim.rs`.
- `plat-nat64::repl` (export/import of blocks, BIBs, subscriber directory),
  TCP pickup window for adopted BIBs; `plat-io::cred` (socket peer
  credentials); `plat-tls` peer (mutual, serverAuth+clientAuth) configs;
  `services/platd/src/cluster/` (control, replicator, peer channel).
- Config: `[cluster] partition = "contiguous"|"slices"` and slice settings,
  `[cluster.members]`, `[cluster.ha]` (lease, heartbeat, auto_failover,
  failback, `tcp_adopt_secs`, ring sizes, `tls`), `[cluster.steering]`
  (`mode = "drop"|"count"`; `forward` rejected), `nat64.block_cooldown_secs`.
- Audit records: `cluster_view_change`, `cluster_member_state`,
  `cluster_slice_acquire`, `cluster_slice_release` (incl. handover),
  `nat_port_block_adopt`, `cluster_peer_server`, `cluster_peer_client`,
  `cluster_peer_rejected`, `cluster_peer_suppressed`,
  `cluster_replication_gap`, `cluster_hook`, `cluster_operator_command`.
- Drop reasons `wrong_node`, `cluster_fenced`, `missteered`.
- Metrics: `plat_cluster_{epoch,leader,lease_remaining_ms,slices,peer_up,
  peer_rejected_total,handovers_total,takeovers_total,resync_total,
  repl_events_total,repl_dropped_total,repl_lag_records,
  repl_ack_timeouts_total,directory_entries,hook_failures_total,
  state_persist_failures_total,steer_missteered_total}`,
  `plat_pool_{blocks_free,blocks_total,releases_deferred_total,
  paired_exhausted_total}`, `cluster_reserve_starved`; mgmt `/cluster`.
- CLI: `platd witness`, `platd cluster status`, `platd cluster takeover
  [--force]`, `platd cluster restore` (operator socket `state_dir/ctl.sock`,
  root or daemon uid only).
- Deploy: `deploy/hooks/frr-{announce,withdraw}.sh`,
  `deploy/systemd/plat-v6-announce.sh` with
  `platd.service.d.example/v6-announce.conf` and
  `frr.service.d.example/plat-v6-announce.conf`; `PLAT_V6_MODE` /
  `PLAT_V4_POOL` in `plat-tun-setup.sh`; Lima `deploy/lima/*.yaml`;
  cluster test bed `deploy/tests/cluster/` (F1–F13, takeover trials).
- Dependencies: `rustix` (workspace, `event`/`net`/`process`) and `libc`
  (`plat-io`, peer credentials). Both MIT/Apache-2.0; `cargo deny` clean.

#### Compliance

- POAM-010 closed; POAM-007 Partial; POAM-017 split (a) open, (b) partial,
  (c) closed with HA; new POAM-028 to POAM-033.

### Documentation: Linux TUN throughput (branch `perf/linux-throughput`)

- README "Measured performance" and ARCHITECTURE.md: indicative Linux TUN
  numbers (Lima VM on Apple M2 Max, virtio, main @a080417): about
  0.45–0.62 Mpps per worker, 1→2 workers about 1.75×, 4 workers
  generator-bound at 1.05–1.60 Mpps, v4→v6 return path, CPU split kernel 86% /
  engine+xlat about 10% / locks about 0.7%. Validate on bare metal before sizing.
- POA&M: POAM-015 downgraded to "Risk accepted pending AF_XDP" with
  re-check trigger; POAM-016 evidence and options added (still Open).
  NIST SC-5(2) row cites the measurement. No code changes.

### Linux validation (branch `fix/linux-validation`)

Found by running `docs/compliance/LINUX_VERIFICATION.md` on Ubuntu 24.04.5
aarch64 / systemd 255 (2026-10-29); results recorded there.

#### Breaking / deploy changes (upgrade steps in README)

- `platd.service` no longer uses `LogsDirectory=`/`LogsDirectoryMode=`.
  `/var/log/plat` comes from the new tmpfiles.d entry
  `deploy/systemd/plat.tmpfiles.conf` (install as
  `/usr/lib/tmpfiles.d/plat.conf`): `d /var/log/plat 2750 plat plat-log`.
  The directory must exist before the first start (`systemd-tmpfiles
  --create`), otherwise the start fails with `226/NAMESPACE`.
- New system group `plat-log`: audit files are `-rw-r----- plat:plat-log`
  in a setgid 2750 directory. Log shippers and `verify-log` operators join
  `plat-log` (replaces the ACL guidance); the setup script re-groups existing
  files (bounded depth, `-xdev`, `plat`-owned regular files with one link).
- nftables: the forward policy is written to `/etc/nftables.d/plat.nft`
  and `include "/etc/nftables.d/*.nft"` is added once to
  `/etc/nftables.conf` (an older exact `plat.nft` include is replaced), so
  reload/restart of `nftables.service` restores it. Snapshot
  `/etc/nftables.d/plat.nft.expected`.
- New units `plat-fwguard.service` / `plat-fwguard.timer` (every 2 s, enable
  on its own) and drop-in `nftables.service.d/plat-fwguard.conf`: disable
  IPv4/IPv6 forwarding when `table inet plat` is missing or modified (fail
  closed; journal message). Residual window for direct `nft` changes:
  POAM-019.
- `platd verify-log` exit code **3** for a recovery gap after a damaged
  start, and new flag `--allow-recovery`; `--allow-gap` does not cover it.
  Scripts that treat any non-zero exit as failure are unaffected; scripts
  that expect only 0/1/2 must handle 3.
- Unit: `Wants=`/`After=time-sync.target` only (no
  `systemd-time-wait-sync.service`; enable `chrony-wait.service` or
  `systemd-time-wait-sync.service` to match the time daemon);
  `StartLimitIntervalSec=60`, `StartLimitBurst=5`; `RemoveIPC=yes`,
  `ProcSubset=pid`; `MemoryMax` sizing comment now 800 B/session.

#### Fixed (Linux validation)

- `plat-tun-setup.sh` failed on every start because it rejected the
  `PLAT_FIPS` / `PLAT_MGMT_TLS` keys of `check-config --format env`; it now
  requires `PLAT_*=` lines and ignores unused keys.
- Setup script removes every route on the TUN, of any protocol (was only
  `proto boot`), and verifies all main-table routes.
- Test-hook environment variables of the deploy scripts are honoured only
  with `PLAT_TEST_MODE=1`.
- Audit file: a failed batch write (short write, ENOSPC) is cut back to the
  last durable checkpoint, so no torn record or record outside the chain
  remains; a failed cut-back is reported (`truncate_failed`).
- Every checkpoint is `fdatasync`ed and a new file's header is synced before
  the rename (a power cut left a 0-byte live file).
- Rotation never lets a file exceed `max_bytes` (batches are split), except
  the single recovery batch after an outage.
- No sequence-number reuse after an emptied or damaged newest file: durable
  sequence lease `.<name>.seq` (blocks of 2^20; opened `O_NOFOLLOW`, must be a
  regular file; failures retried, counted and audited; sequence exhaustion
  fails closed without wrapping).
- `verify-log`: an ENOSPC gap announced by `audit_output_failure` with the
  exact `lost` count passes without `--allow-gap`; a partial line inside the
  chain needs a matching `audit_recovery`; an `audit_recovery` after an
  intact file is a broken link; stacked damage is reported as a recovery gap.
- README install: the config is installed after `plat`/`plat-log` are created, as `root:plat 0640` (was `root:root`, unreadable by platd); `systemd-tmpfiles --create` runs before the first start; the post-start `curl` retries until the listener is up.
- Prometheus `interface` label values are escaped.
- Flaky test `rejection_flood_is_rate_limited_and_summarised`.

#### Added (Linux validation)

- Log schema **6**: record `audit_recovery` (`plat.reason`
  `empty_file`/`missing_header`/`truncated_tail`,
  `plat.audit.last_checkpoint_seq`, `plat.audit.max_seq`,
  `plat.audit.lease_state` `ok`/`absent`/`corrupt`/`inflated`/`high`);
  optional `plat.reason` on `audit_output_failure` (`truncate_failed`,
  `seq_lease_failed`, `seq_exhausted`). See `SIEM_LOGGING.md`.
- Metrics `plat_tun_rx_dropped_total{interface}`,
  `plat_tun_tx_dropped_total{interface}` (Linux kernel TUN drops) and
  `plat_audit_seq_lease_failures_total`.
- `make test-deploy` (`sh -n`, shellcheck, stubbed run of the deploy
  scripts against real `check-config` output; fails without shellcheck when
  `CI=true`), run in the CI job `test (native Linux)`.

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
- Linux packages: `make deb`, `make rpm`, `make packages` (cargo-deb and
  cargo-generate-rpm metadata in `services/platd/Cargo.toml`, `dist`
  profile without debug info), built natively for x86_64 and aarch64 by
  `.github/workflows/packages.yml`. The packages install the binary, setup
  and guard scripts, systemd units, nftables drop-in, `plat` user and
  `plat-log` group (`deploy/sysusers.d/plat.conf`), `/var/log/plat` and the
  example config as a conffile; they never enable or restart a unit. Not
  signed.
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
