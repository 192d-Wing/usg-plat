# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and SemVer.

## [Unreleased]

### Memory sizing checked against the config (branch `fix/poam-021`)

Closes POAM-021. SIEM schema unchanged.

- `platd check-config` prints the memory the configuration needs
  (sessions × 800 B + audit queue × 64 B + fragment memory per worker +
  HA replication rings + 256 MiB); `--format env` adds
  `PLAT_MEMORY_REQUIRED_BYTES`. The text format warns when the installed
  unit's (or `--unit <file>`'s) `MemoryMax` is lower.
- **Behaviour change:** `platd run` on Linux refuses to start when that
  requirement exceeds its cgroup v2 `memory.max` or 90 % of RAM, or when RAM
  cannot be determined. Raise `MemoryMax` or lower the limits.

### UDP syslog batching (POAM-018, branch `fix/poam-018`)

- On Linux, UDP syslog sends each sender-thread batch with `sendmmsg`
  (up to 64 datagrams per call) instead of one `send` per record. Still one
  record per datagram (RFC 5426) and in order; partial sends resume; loss
  counting and audit records are unchanged. Measured on Linux loopback:
  about 580 k records/s per destination, from about 310–360 k. New bench
  `audit_logger/udp_e2e_100k`. POAM-018 closed.

### Incremental sweeper (branch `fix/poam-012`)

Closes POAM-012. SIEM schema unchanged.

- The sweeper skips shards with nothing due (per-shard expiry hints, no lock
  taken), holds a shard lock for at most about 15 µs per chunk (resuming from
  a key snapshot), and each pass is budgeted to half of
  `dataplane.sweep_interval_ms`, resuming where it stopped. At 4 M sessions
  an idle pass drops from 44–90 ms to about 0.02 ms and the worker refresh
  p99.99 during passes from 58–469 µs to 6–17 µs (Lima VM). A pass with
  everything due is up to 1.3× slower.
- `bib4` uses 16 × `nat64.table_shards` shards (at most 65 536).
- New counter `plat_sweep_resumed_total`. `SweepStats` gains
  `shards_skipped`, `shards_visited`, `holds`, `long_holds`, `max_hold_ns`
  and `complete`; new `State::sweep_budget`, `State::set_sweep_chunk`.

### Review fixes for POAM-020/024/013 (branch `fix/poams-020-024-013`)

- The cluster configuration digest now also covers
  `translation.cross_node_hairpin`, `nat64.aggregate_prefix_len` and
  `nat64.max_subscribers_per_aggregate` (`cluster_interfaces` is node-local
  and not hashed). **The digest value changes**: a mixed-version cluster
  reports `digest_mismatch` until every member runs this version.
- The cross-node hairpin start gate is stricter: the
  `plat-pool-source-guard` rule must cover every `nat64.pool` CIDR and come
  before any rule that accepts IPv4.
- Cross-node hairpin off by default is documented as RFC deviation 11
  (RFC 4787 REQ-9, RFC 6146 §3.8); pool-source refusal is a silent BCP 38
  drop (deviation 12).

### Audit free-space threshold on by default (branch `fix/poam-020`)

Closes POAM-020. SIEM schema unchanged.

#### Breaking

- `audit.file.min_free_bytes` must be at least 1048576; an explicit `0`
  (formerly "disabled") fails validation. When `[audit.file]` omits it, it
  defaults to max(2 × `max_bytes`, 1 GiB) instead of 0.

#### Changed

- `check-config` (text) prints `audit file min_free_bytes: <n> (AU-5(1))`.

#### Compliance

- AU-5(1) and the FAU_STG.4 row are Implemented; CM-6 secure default
  caveat removed. Tests: `config_edges.rs::audit_edges`,
  `qa_check_config.rs::exit_codes_basic`.

### Spoofed pool sources (branch `fix/poam-024`)

Narrows POAM-024. SIEM schema unchanged.

#### Breaking

- Wire IPv4 packets whose source is inside `nat64.pool` (any node's slice)
  are now refused (`src_not_allowed`) by default, and the host forward
  policy drops them (`plat-pool-source-guard`). Clusters that rely on
  cross-node hairpinning must set `translation.cross_node_hairpin = true`
  and `translation.cluster_interfaces`.

#### Added

- `translation.cross_node_hairpin` (default `false`) and
  `translation.cluster_interfaces` (required with it, at most 16). With the
  switch on, `plat-tun-setup.sh` drops pool sources arriving on any other
  interface, and platd refuses to start unless that rule is in the
  installed-table snapshot (`/etc/nftables.d/plat.nft.expected`).
- `check-config --format env`: `PLAT_CROSS_NODE_HAIRPIN`,
  `PLAT_CLUSTER_IFACES`.

### Per-aggregate subscriber limit (branch `fix/poam-013`)

Closes POAM-013. SIEM schema unchanged (7): no field changes; new
`event.reason` value and drop reason only.

- Added `nat64.aggregate_prefix_len` (32..=`subscriber_prefix_len`, default
  56) and `nat64.max_subscribers_per_aggregate` (1..=2^24,
  default 256). A new subscriber whose aggregate is full is refused before
  any subscriber entry or port block is created: drop reason
  `aggregate_subscriber_limit`, `nat_resource_limit` record with
  `event.reason = "aggregate_subscriber_limit"` and the aggregate prefix as
  `plat.subscriber.prefix`, ICMPv6 Unreachable 1/3 like the other mapping
  limits. Counts follow the sweeper, adoption and handover release.
- Breaking: a config with `subscriber_prefix_len` below 56 fails validation
  until `aggregate_prefix_len` is set.

### Protocol completeness (branch `feat/protocol-completeness`)

Stacked on `feat/cluster-ha`. Closes POAM-001, POAM-002, POAM-011 and
POAM-023; adds POAM-034 and POAM-035. SIEM schema unchanged (7): new drop
reasons and counters only.

#### Breaking

- `translation.icmp_errors_per_sec` must be `0` or at least `4` (a quarter
  of the per-worker bucket is reserved for Packet Too Big / Fragmentation
  Needed). Configs with 1–3 fail validation.
- `translation.send_source_route_failed` defaults to `false`: source-routed
  IPv4 stays a silent `source_route` drop unless enabled.
- Behaviour: TTL / Hop Limit ≤ 1 packets now get ICMP Time Exceeded; an
  inbound TTL 1 packet that the inbound filter refuses is now counted
  `no_binding` / `filtered` instead of `hop_limit`. Non-first fragments are
  translated instead of dropped as `fragment`.

#### Added

- Fragment handling (RFC 6146 §3.4, RFC 7915): per-worker preallocated
  fragment table (`crates/plat-nat64/src/frag.rs`), out-of-order hold
  buffer, reassembly of fragmented ICMP echo, ICMP errors and zero-checksum
  IPv4 UDP only; RFC 5722 overlap detection (also IPv4), RFC 7112 / RFC 1858
  tiny-fragment checks, per-source caps, per-fragment slice checks; ICMP
  errors quoting fragments we sent are translated.
- Config `[translation.fragments]`: `max_entries`, `timeout_ms`,
  `max_fragments_per_datagram`, `max_buffered_fragments`,
  `buffer_slot_bytes`, `reassembly_slots`, `max_reassembly_bytes`,
  `udp_zero_checksum` (`"reassemble"` default, or `"drop"`); `check-config`
  prints the fragment memory per worker (ceiling 64 MiB).
- Locally generated ICMP errors (RFC 7915 §4.4/§5.4, RFC 6146 §3.5): Time
  Exceeded both directions, ICMPv6 Destination Unreachable when a limit
  refuses a mapping, Parameter Problem for an active Routing header,
  opt-in inbound Unreachable (3/1, 3/13) and Source Route Failed (3/5), IPv4
  fragmentation of ≤ 1280-byte IPv6 packets above `ipv4_mtu`. Keys
  `translation.send_time_exceeded`, `send_unreachable`, `send_param_problem`
  (default `true`), `send_inbound_unreachable`, `send_source_route_failed`
  (default `false`), and optional `translation.icmp_source_v6`.
- IPv4 Identification per RFC 7739 §5.3 (`crates/plat-nat64/src/ident.rs`):
  randomized per-worker counter table, one fresh ID per fragmented IPv6
  datagram.
- Drop reasons `fragment_timeout`, `fragment_overlap`, `fragment_tiny`,
  `fragment_too_many`, `fragment_table_full`, `fragment_buffer_full`,
  `reassembly_full`, `reassembly_too_big`, `fragment_unmatched`,
  `icmp_quote_unmatched`; counters `fragments_in_v6`, `fragments_in_v4`,
  `fragments_forwarded`, `fragments_buffered`, `datagrams_reassembled`,
  `fragmented_v6_to_v4`, `icmp_time_exceeded_sent`,
  `icmp_unreachable_sent`, `icmp_param_problem_sent`; gauge
  `plat_fragment_entries`.
- `make ir`: hot-path instructions per packet with cachegrind (Linux,
  `crates/plat-nat64/examples/ir.rs`).

#### Changed

- Fragmentation Needed is decided before the inbound session update and
  sent only when the read-only filter admits the packet (POAM-023); inbound
  Time Exceeded and Source Route Failed are gated the same way.
- Engine API: `Nat64::new_worker`, `Nat64::housekeep`, `Verdict::Consumed`
  (held fragment); `platd` workers run housekeeping every 64 packets and on
  an idle receive.

#### Compliance

- POAM-001, POAM-002 (with documented deviations), POAM-011 and POAM-023
  closed; POAM-034 (stale fragment mapping within `timeout_ms`, AU-10/AU-12
  attribution risk) and POAM-035 (per-worker fragment state; not observed on
  Linux multiqueue TUN, LINUX_VERIFICATION L24) added. Deviations listed in
  `docs/compliance/RFC_COMPLIANCE.md` "Protocol deviations".
- Hot path (cachegrind, `plat-linux`): v6→v4 1107 → 1126 instructions per
  packet (+1.7%), v4→v6 940 → 925 (−1.6%), measured after fix round 1.

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
