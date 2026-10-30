# SIEM Logging and NAT Attribution

Schema version: **7** (`plat.schema`, `plat_audit::LOG_SCHEMA_VERSION`).
Source: `crates/plat-audit`.

## Purpose

An IPv4 abuse report or law-enforcement request names an IPv4 address, a
port, and a time. Behind a NAT64 many subscribers share that address, so the
PLAT must log enough to answer "which subscriber held 192.0.2.10:40123 at
14:16:00Z?" (RFC 6888 §4, RFC 7422), and do it fast enough that logging
never limits forwarding.

## Schema history

| Version | Change |
|---------|--------|
| 1 | Initial schema; chain v1 (`SHA-256("usg-plat audit chain v1")` genesis). |
| 2 | Chain v2: `audit_chain_continue` file header, header-seeded chain, checkpoint `seq_first`/`seq_last` hashed. New records `audit_output_failure`, `audit_remote_loss`. Checkpoints gain `plat.schema` and `plat.node_id`. New `event.reason` `subscriber_table_limit`. Every CEF record gains `cn4` (node id), `cs6` (schema) and `outcome`. |
| 3 | New records `audit_storage_threshold` (AU-5(1)) and `audit_retention_prune` (AU-9, AU-11). |
| 4 | `audit_retention_prune` gains `plat.audit.state` (`scheduled` with outcome `unknown`, then `deleted` / `failed`; CEF `act=`). `audit_storage_threshold` gains state `unknown` (free space undeterminable; no `plat.audit.available_bytes`). |
| 5 | TLS (branch `feat/fips-tls`). `service_start` gains `plat.fips` / `plat.fips_provider` (CEF `cn2`/`cs1`). `audit_remote_loss` gains optional `plat.reason` (`io`, `tls_handshake`, `tls_verify`, `tls_revocation`; CEF `reason`); TCP losses now carry `io`. New records `management_connection`, `management_connection_suppressed`, `tls_revocation_check`, `revocation_source_refresh`. First records that carry peer-supplied text (certificate subject, SANs, issuer DN, serial, URLs), sanitised and capped (see Injection safety). |
| 6 | Branch `fix/linux-validation` (unreleased). New record `audit_recovery` (`plat.reason` `empty_file`/`missing_header`/`truncated_tail`, `plat.audit.last_checkpoint_seq`, `plat.audit.max_seq`, `plat.audit.lease_state` `ok`/`absent`/`corrupt`/`inflated`/`high`; CEF `reason`, `cn3` `lastCheckpointSeq`, `cn2` `maxSeq`, `cs4` `leaseState`). `audit_output_failure` may carry `plat.reason` (`truncate_failed`, `seq_lease_failed`, `seq_exhausted`; CEF `reason`). New lease file `.<name>.seq`. `verify-log` exit 3 and `--allow-recovery`. |
| 7 | Branch `feat/cluster-ha` (unreleased). Cluster high availability. New records `cluster_view_change`, `cluster_member_state`, `cluster_slice_acquire`, `cluster_slice_release`, `nat_port_block_adopt`, `cluster_peer_rejected`, `cluster_peer_suppressed`, `cluster_replication_gap`, `cluster_hook`, `cluster_operator_command`. `nat_port_block_release` may carry `plat.release_reason` (`handover`; CEF `reason`). `service_start` may carry `cluster.node_id`, `cluster.mode`, `cluster.config_digest`, `cluster.slices`, `cluster.slice_count`, `cluster.member_count` (CEF `cs2`/`cs3`/`cs4`/`cn3`). `tls_revocation_check` gains roles `cluster_peer_client` / `cluster_peer_server`. Additive within schema 7 (branch `fix/poams-020-024-013`): `nat_resource_limit` `event.reason` value `aggregate_subscriber_limit` (POAM-013); `cluster.config_digest` now also covers `cross_node_hairpin`, `aggregate_prefix_len` and `max_subscribers_per_aggregate` (value changes, field unchanged). Chain format unchanged. |

Branch `feat/protocol-completeness` (unreleased) adds drop reasons, counters
and one gauge but changes no record type or field name, so the schema stays
7. New `plat.counter.name` values can appear in `dataplane_counter` records
(see below); parsers that enumerate counter names must accept them.

Files written by the v1 chain (schema 1) **no longer verify** with
`platd verify-log`: the first line must be an `audit_chain_continue` header.
Files written under schemas 2–7 use the same chain v2 and verify.

## Controls

| Control | Implementation | Evidence |
|---------|----------------|----------|
| AU-2, AU-12 | Port-block allocate/release, binding create/delete (session mode), resource limits, queue overflow, service start/stop, periodic drop counters, audit output failure, remote loss, storage threshold, retention prune. An allocation record is queued before the block is used; a block returns to the pool only after its release record is queued. | `event.rs`; `plat-nat64/tests/engine.rs::udp_mapping_reply_and_block_log`, `session_mode_logs_bindings`; `hardening.rs::block_is_not_reused_before_its_release_record_is_queued` |
| AU-3 | Who (`source.ip`, `plat.subscriber.prefix`), what (`event.action`), when (`@timestamp`), where (`observer.name`, `plat.node_id`), outcome (`event.outcome`; CEF `outcome`), NAT address and ports, sequence. | `format.rs::json_port_block_record`, `cef_and_syslog`, `storage_and_retention_records` |
| AU-4 | Bounded queue `audit.queue_capacity`; rotation at `audit.file.max_bytes`; retention `audit.file.max_files` (0 = keep all, the default); free-space threshold `audit.file.min_free_bytes` (default max(2 × `max_bytes`, 1 GiB), 0 refused). | `config.rs`; `config_edges.rs::audit_edges` |
| AU-5 | `on_overflow`: `refuse_new_bindings` (default; requires `[audit.file]`) or `drop_and_alert`. A full queue, a failed local file or low free space makes `has_room()` false, so new bindings are refused; `/healthz` returns 503. Records: `audit_queue_overflow`, `audit_output_failure`. Recovery is declared only after a checkpoint in the new file is synced. | `health.rs::file_failure_degrades_fails_closed_and_recovers`; `outputs.rs::queue_overflow_produces_an_audit_record`; `pipeline.rs::overflow_is_counted_and_reported`; `logger.rs::tests::full_volume_never_rotates_prunes_or_flaps` |
| AU-5(1) | `min_free_bytes` threshold (default max(2 × `max_bytes`, 1 GiB) when `[audit.file]` omits it; 0 and values below 1 MiB refused, POAM-020 closed); `audit_storage_threshold` records; fail closed when free space cannot be determined. | `logger.rs::tests::free_space_threshold_degrades_and_recovers`, `undeterminable_free_space_fails_closed_once` |
| AU-6(3), AU-6(4) | ECS-style field names, CEF, RFC 5424 syslog to central collectors. | `format.rs`; `pipeline.rs::file_and_syslog_records_with_valid_chain` |
| AU-8 | JSON and syslog header: RFC 3339 UTC with microseconds from the system clock. CEF `rt`: milliseconds. The platform must run NTP/PTP. | `format.rs::timestamps` |
| AU-9 (Partial) | File mode 0640 in a `plat:plat-log` 2750 directory; SHA-256 chain v2 across batches and files; per-checkpoint `fdatasync`; a failed batch is cut back to the last checkpoint; sequence numbers continue across restarts and files and are never reused (durable lease `.<name>.seq`, `audit_recovery` after a damaged start); atomic rotation; `platd verify-log` (exit 3 for a recovery gap). The chain is unkeyed (POAM-003); a deleted tail plus restart looks like a crash (POAM-027). Linux: L12, L13, L16 PASS (LINUX_VERIFICATION.md). | `health.rs::restart_continues_chain_and_sequence`, `header_and_checkpoint_metadata_are_bound_into_the_chain`, `missing_live_file_resumes_from_newest_rotated_file`; `pipeline.rs::tampering_is_detected` |
| AU-9(2) (Partial) | Best-effort copy on the collectors; every undelivered record is counted and recorded locally (`audit_remote_loss`, with `plat.reason`). `transport = "tls"` (RFC 5425, TLS 1.3, FIPS provider) protects the copy in transit; UDP/TCP remain selectable without TLS. | `health.rs::stalled_collector_never_stalls_the_local_file`; `outputs.rs::tcp_syslog_unreachable_counts_output_errors_without_blocking`; `plat-audit/tests/tls_syslog.rs` (6 tests) |
| AC-17, AU-2 (management) | One `management_connection` record per management connection (mTLS mode): accepted always; rejections through a token bucket (10/s, burst 20) with a `management_connection_suppressed` summary. | `services/platd/src/mgmt/tests.rs::rejected_clients_are_refused_and_audited_once`, `rejection_flood_is_rate_limited_and_summarised` |
| IA-5(2), AU-2 (revocation) | One `tls_revocation_check` per checked certificate (every non-root certificate of the chain); `revocation_source_refresh` on refresher state transitions only. | `plat-tls/tests/revocation_fallback.rs`; `format.rs::revocation_records` |
| SC-13 | `service_start` records whether the FIPS module is active. | `services/platd/src/run.rs::service_start_records_fips_state` |
| AU-2, AU-3, AU-12 (cluster, schema 7) | With `[cluster.ha]`: view changes, member state, slice acquire/release, one `nat_port_block_adopt` per taken-over block, peer refusals (rate-limited, with a summary), replication gaps, route-hook runs and operator commands (peer uid/pid). A slice is set Active only after its `cluster_slice_acquire` and every adopt record are queued; under `refuse_new_bindings` the slice stays fenced until they all fit. A planned handover writes `nat_port_block_release` with `plat.release_reason:"handover"` for every block given away. `service_start` carries the node's cluster mode and config digest. | `plat-audit/src/format.rs::cluster_records_schema_7`; `plat-audit/tests/pipeline.rs::cluster_records_verify`; `plat-nat64/tests/cluster.rs::adoption_is_logged_before_use_and_refused_without_queue_room`, `handover_release_logs_and_clears_the_slice`; `plat-nat64/src/state.rs::adopt_retry_queues_each_record_once`, `refused_then_retried_adoption_logs_each_record_once`; `services/platd/src/cluster/tests.rs::join_replicate_takeover_rejoin_failback`, `manual_takeover_and_restore`, `operator_command_waits_for_audit_room`, `regain_waits_for_audit_room`, `non_owner_replication_is_refused`, `duplicate_id_and_digest_mismatch_are_refused` |
| AU-10 | Planned: hash chain gives integrity against editors who cannot recompute it, not origin authentication. | POAM-003 |
| AU-11 | `max_files > 0` deletes the oldest rotated files after a size rotation, each deletion recorded (`audit_retention_prune`); default 0 keeps every file. The site sets the retention period and archives before deletion. | `health.rs::retention_keeps_at_most_max_files`, `retention_records_every_deletion`, `retention_follows_the_chain_after_a_backward_clock_step` |

## Performance design

- Data plane: build a plain-data event (≤ 48 bytes) and `try_send` it to a
  bounded MPMC queue. No allocation, no formatting, no syscall, never
  blocks. (Since schema 5 `Event` is no longer `Copy`: the TLS records carry
  peer text behind an `Arc`; they are built on management-connection and
  syslog-sender threads, never on a worker.)
- Logger thread (`plat-audit`): drains up to `batch_max` events per wake-up
  (or every `flush_interval_ms`), formats JSON lines, writes the local file
  once per batch and appends one checkpoint per batch. Each checkpoint is
  made durable with `fdatasync` (Linux; `fsync` elsewhere) before the batch
  counts as written, so the sync rate is one per batch: size `batch_max`
  (example 4096) so that the record rate divided by `batch_max` stays well
  within the volume's sync rate. Rotation splits a batch so that no file
  exceeds `max_bytes`, except the single recovery batch after an outage.
- Each syslog destination has its own sender thread (`plat-syslog-<i>`)
  behind a bounded hand-off of 64 batches. The logger only offers the batch
  (`try_send` of a shared `Arc`); a slow or unreachable collector never
  stalls the local file or the event queue.
- Port-block mode logs one record per block (default 512 ports) instead of
  per flow.

## Record format (JSON lines, file and `format = "json"` syslog)

Common fields on every sequenced record:

| Field | Type | Meaning |
|-------|------|---------|
| `@timestamp` | RFC 3339 UTC, µs | Event time |
| `plat.schema` | int | Schema version (7) |
| `event.sequence` | int | Monotonically increasing. With `[audit.file]` configured it continues across restarts and across files, and is never reused while any audit file or the lease file `.<name>.seq` is present (with every audit file removed but the lease kept, numbering resumes above the lease, `lease_state` `high`); numbers of records after the last checkpoint of a crashed file are skipped, not reused. Without a file (syslog only) it restarts at 1 with each process. A gap means records were lost (see AU-5 records). |
| `event.kind`, `event.category` | `event`, `network` | ECS categorisation |
| `event.action` | string | Record type, below; also the syslog MSGID |
| `observer.type`, `observer.name` | `nat64`, node name | Which PLAT |
| `plat.node_id` | int | Cluster node index |
| `event.outcome` | `success`, `failure`, `unknown` | Absent on `dataplane_counter` |

Not sequenced: `audit_chain_continue` and `audit_checkpoint` exist only in the
local file, are never sent to syslog, and carry no `event.sequence`,
`event.kind`, `event.category` or `observer.type`.

### Record types

| `event.action` | Syslog severity | `event.outcome` | Extra fields |
|----------------|-----------------|-----------------|--------------|
| `nat_port_block_allocate` | 6 | `success` | `source.ip` (subscriber prefix address), `plat.subscriber.prefix`, `source.nat.ip`, `plat.nat.port_start`, `plat.nat.port_end` |
| `nat_port_block_release` | 6 | `success` | as allocate, plus `event.duration` (ns, whole seconds the block was held); optional `plat.release_reason` (`handover`, schema 7) |
| `nat_port_block_adopt` | 6 | `success` | as allocate, plus `plat.block.allocated_us` (original allocation, UTC µs), `cluster.epoch`, optional `cluster.prev_owner` |
| `nat_binding_create` | 6 | `success` | `network.transport` (`tcp`/`udp`/`icmp`), `source.ip` (full IPv6 host), `source.port`, `source.nat.ip`, `source.nat.port` |
| `nat_binding_delete` | 6 | `success` | as create, plus `event.duration` |
| `nat_resource_limit` | 4 | `failure` | `event.reason`, `source.ip`, `plat.subscriber.prefix` |
| `service_start`, `service_stop` | 5 | `success` | `service.version`; `service_start` also `plat.fips` (bool), `plat.fips_provider`, and (schema 7) `cluster.node_id`, `cluster.mode`, `cluster.config_digest`, `cluster.slices`, `cluster.slice_count`, `cluster.member_count` |
| `dataplane_counter` | 6 | (none) | `plat.counter.name`, `plat.counter.value` |
| `audit_queue_overflow` | 4 | `failure` | `plat.audit.lost` |
| `audit_output_failure` | 3 (`degraded`), 4 (`recovered`) | `failure` | `plat.audit.destination` (`file`), `plat.audit.state` (`degraded` / `recovered`), `plat.audit.lost`, `plat.reason` (optional: `truncate_failed`, `seq_lease_failed`, `seq_exhausted`) |
| `audit_recovery` | 4 | `failure` | `plat.audit.destination` (`file`), `plat.reason` (`empty_file` / `missing_header` / `truncated_tail`), `plat.audit.last_checkpoint_seq`, `plat.audit.max_seq`, `plat.audit.lease_state` |
| `audit_remote_loss` | 4 | `failure` | `plat.audit.destination` (`syslog`), `destination.ip`, `destination.port`, `plat.audit.lost`, `plat.reason` (optional) |
| `management_connection` | 5 (`accepted`), 4 (rejected) | `success` (`accepted`), `failure` | `source.ip`, `source.port`, `plat.mgmt.reason`, optional `tls.client.subject`, `tls.client.hash.sha256`, `url.path`, `plat.mgmt.allow_entry`, `tls.client.x509.alternative_names` |
| `management_connection_suppressed` | 4 | `failure` | `plat.mgmt.suppressed`, `plat.mgmt.window_secs` |
| `tls_revocation_check` | 6 (`good` and allowed), 4 (otherwise) | `success` if the certificate was allowed, else `failure` | `plat.tls.role`, `tls.client.hash.sha256` or `tls.server.hash.sha256`, `x509.serial_number`, `x509.issuer.distinguished_name`, `plat.revocation.chain_index`, `.status`, `.source`, `.policy`, optional `plat.ocsp.reason`, `plat.crl.reason`, `plat.revocation.reason`, `plat.revocation.date`, `plat.ocsp.responder`, `plat.crl.source` |
| `revocation_source_refresh` | 5 (`recovered`), 4 (otherwise) | `success` (`recovered`), `failure` | `plat.revocation.transition`, `plat.crl.source` or `plat.ocsp.key`, optional `event.reason` |
| `audit_storage_threshold` | 4 (`below_threshold`, `unknown`), 5 (`recovered`) | `failure` / `success` (`recovered`) | `plat.audit.destination` (`file`), `plat.audit.state`, `plat.audit.available_bytes` (omitted for `unknown`), `plat.audit.min_free_bytes` |
| `cluster_view_change` | 5 | `success` | `cluster.epoch`, `cluster.leader`, `cluster.members_live` (array of ids), `cluster.reason` |
| `cluster_member_state` | 4 (`down`), 5 | `success` | `cluster.peer.id`, `cluster.peer.name`, `cluster.peer.identity`, `cluster.peer.ip`, `cluster.peer.state`, `cluster.epoch` |
| `cluster_slice_acquire` | 5 (in sync), 4 (not in sync) | `success` (in sync), `unknown` (not in sync) | `cluster.slice`, `cluster.epoch`, optional `cluster.prev_owner`, `cluster.reason`, `cluster.blocks_adopted`, `cluster.bibs_adopted`, `cluster.blocks_quarantined`, `cluster.in_sync` |
| `cluster_slice_release` | 5, 4 (`fenced`, `lease_lost`) | `success` | `cluster.slice`, `cluster.epoch`, optional `cluster.new_owner`, `cluster.reason` |
| `cluster_peer_rejected` | 4 | `failure` | `source.ip`, `source.port`, optional `tls.client.identity`, optional `cluster.claimed_id`, `cluster.reason` |
| `cluster_peer_suppressed` | 4 | `failure` | `cluster.suppressed`, `cluster.window_secs` |
| `cluster_replication_gap` | 4 | `failure` | `cluster.slice`, `cluster.lost`, `cluster.action` (`resync`) |
| `cluster_hook` | 5 (success), 4 (failure) | `success` / `failure` | `cluster.hook`, `cluster.slice`, `cluster.epoch`, optional `process.exit_code`, `event.duration` (ns) |
| `cluster_operator_command` | 4 (accepted `takeover`/`restore`, and every refusal) | `success` (accepted), `failure` (refused) | `cluster.command`, optional `cluster.member`, `cluster.force`, optional `user.id`, optional `process.pid`, `cluster.reason` (refused only) |
| `audit_retention_prune` | 5 (`scheduled`, `deleted`), 4 (`failed`) | `unknown` (`scheduled`), `success` (`deleted`), `failure` (`failed`) | `plat.audit.state`, `plat.audit.pruned_rotated_us`, `plat.audit.pruned_seq_first`, `plat.audit.pruned_seq_last`, `plat.audit.pruned_chain_prefix` |

### `nat_port_block_allocate` / `nat_port_block_release`

```json
{"@timestamp":"2026-10-28T14:16:00.000001Z","plat.schema":7,"event.sequence":7,"event.kind":"event","event.category":"network","event.action":"nat_port_block_allocate","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"success","source.ip":"2001:db8:100:1::","plat.subscriber.prefix":"2001:db8:100:1::/64","source.nat.ip":"192.0.2.10","plat.nat.port_start":1024,"plat.nat.port_end":1535}
```

A block is released after it has been empty for 60 s, and only once its
release record has been queued; until then it stays with its subscriber (a
release can be deferred, never skipped). Live blocks get **no** release
record at shutdown or on a crash (POAM-009).

### `nat_binding_create` / `nat_binding_delete` (`audit.mode = "session"`)

```json
{"@timestamp":"2026-10-28T14:16:00.120000Z","plat.schema":7,"event.sequence":8,"event.kind":"event","event.category":"network","event.action":"nat_binding_create","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"success","network.transport":"udp","source.ip":"2001:db8:100:1::5","source.port":40000,"source.nat.ip":"192.0.2.10","source.nat.port":1100}
```

Destinations are deliberately **not** logged (privacy; not needed for
attribution).

### `nat_resource_limit`

`event.reason` ∈ `pool_exhausted`, `subscriber_block_limit`,
`subscriber_session_limit`, `global_session_limit`,
`subscriber_table_limit`, `aggregate_subscriber_limit` (schema 7, additive:
`nat64.max_subscribers_per_aggregate` reached; `source.ip` and
`plat.subscriber.prefix` carry the aggregate prefix and
`nat64.aggregate_prefix_len`, e.g. `2001:db8:100::/56`). Rate-limited to one
record per second per reason.

```json
{"@timestamp":"2026-10-28T14:16:01.000000Z","plat.schema":7,"event.sequence":9,"event.kind":"event","event.category":"network","event.action":"nat_resource_limit","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","event.reason":"subscriber_block_limit","source.ip":"2001:db8:100:1::","plat.subscriber.prefix":"2001:db8:100:1::/64"}
```

### `service_start` / `service_stop`

`service_start` is the first record queued after the logger starts and
before any packet is translated. `service_stop` is queued on every exit after
the logger has started, and the logger drains before the process exits. A
crash (`panic = "abort"`, OOM kill, `SIGKILL`) writes no `service_stop`.

`plat.fips` is `true` when the AWS-LC FIPS module is the active provider
and reports FIPS mode. With `tls.require_fips = true` (the default) the
daemon refuses to start when it is not, before any audit file or record
exists, so a `service_start` with `plat.fips:false` means the operator set
`require_fips = false`. A build without the `tls` feature records
`plat.fips:false`, `plat.fips_provider:"none"` (and can start only with
`require_fips = false` and no TLS configured).

```json
{"@timestamp":"2026-10-28T14:00:00.000000Z","plat.schema":7,"event.sequence":1,"event.kind":"event","event.category":"network","event.action":"service_start","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"success","service.version":"0.1.0","plat.fips":true,"plat.fips_provider":"aws-lc-rs-fips"}
```

With clustering (schema 7) `service_start` also records this node's cluster
identity (CM-2, CM-3; POAM-017(c)): `cluster.node_id`, `cluster.mode`
(`contiguous`, `slices` or `ha`), `cluster.config_digest` (SHA-256 hex over
the cluster-relevant configuration: pool, port range and block size,
subscriber prefix length, paired pooling, partition, slice length, members
and HA timing), `cluster.slices` (owned CIDRs at start, at most 256 written;
contiguous mode prints its share, HA prints `[]` and the
`cluster_slice_acquire` records follow), `cluster.slice_count` (full count)
and `cluster.member_count`. All nodes of one cluster must log the same
digest; a different digest is refused on the peer channel
(`cluster_peer_rejected` `digest_mismatch`).

```json
{"@timestamp":"2026-10-29T08:00:00.000000Z","plat.schema":7,"event.sequence":1,"event.kind":"event","event.category":"network","event.action":"service_start","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"success","service.version":"0.1.0","plat.fips":true,"plat.fips_provider":"aws-lc-rs-fips","cluster.node_id":0,"cluster.mode":"ha","cluster.config_digest":"9f2c…(64 hex)","cluster.slices":[],"cluster.slice_count":0,"cluster.member_count":2}
```

### Cluster records (schema 7)

Written only with `[cluster.ha]` enabled (except `service_start` fields
above). They are control-plane records (cluster threads), never per packet.

- `cluster_view_change`: a view (`epoch`, leader, live members) took effect
  after a majority acknowledged it. `cluster.reason` ∈ `election`,
  `member_joined`, `member_lost`, `leader_lost`, `manual`.
- `cluster_member_state`: a peer went `up`, `down`, `syncing` or `in_sync`.
- `cluster_slice_acquire`: this node became owner of `cluster.slice`.
  `cluster.reason` ∈ `startup`, `takeover`, `handover`, `failback`, `manual`.
  It and every `nat_port_block_adopt` for the slice are queued **before** the
  node translates or allocates in that slice (AU-10). `cluster.in_sync:false`
  means the replicated state was incomplete (outcome `unknown`): blocks of
  that slice without an adopt record may have been in use on the previous
  owner, and `cluster.blocks_quarantined` blocks are held back before reuse.
- `cluster_slice_release`: this node stopped using a slice. `cluster.reason`
  ∈ `handover` (graceful; each handed-over block also gets a
  `nat_port_block_release` with `plat.release_reason:"handover"`), `fenced`,
  `shutdown`, `lease_lost` (self-fence after losing quorum).
- `nat_port_block_adopt`: a block taken over from `cluster.prev_owner`, with
  its original allocation time `plat.block.allocated_us`. It continues the
  allocation that the previous owner logged; the subscriber and range are
  unchanged.
- `cluster_peer_rejected`: a peer connection or replication input was
  refused. `cluster.reason` ∈ `not_allowed` (address or identity not a
  member, or replication for a slice the sender does not own),
  `id_mismatch`, `duplicate_id`, `digest_mismatch`, `version`, `overlap`,
  `handshake`, `protocol` (malformed or unexpected frame on an established
  connection), `invalid_input` (replicated record outside the slice, pool
  or client prefixes), `capacity` (connection or pending-handshake limit). `tls.client.identity` is peer-supplied
  text (sanitised and capped like `tls.client.subject`). Rate-limited, with a
  `cluster_peer_suppressed` summary.
- `cluster_replication_gap`: replication records for a slice were lost
  (ring or peer queue full); the slice resyncs by snapshot. At most one per
  slice per 10 s.
- `cluster_hook`: one run of the `announce`/`withdraw` route hook.
  `process.exit_code` is absent when the hook was killed on timeout.
- `cluster_operator_command`: a command on the operator socket
  (`platd cluster status|takeover|restore`). Accepted `takeover` and
  `restore` are logged before they act; every refusal (of any command) is
  logged. An accepted `status` is read-only and is **not** logged (the
  formatter would give it severity 5, but the daemon never emits it). With
  `audit.on_overflow = "refuse_new_bindings"` an accepted command whose
  record cannot be queued is not run (the client gets
  `error: audit queue full, command not run; retry`); refusal records are
  best-effort. `user.id` and `process.pid`
  are the peer credentials of the client (`SO_PEERCRED`; `getpeereid` on
  macOS, without a pid). Only uid 0 and the daemon's own uid are accepted.
  `cluster.force:true` marks `takeover --force` of a member whose peer link
  is up. `cluster.reason` ∈ `not_authorized`, `no_credentials`,
  `auto_failover`, `member_up`, `unknown_member`, `invalid`, `rejected`.

```json
{"@timestamp":"2026-10-29T08:10:03.200000Z","plat.schema":7,"event.sequence":5120,"event.kind":"event","event.category":"network","event.action":"cluster_slice_acquire","observer.type":"nat64","observer.name":"plat-02","plat.node_id":1,"event.outcome":"success","cluster.slice":"192.0.2.16/28","cluster.epoch":9,"cluster.prev_owner":0,"cluster.reason":"takeover","cluster.blocks_adopted":5,"cluster.bibs_adopted":70,"cluster.blocks_quarantined":1,"cluster.in_sync":true}
{"@timestamp":"2026-10-29T08:10:03.200010Z","plat.schema":7,"event.sequence":5121,"event.kind":"event","event.category":"network","event.action":"nat_port_block_adopt","observer.type":"nat64","observer.name":"plat-02","plat.node_id":1,"event.outcome":"success","source.ip":"2001:db8:100:1::","plat.subscriber.prefix":"2001:db8:100:1::/64","source.nat.ip":"192.0.2.17","plat.nat.port_start":1024,"plat.nat.port_end":1535,"plat.block.allocated_us":1793260000000000,"cluster.epoch":9,"cluster.prev_owner":0}
{"@timestamp":"2026-10-29T08:10:04.000000Z","plat.schema":7,"event.sequence":5190,"event.kind":"event","event.category":"network","event.action":"cluster_peer_rejected","observer.type":"nat64","observer.name":"plat-02","plat.node_id":1,"event.outcome":"failure","source.ip":"198.51.100.30","source.port":40000,"tls.client.identity":"dns:plat-01.cluster.example","cluster.claimed_id":0,"cluster.reason":"duplicate_id"}
```

More schema-7 examples (field order as in the golden test
`plat-audit/src/format.rs::cluster_records_schema_7`; values illustrative):

```json
{"@timestamp":"2026-10-29T08:10:00.100000Z","plat.schema":7,"event.sequence":5101,"event.kind":"event","event.category":"network","event.action":"cluster_view_change","observer.type":"nat64","observer.name":"plat-02","plat.node_id":1,"event.outcome":"success","cluster.epoch":9,"cluster.leader":1,"cluster.members_live":[1,2],"cluster.reason":"member_lost"}
{"@timestamp":"2026-10-29T08:10:00.000000Z","plat.schema":7,"event.sequence":5100,"event.kind":"event","event.category":"network","event.action":"cluster_member_state","observer.type":"nat64","observer.name":"plat-02","plat.node_id":1,"event.outcome":"success","cluster.peer.id":0,"cluster.peer.name":"plat-01","cluster.peer.identity":"dns:plat-01.cluster.example","cluster.peer.ip":"198.51.100.11","cluster.peer.state":"down","cluster.epoch":8}
{"@timestamp":"2026-10-29T08:09:58.000000Z","plat.schema":7,"event.sequence":7310,"event.kind":"event","event.category":"network","event.action":"cluster_slice_release","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"success","cluster.slice":"192.0.2.16/28","cluster.epoch":8,"cluster.reason":"lease_lost"}
{"@timestamp":"2026-10-29T09:00:00.000000Z","plat.schema":7,"event.sequence":7400,"event.kind":"event","event.category":"network","event.action":"nat_port_block_release","observer.type":"nat64","observer.name":"plat-02","plat.node_id":1,"event.outcome":"success","source.ip":"2001:db8:100:1::","plat.subscriber.prefix":"2001:db8:100:1::/64","source.nat.ip":"192.0.2.17","plat.nat.port_start":1024,"plat.nat.port_end":1535,"event.duration":3000000000000,"plat.release_reason":"handover"}
{"@timestamp":"2026-10-29T08:11:00.000000Z","plat.schema":7,"event.sequence":5200,"event.kind":"event","event.category":"network","event.action":"cluster_peer_suppressed","observer.type":"nat64","observer.name":"plat-02","plat.node_id":1,"event.outcome":"failure","cluster.suppressed":12,"cluster.window_secs":60}
{"@timestamp":"2026-10-29T08:12:00.000000Z","plat.schema":7,"event.sequence":5300,"event.kind":"event","event.category":"network","event.action":"cluster_replication_gap","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","cluster.slice":"192.0.2.16/28","cluster.lost":33,"cluster.action":"resync"}
{"@timestamp":"2026-10-29T08:10:03.201500Z","plat.schema":7,"event.sequence":5140,"event.kind":"event","event.category":"network","event.action":"cluster_hook","observer.type":"nat64","observer.name":"plat-02","plat.node_id":1,"event.outcome":"success","cluster.hook":"announce","cluster.slice":"192.0.2.16/28","cluster.epoch":9,"process.exit_code":0,"event.duration":1500000}
{"@timestamp":"2026-10-29T08:20:00.000000Z","plat.schema":7,"event.sequence":5400,"event.kind":"event","event.category":"network","event.action":"cluster_operator_command","observer.type":"nat64","observer.name":"plat-02","plat.node_id":1,"event.outcome":"success","cluster.command":"takeover","cluster.member":0,"cluster.force":true,"user.id":"0","process.pid":4242}
{"@timestamp":"2026-10-29T08:20:05.000000Z","plat.schema":7,"event.sequence":5401,"event.kind":"event","event.category":"network","event.action":"cluster_operator_command","observer.type":"nat64","observer.name":"plat-02","plat.node_id":1,"event.outcome":"failure","cluster.command":"takeover","cluster.member":0,"cluster.force":false,"user.id":"1001","process.pid":5150,"cluster.reason":"not_authorized"}
```

A `cluster_hook` killed on timeout has no `process.exit_code` and outcome
`failure`. `user.id` is a string (ECS); `process.pid` is absent on macOS.

### `dataplane_counter`

Every `audit.summary_interval_secs` (default 60; 0 disables), one record per
**drop reason** whose count is non-zero. Values are cumulative since the
process started (they reset on restart). Only drop reasons appear here;
non-drop counters such as `tx_queue_full`, `icmp_errors_generated` or
`fragmented_v4_to_v6` are only in `/metrics`.

Fragment and ICMP drop reasons (`feat/protocol-completeness`, schema
unchanged) appear here as `plat.counter.name`: `fragment_timeout`,
`fragment_overlap`, `fragment_tiny`, `fragment_too_many`,
`fragment_table_full`, `fragment_buffer_full`, `reassembly_full`,
`reassembly_too_big`, `fragment_unmatched`, `icmp_quote_unmatched`. A drop
answered with a locally generated ICMP error is still counted under its
reason (for example `hop_limit`, `port_exhausted`, `too_big`). Inbound
TTL ≤ 1 packets that the inbound filter refuses are counted `no_binding` or
`filtered`, not `hop_limit` (Time Exceeded is filter-gated); a too-big DF
IPv4 packet the filter refuses is counted the same way, not `too_big`.

```json
{"@timestamp":"2026-10-29T14:17:00.000000Z","plat.schema":7,"event.sequence":41,"event.kind":"event","event.category":"network","event.action":"dataplane_counter","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"plat.counter.name":"fragment_overlap","plat.counter.value":3}
```

SIEM guidance: a rising `fragment_overlap` or `fragment_tiny` indicates
fragment-evasion or Teardrop-style traffic; `fragment_table_full`,
`fragment_buffer_full` and `reassembly_full` indicate a fragment flood
against the per-worker limits (SC-5); `fragment_unmatched` /
`icmp_quote_unmatched` that do not follow a flood can indicate fragments
steered across workers (POAM-035). Correlate with the source by packet
capture: these counters carry no addresses.

```json
{"@timestamp":"2026-10-28T14:17:00.000000Z","plat.schema":7,"event.sequence":40,"event.kind":"event","event.category":"network","event.action":"dataplane_counter","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"plat.counter.name":"filtered","plat.counter.value":12}
```

### `audit_queue_overflow`

`plat.audit.lost`: records lost to a full queue since the previous overflow
record (the logger reports the delta as soon as it sees it). A quarantined
port-block release that cannot be queued is retried on the next sweep and is
**not** counted as lost.

### `audit_output_failure`

The local file (the authoritative copy) could not be written, flushed,
opened or rotated.

- `degraded`: written to the syslog destinations when the failure happens
  (`plat.audit.lost` = records of the failed batch), and again on each failed
  retry, so collectors see a `degraded` record about once per second during
  an outage.
- `recovered`: the first record in the new file after a successful retry;
  `plat.audit.lost` = total records not written during the outage. It is
  also sent to the syslog destinations. Its `event.outcome` is `failure`
  because records were lost.

```json
{"@timestamp":"2026-10-28T14:20:00.000000Z","plat.schema":7,"event.sequence":512,"event.kind":"event","event.category":"network","event.action":"audit_output_failure","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","plat.audit.destination":"file","plat.audit.state":"degraded","plat.audit.lost":12}
```

`plat_audit_file_lost_total` also counts records that reached the failed file
after its last checkpoint (its unverified tail), so the sequence gap that
`verify-log` reports equals `file_lost` minus that tail.

The failed file is cut back to its last durable checkpoint, so it ends in a
complete line and verifies. Optional `plat.reason` (schema 6; `degraded`,
`lost` 0 unless stated):

- `truncate_failed`: the cut-back (`set_len` / sync) failed; the file may end
  in a partial batch (unverified tail).
- `seq_lease_failed`: the sequence lease `.<name>.seq` could not be written;
  emitted once per failure streak, retried every flush interval, each failure
  counted in `plat_audit_seq_lease_failures_total`.
- `seq_exhausted`: the u64 sequence space is used up; further events are
  dropped (`lost` = their count), the file is synced and closed, and the
  logger stays degraded (fail closed).

### `audit_recovery` (schema 6)

First record of the new live file after a start-up that found the newest
audit file damaged: `plat.reason` `empty_file` (0 bytes), `missing_header`
(no complete `audit_chain_continue` line) or `truncated_tail` (last line
without `\n`, e.g. a power cut). Severity 4, `event.outcome` `failure`.

- `plat.audit.last_checkpoint_seq`: last durable checkpoint found on disk;
  records after it may be lost.
- `plat.audit.max_seq`: highest sequence number that may have been used
  (the larger of the files' maximum and the `.<name>.seq` lease). Numbering
  resumes at `max_seq + 1`, so no number is reused; the skipped range is a
  *recovery gap* in `verify-log` (exit 3).
- `plat.audit.lease_state`: `ok` (lease used), `absent` (no lease file),
  `corrupt` (not a regular file, or unreadable / not a number), `inflated`
  (above the wrap guard `u64::MAX - 2^21`; ignored), `high` (used, but more
  than one lease block above the files' maximum: a large skip, or a planted
  lease).

```json
{"@timestamp":"2026-10-29T06:01:00.000000Z","plat.schema":7,"event.sequence":2099522,"event.kind":"event","event.category":"network","event.action":"audit_recovery","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","plat.audit.destination":"file","plat.reason":"truncated_tail","plat.audit.last_checkpoint_seq":1699072,"plat.audit.max_seq":2099521,"plat.audit.lease_state":"ok"}
```

A clean start (intact newest file) writes no `audit_recovery`, even if the
lease is corrupt or inflated (only warned in the journal).

### `audit_remote_loss`

Records not delivered to one collector: its hand-off queue was full, the
send, connect or TLS handshake failed, or the record fell in the 5 s TCP/TLS
reconnect back-off. Written to the local file and offered to every syslog
destination.

`plat.reason` (TCP and TLS destinations) names the cause of the outage the
lost batches fell in:

| `plat.reason` | Cause |
|---------------|-------|
| `io` | connect failure, socket error, EOF or write failure (TCP and TLS) |
| `tls_verify` | certificate verification failed: wrong CA, wrong `server_name`, or the collector rejected our client certificate (or its absence) |
| `tls_revocation` | the collector chain was `revoked` or its status could not be determined under the policy |
| `tls_handshake` | handshake timeout or any other TLS error |
| (absent) | losses caused only by a full hand-off queue, and UDP losses |

A TLS connect waits up to 300 ms after the handshake for a collector's
rejection of our certificate (TLS 1.3 verifies the client after the client's
Finished), so such a rejection is reported as `tls_verify` rather than
counted as delivered. Every lost batch is counted once; the sum of
`plat.audit.lost` over `audit_remote_loss` records equals
`plat_audit_remote_lost_total` for that destination.

```json
{"@timestamp":"2026-10-28T14:21:00.000000Z","plat.schema":7,"event.sequence":700,"event.kind":"event","event.category":"network","event.action":"audit_remote_loss","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","plat.audit.destination":"syslog","destination.ip":"198.51.100.10","destination.port":6514,"plat.audit.lost":3,"plat.reason":"tls_verify"}
```

### `audit_storage_threshold`

Free space on the log volume, checked at most once per second whenever
`[audit.file]` is configured (`min_free_bytes` is always ≥ 1 MiB; default
max(2 × `max_bytes`, 1 GiB)).

- `below_threshold`: free space < `min_free_bytes`; the pipeline is degraded
  (new bindings refused, `/healthz` 503) while records keep being written.
- `recovered`: free space ≥ threshold + 10 %.
- `unknown`: free space cannot be determined (`statvfs` failed); treated as
  below the threshold (fail closed). Written once per episode, without
  `plat.audit.available_bytes`; it clears with a `recovered` record.

```json
{"@timestamp":"2026-10-28T14:22:00.000000Z","plat.schema":7,"event.sequence":800,"event.kind":"event","event.category":"network","event.action":"audit_storage_threshold","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","plat.audit.destination":"file","plat.audit.state":"below_threshold","plat.audit.available_bytes":1073741824,"plat.audit.min_free_bytes":2147483648}
```

### `audit_retention_prune`

Retention (`max_files > 0`) of a rotated file `<path>.<pruned_rotated_us>`
that held records `pruned_seq_first..=pruned_seq_last` and whose last
checkpoint chain starts with `pruned_chain_prefix` (16 hex digits; the next
file's header carries the full value). Two phases:

1. `scheduled` (`event.outcome:"unknown"`): written to the live chain (and
   to syslog) and synced **before** the file is touched.
2. In the next batch, the result for the same range: `deleted` (`success`)
   or `failed` (`failure`: unlink error, checkpoint sync error, or the batch
   carrying the `scheduled` record failed). A failed prune is scheduled again
   at the next rotation with a new `scheduled` record.

```json
{"@timestamp":"2026-10-28T15:00:00.000000Z","plat.schema":7,"event.sequence":90001,"event.kind":"event","event.category":"network","event.action":"audit_retention_prune","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"unknown","plat.audit.state":"scheduled","plat.audit.pruned_rotated_us":1793196960000000,"plat.audit.pruned_seq_first":1,"plat.audit.pruned_seq_last":45000,"plat.audit.pruned_chain_prefix":"9f2c4e01b7a6d3c8"}
```

### `management_connection` (mTLS management only)

One record per TCP connection accepted by the mTLS listener
(`[management.tls]`). The plaintext loopback listener writes none.

| `plat.mgmt.reason` | Meaning |
|--------------------|---------|
| `accepted` | handshake, revocation check and allow-list passed; `url.path` is `/metrics`, `/healthz`, `/cluster` (schema 7, read-only cluster view) or `other` (also `other` when the request read failed) |
| `no_client_cert` | the client presented no certificate |
| `bad_cert` | chain or certificate rejected by path validation |
| `revoked` | a certificate in the client chain is revoked |
| `revocation_check_failed` | status could not be determined under the policy |
| `not_allowlisted` | valid certificate, no `allowed_clients` entry matched; `close_notify`, no HTTP response |
| `handshake_timeout` | no ClientHello within 2 s, or the handshake missed `handshake_timeout_ms` |
| `handshake_failed` | any other TLS failure, including a peer that connects and closes without TLS (port scan, TCP health check) |
| `over_capacity` | `max_connections` reached, or `max_connections_per_ip` reached for that source address; closed before any TLS work |

- `tls.client.subject` (subject CN, only when exactly one CN is present),
  `tls.client.hash.sha256` (SHA-256 of the leaf DER) and
  `tls.client.x509.alternative_names` (array of `dns:` / `uri:` SANs, at most
  8 entries, each ≤ 128 bytes) are present whenever a certificate was
  received.
- `plat.mgmt.allow_entry` is the matched entry (`cn:…`, `dns:…`, `uri:…`,
  `sha256:…`) on `accepted` records.
- `accepted` records are always written. All other reasons pass a token
  bucket (10/s, burst 20) shared with the revocation records of rejected
  management handshakes; what the bucket drops is counted and reported by
  `management_connection_suppressed` (checked every 60 s and at shutdown).
- Ordering: for an **accepted** connection the `tls_revocation_check`
  records of its chain precede the `management_connection` record; for a
  **rejected** connection they are held until the allow-list decision and
  follow it (rate-limited as above).
- `over_capacity` by `max_connections_per_ip` is keyed per IPv4 address and
  per IPv6 /64 (IPv4-mapped IPv6 peers count as their IPv4 address);
  `source.ip` still records the full address.

```json
{"@timestamp":"2026-10-28T14:30:00.000000Z","plat.schema":7,"event.sequence":901,"event.kind":"event","event.category":"network","event.action":"management_connection","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"success","source.ip":"2001:db8:ff::10","source.port":50412,"plat.mgmt.reason":"accepted","tls.client.subject":"prometheus-01","tls.client.hash.sha256":"<64 hex>","url.path":"/metrics","plat.mgmt.allow_entry":"dns:prometheus-01.ops.example.net","tls.client.x509.alternative_names":["dns:prometheus-01.ops.example.net"]}
```

### `management_connection_suppressed`

`plat.mgmt.suppressed` rejection records (connection and revocation) dropped
by the token bucket during the last `plat.mgmt.window_secs` seconds.

```json
{"@timestamp":"2026-10-28T14:31:00.000000Z","plat.schema":7,"event.sequence":950,"event.kind":"event","event.category":"network","event.action":"management_connection_suppressed","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","plat.mgmt.suppressed":41,"plat.mgmt.window_secs":60}
```

### `tls_revocation_check`

One record per non-root certificate of a checked chain (leaf
`chain_index` 0, then intermediates), for management clients
(`plat.tls.role:"mgmt_client"`, hash field `tls.client.hash.sha256`) and
syslog collectors (`"syslog_server"`, `tls.server.hash.sha256`), and
(schema 7) cluster peers (`"cluster_peer_client"` for a peer that connected
here, `tls.client.hash.sha256`; `"cluster_peer_server"` for a peer this node
dialed, `tls.server.hash.sha256`). With
`tls.revocation.mode = "off"` the leaf gets one `not_checked` record.

- `plat.revocation.status`: `good`, `revoked`, `unavailable`, `fatal`
  (attack-class failure: bad signature, unauthorized responder, nonce or
  CertID mismatch, wrong CRL issuer), `not_checked` (mode off, or remaining
  elements after the chain was already rejected; those are not fetched).
- `plat.revocation.source`: `ocsp_stapled`, `ocsp_cache`, `ocsp_fetch`,
  `crl_cache`, `crl_fetch`, `crl_file`, `none` (no source decided; under
  `soft_fail` an accepted certificate has `source:none`).
- `plat.revocation.policy`: `hard_fail`, `soft_fail` or `off`.
- `plat.ocsp.reason` (why OCSP did not decide): `timeout`, `connect`,
  `http_status`, `content_type`, `too_large`, `malformed`, `bad_signature`,
  `unauthorized_responder`, `stale`, `nonce_mismatch`, `no_responder`,
  `cert_id_mismatch`, `unknown_status`, `budget`.
- `plat.crl.reason`: `timeout`, `connect`, `http_status`, `too_large`,
  `malformed`, `bad_signature`, `wrong_issuer`, `no_crl_sign`, `stale`,
  `not_yet_valid` (thisUpdate in the future beyond the skew), `no_next_update`,
  `indirect`, `delta`, `scope_mismatch` (IssuingDistributionPoint does not
  cover the certificate), `critical_ext`, `rollback` (cRLNumber lower than one
  already seen for that issuer and scope, or missing after a numbered one),
  `no_source`, `budget`.
- `plat.revocation.reason` / `plat.revocation.date` (revoked only):
  RFC 5280 reason (`unspecified`, `key_compromise`, `ca_compromise`,
  `affiliation_changed`, `superseded`, `cessation_of_operation`,
  `certificate_hold`, `remove_from_crl`, `privilege_withdrawn`,
  `aa_compromise`) and revocation time.
- `plat.ocsp.responder` / `plat.crl.source`: `host:port` of the source used.

```json
{"@timestamp":"2026-10-28T14:32:00.000000Z","plat.schema":7,"event.sequence":960,"event.kind":"event","event.category":"network","event.action":"tls_revocation_check","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","plat.tls.role":"syslog_server","tls.server.hash.sha256":"<64 hex>","x509.serial_number":"01ab","x509.issuer.distinguished_name":"CN=Intermediate,O=Example","plat.revocation.chain_index":1,"plat.revocation.status":"revoked","plat.revocation.source":"crl_fetch","plat.revocation.policy":"hard_fail","plat.ocsp.reason":"connect","plat.revocation.reason":"key_compromise","plat.revocation.date":"2026-10-20T00:00:00.000000Z","plat.ocsp.responder":"ocsp.example.net:80","plat.crl.source":"crl.example.net:80"}
```

### `revocation_source_refresh`

Written by the `plat-revocation` refresher only on a state transition of a
watched source (a CRL URL/file/CDP, or an OCSP watch entry):

| `plat.revocation.transition` | Meaning |
|------------------------------|---------|
| `failing` | refresh started failing (`event.reason` = the CRL/OCSP reason above) |
| `recovered` | a failing source refreshed successfully |
| `stale_dropped` | cached data passed nextUpdate without a replacement and was dropped |
| `rollback_rejected` | a fetched CRL had a lower (or missing) cRLNumber and was refused |
| `state_rejected` | the persisted `cache_dir/crl-numbers` file was rejected at load (`plat.crl.source:"crl-numbers"`; `event.reason` `state_oversize`, `state_unreadable`, `state_not_utf8` or `state_bad_lines`); rollback marks from it are missing or partial. The rejected file is kept on disk as `crl-numbers.rejected.<ts>` when it is a regular file (a non-regular entry stays in place); its path appears in the operational log |
| `state_persist_failed` | writing `crl-numbers` failed (`event.reason` `state_write_failed`); retried at the next store, one record per failure streak |

```json
{"@timestamp":"2026-10-28T14:33:00.000000Z","plat.schema":7,"event.sequence":970,"event.kind":"event","event.category":"network","event.action":"revocation_source_refresh","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","plat.revocation.transition":"failing","plat.crl.source":"crl.example.net:80","event.reason":"timeout"}
```

### `audit_chain_continue` (local file only, first line of every file)

```json
{"@timestamp":"2026-10-28T14:00:00.000000Z","plat.schema":7,"event.action":"audit_chain_continue","observer.name":"plat-01","plat.node_id":0,"plat.audit.prev_chain":"<64 hex digits; all zero if no predecessor is known>","plat.audit.prev_seq":45000,"plat.audit.next_seq":45001}
```

`prev_chain` / `prev_seq`: the previous file's final checkpoint chain and its
`seq_last`. `next_seq`: the first sequence number in this file.

### `audit_checkpoint` (local file only, after every batch)

```json
{"@timestamp":"2026-10-28T14:00:00.100000Z","plat.schema":7,"event.action":"audit_checkpoint","observer.name":"plat-01","plat.node_id":0,"plat.audit.seq_first":45001,"plat.audit.seq_last":45012,"plat.audit.batch_sha256":"<64 hex>","plat.audit.chain_sha256":"<64 hex>"}
```

Chain v2:

- Seed: `chain_0 = SHA-256("usg-plat audit chain v2" ‖ header line)`, where
  the header line includes its trailing newline.
- `batch_sha256 = SHA-256(record lines of the batch, each with its newline)`.
- `chain_sha256 = SHA-256(previous chain ‖ batch_sha256 ‖ seq_first ‖ seq_last)`,
  with the sequence numbers as big-endian u64.

The chain is unkeyed: it detects edits, insertions, deletions and reordering
by anyone who does not recompute it, and a rewritten file no longer links to
its successor's header. Someone with write access to the files can recompute
every hash (POAM-003); the syslog copy on a separate system is the control
for that case (best-effort; use `transport = "tls"` to protect it in transit).

## `platd verify-log`

```text
platd verify-log [--allow-tail] [--allow-gap] [--allow-recovery] FILE...
```

Pass the live file and any rotated files (`<path>.<µs>`), in any order. Each
file is verified on its own: line 1 must be an `audit_chain_continue` header;
records must be numbered consecutively from its `next_seq`; each checkpoint
must match the batch hash, its `seq_first`/`seq_last` and the chain; a second
header is rejected. The files are then sorted by header `next_seq` and
linked: each header must name the previous file's final chain and checkpoint
sequence.

| Exit | Meaning |
|------|---------|
| 0 | Every file verifies and the files form one chain. |
| 1 | A file fails verification; or a file has records after its last checkpoint (unverified tail, e.g. the live file or a crash) without `--allow-tail`; or records are missing between files (gap) without `--allow-gap`; or a link is broken (file removed, replaced or reordered, or a sequence number reused). |
| 2 | A file cannot be opened or read. |
| 3 | Everything else verifies, but a range is skipped after a damaged start (an `audit_recovery` recovery gap, printed `RECOVERY GAP N..=M (restart after damaged log; verify against the remote copy): audit_recovery at record X`) and `--allow-recovery` was not given. `--allow-gap` does not cover it; with `--allow-recovery` the line is prefixed `WARNING:` and the exit is 0. Exit 1 takes precedence over 3. |

A gap means records were not written locally (see `audit_output_failure` and
the syslog copy). A gap is *accounted* (printed as `OK: accounted gap:
N..=M`, exit 0 without `--allow-gap`) only when the file after it opens with
a checkpointed record that announces exactly that range: an
`audit_output_failure` for the file (`plat.audit.state` `recovered`) whose
`plat.audit.lost` equals `M - N + 1` (the batches dropped during an ENOSPC
or I/O outage). A range skipped by a valid `audit_recovery` whose
`plat.audit.max_seq` is `M` (start-up after a damaged newest file) is a
*recovery gap* (exit 3, see above). A partial final line on a file other
than the newest is accepted only when the next file opens with an
`audit_recovery` naming that file's last checkpoint (`truncated_tail`, or
`empty_file` / `missing_header` when the file that held that record was
itself emptied); the partial line still needs `--allow-tail`. An
`audit_recovery` after an intact file is a broken link. Every other gap, or
a different count, fails (exit 1).

Limitation (POAM-027): deleting the newest records and restarting is
indistinguishable, locally, from a power cut; it shows only as a recovery
gap. The remote copy is the reference for that range, and the chain is
unkeyed (POAM-003). Removal of the oldest retained file is not detectable from
the files alone: compare its header `prev_seq` / `prev_chain` with the newest
`audit_retention_prune` record that names it. Truncation exactly at the
newest checkpoint is also not detectable locally.

## Log directory

- The live file is `audit.file.path`; rotated files are `<path>.<µs>`.
- A new file is prepared as a hidden temporary `.<name>.new` and renamed into
  place. Log shippers must ignore `.*.new` files. A temporary file left by a
  crash is kept as a rotated file at the next start-up if it holds records,
  and removed if it holds only a header.
- Restarts with no traffic do not create rotated files: a live file that holds
  only a header is replaced in place.
- The directory is `plat:plat-log` mode 2750 (from
  `/usr/lib/tmpfiles.d/plat.conf`, not `LogsDirectory=`); files are created
  0640 and inherit group `plat-log`. Add log shippers and `verify-log`
  operators to `plat-log`, never to `plat`.
- `.<name>.seq` holds the durable sequence high-water mark (numbers
  reserved in blocks of 2^20; after an emptied or cut-off newest file,
  numbering resumes above it so no sequence number is reused). It holds
  decimal text, `-rw-r----- plat:plat-log`, written (tmp, fsync,
  rename, directory fsync) about once per 2^20 records. Log shippers must
  ignore it, like `.*.new`; `nat64-audit.jsonl*` globs do not match it.

## Syslog

- RFC 5424, facility local0. Severity per record type (table above).
  `MSGID` = `event.action`. `APP-NAME` = `audit.syslog.app_name` (default
  `platd`, 1–48 printable ASCII).
- UDP: one datagram per record (RFC 5426 §3.1), in sequence order, on the
  destination's own thread. On Linux a batch goes out in `sendmmsg` calls of
  up to 64 datagrams; a partial send resumes at the first unsent datagram,
  and each datagram the kernel refuses (e.g. oversize, unreachable
  collector) is one lost record. Other platforms send one datagram per
  `send`. Measured about **580 k records/s per destination** on Linux
  loopback (before batching: about 310–360 k); above it records are
  counted in `plat_audit_remote_lost_total` and recorded as
  `audit_remote_loss`. For sustained rates near that (e.g.
  `audit.mode = "session"`), use TCP or several collectors.
- TCP: RFC 6587 octet-counting, one write per batch, 2 s connect and write
  timeouts, 5 s reconnect back-off. A failed write counts the whole batch as
  lost (some frames may have arrived).
- TLS (RFC 5425, `transport = "tls"`): TLS 1.3 only (deviation from RFC 5425
  §4.2, which mandates TLS 1.2 support; see `RFC_COMPLIANCE.md`), FIPS
  provider, octet-counted framing as for TCP, one write per batch, 2 s
  connect and write timeouts, handshake deadline `max(2 s, budget_ms + 1 s)`
  (2 s with revocation off), 5 s reconnect back-off, `close_notify` at
  shutdown. The collector certificate must chain to `ca_file` (system roots
  are never used) and match `server_name`; its full chain is
  revocation-checked (stapled OCSP accepted for the leaf). Optional client
  certificate (`cert_file`/`key_file`). Session resumption is off, so every
  reconnect re-verifies. A bad CA, certificate or key file fails start-up.
- UDP and TCP carry no transport protection; use them only on a protected
  management network.
- The remote copy is **best-effort**: remote loss never degrades the pipeline
  or refuses bindings; it is counted and recorded in the local file.

### CEF

```text
<134>1 2026-10-28T14:16:00.000001Z plat-01 platd 4242 nat_port_block_allocate - CEF:0|USG|usg-plat|0.1.0|nat_port_block_allocate|nat_port_block_allocate|3|rt=1793196960000 dvchost=plat-01 cn1=7 cn1Label=sequence cn4=0 cn4Label=nodeId cs6=7 cs6Label=schema outcome=success c6a2=2001:db8:100:1:: cn2=64 cn2Label=subscriberPrefixLen sourceTranslatedAddress=192.0.2.10 cs1=1024-1535 cs1Label=portRange
```

Header: `CEF:0|USG|usg-plat|<version>|<event.action>|<event.action>|<severity>`.
CEF severity from syslog severity: 3 → 9, 4 → 7, 5 → 4, 6 → 3.

Common extension keys on every record: `rt` (epoch **milliseconds**; JSON
keeps microseconds), `dvchost` (node name), `cn1` (`sequence`), `cn4`
(`nodeId`), `cs6` (`schema`), and `outcome` (absent on `dataplane_counter`).

| Record | Extension keys |
|--------|----------------|
| `nat_port_block_allocate`, `nat_port_block_release` | `c6a2` (subscriber prefix address), `cn2` (`subscriberPrefixLen`), `sourceTranslatedAddress`, `cs1` (`portRange`, `start-end`); release adds `reason=handover` when handed over |
| `nat_port_block_adopt` | as allocate, plus `cs3` (`epoch`), `cs4` (`allocatedUs`), `cn3` (`prevOwner`, optional) |
| `cluster_view_change` | `reason`, `cn2` (`epoch`), `cn3` (`leader`), `cs1` (`membersLive`, comma-separated) |
| `cluster_member_state` | `act` (state), `src`/`c6a2` (peer IP), `cn2` (`epoch`), `cn3` (`peerId`), `cs1` (`peerName`), `cs2` (`peerIdentity`) |
| `cluster_slice_acquire` | `reason`, `cs1` (`slice`), `cn2` (`epoch`), `cs2` (`adopted`, `blocks:N bibs:N quarantined:N`), `cs4` (`inSync`), `cn3` (`prevOwner`, optional) |
| `cluster_slice_release` | `reason`, `cs1` (`slice`), `cn2` (`epoch`), `cn3` (`newOwner`, optional) |
| `cluster_peer_rejected` | `act=reject`, `src`/`c6a2`, `spt`, `reason`, `suser` (identity, optional), `cn3` (`claimedId`, optional) |
| `cluster_peer_suppressed` | `cn3` (`suppressed`), `cn2` (`windowSecs`) |
| `cluster_replication_gap` | `act=resync`, `cs1` (`slice`), `cn3` (`lost`) |
| `cluster_hook` | `act` (`announce`/`withdraw`), `cs1` (`slice`), `cn2` (`epoch`), `cs3` (`durationUs`), `cn3` (`exitCode`, optional) |
| `cluster_operator_command` | `act` (command), `cs1` (`force`), `cn3` (`member`, optional), `suid`, `spid` (optional), `reason` (refused only) |
| `nat_binding_create`, `nat_binding_delete` | `proto`, `c6a2`, `spt`, `sourceTranslatedAddress`, `sourceTranslatedPort` |
| `nat_resource_limit` | `reason`, `c6a2`, `cn2` (`subscriberPrefixLen`) |
| `service_start`, `service_stop` | none; `service_start` adds `cs1` (`fipsProvider`), `cn2` (`fips`, 1/0), and with clustering `cs2` (`clusterMode`), `cs3` (`configDigest`), `cs4` (`slices`, comma-separated), `cn3` (`memberCount`); the node id is `cn4` |
| `dataplane_counter` | `cs2` (`counter`), `cn3` (`value`) |
| `audit_queue_overflow` | `cn3` (`lost`) |
| `audit_output_failure` | `cs3=file` (`destination`), `cs4` (`state`), `cn3` (`lost`), `reason` (optional) |
| `audit_recovery` | `cs3=file` (`destination`), `reason`, `cn3` (`lastCheckpointSeq`), `cn2` (`maxSeq`), `cs4` (`leaseState`) |
| `audit_remote_loss` | `cs3=syslog` (`destination`), `cs5` (`collector`, `ip:port`), `cn3` (`lost`), `reason` (optional) |
| `audit_storage_threshold` | `cs3=file` (`destination`), `cs4` (`state`), `cn3` (`availableBytes`, omitted for `unknown`), `cn2` (`minFreeBytes`) |
| `management_connection` | `act` (`accept`/`reject`), `src` (IPv4) or `c6a2` (IPv6), `spt`, `reason` (`plat.mgmt.reason`), `suser` (subject), `cs1` (`clientCertSha256`), `request` (path), `cs2` (`allowEntry`), `cs3` (`subjectAltNames`, comma-separated, ≤ 8) |
| `management_connection_suppressed` | `cn3` (`suppressed`), `cn2` (`windowSecs`) |
| `tls_revocation_check` | `act` (status), `cs1` (`tlsRole`), `cs2` (`revocationSource`), `cn2` (`chainIndex`), `cs5` (`certSha256`), `cs3` (`serialNumber`), `cs4` (`issuer`), `flexString1` (`policy`), `reason` (revocation reason, else OCSP, else CRL reason), `msg=ocsp:<reason> crl:<reason>` (`-` when absent) |
| `revocation_source_refresh` | `act` (transition), `cs1` (`crlSource` or `ocspKey`), `reason` (optional) |
| `audit_retention_prune` | `act` (state), `cs3=file` (`destination`), `cn3` (`prunedRotatedUs`), `cs5` (`prunedSeqRange`, `first-last`), `cs4` (`prunedChainPrefix`) |

The custom keys `cn2`, `cn3`, `cs1`–`cs5` and `flexString1` carry different meanings per
record type; SIEM parsers must key on the matching `…Label` field.
`release` and `delete` records carry no duration in CEF.

## Correlation recipe

Given `(ipv4, port, time)` from an external report:

1. Find the latest `nat_port_block_allocate` with `source.nat.ip = ipv4`,
   `plat.nat.port_start ≤ port ≤ plat.nat.port_end`, `@timestamp ≤ time`.
2. Confirm that the allocation was still open at `time`. It is closed by the
   first of:
   - a `nat_port_block_release` for the same address and port range;
   - a `service_stop` from the same `observer.name` (no release records are
     written at shutdown, POAM-009);
   - a `service_start` from the same `observer.name` (a crash writes no
     `service_stop`; every allocation made before a restart is void after it);
   - with HA (schema 7): a `cluster_slice_release` from that node for the
     slice holding `ipv4`, or a `cluster_slice_acquire` for that slice from
     **another** node with a higher `cluster.epoch` (crash takeover: the new
     owner's acquire ends the earlier owner's allocations).
   If the allocation was continued by a `nat_port_block_adopt` on the new
   owner (same address, range and subscriber, `cluster.prev_owner` = the
   first node), follow it on that node: the adopt record continues the same
   attribution until its own release.
3. Check for evidence gaps between the allocation and `time`: a gap in
   `event.sequence`, `audit_output_failure`, `audit_queue_overflow` or
   `audit_remote_loss` records from that node. A release can be deferred
   (written later than the block became empty) but is never skipped while
   records are being written.
4. The subscriber is `plat.subscriber.prefix`; join with the access network's
   prefix-delegation (DHCPv6-PD/RADIUS) logs to identify the customer.
5. Check that `observer.name` is the node that owned `ipv4` at `time`
   (`platd check-config` prints each node's slice). Without HA, duplicate node
   identity or overlapping `cluster.owned_pool` across nodes is **not**
   detected by the software (POAM-017): verify node configuration as part of
   the evidence, and compare `cluster.config_digest` of every node's
   `service_start`. With HA, ownership at `time` is the node with the latest
   `cluster_slice_acquire` for the slice (highest `cluster.epoch`) not yet
   followed by its `cluster_slice_release`.
6. If the record falls in a pruned file, the newest `audit_retention_prune`
   records name what retention removed (`deleted`) and when.

Audit-integrity alerts (AU-5, AU-9, SI-4):

- Alert on **every** `audit_recovery`: the node restarted after a damaged
  newest file (power cut, or deletion/emptying of records). Reconcile the
  range `last_checkpoint_seq + 1 ..= max_seq` against the collector copy; the
  local files cannot prove what was there. Treat `lease_state` `corrupt`,
  `inflated` or `high` as a possible tampering indicator.
- Alert on every `audit_output_failure` with `plat.audit.destination`
  `file` (any `plat.reason`); for `degraded` records use the remote copy to
  reconcile what the local file lost.
- `plat-fwguard` trips (forward policy missing or modified, IP forwarding
  disabled) are **journal-only**, not audit records (NIST-502): ship the
  systemd journal (`journalctl -u plat-fwguard -u nftables -p err`) to the
  SIEM and alert on `plat-fwguard:` messages.

Cluster alerts (CP-10, IA-3, AU-10): alert on every `cluster_peer_rejected`
(`duplicate_id` and `digest_mismatch` indicate a cloned or drifted
configuration), every `cluster_slice_acquire` with `cluster.in_sync:false`,
`cluster_slice_release` with `lease_lost`, failed `cluster_hook` records
(routes may still point at the old owner), repeated
`cluster_replication_gap` for one slice, every `cluster_operator_command`
with `cluster.force:true` or `cluster.reason` `not_authorized` /
`no_credentials` (AC-3), and every `cluster_view_change` with
`cluster.reason:"manual"`. In manual mode (`auto_failover = false`) the
software does not prove that a member taken over is stopped: correlate a
manual takeover with the operator's change record. Takeover timing is not
yet verified on a real multi-node network (LINUX_VERIFICATION L19–L23 not
run).

Management access review (AC-17, AU-6): group `management_connection` by
`tls.client.hash.sha256` / `plat.mgmt.allow_entry`; alert on any
`not_allowlisted`, `revoked`, `bad_cert` or a non-zero
`management_connection_suppressed`. Join the `tls_revocation_check` records
of the same client hash for the status decision. For a syslog collector,
`audit_remote_loss` with `plat.reason` `tls_verify` or `tls_revocation`
means the collector's identity was refused, not a network outage.

Example Splunk SPL:

```text
index=nat64 event.action=nat_port_block_allocate source.nat.ip="192.0.2.10"
| where plat.nat.port_start<=40123 AND plat.nat.port_end>=40123
| where _time <= strptime("2026-10-28T14:16:00Z","%Y-%m-%dT%H:%M:%SZ")
| sort - _time | head 1 | table _time plat.subscriber.prefix observer.name
```

Then search the same `observer.name` between that `_time` and the report time
for `nat_port_block_release` (same address and range), `service_stop`,
`service_start`, and the audit-health actions in step 3.

## Metrics and health (not SIEM records)

`GET /metrics` on the management listener (loopback, or mTLS):

- `plat_drops_total{reason=...}`: `malformed`, `unsupported_proto`,
  `bad_checksum`, `src_not_allowed`, `dst_not_translatable`,
  `dst_forbidden`, `no_binding`, `filtered`, `tcp_no_state`,
  `port_exhausted`, `subscriber_limit`, `session_limit`,
  `audit_unavailable`, `fragment`, `too_big`, `hop_limit`,
  `icmp_untranslatable`, `wrong_node`, `source_route`,
  `subscriber_table_full`, `aggregate_subscriber_limit` (new subscriber's
  aggregate prefix full), `cluster_fenced` (slice fenced or adopting on
  this node), `missteered` (HA `steering.mode = "drop"`: new subscriber
  homed on another member); fragments: `fragment_timeout` (incomplete
  datagram expired), `fragment_overlap` (overlap or duplicate, RFC 5722;
  the datagram is poisoned), `fragment_tiny` (first fragment short of the
  transport header or the IPv6 header chain, IPv4 TCP offset 1),
  `fragment_too_many` (above `max_fragments_per_datagram` or more than 8
  gaps), `fragment_table_full`, `fragment_buffer_full`, `reassembly_full`,
  `reassembly_too_big`, `fragment_unmatched` (non-first fragment with no
  entry while buffering is off or full, or on another worker),
  `icmp_quote_unmatched` (ICMP error quoting a non-first fragment this
  worker cannot map). `fragment` remains for reassembly turned off
  (`reassembly_slots = 0`), zero-checksum UDP under
  `udp_zero_checksum = "drop"` and other unsupported fragment shapes.
- `plat_<name>_total` for `rx_packets`, `tx_packets`, `rx_bytes`,
  `tx_bytes`, `v6_to_v4`, `v4_to_v6`, `hairpin`, `icmp_errors_translated`,
  `icmp_errors_generated`, `icmp_errors_rate_limited`,
  `fragmented_v4_to_v6`, `fragmented_v6_to_v4`, `fragments_in_v6`,
  `fragments_in_v4`, `fragments_forwarded`, `fragments_buffered`,
  `datagrams_reassembled`, `icmp_time_exceeded_sent`,
  `icmp_unreachable_sent` (Destination Unreachable, including Source Route
  Failed), `icmp_param_problem_sent`, `bib_created`, `session_created`, `io_errors`,
  `tx_queue_full` (TUN `EAGAIN` back-pressure, separate from `io_errors`);
  `plat_worker_rx_packets_total{worker=...}`.
- Gauges `plat_sessions`, `plat_bibs`, `plat_pool_blocks_free`,
  `plat_pool_blocks_total`, `plat_audit_queue_depth`, `plat_audit_degraded`,
  `plat_audit_storage_low`, `plat_fragment_entries` (live fragment-table
  entries summed over workers, updated by each worker's housekeeping, every
  64 packets and on an idle receive).
- Counter `plat_pool_releases_deferred_total`: port-block releases the
  sweeper deferred because the `nat_port_block_release` record could not
  yet be queued (the block stays out of the pool until it is).
- Counter `plat_sweep_resumed_total`: sweeper passes that reached their
  budget (half of `dataplane.sweep_interval_ms`) before the end of their
  cycle; the next pass resumes there (POAM-012). A steadily rising value
  means reclamation lags expiry by more than one interval.
- Audit counters `plat_audit_enqueued_total`, `plat_audit_lost_total`
  (records abandoned on a full queue, plus deferred port-block release
  records that could not be queued because the sink is disconnected, i.e.
  the logger has stopped, counted once per block; a deferred release that meets a full queue is
  retried and not counted), `plat_audit_written_total` (records
  whose checkpoint was flushed; without a file, records handed to the syslog
  senders), `plat_audit_output_errors_total`, `plat_audit_file_lost_total`,
  `plat_audit_remote_lost_total`, `plat_audit_seq_lease_failures_total`
  (failed writes of the sequence lease `.<name>.seq`).
- Cluster (HA): gauges `plat_cluster_epoch`, `plat_cluster_leader`,
  `plat_cluster_lease_remaining_ms`, `plat_cluster_peer_up{peer}`,
  `plat_cluster_slices{state}` (`active`, `fenced`, `backup_in_sync`,
  `backup_syncing`, `unprotected`), `plat_cluster_repl_lag_records{peer}`,
  `plat_cluster_directory_entries`; counters
  `plat_cluster_repl_events_total`,
  `plat_cluster_repl_dropped_total{reason}` (`ring`, `peer_queue`),
  `plat_cluster_resync_total`, `plat_cluster_takeovers_total{reason}`,
  `plat_cluster_handovers_total`, `plat_cluster_peer_rejected_total{reason}`,
  `plat_cluster_hook_failures_total{hook}`,
  `plat_cluster_state_persist_failures_total`, and the per-worker
  `plat_cluster_steer_missteered_total`, `plat_cluster_reserve_starved_total`,
  and `plat_pool_paired_exhausted_total` (strict paired pooling refused: the
  subscriber's address is full while other addresses have free blocks).
  `GET /cluster` returns the view and per-slice owners as JSON. `/healthz`
  returns 503 for 60 s after a duplicate member id was seen.
- Linux only: `plat_tun_rx_dropped_total{interface}` and
  `plat_tun_tx_dropped_total{interface}`, the kernel's drop counters for the
  TUN (`/sys/class/net/<if>/statistics/{rx,tx}_dropped`, read at scrape).
  Congestion drops on a Linux TUN appear here, not in `tx_queue_full`
  (which counts `EAGAIN` and stayed 0 in Linux testing).
- TLS: `plat_fips_mode` (1/0); `plat_mgmt_connections_total{outcome}`
  (`accepted`, `rejected`); `plat_mgmt_rejections_total{reason}` (the
  `plat.mgmt.reason` values); `plat_revocation_checks_total{role,status,source}`;
  `plat_revocation_refresh_failures_total{kind}` (`crl`, `ocsp`; every
  transition except `recovered` and the `state_*` ones); gauges `plat_ocsp_cache_entries`,
  `plat_crl_cache_entries`, `plat_crl_cache_bytes`; `plat_crl_state_errors_total` (crl-numbers load/persist problems and failed move-aside);
  `plat_tls_cert_expiry_seconds{role,file}`; per TLS syslog destination
  `plat_audit_remote_tls_handshakes_total{dest}` and
  `plat_audit_remote_tls_failures_total{dest,reason}` (`io`, `tls_handshake`,
  `tls_verify`, `tls_revocation`).
- Histograms `plat_ocsp_fetch_seconds{outcome}` and
  `plat_crl_fetch_seconds{outcome}` (`outcome` = `ok` | `error`; buckets
  0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 s, +Inf): latency of the HTTP
  exchange only (connect/timeout/status/size/content-type failures are
  `error`; signature and response validation are not included and are
  counted by `plat_revocation_checks_total`). URL sources only.
- Gauge `plat_crl_next_update_seconds{issuer}` (`issuer` = 16 hex chars, the
  first 8 bytes of the SHA-256 issuer key hash): seconds until the earliest
  nextUpdate over that issuer's verified CRLs; negative if stale. At most
  `crl.max_crls` series.
- Counter `plat_crl_state_dir_sync_failures_total`: directory fsyncs that
  failed after a successful rename (counted and warned only; not in
  `plat_crl_state_errors_total`, no audit record).
- `crl-numbers` state: a rejected regular file is moved aside as
  `crl-numbers.rejected.<unix_ts>` (exclusive name, mode 0600); the
  just-moved file and the 2 newest other rejected files are kept, and only
  regular files are pruned. A non-regular entry (directory, symlink) is left
  in place and counted, warned and audited. A failed move-aside increments
  `plat_crl_state_errors_total` and is warned (the `state_rejected` record
  covers it). At start, only this daemon's own regular temp files older than
  start − 60 s are removed.

`GET /healthz`: `200 ok`, or `503` with `unhealthy:` and one or more of
`audit file not writable`, `audit volume below min_free_bytes`,
`audit queue full`, `audit queue above 90%`.

## Injection safety

Data-plane and audit-health records contain no attacker-controlled text:
values are IP addresses, integers, and fixed strings; `node.name` is
restricted to `[A-Za-z0-9-_.]` and `syslog.app_name` to printable ASCII
without spaces at config load.

Since schema 5, TLS records carry peer-supplied text (certificate subject,
SANs, issuer DN, serial, responder/CRL source, matched allow-list entry).
Each value is an `AuditText`: control, bidi and zero-width characters are
replaced with `?`, and it is truncated at a character boundary (subject and
SAN 128 bytes, DN 256, other 128; at most 8 SANs). The JSON formatter
escapes `"`, `\` and control characters; CEF escapes `\`, `=`, CR and LF.
`plat-audit/tests/qa_schema.rs` (property test with hostile strings) checks
that JSON stays one flat object with an unchanged key set and that CEF gets
no raw line break or injected extension key (CWE-117).
