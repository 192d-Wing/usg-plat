# SIEM Logging and NAT Attribution

Schema version: **4** (`plat.schema`, `plat_audit::LOG_SCHEMA_VERSION`).
Source: `crates/plat-audit`.

## Purpose

An IPv4 abuse report or law-enforcement request names an IPv4 address, a
port, and a time. Behind a NAT64 many subscribers share that address, so the
PLAT must log enough to answer "which subscriber held 192.0.2.10:40123 at
14:16:00Z?" (RFC 6888 REQ-12, RFC 7422), and do it fast enough that logging
never limits forwarding.

## Schema history

| Version | Change |
|---------|--------|
| 1 | Initial schema; chain v1 (`SHA-256("usg-plat audit chain v1")` genesis). |
| 2 | Chain v2: `audit_chain_continue` file header, header-seeded chain, checkpoint `seq_first`/`seq_last` hashed. New records `audit_output_failure`, `audit_remote_loss`. Checkpoints gain `plat.schema` and `plat.node_id`. New `event.reason` `subscriber_table_limit`. Every CEF record gains `cn4` (node id), `cs6` (schema) and `outcome`. |
| 3 | New records `audit_storage_threshold` (AU-5(1)) and `audit_retention_prune` (AU-9, AU-11). |
| 4 | `audit_retention_prune` gains `plat.audit.state` (`scheduled` with outcome `unknown`, then `deleted` / `failed`; CEF `act=`). `audit_storage_threshold` gains state `unknown` (free space undeterminable; no `plat.audit.available_bytes`). |

Files written by the v1 chain (schema 1) **no longer verify** with
`platd verify-log`: the first line must be an `audit_chain_continue` header.
Files written under schemas 2–4 use the same chain v2 and verify.

## Controls

| Control | Implementation | Evidence |
|---------|----------------|----------|
| AU-2, AU-12 | Port-block allocate/release, binding create/delete (session mode), resource limits, queue overflow, service start/stop, periodic drop counters, audit output failure, remote loss, storage threshold, retention prune. An allocation record is queued before the block is used; a block returns to the pool only after its release record is queued. | `event.rs`; `plat-nat64/tests/engine.rs::udp_mapping_reply_and_block_log`, `session_mode_logs_bindings`; `hardening.rs::block_is_not_reused_before_its_release_record_is_queued` |
| AU-3 | Who (`source.ip`, `plat.subscriber.prefix`), what (`event.action`), when (`@timestamp`), where (`observer.name`, `plat.node_id`), outcome (`event.outcome`; CEF `outcome`), NAT address and ports, sequence. | `format.rs::json_port_block_record`, `cef_and_syslog`, `storage_and_retention_records` |
| AU-4 | Bounded queue `audit.queue_capacity`; rotation at `audit.file.max_bytes`; retention `audit.file.max_files` (0 = keep all, the default); free-space threshold `audit.file.min_free_bytes`. | `config.rs`; `config_edges.rs::audit_edges` |
| AU-5 | `on_overflow`: `refuse_new_bindings` (default; requires `[audit.file]`) or `drop_and_alert`. A full queue, a failed local file or low free space makes `has_room()` false, so new bindings are refused; `/healthz` returns 503. Records: `audit_queue_overflow`, `audit_output_failure`. Recovery is declared only after a checkpoint in the new file is synced. | `health.rs::file_failure_degrades_fails_closed_and_recovers`; `outputs.rs::queue_overflow_produces_an_audit_record`; `pipeline.rs::overflow_is_counted_and_reported`; `logger.rs::tests::full_volume_never_rotates_prunes_or_flaps` |
| AU-5(1) | `min_free_bytes` threshold (default 0 = off; the example sets 2 GiB); `audit_storage_threshold` records; fail closed when free space cannot be determined. | `logger.rs::tests::free_space_threshold_degrades_and_recovers`, `undeterminable_free_space_fails_closed_once` |
| AU-6(3), AU-6(4) | ECS-style field names, CEF, RFC 5424 syslog to central collectors. | `format.rs`; `pipeline.rs::file_and_syslog_records_with_valid_chain` |
| AU-8 | JSON and syslog header: RFC 3339 UTC with microseconds from the system clock. CEF `rt`: milliseconds. The platform must run NTP/PTP. | `format.rs::timestamps` |
| AU-9 (Partial) | File mode 0640 in a 0700 directory; SHA-256 chain v2 across batches and files; sequence numbers continue across restarts and files; atomic rotation; `platd verify-log`. The chain is unkeyed (POAM-003). | `health.rs::restart_continues_chain_and_sequence`, `header_and_checkpoint_metadata_are_bound_into_the_chain`, `missing_live_file_resumes_from_newest_rotated_file`; `pipeline.rs::tampering_is_detected` |
| AU-9(2) (Partial) | Best-effort copy on the collectors; every undelivered record is counted and recorded locally (`audit_remote_loss`). No TLS (POAM-005). | `health.rs::stalled_collector_never_stalls_the_local_file`; `outputs.rs::tcp_syslog_unreachable_counts_output_errors_without_blocking` |
| AU-10 | Planned: hash chain gives integrity against editors who cannot recompute it, not origin authentication. | POAM-003 |
| AU-11 | `max_files > 0` deletes the oldest rotated files after a size rotation, each deletion recorded (`audit_retention_prune`); default 0 keeps every file. The site sets the retention period and archives before deletion. | `health.rs::retention_keeps_at_most_max_files`, `retention_records_every_deletion`, `retention_follows_the_chain_after_a_backward_clock_step` |

## Performance design

- Data plane: build a `Copy` event (≤ 48 bytes) and `try_send` it to a
  bounded MPMC queue. No allocation, no formatting, no syscall, never
  blocks.
- Logger thread (`plat-audit`): drains up to `batch_max` events per wake-up
  (or every `flush_interval_ms`), formats JSON lines, writes the local file
  once per batch and appends one checkpoint per batch.
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
| `plat.schema` | int | Schema version (4) |
| `event.sequence` | int | Monotonically increasing. With `[audit.file]` configured it continues across restarts and across files, and is never reused while any audit file is present; numbers of records after the last checkpoint of a crashed file are skipped, not reused. Without a file (syslog only) it restarts at 1 with each process. A gap means records were lost (see AU-5 records). |
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
| `nat_port_block_release` | 6 | `success` | as allocate, plus `event.duration` (ns, whole seconds the block was held) |
| `nat_binding_create` | 6 | `success` | `network.transport` (`tcp`/`udp`/`icmp`), `source.ip` (full IPv6 host), `source.port`, `source.nat.ip`, `source.nat.port` |
| `nat_binding_delete` | 6 | `success` | as create, plus `event.duration` |
| `nat_resource_limit` | 4 | `failure` | `event.reason`, `source.ip`, `plat.subscriber.prefix` |
| `service_start`, `service_stop` | 5 | `success` | `service.version` |
| `dataplane_counter` | 6 | (none) | `plat.counter.name`, `plat.counter.value` |
| `audit_queue_overflow` | 4 | `failure` | `plat.audit.lost` |
| `audit_output_failure` | 3 (`degraded`), 4 (`recovered`) | `failure` | `plat.audit.destination` (`file`), `plat.audit.state` (`degraded` / `recovered`), `plat.audit.lost` |
| `audit_remote_loss` | 4 | `failure` | `plat.audit.destination` (`syslog`), `destination.ip`, `destination.port`, `plat.audit.lost` |
| `audit_storage_threshold` | 4 (`below_threshold`, `unknown`), 5 (`recovered`) | `failure` / `success` (`recovered`) | `plat.audit.destination` (`file`), `plat.audit.state`, `plat.audit.available_bytes` (omitted for `unknown`), `plat.audit.min_free_bytes` |
| `audit_retention_prune` | 5 (`scheduled`, `deleted`), 4 (`failed`) | `unknown` (`scheduled`), `success` (`deleted`), `failure` (`failed`) | `plat.audit.state`, `plat.audit.pruned_rotated_us`, `plat.audit.pruned_seq_first`, `plat.audit.pruned_seq_last`, `plat.audit.pruned_chain_prefix` |

### `nat_port_block_allocate` / `nat_port_block_release`

```json
{"@timestamp":"2026-10-28T14:16:00.000001Z","plat.schema":4,"event.sequence":7,"event.kind":"event","event.category":"network","event.action":"nat_port_block_allocate","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"success","source.ip":"2001:db8:100:1::","plat.subscriber.prefix":"2001:db8:100:1::/64","source.nat.ip":"192.0.2.10","plat.nat.port_start":1024,"plat.nat.port_end":1535}
```

A block is released after it has been empty for 60 s, and only once its
release record has been queued; until then it stays with its subscriber (a
release can be deferred, never skipped). Live blocks get **no** release
record at shutdown or on a crash (POAM-009).

### `nat_binding_create` / `nat_binding_delete` (`audit.mode = "session"`)

```json
{"@timestamp":"2026-10-28T14:16:00.120000Z","plat.schema":4,"event.sequence":8,"event.kind":"event","event.category":"network","event.action":"nat_binding_create","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"success","network.transport":"udp","source.ip":"2001:db8:100:1::5","source.port":40000,"source.nat.ip":"192.0.2.10","source.nat.port":1100}
```

Destinations are deliberately **not** logged (privacy; not needed for
attribution).

### `nat_resource_limit`

`event.reason` ∈ `pool_exhausted`, `subscriber_block_limit`,
`subscriber_session_limit`, `global_session_limit`,
`subscriber_table_limit`. Rate-limited to one record per second per reason.

```json
{"@timestamp":"2026-10-28T14:16:01.000000Z","plat.schema":4,"event.sequence":9,"event.kind":"event","event.category":"network","event.action":"nat_resource_limit","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","event.reason":"subscriber_block_limit","source.ip":"2001:db8:100:1::","plat.subscriber.prefix":"2001:db8:100:1::/64"}
```

### `service_start` / `service_stop`

`service_start` is the first record queued after the logger starts and
before any packet is translated. `service_stop` is queued on every exit after
the logger has started, and the logger drains before the process exits. A
crash (`panic = "abort"`, OOM kill, `SIGKILL`) writes no `service_stop`.

```json
{"@timestamp":"2026-10-28T14:00:00.000000Z","plat.schema":4,"event.sequence":1,"event.kind":"event","event.category":"network","event.action":"service_start","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"success","service.version":"0.1.0"}
```

### `dataplane_counter`

Every `audit.summary_interval_secs` (default 60; 0 disables), one record per
**drop reason** whose count is non-zero. Values are cumulative since the
process started (they reset on restart). Only drop reasons appear here;
non-drop counters such as `tx_queue_full`, `icmp_errors_generated` or
`fragmented_v4_to_v6` are only in `/metrics`.

```json
{"@timestamp":"2026-10-28T14:17:00.000000Z","plat.schema":4,"event.sequence":40,"event.kind":"event","event.category":"network","event.action":"dataplane_counter","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"plat.counter.name":"filtered","plat.counter.value":12}
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
{"@timestamp":"2026-10-28T14:20:00.000000Z","plat.schema":4,"event.sequence":512,"event.kind":"event","event.category":"network","event.action":"audit_output_failure","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","plat.audit.destination":"file","plat.audit.state":"degraded","plat.audit.lost":12}
```

`plat_audit_file_lost_total` also counts records that reached the failed file
after its last checkpoint (its unverified tail), so the sequence gap that
`verify-log` reports equals `file_lost` minus that tail.

### `audit_remote_loss`

Records not delivered to one collector: its hand-off queue was full, the
send or connect failed, or the record fell in the 5 s TCP reconnect back-off.
Written to the local file and offered to every syslog destination.

```json
{"@timestamp":"2026-10-28T14:21:00.000000Z","plat.schema":4,"event.sequence":700,"event.kind":"event","event.category":"network","event.action":"audit_remote_loss","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","plat.audit.destination":"syslog","destination.ip":"198.51.100.10","destination.port":514,"plat.audit.lost":3}
```

### `audit_storage_threshold`

Free space on the log volume, checked at most once per second when
`min_free_bytes > 0`.

- `below_threshold`: free space < `min_free_bytes`; the pipeline is degraded
  (new bindings refused, `/healthz` 503) while records keep being written.
- `recovered`: free space ≥ threshold + 10 %.
- `unknown`: free space cannot be determined (`statvfs` failed); treated as
  below the threshold (fail closed). Written once per episode, without
  `plat.audit.available_bytes`; it clears with a `recovered` record.

```json
{"@timestamp":"2026-10-28T14:22:00.000000Z","plat.schema":4,"event.sequence":800,"event.kind":"event","event.category":"network","event.action":"audit_storage_threshold","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"failure","plat.audit.destination":"file","plat.audit.state":"below_threshold","plat.audit.available_bytes":1073741824,"plat.audit.min_free_bytes":2147483648}
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
{"@timestamp":"2026-10-28T15:00:00.000000Z","plat.schema":4,"event.sequence":90001,"event.kind":"event","event.category":"network","event.action":"audit_retention_prune","observer.type":"nat64","observer.name":"plat-01","plat.node_id":0,"event.outcome":"unknown","plat.audit.state":"scheduled","plat.audit.pruned_rotated_us":1793196960000000,"plat.audit.pruned_seq_first":1,"plat.audit.pruned_seq_last":45000,"plat.audit.pruned_chain_prefix":"9f2c4e01b7a6d3c8"}
```

### `audit_chain_continue` (local file only, first line of every file)

```json
{"@timestamp":"2026-10-28T14:00:00.000000Z","plat.schema":4,"event.action":"audit_chain_continue","observer.name":"plat-01","plat.node_id":0,"plat.audit.prev_chain":"<64 hex digits; all zero if no predecessor is known>","plat.audit.prev_seq":45000,"plat.audit.next_seq":45001}
```

`prev_chain` / `prev_seq`: the previous file's final checkpoint chain and its
`seq_last`. `next_seq`: the first sequence number in this file.

### `audit_checkpoint` (local file only, after every batch)

```json
{"@timestamp":"2026-10-28T14:00:00.100000Z","plat.schema":4,"event.action":"audit_checkpoint","observer.name":"plat-01","plat.node_id":0,"plat.audit.seq_first":45001,"plat.audit.seq_last":45012,"plat.audit.batch_sha256":"<64 hex>","plat.audit.chain_sha256":"<64 hex>"}
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
for that case (best-effort, POAM-005).

## `platd verify-log`

```text
platd verify-log [--allow-tail] [--allow-gap] FILE...
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

A gap means records were not written locally (see `audit_output_failure` and
the syslog copy). Removal of the oldest retained file is not detectable from
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
- The unit sets `LogsDirectoryMode=0700`; files are created 0640. Grant a log
  shipper or `verify-log` operator access with an ACL, not through the `plat`
  group.

## Syslog

- RFC 5424, facility local0. Severity per record type (table above).
  `MSGID` = `event.action`. `APP-NAME` = `audit.syslog.app_name` (default
  `platd`, 1–48 printable ASCII).
- UDP: one datagram (one `send`) per record (RFC 5426), on the destination's
  own thread. Measured ceiling about **310 k records/s per destination**
  (macOS loopback); above it records are counted in
  `plat_audit_remote_lost_total` and recorded as `audit_remote_loss`. For
  sustained rates near that (e.g. `audit.mode = "session"`), use TCP or
  several collectors (POAM-018).
- TCP: RFC 6587 octet-counting, one write per batch, 2 s connect and write
  timeouts, 5 s reconnect back-off. A failed write counts the whole batch as
  lost (some frames may have arrived).
- No TLS (RFC 5425): use a protected management network (POAM-005).
- The remote copy is **best-effort**: remote loss never degrades the pipeline
  or refuses bindings; it is counted and recorded in the local file.

### CEF

```text
<134>1 2026-10-28T14:16:00.000001Z plat-01 platd 4242 nat_port_block_allocate - CEF:0|USG|usg-plat|0.1.0|nat_port_block_allocate|nat_port_block_allocate|3|rt=1793196960000 dvchost=plat-01 cn1=7 cn1Label=sequence cn4=0 cn4Label=nodeId cs6=4 cs6Label=schema outcome=success c6a2=2001:db8:100:1:: cn2=64 cn2Label=subscriberPrefixLen sourceTranslatedAddress=192.0.2.10 cs1=1024-1535 cs1Label=portRange
```

Header: `CEF:0|USG|usg-plat|<version>|<event.action>|<event.action>|<severity>`.
CEF severity from syslog severity: 3 → 9, 4 → 7, 5 → 4, 6 → 3.

Common extension keys on every record: `rt` (epoch **milliseconds**; JSON
keeps microseconds), `dvchost` (node name), `cn1` (`sequence`), `cn4`
(`nodeId`), `cs6` (`schema`), and `outcome` (absent on `dataplane_counter`).

| Record | Extension keys |
|--------|----------------|
| `nat_port_block_allocate`, `nat_port_block_release` | `c6a2` (subscriber prefix address), `cn2` (`subscriberPrefixLen`), `sourceTranslatedAddress`, `cs1` (`portRange`, `start-end`) |
| `nat_binding_create`, `nat_binding_delete` | `proto`, `c6a2`, `spt`, `sourceTranslatedAddress`, `sourceTranslatedPort` |
| `nat_resource_limit` | `reason`, `c6a2`, `cn2` (`subscriberPrefixLen`) |
| `service_start`, `service_stop` | none |
| `dataplane_counter` | `cs2` (`counter`), `cn3` (`value`) |
| `audit_queue_overflow` | `cn3` (`lost`) |
| `audit_output_failure` | `cs3=file` (`destination`), `cs4` (`state`), `cn3` (`lost`) |
| `audit_remote_loss` | `cs3=syslog` (`destination`), `cs5` (`collector`, `ip:port`), `cn3` (`lost`) |
| `audit_storage_threshold` | `cs3=file` (`destination`), `cs4` (`state`), `cn3` (`availableBytes`, omitted for `unknown`), `cn2` (`minFreeBytes`) |
| `audit_retention_prune` | `act` (state), `cs3=file` (`destination`), `cn3` (`prunedRotatedUs`), `cs5` (`prunedSeqRange`, `first-last`), `cs4` (`prunedChainPrefix`) |

The custom keys `cn2`, `cn3`, `cs4` and `cs5` carry different meanings per
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
     `service_stop`; every allocation made before a restart is void after it).
3. Check for evidence gaps between the allocation and `time`: a gap in
   `event.sequence`, `audit_output_failure`, `audit_queue_overflow` or
   `audit_remote_loss` records from that node. A release can be deferred
   (written later than the block became empty) but is never skipped while
   records are being written.
4. The subscriber is `plat.subscriber.prefix`; join with the access network's
   prefix-delegation (DHCPv6-PD/RADIUS) logs to identify the customer.
5. Check that `observer.name` is the node that owned `ipv4` at `time`
   (`platd check-config` prints each node's slice). Duplicate node identity or
   overlapping `cluster.owned_pool` across nodes is **not** detected by the
   software (POAM-017): verify node configuration as part of the evidence.
6. If the record falls in a pruned file, the newest `audit_retention_prune`
   records name what retention removed (`deleted`) and when.

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

`GET /metrics` on the loopback management listener:

- `plat_drops_total{reason=...}`: `malformed`, `unsupported_proto`,
  `bad_checksum`, `src_not_allowed`, `dst_not_translatable`,
  `dst_forbidden`, `no_binding`, `filtered`, `tcp_no_state`,
  `port_exhausted`, `subscriber_limit`, `session_limit`,
  `audit_unavailable`, `fragment`, `too_big`, `hop_limit`,
  `icmp_untranslatable`, `wrong_node`, `source_route`,
  `subscriber_table_full`.
- `plat_<name>_total` for `rx_packets`, `tx_packets`, `rx_bytes`,
  `tx_bytes`, `v6_to_v4`, `v4_to_v6`, `hairpin`, `icmp_errors_translated`,
  `icmp_errors_generated`, `icmp_errors_rate_limited`,
  `fragmented_v4_to_v6`, `bib_created`, `session_created`, `io_errors`,
  `tx_queue_full` (TUN `EAGAIN` back-pressure, separate from `io_errors`);
  `plat_worker_rx_packets_total{worker=...}`.
- Gauges `plat_sessions`, `plat_bibs`, `plat_pool_blocks_free`,
  `plat_pool_blocks_total`, `plat_audit_queue_depth`, `plat_audit_degraded`,
  `plat_audit_storage_low`.
- Counter `plat_pool_releases_deferred_total`: port-block releases the
  sweeper deferred because the `nat_port_block_release` record could not
  yet be queued (the block stays out of the pool until it is).
- Audit counters `plat_audit_enqueued_total`, `plat_audit_lost_total`
  (records abandoned on a full queue, plus deferred port-block release
  records that could not be queued because the sink is disconnected, i.e.
  the logger has stopped, counted once per block; a deferred release that meets a full queue is
  retried and not counted), `plat_audit_written_total` (records
  whose checkpoint was flushed; without a file, records handed to the syslog
  senders), `plat_audit_output_errors_total`, `plat_audit_file_lost_total`,
  `plat_audit_remote_lost_total`.

`GET /healthz`: `200 ok`, or `503` with `unhealthy:` and one or more of
`audit file not writable`, `audit volume below min_free_bytes`,
`audit queue full`, `audit queue above 90%`.

## Injection safety

No record contains attacker-controlled text: values are IP addresses,
integers, and fixed strings; `node.name` is restricted to `[A-Za-z0-9-_.]`
and `syslog.app_name` to printable ASCII without spaces at config load.
JSON/CEF escaping is therefore unnecessary (CWE-117).
