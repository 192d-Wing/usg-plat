//! NAT attribution and security audit logging for SIEM correlation.
//!
//! ```text
//!  worker 0 ─┐  try_send (never blocks)   ┌──────────────┐  JSON lines + SHA-256 checkpoints
//!  worker 1 ─┼──────────────────────────▶ │ plat-audit   │─▶ local file   (AU-9, authoritative)
//!  worker N ─┤   bounded MPMC queue       │ batch, fmt   │
//!  sweeper  ─┘                            └──────┬───────┘
//!                       bounded hand-off, try_send│ (never waits on a collector)
//!                                    plat-syslog-i ─▶ syslog UDP/TCP/TLS JSON|CEF (AU-6(4), RFC 5425)
//! ```
//!
//! The data plane only builds a small plain-data [`Event`] and hands it off with
//! a non-blocking `try_send`; formatting, hashing and I/O happen on the
//! logger threads in batches (one write per batch to the file and to each
//! TCP collector; UDP syslog is one datagram per record on its own thread).
//! If the local file cannot be written the pipeline is *degraded*:
//! [`AuditSink::has_room`] returns false so `refuse_new_bindings` fails
//! closed, and `audit_output_failure` records go to the other destinations.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-2, AU-3, AU-12 (event content and generation)
//! - NIST 800-53: AU-4, AU-5 (capacity and processing-failure response)
//! - NIST 800-53: AU-6(3), AU-6(4) (correlation fields, central export)
//! - NIST 800-53: AU-8 (UTC microsecond time stamps)
//! - NIST 800-53: AU-9 (hash-chained local log, unkeyed; see `logger`)
//! - RFC 6888 REQ-12, RFC 7422 - port-block logging for attribution

pub mod event;
pub mod format;
pub mod logger;
pub mod sink;
#[cfg(feature = "tls")]
pub mod tls;
pub mod verify;

pub use event::{
    AcquireReason, AuditText, BlockAdopt, BlockReleaseReason, ClusterMemberChange, ClusterStart, ClusterView, Event,
    FipsMark, HookKind, HookRun, LeaseState, LifecycleKind, LimitKind, MemberState, MgmtConnection, MgmtPath,
    MgmtReason, OperatorCommand, OperatorCommandKind, OperatorRefusal, OutputFailureReason, PeerRejectReason,
    PeerRejected, PruneState, RecoveryReason, RefreshKind, RefreshTransition, RemoteLossReason, RevocationCheck,
    RevocationRefresh, RevocationSource, RevocationStatus, SliceAcquire, SliceCidr, SliceReleaseReason, StorageState,
    TlsRole, ViewReason,
};
pub use logger::{Logger, LoggerHandle, NodeIdent};
pub use sink::{AuditSink, AuditStats, RemoteStats, TryEmit};

/// Version of the SIEM record schema (`plat.schema`). Bump on any field
/// or record-type change; downstream parsers key on it.
///
/// 2: `audit_chain_continue`, `audit_output_failure`, `audit_remote_loss`
/// records; `plat.schema`/`plat.node_id` on checkpoints; chain v2 (header
/// and checkpoint sequence range hashed); `subscriber_table_limit` reason;
/// CEF `cn4` (node id), `cs6` (schema), `outcome`.
///
/// 3: `audit_storage_threshold` (AU-5(1)) and `audit_retention_prune`
/// (AU-9/AU-11) records.
///
/// 4: `audit_retention_prune` carries `plat.audit.state`
/// (`scheduled` with `event.outcome:"unknown"`, then `deleted`/`failed` with
/// `success`/`failure`; CEF `act`); `audit_storage_threshold` state
/// `unknown` (free space undeterminable, fail closed; no
/// `plat.audit.available_bytes`).
///
/// 5: `service_start` carries `plat.fips` / `plat.fips_provider` (SC-13);
/// `audit_remote_loss` may carry `plat.reason`
/// (`io`|`tls_handshake`|`tls_verify`|`tls_revocation`); new records
/// `management_connection`, `management_connection_suppressed`,
/// `tls_revocation_check` and `revocation_source_refresh` (AC-17, IA-3,
/// IA-5(2)). Certificate text in these is sanitized, capped and escaped.
///
/// 6: new record `audit_recovery` (AU-5, AU-9): first record after a
/// start-up that found the newest audit file empty, without a header or
/// ending in a partial line; `plat.reason`
/// (`empty_file`|`missing_header`|`truncated_tail`),
/// `plat.audit.last_checkpoint_seq`, `plat.audit.max_seq`
/// (CEF `reason`, `cn3`/`lastCheckpointSeq`, `cn2`/`maxSeq`).
/// `audit_output_failure` may carry `plat.reason` (`truncate_failed`: a
/// failed batch could not be cut back to the last checkpoint; CEF `reason`).
///
/// 7: cluster high availability (CP-10, AU-10, IA-3). New records
/// `cluster_view_change`, `cluster_member_state`, `cluster_slice_acquire`,
/// `cluster_slice_release`, `nat_port_block_adopt`, `cluster_peer_rejected`,
/// `cluster_peer_suppressed`, `cluster_replication_gap` and `cluster_hook`.
/// `nat_port_block_release` may carry `plat.release_reason` (`handover`).
/// `service_start` may carry `cluster.node_id`, `cluster.mode`,
/// `cluster.config_digest`, `cluster.slices` and `cluster.member_count`.
pub const LOG_SCHEMA_VERSION: u32 = 7;
