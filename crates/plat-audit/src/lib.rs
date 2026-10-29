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
    AuditText, Event, FipsMark, LifecycleKind, LimitKind, MgmtConnection, MgmtPath, MgmtReason, PruneState,
    RefreshKind, RefreshTransition, RemoteLossReason, RevocationCheck, RevocationRefresh, RevocationSource,
    RevocationStatus, StorageState, TlsRole,
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
pub const LOG_SCHEMA_VERSION: u32 = 5;
