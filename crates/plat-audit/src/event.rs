//! Audit event payloads. Data-plane variants are small plain data, so
//! building and queueing them never allocates. Management-plane and TLS
//! variants (`management_connection`, `tls_revocation_check`,
//! `revocation_source_refresh`) carry peer-supplied text behind an `Arc`;
//! they are built off the hot path (management and TLS threads only).

use std::net::IpAddr;
use std::sync::Arc;

/// Why a resource limit fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    PoolExhausted,
    SubscriberBlocks,
    SubscriberSessions,
    GlobalSessions,
    /// `nat64.max_subscribers` reached (SC-5).
    SubscriberTable,
}

impl LimitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolExhausted => "pool_exhausted",
            Self::SubscriberBlocks => "subscriber_block_limit",
            Self::SubscriberSessions => "subscriber_session_limit",
            Self::GlobalSessions => "global_session_limit",
            Self::SubscriberTable => "subscriber_table_limit",
        }
    }
}

/// State reported by `audit_storage_threshold` (AU-5(1)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageState {
    /// Free space fell below `min_free_bytes`: degraded.
    Below,
    /// Free space is back above the threshold plus 10 %.
    Recovered,
    /// Free space cannot be determined (`statvfs` failed): treated as below
    /// the threshold, fail closed (SEC-204).
    Unknown,
}

impl StorageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Below => "below_threshold",
            Self::Recovered => "recovered",
            Self::Unknown => "unknown",
        }
    }
}

/// Phase reported by `audit_retention_prune` (AU-9, AU-11). A deletion is
/// first recorded as `Scheduled` (synced before the file is touched), then
/// its result as `Deleted` or `Failed` in a later batch (NIST-202).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneState {
    Scheduled,
    Deleted,
    Failed,
}

impl PruneState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Deleted => "deleted",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    Start,
    Stop,
}

/// FIPS module state recorded on `service_start` (`plat.fips`,
/// `plat.fips_provider`; schema 5).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-13 (Cryptographic Protection), AU-3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FipsMark {
    pub active: bool,
    pub provider: &'static str,
}

/// Cause of an `audit_remote_loss` (`plat.reason`; schema 5). Absent for
/// losses with no single cause (queue full, back-off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteLossReason {
    Io,
    TlsHandshake,
    TlsVerify,
    TlsRevocation,
}

impl RemoteLossReason {
    pub const ALL: [Self; 4] = [Self::Io, Self::TlsHandshake, Self::TlsVerify, Self::TlsRevocation];

    /// Position in [`Self::ALL`].
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::TlsHandshake => "tls_handshake",
            Self::TlsVerify => "tls_verify",
            Self::TlsRevocation => "tls_revocation",
        }
    }
}

/// Peer-supplied text (certificate subject, issuer DN, serial, source
/// name) made safe for every output format. Control characters and
/// Unicode bidi/zero-width formatting characters become `?`, and the text
/// is truncated at a character boundary to the cap (CWE-117). JSON and CEF
/// escaping of the remaining `"`, `\` and `=` happens in `format`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditText(Box<str>);

impl AuditText {
    /// Cap for `tls.client.subject`.
    pub const SUBJECT_MAX: usize = 128;
    /// Cap for `x509.issuer.distinguished_name`.
    pub const DN_MAX: usize = 256;
    /// Cap for serial numbers (hex), source names and OCSP keys.
    pub const SHORT_MAX: usize = 128;

    pub fn new(s: &str, max: usize) -> Self {
        let mut out = String::with_capacity(s.len().min(max));
        for c in s.chars() {
            let c = if c.is_control()
                || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                '?'
            } else {
                c
            };
            if out.len() + c.len_utf8() > max {
                break;
            }
            out.push(c);
        }
        Self(out.into_boxed_str())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `plat.mgmt.reason` of a `management_connection` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtReason {
    Accepted,
    NoClientCert,
    BadCert,
    NotAllowlisted,
    HandshakeTimeout,
    HandshakeFailed,
    OverCapacity,
    Revoked,
    RevocationCheckFailed,
}

impl MgmtReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::NoClientCert => "no_client_cert",
            Self::BadCert => "bad_cert",
            Self::NotAllowlisted => "not_allowlisted",
            Self::HandshakeTimeout => "handshake_timeout",
            Self::HandshakeFailed => "handshake_failed",
            Self::OverCapacity => "over_capacity",
            Self::Revoked => "revoked",
            Self::RevocationCheckFailed => "revocation_check_failed",
        }
    }
}

/// First request path of an accepted management connection (`url.path`),
/// as an enum so the raw request line never reaches the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtPath {
    Metrics,
    Healthz,
    Other,
}

impl MgmtPath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Metrics => "/metrics",
            Self::Healthz => "/healthz",
            Self::Other => "other",
        }
    }
}

/// One management connection, accepted or rejected.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-17, AU-2, AU-3, IA-3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MgmtConnection {
    pub ip: IpAddr,
    pub port: u16,
    /// Client certificate subject CN, if a certificate was presented.
    pub subject: Option<AuditText>,
    /// SHA-256 of the client certificate DER.
    pub cert_sha256: Option<[u8; 32]>,
    pub reason: MgmtReason,
    /// Accepted connections only.
    pub path: Option<MgmtPath>,
    /// The typed allow-list entry that authorised the client (accepted
    /// connections only), e.g. `dns:prom-01.ops.example.net`.
    pub allow_entry: Option<AuditText>,
    /// Client certificate DNS and URI SANs, typed (`dns:` / `uri:`),
    /// sanitised, at most [`MgmtConnection::SANS_MAX`] entries of
    /// [`AuditText::SUBJECT_MAX`] bytes each.
    pub sans: Vec<AuditText>,
}

impl MgmtConnection {
    /// Most SANs recorded per connection (AU-3, SC-5).
    pub const SANS_MAX: usize = 8;
}

/// Which side of a TLS session the checked chain belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRole {
    /// Management client chain (`tls.client.hash.sha256`).
    MgmtClient,
    /// Syslog collector chain (`tls.server.hash.sha256`).
    SyslogServer,
}

impl TlsRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MgmtClient => "mgmt_client",
            Self::SyslogServer => "syslog_server",
        }
    }
}

/// `plat.revocation.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    Good,
    Revoked,
    Unavailable,
    Fatal,
    NotChecked,
}

impl RevocationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Revoked => "revoked",
            Self::Unavailable => "unavailable",
            Self::Fatal => "fatal",
            Self::NotChecked => "not_checked",
        }
    }
}

/// `plat.revocation.source`: where the deciding status came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationSource {
    OcspStapled,
    OcspCache,
    OcspFetch,
    CrlCache,
    CrlFetch,
    CrlFile,
    None,
}

impl RevocationSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OcspStapled => "ocsp_stapled",
            Self::OcspCache => "ocsp_cache",
            Self::OcspFetch => "ocsp_fetch",
            Self::CrlCache => "crl_cache",
            Self::CrlFetch => "crl_fetch",
            Self::CrlFile => "crl_file",
            Self::None => "none",
        }
    }
}

/// One certificate of one chain checked for revocation.
///
/// The `&'static str` reasons come from the closed vocabularies in
/// `plat-tls` (OCSP/CRL failure reasons, RFC 5280 reason code names,
/// policy name), never from peer data.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: IA-5(2)(b)(1), AU-2, AU-3
/// - RFC 6960, RFC 5280 §6.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationCheck {
    pub role: TlsRole,
    /// SHA-256 of the checked certificate DER.
    pub cert_sha256: [u8; 32],
    /// Serial number, hex.
    pub serial_hex: AuditText,
    pub issuer_dn: AuditText,
    /// 0 = leaf.
    pub chain_index: u8,
    pub status: RevocationStatus,
    pub source: RevocationSource,
    pub ocsp_reason: Option<&'static str>,
    pub crl_reason: Option<&'static str>,
    /// RFC 5280 CRLReason name, when revoked.
    pub revocation_reason: Option<&'static str>,
    /// Revocation time, UTC µs, when revoked.
    pub revocation_date_us: Option<u64>,
    /// OCSP responder `host:port`.
    pub ocsp_responder: Option<AuditText>,
    /// CRL `host:port` or file basename.
    pub crl_source: Option<AuditText>,
    /// `hard_fail` | `soft_fail` | `off`.
    pub policy: &'static str,
    /// The certificate did not cause the chain to be rejected.
    pub allowed: bool,
}

/// What kind of item the background refresher tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshKind {
    Crl,
    Ocsp,
}

/// `plat.revocation.transition` of a `revocation_source_refresh` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTransition {
    Failing,
    Recovered,
    StaleDropped,
    RollbackRejected,
    /// Persisted cRLNumber state rejected or partly skipped at start.
    StateRejected,
    /// Writing the cRLNumber state failed (first failure of a streak).
    StatePersistFailed,
}

impl RefreshTransition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Failing => "failing",
            Self::Recovered => "recovered",
            Self::StaleDropped => "stale_dropped",
            Self::RollbackRejected => "rollback_rejected",
            Self::StateRejected => "state_rejected",
            Self::StatePersistFailed => "state_persist_failed",
        }
    }
}

/// A state change of one refreshed revocation source (never per attempt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRefresh {
    pub kind: RefreshKind,
    /// CRL `host:port` / file basename, or OCSP key (issuer key hash:serial).
    pub source: AuditText,
    pub transition: RefreshTransition,
    pub reason: Option<&'static str>,
}

/// One audit record. Times are UTC microseconds since the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A port block was assigned to a subscriber (RFC 7422 bulk allocation).
    PortBlockAlloc { ts_us: u64, sub: u128, sub_len: u8, v4: u32, port_lo: u16, port_hi: u16 },
    /// A port block was returned to the pool.
    PortBlockRelease { ts_us: u64, sub: u128, sub_len: u8, v4: u32, port_lo: u16, port_hi: u16, held_secs: u32 },
    /// BIB entry created (session-mode logging).
    BibCreate { ts_us: u64, proto: u8, v6: u128, v6_port: u16, v4: u32, v4_port: u16 },
    /// BIB entry removed (session-mode logging).
    BibDelete { ts_us: u64, proto: u8, v6: u128, v6_port: u16, v4: u32, v4_port: u16, held_secs: u32 },
    /// A resource limit refused a mapping (rate-limited by the emitter).
    Limit { ts_us: u64, kind: LimitKind, sub: u128, sub_len: u8 },
    Lifecycle {
        ts_us: u64,
        kind: LifecycleKind,
        /// FIPS module state; set on `Start` (schema 5).
        fips: Option<FipsMark>,
    },
    /// Counter snapshot (drops etc.), emitted by the logger itself.
    Counter { ts_us: u64, name: &'static str, value: u64 },
    /// Records lost because the queue was full (AU-5 alert).
    QueueOverflow { ts_us: u64, lost: u64 },
    /// The local audit file (the authoritative AU-9 copy) could not be
    /// written (`recovered == false`, sent to the remaining destinations)
    /// or is being written again (`recovered == true`, first record of the
    /// new file). `lost` records were not written to the file. Emitted by
    /// the logger itself (AU-5).
    OutputFailure { ts_us: u64, lost: u64, recovered: bool },
    /// Records not delivered to a syslog collector (queue full, connection
    /// failure, reconnect back-off). Emitted by the logger itself into the
    /// local file (AU-5, AU-9(2)).
    RemoteLoss { ts_us: u64, ip: IpAddr, port: u16, lost: u64, reason: Option<RemoteLossReason> },
    /// Free space on the log volume crossed `audit.file.min_free_bytes`
    /// (`Below`/`Unknown`: pipeline degraded, new bindings refused;
    /// `Recovered`: back above the threshold plus 10 %). `available` is 0
    /// and not formatted for `Unknown`. Emitted by the logger (AU-5(1)).
    StorageThreshold { ts_us: u64, available: u64, threshold: u64, state: StorageState },
    /// Retention (`audit.file.max_files`) of a rotated audit file. The
    /// `Scheduled` record is written to the live chain and synced before
    /// the file is deleted; the result (`Deleted` / `Failed`) follows in a
    /// later batch (AU-9, AU-11). The file is `<path>.<rotated_us>`; it held
    /// records `seq_first..=seq_last` and its last checkpoint chain starts
    /// with `chain_prefix` (the next file's header names the full chain
    /// value).
    RetentionPrune { ts_us: u64, rotated_us: u64, seq_first: u64, seq_last: u64, chain_prefix: u64, state: PruneState },
    /// A management connection was accepted or rejected (AC-17, AU-2).
    ManagementConnection { ts_us: u64, conn: Arc<MgmtConnection> },
    /// Rejected-connection records suppressed by the rate limit over the
    /// last `window_secs` (summary; SC-5, AU-5).
    ManagementSuppressed { ts_us: u64, suppressed: u64, window_secs: u32 },
    /// Revocation status of one certificate in a chain (IA-5(2)).
    RevocationCheck { ts_us: u64, check: Arc<RevocationCheck> },
    /// Background refresher state change for a revocation source.
    RevocationRefresh { ts_us: u64, refresh: Arc<RevocationRefresh> },
}

impl Event {
    pub fn ts_us(&self) -> u64 {
        match *self {
            Event::PortBlockAlloc { ts_us, .. }
            | Event::PortBlockRelease { ts_us, .. }
            | Event::BibCreate { ts_us, .. }
            | Event::BibDelete { ts_us, .. }
            | Event::Limit { ts_us, .. }
            | Event::Lifecycle { ts_us, .. }
            | Event::Counter { ts_us, .. }
            | Event::QueueOverflow { ts_us, .. }
            | Event::OutputFailure { ts_us, .. }
            | Event::RemoteLoss { ts_us, .. }
            | Event::StorageThreshold { ts_us, .. }
            | Event::RetentionPrune { ts_us, .. }
            | Event::ManagementConnection { ts_us, .. }
            | Event::ManagementSuppressed { ts_us, .. }
            | Event::RevocationCheck { ts_us, .. }
            | Event::RevocationRefresh { ts_us, .. } => ts_us,
        }
    }

    /// `event.action` value; also used as the syslog MSGID.
    pub fn action(&self) -> &'static str {
        match self {
            Event::PortBlockAlloc { .. } => "nat_port_block_allocate",
            Event::PortBlockRelease { .. } => "nat_port_block_release",
            Event::BibCreate { .. } => "nat_binding_create",
            Event::BibDelete { .. } => "nat_binding_delete",
            Event::Limit { .. } => "nat_resource_limit",
            Event::Lifecycle { kind: LifecycleKind::Start, .. } => "service_start",
            Event::Lifecycle { kind: LifecycleKind::Stop, .. } => "service_stop",
            Event::Counter { .. } => "dataplane_counter",
            Event::QueueOverflow { .. } => "audit_queue_overflow",
            Event::OutputFailure { .. } => "audit_output_failure",
            Event::RemoteLoss { .. } => "audit_remote_loss",
            Event::StorageThreshold { .. } => "audit_storage_threshold",
            Event::RetentionPrune { .. } => "audit_retention_prune",
            Event::ManagementConnection { .. } => "management_connection",
            Event::ManagementSuppressed { .. } => "management_connection_suppressed",
            Event::RevocationCheck { .. } => "tls_revocation_check",
            Event::RevocationRefresh { .. } => "revocation_source_refresh",
        }
    }

    /// Syslog severity (RFC 5424): 3 error, 4 warning, 5 notice,
    /// 6 informational.
    pub fn severity(&self) -> u8 {
        match self {
            Event::OutputFailure { recovered: false, .. } => 3,
            Event::ManagementConnection { conn, .. } if conn.reason != MgmtReason::Accepted => 4,
            Event::RevocationCheck { check, .. } if check.status != RevocationStatus::Good || !check.allowed => 4,
            Event::RevocationRefresh { refresh, .. } if refresh.transition != RefreshTransition::Recovered => 4,
            Event::ManagementSuppressed { .. }
            | Event::Limit { .. }
            | Event::QueueOverflow { .. }
            | Event::OutputFailure { .. }
            | Event::RemoteLoss { .. }
            | Event::StorageThreshold { state: StorageState::Below | StorageState::Unknown, .. }
            | Event::RetentionPrune { state: PruneState::Failed, .. } => 4,
            Event::Lifecycle { .. }
            | Event::StorageThreshold { .. }
            | Event::RetentionPrune { .. }
            | Event::ManagementConnection { .. }
            | Event::RevocationRefresh { .. } => 5,
            _ => 6,
        }
    }

    /// `event.outcome` (ECS) / CEF `outcome`; `None` for counter snapshots.
    pub fn outcome(&self) -> Option<&'static str> {
        match self {
            Event::PortBlockAlloc { .. }
            | Event::PortBlockRelease { .. }
            | Event::BibCreate { .. }
            | Event::BibDelete { .. }
            | Event::Lifecycle { .. }
            | Event::StorageThreshold { state: StorageState::Recovered, .. }
            | Event::RetentionPrune { state: PruneState::Deleted, .. } => Some("success"),
            // The deletion has not happened yet (NIST-202).
            Event::RetentionPrune { state: PruneState::Scheduled, .. } => Some("unknown"),
            Event::Limit { .. }
            | Event::QueueOverflow { .. }
            | Event::OutputFailure { .. }
            | Event::RemoteLoss { .. }
            | Event::StorageThreshold { .. }
            | Event::RetentionPrune { .. } => Some("failure"),
            Event::ManagementConnection { conn, .. } => {
                Some(if conn.reason == MgmtReason::Accepted { "success" } else { "failure" })
            }
            Event::RevocationCheck { check, .. } => Some(if check.allowed { "success" } else { "failure" }),
            Event::RevocationRefresh { refresh, .. } => {
                Some(if refresh.transition == RefreshTransition::Recovered { "success" } else { "failure" })
            }
            Event::ManagementSuppressed { .. } => Some("failure"),
            Event::Counter { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The data plane copies events into the queue; keep them small.
    #[test]
    fn event_stays_small() {
        assert!(std::mem::size_of::<Event>() <= 48, "{}", std::mem::size_of::<Event>());
    }

    #[test]
    fn audit_text_sanitizes_and_caps() {
        assert_eq!(AuditText::new("a\nb\u{202e}c\u{7f}", 64).as_str(), "a?b?c?");
        // Truncates at a char boundary, never mid-UTF-8.
        assert_eq!(AuditText::new("ab\u{e9}", 3).as_str(), "ab");
        assert_eq!(AuditText::new(&"x".repeat(500), AuditText::SUBJECT_MAX).as_str().len(), 128);
        assert_eq!(AuditText::new("CN=a \"q\" \\ =", 64).as_str(), "CN=a \"q\" \\ =");
    }

    #[test]
    fn tls_outcomes_and_severity() {
        let conn = |reason| Event::ManagementConnection {
            ts_us: 0,
            conn: Arc::new(MgmtConnection {
                ip: "192.0.2.1".parse().unwrap(),
                port: 1,
                subject: None,
                cert_sha256: None,
                reason,
                path: None,
                allow_entry: None,
                sans: Vec::new(),
            }),
        };
        assert_eq!((conn(MgmtReason::Accepted).outcome(), conn(MgmtReason::Accepted).severity()), (Some("success"), 5));
        assert_eq!((conn(MgmtReason::Revoked).outcome(), conn(MgmtReason::Revoked).severity()), (Some("failure"), 4));
        let ev = Event::RevocationRefresh {
            ts_us: 0,
            refresh: Arc::new(RevocationRefresh {
                kind: RefreshKind::Crl,
                source: AuditText::new("crl.example.net:80", 64),
                transition: RefreshTransition::Recovered,
                reason: None,
            }),
        };
        assert_eq!((ev.outcome(), ev.severity(), ev.action()), (Some("success"), 5, "revocation_source_refresh"));
    }

    #[test]
    fn limit_reasons() {
        assert_eq!(LimitKind::SubscriberTable.as_str(), "subscriber_table_limit");
        assert_eq!(LimitKind::PoolExhausted.as_str(), "pool_exhausted");
    }
}
