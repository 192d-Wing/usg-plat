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

/// Why start-up wrote an `audit_recovery` record (AU-5, AU-9): the newest
/// audit file on disk did not end at a complete checkpoint, so records
/// written after the last durable checkpoint may be lost (power cut).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReason {
    /// The newest file is empty (0 bytes).
    EmptyFile,
    /// The newest file has bytes but no complete `audit_chain_continue` header.
    MissingHeader,
    /// The newest file ends in a partial line.
    TruncatedTail,
}

impl RecoveryReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmptyFile => "empty_file",
            Self::MissingHeader => "missing_header",
            Self::TruncatedTail => "truncated_tail",
        }
    }
}

/// State of the durable sequence high-water mark `.<name>.seq` when
/// start-up read it (`plat.audit.lease_state` of `audit_recovery`; SEC-304).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// A regular file holding a number, used.
    Ok,
    /// No lease file (first start, or an installation from before it).
    Absent,
    /// Not a regular file (symlink, FIFO, directory), unreadable or
    /// unparsable: ignored.
    Corrupt,
    /// Within the wrap guard but more than one lease above the highest
    /// sequence in the files (files holding the top numbers were lost, or a
    /// planted value): used anyway so no number is reused (SEC-302).
    High,
    /// Above the wrap guard (`u64::MAX - 2 * SEQ_LEASE`): ignored so a
    /// planted value cannot burn the sequence space (SEC-302).
    Inflated,
}

impl LeaseState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Absent => "absent",
            Self::Corrupt => "corrupt",
            Self::High => "high",
            Self::Inflated => "inflated",
        }
    }
}

/// Specific cause of an `audit_output_failure` (`plat.reason`; schema 6).
/// Absent for an ordinary write failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFailureReason {
    /// A failed batch could not be cut back to the last durable checkpoint
    /// (`set_len`/sync failed): the file may end in records outside the
    /// chain (`verify-log` reports them as an unverified tail).
    TruncateFailed,
    /// The sequence high-water mark `.<name>.seq` could not be written
    /// (once per failure streak; retried every flush interval, SEC-303).
    SeqLeaseFailed,
    /// The 64-bit sequence space is used up: the logger stops writing and
    /// stays degraded (fail closed, SEC-302). Last numbered record.
    SeqExhausted,
}

impl OutputFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TruncateFailed => "truncate_failed",
            Self::SeqLeaseFailed => "seq_lease_failed",
            Self::SeqExhausted => "seq_exhausted",
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
    /// Read-only cluster view (schema 7).
    Cluster,
    Other,
}

impl MgmtPath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Metrics => "/metrics",
            Self::Healthz => "/healthz",
            Self::Cluster => "/cluster",
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
    /// Chain of a cluster peer that connected to this node (schema 7).
    PeerClient,
    /// Chain of a cluster peer this node connected to (schema 7).
    PeerServer,
}

impl TlsRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MgmtClient => "mgmt_client",
            Self::SyslogServer => "syslog_server",
            Self::PeerClient => "cluster_peer_client",
            Self::PeerServer => "cluster_peer_server",
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

/// An IPv4 pool slice (`cluster.slice`), formatted as a CIDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceCidr {
    pub net: u32,
    pub len: u8,
}

/// `cluster.reason` of a `cluster_view_change` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewReason {
    /// First view after start-up or after an election.
    Election,
    MemberJoined,
    MemberLost,
    /// The leader's lease ran out and a new leader was elected.
    LeaderLost,
    /// Operator action (manual takeover command).
    Manual,
}

impl ViewReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Election => "election",
            Self::MemberJoined => "member_joined",
            Self::MemberLost => "member_lost",
            Self::LeaderLost => "leader_lost",
            Self::Manual => "manual",
        }
    }
}

/// A new cluster view took effect (majority-acked).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-2, AU-3, CP-10
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterView {
    pub epoch: u64,
    pub leader: u16,
    /// Live member ids, at most [`ClusterView::MEMBERS_MAX`] recorded.
    pub members_live: Vec<u16>,
    pub reason: ViewReason,
}

impl ClusterView {
    /// Matches the config limit on `[[cluster.members]]` (SC-5).
    pub const MEMBERS_MAX: usize = 64;
}

/// `cluster.peer.state` of a `cluster_member_state` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberState {
    Up,
    Down,
    Syncing,
    InSync,
}

impl MemberState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Syncing => "syncing",
            Self::InSync => "in_sync",
        }
    }
}

/// A peer's connection or replication state changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMemberChange {
    pub peer_id: u16,
    /// Configured member name and identity (operator text, sanitized anyway).
    pub name: AuditText,
    pub identity: AuditText,
    pub ip: IpAddr,
    pub state: MemberState,
    pub epoch: u64,
}

/// `cluster.reason` of a `cluster_slice_acquire` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireReason {
    Startup,
    Takeover,
    Handover,
    Failback,
    /// Operator takeover command (two-node clusters without a witness).
    Manual,
}

impl AcquireReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Takeover => "takeover",
            Self::Handover => "handover",
            Self::Failback => "failback",
            Self::Manual => "manual",
        }
    }
}

/// This node became owner of a slice. Written, with every
/// `nat_port_block_adopt` for it, before the slice is used (AU-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceAcquire {
    pub slice: SliceCidr,
    pub epoch: u64,
    /// Previous owner, if any.
    pub prev_owner: Option<u16>,
    pub reason: AcquireReason,
    pub blocks_adopted: u32,
    pub bibs_adopted: u64,
    pub blocks_quarantined: u32,
    /// The replicated state was complete (in-sync backup).
    pub in_sync: bool,
}

/// `cluster.reason` of a `cluster_slice_release` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceReleaseReason {
    Handover,
    /// Fenced by a view this node is not part of.
    Fenced,
    Shutdown,
    /// This node's lease expired (self-fence).
    LeaseLost,
}

impl SliceReleaseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Handover => "handover",
            Self::Fenced => "fenced",
            Self::Shutdown => "shutdown",
            Self::LeaseLost => "lease_lost",
        }
    }
}

/// `plat.release_reason` of a `nat_port_block_release` (schema 7). Absent
/// for ordinary releases (idle, subscriber removed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReleaseReason {
    /// Given to the new slice owner by a graceful handover.
    Handover,
}

impl BlockReleaseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Handover => "handover",
        }
    }
}

/// A port block taken over from a previous slice owner (RFC 7422 §2
/// continuity). Same fields as `nat_port_block_allocate` plus the original
/// allocation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockAdopt {
    pub sub: u128,
    pub sub_len: u8,
    pub v4: u32,
    pub port_lo: u16,
    pub port_hi: u16,
    /// Original allocation time on the previous owner, UTC µs.
    pub allocated_us: u64,
    pub prev_owner: Option<u16>,
    pub epoch: u64,
}

/// `cluster.reason` of a `cluster_peer_rejected` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRejectReason {
    /// Source IP or certificate identity is not a configured member/witness.
    NotAllowed,
    /// Certificate identity does not belong to the claimed node id.
    IdMismatch,
    /// The id is already connected from another address or certificate.
    DuplicateId,
    DigestMismatch,
    Version,
    /// Owned pool overlaps this node's (legacy partition).
    Overlap,
    /// TLS handshake failed or timed out.
    Handshake,
    /// Malformed or out-of-sequence frame on an established connection.
    Protocol,
    /// Replication input outside the slice, pool or client prefixes, or
    /// from a member that does not own the slice.
    InvalidInput,
    /// A connection or handshake limit was reached (SC-5).
    Capacity,
}

impl PeerRejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAllowed => "not_allowed",
            Self::IdMismatch => "id_mismatch",
            Self::DuplicateId => "duplicate_id",
            Self::DigestMismatch => "digest_mismatch",
            Self::Version => "version",
            Self::Overlap => "overlap",
            Self::Handshake => "handshake",
            Self::Protocol => "protocol",
            Self::InvalidInput => "invalid_input",
            Self::Capacity => "capacity",
        }
    }
}

/// A peer connection was refused (IA-3, AC-3). Rate-limited by the emitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRejected {
    pub ip: IpAddr,
    pub port: u16,
    /// Typed certificate identity presented, if any (peer text, sanitized).
    pub identity: Option<AuditText>,
    /// Node id claimed in the Hello, if one was received.
    pub claimed_id: Option<u16>,
    pub reason: PeerRejectReason,
}

/// `cluster.hook` of a `cluster_hook` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    Announce,
    Withdraw,
}

impl HookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announce => "announce",
            Self::Withdraw => "withdraw",
        }
    }
}

/// One route hook run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRun {
    pub hook: HookKind,
    pub slice: SliceCidr,
    pub epoch: u64,
    /// Exit code; `None` if killed (timeout) or not started.
    pub exit_code: Option<i32>,
    pub duration_us: u64,
    pub success: bool,
}

/// `cluster.command` of a `cluster_operator_command` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorCommandKind {
    Status,
    Takeover,
    Restore,
    /// A line that did not parse.
    Invalid,
}

impl OperatorCommandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Takeover => "takeover",
            Self::Restore => "restore",
            Self::Invalid => "invalid",
        }
    }
}

/// `cluster.reason` of a refused `cluster_operator_command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorRefusal {
    /// The peer uid is neither root nor the daemon user (AC-3).
    NotAuthorized,
    /// Peer credentials could not be read.
    NoCredentials,
    /// The command is only valid with `auto_failover = false`.
    AutoFailover,
    /// `takeover` of a member whose peer link is up, without `--force`.
    MemberUp,
    UnknownMember,
    /// The line did not parse.
    Invalid,
    /// Membership refused it (or the control thread did not answer).
    Rejected,
}

impl OperatorRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAuthorized => "not_authorized",
            Self::NoCredentials => "no_credentials",
            Self::AutoFailover => "auto_failover",
            Self::MemberUp => "member_up",
            Self::UnknownMember => "unknown_member",
            Self::Invalid => "invalid",
            Self::Rejected => "rejected",
        }
    }
}

/// An operator command on the cluster socket (`platd cluster ...`), logged
/// before the command acts, and for every refusal (AC-3, AU-2, AU-12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorCommand {
    pub command: OperatorCommandKind,
    pub member: Option<u16>,
    pub force: bool,
    /// Peer process credentials (`SO_PEERCRED` / `getpeereid`).
    pub peer_uid: Option<u32>,
    pub peer_pid: Option<i32>,
    /// `None`: accepted (about to act).
    pub refused: Option<OperatorRefusal>,
}

/// Cluster fields of `service_start` (schema 7; CM-2, CM-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterStart {
    pub node_id: u16,
    /// `contiguous` | `slices` | `ha`.
    pub mode: &'static str,
    /// SHA-256 over the cluster-relevant configuration.
    pub config_digest: [u8; 32],
    /// Owned CIDRs at start (empty for HA: acquire records follow). At most
    /// [`ClusterStart::SLICES_MAX`] are written; `cluster.slice_count`
    /// always carries the full count.
    pub slices: Vec<SliceCidr>,
    pub member_count: u16,
}

impl ClusterStart {
    /// Cap on CIDRs written per record (a contiguous share or an
    /// `owned_pool` is covered by few CIDRs; SC-5).
    pub const SLICES_MAX: usize = 256;
}

/// One audit record. Times are UTC microseconds since the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A port block was assigned to a subscriber (RFC 7422 bulk allocation).
    PortBlockAlloc { ts_us: u64, sub: u128, sub_len: u8, v4: u32, port_lo: u16, port_hi: u16 },
    /// A port block was returned to the pool. `reason` is set for a
    /// handover to another node (schema 7).
    PortBlockRelease {
        ts_us: u64,
        sub: u128,
        sub_len: u8,
        v4: u32,
        port_lo: u16,
        port_hi: u16,
        held_secs: u32,
        reason: Option<BlockReleaseReason>,
    },
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
        /// Cluster identity, digest and slices; set on `Start` (schema 7).
        cluster: Option<Arc<ClusterStart>>,
    },
    /// Counter snapshot (drops etc.), emitted by the logger itself.
    Counter { ts_us: u64, name: &'static str, value: u64 },
    /// Records lost because the queue was full (AU-5 alert).
    QueueOverflow { ts_us: u64, lost: u64 },
    /// The local audit file (the authoritative AU-9 copy) could not be
    /// written (`recovered == false`, sent to the remaining destinations)
    /// or is being written again (`recovered == true`, first record of the
    /// new file). `lost` records were not written to the file. Emitted by
    /// the logger itself (AU-5). `reason` names a specific cause
    /// (`plat.reason`; schema 6), e.g. a failed cut-back of the file.
    OutputFailure { ts_us: u64, lost: u64, recovered: bool, reason: Option<OutputFailureReason> },
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
    /// Start-up found the newest audit file empty, without a header, or
    /// ending in a partial line (crash or power cut). `last_checkpoint_seq`
    /// is the last durable checkpoint found on disk and `max_seq` the
    /// highest sequence that may have been used (the highest seen, or the
    /// durable high-water mark `.<name>.seq` if higher); numbering resumes
    /// at `max_seq + 1`, so records `last_checkpoint_seq + 1..=max_seq` may
    /// be lost and no number is reused. `lease_state` says whether the
    /// high-water mark was used. First record of the new file (AU-5, AU-9).
    AuditRecovery {
        ts_us: u64,
        reason: RecoveryReason,
        last_checkpoint_seq: u64,
        max_seq: u64,
        lease_state: LeaseState,
    },
    /// A management connection was accepted or rejected (AC-17, AU-2).
    ManagementConnection { ts_us: u64, conn: Arc<MgmtConnection> },
    /// Rejected-connection records suppressed by the rate limit over the
    /// last `window_secs` (summary; SC-5, AU-5).
    ManagementSuppressed { ts_us: u64, suppressed: u64, window_secs: u32 },
    /// Revocation status of one certificate in a chain (IA-5(2)).
    RevocationCheck { ts_us: u64, check: Arc<RevocationCheck> },
    /// Background refresher state change for a revocation source.
    RevocationRefresh { ts_us: u64, refresh: Arc<RevocationRefresh> },
    /// A new cluster view took effect (schema 7).
    ClusterViewChange { ts_us: u64, view: Arc<ClusterView> },
    /// A peer changed connection or replication state (schema 7).
    ClusterMemberState { ts_us: u64, member: Arc<ClusterMemberChange> },
    /// This node acquired a slice (schema 7).
    ClusterSliceAcquire { ts_us: u64, acquire: Arc<SliceAcquire> },
    /// This node gave up a slice (schema 7).
    ClusterSliceRelease { ts_us: u64, slice: SliceCidr, epoch: u64, new_owner: Option<u16>, reason: SliceReleaseReason },
    /// A port block adopted from the previous slice owner (schema 7).
    PortBlockAdopt { ts_us: u64, adopt: Arc<BlockAdopt> },
    /// A peer connection was refused (schema 7).
    ClusterPeerRejected { ts_us: u64, rejected: Arc<PeerRejected> },
    /// Peer-rejected records suppressed over `window_secs` (schema 7).
    ClusterPeerSuppressed { ts_us: u64, suppressed: u64, window_secs: u32 },
    /// Replication records for a slice were lost; the slice resyncs
    /// (rate-limited, one per slice per 10 s; schema 7).
    ClusterReplicationGap { ts_us: u64, slice: SliceCidr, lost: u64 },
    /// A route hook ran (schema 7).
    ClusterHook { ts_us: u64, run: Arc<HookRun> },
    /// An operator command was accepted (before it acts) or refused
    /// (schema 7).
    ClusterOperatorCommand { ts_us: u64, cmd: Arc<OperatorCommand> },
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
            | Event::AuditRecovery { ts_us, .. }
            | Event::ManagementConnection { ts_us, .. }
            | Event::ManagementSuppressed { ts_us, .. }
            | Event::RevocationCheck { ts_us, .. }
            | Event::RevocationRefresh { ts_us, .. }
            | Event::ClusterViewChange { ts_us, .. }
            | Event::ClusterMemberState { ts_us, .. }
            | Event::ClusterSliceAcquire { ts_us, .. }
            | Event::ClusterSliceRelease { ts_us, .. }
            | Event::PortBlockAdopt { ts_us, .. }
            | Event::ClusterPeerRejected { ts_us, .. }
            | Event::ClusterPeerSuppressed { ts_us, .. }
            | Event::ClusterReplicationGap { ts_us, .. }
            | Event::ClusterHook { ts_us, .. }
            | Event::ClusterOperatorCommand { ts_us, .. } => ts_us,
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
            Event::AuditRecovery { .. } => "audit_recovery",
            Event::ManagementConnection { .. } => "management_connection",
            Event::ManagementSuppressed { .. } => "management_connection_suppressed",
            Event::RevocationCheck { .. } => "tls_revocation_check",
            Event::RevocationRefresh { .. } => "revocation_source_refresh",
            Event::ClusterViewChange { .. } => "cluster_view_change",
            Event::ClusterMemberState { .. } => "cluster_member_state",
            Event::ClusterSliceAcquire { .. } => "cluster_slice_acquire",
            Event::ClusterSliceRelease { .. } => "cluster_slice_release",
            Event::PortBlockAdopt { .. } => "nat_port_block_adopt",
            Event::ClusterPeerRejected { .. } => "cluster_peer_rejected",
            Event::ClusterPeerSuppressed { .. } => "cluster_peer_suppressed",
            Event::ClusterReplicationGap { .. } => "cluster_replication_gap",
            Event::ClusterHook { .. } => "cluster_hook",
            Event::ClusterOperatorCommand { .. } => "cluster_operator_command",
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
            Event::ClusterMemberState { member, .. } if member.state == MemberState::Down => 4,
            Event::ClusterSliceAcquire { acquire, .. } if !acquire.in_sync => 4,
            Event::ClusterSliceRelease {
                reason: SliceReleaseReason::Fenced | SliceReleaseReason::LeaseLost, ..
            } => 4,
            Event::ClusterHook { run, .. } if !run.success => 4,
            // Every accepted command changes ownership or reads state; a
            // takeover/restore is a warning-level operator action.
            Event::ClusterOperatorCommand { cmd, .. }
                if cmd.refused.is_some() || cmd.command != OperatorCommandKind::Status =>
            {
                4
            }
            Event::ClusterOperatorCommand { .. } => 5,
            Event::ClusterPeerRejected { .. }
            | Event::ClusterPeerSuppressed { .. }
            | Event::ClusterReplicationGap { .. } => 4,
            Event::ManagementSuppressed { .. }
            | Event::Limit { .. }
            | Event::QueueOverflow { .. }
            | Event::OutputFailure { .. }
            | Event::RemoteLoss { .. }
            | Event::AuditRecovery { .. }
            | Event::StorageThreshold { state: StorageState::Below | StorageState::Unknown, .. }
            | Event::RetentionPrune { state: PruneState::Failed, .. } => 4,
            Event::Lifecycle { .. }
            | Event::StorageThreshold { .. }
            | Event::RetentionPrune { .. }
            | Event::ManagementConnection { .. }
            | Event::RevocationRefresh { .. }
            | Event::ClusterViewChange { .. }
            | Event::ClusterMemberState { .. }
            | Event::ClusterSliceAcquire { .. }
            | Event::ClusterSliceRelease { .. }
            | Event::ClusterHook { .. } => 5,
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
            | Event::AuditRecovery { .. }
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
            Event::ClusterViewChange { .. }
            | Event::ClusterMemberState { .. }
            | Event::ClusterSliceRelease { .. }
            | Event::PortBlockAdopt { .. } => Some("success"),
            // A takeover without complete state still succeeded, but
            // attribution continuity is not guaranteed for it.
            Event::ClusterSliceAcquire { acquire, .. } => Some(if acquire.in_sync { "success" } else { "unknown" }),
            Event::ClusterHook { run, .. } => Some(if run.success { "success" } else { "failure" }),
            Event::ClusterOperatorCommand { cmd, .. } => {
                Some(if cmd.refused.is_none() { "success" } else { "failure" })
            }
            Event::ClusterPeerRejected { .. }
            | Event::ClusterPeerSuppressed { .. }
            | Event::ClusterReplicationGap { .. } => Some("failure"),
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
