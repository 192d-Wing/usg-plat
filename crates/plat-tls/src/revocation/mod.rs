//! Certificate revocation checking for every non-root certificate of a
//! validated chain (management client chains, syslog collector chains).
//!
//! Decision per certificate, first conclusive result wins:
//! 1. OCSP (stapled for the syslog leaf, then cache, then fetch). A fresh,
//!    valid `good` or `revoked` decides; `revoked` is final.
//! 2. CRL (cache, then fetch), when OCSP is unavailable, stale or `unknown`.
//! 3. Neither conclusive: `hard_fail` rejects; `soft_fail` accepts only if
//!    no data could be obtained at all (stale data always rejects, QN2).
//!
//! Attack-class failures (bad OCSP/CRL signature, unauthorized responder,
//! nonce or CertID mismatch, CRL from the wrong issuer) reject in every mode
//! with no fallback, whatever a source reports.
//!
//! The OCSP ([`ocsp::OcspClient`]) and CRL ([`crl::CrlClient`])
//! implementations plug in through [`OcspSource`] and [`CrlSource`];
//! [`RevocationChecker::new`] installs both. Tests may substitute scripted
//! sources with [`RevocationChecker::with_sources`].
//!
//! Locking: the checker itself holds no lock across a lookup; sources own
//! their caches (leaf `parking_lot` mutexes, never held across I/O, parsing,
//! signature verification or the hook call). The only lock here is the
//! refresher wake flag.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5(2)(b)(1) (PKI-Based Authentication - certification
//!   path validation including status information); IA-5(2)(b)(2) - local
//!   cache of revocation data (OCSP/CRL caches, `cache_dir`)
//! - NIST 800-53: AU-2, AU-12 - one [`RevocationRecord`] per checked
//!   certificate, delivered to the caller's [`RevocationHook`]
//! - NIST 800-53: SC-5 - shared per-chain time budget
//! - RFC 6960 (OCSP), RFC 5280 §5, §6.3 (CRL)
// POAM: POAM-025 (narrowed) - the OCSP responder certificate's own
// revocation is not checked (id-pkix-ocsp-nocheck assumed); indirect CRLs,
// delta CRLs and LDAP/non-HTTP distribution points are not supported;
// `ToSocketAddrs` resolution has no timeout.

pub mod chain;
pub mod crl;
mod flight;
pub mod http;
pub mod ocsp;
pub mod refresher;
pub mod sig;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use plat_common::config::{CrlConfig, OcspConfig, RevocationConfig, RevocationMode};
use rustls_pki_types::{CertificateDer, UnixTime};

pub use chain::{Anchors, Cert, ChainError, ChainLink};
pub use refresher::spawn_refresher;

use crate::TlsError;

/// Which TLS role the checked chain belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    MgmtClient,
    SyslogServer,
}

/// Where a status came from (`plat.revocation.source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    OcspStapled,
    OcspCache,
    OcspFetch,
    CrlCache,
    CrlFetch,
    CrlFile,
    None,
}

/// OCSP failure reasons (`plat.ocsp.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspReason {
    Timeout,
    Connect,
    HttpStatus,
    ContentType,
    TooLarge,
    Malformed,
    BadSignature,
    UnauthorizedResponder,
    Stale,
    NonceMismatch,
    NoResponder,
    CertIdMismatch,
    UnknownStatus,
    Budget,
}

impl OcspReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::HttpStatus => "http_status",
            Self::ContentType => "content_type",
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::UnauthorizedResponder => "unauthorized_responder",
            Self::Stale => "stale",
            Self::NonceMismatch => "nonce_mismatch",
            Self::NoResponder => "no_responder",
            Self::CertIdMismatch => "cert_id_mismatch",
            Self::UnknownStatus => "unknown_status",
            Self::Budget => "budget",
        }
    }

    /// Indicates forgery or tampering: reject in every mode, no fallback.
    pub fn is_fatal(self) -> bool {
        matches!(self, Self::BadSignature | Self::UnauthorizedResponder | Self::NonceMismatch | Self::CertIdMismatch)
    }
}

/// CRL failure reasons (`plat.crl.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlReason {
    Timeout,
    Connect,
    HttpStatus,
    TooLarge,
    Malformed,
    BadSignature,
    WrongIssuer,
    NoCrlSign,
    Stale,
    /// thisUpdate in the future (beyond the clock skew).
    NotYetValid,
    NoNextUpdate,
    Indirect,
    Delta,
    ScopeMismatch,
    CriticalExt,
    Rollback,
    NoSource,
    Budget,
}

impl CrlReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::HttpStatus => "http_status",
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::WrongIssuer => "wrong_issuer",
            Self::NoCrlSign => "no_crl_sign",
            Self::Stale => "stale",
            Self::NotYetValid => "not_yet_valid",
            Self::NoNextUpdate => "no_next_update",
            Self::Indirect => "indirect",
            Self::Delta => "delta",
            Self::ScopeMismatch => "scope_mismatch",
            Self::CriticalExt => "critical_ext",
            Self::Rollback => "rollback",
            Self::NoSource => "no_source",
            Self::Budget => "budget",
        }
    }

    /// Indicates forgery or tampering: reject in every mode, no fallback.
    pub fn is_fatal(self) -> bool {
        matches!(self, Self::BadSignature | Self::WrongIssuer)
    }
}

/// A failure of one source for one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    Ocsp(OcspReason),
    Crl(CrlReason),
}

impl SourceError {
    pub fn is_fatal(self) -> bool {
        match self {
            Self::Ocsp(r) => r.is_fatal(),
            Self::Crl(r) => r.is_fatal(),
        }
    }

    /// Data existed but was past `nextUpdate` (QN2: never soft-accepted).
    pub fn is_stale(self) -> bool {
        matches!(self, Self::Ocsp(OcspReason::Stale) | Self::Crl(CrlReason::Stale | CrlReason::NotYetValid))
    }
}

/// RFC 5280 §5.3.1 CRLReason (also used by OCSP `revoked`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl RevocationReason {
    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => Self::Unspecified,
            1 => Self::KeyCompromise,
            2 => Self::CaCompromise,
            3 => Self::AffiliationChanged,
            4 => Self::Superseded,
            5 => Self::CessationOfOperation,
            6 => Self::CertificateHold,
            8 => Self::RemoveFromCrl,
            9 => Self::PrivilegeWithdrawn,
            10 => Self::AaCompromise,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "key_compromise",
            Self::CaCompromise => "ca_compromise",
            Self::AffiliationChanged => "affiliation_changed",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessation_of_operation",
            Self::CertificateHold => "certificate_hold",
            Self::RemoveFromCrl => "remove_from_crl",
            Self::PrivilegeWithdrawn => "privilege_withdrawn",
            Self::AaCompromise => "aa_compromise",
        }
    }
}

/// Final status of one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertStatus {
    Good,
    Revoked { reason: RevocationReason, at_us: u64 },
    Unavailable(Vec<SourceError>),
    Fatal(SourceError),
}

/// What one source concluded for one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    Good(Source),
    Revoked {
        source: Source,
        reason: RevocationReason,
        at_us: u64,
    },
    /// No conclusive answer (no responder/source, transport error, stale,
    /// OCSP `unknown`), or an attack-class failure (`SourceError::is_fatal`).
    Failed(SourceError),
}

/// A source's answer plus where it came from, for the audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub outcome: LookupOutcome,
    /// OCSP responder or CRL source as `host:port` or file basename.
    pub origin: Option<String>,
}

impl Lookup {
    pub fn failed(e: SourceError) -> Self {
        Self { outcome: LookupOutcome::Failed(e), origin: None }
    }
}

/// Everything a source needs to check one certificate.
#[derive(Debug)]
pub struct CertCtx<'a> {
    pub role: Role,
    /// 0 = leaf.
    pub index: u8,
    pub cert: &'a Cert,
    pub issuer: &'a Cert,
    /// Stapled OCSP response (syslog leaf only).
    pub stapled: Option<&'a [u8]>,
    /// End of the per-chain budget; sources must not block past it.
    pub deadline: Instant,
    pub now: UnixTime,
    pub settings: &'a RevocationSettings,
}

/// OCSP implementation seam (WU-1b).
pub trait OcspSource: Send + Sync + fmt::Debug {
    fn lookup(&self, ctx: &CertCtx<'_>) -> Lookup;

    /// Cached responses (`plat_ocsp_cache_entries`).
    fn cache_entries(&self) -> usize {
        0
    }

    /// Background refresh of watched items; called by the refresher at
    /// least every 500 ms. Must only do work that is due. Returns how long
    /// until it next has work, if it knows.
    fn refresh(&self, _now: UnixTime) -> Option<Duration> {
        None
    }
}

/// CRL implementation seam (WU-1c).
pub trait CrlSource: Send + Sync + fmt::Debug {
    fn lookup(&self, ctx: &CertCtx<'_>) -> Lookup;

    /// Verified CRLs and their estimated memory (`plat_crl_cache_entries`,
    /// `plat_crl_cache_bytes`).
    fn cache_usage(&self) -> (usize, usize) {
        (0, 0)
    }

    /// cRLNumber state problems so far (`plat_crl_state_errors_total`).
    fn state_errors(&self) -> u64 {
        0
    }

    /// See [`OcspSource::refresh`].
    fn refresh(&self, _now: UnixTime) -> Option<Duration> {
        None
    }
}

/// A source that never produces data (tests; OCSP disabled).
#[derive(Debug, Default)]
pub struct NoOcsp;

impl OcspSource for NoOcsp {
    fn lookup(&self, _ctx: &CertCtx<'_>) -> Lookup {
        Lookup::failed(SourceError::Ocsp(OcspReason::NoResponder))
    }
}

/// A source that never produces data (tests; CRL disabled).
#[derive(Debug, Default)]
pub struct NoCrl;

impl CrlSource for NoCrl {
    fn lookup(&self, _ctx: &CertCtx<'_>) -> Lookup {
        Lookup::failed(SourceError::Crl(CrlReason::NoSource))
    }
}

/// Revocation policy, from `[tls.revocation]` (or a syslog override).
#[derive(Debug, Clone)]
pub struct RevocationSettings {
    pub mode: RevocationMode,
    pub skew: Duration,
    pub budget: Duration,
    pub cache_dir: Option<PathBuf>,
    pub ocsp: OcspConfig,
    pub crl: CrlConfig,
}

impl From<&RevocationConfig> for RevocationSettings {
    fn from(c: &RevocationConfig) -> Self {
        Self {
            mode: c.mode,
            skew: Duration::from_secs(u64::from(c.clock_skew_secs)),
            budget: Duration::from_millis(c.budget_ms),
            cache_dir: c.cache_dir.clone(),
            ocsp: c.ocsp.clone(),
            crl: c.crl.clone(),
        }
    }
}

/// `plat.revocation.status` of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordStatus {
    Good,
    Revoked,
    Unavailable,
    Fatal,
    NotChecked,
}

/// One checked certificate, for the audit hook (callers map it to
/// `plat_audit::Event::RevocationCheck`; this crate never depends on
/// plat-audit). Text fields are untrusted and uncapped here; the audit
/// layer sanitizes and caps them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    pub role: Role,
    pub chain_index: u8,
    pub cert_sha256: [u8; 32],
    pub serial_hex: String,
    pub issuer_dn: String,
    pub status: RecordStatus,
    pub source: Source,
    pub ocsp_reason: Option<OcspReason>,
    pub crl_reason: Option<CrlReason>,
    pub revocation_reason: Option<RevocationReason>,
    pub revocation_date_us: Option<u64>,
    pub ocsp_responder: Option<String>,
    pub crl_source: Option<String>,
    pub policy: RevocationMode,
    /// This certificate did not cause the chain to be rejected.
    pub allowed: bool,
}

/// Receives every [`RevocationRecord`]. Called on the handshake thread,
/// with no lock held; must not block (use `AuditSink::emit`).
pub type RevocationHook = Arc<dyn Fn(&RevocationRecord) + Send + Sync>;

/// Result for a whole chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainOutcome {
    /// Every non-root certificate good, or accepted under soft_fail.
    Accepted,
    /// `mode = "off"`.
    NotChecked,
    Revoked,
    /// No conclusive status (hard_fail, or stale under soft_fail).
    Unavailable,
    /// Attack-class failure.
    Fatal,
    /// The validated path could not be rebuilt.
    PathError,
}

impl ChainOutcome {
    pub fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted | Self::NotChecked)
    }
}

#[derive(Debug, Clone)]
pub struct ChainVerdict {
    pub outcome: ChainOutcome,
    /// One per non-root certificate (or one `not_checked` / path-error
    /// record for the leaf).
    pub records: Vec<RevocationRecord>,
}

/// Kind of background source in a [`RefreshRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshKind {
    Crl,
    Ocsp,
}

/// State change of a refreshed source (`revocation_source_refresh`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTransition {
    /// First failure after success (or after start).
    Failing,
    /// First success after failures.
    Recovered,
    /// The cached copy passed `nextUpdate` and was dropped.
    StaleDropped,
    /// A replacement CRL had a lower `cRLNumber` (rollback) and was refused.
    RollbackRejected,
    /// The persisted cRLNumber state (`cache_dir/crl-numbers`) was rejected
    /// or partly skipped at start (reason `state_*`).
    StateRejected,
    /// Writing the cRLNumber state failed (first failure of a streak).
    StatePersistFailed,
}

/// One refresher state change, for the audit layer (stage 3 maps it to
/// `plat_audit::Event::RevocationRefresh`). Emitted only on transitions,
/// so it cannot flood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    pub kind: RefreshKind,
    /// CRL `host:port` / file basename, or OCSP key `issuer_key_hash:serial`.
    pub source: String,
    pub transition: RefreshTransition,
    /// `CrlReason` / `OcspReason` string for failures.
    pub reason: Option<&'static str>,
}

/// Receives every [`RefreshRecord`]; called with no lock held; must not
/// block.
pub type RefreshHook = Arc<dyn Fn(&RefreshRecord) + Send + Sync>;

/// SHA-256 of the issuer's `subjectPublicKey` bits: keys the OCSP and CRL
/// caches (RFC 6960 issuerKeyHash with SHA-256).
pub fn issuer_key_hash(issuer: &Cert) -> [u8; 32] {
    let bits = issuer.spki().subject_public_key.raw_bytes();
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bits);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Lowercase hex.
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Uniform random value in `[0, n)` from the FIPS DRBG (jitter only).
pub(crate) fn jitter(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut b = [0u8; 8];
    if aws_lc_rs::rand::fill(&mut b).is_err() {
        return n / 2;
    }
    u64::from_le_bytes(b) % n
}

/// Next refresh time for data valid `this..next` (unix seconds):
/// `this + 0.8 × (next − this)`, capped at `next − margin`, ±10 % jitter
/// of the interval, never earlier than `now + 30` (data that is not
/// replaced upstream must not cause a fetch storm).
pub(crate) fn schedule(this: u64, next: u64, margin: u64, now: u64) -> u64 {
    let span = next.saturating_sub(this);
    let mut due = this.saturating_add(span / 5 * 4).min(next.saturating_sub(margin));
    let j = span / 10;
    due = due.saturating_sub(j).saturating_add(jitter(j.saturating_mul(2).saturating_add(1)));
    due.max(now.saturating_add(30))
}

/// Exponential failure back-off: 30 s doubling to 10 min.
pub(crate) fn next_backoff(prev: u64) -> u64 {
    if prev == 0 { 30 } else { prev.saturating_mul(2).min(600) }
}

/// Cache occupancy of one checker, for the metrics endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub ocsp_entries: usize,
    pub crl_entries: usize,
    pub crl_bytes: usize,
    /// cRLNumber state load problems and write failures
    /// (`plat_crl_state_errors_total`).
    pub crl_state_errors: u64,
}

/// Shared revocation checker: one per process (plus one per syslog
/// destination with a `revocation` override).
pub struct RevocationChecker {
    settings: RevocationSettings,
    hook: RevocationHook,
    ocsp: Box<dyn OcspSource>,
    crl: Box<dyn CrlSource>,
    wake: Mutex<bool>,
    cv: Condvar,
}

impl fmt::Debug for RevocationChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationChecker")
            .field("mode", &self.settings.mode)
            .field("ocsp", &self.ocsp)
            .field("crl", &self.crl)
            .finish_non_exhaustive()
    }
}

/// Microseconds since the epoch.
fn unix_us(t: UnixTime) -> u64 {
    t.as_secs().saturating_mul(1_000_000)
}

impl RevocationChecker {
    /// Builds a checker with the OCSP and CRL clients and no refresh
    /// hook. See [`new_with_refresh_hook`](Self::new_with_refresh_hook).
    pub fn new(settings: RevocationSettings, hook: RevocationHook) -> Result<Arc<Self>, TlsError> {
        Self::new_with_refresh_hook(settings, hook, Arc::new(|_: &RefreshRecord| {}))
    }

    /// Builds a checker with the OCSP and CRL clients. Checks `cache_dir`
    /// ownership and mode when set, loads `crl.files` and the on-disk CRL
    /// cache (fails closed on an unreadable configured file).
    pub fn new_with_refresh_hook(
        settings: RevocationSettings,
        hook: RevocationHook,
        refresh: RefreshHook,
    ) -> Result<Arc<Self>, TlsError> {
        if let Some(d) = &settings.cache_dir {
            crate::load::check_cache_dir(d)?;
        }
        let ocsp = ocsp::OcspClient::new(&settings, refresh.clone())?;
        let crl = crl::CrlClient::new(&settings, refresh, UnixTime::now())?;
        Self::with_sources(settings, hook, Box::new(ocsp), Box::new(crl))
    }

    /// Builds a checker with explicit sources (OCSP/CRL modules, tests).
    pub fn with_sources(
        settings: RevocationSettings,
        hook: RevocationHook,
        ocsp: Box<dyn OcspSource>,
        crl: Box<dyn CrlSource>,
    ) -> Result<Arc<Self>, TlsError> {
        if let Some(d) = &settings.cache_dir {
            crate::load::check_cache_dir(d)?;
        }
        Ok(Arc::new(Self { settings, hook, ocsp, crl, wake: Mutex::new(false), cv: Condvar::new() }))
    }

    pub fn settings(&self) -> &RevocationSettings {
        &self.settings
    }

    /// Cache occupancy (each source takes its own leaf lock briefly).
    pub fn cache_stats(&self) -> CacheStats {
        let (crl_entries, crl_bytes) = self.crl.cache_usage();
        CacheStats {
            ocsp_entries: self.ocsp.cache_entries(),
            crl_entries,
            crl_bytes,
            crl_state_errors: self.crl.state_errors(),
        }
    }

    /// Wakes the refresher early (new watch item).
    pub fn notify(&self) {
        *self.wake.lock() = true;
        self.cv.notify_one();
    }

    /// Lets the sources do due background work as of `now`; returns the
    /// wait until the next call (≤ `max`). Called by the refresher thread;
    /// public so tests can drive it with a fake clock.
    pub fn refresh_once(&self, now: UnixTime, max: Duration) -> Duration {
        let mut wait = max;
        if self.settings.mode != RevocationMode::Off {
            if self.settings.ocsp.enabled {
                wait = wait.min(self.ocsp.refresh(now).unwrap_or(max));
            }
            if self.settings.crl.enabled {
                wait = wait.min(self.crl.refresh(now).unwrap_or(max));
            }
        }
        wait
    }

    /// Waits up to `d` or until [`notify`](Self::notify).
    pub(crate) fn wait(&self, d: Duration) {
        let mut g = self.wake.lock();
        if !*g {
            let _ = self.cv.wait_for(&mut g, d);
        }
        *g = false;
    }

    fn record(&self, role: Role, link_cert: &Cert, index: u8) -> RevocationRecord {
        RevocationRecord {
            role,
            chain_index: index,
            cert_sha256: link_cert.sha256(),
            serial_hex: link_cert.serial_hex(),
            issuer_dn: link_cert.issuer_dn(),
            status: RecordStatus::NotChecked,
            source: Source::None,
            ocsp_reason: None,
            crl_reason: None,
            revocation_reason: None,
            revocation_date_us: None,
            ocsp_responder: None,
            crl_source: None,
            policy: self.settings.mode,
            allowed: false,
        }
    }

    /// Checks every non-root certificate of the chain `leaf` →
    /// `intermediates` → `anchors` (already validated by webpki). Calls
    /// the hook once per record and returns the verdict.
    pub fn check_chain(
        &self,
        role: Role,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        anchors: &Anchors,
        stapled: Option<&[u8]>,
        now: UnixTime,
    ) -> ChainVerdict {
        let verdict = self.decide_chain(role, leaf, intermediates, anchors, stapled, now);
        for r in &verdict.records {
            (self.hook)(r);
        }
        verdict
    }

    fn decide_chain(
        &self,
        role: Role,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        anchors: &Anchors,
        stapled: Option<&[u8]>,
        now: UnixTime,
    ) -> ChainVerdict {
        let leaf_only = |status, allowed| {
            Cert::parse(leaf)
                .map(|c| {
                    let mut r = self.record(role, &c, 0);
                    r.status = status;
                    r.allowed = allowed;
                    vec![r]
                })
                .unwrap_or_default()
        };
        if self.settings.mode == RevocationMode::Off {
            return ChainVerdict {
                outcome: ChainOutcome::NotChecked,
                records: leaf_only(RecordStatus::NotChecked, true),
            };
        }
        let path = match chain::rebuild(leaf, intermediates, anchors) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("revocation: path rebuild failed: {e}");
                return ChainVerdict {
                    outcome: ChainOutcome::PathError,
                    records: leaf_only(RecordStatus::Fatal, false),
                };
            }
        };
        let deadline = Instant::now() + self.settings.budget;
        let mut records = Vec::with_capacity(path.len());
        let mut outcome = ChainOutcome::Accepted;
        for link in &path {
            let mut rec = self.record(role, &link.cert, link.index);
            if outcome != ChainOutcome::Accepted {
                // Already rejected: not fetched, recorded as not checked.
                records.push(rec);
                continue;
            }
            let ctx = CertCtx {
                role,
                index: link.index,
                cert: &link.cert,
                issuer: &link.issuer,
                stapled: if link.index == 0 { stapled.filter(|s| !s.is_empty()) } else { None },
                deadline,
                now,
                settings: &self.settings,
            };
            let status = self.decide_cert(&ctx, &mut rec);
            let (st, allowed, chain_out) = match status {
                CertStatus::Good => (RecordStatus::Good, true, ChainOutcome::Accepted),
                CertStatus::Revoked { reason, at_us } => {
                    rec.revocation_reason = Some(reason);
                    rec.revocation_date_us = Some(at_us);
                    (RecordStatus::Revoked, false, ChainOutcome::Revoked)
                }
                CertStatus::Fatal(_) => (RecordStatus::Fatal, false, ChainOutcome::Fatal),
                CertStatus::Unavailable(errs) => {
                    // QN2: soft_fail only when no data at all (nothing stale).
                    let soft = self.settings.mode == RevocationMode::SoftFail && !errs.iter().any(|e| e.is_stale());
                    if soft {
                        rec.source = Source::None;
                        (RecordStatus::Unavailable, true, ChainOutcome::Accepted)
                    } else {
                        (RecordStatus::Unavailable, false, ChainOutcome::Unavailable)
                    }
                }
            };
            rec.status = st;
            rec.allowed = allowed;
            outcome = chain_out;
            records.push(rec);
        }
        ChainVerdict { outcome, records }
    }

    /// OCSP, then CRL, for one certificate. Fills the record's source,
    /// reasons and origins.
    fn decide_cert(&self, ctx: &CertCtx<'_>, rec: &mut RevocationRecord) -> CertStatus {
        let mut errs = Vec::with_capacity(2);
        let budget_left = || Instant::now() < ctx.deadline;
        if self.settings.ocsp.enabled {
            let l = if budget_left() {
                self.ocsp.lookup(ctx)
            } else {
                Lookup::failed(SourceError::Ocsp(OcspReason::Budget))
            };
            rec.ocsp_responder = l.origin;
            match conclude(l.outcome, rec) {
                Ok(s) => return s,
                Err(e) => {
                    if let SourceError::Ocsp(r) = e {
                        rec.ocsp_reason = Some(r);
                    }
                    if e.is_fatal() {
                        return CertStatus::Fatal(e);
                    }
                    errs.push(e);
                }
            }
        }
        if self.settings.crl.enabled {
            let l =
                if budget_left() { self.crl.lookup(ctx) } else { Lookup::failed(SourceError::Crl(CrlReason::Budget)) };
            rec.crl_source = l.origin;
            match conclude(l.outcome, rec) {
                Ok(s) => return s,
                Err(e) => {
                    if let SourceError::Crl(r) = e {
                        rec.crl_reason = Some(r);
                    }
                    if e.is_fatal() {
                        return CertStatus::Fatal(e);
                    }
                    errs.push(e);
                }
            }
        }
        CertStatus::Unavailable(errs)
    }
}

/// A conclusive outcome sets the record source; a failure is returned.
fn conclude(o: LookupOutcome, rec: &mut RevocationRecord) -> Result<CertStatus, SourceError> {
    match o {
        LookupOutcome::Good(src) => {
            rec.source = src;
            Ok(CertStatus::Good)
        }
        LookupOutcome::Revoked { source, reason, at_us } => {
            rec.source = source;
            Ok(CertStatus::Revoked { reason, at_us })
        }
        LookupOutcome::Failed(e) => Err(e),
    }
}

/// Current time in the µs unit of [`LookupOutcome::Revoked`].
pub fn now_us() -> u64 {
    unix_us(UnixTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_classes() {
        for r in [
            OcspReason::BadSignature,
            OcspReason::UnauthorizedResponder,
            OcspReason::NonceMismatch,
            OcspReason::CertIdMismatch,
        ] {
            assert!(SourceError::Ocsp(r).is_fatal());
        }
        for r in [OcspReason::Timeout, OcspReason::Stale, OcspReason::UnknownStatus, OcspReason::NoResponder] {
            assert!(!SourceError::Ocsp(r).is_fatal());
        }
        assert!(SourceError::Crl(CrlReason::WrongIssuer).is_fatal());
        assert!(!SourceError::Crl(CrlReason::Rollback).is_fatal());
        assert!(SourceError::Crl(CrlReason::Stale).is_stale());
        assert!(SourceError::Crl(CrlReason::NotYetValid).is_stale());
    }

    #[test]
    fn reason_codes() {
        assert_eq!(RevocationReason::from_code(1).map(RevocationReason::as_str), Some("key_compromise"));
        assert_eq!(RevocationReason::from_code(7), None);
        assert_eq!(RevocationReason::from_code(11), None);
    }
}
