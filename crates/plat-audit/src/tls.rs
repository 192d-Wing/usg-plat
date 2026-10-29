//! TLS syslog options and the mapping of `plat-tls` revocation records to
//! audit events (one place for both the management and syslog roles).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-2, AU-3, AU-12 - every certificate checked for
//!   revocation becomes one `tls_revocation_check` record; refresher state
//!   changes become `revocation_source_refresh` records
//! - NIST 800-53: IA-5(2)(b)(1), SC-8, AU-9(2)

use std::sync::Arc;

use plat_common::Clock;
use plat_common::config::{RevocationConfig, SyslogTlsConfig};
use plat_tls::revocation::{RecordStatus, RefreshKind as TRefreshKind, RefreshTransition as TTransition, Role, Source};
use plat_tls::{RefreshRecord, RevocationChecker, RevocationHook, RevocationRecord, RevocationSettings};

use crate::event::{
    AuditText, Event, RefreshKind, RefreshTransition, RevocationCheck, RevocationRefresh, RevocationSource,
    RevocationStatus, TlsRole,
};

/// What `Logger::spawn` needs to build TLS syslog destinations.
pub struct TlsOptions {
    /// `tls.pq_hybrid`.
    pub pq_hybrid: bool,
    /// `[tls.revocation]`, used when there is no shared checker.
    pub revocation: RevocationConfig,
    /// The process-wide checker (platd; has the background refresher).
    /// Destinations without a `revocation` override use it.
    pub shared: Option<Arc<RevocationChecker>>,
    /// Receives the records of private checkers (destinations with a
    /// `revocation` override, or every destination when `shared` is
    /// `None`). Must not block.
    pub hook: RevocationHook,
}

impl std::fmt::Debug for TlsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsOptions")
            .field("pq_hybrid", &self.pq_hybrid)
            .field("shared", &self.shared.is_some())
            .finish_non_exhaustive()
    }
}

impl TlsOptions {
    /// The checker for one destination. An override gets its own checker,
    /// caches and no refresher (fetch on demand only).
    pub(crate) fn checker_for(&self, t: &SyslogTlsConfig) -> Result<Arc<RevocationChecker>, plat_tls::TlsError> {
        match (&t.revocation, &self.shared) {
            (None, Some(shared)) => Ok(shared.clone()),
            (Some(r), _) => RevocationChecker::new(RevocationSettings::from(r), self.hook.clone()),
            (None, None) => RevocationChecker::new(RevocationSettings::from(&self.revocation), self.hook.clone()),
        }
    }
}

/// The `tls_revocation_check` record for one checked certificate. Peer
/// text (serial, issuer DN, sources) is sanitized and capped.
pub fn revocation_event(r: &RevocationRecord) -> Event {
    let short = |s: &Option<String>| s.as_deref().map(|s| AuditText::new(s, AuditText::SHORT_MAX));
    Event::RevocationCheck {
        ts_us: Clock::wall_us(),
        check: Arc::new(RevocationCheck {
            role: match r.role {
                Role::MgmtClient => TlsRole::MgmtClient,
                Role::SyslogServer => TlsRole::SyslogServer,
            },
            cert_sha256: r.cert_sha256,
            serial_hex: AuditText::new(&r.serial_hex, AuditText::SHORT_MAX),
            issuer_dn: AuditText::new(&r.issuer_dn, AuditText::DN_MAX),
            chain_index: r.chain_index,
            status: match r.status {
                RecordStatus::Good => RevocationStatus::Good,
                RecordStatus::Revoked => RevocationStatus::Revoked,
                RecordStatus::Unavailable => RevocationStatus::Unavailable,
                RecordStatus::Fatal => RevocationStatus::Fatal,
                RecordStatus::NotChecked => RevocationStatus::NotChecked,
            },
            source: match r.source {
                Source::OcspStapled => RevocationSource::OcspStapled,
                Source::OcspCache => RevocationSource::OcspCache,
                Source::OcspFetch => RevocationSource::OcspFetch,
                Source::CrlCache => RevocationSource::CrlCache,
                Source::CrlFetch => RevocationSource::CrlFetch,
                Source::CrlFile => RevocationSource::CrlFile,
                Source::None => RevocationSource::None,
            },
            ocsp_reason: r.ocsp_reason.map(|x| x.as_str()),
            crl_reason: r.crl_reason.map(|x| x.as_str()),
            revocation_reason: r.revocation_reason.map(|x| x.as_str()),
            revocation_date_us: r.revocation_date_us,
            ocsp_responder: short(&r.ocsp_responder),
            crl_source: short(&r.crl_source),
            policy: r.policy.as_str(),
            allowed: r.allowed,
        }),
    }
}

/// The `revocation_source_refresh` record for one refresher transition.
pub fn refresh_event(r: &RefreshRecord) -> Event {
    Event::RevocationRefresh {
        ts_us: Clock::wall_us(),
        refresh: Arc::new(RevocationRefresh {
            kind: match r.kind {
                TRefreshKind::Crl => RefreshKind::Crl,
                TRefreshKind::Ocsp => RefreshKind::Ocsp,
            },
            source: AuditText::new(&r.source, AuditText::SHORT_MAX),
            transition: match r.transition {
                TTransition::Failing => RefreshTransition::Failing,
                TTransition::Recovered => RefreshTransition::Recovered,
                TTransition::StaleDropped => RefreshTransition::StaleDropped,
                TTransition::RollbackRejected => RefreshTransition::RollbackRejected,
                TTransition::StateRejected => RefreshTransition::StateRejected,
                TTransition::StatePersistFailed => RefreshTransition::StatePersistFailed,
            },
            reason: r.reason,
        }),
    }
}
