//! CRL client (RFC 5280 §5, §6.3): the fallback when OCSP gives no
//! decision.
//!
//! Sources per certificate, configured before learned:
//! 1. `crl.files` (DER or PEM; loaded at start, re-read by the refresher),
//! 2. `crl.urls` (`http://`; pre-fetched by the refresher),
//! 3. the certificate's CRL Distribution Points (`crl.use_cdp`): `http://`
//!    fullName URIs only; LDAP/other schemes, `cRLIssuer` and
//!    `nameRelativeToCRLIssuer` are ignored.
//!
//! A CRL decides for a certificate only if it is verified against the
//! certificate's issuer (name and key), fresh, and its IDP scope covers
//! the certificate. Lookups use the cache first (verified entries, then
//! unverified bytes verified on first use), then fetch URL sources in
//! order within the chain budget, single-flight per source.
//!
//! Attack-class results (always fatal): a bad signature, or a CDP of this
//! certificate serving a CRL from another issuer. A configured URL/file
//! for another CA is simply not applicable. A bad signature on a
//! `cache_dir` file is treated as tampering of local data: the file is
//! deleted and the source counts as unavailable (tampering can only
//! delete data).
//!
//! Locks (`state`, `watch`, single-flight) are leaf `parking_lot` mutexes,
//! never held across I/O, parsing, signature verification or a hook call,
//! and never two at once.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5(2)(b)(1) - CRL fallback for every non-root
//!   certificate; IA-5(2)(b)(2) - verified CRL cache and on-disk cache
//! - NIST 800-53: SC-5 - `max_bytes` / `timeout_ms` per fetch,
//!   `max_crls` / `cache_bytes` memory bound, bounded watch list
//! - RFC 5280 §4.2.1.13 (CDP), §5, §6.3

pub mod cache;
pub mod disk;
pub mod parse;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use der::Decode;
use der::asn1::ObjectIdentifier as Oid;
use parking_lot::Mutex;
use plat_common::HttpUrl;
use plat_common::config::CrlConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateRevocationListDer, UnixTime};
use x509_cert::ext::pkix::CrlDistributionPoints;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

use self::cache::{CrlCache, Pending, PendingKind, SrcKey};
use self::disk::DiskCache;
use self::parse::CrlEntry;
use super::flight::{Flight, SingleFlight};
use super::http::{self, HttpError};
use super::{
    Cert, CertCtx, CrlReason, CrlSource, Lookup, LookupOutcome, RefreshHook, RefreshKind, RefreshRecord,
    RefreshTransition, RevocationSettings, Source, SourceError,
};
use crate::TlsError;

const ID_CE_CRL_DISTRIBUTION_POINTS: Oid = Oid::new_unwrap("2.5.29.31");
/// Most CDP URIs taken from one certificate.
const MAX_CDP_URIS: usize = 4;
/// Learned (CDP) watch items unused this long are dropped.
const WATCH_TTL: u64 = 24 * 3600;
/// Re-read interval for configured files whose issuer is still unknown.
const FILE_POLL: u64 = 300;
const CRL_TYPES: &[&str] = &["application/pkix-crl", "application/octet-stream"];

/// One CRL source.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SrcRef {
    Url { url: HttpUrl, text: String, cdp: bool },
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Src {
    key: SrcKey,
    r: SrcRef,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b);
    let mut k = [0u8; 32];
    k.copy_from_slice(d.as_ref());
    k
}

impl Src {
    fn url(url: HttpUrl, text: &str, cdp: bool) -> Self {
        Self { key: sha256(text.as_bytes()), r: SrcRef::Url { url, text: text.to_owned(), cdp } }
    }

    fn file(p: &Path) -> Self {
        Self { key: sha256(p.as_os_str().as_encoded_bytes()), r: SrcRef::File(p.to_path_buf()) }
    }

    /// `host:port` or file basename (audit `plat.crl.source`).
    fn origin(&self) -> String {
        match &self.r {
            SrcRef::Url { url, .. } => url.authority(),
            SrcRef::File(p) => p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        }
    }

    /// The CDP URI this source came from (IDP name matching).
    fn cdp(&self) -> Option<&str> {
        match &self.r {
            SrcRef::Url { text, cdp: true, .. } => Some(text),
            _ => None,
        }
    }

    fn cached_source(&self) -> Source {
        if matches!(self.r, SrcRef::File(_)) { Source::CrlFile } else { Source::CrlCache }
    }
}

/// `http://` fullName URIs of the certificate's CDPs (no cRLIssuer).
fn cdp_sources(cert: &Cert) -> Vec<Src> {
    let Some(v) = cert.extension(ID_CE_CRL_DISTRIBUTION_POINTS) else { return Vec::new() };
    let Ok(dps) = CrlDistributionPoints::from_der(v) else { return Vec::new() };
    let mut out = Vec::new();
    for dp in dps.0.iter().filter(|d| d.crl_issuer.is_none()) {
        let Some(DistributionPointName::FullName(names)) = &dp.distribution_point else { continue };
        for n in names {
            if let GeneralName::UniformResourceIdentifier(u) = n
                && let Ok(url) = HttpUrl::parse(u.as_str())
                && out.len() < MAX_CDP_URIS
            {
                out.push(Src::url(url, u.as_str(), true));
            }
        }
    }
    out
}

/// DER from a file that may hold PEM (`X509 CRL`).
fn file_der(bytes: Vec<u8>) -> Result<Vec<u8>, CrlReason> {
    if bytes.starts_with(b"-----BEGIN") {
        CertificateRevocationListDer::from_pem_slice(&bytes)
            .map(|d| d.as_ref().to_vec())
            .map_err(|_| CrlReason::Malformed)
    } else {
        Ok(bytes)
    }
}

fn map_http(e: HttpError) -> CrlReason {
    match e {
        HttpError::Timeout => CrlReason::Timeout,
        HttpError::Connect => CrlReason::Connect,
        HttpError::Status(_) | HttpError::ContentType => CrlReason::HttpStatus,
        HttpError::TooLarge => CrlReason::TooLarge,
        HttpError::Malformed => CrlReason::Malformed,
    }
}

#[derive(Debug, Clone)]
struct Watch {
    src: Src,
    issuer: Option<Cert>,
    configured: bool,
    last_seen: u64,
    due: u64,
    backoff: u64,
    failing: bool,
    had_data: bool,
}

/// Failure accumulation for one lookup: a stale result dominates (QN2:
/// stale data is never soft-accepted).
#[derive(Default)]
struct Errs {
    /// `Stale` or `NotYetValid` (stale wins).
    stale: Option<CrlReason>,
    last: Option<CrlReason>,
    origin: Option<String>,
}

impl Errs {
    fn note(&mut self, r: CrlReason, s: &Src) {
        if r == CrlReason::Stale || (r == CrlReason::NotYetValid && self.stale.is_none()) {
            self.stale = Some(r);
        }
        self.last = Some(r);
        self.origin = Some(s.origin());
    }

    fn into_lookup(self) -> Lookup {
        let r = self.stale.or(self.last).unwrap_or(CrlReason::NoSource);
        Lookup { outcome: LookupOutcome::Failed(SourceError::Crl(r)), origin: self.origin }
    }
}

/// The CRL [`CrlSource`].
pub struct CrlClient {
    cfg: CrlConfig,
    skew: u64,
    configured: Vec<Src>,
    state: Mutex<CrlCache>,
    flight: SingleFlight<SrcKey>,
    watch: Mutex<HashMap<SrcKey, Watch>>,
    disk: Option<DiskCache>,
    hook: RefreshHook,
    /// Serialises `crl-numbers` writes so an older snapshot can never be
    /// renamed over a newer one (SEC-102); `true` while writes fail (one
    /// audit record per failure streak).
    persist: Mutex<bool>,
    /// cRLNumber state load problems + write failures (SEC-103, NIST-102).
    state_errors: AtomicU64,
}

impl std::fmt::Debug for CrlClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlClient").field("configured", &self.configured.len()).finish_non_exhaustive()
    }
}

fn decide(e: &CrlEntry, cert: &Cert, source: Source) -> LookupOutcome {
    match e.revoked.get(cert.serial()) {
        Some(&(reason, at_us)) => LookupOutcome::Revoked { source, reason, at_us },
        None => LookupOutcome::Good(source),
    }
}

/// `plat.crl.source` of cRLNumber state records.
const HWM_SOURCE: &str = "crl-numbers";

impl CrlClient {
    /// Parses configured URLs, loads configured files (an unreadable file
    /// fails start; a stale/invalid one is logged and retried by the
    /// refresher) and the on-disk cache.
    pub fn new(s: &RevocationSettings, hook: RefreshHook, now: UnixTime) -> Result<Self, TlsError> {
        let now = now.as_secs();
        let cfg = s.crl.clone();
        let skew = s.skew.as_secs();
        let mut configured = Vec::with_capacity(cfg.files.len() + cfg.urls.len());
        for p in &cfg.files {
            configured.push(Src::file(p));
        }
        for u in &cfg.urls {
            let url = HttpUrl::parse(u).map_err(|e| TlsError::Config(format!("crl.urls {u}: {e}")))?;
            configured.push(Src::url(url, u, false));
        }
        let mut state = CrlCache::new(cfg.max_crls as usize, usize::try_from(cfg.cache_bytes).unwrap_or(usize::MAX));
        for p in &cfg.files {
            let bytes = disk::read_capped(p, cfg.max_bytes)
                .map_err(|e| TlsError::Io(p.clone(), e))?
                .ok_or_else(|| TlsError::TooLarge(p.clone(), cfg.max_bytes))?;
            match file_der(bytes).and_then(|d| parse::inspect(&d, now, skew).map(|_| d)) {
                Ok(der) => {
                    let pend = Pending { der: Arc::new(der), kind: PendingKind::File, at: now };
                    state.put_pending(Src::file(p).key, pend, now);
                }
                Err(r) => tracing::warn!("revocation: CRL file {} unusable: {}", p.display(), r.as_str()),
            }
        }
        let disk = s.cache_dir.as_deref().map(DiskCache::new);
        let mut hwm_problem = None;
        if let Some(d) = &disk {
            let l = d.load_hwm((cfg.max_crls as usize).saturating_mul(4));
            for (k, n) in l.marks {
                state.seed_hwm(k, n);
            }
            hwm_problem = l.problem;
            for (k, der) in d.load(cfg.max_crls as usize, cfg.max_bytes, now, skew) {
                state.put_pending(k, Pending { der: Arc::new(der), kind: PendingKind::Disk, at: now }, now);
            }
        }
        let mut watch = HashMap::new();
        for src in &configured {
            let due = if matches!(src.r, SrcRef::File(_)) { now + FILE_POLL } else { now };
            watch.insert(
                src.key,
                Watch {
                    src: src.clone(),
                    issuer: None,
                    configured: true,
                    last_seen: now,
                    due,
                    backoff: 0,
                    failing: false,
                    had_data: false,
                },
            );
        }
        let me = Self {
            cfg,
            skew,
            configured,
            state: Mutex::new(state),
            flight: SingleFlight::new(),
            watch: Mutex::new(watch),
            disk,
            hook,
            persist: Mutex::new(false),
            state_errors: AtomicU64::new(0),
        };
        if let Some(p) = hwm_problem {
            // SEC-103 / NIST-102: rollback marks were (partly) lost; the
            // start continues (fail-open on the marks only), but loudly.
            // COMPLIANCE MAPPING:
            // - NIST 800-53: AU-5, SI-4 - persisted-state failure surfaced
            match p {
                disk::HwmProblem::BadLines(n) => {
                    tracing::warn!("revocation: {HWM_SOURCE}: skipped {n} malformed line(s)");
                }
                _ => tracing::warn!("revocation: {HWM_SOURCE} ignored: {}", p.as_str()),
            }
            me.state_error(RefreshTransition::StateRejected, p.as_str());
        }
        Ok(me)
    }

    /// Counts a cRLNumber state problem and emits its audit record.
    fn state_error(&self, transition: RefreshTransition, reason: &'static str) {
        self.state_errors.fetch_add(1, Ordering::Relaxed);
        (self.hook)(&RefreshRecord {
            kind: RefreshKind::Crl,
            source: HWM_SOURCE.to_owned(),
            transition,
            reason: Some(reason),
        });
    }

    /// Number of verified CRLs (`plat_crl_cache_entries`).
    pub fn cache_len(&self) -> usize {
        self.state.lock().len()
    }

    /// Estimated cache memory (`plat_crl_cache_bytes`).
    pub fn cache_bytes(&self) -> usize {
        self.state.lock().bytes()
    }

    fn emit(&self, s: &Src, transition: RefreshTransition, reason: Option<CrlReason>) {
        (self.hook)(&RefreshRecord {
            kind: RefreshKind::Crl,
            source: s.origin(),
            transition,
            reason: reason.map(CrlReason::as_str),
        });
    }

    /// Records a source seen for `issuer`: learned CDPs join the watch list
    /// (bounded by `max_crls`; least recently seen learned item evicted);
    /// verified sources get their issuer so the refresher can verify.
    fn learn(&self, s: &Src, issuer: Option<&Cert>, now: u64) {
        let cap = (self.cfg.max_crls as usize).max(1);
        let mut w = self.watch.lock();
        if let Some(it) = w.get_mut(&s.key) {
            it.last_seen = now;
            if let Some(i) = issuer {
                it.issuer = Some(i.clone());
            }
            return;
        }
        if s.cdp().is_none() {
            return;
        }
        if w.len() >= cap {
            match w.iter().filter(|(_, v)| !v.configured).min_by_key(|(_, v)| v.last_seen).map(|(k, _)| *k) {
                Some(k) => {
                    w.remove(&k);
                }
                None => return,
            }
        }
        w.insert(
            s.key,
            Watch {
                src: s.clone(),
                issuer: issuer.cloned(),
                configured: false,
                last_seen: now,
                due: now.saturating_add(30),
                backoff: 0,
                failing: false,
                had_data: false,
            },
        );
    }

    /// Sets the next refresh from the verified entry (separate lock
    /// sections, never nested).
    fn reschedule(&self, k: &SrcKey, e: &CrlEntry, now: u64) {
        let due = super::schedule(e.this_update, e.next_update, u64::from(self.cfg.refresh_margin_secs), now);
        if let Some(it) = self.watch.lock().get_mut(k) {
            it.due = due;
            it.had_data = true;
        }
    }

    /// Persists the cRLNumber high-water marks to `cache_dir` if they
    /// changed. Writers are serialised by `persist` and take their
    /// snapshot inside it, so the file only moves forward; the cache lock
    /// is held only for the snapshot. A failed write re-arms the dirty
    /// flag so the next store retries, and is counted and audited
    /// (SEC-102, NIST-102).
    fn persist_hwm(&self) {
        let Some(d) = &self.disk else { return };
        let mut failing = self.persist.lock();
        let snap = self.state.lock().take_hwm_if_dirty();
        let Some(m) = snap else { return };
        match d.store_hwm(&m) {
            Ok(()) => *failing = false,
            Err(err) => {
                self.state.lock().mark_hwm_dirty();
                tracing::warn!("revocation: cRLNumber state write failed: {err}");
                if std::mem::replace(&mut *failing, true) {
                    self.state_errors.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.state_error(RefreshTransition::StatePersistFailed, "state_write_failed");
                }
            }
        }
    }

    /// Stores a verified CRL (rollback-checked) and persists its DER.
    fn store(&self, s: &Src, e: CrlEntry, der: &[u8], issuer: &Cert, now: u64) -> Result<Arc<CrlEntry>, CrlReason> {
        let r = self.state.lock().put(s.key, e, now);
        match r {
            Ok(e) => {
                self.persist_hwm();
                if let (Some(d), SrcRef::Url { .. }) = (&self.disk, &s.r)
                    && let Err(err) = d.store(&s.key, der)
                {
                    tracing::warn!("revocation: CRL disk cache write failed: {err}");
                }
                self.learn(s, Some(issuer), now);
                self.reschedule(&s.key, &e, now);
                Ok(e)
            }
            Err(CrlReason::Rollback) => {
                self.emit(s, RefreshTransition::RollbackRejected, Some(CrlReason::Rollback));
                Err(CrlReason::Rollback)
            }
            Err(r) => Err(r),
        }
    }

    /// Cache step for one source: a verified entry for this issuer, else
    /// unverified bytes verified now. `Some` is conclusive or fatal.
    fn cached_or_pending(
        &self,
        s: &Src,
        ctx: &CertCtx<'_>,
        ikh: &[u8; 32],
        now: u64,
        errs: &mut Errs,
    ) -> Option<Lookup> {
        let (v, p) = {
            let mut st = self.state.lock();
            (st.get(&s.key, now), st.pending(&s.key))
        };
        if let Some(e) = v
            && &e.issuer_key_hash == ikh
        {
            if !e.fresh(now, self.skew) {
                self.state.lock().remove(&s.key);
                errs.note(CrlReason::Stale, s);
            } else if e.covers(ctx.cert, s.cdp()) {
                return Some(Lookup { outcome: decide(&e, ctx.cert, s.cached_source()), origin: Some(s.origin()) });
            } else {
                errs.note(CrlReason::ScopeMismatch, s);
            }
            return None;
        }
        let p = p?;
        match parse::verify(&p.der, ctx.issuer, now, self.skew) {
            Err(CrlReason::WrongIssuer) => None, // another CA's CRL
            Err(r) if p.kind == PendingKind::Disk => {
                // Local data failed re-verification: delete, never fatal.
                self.state.lock().remove_pending(&s.key);
                if let Some(d) = &self.disk {
                    d.remove(&s.key);
                }
                if !r.is_fatal() {
                    errs.note(r, s);
                }
                None
            }
            Err(r) if r.is_fatal() => {
                Some(Lookup { outcome: LookupOutcome::Failed(SourceError::Crl(r)), origin: Some(s.origin()) })
            }
            Err(r) => {
                errs.note(r, s);
                None
            }
            Ok(e) => {
                let put = self.state.lock().put(s.key, e, now);
                match put {
                    Ok(e) => {
                        self.persist_hwm();
                        self.learn(s, Some(ctx.issuer), now);
                        self.reschedule(&s.key, &e, now);
                        if e.covers(ctx.cert, s.cdp()) {
                            let src = if p.kind == PendingKind::File { Source::CrlFile } else { Source::CrlCache };
                            return Some(Lookup { outcome: decide(&e, ctx.cert, src), origin: Some(s.origin()) });
                        }
                        errs.note(CrlReason::ScopeMismatch, s);
                    }
                    Err(r) => errs.note(r, s),
                }
                None
            }
        }
    }

    /// Fetches the source's bytes (no lock held).
    fn obtain(&self, s: &Src, deadline: Instant) -> Result<Vec<u8>, CrlReason> {
        match &s.r {
            SrcRef::Url { url, .. } => {
                let deadline = deadline.min(Instant::now() + Duration::from_millis(self.cfg.timeout_ms));
                let max_body = usize::try_from(self.cfg.max_bytes).unwrap_or(usize::MAX);
                let req = http::Request {
                    post: None,
                    accept: "application/pkix-crl",
                    accept_types: CRL_TYPES,
                    max_body,
                    deadline,
                };
                http::fetch(url, &req).map(|r| r.body).map_err(map_http)
            }
            SrcRef::File(p) => match disk::read_capped(p, self.cfg.max_bytes) {
                Ok(Some(b)) => file_der(b),
                Ok(None) => Err(CrlReason::TooLarge),
                Err(_) => Err(CrlReason::NoSource),
            },
        }
    }
}

impl CrlSource for CrlClient {
    fn cache_usage(&self) -> (usize, usize) {
        let st = self.state.lock();
        (st.len(), st.bytes())
    }

    fn state_errors(&self) -> u64 {
        self.state_errors.load(Ordering::Relaxed)
    }

    fn lookup(&self, ctx: &CertCtx<'_>) -> Lookup {
        let now = ctx.now.as_secs();
        let ikh = super::issuer_key_hash(ctx.issuer);
        let mut srcs = self.configured.clone();
        if self.cfg.use_cdp {
            for s in cdp_sources(ctx.cert) {
                if !srcs.iter().any(|x| x.key == s.key) {
                    srcs.push(s);
                }
            }
        }
        if srcs.is_empty() {
            return Lookup::failed(SourceError::Crl(CrlReason::NoSource));
        }
        for s in srcs.iter().filter(|s| s.cdp().is_some()) {
            self.learn(s, None, now);
        }
        let mut errs = Errs::default();
        for s in &srcs {
            if let Some(l) = self.cached_or_pending(s, ctx, &ikh, now, &mut errs) {
                return l;
            }
        }
        for s in srcs.iter().filter(|s| matches!(s.r, SrcRef::Url { .. })) {
            if Instant::now() >= ctx.deadline {
                errs.note(CrlReason::Budget, s);
                break;
            }
            match self.flight.begin(&s.key, ctx.deadline) {
                Flight::Leader(_g) => {
                    let r = self.obtain(s, ctx.deadline).and_then(|der| {
                        let e = parse::verify(&der, ctx.issuer, now, self.skew);
                        if matches!(e, Err(CrlReason::WrongIssuer)) && s.cdp().is_none() {
                            // A configured URL for another CA: keep it for them.
                            let pend = Pending { der: Arc::new(der), kind: PendingKind::Prefetch, at: now };
                            self.state.lock().put_pending(s.key, pend, now);
                            return Err(CrlReason::WrongIssuer);
                        }
                        self.store(s, e?, &der, ctx.issuer, now)
                    });
                    match r {
                        Ok(e) if e.covers(ctx.cert, s.cdp()) => {
                            return Lookup {
                                outcome: decide(&e, ctx.cert, Source::CrlFetch),
                                origin: Some(s.origin()),
                            };
                        }
                        Ok(_) => errs.note(CrlReason::ScopeMismatch, s),
                        Err(CrlReason::WrongIssuer) if s.cdp().is_none() => {}
                        Err(r) if r.is_fatal() => {
                            return Lookup {
                                outcome: LookupOutcome::Failed(SourceError::Crl(r)),
                                origin: Some(s.origin()),
                            };
                        }
                        Err(r) => errs.note(r, s),
                    }
                }
                Flight::Waited => {
                    if let Some(l) = self.cached_or_pending(s, ctx, &ikh, now, &mut errs) {
                        return l;
                    }
                }
                Flight::TimedOut => errs.note(CrlReason::Timeout, s),
            }
        }
        errs.into_lookup()
    }

    /// Refreshes due sources serially: configured URLs/files from start,
    /// learned CDPs for 24 h after last use. Emits a record only on a
    /// state change.
    fn refresh(&self, now: UnixTime) -> Option<Duration> {
        let now = now.as_secs();
        let due: Vec<Watch> = {
            let mut w = self.watch.lock();
            w.retain(|_, v| v.configured || v.last_seen.saturating_add(WATCH_TTL) > now);
            w.values().filter(|v| v.due <= now).cloned().collect()
        };
        for it in due {
            let s = &it.src;
            let deadline = Instant::now() + Duration::from_millis(self.cfg.timeout_ms);
            let Flight::Leader(_g) = self.flight.begin(&s.key, deadline) else { continue };
            let res: Result<Option<(u64, u64)>, CrlReason> =
                self.obtain(s, deadline).and_then(|der| match &it.issuer {
                    Some(iss) => {
                        let e = parse::verify(&der, iss, now, self.skew)?;
                        let e = self.store(s, e, &der, iss, now)?;
                        Ok(Some((e.this_update, e.next_update)))
                    }
                    None => {
                        let e = parse::inspect(&der, now, self.skew)?;
                        let kind =
                            if matches!(s.r, SrcRef::File(_)) { PendingKind::File } else { PendingKind::Prefetch };
                        let tn = (e.this_update, e.next_update);
                        self.state.lock().put_pending(s.key, Pending { der: Arc::new(der), kind, at: now }, now);
                        Ok(Some(tn))
                    }
                });
            // A cached copy past nextUpdate is dropped, whatever happened.
            let stale = {
                let mut st = self.state.lock();
                match st.get(&s.key, now) {
                    Some(e) if !e.fresh(now, self.skew) => st.remove(&s.key).is_some(),
                    _ => false,
                }
            };
            let mut transitions = Vec::with_capacity(2);
            {
                let mut w = self.watch.lock();
                let Some(cur) = w.get_mut(&s.key) else { continue };
                match &res {
                    Ok(Some((this, next))) => {
                        cur.backoff = 0;
                        if it.issuer.is_none() {
                            let margin = u64::from(self.cfg.refresh_margin_secs);
                            cur.due = super::schedule(*this, *next, margin, now);
                            if matches!(s.r, SrcRef::File(_)) {
                                cur.due = cur.due.min(now + FILE_POLL);
                            }
                        }
                        if cur.failing {
                            cur.failing = false;
                            transitions.push((RefreshTransition::Recovered, None));
                        }
                    }
                    Ok(None) => {}
                    Err(r) => {
                        cur.backoff = super::next_backoff(cur.backoff);
                        cur.due = now.saturating_add(cur.backoff);
                        if !cur.failing {
                            cur.failing = true;
                            transitions.push((RefreshTransition::Failing, Some(*r)));
                        }
                    }
                }
                if stale && cur.had_data {
                    cur.had_data = false;
                    transitions.push((RefreshTransition::StaleDropped, Some(CrlReason::Stale)));
                }
            }
            for (t, r) in transitions {
                self.emit(s, t, r);
            }
        }
        let w = self.watch.lock();
        w.values().map(|v| v.due).min().map(|d| Duration::from_secs(d.saturating_sub(now)))
    }
}
