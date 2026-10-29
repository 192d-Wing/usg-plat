//! OCSP client (RFC 6960): stapled response (syslog leaf), then the
//! bounded cache, then a fetch from the responder (configured
//! `responder_url` for the leaf, else the certificate's AIA id-ad-ocsp
//! `http://` URI).
//!
//! Fetches are single-flight per `(issuer_key_hash, serial)`, bounded by
//! `min(chain deadline, ocsp.timeout_ms)`, and go through the capped HTTP
//! client (16 KiB body, no redirects). Certificates answered `good` join a
//! bounded watch list that the refresher keeps warm for 24 h.
//!
//! Locks (`cache`, `watch`, single-flight) are leaf `parking_lot` mutexes,
//! never held across I/O, parsing, signature verification or a hook call,
//! and never two at once.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5(2)(b)(1) - online status of every non-root
//!   certificate
//! - NIST 800-53: SC-5 - size/time caps, bounded cache and watch list,
//!   negative cache, single-flight
//! - RFC 6960 §4.1, §4.2, Appendix A; RFC 8954 (nonce); RFC 6066 §8
//!   (stapled response, leaf only)

pub mod cache;
pub mod request;
pub mod response;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use der::Decode;
use der::asn1::ObjectIdentifier as Oid;
use parking_lot::Mutex;
use plat_common::HttpUrl;
use plat_common::config::{OcspConfig, OcspMethod};
use rustls_pki_types::UnixTime;
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
use x509_cert::ext::pkix::name::GeneralName;

use self::cache::{Entry, Key, NEGATIVE_TTL, OcspCache};
use self::response::{Expect, Status, Verified};
use super::flight::{Flight, SingleFlight};
use super::http::{self, HttpError};
use super::{
    CertCtx, Lookup, LookupOutcome, OcspReason, OcspSource, RefreshHook, RefreshKind, RefreshRecord, RefreshTransition,
    RevocationSettings, Source, SourceError,
};
use crate::TlsError;
use crate::revocation::Cert;

/// RFC 6960 Appendix A response size cap.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;
/// Watch items not seen in an accepted check for this long are dropped.
const WATCH_TTL: u64 = 24 * 3600;
/// Refresh this long before a cached response expires at the latest.
const OCSP_MARGIN: u64 = 60;

const ID_PE_AIA: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.1.1");
const ID_AD_OCSP: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.1");
const OCSP_RESPONSE: &str = "application/ocsp-response";

/// The first `http://` id-ad-ocsp URI of the certificate's AIA.
pub fn aia_responder(cert: &Cert) -> Option<HttpUrl> {
    let aia = AuthorityInfoAccessSyntax::from_der(cert.extension(ID_PE_AIA)?).ok()?;
    aia.0.iter().filter(|a| a.access_method == ID_AD_OCSP).find_map(|a| match &a.access_location {
        GeneralName::UniformResourceIdentifier(u) => HttpUrl::parse(u.as_str()).ok(),
        _ => None,
    })
}

fn map_http(e: HttpError) -> OcspReason {
    match e {
        HttpError::Timeout => OcspReason::Timeout,
        HttpError::Connect => OcspReason::Connect,
        HttpError::Status(_) => OcspReason::HttpStatus,
        HttpError::ContentType => OcspReason::ContentType,
        HttpError::TooLarge => OcspReason::TooLarge,
        HttpError::Malformed => OcspReason::Malformed,
    }
}

#[derive(Debug, Clone)]
struct Watch {
    cert: Cert,
    issuer: Cert,
    url: HttpUrl,
    last_seen: u64,
    due: u64,
    backoff: u64,
    failing: bool,
    /// A live cached response existed (for the one-shot stale-drop record).
    had_data: bool,
}

/// The OCSP [`OcspSource`].
pub struct OcspClient {
    cfg: OcspConfig,
    skew: u64,
    responder: Option<HttpUrl>,
    cache: Mutex<OcspCache>,
    flight: SingleFlight<Key>,
    watch: Mutex<HashMap<Key, Watch>>,
    hook: RefreshHook,
}

impl std::fmt::Debug for OcspClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcspClient")
            .field("responder", &self.responder)
            .field("cache_entries", &self.cache.lock().len())
            .finish_non_exhaustive()
    }
}

fn key(cert: &Cert, issuer: &Cert) -> Key {
    (super::issuer_key_hash(issuer), cert.serial().to_vec())
}

fn key_text(k: &Key) -> String {
    format!("{}:{}", super::hex(&k.0), super::hex(&k.1))
}

impl OcspClient {
    pub fn new(s: &RevocationSettings, hook: RefreshHook) -> Result<Self, TlsError> {
        let responder = match &s.ocsp.responder_url {
            Some(u) => Some(HttpUrl::parse(u).map_err(|e| TlsError::Config(format!("ocsp.responder_url: {e}")))?),
            None => None,
        };
        Ok(Self {
            cfg: s.ocsp.clone(),
            skew: s.skew.as_secs(),
            responder,
            cache: Mutex::new(OcspCache::new(s.ocsp.cache_entries as usize)),
            flight: SingleFlight::new(),
            watch: Mutex::new(HashMap::new()),
            hook,
        })
    }

    /// Number of cached responses (`plat_ocsp_cache_entries`).
    pub fn cache_len(&self) -> usize {
        self.cache.lock().len()
    }

    fn expect<'a>(&self, id: &'a x509_ocsp::CertId, nonce: Option<&'a [u8]>, now: u64) -> Expect<'a> {
        Expect {
            cert_id: id,
            nonce,
            require_nonce: self.cfg.require_nonce && nonce.is_some(),
            now,
            skew: self.skew,
            max_age: u64::from(self.cfg.max_age_secs),
        }
    }

    fn url_for(&self, ctx: &CertCtx<'_>) -> Option<HttpUrl> {
        if ctx.index == 0
            && let Some(u) = &self.responder
        {
            return Some(u.clone());
        }
        if self.cfg.use_aia { aia_responder(ctx.cert) } else { None }
    }

    /// Fetches and validates one response (no lock held).
    fn fetch(
        &self,
        cert: &Cert,
        issuer: &Cert,
        url: &HttpUrl,
        deadline: Instant,
        now: u64,
    ) -> Result<Verified, OcspReason> {
        let req = request::build(cert, issuer, self.cfg.cert_id_hash, self.cfg.nonce).ok_or(OcspReason::Malformed)?;
        let deadline = deadline.min(Instant::now() + Duration::from_millis(self.cfg.timeout_ms));
        let get_url;
        let (target, post) = match self.cfg.method {
            OcspMethod::Post => (url, Some(("application/ocsp-request", req.der.as_slice()))),
            OcspMethod::Get => {
                get_url = HttpUrl { path: request::get_path(&url.path, &req.der), ..url.clone() };
                (&get_url, None)
            }
        };
        let r = http::Request {
            post,
            accept: OCSP_RESPONSE,
            accept_types: &[OCSP_RESPONSE],
            max_body: MAX_RESPONSE_BYTES,
            deadline,
        };
        let body = http::fetch(target, &r).map_err(map_http)?.body;
        let nonce = req.nonce.as_ref().map(|n| n.as_slice());
        let mut e = self.expect(&req.cert_id, nonce, now);
        e.require_nonce = self.cfg.require_nonce;
        response::verify(&body, issuer, &e)
    }

    /// Caches a fetch result; returns the lookup outcome for it.
    fn store(&self, k: &Key, r: Result<Verified, OcspReason>, src: Source, now: u64) -> LookupOutcome {
        match r {
            Ok(v) => {
                let entry = match v.status {
                    Status::Unknown => Entry::Negative { reason: OcspReason::UnknownStatus, until: now + NEGATIVE_TTL },
                    s => Entry::Status { status: s, this_update: v.this_update, expires: v.expires },
                };
                self.cache.lock().put(k.clone(), entry, now);
                outcome(v.status, src)
            }
            Err(reason) => {
                if !reason.is_fatal() {
                    self.cache.lock().put(k.clone(), Entry::Negative { reason, until: now + NEGATIVE_TTL }, now);
                }
                LookupOutcome::Failed(SourceError::Ocsp(reason))
            }
        }
    }

    fn cached(&self, k: &Key, now: u64) -> Option<LookupOutcome> {
        match self.cache.lock().get(k, now)? {
            Entry::Status { status, .. } => Some(outcome(status, Source::OcspCache)),
            Entry::Negative { reason, .. } => Some(LookupOutcome::Failed(SourceError::Ocsp(reason))),
        }
    }

    /// Adds a `good` certificate to the watch list (bounded by
    /// `cache_entries`; the least recently seen item is evicted).
    fn remember(&self, k: &Key, ctx: &CertCtx<'_>, url: &HttpUrl, now: u64) {
        let due = match self.cache.lock().get(k, now) {
            Some(Entry::Status { this_update, expires, .. }) => {
                super::schedule(this_update, expires, OCSP_MARGIN.min(expires.saturating_sub(this_update) / 5), now)
            }
            _ => return,
        };
        let cap = (self.cfg.cache_entries as usize).max(1);
        let mut w = self.watch.lock();
        if let Some(item) = w.get_mut(k) {
            item.last_seen = now;
            item.due = due;
            return;
        }
        if w.len() >= cap
            && let Some(victim) = w.iter().min_by_key(|(_, v)| v.last_seen).map(|(k, _)| k.clone())
        {
            w.remove(&victim);
        }
        w.insert(
            k.clone(),
            Watch {
                cert: ctx.cert.clone(),
                issuer: ctx.issuer.clone(),
                url: url.clone(),
                last_seen: now,
                due,
                backoff: 0,
                failing: false,
                had_data: true,
            },
        );
    }

    fn emit(&self, k: &Key, transition: RefreshTransition, reason: Option<OcspReason>) {
        (self.hook)(&RefreshRecord {
            kind: RefreshKind::Ocsp,
            source: key_text(k),
            transition,
            reason: reason.map(OcspReason::as_str),
        });
    }
}

fn outcome(s: Status, src: Source) -> LookupOutcome {
    match s {
        Status::Good => LookupOutcome::Good(src),
        Status::Revoked { reason, at_us } => LookupOutcome::Revoked { source: src, reason, at_us },
        Status::Unknown => LookupOutcome::Failed(SourceError::Ocsp(OcspReason::UnknownStatus)),
    }
}

impl OcspSource for OcspClient {
    fn cache_entries(&self) -> usize {
        self.cache_len()
    }

    fn lookup(&self, ctx: &CertCtx<'_>) -> Lookup {
        let now = ctx.now.as_secs();
        let k = key(ctx.cert, ctx.issuer);
        let url = self.url_for(ctx);
        let origin = url.as_ref().map(HttpUrl::authority);
        // A stale or unusable staple is remembered so that QN2 (stale never
        // soft-accepted) still holds when nothing else answers.
        let mut staple_err = None;

        // 1. Stapled (leaf only; never when nonces are required).
        if let Some(st) = ctx.stapled
            && !self.cfg.require_nonce
        {
            match request::cert_id(ctx.cert, ctx.issuer, self.cfg.cert_id_hash) {
                Some(id) => {
                    let e = self.expect(&id, None, now);
                    let r = response::verify(st, ctx.issuer, &e);
                    match r {
                        Ok(v) if v.status != Status::Unknown => {
                            let o = self.store(&k, Ok(v), Source::OcspStapled, now);
                            return Lookup { outcome: o, origin: Some("stapled".into()) };
                        }
                        Ok(_) => staple_err = Some(OcspReason::UnknownStatus),
                        Err(r) if r.is_fatal() => {
                            return Lookup {
                                outcome: LookupOutcome::Failed(SourceError::Ocsp(r)),
                                origin: Some("stapled".into()),
                            };
                        }
                        Err(r) => staple_err = Some(r),
                    }
                }
                None => staple_err = Some(OcspReason::Malformed),
            }
        }
        let with_staple = |o: LookupOutcome| match (o, staple_err) {
            (LookupOutcome::Failed(SourceError::Ocsp(r)), Some(OcspReason::Stale))
                if r != OcspReason::Stale && !r.is_fatal() =>
            {
                LookupOutcome::Failed(SourceError::Ocsp(OcspReason::Stale))
            }
            (o, _) => o,
        };

        // 2. Cache.
        if let Some(o) = self.cached(&k, now) {
            if matches!(o, LookupOutcome::Good(_))
                && let Some(u) = &url
            {
                self.remember(&k, ctx, u, now);
            }
            return Lookup { outcome: with_staple(o), origin };
        }

        // 3. Fetch.
        let Some(url) = url else {
            let r = staple_err.unwrap_or(OcspReason::NoResponder);
            return Lookup { outcome: LookupOutcome::Failed(SourceError::Ocsp(r)), origin: None };
        };
        let o = match self.flight.begin(&k, ctx.deadline) {
            Flight::Leader(_g) => {
                let r = self.fetch(ctx.cert, ctx.issuer, &url, ctx.deadline, now);
                let o = self.store(&k, r, Source::OcspFetch, now);
                if matches!(o, LookupOutcome::Good(_)) {
                    self.remember(&k, ctx, &url, now);
                }
                o
            }
            Flight::Waited => {
                self.cached(&k, now).unwrap_or(LookupOutcome::Failed(SourceError::Ocsp(OcspReason::Timeout)))
            }
            Flight::TimedOut => LookupOutcome::Failed(SourceError::Ocsp(OcspReason::Timeout)),
        };
        Lookup { outcome: with_staple(o), origin: Some(url.authority()) }
    }

    /// Re-fetches watched responses that are due; drops items not seen
    /// for 24 h. Serial; each fetch bounded by `ocsp.timeout_ms`.
    fn refresh(&self, now: UnixTime) -> Option<Duration> {
        let now = now.as_secs();
        let due: Vec<(Key, Watch)> = {
            let mut w = self.watch.lock();
            w.retain(|_, v| v.last_seen.saturating_add(WATCH_TTL) > now);
            w.iter().filter(|(_, v)| v.due <= now).map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (k, item) in due {
            let deadline = Instant::now() + Duration::from_millis(self.cfg.timeout_ms);
            let Flight::Leader(_g) = self.flight.begin(&k, deadline) else { continue };
            let r = self.fetch(&item.cert, &item.issuer, &item.url, deadline, now);
            let ok = matches!(&r, Ok(v) if v.status != Status::Unknown);
            let reason = r.as_ref().err().copied().or(if ok { None } else { Some(OcspReason::UnknownStatus) });
            if let Ok(v) = r
                && ok
            {
                self.cache.lock().put(
                    k.clone(),
                    Entry::Status { status: v.status, this_update: v.this_update, expires: v.expires },
                    now,
                );
            }
            let live = matches!(self.cache.lock().get(&k, now), Some(Entry::Status { .. }));
            let mut transition = None;
            {
                let mut w = self.watch.lock();
                let Some(it) = w.get_mut(&k) else { continue };
                if ok {
                    it.backoff = 0;
                    it.had_data = true;
                    if it.failing {
                        it.failing = false;
                        transition = Some((RefreshTransition::Recovered, None));
                    }
                } else {
                    it.backoff = super::next_backoff(it.backoff);
                    it.due = now.saturating_add(it.backoff);
                    if !it.failing {
                        it.failing = true;
                        transition = Some((RefreshTransition::Failing, reason));
                    } else if !live && it.had_data {
                        it.had_data = false;
                        transition = Some((RefreshTransition::StaleDropped, reason));
                    }
                }
            }
            if ok {
                self.reschedule(&k, now);
            }
            if let Some((t, r)) = transition {
                self.emit(&k, t, r);
            }
        }
        let w = self.watch.lock();
        w.values().map(|v| v.due).min().map(|d| Duration::from_secs(d.saturating_sub(now)))
    }
}

impl OcspClient {
    /// Sets the next refresh from the cached entry (two separate lock
    /// sections, never nested).
    fn reschedule(&self, k: &Key, now: u64) {
        let Some(Entry::Status { this_update, expires, .. }) = self.cache.lock().get(k, now) else { return };
        let due = super::schedule(this_update, expires, OCSP_MARGIN.min(expires.saturating_sub(this_update) / 5), now);
        if let Some(it) = self.watch.lock().get_mut(k) {
            it.due = due;
        }
    }
}
