//! Path rebuild (chain.rs) and the per-certificate decision order of the
//! revocation checker, with scripted OCSP/CRL sources.

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use plat_common::config::{CrlConfig, OcspConfig, RevocationMode};
use plat_tls::revocation::chain::{self, Anchors, ChainError, MAX_DEPTH};
use plat_tls::revocation::{
    CertCtx, ChainOutcome, CrlReason, CrlSource, Lookup, LookupOutcome, OcspReason, OcspSource, RecordStatus,
    RevocationChecker, RevocationReason, RevocationRecord, RevocationSettings, Role, Source, SourceError,
};
use rustls_pki_types::{CertificateDer, UnixTime};
use support::pki::{Ca, LeafOpts};

fn anchors(ca: &[&Ca]) -> Anchors {
    Anchors::parse(&ca.iter().map(|c| c.der.clone()).collect::<Vec<_>>()).unwrap()
}

fn subjects(path: &[chain::ChainLink]) -> Vec<String> {
    path.iter().map(|l| l.issuer.x509.tbs_certificate.subject.to_string()).collect()
}

#[test]
fn rebuild_zero_one_two_intermediates() {
    let root = Ca::root("Root A");
    let a = anchors(&[&root]);
    let leaf = root.leaf(&LeafOpts::client("direct"));
    let p = chain::rebuild(&leaf.der, &[], &a).unwrap();
    assert_eq!((p.len(), p[0].index), (1, 0));
    let i1 = root.intermediate("Inter 1");
    let i2 = i1.intermediate("Inter 2");
    let leaf = i2.leaf(&LeafOpts::client("deep"));
    // Presented out of order, with unrelated extras.
    let other = Ca::root("Other Root");
    let stray = other.intermediate("Stray");
    let p =
        chain::rebuild(&leaf.der, &[stray.der.clone(), i1.der.clone(), other.der.clone(), i2.der.clone()], &a).unwrap();
    assert_eq!(p.iter().map(|l| l.index).collect::<Vec<_>>(), [0, 1, 2]);
    assert!(subjects(&p)[0].contains("Inter 2") && subjects(&p)[2].contains("Root A"), "{:?}", subjects(&p));
    // The anchor itself has nothing to check.
    assert!(chain::rebuild(&root.der, &[], &a).unwrap().is_empty());
}

#[test]
fn candidate_with_wrong_key_is_skipped() {
    let root = Ca::root("Root B");
    let real = root.intermediate("Same Name");
    // Same subject DN, different key, also chaining to the root.
    let imposter = root.intermediate("Same Name");
    let leaf = real.leaf(&LeafOpts::client("c"));
    let p = chain::rebuild(&leaf.der, &[imposter.der.clone(), real.der.clone()], &anchors(&[&root])).unwrap();
    assert_eq!(p.len(), 2);
    assert_eq!(p[0].issuer.der, real.der);
}

#[test]
fn missing_issuer_and_depth_cap() {
    let root = Ca::root("Root C");
    let i1 = root.intermediate("Missing");
    let leaf = i1.leaf(&LeafOpts::client("c"));
    assert_eq!(chain::rebuild(&leaf.der, &[], &anchors(&[&root])).unwrap_err(), ChainError::NoIssuer(0));
    // Not chained to the configured anchor at all.
    let other = Ca::root("Root D");
    assert_eq!(
        chain::rebuild(&leaf.der, std::slice::from_ref(&i1.der), &anchors(&[&other])).unwrap_err(),
        ChainError::NoIssuer(1)
    );
    // MAX_DEPTH + 1 non-root certificates.
    let mut cas = vec![root.intermediate("D0")];
    for i in 1..MAX_DEPTH {
        let next = cas[i - 1].intermediate(&format!("D{i}"));
        cas.push(next);
    }
    let leaf = cas[MAX_DEPTH - 1].leaf(&LeafOpts::client("too deep"));
    let inter: Vec<CertificateDer<'static>> = cas.iter().map(|c| c.der.clone()).collect();
    assert_eq!(chain::rebuild(&leaf.der, &inter, &anchors(&[&root])).unwrap_err(), ChainError::TooDeep);
    // One shorter is fine.
    let leaf = cas[MAX_DEPTH - 2].leaf(&LeafOpts::client("deep ok"));
    assert_eq!(chain::rebuild(&leaf.der, &inter[..MAX_DEPTH - 1], &anchors(&[&root])).unwrap().len(), MAX_DEPTH);
    assert_eq!(
        chain::rebuild(&leaf.der, &vec![root.der.clone(); 17], &anchors(&[&root])).unwrap_err(),
        ChainError::TooManyIntermediates
    );
    assert_eq!(
        chain::rebuild(&CertificateDer::from(vec![0x30, 0x00]), &[], &anchors(&[&root])).unwrap_err(),
        ChainError::Malformed(0)
    );
}

#[test]
fn rsa_and_p384_signatures() {
    let rsa = Ca::root_with("RSA Root", &rcgen::PKCS_RSA_SHA256);
    let p384 = rsa.intermediate_with("P-384 Inter", &rcgen::PKCS_ECDSA_P384_SHA384);
    let leaf = p384.leaf(&LeafOpts::client("c"));
    assert_eq!(chain::rebuild(&leaf.der, std::slice::from_ref(&p384.der), &anchors(&[&rsa])).unwrap().len(), 2);
}

/// Scripted source: outcome per chain index; counts calls.
#[derive(Debug)]
struct Scripted {
    outcomes: Vec<LookupOutcome>,
    delay: Duration,
    calls: AtomicUsize,
    stapled_seen: Mutex<Vec<(u8, bool)>>,
}

impl Scripted {
    fn new(outcomes: Vec<LookupOutcome>) -> Arc<Self> {
        Arc::new(Self { outcomes, delay: Duration::ZERO, calls: AtomicUsize::new(0), stapled_seen: Mutex::new(vec![]) })
    }

    fn get(&self, ctx: &CertCtx<'_>) -> Lookup {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.stapled_seen.lock().unwrap().push((ctx.index, ctx.stapled.is_some()));
        std::thread::sleep(self.delay);
        Lookup { outcome: self.outcomes[usize::from(ctx.index)].clone(), origin: Some("src.example.net:80".into()) }
    }
}

#[derive(Debug)]
struct O(Arc<Scripted>);
#[derive(Debug)]
struct C(Arc<Scripted>);

impl OcspSource for O {
    fn lookup(&self, ctx: &CertCtx<'_>) -> Lookup {
        self.0.get(ctx)
    }
}

impl CrlSource for C {
    fn lookup(&self, ctx: &CertCtx<'_>) -> Lookup {
        self.0.get(ctx)
    }
}

fn settings(mode: RevocationMode) -> RevocationSettings {
    RevocationSettings {
        mode,
        skew: Duration::from_secs(300),
        budget: Duration::from_millis(500),
        cache_dir: None,
        ocsp: OcspConfig::default(),
        crl: CrlConfig::default(),
    }
}

struct Fixture {
    leaf: CertificateDer<'static>,
    inter: CertificateDer<'static>,
    anchors: Anchors,
}

fn fixture() -> Fixture {
    let root = Ca::root("Rev Root");
    let inter = root.intermediate("Rev Inter");
    let leaf = inter.leaf(&LeafOpts::client("rev-client"));
    Fixture { leaf: leaf.der, inter: inter.der.clone(), anchors: anchors(&[&root]) }
}

fn run(
    mode: RevocationMode,
    ocsp: &Arc<Scripted>,
    crl: &Arc<Scripted>,
    tweak: impl FnOnce(&mut RevocationSettings),
) -> (ChainOutcome, Vec<RevocationRecord>) {
    let f = fixture();
    let mut s = settings(mode);
    tweak(&mut s);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let hook_seen = seen.clone();
    let hook: plat_tls::RevocationHook =
        Arc::new(move |r: &RevocationRecord| hook_seen.lock().unwrap().push(r.clone()));
    let c = RevocationChecker::with_sources(s, hook, Box::new(O(ocsp.clone())), Box::new(C(crl.clone()))).unwrap();
    let v = c.check_chain(
        Role::MgmtClient,
        &f.leaf,
        std::slice::from_ref(&f.inter),
        &f.anchors,
        Some(b"staple"),
        UnixTime::now(),
    );
    let hooked = seen.lock().unwrap().clone();
    assert_eq!(hooked, v.records, "hook sees exactly the verdict records");
    (v.outcome, v.records)
}

const GOOD_OCSP: LookupOutcome = LookupOutcome::Good(Source::OcspFetch);
const GOOD_CRL: LookupOutcome = LookupOutcome::Good(Source::CrlFetch);
const NO_OCSP: LookupOutcome = LookupOutcome::Failed(SourceError::Ocsp(OcspReason::NoResponder));
const NO_CRL: LookupOutcome = LookupOutcome::Failed(SourceError::Crl(CrlReason::NoSource));

fn revoked(source: Source) -> LookupOutcome {
    LookupOutcome::Revoked { source, reason: RevocationReason::KeyCompromise, at_us: 1_000_000 }
}

#[test]
fn ocsp_good_decides_without_crl() {
    let (o, c) = (Scripted::new(vec![GOOD_OCSP; 2]), Scripted::new(vec![GOOD_CRL; 2]));
    let (out, recs) = run(RevocationMode::HardFail, &o, &c, |_| {});
    assert_eq!(out, ChainOutcome::Accepted);
    assert_eq!(c.calls.load(Ordering::SeqCst), 0);
    assert_eq!(recs.len(), 2);
    assert!(recs.iter().all(|r| r.status == RecordStatus::Good && r.source == Source::OcspFetch && r.allowed));
    assert_eq!((recs[0].chain_index, recs[1].chain_index), (0, 1));
    assert_eq!(recs[0].ocsp_responder.as_deref(), Some("src.example.net:80"));
    // Stapled response offered for the leaf only.
    assert_eq!(*o.stapled_seen.lock().unwrap(), [(0, true), (1, false)]);
}

#[test]
fn crl_fallback_and_finality() {
    // OCSP unavailable, CRL good.
    let (o, c) = (Scripted::new(vec![NO_OCSP; 2]), Scripted::new(vec![GOOD_CRL; 2]));
    let (out, recs) = run(RevocationMode::HardFail, &o, &c, |_| {});
    assert_eq!(out, ChainOutcome::Accepted);
    assert!(recs.iter().all(|r| r.source == Source::CrlFetch && r.ocsp_reason == Some(OcspReason::NoResponder)));
    // OCSP revoked is final: CRL never consulted.
    let (o, c) = (Scripted::new(vec![revoked(Source::OcspFetch), GOOD_OCSP]), Scripted::new(vec![GOOD_CRL; 2]));
    let (out, recs) = run(RevocationMode::SoftFail, &o, &c, |_| {});
    assert_eq!(out, ChainOutcome::Revoked);
    assert_eq!(c.calls.load(Ordering::SeqCst), 0);
    assert_eq!(recs[0].revocation_reason, Some(RevocationReason::KeyCompromise));
    assert_eq!(recs[0].revocation_date_us, Some(1_000_000));
    // The intermediate after a rejected leaf is recorded, not fetched.
    assert_eq!((recs[1].status, recs[1].allowed), (RecordStatus::NotChecked, false));
    assert_eq!(o.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn attack_class_failures_are_fatal_in_every_mode() {
    for mode in [RevocationMode::HardFail, RevocationMode::SoftFail] {
        let o = Scripted::new(vec![LookupOutcome::Failed(SourceError::Ocsp(OcspReason::BadSignature)); 2]);
        let c = Scripted::new(vec![GOOD_CRL; 2]);
        let (out, recs) = run(mode, &o, &c, |_| {});
        assert_eq!(out, ChainOutcome::Fatal);
        assert_eq!(c.calls.load(Ordering::SeqCst), 0, "no fallback after a forged response");
        assert_eq!(recs[0].status, RecordStatus::Fatal);
        let o = Scripted::new(vec![NO_OCSP; 2]);
        let c = Scripted::new(vec![LookupOutcome::Failed(SourceError::Crl(CrlReason::WrongIssuer)); 2]);
        assert_eq!(run(mode, &o, &c, |_| {}).0, ChainOutcome::Fatal);
    }
}

#[test]
fn failure_policy_and_stale_data() {
    let none = || (Scripted::new(vec![NO_OCSP; 2]), Scripted::new(vec![NO_CRL; 2]));
    let (o, c) = none();
    assert_eq!(run(RevocationMode::HardFail, &o, &c, |_| {}).0, ChainOutcome::Unavailable);
    let (o, c) = none();
    let (out, recs) = run(RevocationMode::SoftFail, &o, &c, |_| {});
    assert_eq!(out, ChainOutcome::Accepted);
    assert!(recs.iter().all(|r| r.status == RecordStatus::Unavailable && r.allowed && r.source == Source::None));
    assert!(recs.iter().all(|r| r.crl_reason == Some(CrlReason::NoSource)));
    // QN2: stale data is never soft-accepted.
    let o = Scripted::new(vec![LookupOutcome::Failed(SourceError::Ocsp(OcspReason::Stale)); 2]);
    let c = Scripted::new(vec![NO_CRL; 2]);
    assert_eq!(run(RevocationMode::SoftFail, &o, &c, |_| {}).0, ChainOutcome::Unavailable);
    // Only CRL enabled: OCSP never consulted.
    let (o, c) = (Scripted::new(vec![GOOD_OCSP; 2]), Scripted::new(vec![GOOD_CRL; 2]));
    let (out, recs) = run(RevocationMode::HardFail, &o, &c, |s| s.ocsp.enabled = false);
    assert_eq!((out, o.calls.load(Ordering::SeqCst)), (ChainOutcome::Accepted, 0));
    assert!(recs.iter().all(|r| r.source == Source::CrlFetch && r.ocsp_reason.is_none()));
}

#[test]
fn revoked_intermediate_rejects_chain() {
    let o = Scripted::new(vec![GOOD_OCSP, NO_OCSP]);
    let c = Scripted::new(vec![GOOD_CRL, revoked(Source::CrlFetch)]);
    let (out, recs) = run(RevocationMode::SoftFail, &o, &c, |_| {});
    assert_eq!(out, ChainOutcome::Revoked);
    assert_eq!((recs[0].status, recs[0].allowed), (RecordStatus::Good, true));
    assert_eq!((recs[1].status, recs[1].source, recs[1].chain_index), (RecordStatus::Revoked, Source::CrlFetch, 1));
    assert!(recs[1].issuer_dn.contains("Rev Root"), "{}", recs[1].issuer_dn);
}

#[test]
fn budget_is_shared_across_the_chain() {
    let o = Arc::new(Scripted {
        outcomes: vec![NO_OCSP; 2],
        delay: Duration::from_millis(80),
        calls: AtomicUsize::new(0),
        stapled_seen: Mutex::new(vec![]),
    });
    let c = Scripted::new(vec![GOOD_CRL; 2]);
    let (out, recs) = run(RevocationMode::SoftFail, &o, &c, |s| s.budget = Duration::from_millis(50));
    // Leaf: OCSP ran (slow), then the budget was gone before CRL.
    assert_eq!(recs[0].crl_reason, Some(CrlReason::Budget));
    // Intermediate: nothing left at all.
    assert_eq!(recs[1].ocsp_reason, Some(OcspReason::Budget));
    assert_eq!(recs[1].crl_reason, Some(CrlReason::Budget));
    assert_eq!(o.calls.load(Ordering::SeqCst), 1);
    assert_eq!(c.calls.load(Ordering::SeqCst), 0);
    assert_eq!(out, ChainOutcome::Accepted, "soft_fail: no data obtainable");
}

#[test]
fn mode_off_records_not_checked() {
    let (o, c) = (Scripted::new(vec![GOOD_OCSP; 2]), Scripted::new(vec![GOOD_CRL; 2]));
    let (out, recs) = run(RevocationMode::Off, &o, &c, |_| {});
    assert_eq!(out, ChainOutcome::NotChecked);
    assert!(out.is_accepted());
    assert_eq!(recs.len(), 1);
    assert_eq!(
        (recs[0].status, recs[0].allowed, recs[0].policy),
        (RecordStatus::NotChecked, true, RevocationMode::Off)
    );
    assert_eq!(o.calls.load(Ordering::SeqCst) + c.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn path_error_rejects() {
    let f = fixture();
    let hook: plat_tls::RevocationHook = Arc::new(|_| {});
    let o = Scripted::new(vec![GOOD_OCSP; 2]);
    let c = RevocationChecker::with_sources(
        settings(RevocationMode::SoftFail),
        hook,
        Box::new(O(o.clone())),
        Box::new(C(Scripted::new(vec![GOOD_CRL; 2]))),
    )
    .unwrap();
    // Intermediate not presented: the path cannot be rebuilt.
    let v = c.check_chain(Role::SyslogServer, &f.leaf, &[], &f.anchors, None, UnixTime::now());
    assert_eq!(v.outcome, ChainOutcome::PathError);
    assert_eq!(v.records[0].status, RecordStatus::Fatal);
    assert_eq!(o.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn refresher_stops_promptly() {
    let hook: plat_tls::RevocationHook = Arc::new(|_| {});
    let c = RevocationChecker::new(settings(RevocationMode::HardFail), hook).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let t = plat_tls::spawn_refresher(c.clone(), stop.clone()).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let start = std::time::Instant::now();
    stop.store(true, Ordering::Release);
    c.notify();
    t.join().unwrap();
    assert!(start.elapsed() < Duration::from_millis(600));
}
