//! OCSP source (RFC 6960) against the in-test responder: validation,
//! failure classes and policy, cache, negative cache, single-flight,
//! GET/POST, responder override, stapling.

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use plat_common::config::{OcspCertIdHash, OcspMethod, RevocationMode};
use plat_tls::revocation::ocsp::{request, response};
use plat_tls::revocation::{
    Cert, ChainOutcome, OcspReason, RecordStatus, RevocationReason, RevocationSettings, Role, Source,
};
use rustls_pki_types::{CertificateDer, UnixTime};
use support::http_server::{HttpServer, Reply};
use support::pki::{Ca, CaOpts, LeafOpts};
use support::revoc::{self, NonceMode, OcspCfg, Rig, Signer, St, ocsp_handler, serial_of};

/// root → inter → leaf, both non-root certificates pointing at `srv`.
struct Fx {
    root: Ca,
    inter: Ca,
    leaf: CertificateDer<'static>,
    cfg: Arc<Mutex<OcspCfg>>,
    srv: HttpServer,
}

impl Fx {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(tweak: impl FnOnce(&mut OcspCfg)) -> Self {
        let cfg = Arc::new(Mutex::new(OcspCfg::default()));
        let srv = HttpServer::start(ocsp_handler(cfg.clone()));
        let url = srv.url("/ocsp");
        let root = Ca::root("OCSP Root");
        let inter = root.intermediate_opts(
            "OCSP Inter",
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &CaOpts { ocsp: vec![url.clone()], ..CaOpts::default() },
        );
        let leaf = inter.leaf(&LeafOpts { ocsp: vec![url], ..LeafOpts::client("ocsp-client") }).der;
        {
            let mut c = cfg.lock().unwrap();
            c.sign_for(&root, Signer::ca(&root));
            c.sign_for(&inter, Signer::ca(&inter));
            c.status.insert(serial_of(&inter.der), St::Good);
            c.status.insert(serial_of(&leaf), St::Good);
            tweak(&mut c);
        }
        Fx { root, inter, leaf, cfg, srv }
    }

    fn set_leaf(&self, st: St) {
        self.cfg.lock().unwrap().status.insert(serial_of(&self.leaf), st);
    }

    fn chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.inter.der.clone()]
    }

    fn run(&self, s: RevocationSettings) -> (Rig, plat_tls::revocation::ChainVerdict) {
        let rig = Rig::new(s);
        let v = rig.check(&self.leaf, &self.chain(), &revoc::anchors(&[&self.root]));
        (rig, v)
    }
}

/// OCSP only (CRL off), so OCSP failures reach the failure policy.
fn ocsp_only(mode: RevocationMode) -> RevocationSettings {
    let mut s = revoc::settings(mode);
    s.crl.enabled = false;
    s
}

#[test]
fn good_then_cached() {
    let fx = Fx::new();
    let rig = Rig::new(ocsp_only(RevocationMode::HardFail));
    let a = revoc::anchors(&[&fx.root]);
    let v = rig.check(&fx.leaf, &fx.chain(), &a);
    assert_eq!(v.outcome, ChainOutcome::Accepted, "{:?}", v.records);
    assert!(v.records.iter().all(|r| r.status == RecordStatus::Good && r.source == Source::OcspFetch));
    assert_eq!(fx.srv.count(), 2, "leaf and intermediate fetched once each");
    assert!(v.records[0].ocsp_responder.as_deref().unwrap().starts_with("127.0.0.1:"));
    let last = fx.srv.last.lock().unwrap().clone().unwrap();
    assert_eq!(last.method, "POST");
    assert!(last.headers.iter().any(|(k, v)| k == "content-type" && v == "application/ocsp-request"));

    let v = rig.check(&fx.leaf, &fx.chain(), &a);
    assert_eq!(v.outcome, ChainOutcome::Accepted);
    assert!(v.records.iter().all(|r| r.source == Source::OcspCache));
    assert_eq!(fx.srv.count(), 2, "cache hit: no second fetch");
}

#[test]
fn revoked_rejects_in_every_mode() {
    let fx = Fx::new();
    fx.set_leaf(St::Revoked(1));
    for mode in [RevocationMode::HardFail, RevocationMode::SoftFail] {
        let (_, v) = fx.run(ocsp_only(mode));
        assert_eq!(v.outcome, ChainOutcome::Revoked);
        let r = &v.records[0];
        assert_eq!((r.status, r.source), (RecordStatus::Revoked, Source::OcspFetch));
        assert_eq!(r.revocation_reason, Some(RevocationReason::KeyCompromise));
        assert!(r.revocation_date_us.is_some());
        assert_eq!(v.records[1].status, RecordStatus::NotChecked, "rest of a rejected chain is not fetched");
    }
}

#[test]
fn unknown_is_no_decision() {
    let fx = Fx::new();
    fx.set_leaf(St::Unknown);
    let (_, v) = fx.run(ocsp_only(RevocationMode::HardFail));
    assert_eq!(v.outcome, ChainOutcome::Unavailable);
    assert_eq!(v.records[0].ocsp_reason, Some(OcspReason::UnknownStatus));
    let (_, v) = fx.run(ocsp_only(RevocationMode::SoftFail));
    assert_eq!(v.outcome, ChainOutcome::Accepted);
    assert_eq!((v.records[0].status, v.records[0].source), (RecordStatus::Unavailable, Source::None));
}

#[test]
fn stale_or_future_never_soft_accepted() {
    for tweak in [
        (|c: &mut OcspCfg| {
            c.this_off = -7200;
            c.next_off = Some(-3600);
        }) as fn(&mut OcspCfg),
        |c| {
            c.this_off = 3600;
            c.next_off = Some(7200);
        },
        |c| {
            // No nextUpdate and older than max_age (3600 s).
            c.this_off = -7200;
            c.next_off = None;
        },
    ] {
        let fx = Fx::with(tweak);
        for mode in [RevocationMode::HardFail, RevocationMode::SoftFail] {
            let (_, v) = fx.run(ocsp_only(mode));
            assert_eq!(v.outcome, ChainOutcome::Unavailable, "{mode:?}");
            assert_eq!(v.records[0].ocsp_reason, Some(OcspReason::Stale));
        }
    }
    // No nextUpdate but within max_age: good.
    let fx = Fx::with(|c| c.next_off = None);
    assert_eq!(fx.run(ocsp_only(RevocationMode::HardFail)).1.outcome, ChainOutcome::Accepted);
}

fn fatal(fx: &Fx, want: OcspReason) {
    for mode in [RevocationMode::HardFail, RevocationMode::SoftFail] {
        let mut s = revoc::settings(mode);
        s.crl.enabled = true; // fatal: no CRL fallback even when enabled
        let (_, v) = fx.run(s);
        assert_eq!(v.outcome, ChainOutcome::Fatal, "{mode:?} {:?}", v.records);
        assert_eq!(v.records[0].status, RecordStatus::Fatal);
        assert_eq!(v.records[0].ocsp_reason, Some(want));
        assert_eq!(v.records[0].crl_reason, None, "CRL not consulted");
    }
}

#[test]
fn bad_signature_is_fatal() {
    fatal(&Fx::with(|c| c.corrupt_sig = true), OcspReason::BadSignature);
}

#[test]
fn cert_id_mismatch_is_fatal() {
    fatal(&Fx::with(|c| c.wrong_serial = true), OcspReason::CertIdMismatch);
}

#[test]
fn nonce_rules() {
    fatal(&Fx::with(|c| c.nonce = NonceMode::Wrong), OcspReason::NonceMismatch);
    let fx = Fx::with(|c| c.nonce = NonceMode::Omit);
    assert_eq!(fx.run(ocsp_only(RevocationMode::HardFail)).1.outcome, ChainOutcome::Accepted, "missing nonce ok");
    let mut s = ocsp_only(RevocationMode::SoftFail);
    s.ocsp.require_nonce = true;
    let (_, v) = fx.run(s);
    assert_eq!((v.outcome, v.records[0].ocsp_reason), (ChainOutcome::Fatal, Some(OcspReason::NonceMismatch)));
    // Echoed nonce with require_nonce: good.
    let fx = Fx::new();
    let mut s = ocsp_only(RevocationMode::HardFail);
    s.ocsp.require_nonce = true;
    assert_eq!(fx.run(s).1.outcome, ChainOutcome::Accepted);
}

#[test]
fn delegated_responders() {
    // Authorized: issued by the leaf's issuer, id-kp-OCSPSigning.
    let fx = Fx::new();
    let d = fx.inter.responder("Inter OCSP Signer", true);
    fx.cfg.lock().unwrap().signers.retain(|_| false);
    {
        let mut c = fx.cfg.lock().unwrap();
        c.sign_for(&fx.root, Signer::ca(&fx.root));
        c.sign_for(&fx.inter, Signer::delegate(&d));
    }
    assert_eq!(fx.run(ocsp_only(RevocationMode::HardFail)).1.outcome, ChainOutcome::Accepted);

    // No OCSPSigning EKU.
    let no_eku = fx.inter.responder("No EKU", false);
    fx.cfg.lock().unwrap().signers.retain(|_| false);
    {
        let mut c = fx.cfg.lock().unwrap();
        c.sign_for(&fx.root, Signer::ca(&fx.root));
        c.sign_for(&fx.inter, Signer::delegate(&no_eku));
    }
    fatal(&fx, OcspReason::UnauthorizedResponder);

    // Issued by another CA (with the EKU).
    let other = Ca::root("Other OCSP Root").responder("Foreign Signer", true);
    fx.cfg.lock().unwrap().signers.retain(|_| false);
    {
        let mut c = fx.cfg.lock().unwrap();
        c.sign_for(&fx.root, Signer::ca(&fx.root));
        c.sign_for(&fx.inter, Signer::delegate(&other));
    }
    fatal(&fx, OcspReason::UnauthorizedResponder);
}

#[test]
fn transport_failures_are_unavailable() {
    let replies: Vec<(Reply, OcspReason)> = vec![
        (Reply::Ok { status: 500, content_type: "text/plain".into(), body: b"x".to_vec() }, OcspReason::HttpStatus),
        (Reply::ok("text/html", b"<html>".to_vec()), OcspReason::ContentType),
        (Reply::ok("application/ocsp-response", vec![0u8; 17 * 1024]), OcspReason::TooLarge),
        (Reply::ok("application/ocsp-response", b"\x30\x03\x0a\x01\x00".to_vec()), OcspReason::Malformed),
        (Reply::Close, OcspReason::Malformed),
        (Reply::Delay(Duration::from_millis(1500), Box::new(Reply::Close)), OcspReason::Timeout),
    ];
    for (reply, want) in replies {
        let srv = HttpServer::start(move |_| reply.clone());
        let url = srv.url("/");
        let root = Ca::root("T Root");
        let leaf = root.leaf(&LeafOpts { ocsp: vec![url], ..LeafOpts::client("t") }).der;
        let a = revoc::anchors(&[&root]);
        let rig = Rig::new(ocsp_only(RevocationMode::HardFail));
        let v = rig.check(&leaf, &[], &a);
        assert_eq!((v.outcome, v.records[0].ocsp_reason), (ChainOutcome::Unavailable, Some(want)));
        // Soft-fail accepts (no data at all), recorded as source none.
        let rig = Rig::new(ocsp_only(RevocationMode::SoftFail));
        let v = rig.check(&leaf, &[], &a);
        assert_eq!((v.outcome, v.records[0].source), (ChainOutcome::Accepted, Source::None));
    }
    // Connection refused.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let root = Ca::root("T Root");
    let leaf = root.leaf(&LeafOpts { ocsp: vec![format!("http://127.0.0.1:{port}/")], ..LeafOpts::client("t") }).der;
    let v = Rig::new(ocsp_only(RevocationMode::HardFail)).check(&leaf, &[], &revoc::anchors(&[&root]));
    assert_eq!(v.records[0].ocsp_reason, Some(OcspReason::Connect));
    // No responder at all.
    let leaf = root.leaf(&LeafOpts::client("no-aia")).der;
    let v = Rig::new(ocsp_only(RevocationMode::HardFail)).check(&leaf, &[], &revoc::anchors(&[&root]));
    assert_eq!(v.records[0].ocsp_reason, Some(OcspReason::NoResponder));
}

#[test]
fn negative_cache() {
    let srv = HttpServer::start(|_| Reply::Ok { status: 503, content_type: "x/y".into(), body: Vec::new() });
    let root = Ca::root("Neg Root");
    let leaf = root.leaf(&LeafOpts { ocsp: vec![srv.url("/")], ..LeafOpts::client("n") }).der;
    let a = revoc::anchors(&[&root]);
    let rig = Rig::new(ocsp_only(RevocationMode::HardFail));
    rig.check(&leaf, &[], &a);
    rig.check(&leaf, &[], &a);
    assert_eq!(srv.count(), 1, "failure cached for 10 s");
    rig.check_at(Role::MgmtClient, &leaf, &[], &a, None, revoc::at(11));
    assert_eq!(srv.count(), 2, "negative entry expired");
}

#[test]
fn cache_bound_evicts() {
    let fx = Fx::new();
    let mut s = ocsp_only(RevocationMode::HardFail);
    s.ocsp.cache_entries = 1;
    let rig = Rig::new(s);
    let a = revoc::anchors(&[&fx.root]);
    rig.check(&fx.leaf, &fx.chain(), &a);
    rig.check(&fx.leaf, &fx.chain(), &a);
    // One slot for two certificates: each check evicts the other entry.
    assert_eq!(fx.srv.count(), 4);
}

#[test]
fn single_flight() {
    let fx = Fx::new();
    let slow = fx.cfg.clone();
    let srv = HttpServer::start(move |r| {
        let c = slow.lock().unwrap().clone();
        Reply::Delay(
            Duration::from_millis(300),
            Box::new(Reply::ok("application/ocsp-response", revoc::respond(&c, &revoc::request_der(r)))),
        )
    });
    let root = &fx.root;
    let leaf = fx.inter.leaf(&LeafOpts { ocsp: vec![srv.url("/")], ..LeafOpts::client("sf") }).der;
    fx.cfg.lock().unwrap().status.insert(serial_of(&leaf), St::Good);
    let mut s = ocsp_only(RevocationMode::HardFail);
    s.ocsp.responder_url = None;
    let rig = Arc::new(Rig::new(s));
    let a = revoc::anchors(&[root]);
    // Intermediate answered from the fast responder first.
    rig.check(&fx.leaf, &fx.chain(), &a);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (rig, leaf, chain, a) = (rig.clone(), leaf.clone(), fx.chain(), a.clone());
            std::thread::spawn(move || rig.check(&leaf, &chain, &a).outcome)
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap(), ChainOutcome::Accepted);
    }
    assert_eq!(srv.count(), 1, "8 concurrent checks, one fetch");
}

#[test]
fn get_method_and_sha1_cert_id() {
    let fx = Fx::new();
    let mut s = ocsp_only(RevocationMode::HardFail);
    s.ocsp.method = OcspMethod::Get;
    s.ocsp.cert_id_hash = OcspCertIdHash::Sha1;
    let (_, v) = fx.run(s);
    assert_eq!(v.outcome, ChainOutcome::Accepted, "{:?}", v.records);
    let last = fx.srv.last.lock().unwrap().clone().unwrap();
    assert_eq!(last.method, "GET");
    assert!(last.path.starts_with("/ocsp/M"), "{}", last.path);
}

#[test]
fn responder_url_applies_to_leaf_only() {
    let fx = Fx::new();
    let cfg = fx.cfg.clone();
    let pinned = HttpServer::start(ocsp_handler(cfg));
    let mut s = ocsp_only(RevocationMode::HardFail);
    s.ocsp.responder_url = Some(pinned.url("/pinned"));
    let (_, v) = fx.run(s);
    assert_eq!(v.outcome, ChainOutcome::Accepted);
    assert_eq!((pinned.count(), fx.srv.count()), (1, 1), "leaf → pinned, intermediate → AIA");
    // use_aia = false: intermediate has no responder.
    let mut s = ocsp_only(RevocationMode::HardFail);
    s.ocsp.responder_url = Some(pinned.url("/pinned"));
    s.ocsp.use_aia = false;
    let (_, v) = fx.run(s);
    assert_eq!(v.records[1].ocsp_reason, Some(OcspReason::NoResponder));
}

#[test]
fn stapled_response() {
    let fx = Fx::new();
    let a = revoc::anchors(&[&fx.root]);
    let leaf_cert = Cert::parse(&fx.leaf).unwrap();
    let inter_cert = Cert::parse(&fx.inter.der).unwrap();
    let staple_for = |st: St, tweak: fn(&mut OcspCfg)| {
        let req = request::build(&leaf_cert, &inter_cert, OcspCertIdHash::Sha256, false).unwrap();
        let mut c = fx.cfg.lock().unwrap().clone();
        c.status.insert(serial_of(&fx.leaf), st);
        tweak(&mut c);
        revoc::respond(&c, &req.der)
    };
    let rig = Rig::new(ocsp_only(RevocationMode::HardFail));
    let good = staple_for(St::Good, |_| {});
    let v = rig.check_at(Role::SyslogServer, &fx.leaf, &fx.chain(), &a, Some(&good), UnixTime::now());
    assert_eq!(v.outcome, ChainOutcome::Accepted);
    assert_eq!(v.records[0].source, Source::OcspStapled);
    assert_eq!(v.records[1].source, Source::OcspFetch, "intermediates never use the staple");
    assert_eq!(fx.srv.count(), 1);

    let rig = Rig::new(ocsp_only(RevocationMode::HardFail));
    let revoked = staple_for(St::Revoked(4), |_| {});
    let v = rig.check_at(Role::SyslogServer, &fx.leaf, &fx.chain(), &a, Some(&revoked), UnixTime::now());
    assert_eq!((v.outcome, v.records[0].source), (ChainOutcome::Revoked, Source::OcspStapled));

    // Stale staple: falls through to a fetch.
    let rig = Rig::new(ocsp_only(RevocationMode::HardFail));
    let stale = staple_for(St::Good, |c| {
        c.this_off = -7200;
        c.next_off = Some(-3600);
    });
    let v = rig.check_at(Role::SyslogServer, &fx.leaf, &fx.chain(), &a, Some(&stale), UnixTime::now());
    assert_eq!((v.outcome, v.records[0].source), (ChainOutcome::Accepted, Source::OcspFetch));

    // Forged staple: fatal.
    let forged = staple_for(St::Good, |c| c.corrupt_sig = true);
    let v = rig.check_at(Role::SyslogServer, &fx.leaf, &fx.chain(), &a, Some(&forged), UnixTime::now());
    assert_eq!((v.outcome, v.records[0].ocsp_reason), (ChainOutcome::Fatal, Some(OcspReason::BadSignature)));
}

#[test]
fn slow_responder_does_not_block_other_checks() {
    let slow = HttpServer::start(|_| Reply::Delay(Duration::from_millis(900), Box::new(Reply::Close)));
    let fx = Fx::new();
    let slow_leaf = fx.inter.leaf(&LeafOpts { ocsp: vec![slow.url("/")], ..LeafOpts::client("slow") }).der;
    let rig = Arc::new(Rig::new(ocsp_only(RevocationMode::SoftFail)));
    let a = revoc::anchors(&[&fx.root]);
    rig.check(&fx.leaf, &fx.chain(), &a); // warm the intermediate
    let (r2, chain, a2) = (rig.clone(), fx.chain(), a.clone());
    let t = std::thread::spawn(move || r2.check(&slow_leaf, &chain, &a2));
    std::thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    assert_eq!(rig.check(&fx.leaf, &fx.chain(), &a).outcome, ChainOutcome::Accepted);
    assert!(start.elapsed() < Duration::from_millis(300), "{:?}", start.elapsed());
    t.join().unwrap();
}

proptest::proptest! {
    #[test]
    fn response_parser_never_panics(raw in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)) {
        let root = ROOT.with(|r| r.clone());
        let id = request::cert_id(&root, &root, OcspCertIdHash::Sha256).unwrap();
        let e = response::Expect { cert_id: &id, nonce: None, require_nonce: false, now: 0, skew: 0, max_age: 0 };
        let _ = response::verify(&raw, &root, &e);
    }
}

thread_local! {
    static ROOT: Cert = Cert::parse(&Ca::root("Prop Root").der).unwrap();
}
