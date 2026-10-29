//! CRL source (RFC 5280 §5, §6.3) against the in-test CDP server:
//! verification, unsupported features, policy, size caps, configured
//! files, the on-disk cache and the memory bound.

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use std::sync::{Arc, Mutex};

use plat_common::config::RevocationMode;
use plat_tls::revocation::{ChainOutcome, CrlReason, RecordStatus, RevocationReason, RevocationSettings, Source};
use rustls_pki_types::CertificateDer;
use support::http_server::{HttpServer, Reply};
use support::pki::{Ca, CaOpts, LeafOpts, TempDir};
use support::revoc::{self, CrlOpts, Rig, crl_handler, serial_of};

/// root → leaf with a CDP pointing at `srv`, which serves `body`.
struct Fx {
    root: Ca,
    leaf: CertificateDer<'static>,
    body: Arc<Mutex<Vec<u8>>>,
    srv: HttpServer,
}

impl Fx {
    fn new() -> Self {
        let body = Arc::new(Mutex::new(Vec::new()));
        let srv = HttpServer::start(crl_handler(body.clone()));
        let root = Ca::root("CRL Root");
        let leaf = root.leaf(&LeafOpts { cdp: vec![srv.url("/root.crl")], ..LeafOpts::client("crl-client") }).der;
        Fx { root, leaf, body, srv }
    }

    fn serve(&self, der: Vec<u8>) {
        *self.body.lock().unwrap() = der;
    }

    fn serve_opts(&self, o: &CrlOpts) {
        self.serve(revoc::crl(&self.root, o));
    }

    fn revoked_leaf(&self) -> CrlOpts {
        CrlOpts { revoked: vec![(serial_of(&self.leaf), Some(1))], ..CrlOpts::default() }
    }

    fn check(&self, s: RevocationSettings) -> plat_tls::revocation::ChainVerdict {
        Rig::new(s).check(&self.leaf, &[], &revoc::anchors(&[&self.root]))
    }
}

/// CRL only (OCSP off).
fn crl_only(mode: RevocationMode) -> RevocationSettings {
    let mut s = revoc::settings(mode);
    s.ocsp.enabled = false;
    s
}

fn unusable(fx: &Fx, want: CrlReason) {
    let v = fx.check(crl_only(RevocationMode::HardFail));
    assert_eq!((v.outcome, v.records[0].crl_reason), (ChainOutcome::Unavailable, Some(want)), "{:?}", v.records);
}

#[test]
fn good_and_cached() {
    let fx = Fx::new();
    fx.serve_opts(&CrlOpts { revoked: vec![(vec![0x01, 0x02], Some(1))], ..CrlOpts::default() });
    let rig = Rig::new(crl_only(RevocationMode::HardFail));
    let a = revoc::anchors(&[&fx.root]);
    let v = rig.check(&fx.leaf, &[], &a);
    assert_eq!(v.outcome, ChainOutcome::Accepted, "{:?}", v.records);
    assert_eq!((v.records[0].status, v.records[0].source), (RecordStatus::Good, Source::CrlFetch));
    assert!(v.records[0].crl_source.as_deref().unwrap().starts_with("127.0.0.1:"));
    let v = rig.check(&fx.leaf, &[], &a);
    assert_eq!(v.records[0].source, Source::CrlCache);
    assert_eq!(fx.srv.count(), 1);
    let req = fx.srv.last.lock().unwrap().clone().unwrap();
    assert!(req.headers.iter().any(|(k, v)| k == "accept" && v == "application/pkix-crl"));
}

#[test]
fn revoked_rejects_in_every_mode() {
    let fx = Fx::new();
    fx.serve_opts(&fx.revoked_leaf());
    for mode in [RevocationMode::HardFail, RevocationMode::SoftFail] {
        let v = fx.check(crl_only(mode));
        assert_eq!(v.outcome, ChainOutcome::Revoked);
        assert_eq!(v.records[0].revocation_reason, Some(RevocationReason::KeyCompromise));
    }
}

#[test]
fn stale_rejected_even_in_soft_fail() {
    let fx = Fx::new();
    fx.serve_opts(&CrlOpts { this_off: -7200, next_off: Some(-3600), ..CrlOpts::default() });
    for mode in [RevocationMode::HardFail, RevocationMode::SoftFail] {
        let v = fx.check(crl_only(mode));
        assert_eq!((v.outcome, v.records[0].crl_reason), (ChainOutcome::Unavailable, Some(CrlReason::Stale)));
    }
}

#[test]
fn missing_next_update_is_unusable() {
    let fx = Fx::new();
    fx.serve_opts(&CrlOpts { next_off: None, ..CrlOpts::default() });
    unusable(&fx, CrlReason::NoNextUpdate);
}

#[test]
fn forged_crls_are_fatal() {
    let fx = Fx::new();
    // Bad signature (right issuer name).
    fx.serve_opts(&CrlOpts { corrupt_sig: true, ..CrlOpts::default() });
    for mode in [RevocationMode::HardFail, RevocationMode::SoftFail] {
        let v = fx.check(crl_only(mode));
        assert_eq!((v.outcome, v.records[0].crl_reason), (ChainOutcome::Fatal, Some(CrlReason::BadSignature)));
    }
    // Same issuer name, different key.
    let imposter = Ca::root("CRL Root");
    fx.serve(revoc::crl(&imposter, &CrlOpts::default()));
    let v = fx.check(crl_only(RevocationMode::SoftFail));
    assert_eq!((v.outcome, v.records[0].crl_reason), (ChainOutcome::Fatal, Some(CrlReason::BadSignature)));
    // Another CA's CRL from this certificate's CDP.
    let other = Ca::root("Other CRL Root");
    fx.serve(revoc::crl(&other, &CrlOpts::default()));
    let v = fx.check(crl_only(RevocationMode::SoftFail));
    assert_eq!((v.outcome, v.records[0].crl_reason), (ChainOutcome::Fatal, Some(CrlReason::WrongIssuer)));
}

#[test]
fn issuer_without_crl_sign() {
    let body = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpServer::start(crl_handler(body.clone()));
    let root = Ca::root("KU Root");
    let inter = root.intermediate_opts(
        "KU Inter",
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &CaOpts { no_crl_sign: true, ..CaOpts::default() },
    );
    let leaf = inter.leaf(&LeafOpts { cdp: vec![srv.url("/")], ..LeafOpts::client("ku") }).der;
    *body.lock().unwrap() = revoc::crl(&inter, &CrlOpts::default());
    let mut s = crl_only(RevocationMode::HardFail);
    s.crl.use_cdp = true;
    let v = Rig::new(s).check(&leaf, std::slice::from_ref(&inter.der), &revoc::anchors(&[&root]));
    assert_eq!(v.records[0].crl_reason, Some(CrlReason::NoCrlSign));
}

#[test]
fn unsupported_features_are_unusable() {
    let fx = Fx::new();
    let cases: Vec<(CrlOpts, CrlReason)> = vec![
        (CrlOpts { delta: true, ..CrlOpts::default() }, CrlReason::Delta),
        (CrlOpts { indirect: true, ..CrlOpts::default() }, CrlReason::Indirect),
        (
            CrlOpts { revoked: vec![(vec![9], None)], entry_cert_issuer: true, ..CrlOpts::default() },
            CrlReason::Indirect,
        ),
        (CrlOpts { only_some_reasons: true, ..CrlOpts::default() }, CrlReason::ScopeMismatch),
        (CrlOpts { only_ca: true, ..CrlOpts::default() }, CrlReason::ScopeMismatch),
        (
            CrlOpts { idp_uri: Some("http://elsewhere.invalid/x.crl".into()), ..CrlOpts::default() },
            CrlReason::ScopeMismatch,
        ),
        (CrlOpts { unknown_critical: true, ..CrlOpts::default() }, CrlReason::CriticalExt),
        (CrlOpts { revoked: vec![(vec![9], Some(8))], ..CrlOpts::default() }, CrlReason::Malformed),
        // RFC-005: duplicate extension.
        (CrlOpts { dup_number: true, ..CrlOpts::default() }, CrlReason::Malformed),
        // RFC-003: future-dated thisUpdate is not yet valid, not stale.
        (CrlOpts { this_off: 7200, ..CrlOpts::default() }, CrlReason::NotYetValid),
    ];
    for (o, want) in cases {
        fx.serve_opts(&o);
        unusable(&fx, want);
    }
    // Matching IDP name and onlyContainsUserCerts for a leaf: usable.
    fx.serve_opts(&CrlOpts { idp_uri: Some(fx.srv.url("/root.crl")), only_user: true, ..CrlOpts::default() });
    assert_eq!(fx.check(crl_only(RevocationMode::HardFail)).outcome, ChainOutcome::Accepted);
}

#[test]
fn size_caps() {
    // Declared too large: refused before reading the body.
    let srv = HttpServer::start(|_| {
        Reply::Raw(
            b"HTTP/1.0 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: 99999999\r\n\r\n".to_vec(),
        )
    });
    let root = Ca::root("Big Root");
    let leaf = root.leaf(&LeafOpts { cdp: vec![srv.url("/")], ..LeafOpts::client("big") }).der;
    let mut s = crl_only(RevocationMode::HardFail);
    s.crl.max_bytes = 4096;
    let v = Rig::new(s.clone()).check(&leaf, &[], &revoc::anchors(&[&root]));
    assert_eq!(v.records[0].crl_reason, Some(CrlReason::TooLarge));
    // Undeclared and too large while reading.
    let srv = HttpServer::start(|_| {
        let mut b = b"HTTP/1.0 200 OK\r\nContent-Type: application/pkix-crl\r\n\r\n".to_vec();
        b.extend(std::iter::repeat_n(0x30u8, 8192));
        Reply::Raw(b)
    });
    let leaf = root.leaf(&LeafOpts { cdp: vec![srv.url("/")], ..LeafOpts::client("big2") }).der;
    let v = Rig::new(s).check(&leaf, &[], &revoc::anchors(&[&root]));
    assert_eq!(v.records[0].crl_reason, Some(CrlReason::TooLarge));
}

#[test]
fn cdp_unavailable() {
    let srv = HttpServer::start(|_| Reply::Ok { status: 404, content_type: "text/plain".into(), body: Vec::new() });
    let root = Ca::root("404 Root");
    let leaf = root.leaf(&LeafOpts { cdp: vec![srv.url("/")], ..LeafOpts::client("nf") }).der;
    let a = revoc::anchors(&[&root]);
    let v = Rig::new(crl_only(RevocationMode::HardFail)).check(&leaf, &[], &a);
    assert_eq!((v.outcome, v.records[0].crl_reason), (ChainOutcome::Unavailable, Some(CrlReason::HttpStatus)));
    let v = Rig::new(crl_only(RevocationMode::SoftFail)).check(&leaf, &[], &a);
    assert_eq!((v.outcome, v.records[0].source), (ChainOutcome::Accepted, Source::None));
    // No CDP and nothing configured.
    let leaf = root.leaf(&LeafOpts::client("no-cdp")).der;
    let v = Rig::new(crl_only(RevocationMode::HardFail)).check(&leaf, &[], &a);
    assert_eq!(v.records[0].crl_reason, Some(CrlReason::NoSource));
}

#[test]
fn configured_files_der_and_pem() {
    let dir = TempDir::new("crlfiles");
    let root = Ca::root("File Root");
    let other = Ca::root("Unrelated File Root");
    let leaf = root.leaf(&LeafOpts::client("file")).der;
    let revoked = root.leaf(&LeafOpts::client("file-revoked")).der;
    let der = revoc::crl(&root, &CrlOpts { revoked: vec![(serial_of(&revoked), Some(4))], ..CrlOpts::default() });
    let pem_text =
        format!("-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----\n", b64(&revoc::crl(&root, &CrlOpts::default())));
    let der_path = dir.path().join("root.crl");
    std::fs::write(&der_path, &der).unwrap();
    let pem_path = dir.write("root.pem", &pem_text, 0o644);
    let other_path = dir.path().join("other.crl");
    std::fs::write(&other_path, revoc::crl(&other, &CrlOpts::default())).unwrap();
    let a = revoc::anchors(&[&root]);
    for p in [der_path.clone(), pem_path] {
        let mut s = crl_only(RevocationMode::HardFail);
        s.crl.files = vec![other_path.clone(), p];
        let rig = Rig::new(s);
        let v = rig.check(&leaf, &[], &a);
        assert_eq!((v.outcome, v.records[0].source), (ChainOutcome::Accepted, Source::CrlFile), "{:?}", v.records);
        assert!(v.records[0].crl_source.as_deref().unwrap().starts_with("root."));
        assert_eq!(rig.check(&leaf, &[], &a).records[0].source, Source::CrlFile);
    }
    let mut s = crl_only(RevocationMode::HardFail);
    s.crl.files = vec![der_path];
    assert_eq!(Rig::new(s).check(&revoked, &[], &a).outcome, ChainOutcome::Revoked);
    // An unreadable configured file fails start.
    let mut s = crl_only(RevocationMode::HardFail);
    s.crl.files = vec![dir.path().join("missing.crl")];
    assert!(plat_tls::RevocationChecker::new(s, Arc::new(|_: &plat_tls::RevocationRecord| {})).is_err());
}

fn b64(d: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in d.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            o.push(if i <= c.len() { char::from(T[((v >> (18 - 6 * i)) & 63) as usize]) } else { '=' });
        }
    }
    o
}

fn cache_files(dir: &TempDir) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "crl"))
        .collect()
}

#[test]
fn disk_cache_persists_and_reverifies() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("crlcache");
    let fx = Fx::new();
    fx.serve_opts(&CrlOpts::default());
    let mut s = crl_only(RevocationMode::HardFail);
    s.cache_dir = Some(dir.path().to_path_buf());
    let a = revoc::anchors(&[&fx.root]);
    assert_eq!(Rig::new(s.clone()).check(&fx.leaf, &[], &a).records[0].source, Source::CrlFetch);
    let files = cache_files(&dir);
    assert_eq!(files.len(), 1);
    assert_eq!(std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777, 0o600);

    // Restart during a CDP outage: the persisted CRL is re-verified and used.
    fx.serve(Vec::new());
    let v = Rig::new(s.clone()).check(&fx.leaf, &[], &a);
    assert_eq!((v.outcome, v.records[0].source), (ChainOutcome::Accepted, Source::CrlCache), "{:?}", v.records);
    assert_eq!(fx.srv.count(), 1, "no fetch after restart");

    // Tampered (signature byte flipped): deleted on use, never fatal.
    let mut der = std::fs::read(&files[0]).unwrap();
    let n = der.len() - 3;
    der[n] ^= 0x55;
    std::fs::write(&files[0], &der).unwrap();
    let v = Rig::new(s.clone()).check(&fx.leaf, &[], &a);
    assert_eq!(v.outcome, ChainOutcome::Unavailable);
    assert_ne!(v.records[0].crl_reason, Some(CrlReason::BadSignature));
    assert!(cache_files(&dir).is_empty(), "tampered file deleted");

    // Stale file: deleted at load.
    std::fs::write(
        &files[0],
        revoc::crl(&fx.root, &CrlOpts { this_off: -7200, next_off: Some(-3600), ..CrlOpts::default() }),
    )
    .unwrap();
    let _rig = Rig::new(s);
    assert!(cache_files(&dir).is_empty(), "stale file deleted at start");
}

#[test]
fn memory_bound_evicts() {
    let fx = Fx::new();
    fx.serve_opts(&CrlOpts::default());
    let body2 = Arc::new(Mutex::new(Vec::new()));
    let srv2 = HttpServer::start(crl_handler(body2.clone()));
    let root2 = Ca::root("CRL Root 2");
    let leaf2 = root2.leaf(&LeafOpts { cdp: vec![srv2.url("/")], ..LeafOpts::client("two") }).der;
    *body2.lock().unwrap() = revoc::crl(&root2, &CrlOpts::default());
    let mut s = crl_only(RevocationMode::HardFail);
    s.crl.max_crls = 1;
    let rig = Rig::new(s);
    let a = revoc::anchors(&[&fx.root, &root2]);
    rig.check(&fx.leaf, &[], &a);
    rig.check(&leaf2, &[], &a);
    let v = rig.check(&fx.leaf, &[], &a);
    assert_eq!(v.records[0].source, Source::CrlFetch, "evicted by the bound, fetched again");
    assert_eq!((fx.srv.count(), srv2.count()), (2, 1));
}

/// RFC-001 / RFC 5280 §6.3.3(b)(2)(i): a CRL whose IDP names partition A
/// must not decide for a certificate in partition B, whether it came from
/// `crl.files` or `crl.urls`.
#[test]
fn partitioned_crl_never_answers_for_another_partition() {
    const A: &str = "http://pki.example.invalid/a.crl";
    const B: &str = "http://pki.example.invalid/b.crl";
    let root = Ca::root("Partition Root");
    let in_a = root.leaf(&LeafOpts { cdp: vec![A.into()], ..LeafOpts::client("part-a") }).der;
    let in_b = root.leaf(&LeafOpts { cdp: vec![B.into()], ..LeafOpts::client("part-b") }).der;
    let no_cdp = root.leaf(&LeafOpts::client("part-none")).der;
    let crl_a = revoc::crl(&root, &CrlOpts { idp_uri: Some(A.into()), ..CrlOpts::default() });
    let a = revoc::anchors(&[&root]);
    let check = |s: &RevocationSettings, leaf: &CertificateDer<'static>| {
        let v = Rig::new(s.clone()).check(leaf, &[], &a);
        (v.outcome, v.records[0].crl_reason)
    };
    let scope = (ChainOutcome::Unavailable, Some(CrlReason::ScopeMismatch));

    // Via crl.files.
    let dir = TempDir::new("crlpart");
    let p = dir.path().join("a.crl");
    std::fs::write(&p, &crl_a).unwrap();
    let mut s = crl_only(RevocationMode::HardFail);
    s.crl.use_cdp = false;
    s.crl.files = vec![p];
    assert_eq!(check(&s, &in_a).0, ChainOutcome::Accepted);
    assert_eq!(check(&s, &in_b), scope);
    assert_eq!(check(&s, &no_cdp), scope);

    // Via crl.urls.
    let body = Arc::new(Mutex::new(crl_a));
    let srv = HttpServer::start(crl_handler(body));
    let mut s = crl_only(RevocationMode::HardFail);
    s.crl.use_cdp = false;
    s.crl.urls = vec![srv.url("/a.crl")];
    assert_eq!(check(&s, &in_a).0, ChainOutcome::Accepted);
    assert_eq!(check(&s, &in_b), scope);
    assert_eq!(check(&s, &no_cdp), scope);
}

/// Runs `f` on a thread; fails if it does not finish within 3 s, then
/// unblocks any FIFO in `fifos` so the process can exit.
fn finishes<F: FnOnce() + Send + 'static>(f: F, fifos: &[std::path::PathBuf]) -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    let ok = rx.recv_timeout(std::time::Duration::from_secs(3)).is_ok();
    if !ok {
        for p in fifos {
            let _ = std::fs::OpenOptions::new().write(true).open(p);
        }
    }
    ok
}

fn mkfifo(p: &std::path::Path) {
    assert!(std::process::Command::new("mkfifo").arg(p).status().unwrap().success());
}

/// SEC-002: a FIFO in `crl.files` fails start instead of hanging.
#[test]
fn fifo_crl_file_does_not_hang() {
    let dir = TempDir::new("crlfifo");
    let p = dir.path().join("root.crl");
    mkfifo(&p);
    let mut s = crl_only(RevocationMode::HardFail);
    s.crl.files = vec![p.clone()];
    let ok = finishes(
        move || {
            assert!(plat_tls::RevocationChecker::new(s, Arc::new(|_: &plat_tls::RevocationRecord| {})).is_err());
        },
        &[p],
    );
    assert!(ok, "start hung on a FIFO in crl.files");
}

/// SEC-002: a FIFO in `cache_dir` is skipped (and removed) at load.
#[test]
fn fifo_in_cache_dir_does_not_hang() {
    let dir = TempDir::new("crlcachefifo");
    let p = dir.path().join(format!("{}.crl", "ab".repeat(32)));
    mkfifo(&p);
    let mut s = crl_only(RevocationMode::HardFail);
    s.cache_dir = Some(dir.path().to_path_buf());
    let ok = finishes(
        move || {
            let _rig = Rig::new(s);
        },
        std::slice::from_ref(&p),
    );
    assert!(ok, "cache load hung on a FIFO");
    assert!(!p.exists(), "unusable FIFO removed");
}

/// SEC-005: the highest cRLNumber per issuer + scope survives a restart
/// (cache_dir), so an older or unnumbered CRL served afterwards is refused
/// as a rollback.
#[test]
fn crl_number_high_water_mark_persists() {
    let dir = TempDir::new("crlhwm");
    let fx = Fx::new();
    fx.serve_opts(&CrlOpts { number: 5, ..CrlOpts::default() });
    let mut s = crl_only(RevocationMode::HardFail);
    s.cache_dir = Some(dir.path().to_path_buf());
    let a = revoc::anchors(&[&fx.root]);
    let rig = Rig::new(s.clone());
    assert_eq!(rig.check(&fx.leaf, &[], &a).outcome, ChainOutcome::Accepted);
    assert!(dir.path().join("crl-numbers").exists());
    // SI-4: one successful CRL fetch, one issuer with a future nextUpdate.
    let (ocsp, crl) = rig.c.fetch_stats();
    assert_eq!(ocsp.map(|h| h.buckets[0][9]), Some(0));
    let crl = crl.unwrap();
    assert_eq!((crl.buckets[0][9], crl.buckets[1][9]), (1, 0));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let nu = rig.c.crl_next_update(now);
    assert_eq!(nu.len(), 1);
    assert_eq!(nu[0].0.len(), 16);
    assert!(nu[0].1 > 0, "{nu:?}");
    drop(rig);
    // Restart without the cached CRL itself: only the mark remains.
    for f in cache_files(&dir) {
        std::fs::remove_file(f).unwrap();
    }
    for old in [CrlOpts { number: 3, ..CrlOpts::default() }, CrlOpts { no_number: true, ..CrlOpts::default() }] {
        fx.serve_opts(&old);
        let v = Rig::new(s.clone()).check(&fx.leaf, &[], &a);
        assert_eq!((v.outcome, v.records[0].crl_reason), (ChainOutcome::Unavailable, Some(CrlReason::Rollback)));
    }
    fx.serve_opts(&CrlOpts { number: 6, ..CrlOpts::default() });
    assert_eq!(Rig::new(s).check(&fx.leaf, &[], &a).outcome, ChainOutcome::Accepted);
}

/// SEC-102 / SEC-103 / NIST-102: an unusable `crl-numbers` is reported at
/// start, a failed write is counted and audited once, and the next new
/// high is written once the path is usable again.
#[test]
fn crl_number_state_problems_are_surfaced() {
    use plat_tls::revocation::RefreshTransition;
    let dir = TempDir::new("crlhwmerr");
    let blocker = dir.path().join("crl-numbers");
    std::fs::create_dir(&blocker).unwrap();
    std::fs::write(blocker.join("x"), b"x").unwrap();
    let fx = Fx::new();
    fx.serve_opts(&CrlOpts { number: 5, ..CrlOpts::default() });
    let mut s = crl_only(RevocationMode::HardFail);
    s.cache_dir = Some(dir.path().to_path_buf());
    let a = revoc::anchors(&[&fx.root]);
    let rig = Rig::new(s.clone());
    // SEC-304: a non-regular path is not moved aside; it stays in place
    // and so blocks the first write.
    assert!(
        std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with("crl-numbers.rejected."))
    );
    assert!(blocker.join("x").is_file());
    assert_eq!(rig.check(&fx.leaf, &[], &a).outcome, ChainOutcome::Accepted);
    let tr: Vec<_> = rig.refresh.lock().unwrap().iter().map(|r| (r.transition, r.source.clone(), r.reason)).collect();
    assert!(tr.contains(&(RefreshTransition::StateRejected, "crl-numbers".into(), Some("state_unreadable"))), "{tr:?}");
    assert!(
        tr.contains(&(RefreshTransition::StatePersistFailed, "crl-numbers".into(), Some("state_write_failed"))),
        "{tr:?}"
    );
    assert_eq!(rig.c.cache_stats().crl_state_errors, 2);
    // Path usable again: the next new high persists (no stale temp files).
    std::fs::remove_dir_all(&blocker).unwrap();
    fx.serve_opts(&CrlOpts { number: 6, ..CrlOpts::default() });
    for f in cache_files(&dir) {
        std::fs::remove_file(f).unwrap();
    }
    let rig2 = Rig::new(s.clone());
    assert_eq!(rig2.check(&fx.leaf, &[], &a).outcome, ChainOutcome::Accepted);
    assert!(blocker.is_file());
    assert!(
        std::fs::read_dir(dir.path()).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".tmp"))
    );
    // Bad lines are reported but good lines still apply.
    let good = std::fs::read_to_string(&blocker).unwrap();
    std::fs::write(&blocker, format!("garbage\n{good}")).unwrap();
    for f in cache_files(&dir) {
        std::fs::remove_file(f).unwrap();
    }
    fx.serve_opts(&CrlOpts { number: 3, ..CrlOpts::default() });
    let rig3 = Rig::new(s);
    let v = rig3.check(&fx.leaf, &[], &a);
    assert_eq!(v.records[0].crl_reason, Some(CrlReason::Rollback));
    assert!(rig3.refresh.lock().unwrap().iter().any(|r| r.reason == Some("state_bad_lines")));
}

/// RFC-101 / RFC-104: directoryName IDP names. Via a CDP fetch and via a
/// configured URL, an IDP directoryName equal to a directoryName in the
/// certificate's CDP matches; another directoryName does not. For a
/// certificate without CDP, an IDP naming the issuer DN matches.
#[test]
fn directory_name_idp_scope() {
    let root = Ca::root("Dir Root");
    let part_a = revoc::subject_der(&Ca::root("Partition A").der);
    let part_b = revoc::subject_der(&Ca::root("Partition B").der);
    let issuer = revoc::subject_der(&root.der);
    let a = revoc::anchors(&[&root]);
    let check = |s: &RevocationSettings, leaf: &CertificateDer<'static>| {
        let v = Rig::new(s.clone()).check(leaf, &[], &a);
        (v.outcome, v.records[0].crl_reason)
    };
    let scope = (ChainOutcome::Unavailable, Some(CrlReason::ScopeMismatch));
    let body =
        Arc::new(Mutex::new(revoc::crl(&root, &CrlOpts { idp_dirs: vec![part_a.clone()], ..CrlOpts::default() })));
    let srv = HttpServer::start(crl_handler(body.clone()));
    let url = srv.url("/dir.crl");
    let leaf = |dn: &[u8], cn: &str| {
        root.leaf(&LeafOpts { cdp: vec![url.clone()], cdp_dir: Some(dn.to_vec()), ..LeafOpts::client(cn) }).der
    };
    let (in_a, in_b) = (leaf(&part_a, "dir-a"), leaf(&part_b, "dir-b"));

    // CDP fetch (fetch URI is not an IDP name; the directoryName decides).
    let s = crl_only(RevocationMode::HardFail);
    assert_eq!(check(&s, &in_a).0, ChainOutcome::Accepted);
    assert_eq!(check(&s, &in_b), scope);

    // Configured URL.
    let mut s = crl_only(RevocationMode::HardFail);
    s.crl.use_cdp = false;
    s.crl.urls = vec![url.clone()];
    assert_eq!(check(&s, &in_a).0, ChainOutcome::Accepted);
    assert_eq!(check(&s, &in_b), scope);

    // No CDP: the IDP must name the issuer.
    let no_cdp = root.leaf(&LeafOpts::client("dir-none")).der;
    assert_eq!(check(&s, &no_cdp), scope);
    *body.lock().unwrap() = revoc::crl(&root, &CrlOpts { idp_dirs: vec![issuer], ..CrlOpts::default() });
    assert_eq!(check(&s, &no_cdp).0, ChainOutcome::Accepted);
    *body.lock().unwrap() = revoc::crl(&root, &CrlOpts { idp_dirs: vec![part_b], ..CrlOpts::default() });
    assert_eq!(check(&s, &no_cdp), scope);

    // RFC-103: an IDP over the name cap is refused, never truncated.
    *body.lock().unwrap() = revoc::crl(&root, &CrlOpts { idp_dirs: vec![part_a; 65], ..CrlOpts::default() });
    assert_eq!(check(&s, &in_a), scope);
}
