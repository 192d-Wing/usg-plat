//! OCSP ↔ CRL decision-order matrix with the real clients against the
//! in-test responder and CDP servers, full-chain cases for both roles
//! (including real TLS handshakes), and the background refresher driven
//! with a fake clock.

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use plat_common::config::{OcspCertIdHash, RevocationMode};
use plat_tls::revocation::{
    Anchors, Cert, ChainOutcome, ChainVerdict, CrlReason, OcspReason, RecordStatus, RefreshKind, RefreshTransition,
    RevocationSettings, Role, Source,
};
use plat_tls::{ClientSettings, ServerSettings, client_config, server_config};
use rustls::{CertificateError, ClientConnection, Error, ServerConnection};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use support::http_server::{HttpServer, Reply};
use support::pki::{Ca, CaOpts, Leaf, LeafOpts, TempDir};
use support::revoc::{self, CrlOpts, OcspCfg, Rig, Signer, St, crl_handler, serial_of};

/// OCSP responder with an outage switch.
fn responder(cfg: Arc<Mutex<OcspCfg>>, down: Arc<AtomicBool>) -> HttpServer {
    let h = revoc::ocsp_handler(cfg);
    HttpServer::start(move |r| {
        if down.load(Ordering::Acquire) {
            Reply::Ok { status: 503, content_type: "text/plain".into(), body: Vec::new() }
        } else {
            h(r)
        }
    })
}

/// root → inter → leaf; both non-root certificates have AIA (one OCSP
/// responder) and a CDP (one CRL server per issuer).
struct Fx {
    root: Ca,
    inter: Ca,
    leaf: Leaf,
    ocsp: Arc<Mutex<OcspCfg>>,
    ocsp_down: Arc<AtomicBool>,
    ocsp_srv: HttpServer,
    root_crl: Arc<Mutex<Vec<u8>>>,
    inter_crl: Arc<Mutex<Vec<u8>>>,
    root_srv: HttpServer,
    inter_srv: HttpServer,
}

impl Fx {
    fn new(leaf_opts: LeafOpts) -> Self {
        let ocsp = Arc::new(Mutex::new(OcspCfg::default()));
        let ocsp_down = Arc::new(AtomicBool::new(false));
        let ocsp_srv = responder(ocsp.clone(), ocsp_down.clone());
        let root_crl = Arc::new(Mutex::new(Vec::new()));
        let inter_crl = Arc::new(Mutex::new(Vec::new()));
        let root_srv = HttpServer::start(crl_handler(root_crl.clone()));
        let inter_srv = HttpServer::start(crl_handler(inter_crl.clone()));
        let root = Ca::root("FB Root");
        let inter = root.intermediate_opts(
            "FB Inter",
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &CaOpts { ocsp: vec![ocsp_srv.url("/")], cdp: vec![root_srv.url("/root.crl")], ..CaOpts::default() },
        );
        let leaf = inter.leaf(&LeafOpts {
            ocsp: vec![ocsp_srv.url("/")],
            cdp: vec![inter_srv.url("/inter.crl")],
            ..leaf_opts
        });
        {
            let mut c = ocsp.lock().unwrap();
            c.sign_for(&root, Signer::ca(&root));
            c.sign_for(&inter, Signer::ca(&inter));
            c.status.insert(serial_of(&inter.der), St::Good);
            c.status.insert(serial_of(&leaf.der), St::Good);
        }
        *root_crl.lock().unwrap() = revoc::crl(&root, &CrlOpts::default());
        *inter_crl.lock().unwrap() = revoc::crl(&inter, &CrlOpts::default());
        Fx { root, inter, leaf, ocsp, ocsp_down, ocsp_srv, root_crl, inter_crl, root_srv, inter_srv }
    }

    fn client() -> Self {
        Self::new(LeafOpts::client("fb-client"))
    }

    fn anchors(&self) -> Anchors {
        revoc::anchors(&[&self.root])
    }

    fn chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.inter.der.clone()]
    }

    fn ocsp_leaf(&self, st: St) {
        self.ocsp.lock().unwrap().status.insert(serial_of(&self.leaf.der), st);
    }

    fn crl_revokes_leaf(&self) {
        let o = CrlOpts { revoked: vec![(serial_of(&self.leaf.der), Some(1))], ..CrlOpts::default() };
        *self.inter_crl.lock().unwrap() = revoc::crl(&self.inter, &o);
    }

    fn crls_down(&self) {
        self.root_crl.lock().unwrap().clear();
        self.inter_crl.lock().unwrap().clear();
    }

    fn crl_fetches(&self) -> usize {
        self.root_srv.count() + self.inter_srv.count()
    }

    fn check_role(&self, s: RevocationSettings, role: Role) -> ChainVerdict {
        let rig = Rig::new(s);
        let v = rig.check_at(role, &self.leaf.der, &self.chain(), &self.anchors(), None, UnixTime::now());
        assert_eq!(*rig.recs.lock().unwrap(), v.records, "hook sees exactly one record per chain element");
        v
    }

    fn check(&self, s: RevocationSettings) -> ChainVerdict {
        self.check_role(s, Role::MgmtClient)
    }
}

fn hard() -> RevocationSettings {
    revoc::settings(RevocationMode::HardFail)
}

fn soft() -> RevocationSettings {
    revoc::settings(RevocationMode::SoftFail)
}

fn sources(v: &ChainVerdict) -> Vec<Source> {
    v.records.iter().map(|r| r.source).collect()
}

#[test]
fn ocsp_good_crl_not_fetched() {
    let fx = Fx::client();
    let v = fx.check(hard());
    assert_eq!(v.outcome, ChainOutcome::Accepted);
    assert_eq!(sources(&v), [Source::OcspFetch, Source::OcspFetch]);
    assert_eq!(fx.crl_fetches(), 0);
}

#[test]
fn ocsp_down_crl_decides() {
    let fx = Fx::client();
    fx.ocsp_down.store(true, Ordering::Release);
    let v = fx.check(hard());
    assert_eq!(v.outcome, ChainOutcome::Accepted, "{:?}", v.records);
    assert_eq!(sources(&v), [Source::CrlFetch, Source::CrlFetch]);
    assert!(v.records.iter().all(|r| r.ocsp_reason == Some(OcspReason::HttpStatus)));

    fx.crl_revokes_leaf();
    let v = fx.check(soft());
    assert_eq!((v.outcome, v.records[0].source), (ChainOutcome::Revoked, Source::CrlFetch));
}

#[test]
fn ocsp_unknown_crl_good() {
    let fx = Fx::client();
    fx.ocsp_leaf(St::Unknown);
    let v = fx.check(hard());
    assert_eq!(v.outcome, ChainOutcome::Accepted);
    assert_eq!((v.records[0].source, v.records[0].ocsp_reason), (Source::CrlFetch, Some(OcspReason::UnknownStatus)));
    assert_eq!(v.records[1].source, Source::OcspFetch);
}

#[test]
fn ocsp_stale_and_no_crl_rejects_in_both_modes() {
    let fx = Fx::client();
    {
        let mut c = fx.ocsp.lock().unwrap();
        c.this_off = -7200;
        c.next_off = Some(-3600);
    }
    fx.crls_down();
    for s in [hard(), soft()] {
        let v = fx.check(s);
        assert_eq!(v.outcome, ChainOutcome::Unavailable, "{:?}", v.records);
        assert_eq!(v.records[0].ocsp_reason, Some(OcspReason::Stale));
        assert!(!v.records[0].allowed);
    }
}

#[test]
fn ocsp_forgery_is_fatal_without_fallback() {
    let fx = Fx::client();
    fx.ocsp.lock().unwrap().corrupt_sig = true;
    for s in [hard(), soft()] {
        let v = fx.check(s);
        assert_eq!((v.outcome, v.records[0].status), (ChainOutcome::Fatal, RecordStatus::Fatal));
        assert_eq!(v.records[0].ocsp_reason, Some(OcspReason::BadSignature));
    }
    assert_eq!(fx.crl_fetches(), 0, "no CRL fallback after a forgery");
}

#[test]
fn ocsp_revoked_is_final() {
    let fx = Fx::client();
    fx.ocsp_leaf(St::Revoked(1));
    let v = fx.check(soft());
    assert_eq!((v.outcome, v.records[0].source), (ChainOutcome::Revoked, Source::OcspFetch));
    assert_eq!(fx.crl_fetches(), 0);
}

#[test]
fn both_down() {
    let fx = Fx::client();
    fx.ocsp_down.store(true, Ordering::Release);
    fx.crls_down();
    let v = fx.check(hard());
    assert_eq!(v.outcome, ChainOutcome::Unavailable);
    assert_eq!(v.records[0].crl_reason, Some(CrlReason::Malformed), "empty body is not a CRL");
    let v = fx.check(soft());
    assert_eq!(v.outcome, ChainOutcome::Accepted);
    assert!(v.records.iter().all(|r| r.source == Source::None && r.status == RecordStatus::Unavailable && r.allowed));
}

#[test]
fn budget_exhausted_mid_chain() {
    let slow = HttpServer::start(|_| Reply::Delay(Duration::from_millis(1500), Box::new(Reply::Close)));
    let root = Ca::root("Budget Root");
    let inter = root.intermediate_opts(
        "Budget Inter",
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &CaOpts { ocsp: vec![slow.url("/")], ..CaOpts::default() },
    );
    let leaf = inter.leaf(&LeafOpts { ocsp: vec![slow.url("/")], ..LeafOpts::client("budget") }).der;
    let mut s = soft();
    s.budget = Duration::from_millis(400);
    s.ocsp.timeout_ms = 2000;
    let v = Rig::new(s).check(&leaf, std::slice::from_ref(&inter.der), &revoc::anchors(&[&root]));
    assert_eq!(v.outcome, ChainOutcome::Accepted, "soft_fail: no data, nothing stale");
    assert_eq!(v.records[0].ocsp_reason, Some(OcspReason::Timeout));
    assert_eq!(v.records[0].crl_reason, Some(CrlReason::Budget));
    assert_eq!(
        (v.records[1].ocsp_reason, v.records[1].crl_reason),
        (Some(OcspReason::Budget), Some(CrlReason::Budget))
    );
    assert_eq!(slow.count(), 1, "the intermediate is not fetched once the budget is spent");
}

#[test]
fn revoked_intermediate_rejects_both_roles_both_sources() {
    for role in [Role::MgmtClient, Role::SyslogServer] {
        // Via OCSP (the root's responder answers for the intermediate).
        let fx = Fx::new(LeafOpts::server("syslog.example.net"));
        fx.ocsp.lock().unwrap().status.insert(serial_of(&fx.inter.der), St::Revoked(2));
        let v = fx.check_role(hard(), role);
        assert_eq!(v.outcome, ChainOutcome::Revoked, "{role:?}");
        assert_eq!(v.records[0].status, RecordStatus::Good);
        assert_eq!((v.records[1].status, v.records[1].source), (RecordStatus::Revoked, Source::OcspFetch));
        assert_eq!(v.records[1].chain_index, 1);

        // Via CRL (OCSP down; the root's CRL lists the intermediate).
        let fx = Fx::new(LeafOpts::server("syslog.example.net"));
        fx.ocsp_down.store(true, Ordering::Release);
        let o = CrlOpts { revoked: vec![(serial_of(&fx.inter.der), Some(2))], ..CrlOpts::default() };
        *fx.root_crl.lock().unwrap() = revoc::crl(&fx.root, &o);
        let v = fx.check_role(soft(), role);
        assert_eq!(v.outcome, ChainOutcome::Revoked, "{role:?}");
        assert_eq!((v.records[1].status, v.records[1].source), (RecordStatus::Revoked, Source::CrlFetch));
    }
}

// ------------------------------------------------------- handshakes --

fn drive(conn: &mut rustls::Connection, s: &mut TcpStream) -> Result<(), Error> {
    while conn.is_handshaking() {
        conn.complete_io(s).map_err(|e| match e.into_inner().map(|i| i.downcast::<Error>()) {
            Some(Ok(e)) => *e,
            Some(Err(e)) => Error::General(e.to_string()),
            None => Error::General("io".into()),
        })?;
    }
    Ok(())
}

/// Returns (client result, server result).
fn handshake(
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    name: &str,
) -> (Result<(), Error>, Result<(), Error>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut conn = rustls::Connection::from(ServerConnection::new(server).unwrap());
        drive(&mut conn, &mut s)
    });
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut conn = rustls::Connection::from(
        ClientConnection::new(client, ServerName::try_from(name.to_owned()).unwrap()).unwrap(),
    );
    let c = drive(&mut conn, &mut s);
    drop(s);
    (c, srv.join().unwrap())
}

#[test]
fn syslog_handshake_uses_staple_for_leaf() {
    plat_tls::init_fips();
    let fx = Fx::new(LeafOpts::server("syslog.example.net"));
    let leaf = Cert::parse(&fx.leaf.der).unwrap();
    let inter = Cert::parse(&fx.inter.der).unwrap();
    let req = plat_tls::revocation::ocsp::request::build(&leaf, &inter, OcspCertIdHash::Sha256, false).unwrap();
    let staple = revoc::respond(&fx.ocsp.lock().unwrap().clone(), &req.der);
    let key = PrivateKeyDer::from_pem_slice(fx.leaf.key_pem.as_bytes()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::default_fips_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert_with_ocsp(vec![fx.leaf.der.clone(), fx.inter.der.clone()], key, staple)
        .unwrap();
    let dir = TempDir::new("staple");
    let ca = dir.write("ca.pem", &fx.root.pem, 0o644);
    let rig = Rig::new(hard());
    let client = client_config(&ClientSettings {
        ca_file: ca,
        client_auth: None,
        pq_hybrid: true,
        revocation: Some(rig.c.clone()),
    })
    .unwrap();
    let (c, s) = handshake(Arc::new(server), client, "syslog.example.net");
    assert!(c.is_ok() && s.is_ok(), "{c:?} {s:?}");
    let recs = rig.recs.lock().unwrap().clone();
    assert_eq!(recs.iter().map(|r| r.source).collect::<Vec<_>>(), [Source::OcspStapled, Source::OcspFetch]);
    assert!(recs.iter().all(|r| r.role == Role::SyslogServer));
    assert_eq!(fx.ocsp_srv.count(), 1, "only the intermediate fetched");
}

#[test]
fn mgmt_handshake_rejects_revoked_intermediate() {
    let fx = Fx::client();
    fx.ocsp.lock().unwrap().status.insert(serial_of(&fx.inter.der), St::Revoked(2));
    let dir = TempDir::new("mgmtrev");
    let ca = dir.write("ca.pem", &fx.root.pem, 0o644);
    let srv_leaf = fx.root.leaf(&LeafOpts::server("mgmt.example.net"));
    let cert = dir.write("srv.pem", &srv_leaf.pem, 0o644);
    let key = dir.write("srv.key", &srv_leaf.key_pem, 0o600);
    let ccert = dir.write("cli.pem", &format!("{}{}", fx.leaf.pem, fx.inter.pem), 0o644);
    let ckey = dir.write("cli.key", &fx.leaf.key_pem, 0o600);
    let rig = Rig::new(hard());
    let server = server_config(&ServerSettings {
        cert_file: cert,
        key_file: key,
        client_ca_file: ca.clone(),
        pq_hybrid: true,
        revocation: Some(rig.c.clone()),
    })
    .unwrap();
    let client = client_config(&ClientSettings {
        ca_file: ca,
        client_auth: Some((ccert, ckey)),
        pq_hybrid: true,
        revocation: None,
    })
    .unwrap();
    let (_, s) = handshake(server, client, "mgmt.example.net");
    assert_eq!(s, Err(Error::InvalidCertificate(CertificateError::Revoked)));
    let recs = rig.recs.lock().unwrap().clone();
    assert_eq!(recs.iter().map(|r| r.status).collect::<Vec<_>>(), [RecordStatus::Good, RecordStatus::Revoked]);
}

// -------------------------------------------------------- refresher --

#[test]
fn refresher_prefetches_and_refreshes_before_next_update() {
    let body = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpServer::start(crl_handler(body.clone()));
    let root = Ca::root("Refresh Root");
    *body.lock().unwrap() = revoc::crl(&root, &CrlOpts::default()); // valid 7 days
    let leaf = root.leaf(&LeafOpts::client("refresh")).der;
    let mut s = revoc::settings(RevocationMode::HardFail);
    s.ocsp.enabled = false;
    s.crl.urls = vec![srv.url("/configured.crl")];
    let rig = Rig::new(s);
    let a = revoc::anchors(&[&root]);
    let max = Duration::from_millis(500);

    rig.c.refresh_once(UnixTime::now(), max);
    assert_eq!(srv.count(), 1, "configured URL pre-fetched at start");
    let v = rig.check(&leaf, &[], &a);
    assert_eq!((v.outcome, v.records[0].source), (ChainOutcome::Accepted, Source::CrlCache));
    assert_eq!(srv.count(), 1, "pre-fetched bytes verified on first use, no fetch");

    rig.c.refresh_once(revoc::at(600), max);
    assert_eq!(srv.count(), 1, "nothing due yet");
    // 0.8 × 7 d ± 10 % ≈ 5.0..6.2 d, capped at nextUpdate − 1 h.
    let t = 7 * 24 * 3600 - 2 * 3600;
    rig.c.refresh_once(revoc::at(t), max);
    assert_eq!(srv.count(), 2, "refreshed before nextUpdate");
    rig.c.refresh_once(revoc::at(t + 5), max);
    assert_eq!(srv.count(), 2, "not refetched immediately (30 s floor)");

    // Failure: one `failing` record, back-off, then one `recovered`.
    body.lock().unwrap().clear();
    rig.c.refresh_once(revoc::at(t + 100), max);
    rig.c.refresh_once(revoc::at(t + 110), max); // inside the 30 s back-off
    assert_eq!(srv.count(), 3);
    rig.c.refresh_once(revoc::at(t + 200), max);
    assert_eq!(srv.count(), 4);
    *body.lock().unwrap() = revoc::crl(&root, &CrlOpts { number: 2, ..CrlOpts::default() });
    rig.c.refresh_once(revoc::at(t + 400), max);
    let recs = rig.refresh.lock().unwrap().clone();
    let tr: Vec<_> = recs.iter().map(|r| (r.kind, r.transition)).collect();
    assert_eq!(tr, [(RefreshKind::Crl, RefreshTransition::Failing), (RefreshKind::Crl, RefreshTransition::Recovered)]);
    assert!(recs[0].source.starts_with("127.0.0.1:") && recs[0].reason == Some("malformed"));
}

#[test]
fn refresher_drops_stale_and_refuses_rollback() {
    let fx = Fx::client();
    fx.ocsp_down.store(true, Ordering::Release);
    let short = CrlOpts { next_off: Some(3600), number: 5, ..CrlOpts::default() };
    *fx.inter_crl.lock().unwrap() = revoc::crl(&fx.inter, &short);
    let mut s = hard();
    s.ocsp.enabled = false;
    let rig = Rig::new(s);
    let a = fx.anchors();
    assert_eq!(rig.check(&fx.leaf.der, &fx.chain(), &a).outcome, ChainOutcome::Accepted);
    let max = Duration::from_millis(500);

    // Rollback: a lower cRLNumber is refused, the cached copy stays.
    *fx.inter_crl.lock().unwrap() = revoc::crl(&fx.inter, &CrlOpts { number: 3, ..short.clone() });
    rig.c.refresh_once(revoc::at(3000), max);
    let tr: Vec<_> = rig.refresh.lock().unwrap().iter().map(|r| r.transition).collect();
    assert!(tr.contains(&RefreshTransition::RollbackRejected), "{tr:?}");

    // Outage past nextUpdate: dropped once, audited.
    rig.refresh.lock().unwrap().clear();
    fx.inter_crl.lock().unwrap().clear();
    rig.c.refresh_once(revoc::at(7200 + 600), max);
    rig.c.refresh_once(revoc::at(7200 + 1200), max);
    let tr: Vec<_> = rig.refresh.lock().unwrap().iter().map(|r| r.transition).collect();
    assert_eq!(tr.iter().filter(|t| **t == RefreshTransition::StaleDropped).count(), 1, "{tr:?}");
    let v = rig.check_at(Role::MgmtClient, &fx.leaf.der, &fx.chain(), &a, None, revoc::at(7200 + 1300));
    assert_eq!(v.outcome, ChainOutcome::Unavailable, "no stale data used");
}

#[test]
fn refresher_keeps_ocsp_warm() {
    let fx = Fx::client();
    let rig = Rig::new(hard());
    let a = fx.anchors();
    rig.check(&fx.leaf.der, &fx.chain(), &a);
    assert_eq!(fx.ocsp_srv.count(), 2);
    rig.c.refresh_once(revoc::at(60), Duration::from_millis(500));
    assert_eq!(fx.ocsp_srv.count(), 2, "nothing due");
    // max_age 3600 → refresh around 0.8 × 3600 s.
    rig.c.refresh_once(revoc::at(3400), Duration::from_millis(500));
    assert_eq!(fx.ocsp_srv.count(), 4, "both watched responses refreshed");
    let v = rig.check_at(Role::MgmtClient, &fx.leaf.der, &fx.chain(), &a, None, revoc::at(3450));
    assert_eq!(sources(&v), [Source::OcspCache, Source::OcspCache]);
}
