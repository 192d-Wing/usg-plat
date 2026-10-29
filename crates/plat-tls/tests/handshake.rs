//! End-to-end TLS 1.3 handshakes over loopback with the policy configs:
//! FIPS, key exchange, mutual authentication, name checks, and the
//! revocation wrapper on both sides.

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use plat_common::config::{CrlConfig, OcspConfig, RevocationMode};
use plat_tls::revocation::{
    CertCtx, ChainOutcome, OcspSource, RecordStatus, RevocationChecker, RevocationReason, RevocationRecord,
    RevocationSettings, Role, Source,
};
use plat_tls::revocation::{Lookup, LookupOutcome};
use plat_tls::{AllowList, ClientSettings, ServerSettings, client_config, peer_identity, server_config};
use rustls::{CertificateError, ClientConfig, ClientConnection, Error, ServerConfig, ServerConnection};
use rustls_pki_types::{CertificateDer, ServerName};
use support::pki::{Ca, LeafOpts, TempDir};

struct Pki {
    dir: TempDir,
    root: Ca,
    inter: Ca,
}

impl Pki {
    fn new() -> Self {
        Self::named("HS")
    }

    fn named(tag: &str) -> Self {
        let root = Ca::root(&format!("{tag} Root"));
        let inter = root.intermediate(&format!("{tag} Inter"));
        Self { dir: TempDir::new("hs"), root, inter }
    }

    fn ca_file(&self) -> std::path::PathBuf {
        self.dir.write("ca.pem", &self.root.pem, 0o644)
    }

    /// Leaf + intermediate chain file and key file.
    fn leaf_files(
        &self,
        name: &str,
        o: &LeafOpts,
    ) -> (std::path::PathBuf, std::path::PathBuf, CertificateDer<'static>) {
        let l = self.inter.leaf(o);
        let cert = self.dir.write(&format!("{name}.pem"), &format!("{}{}", l.pem, self.inter.pem), 0o644);
        let key = self.dir.write(&format!("{name}.key"), &l.key_pem, 0o600);
        (cert, key, l.der)
    }
}

type Recs = Arc<Mutex<Vec<RevocationRecord>>>;

fn checker(mode: RevocationMode, ocsp: Option<Box<dyn OcspSource>>) -> (Arc<RevocationChecker>, Recs) {
    let recs: Recs = Arc::new(Mutex::new(Vec::new()));
    let r = recs.clone();
    let s = RevocationSettings {
        mode,
        skew: Duration::from_secs(300),
        budget: Duration::from_millis(500),
        cache_dir: None,
        ocsp: OcspConfig::default(),
        crl: CrlConfig::default(),
    };
    let hook: plat_tls::RevocationHook = Arc::new(move |x: &RevocationRecord| r.lock().unwrap().push(x.clone()));
    let c = match ocsp {
        Some(o) => RevocationChecker::with_sources(s, hook, o, Box::new(plat_tls::revocation::NoCrl)).unwrap(),
        None => RevocationChecker::new(s, hook).unwrap(),
    };
    (c, recs)
}

struct Outcome {
    client: Result<(), Error>,
    server: Result<(), Error>,
    group: Option<String>,
    suite: Option<String>,
    peer: Option<Vec<CertificateDer<'static>>>,
}

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

/// Exchanges "hello"/"world" after the handshake. In TLS 1.3 a server-side
/// rejection of the client certificate surfaces on the client's first read.
fn ping(conn: &mut rustls::Connection, s: &mut TcpStream, first: &[u8], reply: &[u8]) -> Result<(), Error> {
    let io = |e: std::io::Error| Error::General(e.to_string());
    let flush = |conn: &mut rustls::Connection, s: &mut TcpStream| -> Result<(), Error> {
        while conn.wants_write() {
            conn.write_tls(s).map_err(io)?;
        }
        Ok(())
    };
    if !first.is_empty() {
        conn.writer().write_all(first).map_err(io)?;
    }
    let mut b = [0u8; 5];
    let mut got = 0;
    while got < b.len() {
        flush(conn, s)?;
        match conn.reader().read(&mut b[got..]) {
            Ok(0) => return Err(Error::General("eof".into())),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if conn.read_tls(s).map_err(io)? == 0 {
                    return Err(Error::General("eof".into()));
                }
                conn.process_new_packets()?;
            }
            Err(e) => return Err(io(e)),
        }
    }
    if !reply.is_empty() {
        conn.writer().write_all(reply).map_err(io)?;
        flush(conn, s)?;
    }
    Ok(())
}

fn handshake(server: Arc<ServerConfig>, client: Arc<ClientConfig>, name: &str) -> Outcome {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut conn = rustls::Connection::from(ServerConnection::new(server).unwrap());
        let r = drive(&mut conn, &mut s);
        let peer = conn.peer_certificates().map(|c| c.iter().map(|d| d.clone().into_owned()).collect::<Vec<_>>());
        if r.is_ok() {
            let _ = ping(&mut conn, &mut s, b"", b"world");
        }
        (r, peer)
    });
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let sn = ServerName::try_from(name.to_owned()).unwrap();
    let mut conn = rustls::Connection::from(ClientConnection::new(client, sn).unwrap());
    let mut client = drive(&mut conn, &mut s);
    let group = conn.negotiated_key_exchange_group().map(|g| format!("{:?}", g.name()));
    let suite = conn.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite()));
    if client.is_ok() {
        client = ping(&mut conn, &mut s, b"hello", b"");
    }
    drop(s);
    let (server, peer) = srv.join().unwrap();
    Outcome { client, server, group, suite, peer }
}

fn server_cfg(p: &Pki, pq: bool, rev: Option<Arc<RevocationChecker>>) -> Arc<ServerConfig> {
    let (cert, key, _) = p.leaf_files("server", &LeafOpts::server("mgmt.example.net"));
    let cfg = server_config(&ServerSettings {
        cert_file: cert,
        key_file: key,
        client_ca_file: p.ca_file(),
        pq_hybrid: pq,
        revocation: rev,
    })
    .unwrap();
    assert!(cfg.fips());
    cfg
}

fn client_cfg(p: &Pki, ca: std::path::PathBuf, pq: bool, rev: Option<Arc<RevocationChecker>>) -> Arc<ClientConfig> {
    let o = LeafOpts {
        uris: vec!["spiffe://ops/prom".into()],
        dns: vec!["prom-01.ops.example.net".into()],
        ..LeafOpts::client("prom-01")
    };
    let (cert, key, _) = p.leaf_files("client", &o);
    client_config(&ClientSettings { ca_file: ca, client_auth: Some((cert, key)), pq_hybrid: pq, revocation: rev })
        .unwrap()
}

#[test]
fn mutual_tls13_with_hybrid_kx() {
    plat_tls::require_fips().unwrap();
    let p = Pki::new();
    let o = handshake(server_cfg(&p, true, None), client_cfg(&p, p.ca_file(), true, None), "mgmt.example.net");
    o.client.unwrap();
    o.server.unwrap();
    assert_eq!(o.group.as_deref(), Some("X25519MLKEM768"));
    assert!(o.suite.unwrap().starts_with("TLS13_AES_"));
    // Server side sees the client chain; identity and allow-list.
    let peer = o.peer.unwrap();
    assert_eq!(peer.len(), 2);
    let id = peer_identity(&peer[0]);
    assert_eq!(id.subject_cn.as_deref(), Some("prom-01"));
    assert_eq!(id.uri_sans, ["spiffe://ops/prom"]);
    assert_eq!(id.dns_sans, ["prom-01.ops.example.net"]);
    assert_eq!(id.fingerprint_sha256.len(), 64);
    assert!(AllowList::new(&["uri:spiffe://ops/prom".into()]).unwrap().permits(&id));
    assert!(AllowList::new(&[format!("sha256:{}", id.fingerprint_sha256)]).unwrap().permits(&id));
    assert!(!AllowList::new(&["cn:prom-02".into()]).unwrap().permits(&id));
}

#[test]
fn classic_groups_when_pq_off() {
    let p = Pki::new();
    let o = handshake(server_cfg(&p, true, None), client_cfg(&p, p.ca_file(), false, None), "mgmt.example.net");
    o.client.unwrap();
    assert_eq!(o.group.as_deref(), Some("secp256r1"));
}

#[test]
fn server_verification_failures() {
    let p = Pki::new();
    let other = Ca::root("Other Root");
    let wrong_ca = p.dir.write("other-ca.pem", &other.pem, 0o644);
    let o = handshake(server_cfg(&p, true, None), client_cfg(&p, wrong_ca, true, None), "mgmt.example.net");
    assert_eq!(o.client.unwrap_err(), Error::InvalidCertificate(CertificateError::UnknownIssuer));
    assert!(o.server.is_err());
    let o = handshake(server_cfg(&p, true, None), client_cfg(&p, p.ca_file(), true, None), "siem.example.net");
    assert!(matches!(
        o.client.unwrap_err(),
        Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. })
    ));
}

#[test]
fn client_certificate_required_and_chained() {
    let p = Pki::new();
    let no_cert =
        client_config(&ClientSettings { ca_file: p.ca_file(), client_auth: None, pq_hybrid: true, revocation: None })
            .unwrap();
    let o = handshake(server_cfg(&p, true, None), no_cert, "mgmt.example.net");
    assert_eq!(o.server.unwrap_err(), Error::NoCertificatesPresented);
    assert!(o.client.is_err());
    // Client certificate from an unknown CA.
    let stranger = Pki::named("Stranger");
    let o = handshake(server_cfg(&p, true, None), client_cfg(&stranger, p.ca_file(), true, None), "mgmt.example.net");
    assert_eq!(o.server.unwrap_err(), Error::InvalidCertificate(CertificateError::UnknownIssuer));
    // Impostor CA reusing our CA names with its own keys.
    let impostor = Pki::new();
    let o = handshake(server_cfg(&p, true, None), client_cfg(&impostor, p.ca_file(), true, None), "mgmt.example.net");
    assert_eq!(o.server.unwrap_err(), Error::InvalidCertificate(CertificateError::BadSignature));
}

#[test]
fn revocation_wrapper_on_both_sides() {
    let p = Pki::new();
    // Mode off: accepted, one not_checked record per side.
    let (srv_rev, srv_recs) = checker(RevocationMode::Off, None);
    let (cli_rev, cli_recs) = checker(RevocationMode::Off, None);
    let o = handshake(
        server_cfg(&p, true, Some(srv_rev)),
        client_cfg(&p, p.ca_file(), true, Some(cli_rev)),
        "mgmt.example.net",
    );
    o.client.unwrap();
    o.server.unwrap();
    let s = srv_recs.lock().unwrap();
    assert_eq!((s.len(), s[0].role, s[0].status), (1, Role::MgmtClient, RecordStatus::NotChecked));
    assert_eq!(cli_recs.lock().unwrap()[0].role, Role::SyslogServer);
    drop(s);

    // hard_fail with no OCSP/CRL data yet: rejected (fail closed), with a
    // record per chain element.
    let (srv_rev, srv_recs) = checker(RevocationMode::HardFail, None);
    let o = handshake(server_cfg(&p, true, Some(srv_rev)), client_cfg(&p, p.ca_file(), true, None), "mgmt.example.net");
    assert_eq!(o.server.unwrap_err(), Error::InvalidCertificate(CertificateError::UnknownRevocationStatus));
    let s = srv_recs.lock().unwrap();
    // Leaf unavailable (rejects); the intermediate is then recorded, not fetched.
    assert_eq!(s.len(), 2);
    assert_eq!((s[0].status, s[0].allowed, s[0].chain_index), (RecordStatus::Unavailable, false, 0));
    assert_eq!((s[1].status, s[1].allowed, s[1].chain_index), (RecordStatus::NotChecked, false, 1));
    drop(s);

    // soft_fail with no data: accepted and audited as source none.
    let (cli_rev, cli_recs) = checker(RevocationMode::SoftFail, None);
    let o = handshake(server_cfg(&p, true, None), client_cfg(&p, p.ca_file(), true, Some(cli_rev)), "mgmt.example.net");
    o.client.unwrap();
    assert!(cli_recs.lock().unwrap().iter().all(|r| r.allowed && r.source == Source::None));
}

#[derive(Debug)]
struct RevokeAll;

impl OcspSource for RevokeAll {
    fn lookup(&self, _ctx: &CertCtx<'_>) -> Lookup {
        Lookup {
            outcome: LookupOutcome::Revoked {
                source: Source::OcspFetch,
                reason: RevocationReason::Superseded,
                at_us: 0,
            },
            origin: None,
        }
    }
}

#[test]
fn revoked_collector_is_rejected() {
    let p = Pki::new();
    let (cli_rev, recs) = checker(RevocationMode::SoftFail, Some(Box::new(RevokeAll)));
    let o = handshake(
        server_cfg(&p, true, None),
        client_cfg(&p, p.ca_file(), true, Some(cli_rev.clone())),
        "mgmt.example.net",
    );
    assert_eq!(o.client.unwrap_err(), Error::InvalidCertificate(CertificateError::Revoked));
    let r = recs.lock().unwrap();
    assert_eq!((r[0].status, r[0].revocation_reason), (RecordStatus::Revoked, Some(RevocationReason::Superseded)));
    assert_eq!(r[1].status, RecordStatus::NotChecked);
    assert!(!ChainOutcome::Revoked.is_accepted());
}
