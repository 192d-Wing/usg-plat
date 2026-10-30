//! Cluster peer channel (WU5): one `PeerSettings` builds both roles; mutual
//! TLS 1.3 over the cluster CA in both directions, typed identity binding,
//! revocation under the peer roles, and fail-closed loading.

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use plat_common::config::{ClusterTlsConfig, CrlConfig, OcspConfig, RevocationMode};
use plat_tls::revocation::{RevocationChecker, RevocationRecord, RevocationSettings, Role};
use plat_tls::{AllowList, PeerConfigs, PeerSettings, peer_configs, peer_identity, peer_server_name};
use rustls::{ClientConnection, Error, ServerConnection};
use support::pki::{Ca, LeafOpts, TempDir};

struct Pki {
    dir: TempDir,
    root: Ca,
    inter: Ca,
}

impl Pki {
    fn new(tag: &str) -> Self {
        let root = Ca::root(&format!("{tag} Root"));
        let inter = root.intermediate(&format!("{tag} Inter"));
        Self { dir: TempDir::new("peer"), root, inter }
    }

    fn ca_file(&self) -> std::path::PathBuf {
        self.dir.write("ca.pem", &self.root.pem, 0o644)
    }

    fn settings(&self, name: &str, o: &LeafOpts, rev: Option<Arc<RevocationChecker>>) -> PeerSettings {
        let l = self.inter.leaf(o);
        let cert = self.dir.write(&format!("{name}.pem"), &format!("{}{}", l.pem, self.inter.pem), 0o644);
        let key = self.dir.write(&format!("{name}.key"), &l.key_pem, 0o600);
        let cfg = ClusterTlsConfig { cert_file: cert, key_file: key, ca_file: self.ca_file(), revocation: None };
        PeerSettings::from_config(&cfg, true, rev)
    }
}

fn peer(name: &str) -> LeafOpts {
    LeafOpts { peer: true, ..LeafOpts::server(name) }
}

fn drive(conn: &mut rustls::Connection, s: &mut TcpStream) -> Result<(), Error> {
    while conn.is_handshaking() {
        conn.complete_io(s).map_err(|e| match e.into_inner().map(|i| i.downcast::<Error>()) {
            Some(Ok(e)) => *e,
            Some(Err(e)) => Error::General(e.to_string()),
            None => Error::General("io".into()),
        })?;
    }
    // Flush the client's Finished so the server completes too.
    while conn.wants_write() {
        conn.write_tls(s).map_err(|e| Error::General(e.to_string()))?;
    }
    Ok(())
}

type Ids = (Result<(), Error>, Result<(), Error>, Option<plat_tls::PeerIdentity>, Option<plat_tls::PeerIdentity>);

/// Node `a` dials node `b`. Returns both results and the identity each side saw.
fn connect(a: &PeerConfigs, b: &PeerConfigs, identity_of_b: &str) -> Ids {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let server = b.server.clone();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut conn = rustls::Connection::from(ServerConnection::new(server).unwrap());
        let r = drive(&mut conn, &mut s);
        (r, conn.peer_certificates().and_then(|c| c.first()).map(peer_identity))
    });
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let sn = peer_server_name(identity_of_b, addr.ip()).unwrap();
    let mut conn = rustls::Connection::from(ClientConnection::new(a.client.clone(), sn).unwrap());
    let c = drive(&mut conn, &mut s);
    let seen = conn.peer_certificates().and_then(|c| c.first()).map(peer_identity);
    let (sr, seen_by_b) = srv.join().unwrap();
    drop(s);
    (c, sr, seen, seen_by_b)
}

#[test]
fn both_directions_with_identity_binding() {
    plat_tls::require_fips().unwrap();
    let p = Pki::new("Cluster");
    let a = peer_configs(&p.settings("a", &peer("plat-01.cluster.example"), None)).unwrap();
    let b = peer_configs(&p.settings("b", &peer("plat-02.cluster.example"), None)).unwrap();
    assert!(a.server.fips() && a.client.fips());
    for (from, to, to_id, from_id) in [
        (&a, &b, "dns:plat-02.cluster.example", "dns:plat-01.cluster.example"),
        (&b, &a, "dns:plat-01.cluster.example", "dns:plat-02.cluster.example"),
    ] {
        let (c, s, seen_server, seen_client) = connect(from, to, to_id);
        c.unwrap();
        s.unwrap();
        // The caller binds identities exactly to the member entry.
        let want_server = AllowList::new(&[to_id.to_string()]).unwrap();
        let want_client = AllowList::new(&[from_id.to_string()]).unwrap();
        assert!(want_server.permits(&seen_server.unwrap()));
        let seen_client = seen_client.unwrap();
        assert!(want_client.permits(&seen_client));
        assert!(!want_server.permits(&seen_client), "identity bound to one member only");
    }
}

#[test]
fn foreign_ca_and_wrong_name_are_refused() {
    plat_tls::require_fips().unwrap();
    let p = Pki::new("Cluster");
    let other = Pki::new("Other");
    let a = peer_configs(&p.settings("a", &peer("plat-01.cluster.example"), None)).unwrap();
    let b = peer_configs(&p.settings("b", &peer("plat-02.cluster.example"), None)).unwrap();
    let x = peer_configs(&other.settings("x", &peer("plat-02.cluster.example"), None)).unwrap();
    // Dialing an impostor from another CA: the client refuses its chain.
    let (c, _, _, _) = connect(&a, &x, "dns:plat-02.cluster.example");
    assert!(c.is_err());
    // An impostor dialing in: the server refuses its client certificate.
    let (_, s, _, _) = connect(&x, &b, "dns:plat-02.cluster.example");
    assert!(s.is_err());
    // Expected name not in the server certificate.
    let (c, _, _, _) = connect(&a, &b, "dns:plat-03.cluster.example");
    assert!(c.is_err());
}

#[test]
fn server_only_certificate_cannot_dial() {
    plat_tls::require_fips().unwrap();
    let p = Pki::new("Cluster");
    // A serverAuth-only certificate cannot act as a peer client.
    let a = peer_configs(&p.settings("a", &LeafOpts::server("plat-01.cluster.example"), None)).unwrap();
    let b = peer_configs(&p.settings("b", &peer("plat-02.cluster.example"), None)).unwrap();
    let (_, s, _, _) = connect(&a, &b, "dns:plat-02.cluster.example");
    assert!(s.is_err());
}

#[test]
fn revocation_runs_under_peer_roles() {
    plat_tls::require_fips().unwrap();
    let recs: Arc<Mutex<Vec<RevocationRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let r = recs.clone();
    let settings = RevocationSettings {
        mode: RevocationMode::SoftFail,
        skew: Duration::from_secs(300),
        budget: Duration::from_millis(500),
        cache_dir: None,
        ocsp: OcspConfig { enabled: false, ..OcspConfig::default() },
        crl: CrlConfig { use_cdp: false, ..CrlConfig::default() },
    };
    let hook: plat_tls::RevocationHook = Arc::new(move |x: &RevocationRecord| r.lock().unwrap().push(x.clone()));
    let chk = RevocationChecker::new(settings, hook).unwrap();
    let p = Pki::new("Cluster");
    let a = peer_configs(&p.settings("a", &peer("plat-01.cluster.example"), Some(chk.clone()))).unwrap();
    let b = peer_configs(&p.settings("b", &peer("plat-02.cluster.example"), Some(chk))).unwrap();
    let (c, s, _, _) = connect(&a, &b, "dns:plat-02.cluster.example");
    c.unwrap();
    s.unwrap();
    let roles: Vec<Role> = recs.lock().unwrap().iter().map(|r| r.role).collect();
    assert!(roles.contains(&Role::PeerClient) && roles.contains(&Role::PeerServer), "{roles:?}");
}

#[test]
fn loading_fails_closed() {
    let p = Pki::new("Cluster");
    let mut s = p.settings("a", &peer("plat-01.cluster.example"), None);
    s.ca_file = p.dir.write("empty.pem", "", 0o644);
    assert!(peer_configs(&s).is_err());
    let mut s = p.settings("a", &peer("plat-01.cluster.example"), None);
    s.key_file = p.dir.write("loose.key", &p.inter.leaf(&peer("x.example")).key_pem, 0o644);
    assert!(peer_configs(&s).is_err(), "world-readable key");
}

#[test]
fn server_name_for_non_dns_identity_is_the_peer_ip() {
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let p = Pki::new("Cluster");
    let o = LeafOpts { ips: vec![ip], ..peer("plat-02.cluster.example") };
    let a = peer_configs(&p.settings("a", &peer("plat-01.cluster.example"), None)).unwrap();
    let b = peer_configs(&p.settings("b", &o, None)).unwrap();
    let (c, s, _, _) = connect(&a, &b, "cn:plat-02.cluster.example");
    c.unwrap();
    s.unwrap();
}
