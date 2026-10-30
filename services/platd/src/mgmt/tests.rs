//! QA: the mutual-TLS management listener against real TLS 1.3 clients:
//! accepted and rejected connections (no certificate, unknown CA, not
//! allow-listed, revoked), exactly one `management_connection` record per
//! connection, the connection cap, the handshake timeout, isolation from a
//! slow client, and the rejection rate limit with its summary record.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;

use plat_common::Config;
use plat_nat64::Nat64;
use plat_tls::revocation::RecordStatus;
use plat_tls::{RevocationChecker, RevocationRecord, RevocationSettings};

use super::*;
use crate::test_pki::{Ca, Leaf, TempDir};

/// Non-blocking poll of the audit queue (platd does not name the channel
/// crate).
type Rx = Box<dyn Fn() -> Option<Event> + Send>;

const SERVER_NAME: &str = "mgmt.test";
const ALLOWED: &str = "prom.test";

struct Pki {
    dir: TempDir,
    ca: Ca,
    ca_file: PathBuf,
    srv_cert: PathBuf,
    srv_key: PathBuf,
}

impl Pki {
    fn new(tag: &str) -> Self {
        let dir = TempDir::new(tag);
        let ca = Ca::new("mgmt test CA");
        let srv = ca.leaf(SERVER_NAME, true);
        let ca_file = dir.write("ca.pem", ca.pem.as_bytes());
        let srv_cert = dir.write("srv.pem", srv.pem.as_bytes());
        let srv_key = dir.write("srv.key", srv.key_pem.as_bytes());
        Self { dir, ca, ca_file, srv_cert, srv_key }
    }

    fn client_files(&self, name: &str, leaf: &Leaf) -> (PathBuf, PathBuf) {
        (
            self.dir.write(&format!("{name}.pem"), leaf.pem.as_bytes()),
            self.dir.write(&format!("{name}.key"), leaf.key_pem.as_bytes()),
        )
    }

    fn mgmt(&self, rev: Option<Arc<RevocationChecker>>, max: usize, timeout: Duration) -> MgmtTls {
        let config = plat_tls::server_config(&plat_tls::ServerSettings {
            cert_file: self.srv_cert.clone(),
            key_file: self.srv_key.clone(),
            client_ca_file: self.ca_file.clone(),
            pq_hybrid: true,
            revocation: rev,
        })
        .unwrap();
        MgmtTls {
            config,
            allow: AllowList::new(&[format!("dns:{ALLOWED}")]).unwrap(),
            max_connections: max,
            max_per_ip: max,
            handshake_timeout: timeout,
        }
    }

    /// Client config trusting the management CA, with an optional client
    /// certificate.
    fn client(&self, cert: Option<(PathBuf, PathBuf)>) -> Arc<rustls::ClientConfig> {
        plat_tls::client_config(&plat_tls::ClientSettings {
            ca_file: self.ca_file.clone(),
            client_auth: cert,
            pq_hybrid: true,
            revocation: None,
        })
        .unwrap()
    }
}

fn sources() -> Sources {
    let cfg = Config::from_toml(include_str!("../../../../config/platd.example.toml")).unwrap();
    let (sink, _rx) = AuditSink::bounded(16);
    let nat = Arc::new(Nat64::new(&cfg, plat_cluster::owned(&cfg), sink.clone(), Clock::new()).unwrap());
    Sources {
        nat,
        workers: vec![Arc::new(plat_common::Counters::default())],
        audit: sink,
        fips: true,
        extra: Vec::new(),
        cluster: None,
    }
}

struct Server {
    addr: SocketAddr,
    stats: Arc<MgmtStats>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    next: Rx,
    seen: Vec<Event>,
}

impl Server {
    fn start(tls: MgmtTls, limiter: RejectLimiter) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let (sink, rx) = AuditSink::bounded(1024);
        let stats = Arc::new(MgmtStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let thread = spawn_on(l, tls, sources(), sink, stats.clone(), Arc::new(limiter), stop.clone()).unwrap();
        Self { addr, stats, stop, thread: Some(thread), next: Box::new(move || rx.try_recv().ok()), seen: Vec::new() }
    }

    /// Waits until `n` management records (connection or suppressed) have
    /// been queued; returns all seen so far.
    fn records(&mut self, n: usize, limit: Duration) -> Vec<Event> {
        let t = Instant::now();
        loop {
            while let Some(ev) = (self.next)() {
                if matches!(ev, Event::ManagementConnection { .. } | Event::ManagementSuppressed { .. }) {
                    self.seen.push(ev);
                }
            }
            if self.seen.len() >= n {
                return self.seen.clone();
            }
            assert!(t.elapsed() < limit, "expected {n} records, got {:?}", self.seen);
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Asserts no further record arrives within `d`.
    fn quiet(&mut self, d: Duration) {
        let n = self.seen.len();
        std::thread::sleep(d);
        while let Some(ev) = (self.next)() {
            if matches!(ev, Event::ManagementConnection { .. } | Event::ManagementSuppressed { .. }) {
                self.seen.push(ev);
            }
        }
        assert_eq!(self.seen.len(), n, "unexpected records: {:?}", &self.seen[n..]);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn conn_of(ev: &Event) -> Option<&MgmtConnection> {
    match ev {
        Event::ManagementConnection { conn, .. } => Some(conn),
        _ => None,
    }
}

/// One HTTPS request; `Ok(response)` or the client-side failure.
fn get(addr: SocketAddr, cfg: Arc<rustls::ClientConfig>, path: &str) -> Result<String, stream::TlsIoError> {
    let mut sock = TcpStream::connect(addr).map_err(stream::TlsIoError::Io)?;
    let name = rustls_pki_types::ServerName::try_from(SERVER_NAME).unwrap().to_owned();
    let mut conn = rustls::ClientConnection::new(cfg, name).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    stream::handshake(&mut conn, &mut sock, deadline)?;
    stream::await_rejection(&mut conn, &mut sock, Duration::from_millis(200))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {SERVER_NAME}\r\n\r\n");
    stream::write_all(&mut conn, &mut sock, req.as_bytes(), deadline)?;
    let mut buf = vec![0u8; 1 << 20];
    let n = stream::read_until(&mut conn, &mut sock, &mut buf, deadline, |_| false)?;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// AC-17 / IA-3 / AU-2: an allow-listed client certificate gets the
/// read-only endpoints; each connection is one `accepted` record with the
/// peer, subject, fingerprint and path.
#[test]
fn allow_listed_client_gets_metrics_and_healthz() {
    let pki = Pki::new("mgmt-ok");
    let leaf = pki.ca.leaf(ALLOWED, false);
    let client = pki.client(Some(pki.client_files("prom", &leaf)));
    let mut srv = Server::start(pki.mgmt(None, 4, Duration::from_secs(5)), RejectLimiter::standard());

    let m = get(srv.addr, client.clone(), "/metrics").unwrap();
    assert!(m.starts_with("HTTP/1.1 200 OK\r\n"), "{m}");
    assert!(m.contains("plat_sessions ") && m.contains("plat_fips_mode 1"), "{m}");
    let h = get(srv.addr, client.clone(), "/healthz").unwrap();
    assert!(h.starts_with("HTTP/1.1 200 OK\r\n") && h.ends_with("ok\n"), "{h}");
    let o = get(srv.addr, client, "/x").unwrap();
    assert!(o.starts_with("HTTP/1.1 404"), "{o}");

    let recs = srv.records(3, Duration::from_secs(5));
    let fp = plat_tls::peer_identity(&leaf.der).sha256;
    let paths: Vec<_> = recs.iter().filter_map(conn_of).map(|c| c.path).collect();
    assert_eq!(paths, [Some(MgmtPath::Metrics), Some(MgmtPath::Healthz), Some(MgmtPath::Other)]);
    for c in recs.iter().filter_map(conn_of) {
        assert_eq!(c.reason, MgmtReason::Accepted);
        assert_eq!(c.subject.as_ref().map(AuditText::as_str), Some(ALLOWED));
        assert_eq!(c.cert_sha256, Some(fp));
        assert_eq!(c.ip, std::net::IpAddr::from([127, 0, 0, 1]));
        // NIST-009: the matched entry and the peer's SANs.
        assert_eq!(c.allow_entry.as_ref().map(AuditText::as_str), Some("dns:prom.test"));
        assert_eq!(c.sans.iter().map(AuditText::as_str).collect::<Vec<_>>(), ["dns:prom.test"]);
    }
    assert_eq!(srv.stats.get(MgmtReason::Accepted), 3);
    srv.quiet(Duration::from_millis(200));
}

/// IA-3 / AC-3: no certificate, a certificate from an unknown CA, and a
/// valid but not allow-listed certificate are each refused with exactly
/// one record and the right reason; nothing is served.
#[test]
fn rejected_clients_are_refused_and_audited_once() {
    let pki = Pki::new("mgmt-reject");
    let stranger = Ca::new("unknown CA");
    let foreign = stranger.leaf(ALLOWED, false);
    let other = pki.ca.leaf("intruder.test", false);
    let mut srv = Server::start(pki.mgmt(None, 4, Duration::from_secs(5)), RejectLimiter::standard());

    let no_cert = get(srv.addr, pki.client(None), "/metrics");
    assert!(no_cert.is_err(), "{no_cert:?}");
    let unknown = get(srv.addr, pki.client(Some(pki.client_files("foreign", &foreign))), "/metrics");
    assert!(unknown.is_err(), "{unknown:?}");
    // Authenticated but not authorized: the handshake completes, then the
    // server closes without a response.
    let denied = get(srv.addr, pki.client(Some(pki.client_files("other", &other))), "/metrics");
    assert!(denied.as_deref().map_or(true, str::is_empty), "{denied:?}");

    let recs = srv.records(3, Duration::from_secs(5));
    let reasons: Vec<_> = recs.iter().filter_map(conn_of).map(|c| c.reason).collect();
    assert_eq!(reasons, [MgmtReason::NoClientCert, MgmtReason::BadCert, MgmtReason::NotAllowlisted]);
    let denied_rec = conn_of(&recs[2]).unwrap();
    assert_eq!(denied_rec.subject.as_ref().map(AuditText::as_str), Some("intruder.test"));
    assert_eq!(denied_rec.cert_sha256, Some(plat_tls::peer_identity(&other.der).sha256));
    assert!(denied_rec.allow_entry.is_none());
    assert_eq!(denied_rec.sans.iter().map(AuditText::as_str).collect::<Vec<_>>(), ["dns:intruder.test"]);
    assert!(recs.iter().filter_map(conn_of).all(|c| c.path.is_none()));
    assert_eq!(srv.stats.get(MgmtReason::Accepted), 0);
    srv.quiet(Duration::from_millis(200));
}

/// IA-5(2): a revoked client certificate (CRL) is refused as `revoked`,
/// and the checker reports the revoked leaf; an unrevoked one is accepted.
#[test]
fn revoked_client_is_refused() {
    let pki = Pki::new("mgmt-revoked");
    let good = pki.ca.leaf(ALLOWED, false);
    let bad = pki.ca.leaf(ALLOWED, false);
    let crl = pki.dir.write("ca.crl", &pki.ca.crl(&[bad.serial]));
    let mut rc = plat_common::config::RevocationConfig::default();
    rc.ocsp.enabled = false;
    rc.crl.use_cdp = false;
    rc.crl.files = vec![crl];
    let seen: Arc<parking_lot::Mutex<Vec<RevocationRecord>>> = Arc::default();
    let s2 = seen.clone();
    let checker = RevocationChecker::new(
        RevocationSettings::from(&rc),
        Arc::new(move |r: &RevocationRecord| s2.lock().push(r.clone())),
    )
    .unwrap();
    let mut srv = Server::start(pki.mgmt(Some(checker), 4, Duration::from_secs(5)), RejectLimiter::standard());

    let r = get(srv.addr, pki.client(Some(pki.client_files("bad", &bad))), "/metrics");
    assert!(r.is_err(), "{r:?}");
    let ok = get(srv.addr, pki.client(Some(pki.client_files("good", &good))), "/metrics").unwrap();
    assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");

    let recs = srv.records(2, Duration::from_secs(5));
    let reasons: Vec<_> = recs.iter().filter_map(conn_of).map(|c| c.reason).collect();
    assert_eq!(reasons, [MgmtReason::Revoked, MgmtReason::Accepted]);
    let checks = seen.lock().clone();
    let st: Vec<_> = checks.iter().map(|r| (r.status, r.allowed)).collect();
    assert_eq!(st, [(RecordStatus::Revoked, false), (RecordStatus::Good, true)]);
}

/// SC-5: over `max_connections` a connection is closed before any TLS work
/// (`over_capacity`); a client that never sends a ClientHello is dropped
/// at the handshake timeout (`handshake_timeout`), freeing its slot.
#[test]
fn connection_cap_and_handshake_timeout() {
    let pki = Pki::new("mgmt-cap");
    let leaf = pki.ca.leaf(ALLOWED, false);
    let client = pki.client(Some(pki.client_files("prom", &leaf)));
    let timeout = Duration::from_millis(400);
    let mut srv = Server::start(pki.mgmt(None, 1, timeout), RejectLimiter::standard());

    let mut slow = TcpStream::connect(srv.addr).unwrap();
    let t = Instant::now();
    while srv.stats.active.load(Ordering::Acquire) == 0 {
        assert!(t.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(5));
    }
    let over = get(srv.addr, client.clone(), "/metrics");
    assert!(over.is_err(), "{over:?}");
    let recs = srv.records(1, Duration::from_secs(2));
    assert_eq!(conn_of(&recs[0]).unwrap().reason, MgmtReason::OverCapacity);

    // The silent client is cut off at the handshake timeout.
    let recs = srv.records(2, Duration::from_secs(3));
    assert_eq!(conn_of(&recs[1]).unwrap().reason, MgmtReason::HandshakeTimeout);
    assert!(t.elapsed() >= timeout);
    slow.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut b = [0u8; 16];
    assert_eq!(slow.read(&mut b).unwrap_or(0), 0, "server closed the slow connection");

    let t = Instant::now();
    while srv.stats.active.load(Ordering::Acquire) != 0 {
        assert!(t.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(get(srv.addr, client, "/healthz").unwrap().starts_with("HTTP/1.1 200 OK"));
}

/// A slow client holding a slot does not delay another client.
#[test]
fn slow_client_does_not_block_others() {
    let pki = Pki::new("mgmt-slow");
    let leaf = pki.ca.leaf(ALLOWED, false);
    let client = pki.client(Some(pki.client_files("prom", &leaf)));
    let srv = Server::start(pki.mgmt(None, 2, Duration::from_secs(5)), RejectLimiter::standard());
    let _slow = TcpStream::connect(srv.addr).unwrap();
    std::thread::sleep(Duration::from_millis(150));
    let t = Instant::now();
    assert!(get(srv.addr, client, "/metrics").unwrap().starts_with("HTTP/1.1 200 OK"));
    assert!(t.elapsed() < Duration::from_secs(2), "served in {:?}", t.elapsed());
}

/// SC-5 / AU-5: a rejection flood is audited up to the bucket, the rest is
/// counted, and one `management_connection_suppressed` summary follows.
/// The window is longer than any test run, so a loaded host cannot split
/// the flood across two windows; the summary comes from the flush at
/// shutdown (the periodic path is covered by
/// `reject_limiter_summarises_a_window_once`).
#[test]
fn rejection_flood_is_rate_limited_and_summarised() {
    let pki = Pki::new("mgmt-flood");
    let mut srv = Server::start(
        pki.mgmt(None, 4, Duration::from_secs(5)),
        RejectLimiter::new(0.0, 2.0, Duration::from_secs(3600)),
    );
    for _ in 0..5 {
        assert!(get(srv.addr, pki.client(None), "/metrics").is_err());
    }
    let t = Instant::now();
    while srv.stats.get(MgmtReason::NoClientCert) < 5 {
        assert!(t.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
    let recs = srv.records(2, Duration::from_secs(3));
    assert_eq!(recs.iter().filter_map(conn_of).count(), 2, "{recs:?}");
    assert!(!recs.iter().any(|e| matches!(e, Event::ManagementSuppressed { .. })), "{recs:?}");
    // Stop: the accept thread drains and flushes the summary.
    srv.stop.store(true, Ordering::Relaxed);
    if let Some(th) = srv.thread.take() {
        th.join().unwrap();
    }
    let recs = srv.records(3, Duration::from_secs(3));
    assert_eq!(recs.iter().filter_map(conn_of).count(), 2, "{recs:?}");
    let summary: Vec<_> = recs
        .iter()
        .filter_map(|e| match e {
            Event::ManagementSuppressed { suppressed, .. } => Some(*suppressed),
            _ => None,
        })
        .collect();
    assert_eq!(summary, [3]);
}

/// AU-5: the periodic summary reports a window's suppressed records once,
/// only after the window has ended, and nothing for an empty window.
#[test]
fn reject_limiter_summarises_a_window_once() {
    let window = Duration::from_millis(50);
    let l = RejectLimiter::new(0.0, 2.0, window);
    let admitted = (0..5).filter(|_| l.admit()).count();
    assert_eq!(admitted, 2);
    std::thread::sleep(window + Duration::from_millis(10));
    match l.summary(false) {
        Some(Event::ManagementSuppressed { suppressed, .. }) => assert_eq!(suppressed, 3),
        other => panic!("{other:?}"),
    }
    std::thread::sleep(window + Duration::from_millis(10));
    assert!(l.summary(false).is_none(), "an empty window is not summarised");
}

/// SEC-001: one source address cannot hold more than `max_per_ip` slots,
/// and a client that connects but sends no ClientHello is dropped at the
/// 2 s first-flight deadline, well before the handshake timeout.
#[test]
fn per_ip_cap_and_client_hello_deadline() {
    let pki = Pki::new("mgmt-perip");
    let leaf = pki.ca.leaf(ALLOWED, false);
    let client = pki.client(Some(pki.client_files("prom", &leaf)));
    let mut tls = pki.mgmt(None, 4, Duration::from_secs(10));
    tls.max_per_ip = 1;
    let mut srv = Server::start(tls, RejectLimiter::standard());

    let t = Instant::now();
    let _silent = TcpStream::connect(srv.addr).unwrap();
    while srv.stats.active.load(Ordering::Acquire) == 0 {
        assert!(t.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(5));
    }
    // Global cap (4) not reached, but this source already holds its slot.
    assert!(get(srv.addr, client.clone(), "/metrics").is_err());
    let recs = srv.records(1, Duration::from_secs(2));
    assert_eq!(conn_of(&recs[0]).unwrap().reason, MgmtReason::OverCapacity);

    // The silent client is cut at the ClientHello deadline (2 s), not the
    // 10 s handshake timeout.
    let recs = srv.records(2, Duration::from_secs(4));
    assert_eq!(conn_of(&recs[1]).unwrap().reason, MgmtReason::HandshakeTimeout);
    let waited = t.elapsed();
    assert!(waited >= Duration::from_secs(2) && waited < Duration::from_secs(5), "{waited:?}");
    let t = Instant::now();
    while srv.stats.active.load(Ordering::Acquire) != 0 {
        assert!(t.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(get(srv.addr, client, "/healthz").unwrap().starts_with("HTTP/1.1 200 OK"));
}

/// SEC-003: revocation records of valid but non-allow-listed management
/// certificates pass the rejection bucket; an authorized client's records
/// are always emitted.
#[test]
fn revocation_records_of_rejected_clients_are_rate_limited() {
    let pki = Pki::new("mgmt-revflood");
    let good = pki.ca.leaf(ALLOWED, false);
    let other = pki.ca.leaf("intruder.test", false);
    let crl = pki.dir.write("ca.crl", &pki.ca.crl(&[]));
    let mut rc = plat_common::config::RevocationConfig::default();
    rc.ocsp.enabled = false;
    rc.crl.use_cdp = false;
    rc.crl.files = vec![crl];
    let (sink, rx) = AuditSink::bounded(1024);
    let limiter = Arc::new(RejectLimiter::new(0.0, 1.0, Duration::from_secs(60)));
    let hook = crate::tls::revocation_hook(
        crate::run::HookSink::new(sink.clone()),
        Arc::new(crate::tls::RevocationMetrics::default()),
        limiter.clone(),
    );
    let checker = RevocationChecker::new(RevocationSettings::from(&rc), hook).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let stats = Arc::new(MgmtStats::default());
    let stop = Arc::new(AtomicBool::new(false));
    let th = spawn_on(
        l,
        pki.mgmt(Some(checker), 4, Duration::from_secs(5)),
        sources(),
        sink,
        stats.clone(),
        limiter,
        stop.clone(),
    )
    .unwrap();

    let other_cfg = pki.client(Some(pki.client_files("other", &other)));
    for _ in 0..5 {
        let _ = get(addr, other_cfg.clone(), "/metrics");
    }
    let ok = get(addr, pki.client(Some(pki.client_files("prom", &good))), "/metrics").unwrap();
    assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");
    stop.store(true, Ordering::Relaxed);
    th.join().unwrap();
    let mut rev = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let Event::RevocationCheck { check, .. } = ev {
            rev.push(check.cert_sha256);
        }
    }
    let other_fp = plat_tls::peer_identity(&other.der).sha256;
    let good_fp = plat_tls::peer_identity(&good.der).sha256;
    // Bucket of one shared with the five NotAllowlisted connection records:
    // at most one record for the intruder, the allowed client's always.
    assert!(rev.iter().filter(|h| **h == other_fp).count() <= 1, "{rev:?}");
    assert_eq!(rev.iter().filter(|h| **h == good_fp).count(), 1, "{rev:?}");
}

#[test]
fn per_ip_key_aggregates_ipv6_slash64_and_v4_mapped() {
    // SEC-101: many addresses in one /64 share a single key.
    let base: std::net::Ipv6Addr = "2001:db8:1:2::".parse().unwrap();
    let k = source_key(IpAddr::V6(base));
    let keys: std::collections::HashSet<IpAddr> = (0u64..1000)
        .map(|i| {
            let v = u128::from(base) | u128::from(i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            source_key(IpAddr::V6(v.into()))
        })
        .collect();
    assert_eq!(keys.len(), 1);
    assert!(keys.contains(&k));
    // Another /64 is a different key.
    assert_ne!(source_key("2001:db8:1:3::1".parse().unwrap()), k);
    // v4-mapped equals plain IPv4; distinct IPv4 addresses stay distinct.
    let v4: IpAddr = "192.0.2.7".parse().unwrap();
    assert_eq!(source_key("::ffff:192.0.2.7".parse().unwrap()), v4);
    assert_eq!(source_key(v4), v4);
    assert_ne!(source_key("192.0.2.8".parse().unwrap()), v4);
}
