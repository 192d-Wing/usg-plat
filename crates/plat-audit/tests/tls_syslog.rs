//! QA: RFC 5425 TLS syslog to an in-test rustls collector: octet-counted
//! framing over TLS 1.3, collector certificate rejection (wrong CA, wrong
//! name), revoked collector chain (CRL), mutual TLS, reconnect after an
//! outage, and AU-5 loss accounting with `plat.reason`. Certificates are
//! generated per test (rcgen); no key is committed.

#![cfg(feature = "tls")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use plat_audit::tls::TlsOptions;
use plat_audit::{AuditSink, AuditStats, Event, Logger, NodeIdent, RemoteLossReason};
use plat_common::config::{
    AuditConfig, AuditFileConfig, AuditMode, LogFormat, OverflowPolicy, RevocationConfig, RevocationMode, SyslogConfig,
    SyslogTlsConfig, SyslogTransport,
};
use plat_tls::RevocationRecord;
use plat_tls::revocation::RecordStatus;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SanType, SerialNumber,
};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

// ---------------------------------------------------------------- PKI

static SERIAL: AtomicU64 = AtomicU64::new(0x5000);

struct Ca {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct Leaf {
    der: CertificateDer<'static>,
    pem: String,
    key_pem: String,
    serial: u64,
}

impl Ca {
    fn new(cn: &str) -> Self {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        p.serial_number = Some(SerialNumber::from(SERIAL.fetch_add(1, Ordering::Relaxed)));
        let cert = p.self_signed(&key).unwrap();
        Self { pem: cert.pem(), issuer: Issuer::new(p, key) }
    }

    fn leaf(&self, cn: &str, server: bool) -> Leaf {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.subject_alt_names = vec![SanType::DnsName(cn.try_into().unwrap())];
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages =
            vec![if server { ExtendedKeyUsagePurpose::ServerAuth } else { ExtendedKeyUsagePurpose::ClientAuth }];
        p.use_authority_key_identifier_extension = true;
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        p.serial_number = Some(SerialNumber::from(serial));
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        Leaf { der: cert.der().clone(), pem: cert.pem(), key_pem: key.serialize_pem(), serial }
    }

    /// A CRL (DER) revoking `serials`, valid until 2049.
    fn crl(&self, serials: &[u64]) -> Vec<u8> {
        let p = CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(2049, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from(*s),
                    revocation_time: rcgen::date_time_ymd(2021, 1, 1),
                    reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        p.signed_by(&self.issuer).unwrap().der().to_vec()
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "plat-audit-tls-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn write(&self, name: &str, content: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = self.0.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------- collector

/// Collector TLS config without client authentication (test only; the
/// production policy builder always requires a client certificate).
fn collector_config(leaf: &Leaf) -> Arc<ServerConfig> {
    let provider = plat_tls::policy::fips_provider(true).unwrap();
    let key = PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes()).unwrap();
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der.clone()], key)
        .unwrap();
    Arc::new(cfg)
}

/// An in-test RFC 5425 collector: accepts connections one at a time and
/// splits the stream into octet-counted frames.
struct Collector {
    addr: SocketAddr,
    frames: Arc<Mutex<Vec<String>>>,
    handshakes: Arc<AtomicUsize>,
    clean_closes: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Collector {
    fn start(addr: SocketAddr, cfg: Arc<ServerConfig>) -> Self {
        let l = TcpListener::bind(addr).unwrap();
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap();
        let frames = Arc::new(Mutex::new(Vec::new()));
        let handshakes = Arc::new(AtomicUsize::new(0));
        let clean_closes = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (frames, handshakes, clean, stop) =
                (frames.clone(), handshakes.clone(), clean_closes.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let Ok((mut sock, _)) = l.accept() else {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    };
                    sock.set_nonblocking(false).unwrap();
                    let mut conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
                    let deadline = Instant::now() + Duration::from_secs(5);
                    if plat_tls::stream::handshake(&mut conn, &mut sock, deadline).is_err() {
                        continue;
                    }
                    handshakes.fetch_add(1, Ordering::Relaxed);
                    sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                    let mut s = rustls::StreamOwned::new(conn, sock);
                    let mut acc = Vec::new();
                    let mut chunk = [0u8; 16 << 10];
                    while !stop.load(Ordering::Relaxed) {
                        match s.read(&mut chunk) {
                            Ok(0) => {
                                clean.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            Ok(n) => {
                                acc.extend_from_slice(&chunk[..n]);
                                split_frames(&mut acc, &frames);
                            }
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) => {}
                            Err(_) => break,
                        }
                    }
                }
            })
        };
        Self { addr, frames, handshakes, clean_closes, stop, thread: Some(thread) }
    }

    fn frames(&self) -> Vec<String> {
        self.frames.lock().unwrap().clone()
    }

    /// Stops accepting and drops the listener and any open connection.
    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// RFC 5425 §4.3: `MSG-LEN SP SYSLOG-MSG`, MSG-LEN in octets.
fn split_frames(acc: &mut Vec<u8>, out: &Mutex<Vec<String>>) {
    loop {
        let Some(sp) = acc.iter().position(|b| *b == b' ') else { return };
        let len: usize = std::str::from_utf8(&acc[..sp]).unwrap().parse().expect("MSG-LEN is decimal");
        assert!(len > 0 && acc[0] != b'0', "MSG-LEN has no leading zero");
        if acc.len() < sp + 1 + len {
            return;
        }
        let msg = String::from_utf8(acc[sp + 1..sp + 1 + len].to_vec()).unwrap();
        acc.drain(..sp + 1 + len);
        out.lock().unwrap().push(msg);
    }
}

// -------------------------------------------------------------- logger

fn audit_cfg(path: &Path, syslog: SyslogConfig) -> AuditConfig {
    AuditConfig {
        mode: AuditMode::PortBlock,
        queue_capacity: 1024,
        on_overflow: OverflowPolicy::RefuseNewBindings,
        batch_max: 8,
        flush_interval_ms: 10,
        summary_interval_secs: 0,
        file: Some(AuditFileConfig { path: path.into(), max_bytes: 1 << 30, max_files: 0, min_free_bytes: 0 }),
        syslog: vec![syslog],
    }
}

fn tls_dest(addr: SocketAddr, server_name: &str, ca_file: PathBuf, client: Option<(PathBuf, PathBuf)>) -> SyslogConfig {
    SyslogConfig {
        address: addr,
        transport: SyslogTransport::Tls,
        format: LogFormat::Json,
        app_name: "platd".into(),
        tls: Some(SyslogTlsConfig {
            server_name: server_name.into(),
            ca_file,
            cert_file: client.as_ref().map(|c| c.0.clone()),
            key_file: client.map(|c| c.1),
            revocation: None,
        }),
    }
}

fn revocation_off() -> RevocationConfig {
    RevocationConfig { mode: RevocationMode::Off, ..RevocationConfig::default() }
}

/// Hard-fail, CRL from a file only.
fn revocation_crl_file(path: PathBuf) -> RevocationConfig {
    let mut r = RevocationConfig { mode: RevocationMode::HardFail, ..RevocationConfig::default() };
    r.ocsp.enabled = false;
    r.crl.enabled = true;
    r.crl.use_cdp = false;
    r.crl.files = vec![path];
    r
}

type Records = Arc<Mutex<Vec<RevocationRecord>>>;

struct Running {
    sink: AuditSink,
    stats: Arc<AuditStats>,
    handle: plat_audit::LoggerHandle,
    records: Records,
}

fn spawn(path: &Path, dest: SyslogConfig, revocation: RevocationConfig) -> std::io::Result<Running> {
    let (sink, rx) = AuditSink::bounded(1024);
    let records: Records = Arc::default();
    let r = records.clone();
    let opts = TlsOptions {
        pq_hybrid: true,
        revocation,
        shared: None,
        hook: Arc::new(move |rec: &RevocationRecord| r.lock().unwrap().push(rec.clone())),
    };
    let stats = sink.stats().clone();
    let node = NodeIdent { name: "plat-qa".into(), id: 3, pid: 77 };
    let handle = Logger::new(audit_cfg(path, dest), node, rx, stats.clone()).with_tls(opts).spawn()?;
    Ok(Running { sink, stats, handle, records })
}

fn ev(i: u16) -> Event {
    Event::PortBlockAlloc {
        ts_us: 1_793_196_960_000_000,
        sub: 0x2001_0db8 << 96,
        sub_len: 64,
        v4: 0xc000_0201,
        port_lo: i,
        port_hi: i.wrapping_add(511),
    }
}

fn wait(what: &str, limit: Duration, f: impl Fn() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < limit, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn seq_of(line: &str) -> Option<u64> {
    let i = line.find("\"event.sequence\":")? + 17;
    line[i..].split(',').next()?.parse().ok()
}

/// `(lost, reason)` of every `audit_remote_loss` record in the local file.
fn loss_records(path: &Path) -> Vec<(u64, Option<String>)> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| l.contains("\"event.action\":\"audit_remote_loss\""))
        .map(|l| {
            let i = l.find("\"plat.audit.lost\":").unwrap() + 18;
            let lost = l[i..].chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap();
            let reason = l.find("\"plat.reason\":\"").map(|i| {
                let r = &l[i + 15..];
                r[..r.find('"').unwrap()].to_owned()
            });
            (lost, reason)
        })
        .collect()
}

fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

// --------------------------------------------------------------- tests

/// RFC 5425 §4.3 framing over TLS 1.3; one handshake; close_notify at
/// shutdown (§4.4).
#[test]
fn records_arrive_octet_counted_over_tls() {
    let dir = TempDir::new("framing");
    let ca = Ca::new("syslog test CA");
    let srv = ca.leaf("siem.test", true);
    let ca_file = dir.write("ca.pem", ca.pem.as_bytes());
    let col = Collector::start("127.0.0.1:0".parse().unwrap(), collector_config(&srv));
    let path = dir.0.join("audit.jsonl");
    let run = spawn(&path, tls_dest(col.addr, "siem.test", ca_file, None), revocation_off()).unwrap();
    for i in 0..20 {
        assert!(run.sink.emit(ev(i)));
    }
    wait("20 frames", Duration::from_secs(10), || col.frames().len() >= 20);
    let Running { sink, stats, handle, .. } = run;
    drop(sink);
    handle.join();
    wait("close_notify", Duration::from_secs(5), || col.clean_closes.load(Ordering::Relaxed) == 1);

    let frames = col.frames();
    for f in &frames {
        assert!(f.starts_with('<'), "RFC 5424 header: {f}");
        assert!(f.contains("\"event.action\":"), "{f}");
    }
    let alloc = frames.iter().filter(|f| f.contains("nat_port_block_alloc")).count();
    assert_eq!(alloc, 20, "every record delivered exactly once");
    let r = &stats.remotes()[0];
    assert_eq!(r.transport, "tls");
    assert_eq!(r.tls_handshakes.load(Ordering::Relaxed), 1);
    assert_eq!(col.handshakes.load(Ordering::Relaxed), 1);
    assert_eq!(stats.remote_lost.load(Ordering::Relaxed), 0);
    assert!(loss_records(&path).is_empty());
}

/// Wrong CA and wrong server name: nothing is delivered, every record is
/// counted lost and reported with `plat.reason = tls_verify` (AU-5).
#[test]
fn wrong_ca_or_name_rejects_collector_and_accounts_loss() {
    let ca = Ca::new("syslog test CA");
    let other = Ca::new("impostor CA");
    let srv = ca.leaf("siem.test", true);
    for (tag, name, trust) in [("wrong-ca", "siem.test", &other), ("wrong-name", "other.test", &ca)] {
        let dir = TempDir::new(tag);
        let ca_file = dir.write("ca.pem", trust.pem.as_bytes());
        let col = Collector::start("127.0.0.1:0".parse().unwrap(), collector_config(&srv));
        let path = dir.0.join("audit.jsonl");
        let run = spawn(&path, tls_dest(col.addr, name, ca_file, None), revocation_off()).unwrap();
        for i in 0..20 {
            assert!(run.sink.emit(ev(i)));
        }
        let Running { sink, stats, handle, .. } = run;
        wait("handshake failure", Duration::from_secs(10), || {
            stats.remotes().first().is_some_and(|r| r.failures(RemoteLossReason::TlsVerify) > 0)
        });
        drop(sink);
        handle.join();
        assert!(col.frames().is_empty(), "{tag}: nothing reaches an unverified collector");
        assert_eq!(col.handshakes.load(Ordering::Relaxed), 0, "{tag}");
        let losses = loss_records(&path);
        let reported: u64 = losses.iter().map(|l| l.0).sum();
        assert_eq!(reported, stats.remote_lost.load(Ordering::Relaxed), "{tag}");
        assert!(reported >= 20, "{tag}: all 20 records lost, got {reported}");
        assert!(losses.iter().any(|l| l.1.as_deref() == Some("tls_verify")), "{tag}: {losses:?}");
        assert!(losses.iter().all(|l| l.1.as_deref() != Some("tls_handshake")), "{tag}: {losses:?}");
        assert!(!stats.degraded(), "a remote failure does not degrade the local file");
    }
}

/// The collector's chain is checked for revocation (IA-5(2)): a revoked
/// collector leaf is refused with `plat.reason = tls_revocation`; with a CRL
/// that does not list it the same collector is accepted. One
/// `tls_revocation_check` record per chain element.
#[test]
fn revoked_collector_chain_is_refused() {
    let ca = Ca::new("syslog test CA");
    let srv = ca.leaf("siem.test", true);

    // Positive control: CRL from the right issuer, serial not listed.
    let dir = TempDir::new("crl-good");
    let ca_file = dir.write("ca.pem", ca.pem.as_bytes());
    let crl = dir.write("ca.crl", &ca.crl(&[srv.serial + 1000]));
    let col = Collector::start("127.0.0.1:0".parse().unwrap(), collector_config(&srv));
    let path = dir.0.join("audit.jsonl");
    let run = spawn(&path, tls_dest(col.addr, "siem.test", ca_file, None), revocation_crl_file(crl)).unwrap();
    assert!(run.sink.emit(ev(1)));
    wait("delivery", Duration::from_secs(10), || !col.frames().is_empty());
    let recs = run.records.lock().unwrap().clone();
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!((recs[0].status, recs[0].chain_index, recs[0].allowed), (RecordStatus::Good, 0, true));
    drop(run.sink);
    run.handle.join();

    // Revoked.
    let dir = TempDir::new("crl-revoked");
    let ca_file = dir.write("ca.pem", ca.pem.as_bytes());
    let crl = dir.write("ca.crl", &ca.crl(&[srv.serial]));
    let col = Collector::start("127.0.0.1:0".parse().unwrap(), collector_config(&srv));
    let path = dir.0.join("audit.jsonl");
    let run = spawn(&path, tls_dest(col.addr, "siem.test", ca_file, None), revocation_crl_file(crl)).unwrap();
    for i in 0..5 {
        assert!(run.sink.emit(ev(i)));
    }
    let Running { sink, stats, handle, records } = run;
    wait("revocation failure", Duration::from_secs(10), || {
        stats.remotes().first().is_some_and(|r| r.failures(RemoteLossReason::TlsRevocation) > 0)
    });
    drop(sink);
    handle.join();
    assert!(col.frames().is_empty());
    let recs = records.lock().unwrap().clone();
    assert!(!recs.is_empty());
    assert!(recs.iter().all(|r| r.status == RecordStatus::Revoked && !r.allowed), "{recs:?}");
    let losses = loss_records(&path);
    assert!(losses.iter().any(|l| l.1.as_deref() == Some("tls_revocation")), "{losses:?}");
    assert_eq!(losses.iter().map(|l| l.0).sum::<u64>(), stats.remote_lost.load(Ordering::Relaxed));
}

/// Mutual TLS to the collector (RFC 5425 §5.1): with our client
/// certificate the collector accepts; without it the collector's rejection
/// is detected at connect time, so no batch is wrongly counted delivered.
#[test]
fn mutual_tls_to_collector() {
    let ca = Ca::new("syslog test CA");
    let srv = ca.leaf("siem.test", true);
    let client = ca.leaf("plat-node-1.test", false);
    let dir = TempDir::new("mtls");
    let ca_file = dir.write("ca.pem", ca.pem.as_bytes());
    let srv_cert = dir.write("srv.pem", srv.pem.as_bytes());
    let srv_key = dir.write("srv.key", srv.key_pem.as_bytes());
    let cli_cert = dir.write("cli.pem", client.pem.as_bytes());
    let cli_key = dir.write("cli.key", client.key_pem.as_bytes());
    // The production server policy: client certificate required.
    let cfg = plat_tls::server_config(&plat_tls::ServerSettings {
        cert_file: srv_cert,
        key_file: srv_key,
        client_ca_file: ca_file.clone(),
        pq_hybrid: true,
        revocation: None,
    })
    .unwrap();

    let col = Collector::start("127.0.0.1:0".parse().unwrap(), cfg.clone());
    let path = dir.0.join("audit-ok.jsonl");
    let dest = tls_dest(col.addr, "siem.test", ca_file.clone(), Some((cli_cert, cli_key)));
    let run = spawn(&path, dest, revocation_off()).unwrap();
    for i in 0..10 {
        assert!(run.sink.emit(ev(i)));
    }
    wait("mTLS delivery", Duration::from_secs(10), || {
        col.frames().iter().filter(|f| f.contains("nat_port_block_alloc")).count() == 10
    });
    drop(run.sink);
    run.handle.join();

    let col = Collector::start("127.0.0.1:0".parse().unwrap(), cfg);
    let path = dir.0.join("audit-nocert.jsonl");
    let run = spawn(&path, tls_dest(col.addr, "siem.test", ca_file, None), revocation_off()).unwrap();
    for i in 0..10 {
        assert!(run.sink.emit(ev(i)));
    }
    let Running { sink, stats, handle, .. } = run;
    wait("rejection", Duration::from_secs(10), || {
        stats.remotes().first().is_some_and(|r| r.failures(RemoteLossReason::TlsVerify) > 0)
    });
    drop(sink);
    handle.join();
    assert!(col.frames().is_empty());
    assert!(stats.remote_lost.load(Ordering::Relaxed) >= 10);
    let losses = loss_records(&path);
    assert!(losses.iter().all(|l| l.1.as_deref() == Some("tls_verify")), "{losses:?}");
}

/// The collector goes away and comes back: the sender reconnects after the
/// back-off (second handshake), and every record the collector did not get
/// is in the local file's `audit_remote_loss` accounting (AU-5, AU-9(2)).
#[test]
fn reconnects_after_outage_and_accounts_every_missing_record() {
    let dir = TempDir::new("reconnect");
    let ca = Ca::new("syslog test CA");
    let srv = ca.leaf("siem.test", true);
    let ca_file = dir.write("ca.pem", ca.pem.as_bytes());
    let addr = free_addr();
    let cfg = collector_config(&srv);
    let path = dir.0.join("audit.jsonl");
    let mut col = Collector::start(addr, cfg.clone());
    let run = spawn(&path, tls_dest(addr, "siem.test", ca_file, None), revocation_off()).unwrap();
    for i in 0..10 {
        assert!(run.sink.emit(ev(i)));
    }
    wait("first delivery", Duration::from_secs(10), || col.frames().len() >= 10);
    let mut received = col.frames();

    // Outage: emit until the sender notices the dead connection.
    col.shutdown();
    drop(col);
    let r = run.stats.remotes()[0].clone();
    let mut i = 100;
    wait("write failure", Duration::from_secs(10), || {
        let _ = run.sink.emit(ev(i));
        r.failures(RemoteLossReason::Io) > 0
    });
    for _ in 0..20 {
        i += 1;
        assert!(run.sink.emit(ev(i)));
        std::thread::sleep(Duration::from_millis(20));
    }

    // Back: after the 5 s back-off the next batch reconnects.
    let col = Collector::start(addr, cfg);
    wait("reconnect", Duration::from_secs(15), || {
        let _ = run.sink.emit(ev(500));
        std::thread::sleep(Duration::from_millis(50));
        r.tls_handshakes.load(Ordering::Relaxed) == 2
    });
    wait("delivery after reconnect", Duration::from_secs(10), || !col.frames().is_empty());
    let Running { sink, stats, handle, .. } = run;
    drop(sink);
    handle.join();
    received.extend(col.frames());

    let got: BTreeSet<u64> = received.iter().filter_map(|f| seq_of(f)).collect();
    let text = std::fs::read_to_string(&path).unwrap();
    // Records offered to the collector (the final loss records are written
    // after the senders closed and are file-only).
    let offered: BTreeSet<u64> = text
        .lines()
        .filter(|l| l.contains("\"event.action\":\"nat_port_block_allocate\""))
        .filter_map(seq_of)
        .collect();
    let missing = offered.difference(&got).count() as u64;
    let lost = stats.remote_lost.load(Ordering::Relaxed);
    assert!(missing > 0, "the outage lost records");
    assert!(missing <= lost, "every missing record is counted: missing {missing}, counted {lost}");
    let losses = loss_records(&path);
    assert_eq!(losses.iter().map(|l| l.0).sum::<u64>(), lost, "{losses:?}");
    assert!(losses.iter().any(|l| l.1.as_deref() == Some("io")), "{losses:?}");
}

/// A TLS destination without `Logger::with_tls`, or with an unreadable CA,
/// fails `spawn` (fail closed: no plaintext fallback).
#[test]
fn tls_destination_fails_closed_at_spawn() {
    let dir = TempDir::new("closed");
    let path = dir.0.join("audit.jsonl");
    let dest = tls_dest(free_addr(), "siem.test", dir.0.join("missing-ca.pem"), None);
    assert!(spawn(&path, dest.clone(), revocation_off()).is_err());
    let (sink, rx) = AuditSink::bounded(16);
    let node = NodeIdent { name: "n".into(), id: 0, pid: 1 };
    let ca = Ca::new("syslog test CA");
    let mut dest = dest;
    if let Some(t) = dest.tls.as_mut() {
        t.ca_file = dir.write("ca.pem", ca.pem.as_bytes());
    }
    let err = Logger::new(audit_cfg(&path, dest), node, rx, sink.stats().clone()).spawn().unwrap_err();
    assert!(err.to_string().contains("with_tls"), "{err}");
}
