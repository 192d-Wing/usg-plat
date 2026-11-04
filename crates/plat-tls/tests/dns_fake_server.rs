//! The real hickory resolver (`revocation::dns`) against an in-process
//! fake DNS server on 127.0.0.1 (UDP): answers, late answers, no answers,
//! NXDOMAIN, truncation, a flood of slow names, the hosts file, reloads and
//! an HTTP fetch by name.
//!
//! The server is a hand-built minimal responder (header + one question,
//! A/AAAA answers); the behaviour is chosen by the first label.

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use plat_common::HttpUrl;
use plat_tls::revocation::dns::{self, Dns, MAX_INFLIGHT, ResolverSettings};
use plat_tls::revocation::http::{self as rhttp, HttpError, Request};
use support::http_server::{HttpServer, Reply};
use support::pki::TempDir;

const OK_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const V6_10: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);

struct FakeDns {
    addr: SocketAddr,
    queries: Arc<Mutex<HashMap<String, usize>>>,
    /// Question names as received (case preserved).
    raw: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for FakeDns {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

impl FakeDns {
    /// `v4` is the address answered for `ok.*` / `ocsp.*` A queries.
    fn start(v4: Ipv4Addr) -> Self {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let addr = s.local_addr().unwrap();
        let queries = Arc::new(Mutex::new(HashMap::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let raw = Arc::new(Mutex::new(Vec::new()));
        let (q, st, rw) = (queries.clone(), stop.clone(), raw.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while !st.load(Ordering::Acquire) {
                let Ok((n, peer)) = s.recv_from(&mut buf) else { continue };
                let Some((name, qtype, qend)) = question(&buf[..n]) else { continue };
                *q.lock().unwrap().entry(name.clone()).or_insert(0) += 1;
                rw.lock().unwrap().push(String::from_utf8_lossy(&buf[13..qend.saturating_sub(5)]).into_owned());
                let first = name.split('.').next().unwrap_or("").to_string();
                let msg = buf[..qend].to_vec();
                let sock = s.try_clone().unwrap();
                let reply = move |m: Vec<u8>| {
                    let _ = sock.send_to(&m, peer);
                };
                match first.as_str() {
                    "ok" => reply(answer(&msg, qtype, v4, V6_10)),
                    // ::1 refuses at once (the HTTP server is IPv4 only).
                    "ocsp" => reply(answer(&msg, qtype, v4, std::net::Ipv6Addr::LOCALHOST)),
                    "late" => {
                        let m = answer(&msg, qtype, v4, V6_10);
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_secs(3));
                            reply(m);
                        });
                    }
                    "nx" => reply(header_only(&msg, 3, false)),
                    "tc" => reply(header_only(&msg, 0, true)),
                    // Answer with every letter of the question case-flipped.
                    "flip" => {
                        let mut m = msg.clone();
                        for b in &mut m[12..qend - 4] {
                            if b.is_ascii_alphabetic() {
                                *b ^= 0x20;
                            }
                        }
                        reply(answer(&m, qtype, v4, V6_10));
                    }
                    _ => {} // never answers (incl. "never", "flood*")
                }
            }
        });
        Self { addr, queries, raw, stop }
    }

    fn count(&self, name: &str) -> usize {
        self.queries.lock().unwrap().iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| *v).sum()
    }
}

/// (lowercased name without the root dot, qtype, end of question).
fn question(m: &[u8]) -> Option<(String, u16, usize)> {
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let l = *m.get(i)? as usize;
        i += 1;
        if l == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(m.get(i..i + l)?).to_ascii_lowercase());
        i += l;
    }
    let qtype = u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]);
    Some((labels.join("."), qtype, i + 4))
}

fn header_only(q: &[u8], rcode: u8, tc: bool) -> Vec<u8> {
    let mut m = q.to_vec();
    m[2] = 0x81 | if tc { 0x02 } else { 0 }; // QR, RD (+TC)
    m[3] = 0x80 | rcode; // RA
    m[6..12].fill(0); // AN/NS/AR = 0
    m
}

fn answer(q: &[u8], qtype: u16, v4: Ipv4Addr, v6: std::net::Ipv6Addr) -> Vec<u8> {
    let mut m = header_only(q, 0, false);
    let rdata: Vec<u8> = match qtype {
        1 => v4.octets().to_vec(),
        28 => v6.octets().to_vec(),
        _ => return m,
    };
    m[7] = 1; // ANCOUNT
    m.extend_from_slice(&[0xc0, 0x0c]);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    m.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    m.extend_from_slice(&rdata);
    m
}

fn settings(srv: &FakeDns) -> ResolverSettings {
    ResolverSettings {
        nameservers: vec![srv.addr],
        timeout: Duration::from_secs(2),
        hosts_file: None,
        ..ResolverSettings::default()
    }
}

fn secs(s: u64) -> Instant {
    Instant::now() + Duration::from_secs(s)
}

fn v6_10() -> IpAddr {
    IpAddr::V6(V6_10)
}

#[test]
fn answers_ipv6_first_and_caches() {
    let srv = FakeDns::start(OK_V4);
    let d = Dns::new(settings(&srv));
    let r = d.resolve("ok.test", 443, secs(5)).unwrap();
    assert_eq!(r, vec![SocketAddr::new(v6_10(), 443), SocketAddr::new(OK_V4.into(), 443)]);
    let n = srv.count("ok.test");
    assert!(n >= 1);
    assert_eq!(d.resolve("OK.test", 80, secs(5)).unwrap().len(), 2);
    assert_eq!(srv.count("ok.test"), n, "second lookup is a cache hit");
}

#[test]
fn late_and_missing_answers_time_out_within_the_deadline() {
    let srv = FakeDns::start(OK_V4);
    let d = Dns::new(settings(&srv));
    for host in ["late.test", "never.test"] {
        let t0 = Instant::now();
        assert_eq!(d.resolve(host, 80, t0 + Duration::from_secs(1)), Err(HttpError::Timeout), "{host}");
        let e = t0.elapsed();
        assert!(e < Duration::from_millis(1100), "{host}: {e:?}");
    }
    assert_eq!(d.stats().timeouts, 2);
    // Cancelled at the deadline: nothing stays in flight.
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(d.stats().in_flight, 0);
}

#[test]
fn nxdomain_and_truncation_fail_before_the_deadline() {
    let srv = FakeDns::start(OK_V4);
    let d = Dns::new(settings(&srv));
    assert_eq!(d.resolve("nx.test", 80, secs(5)), Err(HttpError::Connect));
    assert_eq!(d.stats().errors, 1);
    // TC with no TCP listener: error or timeout, never past the deadline.
    let t0 = Instant::now();
    assert!(d.resolve("tc.test", 80, t0 + Duration::from_secs(1)).is_err());
    assert!(t0.elapsed() < Duration::from_millis(1100));
}

/// SC-5: 100 distinct names that never answer stay within the in-flight
/// cap, all return by the deadline, the counters add up, and a healthy
/// lookup works afterwards.
#[test]
fn flood_of_slow_names_is_bounded_and_recovers() {
    let srv = FakeDns::start(OK_V4);
    let d = Arc::new(Dns::new(settings(&srv)));
    let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let (d, peak, stop) = (d.clone(), peak.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                peak.fetch_max(d.stats().in_flight, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_millis(800);
    let hs: Vec<_> = (0..100)
        .map(|i| {
            let d = d.clone();
            std::thread::spawn(move || d.resolve(&format!("flood{i}.test"), 80, deadline))
        })
        .collect();
    for h in hs {
        assert_eq!(h.join().unwrap(), Err(HttpError::Timeout));
    }
    assert!(t0.elapsed() < Duration::from_millis(1000), "{:?}", t0.elapsed());
    stop.store(true, Ordering::Release);
    sampler.join().unwrap();
    assert!(peak.load(Ordering::Relaxed) <= MAX_INFLIGHT);
    let st = d.stats();
    assert_eq!(st.timeouts + st.saturated, 100, "{st:?}");
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!((d.stats().in_flight, d.stats().queued), (0, 0));
    assert!(d.resolve("ok.test", 80, secs(5)).is_ok());
}

#[test]
fn hosts_file_is_consulted_and_reloaded() {
    let srv = FakeDns::start(OK_V4);
    let dir = TempDir::new("dns-hosts");
    let hosts = dir.write("hosts", "192.0.2.77 pki-only.test\n", 0o644);
    let s = ResolverSettings { hosts_file: Some(hosts.clone()), reload_interval: Duration::ZERO, ..settings(&srv) };
    let d = Dns::new(s);
    assert_eq!(d.resolve("pki-only.test", 80, secs(5)).unwrap(), vec![SocketAddr::from(([192, 0, 2, 77], 80))]);
    assert_eq!(srv.count("pki-only.test"), 0, "answered from the hosts file");
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(&hosts, "192.0.2.78 other-only.test\n").unwrap();
    let end = secs(5);
    while d.resolve("other-only.test", 80, secs(1)).is_err() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(d.resolve("other-only.test", 80, secs(5)).unwrap(), vec![SocketAddr::from(([192, 0, 2, 78], 80))]);
}

/// Q2: a resolv.conf that no longer parses keeps the last good resolver.
#[test]
fn bad_resolv_conf_keeps_last_good_config() {
    let dir = TempDir::new("dns-conf");
    let conf = dir.write("resolv.conf", "nameserver 127.0.0.1\n", 0o644);
    let hosts = dir.write("hosts", "192.0.2.80 a.test\n", 0o644);
    let s = ResolverSettings {
        nameservers: Vec::new(),
        timeout: Duration::from_millis(200),
        hosts_file: Some(hosts.clone()),
        resolv_conf: conf.clone(),
        reload_interval: Duration::ZERO,
    };
    let d = Dns::new(s);
    assert!(d.resolve("a.test", 80, secs(5)).is_ok());
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(&conf, "search example.net\n").unwrap(); // no nameserver
    std::fs::write(&hosts, "192.0.2.81 b.test\n").unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let end = Instant::now() + Duration::from_millis(300);
    while Instant::now() < end {
        assert!(d.resolve("a.test", 80, secs(5)).is_ok(), "old config kept");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(d.resolve("b.test", 80, Instant::now() + Duration::from_millis(500)).is_err(), "new files rejected");
}

#[test]
fn missing_resolv_conf_fails_closed() {
    let s = ResolverSettings {
        resolv_conf: PathBuf::from("/nonexistent/plat/resolv.conf"),
        hosts_file: None,
        ..ResolverSettings::default()
    };
    let d = Dns::new(s);
    assert_eq!(d.resolve("x.test", 80, secs(2)), Err(HttpError::Connect));
}

/// End to end: an OCSP/CRL-style HTTP fetch by name through the
/// process-wide resolver configured to use the fake server.
#[test]
fn fetch_by_name_through_the_global_resolver() {
    let srv = FakeDns::start(Ipv4Addr::LOCALHOST);
    assert!(dns::configure(ResolverSettings {
        nameservers: vec![srv.addr],
        hosts_file: None,
        ..ResolverSettings::default()
    }));
    let http = HttpServer::start(|_| Reply::ok("application/pkix-crl", b"crl".to_vec()));
    let url = HttpUrl::parse(&format!("http://ocsp.test:{}/ca.crl", http.addr.port())).unwrap();
    let req = Request {
        post: None,
        accept: "application/pkix-crl",
        accept_types: &["application/pkix-crl"],
        max_body: 1024,
        deadline: secs(5),
    };
    // IPv6 (::1) is tried first and refused; IPv4 answers.
    let r = rhttp::fetch(&url, &req).unwrap();
    assert_eq!(r.body, b"crl");
    assert!(srv.count("ocsp.test") >= 1);
    assert_eq!(dns::stats().errors, 0);
}

/// QA (Q2): the hosts file is rewritten repeatedly while lookups run;
/// no panic, every caller returns by its deadline, and the final content
/// is served once writes stop.
#[test]
fn qa_reload_races_with_lookups() {
    let srv = FakeDns::start(OK_V4);
    let dir = TempDir::new("dns-race");
    let hosts = dir.write("hosts", "192.0.2.90 race.test\n", 0o644);
    let s = ResolverSettings { hosts_file: Some(hosts.clone()), reload_interval: Duration::ZERO, ..settings(&srv) };
    let d = Arc::new(Dns::new(s));
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (hosts, stop) = (hosts.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut i = 0u8;
            while !stop.load(Ordering::Acquire) {
                // Alternate valid content and a truncated/garbled file.
                let body =
                    if i % 3 == 2 { "192.0.2.\n".to_string() } else { format!("192.0.2.{} race.test\n", 90 + i % 2) };
                let tmp = hosts.with_extension("tmp");
                std::fs::write(&tmp, body).unwrap();
                std::fs::rename(&tmp, &hosts).unwrap();
                i = i.wrapping_add(1);
                std::thread::sleep(Duration::from_millis(3));
            }
        })
    };
    let hs: Vec<_> = (0..8)
        .map(|_| {
            let d = d.clone();
            std::thread::spawn(move || {
                for _ in 0..50 {
                    let dl = Instant::now() + Duration::from_millis(500);
                    let _ = d.resolve("race.test", 80, dl);
                    assert!(Instant::now() < dl + Duration::from_millis(50));
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    stop.store(true, Ordering::Release);
    writer.join().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(&hosts, "192.0.2.99 race.test\n").unwrap();
    // The reload runs off the lookup thread (SEC-003) and is swapped in by
    // a later lookup, so poll for it (bounded).
    let want = vec![SocketAddr::from(([192, 0, 2, 99], 80))];
    let end = secs(5);
    while d.resolve("race.test", 80, secs(1)).ok().as_ref() != Some(&want) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(d.resolve("race.test", 80, secs(5)).unwrap(), want);
    assert_eq!((d.stats().in_flight, d.stats().queued), (0, 0));
}

/// SEC-002: query names go out with 0x20 case randomisation, and the
/// server's echo of the question case is accepted.
#[test]
fn query_case_is_randomised_and_echo_accepted() {
    let srv = FakeDns::start(OK_V4);
    let d = Dns::new(settings(&srv));
    for l in ["alpha", "bravo", "charlie", "delta", "echo"] {
        assert!(d.resolve(&format!("ok.{l}.test"), 80, secs(5)).is_ok(), "{l}");
    }
    let raw = srv.raw.lock().unwrap().clone();
    assert!(raw.iter().any(|n| n.bytes().any(|b| b.is_ascii_uppercase())), "{raw:?}");
}

/// SEC-002: a reply whose question case does not match the query is not
/// accepted; the lookup fails by its deadline.
#[test]
fn mismatched_question_case_is_rejected() {
    let srv = FakeDns::start(OK_V4);
    let d = Dns::new(settings(&srv));
    let t0 = Instant::now();
    assert!(d.resolve("flip.example.test", 80, t0 + Duration::from_secs(1)).is_err());
    assert!(t0.elapsed() < Duration::from_millis(1100));
    assert!(srv.count("flip.example.test") >= 1);
}

/// SEC-004: single-label names are refused without a query.
#[test]
fn single_label_names_are_refused() {
    let srv = FakeDns::start(OK_V4);
    let d = Dns::new(settings(&srv));
    for h in ["ok", "ok.", "localhost"] {
        assert_eq!(d.resolve(h, 80, secs(2)), Err(HttpError::Connect), "{h}");
    }
    assert_eq!(srv.raw.lock().unwrap().len(), 0);
}

/// SEC-007: while every slot is held, waiting names send no query (nothing
/// reaches the network without a slot), and a cached name is answered from
/// the local cache without a query.
#[test]
fn no_query_without_a_slot() {
    let srv = FakeDns::start(OK_V4);
    let d = Arc::new(Dns::new(settings(&srv)));
    assert!(d.resolve("ok.cached.test", 80, secs(5)).is_ok());
    let cached_queries = srv.count("ok.cached.test");
    let busy: Vec<_> = (0..MAX_INFLIGHT)
        .map(|i| {
            let d = d.clone();
            std::thread::spawn(move || d.resolve(&format!("busy{i}.test"), 80, secs(3)))
        })
        .collect();
    let end = secs(5);
    while d.stats().in_flight < MAX_INFLIGHT && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(d.stats().in_flight, MAX_INFLIGHT);
    let waiters: Vec<_> = (0..20)
        .map(|i| {
            let d = d.clone();
            std::thread::spawn(move || {
                d.resolve(&format!("wait{i}.test"), 80, Instant::now() + Duration::from_millis(400))
            })
        })
        .collect();
    let t0 = Instant::now();
    assert!(d.resolve("ok.cached.test", 80, t0 + Duration::from_millis(500)).is_ok());
    assert!(t0.elapsed() < Duration::from_millis(100), "{:?}", t0.elapsed());
    for w in waiters {
        assert_eq!(w.join().unwrap(), Err(HttpError::Timeout));
    }
    let waited = (0..20).map(|i| srv.count(&format!("wait{i}.test"))).sum::<usize>();
    assert_eq!(waited, 0, "no query sent without a slot");
    assert_eq!(srv.count("ok.cached.test"), cached_queries, "cache hit, no query");
    for b in busy {
        let _ = b.join();
    }
}
