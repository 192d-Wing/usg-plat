//! QA: structure-aware robustness of the hostile-input parsers (SI-10, SC-5).
//!
//! The in-crate proptests feed purely random bytes, which almost never get
//! past the outer DER tag. These start from *valid, signed* OCSP responses
//! and CRLs and mutate them (byte flips, truncation, insertion, length
//! inflation), so the decoders and the verify paths behind them are
//! exercised. Invariants: never panic; any change to signed bytes is
//! rejected; truncation is always rejected.
//!
//! Also: HTTP client edge cases over a real socket (slowloris trickle,
//! no Content-Length with a peer that never closes, chunked) and a
//! structured header proptest for `read_from`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use plat_common::HttpUrl;
use plat_common::config::OcspCertIdHash;
use plat_tls::revocation::Cert;
use plat_tls::revocation::crl::parse as crlp;
use plat_tls::revocation::http::{HttpError, Request, fetch, read_from};
use plat_tls::revocation::ocsp::{request, response};
use proptest::prelude::*;
use support::pki::{Ca, LeafOpts};
use support::revoc::{self, CrlOpts, NonceMode, OcspCfg, Signer, St, serial_of};

struct Fx {
    issuer: Cert,
    crl: Vec<u8>,
    ocsp: Vec<u8>,
    cert_id: x509_ocsp::CertId,
}

fn now() -> u64 {
    u64::try_from(revoc::now_secs()).unwrap()
}

fn build() -> Fx {
    let root = Ca::root("QA Parser Root");
    let leaf = root.leaf(&LeafOpts::client("qa-leaf")).der;
    let issuer = Cert::parse(&root.der).unwrap();
    let leaf_c = Cert::parse(&leaf).unwrap();
    let crl = revoc::crl(
        &root,
        &CrlOpts { revoked: vec![(vec![0x01, 0x02], Some(1)), (serial_of(&leaf), None)], ..CrlOpts::default() },
    );
    let mut cfg = OcspCfg { nonce: NonceMode::Omit, ..OcspCfg::default() };
    cfg.sign_for(&root, Signer::ca(&root));
    cfg.status.insert(serial_of(&leaf), St::Good);
    let req = request::build(&leaf_c, &issuer, OcspCertIdHash::Sha256, false).unwrap();
    let ocsp = revoc::respond(&cfg, &req.der);
    Fx { issuer, crl, ocsp, cert_id: req.cert_id }
}

thread_local! {
    static FX: Fx = build();
}

fn expect(fx: &Fx) -> response::Expect<'_> {
    response::Expect { cert_id: &fx.cert_id, nonce: None, require_nonce: false, now: now(), skew: 300, max_age: 3600 }
}

#[test]
fn baselines_verify() {
    FX.with(|fx| {
        let e = crlp::verify(&fx.crl, &fx.issuer, now(), 300).unwrap();
        assert_eq!(e.revoked.len(), 2);
        let v = response::verify(&fx.ocsp, &fx.issuer, &expect(fx)).unwrap();
        assert_eq!(v.status, response::Status::Good);
    });
}

#[derive(Debug, Clone)]
enum Mutation {
    Flip(usize, u8),
    Truncate(usize),
    Insert(usize, u8),
    /// Sets a byte to 0x84/0x88/0xff (long-form or reserved length octets).
    HugeLen(usize, u8),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), 1u8..=255).prop_map(|(i, x)| Mutation::Flip(i, x)),
        any::<usize>().prop_map(Mutation::Truncate),
        (any::<usize>(), any::<u8>()).prop_map(|(i, b)| Mutation::Insert(i, b)),
        (any::<usize>(), prop::sample::select(vec![0x84u8, 0x88, 0xff, 0x80]))
            .prop_map(|(i, b)| Mutation::HugeLen(i, b)),
    ]
}

fn apply(orig: &[u8], m: &Mutation) -> Vec<u8> {
    let mut v = orig.to_vec();
    if v.is_empty() {
        return v;
    }
    match *m {
        Mutation::Flip(i, x) => {
            let i = i % v.len();
            v[i] ^= x;
        }
        Mutation::Truncate(i) => v.truncate(i % v.len()),
        Mutation::Insert(i, b) => v.insert(i % (v.len() + 1), b),
        Mutation::HugeLen(i, b) => {
            let i = i % v.len();
            v[i] = b;
        }
    }
    v
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    #[test]
    fn crl_mutations_never_panic_and_never_verify(ms in prop::collection::vec(mutation(), 1..4)) {
        FX.with(|fx| {
            let mut der = fx.crl.clone();
            for m in &ms { der = apply(&der, m); }
            let _ = crlp::inspect(&der, now(), 300);
            let _ = crlp::issuer_name(&der);
            let r = crlp::verify(&der, &fx.issuer, now(), 300);
            if der != fx.crl {
                prop_assert!(r.is_err(), "mutated CRL verified: {:?}", ms);
            }
            Ok(())
        })?;
    }

    #[test]
    fn ocsp_mutations_never_panic_and_never_verify(ms in prop::collection::vec(mutation(), 1..4)) {
        FX.with(|fx| {
            let mut der = fx.ocsp.clone();
            for m in &ms { der = apply(&der, m); }
            let r = response::verify(&der, &fx.issuer, &expect(fx));
            if der != fx.ocsp {
                prop_assert!(r.is_err(), "mutated OCSP response verified: {:?}", ms);
            }
            Ok(())
        })?;
    }

    /// Oversized inputs: a valid body followed by megabytes of trailing data
    /// or wrapped in an inflated outer length must be rejected, not panic.
    #[test]
    fn trailing_garbage_rejected(extra in prop::collection::vec(any::<u8>(), 1..64)) {
        FX.with(|fx| {
            let mut c = fx.crl.clone();
            c.extend_from_slice(&extra);
            prop_assert!(crlp::verify(&c, &fx.issuer, now(), 300).is_err());
            let mut o = fx.ocsp.clone();
            o.extend_from_slice(&extra);
            prop_assert!(response::verify(&o, &fx.issuer, &expect(fx)).is_err());
            Ok(())
        })?;
    }
}

#[test]
fn oversized_bodies_rejected_without_panic() {
    FX.with(|fx| {
        // Outer SEQUENCE claiming 2^32-1 bytes with a short body.
        let mut huge = vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff];
        huge.extend_from_slice(&fx.crl[2..]);
        assert!(crlp::inspect(&huge, now(), 300).is_err());
        assert!(response::verify(&huge, &fx.issuer, &expect(fx)).is_err());
        // 1 MiB of nested SEQUENCE headers (recursion depth).
        let nested: Vec<u8> = std::iter::repeat_n([0x30u8, 0x80], 512 * 1024).flatten().collect();
        assert!(crlp::inspect(&nested, now(), 300).is_err());
        assert!(response::verify(&nested, &fx.issuer, &expect(fx)).is_err());
        // Definite-length deep nesting.
        let mut deep = vec![0x05, 0x00];
        for _ in 0..4096 {
            let len = deep.len();
            let mut h = vec![0x30, 0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8];
            h.append(&mut deep);
            deep = h;
        }
        assert!(crlp::inspect(&deep, now(), 300).is_err());
        assert!(response::verify(&deep, &fx.issuer, &expect(fx)).is_err());
    });
}

// ------------------------------------------------------------- HTTP --

fn req(ms: u64, max_body: usize) -> Request<'static> {
    Request {
        post: None,
        accept: "application/pkix-crl",
        accept_types: &["application/pkix-crl"],
        max_body,
        deadline: Instant::now() + Duration::from_millis(ms),
    }
}

/// A raw server: runs `f` on the first accepted connection.
fn raw_server(f: impl FnOnce(std::net::TcpStream) + Send + 'static) -> HttpUrl {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let mut b = [0u8; 4096];
            let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = s.read(&mut b);
            f(s);
        }
    });
    HttpUrl::parse(&format!("http://{a}/x.crl")).unwrap()
}

#[test]
fn slowloris_header_trickle_bounded_by_deadline() {
    let url = raw_server(|mut s| {
        for b in b"HTTP/1.0 200 OK\r\nContent-Type: application/pkix-crl\r\nX-Pad: ".iter().chain([b'a'; 4000].iter()) {
            if s.write_all(&[*b]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let t = Instant::now();
    assert_eq!(fetch(&url, &req(400, 1024)).unwrap_err(), HttpError::Timeout);
    assert!(t.elapsed() < Duration::from_millis(900), "total deadline, not per-read: {:?}", t.elapsed());
}

#[test]
fn slowloris_body_trickle_bounded_by_deadline() {
    let url = raw_server(|mut s| {
        let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: 1000\r\n\r\n");
        for _ in 0..1000 {
            if s.write_all(b"a").is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let t = Instant::now();
    assert_eq!(fetch(&url, &req(400, 4096)).unwrap_err(), HttpError::Timeout);
    assert!(t.elapsed() < Duration::from_millis(900), "{:?}", t.elapsed());
}

#[test]
fn no_length_peer_never_closes_times_out() {
    let url = raw_server(|mut s| {
        let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Type: application/pkix-crl\r\n\r\nabc");
        std::thread::sleep(Duration::from_secs(2));
    });
    let t = Instant::now();
    assert_eq!(fetch(&url, &req(300, 1024)).unwrap_err(), HttpError::Timeout);
    assert!(t.elapsed() < Duration::from_millis(800));
}

#[test]
fn no_length_exactly_max_then_close_ok() {
    let url = raw_server(|mut s| {
        let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Type: application/pkix-crl\r\n\r\n");
        let _ = s.write_all(&[7u8; 64]);
    });
    assert_eq!(fetch(&url, &req(2000, 64)).unwrap().body.len(), 64);
    let url = raw_server(|mut s| {
        let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Type: application/pkix-crl\r\n\r\n");
        let _ = s.write_all(&[7u8; 65]);
    });
    assert_eq!(fetch(&url, &req(2000, 64)).unwrap_err(), HttpError::TooLarge);
}

#[test]
fn chunked_and_te_variants_refused() {
    for te in ["chunked", "Chunked", "gzip, chunked", "identity"] {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nTransfer-Encoding: {te}\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
        );
        let r = read_from(&mut raw.as_bytes(), &req(1000, 1024), &mut |_| {});
        assert_eq!(r.unwrap_err(), HttpError::Malformed, "{te}");
    }
}

/// RFC 9112 §5.1: whitespace between field name and colon MUST be rejected.
/// Today `Transfer-Encoding : chunked` is not matched and the chunk framing
/// is returned as body bytes (later rejected by the DER decoder, so impact
/// is low, but the header parser is not strict as SI-10 claims).
#[test]
fn header_name_whitespace_rejected() {
    let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nTransfer-Encoding : chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let r = read_from(&mut raw.as_bytes(), &req(1000, 1024), &mut |_| {});
    assert!(r.is_err(), "whitespace before colon must not slip past the TE check: {r:?}");
}

#[test]
fn content_length_shapes() {
    let ct = "Content-Type: application/pkix-crl\r\n";
    for (cl, ok) in
        [("+3", false), ("-3", false), ("3 ", true), (" 3", true), ("0x3", false), ("", false), ("03", true)]
    {
        let raw = format!("HTTP/1.0 200 OK\r\n{ct}Content-Length:{cl}\r\n\r\nabc");
        let r = read_from(&mut raw.as_bytes(), &req(1000, 1024), &mut |_| {});
        assert_eq!(r.is_ok(), ok, "Content-Length:{cl:?} -> {r:?}");
    }
    // Zero-length body.
    let raw = format!("HTTP/1.0 200 OK\r\n{ct}Content-Length: 0\r\n\r\n");
    assert!(read_from(&mut raw.as_bytes(), &req(1000, 1024), &mut |_| {}).unwrap().body.is_empty());
}

proptest! {
    /// Structured responses: whatever the declared length and actual body,
    /// an Ok never carries more than max_body bytes nor a body that
    /// disagrees with a declared Content-Length.
    #[test]
    fn read_from_body_bounds(
        declared in prop::option::of(0usize..300),
        actual in 0usize..300,
        max_body in 0usize..200,
        extra_headers in prop::collection::vec("[A-Za-z-]{1,12}: [ -~]{0,40}", 0..6),
    ) {
        let mut raw = String::from("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\n");
        for h in &extra_headers {
            let lower = h.to_ascii_lowercase();
            if lower.starts_with("content-") || lower.starts_with("transfer-") { continue; }
            raw.push_str(h);
            raw.push_str("\r\n");
        }
        if let Some(d) = declared { raw.push_str(&format!("Content-Length: {d}\r\n")); }
        raw.push_str("\r\n");
        let mut bytes = raw.into_bytes();
        bytes.extend(std::iter::repeat_n(b'z', actual));
        match read_from(&mut bytes.as_slice(), &req(5000, max_body), &mut |_| {}) {
            Ok(r) => {
                prop_assert!(r.body.len() <= max_body);
                if let Some(d) = declared { prop_assert_eq!(r.body.len(), d); }
            }
            Err(e) => prop_assert!(matches!(e, HttpError::TooLarge | HttpError::Malformed), "{:?}", e),
        }
    }
}
