//! QA: key/cert file edge cases beyond the mode table (SC-12, IA-5(2)(a)(1),
//! AC-6): non-regular files, symlinks, special bits, and a property test
//! over the pure permission decision.

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use std::sync::mpsc;
use std::time::Duration;

use plat_tls::load::key_perm_decision;
use plat_tls::{TlsError, check_cache_dir, check_key_file, load_certs, load_key};
use proptest::prelude::*;
use support::pki::{Ca, LeafOpts, TempDir, set_mode};

proptest! {
    /// Whatever (uid, gid, mode), an accepted key is owner-readable, has no
    /// owner-execute, no group write/execute, no other bits, and is owned
    /// by us or by root with our group and group-read.
    #[test]
    fn perm_decision_invariants(uid in 0u32..4, gid in 0u32..4, mode in 0u32..0o10000, euid in 0u32..4, egid in 0u32..4) {
        if key_perm_decision(uid, gid, mode, euid, egid).is_ok() {
            let p = mode & 0o777;
            prop_assert_eq!(p & 0o137, 0);
            prop_assert!(p & 0o400 != 0);
            prop_assert!(uid == euid || (uid == 0 && gid == egid && p & 0o040 != 0));
        }
    }
}

#[test]
fn special_bits_are_rejected() {
    // QA-004: setuid/setgid/sticky on a key file are rejected.
    for m in [0o4600, 0o2600, 0o1600, 0o104_600] {
        assert!(key_perm_decision(1000, 1000, m, 1000, 1000).is_err(), "{m:o}");
    }
    key_perm_decision(1000, 1000, 0o100_600, 1000, 1000).unwrap();
}

#[test]
fn key_is_a_directory() {
    let d = TempDir::new("qa-keydir");
    let p = d.path().join("k.key");
    std::fs::create_dir(&p).unwrap();
    set_mode(&p, 0o700);
    assert!(load_key(&p).is_err());
    assert!(check_key_file(&p).is_err());
}

#[test]
fn symlink_judged_by_target() {
    let d = TempDir::new("qa-keylink");
    let leaf = Ca::root("Link Root").leaf(&LeafOpts::client("c"));
    let open = d.write("open.key", &leaf.key_pem, 0o644);
    let link = d.path().join("link.key");
    std::os::unix::fs::symlink(&open, &link).unwrap();
    // The link itself is 0777; the target is world-readable: reject.
    assert!(matches!(load_key(&link), Err(TlsError::Permissions(..))));
    let tight = d.write("tight.key", &leaf.key_pem, 0o600);
    let link2 = d.path().join("link2.key");
    std::os::unix::fs::symlink(&tight, &link2).unwrap();
    load_key(&link2).unwrap();
    // Dangling link: I/O error, not a panic.
    let dangling = d.path().join("dangling.key");
    std::os::unix::fs::symlink(d.path().join("nope"), &dangling).unwrap();
    assert!(matches!(load_key(&dangling), Err(TlsError::Io(..))));
}

#[test]
fn cache_dir_symlink_and_special_bits() {
    let d = TempDir::new("qa-cachedir");
    let real = d.path().join("real");
    std::fs::create_dir(&real).unwrap();
    set_mode(&real, 0o700);
    let link = d.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    check_cache_dir(&link).unwrap();
    for bad in [0o710, 0o701, 0o770, 0o777] {
        set_mode(&real, bad);
        assert!(matches!(check_cache_dir(&real), Err(TlsError::Permissions(..))), "{bad:o}");
    }
}

#[test]
fn key_file_with_cert_then_key_and_two_keys() {
    let d = TempDir::new("qa-keymix");
    let a = Ca::root("Mix Root").leaf(&LeafOpts::client("a"));
    let b = Ca::root("Mix Root 2").leaf(&LeafOpts::client("b"));
    let p = d.write("mix.key", &format!("{}{}{}", a.pem, a.key_pem, b.key_pem), 0o600);
    let k = load_key(&p).unwrap();
    // First key wins.
    let only_a = d.write("a.key", &a.key_pem, 0o600);
    assert_eq!(k.secret_der(), load_key(&only_a).unwrap().secret_der());
}

#[test]
fn cert_bundle_limits() {
    let d = TempDir::new("qa-bundle");
    let root = Ca::root("Bundle Root");
    let many: String = std::iter::repeat_n(root.pem.as_str(), 257).collect();
    let p = d.write("many.pem", &many, 0o644);
    if many.len() <= 1 << 20 {
        assert!(matches!(load_certs(&p), Err(TlsError::Pem(..))));
    }
    let exact: String = std::iter::repeat_n(root.pem.as_str(), 256).collect();
    if exact.len() <= 1 << 20 {
        assert_eq!(load_certs(&d.write("exact.pem", &exact, 0o644)).unwrap().len(), 256);
    }
    // A private key in a certificate file is not a certificate.
    let leaf = root.leaf(&LeafOpts::client("c"));
    assert!(matches!(load_certs(&d.write("k.pem", &leaf.key_pem, 0o600)), Err(TlsError::NoCertificates(_))));
}

/// A FIFO at the key path must not hang `check-config` / start: open(2) on
/// a FIFO with no writer blocks forever, before the regular-file check.
#[test]
fn fifo_key_does_not_hang() {
    let d = TempDir::new("qa-fifo");
    let p = d.path().join("k.key");
    let st = std::process::Command::new("mkfifo").arg(&p).status().unwrap();
    assert!(st.success());
    set_mode(&p, 0o600);
    let (tx, rx) = mpsc::channel();
    let p2 = p.clone();
    std::thread::spawn(move || {
        let r = check_key_file(&p2).is_err() && load_key(&p2).is_err() && load_certs(&p2).is_err();
        let _ = tx.send(r);
    });
    let r = rx.recv_timeout(Duration::from_secs(3));
    if r.is_err() {
        // Unblock the stuck open so the test process can exit.
        let _ = std::fs::OpenOptions::new().write(true).open(&p);
    }
    assert_eq!(r, Ok(true), "a loader hung or accepted a FIFO");
}

/// Plan §8: a TLS 1.2-only server must fail the handshake (TLS 1.3 only,
/// RFC 9325 §4.1 as profiled). rustls is built without `tls12`, so the
/// "server" is a raw socket that answers the ClientHello with a TLS 1.2
/// ServerHello (no supported_versions extension).
#[test]
fn tls12_only_server_is_refused() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    let d = TempDir::new("qa-tls12");
    let root = Ca::root("TLS12 Root");
    let ca = d.write("ca.pem", &root.pem, 0o644);
    let cfg = plat_tls::client_config(&plat_tls::ClientSettings {
        ca_file: ca,
        client_auth: None,
        pq_hybrid: true,
        revocation: None,
    })
    .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut hdr = [0u8; 5];
        s.read_exact(&mut hdr).unwrap();
        let mut ch = vec![0u8; usize::from(u16::from_be_bytes([hdr[3], hdr[4]]))];
        s.read_exact(&mut ch).unwrap();
        // ServerHello: legacy_version 0x0303, random, empty session id,
        // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, null compression, no ext.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.extend_from_slice(&[0x00, 0xc0, 0x2b, 0x00]);
        let mut hs = vec![0x02, 0x00, 0x00, u8::try_from(body.len()).unwrap()];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x03, 0x00, u8::try_from(hs.len()).unwrap()];
        rec.extend_from_slice(&hs);
        let _ = s.write_all(&rec);
        // Some(true): alert record received; None: client closed/reset first.
        let mut alert = [0u8; 7];
        let got = match s.read_exact(&mut alert) {
            Ok(()) => Some(alert[0] == 0x15),
            Err(_) => None,
        };
        (ch, got)
    });
    let name = plat_tls::policy::server_name("svc.example.net").unwrap();
    let mut conn = rustls::ClientConnection::new(cfg, name).unwrap();
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let r = conn.complete_io(&mut sock);
    let err = r.expect_err("handshake with a TLS 1.2 ServerHello must fail");
    let refused = refused_tls12(&err);
    assert!(refused, "client must refuse TLS 1.2, got {err:?}");
    drop(sock);
    let (ch, alerted) = srv.join().unwrap();
    // ClientHello offers only TLS 1.3 in supported_versions (ext 0x002b).
    let versions = client_hello_ext(&ch, 0x002b).expect("supported_versions present");
    assert_eq!(versions, [0x02, 0x03, 0x04], "only TLS 1.3 offered");
    // An alert record must arrive unless the socket closed first; a closed
    // socket is tolerated only because the client error was checked above.
    assert_ne!(alerted, Some(false), "client sends a fatal alert record");
}

/// True when the client error is the expected TLS 1.2 refusal.
fn refused_tls12(err: &std::io::Error) -> bool {
    use rustls::Error as E;
    matches!(
        err.get_ref().and_then(|e| e.downcast_ref::<E>()),
        Some(E::PeerIncompatible(_) | E::PeerMisbehaved(_) | E::InappropriateHandshakeMessage { .. })
    )
}

/// Walks a ClientHello handshake message and returns the body of
/// extension `ty`. Every read is bounds-checked; malformed input -> None.
fn client_hello_ext(ch: &[u8], ty: u16) -> Option<&[u8]> {
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        let (h, t) = (b.get(..n)?, b.get(n..)?);
        *b = t;
        Some(h)
    }
    fn u8v<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
        let n = usize::from(*take(b, 1)?.first()?);
        take(b, n)
    }
    fn u16n(b: &mut &[u8]) -> Option<usize> {
        let x = take(b, 2)?;
        Some(usize::from(u16::from_be_bytes([x[0], x[1]])))
    }
    let mut b = ch;
    if take(&mut b, 1)? != [0x01] {
        return None; // not a ClientHello
    }
    let l = take(&mut b, 3)?;
    let len = usize::from(l[0]) << 16 | usize::from(l[1]) << 8 | usize::from(l[2]);
    let mut b = take(&mut b, len)?;
    take(&mut b, 2 + 32)?; // legacy_version, random
    u8v(&mut b)?; // legacy_session_id
    let n = u16n(&mut b)?;
    take(&mut b, n)?; // cipher_suites
    u8v(&mut b)?; // legacy_compression_methods
    let n = u16n(&mut b)?;
    let mut exts = take(&mut b, n)?;
    while !exts.is_empty() {
        let t = u16n(&mut exts)?;
        let n = u16n(&mut exts)?;
        let body = take(&mut exts, n)?;
        if t == usize::from(ty) {
            return Some(body);
        }
    }
    None
}
