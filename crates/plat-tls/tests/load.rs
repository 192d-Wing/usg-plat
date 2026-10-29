//! Certificate/key loading and file-permission rules (SC-12, IA-5(2)(a)(1)).

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod support;

use plat_tls::{ClientSettings, TlsError, check_cache_dir, check_key_file, load_certs, load_key};
use support::pki::{Ca, LeafOpts, TempDir};

#[test]
fn certificates() {
    let d = TempDir::new("certs");
    let root = Ca::root("Load Root");
    let inter = root.intermediate("Load Inter");
    let leaf = inter.leaf(&LeafOpts::server("svc.example.net"));
    let bundle = d.write("chain.pem", &format!("{}{}", leaf.pem, inter.pem), 0o644);
    assert_eq!(load_certs(&bundle).unwrap(), vec![leaf.der.clone(), inter.der.clone()]);
    let empty = d.write("empty.pem", "", 0o644);
    assert!(matches!(load_certs(&empty), Err(TlsError::NoCertificates(_))));
    let text = d.write("text.pem", "not a certificate\n", 0o644);
    assert!(matches!(load_certs(&text), Err(TlsError::NoCertificates(_))));
    let broken = d.write("broken.pem", "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n", 0o644);
    assert!(load_certs(&broken).is_err());
    let big = d.write("big.pem", &"a".repeat((1 << 20) + 1), 0o644);
    assert!(matches!(load_certs(&big), Err(TlsError::TooLarge(..))));
    assert!(matches!(load_certs(&d.path().join("missing.pem")), Err(TlsError::Io(..))));
}

#[test]
fn key_permissions_on_disk() {
    let d = TempDir::new("keys");
    let leaf = Ca::root("Key Root").leaf(&LeafOpts::client("c"));
    for ok in [0o600, 0o400, 0o640, 0o440] {
        let p = d.write(&format!("ok-{ok:o}.key"), &leaf.key_pem, ok);
        load_key(&p).unwrap();
        check_key_file(&p).unwrap();
    }
    for bad in [0o644, 0o660, 0o606, 0o620, 0o666, 0o700] {
        let p = d.write(&format!("bad-{bad:o}.key"), &leaf.key_pem, bad);
        assert!(matches!(load_key(&p), Err(TlsError::Permissions(..))), "{bad:o}");
        assert!(matches!(check_key_file(&p), Err(TlsError::Permissions(..))), "{bad:o}");
    }
}

#[test]
fn key_contents() {
    let d = TempDir::new("keyfmt");
    let leaf = Ca::root("Key Root 2").leaf(&LeafOpts::client("c"));
    let enc = d.write(
        "enc.key",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIBAA==\n-----END ENCRYPTED PRIVATE KEY-----\n",
        0o600,
    );
    assert!(matches!(load_key(&enc), Err(TlsError::EncryptedKey(_))));
    let cert_as_key = d.write("cert.key", &leaf.pem, 0o600);
    assert!(matches!(load_key(&cert_as_key), Err(TlsError::NoKey(_))));
    let empty = d.write("empty.key", "", 0o600);
    assert!(matches!(load_key(&empty), Err(TlsError::NoKey(_))));
}

#[test]
fn cache_dir_rules() {
    let d = TempDir::new("cache");
    check_cache_dir(d.path()).unwrap();
    let open = d.path().join("open");
    std::fs::create_dir(&open).unwrap();
    support::pki::set_mode(&open, 0o755);
    assert!(matches!(check_cache_dir(&open), Err(TlsError::Permissions(..))));
    let f = d.write("file", "", 0o600);
    assert!(matches!(check_cache_dir(&f), Err(TlsError::Permissions(..))));
}

/// Fail closed: a bad client key or CA stops the config from being built.
#[test]
fn client_config_fails_closed() {
    let d = TempDir::new("cfg");
    let root = Ca::root("Cfg Root");
    let leaf = root.leaf(&LeafOpts::client("platd"));
    let ca = d.write("ca.pem", &root.pem, 0o644);
    let cert = d.write("c.pem", &leaf.pem, 0o644);
    let key = d.write("c.key", &leaf.key_pem, 0o644);
    let s = ClientSettings {
        ca_file: ca.clone(),
        client_auth: Some((cert.clone(), key)),
        pq_hybrid: true,
        revocation: None,
    };
    assert!(matches!(plat_tls::client_config(&s), Err(TlsError::Permissions(..))));
    let key = d.write("c2.key", &leaf.key_pem, 0o600);
    let s = ClientSettings { client_auth: Some((cert, key)), ..s };
    assert!(plat_tls::client_config(&s).unwrap().fips());
    let s = ClientSettings { ca_file: d.write("bad-ca.pem", "", 0o644), ..s };
    assert!(matches!(plat_tls::client_config(&s), Err(TlsError::NoCertificates(_))));
}
