//! QA: `platd check-config` exit codes as an operator sees them (CM-6).
//! 0 = usable; 2 = unreadable/unparseable/invalid config or unusable TLS
//! material. Runs the real binary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};

const EXAMPLE: &str = include_str!("../../../config/platd.example.toml");

struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("platd-qa-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn write(&self, name: &str, body: &str, mode: u32) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Pki {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

fn pki(days_left: i64) -> Pki {
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "QA CA");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = p.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(p, ca_key);
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut l = CertificateParams::new(vec!["mgmt.example.net".into()]).unwrap();
    l.distinguished_name.push(DnType::CommonName, "mgmt.example.net");
    l.not_after = (std::time::SystemTime::now()
        + std::time::Duration::from_secs(u64::try_from(days_left).unwrap() * 86_400))
    .into();
    let cert = l.signed_by(&key, &issuer).unwrap();
    Pki { ca_pem: ca.pem(), cert_pem: cert.pem(), key_pem: key.serialize_pem() }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_platd")).args(args).env("RUST_LOG", "off").output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

fn check(cfg: &Path, env: bool) -> Output {
    let p = cfg.to_str().unwrap();
    if env { run(&["check-config", "--config", p, "--format", "env"]) } else { run(&["check-config", "--config", p]) }
}

fn mgmt_cfg(d: &Dir, key_mode: u32, days: i64) -> PathBuf {
    let k = pki(days);
    let ca = d.write("ca.pem", &k.ca_pem, 0o644);
    let cert = d.write("m.pem", &k.cert_pem, 0o644);
    let key = d.write("m.key", &k.key_pem, key_mode);
    let text = EXAMPLE.replace(
        "listen = \"127.0.0.1:9464\"",
        &format!(
            "listen = \"127.0.0.1:9464\"\n[management.tls]\ncert_file = \"{}\"\nkey_file = \"{}\"\n\
             client_ca_file = \"{}\"\nallowed_clients = [\"cn:prom\"]",
            cert.display(),
            key.display(),
            ca.display()
        ),
    );
    d.write("platd.toml", &text, 0o644)
}

#[test]
fn exit_codes_basic() {
    let d = Dir::new("basic");
    let ok = d.write("ok.toml", EXAMPLE, 0o644);
    let o = check(&ok, false);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("TLS:") && out.contains("management: plain-loopback"), "{out}");
    assert!(out.contains("audit file min_free_bytes: 2147483648 (AU-5(1))"), "{out}");
    assert_eq!(code(&check(&ok, true)), 0);
    // POAM-020: an omitted threshold is shown with its computed default;
    // an explicit 0 is refused (exit 2) in both formats.
    let dflt = d.write("dflt.toml", &EXAMPLE.replace("min_free_bytes = 2147483648\n", ""), 0o644);
    let o = check(&dflt, false);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("audit file min_free_bytes: 2147483648 (AU-5(1))"));
    let zero = d.write("zero.toml", &EXAMPLE.replace("min_free_bytes = 2147483648", "min_free_bytes = 0"), 0o644);
    let o = check(&zero, false);
    assert_eq!(code(&o), 2);
    assert!(String::from_utf8_lossy(&o.stderr).contains("min_free_bytes"));
    assert_eq!(code(&check(&zero, true)), 2);
    // Missing file, parse error, validation error.
    assert_eq!(code(&check(&d.0.join("missing.toml"), false)), 2);
    assert_eq!(code(&check(&d.0.join("missing.toml"), true)), 2);
    let unk = d.write("unk.toml", &format!("{EXAMPLE}\n[tls]\nbogus = 1\n"), 0o644);
    assert_eq!(code(&check(&unk, false)), 2);
    let inv = d.write("inv.toml", &EXAMPLE.replace("127.0.0.1:9464", "0.0.0.0:9464"), 0o644);
    assert_eq!(code(&check(&inv, false)), 2);
    assert_eq!(code(&check(&inv, true)), 2);
    // Usage error (clap).
    assert_eq!(code(&run(&["check-config", "--format", "xml", "--config", ok.to_str().unwrap()])), 2);
}

#[test]
fn mgmt_tls_good_and_bad_material() {
    let d = Dir::new("mgmt");
    let cfg = mgmt_cfg(&d, 0o600, 365);
    let o = check(&cfg, false);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("management: mTLS"), "{out}");
    let o = check(&cfg, true);
    assert_eq!(code(&o), 0);
    assert!(String::from_utf8_lossy(&o.stdout).contains("PLAT_MGMT_TLS=1\n"));
    // World-readable key: text mode fails closed.
    std::fs::set_permissions(d.0.join("m.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = check(&cfg, false);
    assert_eq!(code(&o), 2, "{}", String::from_utf8_lossy(&o.stdout));
    assert!(String::from_utf8_lossy(&o.stderr).contains("permissions"));
    // Missing CA file.
    std::fs::set_permissions(d.0.join("m.key"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(d.0.join("ca.pem")).unwrap();
    assert_eq!(code(&check(&cfg, false)), 2);
}

#[test]
fn expiring_cert_warns_but_passes() {
    let d = Dir::new("expiry");
    let cfg = mgmt_cfg(&d, 0o600, 10);
    let o = check(&cfg, false);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("WARNING"), "{}", String::from_utf8_lossy(&o.stdout));
}

#[test]
fn bad_cache_dir_fails() {
    let d = Dir::new("cachedir");
    let open = d.0.join("cache");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    let text =
        EXAMPLE.replacen("[tls.revocation]\n", &format!("[tls.revocation]\ncache_dir = \"{}\"\n", open.display()), 1);
    if !text.contains("cache_dir = \"/") {
        return; // example has no [tls.revocation] table to extend
    }
    let cfg = d.write("c.toml", &text, 0o644);
    let o = check(&cfg, false);
    assert_eq!(code(&o), 2);
    assert!(String::from_utf8_lossy(&o.stderr).contains("cache_dir"), "{}", String::from_utf8_lossy(&o.stderr));
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(code(&check(&cfg, false)), 0);
}

/// The plan says key permissions are "checked in check-config and at
/// start (fail closed)". The env format (used by the systemd setup script
/// and POAM-017 node comparison) never loads TLS material, so it exits 0
/// with a world-readable management key.
#[test]
fn env_format_fails_closed_on_bad_key() {
    let d = Dir::new("envkey");
    let cfg = mgmt_cfg(&d, 0o644, 365);
    assert_eq!(code(&check(&cfg, true)), 2);
}
