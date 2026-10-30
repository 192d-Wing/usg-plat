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
fn pool_capacity_is_reported_and_undersized_pool_warns() {
    let d = Dir::new("capacity");
    // Example: a /24 serves 32 256 one-block subscribers, below max_subscribers.
    let ex = d.write("ex.toml", EXAMPLE, 0o644);
    let o = check(&ex, false);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("port blocks: 126 per address x 256 addresses = 32256 (512 ports each)"), "{out}");
    assert!(out.contains("8064 at 4 blocks") && out.contains("WARNING: the pool has 32256 blocks"), "{out}");
    // The warning names smaller uniform layouts with the same 2048-port maximum.
    assert!(out.contains("hint: port_block_size = 128, max_blocks_per_subscriber = 16"), "{out}");
    assert!(out.contains("serves 129024 at 1 block (7-bit"), "{out}");
    // Room for one block each but not four: the softer warning.
    let mid = d.write("mid.toml", &EXAMPLE.replace("max_subscribers = 1000000", "max_subscribers = 10000"), 0o644);
    let out = String::from_utf8_lossy(&check(&mid, false).stdout).into_owned();
    assert!(out.contains("WARNING: only 8064 of 10000 subscribers can hold 4 blocks"), "{out}");
    // Sized to fit: no capacity warning.
    let fit = d.write("fit.toml", &EXAMPLE.replace("max_subscribers = 1000000", "max_subscribers = 8000"), 0o644);
    let out = String::from_utf8_lossy(&check(&fit, false).stdout).into_owned();
    assert!(
        out.contains("port blocks:")
            && !out.contains("WARNING: the pool")
            && !out.contains("WARNING: only")
            && !out.contains("hint:"),
        "{out}"
    );
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

/// End-to-end: with `[cluster.ha]` enabled, a block size that shrinks the
/// reserve-ahead budget below 4096 ports gets the advisory; the boundary
/// (exactly 4096) and the default layout do not. Exit code stays 0.
#[test]
fn ha_reserve_ahead_advisory_end_to_end() {
    let d = Dir::new("ha-reserve");
    let k = pki(30);
    let ca = d.write("ca.pem", &k.ca_pem, 0o644);
    let cert = d.write("p.pem", &k.cert_pem, 0o644);
    let key = d.write("p.key", &k.key_pem, 0o600);
    let state = d.0.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let ha = |block: u16, reserve: Option<u16>| {
        let name = EXAMPLE.lines().find(|l| l.starts_with("name = ")).unwrap().to_string();
        let r = reserve.map(|r| format!("reserve_ahead_blocks = {r}\n")).unwrap_or_default();
        let mut t = EXAMPLE
            .replace("port_block_size = 512", &format!("port_block_size = {block}"))
            .replace("node_count = 1", "node_count = 2\npartition = \"slices\"");
        t = t.replacen(
            "[translation]\n",
            &format!(
                "[[cluster.members]]\nid = 0\n{name}\npeer_addr = \"198.51.100.11:7946\"\nidentity = \"dns:plat-01.cluster.example\"\n\n\
                 [[cluster.members]]\nid = 1\nname = \"plat-02-qa\"\npeer_addr = \"198.51.100.12:7946\"\nidentity = \"dns:plat-02.cluster.example\"\n\n\
                 [cluster.ha]\nenabled = true\nlisten = \"198.51.100.11:7946\"\n{r}state_dir = {:?}\n\
                 [cluster.ha.tls]\ncert_file = {:?}\nkey_file = {:?}\nca_file = {:?}\n\n[translation]\n",
                state, cert, key, ca
            ),
            1,
        );
        t
    };
    let run_case = |tag: &str, block: u16, reserve: Option<u16>| {
        let p = d.write(&format!("{tag}.toml"), &ha(block, reserve), 0o644);
        let o = check(&p, false);
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        (code(&o), out, String::from_utf8_lossy(&o.stderr).into_owned())
    };
    // 128 x default reserve (8) = 1024 ports: advisory suggests 32.
    let (c, out, err) = run_case("small", 128, None);
    assert_eq!(c, 0, "{out}{err}");
    assert!(
        out.contains("WARNING: cluster.ha.reserve_ahead_blocks = 8 x port_block_size = 128 reserves 1024 ports")
            && out.contains("consider reserve_ahead_blocks = 32"),
        "{out}"
    );
    // Exactly 4096 ports (128 x 32): no advisory (strict < threshold).
    let (c, out, err) = run_case("edge", 128, Some(32));
    assert_eq!(c, 0, "{out}{err}");
    assert!(!out.contains("reserve_ahead_blocks ="), "{out}");
    // 4095 is impossible with power-of-two sizes; 128 x 31 = 3968 warns.
    let (_, out, _) = run_case("below", 128, Some(31));
    assert!(out.contains("reserves 3968 ports") && out.contains("consider reserve_ahead_blocks = 32"), "{out}");
    // 64-port blocks need 64 to reach 4096; with reserve 1 the suggestion is capped at 64.
    let (_, out, _) = run_case("cap", 64, Some(1));
    assert!(out.contains("consider reserve_ahead_blocks = 64"), "{out}");
    // Default layout with HA: no advisory.
    let (c, out, err) = run_case("default", 512, None);
    assert_eq!(c, 0, "{out}{err}");
    assert!(!out.contains("reserve_ahead_blocks ="), "{out}");
}

/// Hints only name divisor sizes smaller than the current one: 256-port
/// blocks get only the 128 hint; 192 x 1 gets none (256 is not smaller and
/// 192 is not a multiple of 128).
#[test]
fn smaller_block_hint_boundaries_end_to_end() {
    let d = Dir::new("hint-bounds");
    let p = d.write(
        "b256.toml",
        &EXAMPLE
            .replace("port_block_size = 512", "port_block_size = 256")
            .replace("max_blocks_per_subscriber = 4", "max_blocks_per_subscriber = 8"),
        0o644,
    );
    let out = String::from_utf8_lossy(&check(&p, false).stdout).into_owned();
    assert!(out.contains("WARNING: the pool"), "{out}");
    assert!(out.contains("hint: port_block_size = 128, max_blocks_per_subscriber = 16"), "{out}");
    assert!(!out.contains("hint: port_block_size = 256"), "{out}");
    let p = d.write(
        "b192.toml",
        &EXAMPLE
            .replace("port_block_size = 512", "port_block_size = 192")
            .replace("max_blocks_per_subscriber = 4", "max_blocks_per_subscriber = 1"),
        0o644,
    );
    let o = check(&p, false);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert_eq!(code(&o), 0, "{out}");
    assert!(out.contains("WARNING: the pool") && !out.contains("hint:"), "{out}");
}
