//! Test-only PKI (rcgen, generated per test in a private temporary
//! directory; no key is committed).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SanType, SerialNumber,
};
use rustls_pki_types::CertificateDer;

/// Serializes tests that depend on the FIPS state (the
/// `plat_tls::fips::force_inactive_for_tests` hook is process-global).
pub static FIPS_HOOK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

static SERIAL: AtomicU64 = AtomicU64::new(0x9000);

pub struct Ca {
    pub pem: String,
    issuer: Issuer<'static, KeyPair>,
}

pub struct Leaf {
    pub der: CertificateDer<'static>,
    pub pem: String,
    pub key_pem: String,
    pub serial: u64,
}

impl Ca {
    pub fn new(cn: &str) -> Self {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        p.serial_number = Some(SerialNumber::from(SERIAL.fetch_add(1, Ordering::Relaxed)));
        let cert = p.self_signed(&key).unwrap();
        Self { pem: cert.pem(), issuer: Issuer::new(p, key) }
    }

    /// A leaf with `cn` as subject CN and DNS SAN.
    pub fn leaf(&self, cn: &str, server: bool) -> Leaf {
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
    pub fn crl(&self, serials: &[u64]) -> Vec<u8> {
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

/// A private temporary directory (0700) removed on drop; files are 0600.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "platd-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }

    pub fn write(&self, name: &str, content: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = self.0.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
