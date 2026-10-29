//! In-test PKI (rcgen, aws-lc-rs keys): root, intermediates and leaves,
//! written to a private temporary directory. No key is ever committed.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{
    BasicConstraints, CertificateParams, CrlDistributionPoint, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber, SignatureAlgorithm,
};
use rustls_pki_types::CertificateDer;

static SERIAL: AtomicU64 = AtomicU64::new(0x1000);

fn serial() -> SerialNumber {
    SerialNumber::from(SERIAL.fetch_add(1, Ordering::Relaxed))
}

/// A certificate authority that can issue certificates.
#[derive(Debug)]
pub struct Ca {
    pub der: CertificateDer<'static>,
    pub pem: String,
    pub issuer: Issuer<'static, KeyPair>,
}

/// An issued end-entity certificate and its key.
#[derive(Debug)]
pub struct Leaf {
    pub der: CertificateDer<'static>,
    pub pem: String,
    pub key_pem: String,
}

/// What a leaf certificate carries.
#[derive(Debug, Default, Clone)]
pub struct LeafOpts {
    pub cn: String,
    pub dns: Vec<String>,
    pub uris: Vec<String>,
    pub ips: Vec<std::net::IpAddr>,
    /// id-kp-serverAuth (otherwise clientAuth).
    pub server: bool,
    pub cdp: Vec<String>,
    /// CDP as one fullName with this directoryName (DER of a Name) plus
    /// the `cdp` URIs (replaces the rcgen-built CDP).
    pub cdp_dir: Option<Vec<u8>>,
    /// AIA id-ad-ocsp URIs.
    pub ocsp: Vec<String>,
}

/// Extras for an intermediate CA.
#[derive(Debug, Default, Clone)]
pub struct CaOpts {
    pub cdp: Vec<String>,
    pub ocsp: Vec<String>,
    /// Omit cRLSign from keyUsage.
    pub no_crl_sign: bool,
}

/// CRLDistributionPoints with one DP whose fullName is the directoryName
/// `dn` (DER of a Name) followed by `uris`.
pub fn cdp_dir_ext(dn: &[u8], uris: &[String]) -> rcgen::CustomExtension {
    use der::{Decode, Encode};
    use x509_cert::ext::pkix::crl::dp::DistributionPoint;
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
    let mut names = vec![GeneralName::DirectoryName(x509_cert::name::Name::from_der(dn).unwrap())];
    names.extend(uris.iter().map(|u| GeneralName::UniformResourceIdentifier(der::asn1::Ia5String::new(u).unwrap())));
    let v = x509_cert::ext::pkix::CrlDistributionPoints(vec![DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(names)),
        reasons: None,
        crl_issuer: None,
    }]);
    rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 31], v.to_der().unwrap())
}

/// DER of an AuthorityInfoAccess extension value with id-ad-ocsp URIs.
pub fn aia_ext(uris: &[String]) -> rcgen::CustomExtension {
    use der::Encode;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{AccessDescription, AuthorityInfoAccessSyntax};
    let v = AuthorityInfoAccessSyntax(
        uris.iter()
            .map(|u| AccessDescription {
                access_method: der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1"),
                access_location: GeneralName::UniformResourceIdentifier(der::asn1::Ia5String::new(u).unwrap()),
            })
            .collect(),
    );
    rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], v.to_der().unwrap())
}

impl LeafOpts {
    pub fn server(name: &str) -> Self {
        Self { cn: name.into(), dns: vec![name.into()], server: true, ..Self::default() }
    }

    pub fn client(cn: &str) -> Self {
        Self { cn: cn.into(), ..Self::default() }
    }
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.distinguished_name.push(DnType::OrganizationName, "usg-plat test");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.serial_number = Some(serial());
    p
}

impl Ca {
    pub fn root(cn: &str) -> Self {
        Self::root_with(cn, &rcgen::PKCS_ECDSA_P256_SHA256)
    }

    pub fn root_with(cn: &str, alg: &'static SignatureAlgorithm) -> Self {
        let key = KeyPair::generate_for(alg).unwrap();
        let p = ca_params(cn);
        let cert = p.self_signed(&key).unwrap();
        Self { der: cert.der().clone(), pem: cert.pem(), issuer: Issuer::new(p, key) }
    }

    /// An intermediate CA issued by `self`.
    pub fn intermediate(&self, cn: &str) -> Self {
        self.intermediate_with(cn, &rcgen::PKCS_ECDSA_P256_SHA256)
    }

    pub fn intermediate_with(&self, cn: &str, alg: &'static SignatureAlgorithm) -> Self {
        self.intermediate_opts(cn, alg, &CaOpts::default())
    }

    pub fn intermediate_opts(&self, cn: &str, alg: &'static SignatureAlgorithm, o: &CaOpts) -> Self {
        let key = KeyPair::generate_for(alg).unwrap();
        let mut p = ca_params(cn);
        p.use_authority_key_identifier_extension = true;
        if !o.cdp.is_empty() {
            p.crl_distribution_points = vec![CrlDistributionPoint { uris: o.cdp.clone() }];
        }
        if !o.ocsp.is_empty() {
            p.custom_extensions.push(aia_ext(&o.ocsp));
        }
        if o.no_crl_sign {
            p.key_usages.retain(|k| *k != KeyUsagePurpose::CrlSign);
        }
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        Self { der: cert.der().clone(), pem: cert.pem(), issuer: Issuer::new(p, key) }
    }

    pub fn leaf(&self, o: &LeafOpts) -> Leaf {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, o.cn.as_str());
        p.subject_alt_names = o
            .dns
            .iter()
            .map(|d| SanType::DnsName(d.as_str().try_into().unwrap()))
            .chain(o.uris.iter().map(|u| SanType::URI(u.as_str().try_into().unwrap())))
            .chain(o.ips.iter().map(|ip| SanType::IpAddress(*ip)))
            .collect();
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages =
            vec![if o.server { ExtendedKeyUsagePurpose::ServerAuth } else { ExtendedKeyUsagePurpose::ClientAuth }];
        p.use_authority_key_identifier_extension = true;
        p.serial_number = Some(serial());
        if let Some(dn) = &o.cdp_dir {
            p.custom_extensions.push(cdp_dir_ext(dn, &o.cdp));
        } else if !o.cdp.is_empty() {
            p.crl_distribution_points = vec![CrlDistributionPoint { uris: o.cdp.clone() }];
        }
        if !o.ocsp.is_empty() {
            p.custom_extensions.push(aia_ext(&o.ocsp));
        }
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        Leaf { der: cert.der().clone(), pem: cert.pem(), key_pem: key.serialize_pem() }
    }
}

/// A delegated OCSP responder certificate and its key.
#[derive(Debug)]
pub struct Responder {
    pub der: CertificateDer<'static>,
    pub key: KeyPair,
}

impl Ca {
    /// PKCS#8 of the CA key (for signing OCSP responses and CRLs).
    pub fn key_pkcs8(&self) -> Vec<u8> {
        self.issuer.key().serialize_der()
    }

    /// A responder certificate issued by `self`, with id-kp-OCSPSigning
    /// when `eku`.
    pub fn responder(&self, cn: &str, eku: bool) -> Responder {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages =
            if eku { vec![ExtendedKeyUsagePurpose::OcspSigning] } else { vec![ExtendedKeyUsagePurpose::ClientAuth] };
        p.serial_number = Some(serial());
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        Responder { der: cert.der().clone(), key }
    }
}

/// A private temporary directory removed on drop.
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "plat-tls-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        set_mode(&p, 0o700);
        Self(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Writes `content` to `name` with `mode`.
    pub fn write(&self, name: &str, content: &str, mode: u32) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, content).unwrap();
        set_mode(&p, mode);
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}
