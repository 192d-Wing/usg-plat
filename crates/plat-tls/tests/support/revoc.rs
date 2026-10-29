//! In-test OCSP responses and CRLs built from the `x509-ocsp` /
//! `x509-cert` types and signed with aws-lc-rs (keys from the rcgen test
//! PKI). Every knob a test needs to forge, age or mis-scope data is here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use der::asn1::{BitString, GeneralizedTime, Ia5String, ObjectIdentifier as Oid, OctetString, UtcTime};
use der::{Decode, Encode};
use rustls_pki_types::CertificateDer;
use x509_cert::Certificate;
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::crl::dp::IssuingDistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;
use x509_ocsp::{
    BasicOcspResponse, CertStatus, OcspGeneralizedTime, OcspRequest, OcspResponse, ResponderId, ResponseBytes,
    ResponseData, RevokedInfo, SingleResponse, Version,
};

use super::http_server::{Reply, Request};
use super::pki::{Ca, Responder};

const ECDSA_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
const NONCE: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.1.2");

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn gt(off: i64) -> GeneralizedTime {
    GeneralizedTime::from_unix_duration(Duration::from_secs((now_secs() + off) as u64)).unwrap()
}

fn ut(off: i64) -> Time {
    Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs((now_secs() + off) as u64)).unwrap())
}

/// ECDSA P-256/SHA-256 signature with a PKCS#8 key.
pub fn sign(pkcs8: &[u8], msg: &[u8]) -> Vec<u8> {
    let k = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8).unwrap();
    k.sign(&SystemRandom::new(), msg).unwrap().as_ref().to_vec()
}

fn alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned { oid: ECDSA_SHA256, parameters: None }
}

pub fn serial_of(der: &CertificateDer<'_>) -> Vec<u8> {
    Certificate::from_der(der).unwrap().tbs_certificate.serial_number.as_bytes().to_vec()
}

/// DER of the subject Name of `der`.
pub fn subject_der(der: &CertificateDer<'_>) -> Vec<u8> {
    subject(der).to_der().unwrap()
}

fn subject(der: &CertificateDer<'_>) -> Name {
    Certificate::from_der(der).unwrap().tbs_certificate.subject
}

// ---------------------------------------------------------------- OCSP --

/// Status answered for a serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum St {
    Good,
    Revoked(u8),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NonceMode {
    #[default]
    Echo,
    Omit,
    Wrong,
}

/// Who signs a response.
#[derive(Debug, Clone)]
pub struct Signer {
    pub name: Name,
    pub pkcs8: Vec<u8>,
    /// Certificates included in the response.
    pub certs: Vec<CertificateDer<'static>>,
}

impl Signer {
    pub fn ca(ca: &Ca) -> Self {
        Self { name: subject(&ca.der), pkcs8: ca.key_pkcs8(), certs: Vec::new() }
    }

    pub fn delegate(r: &Responder) -> Self {
        Self { name: subject(&r.der), pkcs8: r.key.serialize_der(), certs: vec![r.der.clone()] }
    }
}

/// Knobs of the in-test responder.
#[derive(Debug, Clone)]
pub struct OcspCfg {
    /// serial → status; serials not listed answer `unknown`.
    pub status: HashMap<Vec<u8>, St>,
    /// issuer key hash in the request (as sent) → signer.
    pub signers: Vec<(Vec<u8>, Signer)>,
    pub this_off: i64,
    /// `None` omits nextUpdate.
    pub next_off: Option<i64>,
    pub nonce: NonceMode,
    pub corrupt_sig: bool,
    pub wrong_serial: bool,
}

impl Default for OcspCfg {
    fn default() -> Self {
        Self {
            status: HashMap::new(),
            signers: Vec::new(),
            this_off: -60,
            next_off: Some(3600),
            nonce: NonceMode::Echo,
            corrupt_sig: false,
            wrong_serial: false,
        }
    }
}

impl OcspCfg {
    /// Registers `ca` as the signer for certificates it issued.
    pub fn sign_for(&mut self, ca: &Ca, s: Signer) {
        let c = Certificate::from_der(&ca.der).unwrap();
        let bits = c.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes().to_vec();
        for alg in [&aws_lc_rs::digest::SHA256, &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY] {
            self.signers.push((aws_lc_rs::digest::digest(alg, &bits).as_ref().to_vec(), s.clone()));
        }
    }
}

fn b64_decode(s: &str) -> Vec<u8> {
    let s = s.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=");
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            _ => 63,
        }
    };
    let mut out = Vec::new();
    for ch in s.as_bytes().chunks(4) {
        let pad = ch.iter().filter(|&&c| c == b'=').count();
        let v = ch.iter().fold(0u32, |a, &c| (a << 6) | if c == b'=' { 0 } else { val(c) });
        let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    out
}

/// The DER request from a POST body or a GET path.
pub fn request_der(r: &Request) -> Vec<u8> {
    if r.method == "POST" { r.body.clone() } else { b64_decode(r.path.rsplit('/').next().unwrap()) }
}

/// Builds a signed response to `req` per `cfg`.
pub fn respond(cfg: &OcspCfg, req: &[u8]) -> Vec<u8> {
    let req = OcspRequest::from_der(req).unwrap();
    let mut id = req.tbs_request.request_list[0].req_cert.clone();
    let st = cfg.status.get(id.serial_number.as_bytes()).copied().unwrap_or(St::Unknown);
    let signer = cfg
        .signers
        .iter()
        .find(|(h, _)| h.as_slice() == id.issuer_key_hash.as_bytes())
        .map(|(_, s)| s.clone())
        .expect("no signer for issuer");
    if cfg.wrong_serial {
        id.serial_number = SerialNumber::new(&[0x7f, 0x7f]).unwrap();
    }
    let cert_status = match st {
        St::Good => CertStatus::good(),
        St::Unknown => CertStatus::unknown(),
        St::Revoked(code) => CertStatus::Revoked(RevokedInfo {
            revocation_time: OcspGeneralizedTime(gt(-3600)),
            revocation_reason: Some(x509_cert::ext::pkix::CrlReason::from_der(&[0x0a, 0x01, code]).unwrap()),
        }),
    };
    let sent = req.tbs_request.request_extensions.as_ref().and_then(|e| e.iter().find(|x| x.extn_id == NONCE).cloned());
    let nonce = match (cfg.nonce, sent) {
        (NonceMode::Echo, Some(x)) => Some(x),
        (NonceMode::Wrong, Some(_)) | (NonceMode::Wrong, None) => {
            let v = OctetString::new(vec![9u8; 32]).unwrap().to_der().unwrap();
            Some(Extension { extn_id: NONCE, critical: false, extn_value: OctetString::new(v).unwrap() })
        }
        _ => None,
    };
    let data = ResponseData {
        version: Version::V1,
        responder_id: ResponderId::ByName(signer.name.clone()),
        produced_at: OcspGeneralizedTime(gt(0)),
        responses: vec![SingleResponse {
            cert_id: id,
            cert_status,
            this_update: OcspGeneralizedTime(gt(cfg.this_off)),
            next_update: cfg.next_off.map(|o| OcspGeneralizedTime(gt(o))),
            single_extensions: None,
        }],
        response_extensions: nonce.map(|n| vec![n]),
    };
    let mut sig = sign(&signer.pkcs8, &data.to_der().unwrap());
    if cfg.corrupt_sig {
        let n = sig.len() - 3;
        sig[n] ^= 0x55;
    }
    let certs = (!signer.certs.is_empty())
        .then(|| signer.certs.iter().map(|c| Certificate::from_der(c).unwrap()).collect::<Vec<_>>());
    let basic = BasicOcspResponse {
        tbs_response_data: data,
        signature_algorithm: alg(),
        signature: BitString::from_bytes(&sig).unwrap(),
        certs,
    };
    OcspResponse {
        response_status: x509_ocsp::OcspResponseStatus::Successful,
        response_bytes: Some(ResponseBytes {
            response_type: Oid::new_unwrap("1.3.6.1.5.5.7.48.1.1"),
            response: OctetString::new(basic.to_der().unwrap()).unwrap(),
        }),
    }
    .to_der()
    .unwrap()
}

/// A responder handler driven by a shared, mutable config.
pub fn ocsp_handler(cfg: Arc<Mutex<OcspCfg>>) -> impl Fn(&Request) -> Reply + Send + Sync + 'static {
    move |r: &Request| {
        let c = cfg.lock().unwrap().clone();
        Reply::ok("application/ocsp-response", respond(&c, &request_der(r)))
    }
}

// ----------------------------------------------------------------- CRL --

/// Knobs of a built CRL.
#[derive(Debug, Clone)]
pub struct CrlOpts {
    /// (serial, reasonCode)
    pub revoked: Vec<(Vec<u8>, Option<u8>)>,
    pub this_off: i64,
    pub next_off: Option<i64>,
    pub number: u8,
    /// Omit the cRLNumber extension.
    pub no_number: bool,
    /// Add the cRLNumber extension twice.
    pub dup_number: bool,
    pub delta: bool,
    pub indirect: bool,
    pub only_some_reasons: bool,
    pub only_ca: bool,
    pub only_user: bool,
    pub idp_uri: Option<String>,
    /// IDP fullName directoryNames (DER of Names), after `idp_uri`.
    pub idp_dirs: Vec<Vec<u8>>,
    pub unknown_critical: bool,
    pub entry_cert_issuer: bool,
    pub corrupt_sig: bool,
}

impl Default for CrlOpts {
    fn default() -> Self {
        Self {
            revoked: Vec::new(),
            this_off: -60,
            next_off: Some(7 * 24 * 3600),
            number: 1,
            no_number: false,
            dup_number: false,
            delta: false,
            indirect: false,
            only_some_reasons: false,
            only_ca: false,
            only_user: false,
            idp_uri: None,
            idp_dirs: Vec::new(),
            unknown_critical: false,
            entry_cert_issuer: false,
            corrupt_sig: false,
        }
    }
}

fn ext(oid: &str, critical: bool, value: Vec<u8>) -> Extension {
    Extension { extn_id: Oid::new_unwrap(oid), critical, extn_value: OctetString::new(value).unwrap() }
}

/// A CRL signed by `ca` (issuer name from `ca`).
pub fn crl(ca: &Ca, o: &CrlOpts) -> Vec<u8> {
    crl_signed(&subject(&ca.der), &ca.key_pkcs8(), o)
}

/// A CRL with issuer `name`, signed with `pkcs8`.
pub fn crl_signed(name: &Name, pkcs8: &[u8], o: &CrlOpts) -> Vec<u8> {
    let mut exts = Vec::new();
    if !o.no_number {
        exts.push(ext("2.5.29.20", false, der::asn1::Uint::new(&[o.number]).unwrap().to_der().unwrap()));
    }
    if o.dup_number {
        exts.push(ext("2.5.29.20", false, der::asn1::Uint::new(&[o.number]).unwrap().to_der().unwrap()));
    }
    if o.delta {
        exts.push(ext("2.5.29.27", true, der::asn1::Uint::new(&[1]).unwrap().to_der().unwrap()));
    }
    if o.indirect || o.only_some_reasons || o.only_ca || o.only_user || o.idp_uri.is_some() || !o.idp_dirs.is_empty() {
        let names: Vec<GeneralName> = o
            .idp_uri
            .iter()
            .map(|u| GeneralName::UniformResourceIdentifier(Ia5String::new(u).unwrap()))
            .chain(o.idp_dirs.iter().map(|d| GeneralName::DirectoryName(Name::from_der(d).unwrap())))
            .collect();
        let idp = IssuingDistributionPoint {
            distribution_point: (!names.is_empty()).then_some(DistributionPointName::FullName(names)),
            only_contains_user_certs: o.only_user,
            only_contains_ca_certs: o.only_ca,
            only_some_reasons: o
                .only_some_reasons
                .then(|| x509_cert::ext::pkix::crl::dp::Reasons::KeyCompromise.into()),
            indirect_crl: o.indirect,
            only_contains_attribute_certs: false,
        };
        exts.push(ext("2.5.29.28", true, idp.to_der().unwrap()));
    }
    if o.unknown_critical {
        exts.push(ext("1.3.6.1.4.1.99999.1", true, vec![0x05, 0x00]));
    }
    let revoked: Vec<RevokedCert> = o
        .revoked
        .iter()
        .map(|(s, r)| {
            let mut e = Vec::new();
            if let Some(code) = r {
                e.push(ext("2.5.29.21", false, vec![0x0a, 0x01, *code]));
            }
            if o.entry_cert_issuer {
                let gn = vec![GeneralName::DirectoryName(name.clone())];
                e.push(ext("2.5.29.29", true, gn.to_der().unwrap()));
            }
            RevokedCert {
                serial_number: SerialNumber::new(s).unwrap(),
                revocation_date: ut(-3600),
                crl_entry_extensions: (!e.is_empty()).then_some(e),
            }
        })
        .collect();
    let tbs = TbsCertList {
        version: x509_cert::Version::V2,
        signature: alg(),
        issuer: name.clone(),
        this_update: ut(o.this_off),
        next_update: o.next_off.map(ut),
        revoked_certificates: (!revoked.is_empty()).then_some(revoked),
        crl_extensions: Some(exts),
    };
    let mut sig = sign(pkcs8, &tbs.to_der().unwrap());
    if o.corrupt_sig {
        let n = sig.len() - 3;
        sig[n] ^= 0x55;
    }
    CertificateList { tbs_cert_list: tbs, signature_algorithm: alg(), signature: BitString::from_bytes(&sig).unwrap() }
        .to_der()
        .unwrap()
}

/// A CDP/CRL server whose body can be swapped by the test.
pub fn crl_handler(body: Arc<Mutex<Vec<u8>>>) -> impl Fn(&Request) -> Reply + Send + Sync + 'static {
    move |_r: &Request| Reply::ok("application/pkix-crl", body.lock().unwrap().clone())
}

// ----------------------------------------------------------------- rig --

use plat_common::config::{CrlConfig, OcspConfig, RevocationMode};
use plat_tls::revocation::{
    Anchors, ChainVerdict, RefreshRecord, RevocationChecker, RevocationRecord, RevocationSettings, Role,
};
use rustls_pki_types::UnixTime;

pub type Recs = Arc<Mutex<Vec<RevocationRecord>>>;

/// Short timeouts so failure tests stay fast; OCSP and CRL both on.
pub fn settings(mode: RevocationMode) -> RevocationSettings {
    RevocationSettings {
        mode,
        skew: Duration::from_secs(300),
        budget: Duration::from_millis(4000),
        cache_dir: None,
        ocsp: OcspConfig { timeout_ms: 1000, ..OcspConfig::default() },
        crl: CrlConfig { timeout_ms: 1000, ..CrlConfig::default() },
    }
}

pub fn anchors(ca: &[&Ca]) -> Anchors {
    Anchors::parse(&ca.iter().map(|c| c.der.clone()).collect::<Vec<_>>()).unwrap()
}

/// A real checker (OCSP + CRL clients) with captured hook output.
#[derive(Debug)]
pub struct Rig {
    pub c: Arc<RevocationChecker>,
    pub recs: Recs,
    pub refresh: Arc<Mutex<Vec<RefreshRecord>>>,
}

impl Rig {
    pub fn new(s: RevocationSettings) -> Self {
        let recs: Recs = Arc::new(Mutex::new(Vec::new()));
        let refresh = Arc::new(Mutex::new(Vec::new()));
        let (r, f) = (recs.clone(), refresh.clone());
        let c = RevocationChecker::new_with_refresh_hook(
            s,
            Arc::new(move |x: &RevocationRecord| r.lock().unwrap().push(x.clone())),
            Arc::new(move |x: &RefreshRecord| f.lock().unwrap().push(x.clone())),
        )
        .unwrap();
        Self { c, recs, refresh }
    }

    pub fn check_at(
        &self,
        role: Role,
        leaf: &CertificateDer<'_>,
        inter: &[CertificateDer<'static>],
        a: &Anchors,
        stapled: Option<&[u8]>,
        now: UnixTime,
    ) -> ChainVerdict {
        let v = self.c.check_chain(role, leaf, inter, a, stapled, now);
        assert_eq!(v.records.len(), inter.len() + 1, "one record per non-root certificate");
        v
    }

    pub fn check(&self, leaf: &CertificateDer<'_>, inter: &[CertificateDer<'static>], a: &Anchors) -> ChainVerdict {
        self.check_at(Role::MgmtClient, leaf, inter, a, None, UnixTime::now())
    }
}

/// `UnixTime` `secs` from now.
pub fn at(secs: i64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs((now_secs() + secs) as u64))
}
