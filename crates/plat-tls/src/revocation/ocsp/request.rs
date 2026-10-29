//! OCSP request construction (RFC 6960 §4.1) and the GET encoding
//! (Appendix A.1). CertID hashes and the nonce come from the FIPS module.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-13 - SHA-256 CertID (SHA-1 only when configured for
//!   RFC 5019 responders; identification, not a signature), DRBG nonce
//! - RFC 6960 §4.1.1, §4.4.1; RFC 8954 (nonce length 32)

use aws_lc_rs::digest;
use der::Encode;
use der::asn1::{Null, ObjectIdentifier as Oid, OctetString};
use plat_common::config::OcspCertIdHash;
use x509_cert::ext::Extension;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_ocsp::{CertId, OcspRequest, Request, TbsRequest, Version};

use crate::revocation::Cert;

pub const ID_SHA1: Oid = Oid::new_unwrap("1.3.14.3.2.26");
pub const ID_SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const ID_PKIX_OCSP_NONCE: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.1.2");

/// RFC 8954 §2.1: 1..=32 octets; we always send 32.
pub const NONCE_LEN: usize = 32;

/// A serialized request and what the response must echo.
#[derive(Debug, Clone)]
pub struct BuiltRequest {
    pub der: Vec<u8>,
    pub cert_id: CertId,
    pub nonce: Option<[u8; NONCE_LEN]>,
}

fn hash(alg: OcspCertIdHash, data: &[u8]) -> Vec<u8> {
    let a = match alg {
        OcspCertIdHash::Sha256 => &digest::SHA256,
        OcspCertIdHash::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
    };
    digest::digest(a, data).as_ref().to_vec()
}

/// CertID for `cert` issued by `issuer` (RFC 6960 §4.1.1).
pub fn cert_id(cert: &Cert, issuer: &Cert, alg: OcspCertIdHash) -> Option<CertId> {
    let (oid, params) = match alg {
        OcspCertIdHash::Sha256 => (ID_SHA256, None),
        // RFC 5019 responders expect the NULL parameter with SHA-1.
        OcspCertIdHash::Sha1 => (ID_SHA1, Some(der::Any::from(Null))),
    };
    Some(CertId {
        hash_algorithm: AlgorithmIdentifierOwned { oid, parameters: params },
        issuer_name_hash: OctetString::new(hash(alg, cert.issuer_der())).ok()?,
        issuer_key_hash: OctetString::new(hash(alg, issuer.spki().subject_public_key.raw_bytes())).ok()?,
        serial_number: cert.x509.tbs_certificate.serial_number.clone(),
    })
}

/// True if `got` identifies the same certificate as `want` (hash
/// algorithm compared by OID; parameters vary between responders).
pub fn same_cert_id(want: &CertId, got: &CertId) -> bool {
    want.hash_algorithm.oid == got.hash_algorithm.oid
        && want.issuer_name_hash == got.issuer_name_hash
        && want.issuer_key_hash == got.issuer_key_hash
        && want.serial_number == got.serial_number
}

/// Builds an unsigned single-certificate request, with a fresh nonce when
/// `nonce` is set. `None` only if the DRBG or the encoder fails.
pub fn build(cert: &Cert, issuer: &Cert, alg: OcspCertIdHash, nonce: bool) -> Option<BuiltRequest> {
    let id = cert_id(cert, issuer, alg)?;
    let mut n = [0u8; NONCE_LEN];
    let (exts, nonce) = if nonce {
        aws_lc_rs::rand::fill(&mut n).ok()?;
        let value = OctetString::new(n.to_vec()).ok()?.to_der().ok()?;
        let e = Extension { extn_id: ID_PKIX_OCSP_NONCE, critical: false, extn_value: OctetString::new(value).ok()? };
        (Some(vec![e]), Some(n))
    } else {
        (None, None)
    };
    let req = OcspRequest {
        tbs_request: TbsRequest {
            version: Version::V1,
            requestor_name: None,
            request_list: vec![Request { req_cert: id.clone(), single_request_extensions: None }],
            request_extensions: exts,
        },
        optional_signature: None,
    };
    Some(BuiltRequest { der: req.to_der().ok()?, cert_id: id, nonce })
}

/// RFC 6960 Appendix A.1 GET path: `<base path>/<url-encoded base64>`.
pub fn get_path(base: &str, der: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(base.len() + der.len() * 2 + 2);
    out.push_str(base.trim_end_matches('/'));
    out.push('/');
    let mut push = |c: u8| match c {
        b'+' => out.push_str("%2B"),
        b'/' => out.push_str("%2F"),
        b'=' => out.push_str("%3D"),
        c => out.push(char::from(c)),
    };
    for chunk in der.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                push(B64[((v >> (18 - 6 * i)) & 0x3f) as usize]);
            } else {
                push(b'=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_encoding() {
        assert_eq!(get_path("/ocsp/", b""), "/ocsp/");
        assert_eq!(get_path("/", b"f"), "/Zg%3D%3D");
        assert_eq!(get_path("/x", b"fo"), "/x/Zm8%3D");
        assert_eq!(get_path("/x", b"foo"), "/x/Zm9v");
        assert_eq!(get_path("/x", &[0xfb, 0xff]), "/x/%2B%2F8%3D");
    }
}
