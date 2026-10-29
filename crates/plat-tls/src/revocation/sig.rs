//! Signature verification for certificates, OCSP responses and CRLs, inside
//! the AWS-LC FIPS module (`aws-lc-rs`).
//!
//! Accepted algorithms: ECDSA P-256/P-384 with SHA-256/384/512, RSA PKCS#1
//! v1.5 and RSASSA-PSS with SHA-256/384/512, RSA keys 2048..=8192 bits.
//! SHA-1 signatures are rejected (`SigError::Sha1`). RSASSA-PSS parameters
//! must be one of the three canonical encodings (MGF1 with the same hash,
//! salt length = hash length, trailer 1), as webpki does.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS 186-5 signature
//!   verification in the validated module; SHA-1 refused (SP 800-131A).
//! - RFC 5280 §4.1.1.2, RFC 4055 §3.1 (PSS parameters), RFC 5758 §3.2

use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use der::asn1::ObjectIdentifier as Oid;
use der::{Encode, Tag, Tagged};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// Why a signature did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    /// SHA-1 based signature (never accepted).
    Sha1,
    /// Algorithm, curve, parameters or key type not in the accepted set.
    Unsupported,
    /// Well-formed but the signature does not verify with this key.
    BadSignature,
}

const ECDSA_SHA1: Oid = Oid::new_unwrap("1.2.840.10045.4.1");
const ECDSA_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: Oid = Oid::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_SHA512: Oid = Oid::new_unwrap("1.2.840.10045.4.3.4");
const RSA_SHA1: Oid = Oid::new_unwrap("1.2.840.113549.1.1.5");
const RSA_PSS: Oid = Oid::new_unwrap("1.2.840.113549.1.1.10");
const RSA_SHA256: Oid = Oid::new_unwrap("1.2.840.113549.1.1.11");
const RSA_SHA384: Oid = Oid::new_unwrap("1.2.840.113549.1.1.12");
const RSA_SHA512: Oid = Oid::new_unwrap("1.2.840.113549.1.1.13");
const DSA_SHA1: Oid = Oid::new_unwrap("1.2.840.10040.4.3");

const EC_PUBLIC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
const RSA_ENCRYPTION: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
const SECP256R1: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: Oid = Oid::new_unwrap("1.3.132.0.34");

/// Canonical DER of RSASSA-PSS-params for SHA-256/384/512 (RFC 4055):
/// `SEQUENCE { [0] sha-N NULL, [1] mgf1(sha-N NULL), [2] saltLength N/8 }`.
fn pss_params(hash_last: u8, salt: u8) -> [u8; 54] {
    let hash = [0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, hash_last, 0x05, 0x00];
    let mut p = [0u8; 54];
    p[..4].copy_from_slice(&[0x30, 0x34, 0xa0, 0x0f]);
    p[4..19].copy_from_slice(&hash);
    p[19..32].copy_from_slice(&[0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01]);
    p[32..34].copy_from_slice(&[0x01, 0x08]);
    p[34..49].copy_from_slice(&hash);
    p[49..54].copy_from_slice(&[0xa2, 0x03, 0x02, 0x01, salt]);
    p
}

/// Parameters absent, or an explicit NULL (RFC 4055 §5 allows both for
/// PKCS#1 v1.5; RFC 5758 requires absent for ECDSA, enforced separately).
fn absent_or_null(alg: &AlgorithmIdentifierOwned) -> bool {
    alg.parameters.as_ref().is_none_or(|p| p.tag() == Tag::Null && p.value().is_empty())
}

fn ec_curve(spki: &SubjectPublicKeyInfoOwned) -> Option<Oid> {
    if spki.algorithm.oid != EC_PUBLIC_KEY {
        return None;
    }
    spki.algorithm.parameters.as_ref()?.decode_as::<Oid>().ok()
}

/// Maps (key, signature algorithm) to an aws-lc-rs verification algorithm.
fn algorithm(
    spki: &SubjectPublicKeyInfoOwned,
    alg: &AlgorithmIdentifierOwned,
) -> Result<&'static dyn VerificationAlgorithm, SigError> {
    let oid = alg.oid;
    if [ECDSA_SHA1, RSA_SHA1, DSA_SHA1].contains(&oid) {
        return Err(SigError::Sha1);
    }
    if [ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512].contains(&oid) {
        if alg.parameters.is_some() {
            return Err(SigError::Unsupported);
        }
        let curve = ec_curve(spki).ok_or(SigError::Unsupported)?;
        return Ok(match (curve, oid) {
            (SECP256R1, ECDSA_SHA256) => &signature::ECDSA_P256_SHA256_ASN1,
            (SECP256R1, ECDSA_SHA384) => &signature::ECDSA_P256_SHA384_ASN1,
            (SECP256R1, ECDSA_SHA512) => &signature::ECDSA_P256_SHA512_ASN1,
            (SECP384R1, ECDSA_SHA256) => &signature::ECDSA_P384_SHA256_ASN1,
            (SECP384R1, ECDSA_SHA384) => &signature::ECDSA_P384_SHA384_ASN1,
            (SECP384R1, ECDSA_SHA512) => &signature::ECDSA_P384_SHA512_ASN1,
            _ => return Err(SigError::Unsupported),
        });
    }
    if spki.algorithm.oid != RSA_ENCRYPTION || !absent_or_null(&spki.algorithm) {
        return Err(SigError::Unsupported);
    }
    if [RSA_SHA256, RSA_SHA384, RSA_SHA512].contains(&oid) {
        if !absent_or_null(alg) {
            return Err(SigError::Unsupported);
        }
        return Ok(match oid {
            RSA_SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            RSA_SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            _ => &signature::RSA_PKCS1_2048_8192_SHA512,
        });
    }
    if oid == RSA_PSS {
        let params = alg.parameters.as_ref().and_then(|p| p.to_der().ok()).ok_or(SigError::Unsupported)?;
        return if params == pss_params(0x01, 32) {
            Ok(&signature::RSA_PSS_2048_8192_SHA256)
        } else if params == pss_params(0x02, 48) {
            Ok(&signature::RSA_PSS_2048_8192_SHA384)
        } else if params == pss_params(0x03, 64) {
            Ok(&signature::RSA_PSS_2048_8192_SHA512)
        } else {
            Err(SigError::Unsupported)
        };
    }
    Err(SigError::Unsupported)
}

/// Verifies `sig` over `msg` with the key in `spki` using `alg`.
pub fn verify(
    spki: &SubjectPublicKeyInfoOwned,
    alg: &AlgorithmIdentifierOwned,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), SigError> {
    let a = algorithm(spki, alg)?;
    let key = spki.subject_public_key.as_bytes().ok_or(SigError::Unsupported)?;
    UnparsedPublicKey::new(a, key).verify(msg, sig).map_err(|_| SigError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    #[test]
    fn pss_sha256_params_match_rfc4055_encoding() {
        // From webpki's data/alg-rsa-pss-sha256.der (parameters only).
        let want = [
            0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d,
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
        ];
        assert_eq!(pss_params(0x01, 32), want);
        // It decodes as one DER SEQUENCE.
        der::asn1::AnyRef::from_der(&want).unwrap();
    }

    #[test]
    fn sha1_refused() {
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned { oid: RSA_ENCRYPTION, parameters: None },
            subject_public_key: der::asn1::BitString::from_bytes(&[0]).unwrap(),
        };
        let alg = AlgorithmIdentifierOwned { oid: RSA_SHA1, parameters: None };
        assert_eq!(verify(&spki, &alg, b"m", b"s"), Err(SigError::Sha1));
        let alg = AlgorithmIdentifierOwned { oid: ECDSA_SHA256, parameters: None };
        assert_eq!(verify(&spki, &alg, b"m", b"s"), Err(SigError::Unsupported));
    }
}
