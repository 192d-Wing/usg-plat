//! Signature verification for certificates, OCSP responses and CRLs, inside
//! the AWS-LC FIPS module (`aws-lc-rs`).
//!
//! Accepted algorithms: ECDSA P-256/P-384 with SHA-256/384/512, RSA PKCS#1
//! v1.5 and RSASSA-PSS with SHA-256/384/512, RSA keys 2048..=8192 bits.
//! SHA-1 signatures are rejected (`SigError::Sha1`). RSASSA-PSS parameters
//! are decoded structurally and must be MGF1 with the same hash, salt length
//! = hash length, trailer absent (default 1); see `pss_algorithm`.
//!
//! The accepted set is table-driven (`ACCEPTED`, `PSS_HASHES`) so a successor
//! algorithm is one row, and `accepted_signature_algorithms` enumerates it
//! for the CBOM drift test (`tests/cbom.rs`).
//!
//! CBOM: crypto/algorithm/x509sig/* (one bom-ref per table name)
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS 186-5 signature
//!   verification in the FIPS module (CMVP in process, POAM-026); SHA-1 refused (SP 800-131A).
//! - NIST 800-53: SA-8 (crypto-agility: table-driven algorithm set)
//! - RFC 5280 §4.1.1.2, RFC 4055 §3.1 (PSS parameters), RFC 5758 §3.2
//!
//! POAM: POAM-041 classical signatures only (no ML-DSA / SLH-DSA rows yet).

// CBOM: crypto/algorithm/sha-256/aws-lc-fips
// CBOM: crypto/algorithm/sha-384/aws-lc-fips
// CBOM: crypto/algorithm/sha-512/aws-lc-fips
use aws_lc_rs::digest;
use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use der::asn1::{ContextSpecific, ObjectIdentifier as Oid};
use der::oid::db::rfc5912::{ID_MGF_1, ID_SHA_256, ID_SHA_384, ID_SHA_512};
use der::{Decode, Reader, SliceReader, Tag, TagNumber, Tagged};
use x509_cert::spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef, SubjectPublicKeyInfoOwned};

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

/// Public key type a table row applies to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyType {
    /// `id-ecPublicKey` on the named curve.
    Ec(Oid),
    /// `rsaEncryption` (parameters absent or NULL).
    Rsa,
}

/// One accepted (signature OID, key type) pair, its CBOM name and the
/// aws-lc-rs verification algorithm.
struct Accepted {
    sig: Oid,
    key: KeyType,
    name: &'static str,
    alg: &'static dyn VerificationAlgorithm,
}

// CBOM: crypto/algorithm/x509sig/*
/// Signature algorithms with fixed parameters (ECDSA: parameters absent,
/// RFC 5758 §3.2; PKCS#1 v1.5: absent or NULL). RSASSA-PSS is in `PSS_HASHES`.
static ACCEPTED: [Accepted; 9] = [
    Accepted {
        sig: ECDSA_SHA256,
        key: KeyType::Ec(SECP256R1),
        name: "ecdsa-p256-sha256",
        alg: &signature::ECDSA_P256_SHA256_ASN1,
    },
    Accepted {
        sig: ECDSA_SHA384,
        key: KeyType::Ec(SECP256R1),
        name: "ecdsa-p256-sha384",
        alg: &signature::ECDSA_P256_SHA384_ASN1,
    },
    Accepted {
        sig: ECDSA_SHA512,
        key: KeyType::Ec(SECP256R1),
        name: "ecdsa-p256-sha512",
        alg: &signature::ECDSA_P256_SHA512_ASN1,
    },
    Accepted {
        sig: ECDSA_SHA256,
        key: KeyType::Ec(SECP384R1),
        name: "ecdsa-p384-sha256",
        alg: &signature::ECDSA_P384_SHA256_ASN1,
    },
    Accepted {
        sig: ECDSA_SHA384,
        key: KeyType::Ec(SECP384R1),
        name: "ecdsa-p384-sha384",
        alg: &signature::ECDSA_P384_SHA384_ASN1,
    },
    Accepted {
        sig: ECDSA_SHA512,
        key: KeyType::Ec(SECP384R1),
        name: "ecdsa-p384-sha512",
        alg: &signature::ECDSA_P384_SHA512_ASN1,
    },
    Accepted {
        sig: RSA_SHA256,
        key: KeyType::Rsa,
        name: "rsa-pkcs1-sha256",
        alg: &signature::RSA_PKCS1_2048_8192_SHA256,
    },
    Accepted {
        sig: RSA_SHA384,
        key: KeyType::Rsa,
        name: "rsa-pkcs1-sha384",
        alg: &signature::RSA_PKCS1_2048_8192_SHA384,
    },
    Accepted {
        sig: RSA_SHA512,
        key: KeyType::Rsa,
        name: "rsa-pkcs1-sha512",
        alg: &signature::RSA_PKCS1_2048_8192_SHA512,
    },
];

// CBOM: crypto/algorithm/x509sig/*
/// Hashes accepted inside RSASSA-PSS-params, with the CBOM name, the matching
/// aws-lc-rs digest (for the salt length) and verification algorithm.
const PSS_HASHES: [(Oid, &str, &digest::Algorithm, &signature::RsaParameters); 3] = [
    (ID_SHA_256, "rsa-pss-sha256", &digest::SHA256, &signature::RSA_PSS_2048_8192_SHA256),
    (ID_SHA_384, "rsa-pss-sha384", &digest::SHA384, &signature::RSA_PSS_2048_8192_SHA384),
    (ID_SHA_512, "rsa-pss-sha512", &digest::SHA512, &signature::RSA_PSS_2048_8192_SHA512),
];

/// Names of every accepted certificate/OCSP/CRL signature algorithm, in table
/// order (the CBOM `crypto/algorithm/x509sig/<name>` bom-refs).
pub fn accepted_signature_algorithms() -> impl Iterator<Item = &'static str> {
    ACCEPTED.iter().map(|a| a.name).chain(PSS_HASHES.iter().map(|&(_, n, _, _)| n))
}

/// Reads the explicitly tagged `[number]` field if it is next, else `None`.
fn explicit_field<'a, T: Decode<'a>>(r: &mut SliceReader<'a>, number: u8) -> der::Result<Option<T>> {
    let want = Tag::ContextSpecific { constructed: true, number: TagNumber::new(number) };
    if r.is_finished() || r.peek_tag()? != want {
        return Ok(None);
    }
    Ok(Some(ContextSpecific::<T>::decode(r)?.value))
}

fn ref_absent_or_null(alg: &AlgorithmIdentifierRef<'_>) -> bool {
    alg.parameters.is_none_or(|p| p.tag() == Tag::Null && p.value().is_empty())
}

/// Structural RSASSA-PSS-params check (RFC 4055 §3.1):
///
/// ```text
/// SEQUENCE { hashAlgorithm [0], maskGenAlgorithm [1], saltLength [2], trailerField [3] }
/// ```
///
/// Accepts only hash SHA-256/384/512 (parameters absent or NULL), MGF1 with
/// the same hash, saltLength equal to the digest length and trailerField
/// absent (1 is the DEFAULT, so DER forbids encoding it). Absent hash/MGF
/// (SHA-1 defaults), unknown or out-of-order fields and trailing data are
/// rejected.
///
/// The hash and MGF1 hash parameters may each independently be absent or
/// NULL (RFC 4055 §2.1). An explicitly encoded trailerField, including
/// `[3] INTEGER 1` as emitted by some older Java/BouncyCastle encoders, is
/// non-DER (X.690 §11.5) and is rejected; the caller reports it as
/// `SigError::Unsupported`.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-13 (Cryptographic Protection)
/// - RFC 4055 §2.1 - SHA-2 parameters absent or NULL
/// - RFC 4055 §3.1 - RSASSA-PSS-params, DER (X.690 §11.5 DEFAULT omission)
fn pss_algorithm(params: &der::Any) -> Option<&'static signature::RsaParameters> {
    if params.tag() != Tag::Sequence {
        return None;
    }
    let mut r = SliceReader::new(params.value()).ok()?;
    let hash: AlgorithmIdentifierRef<'_> = explicit_field(&mut r, 0).ok()??;
    let mgf: AlgorithmIdentifierRef<'_> = explicit_field(&mut r, 1).ok()??;
    let salt: u32 = explicit_field(&mut r, 2).ok()??;
    // Any remaining bytes (trailerField, even "1", or unknown fields) are refused.
    if !r.is_finished() {
        return None;
    }
    let &(_, _, dig, alg) = PSS_HASHES.iter().find(|(oid, _, _, _)| *oid == hash.oid)?;
    if !ref_absent_or_null(&hash) || mgf.oid != ID_MGF_1 {
        return None;
    }
    let mgf_hash: AlgorithmIdentifierRef<'_> = mgf.parameters?.decode_as().ok()?;
    if mgf_hash.oid != hash.oid || !ref_absent_or_null(&mgf_hash) {
        return None;
    }
    (usize::try_from(salt).ok()? == dig.output_len()).then_some(alg)
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
    if let Some(curve) = ec_curve(spki) {
        // RFC 5758 §3.2: ECDSA signature parameters MUST be absent.
        if alg.parameters.is_some() {
            return Err(SigError::Unsupported);
        }
        return ACCEPTED
            .iter()
            .find(|a| a.sig == oid && a.key == KeyType::Ec(curve))
            .map(|a| a.alg)
            .ok_or(SigError::Unsupported);
    }
    if spki.algorithm.oid != RSA_ENCRYPTION || !absent_or_null(&spki.algorithm) {
        return Err(SigError::Unsupported);
    }
    if let Some(a) = ACCEPTED.iter().find(|a| a.sig == oid && a.key == KeyType::Rsa) {
        return if absent_or_null(alg) { Ok(a.alg) } else { Err(SigError::Unsupported) };
    }
    if oid == RSA_PSS {
        return alg
            .parameters
            .as_ref()
            .and_then(pss_algorithm)
            .map(|a| a as &'static dyn VerificationAlgorithm)
            .ok_or(SigError::Unsupported);
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

    /// Explicit `[n]` wrapper around `inner` (all lengths < 128 here).
    fn ctx(n: u8, inner: &[u8]) -> Vec<u8> {
        let mut v = vec![0xa0 | n, inner.len() as u8];
        v.extend_from_slice(inner);
        v
    }

    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        let inner = parts.concat();
        let mut v = vec![0x30, inner.len() as u8];
        v.extend_from_slice(&inner);
        v
    }

    fn hash_alg(last: u8, null: bool) -> Vec<u8> {
        let oid: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last];
        seq(&[oid, if null { &[0x05, 0x00] } else { &[] }])
    }

    fn mgf1(hash: &[u8]) -> Vec<u8> {
        seq(&[&[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08], hash])
    }

    fn salt(n: u8) -> Vec<u8> {
        if n >= 0x80 { ctx(2, &[0x02, 0x02, 0x00, n]) } else { ctx(2, &[0x02, 0x01, n]) }
    }

    /// Canonical params for SHA-2 hash `last` (1/2/3 = 256/384/512).
    fn params(last: u8, salt_len: u8) -> Vec<u8> {
        let h = hash_alg(last, true);
        seq(&[&ctx(0, &h), &ctx(1, &mgf1(&h)), &salt(salt_len)])
    }

    fn check(der: &[u8]) -> Option<&'static signature::RsaParameters> {
        pss_algorithm(&der::Any::from_der(der).unwrap())
    }

    fn is(got: Option<&'static signature::RsaParameters>, want: &'static signature::RsaParameters) -> bool {
        // aws-lc-rs algorithms are consts (no stable address); Debug names them.
        got.is_some_and(|g| format!("{g:?}") == format!("{want:?}"))
    }

    // From webpki's data/alg-rsa-pss-sha{256,384,512}.der (parameters only).
    const WEBPKI_SHA256: [u8; 54] = [
        0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
    ];
    const WEBPKI_SHA384: [u8; 54] = [
        0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
        0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x30,
    ];
    const WEBPKI_SHA512: [u8; 54] = [
        0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
        0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x40,
    ];

    #[test]
    fn pss_webpki_vectors_accepted() {
        assert!(is(check(&WEBPKI_SHA256), &signature::RSA_PSS_2048_8192_SHA256));
        assert!(is(check(&WEBPKI_SHA384), &signature::RSA_PSS_2048_8192_SHA384));
        assert!(is(check(&WEBPKI_SHA512), &signature::RSA_PSS_2048_8192_SHA512));
        assert_eq!(params(1, 32), WEBPKI_SHA256);
    }

    #[test]
    fn pss_hash_params_absent_accepted() {
        let h = hash_alg(1, false);
        let p = seq(&[&ctx(0, &h), &ctx(1, &mgf1(&h)), &salt(32)]);
        assert!(is(check(&p), &signature::RSA_PSS_2048_8192_SHA256));
    }

    #[test]
    fn pss_wrong_hash_rejected() {
        // SHA-224 (2.16.840.1.101.3.4.2.4).
        assert!(check(&params(4, 28)).is_none());
        // SHA-1 (1.3.14.3.2.26) in hash and MGF1.
        let sha1 = seq(&[&[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a], &[0x05, 0x00]]);
        assert!(check(&seq(&[&ctx(0, &sha1), &ctx(1, &mgf1(&sha1)), &salt(20)])).is_none());
    }

    #[test]
    fn pss_mgf_mismatch_and_non_mgf1_rejected() {
        let h = hash_alg(1, true);
        let p = seq(&[&ctx(0, &h), &ctx(1, &mgf1(&hash_alg(2, true))), &salt(32)]);
        assert!(check(&p).is_none());
        // id-RSASSA-PSS OID in place of id-mgf1.
        let bad = seq(&[&[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a], &h]);
        assert!(check(&seq(&[&ctx(0, &h), &ctx(1, &bad), &salt(32)])).is_none());
    }

    #[test]
    fn pss_wrong_salt_rejected() {
        for (last, len) in [(1u8, 32u8), (2, 48), (3, 64)] {
            assert!(check(&params(last, len)).is_some());
            for bad in [0, len - 1, len + 1] {
                assert!(check(&params(last, bad)).is_none(), "hash {last} salt {bad}");
            }
        }
    }

    #[test]
    fn pss_structure_rejected() {
        let h = hash_alg(1, true);
        let (c0, c1, c2) = (ctx(0, &h), ctx(1, &mgf1(&h)), salt(32));
        // trailerField 2, and 1 (DEFAULT, forbidden in DER).
        assert!(check(&seq(&[&c0, &c1, &c2, &ctx(3, &[0x02, 0x01, 0x02])])).is_none());
        assert!(check(&seq(&[&c0, &c1, &c2, &ctx(3, &[0x02, 0x01, 0x01])])).is_none());
        // Missing hashAlgorithm (default SHA-1) / missing MGF / missing salt.
        assert!(check(&seq(&[&c1, &c2])).is_none());
        assert!(check(&seq(&[&c0, &c2])).is_none());
        assert!(check(&seq(&[&c0, &c1])).is_none());
        // Extra field, out of order, trailing bytes inside the SEQUENCE.
        assert!(check(&seq(&[&c0, &c1, &c2, &ctx(4, &[0x05, 0x00])])).is_none());
        assert!(check(&seq(&[&c1, &c0, &c2])).is_none());
        assert!(check(&seq(&[&c0, &c1, &c2, &[0x00]])).is_none());
        // Not a SEQUENCE.
        assert!(pss_algorithm(&der::Any::new(Tag::Set, &WEBPKI_SHA256[2..]).unwrap()).is_none());
    }

    #[test]
    fn pss_inner_trailing_and_encoding_rejected() {
        let h = hash_alg(1, true);
        let (c0, c1) = (ctx(0, &h), ctx(1, &mgf1(&h)));
        // Trailing byte inside the [2] wrapper.
        assert!(check(&seq(&[&c0, &c1, &ctx(2, &[0x02, 0x01, 0x20, 0x00])])).is_none());
        // Trailing byte after the MGF1 inner AlgorithmIdentifier.
        let mgf_trailing = seq(&[&[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08], &h, &[0x00]]);
        assert!(check(&seq(&[&c0, &ctx(1, &mgf_trailing), &salt(32)])).is_none());
        // Non-minimal and negative saltLength.
        assert!(check(&seq(&[&c0, &c1, &ctx(2, &[0x02, 0x02, 0x00, 0x20])])).is_none());
        assert!(check(&seq(&[&c0, &c1, &ctx(2, &[0x02, 0x01, 0xe0])])).is_none());
        // Primitive [0] tag instead of constructed.
        let mut prim = ctx(0, &h);
        prim[0] = 0x80;
        assert!(check(&seq(&[&prim, &c1, &salt(32)])).is_none());
    }

    #[test]
    fn pss_mixed_absent_and_null_hash_params_accepted() {
        let (null, absent) = (hash_alg(1, true), hash_alg(1, false));
        for (outer, inner) in [(&null, &absent), (&absent, &null)] {
            let p = seq(&[&ctx(0, outer), &ctx(1, &mgf1(inner)), &salt(32)]);
            assert!(is(check(&p), &signature::RSA_PSS_2048_8192_SHA256));
        }
    }

    /// Documents a dependency guarantee, not our code: `der::Any::from_der`
    /// refuses trailing data, so params with bytes after the SEQUENCE never
    /// reach `pss_algorithm`.
    #[test]
    fn der_any_refuses_trailing_data() {
        let mut t = WEBPKI_SHA256.to_vec();
        t.push(0);
        assert!(der::Any::from_der(&t).is_err());
    }

    #[test]
    fn pss_with_rsassa_pss_spki_refused() {
        // RFC 4055 §1.2: an id-RSASSA-PSS key is not accepted; only rsaEncryption.
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned { oid: RSA_PSS, parameters: None },
            subject_public_key: der::asn1::BitString::from_bytes(&[0]).unwrap(),
        };
        let alg =
            AlgorithmIdentifierOwned { oid: RSA_PSS, parameters: Some(der::Any::from_der(&WEBPKI_SHA256).unwrap()) };
        assert!(matches!(algorithm(&spki, &alg), Err(SigError::Unsupported)));
    }

    fn spki(key: KeyType) -> SubjectPublicKeyInfoOwned {
        let algorithm = match key {
            KeyType::Ec(curve) => AlgorithmIdentifierOwned {
                oid: EC_PUBLIC_KEY,
                parameters: Some(der::Any::encode_from(&curve).unwrap()),
            },
            KeyType::Rsa => AlgorithmIdentifierOwned { oid: RSA_ENCRYPTION, parameters: None },
        };
        SubjectPublicKeyInfoOwned { algorithm, subject_public_key: der::asn1::BitString::from_bytes(&[0]).unwrap() }
    }

    #[test]
    fn table_rows_round_trip() {
        for a in &ACCEPTED {
            let alg = AlgorithmIdentifierOwned { oid: a.sig, parameters: None };
            let got = algorithm(&spki(a.key), &alg).unwrap_or_else(|e| panic!("{}: {e:?}", a.name));
            assert_eq!(format!("{got:?}"), format!("{:?}", a.alg), "{}", a.name);
        }
        for (der, (_, name, _, want)) in
            [&WEBPKI_SHA256[..], &WEBPKI_SHA384, &WEBPKI_SHA512].into_iter().zip(PSS_HASHES)
        {
            let alg = AlgorithmIdentifierOwned { oid: RSA_PSS, parameters: Some(der::Any::from_der(der).unwrap()) };
            let got = algorithm(&spki(KeyType::Rsa), &alg).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(format!("{got:?}"), format!("{want:?}"), "{name}");
        }
        let names: Vec<_> = accepted_signature_algorithms().collect();
        assert_eq!(names.len(), ACCEPTED.len() + PSS_HASHES.len());
        assert!(names.iter().all(|n| !n.contains("sha1")), "{names:?}");
    }

    #[test]
    fn table_refuses_sha1_dsa_unknown_and_wrong_key() {
        let p256 = spki(KeyType::Ec(SECP256R1));
        let rsa = spki(KeyType::Rsa);
        for (key, oid) in [(&p256, ECDSA_SHA1), (&rsa, RSA_SHA1), (&rsa, DSA_SHA1)] {
            let alg = AlgorithmIdentifierOwned { oid, parameters: None };
            assert_eq!(algorithm(key, &alg).err(), Some(SigError::Sha1));
        }
        let unknown = Oid::new_unwrap("1.2.840.10045.4.3.1"); // ecdsa-with-SHA224
        for (key, oid) in [(&p256, unknown), (&p256, RSA_SHA256), (&rsa, ECDSA_SHA256), (&rsa, unknown)] {
            let alg = AlgorithmIdentifierOwned { oid, parameters: None };
            assert_eq!(algorithm(key, &alg).err(), Some(SigError::Unsupported));
        }
        // P-521 is not in the table; ECDSA parameters must be absent.
        let p521 = spki(KeyType::Ec(Oid::new_unwrap("1.3.132.0.35")));
        let alg = AlgorithmIdentifierOwned { oid: ECDSA_SHA256, parameters: None };
        assert_eq!(algorithm(&p521, &alg).err(), Some(SigError::Unsupported));
        let alg = AlgorithmIdentifierOwned { oid: ECDSA_SHA256, parameters: Some(der::Any::null()) };
        assert_eq!(algorithm(&p256, &alg).err(), Some(SigError::Unsupported));
        // PKCS#1 v1.5 parameters other than absent/NULL are refused.
        let alg =
            AlgorithmIdentifierOwned { oid: RSA_SHA256, parameters: Some(der::Any::encode_from(&SECP256R1).unwrap()) };
        assert_eq!(algorithm(&rsa, &alg).err(), Some(SigError::Unsupported));
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

    // --- QA (run 20261103-081215-sbom-cbom): end-to-end per-row coverage ---

    const SECP384R1_T: Oid = Oid::new_unwrap("1.3.132.0.34");

    /// aws-lc-rs 1.19 only exposes the curve-native ECDSA signers; the
    /// cross-hash rows (p256-sha384, ...) are covered by dispatch tests and
    /// by checking that a curve-native signature does not verify under them.
    fn ec_signer(row: &str) -> Option<&'static signature::EcdsaSigningAlgorithm> {
        match row {
            "ecdsa-p256-sha256" => Some(&signature::ECDSA_P256_SHA256_ASN1_SIGNING),
            "ecdsa-p384-sha384" => Some(&signature::ECDSA_P384_SHA384_ASN1_SIGNING),
            r if r.starts_with("ecdsa-p256") => None,
            r if r.starts_with("ecdsa-p384") => None,
            other => panic!("no signer for {other}"),
        }
    }

    fn native(key: KeyType) -> &'static signature::EcdsaSigningAlgorithm {
        if key == KeyType::Ec(SECP256R1) {
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING
        } else {
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING
        }
    }

    fn spki_with_key(key: KeyType, pk: &[u8]) -> SubjectPublicKeyInfoOwned {
        let mut s = spki(key);
        s.subject_public_key = der::asn1::BitString::from_bytes(pk).unwrap();
        s
    }

    /// Every ECDSA row verifies a real signature, rejects a tampered message,
    /// and the same key is refused under SHA-1.
    #[test]
    fn every_ecdsa_row_verifies_real_signature() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair};
        let rng = SystemRandom::new();
        let mut n = 0;
        for a in ACCEPTED.iter().filter(|a| matches!(a.key, KeyType::Ec(_))) {
            let kp = EcdsaKeyPair::generate(ec_signer(a.name).unwrap_or(native(a.key))).unwrap();
            let sig = kp.sign(&rng, b"tbs").unwrap();
            let spki = spki_with_key(a.key, kp.public_key().as_ref());
            let alg = AlgorithmIdentifierOwned { oid: a.sig, parameters: None };
            if ec_signer(a.name).is_some() {
                assert_eq!(verify(&spki, &alg, b"tbs", sig.as_ref()), Ok(()), "{}", a.name);
                assert_eq!(verify(&spki, &alg, b"tbX", sig.as_ref()), Err(SigError::BadSignature), "{}", a.name);
            } else {
                // Dispatch reaches aws-lc with this row's hash: native-hash signature fails.
                assert_eq!(verify(&spki, &alg, b"tbs", sig.as_ref()), Err(SigError::BadSignature), "{}", a.name);
            }
            let sha1 = AlgorithmIdentifierOwned { oid: ECDSA_SHA1, parameters: None };
            assert_eq!(verify(&spki, &sha1, b"tbs", sig.as_ref()), Err(SigError::Sha1), "{}", a.name);
            n += 1;
        }
        assert_eq!(n, 6);
    }

    /// Every RSA PKCS#1 v1.5 and PSS row verifies a real 2048-bit signature;
    /// a signature under one hash does not verify under another row.
    #[test]
    fn every_rsa_row_verifies_real_signature() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::rsa::KeySize;
        use aws_lc_rs::signature::{KeyPair, RsaKeyPair};
        let rng = SystemRandom::new();
        let kp = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let spki = spki_with_key(KeyType::Rsa, kp.public_key().as_ref());
        let pkcs1: [(&str, &'static dyn signature::RsaEncoding); 3] = [
            ("rsa-pkcs1-sha256", &signature::RSA_PKCS1_SHA256),
            ("rsa-pkcs1-sha384", &signature::RSA_PKCS1_SHA384),
            ("rsa-pkcs1-sha512", &signature::RSA_PKCS1_SHA512),
        ];
        let mut sigs = Vec::new();
        for (name, pad) in pkcs1 {
            let a = ACCEPTED.iter().find(|a| a.name == name).unwrap();
            let mut sig = vec![0; kp.public_modulus_len()];
            kp.sign(pad, &rng, b"tbs", &mut sig).unwrap();
            for params in [None, Some(der::Any::null())] {
                let alg = AlgorithmIdentifierOwned { oid: a.sig, parameters: params };
                assert_eq!(verify(&spki, &alg, b"tbs", &sig), Ok(()), "{name}");
            }
            sigs.push((a.sig, sig));
        }
        // Cross-row: sha256 signature under the sha384 OID fails.
        let alg = AlgorithmIdentifierOwned { oid: sigs[1].0, parameters: None };
        assert_eq!(verify(&spki, &alg, b"tbs", &sigs[0].1), Err(SigError::BadSignature));
        // SHA-1 refused with a valid RSA key.
        let alg = AlgorithmIdentifierOwned { oid: RSA_SHA1, parameters: None };
        assert_eq!(verify(&spki, &alg, b"tbs", &sigs[0].1), Err(SigError::Sha1));

        let pss: [(&[u8], &'static dyn signature::RsaEncoding); 3] = [
            (&WEBPKI_SHA256, &signature::RSA_PSS_SHA256),
            (&WEBPKI_SHA384, &signature::RSA_PSS_SHA384),
            (&WEBPKI_SHA512, &signature::RSA_PSS_SHA512),
        ];
        for (i, (params, pad)) in pss.iter().enumerate() {
            let mut sig = vec![0; kp.public_modulus_len()];
            kp.sign(*pad, &rng, b"tbs", &mut sig).unwrap();
            let alg = AlgorithmIdentifierOwned { oid: RSA_PSS, parameters: Some(der::Any::from_der(params).unwrap()) };
            assert_eq!(verify(&spki, &alg, b"tbs", &sig), Ok(()), "pss row {i}");
            assert_eq!(verify(&spki, &alg, b"tbX", &sig), Err(SigError::BadSignature), "pss row {i}");
            let other = pss[(i + 1) % 3].0;
            let alg = AlgorithmIdentifierOwned { oid: RSA_PSS, parameters: Some(der::Any::from_der(other).unwrap()) };
            assert_eq!(verify(&spki, &alg, b"tbs", &sig), Err(SigError::BadSignature), "pss cross {i}");
        }
    }

    /// Unsupported curves and malformed key parameters are refused before any
    /// verification: P-521, secp256k1, brainpoolP256r1, EC key without curve,
    /// RSA key with non-NULL parameters, and a curve/hash row swap.
    #[test]
    fn unsupported_curves_and_params_refused() {
        let alg = |oid| AlgorithmIdentifierOwned { oid, parameters: None };
        for curve in ["1.3.132.0.35", "1.3.132.0.10", "1.3.36.3.3.2.8.1.1.7"] {
            let k = spki(KeyType::Ec(Oid::new_unwrap(curve)));
            for oid in [ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512] {
                assert_eq!(algorithm(&k, &alg(oid)).err(), Some(SigError::Unsupported), "{curve}");
            }
            assert_eq!(algorithm(&k, &alg(ECDSA_SHA1)).err(), Some(SigError::Sha1), "{curve}");
        }
        let mut no_curve = spki(KeyType::Ec(SECP256R1));
        no_curve.algorithm.parameters = None;
        assert_eq!(algorithm(&no_curve, &alg(ECDSA_SHA256)).err(), Some(SigError::Unsupported));
        let mut rsa_params = spki(KeyType::Rsa);
        rsa_params.algorithm.parameters = Some(der::Any::encode_from(&SECP256R1).unwrap());
        assert_eq!(algorithm(&rsa_params, &alg(RSA_SHA256)).err(), Some(SigError::Unsupported));
        // RSA signature OIDs on a P-384 key and PSS on an EC key.
        let p384 = spki(KeyType::Ec(SECP384R1_T));
        for oid in [RSA_SHA256, RSA_SHA384, RSA_SHA512, RSA_PSS] {
            assert_eq!(algorithm(&p384, &alg(oid)).err(), Some(SigError::Unsupported));
        }
        // RSA-PSS with absent parameters is refused.
        assert_eq!(algorithm(&spki(KeyType::Rsa), &alg(RSA_PSS)).err(), Some(SigError::Unsupported));
    }
}
