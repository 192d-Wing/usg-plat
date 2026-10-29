//! Signature verification for certificates, OCSP responses and CRLs, inside
//! the AWS-LC FIPS module (`aws-lc-rs`).
//!
//! Accepted algorithms: ECDSA P-256/P-384 with SHA-256/384/512, RSA PKCS#1
//! v1.5 and RSASSA-PSS with SHA-256/384/512, RSA keys 2048..=8192 bits.
//! SHA-1 signatures are rejected (`SigError::Sha1`). RSASSA-PSS parameters
//! are decoded structurally and must be MGF1 with the same hash, salt length
//! = hash length, trailer absent (default 1); see `pss_algorithm`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS 186-5 signature
//!   verification in the validated module; SHA-1 refused (SP 800-131A).
//! - RFC 5280 §4.1.1.2, RFC 4055 §3.1 (PSS parameters), RFC 5758 §3.2

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

/// Hashes accepted inside RSASSA-PSS-params, with the matching aws-lc-rs
/// digest (for the salt length) and verification algorithm.
const PSS_HASHES: [(Oid, &digest::Algorithm, &signature::RsaParameters); 3] = [
    (ID_SHA_256, &digest::SHA256, &signature::RSA_PSS_2048_8192_SHA256),
    (ID_SHA_384, &digest::SHA384, &signature::RSA_PSS_2048_8192_SHA384),
    (ID_SHA_512, &digest::SHA512, &signature::RSA_PSS_2048_8192_SHA512),
];

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
    let &(_, dig, alg) = PSS_HASHES.iter().find(|(oid, _, _)| *oid == hash.oid)?;
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
