//! OCSP response validation (RFC 6960 §3.2, §4.2.2.2). Responder bytes are
//! hostile: strict DER, size-capped before this point, and every check
//! runs before the status is believed.
//!
//! Order: decode → authorized signer → signature (FIPS) → CertID → nonce →
//! freshness → status. Signature, signer, CertID and nonce failures are
//! attack-class (`OcspReason::is_fatal`).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5(2)(b)(1) - only the issuer or a delegated
//!   responder it certified (id-kp-OCSPSigning) may answer
//! - NIST 800-53: SC-13 - signature verified in the AWS-LC FIPS module
//! - NIST 800-53: SI-10 - strict DER, unknown critical extensions refused
//! - RFC 6960 §3.2 (acceptance), §4.2.2.2 (authorized responders), RFC 8954

use aws_lc_rs::digest;
use der::asn1::{ObjectIdentifier as Oid, OctetString};
use der::{Decode, Encode};
use rustls_pki_types::CertificateDer;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_ocsp::{BasicOcspResponse, CertId, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};

use super::request::{ID_PKIX_OCSP_NONCE, same_cert_id};
use crate::revocation::chain::first_inner_tlv;
use crate::revocation::{Cert, OcspReason, RevocationReason};

const ID_PKIX_OCSP_BASIC: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.1.1");
const ID_CE_EXT_KEY_USAGE: Oid = Oid::new_unwrap("2.5.29.37");
const ID_KP_OCSP_SIGNING: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.9");

/// Most certificates considered in a response's `certs` field.
const MAX_RESPONSE_CERTS: usize = 4;

/// A validated status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Good,
    Revoked { reason: RevocationReason, at_us: u64 },
    Unknown,
}

/// A validated, fresh response for one certificate (unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub status: Status,
    pub this_update: u64,
    /// Cache lifetime end: `min(nextUpdate, thisUpdate + max_age)`.
    pub expires: u64,
}

/// What the caller expects and allows.
#[derive(Debug, Clone, Copy)]
pub struct Expect<'a> {
    pub cert_id: &'a CertId,
    /// Nonce we sent (`None` for stapled/cached responses).
    pub nonce: Option<&'a [u8]>,
    pub require_nonce: bool,
    pub now: u64,
    pub skew: u64,
    pub max_age: u64,
}

fn secs(t: &x509_ocsp::OcspGeneralizedTime) -> u64 {
    t.0.to_unix_duration().as_secs()
}

fn sha1(b: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, b).as_ref().to_vec()
}

/// True if `rid` names `c` (byName: subject DER; byKey: SHA-1 of the key).
fn responder_is(rid: &ResponderId, c: &Cert) -> bool {
    match rid {
        ResponderId::ByName(n) => n.to_der().is_ok_and(|d| d == c.subject_der()),
        ResponderId::ByKey(h) => h.as_bytes() == sha1(c.spki().subject_public_key.raw_bytes()).as_slice(),
    }
}

/// RFC 6960 §4.2.2.2 delegated responder: issued directly by `issuer`,
/// id-kp-OCSPSigning, valid now (± skew).
fn delegated_ok(d: &Cert, issuer: &Cert, now: u64, skew: u64) -> bool {
    let v = &d.x509.tbs_certificate.validity;
    let nb = v.not_before.to_unix_duration().as_secs();
    let na = v.not_after.to_unix_duration().as_secs();
    let eku = d
        .extension(ID_CE_EXT_KEY_USAGE)
        .and_then(|e| ExtendedKeyUsage::from_der(e).ok())
        .is_some_and(|e| e.0.contains(&ID_KP_OCSP_SIGNING));
    eku && nb <= now.saturating_add(skew)
        && now <= na.saturating_add(skew)
        && d.issuer_der() == issuer.subject_der()
        && d.is_signed_by(issuer)
}

/// Picks the signer: the issuer itself, or an authorized delegate from the
/// response's `certs`.
fn signer(basic: &BasicOcspResponse, issuer: &Cert, e: &Expect<'_>) -> Result<Cert, OcspReason> {
    let rid = &basic.tbs_response_data.responder_id;
    if responder_is(rid, issuer) {
        return Ok(issuer.clone());
    }
    let certs = basic.certs.as_deref().unwrap_or(&[]);
    if certs.len() > MAX_RESPONSE_CERTS {
        return Err(OcspReason::Malformed);
    }
    for c in certs {
        let Some(c) = c.to_der().ok().and_then(|d| Cert::parse(&CertificateDer::from(d))) else {
            return Err(OcspReason::Malformed);
        };
        if responder_is(rid, &c) {
            return if delegated_ok(&c, issuer, e.now, e.skew) {
                Ok(c)
            } else {
                Err(OcspReason::UnauthorizedResponder)
            };
        }
    }
    Err(OcspReason::UnauthorizedResponder)
}

/// Validates a DER `OCSPResponse` for `cert` (issued by `issuer`).
pub fn verify(der: &[u8], issuer: &Cert, e: &Expect<'_>) -> Result<Verified, OcspReason> {
    let resp = OcspResponse::from_der(der).map_err(|_| OcspReason::Malformed)?;
    if resp.response_status != OcspResponseStatus::Successful {
        // tryLater / internalError / unauthorized...: no data (not signed,
        // so never treated as an attack).
        return Err(OcspReason::Malformed);
    }
    let bytes = resp.response_bytes.ok_or(OcspReason::Malformed)?;
    if bytes.response_type != ID_PKIX_OCSP_BASIC {
        return Err(OcspReason::Malformed);
    }
    let raw = bytes.response.as_bytes();
    let basic = BasicOcspResponse::from_der(raw).map_err(|_| OcspReason::Malformed)?;
    let tbs_raw = first_inner_tlv(raw).ok_or(OcspReason::Malformed)?;

    let signer = signer(&basic, issuer, e)?;
    let sig = basic.signature.as_bytes().ok_or(OcspReason::Malformed)?;
    crate::revocation::sig::verify(signer.spki(), &basic.signature_algorithm, tbs_raw, sig)
        .map_err(|_| OcspReason::BadSignature)?;

    let data = &basic.tbs_response_data;
    let single =
        data.responses.iter().find(|s| same_cert_id(e.cert_id, &s.cert_id)).ok_or(OcspReason::CertIdMismatch)?;

    let mut echoed: Option<&[u8]> = None;
    for x in data.response_extensions.as_deref().unwrap_or(&[]) {
        if x.extn_id == ID_PKIX_OCSP_NONCE {
            if echoed.is_some() {
                return Err(OcspReason::Malformed);
            }
            // extnValue wraps the DER of the nonce OCTET STRING.
            let inner = OctetString::from_der(x.extn_value.as_bytes()).map_err(|_| OcspReason::Malformed)?;
            echoed = Some(x.extn_value.as_bytes());
            if let Some(sent) = e.nonce
                && inner.as_bytes() != sent
            {
                return Err(OcspReason::NonceMismatch);
            }
        } else if x.critical {
            return Err(OcspReason::Malformed);
        }
    }
    if e.require_nonce && (e.nonce.is_none() || echoed.is_none()) {
        return Err(OcspReason::NonceMismatch);
    }
    if single.single_extensions.as_deref().unwrap_or(&[]).iter().any(|x| x.critical) {
        return Err(OcspReason::Malformed);
    }

    let this = secs(&single.this_update);
    if this > e.now.saturating_add(e.skew) {
        return Err(OcspReason::Stale);
    }
    let cap = this.saturating_add(e.max_age);
    let expires = match &single.next_update {
        Some(n) => {
            let n = secs(n);
            if n.saturating_add(e.skew) < e.now {
                return Err(OcspReason::Stale);
            }
            n.min(cap)
        }
        None => {
            if e.now.saturating_sub(this) > e.max_age {
                return Err(OcspReason::Stale);
            }
            cap
        }
    };
    let status = match &single.cert_status {
        CertStatus::Good(_) => Status::Good,
        CertStatus::Revoked(info) => Status::Revoked {
            reason: info
                .revocation_reason
                .and_then(|r| RevocationReason::from_code(r as u8))
                .unwrap_or(RevocationReason::Unspecified),
            at_us: secs(&info.revocation_time).saturating_mul(1_000_000),
        },
        CertStatus::Unknown(_) => Status::Unknown,
    };
    Ok(Verified { status, this_update: this, expires })
}
