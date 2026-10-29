//! Certification path reconstruction for revocation checking.
//!
//! webpki validates the chain but does not expose the path it built, so
//! this module rebuilds it: starting at the leaf, an issuer candidate is a
//! presented intermediate or a configured trust anchor whose subject equals
//! the certificate's issuer (DER), and it is accepted only if its key
//! verifies the certificate's signature (FIPS, `sig`). Depth is capped and
//! the search is bounded, so a hostile peer cannot turn path building into
//! a CPU sink. A certificate whose issuer cannot be found is an error,
//! never "good".
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5(2)(b)(1) - every non-root certificate of the path
//!   is identified for revocation checking
//! - NIST 800-53: SC-5 - depth 8, at most 64 signature verifications
//! - RFC 5280 §6.1 (path), §4.1.2.4/§4.1.2.6 (issuer/subject names)

use std::fmt;

use der::asn1::ObjectIdentifier as Oid;
use der::{Decode, Encode};
use rustls_pki_types::CertificateDer;
use x509_cert::Certificate;
use x509_cert::ext::pkix::BasicConstraints;

use super::sig;

/// Longest path rebuilt (non-root certificates).
pub const MAX_DEPTH: usize = 8;
/// Most presented intermediates considered.
pub const MAX_INTERMEDIATES: usize = 16;
/// Most signature verifications per rebuild.
const MAX_SIG_CHECKS: usize = 64;

const BASIC_CONSTRAINTS: Oid = Oid::new_unwrap("2.5.29.19");

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("certificate {0} is not valid DER X.509")]
    Malformed(usize),
    #[error("no issuer found for chain element {0}")]
    NoIssuer(usize),
    #[error("path longer than {MAX_DEPTH}")]
    TooDeep,
    #[error("more than {MAX_INTERMEDIATES} intermediates presented")]
    TooManyIntermediates,
}

/// A parsed certificate plus the raw pieces revocation code needs.
#[derive(Clone)]
pub struct Cert {
    pub der: CertificateDer<'static>,
    pub x509: Certificate,
    /// Raw `tbsCertificate` TLV (the signed bytes).
    tbs_raw: Vec<u8>,
    subject_der: Vec<u8>,
    issuer_der: Vec<u8>,
}

impl fmt::Debug for Cert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cert").field("subject", &self.x509.tbs_certificate.subject.to_string()).finish()
    }
}

/// The first TLV inside the outer SEQUENCE of `der`.
pub(crate) fn first_inner_tlv(der: &[u8]) -> Option<&[u8]> {
    use der::{Reader, SliceReader};
    let mut r = SliceReader::new(der).ok()?;
    let outer = der::Header::decode(&mut r).ok()?;
    if outer.tag != der::Tag::Sequence {
        return None;
    }
    r.tlv_bytes().ok()
}

impl Cert {
    pub fn parse(der: &CertificateDer<'_>) -> Option<Self> {
        let x509 = Certificate::from_der(der.as_ref()).ok()?;
        let tbs_raw = first_inner_tlv(der.as_ref())?.to_vec();
        let subject_der = x509.tbs_certificate.subject.to_der().ok()?;
        let issuer_der = x509.tbs_certificate.issuer.to_der().ok()?;
        Some(Self { der: der.clone().into_owned(), x509, tbs_raw, subject_der, issuer_der })
    }

    /// Serial number content octets (two's complement, as encoded).
    pub fn serial(&self) -> &[u8] {
        self.x509.tbs_certificate.serial_number.as_bytes()
    }

    /// Serial number as lowercase hex.
    pub fn serial_hex(&self) -> String {
        self.serial().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Issuer DN in RFC 4514 form (for audit records; untrusted text).
    pub fn issuer_dn(&self) -> String {
        self.x509.tbs_certificate.issuer.to_string()
    }

    pub fn subject_der(&self) -> &[u8] {
        &self.subject_der
    }

    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer_der
    }

    pub fn spki(&self) -> &x509_cert::spki::SubjectPublicKeyInfoOwned {
        &self.x509.tbs_certificate.subject_public_key_info
    }

    /// SHA-256 of the certificate DER (FIPS module).
    pub fn sha256(&self) -> [u8; 32] {
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, self.der.as_ref());
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }

    /// Raw `extnValue` content of the extension `oid`, if present once.
    /// OCSP (AIA) and CRL (CDP, keyUsage) code parses what it needs.
    pub fn extension(&self, oid: Oid) -> Option<&[u8]> {
        let exts = self.x509.tbs_certificate.extensions.as_ref()?;
        let mut it = exts.iter().filter(|e| e.extn_id == oid);
        let e = it.next()?;
        if it.next().is_some() {
            return None;
        }
        Some(e.extn_value.as_bytes())
    }

    /// basicConstraints cA.
    pub fn is_ca(&self) -> bool {
        self.extension(BASIC_CONSTRAINTS).and_then(|v| BasicConstraints::from_der(v).ok()).is_some_and(|b| b.ca)
    }

    /// True if `issuer`'s key verifies this certificate's signature.
    pub fn is_signed_by(&self, issuer: &Cert) -> bool {
        let sig = match self.x509.signature.as_bytes() {
            Some(s) => s,
            None => return false,
        };
        // RFC 5280 §4.1.1.2: outer and inner algorithm must be identical.
        if self.x509.signature_algorithm != self.x509.tbs_certificate.signature {
            return false;
        }
        sig::verify(issuer.spki(), &self.x509.signature_algorithm, &self.tbs_raw, sig).is_ok()
    }
}

/// Configured trust anchors, parsed once.
#[derive(Debug, Clone, Default)]
pub struct Anchors(Vec<Cert>);

impl Anchors {
    /// Parses every anchor; `None` if any is not valid X.509.
    pub fn parse(certs: &[CertificateDer<'_>]) -> Option<Self> {
        certs.iter().map(Cert::parse).collect::<Option<Vec<_>>>().map(Self)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One non-root certificate of the path with its issuer.
#[derive(Debug, Clone)]
pub struct ChainLink {
    /// 0 = leaf.
    pub index: u8,
    pub cert: Cert,
    pub issuer: Cert,
}

struct Search<'a> {
    inter: &'a [Cert],
    anchors: &'a Anchors,
    checks: usize,
}

impl Search<'_> {
    fn signed(&mut self, c: &Cert, by: &Cert) -> bool {
        if self.checks >= MAX_SIG_CHECKS {
            return false;
        }
        self.checks += 1;
        c.is_signed_by(by)
    }

    /// Depth-first: an anchor ends the path; otherwise try each unused
    /// intermediate whose subject matches and whose key verifies.
    fn walk(&mut self, cur: &Cert, used: u32, out: &mut Vec<ChainLink>) -> Result<(), ChainError> {
        let idx = out.len();
        if idx >= MAX_DEPTH {
            return Err(ChainError::TooDeep);
        }
        for a in &self.anchors.0 {
            if a.subject_der == cur.issuer_der && self.signed(cur, a) {
                out.push(ChainLink { index: idx as u8, cert: cur.clone(), issuer: a.clone() });
                return Ok(());
            }
        }
        let mut deepest = ChainError::NoIssuer(idx);
        for (i, c) in self.inter.iter().enumerate() {
            if used & (1 << i) != 0 || c.subject_der != cur.issuer_der || !self.signed(cur, c) {
                continue;
            }
            out.push(ChainLink { index: idx as u8, cert: cur.clone(), issuer: c.clone() });
            match self.walk(c, used | (1 << i), out) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    out.truncate(idx);
                    if e == ChainError::TooDeep || matches!(deepest, ChainError::NoIssuer(_)) {
                        deepest = e;
                    }
                }
            }
        }
        Err(deepest)
    }
}

/// Rebuilds the path from `leaf` to a configured anchor and returns every
/// non-root certificate with its issuer, leaf first. A leaf that is itself
/// an anchor yields an empty path (nothing to check).
pub fn rebuild(
    leaf: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &Anchors,
) -> Result<Vec<ChainLink>, ChainError> {
    if intermediates.len() > MAX_INTERMEDIATES {
        return Err(ChainError::TooManyIntermediates);
    }
    if anchors.0.iter().any(|a| a.der.as_ref() == leaf.as_ref()) {
        return Ok(Vec::new());
    }
    let leaf = Cert::parse(leaf).ok_or(ChainError::Malformed(0))?;
    let inter = intermediates
        .iter()
        .enumerate()
        .map(|(i, c)| Cert::parse(c).ok_or(ChainError::Malformed(i + 1)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut s = Search { inter: &inter, anchors, checks: 0 };
    let mut out = Vec::with_capacity(4);
    s.walk(&leaf, 0, &mut out)?;
    Ok(out)
}
