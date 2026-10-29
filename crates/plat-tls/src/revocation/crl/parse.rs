//! CRL parsing and verification (RFC 5280 §5, §6.3) with the `x509-cert`
//! `CertificateList` types. CRL bytes are hostile (size-capped before this
//! point).
//!
//! [`verify`] checks issuer name, issuer keyUsage and the FIPS signature
//! over the raw `tbsCertList` **before** decoding the revoked list, so no
//! allocation proportional to an unverified CRL happens beyond the capped
//! buffer. [`inspect`] is the structural subset (no signature) used only
//! to triage the on-disk cache and pre-fetched data, which are always
//! fully verified before use.
//!
//! Not supported (unusable, never "good"): indirect CRLs, delta CRLs,
//! `onlyContainsAttributeCerts`, unknown critical extensions, CRLs without
//! `nextUpdate`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5(2)(b)(1) - CRL validation for path
//!   certificates; SC-13 - FIPS signature verification
//! - NIST 800-53: SI-10 - strict DER, unknown critical extensions refused
//! - RFC 5280 §5.1.2.4-5 (thisUpdate/nextUpdate), §5.2.3 (cRLNumber),
//!   §5.2.4 (delta), §5.2.5 (IDP), §5.3.1 (reasonCode), §5.3.3
//!   (certificateIssuer), §6.3.3 (CRL processing)

use std::collections::HashMap;

use der::asn1::{BitString, ObjectIdentifier as Oid};
use der::{Decode, Encode, Reader, SliceReader, Tag};
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::crl::dp::IssuingDistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{CrlDistributionPoints, CrlNumber, KeyUsage, KeyUsages};
use x509_cert::name::Name;
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::revocation::{Cert, CrlReason, RevocationReason};

const ID_CE_KEY_USAGE: Oid = Oid::new_unwrap("2.5.29.15");
const ID_CE_ISSUER_ALT_NAME: Oid = Oid::new_unwrap("2.5.29.18");
const ID_CE_CRL_NUMBER: Oid = Oid::new_unwrap("2.5.29.20");
const ID_CE_CRL_REASONS: Oid = Oid::new_unwrap("2.5.29.21");
const ID_CE_INVALIDITY_DATE: Oid = Oid::new_unwrap("2.5.29.24");
const ID_CE_DELTA_CRL_INDICATOR: Oid = Oid::new_unwrap("2.5.29.27");
const ID_CE_ISSUING_DISTRIBUTION_POINT: Oid = Oid::new_unwrap("2.5.29.28");
const ID_CE_CERTIFICATE_ISSUER: Oid = Oid::new_unwrap("2.5.29.29");
const ID_CE_AUTHORITY_KEY_IDENTIFIER: Oid = Oid::new_unwrap("2.5.29.35");
const ID_CE_CRL_DISTRIBUTION_POINTS: Oid = Oid::new_unwrap("2.5.29.31");
const ID_CE_FRESHEST_CRL: Oid = Oid::new_unwrap("2.5.29.46");

/// Fixed per-entry overhead in the memory estimate.
const ENTRY_OVERHEAD: usize = 24;
/// Fixed per-CRL overhead in the memory estimate.
const CRL_OVERHEAD: usize = 512;

/// IDP scope of a CRL (RFC 5280 §5.2.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    pub only_user: bool,
    pub only_ca: bool,
    /// `onlySomeReasons` present: partial, never covers a certificate.
    pub partial: bool,
    /// The IDP names a distribution point.
    pub named: bool,
    /// fullName URIs of that distribution point (any scheme).
    pub uris: Vec<String>,
    /// fullName directoryNames of that distribution point (DER).
    pub dir_names: Vec<Vec<u8>>,
}

impl Scope {
    /// Stable digest of the scope, for the per-issuer+scope cRLNumber
    /// high-water mark.
    pub fn key(&self) -> [u8; 32] {
        let mut b =
            vec![u8::from(self.only_user), u8::from(self.only_ca), u8::from(self.partial), u8::from(self.named)];
        for u in &self.uris {
            b.extend_from_slice(&(u.len() as u64).to_be_bytes());
            b.extend_from_slice(u.as_bytes());
        }
        b.push(0xff);
        for d in &self.dir_names {
            b.extend_from_slice(&(d.len() as u64).to_be_bytes());
            b.extend_from_slice(d);
        }
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &b);
        let mut k = [0u8; 32];
        k.copy_from_slice(d.as_ref());
        k
    }
}

/// A verified CRL, stored parsed (never as raw DER).
#[derive(Debug, Clone)]
pub struct CrlEntry {
    pub issuer_key_hash: [u8; 32],
    pub scope: Scope,
    pub this_update: u64,
    pub next_update: u64,
    /// cRLNumber content octets (big-endian, as encoded).
    pub crl_number: Option<Vec<u8>>,
    /// serial content octets → (reason, revocationDate µs).
    pub revoked: HashMap<Vec<u8>, (RevocationReason, u64)>,
    /// Estimated memory: Σ(serial bytes + 24) + 512.
    pub size: usize,
}

impl CrlEntry {
    /// Fresh at `now` (± skew).
    pub fn fresh(&self, now: u64, skew: u64) -> bool {
        self.this_update <= now.saturating_add(skew) && now <= self.next_update.saturating_add(skew)
    }

    /// Whether this CRL's scope covers `cert` (RFC 5280 §6.3.3(b)).
    ///
    /// `cdp` is the CDP URI the CRL was fetched from (`None` for
    /// configured URLs/files). A named IDP must match whatever the source:
    /// - fetched via a CDP: that URI must be one of the IDP names, or an
    ///   IDP directoryName must equal a directoryName in the certificate's
    ///   CDP (§6.3.3(b)(2)(i), RFC-101);
    /// - configured source, certificate with CDP fullNames: one IDP name
    ///   must equal one of them (§6.3.3(b)(2)(i));
    /// - configured source, certificate without CDP: the IDP must name the
    ///   CRL issuer (directoryName equal to the certificate's issuer).
    ///
    /// Anything else is a scope mismatch, so a partitioned CRL never
    /// answers for a certificate in another partition. directoryNames are
    /// compared as DER bytes, not with the RFC 5280 §7.1 rules: names that
    /// differ only in case or string type do not match (fails closed).
    pub fn covers(&self, cert: &Cert, cdp: Option<&str>) -> bool {
        let s = &self.scope;
        if s.partial || (s.only_user && cert.is_ca()) || (s.only_ca && !cert.is_ca()) {
            return false;
        }
        if !s.named {
            return true;
        }
        if let Some(u) = cdp {
            if s.uris.iter().any(|x| x == u) {
                return true;
            }
            if s.dir_names.is_empty() {
                return false;
            }
            let (_, dirs) = cert_cdp_names(cert);
            return s.dir_names.iter().any(|d| dirs.contains(d));
        }
        let (uris, dirs) = cert_cdp_names(cert);
        if uris.is_empty() && dirs.is_empty() {
            return s.dir_names.iter().any(|d| d.as_slice() == cert.issuer_der());
        }
        s.uris.iter().any(|x| uris.contains(x)) || s.dir_names.iter().any(|d| dirs.contains(d))
    }
}

/// Most CDP names compared per certificate (SC-5). Names past the cap
/// are not compared, which can only cause a mismatch (fails closed).
const MAX_CDP_NAMES: usize = 16;

/// Most names in a CRL's IDP (SC-5). An IDP with more names is not
/// truncated (a dropped name could silently change the scope): the CRL is
/// rejected as `ScopeMismatch` (RFC-103).
const MAX_IDP_NAMES: usize = 64;

/// fullName URIs and directoryNames (DER) of the certificate's CRL
/// distribution points that have no `cRLIssuer` (§6.3.3(b)(2)(i)).
/// An undecodable CDP extension yields no names (and so no match for a
/// named IDP).
fn cert_cdp_names(cert: &Cert) -> (Vec<String>, Vec<Vec<u8>>) {
    let (mut uris, mut dirs) = (Vec::new(), Vec::new());
    let Some(v) = cert.extension(ID_CE_CRL_DISTRIBUTION_POINTS) else { return (uris, dirs) };
    let Ok(dps) = CrlDistributionPoints::from_der(v) else { return (uris, dirs) };
    for dp in dps.0.iter().filter(|d| d.crl_issuer.is_none()) {
        let Some(DistributionPointName::FullName(names)) = &dp.distribution_point else { continue };
        for n in names.iter().take(MAX_CDP_NAMES) {
            match n {
                GeneralName::UniformResourceIdentifier(u) => uris.push(u.as_str().to_owned()),
                GeneralName::DirectoryName(d) => {
                    if let Ok(b) = d.to_der() {
                        dirs.push(b);
                    }
                }
                _ => {}
            }
        }
    }
    (uris, dirs)
}

/// `a < b` for unsigned big-endian integers given as content octets.
pub fn number_lt(a: &[u8], b: &[u8]) -> bool {
    let strip = |x: &[u8]| -> Vec<u8> { x.iter().copied().skip_while(|&c| c == 0).collect() };
    let (a, b) = (strip(a), strip(b));
    a.len() < b.len() || (a.len() == b.len() && a < b)
}

/// The signed pieces of a CRL, split without decoding the revoked list.
struct Raw<'a> {
    tbs: &'a [u8],
    alg: AlgorithmIdentifierOwned,
    sig: BitString,
    issuer: Vec<u8>,
}

fn split(der: &[u8]) -> Result<Raw<'_>, CrlReason> {
    let m = |_| CrlReason::Malformed;
    let mut r = SliceReader::new(der).map_err(m)?;
    let outer = der::Header::decode(&mut r).map_err(m)?;
    if outer.tag != Tag::Sequence {
        return Err(CrlReason::Malformed);
    }
    let tbs = r.tlv_bytes().map_err(m)?;
    let alg = AlgorithmIdentifierOwned::decode(&mut r).map_err(m)?;
    let sig = BitString::decode(&mut r).map_err(m)?;
    r.finish(()).map_err(m)?;
    // tbsCertList prefix: version?, signature, issuer.
    let mut t = SliceReader::new(tbs).map_err(m)?;
    let h = der::Header::decode(&mut t).map_err(m)?;
    if h.tag != Tag::Sequence {
        return Err(CrlReason::Malformed);
    }
    if t.peek_tag().map_err(m)? == Tag::Integer {
        let _ = u8::decode(&mut t).map_err(m)?;
    }
    let inner = AlgorithmIdentifierOwned::decode(&mut t).map_err(m)?;
    if inner != alg {
        return Err(CrlReason::Malformed);
    }
    let issuer = Name::decode(&mut t).map_err(m)?.to_der().map_err(m)?;
    Ok(Raw { tbs, alg, sig, issuer })
}

/// Issuer keyUsage, if present, must assert cRLSign (RFC 5280 §6.3.3(f)).
fn crl_sign_ok(issuer: &Cert) -> bool {
    match issuer.extension(ID_CE_KEY_USAGE) {
        None => true,
        Some(v) => KeyUsage::from_der(v).is_ok_and(|ku| ku.0.contains(KeyUsages::CRLSign)),
    }
}

/// The issuer name of a CRL (DER), for source triage.
pub fn issuer_name(der: &[u8]) -> Result<Vec<u8>, CrlReason> {
    split(der).map(|r| r.issuer)
}

/// Full verification against `issuer`, then [`inspect`].
///
/// `WrongIssuer` means the CRL is for another CA (name mismatch); the
/// caller decides whether that is an attack (CDP of this certificate) or
/// simply not applicable (a configured source for another CA).
pub fn verify(der: &[u8], issuer: &Cert, now: u64, skew: u64) -> Result<CrlEntry, CrlReason> {
    let raw = split(der)?;
    if raw.issuer != issuer.subject_der() {
        return Err(CrlReason::WrongIssuer);
    }
    if !crl_sign_ok(issuer) {
        return Err(CrlReason::NoCrlSign);
    }
    let sig = raw.sig.as_bytes().ok_or(CrlReason::Malformed)?;
    crate::revocation::sig::verify(issuer.spki(), &raw.alg, raw.tbs, sig).map_err(|_| CrlReason::BadSignature)?;
    let mut e = inspect(der, now, skew)?;
    e.issuer_key_hash = crate::revocation::issuer_key_hash(issuer);
    Ok(e)
}

fn secs(t: &x509_cert::time::Time) -> u64 {
    t.to_unix_duration().as_secs()
}

fn idp_scope(v: &[u8]) -> Result<Scope, CrlReason> {
    let idp = IssuingDistributionPoint::from_der(v).map_err(|_| CrlReason::Malformed)?;
    if idp.indirect_crl {
        return Err(CrlReason::Indirect);
    }
    if idp.only_contains_attribute_certs || (idp.only_contains_user_certs && idp.only_contains_ca_certs) {
        return Err(CrlReason::ScopeMismatch);
    }
    let mut s = Scope {
        only_user: idp.only_contains_user_certs,
        only_ca: idp.only_contains_ca_certs,
        partial: idp.only_some_reasons.is_some(),
        named: idp.distribution_point.is_some(),
        uris: Vec::new(),
        dir_names: Vec::new(),
    };
    if let Some(DistributionPointName::FullName(names)) = &idp.distribution_point {
        if names.len() > MAX_IDP_NAMES {
            return Err(CrlReason::ScopeMismatch);
        }
        for n in names {
            match n {
                GeneralName::UniformResourceIdentifier(u) => s.uris.push(u.as_str().to_owned()),
                GeneralName::DirectoryName(d) => s.dir_names.push(d.to_der().map_err(|_| CrlReason::Malformed)?),
                _ => {}
            }
        }
    }
    Ok(s)
}

/// Whether any extension OID occurs twice (lists are short; quadratic
/// is fine and allocation-free).
fn has_duplicate(exts: &[x509_cert::ext::Extension]) -> bool {
    exts.iter().enumerate().any(|(i, a)| exts.iter().skip(i + 1).any(|b| b.extn_id == a.extn_id))
}

/// Structural checks and the parsed revoked set, without the signature.
/// Never use the result to decide unless it came from [`verify`].
pub fn inspect(der: &[u8], now: u64, skew: u64) -> Result<CrlEntry, CrlReason> {
    let crl = CertificateList::from_der(der).map_err(|_| CrlReason::Malformed)?;
    let tbs = &crl.tbs_cert_list;
    if crl.signature_algorithm != tbs.signature {
        return Err(CrlReason::Malformed);
    }
    let entries = tbs.revoked_certificates.as_deref().unwrap_or(&[]);
    let has_ext = tbs.crl_extensions.is_some() || entries.iter().any(|e| e.crl_entry_extensions.is_some());
    if has_ext && tbs.version != x509_cert::Version::V2 {
        return Err(CrlReason::Malformed);
    }
    let this_update = secs(&tbs.this_update);
    let next_update = secs(tbs.next_update.as_ref().ok_or(CrlReason::NoNextUpdate)?);
    // RFC-003: a future-dated CRL is not yet valid, not stale (same
    // treatment: never decides, never soft-accepted).
    if this_update > now.saturating_add(skew) {
        return Err(CrlReason::NotYetValid);
    }
    if next_update.saturating_add(skew) < now {
        return Err(CrlReason::Stale);
    }
    let mut scope = Scope::default();
    let mut crl_number = None;
    let crl_exts = tbs.crl_extensions.as_deref().unwrap_or(&[]);
    // RFC-005 / RFC 5280 §4.2: an extension appears at most once.
    if has_duplicate(crl_exts) {
        return Err(CrlReason::Malformed);
    }
    for x in crl_exts {
        match x.extn_id {
            ID_CE_DELTA_CRL_INDICATOR => return Err(CrlReason::Delta),
            ID_CE_ISSUING_DISTRIBUTION_POINT => scope = idp_scope(x.extn_value.as_bytes())?,
            ID_CE_CRL_NUMBER => {
                let n = CrlNumber::from_der(x.extn_value.as_bytes()).map_err(|_| CrlReason::Malformed)?;
                crl_number = Some(n.0.as_bytes().to_vec());
            }
            ID_CE_AUTHORITY_KEY_IDENTIFIER | ID_CE_ISSUER_ALT_NAME | ID_CE_FRESHEST_CRL => {}
            _ if x.critical => return Err(CrlReason::CriticalExt),
            _ => {}
        }
    }
    let mut revoked = HashMap::with_capacity(entries.len());
    let mut size = CRL_OVERHEAD;
    for e in entries {
        let mut reason = RevocationReason::Unspecified;
        let entry_exts = e.crl_entry_extensions.as_deref().unwrap_or(&[]);
        if has_duplicate(entry_exts) {
            return Err(CrlReason::Malformed);
        }
        for x in entry_exts {
            match x.extn_id {
                ID_CE_CRL_REASONS => {
                    let r = x509_cert::ext::pkix::CrlReason::from_der(x.extn_value.as_bytes())
                        .map_err(|_| CrlReason::Malformed)?;
                    reason = RevocationReason::from_code(r as u8).ok_or(CrlReason::Malformed)?;
                    // removeFromCRL only appears in delta CRLs.
                    if reason == RevocationReason::RemoveFromCrl {
                        return Err(CrlReason::Malformed);
                    }
                }
                ID_CE_CERTIFICATE_ISSUER => return Err(CrlReason::Indirect),
                ID_CE_INVALIDITY_DATE => {}
                _ if x.critical => return Err(CrlReason::CriticalExt),
                _ => {}
            }
        }
        let serial = e.serial_number.as_bytes().to_vec();
        size = size.saturating_add(serial.len() + ENTRY_OVERHEAD);
        let at = secs(&e.revocation_date).saturating_mul(1_000_000);
        revoked.entry(serial).or_insert((reason, at));
    }
    Ok(CrlEntry { issuer_key_hash: [0; 32], scope, this_update, next_update, crl_number, revoked, size })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_order() {
        assert!(number_lt(&[1], &[2]));
        assert!(number_lt(&[0, 0xff], &[1, 0]));
        assert!(!number_lt(&[0, 2], &[2]));
        assert!(!number_lt(&[3], &[2]));
    }

    proptest::proptest! {
        #[test]
        fn never_panics(raw in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
            let _ = inspect(&raw, 0, 0);
            let _ = issuer_name(&raw);
        }
    }
}
