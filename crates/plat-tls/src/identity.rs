//! Peer identity from a verified certificate, and the management client
//! allow-list.
//!
//! Only called on an end-entity certificate that already chained to the
//! configured CA. A certificate that cannot be parsed yields an identity
//! with only the fingerprint, which matches no allow-list entry (fail
//! closed).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement) - exact allow-list match on
//!   subject CN, DNS SAN or URI SAN; no wildcards
//! - NIST 800-53: IA-3, IA-5(2)(a)(2) - map the authenticated identity to
//!   an account (allow-list entry)

use der::asn1::ObjectIdentifier as Oid;
use der::{Decode, Tagged};
use rustls_pki_types::CertificateDer;
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

use crate::TlsError;

const CN: Oid = Oid::new_unwrap("2.5.4.3");
const SAN: Oid = Oid::new_unwrap("2.5.29.17");

/// Identity of a TLS peer, from its end-entity certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Subject CN, only if exactly one CN attribute is present.
    pub subject_cn: Option<String>,
    pub dns_sans: Vec<String>,
    pub uri_sans: Vec<String>,
    /// SHA-256 of the certificate DER.
    pub sha256: [u8; 32],
    /// `sha256` as lowercase hex.
    pub fingerprint_sha256: String,
}

fn text(v: &der::Any) -> Option<String> {
    use der::Tag;
    match v.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String => {
            std::str::from_utf8(v.value()).ok().map(str::to_owned)
        }
        _ => None,
    }
}

/// Extracts the identity of `cert`. Never fails: unparseable fields are
/// left empty.
pub fn peer_identity(cert: &CertificateDer<'_>) -> PeerIdentity {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert.as_ref());
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(d.as_ref());
    let mut id = PeerIdentity {
        sha256,
        fingerprint_sha256: sha256.iter().map(|b| format!("{b:02x}")).collect(),
        ..PeerIdentity::default()
    };
    let Ok(c) = Certificate::from_der(cert.as_ref()) else {
        return id;
    };
    let tbs = &c.tbs_certificate;
    let cns: Vec<_> =
        tbs.subject.0.iter().flat_map(|rdn| rdn.0.iter()).filter(|a| a.oid == CN).map(|a| text(&a.value)).collect();
    if let [Some(cn)] = cns.as_slice() {
        id.subject_cn = Some(cn.clone());
    }
    let sans: Vec<_> = tbs.extensions.iter().flatten().filter(|e| e.extn_id == SAN).collect();
    if let [ext] = sans.as_slice()
        && let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes())
    {
        for n in san.0 {
            match n {
                GeneralName::DnsName(s) => id.dns_sans.push(s.to_string()),
                GeneralName::UniformResourceIdentifier(s) => id.uri_sans.push(s.to_string()),
                _ => {}
            }
        }
    }
    id
}

/// Subject and validity end of a configured certificate (`check-config`
/// TLS summary, `plat_tls_cert_expiry_seconds`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSummary {
    /// Subject DN in RFC 4514 form.
    pub subject: String,
    /// `notAfter`, seconds since the Unix epoch.
    pub not_after: u64,
}

/// Summarises `cert`; `None` if it is not valid X.509.
pub fn cert_summary(cert: &CertificateDer<'_>) -> Option<CertSummary> {
    let c = Certificate::from_der(cert.as_ref()).ok()?;
    let tbs = &c.tbs_certificate;
    Some(CertSummary {
        subject: tbs.subject.to_string(),
        not_after: tbs.validity.not_after.to_unix_duration().as_secs(),
    })
}

/// One typed allow-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// Subject CN, ASCII case-insensitive.
    Cn(String),
    /// DNS SAN, ASCII case-insensitive.
    Dns(String),
    /// URI SAN, exact.
    Uri(String),
    /// SHA-256 of the certificate DER.
    Sha256([u8; 32]),
}

fn parse_entry(e: &str) -> Result<Entry, TlsError> {
    let bad = || TlsError::Config(format!("allow-list entry {e:?} must be typed: cn:, dns:, uri: or sha256:"));
    let (kind, v) = e.split_once(':').ok_or_else(bad)?;
    if v.is_empty() {
        return Err(bad());
    }
    match kind {
        "cn" => Ok(Entry::Cn(v.to_owned())),
        "dns" => Ok(Entry::Dns(v.to_owned())),
        "uri" => Ok(Entry::Uri(v.to_owned())),
        "sha256" => {
            let b = v.as_bytes();
            if b.len() != 64 {
                return Err(bad());
            }
            let mut out = [0u8; 32];
            for (i, o) in out.iter_mut().enumerate() {
                let hex = std::str::from_utf8(b.get(i * 2..i * 2 + 2).ok_or_else(bad)?).map_err(|_| bad())?;
                *o = u8::from_str_radix(hex, 16).map_err(|_| bad())?;
            }
            Ok(Entry::Sha256(out))
        }
        _ => Err(bad()),
    }
}

/// Exact-match client allow-list (`management.tls.allowed_clients`).
///
/// Entries are typed (SEC-004), so a value meant for one field never
/// matches another: `cn:` matches the subject CN and `dns:` a DNS SAN
/// (ASCII case-insensitive, DNS names are case-insensitive), `uri:` a URI
/// SAN (exact, case-sensitive), `sha256:` the certificate DER fingerprint.
/// No wildcards, no prefix or suffix matching. Untyped entries are
/// rejected.
#[derive(Debug, Clone)]
pub struct AllowList {
    /// (configured text, parsed entry)
    entries: Vec<(String, Entry)>,
}

impl AllowList {
    pub fn new(entries: &[String]) -> Result<Self, TlsError> {
        if entries.is_empty() {
            return Err(TlsError::Config("allow-list must not be empty".into()));
        }
        let entries = entries.iter().map(|e| parse_entry(e).map(|p| (e.clone(), p))).collect::<Result<_, _>>()?;
        Ok(Self { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The first entry (as configured, e.g. `dns:host`) that `id` matches.
    pub fn matched<'a>(&'a self, id: &PeerIdentity) -> Option<&'a str> {
        self.entries
            .iter()
            .find(|(_, e)| match e {
                Entry::Cn(v) => id.subject_cn.as_deref().is_some_and(|cn| cn.eq_ignore_ascii_case(v)),
                Entry::Dns(v) => id.dns_sans.iter().any(|d| d.eq_ignore_ascii_case(v)),
                Entry::Uri(v) => id.uri_sans.iter().any(|u| u == v),
                Entry::Sha256(h) => &id.sha256 == h,
            })
            .map(|(t, _)| t.as_str())
    }

    pub fn permits(&self, id: &PeerIdentity) -> bool {
        self.matched(id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(cn: Option<&str>, dns: &[&str], uri: &[&str]) -> PeerIdentity {
        PeerIdentity {
            subject_cn: cn.map(str::to_owned),
            dns_sans: dns.iter().map(|s| (*s).to_owned()).collect(),
            uri_sans: uri.iter().map(|s| (*s).to_owned()).collect(),
            ..PeerIdentity::default()
        }
    }

    #[test]
    fn exact_matching() {
        let a = AllowList::new(&[
            "cn:prom-01.ops.example.net".into(),
            "dns:prom-02.ops.example.net".into(),
            "uri:spiffe://ops/prom".into(),
        ])
        .unwrap();
        assert_eq!(a.matched(&id(Some("prom-01.ops.example.net"), &[], &[])), Some("cn:prom-01.ops.example.net"));
        assert!(a.permits(&id(Some("PROM-01.ops.example.net"), &[], &[])));
        assert!(a.permits(&id(None, &["prom-02.OPS.example.net"], &[])));
        assert!(a.permits(&id(None, &[], &["spiffe://ops/prom"])));
        // Typed: a CN entry never matches a SAN and vice versa.
        assert!(!a.permits(&id(None, &["prom-01.ops.example.net"], &[])));
        assert!(!a.permits(&id(Some("prom-02.ops.example.net"), &[], &[])));
        assert!(!a.permits(&id(None, &[], &["spiffe://ops/Prom"])));
        assert!(!a.permits(&id(None, &[], &["spiffe://ops/prom/x"])));
        assert!(!a.permits(&id(Some("x.prom-01.ops.example.net"), &[], &[])));
        assert!(!a.permits(&id(None, &[], &[])));
        // A literal '*' entry (rejected by config anyway) is not a wildcard.
        let w = AllowList::new(&["dns:*.example.net".into()]).unwrap();
        assert!(!w.permits(&id(Some("a.example.net"), &["a.example.net"], &[])));
        assert!(AllowList::new(&[]).is_err());
    }

    #[test]
    fn fingerprint_and_untyped() {
        let mut who = id(None, &[], &[]);
        who.sha256 = [0xab; 32];
        let a = AllowList::new(&[format!("sha256:{}", "AB".repeat(32))]).unwrap();
        assert!(a.permits(&who));
        who.sha256 = [0xac; 32];
        assert!(!a.permits(&who));
        for bad in ["prom", "cn:", "host:x", "sha256:ab", "sha256:é"] {
            assert!(AllowList::new(&[bad.into()]).is_err(), "{bad}");
        }
        assert!(AllowList::new(&[format!("sha256:{}", "zz".repeat(32))]).is_err());
    }
}
