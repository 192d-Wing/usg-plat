//! Certificate verifiers: the stock webpki verifiers, wrapped so that a
//! chain that passes path validation is then checked for revocation.
//!
//! The inner verifier always runs first (path to a configured anchor,
//! validity, EKU, server name; handshake signatures are delegated to it).
//! Only if it accepts does [`RevocationChecker::check_chain`] run. Neither
//! inner verifier is given CRLs, and no system or webpki roots are used.
//! Revocation runs on the thread doing the handshake (management
//! connection thread, syslog sender thread), never on an accept or logger
//! thread.
//!
//! Failures map to rustls certificate errors: a revoked certificate to
//! `CertificateError::Revoked`; no conclusive status, an attack-class
//! failure, or a path that cannot be rebuilt to
//! `CertificateError::UnknownRevocationStatus`. Callers map those to their
//! audit reasons (`revoked`, `revocation_check_failed`, `tls_revocation`).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-3, IA-5(2)(b)(1) - mutual certificate authentication with
//!   path validation and full-chain revocation checking
//! - NIST 800-53: SC-8, SC-23 (Session Authenticity)
//! - RFC 5425 §5.2, RFC 6125 - server name verified by webpki

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::TlsError;
use crate::revocation::{Anchors, ChainOutcome, RevocationChecker, Role};

/// Trust anchors from one CA file, as a rustls root store (for webpki)
/// and parsed (for revocation path rebuild).
#[derive(Debug, Clone)]
pub struct CaBundle {
    pub roots: Arc<RootCertStore>,
    pub anchors: Arc<Anchors>,
}

impl CaBundle {
    /// Loads every certificate in `path` as a trust anchor. Any certificate
    /// that is not a usable anchor is an error (no silent skipping).
    pub fn load(path: &Path) -> Result<Self, TlsError> {
        let certs = crate::load::load_certs(path)?;
        let mut roots = RootCertStore::empty();
        let (added, ignored) = roots.add_parsable_certificates(certs.iter().cloned());
        if ignored != 0 || added == 0 {
            return Err(TlsError::Pem(path.into(), format!("{ignored} certificate(s) not usable as trust anchors")));
        }
        let anchors = Anchors::parse(&certs)
            .ok_or_else(|| TlsError::Pem(path.into(), "trust anchor is not valid X.509".into()))?;
        Ok(Self { roots: Arc::new(roots), anchors: Arc::new(anchors) })
    }
}

fn revocation_error(o: ChainOutcome) -> Error {
    match o {
        ChainOutcome::Revoked => Error::InvalidCertificate(CertificateError::Revoked),
        _ => Error::InvalidCertificate(CertificateError::UnknownRevocationStatus),
    }
}

/// Syslog collector verifier: webpki over the configured CA, then
/// revocation for the full chain (stapled OCSP covers the leaf).
pub struct RevocationServerVerifier {
    inner: Arc<WebPkiServerVerifier>,
    role: Role,
    anchors: Arc<Anchors>,
    rev: Option<Arc<RevocationChecker>>,
}

impl fmt::Debug for RevocationServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationServerVerifier").field("revocation", &self.rev.is_some()).finish_non_exhaustive()
    }
}

impl ServerCertVerifier for RevocationServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let ok = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        if let Some(rev) = &self.rev {
            let stapled = (!ocsp_response.is_empty()).then_some(ocsp_response);
            let v = rev.check_chain(self.role, end_entity, intermediates, &self.anchors, stapled, now);
            if !v.outcome.is_accepted() {
                return Err(revocation_error(v.outcome));
            }
        }
        Ok(ok)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Management client verifier: client certificate REQUIRED, webpki over
/// the client CA, then revocation for the full chain.
pub struct RevocationClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    role: Role,
    anchors: Arc<Anchors>,
    rev: Option<Arc<RevocationChecker>>,
}

impl fmt::Debug for RevocationClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationClientVerifier").field("revocation", &self.rev.is_some()).finish_non_exhaustive()
    }
}

impl ClientCertVerifier for RevocationClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let ok = self.inner.verify_client_cert(end_entity, intermediates, now)?;
        if let Some(rev) = &self.rev {
            let v = rev.check_chain(self.role, end_entity, intermediates, &self.anchors, None, now);
            if !v.outcome.is_accepted() {
                return Err(revocation_error(v.outcome));
            }
        }
        Ok(ok)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn client_verifier(
    role: Role,
    ca: &CaBundle,
    provider: Arc<CryptoProvider>,
    rev: Option<Arc<RevocationChecker>>,
) -> Result<Arc<RevocationClientVerifier>, TlsError> {
    let inner = WebPkiClientVerifier::builder_with_provider(ca.roots.clone(), provider)
        .build()
        .map_err(|e| TlsError::Verifier(e.to_string()))?;
    Ok(Arc::new(RevocationClientVerifier { inner, role, anchors: ca.anchors.clone(), rev }))
}

fn server_verifier(
    role: Role,
    ca: &CaBundle,
    provider: Arc<CryptoProvider>,
    rev: Option<Arc<RevocationChecker>>,
) -> Result<Arc<RevocationServerVerifier>, TlsError> {
    let inner = WebPkiServerVerifier::builder_with_provider(ca.roots.clone(), provider)
        .build()
        .map_err(|e| TlsError::Verifier(e.to_string()))?;
    Ok(Arc::new(RevocationServerVerifier { inner, role, anchors: ca.anchors.clone(), rev }))
}

/// Builds the management client verifier (mandatory client auth).
pub fn mgmt_client_verifier(
    ca: &CaBundle,
    provider: Arc<CryptoProvider>,
    rev: Option<Arc<RevocationChecker>>,
) -> Result<Arc<RevocationClientVerifier>, TlsError> {
    client_verifier(Role::MgmtClient, ca, provider, rev)
}

/// Builds the syslog collector verifier.
pub fn syslog_server_verifier(
    ca: &CaBundle,
    provider: Arc<CryptoProvider>,
    rev: Option<Arc<RevocationChecker>>,
) -> Result<Arc<RevocationServerVerifier>, TlsError> {
    server_verifier(Role::SyslogServer, ca, provider, rev)
}

/// Builds the verifier for peers connecting to this node (mandatory client
/// auth over the cluster CA, revocation as [`Role::PeerClient`]).
pub fn peer_client_verifier(
    ca: &CaBundle,
    provider: Arc<CryptoProvider>,
    rev: Option<Arc<RevocationChecker>>,
) -> Result<Arc<RevocationClientVerifier>, TlsError> {
    client_verifier(Role::PeerClient, ca, provider, rev)
}

/// Builds the verifier for peers this node connects to (cluster CA,
/// revocation as [`Role::PeerServer`]).
pub fn peer_server_verifier(
    ca: &CaBundle,
    provider: Arc<CryptoProvider>,
    rev: Option<Arc<RevocationChecker>>,
) -> Result<Arc<RevocationServerVerifier>, TlsError> {
    server_verifier(Role::PeerServer, ca, provider, rev)
}
