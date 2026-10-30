//! The single TLS policy for every endpoint (SC-13: one code location).
//!
//! - Protocol: TLS 1.3 only (the rustls `tls12` feature is not compiled).
//! - Cipher suites: the AWS-LC FIPS provider's TLS 1.3 suites that report
//!   `fips()` (TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256).
//! - Key exchange: X25519MLKEM768 (hybrid, preferred, `tls.pq_hybrid`),
//!   then secp256r1, secp384r1; each must report `fips()`.
//! - Every built config is asserted `fips()`, else `TlsError::NotFips`.
//! - No session resumption: the server issues no tickets and keeps no
//!   session cache; the client does not resume. Every connection runs full
//!   certificate verification (and revocation). No 0-RTT.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-13, SC-8(1) - FIPS-approved suites and groups only
//! - NIST SP 800-52 Rev 2 §3.1 (TLS 1.3 supported), RFC 9325 §4.1, §4.2
//! - RFC 8446 §2.3 / §4.2.10 - no 0-RTT early data

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use plat_common::config::{ClusterTlsConfig, ManagementTlsConfig, SyslogTlsConfig};
use rustls::client::Resumption;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::server::NoServerSessionStorage;
use rustls::{ClientConfig, ServerConfig, SupportedProtocolVersion};
use rustls_pki_types::ServerName;

use crate::TlsError;
use crate::load::{load_certs, load_key};
use crate::revocation::RevocationChecker;
use crate::verify::{
    CaBundle, mgmt_client_verifier, peer_client_verifier, peer_server_verifier, syslog_server_verifier,
};

static VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// The FIPS provider restricted to the policy's suites and groups.
pub fn fips_provider(pq_hybrid: bool) -> Result<Arc<CryptoProvider>, TlsError> {
    let mut p = rustls::crypto::default_fips_provider();
    p.cipher_suites.retain(|s| s.version() == &rustls::version::TLS13 && s.fips());
    let mut groups = Vec::with_capacity(3);
    if pq_hybrid {
        groups.push(kx_group::X25519MLKEM768);
    }
    groups.extend([kx_group::SECP256R1, kx_group::SECP384R1]);
    p.kx_groups = groups.into_iter().filter(|g| g.fips()).collect();
    if p.cipher_suites.is_empty() || p.kx_groups.is_empty() || !p.fips() {
        return Err(TlsError::NotFips("provider offers no FIPS TLS 1.3 suites/groups".into()));
    }
    if pq_hybrid && p.kx_groups.len() != 3 {
        return Err(TlsError::NotFips("X25519MLKEM768 is not FIPS-approved in this provider build".into()));
    }
    Ok(Arc::new(p))
}

/// Names of the offered key-exchange groups, in preference order
/// (`check-config`).
pub fn kx_group_names(pq_hybrid: bool) -> Result<Vec<String>, TlsError> {
    Ok(fips_provider(pq_hybrid)?.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect())
}

/// Names of the offered cipher suites (`check-config`).
pub fn cipher_suite_names() -> Result<Vec<String>, TlsError> {
    Ok(fips_provider(false)?.cipher_suites.iter().map(|s| format!("{:?}", s.suite())).collect())
}

/// Validates a syslog `server_name` (DNS name or IP literal).
pub fn server_name(s: &str) -> Result<ServerName<'static>, TlsError> {
    ServerName::try_from(s.to_owned()).map_err(|e| TlsError::Config(format!("server_name {s:?}: {e}")))
}

/// TLS client (syslog collector) settings.
#[derive(Debug, Clone)]
pub struct ClientSettings {
    pub ca_file: PathBuf,
    /// Client certificate chain and key for mutual TLS.
    pub client_auth: Option<(PathBuf, PathBuf)>,
    pub pq_hybrid: bool,
    pub revocation: Option<Arc<RevocationChecker>>,
}

impl ClientSettings {
    pub fn from_config(t: &SyslogTlsConfig, pq_hybrid: bool, revocation: Option<Arc<RevocationChecker>>) -> Self {
        Self {
            ca_file: t.ca_file.clone(),
            client_auth: t.cert_file.clone().zip(t.key_file.clone()),
            pq_hybrid,
            revocation,
        }
    }
}

/// TLS server (management) settings.
#[derive(Debug, Clone)]
pub struct ServerSettings {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub client_ca_file: PathBuf,
    pub pq_hybrid: bool,
    pub revocation: Option<Arc<RevocationChecker>>,
}

impl ServerSettings {
    pub fn from_config(t: &ManagementTlsConfig, pq_hybrid: bool, revocation: Option<Arc<RevocationChecker>>) -> Self {
        Self {
            cert_file: t.cert_file.clone(),
            key_file: t.key_file.clone(),
            client_ca_file: t.client_ca_file.clone(),
            pq_hybrid,
            revocation,
        }
    }
}

/// Builds the syslog client config. Fails closed on any unreadable or
/// unusable CA, certificate or key.
pub fn client_config(s: &ClientSettings) -> Result<Arc<ClientConfig>, TlsError> {
    let provider = fips_provider(s.pq_hybrid)?;
    let ca = CaBundle::load(&s.ca_file)?;
    let verifier = syslog_server_verifier(&ca, provider.clone(), s.revocation.clone())?;
    // COMPLIANCE MAPPING:
    // - NIST 800-53: IA-3, IA-5(2)(b)(1) - rustls 0.23 accepts a custom server
    //   verifier only through this builder. The verifier is not permissive:
    //   it delegates to `WebPkiServerVerifier` (configured CA only) first
    //   and only adds the revocation check. This is the only use in the
    //   workspace.
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(VERSIONS)?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut cfg = match &s.client_auth {
        Some((cert, key)) => {
            let chain = load_certs(cert)?;
            let key = load_key(key)?;
            builder.with_client_auth_cert(chain, key)?
        }
        None => builder.with_no_client_auth(),
    };
    cfg.resumption = Resumption::disabled();
    cfg.enable_early_data = false;
    if !cfg.fips() {
        return Err(TlsError::NotFips("client config".into()));
    }
    Ok(Arc::new(cfg))
}

/// Builds the management server config (client certificate required).
pub fn server_config(s: &ServerSettings) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = fips_provider(s.pq_hybrid)?;
    let ca = CaBundle::load(&s.client_ca_file)?;
    let verifier = mgmt_client_verifier(&ca, provider.clone(), s.revocation.clone())?;
    let chain = load_certs(&s.cert_file)?;
    let key = load_key(&s.key_file)?;
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(VERSIONS)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    cfg.send_tls13_tickets = 0;
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    cfg.max_early_data_size = 0;
    if !cfg.fips() {
        return Err(TlsError::NotFips("server config".into()));
    }
    Ok(Arc::new(cfg))
}

/// Cluster peer channel settings: one certificate, key and CA for both
/// roles (every node listens and dials). Client certificates are required
/// in both directions.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-8, SC-8(1), SC-13 - TLS 1.3 FIPS policy as above
/// - NIST 800-53: IA-3, IA-5(2) - mutual authentication over the cluster CA
///   with full-chain revocation; the caller binds the peer identity to the
///   member (`AllowList` of that member's `identity`) after the handshake
#[derive(Debug, Clone)]
pub struct PeerSettings {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub ca_file: PathBuf,
    pub pq_hybrid: bool,
    pub revocation: Option<Arc<RevocationChecker>>,
}

impl PeerSettings {
    pub fn from_config(t: &ClusterTlsConfig, pq_hybrid: bool, revocation: Option<Arc<RevocationChecker>>) -> Self {
        Self {
            cert_file: t.cert_file.clone(),
            key_file: t.key_file.clone(),
            ca_file: t.ca_file.clone(),
            pq_hybrid,
            revocation,
        }
    }
}

/// Server and client configs for the peer channel, built from one
/// [`PeerSettings`] (CA, certificate and key loaded once).
#[derive(Debug, Clone)]
pub struct PeerConfigs {
    /// Accepting side: client certificate required.
    pub server: Arc<ServerConfig>,
    /// Dialing side: presents the same certificate.
    pub client: Arc<ClientConfig>,
}

/// Builds both peer configs. Fails closed on any unreadable or unusable CA,
/// certificate or key, or a non-FIPS result.
pub fn peer_configs(s: &PeerSettings) -> Result<PeerConfigs, TlsError> {
    let provider = fips_provider(s.pq_hybrid)?;
    let ca = CaBundle::load(&s.ca_file)?;
    let chain = load_certs(&s.cert_file)?;
    let key = load_key(&s.key_file)?;

    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(VERSIONS)?
        .with_client_cert_verifier(peer_client_verifier(&ca, provider.clone(), s.revocation.clone())?)
        .with_single_cert(chain.clone(), key.clone_key())?;
    server.send_tls13_tickets = 0;
    server.session_storage = Arc::new(NoServerSessionStorage {});
    server.max_early_data_size = 0;
    if !server.fips() {
        return Err(TlsError::NotFips("peer server config".into()));
    }

    // COMPLIANCE MAPPING:
    // - NIST 800-53: IA-3, IA-5(2)(b)(1) - as `client_config`: the custom
    //   verifier delegates to `WebPkiServerVerifier` (cluster CA only) and
    //   only adds the revocation check.
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(VERSIONS)?
        .dangerous()
        .with_custom_certificate_verifier(peer_server_verifier(&ca, provider, s.revocation.clone())?)
        .with_client_auth_cert(chain, key)?;
    client.resumption = Resumption::disabled();
    client.enable_early_data = false;
    if !client.fips() {
        return Err(TlsError::NotFips("peer client config".into()));
    }
    Ok(PeerConfigs { server: Arc::new(server), client: Arc::new(client) })
}

/// Server name used to dial a peer: the DNS name of a `dns:` identity,
/// otherwise the peer's IP address (its certificate then needs an IP SAN).
/// The typed identity itself is matched exactly after the handshake.
pub fn peer_server_name(identity: &str, addr: IpAddr) -> Result<ServerName<'static>, TlsError> {
    match identity.strip_prefix("dns:") {
        Some(name) => server_name(name),
        None => Ok(ServerName::IpAddress(addr.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suites_and_groups() {
        let p = fips_provider(true).unwrap();
        assert!(p.fips());
        assert!(p.cipher_suites.iter().all(|s| s.version() == &rustls::version::TLS13 && s.fips()));
        assert_eq!(p.cipher_suites.len(), 2);
        assert_eq!(kx_group_names(true).unwrap(), ["X25519MLKEM768", "secp256r1", "secp384r1"]);
        assert_eq!(kx_group_names(false).unwrap(), ["secp256r1", "secp384r1"]);
        let suites = cipher_suite_names().unwrap();
        assert!(suites.iter().all(|s| s.starts_with("TLS13_AES_")), "{suites:?}");
    }

    #[test]
    fn server_names() {
        server_name("siem.example.net").unwrap();
        server_name("2001:db8::10").unwrap();
        assert!(server_name("bad name").is_err());
    }

    #[test]
    fn peer_server_names() {
        let ip: IpAddr = "198.51.100.12".parse().unwrap();
        assert_eq!(
            peer_server_name("dns:plat-02.cluster.example", ip).unwrap(),
            ServerName::try_from("plat-02.cluster.example").unwrap()
        );
        assert_eq!(peer_server_name("cn:plat-02", ip).unwrap(), ServerName::IpAddress(ip.into()));
        assert!(peer_server_name("dns:bad name", ip).is_err());
    }
}
