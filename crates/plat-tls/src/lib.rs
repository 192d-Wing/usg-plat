//! FIPS TLS for the usg-plat management and audit planes.
//!
//! Everything cryptographic outside the data plane lives here: the AWS-LC
//! FIPS provider (installed as the process default), the single TLS policy
//! (TLS 1.3 only, FIPS suites and groups), certificate/key loading with
//! file-permission checks, client identity and allow-list matching, and
//! certificate revocation checking for every non-root certificate of a
//! validated chain.
//!
//! ```text
//!  platd mgmt (mTLS server) ──┐                     ┌─ policy: TLS 1.3, FIPS suites/groups
//!                             ├─▶ plat-tls ─────────┼─ verify: WebPki + RevocationChecker
//!  plat-audit syslog (client)─┘                     └─ load: PEM, key perms, zeroize
//! ```
//!
//! Data-plane crates never depend on this crate. All I/O is blocking `std`
//! on the calling (management, syslog sender, refresher) thread.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8, SC-8(1) (Transmission Confidentiality and Integrity)
//! - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS provider, one policy
//! - NIST 800-53: SC-12 (Key Establishment and Management), IA-5(2), IA-3
//! - RFC 8446 (TLS 1.3), RFC 9325 §4.1, §4.2

#![forbid(unsafe_code)]

pub mod fips;
pub mod identity;
pub mod load;
pub mod policy;
pub mod revocation;
pub mod stream;
pub mod verify;

use std::path::PathBuf;

pub use fips::{FipsStatus, init_fips, require_fips};
pub use identity::{AllowList, CertSummary, PeerIdentity, cert_summary, peer_identity};
pub use load::{check_cache_dir, check_key_file, load_certs, load_key};
pub use policy::{ClientSettings, ServerSettings, client_config, server_config};
pub use revocation::{
    CacheStats, RefreshHook, RefreshRecord, RevocationChecker, RevocationHook, RevocationRecord, RevocationSettings,
    spawn_refresher,
};
pub use verify::{CaBundle, mgmt_client_verifier, syslog_server_verifier};

/// Errors building TLS material. Messages name the file, never its contents.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("reading {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("{0}: {1}")]
    Pem(PathBuf, String),
    #[error("{0}: no certificates found")]
    NoCertificates(PathBuf),
    #[error("{0}: no private key found")]
    NoKey(PathBuf),
    #[error("{0}: encrypted private keys are not supported (deliver the key via systemd LoadCredential=)")]
    EncryptedKey(PathBuf),
    #[error("{0}: larger than {1} bytes")]
    TooLarge(PathBuf, u64),
    #[error("{0}: unsafe permissions: {1}")]
    Permissions(PathBuf, String),
    #[error("FIPS mode not active: {0}")]
    NotFips(String),
    #[error("TLS: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("certificate verifier: {0}")]
    Verifier(String),
    #[error("invalid TLS setting: {0}")]
    Config(String),
}
