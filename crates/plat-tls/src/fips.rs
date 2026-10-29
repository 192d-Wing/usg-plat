//! FIPS provider installation and status.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-13 (Cryptographic Protection) - the AWS-LC FIPS
//!   module (via `aws-lc-rs`) is the process-default rustls provider, and
//!   the daemon refuses to start unless the module reports FIPS mode.
//! - FIPS 140-3: the module runs its power-on self tests when first used;
//!   `aws_lc_rs::try_fips_mode` reports the module's own status.

use std::sync::OnceLock;
#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicBool, Ordering};

use rustls::crypto::CryptoProvider;

use crate::TlsError;

/// Name recorded as `plat.fips_provider`.
pub const PROVIDER_NAME: &str = "aws-lc-rs-fips";

/// Result of [`init_fips`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsStatus {
    /// The FIPS provider is the process default and the module reports
    /// FIPS mode.
    pub active: bool,
    pub provider: &'static str,
    /// Human-readable detail (AWS-LC version, FIPS branch, failure cause).
    pub detail: String,
}

static STATUS: OnceLock<FipsStatus> = OnceLock::new();

#[cfg(feature = "test-hooks")]
static FORCE_INACTIVE: AtomicBool = AtomicBool::new(false);

/// Test hook: make [`require_fips`] fail as if the module were inactive.
#[cfg(feature = "test-hooks")]
pub fn force_inactive_for_tests(on: bool) {
    FORCE_INACTIVE.store(on, Ordering::Relaxed);
}

fn forced_inactive() -> bool {
    #[cfg(feature = "test-hooks")]
    {
        FORCE_INACTIVE.load(Ordering::Relaxed)
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        false
    }
}

/// Installs the AWS-LC FIPS provider as the rustls process default and
/// reports whether FIPS mode is active. Idempotent: the first call decides,
/// later calls return the same status. Never panics.
pub fn init_fips() -> FipsStatus {
    STATUS.get_or_init(probe).clone()
}

fn probe() -> FipsStatus {
    // A different provider installed earlier (by another library) is not
    // replaced; the check below then reports it.
    let _ = rustls::crypto::default_fips_provider().install_default();
    let default_fips = CryptoProvider::get_default().is_some_and(|p| p.fips());
    let module = aws_lc_rs::try_fips_mode();
    let branch = aws_lc_rs::fips_version().map_or_else(|| "none".to_owned(), |v| v.to_string());
    let mut detail = format!("AWS-LC {} (FIPS branch {branch})", aws_lc_rs::awslc_version());
    if !default_fips {
        detail.push_str("; process-default rustls provider is not FIPS");
    }
    if let Err(e) = module {
        detail.push_str("; module: ");
        detail.push_str(e);
    }
    FipsStatus { active: default_fips && module.is_ok(), provider: PROVIDER_NAME, detail }
}

/// `Ok` only if [`init_fips`] reports FIPS mode active (SC-13 start gate).
pub fn require_fips() -> Result<(), TlsError> {
    let s = init_fips();
    if forced_inactive() {
        return Err(TlsError::NotFips("forced inactive by test hook".into()));
    }
    if s.active { Ok(()) } else { Err(TlsError::NotFips(s.detail)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent_and_active() {
        let a = init_fips();
        let b = init_fips();
        assert_eq!(a, b);
        assert!(a.active, "{}", a.detail);
        assert_eq!(a.provider, PROVIDER_NAME);
        assert!(CryptoProvider::get_default().is_some_and(|p| p.fips()));
        require_fips().unwrap();
    }
}
