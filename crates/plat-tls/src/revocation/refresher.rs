//! Background refresher thread (`plat-revocation`).
//!
//! One thread per process, owned by `platd run`, shared with every
//! verifier through the `Arc<RevocationChecker>`. It lets the OCSP and CRL
//! sources do due work (pre-fetch configured CRLs, refresh before
//! `nextUpdate`, back off on failure); the sources decide what is due. The
//! thread wakes at least every 500 ms to check `stop`, so shutdown joins
//! promptly (before the audit logger stops).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5(2)(b)(1), IA-5(2)(b)(2) - revocation data kept fresh so handshakes rarely
//!   block on a fetch; SC-5 - serial, one fetch at a time

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use rustls_pki_types::UnixTime;

use super::RevocationChecker;

/// Longest sleep between `stop` checks.
pub const MAX_WAIT: Duration = Duration::from_millis(500);

/// Spawns the refresher. Set `stop` and call [`RevocationChecker::notify`]
/// (or wait ≤ 500 ms), then join.
pub fn spawn_refresher(c: Arc<RevocationChecker>, stop: Arc<AtomicBool>) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new().name("plat-revocation".into()).spawn(move || {
        // Acquire pairs with the caller's Release store of `stop`.
        while !stop.load(Ordering::Acquire) {
            let wait = c.refresh_once(UnixTime::now(), MAX_WAIT);
            if stop.load(Ordering::Acquire) {
                break;
            }
            c.wait(wait);
        }
    })
}
