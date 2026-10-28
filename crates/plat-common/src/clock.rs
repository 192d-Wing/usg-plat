//! Coarse monotonic clock for the data plane.
//!
//! Workers read a single relaxed atomic instead of calling into the OS per
//! packet; a ticker thread advances it. Session timers only need
//! millisecond-scale accuracy (RFC 6146 timers are minutes).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct Inner {
    origin: Instant,
    now_ms: AtomicU64,
}

/// Shared coarse clock. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Clock {
    inner: Arc<Inner>,
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    pub fn new() -> Self {
        Self { inner: Arc::new(Inner { origin: Instant::now(), now_ms: AtomicU64::new(0) }) }
    }

    /// Milliseconds since process start, as of the last tick.
    #[inline]
    pub fn now_ms(&self) -> u64 {
        self.inner.now_ms.load(Ordering::Relaxed)
    }

    /// Refreshes the cached time. Called by the ticker thread.
    pub fn tick(&self) {
        let ms = self.inner.origin.elapsed().as_millis() as u64;
        self.inner.now_ms.store(ms, Ordering::Relaxed);
    }

    /// Advances the clock manually (tests and simulation only).
    pub fn advance(&self, d: Duration) {
        self.inner.now_ms.fetch_add(d.as_millis() as u64, Ordering::Relaxed);
    }

    /// Wall-clock UTC microseconds since the Unix epoch, for audit records.
    ///
    /// NIST 800-53: AU-8 - time stamps come from the system clock, which must
    /// be synchronised to an authoritative source (NTP/PTP) by the platform.
    #[inline]
    pub fn wall_us() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
    }
}
