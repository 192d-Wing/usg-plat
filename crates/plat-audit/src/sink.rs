//! The data plane's handle to the audit pipeline.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crossbeam_channel::{Receiver, Sender, TrySendError};
use crossbeam_utils::CachePadded;

use crate::event::{Event, RemoteLossReason};

/// Counters of one syslog destination (`plat_audit_remote_*`).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-5, AU-9(2), SI-4 - TLS handshake failures toward a
///   collector are visible per destination and per cause.
#[derive(Debug)]
pub struct RemoteStats {
    pub address: SocketAddr,
    /// `udp` | `tcp` | `tls`.
    pub transport: &'static str,
    /// Completed TLS handshakes.
    pub tls_handshakes: AtomicU64,
    /// Failed connections or writes (TCP and TLS) by
    /// [`RemoteLossReason::index`].
    failures: [AtomicU64; 4],
    /// Cause of the most recent undelivered batch (0 = none, else
    /// `index + 1`); taken by the next `audit_remote_loss` record.
    last_reason: AtomicU8,
}

impl RemoteStats {
    pub fn new(address: SocketAddr, transport: &'static str) -> Self {
        Self {
            address,
            transport,
            tls_handshakes: AtomicU64::new(0),
            failures: Default::default(),
            last_reason: AtomicU8::new(0),
        }
    }

    /// Failed connections (or TLS writes) with this cause.
    pub fn failures(&self, r: RemoteLossReason) -> u64 {
        self.failures.get(r.index()).map_or(0, |a| a.load(Ordering::Relaxed))
    }

    pub(crate) fn count_failure(&self, r: RemoteLossReason) {
        if let Some(a) = self.failures.get(r.index()) {
            a.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records the cause of the batch just lost.
    pub(crate) fn note_loss(&self, r: RemoteLossReason) {
        self.last_reason.store(r.index() as u8 + 1, Ordering::Relaxed);
    }

    /// Takes the cause noted since the last call, if any.
    pub(crate) fn take_reason(&self) -> Option<RemoteLossReason> {
        match self.last_reason.swap(0, Ordering::Relaxed) {
            0 => None,
            n => RemoteLossReason::ALL.get(usize::from(n) - 1).copied(),
        }
    }
}

/// Audit pipeline counters and health.
///
/// Fields written by the data plane (`enqueued`, `lost`) and the one it
/// reads per new binding (`degraded`) each sit on their own cache line, so
/// the logger's per-batch updates never invalidate the workers' lines.
#[derive(Debug, Default)]
pub struct AuditStats {
    pub enqueued: CachePadded<AtomicU64>,
    /// Records lost to a full queue (AU-5).
    pub lost: CachePadded<AtomicU64>,
    /// Records durably written to the local file (checkpoint flushed), or,
    /// with no file configured, handed to the syslog senders.
    pub written: CachePadded<AtomicU64>,
    /// Failed write/flush/open/send operations on any destination.
    pub output_errors: AtomicU64,
    /// Records not written to the local file because it failed (AU-5).
    pub file_lost: AtomicU64,
    /// Records not delivered to a syslog collector (AU-5, AU-9(2)).
    pub remote_lost: AtomicU64,
    /// Failed writes of the sequence high-water mark `.<name>.seq`
    /// (SEC-303; each also counts in `output_errors`).
    pub seq_lease_failures: AtomicU64,
    degraded: CachePadded<AtomicBool>,
    /// The local file cannot be written (part of `degraded`).
    file_down: AtomicBool,
    /// The log volume is below `audit.file.min_free_bytes` (part of
    /// `degraded`, AU-5(1)).
    storage_low: AtomicBool,
    /// Per syslog destination, in configuration order; set once by
    /// `Logger::spawn`.
    remotes: OnceLock<Vec<Arc<RemoteStats>>>,
}

impl AuditStats {
    /// True while the authoritative local audit file cannot be written or
    /// its volume is below the free-space threshold.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-5 - audit processing failure is visible to the data
    ///   plane (`has_room`) and to `/healthz`.
    #[inline]
    pub fn degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// Per-destination syslog counters (empty before `Logger::spawn`).
    pub fn remotes(&self) -> &[Arc<RemoteStats>] {
        self.remotes.get().map_or(&[], Vec::as_slice)
    }

    pub(crate) fn set_remotes(&self, r: Vec<Arc<RemoteStats>>) {
        let _ = self.remotes.set(r);
    }

    /// True while the local audit file cannot be written.
    pub fn file_down(&self) -> bool {
        self.file_down.load(Ordering::Relaxed)
    }

    /// True while the log volume is below `audit.file.min_free_bytes`.
    pub fn storage_low(&self) -> bool {
        self.storage_low.load(Ordering::Relaxed)
    }

    /// Publishes the file state; `degraded` is set while either holds.
    pub(crate) fn set_file_state(&self, file_down: bool, storage_low: bool) {
        self.file_down.store(file_down, Ordering::Relaxed);
        self.storage_low.store(storage_low, Ordering::Relaxed);
        self.degraded.store(file_down || storage_low, Ordering::Relaxed);
    }
}

/// Cloneable, non-blocking audit sender.
#[derive(Debug, Clone)]
pub struct AuditSink {
    tx: Sender<Event>,
    stats: Arc<AuditStats>,
}

impl AuditSink {
    /// Creates a bounded queue of `capacity` events.
    pub fn bounded(capacity: usize) -> (Self, Receiver<Event>) {
        let (tx, rx) = crossbeam_channel::bounded(capacity);
        (Self { tx, stats: Arc::new(AuditStats::default()) }, rx)
    }

    /// Queues an event without blocking. Returns `false` (and counts the
    /// loss) when the queue is full or the logger has stopped.
    #[inline]
    pub fn emit(&self, ev: Event) -> bool {
        match self.tx.try_send(ev) {
            Ok(()) => {
                self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.stats.lost.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Queues an event without blocking, for records the caller retries
    /// (a quarantined port-block release). Nothing is counted as lost here:
    /// a full queue is retryable (the record is re-created and queued on a
    /// later attempt), and a disconnected queue (logger stopped) is reported
    /// as [`TryEmit::Disconnected`] so the caller counts the abandoned record
    /// once per retried item via [`AuditSink::count_lost`], not once per
    /// attempt (NIST-401).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-5, SI-4 - `lost` / `audit_queue_overflow` count
    ///   only records that are really abandoned, each exactly once
    ///   (NIST-201 / PERF-203 / SEC-302 / NIST-401)
    #[inline]
    pub fn try_emit(&self, ev: Event) -> TryEmit {
        match self.tx.try_send(ev) {
            Ok(()) => {
                self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
                TryEmit::Queued
            }
            Err(TrySendError::Full(_)) => TryEmit::Full,
            Err(TrySendError::Disconnected(_)) => TryEmit::Disconnected,
        }
    }

    /// Counts one abandoned record (see [`AuditSink::try_emit`]).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-5 - audit processing failure is counted
    #[inline]
    pub fn count_lost(&self) {
        self.stats.lost.fetch_add(1, Ordering::Relaxed);
    }

    /// True when attribution records can be queued **and** the local audit
    /// file is writable; used to refuse new bindings early under
    /// `refuse_new_bindings` (AU-5: fail closed on audit processing failure).
    #[inline]
    pub fn has_room(&self) -> bool {
        !self.stats.degraded() && !self.tx.is_full()
    }

    pub fn queued(&self) -> usize {
        self.tx.len()
    }

    /// Queue capacity (events).
    pub fn capacity(&self) -> usize {
        self.tx.capacity().unwrap_or(usize::MAX)
    }

    pub fn stats(&self) -> &Arc<AuditStats> {
        &self.stats
    }
}

/// Outcome of [`AuditSink::try_emit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryEmit {
    /// The record was queued.
    Queued,
    /// The queue is full; retry later (not a loss).
    Full,
    /// The logger has stopped; no retry can succeed. The caller counts the
    /// abandoned record once with [`AuditSink::count_lost`].
    Disconnected,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LifecycleKind;

    fn ev() -> Event {
        Event::Lifecycle { ts_us: 0, kind: LifecycleKind::Start, fips: None, cluster: None }
    }

    /// SEC-302 / NIST-401: `try_emit` never counts; a full queue is
    /// retryable and a disconnect is reported for the caller to count once.
    #[test]
    fn try_emit_reports_full_and_disconnect_without_counting() {
        let (sink, rx) = AuditSink::bounded(1);
        assert_eq!(sink.try_emit(ev()), TryEmit::Queued);
        assert_eq!(sink.try_emit(ev()), TryEmit::Full);
        drop(rx);
        assert_eq!(sink.try_emit(ev()), TryEmit::Disconnected);
        assert_eq!(sink.try_emit(ev()), TryEmit::Disconnected);
        assert_eq!(sink.stats().lost.load(Ordering::Relaxed), 0);
        sink.count_lost();
        assert_eq!(sink.stats().lost.load(Ordering::Relaxed), 1);
        assert_eq!(sink.stats().enqueued.load(Ordering::Relaxed), 1);
    }
}
