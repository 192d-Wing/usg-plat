//! The data plane's handle to the audit pipeline.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crossbeam_channel::{Receiver, Sender, TrySendError};
use crossbeam_utils::CachePadded;

use crate::event::Event;

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
    degraded: CachePadded<AtomicBool>,
    /// The local file cannot be written (part of `degraded`).
    file_down: AtomicBool,
    /// The log volume is below `audit.file.min_free_bytes` (part of
    /// `degraded`, AU-5(1)).
    storage_low: AtomicBool,
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
    /// (a quarantined port-block release): a full queue is **not** counted
    /// as lost, because the record is re-created and queued on a later
    /// attempt. Returns `false` when the event was not queued.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-5, SI-4 - `lost` / `audit_queue_overflow` count
    ///   only records that are really abandoned (NIST-201 / PERF-203)
    #[inline]
    pub fn try_emit(&self, ev: Event) -> bool {
        let ok = self.tx.try_send(ev).is_ok();
        if ok {
            self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
        }
        ok
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
