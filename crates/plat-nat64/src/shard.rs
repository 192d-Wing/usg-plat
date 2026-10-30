//! Lock-sharded hash map.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};

use ahash::RandomState;
use crossbeam_utils::CachePadded;
use parking_lot::{Mutex, MutexGuard};

pub type Map<K, V> = HashMap<K, V, RandomState>;

/// One shard: the map and its earliest-due hint (POAM-012). The hint
/// shares the padded line with the mutex that every user writes anyway,
/// so maintaining it costs no extra cache line.
#[derive(Debug)]
struct Shard<K, V> {
    map: Mutex<Map<K, V>>,
    due: AtomicU64,
}

/// A hash map split into `2^n` independently locked shards.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - `ahash::RandomState` keys are random per process,
///   so an attacker cannot pre-compute colliding flows (hash flooding).
#[derive(Debug)]
pub struct Sharded<K, V> {
    shards: Box<[CachePadded<Shard<K, V>>]>,
    mask: usize,
    hasher: RandomState,
}

impl<K: Hash + Eq, V> Sharded<K, V> {
    pub fn new(shards: u32) -> Self {
        let n = (shards.max(1) as usize).next_power_of_two();
        Self {
            shards: (0..n)
                .map(|_| {
                    CachePadded::new(Shard {
                        map: Mutex::new(Map::with_hasher(RandomState::new())),
                        due: AtomicU64::new(u64::MAX),
                    })
                })
                .collect(),
            mask: n - 1,
            hasher: RandomState::new(),
        }
    }

    #[inline]
    pub fn index_of(&self, k: &K) -> usize {
        (self.hasher.hash_one(k) as usize) & self.mask
    }

    #[inline]
    pub fn lock(&self, k: &K) -> MutexGuard<'_, Map<K, V>> {
        self.shards[self.index_of(k)].map.lock()
    }

    /// [`Sharded::lock`] that also returns the shard's due hint.
    #[inline]
    pub fn lock_due(&self, k: &K) -> (MutexGuard<'_, Map<K, V>>, &AtomicU64) {
        let s = &self.shards[self.index_of(k)];
        (s.map.lock(), &s.due)
    }

    #[inline]
    pub fn lock_index(&self, i: usize) -> MutexGuard<'_, Map<K, V>> {
        self.shards[i].map.lock()
    }

    /// Due hint of shard `i` (see [`lower_due`]); `None` out of range.
    #[inline]
    pub fn due_index(&self, i: usize) -> Option<&AtomicU64> {
        self.shards.get(i).map(|s| &s.due)
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Sum of entries (takes every lock in turn; for metrics, not hot path).
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.map.lock().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Lowers a shard due hint to `t` (monotonic ms). The hint is a lower
/// bound of the earliest time anything in the shard needs the sweeper; the
/// sweeper skips a shard whose hint is in the future without locking it
/// (POAM-012). Only a store that lowers the hint writes: the load is on the
/// line the caller's shard lock already owns.
///
/// Relaxed is enough: every lowering is to a time at or after the caller's
/// `now`, the hint is advisory for timing only (a missed lowering is seen on
/// the next pass at the latest), and `fetch_min` never loses a concurrent
/// lowering.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5, SC-10 - sweeper cost proportional to due work
#[inline]
pub fn lower_due(due: &AtomicU64, t: u64) {
    if t < due.load(Ordering::Relaxed) {
        due.fetch_min(t, Ordering::Relaxed);
    }
}
