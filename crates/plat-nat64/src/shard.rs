//! Lock-sharded hash map.

use std::collections::HashMap;
use std::hash::Hash;

use ahash::RandomState;
use crossbeam_utils::CachePadded;
use parking_lot::{Mutex, MutexGuard};

pub type Map<K, V> = HashMap<K, V, RandomState>;
type Shard<K, V> = CachePadded<Mutex<Map<K, V>>>;

/// A hash map split into `2^n` independently locked shards.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - `ahash::RandomState` keys are random per process,
///   so an attacker cannot pre-compute colliding flows (hash flooding).
#[derive(Debug)]
pub struct Sharded<K, V> {
    shards: Box<[Shard<K, V>]>,
    mask: usize,
    hasher: RandomState,
}

impl<K: Hash + Eq, V> Sharded<K, V> {
    pub fn new(shards: u32) -> Self {
        let n = (shards.max(1) as usize).next_power_of_two();
        Self {
            shards: (0..n).map(|_| CachePadded::new(Mutex::new(Map::with_hasher(RandomState::new())))).collect(),
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
        self.shards[self.index_of(k)].lock()
    }

    #[inline]
    pub fn lock_index(&self, i: usize) -> MutexGuard<'_, Map<K, V>> {
        self.shards[i].lock()
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Sum of entries (takes every lock in turn; for metrics, not hot path).
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
