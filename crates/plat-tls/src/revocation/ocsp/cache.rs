//! Bounded OCSP response cache keyed by `(issuer_key_hash, serial)`.
//!
//! Positive entries (validated `good` / `revoked`) live until
//! `min(nextUpdate, thisUpdate + max_age)`; failures (transport errors,
//! `unknown`, stale) are negatively cached for [`NEGATIVE_TTL`] so a dead
//! responder is not hammered. When full, the earliest-expiring entry is
//! evicted. The owner wraps this in a leaf mutex never held across I/O.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5(2)(b)(2) - local cache of revocation data
//! - NIST 800-53: SC-5 - `ocsp.cache_entries` bound, negative caching;
//!   std `RandomState` (randomly keyed hasher)

use std::collections::HashMap;

use super::response::Status;
use crate::revocation::OcspReason;

/// Lifetime of a negative entry, seconds.
pub const NEGATIVE_TTL: u64 = 10;

pub type Key = ([u8; 32], Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    Status { status: Status, this_update: u64, expires: u64 },
    Negative { reason: OcspReason, until: u64 },
}

impl Entry {
    fn end(&self) -> u64 {
        match *self {
            Entry::Status { expires, .. } => expires,
            Entry::Negative { until, .. } => until,
        }
    }
}

#[derive(Debug)]
pub struct OcspCache {
    map: HashMap<Key, Entry>,
    cap: usize,
}

impl OcspCache {
    pub fn new(cap: usize) -> Self {
        Self { map: HashMap::new(), cap: cap.max(1) }
    }

    /// The live entry for `k` (expired entries are removed).
    pub fn get(&mut self, k: &Key, now: u64) -> Option<Entry> {
        match self.map.get(k) {
            Some(e) if e.end() > now => Some(*e),
            Some(_) => {
                self.map.remove(k);
                None
            }
            None => None,
        }
    }

    /// Inserts or replaces; evicts the earliest-expiring entry when full.
    /// A negative entry never replaces a live positive one.
    pub fn put(&mut self, k: Key, e: Entry, now: u64) {
        if e.end() <= now {
            return;
        }
        if matches!(e, Entry::Negative { .. })
            && self.map.get(&k).is_some_and(|old| matches!(old, Entry::Status { .. }) && old.end() > now)
        {
            return;
        }
        if !self.map.contains_key(&k) && self.map.len() >= self.cap {
            self.map.retain(|_, v| v.end() > now);
            if self.map.len() >= self.cap
                && let Some(victim) = self.map.iter().min_by_key(|(_, v)| v.end()).map(|(k, _)| k.clone())
            {
                self.map.remove(&victim);
            }
        }
        self.map.insert(k, e);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u8) -> Key {
        ([n; 32], vec![n])
    }

    #[test]
    fn bound_expiry_and_negative() {
        let mut c = OcspCache::new(2);
        c.put(k(1), Entry::Status { status: Status::Good, this_update: 0, expires: 100 }, 10);
        c.put(k(2), Entry::Status { status: Status::Good, this_update: 0, expires: 50 }, 10);
        c.put(k(3), Entry::Status { status: Status::Good, this_update: 0, expires: 200 }, 10);
        assert_eq!(c.len(), 2);
        assert!(c.get(&k(2), 10).is_none(), "earliest-expiring evicted");
        assert!(c.get(&k(1), 100).is_none(), "expired at nextUpdate");
        c.put(k(3), Entry::Negative { reason: OcspReason::Timeout, until: 20 }, 10);
        assert!(matches!(c.get(&k(3), 10), Some(Entry::Status { .. })), "negative never hides positive");
        c.put(k(4), Entry::Negative { reason: OcspReason::Timeout, until: 20 }, 10);
        assert!(matches!(c.get(&k(4), 19), Some(Entry::Negative { .. })));
        assert!(c.get(&k(4), 20).is_none());
    }
}
