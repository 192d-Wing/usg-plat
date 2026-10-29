//! Single-flight markers shared by handshake threads and the refresher:
//! at most one fetch per key at a time; others wait on a `Condvar` until
//! the leader finishes or their deadline passes, then re-read the cache.
//!
//! The mutex is a leaf lock held only to insert/remove/test a key, never
//! across the fetch itself.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 - N concurrent handshakes for one certificate cause
//!   one responder/CDP request, not N

use std::collections::HashSet;
use std::hash::Hash;
use std::time::Instant;

use parking_lot::{Condvar, Mutex};

#[derive(Debug)]
pub(crate) struct SingleFlight<K: Hash + Eq> {
    busy: Mutex<HashSet<K>>,
    cv: Condvar,
}

/// Result of [`SingleFlight::begin`].
pub(crate) enum Flight<'a, K: Hash + Eq + Clone> {
    /// This caller fetches; the marker is released when the guard drops.
    Leader(Leader<'a, K>),
    /// Another caller finished; re-read the cache.
    Waited,
    /// The deadline passed while another caller was still fetching.
    TimedOut,
}

pub(crate) struct Leader<'a, K: Hash + Eq + Clone> {
    sf: &'a SingleFlight<K>,
    key: K,
}

impl<K: Hash + Eq + Clone> Drop for Leader<'_, K> {
    fn drop(&mut self) {
        self.sf.busy.lock().remove(&self.key);
        self.sf.cv.notify_all();
    }
}

impl<K: Hash + Eq + Clone> SingleFlight<K> {
    pub(crate) fn new() -> Self {
        // std `RandomState`: randomly keyed per process.
        Self { busy: Mutex::new(HashSet::new()), cv: Condvar::new() }
    }

    pub(crate) fn begin(&self, key: &K, deadline: Instant) -> Flight<'_, K> {
        let mut g = self.busy.lock();
        if g.insert(key.clone()) {
            return Flight::Leader(Leader { sf: self, key: key.clone() });
        }
        while g.contains(key) {
            if self.cv.wait_until(&mut g, deadline).timed_out() {
                return if g.contains(key) { Flight::TimedOut } else { Flight::Waited };
            }
        }
        Flight::Waited
    }
}
