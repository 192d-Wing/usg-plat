//! Bounded in-memory CRL store, keyed by `sha256(source)`.
//!
//! - `verified`: parsed, signature-checked [`CrlEntry`]s behind `Arc` (a
//!   lookup clones the `Arc` and releases the lock before searching).
//! - `pending`: raw DER not yet verified because the issuer certificate
//!   was not known when it was obtained (on-disk cache at start,
//!   configured files, pre-fetched `crl.urls`). It is verified against the
//!   real issuer on first use and never decides before that.
//!
//! Bounds: `crl.max_crls` entries and `crl.cache_bytes` estimated bytes,
//! each counted over both maps. Over a bound, the verified CRL not used in
//! the last minute with the earliest `nextUpdate` is evicted (then the
//! oldest pending item, then any verified CRL). A CRL with a lower
//! `cRLNumber` than the highest seen for the same issuer key and IDP scope
//! (from any source), or without a `cRLNumber` once a numbered one was
//! seen, is refused (rollback, SEC-005). The high-water marks are bounded
//! (`HWM_FACTOR * max_crls`) and persisted by the caller to `cache_dir`
//! when configured.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5(2)(b)(2) - local cache of revocation data
//! - NIST 800-53: SC-5 - `max_crls` / `cache_bytes` bounds; std
//!   `RandomState` hashers
//! - RFC 5280 §5.2.3 - cRLNumber monotonic per scope (rollback protection)

use std::collections::HashMap;
use std::sync::Arc;

use super::parse::{CrlEntry, number_lt};
use crate::revocation::CrlReason;

/// Source key: SHA-256 of the source URL text or file path.
pub type SrcKey = [u8; 32];

/// "Recently used" window for eviction, seconds.
const RECENT: u64 = 60;
/// High-water marks kept per configured CRL slot.
const HWM_FACTOR: usize = 4;
/// Longest cRLNumber kept (RFC 5280 §5.2.3: at most 20 octets).
pub const MAX_CRL_NUMBER: usize = 20;

/// (issuer key hash, scope key).
pub type HwmKey = ([u8; 32], [u8; 32]);

/// Where unverified bytes came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    /// `cache_dir`: tampering may only delete data (never fatal).
    Disk,
    /// A configured `crl.files` entry.
    File,
    /// A configured `crl.urls` entry fetched before any handshake.
    Prefetch,
}

#[derive(Debug, Clone)]
pub struct Pending {
    pub der: Arc<Vec<u8>>,
    pub kind: PendingKind,
    pub at: u64,
}

#[derive(Debug)]
struct Slot {
    entry: Arc<CrlEntry>,
    last_used: u64,
}

#[derive(Debug)]
pub struct CrlCache {
    verified: HashMap<SrcKey, Slot>,
    pending: HashMap<SrcKey, Pending>,
    bytes: usize,
    max_crls: usize,
    max_bytes: usize,
    /// Highest cRLNumber seen per issuer + scope (content octets).
    hwm: HashMap<HwmKey, Vec<u8>>,
    /// `hwm` changed since the last [`CrlCache::take_hwm_if_dirty`].
    hwm_dirty: bool,
}

impl CrlCache {
    pub fn new(max_crls: usize, max_bytes: usize) -> Self {
        Self {
            verified: HashMap::new(),
            pending: HashMap::new(),
            bytes: 0,
            max_crls: max_crls.max(1),
            max_bytes,
            hwm: HashMap::new(),
            hwm_dirty: false,
        }
    }

    /// Seeds a high-water mark (from `cache_dir` at start); keeps the
    /// higher of the two. Bounded like the rest of the map.
    pub fn seed_hwm(&mut self, k: HwmKey, n: Vec<u8>) {
        if n.len() > MAX_CRL_NUMBER {
            return;
        }
        match self.hwm.get(&k) {
            Some(cur) if !number_lt(cur, &n) => {}
            Some(_) => {
                self.hwm.insert(k, n);
            }
            None if self.hwm.len() < self.max_crls * HWM_FACTOR => {
                self.hwm.insert(k, n);
            }
            None => {}
        }
    }

    /// A snapshot of the high-water marks if they changed (for
    /// persisting outside the lock).
    pub fn take_hwm_if_dirty(&mut self) -> Option<Vec<(HwmKey, Vec<u8>)>> {
        if !std::mem::take(&mut self.hwm_dirty) {
            return None;
        }
        Some(self.hwm.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    /// Marks the high-water marks as not persisted (a write failed), so
    /// the next [`CrlCache::take_hwm_if_dirty`] retries (SEC-102).
    pub fn mark_hwm_dirty(&mut self) {
        self.hwm_dirty = true;
    }

    /// Rollback check against the high-water mark (SEC-005), then records
    /// a new high.
    fn check_hwm(&mut self, e: &CrlEntry) -> Result<(), CrlReason> {
        let k = (e.issuer_key_hash, e.scope.key());
        match (&e.crl_number, self.hwm.get(&k)) {
            (None, Some(_)) => Err(CrlReason::Rollback),
            (Some(n), Some(h)) if number_lt(n, h) => Err(CrlReason::Rollback),
            (Some(n), Some(h)) if !number_lt(h, n) => Ok(()),
            (Some(n), _) if n.len() <= MAX_CRL_NUMBER => {
                if !self.hwm.contains_key(&k) && self.hwm.len() >= self.max_crls * HWM_FACTOR {
                    // Bounded: forget an arbitrary other mark.
                    if let Some(v) = self.hwm.keys().find(|x| **x != k).copied() {
                        self.hwm.remove(&v);
                    }
                }
                self.hwm.insert(k, n.clone());
                self.hwm_dirty = true;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// The verified CRL for `k`, marking it used.
    pub fn get(&mut self, k: &SrcKey, now: u64) -> Option<Arc<CrlEntry>> {
        let s = self.verified.get_mut(k)?;
        s.last_used = now;
        Some(s.entry.clone())
    }

    pub fn pending(&self, k: &SrcKey) -> Option<Pending> {
        self.pending.get(k).cloned()
    }

    pub fn remove(&mut self, k: &SrcKey) -> Option<Arc<CrlEntry>> {
        let s = self.verified.remove(k)?;
        self.bytes = self.bytes.saturating_sub(s.entry.size);
        Some(s.entry)
    }

    pub fn remove_pending(&mut self, k: &SrcKey) {
        if let Some(p) = self.pending.remove(k) {
            self.bytes = self.bytes.saturating_sub(p.der.len());
        }
    }

    fn count(&self) -> usize {
        self.verified.len() + self.pending.len()
    }

    /// Frees room for `need` bytes and one more item. False if impossible.
    fn make_room(&mut self, need: usize, keep: &SrcKey, now: u64) -> bool {
        if need > self.max_bytes {
            return false;
        }
        while self.count() >= self.max_crls || self.bytes.saturating_add(need) > self.max_bytes {
            let stale_unused = self
                .verified
                .iter()
                .filter(|(k, s)| *k != keep && s.last_used.saturating_add(RECENT) <= now)
                .min_by_key(|(_, s)| s.entry.next_update)
                .map(|(k, _)| *k);
            let victim_pending =
                || self.pending.iter().filter(|(k, _)| *k != keep).min_by_key(|(_, p)| p.at).map(|(k, _)| *k);
            if let Some(k) = stale_unused {
                self.remove(&k);
            } else if let Some(k) = victim_pending() {
                self.remove_pending(&k);
            } else if let Some(k) = self
                .verified
                .iter()
                .filter(|(k, _)| *k != keep)
                .min_by_key(|(_, s)| s.entry.next_update)
                .map(|(k, _)| *k)
            {
                self.remove(&k);
            } else {
                return false;
            }
        }
        true
    }

    /// Stores a verified CRL for `k`, replacing pending bytes. Refuses a
    /// lower cRLNumber than the cached one or the high-water mark for its
    /// issuer + scope, or a missing one after a numbered CRL (`Rollback`),
    /// and a CRL larger than the whole budget (`TooLarge`).
    pub fn put(&mut self, k: SrcKey, e: CrlEntry, now: u64) -> Result<Arc<CrlEntry>, CrlReason> {
        if let Some(old) = self.verified.get(&k)
            && old.entry.issuer_key_hash == e.issuer_key_hash
            && let (Some(a), Some(b)) = (&e.crl_number, &old.entry.crl_number)
            && number_lt(a, b)
        {
            return Err(CrlReason::Rollback);
        }
        if e.size > self.max_bytes {
            return Err(CrlReason::TooLarge);
        }
        self.check_hwm(&e)?;
        self.remove(&k);
        self.remove_pending(&k);
        if !self.make_room(e.size, &k, now) {
            return Err(CrlReason::TooLarge);
        }
        self.bytes += e.size;
        let entry = Arc::new(e);
        self.verified.insert(k, Slot { entry: entry.clone(), last_used: now });
        Ok(entry)
    }

    /// Stores unverified bytes (only if no verified entry exists for `k`).
    pub fn put_pending(&mut self, k: SrcKey, p: Pending, now: u64) -> bool {
        if self.verified.contains_key(&k) {
            return false;
        }
        self.remove_pending(&k);
        if !self.make_room(p.der.len(), &k, now) {
            return false;
        }
        self.bytes += p.der.len();
        self.pending.insert(k, p);
        true
    }

    /// Earliest `nextUpdate` per issuer key hash over the verified CRLs
    /// (at most `max_crls` items).
    pub fn next_updates(&self) -> Vec<([u8; 32], u64)> {
        let mut out: Vec<([u8; 32], u64)> = Vec::with_capacity(self.verified.len());
        for s in self.verified.values() {
            let e = &s.entry;
            match out.iter_mut().find(|(k, _)| *k == e.issuer_key_hash) {
                Some((_, n)) => *n = (*n).min(e.next_update),
                None => out.push((e.issuer_key_hash, e.next_update)),
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.verified.len()
    }

    pub fn is_empty(&self) -> bool {
        self.verified.is_empty()
    }

    /// Estimated bytes of verified + pending data (`plat_crl_cache_bytes`).
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::crl::parse::Scope;

    fn e(n: u8, next: u64, size: usize) -> CrlEntry {
        CrlEntry {
            issuer_key_hash: [1; 32],
            scope: Scope::default(),
            this_update: 0,
            next_update: next,
            crl_number: Some(vec![n]),
            revoked: HashMap::new(),
            size,
        }
    }

    /// `e` from issuer `i` (independent high-water marks).
    fn ei(i: u8, n: u8, next: u64, size: usize) -> CrlEntry {
        CrlEntry { issuer_key_hash: [i; 32], ..e(n, next, size) }
    }

    #[test]
    fn bounds_and_rollback() {
        let mut c = CrlCache::new(2, 1000);
        c.put([1; 32], e(5, 100, 400), 0).unwrap();
        assert_eq!(c.put([1; 32], e(4, 100, 400), 0).unwrap_err(), CrlReason::Rollback);
        c.put([2; 32], ei(2, 1, 50, 400), 0).unwrap();
        // Count bound: the earliest nextUpdate goes (both unused for 60 s).
        c.put([3; 32], ei(3, 1, 200, 100), 100).unwrap();
        assert!(c.get(&[2; 32], 100).is_none() && c.get(&[1; 32], 100).is_some());
        // Byte bound.
        assert_eq!(c.put([4; 32], ei(4, 1, 200, 1001), 100).unwrap_err(), CrlReason::TooLarge);
        c.put([4; 32], ei(4, 1, 300, 700), 100).unwrap();
        assert!(c.bytes() <= 1000, "{}", c.bytes());
    }

    #[test]
    fn high_water_mark_across_sources() {
        let mut c = CrlCache::new(4, 10_000);
        c.put([1; 32], e(5, 100, 10), 0).unwrap();
        assert!(c.take_hwm_if_dirty().is_some());
        assert!(c.take_hwm_if_dirty().is_none());
        // A failed write re-arms the flag (SEC-102).
        c.mark_hwm_dirty();
        assert!(c.take_hwm_if_dirty().is_some());
        // Another source, same issuer and scope: lower number refused.
        assert_eq!(c.put([2; 32], e(4, 100, 10), 0).unwrap_err(), CrlReason::Rollback);
        // Unnumbered after a numbered one: refused.
        let mut un = e(0, 100, 10);
        un.crl_number = None;
        assert_eq!(c.put([2; 32], un.clone(), 0).unwrap_err(), CrlReason::Rollback);
        // Equal is fine, not dirty.
        c.put([2; 32], e(5, 100, 10), 0).unwrap();
        assert!(c.take_hwm_if_dirty().is_none());
        // A different scope has its own mark.
        let mut other = un;
        other.scope.only_user = true;
        c.put([3; 32], other, 0).unwrap();
        // Seeded (persisted) mark applies at once.
        let mut d = CrlCache::new(4, 10_000);
        d.seed_hwm(([1; 32], Scope::default().key()), vec![9]);
        assert_eq!(d.put([1; 32], e(8, 100, 10), 0).unwrap_err(), CrlReason::Rollback);
        d.put([1; 32], e(10, 100, 10), 0).unwrap();
    }

    #[test]
    fn next_updates_earliest_per_issuer() {
        let mut c = CrlCache::new(4, 10_000);
        c.put([1; 32], e(1, 500, 10), 0).unwrap();
        let mut other = e(1, 300, 10);
        other.scope.only_user = true;
        c.put([2; 32], other, 0).unwrap();
        c.put([3; 32], ei(7, 1, 900, 10), 0).unwrap();
        let mut n = c.next_updates();
        n.sort();
        assert_eq!(n, vec![([1; 32], 300), ([7; 32], 900)]);
    }
}
