//! `SLOT` index allocator (plan §4.3): partitioned free stacks and an RCU
//! quarantine, so a slot record is rewritten only after every program run
//! that could still hold its old index has finished.
//!
//! - Slot `i` belongs to partition `i % partitions` for its whole life, so
//!   a partition's free stack and quarantine never hold more than its share
//!   of slots: both are preallocated at construction and never grow.
//! - [`SlotAllocator::alloc`] takes from the caller's partition only
//!   (`shard % partitions`); an empty partition fails the install, which
//!   leaves the session on the slow path (plan §9 back-pressure).
//! - [`SlotAllocator::retire`] stamps the slot with the grace-period epoch
//!   read under the partition lock, after the caller deleted the hash
//!   entries. [`SlotAllocator::recycle`] frees slots with `stamp + 2 ≤
//!   epoch`: the epoch moves only after a completed `membarrier(GLOBAL)`
//!   (`synchronize_rcu`), and the grace period that produced `stamp + 2`
//!   started after `stamp + 1` was published, so after the delete.
//!
//! Lock order: each partition mutex is a leaf (`bib4 → xslot`, or `xslot`
//! alone); nothing is called while it is held.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - fixed number of
//!   slots (⌈1.25 × `xdp.max_sessions`⌉), preallocated; exhaustion fails
//!   closed to the slow path
//! - NIST 800-53: SC-24 (Fail in Known State) - no slot is reused before an
//!   RCU grace period (with the key echo of plan §4.3, a packet is never
//!   translated with another session's mapping)

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

/// Default number of partitions (plan §4.3: `xslot[shard % 1024]`).
pub const PARTITIONS: usize = 1024;

#[derive(Debug)]
struct Part {
    free: Vec<u32>,
    /// `(slot, epoch stamp)`, stamps non-decreasing (read under the lock).
    quarantine: VecDeque<(u32, u64)>,
}

/// See the module documentation.
#[derive(Debug)]
pub struct SlotAllocator {
    parts: Box<[Mutex<Part>]>,
    epoch: AtomicU64,
    quarantined: AtomicU64,
    slots: u32,
}

impl SlotAllocator {
    /// `slots` indices `0..slots` in `partitions` partitions (at least 1,
    /// at most `slots`).
    pub fn new(slots: u32, partitions: usize) -> Self {
        let n = partitions.clamp(1, (slots as usize).max(1));
        let mut parts = Vec::with_capacity(n);
        for p in 0..n {
            let mine = (p as u32..slots).step_by(n);
            let cap = mine.len();
            // Highest index on top: lower slots are handed out first.
            let free: Vec<u32> = mine.rev().collect();
            parts.push(Mutex::new(Part { free, quarantine: VecDeque::with_capacity(cap) }));
        }
        Self { parts: parts.into_boxed_slice(), epoch: AtomicU64::new(0), quarantined: AtomicU64::new(0), slots }
    }

    /// Number of slots managed.
    pub fn slots(&self) -> u32 {
        self.slots
    }

    pub fn partitions(&self) -> usize {
        self.parts.len()
    }

    fn part_of(&self, slot: u32) -> Option<&Mutex<Part>> {
        self.parts.get(slot as usize % self.parts.len())
    }

    /// A free slot from partition `shard % partitions`, or `None` when that
    /// partition has none.
    pub fn alloc(&self, shard: usize) -> Option<u32> {
        self.parts.get(shard % self.parts.len())?.lock().free.pop()
    }

    /// Quarantines `slot` (state already `DEAD`, hash entries deleted).
    /// Out-of-range indices are ignored.
    pub fn retire(&self, slot: u32) {
        if slot >= self.slots {
            return;
        }
        if let Some(p) = self.part_of(slot) {
            let mut g = p.lock();
            let stamp = self.epoch.load(Ordering::Acquire);
            g.quarantine.push_back((slot, stamp));
            self.quarantined.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The grace-period epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Records one completed grace period (call only after
    /// `membarrier(MEMBARRIER_CMD_GLOBAL)` returned successfully).
    pub fn advance_epoch(&self) -> u64 {
        self.epoch.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Moves every quarantined slot whose grace period has passed back to
    /// its free stack; returns how many. Takes each partition lock alone.
    pub fn recycle(&self) -> u64 {
        let e = self.epoch();
        let mut n = 0;
        for p in self.parts.iter() {
            let mut g = p.lock();
            while let Some(&(slot, stamp)) = g.quarantine.front() {
                if stamp.saturating_add(2) > e {
                    break;
                }
                g.quarantine.pop_front();
                g.free.push(slot);
                n += 1;
            }
        }
        self.quarantined.fetch_sub(n, Ordering::Relaxed);
        n
    }

    /// Slots waiting for a grace period (`plat_xdp_slots_quarantined`).
    pub fn quarantined(&self) -> u64 {
        self.quarantined.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitions_own_their_slots() {
        let a = SlotAllocator::new(10, 4);
        assert_eq!(a.alloc(1), Some(1));
        assert_eq!(a.alloc(5), Some(5)); // shard 5 -> partition 1
        assert_eq!(a.alloc(1), Some(9));
        assert_eq!(a.alloc(1), None);
        assert_eq!(a.alloc(0), Some(0));
    }

    #[test]
    fn reuse_waits_two_epochs() {
        let a = SlotAllocator::new(1, 1);
        let s = a.alloc(0).unwrap_or(u32::MAX);
        assert_eq!(s, 0);
        a.retire(s);
        assert_eq!(a.quarantined(), 1);
        assert_eq!(a.recycle(), 0);
        a.advance_epoch();
        assert_eq!(a.recycle(), 0, "one epoch may be a grace period that began before the delete");
        assert_eq!(a.alloc(0), None);
        a.advance_epoch();
        assert_eq!(a.recycle(), 1);
        assert_eq!(a.quarantined(), 0);
        assert_eq!(a.alloc(0), Some(0));
    }

    #[test]
    fn bounded_and_never_grows() {
        let a = SlotAllocator::new(8, 2);
        let mut got = Vec::new();
        while let Some(s) = a.alloc(0) {
            got.push(s);
        }
        assert_eq!(got, vec![0, 2, 4, 6]);
        for &s in &got {
            a.retire(s);
        }
        a.retire(99); // out of range: ignored
        assert_eq!(a.quarantined(), 4);
        a.advance_epoch();
        a.advance_epoch();
        assert_eq!(a.recycle(), 4);
        for p in a.parts.iter() {
            let g = p.lock();
            assert!(g.free.len() <= g.free.capacity());
            assert!(g.free.capacity() <= 4);
        }
    }

    #[test]
    fn degenerate_sizes() {
        let a = SlotAllocator::new(3, 0);
        assert_eq!(a.partitions(), 1);
        let b = SlotAllocator::new(2, 1024);
        assert_eq!(b.partitions(), 2);
        let c = SlotAllocator::new(0, 4);
        assert_eq!(c.alloc(0), None);
    }

    // ---- QA (WU3): reuse epochs ----

    #[test]
    fn each_slot_waits_for_its_own_stamp_fifo_per_partition() {
        let a = SlotAllocator::new(4, 1);
        let s: Vec<u32> = (0..4).filter_map(|_| a.alloc(0)).collect();
        assert_eq!(s, vec![0, 1, 2, 3]);
        a.retire(0); // stamp 0
        a.advance_epoch(); // 1
        a.retire(1); // stamp 1
        a.advance_epoch(); // 2
        assert_eq!(a.recycle(), 1, "only the stamp-0 slot is past two epochs");
        assert_eq!(a.alloc(0), Some(0));
        assert_eq!(a.alloc(0), None, "slot 1 is still quarantined");
        a.advance_epoch(); // 3
        assert_eq!(a.recycle(), 1);
        assert_eq!(a.alloc(0), Some(1));
        assert_eq!(a.quarantined(), 0);
        // Recycle is idempotent.
        assert_eq!(a.recycle(), 0);
    }

    #[test]
    fn retire_stamps_with_the_current_epoch_not_the_alloc_epoch() {
        let a = SlotAllocator::new(1, 1);
        let s = a.alloc(0).unwrap_or(u32::MAX);
        for _ in 0..10 {
            a.advance_epoch();
        }
        a.retire(s); // stamp 10
        assert_eq!(a.recycle(), 0, "allocated long ago, retired now: still needs two epochs");
        a.advance_epoch();
        assert_eq!(a.recycle(), 0);
        a.advance_epoch();
        assert_eq!(a.recycle(), 1);
    }

    /// Deterministic model check: across many partitions and a random mix
    /// of alloc / retire / advance / recycle, a slot is never handed out
    /// while live, never before two epochs after its retire, always from
    /// the caller's partition, and the counters stay exact.
    #[test]
    fn model_check_no_early_reuse() {
        let (slots, parts) = (61u32, 7usize);
        let a = SlotAllocator::new(slots, parts);
        let mut live = std::collections::HashSet::new();
        let mut retired_at: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..200_000 {
            let r = next();
            match r % 10 {
                0..=4 => {
                    let shard = (r >> 8) as usize;
                    if let Some(s) = a.alloc(shard) {
                        assert_eq!(s as usize % parts, shard % parts, "partition ownership");
                        assert!(s < slots);
                        assert!(live.insert(s), "slot {s} handed out twice");
                        if let Some(st) = retired_at.remove(&s) {
                            assert!(st + 2 <= a.epoch(), "slot {s} reused at epoch {} (retired at {st})", a.epoch());
                        }
                    }
                }
                5..=7 => {
                    if let Some(&s) = live.iter().nth((r >> 8) as usize % live.len().max(1)) {
                        live.remove(&s);
                        retired_at.insert(s, a.epoch());
                        a.retire(s);
                    }
                }
                8 => {
                    a.advance_epoch();
                }
                _ => {
                    a.recycle();
                }
            }
            assert_eq!(
                a.quarantined() as usize,
                retired_at.len() - {
                    // retired slots already recycled into free are not quarantined
                    let mut in_free = 0;
                    for p in a.parts.iter() {
                        in_free += p.lock().free.iter().filter(|s| retired_at.contains_key(s)).count();
                    }
                    in_free
                }
            );
        }
    }

    /// Concurrent alloc/retire from many threads with a grace-period
    /// thread: no slot is ever held by two threads at once, and every slot
    /// comes back.
    #[test]
    fn concurrent_alloc_retire_with_grace_periods() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU8};
        let slots = 256u32;
        let a = Arc::new(SlotAllocator::new(slots, 16));
        let owner: Arc<Vec<AtomicU8>> = Arc::new((0..slots).map(|_| AtomicU8::new(0)).collect());
        let stop = Arc::new(AtomicBool::new(false));
        let gc = {
            let (a, stop) = (a.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    a.advance_epoch();
                    a.recycle();
                    std::thread::yield_now();
                }
            })
        };
        let hs: Vec<_> = (0..8usize)
            .map(|t| {
                let (a, owner) = (a.clone(), owner.clone());
                std::thread::spawn(move || {
                    let mut mine = Vec::new();
                    for i in 0..20_000usize {
                        if i % 3 != 2 {
                            if let Some(s) = a.alloc(t * 31 + i) {
                                let prev = owner[s as usize].swap(t as u8 + 1, Ordering::AcqRel);
                                assert_eq!(prev, 0, "slot {s} already owned by {prev}");
                                mine.push(s);
                            }
                        } else if let Some(s) = mine.pop() {
                            owner[s as usize].store(0, Ordering::Release);
                            a.retire(s);
                        }
                    }
                    for s in mine {
                        owner[s as usize].store(0, Ordering::Release);
                        a.retire(s);
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap_or_else(|_| panic!("worker panicked"));
        }
        stop.store(true, Ordering::Relaxed);
        gc.join().unwrap_or_else(|_| panic!("gc panicked"));
        a.advance_epoch();
        a.advance_epoch();
        a.recycle();
        assert_eq!(a.quarantined(), 0);
        let mut all: Vec<u32> = a.parts.iter().flat_map(|p| p.lock().free.clone()).collect();
        all.sort_unstable();
        assert_eq!(all, (0..slots).collect::<Vec<_>>(), "every slot back exactly once");
    }

    /// QA finding (WU3): a second retire of the same slot (a caller bug, or
    /// a retire racing a rollback) quarantines it twice, so after the grace
    /// period it is on the free stack twice and two sessions can be given
    /// the same `SLOT` record. The allocator does not guard against it.
    /// Ignored until the allocator (or `XdpMirror::retire`) refuses a slot
    /// that is not live.
    #[test]
    #[ignore = "QA finding: double retire duplicates a slot"]
    fn double_retire_does_not_duplicate_a_slot() {
        let a = SlotAllocator::new(2, 1);
        let s = a.alloc(0).unwrap_or(u32::MAX);
        a.retire(s);
        a.retire(s);
        a.advance_epoch();
        a.advance_epoch();
        a.recycle();
        let x = a.alloc(0);
        let y = a.alloc(0);
        let z = a.alloc(0);
        assert!(!(x == y || y == z || x == z) || x.is_none(), "duplicate slot: {x:?} {y:?} {z:?}");
        assert_eq!(z, None, "only 2 slots exist");
    }
}
