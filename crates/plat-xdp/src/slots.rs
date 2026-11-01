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
//! - Each partition keeps a live bit per slot: [`SlotAllocator::retire`]
//!   of a slot that is not live (a double retire, or one racing a
//!   rollback) is refused, so a slot is never on a free stack twice (QA F1).
//! - Counters are per partition, under its lock (no shared atomic written
//!   by every worker, PERF-005); [`SlotAllocator::quarantined`] sums them.
//!
//! Lock order: each partition mutex is a leaf (`bib4 → xslot`, or `xslot`
//! alone; the publisher takes `publisher → xslot`); nothing is called while
//! it is held. NIST-003: never take `bib4`, `bib6` or `subs` while holding
//! a partition lock or the publisher mutex (the publisher and the control
//! thread call the engine, `State::mirror_gc`, only with neither held).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - fixed number of
//!   slots (⌈1.25 × `xdp.max_sessions`⌉), preallocated; exhaustion fails
//!   closed to the slow path; the deferred publish / retire op queues are
//!   preallocated too (two ops per slot, the most a slot can have
//!   outstanding), so they never grow (NIST-004)
//! - NIST 800-53: SC-24 (Fail in Known State) - no slot is reused before an
//!   RCU grace period (with the key echo of plan §4.3, a packet is never
//!   translated with another session's mapping)

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;

/// Default number of partitions (plan §4.3: `xslot[shard % 1024]`).
pub const PARTITIONS: usize = 1024;

/// Deferred hash work of a slot (WU5, plan §4.3 publish-after-unlock):
/// [`OP_PUBLISH`] after an install wrote the record, [`OP_RETIRE`] after a
/// retire marked it `DEAD`. Encoded `slot << 1 | kind`.
pub const OP_PUBLISH: u64 = 0;
/// See [`OP_PUBLISH`].
pub const OP_RETIRE: u64 = 1;

#[derive(Debug)]
struct Part {
    /// Deferred hash work, drained by the publisher. At most one publish
    /// and one retire per slot are outstanding (a slot is reused only
    /// after its retire was drained and its grace period passed), so the
    /// preallocated capacity of two per slot is never exceeded.
    ops: Vec<u64>,
    free: Vec<u32>,
    /// `(slot, epoch stamp)`, stamps non-decreasing (read under the lock).
    quarantine: VecDeque<(u32, u64)>,
    /// Bit `slot / partitions`: handed out by `alloc` and not yet retired.
    live: Box<[u64]>,
}

impl Part {
    /// Word and mask of the live bit of the partition's `local`-th slot.
    fn bit(&mut self, local: usize) -> Option<(&mut u64, u64)> {
        Some((self.live.get_mut(local / 64)?, 1u64 << (local % 64)))
    }
}

/// See the module documentation.
#[derive(Debug)]
pub struct SlotAllocator {
    parts: Box<[Mutex<Part>]>,
    /// PERF-002: partition `i` has queued ops (set under its lock on every
    /// push, cleared by the publisher before it drains), so a publisher
    /// pass locks only partitions with work.
    has_ops: Box<[AtomicBool]>,
    /// PERF-003: ops queued and not yet drained, per partition lane
    /// (`plat_xdp_publish_queue_depth`).
    queued: Box<[AtomicU64]>,
    epoch: AtomicU64,
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
            let live = vec![0u64; cap.div_ceil(64)].into_boxed_slice();
            parts.push(Mutex::new(Part {
                ops: Vec::with_capacity(2 * cap),
                free,
                quarantine: VecDeque::with_capacity(cap),
                live,
            }));
        }
        let has_ops = (0..n).map(|_| AtomicBool::new(false)).collect();
        let queued = (0..n).map(|_| AtomicU64::new(0)).collect();
        Self { parts: parts.into_boxed_slice(), has_ops, queued, epoch: AtomicU64::new(0), slots }
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

    /// PERF-006: a free slot from partition `shard % partitions`, written by
    /// `write` and queued for publishing, all under one partition lock.
    /// `write` stores the record (shared memory only, no lock, no call
    /// into anything else); when it returns `false` the slot goes back to
    /// the free stack. `None`: no free slot, `write` refused, or a full
    /// queue (ruled out by the two-ops-per-slot bound).
    pub fn alloc_publish(&self, shard: usize, write: impl FnOnce(u32) -> bool) -> Option<u32> {
        let n = self.parts.len();
        let i = shard % n;
        let mut g = self.parts.get(i)?.lock();
        if g.ops.len() >= g.ops.capacity() {
            return None;
        }
        let slot = g.free.pop()?;
        if !write(slot) {
            g.free.push(slot);
            return None;
        }
        if let Some((w, m)) = g.bit(slot as usize / n) {
            *w |= m;
        }
        g.ops.push(u64::from(slot) << 1 | OP_PUBLISH);
        self.mark(i);
        Some(slot)
    }

    /// Partition `i` got an op (call with its lock held).
    #[inline]
    fn mark(&self, i: usize) {
        if let Some(q) = self.queued.get(i) {
            q.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(f) = self.has_ops.get(i) {
            f.store(true, Ordering::Release);
        }
    }

    /// Ops queued and not yet drained (control path).
    pub fn queued_ops(&self) -> u64 {
        self.queued.iter().map(|q| q.load(Ordering::Relaxed)).sum()
    }

    /// A free slot from partition `shard % partitions`, or `None` when that
    /// partition has none.
    pub fn alloc(&self, shard: usize) -> Option<u32> {
        let n = self.parts.len();
        let mut g = self.parts.get(shard % n)?.lock();
        let slot = g.free.pop()?;
        if let Some((w, m)) = g.bit(slot as usize / n) {
            *w |= m;
        }
        Some(slot)
    }

    /// Whether `slot` is handed out and not retired.
    pub fn is_live(&self, slot: u32) -> bool {
        let n = self.parts.len();
        slot < self.slots
            && self.part_of(slot).is_some_and(|p| p.lock().bit(slot as usize / n).is_some_and(|(w, m)| *w & m != 0))
    }

    /// Quarantines `slot` (state already `DEAD`, hash entries deleted).
    /// Returns `false`, changing nothing, for an out-of-range index or a
    /// slot that is not live (QA F1: never quarantined twice).
    pub fn retire(&self, slot: u32) -> bool {
        if slot >= self.slots {
            return false;
        }
        let n = self.parts.len();
        let Some(p) = self.part_of(slot) else { return false };
        let mut g = p.lock();
        match g.bit(slot as usize / n) {
            Some((w, m)) if *w & m != 0 => *w &= !m,
            _ => return false,
        }
        let stamp = self.epoch.load(Ordering::Acquire);
        g.quarantine.push_back((slot, stamp));
        true
    }

    /// Queues `op` ([`OP_PUBLISH`] / [`OP_RETIRE`]) for `slot` under its
    /// partition lock; `false` (nothing queued) only if the preallocated
    /// queue is full, which the two-per-slot bound rules out.
    fn push_op(g: &mut Part, slot: u32, op: u64) -> bool {
        if g.ops.len() >= g.ops.capacity() {
            return false;
        }
        g.ops.push(u64::from(slot) << 1 | op);
        true
    }

    /// Queues the publish of a slot handed out by [`SlotAllocator::alloc`]
    /// whose record is written (`PENDING`).
    pub fn defer_publish(&self, slot: u32) -> bool {
        let i = slot as usize % self.parts.len();
        self.part_of(slot).is_some_and(|p| {
            let mut g = p.lock();
            let ok = Self::push_op(&mut g, slot, OP_PUBLISH);
            if ok {
                self.mark(i);
            }
            ok
        })
    }

    /// Ends `slot`'s life as [`SlotAllocator::retire`] does, but queues the
    /// hash deletes and the quarantine for the publisher
    /// ([`SlotAllocator::quarantine`] after the deletes). `false`, changing
    /// nothing, for a slot that is not live or a full queue.
    pub fn defer_retire(&self, slot: u32) -> bool {
        if slot >= self.slots {
            return false;
        }
        let n = self.parts.len();
        let Some(p) = self.part_of(slot) else { return false };
        let mut g = p.lock();
        if g.ops.len() >= g.ops.capacity() {
            return false;
        }
        match g.bit(slot as usize / n) {
            Some((w, m)) if *w & m != 0 => *w &= !m,
            _ => return false,
        }
        let ok = Self::push_op(&mut g, slot, OP_RETIRE);
        if ok {
            self.mark(slot as usize % n);
        }
        ok
    }

    /// Moves every queued op of every partition to `out` (in queue order
    /// per partition), each partition under its own lock. `out` is the
    /// publisher's reusable buffer.
    pub fn drain_ops(&self, out: &mut Vec<u64>) -> usize {
        let before = out.len();
        for (i, p) in self.parts.iter().enumerate() {
            // PERF-002: skip partitions without ops (no lock, no line
            // bounced from the workers). Cleared before the drain, so a
            // push racing it sets the flag again for the next pass.
            if !self.has_ops.get(i).is_some_and(|f| f.swap(false, Ordering::AcqRel)) {
                continue;
            }
            let mut g = p.lock();
            let k = g.ops.len() as u64;
            out.append(&mut g.ops);
            if let Some(q) = self.queued.get(i) {
                q.fetch_sub(k, Ordering::Relaxed);
            }
        }
        out.len() - before
    }

    /// Quarantines a slot whose deferred retire was drained (its hash
    /// entries are gone): stamped with the current epoch, like
    /// [`SlotAllocator::retire`].
    pub fn quarantine(&self, slot: u32) {
        if slot >= self.slots {
            return;
        }
        if let Some(p) = self.part_of(slot) {
            let stamp = self.epoch.load(Ordering::Acquire);
            p.lock().quarantine.push_back((slot, stamp));
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
        n
    }

    /// Slots waiting for a grace period (`plat_xdp_slots_quarantined`).
    /// Sums the partitions, each under its own lock (control path only).
    pub fn quarantined(&self) -> u64 {
        self.parts.iter().map(|p| p.lock().quarantine.len() as u64).sum()
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

    /// QA F1 (WU3): a second retire of the same slot (a caller bug, or a
    /// retire racing a rollback) must not quarantine it twice, or after the
    /// grace period it would be on the free stack twice and two sessions
    /// could be given the same `SLOT` record. The live bit refuses it.
    #[test]
    fn double_retire_does_not_duplicate_a_slot() {
        let a = SlotAllocator::new(2, 1);
        let s = a.alloc(0).unwrap_or(u32::MAX);
        assert!(a.is_live(s));
        assert!(a.retire(s));
        assert!(!a.retire(s), "second retire refused");
        assert!(!a.is_live(s));
        assert!(!a.retire(1), "never handed out");
        assert_eq!(a.quarantined(), 1);
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
