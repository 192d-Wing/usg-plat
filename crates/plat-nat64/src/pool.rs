//! IPv4 pool divided into port blocks (RFC 6888 / RFC 7422 bulk port
//! allocation).
//!
//! Each address in this node's slice of the pool is split into
//! `(port_max - port_min + 1) / block_size` blocks. Blocks are handed out
//! FIFO so a released block is reused as late as possible, which keeps
//! attribution windows in the log from overlapping.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_utils::CachePadded;
use parking_lot::Mutex;

/// A block: index into the pool's address list plus block number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockRef {
    pub addr_idx: u32,
    pub block: u16,
}

/// One address's free blocks.
#[derive(Debug)]
struct AddrFree {
    blocks: VecDeque<u16>,
    /// The address is (or may be, until lazily removed) in `Pool::avail`.
    listed: bool,
}

/// A run of consecutive owned addresses: `[start, start + len)` maps to
/// indices `[base, base + len)`.
#[derive(Debug, Clone, Copy)]
struct Run {
    start: u32,
    len: u32,
    base: u32,
}

/// Port-block pool for this node's addresses.
///
/// Allocation is O(1) amortised: `avail` is a round-robin queue of address
/// indices that have free blocks, so an allocation never scans addresses,
/// and an exhausted pool is detected from one atomic load. Lock order is
/// `free[i]` → `avail`; `avail` is never held while taking `free[i]`.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - bounded, constant work per allocation even when the
///   pool is exhausted (no per-packet scan of every address).
/// - RFC 4787 REQ-2 - paired pooling via `prefer`.
#[derive(Debug)]
pub struct Pool {
    /// Sorted, owned IPv4 addresses.
    addrs: Vec<u32>,
    runs: Vec<Run>,
    free: Vec<Mutex<AddrFree>>,
    /// Padded with `free_blocks` (PERF-103): both are written on block
    /// allocation/release and must not share a line with `runs`, which
    /// `index` reads on every packet.
    avail: CachePadded<Mutex<VecDeque<u32>>>,
    port_min: u16,
    block_size: u16,
    blocks_per_addr: u16,
    free_blocks: CachePadded<AtomicU64>,
}

impl Pool {
    /// `addrs` is this node's slice of the pool (see `plat-cluster`).
    pub fn new(mut addrs: Vec<u32>, port_min: u16, port_max: u16, block_size: u16) -> Self {
        addrs.sort_unstable();
        addrs.dedup();
        let range = u32::from(port_max) - u32::from(port_min) + 1;
        let blocks_per_addr = (range / u32::from(block_size.max(1))).min(u32::from(u16::MAX)) as u16;
        let has = blocks_per_addr > 0;
        let free = addrs
            .iter()
            .map(|_| Mutex::new(AddrFree { blocks: (0..blocks_per_addr).collect(), listed: has }))
            .collect();
        let avail = if has { (0..addrs.len() as u32).collect() } else { VecDeque::new() };
        let mut runs: Vec<Run> = Vec::new();
        for (i, &a) in addrs.iter().enumerate() {
            match runs.last_mut() {
                Some(r) if r.start.checked_add(r.len) == Some(a) => r.len += 1,
                _ => runs.push(Run { start: a, len: 1, base: i as u32 }),
            }
        }
        let total = addrs.len() as u64 * u64::from(blocks_per_addr);
        Self {
            addrs,
            runs,
            free,
            avail: CachePadded::new(Mutex::new(avail)),
            port_min,
            block_size,
            blocks_per_addr,
            free_blocks: CachePadded::new(AtomicU64::new(total)),
        }
    }

    /// Index of `a` if it is one of this node's pool addresses. O(log runs);
    /// a partitioned slice is a single run.
    #[inline]
    pub fn index(&self, a: u32) -> Option<u32> {
        let i = self.runs.partition_point(|r| r.start <= a).checked_sub(1)?;
        let r = self.runs.get(i)?;
        let off = a - r.start;
        (off < r.len).then_some(r.base + off)
    }

    #[inline]
    pub fn addr(&self, idx: u32) -> u32 {
        self.addrs[idx as usize]
    }

    #[inline]
    pub fn block_size(&self) -> u16 {
        self.block_size
    }

    /// First port of a block.
    #[inline]
    pub fn port_lo(&self, b: BlockRef) -> u16 {
        self.port_min + b.block * self.block_size
    }

    /// Which block (of this address) a port falls in.
    #[inline]
    pub fn block_of(&self, addr_idx: u32, port: u16) -> Option<BlockRef> {
        let off = port.checked_sub(self.port_min)?;
        let block = off / self.block_size;
        (block < self.blocks_per_addr).then_some(BlockRef { addr_idx, block })
    }

    pub fn free_blocks(&self) -> u64 {
        self.free_blocks.load(Ordering::Relaxed)
    }

    pub fn total_blocks(&self) -> u64 {
        self.addrs.len() as u64 * u64::from(self.blocks_per_addr)
    }

    /// Takes a block from address `idx`. With `relist`, an address that
    /// still has blocks goes back on the round-robin queue; an emptied one
    /// is delisted.
    fn take(&self, idx: u32, relist: bool) -> Option<BlockRef> {
        let mut f = self.free.get(idx as usize)?.lock();
        let Some(b) = f.blocks.pop_front() else {
            if relist {
                f.listed = false;
            }
            return None;
        };
        self.free_blocks.fetch_sub(1, Ordering::Relaxed);
        if relist {
            if f.blocks.is_empty() {
                f.listed = false;
            } else {
                self.avail.lock().push_back(idx);
            }
        }
        Some(BlockRef { addr_idx: idx, block: b })
    }

    /// Allocates a block, preferring `prefer` (paired pooling, RFC 4787
    /// REQ-2). With `strict`, fails rather than use another address.
    pub fn alloc(&self, prefer: Option<u32>, strict: bool) -> Option<BlockRef> {
        if self.free_blocks() == 0 {
            return None;
        }
        if let Some(p) = prefer {
            // The address stays listed even if this empties it; the stale
            // queue entry is dropped lazily below.
            if let Some(b) = self.take(p, false) {
                return Some(b);
            }
            if strict {
                return None;
            }
        }
        // Each iteration either allocates or removes one stale entry, so the
        // loop is bounded by the queue length and amortised O(1).
        loop {
            let idx = self.avail.lock().pop_front()?;
            if let Some(b) = self.take(idx, true) {
                return Some(b);
            }
        }
    }

    // POAM: POAM-010 no 120 s cool-down: a released block can be allocated
    // again immediately (RFC 6888 REQ-12, RFC 7422 §2).
    pub fn release(&self, b: BlockRef) {
        let Some(m) = self.free.get(b.addr_idx as usize) else { return };
        let mut f = m.lock();
        f.blocks.push_back(b.block);
        self.free_blocks.fetch_add(1, Ordering::Relaxed);
        if !f.listed {
            f.listed = true;
            self.avail.lock().push_back(b.addr_idx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_and_paired_pooling() {
        let p = Pool::new(vec![20, 10], 1024, 2047, 512);
        assert_eq!(p.total_blocks(), 4);
        assert_eq!(p.index(10), Some(0));
        assert_eq!(p.index(11), None);
        let a = p.alloc(None, true).unwrap();
        let b = p.alloc(Some(a.addr_idx), true).unwrap();
        assert_eq!(a.addr_idx, b.addr_idx);
        assert!(p.alloc(Some(a.addr_idx), true).is_none(), "strict paired pooling");
        assert!(p.alloc(Some(a.addr_idx), false).is_some());
        assert_eq!(p.port_lo(b), 1024 + 512 * b.block);
        assert_eq!(p.block_of(0, 1600), Some(BlockRef { addr_idx: 0, block: 1 }));
        assert_eq!(p.block_of(0, 1000), None);
        p.release(a);
        assert_eq!(p.free_blocks(), 2);
    }

    #[test]
    fn index_by_runs() {
        let p = Pool::new(vec![100, 5, 6, 7, 101, 50], 1024, 2047, 512);
        for (a, i) in [(5, 0), (6, 1), (7, 2), (50, 3), (100, 4), (101, 5)] {
            assert_eq!(p.index(a), Some(i), "{a}");
            assert_eq!(p.addr(i), a);
        }
        for a in [0, 4, 8, 49, 51, 99, 102, u32::MAX] {
            assert_eq!(p.index(a), None, "{a}");
        }
        let top = Pool::new(vec![u32::MAX - 1, u32::MAX], 1024, 2047, 512);
        assert_eq!(top.index(u32::MAX), Some(1));
    }

    #[test]
    fn alloc_round_robin_and_relist_after_release() {
        let p = Pool::new(vec![1, 2, 3], 1024, 1024 + 2 * 64 - 1, 64);
        let got: Vec<_> = (0..6).map(|_| p.alloc(None, false).unwrap()).collect();
        assert_eq!(got.iter().map(|b| b.addr_idx).collect::<Vec<_>>(), vec![0, 1, 2, 0, 1, 2]);
        assert!(p.alloc(None, false).is_none());
        p.release(got[4]);
        assert_eq!(p.alloc(None, false), Some(got[4]), "released address is relisted");
        // Prefer path empties an address while it is still queued: the stale
        // entry is skipped.
        let p = Pool::new(vec![1, 2], 1024, 1024 + 64 - 1, 64);
        assert_eq!(p.alloc(Some(0), true).unwrap().addr_idx, 0);
        assert_eq!(p.alloc(None, false).unwrap().addr_idx, 1);
        assert!(p.alloc(None, false).is_none());
    }

    #[test]
    fn fifo_reuse() {
        let p = Pool::new(vec![1], 1024, 1024 + 3 * 64 - 1, 64);
        let a = p.alloc(None, true).unwrap();
        p.release(a);
        let b = p.alloc(None, true).unwrap();
        assert_ne!(a, b, "released block goes to the back of the queue");
    }
}
