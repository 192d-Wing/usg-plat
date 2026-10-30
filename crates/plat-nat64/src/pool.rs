//! IPv4 pool divided into port blocks (RFC 6888 / RFC 7422 bulk port
//! allocation).
//!
//! Each address is split into `(port_max - port_min + 1) / block_size`
//! blocks. Blocks are handed out FIFO so a released block is reused as late
//! as possible, and a released block cools down for
//! `nat64.block_cooldown_secs` before it can be allocated again, which keeps
//! attribution windows in the log from abutting or overlapping.
//!
//! Two layouts share this type:
//! - **Legacy** ([`Pool::new`]): the node's own addresses, all usable.
//! - **Sliced** ([`Pool::new_sliced`], `cluster.partition = "slices"`): the
//!   whole cluster pool, split into fixed slices (`plat-cluster`
//!   `SliceMap`). Only slices in [`SliceState::Active`] translate or
//!   allocate; with an in-sync backup a block is handed out only after the
//!   backup acknowledged its reservation.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use ahash::RandomState;
use crossbeam_utils::CachePadded;
use parking_lot::Mutex;
use plat_cluster::{SliceId, SliceMap};
use plat_common::DropReason;

/// A block: index into the pool's address list plus block number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockRef {
    pub addr_idx: u32,
    pub block: u16,
}

/// Ownership state of one slice (sliced pools only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SliceState {
    /// Not owned by this node (another member's, or nobody's yet).
    Inactive = 0,
    /// Owned under a valid lease: translates and allocates.
    Active = 1,
    /// Owned, but the lease is not (or no longer) valid: drops everything.
    Fenced = 2,
    /// Being taken over: state imported, records not yet all queued.
    Adopting = 3,
}

impl SliceState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Active,
            2 => Self::Fenced,
            3 => Self::Adopting,
            _ => Self::Inactive,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Active => "active",
            Self::Fenced => "fenced",
            Self::Adopting => "adopting",
        }
    }
}

/// Why a block could not be allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocFail {
    /// No free block in any usable slice / address.
    Exhausted,
    /// Free blocks exist, but none is reserved with the in-sync backup yet
    /// (`plat_cluster_reserve_starved_total`).
    Starved,
    /// Strict paired pooling: the subscriber's address has no free block,
    /// other addresses may (`plat_pool_paired_exhausted_total`, B-8).
    PairedExhausted,
}

/// One address's free blocks.
#[derive(Debug)]
struct AddrFree {
    blocks: VecDeque<u16>,
    /// The address is (or may be, until lazily removed) in `Pool::avail`.
    listed: bool,
}

/// A run of consecutive pool addresses: `[start, start + len)` maps to
/// indices `[base, base + len)`.
#[derive(Debug, Clone, Copy)]
struct Run {
    start: u32,
    len: u32,
    base: u32,
}

/// Port-block pool.
///
/// Allocation is O(1) amortised: `avail` is a round-robin queue of address
/// indices (legacy) or slice ids (sliced) that have free blocks, so an
/// allocation never scans addresses, and an exhausted pool is detected from
/// one atomic load. Lock order is `free[i]` / slice → `avail`; `avail` is
/// never held while taking a per-address or per-slice lock.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - bounded, constant work per allocation even when the
///   pool is exhausted (no per-packet scan of every address).
/// - RFC 4787 REQ-2 - paired pooling via `prefer`.
/// - RFC 6888 REQ-12 / RFC 7422 §2 - released blocks cool down before reuse
///   (POAM-010 closed).
#[derive(Debug)]
pub struct Pool {
    /// Sorted pool addresses (this node's in legacy mode, the whole
    /// cluster pool when sliced).
    addrs: Vec<u32>,
    runs: Vec<Run>,
    /// Slice layer; `None` in legacy mode (one branch per packet).
    sliced: Option<Box<Sliced>>,
    free: Vec<Mutex<AddrFree>>,
    /// Padded with `free_blocks` (PERF-103): both are written on block
    /// allocation/release and must not share a line with `runs`, which
    /// `index` reads on every packet.
    avail: CachePadded<Mutex<VecDeque<u32>>>,
    port_min: u16,
    block_size: u16,
    blocks_per_addr: u16,
    /// Allocatable blocks (sliced: in Active slices only).
    free_blocks: CachePadded<AtomicU64>,
    /// Blocks in Active slices (sliced); unused in legacy mode. Padded
    /// (PERF-005): written on ownership changes, off the `runs` line.
    owned_blocks: CachePadded<AtomicU64>,
    cooldown_ms: u64,
    /// Legacy released blocks waiting out the cool-down, oldest first.
    /// Padded (PERF-005): the sweeper's lock writes must not share a line
    /// with the read-mostly fields above.
    cooling: CachePadded<Mutex<VecDeque<(u64, BlockRef)>>>,
}

/// Per-slice allocation state.
#[derive(Debug)]
struct SliceAlloc {
    /// First pool index of the slice.
    base: u32,
    /// Free blocks per address of the slice (offset from `base`).
    addr_free: Box<[VecDeque<u16>]>,
    addr_listed: Box<[bool]>,
    /// Address offsets with free blocks (lazy, like `Pool::avail`).
    avail: VecDeque<u32>,
    /// Ready, unreserved blocks in `addr_free`.
    free: u64,
    /// Acknowledged by the backup; handed out first.
    reserved: VecDeque<BlockRef>,
    /// Sent to the backup, not yet acknowledged.
    pending: Vec<BlockRef>,
    /// Released blocks waiting out the cool-down (monotonic deadlines).
    cooling: VecDeque<(u64, BlockRef)>,
    /// Takeover hold-back (monotonic deadlines).
    held: VecDeque<(u64, BlockRef)>,
    require_reserve: bool,
    /// Address offsets a strictly paired subscriber waited for (starved
    /// under a required reservation): served first by the next top-up
    /// (RFC-004). Preallocated, bounded by `reserve_ahead`, deduplicated.
    wanted: VecDeque<u32>,
    /// In `Sliced::avail`.
    listed: bool,
}

impl SliceAlloc {
    fn ready(&self) -> u64 {
        self.free + self.reserved.len() as u64
    }

    fn allocatable(&self) -> bool {
        !self.reserved.is_empty() || (!self.require_reserve && self.free > 0)
    }

    fn push_free(&mut self, r: BlockRef, front: bool) {
        let off = r.addr_idx - self.base;
        let Some(q) = self.addr_free.get_mut(off as usize) else { return };
        if front {
            q.push_front(r.block);
        } else {
            q.push_back(r.block);
        }
        self.free += 1;
        if let Some(l) = self.addr_listed.get_mut(off as usize)
            && !*l
        {
            *l = true;
            self.avail.push_back(off);
        }
    }

    /// An unreserved free block, from address offset `want` only if given.
    fn take_free(&mut self, want: Option<u32>) -> Option<BlockRef> {
        if let Some(off) = want {
            let b = self.addr_free.get_mut(off as usize)?.pop_front()?;
            self.free -= 1;
            return Some(BlockRef { addr_idx: self.base + off, block: b });
        }
        while let Some(off) = self.avail.pop_front() {
            let Some(q) = self.addr_free.get_mut(off as usize) else { continue };
            if let Some(b) = q.pop_front() {
                if q.is_empty() {
                    if let Some(l) = self.addr_listed.get_mut(off as usize) {
                        *l = false;
                    }
                } else {
                    self.avail.push_back(off);
                }
                self.free -= 1;
                return Some(BlockRef { addr_idx: self.base + off, block: b });
            }
            if let Some(l) = self.addr_listed.get_mut(off as usize) {
                *l = false;
            }
        }
        None
    }

    /// A block for allocation: reserved first, else free unless the slice
    /// requires a reservation. `want` restricts to one address.
    fn take(&mut self, want: Option<u32>) -> Option<BlockRef> {
        let pos = match want {
            None => (!self.reserved.is_empty()).then_some(0),
            Some(off) => self.reserved.iter().position(|r| r.addr_idx == self.base + off),
        };
        if let Some(i) = pos {
            return self.reserved.remove(i);
        }
        if self.require_reserve {
            return None;
        }
        self.take_free(want)
    }
}

/// Slice layer of a sliced pool.
#[derive(Debug)]
struct Sliced {
    /// `addr_idx >> shift` is the slice id (every slice is full and slices
    /// are dense in address order).
    shift: u32,
    /// Read on every packet; written only on ownership changes.
    state: Box<[AtomicU8]>,
    slices: Box<[CachePadded<Mutex<SliceAlloc>>]>,
    /// Slice ids with allocatable blocks (lazy).
    avail: CachePadded<Mutex<VecDeque<SliceId>>>,
    listed: CachePadded<AtomicU32>,
    /// Active slices that require a reservation (an empty `avail` then
    /// means starved rather than exhausted).
    gated: AtomicU32,
    /// Blocks held back after an adoption (quarantine), in every slice.
    /// Read only when an allocation fails.
    held: AtomicU64,
    reserve_ahead: usize,
}

impl Sliced {
    fn fail(&self, starved: bool) -> AllocFail {
        if starved || self.gated.load(Ordering::Relaxed) > 0 { AllocFail::Starved } else { AllocFail::Exhausted }
    }
}

fn build_runs(addrs: &[u32]) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    for (i, &a) in addrs.iter().enumerate() {
        match runs.last_mut() {
            Some(r) if r.start.checked_add(r.len) == Some(a) => r.len += 1,
            _ => runs.push(Run { start: a, len: 1, base: i as u32 }),
        }
    }
    runs
}

fn blocks_per_addr(port_min: u16, port_max: u16, block_size: u16) -> u16 {
    let range = (u32::from(port_max) + 1).saturating_sub(u32::from(port_min));
    (range / u32::from(block_size.max(1))).min(u32::from(u16::MAX)) as u16
}

impl Pool {
    /// Legacy pool over `addrs` (this node's share, see `plat-cluster`).
    /// No cool-down until [`Pool::with_cooldown`].
    pub fn new(mut addrs: Vec<u32>, port_min: u16, port_max: u16, block_size: u16) -> Self {
        addrs.sort_unstable();
        addrs.dedup();
        let blocks_per_addr = blocks_per_addr(port_min, port_max, block_size);
        let has = blocks_per_addr > 0;
        let free = addrs
            .iter()
            .map(|_| Mutex::new(AddrFree { blocks: (0..blocks_per_addr).collect(), listed: has }))
            .collect();
        let avail = if has { (0..addrs.len() as u32).collect() } else { VecDeque::new() };
        let runs = build_runs(&addrs);
        let total = addrs.len() as u64 * u64::from(blocks_per_addr);
        Self {
            addrs,
            runs,
            sliced: None,
            free,
            avail: CachePadded::new(Mutex::new(avail)),
            port_min,
            block_size,
            blocks_per_addr,
            free_blocks: CachePadded::new(AtomicU64::new(total)),
            owned_blocks: CachePadded::new(AtomicU64::new(0)),
            cooldown_ms: 0,
            cooling: CachePadded::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Sliced pool over every address of `slices`. Every slice starts
    /// [`SliceState::Inactive`] with all blocks free and no reservation
    /// required. `reserve_ahead` is the per-slice reservation target.
    pub fn new_sliced(
        slices: &SliceMap,
        port_min: u16,
        port_max: u16,
        block_size: u16,
        reserve_ahead: u16,
    ) -> Result<Self, String> {
        let mut addrs: Vec<u32> = Vec::new();
        for (_, c) in slices.iter() {
            addrs.extend(c.addrs());
        }
        let size = slices.slice_size();
        if addrs.windows(2).any(|w| w[0] >= w[1]) || addrs.len() as u64 != slices.len() as u64 * u64::from(size) {
            return Err("slice table does not cover the pool exactly".into());
        }
        let bpa = blocks_per_addr(port_min, port_max, block_size);
        let state = (0..slices.len()).map(|_| AtomicU8::new(SliceState::Inactive as u8)).collect();
        let sl = (0..slices.len() as u32)
            .map(|s| {
                let mut a = SliceAlloc {
                    base: s * size,
                    addr_free: (0..size).map(|_| VecDeque::new()).collect(),
                    addr_listed: vec![false; size as usize].into_boxed_slice(),
                    avail: VecDeque::new(),
                    free: 0,
                    reserved: VecDeque::new(),
                    pending: Vec::new(),
                    cooling: VecDeque::new(),
                    held: VecDeque::new(),
                    require_reserve: false,
                    wanted: VecDeque::with_capacity(usize::from(reserve_ahead.max(1))),
                    listed: false,
                };
                for i in 0..size {
                    for b in 0..bpa {
                        a.push_free(BlockRef { addr_idx: s * size + i, block: b }, false);
                    }
                }
                CachePadded::new(Mutex::new(a))
            })
            .collect();
        let runs = build_runs(&addrs);
        Ok(Self {
            addrs,
            runs,
            sliced: Some(Box::new(Sliced {
                shift: 32 - u32::from(slices.slice_len()),
                state,
                slices: sl,
                avail: CachePadded::new(Mutex::new(VecDeque::new())),
                listed: CachePadded::new(AtomicU32::new(0)),
                gated: AtomicU32::new(0),
                held: AtomicU64::new(0),
                reserve_ahead: usize::from(reserve_ahead.max(1)),
            })),
            free: Vec::new(),
            avail: CachePadded::new(Mutex::new(VecDeque::new())),
            port_min,
            block_size,
            blocks_per_addr: bpa,
            free_blocks: CachePadded::new(AtomicU64::new(0)),
            owned_blocks: CachePadded::new(AtomicU64::new(0)),
            cooldown_ms: 0,
            cooling: CachePadded::new(Mutex::new(VecDeque::new())),
        })
    }

    /// Released blocks wait `ms` before they can be allocated again.
    pub fn with_cooldown(mut self, ms: u64) -> Self {
        self.cooldown_ms = ms;
        self
    }

    /// Index of `a` if it is a pool address (this node's in legacy mode,
    /// any cluster pool address when sliced). O(log runs).
    #[inline]
    pub fn index(&self, a: u32) -> Option<u32> {
        let i = self.runs.partition_point(|r| r.start <= a).checked_sub(1)?;
        let r = self.runs.get(i)?;
        let off = a - r.start;
        (off < r.len).then_some(r.base + off)
    }

    /// Index of `a` if this node translates for it now (legacy: any of its
    /// addresses; sliced: an address in an Active slice).
    #[inline]
    pub fn local(&self, a: u32) -> Option<u32> {
        let i = self.index(a)?;
        self.idx_active(i).then_some(i)
    }

    /// Whether pool index `idx` may translate now. One relaxed load of a
    /// read-mostly byte when sliced; always true in legacy mode.
    #[inline]
    pub fn idx_active(&self, idx: u32) -> bool {
        match &self.sliced {
            None => true,
            Some(s) => s.state.get((idx >> s.shift) as usize).is_some_and(|b| b.load(Ordering::Relaxed) == 1),
        }
    }

    /// Ownership check for pool index `idx` on the packet path.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-24 (Fail in Known State) - a fenced or adopting
    ///   slice translates nothing (`cluster_fenced`)
    /// - NIST 800-53: SI-4 - another member's slice is `wrong_node`
    #[inline]
    pub fn check_idx(&self, idx: u32) -> Result<(), DropReason> {
        let Some(s) = &self.sliced else { return Ok(()) };
        match s.state.get((idx >> s.shift) as usize).map(|b| b.load(Ordering::Relaxed)) {
            Some(1) => Ok(()),
            Some(0) | None => Err(DropReason::WrongNode),
            Some(_) => Err(DropReason::ClusterFenced),
        }
    }

    /// [`Pool::check_idx`] with the pool mode known at compile time (the
    /// engine's monomorphised paths pass a constant, PERF-001): no work at
    /// all when `sliced` is false.
    #[inline(always)]
    pub fn check_idx_in(&self, sliced: bool, idx: u32) -> Result<(), DropReason> {
        if sliced { self.check_idx(idx) } else { Ok(()) }
    }

    /// [`Pool::local`] with the pool mode known at compile time: legacy is
    /// a plain [`Pool::index`].
    #[inline(always)]
    pub fn local_in(&self, sliced: bool, a: u32) -> Option<u32> {
        if sliced { self.local(a) } else { self.index(a) }
    }

    /// Ownership check for a pool address on the outbound path (no work in
    /// legacy mode).
    #[inline]
    pub fn check_addr(&self, a: u32) -> Result<(), DropReason> {
        if self.sliced.is_none() {
            return Ok(());
        }
        self.check_idx(self.index(a).ok_or(DropReason::WrongNode)?)
    }

    #[inline]
    pub fn addr(&self, idx: u32) -> u32 {
        self.addrs.get(idx as usize).copied().unwrap_or(0)
    }

    #[inline]
    pub fn block_size(&self) -> u16 {
        self.block_size
    }

    pub fn blocks_per_addr(&self) -> u16 {
        self.blocks_per_addr
    }

    pub fn port_min(&self) -> u16 {
        self.port_min
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

    /// With no free block left: whether the cause is the cluster rather
    /// than the pool size (blocks held back after an unsynced adoption, or
    /// slices that hand out only backup-acknowledged blocks). Off the
    /// packet path (only after an allocation failed).
    pub fn cluster_starved(&self) -> bool {
        self.sliced.as_ref().is_some_and(|s| s.held.load(Ordering::Relaxed) > 0 || s.gated.load(Ordering::Relaxed) > 0)
    }

    /// Blocks held back after adoptions (quarantine; sliced only).
    pub fn held_blocks(&self) -> u64 {
        self.sliced.as_ref().map_or(0, |s| s.held.load(Ordering::Relaxed))
    }

    /// Allocatable blocks (sliced: in Active slices).
    pub fn free_blocks(&self) -> u64 {
        self.free_blocks.load(Ordering::Relaxed)
    }

    /// Blocks this node can allocate from (sliced: in Active slices).
    pub fn total_blocks(&self) -> u64 {
        match &self.sliced {
            None => self.addrs.len() as u64 * u64::from(self.blocks_per_addr),
            Some(_) => self.owned_blocks.load(Ordering::Relaxed),
        }
    }

    pub fn is_sliced(&self) -> bool {
        self.sliced.is_some()
    }

    /// Number of slices (0 in legacy mode).
    pub fn slice_count(&self) -> usize {
        self.sliced.as_ref().map_or(0, |s| s.state.len())
    }

    /// Slice of pool index `idx` (sliced pools only).
    #[inline]
    pub fn slice_of_idx(&self, idx: u32) -> Option<SliceId> {
        let s = self.sliced.as_ref()?;
        let id = idx >> s.shift;
        (usize::try_from(id).is_ok_and(|i| i < s.state.len())).then_some(id as SliceId)
    }

    /// Pool index range `[lo, hi)` of slice `id`.
    pub fn slice_range(&self, id: SliceId) -> Option<(u32, u32)> {
        let s = self.sliced.as_ref()?;
        (usize::from(id) < s.state.len()).then(|| (u32::from(id) << s.shift, (u32::from(id) + 1) << s.shift))
    }

    pub fn slice_state(&self, id: SliceId) -> Option<SliceState> {
        let s = self.sliced.as_ref()?;
        s.state.get(usize::from(id)).map(|b| SliceState::from_u8(b.load(Ordering::Acquire)))
    }

    /// Sets the ownership state of slice `id`. Returns the previous state.
    /// The state is stored under the slice lock so the owned/free counters
    /// stay consistent with it.
    pub fn set_slice_state(&self, id: SliceId, st: SliceState) -> Option<SliceState> {
        let s = self.sliced.as_ref()?;
        let m = s.slices.get(usize::from(id))?;
        let flag = s.state.get(usize::from(id))?;
        let mut g = m.lock();
        let old = SliceState::from_u8(flag.load(Ordering::Relaxed));
        if old == st {
            return Some(old);
        }
        let blocks = u64::from(1u32 << s.shift) * u64::from(self.blocks_per_addr);
        let ready = g.ready();
        if old == SliceState::Active {
            self.owned_blocks.fetch_sub(blocks, Ordering::Relaxed);
            self.free_blocks.fetch_sub(ready, Ordering::Relaxed);
            if g.require_reserve {
                s.gated.fetch_sub(1, Ordering::Relaxed);
            }
        }
        // Release: the imported tables and queued audit records happen
        // before a worker can observe Active.
        flag.store(st as u8, Ordering::Release);
        if st == SliceState::Active {
            self.owned_blocks.fetch_add(blocks, Ordering::Relaxed);
            self.free_blocks.fetch_add(ready, Ordering::Relaxed);
            if g.require_reserve {
                s.gated.fetch_add(1, Ordering::Relaxed);
            }
            Self::relist(s, id, &mut g);
        }
        Some(old)
    }

    fn relist(s: &Sliced, id: SliceId, g: &mut SliceAlloc) {
        if !g.listed && g.allocatable() {
            g.listed = true;
            s.listed.fetch_add(1, Ordering::Relaxed);
            s.avail.lock().push_back(id);
        }
    }

    fn is_active(s: &Sliced, id: usize) -> bool {
        s.state.get(id).is_some_and(|b| b.load(Ordering::Relaxed) == SliceState::Active as u8)
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
        self.alloc_block(prefer, strict).ok()
    }

    /// [`Pool::alloc`] with the failure cause.
    pub fn alloc_block(&self, prefer: Option<u32>, strict: bool) -> Result<BlockRef, AllocFail> {
        if let Some(s) = &self.sliced {
            return self.alloc_sliced(s, prefer, strict);
        }
        if self.free_blocks() == 0 {
            return Err(AllocFail::Exhausted);
        }
        if let Some(p) = prefer {
            // The address stays listed even if this empties it; the stale
            // queue entry is dropped lazily below.
            if let Some(b) = self.take(p, false) {
                return Ok(b);
            }
            if strict {
                return Err(AllocFail::PairedExhausted);
            }
        }
        // Each iteration either allocates or removes one stale entry, so the
        // loop is bounded by the queue length and amortised O(1).
        loop {
            let idx = self.avail.lock().pop_front().ok_or(AllocFail::Exhausted)?;
            if let Some(b) = self.take(idx, true) {
                return Ok(b);
            }
        }
    }

    /// Sliced allocation: only Active slices; with a required reservation
    /// only backup-acknowledged blocks.
    fn alloc_sliced(&self, s: &Sliced, prefer: Option<u32>, strict: bool) -> Result<BlockRef, AllocFail> {
        let mut starved = false;
        if let Some(p) = prefer {
            let id = (p >> s.shift) as usize;
            if let Some(m) = s.slices.get(id)
                && Self::is_active(s, id)
            {
                let mut g = m.lock();
                let off = p - g.base;
                if let Some(b) = g.take(Some(off)) {
                    self.free_blocks.fetch_sub(1, Ordering::Relaxed);
                    return Ok(b);
                }
                // Starved also while the address's only free blocks wait
                // for the backup's ack (B-8: not "exhausted").
                let addr = g.base + off;
                starved = g.require_reserve
                    && (g.addr_free.get(off as usize).is_some_and(|q| !q.is_empty())
                        || g.pending.iter().any(|r| r.addr_idx == addr));
                // RFC-004: a strictly paired subscriber can use only this
                // address; ask the next top-up to reserve a block on it.
                if starved && strict && !g.wanted.contains(&off) && g.wanted.len() < s.reserve_ahead {
                    g.wanted.push_back(off);
                }
            }
            if strict {
                return Err(if starved {
                    AllocFail::Starved
                } else if self.free_blocks() > 0 {
                    AllocFail::PairedExhausted
                } else {
                    s.fail(false)
                });
            }
        }
        if s.listed.load(Ordering::Relaxed) == 0 {
            return Err(s.fail(starved));
        }
        // Bounded by the queue length (each slice is listed at most once).
        loop {
            let Some(id) = s.avail.lock().pop_front() else {
                return Err(s.fail(starved));
            };
            let Some(m) = s.slices.get(usize::from(id)) else { continue };
            let mut g = m.lock();
            let active = Self::is_active(s, usize::from(id));
            let got = if active { g.take(None) } else { None };
            if active && g.allocatable() {
                s.avail.lock().push_back(id);
            } else {
                g.listed = false;
                s.listed.fetch_sub(1, Ordering::Relaxed);
                starved |= active && g.require_reserve && g.free > 0;
            }
            if let Some(b) = got {
                self.free_blocks.fetch_sub(1, Ordering::Relaxed);
                return Ok(b);
            }
        }
    }

    /// Returns a block that was allocated but never used (its allocation
    /// record was refused): it goes back at once, at the front.
    pub fn unalloc(&self, b: BlockRef) {
        if let Some(s) = &self.sliced {
            let id = (b.addr_idx >> s.shift) as usize;
            let Some(m) = s.slices.get(id) else { return };
            let mut g = m.lock();
            if g.require_reserve {
                g.reserved.push_front(b);
            } else {
                g.push_free(b, true);
            }
            if Self::is_active(s, id) {
                self.free_blocks.fetch_add(1, Ordering::Relaxed);
                Self::relist(s, id as SliceId, &mut g);
            }
            return;
        }
        let Some(m) = self.free.get(b.addr_idx as usize) else { return };
        let mut f = m.lock();
        f.blocks.push_front(b.block);
        self.free_blocks.fetch_add(1, Ordering::Relaxed);
        if !f.listed {
            f.listed = true;
            self.avail.lock().push_back(b.addr_idx);
        }
    }

    /// Returns a released block. It becomes allocatable after the
    /// cool-down (moved by [`Pool::promote`], which the sweeper runs).
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 6888 REQ-12, RFC 7422 §2 - a released block is not handed to
    ///   another subscriber for `nat64.block_cooldown_secs`, so attribution
    ///   windows never abut (POAM-010)
    pub fn release(&self, b: BlockRef, now_ms: u64) {
        let ready = now_ms + self.cooldown_ms;
        if let Some(s) = &self.sliced {
            let id = (b.addr_idx >> s.shift) as usize;
            if let Some(m) = s.slices.get(id) {
                m.lock().cooling.push_back((ready, b));
            }
            return;
        }
        if self.free.get(b.addr_idx as usize).is_some() {
            self.cooling.lock().push_back((ready, b));
        }
    }

    fn release_now(&self, b: BlockRef) {
        let Some(m) = self.free.get(b.addr_idx as usize) else { return };
        let mut f = m.lock();
        f.blocks.push_back(b.block);
        self.free_blocks.fetch_add(1, Ordering::Relaxed);
        if !f.listed {
            f.listed = true;
            self.avail.lock().push_back(b.addr_idx);
        }
    }

    /// Moves blocks whose cool-down or hold-back ended back to the free
    /// lists. Off the packet path (sweeper). Returns the number moved.
    pub fn promote(&self, now_ms: u64) -> u64 {
        let mut n = 0;
        let Some(s) = &self.sliced else {
            loop {
                let next = {
                    let mut c = self.cooling.lock();
                    match c.front() {
                        Some(&(t, b)) if t <= now_ms => {
                            c.pop_front();
                            Some(b)
                        }
                        _ => None,
                    }
                };
                let Some(b) = next else { return n };
                self.release_now(b);
                n += 1;
            }
        };
        for (id, m) in s.slices.iter().enumerate() {
            let mut g = m.lock();
            let before = g.free;
            let held_before = g.held.len();
            for which in 0..2 {
                loop {
                    let q = if which == 0 { &mut g.cooling } else { &mut g.held };
                    match q.front() {
                        Some(&(t, b)) if t <= now_ms => {
                            q.pop_front();
                            g.push_free(b, false);
                        }
                        _ => break,
                    }
                }
            }
            let added = g.free - before;
            let unheld = held_before - g.held.len();
            if unheld > 0 {
                s.held.fetch_sub(unheld as u64, Ordering::Relaxed);
            }
            if added > 0 {
                n += added;
                if Self::is_active(s, id) {
                    self.free_blocks.fetch_add(added, Ordering::Relaxed);
                    Self::relist(s, id as SliceId, &mut g);
                }
            }
        }
        n
    }

    /// Blocks cooling down or held back (not allocatable yet).
    pub fn cooling_blocks(&self) -> u64 {
        match &self.sliced {
            None => self.cooling.lock().len() as u64,
            Some(s) => s
                .slices
                .iter()
                .map(|m| {
                    let g = m.lock();
                    (g.cooling.len() + g.held.len()) as u64
                })
                .sum(),
        }
    }

    /// Rebuilds slice `id` for a new owner: every block is free except
    /// `in_use` (adopted), `held` (hold-back until the deadline) and
    /// `cooling` (cool-down until the deadline). Reservations are dropped.
    /// The slice must not be Active.
    pub(crate) fn reset_slice(
        &self,
        id: SliceId,
        in_use: &[BlockRef],
        held: &[(u64, BlockRef)],
        cooling: &[(u64, BlockRef)],
    ) -> bool {
        let Some(s) = &self.sliced else { return false };
        let Some(m) = s.slices.get(usize::from(id)) else { return false };
        if Self::is_active(s, usize::from(id)) {
            return false;
        }
        let mut g = m.lock();
        let size = 1u32 << s.shift;
        let base = g.base;
        let mut skip: HashSet<BlockRef, RandomState> = HashSet::with_hasher(RandomState::new());
        skip.extend(in_use.iter().copied());
        skip.extend(held.iter().map(|h| h.1));
        skip.extend(cooling.iter().map(|h| h.1));
        for q in g.addr_free.iter_mut() {
            q.clear();
        }
        for l in g.addr_listed.iter_mut() {
            *l = false;
        }
        g.avail.clear();
        g.free = 0;
        g.reserved.clear();
        g.pending.clear();
        g.wanted.clear();
        g.cooling.clear();
        s.held.fetch_sub(g.held.len() as u64, Ordering::Relaxed);
        g.held.clear();
        for i in 0..size {
            for b in 0..self.blocks_per_addr {
                let r = BlockRef { addr_idx: base + i, block: b };
                if !skip.contains(&r) {
                    g.push_free(r, false);
                }
            }
        }
        let mut h: Vec<_> = held.iter().filter(|x| x.1.addr_idx >> s.shift == u32::from(id)).copied().collect();
        h.sort_unstable_by_key(|x| x.0);
        s.held.fetch_add(h.len() as u64, Ordering::Relaxed);
        g.held.extend(h);
        let mut c: Vec<_> = cooling.iter().filter(|x| x.1.addr_idx >> s.shift == u32::from(id)).copied().collect();
        c.sort_unstable_by_key(|x| x.0);
        g.cooling.extend(c);
        true
    }

    /// Reservation target minus blocks reserved or pending (0 when the
    /// slice needs no top-up).
    pub fn reserve_deficit(&self, id: SliceId) -> usize {
        let Some(s) = &self.sliced else { return 0 };
        let Some(m) = s.slices.get(usize::from(id)) else { return 0 };
        let g = m.lock();
        Self::reserve_want(s, &g)
    }

    /// Blocks the next top-up should reserve: up to the target, plus one
    /// per address a strictly paired subscriber waits for, even when the
    /// target is met (B-8: the target filled with blocks on addresses no
    /// paired subscriber uses left those waiters refused for good). At
    /// most `2 × reserve_ahead` reserved or pending (SC-5).
    fn reserve_want(s: &Sliced, g: &SliceAlloc) -> usize {
        let have = g.reserved.len() + g.pending.len();
        let base = s.reserve_ahead.saturating_sub(have);
        (base + g.wanted.len()).min((2 * s.reserve_ahead).saturating_sub(have))
    }

    /// Moves up to the reservation deficit of free blocks of slice `id` to
    /// the pending set, for the replicator to send as `Reserve`. Off path.
    pub fn reserve_take(&self, id: SliceId) -> Vec<BlockRef> {
        let Some(s) = &self.sliced else { return Vec::new() };
        let Some(m) = s.slices.get(usize::from(id)) else { return Vec::new() };
        let mut g = m.lock();
        let want = Self::reserve_want(s, &g);
        let mut out = Vec::with_capacity(want);
        // COMPLIANCE MAPPING:
        // - RFC 4787 REQ-2 / RFC 6888 REQ-3 - addresses that strictly paired
        //   subscribers wait for are reserved first (RFC-004), so paired
        //   pooling is not starved by round-robin top-up
        while out.len() < want {
            let Some(off) = g.wanted.pop_front() else { break };
            if let Some(b) = g.take_free(Some(off)) {
                out.push(b);
            }
        }
        let base = s.reserve_ahead.saturating_sub(g.reserved.len() + g.pending.len());
        while out.len() < base.min(want) {
            let Some(b) = g.take_free(None) else { break };
            out.push(b);
        }
        if Self::is_active(s, usize::from(id)) {
            self.free_blocks.fetch_sub(out.len() as u64, Ordering::Relaxed);
        }
        g.pending.extend_from_slice(&out);
        out
    }

    /// The backup acknowledged `blocks`: pending → reserved. Unknown blocks
    /// are ignored. Returns the number confirmed.
    pub fn reserve_confirm(&self, id: SliceId, blocks: &[BlockRef]) -> usize {
        let Some(s) = &self.sliced else { return 0 };
        let Some(m) = s.slices.get(usize::from(id)) else { return 0 };
        let mut g = m.lock();
        let mut n = 0;
        for b in blocks {
            if let Some(i) = g.pending.iter().position(|p| p == b) {
                g.pending.swap_remove(i);
                g.reserved.push_back(*b);
                n += 1;
            }
        }
        if Self::is_active(s, usize::from(id)) {
            self.free_blocks.fetch_add(n as u64, Ordering::Relaxed);
            Self::relist(s, id, &mut g);
        }
        n
    }

    /// Drops every reservation of slice `id` (new or lost backup): the
    /// blocks return to the front of the free lists.
    pub fn reserve_reset(&self, id: SliceId) {
        let Some(s) = &self.sliced else { return };
        let Some(m) = s.slices.get(usize::from(id)) else { return };
        let mut g = m.lock();
        let before = g.ready();
        g.wanted.clear();
        let mut blocks = std::mem::take(&mut g.pending);
        blocks.extend(g.reserved.drain(..));
        for b in blocks {
            g.push_free(b, true);
        }
        if Self::is_active(s, usize::from(id)) {
            let after = g.ready();
            self.free_blocks.fetch_add(after.saturating_sub(before), Ordering::Relaxed);
            Self::relist(s, id, &mut g);
        }
    }

    /// With `true`, slice `id` hands out only backup-acknowledged blocks
    /// (set while an in-sync backup exists).
    pub fn set_reserve_required(&self, id: SliceId, on: bool) {
        let Some(s) = &self.sliced else { return };
        let Some(m) = s.slices.get(usize::from(id)) else { return };
        let mut g = m.lock();
        if g.require_reserve == on {
            return;
        }
        g.require_reserve = on;
        if Self::is_active(s, usize::from(id)) {
            if on {
                s.gated.fetch_add(1, Ordering::Relaxed);
            } else {
                s.gated.fetch_sub(1, Ordering::Relaxed);
            }
            Self::relist(s, id, &mut g);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plat_common::Ipv4Cidr;

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
        p.release(a, 0);
        assert_eq!(p.promote(0), 1);
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
        p.release(got[4], 0);
        p.promote(0);
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
        p.release(a, 0);
        p.promote(0);
        let b = p.alloc(None, true).unwrap();
        assert_ne!(a, b, "released block goes to the back of the queue");
    }

    #[test]
    fn cooldown_holds_released_block() {
        let p = Pool::new(vec![1], 1024, 1024 + 64 - 1, 64).with_cooldown(120_000);
        let a = p.alloc(None, true).unwrap();
        p.release(a, 1_000);
        assert_eq!((p.free_blocks(), p.cooling_blocks()), (0, 1));
        assert_eq!(p.promote(120_999), 0, "still cooling");
        assert!(p.alloc(None, false).is_none());
        assert_eq!(p.promote(121_000), 1);
        assert_eq!(p.alloc(None, false), Some(a));
        // A never-used block (refused record) returns at once.
        p.unalloc(a);
        assert_eq!(p.free_blocks(), 1);
    }

    fn sliced() -> Pool {
        let m = SliceMap::new(&[Ipv4Cidr::new([10, 0, 0, 0].into(), 30).unwrap()], 31).unwrap();
        Pool::new_sliced(&m, 1024, 1024 + 2 * 64 - 1, 64, 2).unwrap()
    }

    #[test]
    fn sliced_only_active_slices_allocate() {
        let p = sliced();
        assert_eq!(p.slice_count(), 2);
        assert_eq!(p.total_blocks(), 0);
        assert_eq!(p.alloc_block(None, false), Err(AllocFail::Exhausted));
        assert_eq!(p.check_idx(0), Err(DropReason::WrongNode));
        p.set_slice_state(1, SliceState::Active);
        assert_eq!((p.total_blocks(), p.free_blocks()), (4, 4));
        assert_eq!(p.check_idx(2), Ok(()));
        let b = p.alloc(None, false).unwrap();
        assert_eq!(p.slice_of_idx(b.addr_idx), Some(1));
        assert!(p.alloc(Some(0), true).is_none(), "preferred address in an inactive slice");
        p.set_slice_state(1, SliceState::Fenced);
        assert_eq!(p.check_idx(2), Err(DropReason::ClusterFenced));
        assert!(p.alloc(None, false).is_none());
        assert_eq!(p.free_blocks(), 0);
    }

    #[test]
    fn sliced_reservation_gates_allocation() {
        let p = sliced();
        p.set_reserve_required(0, true);
        p.set_slice_state(0, SliceState::Active);
        assert_eq!(p.alloc_block(None, false), Err(AllocFail::Starved), "nothing reserved yet");
        let r = p.reserve_take(0);
        assert_eq!(r.len(), 2);
        assert_eq!(p.reserve_deficit(0), 0);
        assert!(p.alloc(None, false).is_none(), "pending is not usable");
        assert_eq!(p.reserve_confirm(0, &r[..1]), 1);
        assert_eq!(p.alloc(None, false), Some(r[0]));
        assert_eq!(p.alloc_block(Some(r[0].addr_idx), true), Err(AllocFail::Starved));
        p.reserve_reset(0);
        assert_eq!(p.reserve_deficit(0), 2);
        p.set_reserve_required(0, false);
        assert!(p.alloc(None, false).is_some());
    }

    #[test]
    fn topup_serves_strictly_paired_waiters_first() {
        let p = sliced();
        p.set_reserve_required(0, true);
        p.set_slice_state(0, SliceState::Active);
        let r = p.reserve_take(0);
        assert_eq!(r, [BlockRef { addr_idx: 0, block: 0 }, BlockRef { addr_idx: 1, block: 0 }]);
        assert_eq!(p.reserve_confirm(0, &r), 2);
        assert_eq!(p.alloc(Some(1), true), Some(r[1]));
        // A strictly paired subscriber on address 1 waits: round robin
        // alone would top up address 0 next (RFC-004).
        assert_eq!(p.alloc_block(Some(1), true), Err(AllocFail::Starved));
        assert_eq!(p.reserve_take(0), [BlockRef { addr_idx: 1, block: 1 }]);
    }

    #[test]
    fn sliced_reset_holds_and_cools() {
        let p = sliced();
        let a = BlockRef { addr_idx: 0, block: 0 };
        let h = BlockRef { addr_idx: 0, block: 1 };
        let c = BlockRef { addr_idx: 1, block: 0 };
        assert!(p.reset_slice(0, &[a], &[(600_000, h)], &[(5_000, c)]));
        p.set_slice_state(0, SliceState::Active);
        assert_eq!(p.free_blocks(), 1);
        assert_eq!(p.alloc(None, false), Some(BlockRef { addr_idx: 1, block: 1 }));
        assert!(p.alloc(None, false).is_none());
        assert_eq!(p.promote(5_000), 1);
        assert_eq!(p.alloc(None, false), Some(c));
        assert!(p.alloc(None, false).is_none());
        assert_eq!(p.promote(600_000), 1);
        assert_eq!(p.alloc(None, false), Some(h));
        assert!(!p.reset_slice(0, &[], &[], &[]), "active slice cannot be reset");
    }

    /// B-8: the reservation target filled with blocks on addresses no
    /// strictly paired subscriber uses must not leave the waiters refused
    /// for good: the top-up reserves their addresses beyond the target.
    #[test]
    fn paired_waiters_are_served_when_the_target_is_met() {
        // 4 addresses of 16 blocks in one slice, reserve_ahead 2.
        let m = SliceMap::new(&[Ipv4Cidr::new([10, 0, 0, 0].into(), 30).unwrap()], 30).unwrap();
        let p = Pool::new_sliced(&m, 1024, 1024 + 16 * 64 - 1, 64, 2).unwrap();
        p.set_reserve_required(0, true);
        p.set_slice_state(0, SliceState::Active);
        let pump = |p: &Pool| {
            let r = p.reserve_take(0);
            p.reserve_confirm(0, &r);
        };
        pump(&p);
        // Two new subscribers take the reserved blocks on addresses 0, 1;
        // the top-up refills on addresses 2, 3, which nobody is paired to.
        let a = p.alloc(None, false).unwrap();
        let b = p.alloc(None, false).unwrap();
        assert_eq!((a.addr_idx, b.addr_idx), (0, 1));
        pump(&p);
        assert_eq!(p.reserve_deficit(0), 0);
        // High new-connection rate: both need more blocks on their address.
        // A refusal asks the next top-up for the address.
        let mut got = [0usize; 2];
        for _ in 0..20 {
            for (i, x) in [a, b].iter().enumerate() {
                match p.alloc_block(Some(x.addr_idx), true) {
                    Ok(n) => {
                        assert_eq!(n.addr_idx, x.addr_idx);
                        got[i] += 1;
                    }
                    Err(e) => assert_eq!(e, AllocFail::Starved, "a refusal with free blocks is counted"),
                }
            }
            pump(&p);
        }
        assert!(got.iter().all(|g| *g >= 9), "paired subscribers get blocks on their address: {got:?}");
        // Bounded: never more than 2 x reserve_ahead reserved or pending.
        assert!(p.reserve_deficit(0) <= 4);
    }

    #[test]
    fn strict_paired_full_address_is_counted_apart() {
        let p = sliced();
        p.set_slice_state(0, SliceState::Active);
        let a = p.alloc(Some(0), true).unwrap();
        assert_eq!(a.addr_idx, 0);
        assert!(p.alloc(Some(0), true).is_some());
        assert_eq!(p.alloc_block(Some(0), true), Err(AllocFail::PairedExhausted));
        assert!(p.free_blocks() > 0);
    }
}
