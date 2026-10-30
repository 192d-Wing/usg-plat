//! Cluster replication support for the engine (HA, `partition = "slices"`).
//!
//! - [`ReplRecord`]: one port-block, BIB or subscriber-home change, as the
//!   engine produces it. Converted to and from the `plat-cluster` wire
//!   messages by the replicator (platd).
//! - [`ReplHub`] / [`ReplProducer`]: one bounded SPSC ring per worker plus
//!   one for the sweeper. A push never blocks, locks or allocates; a full ring
//!   drops the record, counts it and marks the slice dirty so the
//!   replicator resyncs it by snapshot.
//! - [`Directory`]: the cluster subscriber directory (`sub → home`), used to
//!   detect mis-steered new subscribers.
//! - [`Shadow`]: the backup's copy of the slices it protects, turned into
//!   an [`AdoptInput`] on takeover.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - every ring, the
//!   directory and the shadow store are bounded; loss is counted, never
//!   back-pressure on a worker
//! - NIST 800-53: CP-10 (System Recovery and Reconstitution), AU-10 - block
//!   and BIB state survives the loss of the slice owner

use std::cell::Cell;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use ahash::RandomState;
use crossbeam_utils::CachePadded;
use parking_lot::Mutex;
use plat_cluster::{MAX_MEMBERS, MemberId, Msg, SliceId, SliceMap, SnapRecord, WireBib, WireBlock};
use plat_packet::proto;

use crate::shard::{Map, Sharded};

/// One replicated state change. `Copy`, at most 64 bytes of payload, so a
/// ring slot never owns heap memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplRecord {
    BlockAlloc { slice: SliceId, sub: u128, block: WireBlock, wall_us: u64 },
    BlockRelease { slice: SliceId, sub: u128, block: WireBlock },
    BibCreate { slice: SliceId, bib: WireBib },
    BibDelete { slice: SliceId, proto: u8, v4: u32, port4: u16 },
    SubHome { sub: u128, slice: SliceId },
    SubGone { sub: u128 },
}

impl ReplRecord {
    /// The slice the record belongs to (`None` for directory records, which
    /// go to every peer).
    pub fn slice(&self) -> Option<SliceId> {
        match *self {
            Self::BlockAlloc { slice, .. }
            | Self::BlockRelease { slice, .. }
            | Self::BibCreate { slice, .. }
            | Self::BibDelete { slice, .. } => Some(slice),
            Self::SubHome { .. } | Self::SubGone { .. } => None,
        }
    }

    /// The wire message, with the replicator's per-slice sequence number
    /// (ignored by the directory records).
    pub fn to_msg(&self, seq: u64) -> Msg {
        match *self {
            Self::BlockAlloc { slice, sub, block, wall_us } => Msg::BlockAlloc { slice, seq, sub, block, wall_us },
            Self::BlockRelease { slice, sub, block } => Msg::BlockRelease { slice, seq, sub, block },
            Self::BibCreate { slice, bib } => Msg::BibCreate { slice, seq, bib },
            Self::BibDelete { slice, proto, v4, port4 } => Msg::BibDelete { slice, seq, proto, v4, port4 },
            Self::SubHome { sub, slice } => Msg::SubHome { sub, slice },
            Self::SubGone { sub } => Msg::SubGone { sub },
        }
    }

    /// The record and its sequence number (0 for directory records) from a
    /// replication message; `None` for every other message.
    pub fn from_msg(m: &Msg) -> Option<(Self, u64)> {
        Some(match *m {
            Msg::BlockAlloc { slice, seq, sub, block, wall_us } => {
                (Self::BlockAlloc { slice, sub, block, wall_us }, seq)
            }
            Msg::BlockRelease { slice, seq, sub, block } => (Self::BlockRelease { slice, sub, block }, seq),
            Msg::BibCreate { slice, seq, bib } => (Self::BibCreate { slice, bib }, seq),
            Msg::BibDelete { slice, seq, proto, v4, port4 } => (Self::BibDelete { slice, proto, v4, port4 }, seq),
            Msg::SubHome { sub, slice } => (Self::SubHome { sub, slice }, 0),
            Msg::SubGone { sub } => (Self::SubGone { sub }, 0),
            _ => return None,
        })
    }
}

/// Words per ring slot: one cache line.
const SLOT_WORDS: usize = 8;

/// Bytes of ring memory per entry (one aligned slot).
pub const REPL_SLOT_BYTES: u64 = 64;

/// One ring slot, aligned to its own cache line (PERF-004): the producer
/// writing slot `t` never shares a line with the consumer reading `t - 1`.
#[derive(Debug)]
#[repr(align(64))]
struct Slot([AtomicU64; SLOT_WORDS]);

/// A preallocated single-producer single-consumer ring of records, each
/// encoded into one cache-line slot of atomics (no `unsafe`).
///
/// The producer writes the slot words with relaxed stores and publishes
/// them with a release store of `tail`; the consumer reads `tail` with
/// acquire, the words relaxed, and frees the slots with a release store of
/// `head`, which the producer reads with acquire before reusing a slot.
#[derive(Debug)]
struct Ring {
    slots: Box<[Slot]>,
    mask: u64,
    /// Next slot to read (consumer-owned).
    head: CachePadded<AtomicU64>,
    /// Next slot to write (producer-owned); also the pushed count.
    tail: CachePadded<AtomicU64>,
    /// Records refused on a full ring (producer-owned).
    dropped: CachePadded<AtomicU64>,
    /// Serialises consumers (off path), so `drain` may be called from any
    /// thread without breaking the single-consumer contract.
    /// Padded (PERF-004): off the line of `slots`/`mask`, which the
    /// producer reads on every push.
    consumer: CachePadded<Mutex<()>>,
}

const T_ALLOC: u64 = 1;
const T_RELEASE: u64 = 2;
const T_BIB: u64 = 3;
const T_BIBDEL: u64 = 4;
const T_HOME: u64 = 5;
const T_GONE: u64 = 6;

fn lo(v: u128) -> u64 {
    v as u64
}

fn hi(v: u128) -> u64 {
    (v >> 64) as u64
}

fn join(h: u64, l: u64) -> u128 {
    (u128::from(h) << 64) | u128::from(l)
}

impl ReplRecord {
    /// Encodes into slot words: word 0 = tag | slice << 8 | small fields.
    #[inline]
    fn encode(&self, w: &[AtomicU64; SLOT_WORDS]) {
        let put = |i: usize, v: u64| {
            if let Some(a) = w.get(i) {
                a.store(v, Ordering::Relaxed);
            }
        };
        match *self {
            Self::BlockAlloc { slice, sub, block, wall_us } => {
                put(0, T_ALLOC | u64::from(slice) << 8 | u64::from(block.block) << 24);
                put(1, lo(sub));
                put(2, hi(sub));
                put(3, wall_us);
                put(4, u64::from(block.addr));
            }
            Self::BlockRelease { slice, sub, block } => {
                put(0, T_RELEASE | u64::from(slice) << 8 | u64::from(block.block) << 24);
                put(1, lo(sub));
                put(2, hi(sub));
                put(4, u64::from(block.addr));
            }
            Self::BibCreate { slice, bib } => {
                put(
                    0,
                    T_BIB
                        | u64::from(slice) << 8
                        | u64::from(bib.proto) << 24
                        | u64::from(bib.port6) << 32
                        | u64::from(bib.port4) << 48,
                );
                put(1, lo(bib.sub));
                put(2, hi(bib.sub));
                put(3, lo(bib.v6));
                put(4, hi(bib.v6));
                put(5, u64::from(bib.v4));
                put(6, bib.created_wall_us);
            }
            Self::BibDelete { slice, proto, v4, port4 } => {
                put(0, T_BIBDEL | u64::from(slice) << 8 | u64::from(proto) << 24 | u64::from(port4) << 32);
                put(1, u64::from(v4));
            }
            Self::SubHome { sub, slice } => {
                put(0, T_HOME | u64::from(slice) << 8);
                put(1, lo(sub));
                put(2, hi(sub));
            }
            Self::SubGone { sub } => {
                put(0, T_GONE);
                put(1, lo(sub));
                put(2, hi(sub));
            }
        }
    }

    fn decode(w: &[AtomicU64; SLOT_WORDS]) -> Option<Self> {
        let g = |i: usize| w.get(i).map_or(0, |a| a.load(Ordering::Relaxed));
        let w0 = g(0);
        let slice = (w0 >> 8) as SliceId;
        Some(match w0 & 0xff {
            T_ALLOC => Self::BlockAlloc {
                slice,
                sub: join(g(2), g(1)),
                block: WireBlock { addr: g(4) as u32, block: (w0 >> 24) as u16 },
                wall_us: g(3),
            },
            T_RELEASE => Self::BlockRelease {
                slice,
                sub: join(g(2), g(1)),
                block: WireBlock { addr: g(4) as u32, block: (w0 >> 24) as u16 },
            },
            T_BIB => Self::BibCreate {
                slice,
                bib: WireBib {
                    sub: join(g(2), g(1)),
                    proto: (w0 >> 24) as u8,
                    v6: join(g(4), g(3)),
                    port6: (w0 >> 32) as u16,
                    v4: g(5) as u32,
                    port4: (w0 >> 48) as u16,
                    created_wall_us: g(6),
                },
            },
            T_BIBDEL => Self::BibDelete { slice, proto: (w0 >> 24) as u8, v4: g(1) as u32, port4: (w0 >> 32) as u16 },
            T_HOME => Self::SubHome { sub: join(g(2), g(1)), slice },
            T_GONE => Self::SubGone { sub: join(g(2), g(1)) },
            _ => return None,
        })
    }
}

impl Ring {
    fn new(entries: usize) -> Self {
        let n = entries.max(2).next_power_of_two();
        Self {
            slots: (0..n).map(|_| Slot(std::array::from_fn(|_| AtomicU64::new(0)))).collect(),
            mask: n as u64 - 1,
            head: CachePadded::new(AtomicU64::new(0)),
            tail: CachePadded::new(AtomicU64::new(0)),
            dropped: CachePadded::new(AtomicU64::new(0)),
            consumer: CachePadded::new(Mutex::new(())),
        }
    }

    /// Producer side (one thread). `head_cache` is the producer's last
    /// view of `head`, so the consumer's line is read only when the ring
    /// looks full.
    #[inline]
    fn push(&self, rec: &ReplRecord, head_cache: &Cell<u64>) -> bool {
        let t = self.tail.load(Ordering::Relaxed);
        if t.wrapping_sub(head_cache.get()) > self.mask {
            let h = self.head.load(Ordering::Acquire);
            head_cache.set(h);
            if t.wrapping_sub(h) > self.mask {
                return false;
            }
        }
        let Some(slot) = self.slots.get((t & self.mask) as usize) else { return false };
        rec.encode(&slot.0);
        self.tail.store(t.wrapping_add(1), Ordering::Release);
        true
    }

    fn pop_into(&self, max: usize, out: &mut Vec<ReplRecord>) -> usize {
        let _c = self.consumer.lock();
        let h = self.head.load(Ordering::Relaxed);
        let t = self.tail.load(Ordering::Acquire);
        let n = (t.wrapping_sub(h)).min(max as u64);
        for i in 0..n {
            if let Some(r) =
                self.slots.get((h.wrapping_add(i) & self.mask) as usize).and_then(|s| ReplRecord::decode(&s.0))
            {
                out.push(r);
            }
        }
        self.head.store(h.wrapping_add(n), Ordering::Release);
        n as usize
    }

    fn len(&self) -> usize {
        self.tail.load(Ordering::Acquire).wrapping_sub(self.head.load(Ordering::Acquire)) as usize
    }
}

/// Shared side of the rings: drained by the replicator thread.
#[derive(Debug)]
pub struct ReplHub {
    rings: Vec<Arc<Ring>>,
    /// One bit per slice: records were lost, resync by snapshot.
    dirty: Box<[AtomicU64]>,
    /// Directory records were lost: resend the whole local directory.
    dir_dirty: AtomicBool,
    /// Round-robin start for `drain`.
    next: AtomicU32,
}

/// One worker's (or the sweeper's) producer end. Owned by one thread:
/// `Send` but not `Sync` (PERF-004), so two threads can never push to the
/// same single-producer ring through a shared reference.
#[derive(Debug)]
pub struct ReplProducer {
    ring: Arc<Ring>,
    /// Last observed consumer position (owner thread only; `Cell` makes
    /// the type `!Sync`).
    head_cache: Cell<u64>,
    hub: Arc<ReplHub>,
}

impl ReplHub {
    /// `producers` rings (workers plus one for the sweeper) of `entries`
    /// records each (rounded up to a power of two), preallocated; `slices`
    /// sizes the dirty bitmap.
    pub fn new(producers: usize, entries: usize, slices: usize) -> (Arc<Self>, Vec<ReplProducer>) {
        let rings: Vec<Arc<Ring>> = (0..producers).map(|_| Arc::new(Ring::new(entries))).collect();
        let hub = Arc::new(Self {
            rings: rings.clone(),
            dirty: (0..slices.div_ceil(64).max(1)).map(|_| AtomicU64::new(0)).collect(),
            dir_dirty: AtomicBool::new(false),
            next: AtomicU32::new(0),
        });
        let prods =
            rings.into_iter().map(|ring| ReplProducer { ring, head_cache: Cell::new(0), hub: hub.clone() }).collect();
        (hub, prods)
    }

    /// Moves up to `max` records into `out`, taking a batch from every ring
    /// in turn so one busy worker cannot starve the others. Records from
    /// one ring keep their order.
    pub fn drain(&self, max: usize, out: &mut Vec<ReplRecord>) -> usize {
        let n = self.rings.len();
        if n == 0 {
            return 0;
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed) as usize;
        let share = max.div_ceil(n).max(1);
        let mut got = 0;
        for i in 0..n {
            if got >= max {
                break;
            }
            if let Some(r) = self.rings.get((start + i) % n) {
                got += r.pop_into(share.min(max - got), out);
            }
        }
        got
    }

    /// Records waiting in all rings.
    pub fn backlog(&self) -> usize {
        self.rings.iter().map(|r| r.len()).sum()
    }

    /// Takes (and clears) the dirty slices.
    pub fn take_dirty(&self) -> Vec<SliceId> {
        let mut out = Vec::new();
        for (w, word) in self.dirty.iter().enumerate() {
            let mut bits = word.swap(0, Ordering::AcqRel);
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                out.push((w * 64 + b) as SliceId);
            }
        }
        out
    }

    /// Marks slice `s` for resync (also used by the replicator itself when
    /// a peer queue overflows).
    pub fn mark_dirty(&self, s: SliceId) {
        if let Some(w) = self.dirty.get(usize::from(s) / 64) {
            w.fetch_or(1 << (usize::from(s) % 64), Ordering::AcqRel);
        }
    }

    /// Takes (and clears) the directory-loss flag.
    pub fn take_dir_dirty(&self) -> bool {
        self.dir_dirty.swap(false, Ordering::AcqRel)
    }

    /// Records accepted by all rings since start.
    pub fn pushed_total(&self) -> u64 {
        self.rings.iter().map(|r| r.tail.load(Ordering::Relaxed)).sum()
    }

    /// Records dropped on a full ring since start
    /// (`plat_cluster_repl_dropped_total{reason="ring"}`).
    pub fn dropped_total(&self) -> u64 {
        self.rings.iter().map(|r| r.dropped.load(Ordering::Relaxed)).sum()
    }
}

impl ReplProducer {
    /// Queues `rec` without blocking, locking or allocating. On a full ring
    /// the record is dropped, counted, and its slice (or the directory)
    /// marked for resync. Returns whether it was queued.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - a slow replicator or peer never stalls a worker
    /// - NIST 800-53: SI-4 - loss is counted and repaired by resync
    #[inline]
    pub fn push(&self, rec: ReplRecord) -> bool {
        self.ring.push(&rec, &self.head_cache) || self.lost(rec)
    }

    #[cold]
    #[inline(never)]
    fn lost(&self, r: ReplRecord) -> bool {
        // Single writer: a plain read-modify-write is enough.
        let d = &self.ring.dropped;
        d.store(d.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        match r.slice() {
            Some(s) => self.hub.mark_dirty(s),
            None => self.hub.dir_dirty.store(true, Ordering::Release),
        }
        false
    }
}

/// Where a subscriber is homed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Home {
    pub node: MemberId,
    pub slice: SliceId,
}

/// Cluster subscriber directory: `sub → home` for subscribers homed on
/// other members. Its own shard set (a leaf in the lock order, after every
/// engine shard).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - at most `cap_per_member` entries per member, so a
///   peer cannot fill the table; refusals are counted
/// - NIST 800-53: AU-10 - a subscriber is homed (and attributed) on one
///   node; a mis-steered one is detected (`cluster.steering.mode`)
#[derive(Debug)]
pub struct Directory {
    map: Sharded<u128, Home>,
    per_member: Box<[AtomicU32]>,
    cap_per_member: u32,
    refused: AtomicU64,
}

impl Directory {
    pub fn new(shards: u32, cap_per_member: u32) -> Self {
        Self {
            map: Sharded::new(shards),
            per_member: (0..MAX_MEMBERS).map(|_| AtomicU32::new(0)).collect(),
            cap_per_member,
            refused: AtomicU64::new(0),
        }
    }

    /// Records `sub` as homed at `h`. Refused (and counted) when `h.node`
    /// already holds its cap or is not a valid member id.
    pub fn insert(&self, sub: u128, h: Home) -> bool {
        let Some(cnt) = self.per_member.get(usize::from(h.node)) else {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let mut g = self.map.lock(&sub);
        match g.get_mut(&sub) {
            Some(old) if old.node == h.node => {
                old.slice = h.slice;
                true
            }
            Some(old) => {
                if cnt.load(Ordering::Relaxed) >= self.cap_per_member {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                if let Some(c) = self.per_member.get(usize::from(old.node)) {
                    c.fetch_sub(1, Ordering::Relaxed);
                }
                cnt.fetch_add(1, Ordering::Relaxed);
                *old = h;
                true
            }
            None => {
                if cnt.load(Ordering::Relaxed) >= self.cap_per_member {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                cnt.fetch_add(1, Ordering::Relaxed);
                g.insert(sub, h);
                true
            }
        }
    }

    /// Removes `sub` if it is homed on `node`.
    pub fn remove(&self, sub: u128, node: MemberId) -> bool {
        let mut g = self.map.lock(&sub);
        if g.get(&sub).is_some_and(|h| h.node == node) {
            g.remove(&sub);
            if let Some(c) = self.per_member.get(usize::from(node)) {
                c.fetch_sub(1, Ordering::Relaxed);
            }
            return true;
        }
        false
    }

    /// One shard lock; called only when a subscriber is created.
    #[inline]
    pub fn home_of(&self, sub: u128) -> Option<Home> {
        self.map.lock(&sub).get(&sub).copied()
    }

    /// Re-homes every subscriber of `slice` to `node` (after a takeover);
    /// entries homed on `except` (normally this node) are removed instead.
    /// Off path; walks every shard.
    pub fn rehome_slice(&self, slice: SliceId, node: MemberId, except: MemberId) -> usize {
        let mut n = 0;
        for i in 0..self.map.shard_count() {
            let mut g = self.map.lock_index(i);
            g.retain(|_, h| {
                if h.slice != slice || h.node == node {
                    return true;
                }
                n += 1;
                if let Some(c) = self.per_member.get(usize::from(h.node)) {
                    c.fetch_sub(1, Ordering::Relaxed);
                }
                if node == except {
                    return false;
                }
                if let Some(c) = self.per_member.get(usize::from(node)) {
                    c.fetch_add(1, Ordering::Relaxed);
                }
                h.node = node;
                true
            });
        }
        n
    }

    /// Drops every entry of `node` (full resync from that member).
    pub fn clear_member(&self, node: MemberId) -> usize {
        let mut n = 0;
        for i in 0..self.map.shard_count() {
            let mut g = self.map.lock_index(i);
            g.retain(|_, h| {
                let keep = h.node != node;
                n += usize::from(!keep);
                keep
            });
        }
        if let Some(c) = self.per_member.get(usize::from(node)) {
            c.store(0, Ordering::Relaxed);
        }
        n
    }

    /// Entries (`plat_cluster_directory_entries`).
    pub fn len(&self) -> u64 {
        self.per_member.iter().map(|c| u64::from(c.load(Ordering::Relaxed))).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inserts refused by the per-member cap.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }
}

/// A replicated record the backup refused (it does not fit the slice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowError {
    /// Slice id out of range.
    Slice,
    /// Address outside the slice, or block/port outside the port range.
    Range,
    /// Protocol other than ICMP/TCP/UDP.
    Proto,
    /// The shadow BIB store is full.
    Full,
}

/// What a new owner imports on takeover (from [`Shadow::take`]).
#[derive(Debug, Clone, Default)]
pub struct AdoptInput {
    /// `(sub, block, original allocation time)`.
    pub blocks: Vec<(u128, WireBlock, u64)>,
    pub bibs: Vec<WireBib>,
    /// Reserved with the backup but never seen allocated: held back for
    /// `takeover_quarantine_secs`.
    pub reserved_unseen: Vec<WireBlock>,
    /// Released by the old owner `age_ms` ago: finish the cool-down.
    pub released: Vec<(WireBlock, u64)>,
    /// The shadow was complete (snapshot plus an unbroken stream).
    pub in_sync: bool,
    /// Hold back every block that is not adopted (the old owner's state is
    /// not known completely).
    pub hold_unknown: bool,
}

#[derive(Debug)]
struct ShadowSlice {
    blocks: Map<(u32, u16), (u128, u64)>,
    reserved: HashSet<(u32, u16), RandomState>,
    released: Map<(u32, u16), u64>,
    bibs: Map<(u8, u32, u16), WireBib>,
    in_sync: bool,
}

impl ShadowSlice {
    fn new() -> Self {
        Self {
            blocks: Map::with_hasher(RandomState::new()),
            reserved: HashSet::with_hasher(RandomState::new()),
            released: Map::with_hasher(RandomState::new()),
            bibs: Map::with_hasher(RandomState::new()),
            in_sync: false,
        }
    }
}

/// The backup's copy of the port blocks and BIBs of slices it protects.
/// Off the packet path (replicator / control threads only).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - records are validated against the slice (address,
///   block and port range, protocol); blocks are bounded by the slice size
///   and BIBs by `max_bibs`
/// - NIST 800-53: SI-10 - malformed replication input is refused
#[derive(Debug)]
pub struct Shadow {
    map: SliceMap,
    port_min: u16,
    block_size: u16,
    blocks_per_addr: u16,
    cooldown_ms: u64,
    slices: Box<[Mutex<ShadowSlice>]>,
    bibs: AtomicU64,
    max_bibs: u64,
}

impl Shadow {
    pub fn new(map: SliceMap, port_min: u16, port_max: u16, block_size: u16, cooldown_ms: u64, max_bibs: u64) -> Self {
        let range = (u32::from(port_max) + 1).saturating_sub(u32::from(port_min));
        let bpa = (range / u32::from(block_size.max(1))).min(u32::from(u16::MAX)) as u16;
        let slices = (0..map.len()).map(|_| Mutex::new(ShadowSlice::new())).collect();
        Self {
            map,
            port_min,
            block_size: block_size.max(1),
            blocks_per_addr: bpa,
            cooldown_ms,
            slices,
            bibs: AtomicU64::new(0),
            max_bibs,
        }
    }

    fn in_slice(&self, slice: SliceId, addr: u32) -> bool {
        self.map.slice_of(addr) == Some(slice)
    }

    fn check_block(&self, slice: SliceId, b: WireBlock) -> Result<(), ShadowError> {
        if !self.in_slice(slice, b.addr) || b.block >= self.blocks_per_addr {
            return Err(ShadowError::Range);
        }
        Ok(())
    }

    fn check_bib(&self, slice: SliceId, b: &WireBib) -> Result<(), ShadowError> {
        if !matches!(b.proto, proto::TCP | proto::UDP | proto::ICMP) {
            return Err(ShadowError::Proto);
        }
        let hi = u32::from(self.port_min) + u32::from(self.blocks_per_addr) * u32::from(self.block_size);
        if !self.in_slice(slice, b.v4) || b.port4 < self.port_min || u32::from(b.port4) >= hi {
            return Err(ShadowError::Range);
        }
        Ok(())
    }

    fn slice(&self, s: SliceId) -> Result<&Mutex<ShadowSlice>, ShadowError> {
        self.slices.get(usize::from(s)).ok_or(ShadowError::Slice)
    }

    /// Applies one streamed record. Directory records are ignored here
    /// (they go to [`Directory`]).
    pub fn apply(&self, rec: &ReplRecord, now_ms: u64) -> Result<(), ShadowError> {
        match *rec {
            ReplRecord::BlockAlloc { slice, sub, block, wall_us } => {
                self.check_block(slice, block)?;
                let mut g = self.slice(slice)?.lock();
                let k = (block.addr, block.block);
                g.reserved.remove(&k);
                g.released.remove(&k);
                g.blocks.insert(k, (sub, wall_us));
            }
            ReplRecord::BlockRelease { slice, block, .. } => {
                self.check_block(slice, block)?;
                let mut g = self.slice(slice)?.lock();
                let k = (block.addr, block.block);
                g.blocks.remove(&k);
                g.released.insert(k, now_ms);
            }
            ReplRecord::BibCreate { slice, bib } => {
                self.check_bib(slice, &bib)?;
                let mut g = self.slice(slice)?.lock();
                let k = (bib.proto, bib.v4, bib.port4);
                if !g.bibs.contains_key(&k) {
                    if self.bibs.load(Ordering::Relaxed) >= self.max_bibs {
                        return Err(ShadowError::Full);
                    }
                    self.bibs.fetch_add(1, Ordering::Relaxed);
                }
                g.bibs.insert(k, bib);
            }
            ReplRecord::BibDelete { slice, proto, v4, port4 } => {
                let mut g = self.slice(slice)?.lock();
                if g.bibs.remove(&(proto, v4, port4)).is_some() {
                    self.bibs.fetch_sub(1, Ordering::Relaxed);
                }
            }
            ReplRecord::SubHome { .. } | ReplRecord::SubGone { .. } => {}
        }
        Ok(())
    }

    /// The primary reserved `blocks` (before handing them out); the
    /// replicator acks the `Reserve` after this returns `Ok`.
    pub fn reserve(&self, slice: SliceId, blocks: &[WireBlock]) -> Result<(), ShadowError> {
        for b in blocks {
            self.check_block(slice, *b)?;
        }
        let mut g = self.slice(slice)?.lock();
        for b in blocks {
            let k = (b.addr, b.block);
            if !g.blocks.contains_key(&k) {
                g.reserved.insert(k);
            }
        }
        Ok(())
    }

    /// Starts a full resync of `slice`: drops its contents, not in sync.
    pub fn snapshot_begin(&self, slice: SliceId) -> Result<(), ShadowError> {
        let mut g = self.slice(slice)?.lock();
        self.bibs.fetch_sub(g.bibs.len() as u64, Ordering::Relaxed);
        *g = ShadowSlice::new();
        Ok(())
    }

    /// Applies snapshot records. Each record is validated; the first
    /// invalid one aborts the chunk (the peer is misbehaving).
    pub fn snapshot_records(&self, slice: SliceId, recs: &[SnapRecord]) -> Result<(), ShadowError> {
        for r in recs {
            match *r {
                SnapRecord::Block { sub, block, alloc_wall_us } => {
                    self.apply(&ReplRecord::BlockAlloc { slice, sub, block, wall_us: alloc_wall_us }, 0)?
                }
                SnapRecord::Bib(bib) => self.apply(&ReplRecord::BibCreate { slice, bib }, 0)?,
            }
        }
        Ok(())
    }

    /// The snapshot is complete: the slice is in sync from now on.
    pub fn snapshot_end(&self, slice: SliceId) -> Result<(), ShadowError> {
        self.slice(slice)?.lock().in_sync = true;
        Ok(())
    }

    /// A gap in the stream (sequence jump or overflow): not in sync until
    /// the next snapshot completes.
    pub fn mark_gap(&self, slice: SliceId) {
        if let Ok(m) = self.slice(slice) {
            m.lock().in_sync = false;
        }
    }

    /// Eligible for takeover (snapshot complete, stream unbroken).
    pub fn in_sync(&self, slice: SliceId) -> bool {
        self.slice(slice).is_ok_and(|m| m.lock().in_sync)
    }

    /// `(blocks, bibs)` held for `slice`.
    pub fn counts(&self, slice: SliceId) -> (usize, usize) {
        self.slice(slice).map_or((0, 0), |m| {
            let g = m.lock();
            (g.blocks.len(), g.bibs.len())
        })
    }

    /// Forgets `slice` (no longer a backup for it).
    pub fn clear(&self, slice: SliceId) {
        let _ = self.snapshot_begin(slice);
    }

    /// Takes the state of `slice` for adoption and clears it. Releases
    /// older than the cool-down are dropped.
    pub fn take(&self, slice: SliceId, now_ms: u64) -> AdoptInput {
        let Ok(m) = self.slice(slice) else { return AdoptInput::default() };
        let mut g = m.lock();
        let s = std::mem::replace(&mut *g, ShadowSlice::new());
        drop(g);
        self.bibs.fetch_sub(s.bibs.len() as u64, Ordering::Relaxed);
        let mut blocks: Vec<_> =
            s.blocks.iter().map(|(&(addr, block), &(sub, wall))| (sub, WireBlock { addr, block }, wall)).collect();
        blocks.sort_unstable_by_key(|b| (b.1.addr, b.1.block));
        let mut bibs: Vec<_> = s.bibs.into_values().collect();
        bibs.sort_unstable_by_key(|b| (b.v4, b.port4, b.proto));
        let mut reserved_unseen: Vec<_> = s.reserved.iter().map(|&(addr, block)| WireBlock { addr, block }).collect();
        reserved_unseen.sort_unstable_by_key(|b| (b.addr, b.block));
        let released = s
            .released
            .iter()
            .filter_map(|(&(addr, block), &t)| {
                let age = now_ms.saturating_sub(t);
                (age < self.cooldown_ms).then_some((WireBlock { addr, block }, age))
            })
            .collect();
        AdoptInput { blocks, bibs, reserved_unseen, released, in_sync: s.in_sync, hold_unknown: !s.in_sync }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plat_common::Ipv4Cidr;

    #[test]
    fn ring_overflow_marks_dirty() {
        let (hub, prods) = ReplHub::new(2, 2, 100);
        let r = ReplRecord::BibDelete { slice: 70, proto: 17, v4: 1, port4: 2 };
        assert!(prods[0].push(r) && prods[0].push(r));
        assert!(!prods[0].push(r), "full ring drops");
        assert!(!prods[0].push(ReplRecord::SubGone { sub: 1 }));
        assert!(prods[1].push(r), "other rings are independent");
        assert_eq!((hub.pushed_total(), hub.dropped_total(), hub.backlog()), (3, 2, 3));
        assert_eq!(hub.take_dirty(), vec![70]);
        assert!(hub.take_dirty().is_empty());
        assert!(hub.take_dir_dirty() && !hub.take_dir_dirty());
        let mut out = Vec::new();
        assert_eq!(hub.drain(10, &mut out), 3);
        assert_eq!(ReplRecord::from_msg(&r.to_msg(9)), Some((r, 9)));
    }

    #[test]
    fn ring_records_round_trip() {
        let (hub, prods) = ReplHub::new(1, 8, 4);
        let bib = WireBib {
            sub: u128::MAX - 1,
            proto: 6,
            v6: u128::MAX - 2,
            port6: 65535,
            v4: u32::MAX,
            port4: 65534,
            created_wall_us: u64::MAX,
        };
        let block = WireBlock { addr: u32::MAX, block: u16::MAX };
        let recs = [
            ReplRecord::BlockAlloc { slice: 4095, sub: u128::MAX, block, wall_us: u64::MAX },
            ReplRecord::BlockRelease { slice: 1, sub: 3 << 100, block },
            ReplRecord::BibCreate { slice: 2, bib },
            ReplRecord::BibDelete { slice: 3, proto: 17, v4: u32::MAX, port4: 65535 },
            ReplRecord::SubHome { sub: u128::MAX, slice: 4095 },
            ReplRecord::SubGone { sub: 1 << 127 },
        ];
        for _ in 0..3 {
            for r in &recs {
                assert!(prods[0].push(*r));
            }
            let mut out = Vec::new();
            assert_eq!(hub.drain(100, &mut out), recs.len());
            assert_eq!(out, recs, "wraps the ring");
        }
        assert_eq!(hub.pushed_total(), 18);
    }

    #[test]
    fn directory_caps_and_rehome() {
        let d = Directory::new(4, 2);
        assert!(d.insert(1, Home { node: 1, slice: 0 }));
        assert!(d.insert(2, Home { node: 1, slice: 1 }));
        assert!(!d.insert(3, Home { node: 1, slice: 0 }), "cap per member");
        assert!(!d.insert(3, Home { node: 999, slice: 0 }));
        assert_eq!(d.refused(), 2);
        assert_eq!(d.rehome_slice(0, 2, 0), 1);
        assert_eq!(d.home_of(1), Some(Home { node: 2, slice: 0 }));
        assert_eq!(d.rehome_slice(0, 0, 0), 1, "rehomed to self: removed");
        assert_eq!(d.home_of(1), None);
        assert!(!d.remove(2, 2));
        assert!(d.remove(2, 1));
        assert!(d.is_empty());
    }

    #[test]
    fn shadow_validates_and_takes() {
        let m = SliceMap::new(&[Ipv4Cidr::new([10, 0, 0, 0].into(), 30).unwrap()], 31).unwrap();
        let sh = Shadow::new(m, 1024, 1024 + 2 * 64 - 1, 64, 120_000, 1);
        let b = WireBlock { addr: 0x0a00_0000, block: 1 };
        assert_eq!(sh.reserve(1, &[b]), Err(ShadowError::Range), "address in slice 0");
        assert_eq!(sh.reserve(0, &[WireBlock { addr: 0x0a00_0000, block: 2 }]), Err(ShadowError::Range));
        sh.reserve(0, &[b, WireBlock { addr: 0x0a00_0001, block: 0 }]).unwrap();
        sh.apply(&ReplRecord::BlockAlloc { slice: 0, sub: 7, block: b, wall_us: 5 }, 0).unwrap();
        let bib = WireBib { sub: 7, proto: 6, v6: 9, port6: 80, v4: 0x0a00_0000, port4: 1100, created_wall_us: 6 };
        assert_eq!(
            sh.apply(&ReplRecord::BibCreate { slice: 0, bib: WireBib { proto: 2, ..bib } }, 0),
            Err(ShadowError::Proto)
        );
        assert_eq!(
            sh.apply(&ReplRecord::BibCreate { slice: 0, bib: WireBib { port4: 1000, ..bib } }, 0),
            Err(ShadowError::Range)
        );
        sh.apply(&ReplRecord::BibCreate { slice: 0, bib }, 0).unwrap();
        assert_eq!(
            sh.apply(&ReplRecord::BibCreate { slice: 0, bib: WireBib { port4: 1101, ..bib } }, 0),
            Err(ShadowError::Full)
        );
        let gone = WireBlock { addr: 0x0a00_0001, block: 1 };
        sh.apply(&ReplRecord::BlockRelease { slice: 0, sub: 8, block: gone }, 1_000).unwrap();
        assert_eq!(sh.counts(0), (1, 1));
        assert!(!sh.in_sync(0));
        sh.snapshot_end(0).unwrap();
        let a = sh.take(0, 31_000);
        assert!(a.in_sync && !a.hold_unknown);
        assert_eq!(a.blocks, vec![(7, b, 5)]);
        assert_eq!(a.bibs, vec![bib]);
        assert_eq!(a.reserved_unseen, vec![WireBlock { addr: 0x0a00_0001, block: 0 }]);
        assert_eq!(a.released, vec![(gone, 30_000)]);
        assert_eq!(sh.counts(0), (0, 0));
        sh.apply(&ReplRecord::BibCreate { slice: 0, bib }, 0).unwrap();
    }
}
