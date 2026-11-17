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
//!   an [`AdoptInput`] on takeover. With session hints it also keeps, per
//!   TCP BIB, up to [`MAX_HINTS`] remotes the primary had an ESTABLISHED
//!   session with, and with `session_hints = "tcp_udp"` per UDP BIB the
//!   remotes of its hinted (aged, bidirectional) sessions (POAM-028).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - every ring, the
//!   directory and the shadow store are bounded; loss is counted, never
//!   back-pressure on a worker
//! - NIST 800-53: CP-10 (System Recovery and Reconstitution), AU-10 - block
//!   and BIB state survives the loss of the slice owner

use std::cell::Cell;
use std::collections::{HashSet, hash_map};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use ahash::RandomState;
use crossbeam_utils::CachePadded;
use parking_lot::Mutex;
use plat_cluster::{
    MAX_MEMBERS, MemberId, Msg, PROTO_TCP, PROTO_UDP, SliceId, SliceMap, SnapRecord, WireBib, WireBlock, WireHint,
};
use plat_packet::proto;

use crate::shard::{Map, Sharded};

/// One replicated state change. `Copy`, at most 64 bytes of payload, so a
/// ring slot never owns heap memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplRecord {
    BlockAlloc {
        slice: SliceId,
        sub: u128,
        block: WireBlock,
        wall_us: u64,
    },
    BlockRelease {
        slice: SliceId,
        sub: u128,
        block: WireBlock,
    },
    BibCreate {
        slice: SliceId,
        bib: WireBib,
    },
    BibDelete {
        slice: SliceId,
        proto: u8,
        v4: u32,
        port4: u16,
    },
    SubHome {
        sub: u128,
        slice: SliceId,
    },
    SubGone {
        sub: u128,
    },
    /// A TCP session on the BIB `(TCP, v4, port4)` reached ESTABLISHED
    /// (once per connection), or a UDP session on `(UDP, v4, port4)` became
    /// eligible or is re-hinted (at most once per `udp_secs`). There is no
    /// delete record: a hint dies with its BIB. `proto` is TCP or UDP.
    SessHint {
        slice: SliceId,
        proto: u8,
        v4: u32,
        port4: u16,
        raddr: u32,
        rport: u16,
    },
}

impl ReplRecord {
    /// The slice the record belongs to (`None` for directory records, which
    /// go to every peer).
    pub fn slice(&self) -> Option<SliceId> {
        match *self {
            Self::BlockAlloc { slice, .. }
            | Self::BlockRelease { slice, .. }
            | Self::BibCreate { slice, .. }
            | Self::BibDelete { slice, .. }
            | Self::SessHint { slice, .. } => Some(slice),
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
            Self::SessHint { slice, proto, v4, port4, raddr, rport } => {
                Msg::SessHint { slice, seq, hint: WireHint { proto, v4, port4, raddr, rport } }
            }
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
            // The codec refuses any protocol other than TCP and UDP.
            Msg::SessHint { slice, seq, hint } => (
                Self::SessHint {
                    slice,
                    proto: hint.proto,
                    v4: hint.v4,
                    port4: hint.port4,
                    raddr: hint.raddr,
                    rport: hint.rport,
                },
                seq,
            ),
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
    /// UDP hints deferred by the producer's bucket, and accepted by it
    /// (producer-owned, written only on the cold UDP hint path).
    udp_deferred: CachePadded<AtomicU64>,
    udp_pushed: CachePadded<AtomicU64>,
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
const T_HINT: u64 = 7;

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
            Self::SessHint { slice, proto, v4, port4, raddr, rport } => {
                put(
                    0,
                    T_HINT
                        | u64::from(slice) << 8
                        | u64::from(port4) << 24
                        | u64::from(rport) << 40
                        | u64::from(proto) << 56,
                );
                put(1, u64::from(v4) | u64::from(raddr) << 32);
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
            T_HINT => {
                let w1 = g(1);
                let h = Self::SessHint {
                    slice: (w0 >> 8) as u16,
                    proto: (w0 >> 56) as u8,
                    v4: w1 as u32,
                    port4: (w0 >> 24) as u16,
                    raddr: (w1 >> 32) as u32,
                    rport: (w0 >> 40) as u16,
                };
                // A zero field never comes from a real session.
                match h {
                    Self::SessHint { v4: 0, .. }
                    | Self::SessHint { port4: 0, .. }
                    | Self::SessHint { raddr: 0, .. }
                    | Self::SessHint { rport: 0, .. } => return None,
                    Self::SessHint { proto: PROTO_TCP | PROTO_UDP, .. } => h,
                    _ => return None,
                }
            }
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
            udp_deferred: CachePadded::new(AtomicU64::new(0)),
            udp_pushed: CachePadded::new(AtomicU64::new(0)),
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

    /// Pops up to `max` records. A session hint at or past `hint_cut` (a
    /// tail read before this call) stops the pop and stays queued, with
    /// everything after it ([`ReplHub::drain`]).
    fn pop_into(&self, max: usize, out: &mut Vec<ReplRecord>, hint_cut: u64) -> usize {
        let _c = self.consumer.lock();
        let h = self.head.load(Ordering::Relaxed);
        let t = self.tail.load(Ordering::Acquire);
        let n = (t.wrapping_sub(h)).min(max as u64);
        let mut taken = 0;
        while taken < n {
            let at = h.wrapping_add(taken);
            let r = self.slots.get((at & self.mask) as usize).and_then(|s| ReplRecord::decode(&s.0));
            if matches!(r, Some(ReplRecord::SessHint { .. })) && at.wrapping_sub(hint_cut) < 1 << 63 {
                break;
            }
            if let Some(r) = r {
                out.push(r);
            }
            taken += 1;
        }
        self.head.store(h.wrapping_add(taken), Ordering::Release);
        taken as usize
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
    /// Reorder scratch of `drain` (single consumer; grows once to the
    /// largest `max` asked for, then is reused).
    scratch: Mutex<DrainScratch>,
    /// Hints dropped by `drain` because their BIB was deleted later in the
    /// same batch.
    hints_superseded: AtomicU64,
    /// Drains that may have left records behind (a ring gave its full
    /// share, or the limit stopped the round): only these can split a
    /// `BibCreate` from its hint.
    drains_truncated: AtomicU64,
}

/// Reused buffers of [`ReplHub::drain`]'s hint reordering.
#[derive(Debug, Default)]
struct DrainScratch {
    /// Hints of the batch with their drain position.
    hints: Vec<(usize, ReplRecord)>,
    /// `(slice, proto, v4, port4, position)` of every TCP or UDP
    /// `BibDelete` in the batch.
    dels: Vec<(SliceId, u8, u32, u16, usize)>,
    /// Per-ring tail read before the pops: the hint cut.
    cuts: Vec<u64>,
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
    /// UDP hint token bucket (owner thread only): tokens, the fraction of
    /// a token carried over (thousandths), last refill (engine ms), and
    /// the rate (`cluster.ha.udp_hints_per_sec`, also the burst).
    udp_tokens: Cell<u32>,
    udp_credit: Cell<u64>,
    udp_refill_ms: Cell<u64>,
    udp_rate: u32,
}

/// Default `cluster.ha.udp_hints_per_sec` ([`ReplHub::new`]).
pub const DEFAULT_UDP_HINTS_PER_SEC: u32 = 2000;

impl ReplHub {
    /// `producers` rings (workers plus one for the sweeper) of `entries`
    /// records each (rounded up to a power of two), preallocated; `slices`
    /// sizes the dirty bitmap. UDP hints use [`DEFAULT_UDP_HINTS_PER_SEC`].
    pub fn new(producers: usize, entries: usize, slices: usize) -> (Arc<Self>, Vec<ReplProducer>) {
        Self::with_udp_hint_rate(producers, entries, slices, DEFAULT_UDP_HINTS_PER_SEC)
    }

    /// [`Self::new`] with `udp_hints_per_sec` UDP hints per second per
    /// producer (burst one second; at least 1).
    pub fn with_udp_hint_rate(
        producers: usize,
        entries: usize,
        slices: usize,
        udp_hints_per_sec: u32,
    ) -> (Arc<Self>, Vec<ReplProducer>) {
        let rate = udp_hints_per_sec.max(1);
        let rings: Vec<Arc<Ring>> = (0..producers).map(|_| Arc::new(Ring::new(entries))).collect();
        let hub = Arc::new(Self {
            rings: rings.clone(),
            dirty: (0..slices.div_ceil(64).max(1)).map(|_| AtomicU64::new(0)).collect(),
            dir_dirty: AtomicBool::new(false),
            next: AtomicU32::new(0),
            scratch: Mutex::new(DrainScratch::default()),
            hints_superseded: AtomicU64::new(0),
            drains_truncated: AtomicU64::new(0),
        });
        let prods = rings
            .into_iter()
            .map(|ring| ReplProducer {
                ring,
                head_cache: Cell::new(0),
                hub: hub.clone(),
                udp_tokens: Cell::new(rate),
                udp_credit: Cell::new(0),
                udp_refill_ms: Cell::new(0),
                udp_rate: rate,
            })
            .collect();
        (hub, prods)
    }

    /// Moves up to `max` records into `out`, taking a batch from every ring
    /// in turn so one busy worker cannot starve the others. Records from
    /// one ring keep their order, except that the batch's session hints
    /// follow every BIB record of the batch ([`Self::hints_last`]).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - no allocation beyond `max` records of reused
    ///   scratch; CP-10 - a hint whose `BibCreate` sits on another ring of
    ///   the same drain is no longer refused `no_bib` (decision Q1 revised)
    pub fn drain(&self, max: usize, out: &mut Vec<ReplRecord>) -> usize {
        self.drain_rounds(max, 1, out)
    }

    /// [`Self::drain`] that repeats the round, up to `rounds` times, while
    /// the previous round stopped at a ring's share or at `max` (PERF-002):
    /// a `BibCreate` left behind by a cut round is then taken before the
    /// batch's hints are reordered behind it, so only a burst of more than
    /// `rounds × max` records can still split a hint from its BIB. One
    /// reorder runs over the whole batch. Returns the records moved.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - at most `rounds × max` records per call; the
    ///   scratch grows once to that and is reused
    /// - NIST 800-53: CP-10 - fewer hints refused `no_bib` under load
    ///   (slices stay hinted)
    pub fn drain_rounds(&self, max: usize, rounds: usize, out: &mut Vec<ReplRecord>) -> usize {
        let from = out.len();
        let mut g = self.scratch.lock();
        let mut got = 0;
        let mut cut = false;
        for _ in 0..rounds.max(1) {
            let (k, c) = self.drain_rings(max, out, &mut g.cuts);
            got += k;
            cut = c;
            if !c {
                break;
            }
        }
        if cut {
            self.drains_truncated.fetch_add(1, Ordering::Relaxed);
        }
        self.hints_last(out, from, &mut g);
        got
    }

    /// One round over the rings. Every tail is read first (`cuts`), then
    /// the rings are popped; hints are taken only below their ring's cut.
    /// A hint below its cut was pushed before the last cut was read, so
    /// its `BibCreate` (pushed before the hint, on any ring) is below the
    /// tail that ring's pop reads afterwards: it is in this batch unless
    /// the share or `max` stopped that ring first.
    fn drain_rings(&self, max: usize, out: &mut Vec<ReplRecord>, cuts: &mut Vec<u64>) -> (usize, bool) {
        let n = self.rings.len();
        if n == 0 {
            return (0, false);
        }
        cuts.clear();
        cuts.extend(self.rings.iter().map(|r| r.tail.load(Ordering::Acquire)));
        let start = self.next.fetch_add(1, Ordering::Relaxed) as usize;
        let share = max.div_ceil(n).max(1);
        let (mut got, mut cut) = (0, false);
        for i in 0..n {
            if got >= max {
                cut = true;
                break;
            }
            if let Some(r) = self.rings.get((start + i) % n) {
                let cap = share.min(max - got);
                let k = r.pop_into(cap, out, cuts.get((start + i) % n).copied().unwrap_or(0));
                cut |= k == cap;
                got += k;
            }
        }
        (got, cut)
    }

    /// Moves the session hints of `out[from..]` behind every other record,
    /// keeping their relative order, so a hint follows its `BibCreate` even
    /// when the two came from different rings (SYN and SYN/ACK on different
    /// workers). Other records keep their drain order. Moving a hint can
    /// only pass records drained after it; the one such record that
    /// matters is a `BibDelete` of the hint's BIB (no other record removes a
    /// shadow BIB): a hint drained before a delete of `(TCP, v4, port4)` in
    /// the same batch is dropped, because sent after the delete it would
    /// be refused `no_bib` (gapping the slice), or after a re-create
    /// attach a remote of the old mapping to the new one. Dropping it is
    /// what the shadow does anyway: a hint dies with its BIB (counted
    /// [`Self::hints_superseded`]). A hint drained after the delete (a
    /// re-created BIB) is kept. With the tail cut of [`Self::drain_rings`]
    /// the batch holds every `BibCreate` of its hints, except one left in
    /// its ring because the share or `max` stopped that ring
    /// ([`Self::drains_truncated`]); that hint is refused `no_bib` and the
    /// slice resyncs (`mark_gap`, POAM-028).
    fn hints_last(&self, out: &mut Vec<ReplRecord>, from: usize, scratch: &mut DrainScratch) {
        let Some(batch) = out.get(from..) else { return };
        if !batch.iter().any(|r| matches!(r, ReplRecord::SessHint { .. })) {
            return;
        }
        let DrainScratch { hints, dels, .. } = scratch;
        hints.clear();
        dels.clear();
        let mut w = from;
        for i in from..out.len() {
            let Some(&r) = out.get(i) else { break };
            match r {
                ReplRecord::SessHint { .. } => {
                    hints.push((i, r));
                    continue;
                }
                ReplRecord::BibDelete { slice, proto: p @ (proto::TCP | proto::UDP), v4, port4 } => {
                    dels.push((slice, p, v4, port4, i))
                }
                _ => {}
            }
            if let Some(slot) = out.get_mut(w) {
                *slot = r;
            }
            w += 1;
        }
        out.truncate(w);
        // Last delete position per BIB: the final element of each key run.
        dels.sort_unstable();
        for &(pos, h) in hints.iter() {
            if let ReplRecord::SessHint { slice, proto: p, v4, port4, .. } = h {
                let key = (slice, p, v4, port4);
                let end = dels.partition_point(|d| (d.0, d.1, d.2, d.3) <= key);
                let deleted_later = end
                    .checked_sub(1)
                    .and_then(|j| dels.get(j))
                    .is_some_and(|d| (d.0, d.1, d.2, d.3) == key && d.4 > pos);
                if deleted_later {
                    self.hints_superseded.fetch_add(1, Ordering::Relaxed);
                } else {
                    out.push(h);
                }
            }
        }
    }

    /// Hints dropped by [`Self::drain`] because a later record of the same
    /// batch deleted their BIB.
    pub fn hints_superseded(&self) -> u64 {
        self.hints_superseded.load(Ordering::Relaxed)
    }

    /// Drains whose last round stopped at a ring's share or at `max`
    /// (conservative: a ring that held exactly its share counts).
    pub fn drains_truncated(&self) -> u64 {
        self.drains_truncated.load(Ordering::Relaxed)
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

    /// UDP hints a producer's bucket deferred to a later packet
    /// (`plat_cluster_udp_hints_deferred_total`).
    pub fn udp_hints_deferred(&self) -> u64 {
        self.rings.iter().map(|r| r.udp_deferred.load(Ordering::Relaxed)).sum()
    }

    /// UDP hints accepted by the buckets (queued, or lost on a full ring
    /// and repaired by resync).
    pub fn udp_hints_pushed(&self) -> u64 {
        self.rings.iter().map(|r| r.udp_pushed.load(Ordering::Relaxed)).sum()
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

    /// Refills the UDP hint bucket to engine time `now_ms` and returns
    /// whether it holds a token, counting a deferral when it does not.
    /// Callers check this before building the hint, so an empty bucket
    /// costs no lookup; [`Self::push_udp_hint`] then takes the token.
    /// Fractions of a token carry over, so any rate is delivered exactly;
    /// a clock that goes backwards adds nothing.
    #[inline]
    pub fn udp_hint_ready(&self, now_ms: u64) -> bool {
        let last = self.udp_refill_ms.get();
        if now_ms > last {
            self.udp_refill_ms.set(now_ms);
            let rate = u64::from(self.udp_rate);
            let credit = self.udp_credit.get().saturating_add((now_ms - last).saturating_mul(rate));
            let t = u64::from(self.udp_tokens.get()).saturating_add(credit / 1000);
            if t >= rate {
                self.udp_tokens.set(self.udp_rate);
                self.udp_credit.set(0);
            } else {
                self.udp_tokens.set(t as u32);
                self.udp_credit.set(credit % 1000);
            }
        }
        if self.udp_tokens.get() == 0 {
            let d = &self.ring.udp_deferred;
            d.store(d.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Queues a UDP session hint if the producer's token bucket has a
    /// token (refilled at `udp_hints_per_sec` from engine time `now_ms`).
    /// Returns false when the bucket is empty (deferred, counted): the
    /// caller keeps the hint pending and retries on a later packet. A hint
    /// lost on a full ring counts as sent (the slice resyncs).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - UDP churn cannot flood the ring or the peer
    ///   channel: at most `udp_hints_per_sec` (plus one second of burst)
    ///   hints per producer
    pub fn push_udp_hint(&self, rec: ReplRecord, now_ms: u64) -> bool {
        if !self.udp_hint_ready(now_ms) {
            return false;
        }
        let t = self.udp_tokens.get();
        self.udp_tokens.set(t - 1);
        let p = &self.ring.udp_pushed;
        p.store(p.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        self.push(rec);
        true
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
    /// A session hint for a BIB the shadow does not hold (it was lost, or
    /// the hint overtook its `BibCreate` from another worker ring). Not a
    /// peer fault: the replicator marks the slice gapped and resyncs.
    NoBib,
    /// A session hint with a zero address or port.
    Invalid,
}

/// Remotes kept per shadow TCP BIB (SC-5): a fifth replaces the oldest and
/// makes the BIB hint-incomplete ([`Hints::lossy`]).
pub const MAX_HINTS: usize = 4;

/// Session hints of one shadow TCP BIB: remote IPv4 `(address, port)`
/// pairs with the time each was learned (shadow clock, seconds), oldest
/// replaced first, duplicates refreshed. Stored inline in [`ShadowBib`]
/// (44 B, PERF-003): no allocation per hinted BIB.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hints {
    addr: [u32; MAX_HINTS],
    learned_s: [u32; MAX_HINTS],
    port: [u16; MAX_HINTS],
    n: u8,
    next: u8,
    lossy: bool,
}

impl Hints {
    /// Adds `remote` learned at `learned_s` (a duplicate only refreshes its
    /// time). At [`MAX_HINTS`] the oldest goes and the set is marked
    /// [`Self::lossy`]; returns whether a remote was evicted. Hints never
    /// retire on close, so every evicted remote may still be a live session
    /// (SEC-002).
    pub fn add(&mut self, remote: (u32, u16), learned_s: u32) -> bool {
        let n = usize::from(self.n).min(MAX_HINTS);
        let dup = (0..n).find(|&i| self.addr.get(i) == Some(&remote.0) && self.port.get(i) == Some(&remote.1));
        if let Some(i) = dup {
            if let Some(t) = self.learned_s.get_mut(i) {
                *t = (*t).max(learned_s);
            }
            return false;
        }
        let i = usize::from(self.next) % MAX_HINTS;
        let evicted = n == MAX_HINTS;
        if let (Some(a), Some(p), Some(t)) = (self.addr.get_mut(i), self.port.get_mut(i), self.learned_s.get_mut(i)) {
            (*a, *p, *t) = (remote.0, remote.1, learned_s);
        }
        self.next = ((i + 1) % MAX_HINTS) as u8;
        self.n = (n + 1).min(MAX_HINTS) as u8;
        self.lossy |= evicted;
        evicted
    }

    /// `(remote, learned_s)` of every hint, oldest slot first.
    pub fn iter(&self) -> impl Iterator<Item = ((u32, u16), u32)> + '_ {
        let n = usize::from(self.n).min(MAX_HINTS);
        self.addr.iter().zip(&self.port).zip(&self.learned_s).take(n).map(|((&a, &p), &t)| ((a, p), t))
    }

    pub fn len(&self) -> usize {
        usize::from(self.n).min(MAX_HINTS)
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The set may lack a live session of the BIB (a remote was evicted,
    /// or an abandoned adoption returned a BIB that was incomplete): the
    /// adopter allows pickup on this BIB even under strict mode.
    pub fn lossy(&self) -> bool {
        self.lossy
    }

    pub fn mark_lossy(&mut self) {
        self.lossy = true;
    }
}

/// Seconds of a millisecond clock reading, as stored in [`Hints`] (wraps
/// after 136 years).
pub fn hint_secs(ms: u64) -> u32 {
    (ms / 1000) as u32
}

/// One shadow BIB with its session hints (TCP only; `None` for every
/// un-hinted BIB). Inline: the hints cost [`SHADOW_BIB_HINT_BYTES`] per
/// shadow entry, hinted or not, and never allocate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowBib {
    pub bib: WireBib,
    pub hints: Option<Hints>,
}

/// What inline [`Hints`] add to every shadow BIB entry
/// (`plat_common::memory::SHADOW_HINT_BYTES` charges this per
/// `max_sessions`, with the hash table's worst-case bucket overhead).
pub const SHADOW_BIB_HINT_BYTES: usize = size_of::<ShadowBib>() - size_of::<WireBib>();
const _: () = assert!(size_of::<Hints>() == 44);
const _: () = assert!(SHADOW_BIB_HINT_BYTES == 48);
// The shadow map bucket grows by the same 48 B (key padding included).
const _: () =
    assert!(size_of::<((u8, u32, u16), ShadowBib)>() - size_of::<((u8, u32, u16), WireBib)>() == SHADOW_BIB_HINT_BYTES);

impl ShadowBib {
    pub fn new(bib: WireBib) -> Self {
        Self { bib, hints: None }
    }
}

/// Session-hint counters of the shadow (SI-4,
/// `plat_cluster_session_hints_*`).
#[derive(Debug, Default)]
pub struct HintStats {
    pub applied: AtomicU64,
    pub no_bib: AtomicU64,
    pub outside_slice: AtomicU64,
    pub invalid: AtomicU64,
    /// A snapshot `Sess` record without its `Bib`.
    pub sess_orphan: AtomicU64,
    /// A fifth remote replaced a (possibly live) one: the BIB is marked
    /// hint-incomplete (`plat_cluster_session_hints_evicted_total`).
    pub evicted: AtomicU64,
    /// UDP hints (`proto="udp"`): applied, and refused because their BIB
    /// is not in the shadow (counted only, never a gap: UDP hints do not
    /// govern strictness, and resyncing on UDP churn would amplify it).
    pub udp_applied: AtomicU64,
    pub udp_no_bib: AtomicU64,
    /// A fifth UDP remote replaced the oldest (no strictness effect).
    pub udp_evicted: AtomicU64,
}

/// What a new owner imports on takeover (from [`Shadow::take`]).
#[derive(Debug, Clone, Default)]
pub struct AdoptInput {
    /// `(sub, block, original allocation time)`.
    pub blocks: Vec<(u128, WireBlock, u64)>,
    pub bibs: Vec<WireBib>,
    /// Session hints of the TCP and UDP BIBs in `bibs` (the hint's BIB is
    /// `(hint.proto, v4, port4)`); hints of other BIBs are ignored.
    pub hints: Vec<WireHint>,
    /// When each of `hints` was learned (shadow clock, seconds; parallel
    /// to `hints`, a missing entry means `hint_now_s`).
    pub hint_learned_s: Vec<u32>,
    /// `(v4, port4)` of TCP BIBs whose hint set is incomplete (a remote
    /// was evicted): pickup stays allowed on them.
    pub hints_lossy: Vec<(u32, u16)>,
    /// The shadow clock (seconds) when the input was taken: hint ages are
    /// measured from it.
    pub hint_now_s: u32,
    /// Reserved with the backup but never seen allocated: held back for
    /// `takeover_quarantine_secs`.
    pub reserved_unseen: Vec<WireBlock>,
    /// Released by the old owner `age_ms` ago: finish the cool-down.
    pub released: Vec<(WireBlock, u64)>,
    /// The shadow was complete (snapshot plus an unbroken stream).
    pub in_sync: bool,
    /// The primary sent session hints for the slice (`SnapshotEnd.hints`)
    /// and none was lost since.
    pub hinted: bool,
    /// Hold back every block that is not adopted (the old owner's state is
    /// not known completely).
    pub hold_unknown: bool,
}

/// The state of one shadow slice moved out by [`Shadow::detach`] for a
/// chunked adoption: the maps as replicated (unsorted), keyed like the
/// shadow.
#[derive(Debug)]
pub struct Detached {
    /// `(addr, block) -> (sub, original allocation time)`.
    pub blocks: Map<(u32, u16), (u128, u64)>,
    pub reserved_unseen: Vec<WireBlock>,
    pub released: Vec<(WireBlock, u64)>,
    /// `(proto, v4, port4) -> BIB`: the key already makes the IPv4 side
    /// unique.
    pub bibs: Map<(u8, u32, u16), ShadowBib>,
    pub in_sync: bool,
    /// See [`AdoptInput::hinted`].
    pub hinted: bool,
    /// See [`AdoptInput::hint_now_s`].
    pub hint_now_s: u32,
    pub hold_unknown: bool,
    pub(crate) charge: ShadowCharge,
    /// Where an abandoned adoption returns the state (see
    /// [`ShadowHome::restore`]).
    pub(crate) home: Option<Box<ShadowHome>>,
}

/// The shadow slice a [`Detached`] came from, with the reservations and
/// release times as they were (bounded by the slice's block count).
#[derive(Debug)]
pub(crate) struct ShadowHome {
    slices: Arc<[Mutex<ShadowSlice>]>,
    slice: SliceId,
    reserved: HashSet<(u32, u16), RandomState>,
    released: Map<(u32, u16), u64>,
    ctr: Arc<AtomicU64>,
    /// Snapshot generations of every slice, and this slice's at detach.
    gens: Arc<[AtomicU64]>,
    gen_at_detach: u64,
}

impl ShadowHome {
    /// Gives the state of an abandoned adoption back to the shadow slice
    /// (lease lost with no new owner: the regain must find it, POAM-047
    /// F1), in O(1) under the slice mutex, when the slice is still empty and
    /// no snapshot began since the detach (the usual case: nothing
    /// replicates to the would-be owner). Otherwise the shadow got newer
    /// state from the owner, which is authoritative: the returned state is
    /// dropped and the slice marked not in sync (SEC-002, PERF-003: no
    /// merge, so no large work under the mutex and no resurrected deletes).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: CP-10, AU-10 - attribution continuity across an
    ///   abandoned takeover: the regain adopts the same mappings
    /// - NIST 800-53: SC-24 - a stale copy never overrides newer replicated
    ///   state; the regain then holds back unknown blocks
    /// - NIST 800-53: SC-5 - the returned BIBs are counted against
    ///   `max_bibs` (they were while detached)
    pub(crate) fn restore(
        self,
        blocks: Map<(u32, u16), (u128, u64)>,
        bibs: Map<(u8, u32, u16), ShadowBib>,
        sync: (bool, bool),
        charge: Option<ShadowCharge>,
    ) {
        let (in_sync, hinted) = sync;
        let Some(m) = self.slices.get(usize::from(self.slice)) else { return };
        let mut g = m.lock();
        let newer =
            self.gens.get(usize::from(self.slice)).map_or(0, |x| x.load(Ordering::Relaxed)) != self.gen_at_detach;
        let empty = g.blocks.is_empty() && g.bibs.is_empty() && g.reserved.is_empty() && g.released.is_empty();
        if empty && !newer {
            self.ctr.fetch_add(bibs.len() as u64, Ordering::Relaxed);
            *g = ShadowSlice {
                blocks,
                reserved: self.reserved,
                released: self.released,
                bibs,
                in_sync,
                hinted,
                hint_gap: false,
            };
        } else {
            g.in_sync = false;
            g.hinted = false;
        }
        drop(g);
        drop(charge);
    }
}

impl Detached {
    fn empty(ctr: Arc<AtomicU64>) -> Self {
        Self {
            blocks: Map::with_hasher(RandomState::new()),
            reserved_unseen: Vec::new(),
            released: Vec::new(),
            bibs: Map::with_hasher(RandomState::new()),
            in_sync: true,
            hinted: false,
            hint_now_s: 0,
            hold_unknown: false,
            charge: ShadowCharge { ctr, n: 0 },
            home: None,
        }
    }
}

/// BIBs of a [`Detached`] slice still counted against the shadow's
/// `max_bibs`; returned when dropped (SC-5).
#[derive(Debug)]
pub(crate) struct ShadowCharge {
    ctr: Arc<AtomicU64>,
    n: u64,
}

impl Drop for ShadowCharge {
    fn drop(&mut self) {
        self.ctr.fetch_sub(self.n, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct ShadowSlice {
    blocks: Map<(u32, u16), (u128, u64)>,
    reserved: HashSet<(u32, u16), RandomState>,
    released: Map<(u32, u16), u64>,
    bibs: Map<(u8, u32, u16), ShadowBib>,
    in_sync: bool,
    /// The last snapshot ended with `hints` and no hint was lost since.
    hinted: bool,
    /// A hint of the current snapshot found no BIB: it ends un-hinted.
    hint_gap: bool,
}

impl ShadowSlice {
    fn new() -> Self {
        Self {
            blocks: Map::with_hasher(RandomState::new()),
            reserved: HashSet::with_hasher(RandomState::new()),
            released: Map::with_hasher(RandomState::new()),
            bibs: Map::with_hasher(RandomState::new()),
            in_sync: false,
            hinted: false,
            hint_gap: false,
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
    slices: Arc<[Mutex<ShadowSlice>]>,
    /// BIBs held, including those of detached slices still being adopted
    /// (shared with their [`Detached`]).
    bibs: Arc<AtomicU64>,
    max_bibs: u64,
    /// Per-slice snapshot generation, bumped by every `snapshot_begin`
    /// (a restore after a newer snapshot is dropped, SEC-002).
    gens: Arc<[AtomicU64]>,
    hint_stats: HintStats,
}

impl Shadow {
    pub fn new(map: SliceMap, port_min: u16, port_max: u16, block_size: u16, cooldown_ms: u64, max_bibs: u64) -> Self {
        let range = (u32::from(port_max) + 1).saturating_sub(u32::from(port_min));
        let bpa = (range / u32::from(block_size.max(1))).min(u32::from(u16::MAX)) as u16;
        let slices: Arc<[Mutex<ShadowSlice>]> = (0..map.len()).map(|_| Mutex::new(ShadowSlice::new())).collect();
        let gens: Arc<[AtomicU64]> = (0..map.len()).map(|_| AtomicU64::new(0)).collect();
        Self {
            map,
            port_min,
            block_size: block_size.max(1),
            blocks_per_addr: bpa,
            cooldown_ms,
            slices,
            bibs: Arc::new(AtomicU64::new(0)),
            max_bibs,
            gens,
            hint_stats: HintStats::default(),
        }
    }

    /// Session-hint counters.
    pub fn hint_stats(&self) -> &HintStats {
        &self.hint_stats
    }

    /// Adds one session hint to its shadow TCP or UDP BIB. A UDP hint
    /// without its BIB is counted (`udp_no_bib`) and accepted: it never
    /// marks the slice gapped (T3, no resync amplification by UDP churn).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SI-10 - zero fields and addresses outside the slice
    ///   are refused; SC-5 - at most [`MAX_HINTS`] remotes per BIB, and a
    ///   hint never creates a BIB; an evicted remote is counted and leaves
    ///   the BIB hint-incomplete (pickup allowed there, SEC-002)
    fn apply_hint(
        &self,
        slice: SliceId,
        p: u8,
        v4: u32,
        port4: u16,
        remote: (u32, u16),
        now_ms: u64,
    ) -> Result<(), ShadowError> {
        let st = &self.hint_stats;
        if v4 == 0 || port4 == 0 || remote.0 == 0 || remote.1 == 0 || !matches!(p, proto::TCP | proto::UDP) {
            st.invalid.fetch_add(1, Ordering::Relaxed);
            return Err(ShadowError::Invalid);
        }
        if !self.in_slice(slice, v4) {
            st.outside_slice.fetch_add(1, Ordering::Relaxed);
            return Err(ShadowError::Range);
        }
        let mut g = self.slice(slice)?.lock();
        if p == proto::UDP {
            let Some(b) = g.bibs.get_mut(&(proto::UDP, v4, port4)) else {
                drop(g);
                st.udp_no_bib.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            };
            let evicted = b.hints.get_or_insert_with(Hints::default).add(remote, hint_secs(now_ms));
            drop(g);
            if evicted {
                st.udp_evicted.fetch_add(1, Ordering::Relaxed);
            }
            st.udp_applied.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let Some(b) = g.bibs.get_mut(&(proto::TCP, v4, port4)) else {
            // The slice copy now lacks an ESTABLISHED session: not hinted
            // until the next snapshot (the caller also marks it gapped).
            // POAM: POAM-028 `ReplHub::drain_rounds` sends a batch's hints
            // after its BIB records (decision Q1 revised) and repeats cut
            // rounds (up to 8 in platd), so this is left for a `BibCreate`
            // still in a ring when the last round stopped at its limit (a
            // burst over 8 x 4096 records; no early-hint buffer): the slice
            // loses its hinted state until the resync; counted `no_bib`.
            g.hinted = false;
            g.hint_gap = true;
            drop(g);
            st.no_bib.fetch_add(1, Ordering::Relaxed);
            return Err(ShadowError::NoBib);
        };
        let evicted = b.hints.get_or_insert_with(Hints::default).add(remote, hint_secs(now_ms));
        drop(g);
        if evicted {
            st.evicted.fetch_add(1, Ordering::Relaxed);
        }
        st.applied.fetch_add(1, Ordering::Relaxed);
        Ok(())
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
                match g.bibs.entry(k) {
                    hash_map::Entry::Occupied(mut e) => {
                        // A replayed create keeps the hints only for the
                        // same mapping.
                        let x = e.get_mut();
                        if x.bib.v6 != bib.v6 || x.bib.port6 != bib.port6 || x.bib.sub != bib.sub {
                            x.hints = None;
                        }
                        x.bib = bib;
                    }
                    hash_map::Entry::Vacant(e) => {
                        if self.bibs.load(Ordering::Relaxed) >= self.max_bibs {
                            return Err(ShadowError::Full);
                        }
                        self.bibs.fetch_add(1, Ordering::Relaxed);
                        e.insert(ShadowBib::new(bib));
                    }
                }
            }
            ReplRecord::BibDelete { slice, proto, v4, port4 } => {
                let mut g = self.slice(slice)?.lock();
                if g.bibs.remove(&(proto, v4, port4)).is_some() {
                    self.bibs.fetch_sub(1, Ordering::Relaxed);
                }
            }
            ReplRecord::SessHint { slice, proto: p, v4, port4, raddr, rport } => {
                self.apply_hint(slice, p, v4, port4, (raddr, rport), now_ms)?
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
        if let Some(x) = self.gens.get(usize::from(slice)) {
            x.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Applies snapshot records. Each record is validated; the first
    /// invalid one aborts the chunk (the peer is misbehaving). A `Sess`
    /// without its `Bib` (which the primary exports first, in the same
    /// chunk sequence) is skipped and counted (`sess_orphan`); the chunk
    /// goes on, the snapshot ends un-hinted and `Err(NoBib)` is returned
    /// after the chunk so the caller resyncs. Hints are stamped with time 0
    /// (tests and the bench; platd uses [`Shadow::snapshot_records_at`]).
    pub fn snapshot_records(&self, slice: SliceId, recs: &[SnapRecord]) -> Result<(), ShadowError> {
        self.snapshot_records_at(slice, recs, 0)
    }

    /// [`Shadow::snapshot_records`] at shadow time `now_ms` (the learned
    /// time of the snapshot's `Sess` records). A snapshot `Bib` replaces
    /// the BIB's hints with the `Sess` records that follow it, so a
    /// completed snapshot carries exactly the primary's ESTABLISHED set at
    /// export, never a merge with older hints (SEC-001).
    pub fn snapshot_records_at(&self, slice: SliceId, recs: &[SnapRecord], now_ms: u64) -> Result<(), ShadowError> {
        let mut orphan = false;
        for r in recs {
            match *r {
                SnapRecord::Block { sub, block, alloc_wall_us } => {
                    self.apply(&ReplRecord::BlockAlloc { slice, sub, block, wall_us: alloc_wall_us }, 0)?
                }
                SnapRecord::Bib(bib) => {
                    self.apply(&ReplRecord::BibCreate { slice, bib }, 0)?;
                    let mut g = self.slice(slice)?.lock();
                    if let Some(x) = g.bibs.get_mut(&(bib.proto, bib.v4, bib.port4)) {
                        x.hints = None;
                    }
                }
                SnapRecord::Sess(h) => {
                    if h.proto != PROTO_TCP && h.proto != PROTO_UDP {
                        self.hint_stats.invalid.fetch_add(1, Ordering::Relaxed);
                        return Err(ShadowError::Proto);
                    }
                    match self.apply_hint(slice, h.proto, h.v4, h.port4, (h.raddr, h.rport), now_ms) {
                        Err(ShadowError::NoBib) => {
                            // Counted as an orphan, not as a streamed no_bib.
                            self.hint_stats.no_bib.fetch_sub(1, Ordering::Relaxed);
                            self.hint_stats.sess_orphan.fetch_add(1, Ordering::Relaxed);
                            orphan = true;
                        }
                        r => r?,
                    }
                }
            }
        }
        if orphan { Err(ShadowError::NoBib) } else { Ok(()) }
    }

    /// The snapshot is complete: the slice is in sync from now on, without
    /// session hints (tests; platd uses [`Shadow::snapshot_end_hinted`]).
    pub fn snapshot_end(&self, slice: SliceId) -> Result<(), ShadowError> {
        self.snapshot_end_hinted(slice, false)
    }

    /// The snapshot is complete: the slice is in sync from now on, and
    /// hinted when the primary sent hints (`SnapshotEnd.hints`) and every
    /// hint of the snapshot found its BIB.
    pub fn snapshot_end_hinted(&self, slice: SliceId, hints: bool) -> Result<(), ShadowError> {
        let mut g = self.slice(slice)?.lock();
        g.in_sync = true;
        g.hinted = hints && !g.hint_gap;
        Ok(())
    }

    /// A gap in the stream (sequence jump or overflow): not in sync (and
    /// not hinted) until the next snapshot completes.
    pub fn mark_gap(&self, slice: SliceId) {
        if let Ok(m) = self.slice(slice) {
            let mut g = m.lock();
            g.in_sync = false;
            g.hinted = false;
        }
    }

    /// The shadow of `slice` carries every ESTABLISHED TCP session of the
    /// primary (in sync and hinted).
    pub fn hinted(&self, slice: SliceId) -> bool {
        self.slice(slice).is_ok_and(|m| {
            let g = m.lock();
            g.in_sync && g.hinted
        })
    }

    /// Session hints held for `slice` (tests).
    pub fn hint_count(&self, slice: SliceId) -> usize {
        self.slice(slice).map_or(0, |m| m.lock().bibs.values().map(|b| b.hints.as_ref().map_or(0, Hints::len)).sum())
    }

    /// Eligible for takeover (snapshot complete, stream unbroken).
    pub fn in_sync(&self, slice: SliceId) -> bool {
        self.slice(slice).is_ok_and(|m| m.lock().in_sync)
    }

    /// BIBs charged to `max_bibs`: held, plus detached and not yet
    /// imported by an adoption.
    pub fn bibs_charged(&self) -> u64 {
        self.bibs.load(Ordering::Relaxed)
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

    /// Moves the state of `slice` out for a chunked adoption
    /// ([`crate::state::State::adopt_begin`]) and clears it. The swap under
    /// the slice mutex is O(1); the BIB and block maps are handed over
    /// unsorted. Only the reservations and recent releases (bounded by the
    /// slice's block count) are copied, outside the mutex. Releases older
    /// than the cool-down are dropped.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - the detached BIBs stay charged to `max_bibs`
    ///   until the adoption drops them, so shadow plus in-flight adoption
    ///   never exceed the cap
    pub fn detach(&self, slice: SliceId, now_ms: u64) -> Detached {
        let Ok(m) = self.slice(slice) else { return Detached::empty(self.bibs.clone()) };
        let s = std::mem::replace(&mut *m.lock(), ShadowSlice::new());
        let reserved_unseen = s.reserved.iter().map(|&(addr, block)| WireBlock { addr, block }).collect();
        let released = s
            .released
            .iter()
            .filter_map(|(&(addr, block), &t)| {
                let age = now_ms.saturating_sub(t);
                (age < self.cooldown_ms).then_some((WireBlock { addr, block }, age))
            })
            .collect();
        let charge = ShadowCharge { ctr: self.bibs.clone(), n: s.bibs.len() as u64 };
        let home = ShadowHome {
            slices: self.slices.clone(),
            slice,
            reserved: s.reserved,
            released: s.released,
            ctr: self.bibs.clone(),
            gens: self.gens.clone(),
            gen_at_detach: self.gens.get(usize::from(slice)).map_or(0, |x| x.load(Ordering::Relaxed)),
        };
        Detached {
            blocks: s.blocks,
            reserved_unseen,
            released,
            bibs: s.bibs,
            in_sync: s.in_sync,
            hinted: s.in_sync && s.hinted,
            hint_now_s: hint_secs(now_ms),
            hold_unknown: !s.in_sync,
            charge,
            home: Some(Box::new(home)),
        }
    }

    /// Takes the state of `slice` for adoption and clears it, sorted (tests
    /// and the bench; platd uses [`Shadow::detach`]). Releases older than
    /// the cool-down are dropped.
    pub fn take(&self, slice: SliceId, now_ms: u64) -> AdoptInput {
        let Ok(m) = self.slice(slice) else { return AdoptInput::default() };
        let mut g = m.lock();
        let s = std::mem::replace(&mut *g, ShadowSlice::new());
        drop(g);
        self.bibs.fetch_sub(s.bibs.len() as u64, Ordering::Relaxed);
        let mut blocks: Vec<_> =
            s.blocks.iter().map(|(&(addr, block), &(sub, wall))| (sub, WireBlock { addr, block }, wall)).collect();
        blocks.sort_unstable_by_key(|b| (b.1.addr, b.1.block));
        let mut hints = Vec::new();
        let mut hints_lossy = Vec::new();
        let mut bibs = Vec::with_capacity(s.bibs.len());
        for x in s.bibs.into_values() {
            if let Some(h) = &x.hints {
                for ((raddr, rport), t) in h.iter() {
                    hints.push((WireHint { proto: x.bib.proto, v4: x.bib.v4, port4: x.bib.port4, raddr, rport }, t));
                }
                // Lossy governs TCP pickup only.
                if h.lossy() && x.bib.proto == proto::TCP {
                    hints_lossy.push((x.bib.v4, x.bib.port4));
                }
            }
            bibs.push(x.bib);
        }
        bibs.sort_unstable_by_key(|b| (b.v4, b.port4, b.proto));
        hints.sort_unstable_by_key(|(h, _)| (h.v4, h.port4, h.proto, h.raddr, h.rport));
        hints_lossy.sort_unstable();
        let (hints, hint_learned_s) = hints.into_iter().unzip();
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
        AdoptInput {
            blocks,
            bibs,
            hints,
            hint_learned_s,
            hints_lossy,
            hint_now_s: hint_secs(now_ms),
            reserved_unseen,
            released,
            in_sync: s.in_sync,
            hinted: s.in_sync && s.hinted,
            hold_unknown: !s.in_sync,
        }
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
        let (hub, prods) = ReplHub::new(1, 16, 4);
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
            ReplRecord::SessHint {
                slice: 4095,
                proto: 6,
                v4: u32::MAX,
                port4: 65535,
                raddr: u32::MAX - 1,
                rport: 65534,
            },
            ReplRecord::SessHint { slice: 0, proto: 6, v4: 1, port4: 1, raddr: 1, rport: 1 },
            ReplRecord::SessHint { slice: 4095, proto: 17, v4: u32::MAX, port4: 65535, raddr: 7, rport: 65535 },
        ];
        for _ in 0..3 {
            for r in &recs {
                assert!(prods[0].push(*r));
            }
            let mut out = Vec::new();
            assert_eq!(hub.drain(100, &mut out), recs.len());
            assert_eq!(out, recs, "wraps the ring");
        }
        assert_eq!(hub.pushed_total(), 27);
        for h in [recs[7], recs[8]] {
            assert_eq!(ReplRecord::from_msg(&h.to_msg(5)), Some((h, 5)));
        }
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

    fn hint_shadow() -> Shadow {
        let m = SliceMap::new(&[Ipv4Cidr::new([10, 0, 0, 0].into(), 30).unwrap()], 31).unwrap();
        Shadow::new(m, 1024, 1024 + 2 * 64 - 1, 64, 120_000, 10)
    }

    fn tcp_bib(port4: u16) -> WireBib {
        WireBib { sub: 7, proto: 6, v6: 9, port6: 80, v4: 0x0a00_0000, port4, created_wall_us: 6 }
    }

    fn hint(port4: u16, raddr: u32, rport: u16) -> ReplRecord {
        ReplRecord::SessHint { slice: 0, proto: 6, v4: 0x0a00_0000, port4, raddr, rport }
    }

    /// SEC-002: a fifth remote evicts the oldest, is counted and leaves the
    /// set lossy; a duplicate refreshes its time without evicting.
    #[test]
    fn hints_evict_counts_and_marks_lossy() {
        let mut h = Hints::default();
        for r in 1..=4u32 {
            assert!(!h.add((r, 443), r));
        }
        assert!(!h.add((2, 443), 9), "duplicate");
        assert!(!h.lossy());
        assert!(h.add((5, 443), 10));
        assert!(h.lossy());
        let got: Vec<_> = h.iter().collect();
        assert_eq!(got, vec![((5, 443), 10), ((2, 443), 9), ((3, 443), 3), ((4, 443), 4)]);
        let sh = hint_shadow();
        sh.apply(&ReplRecord::BibCreate { slice: 0, bib: tcp_bib(1100) }, 0).unwrap();
        for r in 1..=5u32 {
            sh.apply(&hint(1100, r, 443), 0).unwrap();
        }
        assert_eq!(sh.hint_stats().evicted.load(Ordering::Relaxed), 1);
        assert_eq!(sh.take(0, 0).hints_lossy, vec![(0x0a00_0000, 1100)]);
    }

    /// SEC-001: a snapshot `Bib` replaces the BIB's hints with the `Sess`
    /// records after it; hints are stamped with the snapshot's time.
    #[test]
    fn snapshot_bib_replaces_hints() {
        let sh = hint_shadow();
        sh.apply(&ReplRecord::BibCreate { slice: 0, bib: tcp_bib(1100) }, 0).unwrap();
        sh.apply(&hint(1100, 1, 443), 0).unwrap();
        sh.apply(&hint(1100, 2, 443), 0).unwrap();
        let sess = WireHint { proto: 6, v4: 0x0a00_0000, port4: 1100, raddr: 9, rport: 443 };
        sh.snapshot_records_at(0, &[SnapRecord::Bib(tcp_bib(1100)), SnapRecord::Sess(sess)], 50_000).unwrap();
        let a = sh.take(0, 60_000);
        assert_eq!((a.hints, a.hint_learned_s, a.hint_now_s), (vec![sess], vec![50], 60));
    }

    /// PERF-002: rounds repeat while one was cut, so a `BibCreate` left in
    /// its ring by a cut round still goes out before its hint.
    #[test]
    fn drain_rounds_repeat_until_no_ring_is_cut() {
        let creates = |p: &ReplProducer| {
            for port in [1100, 1101, 1102] {
                assert!(p.push(ReplRecord::BibCreate { slice: 0, bib: tcp_bib(port) }));
            }
        };
        let (hub, prods) = ReplHub::new(2, 8, 4);
        creates(&prods[0]);
        assert!(prods[1].push(hint(1102, 7, 443)));
        let mut out = Vec::new();
        assert_eq!(hub.drain_rounds(2, 8, &mut out), 4);
        assert_eq!(out.last(), Some(&hint(1102, 7, 443)), "the hint follows all three creates");
        assert_eq!(hub.drains_truncated(), 0);
        // Too few rounds: the last one is still cut, counted.
        let (hub, prods) = ReplHub::new(2, 8, 4);
        creates(&prods[0]);
        assert!(prods[1].push(hint(1102, 7, 443)));
        out.clear();
        assert_eq!(hub.drain_rounds(2, 2, &mut out), 3);
        assert_eq!(hub.drains_truncated(), 1);
    }

    #[test]
    fn hint_past_its_tail_cut_stays_queued_with_what_follows() {
        let (_hub, prods) = ReplHub::new(1, 8, 4);
        let ring = &prods[0].ring;
        let create = ReplRecord::BibCreate { slice: 0, bib: tcp_bib(1100) };
        assert!(prods[0].push(create) && prods[0].push(ReplRecord::SubGone { sub: 2 }));
        // Pushed after the consumer read its cut (tail 1).
        assert!(prods[0].push(hint(1100, 5, 6)) && prods[0].push(ReplRecord::SubGone { sub: 3 }));
        let mut out = Vec::new();
        assert_eq!(ring.pop_into(8, &mut out, 1), 2, "non-hints past the cut are taken");
        assert_eq!(out, vec![create, ReplRecord::SubGone { sub: 2 }]);
        assert_eq!(ring.len(), 2, "the hint and its successor wait for the next drain");
        out.clear();
        assert_eq!(ring.pop_into(8, &mut out, 4), 2);
        assert_eq!(out, vec![hint(1100, 5, 6), ReplRecord::SubGone { sub: 3 }]);
    }

    #[test]
    fn drain_sends_hints_after_bib_records_of_other_rings() {
        let (hub, prods) = ReplHub::new(2, 16, 4);
        let del = |port4| ReplRecord::BibDelete { slice: 0, proto: 6, v4: 0x0a00_0000, port4 };
        let create = |port4| ReplRecord::BibCreate { slice: 0, bib: tcp_bib(port4) };
        // Ring 1 is drained first: its hint precedes ring 0's create.
        assert!(prods[0].push(create(1100)) && prods[0].push(create(1101)));
        assert!(prods[1].push(hint(1100, 5, 6)) && prods[1].push(ReplRecord::SubGone { sub: 3 }));
        assert!(prods[1].push(hint(1101, 5, 7)));
        hub.next.store(1, Ordering::Relaxed);
        let mut out = vec![ReplRecord::SubGone { sub: 1 }];
        assert_eq!(hub.drain(16, &mut out), 5);
        assert_eq!(
            out,
            vec![
                ReplRecord::SubGone { sub: 1 },
                ReplRecord::SubGone { sub: 3 },
                create(1100),
                create(1101),
                hint(1100, 5, 6),
                hint(1101, 5, 7),
            ]
        );
        let sh = hint_shadow();
        for r in &out[2..] {
            sh.apply(r, 0).unwrap();
        }
        assert_eq!(sh.hint_count(0), 2);
        // A hint drained before a delete of its BIB is dropped; one after a
        // delete (the re-created BIB) is kept; a UDP delete is unrelated.
        assert!(prods[0].push(hint(1100, 5, 8)) && prods[0].push(del(1100)) && prods[0].push(create(1100)));
        assert!(prods[0].push(hint(1100, 5, 9)) && prods[0].push(hint(1101, 5, 10)));
        assert!(prods[1].push(ReplRecord::BibDelete { slice: 0, proto: 17, v4: 0x0a00_0000, port4: 1101 }));
        hub.next.store(0, Ordering::Relaxed);
        out.clear();
        assert_eq!(hub.drain(16, &mut out), 6);
        assert_eq!(
            out,
            vec![
                del(1100),
                create(1100),
                ReplRecord::BibDelete { slice: 0, proto: 17, v4: 0x0a00_0000, port4: 1101 },
                hint(1100, 5, 9),
                hint(1101, 5, 10),
            ]
        );
        assert_eq!(hub.hints_superseded(), 1);
    }

    #[test]
    fn shadow_hints_capped_per_bib_and_dropped_with_bib() {
        let sh = hint_shadow();
        sh.apply(&ReplRecord::BibCreate { slice: 0, bib: tcp_bib(1100) }, 0).unwrap();
        for r in 1..=5u32 {
            sh.apply(&hint(1100, r, 443), 0).unwrap();
        }
        sh.apply(&hint(1100, 5, 443), 0).unwrap();
        assert_eq!(sh.hint_count(0), MAX_HINTS, "capped, duplicate ignored");
        let a = sh.take(0, 0);
        let got: Vec<u32> = a.hints.iter().map(|h| h.raddr).collect();
        assert_eq!(got, vec![2, 3, 4, 5], "the oldest went");
        sh.apply(&ReplRecord::BibCreate { slice: 0, bib: tcp_bib(1100) }, 0).unwrap();
        sh.apply(&hint(1100, 1, 443), 0).unwrap();
        // A replayed identical create keeps the hints; a delete frees them.
        sh.apply(&ReplRecord::BibCreate { slice: 0, bib: tcp_bib(1100) }, 0).unwrap();
        assert_eq!(sh.hint_count(0), 1);
        sh.apply(&ReplRecord::BibDelete { slice: 0, proto: 6, v4: 0x0a00_0000, port4: 1100 }, 0).unwrap();
        assert_eq!(sh.hint_count(0), 0);
        assert_eq!(sh.hint_stats().applied.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn shadow_refuses_hints_without_bib_or_outside_slice() {
        let sh = hint_shadow();
        sh.snapshot_end_hinted(0, true).unwrap();
        assert!(sh.hinted(0));
        assert_eq!(sh.apply(&hint(1100, 1, 443), 0), Err(ShadowError::NoBib));
        assert!(!sh.hinted(0), "a lost hint clears hinted");
        // UDP BIB with the same port: still no TCP BIB.
        sh.apply(&ReplRecord::BibCreate { slice: 0, bib: WireBib { proto: 17, ..tcp_bib(1100) } }, 0).unwrap();
        assert_eq!(sh.apply(&hint(1100, 1, 443), 0), Err(ShadowError::NoBib));
        let out = ReplRecord::SessHint { slice: 1, proto: 6, v4: 0x0a00_0000, port4: 1100, raddr: 1, rport: 1 };
        assert_eq!(sh.apply(&out, 0), Err(ShadowError::Range));
        assert_eq!(sh.apply(&hint(1100, 0, 443), 0), Err(ShadowError::Invalid));
        let st = sh.hint_stats();
        assert_eq!([&st.no_bib, &st.outside_slice, &st.invalid].map(|c| c.load(Ordering::Relaxed)), [2, 1, 1]);
    }

    #[test]
    fn snapshot_end_sets_hinted_and_gap_clears_it() {
        let sh = hint_shadow();
        sh.snapshot_begin(0).unwrap();
        sh.snapshot_records(
            0,
            &[
                SnapRecord::Bib(tcp_bib(1100)),
                SnapRecord::Sess(WireHint { proto: 6, v4: 0x0a00_0000, port4: 1100, raddr: 1, rport: 2 }),
            ],
        )
        .unwrap();
        sh.snapshot_end_hinted(0, true).unwrap();
        assert!(sh.hinted(0) && sh.in_sync(0));
        sh.mark_gap(0);
        assert!(!sh.hinted(0));
        // Hints off on the primary: in sync, not hinted.
        sh.snapshot_begin(0).unwrap();
        sh.snapshot_end_hinted(0, false).unwrap();
        assert!(sh.in_sync(0) && !sh.hinted(0));
        // An orphan Sess: the rest of the chunk applies, the end is un-hinted.
        sh.snapshot_begin(0).unwrap();
        let r = sh.snapshot_records(
            0,
            &[
                SnapRecord::Sess(WireHint { proto: 6, v4: 0x0a00_0000, port4: 1101, raddr: 1, rport: 2 }),
                SnapRecord::Bib(tcp_bib(1100)),
            ],
        );
        assert_eq!(r, Err(ShadowError::NoBib));
        assert_eq!(sh.counts(0), (0, 1));
        sh.snapshot_end_hinted(0, true).unwrap();
        assert!(sh.in_sync(0) && !sh.hinted(0));
        assert_eq!(sh.hint_stats().sess_orphan.load(Ordering::Relaxed), 1);
        assert_eq!(sh.hint_stats().no_bib.load(Ordering::Relaxed), 0);
        // Detach carries the flag.
        sh.snapshot_begin(0).unwrap();
        sh.snapshot_end_hinted(0, true).unwrap();
        assert!(sh.detach(0, 0).hinted);
    }

    #[test]
    fn ring_refuses_zero_hint_fields() {
        let (hub, prods) = ReplHub::new(1, 8, 4);
        assert!(prods[0].push(ReplRecord::SessHint { slice: 0, proto: 6, v4: 1, port4: 1, raddr: 0, rport: 1 }));
        let mut out = Vec::new();
        assert_eq!(hub.drain(10, &mut out), 1);
        assert!(out.is_empty(), "decoded as nothing");
    }

    /// SI-10: a ring hint whose proto (bits 56..63) is not TCP or UDP
    /// decodes as nothing.
    #[test]
    fn ring_refuses_bad_hint_proto() {
        let (hub, prods) = ReplHub::new(1, 8, 4);
        for p in [0, 1, 58, 255] {
            assert!(prods[0].push(ReplRecord::SessHint { slice: 0, proto: p, v4: 1, port4: 1, raddr: 1, rport: 1 }));
        }
        let mut out = Vec::new();
        assert_eq!(hub.drain(10, &mut out), 4);
        assert!(out.is_empty());
    }

    /// SC-5: the UDP hint bucket starts full (one second of burst), defers
    /// when empty (counted, nothing queued) and refills at the rate.
    #[test]
    fn udp_hint_bucket_rate_burst_refill() {
        let (hub, prods) = ReplHub::with_udp_hint_rate(1, 64, 4, 3);
        let h = ReplRecord::SessHint { slice: 0, proto: 17, v4: 1, port4: 1, raddr: 1, rport: 1 };
        let t0 = 10_000;
        assert!((0..3).all(|_| prods[0].push_udp_hint(h, t0)));
        assert!(!prods[0].push_udp_hint(h, t0));
        assert!(!prods[0].push_udp_hint(h, t0 + 300), "0.9 tokens");
        assert!(prods[0].push_udp_hint(h, t0 + 340), "one token after 1/3 s");
        assert!(!prods[0].push_udp_hint(h, t0 + 340));
        // Long idle: capped at the burst.
        assert!((0..3).all(|_| prods[0].push_udp_hint(h, t0 + 60_000)));
        assert!(!prods[0].push_udp_hint(h, t0 + 60_000));
        assert_eq!((hub.udp_hints_pushed(), hub.udp_hints_deferred()), (7, 4));
        let mut out = Vec::new();
        assert_eq!(hub.drain(100, &mut out), 7);
        // Rate 0 is raised to 1.
        let (_, prods) = ReplHub::with_udp_hint_rate(1, 8, 4, 0);
        assert!(prods[0].push_udp_hint(h, t0));
        assert!(!prods[0].push_udp_hint(h, t0));
    }

    /// QA, SC-5: bucket boundaries. Burst is exactly one second of tokens
    /// (at 1/s and at the 100 000/s cap), a refill below one token adds
    /// nothing, exactly 1000/rate ms adds one, and a clock that goes
    /// backwards adds nothing.
    #[test]
    fn qa_udp_hint_bucket_boundaries() {
        let h = ReplRecord::SessHint { slice: 0, proto: 17, v4: 1, port4: 1, raddr: 1, rport: 1 };
        for rate in [1u32, 1000, 100_000] {
            let (hub, prods) = ReplHub::with_udp_hint_rate(1, 1024, 4, rate);
            let p = &prods[0];
            let t0 = 50_000;
            let mut n = 0u64;
            while p.push_udp_hint(h, t0) {
                n += 1;
                assert!(n <= u64::from(rate), "rate {rate}: burst above one second");
            }
            assert_eq!(n, u64::from(rate), "rate {rate}: burst is one second of tokens");
            let step = 1000 / u64::from(rate);
            if step > 1 {
                assert!(!p.push_udp_hint(h, t0 + step - 1), "rate {rate}: below one token");
            }
            assert!(p.push_udp_hint(h, t0 + step.max(1)), "rate {rate}: one token after {step} ms");
            if rate <= 1000 {
                assert!(!p.push_udp_hint(h, t0 + step - 1), "rate {rate}: clock went backwards");
            }
            assert_eq!(hub.udp_hints_pushed(), u64::from(rate) + 1);
            assert!(hub.udp_hints_deferred() >= 1);
        }
    }

    /// QA, SC-5: sustained rate over 10 s of one call per ms never exceeds
    /// burst + rate x elapsed (fractional remainders are not created out of
    /// thin air).
    #[test]
    fn qa_udp_hint_bucket_sustained_rate() {
        let h = ReplRecord::SessHint { slice: 0, proto: 17, v4: 1, port4: 1, raddr: 1, rport: 1 };
        for rate in [3u32, 7, 333, 2000] {
            let (_hub, prods) = ReplHub::with_udp_hint_rate(1, 1 << 16, 4, rate);
            let t0 = 1_000;
            let mut sent = 0u64;
            for ms in 0..10_000u64 {
                for _ in 0..4 {
                    sent += u64::from(prods[0].push_udp_hint(h, t0 + ms));
                }
            }
            let cap = u64::from(rate) * 11;
            assert!(sent <= cap, "rate {rate}: {sent} > {cap}");
        }
    }

    /// QA-2: a rate that does not divide 1000 is delivered in full with
    /// frequent calls (fractions of a token carry over).
    #[test]
    fn qa_udp_hint_bucket_delivers_configured_rate() {
        let h = ReplRecord::SessHint { slice: 0, proto: 17, v4: 1, port4: 1, raddr: 1, rport: 1 };
        for rate in [333u32, 999] {
            let (_hub, prods) = ReplHub::with_udp_hint_rate(1, 1 << 16, 4, rate);
            let mut sent = 0u64;
            // Two calls per ms: more demand than the rate, so the bucket
            // (not the caller) sets the pace (one call per ms caps 999/s
            // at 1000 calls/s).
            for ms in 0..10_000u64 {
                for _ in 0..2 {
                    sent += u64::from(prods[0].push_udp_hint(h, 1_000 + ms));
                }
            }
            // One second of burst plus 10 s at the rate (last ms excluded).
            let want = u64::from(rate) * 11;
            assert!(sent * 100 >= want * 95, "rate {rate}: {sent} of {want}");
            assert!(sent <= want, "rate {rate}: {sent} > {want}");
        }
    }

    /// A UDP hint drained before a delete of its UDP BIB in the same batch
    /// is superseded; a TCP delete of the same `(v4, port4)` does not touch
    /// it.
    #[test]
    fn drain_supersedes_udp_hint_by_udp_delete_only() {
        let (hub, prods) = ReplHub::new(1, 16, 4);
        let h = ReplRecord::SessHint { slice: 0, proto: 17, v4: 1, port4: 1, raddr: 1, rport: 1 };
        assert!(prods[0].push(h));
        assert!(prods[0].push(ReplRecord::BibDelete { slice: 0, proto: 6, v4: 1, port4: 1 }));
        let mut out = Vec::new();
        hub.drain(100, &mut out);
        assert_eq!(out.last(), Some(&h));
        assert!(prods[0].push(h));
        assert!(prods[0].push(ReplRecord::BibDelete { slice: 0, proto: 17, v4: 1, port4: 1 }));
        out.clear();
        hub.drain(100, &mut out);
        assert!(!out.contains(&h));
        assert_eq!(hub.hints_superseded(), 1);
    }
}
