//! Per-worker fragment tracking (RFC 6146 §3.4, RFC 7915 §4/§5).
//!
//! The first fragment of a datagram goes through the normal translation
//! path; its result (the addresses it was translated to) is stored here so
//! that non-first fragments, which carry no transport header, are
//! translated by a header rewrite with the same mapping. Fragments that
//! arrive before their first fragment are held in a bounded buffer pool;
//! the few classes whose checksum cannot be fixed fragment by fragment
//! (ICMP, ICMP errors, zero-checksum IPv4 UDP) are reassembled into a
//! bounded set of reassembly slots.
//!
//! Everything is preallocated when the worker starts and owned by that one
//! worker thread: no locks, no shared state, no allocation per packet.
//! Fragments of one datagram share (src, dst), which is what multiqueue TUN
//! hashes on for fragments, so they reach the same worker.
//!
// POAM: POAM-035 fragment state is per worker. A fragment steered to
// another worker than its datagram's first fragment, or an ICMP error
// quoting a non-first fragment that arrives on another worker, is dropped
// (`fragment_unmatched` / `icmp_quote_unmatched`): fail closed, but lossy.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 - fixed-size 4-way set-associative table, buffer and
//!   reassembly pools bounded by `[translation.fragments]`; randomly keyed
//!   hashing; every refusal is a counted drop
//! - NIST 800-53: SI-10 - overlap and duplicate detection on every tracked
//!   datagram, fragment count and offset bounds
//! - NIST 800-53: SC-10 - entries expire `timeout_ms` after their first
//!   fragment
//! - RFC 6146 §3.4 - FRAGMENT_MIN, out-of-order buffering
//! - RFC 5722 - overlapping fragments discard the whole datagram (applied
//!   to IPv4 as well)

use ahash::RandomState;
use plat_common::config::FragmentsConfig;
use plat_common::{Counters, DropReason};
use plat_packet::{parse_v4, parse_v6};
use plat_xlat::HEADROOM;

/// Ways per set.
pub const WAYS: usize = 4;
/// Disjoint byte ranges tracked per datagram; more gaps than this poison it.
const MAX_RANGES: usize = 8;
const NONE: u16 = u16::MAX;
/// Per-source load buckets (keyed hash of the source; two sources that
/// collide share limits, which only makes them stricter).
const LOAD_BUCKETS: usize = 1024;
const NO_LB: u16 = u16::MAX;
const NO_OWNER: u32 = u32::MAX;
/// Held-fragment slots inspected per buffer eviction attempt (bounded work
/// under a flood).
const EVICT_SCAN: usize = 16;

/// What one source currently holds.
#[derive(Debug, Clone, Copy, Default)]
struct Load {
    live: u16,
    held: u16,
    reasm: u16,
}
/// The fragmentable part of a datagram never exceeds this (RFC 791 / 8200).
const MAX_DGRAM: usize = 65535;
/// Reassembly slot layout: headroom, then room for the largest IPv4 header,
/// then the payload.
const REASM_PAYLOAD_OFF: usize = HEADROOM + 60;

/// What the key identifies. Quote aliases map an ICMP error's quoted
/// (translated) non-first fragment back to the flow (RFC 7915 §4.3/§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Kind {
    /// IPv6 fragments received from subscribers (key = IPv6 header).
    #[default]
    V6In,
    /// IPv4 fragments received from remotes (key = IPv4 header).
    V4In,
    /// Alias: an IPv4 fragment this worker sent (key = pool, server).
    Sent4,
    /// Alias: an IPv6 fragment this worker sent (key = server6, subscriber).
    Sent6,
}

/// Fragment identity: (src, dst, protocol, Identification). IPv4
/// addresses are zero-extended; `proto` uses the family's own numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FragKey {
    pub src: u128,
    pub dst: u128,
    pub id: u32,
    pub proto: u8,
    pub kind: Kind,
}

/// The stored translation of a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fwd {
    /// IPv6 → IPv4: translated addresses, pool index, own-node hairpin,
    /// and the IPv4 Identification chosen for the datagram (RFC 6864).
    To4 { src: u32, dst: u32, idx: u32, hairpin: bool, id4: u16 },
    /// IPv4 → IPv6: subscriber address (the source is the embedded IPv4
    /// source) and pool index.
    To6 { dst: u128, idx: u32 },
    /// [`Kind::Sent4`] alias: the subscriber, the original Identification,
    /// the pool index and the mapped ports (pool port, server port), so an
    /// ICMP error quoting the fragment is checked against the live BIB and
    /// filter (SEC-004).
    Sent4 { sub: u128, id: u32, idx: u32, sport: u16, dport: u16 },
    /// [`Kind::Sent6`] alias: the pool address and its index.
    Sent6 { pool: u32, idx: u32 },
}

/// Entry state as the engine sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum St {
    /// Non-first fragments buffered, first fragment not yet seen.
    Pending,
    /// First fragment translated; non-first fragments are forwarded.
    Pass(Fwd),
    /// Being reassembled into the given slot.
    Reasm(u16),
    /// Refused (overlap, too many fragments): later fragments are dropped
    /// with this reason until the entry expires.
    Poisoned(DropReason),
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    key: FragKey,
    /// Created at; the entry expires `timeout_ms` later (never refreshed).
    born_ms: u64,
    st: Option<St>,
    /// Sorted, merged, disjoint `[start, end)` ranges in 8-byte units.
    ranges: [[u16; 2]; MAX_RANGES],
    nranges: u8,
    nfrags: u8,
    /// Datagram (fragmentable part) length once the last fragment is seen.
    total: Option<u16>,
    /// Buffered fragments: singly linked list of buffer slots.
    head: u16,
    tail: u16,
    nbuf: u16,
    /// Source load bucket ([`NO_LB`] for quote aliases).
    lb: u16,
}

const _: () = assert!(size_of::<Entry>() as u64 <= plat_common::config::FRAG_ENTRY_BYTES);

impl Entry {
    const EMPTY: Entry = Entry {
        key: FragKey { src: 0, dst: 0, id: 0, proto: 0, kind: Kind::V6In },
        born_ms: 0,
        st: None,
        ranges: [[0; 2]; MAX_RANGES],
        nranges: 0,
        nfrags: 0,
        total: None,
        head: NONE,
        tail: NONE,
        nbuf: 0,
        lb: NO_LB,
    };
}

/// Result of accounting one fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acct {
    Partial,
    /// Every byte from 0 to the last fragment's end has been seen.
    Complete,
}

/// A complete datagram lent out of its reassembly slot.
#[derive(Debug)]
pub struct Reassembled {
    pub slot: u16,
    pub buf: Box<[u8]>,
    /// The datagram is `buf[start..start + len]` (headroom in front).
    pub start: usize,
    pub len: usize,
}

/// One worker's fragment state.
#[derive(Debug)]
pub struct FragTable {
    hasher: RandomState,
    entries: Box<[Entry]>,
    set_mask: usize,
    timeout_ms: u64,
    max_frags: u8,
    live: u32,
    scan: usize,
    /// Out-of-order buffer: `slots × slot_bytes`.
    buf: Box<[u8]>,
    slot_bytes: usize,
    blen: Box<[u16]>,
    bnext: Box<[u16]>,
    bfree: u16,
    /// Reassembly slots: `None` while lent out to the engine.
    rbuf: Box<[Box<[u8]>]>,
    rused: Box<[bool]>,
    /// Header length stored in front of the payload of each slot.
    rhl: Box<[u16]>,
    max_reasm: usize,
    /// Entry owning each reassembly slot ([`NO_OWNER`] when free or lent).
    rown: Box<[u32]>,
    /// Entry owning each buffer slot ([`NO_OWNER`] when free).
    bown: Box<[u32]>,
    bscan: usize,
    /// Per-source load and its caps (SEC-001 / SEC-003).
    load: Box<[Load]>,
    /// Applied to IPv6 sources before bucketing (the subscriber prefix).
    src_mask: u128,
    cap_live: u16,
    cap_held: u16,
    cap_reasm: u16,
}

impl FragTable {
    /// Preallocates everything `cfg` allows. Called at worker start only.
    pub fn new(cfg: &FragmentsConfig) -> Self {
        let n = cfg.entries().max(WAYS as u32) as usize;
        let nb = usize::from(cfg.max_buffered_fragments);
        let sb = usize::from(cfg.buffer_slot_bytes);
        let nr = usize::from(cfg.reassembly_slots);
        let max_reasm = (cfg.max_reassembly_bytes as usize).min(MAX_DGRAM);
        Self {
            hasher: RandomState::new(),
            entries: vec![Entry::EMPTY; n].into_boxed_slice(),
            set_mask: n / WAYS - 1,
            timeout_ms: u64::from(cfg.timeout_ms),
            max_frags: cfg.max_fragments_per_datagram.min(255) as u8,
            live: 0,
            scan: 0,
            buf: vec![0u8; nb * sb].into_boxed_slice(),
            slot_bytes: sb,
            blen: vec![0u16; nb].into_boxed_slice(),
            bnext: (0..nb).map(|i| if i + 1 < nb { (i + 1) as u16 } else { NONE }).collect(),
            bfree: if nb > 0 { 0 } else { NONE },
            rbuf: (0..nr).map(|_| vec![0u8; REASM_PAYLOAD_OFF + max_reasm].into_boxed_slice()).collect(),
            rused: vec![false; nr].into_boxed_slice(),
            rhl: vec![0u16; nr].into_boxed_slice(),
            max_reasm,
            rown: vec![NO_OWNER; nr].into_boxed_slice(),
            bown: vec![NO_OWNER; nb].into_boxed_slice(),
            bscan: 0,
            load: vec![Load::default(); LOAD_BUCKETS].into_boxed_slice(),
            src_mask: u128::MAX,
            // COMPLIANCE MAPPING:
            // - NIST 800-53: SC-5 - no one source may hold more than a
            //   sixteenth of the table, a quarter of the held-fragment
            //   buffer or half of the reassembly slots
            cap_live: (n / 16).max(WAYS).min(usize::from(u16::MAX)) as u16,
            cap_held: (nb / 4).max(1) as u16,
            cap_reasm: (nr / 2).max(1) as u16,
        }
    }

    /// Groups IPv6 sources by `mask` (the subscriber prefix) for the
    /// per-source limits; IPv4 sources are grouped per address.
    pub fn set_src_mask(&mut self, mask: u128) {
        self.src_mask = mask;
    }

    /// Load bucket of `k`'s source; quote aliases are not counted (they
    /// follow a first fragment that was).
    #[inline]
    fn bucket(&self, k: &FragKey) -> u16 {
        let src = match k.kind {
            Kind::V6In => k.src & self.src_mask,
            Kind::V4In => k.src,
            Kind::Sent4 | Kind::Sent6 => return NO_LB,
        };
        (self.hasher.hash_one((src, k.kind as u8)) as usize % LOAD_BUCKETS) as u16
    }

    fn load_of(&self, lb: u16) -> Load {
        self.load.get(usize::from(lb)).copied().unwrap_or_default()
    }

    fn load_mut(&mut self, lb: u16) -> Option<&mut Load> {
        self.load.get_mut(usize::from(lb))
    }

    fn lb_of(&self, i: usize) -> u16 {
        self.entries.get(i).map_or(NO_LB, |e| e.lb)
    }

    /// Live entries (the `plat_fragment_entries` gauge).
    pub fn len(&self) -> u32 {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Buffering enabled and a slot free.
    pub fn can_buffer(&self) -> bool {
        self.bfree != NONE
    }

    pub fn reassembly_enabled(&self) -> bool {
        !self.rused.is_empty()
    }

    #[inline]
    fn set_of(&self, k: &FragKey) -> usize {
        ((self.hasher.hash_one(k) as usize) & self.set_mask) * WAYS
    }

    #[inline]
    fn expired(&self, e: &Entry, now: u64) -> bool {
        now >= e.born_ms + self.timeout_ms
    }

    /// Finds the live entry for `k`; an expired one is reclaimed (its held
    /// fragments counted as `fragment_timeout`).
    pub fn find(&mut self, k: &FragKey, now: u64, c: &Counters) -> Option<usize> {
        let s = self.set_of(k);
        for i in s..s + WAYS {
            if self.entries[i].st.is_some() && self.entries[i].key == *k {
                if self.expired(&self.entries[i], now) {
                    self.expire(i, c);
                    return None;
                }
                return Some(i);
            }
        }
        None
    }

    /// Finds or creates the entry for `k` (a new one starts `Pending`).
    ///
    /// A source already holding its share of entries is refused. A full set
    /// reuses an expired way, else evicts (`fragment_table_full`) the entry
    /// of the heaviest source, oldest first: any pass-through, alias or
    /// poisoned entry, or an entry holding buffered or reassembly data whose
    /// source is heavier than `k`'s. A light source therefore cannot be
    /// pushed out by a heavy one, and a heavy one mostly evicts itself.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - per-source entry cap, eviction by load
    pub fn get_or_insert(&mut self, k: &FragKey, now: u64, c: &Counters) -> Result<usize, DropReason> {
        if let Some(i) = self.find(k, now, c) {
            return Ok(i);
        }
        let lb = self.bucket(k);
        let mine = self.load_of(lb).live;
        if lb != NO_LB && mine >= self.cap_live {
            return Err(DropReason::FragmentTableFull);
        }
        let s = self.set_of(k);
        let mut free = None;
        let mut victim: Option<(usize, (bool, u16))> = None;
        for i in s..s + WAYS {
            let e = &self.entries[i];
            let Some(st) = e.st else {
                free = Some(i);
                break;
            };
            if self.expired(e, now) {
                self.expire(i, c);
                free = Some(i);
                break;
            }
            let w = self.load_of(e.lb).live;
            let ok = match st {
                St::Pass(_) | St::Poisoned(_) => true,
                St::Pending | St::Reasm(_) => e.lb != lb && e.lb != NO_LB && w > mine,
            };
            // SEC-007: quote aliases (no load bucket) rank below every
            // other eligible entry, so they are evicted last.
            let rank = (e.lb != NO_LB, w);
            let better = victim.is_none_or(|(v, vr)| rank > vr || (rank == vr && e.born_ms < self.entries[v].born_ms));
            if ok && better {
                victim = Some((i, rank));
            }
        }
        let i = match (free, victim) {
            (Some(i), _) => i,
            (None, Some((v, _))) => {
                c.record_drop(DropReason::FragmentTableFull);
                let held = self.release_data(v);
                c.record_drops(DropReason::FragmentTableFull, held);
                self.remove(v);
                v
            }
            (None, None) => return Err(DropReason::FragmentTableFull),
        };
        self.entries[i] = Entry { key: *k, born_ms: now, st: Some(St::Pending), lb, ..Entry::EMPTY };
        if let Some(l) = self.load_mut(lb) {
            l.live += 1;
        }
        self.live += 1;
        Ok(i)
    }

    /// Inserts (or refreshes) a quote alias. Best effort: a full set skips
    /// it, and ICMP errors quoting that fragment are then unmatched.
    pub fn alias(&mut self, k: &FragKey, fwd: Fwd, now: u64, c: &Counters) {
        if let Ok(i) = self.get_or_insert(k, now, c)
            && matches!(self.entries[i].st, Some(St::Pending | St::Pass(_)))
            && self.entries[i].nbuf == 0
        {
            self.entries[i].st = Some(St::Pass(fwd));
        }
    }

    pub fn state(&self, i: usize) -> Option<St> {
        self.entries.get(i).and_then(|e| e.st)
    }

    pub fn set_pass(&mut self, i: usize, fwd: Fwd) {
        if let Some(e) = self.entries.get_mut(i) {
            e.st = Some(St::Pass(fwd));
        }
    }

    /// Records one fragment `[off8 * 8, off8 * 8 + len)` of entry `i`. On
    /// overlap, duplicate, too many fragments or an inconsistent end, the
    /// entry is poisoned, its held fragments are dropped (counted with the
    /// same reason) and the reason is returned.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5722 - overlap → discard the datagram and its later fragments
    /// - NIST 800-53: SC-5, SI-10 - `max_fragments_per_datagram`
    pub fn account(&mut self, i: usize, off8: u16, len: usize, more: bool, c: &Counters) -> Result<Acct, DropReason> {
        let r = self.account_inner(i, off8, len, more);
        if let Err(d) = r {
            self.poison(i, d, c);
        }
        r
    }

    fn account_inner(&mut self, i: usize, off8: u16, len: usize, more: bool) -> Result<Acct, DropReason> {
        let max_frags = self.max_frags;
        let e = self.entries.get_mut(i).ok_or(DropReason::Malformed)?;
        if let Some(St::Poisoned(d)) = e.st {
            return Err(d);
        }
        e.nfrags = e.nfrags.saturating_add(1);
        if e.nfrags > max_frags {
            return Err(DropReason::FragmentTooMany);
        }
        let start = usize::from(off8) * 8;
        let end_b = start + len;
        if end_b > MAX_DGRAM || len == 0 {
            return Err(DropReason::Malformed);
        }
        let (s, en) = (off8, end_b.div_ceil(8) as u16);
        if let Some(t) = e.total {
            if end_b > usize::from(t) || (!more && end_b != usize::from(t)) {
                return Err(DropReason::FragmentOverlap);
            }
        } else if !more {
            if e.ranges[..usize::from(e.nranges)].iter().any(|r| r[1] > en) {
                return Err(DropReason::FragmentOverlap);
            }
            e.total = Some(end_b as u16);
        }
        let n = usize::from(e.nranges);
        // Any intersection (including an exact duplicate) is an overlap.
        if e.ranges[..n].iter().any(|r| s < r[1] && r[0] < en) {
            return Err(DropReason::FragmentOverlap);
        }
        // Insert sorted into a scratch copy, merge touching neighbours, and
        // refuse if more than MAX_RANGES disjoint ranges remain.
        let mut tmp = [[0u16; 2]; MAX_RANGES + 1];
        let pos = e.ranges[..n].iter().position(|r| r[0] > s).unwrap_or(n);
        tmp[..pos].copy_from_slice(&e.ranges[..pos]);
        tmp[pos] = [s, en];
        tmp[pos + 1..n + 1].copy_from_slice(&e.ranges[pos..n]);
        let mut m = 0;
        for k in 0..=n {
            if m > 0 && tmp[m - 1][1] == tmp[k][0] {
                tmp[m - 1][1] = tmp[k][1];
            } else {
                tmp[m] = tmp[k];
                m += 1;
            }
        }
        if m > MAX_RANGES {
            return Err(DropReason::FragmentTooMany);
        }
        e.ranges[..m].copy_from_slice(&tmp[..m]);
        e.nranges = m as u8;
        let complete = e.total.is_some_and(|t| {
            e.nranges == 1 && e.ranges[0][0] == 0 && e.ranges[0][1] == (usize::from(t).div_ceil(8)) as u16
        });
        Ok(if complete { Acct::Complete } else { Acct::Partial })
    }

    /// Poisons entry `i` with `d`, dropping its held fragments (counted).
    pub fn poison(&mut self, i: usize, d: DropReason, c: &Counters) {
        let held = self.release_data(i);
        c.record_drops(d, held);
        if let Some(e) = self.entries.get_mut(i) {
            e.st = Some(St::Poisoned(d));
        }
    }

    /// Drops entry `i` after its first fragment was refused with `d`; held
    /// fragments are counted with the same reason.
    pub fn abandon(&mut self, i: usize, d: DropReason, c: &Counters) {
        let held = self.release_data(i);
        c.record_drops(d, held);
        self.remove(i);
    }

    /// Holds a copy of the packet `pkt` (a non-first fragment) on entry `i`.
    ///
    /// A source holding its share of the buffer is refused. When the buffer
    /// is full, a pending datagram of a heavier source (among a bounded scan
    /// of slots) is dropped to make room (`fragment_buffer_full`).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - per-source held-fragment cap
    pub fn buffer(&mut self, i: usize, pkt: &[u8], c: &Counters) -> Result<(), DropReason> {
        let lb = self.lb_of(i);
        let mine = self.load_of(lb).held;
        if pkt.len() > self.slot_bytes || mine >= self.cap_held || self.bown.is_empty() {
            return Err(DropReason::FragmentBufferFull);
        }
        if self.bfree == NONE {
            self.evict_buffered(lb, mine, c);
        }
        if self.bfree == NONE {
            return Err(DropReason::FragmentBufferFull);
        }
        let slot = self.bfree;
        let si = usize::from(slot);
        self.bfree = self.bnext[si];
        self.bown[si] = i as u32;
        if let Some(l) = self.load_mut(lb) {
            l.held += 1;
        }
        let off = si * self.slot_bytes;
        self.buf[off..off + pkt.len()].copy_from_slice(pkt);
        self.blen[si] = pkt.len() as u16;
        self.bnext[si] = NONE;
        let e = &mut self.entries[i];
        if e.tail == NONE {
            e.head = slot;
        } else {
            self.bnext[usize::from(e.tail)] = slot;
        }
        e.tail = slot;
        e.nbuf += 1;
        Ok(())
    }

    /// Drops the pending datagram of the heaviest source other than `lb`
    /// found in the next [`EVICT_SCAN`] buffer slots, if it holds more than
    /// `mine` fragments.
    fn evict_buffered(&mut self, lb: u16, mine: u16, c: &Counters) {
        let nb = self.bown.len();
        let mut best: Option<(usize, u16)> = None;
        for _ in 0..EVICT_SCAN.min(nb) {
            let s = self.bscan;
            self.bscan = (self.bscan + 1) % nb;
            let o = self.bown[s] as usize;
            let Some(e) = self.entries.get(o) else { continue };
            if e.lb == lb || e.st != Some(St::Pending) {
                continue;
            }
            let w = self.load_of(e.lb).held;
            if w > mine && best.is_none_or(|(_, bw)| w > bw) {
                best = Some((o, w));
            }
        }
        if let Some((o, _)) = best {
            let held = self.release_data(o);
            c.record_drops(DropReason::FragmentBufferFull, held);
            self.remove(o);
        }
    }

    /// Unlinks the oldest held fragment of entry `i`; read it with
    /// [`FragTable::slot`], then return it with [`FragTable::free_slot`].
    pub fn pop_buffered(&mut self, i: usize) -> Option<u16> {
        let e = self.entries.get_mut(i)?;
        if e.head == NONE {
            return None;
        }
        let s = e.head;
        e.head = self.bnext[usize::from(s)];
        if e.head == NONE {
            e.tail = NONE;
        }
        e.nbuf -= 1;
        let lb = e.lb;
        if let Some(l) = self.load_mut(lb) {
            l.held = l.held.saturating_sub(1);
        }
        Some(s)
    }

    pub fn has_buffered(&self, i: usize) -> bool {
        self.entries.get(i).is_some_and(|e| e.nbuf > 0)
    }

    pub fn slot(&self, s: u16) -> &[u8] {
        let si = usize::from(s);
        let off = si * self.slot_bytes;
        &self.buf[off..off + usize::from(self.blen[si])]
    }

    pub fn free_slot(&mut self, s: u16) {
        let si = usize::from(s);
        self.bown[si] = NO_OWNER;
        self.bnext[si] = self.bfree;
        self.bfree = s;
    }

    /// Starts reassembling entry `i`: reserves a slot, stores `hdr` (the
    /// first fragment's IPv4 header, or a 40-byte IPv6 header without
    /// extension headers) and moves any held fragments in.
    ///
    /// A source holding its share of slots is refused; when every slot is
    /// busy, the oldest reassembly of another source is dropped
    /// (`reassembly_full`) to make room.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - per-source reassembly cap
    pub fn start_reasm(&mut self, i: usize, hdr: &[u8], v6: bool, c: &Counters) -> Result<(), DropReason> {
        let lb = self.lb_of(i);
        if hdr.len() > 60 || self.load_of(lb).reasm >= self.cap_reasm {
            return Err(DropReason::ReassemblyFull);
        }
        if !self.rused.iter().any(|u| !u) {
            let victim = (0..self.rown.len())
                .filter_map(|s| {
                    let o = self.rown[s] as usize;
                    self.entries.get(o).filter(|e| e.lb != lb).map(|e| (o, e.born_ms))
                })
                .min_by_key(|&(_, b)| b);
            if let Some((o, _)) = victim {
                let held = self.release_data(o);
                c.record_drops(DropReason::ReassemblyFull, held);
                self.remove(o);
            }
        }
        let slot = self.rused.iter().position(|u| !u).ok_or(DropReason::ReassemblyFull)?;
        if self.rbuf[slot].is_empty() {
            return Err(DropReason::ReassemblyFull);
        }
        self.rused[slot] = true;
        self.rown[slot] = i as u32;
        if let Some(l) = self.load_mut(lb) {
            l.reasm += 1;
        }
        self.rhl[slot] = hdr.len() as u16;
        self.rbuf[slot][REASM_PAYLOAD_OFF - hdr.len()..REASM_PAYLOAD_OFF].copy_from_slice(hdr);
        self.entries[i].st = Some(St::Reasm(slot as u16));
        while let Some(s) = self.pop_buffered(i) {
            let r = {
                let pkt = self.slot(s);
                let parsed = if v6 {
                    parse_v6(pkt).ok().and_then(|h| h.frag.map(|f| (h.l4_off, h.total_len(), f.offset)))
                } else {
                    parse_v4(pkt).ok().and_then(|h| h.frag.map(|f| (h.hdr_len, h.total_len, f.offset)))
                };
                parsed.ok_or(DropReason::Malformed)
            };
            let res = r.and_then(|(a, b, off)| {
                let start = usize::from(off) * 8;
                let len = b - a;
                if start + len > self.max_reasm {
                    return Err(DropReason::ReassemblyTooBig);
                }
                let si = usize::from(s);
                let src = si * self.slot_bytes + a..si * self.slot_bytes + b;
                let dst = REASM_PAYLOAD_OFF + start;
                let (rb, b) = (&mut self.rbuf[slot], &self.buf);
                rb[dst..dst + len].copy_from_slice(&b[src]);
                Ok(())
            });
            self.free_slot(s);
            res?;
        }
        Ok(())
    }

    /// Copies a fragment's payload into the reassembly slot of entry `i`.
    pub fn reasm_put(&mut self, i: usize, off8: u16, payload: &[u8]) -> Result<(), DropReason> {
        let Some(St::Reasm(slot)) = self.state(i) else {
            return Err(DropReason::Malformed);
        };
        let start = usize::from(off8) * 8;
        if start + payload.len() > self.max_reasm {
            return Err(DropReason::ReassemblyTooBig);
        }
        let d = REASM_PAYLOAD_OFF + start;
        self.rbuf[usize::from(slot)][d..d + payload.len()].copy_from_slice(payload);
        Ok(())
    }

    /// Finishes a complete reassembly: patches the stored header (length,
    /// no fragment fields, IPv4 checksum) and lends the slot buffer out.
    /// The entry is removed; the buffer must come back through
    /// [`FragTable::return_reasm`].
    pub fn take_reasm(&mut self, i: usize) -> Result<Reassembled, DropReason> {
        let (Some(St::Reasm(slot)), Some(total)) = (self.state(i), self.entries[i].total) else {
            return Err(DropReason::Malformed);
        };
        let si = usize::from(slot);
        let hl = usize::from(self.rhl[si]);
        let total = usize::from(total);
        let start = REASM_PAYLOAD_OFF - hl;
        let b = &mut self.rbuf[si];
        if b.get(start).map(|v| v >> 4) == Some(4) {
            if hl + total > MAX_DGRAM {
                return Err(DropReason::ReassemblyTooBig);
            }
            plat_packet::put16(b, start + 2, (hl + total) as u16);
            plat_packet::put16(b, start + 6, 0);
            plat_packet::put16(b, start + 10, 0);
            let c = plat_packet::checksum::finish(plat_packet::checksum::sum(&b[start..start + hl]));
            plat_packet::put16(b, start + 10, c);
        } else {
            plat_packet::put16(b, start + 4, total as u16);
        }
        let buf = std::mem::take(&mut self.rbuf[si]);
        // The slot stays reserved until the buffer returns.
        self.rown[si] = NO_OWNER;
        let lb = self.entries[i].lb;
        if let Some(l) = self.load_mut(lb) {
            l.reasm = l.reasm.saturating_sub(1);
        }
        self.entries[i].st = Some(St::Pending);
        self.remove(i);
        Ok(Reassembled { slot, buf, start, len: hl + total })
    }

    /// Returns a slot buffer lent out by [`FragTable::take_reasm`].
    pub fn return_reasm(&mut self, slot: u16, buf: Box<[u8]>) {
        let si = usize::from(slot);
        if let (Some(b), Some(u)) = (self.rbuf.get_mut(si), self.rused.get_mut(si)) {
            *b = buf;
            *u = false;
        }
    }

    /// Frees entry `i`'s buffered fragments and reassembly slot; returns
    /// how many fragments it held.
    fn release_data(&mut self, i: usize) -> u64 {
        let mut held = 0u64;
        while let Some(s) = self.pop_buffered(i) {
            self.free_slot(s);
            held += 1;
        }
        if let Some(St::Reasm(slot)) = self.state(i) {
            if let Some(u) = self.rused.get_mut(usize::from(slot)) {
                *u = false;
            }
            if let Some(o) = self.rown.get_mut(usize::from(slot)) {
                *o = NO_OWNER;
            }
            let lb = self.lb_of(i);
            if let Some(l) = self.load_mut(lb) {
                l.reasm = l.reasm.saturating_sub(1);
            }
            held += u64::from(self.entries[i].nfrags);
            self.entries[i].st = Some(St::Pending);
        }
        held
    }

    /// Frees entry `i` (and anything it holds, uncounted).
    pub fn remove(&mut self, i: usize) {
        if self.entries.get(i).is_some_and(|e| e.st.is_some()) {
            self.release_data(i);
            let lb = self.entries[i].lb;
            if let Some(l) = self.load_mut(lb) {
                l.live = l.live.saturating_sub(1);
            }
            self.entries[i] = Entry::EMPTY;
            self.live -= 1;
        }
    }

    fn expire(&mut self, i: usize, c: &Counters) {
        let held = self.release_data(i);
        c.record_drops(DropReason::FragmentTimeout, held);
        self.remove(i);
    }

    /// Incremental expiry: scans `sets` sets per call, so held fragments
    /// are dropped (`fragment_timeout`) within about `timeout_ms` plus one
    /// pass even when no packet of their set arrives.
    pub fn housekeep(&mut self, now: u64, sets: usize, c: &Counters) {
        let nsets = self.set_mask + 1;
        for _ in 0..sets.min(nsets) {
            let s = self.scan * WAYS;
            self.scan = (self.scan + 1) & self.set_mask;
            for i in s..s + WAYS {
                if self.entries[i].st.is_some() && self.expired(&self.entries[i], now) {
                    self.expire(i, c);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(buffered: u16, reasm: u16) -> FragmentsConfig {
        FragmentsConfig {
            max_entries: 1024,
            max_buffered_fragments: buffered,
            reassembly_slots: reasm,
            max_fragments_per_datagram: 8,
            ..FragmentsConfig::default()
        }
    }

    fn key(id: u32) -> FragKey {
        FragKey { src: 1, dst: 2, id, proto: 17, kind: Kind::V6In }
    }

    #[test]
    fn insert_lookup_expiry() {
        let c = Counters::default();
        let mut t = FragTable::new(&cfg(4, 1));
        let i = t.get_or_insert(&key(1), 1000, &c).unwrap();
        t.buffer(i, &[0x60; 100], &c).unwrap();
        assert_eq!(t.find(&key(1), 2999, &c), Some(i));
        assert_eq!(t.len(), 1);
        // Expires 2000 ms after creation; the held fragment is counted.
        assert_eq!(t.find(&key(1), 3000, &c), None);
        assert_eq!((t.len(), c.drops(DropReason::FragmentTimeout)), (0, 1));
        assert!(t.can_buffer());
    }

    fn key_from(src: u128, id: u32) -> FragKey {
        FragKey { src, dst: 2, id, proto: 17, kind: Kind::V4In }
    }

    #[test]
    fn housekeeping_expires_without_traffic() {
        let c = Counters::default();
        let mut t = FragTable::new(&cfg(4, 1));
        // Ten sources, so the per-source held cap (1 here) is not the limit.
        for id in 0..10 {
            let i = t.get_or_insert(&key_from(u128::from(id), id), 0, &c).unwrap();
            t.buffer(i, &[0; 10], &c).unwrap_or(());
        }
        for _ in 0..(1024 / WAYS).div_ceil(8) {
            t.housekeep(5000, 8, &c);
        }
        assert_eq!(t.len(), 0);
        assert_eq!(c.drops(DropReason::FragmentTimeout), 4, "four buffer slots held");
        // Every slot came back.
        let mut n = 0;
        for id in 100..110 {
            if !t.can_buffer() {
                break;
            }
            let i = t.get_or_insert(&key_from(u128::from(id), id), 6000, &c).unwrap();
            t.buffer(i, &[0; 10], &c).unwrap();
            n += 1;
        }
        assert_eq!(n, 4);
    }

    #[test]
    fn overlap_and_duplicate_poison() {
        let c = Counters::default();
        let mut t = FragTable::new(&cfg(4, 1));
        let i = t.get_or_insert(&key(1), 0, &c).unwrap();
        assert_eq!(t.account(i, 0, 16, true, &c), Ok(Acct::Partial));
        assert_eq!(t.account(i, 4, 16, true, &c), Ok(Acct::Partial));
        // Duplicate of [32, 48).
        assert_eq!(t.account(i, 4, 16, true, &c), Err(DropReason::FragmentOverlap));
        assert_eq!(t.state(i), Some(St::Poisoned(DropReason::FragmentOverlap)));
        assert_eq!(t.account(i, 6, 8, false, &c), Err(DropReason::FragmentOverlap));

        // Teardrop shape: [0, 24) then [16, 40).
        let j = t.get_or_insert(&key(2), 0, &c).unwrap();
        t.account(j, 0, 24, true, &c).unwrap();
        assert_eq!(t.account(j, 2, 24, false, &c), Err(DropReason::FragmentOverlap));
    }

    #[test]
    fn completion_in_any_order() {
        let c = Counters::default();
        let mut t = FragTable::new(&cfg(4, 1));
        let i = t.get_or_insert(&key(1), 0, &c).unwrap();
        assert_eq!(t.account(i, 2, 5, false, &c), Ok(Acct::Partial));
        assert_eq!(t.account(i, 0, 8, true, &c), Ok(Acct::Partial));
        assert_eq!(t.account(i, 1, 8, true, &c), Ok(Acct::Complete));
    }

    #[test]
    fn end_mismatch_and_too_many() {
        let c = Counters::default();
        let mut t = FragTable::new(&cfg(4, 1));
        let i = t.get_or_insert(&key(1), 0, &c).unwrap();
        t.account(i, 0, 8, false, &c).unwrap();
        assert_eq!(t.account(i, 1, 8, true, &c), Err(DropReason::FragmentOverlap));
        let j = t.get_or_insert(&key(2), 0, &c).unwrap();
        for k in 0..8 {
            t.account(j, k * 2, 8, true, &c).unwrap();
        }
        assert_eq!(t.account(j, 100, 8, true, &c), Err(DropReason::FragmentTooMany));
        // Offsets past 65535 bytes.
        let k = t.get_or_insert(&key(3), 0, &c).unwrap();
        assert_eq!(t.account(k, 8191, 16, false, &c), Err(DropReason::Malformed));
    }

    #[test]
    fn eviction_prefers_pass_through_and_spares_buffered() {
        let c = Counters::default();
        let mut t = FragTable::new(&FragmentsConfig { max_entries: 1024, ..cfg(64, 0) });
        // Fill one set with buffered entries: find WAYS keys in one set.
        let s0 = t.set_of(&key(0));
        let same: Vec<u32> = (0..10_000).filter(|&id| t.set_of(&key(id)) == s0).take(WAYS + 1).collect();
        for &id in &same[..WAYS] {
            let i = t.get_or_insert(&key(id), 0, &c).unwrap();
            t.buffer(i, &[0; 8], &c).unwrap();
        }
        assert_eq!(t.get_or_insert(&key(same[WAYS]), 1, &c), Err(DropReason::FragmentTableFull));
        // Make one way pass-through: it becomes the victim.
        let i = t.find(&key(same[1]), 1, &c).unwrap();
        while let Some(s) = t.pop_buffered(i) {
            t.free_slot(s);
        }
        t.set_pass(i, Fwd::To6 { dst: 9, idx: 0 });
        assert_eq!(t.get_or_insert(&key(same[WAYS]), 1, &c), Ok(i));
        assert_eq!(c.drops(DropReason::FragmentTableFull), 1);
    }

    #[test]
    fn eviction_spares_quote_aliases() {
        let c = Counters::default();
        let mut t = FragTable::new(&cfg(0, 0));
        let alias = |id| FragKey { src: 5, dst: 6, id, proto: 17, kind: Kind::Sent4 };
        let s0 = t.set_of(&alias(0));
        let al: Vec<u32> = (0..100_000).filter(|&id| t.set_of(&alias(id)) == s0).take(WAYS - 1).collect();
        let pass = (0..100_000).find(|&id| t.set_of(&key_from(9, id)) == s0).unwrap();
        let fresh = (pass + 1..200_000).find(|&id| t.set_of(&key_from(9, id)) == s0).unwrap();
        let fwd = Fwd::Sent6 { pool: 1, idx: 0 };
        // Aliases first (oldest), then one pass-through entry.
        for &id in &al {
            t.alias(&alias(id), fwd, 0, &c);
        }
        let p = t.get_or_insert(&key_from(9, pass), 1, &c).unwrap();
        t.set_pass(p, Fwd::To6 { dst: 9, idx: 0 });
        // The pass-through entry goes, not an older alias.
        assert_eq!(t.get_or_insert(&key_from(9, fresh), 2, &c), Ok(p));
        for &id in &al {
            assert!(t.find(&alias(id), 2, &c).is_some(), "alias {id} kept");
        }
    }

    #[test]
    fn flood_is_bounded() {
        let c = Counters::default();
        let mut t = FragTable::new(&cfg(64, 4));
        for id in 0..100_000u32 {
            if let Ok(i) = t.get_or_insert(&key(id), u64::from(id / 100), &c) {
                let _ = t.account(i, 8, 64, true, &c);
                let _ = t.buffer(i, &[0; 64], &c);
            }
        }
        // One source: never more than its share of the table.
        assert!(t.len() <= u32::from(t.cap_live));
    }

    #[test]
    fn one_source_cannot_fill_the_table_or_evict_others() {
        let c = Counters::default();
        let mut t = FragTable::new(&cfg(0, 0));
        // A light source's pass-through entries, spread over the table.
        let light: Vec<usize> = (0..32u32)
            .map(|id| {
                let i = t.get_or_insert(&key_from(7, id), 0, &c).unwrap();
                t.set_pass(i, Fwd::To6 { dst: 9, idx: 0 });
                i
            })
            .collect();
        // A heavy source floods: capped at max_entries / 16.
        let mut ok = 0;
        for id in 0..100_000u32 {
            if let Ok(i) = t.get_or_insert(&key_from(8, id), 1, &c) {
                t.set_pass(i, Fwd::To6 { dst: 9, idx: 0 });
                ok += 1;
            }
        }
        assert!(ok > 0);
        let heavy_live = (0..t.entries.len()).filter(|&i| t.entries[i].key.src == 8).count();
        assert!(heavy_live <= usize::from(t.cap_live), "{heavy_live}");
        // Eviction picks the heavier source first, so every light entry is
        // still there.
        for (id, i) in light.iter().enumerate() {
            assert_eq!(t.find(&key_from(7, id as u32), 1, &c), Some(*i));
        }
    }

    #[test]
    fn buffer_flood_from_one_source_does_not_block_another() {
        let c = Counters::default();
        let mut t = FragTable::new(&cfg(16, 0));
        // Heavy source: at most a quarter of the buffer.
        let mut held = 0;
        for id in 0..64u32 {
            let i = t.get_or_insert(&key_from(8, id), 0, &c).unwrap();
            if t.buffer(i, &[0; 8], &c).is_ok() {
                held += 1;
            }
        }
        assert_eq!(held, 4);
        // Three more sources fill the rest.
        for src in 1..4u128 {
            for id in 0..4u32 {
                let i = t.get_or_insert(&key_from(src, id), 0, &c).unwrap();
                t.buffer(i, &[0; 8], &c).unwrap();
            }
        }
        assert!(!t.can_buffer());
        // A new source still gets a slot: a heavier source's datagram goes.
        let i = t.get_or_insert(&key_from(99, 0), 0, &c).unwrap();
        t.buffer(i, &[0; 8], &c).unwrap();
        assert_eq!(c.drops(DropReason::FragmentBufferFull), 1);
    }

    #[test]
    fn reassembly_slot_is_reclaimed_from_another_source() {
        let c = Counters::default();
        let mut t = FragTable::new(&cfg(0, 2));
        let hdr = [0x45u8; 20];
        // One source: capped at half the slots.
        let a = t.get_or_insert(&key_from(8, 1), 0, &c).unwrap();
        t.start_reasm(a, &hdr, false, &c).unwrap();
        let b = t.get_or_insert(&key_from(8, 2), 0, &c).unwrap();
        assert_eq!(t.start_reasm(b, &hdr, false, &c), Err(DropReason::ReassemblyFull));
        let d = t.get_or_insert(&key_from(9, 1), 1, &c).unwrap();
        t.start_reasm(d, &hdr, false, &c).unwrap();
        // Both slots busy: a third source takes the oldest other one.
        let e = t.get_or_insert(&key_from(10, 1), 2, &c).unwrap();
        t.start_reasm(e, &hdr, false, &c).unwrap();
        assert_eq!(t.find(&key_from(8, 1), 2, &c), None);
        assert!(matches!(t.state(d), Some(St::Reasm(_))));
    }
}
