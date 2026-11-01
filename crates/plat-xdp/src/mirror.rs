//! The session writer (plan §4.3): installs established UDP sessions into
//! `SLOT` / `IN4` / `OUT6`, retires them, reads the fast path's `seen_ns`,
//! and writes slice state and generation into `SLICE`.
//!
//! Inherent methods only. The `plat-nat64` mirror trait (WU4) and the
//! `impl … for XdpMirror` glue (WU5) are not here; [`SessionEntry`] carries
//! the same facts as plan §4.4's `MirrorEntry` (`k6`, `k4`, remote, `dst6`,
//! slice).
//!
//! **Caller contract.** `install` and `retire` for one session run inside
//! the `bib4` shard critical section that creates or removes it (plan §4.2;
//! lock order `bib4 → xslot`), and only after the attribution record was
//! handed to the audit sink (CLAUDE.md rule 4; I4). So two calls for the
//! same key never race, and no install happens for a session the slow path
//! could not use. Under `on_overflow = "drop_and_alert"` that record may
//! have been dropped (with an alert): the session is then installed like
//! any other, exactly as the slow path keeps using its mapping (the rule 4
//! exception; `plat-nat64` test
//! `drop_and_alert_installs_even_when_the_record_is_lost`). The engine
//! wiring is WU5; until then this is the contract, not enforced code.
//!
//! **Install** (one `SLOT` record, then two `BPF_NOEXIST` inserts):
//! 1. take a slot from the caller's partition ([`SlotAllocator`]);
//! 2. write words 1-7 of the record while it is unreachable, `fence(Release)`;
//! 3. store word 0 (`state = LIVE`, slice, current slice generation);
//! 4. insert `IN4`, then `OUT6`. On any error, roll back (delete what was
//!    inserted, `state = DEAD`, quarantine the slot) and fail; `E2BIG`
//!    (map full) also backs installs off for [`INSTALL_BACKOFF`].
//!
//! **Retire** (only of a live slot, QA F1): `state = DEAD`, delete `OUT6`
//! and `IN4`, quarantine.
//!
//! When `retire` returns, no *new* program run can use the session, but a
//! run that started before (it already read `state = LIVE`) may still
//! translate and forward its one packet: at most one packet per CPU,
//! within one RCU grace period after the retire (SEC-006). If the caller
//! returns the session's port block to the pool at once and it is
//! reassigned within that window, such a packet would leave with a
//! mapping the audit trail attributes to the previous subscriber. This is
//! a recorded residual (fixes-wu34-round-1; WU5 may defer the block return
//! to the next slot epoch). A program that read a hash value just before a
//! delete may also see a reused element: it then reads another live slot
//! whose key echo differs, and passes (plan §4.3 proof sketch). Slot
//! records are rewritten only after the RCU grace period of
//! [`SlotAllocator`].
//!
//! **Counters** are per lane (`shard` or slot modulo [`COUNTER_LANES`]),
//! each lane on its own cache line, so workers installing and retiring in
//! different shards do not share a written line (PERF-005).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-12 / CLAUDE.md rule 4 - by contract (enforced once
//!   wired, WU5), installs follow the attribution record handed to the
//!   sink (I4), except that under `drop_and_alert` the record may have
//!   been dropped; this writer emits no records
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - bounded maps and
//!   slots; full maps back installs off and leave sessions on the slow path
//! - NIST 800-53: SC-7, SC-24 - slice state and generation in `SLICE`;
//!   fencing is one atomic store followed by a full fence
//! - RFC 6146 §3.5.1 - `seen_ns` lets the slow path extend a session kept
//!   alive only by fast-path traffic (WU5 converts the clock)

use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering, fence};
use std::time::{Duration, Instant};

use plat_xdp_core::abi::{
    Key4, Key6, MAX_SLICES, SLICE_ACTIVE, SLOT_DEAD, SLOT_LIVE, SLOT_WORD_HDR, SLOT_WORD_SEEN, SLOT_WORDS, SliceEnt,
    SlotRec,
};

use crate::maps::Words;
use crate::slots::SlotAllocator;

/// Install backoff after the hash maps reported full (plan §4.3).
pub const INSTALL_BACKOFF: Duration = Duration::from_secs(1);

/// `OUT6` / `IN4` element operations (the pins on Linux; an in-memory
/// model in tests). Inserts are `BPF_NOEXIST`.
pub trait SessionTables: Send + Sync + fmt::Debug {
    fn insert_out6(&self, key: &[u8; 40], slot: u32) -> io::Result<()>;
    fn insert_in4(&self, key: &[u8; 12], slot: u32) -> io::Result<()>;
    /// `Ok(false)` when the key was absent.
    fn delete_out6(&self, key: &[u8; 40]) -> io::Result<bool>;
    fn delete_in4(&self, key: &[u8; 12]) -> io::Result<bool>;
}

/// One UDP session as the fast path matches and rewrites it. Ports in host
/// order; addresses in network order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEntry {
    /// Subscriber IPv6 address and port (`k6` source).
    pub src6: [u8; 16],
    pub sport6: u16,
    /// Canonical RFC 6052 embedding of `dst4` (`k6` destination).
    pub dst6: [u8; 16],
    /// Remote IPv4 address and port.
    pub dst4: [u8; 4],
    pub dport: u16,
    /// Pool address and port (`k4`).
    pub pool4: [u8; 4],
    pub pool_port4: u16,
    /// Pool slice of `pool4` (0 without a sliced pool).
    pub slice: u16,
}

impl SessionEntry {
    /// The `OUT6` key.
    pub fn key6(&self) -> Key6 {
        Key6::new(self.src6, self.dst6, self.sport6.to_be_bytes(), self.dport.to_be_bytes())
    }

    /// The `IN4` key.
    pub fn key4(&self) -> Key4 {
        Key4::new(self.pool4, self.dst4, self.pool_port4.to_be_bytes(), self.dport.to_be_bytes())
    }

    /// The `SLOT` record with `state`, `generation` and `seen_ns = 0`.
    pub fn record(&self, state: u8, generation: u32) -> SlotRec {
        SlotRec {
            state,
            slice: self.slice,
            generation,
            src6: self.src6,
            dst6: self.dst6,
            sport6: self.sport6.to_be_bytes(),
            dport: self.dport.to_be_bytes(),
            pool_port4: self.pool_port4.to_be_bytes(),
            pool4: self.pool4,
            dst4: self.dst4,
            ..SlotRec::default()
        }
    }

    /// The entry a record describes (for retiring stale records).
    pub fn from_record(r: &SlotRec) -> Self {
        Self {
            src6: r.src6,
            sport6: u16::from_be_bytes(r.sport6),
            dst6: r.dst6,
            dst4: r.dst4,
            dport: u16::from_be_bytes(r.dport),
            pool4: r.pool4,
            pool_port4: u16::from_be_bytes(r.pool_port4),
            slice: r.slice,
        }
    }
}

/// Why an install did not happen (the session stays on the slow path).
///
/// PERF-002: the WU5 `impl Mirror` maps [`InstallError::MapFull`] and
/// [`InstallError::Slots`] to `MirrorFail::Full` ([`InstallError::is_full`])
/// and the rest to `MirrorFail::Error`; the engine backs off after any
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    /// `OUT6` / `IN4` full (`E2BIG`), or within the backoff after it.
    #[error("fast-path session maps full")]
    MapFull,
    /// The caller's slot partition is empty (all in use or quarantined).
    #[error("no free fast-path slot in the partition")]
    Slots,
    /// Any other failure (duplicate key, slice out of range, syscall error).
    #[error("fast-path install failed")]
    Error,
}

impl InstallError {
    /// Capacity class (maps full, or no free slot in the partition).
    pub const fn is_full(self) -> bool {
        matches!(self, Self::MapFull | Self::Slots)
    }

    /// `reason` label of `plat_xdp_install_failures_total`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MapFull => "map_full",
            Self::Slots => "slots",
            Self::Error => "error",
        }
    }
}

/// Lanes of a [`LaneCounter`].
pub const COUNTER_LANES: usize = 64;

/// One cache-line-aligned lane (128 B: adjacent-line prefetch on x86).
#[derive(Debug, Default)]
#[repr(align(128))]
struct Lane(AtomicU64);

/// A counter split into [`COUNTER_LANES`] padded lanes (PERF-005). Adds
/// and subtracts wrap per lane; [`LaneCounter::get`] sums the lanes with
/// wrapping, which is exact whenever the true total is in `u64` (a gauge
/// that is added and subtracted on different lanes stays correct).
#[derive(Debug)]
pub struct LaneCounter(Box<[Lane]>);

impl Default for LaneCounter {
    fn default() -> Self {
        Self((0..COUNTER_LANES).map(|_| Lane::default()).collect())
    }
}

impl LaneCounter {
    #[inline]
    fn lane(&self, lane: usize) -> Option<&AtomicU64> {
        self.0.get(lane % COUNTER_LANES).map(|l| &l.0)
    }

    /// Adds `n` on lane `lane % COUNTER_LANES`.
    #[inline]
    pub fn add(&self, lane: usize, n: u64) {
        if let Some(a) = self.lane(lane) {
            a.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Subtracts `n` on lane `lane % COUNTER_LANES` (wrapping).
    #[inline]
    pub fn sub(&self, lane: usize, n: u64) {
        if let Some(a) = self.lane(lane) {
            a.fetch_sub(n, Ordering::Relaxed);
        }
    }

    /// The total.
    pub fn get(&self) -> u64 {
        self.0.iter().fold(0u64, |t, l| t.wrapping_add(l.0.load(Ordering::Relaxed)))
    }
}

/// Writer counters (plan §4.7).
#[derive(Debug, Default)]
pub struct MirrorCounters {
    pub installs: LaneCounter,
    pub install_map_full: LaneCounter,
    pub install_slots: LaneCounter,
    pub install_error: LaneCounter,
    pub retires: LaneCounter,
    /// Retires refused because the slot was not live (a double retire or
    /// an out-of-range index; QA F1).
    pub retire_not_live: LaneCounter,
    /// Incremented by the slow path when `seen_ns` extended a session.
    pub revalidated: LaneCounter,
    pub gc_deleted: LaneCounter,
    /// Live installed sessions (`plat_xdp_sessions`).
    pub sessions: LaneCounter,
}

/// See the module documentation.
#[derive(Debug)]
pub struct XdpMirror {
    tables: Arc<dyn SessionTables>,
    slot_mem: Arc<dyn Words>,
    slice_mem: Arc<dyn Words>,
    slots: SlotAllocator,
    origin: Instant,
    /// Nanoseconds since `origin` before which installs are skipped.
    backoff_until: AtomicU64,
    counters: MirrorCounters,
}

impl XdpMirror {
    /// A writer over the given tables and shared memory. `slot_mem` must
    /// hold `slots × 8` words and `slice_mem` [`MAX_SLICES`] words, or
    /// out-of-range writes are skipped and installs fail.
    pub fn with_parts(
        tables: Arc<dyn SessionTables>,
        slot_mem: Arc<dyn Words>,
        slice_mem: Arc<dyn Words>,
        slots: u32,
        partitions: usize,
    ) -> Self {
        Self {
            tables,
            slot_mem,
            slice_mem,
            slots: SlotAllocator::new(slots, partitions),
            origin: Instant::now(),
            backoff_until: AtomicU64::new(0),
            counters: MirrorCounters::default(),
        }
    }

    /// The writer over `platd`'s pins.
    #[cfg(target_os = "linux")]
    pub fn new(maps: &crate::maps::XdpMaps, partitions: usize) -> Self {
        let tables: Arc<dyn SessionTables> = maps.tables.clone();
        let slot_mem: Arc<dyn Words> = maps.slot.clone();
        let slice_mem: Arc<dyn Words> = maps.slice.clone();
        Self::with_parts(tables, slot_mem, slice_mem, maps.slots(), partitions)
    }

    pub fn counters(&self) -> &MirrorCounters {
        &self.counters
    }

    /// The slot allocator (the control thread drives its grace periods).
    pub fn slot_allocator(&self) -> &SlotAllocator {
        &self.slots
    }

    fn slot_words(&self, slot: u32) -> Option<&[AtomicU64]> {
        let base = (slot as usize).checked_mul(SLOT_WORDS)?;
        self.slot_mem.words().get(base..base.checked_add(SLOT_WORDS)?)
    }

    fn slice_word(&self, slice: u16) -> Option<&AtomicU64> {
        if u32::from(slice) >= MAX_SLICES {
            return None;
        }
        self.slice_mem.words().get(usize::from(slice))
    }

    fn now(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn fail(&self, lane: usize, e: InstallError) -> InstallError {
        let c = match e {
            InstallError::MapFull => &self.counters.install_map_full,
            InstallError::Slots => &self.counters.install_slots,
            InstallError::Error => &self.counters.install_error,
        };
        c.add(lane, 1);
        e
    }

    /// Installs `e` from the caller's `shard` (its `bib4` shard index) and
    /// returns the slot. See the module documentation for the order and the
    /// caller contract.
    pub fn install(&self, e: &SessionEntry, shard: usize) -> Result<u32, InstallError> {
        if self.now() < self.backoff_until.load(Ordering::Relaxed) {
            return Err(self.fail(shard, InstallError::MapFull));
        }
        let Some(sw) = self.slice_word(e.slice) else {
            return Err(self.fail(shard, InstallError::Error));
        };
        let generation = SliceEnt::from_bytes(&sw.load(Ordering::Acquire).to_ne_bytes()).generation;
        let Some(slot) = self.slots.alloc(shard) else {
            return Err(self.fail(shard, InstallError::Slots));
        };
        let Some(w) = self.slot_words(slot) else {
            self.slots.retire(slot);
            return Err(self.fail(shard, InstallError::Error));
        };
        let words = e.record(SLOT_LIVE, generation).to_words();
        // Unreachable: no hash entry points here, and the header word still
        // says FREE/DEAD from before.
        for (d, s) in w.iter().zip(words.iter()).skip(1) {
            d.store(*s, Ordering::Relaxed);
        }
        fence(Ordering::Release);
        if let (Some(h), Some(v)) = (w.get(SLOT_WORD_HDR), words.get(SLOT_WORD_HDR)) {
            h.store(*v, Ordering::Release);
        }
        let k4 = e.key4().to_bytes();
        let k6 = e.key6().to_bytes();
        if let Err(err) = self.tables.insert_in4(&k4, slot) {
            self.abandon(slot, None);
            return Err(self.install_err(shard, &err));
        }
        if let Err(err) = self.tables.insert_out6(&k6, slot) {
            self.abandon(slot, Some(&k4));
            return Err(self.install_err(shard, &err));
        }
        let lane = slot as usize;
        self.counters.installs.add(lane, 1);
        self.counters.sessions.add(lane, 1);
        Ok(slot)
    }

    fn install_err(&self, shard: usize, err: &io::Error) -> InstallError {
        if err.raw_os_error() == Some(E2BIG) {
            let until = self.now().saturating_add(INSTALL_BACKOFF.as_nanos() as u64);
            self.backoff_until.store(until, Ordering::Relaxed);
            self.fail(shard, InstallError::MapFull)
        } else {
            self.fail(shard, InstallError::Error)
        }
    }

    /// Rollback of a failed install: `DEAD`, delete the `IN4` entry if it
    /// was inserted, quarantine.
    fn abandon(&self, slot: u32, k4: Option<&[u8; 12]>) {
        self.mark_dead(slot);
        if let Some(k) = k4 {
            let _ = self.tables.delete_in4(k);
        }
        self.slots.retire(slot);
    }

    fn mark_dead(&self, slot: u32) {
        if let Some(h) = self.slot_words(slot).and_then(|w| w.get(SLOT_WORD_HDR)) {
            h.store(SlotRec::hdr_word(SLOT_DEAD, 0, 0), Ordering::Release);
        }
    }

    /// Retires the session installed in `slot` with entry `e` (the same
    /// entry `install` was given). Delete errors other than "absent" are
    /// returned after the slot was still marked `DEAD` and quarantined, so
    /// no new program run uses it either way.
    ///
    /// SEC-006: a program run already past its `state` check when this is
    /// called may still forward one packet with the old mapping (at most
    /// one per CPU, within one RCU grace period); see the module docs.
    ///
    /// QA F1: a slot that is not live (already retired, never handed out,
    /// out of range) or whose record holds another entry is left untouched (no `DEAD` store over a record that
    /// may already belong to another session, no second quarantine) and
    /// counted in `retire_not_live`.
    pub fn retire(&self, slot: u32, e: &SessionEntry) -> io::Result<()> {
        let lane = slot as usize;
        // Live, and still holding `e` (the key echo): a stale retire of a
        // slot recycled to another session must not kill that session.
        if !self.slots.is_live(slot) || self.record(slot).map(|r| SessionEntry::from_record(&r)) != Some(*e) {
            self.counters.retire_not_live.add(lane, 1);
            return Ok(());
        }
        self.mark_dead(slot);
        let r6 = self.tables.delete_out6(&e.key6().to_bytes());
        let r4 = self.tables.delete_in4(&e.key4().to_bytes());
        if self.slots.retire(slot) {
            self.counters.retires.add(lane, 1);
            self.counters.sessions.sub(lane, 1);
        } else {
            self.counters.retire_not_live.add(lane, 1);
        }
        r6.and(r4).map(drop)
    }

    /// The fast path's last-seen time of `slot` (`bpf_ktime_get_coarse_ns`,
    /// i.e. `CLOCK_MONOTONIC_COARSE`; 0 if never touched or out of range).
    /// One atomic load, no syscall.
    pub fn seen_ns(&self, slot: u32) -> u64 {
        self.slot_words(slot).and_then(|w| w.get(SLOT_WORD_SEEN)).map_or(0, |s| s.load(Ordering::Relaxed))
    }

    /// The record in `slot` as currently stored.
    pub fn record(&self, slot: u32) -> Option<SlotRec> {
        let w = self.slot_words(slot)?;
        let mut b = [0u8; 64];
        for (d, s) in b.as_chunks_mut::<8>().0.iter_mut().zip(w) {
            d.copy_from_slice(&s.load(Ordering::Acquire).to_ne_bytes());
        }
        Some(SlotRec::from_bytes(&b))
    }

    /// `SLICE[slice]` as `(state, generation)`.
    pub fn slice(&self, slice: u16) -> Option<(u8, u32)> {
        let e = SliceEnt::from_bytes(&self.slice_word(slice)?.load(Ordering::Acquire).to_ne_bytes());
        Some((e.state, e.generation))
    }

    /// Stores `SLICE[slice] = {state, generation}` (one atomic store, then a
    /// full fence). Prefer [`XdpMirror::activate_slice`] /
    /// [`XdpMirror::deactivate_slice`], which keep the generation rule.
    pub fn set_slice(&self, slice: u16, state: u8, generation: u32) -> bool {
        let Some(w) = self.slice_word(slice) else { return false };
        w.store(SliceEnt::word(state, generation), Ordering::Release);
        fence(Ordering::SeqCst);
        true
    }

    /// Transition to Active: bumps the generation, so records installed
    /// under an earlier ownership never match again, and returns it. Call
    /// after the engine's slice state is Active (plan §9: never more
    /// permissive than the engine).
    pub fn activate_slice(&self, slice: u16) -> Option<u32> {
        let (_, g) = self.slice(slice)?;
        let g = g.wrapping_add(1);
        self.set_slice(slice, SLICE_ACTIVE, g).then_some(g)
    }

    /// Transition to a less permissive `state` (Fenced, Inactive,
    /// Adopting): keeps the generation. Call before the engine's state
    /// changes (plan §9).
    pub fn deactivate_slice(&self, slice: u16, state: u8) -> bool {
        let Some((_, g)) = self.slice(slice) else { return false };
        self.set_slice(slice, state, g)
    }

    /// Scans up to `budget` slots from `cursor` for `LIVE` records whose
    /// generation no longer equals their slice's (stale after a handover),
    /// appending them to `out`; returns the next cursor (wraps at the end).
    /// The caller re-checks each under its `bib4` shard and retires it
    /// (plan §4.3 slice-wide invalidation; WU5).
    pub fn stale_scan(&self, cursor: u32, budget: u32, out: &mut Vec<(u32, SessionEntry)>) -> u32 {
        let n = self.slots.slots();
        if n == 0 {
            return 0;
        }
        let mut c = cursor % n;
        for _ in 0..budget.min(n) {
            if let Some(r) = self.record(c)
                && r.state == SLOT_LIVE
                && self.slice(r.slice).is_none_or(|(_, g)| g != r.generation)
            {
                out.push((c, SessionEntry::from_record(&r)));
            }
            c = (c + 1) % n;
        }
        c
    }
}

/// `E2BIG` (Linux and macOS agree on 7).
const E2BIG: i32 = 7;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::maps::HeapWords;
    use parking_lot::Mutex;
    use plat_xdp_core::abi::{SLICE_FENCED, SLOT_FREE};
    use std::collections::HashMap;

    /// In-memory `OUT6` / `IN4` with the kernel's `NOEXIST` and capacity
    /// semantics.
    #[derive(Debug, Default)]
    pub(crate) struct ModelTables {
        pub cap: usize,
        pub out6: Mutex<HashMap<[u8; 40], u32>>,
        pub in4: Mutex<HashMap<[u8; 12], u32>>,
        pub fail_out6: std::sync::atomic::AtomicBool,
    }

    fn ins<K: std::hash::Hash + Eq + Copy>(m: &Mutex<HashMap<K, u32>>, cap: usize, k: &K, v: u32) -> io::Result<()> {
        let mut g = m.lock();
        if g.contains_key(k) {
            return Err(io::Error::from_raw_os_error(17)); // EEXIST
        }
        if g.len() >= cap {
            return Err(io::Error::from_raw_os_error(E2BIG));
        }
        g.insert(*k, v);
        Ok(())
    }

    impl SessionTables for ModelTables {
        fn insert_out6(&self, key: &[u8; 40], slot: u32) -> io::Result<()> {
            if self.fail_out6.load(Ordering::Relaxed) {
                return Err(io::Error::from_raw_os_error(5));
            }
            ins(&self.out6, self.cap, key, slot)
        }
        fn insert_in4(&self, key: &[u8; 12], slot: u32) -> io::Result<()> {
            ins(&self.in4, self.cap, key, slot)
        }
        fn delete_out6(&self, key: &[u8; 40]) -> io::Result<bool> {
            Ok(self.out6.lock().remove(key).is_some())
        }
        fn delete_in4(&self, key: &[u8; 12]) -> io::Result<bool> {
            Ok(self.in4.lock().remove(key).is_some())
        }
    }

    pub(crate) fn entry(n: u8) -> SessionEntry {
        let mut src6 = [0u8; 16];
        src6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        src6[15] = n;
        let mut dst6 = [0u8; 16];
        dst6[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
        dst6[12..].copy_from_slice(&[203, 0, 113, 5]);
        SessionEntry {
            src6,
            sport6: 40000 + u16::from(n),
            dst6,
            dst4: [203, 0, 113, 5],
            dport: 53,
            pool4: [198, 51, 100, 10],
            pool_port4: 60000 + u16::from(n),
            slice: 0,
        }
    }

    pub(crate) fn mirror(cap: usize, slots: u32) -> (Arc<ModelTables>, XdpMirror) {
        let t = Arc::new(ModelTables { cap, ..Default::default() });
        let m = XdpMirror::with_parts(
            t.clone(),
            Arc::new(HeapWords::new(slots as usize * SLOT_WORDS)),
            Arc::new(HeapWords::new(MAX_SLICES as usize)),
            slots,
            4,
        );
        (t, m)
    }

    #[test]
    fn install_writes_record_and_keys() {
        let (t, m) = mirror(16, 16);
        assert_eq!(m.activate_slice(0), Some(1));
        let e = entry(1);
        let s = m.install(&e, 0).unwrap_or(u32::MAX);
        let r = m.record(s).unwrap_or_default();
        assert_eq!(r, e.record(SLOT_LIVE, 1));
        assert_eq!(t.out6.lock().get(&e.key6().to_bytes()), Some(&s));
        assert_eq!(t.in4.lock().get(&e.key4().to_bytes()), Some(&s));
        assert_eq!(SessionEntry::from_record(&r), e);
        assert_eq!(m.counters().sessions.get(), 1);
        // The program writes seen_ns; the writer reads it.
        if let Some(w) = m.slot_words(s).and_then(|w| w.get(SLOT_WORD_SEEN)) {
            w.store(42, Ordering::Relaxed);
        }
        assert_eq!(m.seen_ns(s), 42);
        assert_eq!(m.seen_ns(u32::MAX), 0);
    }

    #[test]
    fn retire_quarantines_until_two_grace_periods() {
        let (t, m) = mirror(16, 4);
        let e = entry(2);
        let s = m.install(&e, 1).unwrap_or(u32::MAX);
        assert!(m.retire(s, &e).is_ok());
        assert_eq!(m.record(s).map(|r| r.state), Some(SLOT_DEAD));
        assert!(t.out6.lock().is_empty() && t.in4.lock().is_empty());
        assert_eq!(m.slot_allocator().quarantined(), 1);
        // Partition 1 has only slot 1: no reuse before the grace period.
        assert_eq!(m.install(&entry(3), 1), Err(InstallError::Slots));
        m.slot_allocator().advance_epoch();
        m.slot_allocator().advance_epoch();
        assert_eq!(m.slot_allocator().recycle(), 1);
        assert_eq!(m.install(&entry(3), 1), Ok(s));
        assert_eq!(m.counters().sessions.get(), 1);
    }

    #[test]
    fn duplicate_and_error_roll_back() {
        let (t, m) = mirror(16, 16);
        let e = entry(4);
        let s = m.install(&e, 0).unwrap_or(u32::MAX);
        assert_eq!(m.install(&e, 0), Err(InstallError::Error), "same key twice");
        t.fail_out6.store(true, Ordering::Relaxed);
        assert_eq!(m.install(&entry(5), 0), Err(InstallError::Error));
        // Rollback removed the IN4 entry of the failed install only.
        assert_eq!(t.in4.lock().len(), 1);
        assert_eq!(t.in4.lock().get(&e.key4().to_bytes()), Some(&s));
        assert_eq!(m.counters().install_error.get(), 2);
        assert_eq!(m.slot_allocator().quarantined(), 2);
    }

    #[test]
    fn map_full_backs_off() {
        let (_t, m) = mirror(1, 16);
        assert!(m.install(&entry(6), 0).is_ok());
        assert_eq!(m.install(&entry(7), 0), Err(InstallError::MapFull));
        // Within the backoff: refused without touching the maps or slots.
        let q = m.slot_allocator().quarantined();
        assert_eq!(m.install(&entry(8), 0), Err(InstallError::MapFull));
        assert_eq!(m.slot_allocator().quarantined(), q);
        assert_eq!(m.counters().install_map_full.get(), 2);
    }

    #[test]
    fn slices_and_generations() {
        let (_t, m) = mirror(16, 16);
        assert_eq!(m.slice(0), Some((0, 0)));
        assert_eq!(m.activate_slice(7), Some(1));
        let mut e = entry(9);
        e.slice = 7;
        let s = m.install(&e, 0).unwrap_or(u32::MAX);
        assert_eq!(m.record(s).map(|r| r.generation), Some(1));
        assert!(m.deactivate_slice(7, SLICE_FENCED));
        assert_eq!(m.slice(7), Some((SLICE_FENCED, 1)));
        let mut stale = Vec::new();
        assert_eq!(m.stale_scan(0, 16, &mut stale), 0);
        assert!(stale.is_empty(), "fenced, same generation: not stale (the fence alone stops it)");
        assert_eq!(m.activate_slice(7), Some(2));
        m.stale_scan(0, 16, &mut stale);
        assert_eq!(stale, vec![(s, e)]);
        assert!(!m.set_slice(MAX_SLICES as u16, SLICE_ACTIVE, 1));
        e.slice = MAX_SLICES as u16;
        assert_eq!(m.install(&e, 0), Err(InstallError::Error));
        assert_eq!(m.record(15).map(|r| r.state), Some(SLOT_FREE));
    }

    // ---- QA (WU3): writer edge cases ----

    #[test]
    fn rollback_after_in4_failure_leaves_nothing_and_quarantines() {
        let (t, m) = mirror(16, 16);
        assert_eq!(m.activate_slice(0), Some(1));
        // IN4 insert fails because the key already exists (another entry).
        let e = entry(20);
        let s = m.install(&e, 0).unwrap_or(u32::MAX);
        let mut dup = entry(21);
        dup.pool_port4 = e.pool_port4; // same IN4 key, other OUT6 key
        dup.pool4 = e.pool4;
        dup.dst4 = e.dst4;
        dup.dport = e.dport;
        let q = m.slot_allocator().quarantined();
        assert_eq!(m.install(&dup, 0), Err(InstallError::Error));
        assert_eq!(m.slot_allocator().quarantined(), q + 1);
        assert_eq!(t.out6.lock().len(), 1, "no OUT6 entry for the failed install");
        assert_eq!(t.in4.lock().get(&e.key4().to_bytes()), Some(&s), "the existing IN4 entry is kept");
        assert_eq!(m.counters().sessions.get(), 1);
    }

    #[test]
    fn retire_of_an_absent_entry_is_harmless_and_counted_once() {
        let (t, m) = mirror(16, 16);
        let e = entry(22);
        let s = m.install(&e, 0).unwrap_or(u32::MAX);
        // Keys already gone (e.g. the GC deleted them): retire still marks
        // DEAD and quarantines; the sessions gauge never underflows.
        t.out6.lock().clear();
        t.in4.lock().clear();
        assert!(m.retire(s, &e).is_ok());
        assert_eq!(m.record(s).map(|r| r.state), Some(SLOT_DEAD));
        assert_eq!(m.counters().sessions.get(), 0);
        // Out-of-range slot: no write, no quarantine, no panic.
        let q = m.slot_allocator().quarantined();
        assert!(m.retire(u32::MAX, &e).is_ok());
        assert_eq!(m.slot_allocator().quarantined(), q);
        assert_eq!(m.counters().sessions.get(), 0);
    }

    /// QA F1: a double retire neither rewrites the record (which may by
    /// then belong to another session) nor quarantines the slot twice.
    #[test]
    fn double_retire_is_refused_and_counted() {
        let (_t, m) = mirror(16, 16);
        let e = entry(30);
        let s = m.install(&e, 0).unwrap_or(u32::MAX);
        assert!(m.retire(s, &e).is_ok());
        assert!(m.retire(s, &e).is_ok());
        assert_eq!(m.slot_allocator().quarantined(), 1);
        assert_eq!((m.counters().retires.get(), m.counters().retire_not_live.get()), (1, 1));
        m.slot_allocator().advance_epoch();
        m.slot_allocator().advance_epoch();
        assert_eq!(m.slot_allocator().recycle(), 1);
        // Reused by another session: a stale retire of the first leaves it.
        let f = entry(31);
        assert_eq!(m.install(&f, 0), Ok(s));
        let r = m.record(s);
        assert!(m.retire(s, &e).is_ok());
        assert_eq!(m.record(s), r, "the other session's record is untouched");
        assert_eq!(m.counters().retire_not_live.get(), 2);
        assert_eq!(m.counters().sessions.get(), 1);
    }

    #[test]
    fn lane_counters_sum_across_lanes() {
        let c = LaneCounter::default();
        c.add(0, 3);
        c.add(COUNTER_LANES + 1, 2);
        c.sub(5, 1); // a gauge decremented on another lane
        assert_eq!(c.get(), 4);
        assert!(std::mem::align_of::<Lane>() >= 128);
    }

    #[test]
    fn install_takes_the_generation_from_slice_and_never_reuses_early() {
        let (_t, m) = mirror(64, 4);
        assert_eq!(m.activate_slice(0), Some(1));
        assert!(m.deactivate_slice(0, SLICE_FENCED));
        assert_eq!(m.activate_slice(0), Some(2));
        let e = entry(23);
        let s = m.install(&e, 2).unwrap_or(u32::MAX);
        assert_eq!(m.record(s).map(|r| r.generation), Some(2));
        assert_eq!(s % 4, 2, "partition of shard 2");
        assert!(m.retire(s, &e).is_ok());
        m.slot_allocator().advance_epoch();
        m.slot_allocator().recycle();
        // Partition 2 holds only slot 2 of 4: no slot until two epochs.
        assert_eq!(m.install(&entry(24), 2), Err(InstallError::Slots));
        assert_eq!(m.counters().install_slots.get(), 1);
    }
}
