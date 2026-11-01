//! The session writer (plan §4.3): installs established UDP sessions into
//! `SLOT` / `IN4` / `OUT6`, retires them, reads the fast path's `seen_ns`,
//! and writes slice state and generation into `SLICE`.
//!
//! The `plat-nat64` mirror trait is implemented in [`crate::glue`];
//! [`SessionEntry`] carries the facts of plan §4.4's `MirrorEntry` (`k6`,
//! `k4`, remote, `dst6`, slice).
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
//! `drop_and_alert_installs_even_when_the_record_is_lost`).
//!
//! **No syscall under the caller's lock (WU5 gate, PERF-001/003/004).** The
//! `bib4` side only writes shared memory and queues work; the map syscalls
//! run on the publisher thread ([`XdpMirror::flush`],
//! `control::spawn_publisher`). Slot states: `FREE → PENDING → LIVE → DEAD`
//! (or `PENDING → FAILED → DEAD`, or `PENDING → DEAD`); the program
//! forwards only `LIVE`.
//!
//! **Install** (under `bib4`):
//! 1. take a slot from the caller's partition ([`SlotAllocator`]);
//! 2. write words 1-7 of the record while it is unreachable, `fence(Release)`;
//! 3. store word 0 (`state = PENDING`, slice, the engine's generation);
//! 4. queue a publish op on the partition.
//!
//! **Publish** (publisher thread): insert `IN4`, then `OUT6`
//! (`BPF_NOEXIST`), then compare-and-swap `PENDING → LIVE`. A retire that
//! came first (`DEAD`) wins: the publisher deletes what it inserted. On a
//! failure the inserts are rolled back and the record becomes `FAILED`
//! (`E2BIG` also backs installs off for [`INSTALL_BACKOFF`]; `EEXIST` is
//! first retried a few passes); the stale-entry collector then makes the
//! engine forget the slot, so the session can be mirrored again.
//!
//! **Retire** (under `bib4`, only of a live slot, QA F1): `state = DEAD`,
//! queue a retire op. **Publisher**: delete `OUT6` and `IN4` if this writer
//! published them, then quarantine the slot. Retire ops of a pass run
//! before its publishes, so an entry of an expired session is deleted
//! before a new session with the same keys is published.
//!
//! When `retire` returns, no *new* program run can use the session, but a
//! run that started before (it already read `state = LIVE`) may still
//! translate and forward its one packet: at most one packet per CPU,
//! within one RCU grace period after the retire (SEC-006). If the caller
//! returns the session's port block to the pool at once and it is
//! reassigned within that window, such a packet would leave with a
//! mapping the audit trail attributes to the previous subscriber. This is
//! a recorded residual (fixes-wu34-round-1). A program that reads a hash
//! value after the `DEAD` store and before the deferred delete finds a
//! `DEAD` record and passes; one that read it just before a delete may see
//! a reused element: it then reads another slot whose state or key echo
//! differs, and passes (plan §4.3 proof sketch). Slot records are rewritten
//! only after the deletes and then the RCU grace period of
//! [`SlotAllocator`].
//!
//! **Counters** are per lane (`shard` or slot modulo [`COUNTER_LANES`]),
//! each lane on its own cache line, so workers installing and retiring in
//! different shards do not share a written line (PERF-005).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-12 / CLAUDE.md rule 4 - installs follow the
//!   attribution record handed to the sink (I4, enforced by the engine,
//!   `plat-nat64` `tests/mirror.rs`), except that under `drop_and_alert`
//!   the record may have been dropped; this writer emits no records
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - bounded maps and
//!   slots; full maps back installs off and leave sessions on the slow path
//! - NIST 800-53: SC-7, SC-24 - slice state and generation in `SLICE`;
//!   fencing is one atomic store followed by a full fence
//! - RFC 6146 §3.5.1 - `seen_ns` lets the slow path extend a session kept
//!   alive only by fast-path traffic ([`XdpMirror::seen_ms`] converts it to
//!   engine milliseconds)
//! - CLAUDE.md rule 2 - no map syscall under a `bib4` lock (WU5 gate:
//!   `tests/hold_gate.rs`)

use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering, fence};
use std::time::{Duration, Instant};

use plat_xdp_core::abi::{
    Key4, Key6, MAX_SLICES, SLICE_ACTIVE, SLOT_DEAD, SLOT_FAILED, SLOT_LIVE, SLOT_PENDING, SLOT_WORD_HDR,
    SLOT_WORD_SEEN, SLOT_WORDS, SliceEnt, SlotRec,
};

use crate::maps::Words;
use crate::slots::{OP_PUBLISH, OP_RETIRE, SlotAllocator};

/// Install back-off after the hash maps reported full (plan §4.3).
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
/// PERF-002: `impl Mirror` ([`crate::glue`]) maps [`InstallError::MapFull`] and
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
    /// Retires whose hash deletes failed (the slot was still marked `DEAD`
    /// and quarantined).
    pub retire_error: LaneCounter,
    /// Incremented by the slow path when `seen_ns` extended a session.
    pub revalidated: LaneCounter,
    pub gc_deleted: LaneCounter,
    /// Live installed sessions (`plat_xdp_sessions`; includes those whose
    /// entries are not published yet).
    pub sessions: LaneCounter,
    /// Publishes retried after `EEXIST`.
    pub publish_retries: LaneCounter,
    /// Retires whose deferred op could not be queued (unreachable with the
    /// queue bound): the slot and its entries are leaked, never deleted
    /// under the caller's lock (SEC-002).
    pub retire_leaked: LaneCounter,
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
    /// Deferred publish / delete state ([`XdpMirror::flush`]).
    publisher: parking_lot::Mutex<Publisher>,
    /// Completed publisher passes and the time of the last one (ms since
    /// `origin`), for health and metrics (SEC-002).
    passes: AtomicU64,
    last_pass_ms: AtomicU64,
    /// Slots that turned FAILED, for the collector (PERF-005; bounded by
    /// the slot count, preallocated).
    failed: parking_lot::Mutex<Vec<u32>>,
    /// The engine clock and the `CLOCK_MONOTONIC_COARSE` reading (ns) of
    /// its origin, for [`XdpMirror::seen_ms`]; `None` until
    /// [`XdpMirror::with_clock`].
    clock: Option<(plat_common::Clock, u64)>,
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
            publisher: parking_lot::Mutex::new(Publisher::new(slots)),
            passes: AtomicU64::new(0),
            last_pass_ms: AtomicU64::new(0),
            failed: parking_lot::Mutex::new(Vec::with_capacity(slots as usize)),
            origin: Instant::now(),
            backoff_until: AtomicU64::new(0),
            counters: MirrorCounters::default(),
            clock: None,
        }
    }

    /// Converts `seen_ns` with the engine `clock`, whose origin
    /// (`now_ms() == 0`) was `origin_ns` on `CLOCK_MONOTONIC_COARSE`
    /// (Linux: [`crate::control::engine_origin_ns`]).
    pub fn with_clock(mut self, clock: plat_common::Clock, origin_ns: u64) -> Self {
        self.clock = Some((clock, origin_ns));
        self
    }

    /// The fast path's last use of `slot` in engine milliseconds
    /// (`State::now_ms` base), 0 if never (plan §5, RFC-002): `seen_ns`
    /// minus the engine origin, rounded down, clamped to at most the
    /// engine's `now` (the coarse clocks differ by up to one tick, and a
    /// use is never in the future) and to at least 1 (a real use is never
    /// "never"). One atomic load, no syscall.
    pub fn seen_ms(&self, slot: u32) -> u64 {
        let ns = self.seen_ns(slot);
        let Some((clock, origin)) = &self.clock else { return 0 };
        if ns == 0 {
            return 0;
        }
        // RFC-002: rounded up, plus one coarse tick of slack (the coarse
        // clock and the engine origin can differ by a tick), so a session
        // never expires before one full timeout after its last packet.
        ns.saturating_sub(*origin).div_ceil(1_000_000).saturating_add(SEEN_SLACK_MS).min(clock.now_ms()).max(1)
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

    /// Installs `e` under slice `generation` from the caller's `shard` (its
    /// `bib4` shard index) and returns the slot. Refused (`Error`) unless
    /// `SLICE[e.slice]` is Active with exactly `generation` (SEC-005,
    /// RFC-001: the record carries the engine's generation, never one read
    /// back from the map).
    ///
    /// No syscall (WU5 gate): the record is written `PENDING` and its
    /// `IN4` / `OUT6` entries are published later by [`XdpMirror::flush`]
    /// (the publisher thread), which turns it `LIVE`. Map-level failures
    /// (full, key exists) are therefore found by the publisher: the record
    /// becomes `FAILED`, never reachable, and the stale-entry collector
    /// makes the engine forget the slot (see the module docs).
    pub fn install(&self, e: &SessionEntry, generation: u32, shard: usize) -> Result<u32, InstallError> {
        if self.now() < self.backoff_until.load(Ordering::Relaxed) {
            return Err(self.fail(shard, InstallError::MapFull));
        }
        let Some(sw) = self.slice_word(e.slice) else {
            return Err(self.fail(shard, InstallError::Error));
        };
        let cur = SliceEnt::from_bytes(&sw.load(Ordering::Acquire).to_ne_bytes());
        if cur.state != SLICE_ACTIVE || cur.generation != generation {
            return Err(self.fail(shard, InstallError::Error));
        }
        let words = e.record(SLOT_PENDING, generation).to_words();
        // PERF-006: slot, record and publish op under one partition lock.
        // The record is unreachable while written: no hash entry points at
        // the slot and its header still says FREE/DEAD from before.
        let write = |slot: u32| {
            let Some(w) = self.slot_words(slot) else { return false };
            for (d, s) in w.iter().zip(words.iter()).skip(1) {
                d.store(*s, Ordering::Relaxed);
            }
            fence(Ordering::Release);
            if let (Some(h), Some(v)) = (w.get(SLOT_WORD_HDR), words.get(SLOT_WORD_HDR)) {
                h.store(*v, Ordering::Release);
            }
            true
        };
        let Some(slot) = self.slots.alloc_publish(shard, write) else {
            return Err(self.fail(shard, InstallError::Slots));
        };
        self.counters.sessions.add(slot as usize, 1);
        Ok(slot)
    }

    fn hdr(&self, slot: u32) -> Option<&AtomicU64> {
        self.slot_words(slot).and_then(|w| w.get(SLOT_WORD_HDR))
    }

    /// Stores `state` in the header, keeping slice and generation (the
    /// record still describes its session, so a deferred delete and the
    /// collectors can read the keys).
    fn mark(&self, slot: u32, state: u8) {
        if let Some(h) = self.hdr(slot) {
            let r = SlotRec::from_bytes(&{
                let mut b = [0u8; 64];
                if let Some(c) = b.first_chunk_mut::<8>() {
                    *c = h.load(Ordering::Acquire).to_ne_bytes();
                }
                b
            });
            h.store(SlotRec::hdr_word(state, r.slice, r.generation), Ordering::Release);
        }
    }

    /// Retires the session installed in `slot` with entry `e` (the same
    /// entry `install` was given): one `DEAD` store, then the hash deletes
    /// and the quarantine are queued for the publisher (no syscall under
    /// the caller's `bib4` lock; WU5 gate, PERF-003/004). From the store
    /// on, no new program run uses the record (the program forwards only
    /// `LIVE`); the stale `OUT6` / `IN4` entries lead to a dead slot until
    /// the publisher deletes them, and the slot is reused only a grace
    /// period after that.
    ///
    /// SEC-006: a program run already past its `state` check when this is
    /// called may still forward one packet with the old mapping (at most
    /// one per CPU, within one RCU grace period); see the module docs.
    ///
    /// QA F1: a slot that is not live (already retired, never handed out,
    /// out of range) or whose record holds another entry is left untouched
    /// (no `DEAD` store over a record that may already belong to another
    /// session, no second quarantine) and counted in `retire_not_live`.
    pub fn retire(&self, slot: u32, e: &SessionEntry) -> io::Result<()> {
        let lane = slot as usize;
        // Live, and still holding `e` (the key echo): a stale retire of a
        // slot recycled to another session must not kill that session.
        let rec = self.record(slot);
        if !self.slots.is_live(slot)
            || !rec.is_some_and(|r| matches!(r.state, SLOT_PENDING | SLOT_LIVE | SLOT_FAILED))
            || rec.map(|r| SessionEntry::from_record(&r)) != Some(*e)
        {
            self.counters.retire_not_live.add(lane, 1);
            return Ok(());
        }
        self.mark(slot, SLOT_DEAD);
        if self.slots.defer_retire(slot) {
            self.counters.retires.add(lane, 1);
            self.counters.sessions.sub(lane, 1);
            return Ok(());
        }
        // Not reachable with the two-ops-per-slot bound. SEC-002: never
        // take the publisher mutex (or make a syscall) under the caller's
        // `bib4` lock: the record is DEAD, so the program no longer uses
        // it; the slot and its entries are leaked and counted (an operator
        // signal; the maps are recreated with the next attach).
        self.counters.retire_leaked.add(lane, 1);
        self.counters.retires.add(lane, 1);
        self.counters.sessions.sub(lane, 1);
        Ok(())
    }

    /// Deletes `slot`'s `OUT6` / `IN4` entries if this writer published
    /// them (never another slot's entries with the same keys).
    fn delete_keys(&self, p: &mut Publisher, slot: u32, e: &SessionEntry) -> io::Result<()> {
        if !p.take_published(slot) {
            return Ok(());
        }
        let r6 = self.tables.delete_out6(&e.key6().to_bytes());
        let r4 = self.tables.delete_in4(&e.key4().to_bytes());
        let r = r6.and(r4).map(drop);
        if r.is_err() {
            // SEC-003: still published; the caller retries the deletes.
            p.set_published(slot);
        }
        r
    }

    /// One publisher pass (the `plat-xdp-pub` thread; tests call it
    /// directly). Takes every queued op of every partition, then:
    ///
    /// 1. **retires** first: delete the slot's entries if they were
    ///    published, then quarantine the slot (its grace period starts);
    /// 2. **publishes**: for each slot still `PENDING`, insert `IN4` then
    ///    `OUT6` (`BPF_NOEXIST`), then compare-and-swap the header
    ///    `PENDING → LIVE`. A retire that won the race (`DEAD`) makes the
    ///    publisher delete what it inserted. `EEXIST` (a not yet deleted
    ///    entry of an earlier session, queued in a partition drained after
    ///    this one) is retried in the next pass, at most
    ///    [`PUBLISH_RETRIES`] times; that and every other failure turns the
    ///    record `FAILED` (map full also backs installs off for
    ///    [`INSTALL_BACKOFF`]).
    ///
    /// Returns how many ops were processed. Runs syscalls with no lock held
    /// except the publisher's own (uncontended) state.
    pub fn flush(&self) -> usize {
        let mut guard = self.publisher.lock();
        let p = &mut *guard;
        let mut ops = std::mem::take(&mut p.ops);
        ops.clear();
        // Retries of the previous pass go first: SEC-003 deletes that
        // failed, then EEXIST publishes (attempts in `p.tries`, PERF-004).
        for &slot in p.del_retry.iter() {
            ops.push(u64::from(slot) << 1 | OP_RETIRE);
        }
        p.del_retry.clear();
        for &slot in p.retry.iter() {
            ops.push(u64::from(slot) << 1 | OP_PUBLISH);
        }
        p.retry.clear();
        self.slots.drain_ops(&mut ops);
        for &op in ops.iter().filter(|&&op| op & 1 == OP_RETIRE) {
            let slot = (op >> 1) as u32;
            if let Some(r) = self.record(slot)
                && self.delete_keys(p, slot, &SessionEntry::from_record(&r)).is_err()
            {
                // SEC-003: no orphan entries: the slot stays out of the
                // quarantine and the deletes are retried next pass.
                self.counters.retire_error.add(slot as usize, 1);
                p.del_retry.push(slot);
                continue;
            }
            self.slots.quarantine(slot);
        }
        for &op in ops.iter().filter(|&&op| op & 1 == OP_PUBLISH) {
            let slot = (op >> 1) as u32;
            let tried = p.tries.get(slot as usize).copied().unwrap_or(0);
            self.publish(p, slot, tried);
        }
        let n = ops.len();
        p.ops = ops;
        self.passes.fetch_add(1, Ordering::Release);
        self.last_pass_ms.store(self.now() / 1_000_000, Ordering::Relaxed);
        n
    }

    /// Completed publisher passes (SEC-002 liveness).
    pub fn publisher_passes(&self) -> u64 {
        self.passes.load(Ordering::Acquire)
    }

    /// Seconds since the last publisher pass (`plat_xdp_publisher_last_pass_seconds`).
    pub fn publisher_idle_secs(&self) -> f64 {
        let last = self.last_pass_ms.load(Ordering::Relaxed);
        (self.now() / 1_000_000).saturating_sub(last) as f64 / 1000.0
    }

    /// PERF-005: slots whose publish failed, for the collector to take
    /// first (moved into `out`, which the caller reuses).
    pub fn take_failed(&self, out: &mut Vec<u32>, max: usize) {
        let mut f = self.failed.lock();
        let k = f.len().min(max);
        out.extend(f.drain(..k));
    }

    fn publish(&self, p: &mut Publisher, slot: u32, tried: u8) {
        let lane = slot as usize;
        let Some(h) = self.hdr(slot) else { return };
        let Some(r) = self.record(slot) else { return };
        if r.state != SLOT_PENDING {
            // Retired before it was published: its retire op quarantines it.
            if let Some(t) = p.tries.get_mut(slot as usize) {
                *t = 0;
            }
            return;
        }
        let pending = SlotRec::hdr_word(SLOT_PENDING, r.slice, r.generation);
        let e = SessionEntry::from_record(&r);
        let (k4, k6) = (e.key4().to_bytes(), e.key6().to_bytes());
        let res = self.tables.insert_in4(&k4, slot).and_then(|()| {
            self.tables.insert_out6(&k6, slot).inspect_err(|_| {
                let _ = self.tables.delete_in4(&k4);
            })
        });
        match res {
            Ok(()) => {
                let live = SlotRec::hdr_word(SLOT_LIVE, r.slice, r.generation);
                if h.compare_exchange(pending, live, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    p.set_published(slot);
                    self.counters.installs.add(lane, 1);
                } else {
                    // Retired meanwhile: its retire op finds nothing
                    // published and only quarantines.
                    let _ = self.tables.delete_out6(&k6);
                    let _ = self.tables.delete_in4(&k4);
                }
            }
            Err(err) if err.raw_os_error() == Some(EEXIST) && tried < PUBLISH_RETRIES => {
                p.retry.push(slot);
                if let Some(t) = p.tries.get_mut(slot as usize) {
                    *t = tried + 1;
                }
                self.counters.publish_retries.add(lane, 1);
                return;
            }
            Err(err) => {
                let kind = if err.raw_os_error() == Some(E2BIG) {
                    let until = self.now().saturating_add(INSTALL_BACKOFF.as_nanos() as u64);
                    self.backoff_until.store(until, Ordering::Relaxed);
                    InstallError::MapFull
                } else {
                    InstallError::Error
                };
                self.fail(lane, kind);
                let failed = SlotRec::hdr_word(SLOT_FAILED, r.slice, r.generation);
                if h.compare_exchange(pending, failed, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    // PERF-005: the collector takes these first.
                    let mut f = self.failed.lock();
                    if f.len() < f.capacity() {
                        f.push(slot);
                    }
                }
            }
        }
        if let Some(t) = p.tries.get_mut(slot as usize) {
            *t = 0;
        }
    }

    /// The fast path's last-seen time of `slot` (`bpf_ktime_get_coarse_ns`,
    /// i.e. `CLOCK_MONOTONIC_COARSE`; 0 if never touched or out of range).
    /// One atomic load, no syscall.
    pub fn seen_ns(&self, slot: u32) -> u64 {
        self.slot_words(slot).and_then(|w| w.get(SLOT_WORD_SEEN)).map_or(0, |s| s.load(Ordering::Relaxed))
    }

    /// Test support: the program's `seen_ns` store.
    #[cfg(test)]
    pub(crate) fn touch_ns(&self, slot: u32, ns: u64) {
        if let Some(w) = self.slot_words(slot).and_then(|w| w.get(SLOT_WORD_SEEN)) {
            w.store(ns, Ordering::Relaxed);
        }
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
    /// generation no longer equals their slice's (stale after a handover)
    /// and for `FAILED` records (a publish that failed), appending them to
    /// `out`; returns the next cursor (wraps at the end).
    /// The caller re-checks each under its `bib4` shard and retires it
    /// (plan §4.3 slice-wide invalidation; [`crate::glue::gc_step`]).
    pub fn stale_scan(&self, cursor: u32, budget: u32, out: &mut Vec<(u32, SessionEntry)>) -> u32 {
        let n = self.slots.slots();
        if n == 0 {
            return 0;
        }
        let mut c = cursor % n;
        for _ in 0..budget.min(n) {
            if let Some(r) = self.record(c)
                && (r.state == SLOT_FAILED
                    || (r.state == SLOT_LIVE && self.slice(r.slice).is_none_or(|(_, g)| g != r.generation)))
            {
                out.push((c, SessionEntry::from_record(&r)));
            }
            c = (c + 1) % n;
        }
        c
    }
}

/// Slack added to `seen_ms` (RFC-002): one `CLOCK_MONOTONIC_COARSE` tick
/// at the lowest common `HZ` (100).
pub const SEEN_SLACK_MS: u64 = 10;

/// `E2BIG` (Linux and macOS agree on 7).
const E2BIG: i32 = 7;
/// `EEXIST` (Linux and macOS agree on 17).
const EEXIST: i32 = 17;

/// Passes a publish that met `EEXIST` is retried in (the conflicting entry
/// is an earlier session's whose deferred delete is queued in a partition
/// the same pass drained later).
pub const PUBLISH_RETRIES: u8 = 3;

/// The publisher's own state (one lock, taken by [`XdpMirror::flush`] and
/// by the never-taken synchronous retire fallback; never under a `bib4`
/// lock in the normal path). Every buffer is preallocated.
#[derive(Debug)]
struct Publisher {
    /// Bit per slot: its entries were published by this writer.
    published: Box<[u64]>,
    /// The ops of the current pass (reused).
    ops: Vec<u64>,
    /// `EEXIST` publishes for the next pass.
    retry: Vec<u32>,
    /// Publish attempts per slot (PERF-004 / SEC-006: no list search).
    tries: Box<[u8]>,
    /// Slots whose deferred deletes failed, retried next pass (SEC-003).
    del_retry: Vec<u32>,
}

impl Publisher {
    fn new(slots: u32) -> Self {
        let n = slots as usize;
        Self {
            published: vec![0u64; n.div_ceil(64)].into_boxed_slice(),
            ops: Vec::with_capacity(2 * n),
            retry: Vec::with_capacity(n),
            tries: vec![0u8; n].into_boxed_slice(),
            del_retry: Vec::with_capacity(n),
        }
    }

    fn bit(&mut self, slot: u32) -> Option<(&mut u64, u64)> {
        Some((self.published.get_mut(slot as usize / 64)?, 1u64 << (slot % 64)))
    }

    fn set_published(&mut self, slot: u32) {
        if let Some((w, m)) = self.bit(slot) {
            *w |= m;
        }
    }

    fn take_published(&mut self, slot: u32) -> bool {
        match self.bit(slot) {
            Some((w, m)) if *w & m != 0 => {
                *w &= !m;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::maps::HeapWords;
    use parking_lot::Mutex;
    use plat_xdp_core::abi::{SLICE_FENCED, SLOT_FREE};
    use std::collections::HashMap;

    /// In-memory `OUT6` / `IN4` with the kernel's `NOEXIST` and capacity
    /// semantics.
    #[derive(Default)]
    pub(crate) struct ModelTables {
        pub cap: usize,
        pub out6: Mutex<HashMap<[u8; 40], u32>>,
        pub in4: Mutex<HashMap<[u8; 12], u32>>,
        pub fail_out6: std::sync::atomic::AtomicBool,
        /// Called inside every `OUT6` insert (races).
        pub on_out6: Mutex<Option<Box<dyn FnMut() + Send>>>,
        /// Deletes fail with EIO while set (SEC-003).
        pub fail_delete: std::sync::atomic::AtomicBool,
    }

    impl std::fmt::Debug for ModelTables {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ModelTables").field("cap", &self.cap).finish_non_exhaustive()
        }
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
            let r = ins(&self.out6, self.cap, key, slot);
            if let Some(f) = self.on_out6.lock().as_mut() {
                f();
            }
            r
        }
        fn insert_in4(&self, key: &[u8; 12], slot: u32) -> io::Result<()> {
            ins(&self.in4, self.cap, key, slot)
        }
        fn delete_out6(&self, key: &[u8; 40]) -> io::Result<bool> {
            if self.fail_delete.load(Ordering::Relaxed) {
                return Err(io::Error::from_raw_os_error(5));
            }
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
        // Slice 0 Active with generation 1, as `Pool::set_mirror` publishes
        // a legacy pool.
        assert!(m.set_slice(0, SLICE_ACTIVE, 1));
        (t, m)
    }

    #[test]
    fn install_writes_a_pending_record_and_the_publisher_publishes_it() {
        let (t, m) = mirror(16, 16);
        let e = entry(1);
        let s = m.install(&e, 1, 0).unwrap_or(u32::MAX);
        // Under the caller's lock: the record only, PENDING, no map entry.
        assert_eq!(m.record(s), Some(e.record(SLOT_PENDING, 1)));
        assert!(t.out6.lock().is_empty() && t.in4.lock().is_empty(), "no syscall at install");
        assert_eq!((m.counters().sessions.get(), m.counters().installs.get()), (1, 0));
        assert_eq!(m.flush(), 1);
        let r = m.record(s).unwrap_or_default();
        assert_eq!(r, e.record(SLOT_LIVE, 1));
        assert_eq!(t.out6.lock().get(&e.key6().to_bytes()), Some(&s));
        assert_eq!(t.in4.lock().get(&e.key4().to_bytes()), Some(&s));
        assert_eq!(SessionEntry::from_record(&r), e);
        assert_eq!(m.counters().installs.get(), 1);
        assert_eq!(m.flush(), 0, "nothing left");
        // The program writes seen_ns; the writer reads it.
        m.touch_ns(s, 42);
        assert_eq!(m.seen_ns(s), 42);
        assert_eq!(m.seen_ns(u32::MAX), 0);
    }

    #[test]
    fn retire_is_dead_at_once_and_deletes_and_quarantines_later() {
        let (t, m) = mirror(16, 4);
        let e = entry(2);
        let s = m.install(&e, 1, 1).unwrap_or(u32::MAX);
        m.flush();
        assert!(m.retire(s, &e).is_ok());
        // Under the caller's lock: DEAD only (the program stops using it).
        assert_eq!(m.record(s).map(|r| r.state), Some(SLOT_DEAD));
        assert_eq!(t.out6.lock().len(), 1, "delete deferred");
        assert_eq!(m.slot_allocator().quarantined(), 0);
        assert_eq!(m.counters().sessions.get(), 0);
        assert_eq!(m.flush(), 1);
        assert!(t.out6.lock().is_empty() && t.in4.lock().is_empty());
        assert_eq!(m.slot_allocator().quarantined(), 1);
        // Partition 1 has only slot 1: no reuse before the grace period.
        assert_eq!(m.install(&entry(3), 1, 1), Err(InstallError::Slots));
        m.slot_allocator().advance_epoch();
        m.slot_allocator().advance_epoch();
        assert_eq!(m.slot_allocator().recycle(), 1);
        assert_eq!(m.install(&entry(3), 1, 1), Ok(s));
        assert_eq!(m.counters().sessions.get(), 1);
    }

    /// A retire that comes before the publish (same pass or earlier):
    /// nothing is ever inserted, the slot is quarantined once.
    #[test]
    fn retire_before_publish_never_publishes() {
        let (t, m) = mirror(16, 16);
        let e = entry(4);
        let s = m.install(&e, 1, 0).unwrap_or(u32::MAX);
        assert!(m.retire(s, &e).is_ok());
        assert_eq!(m.flush(), 2);
        assert!(t.out6.lock().is_empty() && t.in4.lock().is_empty());
        assert_eq!(m.record(s).map(|r| r.state), Some(SLOT_DEAD));
        assert_eq!(m.slot_allocator().quarantined(), 1);
        assert_eq!(m.counters().installs.get(), 0);
    }

    #[test]
    fn publish_failures_turn_failed_and_are_collectable() {
        let (t, m) = mirror(16, 16);
        let e = entry(5);
        let s = m.install(&e, 1, 0).unwrap_or(u32::MAX);
        m.flush();
        // Same keys again (the engine never does this; a stale entry would):
        // EEXIST, retried PUBLISH_RETRIES passes, then FAILED.
        let mut f = entry(6);
        f.pool4 = e.pool4;
        f.pool_port4 = e.pool_port4;
        f.dst4 = e.dst4;
        f.dport = e.dport;
        let s2 = m.install(&f, 1, 0).unwrap_or(u32::MAX);
        for _ in 0..=PUBLISH_RETRIES {
            m.flush();
        }
        assert_eq!(m.record(s2).map(|r| r.state), Some(SLOT_FAILED));
        assert_eq!(m.counters().publish_retries.get(), u64::from(PUBLISH_RETRIES));
        assert_eq!(m.counters().install_error.get(), 1);
        assert_eq!(t.in4.lock().get(&e.key4().to_bytes()), Some(&s), "the existing entry is kept");
        assert_eq!(t.out6.lock().len(), 1, "no OUT6 entry for the failed publish");
        // The collector reports it; its retire is accepted and deletes
        // nothing of the other session's.
        let mut found = Vec::new();
        m.stale_scan(0, 16, &mut found);
        assert_eq!(found, vec![(s2, f)]);
        assert!(m.retire(s2, &f).is_ok());
        m.flush();
        assert_eq!(t.in4.lock().get(&e.key4().to_bytes()), Some(&s));
        assert_eq!(m.slot_allocator().quarantined(), 1);
        // OUT6 failing: IN4 rolled back, FAILED.
        t.fail_out6.store(true, Ordering::Relaxed);
        let g = entry(7);
        let s3 = m.install(&g, 1, 0).unwrap_or(u32::MAX);
        m.flush();
        assert_eq!(m.record(s3).map(|r| r.state), Some(SLOT_FAILED));
        assert_eq!(t.in4.lock().len(), 1);
        assert_eq!(m.counters().install_error.get(), 2);
    }

    #[test]
    fn map_full_backs_off() {
        let (_t, m) = mirror(1, 16);
        assert!(m.install(&entry(6), 1, 0).is_ok());
        let s = m.install(&entry(7), 1, 0).unwrap_or(u32::MAX);
        m.flush();
        assert_eq!(m.record(s).map(|r| r.state), Some(SLOT_FAILED));
        assert_eq!(m.counters().install_map_full.get(), 1);
        // Within the back-off: refused at once, without taking a slot.
        let q = m.slot_allocator().quarantined();
        assert_eq!(m.install(&entry(8), 1, 0), Err(InstallError::MapFull));
        assert_eq!(m.slot_allocator().quarantined(), q);
        assert_eq!(m.counters().install_map_full.get(), 2);
    }

    #[test]
    fn slices_and_generations() {
        let (_t, m) = mirror(16, 16);
        assert_eq!(m.slice(0), Some((SLICE_ACTIVE, 1)));
        assert_eq!(m.slice(7), Some((0, 0)));
        assert_eq!(m.activate_slice(7), Some(1));
        let mut e = entry(9);
        e.slice = 7;
        let s = m.install(&e, 1, 0).unwrap_or(u32::MAX);
        m.flush();
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
        assert_eq!(m.install(&e, 1, 0), Err(InstallError::Error));
        assert_eq!(m.record(15).map(|r| r.state), Some(SLOT_FREE));
    }

    /// A publish that loses the race with a retire (the `DEAD` store lands
    /// between the publisher's state read and its `PENDING → LIVE` CAS)
    /// deletes what it inserted; the retire's op only quarantines.
    #[test]
    fn publish_losing_to_a_retire_leaves_no_entry() {
        let (t, m) = mirror(16, 16);
        let m = Arc::new(m);
        let e = entry(20);
        let s = m.install(&e, 1, 0).unwrap_or(u32::MAX);
        let (m2, e2) = (m.clone(), e);
        *t.on_out6.lock() = Some(Box::new(move || {
            assert!(m2.retire(s, &e2).is_ok());
        }));
        m.flush();
        t.on_out6.lock().take();
        assert_eq!(m.record(s).map(|r| r.state), Some(SLOT_DEAD));
        assert!(t.out6.lock().is_empty() && t.in4.lock().is_empty(), "inserted, then removed by the publisher");
        assert_eq!(m.counters().installs.get(), 0);
        m.flush();
        assert_eq!(m.slot_allocator().quarantined(), 1);
        assert!(t.out6.lock().is_empty() && t.in4.lock().is_empty());
    }

    #[test]
    fn retire_of_an_absent_entry_is_harmless_and_counted_once() {
        let (t, m) = mirror(16, 16);
        let e = entry(22);
        let s = m.install(&e, 1, 0).unwrap_or(u32::MAX);
        m.flush();
        // Keys already gone: retire still marks DEAD and quarantines; the
        // sessions gauge never underflows.
        t.out6.lock().clear();
        t.in4.lock().clear();
        assert!(m.retire(s, &e).is_ok());
        m.flush();
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
        let s = m.install(&e, 1, 0).unwrap_or(u32::MAX);
        m.flush();
        assert!(m.retire(s, &e).is_ok());
        assert!(m.retire(s, &e).is_ok());
        m.flush();
        assert_eq!(m.slot_allocator().quarantined(), 1);
        assert_eq!((m.counters().retires.get(), m.counters().retire_not_live.get()), (1, 1));
        m.slot_allocator().advance_epoch();
        m.slot_allocator().advance_epoch();
        assert_eq!(m.slot_allocator().recycle(), 1);
        // Reused by another session: a stale retire of the first leaves it.
        let f = entry(31);
        assert_eq!(m.install(&f, 1, 0), Ok(s));
        m.flush();
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
    fn install_needs_the_exact_active_generation_and_never_reuses_early() {
        let (_t, m) = mirror(64, 4);
        assert!(m.deactivate_slice(0, SLICE_FENCED));
        let e = entry(23);
        // SEC-005 / RFC-001: not Active, or another generation: refused.
        assert_eq!(m.install(&e, 1, 2), Err(InstallError::Error));
        assert_eq!(m.activate_slice(0), Some(2));
        assert_eq!(m.install(&e, 1, 2), Err(InstallError::Error), "stale generation");
        assert_eq!(m.install(&e, 3, 2), Err(InstallError::Error), "future generation");
        assert_eq!(m.slot_allocator().quarantined(), 0, "refused before a slot is taken");
        let s = m.install(&e, 2, 2).unwrap_or(u32::MAX);
        m.flush();
        assert_eq!(m.record(s).map(|r| r.generation), Some(2));
        assert_eq!(s % 4, 2, "partition of shard 2");
        assert!(m.retire(s, &e).is_ok());
        m.flush();
        m.slot_allocator().advance_epoch();
        m.slot_allocator().recycle();
        // Partition 2 holds only slot 2 of 4: no slot until two epochs.
        assert_eq!(m.install(&entry(24), 2, 2), Err(InstallError::Slots));
        assert_eq!(m.counters().install_slots.get(), 1);
        assert_eq!(m.counters().install_error.get(), 3);
    }

    /// Concurrency: installs and retires from several threads (each its own
    /// shard, as under `bib4`) against a running publisher: every
    /// published entry belongs to a live slot, and at the end the maps
    /// hold exactly the live sessions.
    #[test]
    fn concurrent_installs_retires_and_publisher_agree() {
        let (t, m) = mirror(1 << 16, 4096);
        let m = Arc::new(m);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let publ = {
            let (m, stop) = (m.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    m.flush();
                }
            })
        };
        let ws: Vec<_> = (0..4u8)
            .map(|w| {
                let m = m.clone();
                std::thread::spawn(move || {
                    let mut live = Vec::new();
                    for i in 0..2000u32 {
                        let mut e = entry(w);
                        e.sport6 = (i % 60000) as u16;
                        e.pool_port4 = 1024 + (i % 60000) as u16;
                        e.dst4 = [10, w, (i >> 8) as u8, i as u8];
                        if let Ok(s) = m.install(&e, 1, usize::from(w)) {
                            live.push((s, e));
                        }
                        if i % 3 == 0
                            && let Some((s, e)) = live.pop()
                        {
                            assert!(m.retire(s, &e).is_ok());
                        }
                        if i % 512 == 0 {
                            m.slot_allocator().advance_epoch();
                            m.slot_allocator().recycle();
                        }
                    }
                    live
                })
            })
            .collect();
        let live: Vec<(u32, SessionEntry)> = ws.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect();
        stop.store(true, Ordering::Release);
        let _ = publ.join();
        m.flush();
        assert_eq!(t.in4.lock().len(), live.len());
        assert_eq!(t.out6.lock().len(), live.len());
        for (s, e) in &live {
            assert_eq!(m.record(*s).map(|r| r.state), Some(SLOT_LIVE));
            assert_eq!(t.in4.lock().get(&e.key4().to_bytes()), Some(s));
        }
        assert_eq!(m.counters().sessions.get(), live.len() as u64);
    }

    /// QA (WU5 redesign): the publisher stopped or never started. Nothing
    /// reaches the hash maps, so the fast path never forwards (only `LIVE`
    /// is forwarded); retires still go DEAD under the caller's lock; slots
    /// are never recycled before their deletes ran (the pool exhausts
    /// into `Slots`, i.e. slow path only), and the per-partition op queues
    /// stay within their two-ops-per-slot bound (SC-5). One late flush
    /// drains everything and the slots come back after the grace period.
    #[test]
    fn publisher_stopped_fails_safe_and_bounded() {
        let (t, m) = mirror(64, 8);
        let mut held = Vec::new();
        for n in 0..32u8 {
            if let Ok(s) = m.install(&entry(n), 1, usize::from(n) % 4) {
                held.push((s, entry(n)));
            }
        }
        assert_eq!(held.len(), 8, "exactly the slot pool, then Slots");
        for (s, _) in &held {
            assert_eq!(m.record(*s).map(|r| r.state), Some(SLOT_PENDING));
        }
        assert!(t.out6.lock().is_empty() && t.in4.lock().is_empty(), "no publisher: no entry");
        for (s, e) in &held {
            assert!(m.retire(*s, e).is_ok());
            assert_eq!(m.record(*s).map(|r| r.state), Some(SLOT_DEAD), "never re-matched");
        }
        assert_eq!(m.counters().retires.get(), 8, "every retire deferred: queue bound held");
        m.slot_allocator().advance_epoch();
        m.slot_allocator().advance_epoch();
        assert_eq!(m.slot_allocator().recycle(), 0, "no recycle before the deletes ran");
        assert_eq!(m.install(&entry(40), 1, 0), Err(InstallError::Slots));
        assert_eq!(m.flush(), 16, "8 publishes (refused: retired) + 8 retires");
        assert!(t.out6.lock().is_empty() && t.in4.lock().is_empty());
        assert_eq!(m.counters().installs.get(), 0);
        m.slot_allocator().advance_epoch();
        m.slot_allocator().advance_epoch();
        assert_eq!(m.slot_allocator().recycle(), 8);
        assert!(m.install(&entry(40), 1, 0).is_ok());
    }

    /// SEC-003: a failed deferred delete keeps the slot out of the
    /// quarantine and is retried until the entries are gone.
    #[test]
    fn failed_deletes_are_retried_and_never_orphaned() {
        let (t, m) = mirror(16, 16);
        let e = entry(40);
        let s = m.install(&e, 1, 0).unwrap_or(u32::MAX);
        m.flush();
        t.fail_delete.store(true, Ordering::Relaxed);
        assert!(m.retire(s, &e).is_ok());
        m.flush();
        m.flush();
        assert_eq!(m.counters().retire_error.get(), 2, "counted per attempt");
        assert_eq!(m.slot_allocator().quarantined(), 0, "not reusable while entries remain");
        t.fail_delete.store(false, Ordering::Relaxed);
        m.flush();
        assert!(t.out6.lock().is_empty() && t.in4.lock().is_empty(), "no orphan entry");
        assert_eq!(m.slot_allocator().quarantined(), 1);
    }

    /// PERF-005 / SEC-002: failed publishes are queued for the collector,
    /// and every pass is counted (publisher liveness).
    #[test]
    fn failed_publishes_are_queued_and_passes_counted() {
        let (_t, m) = mirror(1, 16);
        let p0 = m.publisher_passes();
        assert!(m.install(&entry(41), 1, 0).is_ok());
        let s = m.install(&entry(42), 1, 1).unwrap_or(u32::MAX);
        m.flush();
        assert!(m.publisher_passes() > p0);
        let mut f = Vec::new();
        m.take_failed(&mut f, 16);
        assert_eq!(m.record(f[0]).map(|r| r.state), Some(SLOT_FAILED));
        assert!(f.len() == 1 && (f[0] == s || m.record(s).map(|r| r.state) == Some(SLOT_LIVE)));
        m.take_failed(&mut f, 16);
        assert_eq!(f.len(), 1, "taken once");
        assert!(m.publisher_idle_secs() < 5.0);
        assert_eq!(m.slot_allocator().queued_ops(), 0);
    }
}
