//! Chunked slice adoption (POAM-047): [`State::adopt_slice`] as a
//! resumable cursor ([`Adoption`]) that the `plat-cluster-ctl` thread
//! advances one time-budgeted [`State::adopt_step`] at a time, so its
//! heartbeats and lease renewals run between steps.
//!
//! Phases, in order (one step may span several):
//!
//! 1. stale: leftovers of the slice are removed shard by shard (as
//!    [`State::release_slice`], release records with no reason);
//! 2. plan: blocks validated against the slice, per-subscriber and
//!    aggregate room, reservations, recent releases, and with
//!    `hold_unknown` every unknown block of the slice held back;
//! 3. import blocks, then import BIBs streamed from the replicated map
//!    (no sort, no copy);
//! 4. log: `cluster_slice_acquire`, then one `nat_port_block_adopt` per
//!    imported block, resumable under `refuse_new_bindings`;
//! 5. activate: the slice's free lists are rebuilt and the slice goes
//!    Active in one release-store.
//!
//! Imported blocks and BIBs sit in the live tables from phase 3 on, but the
//! slice is `Adopting`, so no worker uses them: an imported mapping is
//! refused by the Active check on the outbound, inbound and allocation
//! paths and by the XDP install gate. They become usable only with the
//! final `Active` store, after every record is queued.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-12, AU-5 - nothing of the slice is used before its
//!   `cluster_slice_acquire` and `nat_port_block_adopt` records are queued;
//!   under `refuse_new_bindings` a full queue pauses the log phase
//!   (`AdoptError::AuditUnavailable`) and the next step resumes it, each
//!   record queued exactly once per epoch
//! - NIST 800-53: SC-24 - a half-adopted slice never serves; an abandoned
//!   adoption removes what it imported (release records only for blocks
//!   whose adopt record was queued) and leaves the slice Inactive, never
//!   Fenced, so a regain is never taken as complete
//! - NIST 800-53: CP-10, SC-5(2) - the control thread keeps its lease
//!   duties during recovery: each step is bounded by time and item count
//! - NIST 800-53: SC-5 - per-step work is bounded ([`ADOPT_STEP_BUDGET`],
//!   clock read every [`ADOPT_BATCH`] items, at most
//!   [`ADOPT_STEP_MAX_ITEMS`] items); cursor memory is bounded by the
//!   slice's block count and the detached shadow, which stays charged to
//!   the shadow's `max_bibs` until dropped

use std::collections::HashSet;
use std::collections::hash_map::{self, Entry};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ahash::RandomState;
use plat_audit::{BlockAdopt, BlockReleaseReason, Event, SliceAcquire, SliceCidr, TryEmit};
use plat_cluster::{SliceId, WireBib, WireBlock};
use plat_common::Clock;
use plat_common::config::{AuditMode, Filtering};
use plat_packet::proto;

use super::{
    AdoptError, AdoptMeta, AdoptStats, BLOCK_LINGER_MS, Bib, Block, Key4, Key6, Mapped, ReleaseStats, State,
    Subscriber, proto_idx,
};
use crate::pool::{BlockRef, SliceState};
use crate::repl::{AdoptInput, Detached, ShadowCharge, ShadowHome};
use crate::shard::{Map, lower_due};

/// Wall time one [`State::adopt_step`] aims for. A constant, not
/// configuration: with the 100 ms heartbeat default it keeps the control
/// thread's longest stall at a few percent of a tick on any host.
pub const ADOPT_STEP_BUDGET: Duration = Duration::from_millis(5);
/// Items between two clock reads within a step.
pub const ADOPT_BATCH: usize = 1024;
/// Hard cap of items per step, whatever the clock says.
pub const ADOPT_STEP_MAX_ITEMS: usize = 262_144;
/// Items one imported BIB is charged. Inserts into the `bib6`/`bib4`
/// shards cluster their rehashes (uniform hashing grows the shards at about
/// the same time), so 1024 inserts in a row cost several budgets (measured
/// 9-22 ms on the bench host); at 16 the clock is read every 64 BIBs and a
/// step imports at most 16 384 (the 5 ms deadline usually ends it first).
pub const BIB_IMPORT_COST: usize = 16;
/// Items one removed BIB, and one released block with its subscriber, are
/// charged in a removal walk (POAM-048). A removal takes the `bib6` and
/// `bib4` locks, retires the mirror entry and frees the BIB's sessions; a
/// block release builds and queues a record and may drop its subscriber.
/// At one item each, a batch of 1024 cost up to 20 ms on the bench host
/// (4M BIBs); at 16 the clock is read every 64 of them.
pub const RELEASE_ITEM_COST: usize = 16;

/// Where an adoption's records come from.
#[derive(Debug)]
pub enum AdoptSource {
    /// A materialised (and usually sorted) input: tests, the bench, and
    /// takeovers that inherit nothing.
    Input(AdoptInput),
    /// A shadow slice moved out by [`crate::repl::Shadow::detach`].
    Detached(Detached),
}

/// Result of one [`State::adopt_step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Budget used up; call again.
    More,
    /// Every record queued and the slice Active.
    Done(AdoptStats),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Stale,
    PlanBlocks,
    PlanRoom,
    PlanOther,
    HoldUnknown,
    Order,
    ImportBlocks,
    Reserve,
    ImportBibs,
    Log,
    Activate,
    Done,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stale => "stale",
            Self::PlanBlocks | Self::PlanRoom | Self::PlanOther | Self::HoldUnknown | Self::Order => "plan",
            Self::ImportBlocks => "import_blocks",
            Self::Reserve => "reserve",
            Self::ImportBibs => "import_bibs",
            Self::Log => "log",
            Self::Activate => "activate",
            Self::Done => "done",
        }
    }
}

#[derive(Debug)]
enum BlockSrc {
    Vec(std::vec::IntoIter<(u128, WireBlock, u64)>),
    Map(hash_map::IntoIter<(u32, u16), (u128, u64)>),
}

impl BlockSrc {
    fn next(&mut self) -> Option<(u128, WireBlock, u64)> {
        match self {
            Self::Vec(it) => it.next(),
            Self::Map(it) => it.next().map(|((addr, block), (sub, wall))| (sub, WireBlock { addr, block }, wall)),
        }
    }
}

#[derive(Debug)]
enum BibSrc {
    Vec(std::vec::IntoIter<WireBib>),
    Map(hash_map::IntoValues<(u8, u32, u16), WireBib>),
}

impl BibSrc {
    fn len(&self) -> usize {
        match self {
            Self::Vec(it) => it.len(),
            Self::Map(it) => it.len(),
        }
    }

    fn next(&mut self) -> Option<WireBib> {
        match self {
            Self::Vec(it) => it.next(),
            Self::Map(it) => it.next(),
        }
    }
}

/// One adopted block: `(block, sub, original allocation time, imported)`.
/// `imported` is false for a block that lost a race for subscriber room
/// at import (held back instead, never logged).
#[derive(Debug, Clone, Copy)]
struct Adopted {
    r: BlockRef,
    sub: u128,
    wall: u64,
    imported: bool,
}

/// What the subscribers phase of a release walk drops and records.
#[derive(Clone, Copy)]
struct SubRelease<'a> {
    s: SliceId,
    emit: &'a Emit<'a>,
    reason: Option<BlockReleaseReason>,
    /// Pause on a full audit queue (`refuse_new_bindings`).
    pause: bool,
}

/// Resume point of a walk that removes a slice's BIBs (`bib4` shards),
/// then its blocks and emptied subscribers (`subs` shards).
#[derive(Debug, Default)]
pub(super) struct Walk {
    bib_shard: usize,
    sub_shard: usize,
    /// The in-slice keys of one `bib4` shard (bounded by the shard),
    /// drained across steps from `dead_pos` (POAM-048): the step unit is
    /// one BIB removal, not a whole shard.
    dead: Vec<(Key4, Key6)>,
    dead_pos: usize,
    /// Release records go through `try_emit`; a full queue pauses the walk
    /// with the refused record in `pending` (a release under
    /// `refuse_new_bindings`, see `release.rs`).
    pub(super) pause_on_full: bool,
    /// A record refused by a full queue, queued before anything else.
    pub(super) pending: Option<Event>,
    /// The last pass stopped on a full queue.
    pub(super) paused: bool,
    /// When set, the removed BIBs are kept here for the shadow (an abandon
    /// that returns the state, bounded by the detached BIBs).
    collect: Option<Map<(u8, u32, u16), WireBib>>,
}

impl Walk {
    /// "bibs" until every `bib4` shard is done, then "blocks".
    pub(super) fn in_bibs(&self, bib_shards: usize) -> bool {
        self.bib_shard < bib_shards || self.dead_pos < self.dead.len()
    }
}

/// Which removed blocks get a `nat_port_block_release` record.
pub(super) enum Emit<'a> {
    /// Every block (and BIB delete records in session mode): state this
    /// node served or logged.
    All,
    /// Only these: an abandoned adoption's blocks whose adopt record was
    /// queued. No BIB delete records (the adoption logged no creates).
    Only(&'a HashSet<BlockRef, RandomState>),
}

/// Per-step work limit: a deadline read every [`ADOPT_BATCH`] items and a
/// hard item cap. A step always does at least one unit of work.
#[derive(Debug)]
pub(super) struct Budget {
    deadline: Option<Instant>,
    cap: usize,
    items: usize,
    next_check: usize,
    out: bool,
}

impl Budget {
    pub(super) fn new(deadline: Option<Instant>, cap: usize) -> Self {
        Self { deadline, cap, items: 0, next_check: ADOPT_BATCH, out: false }
    }

    pub(super) fn unbounded() -> Self {
        Self::new(None, usize::MAX)
    }

    fn spend(&mut self, n: usize) {
        self.items = self.items.saturating_add(n);
        if self.items >= self.cap {
            self.out = true;
        } else if self.items >= self.next_check {
            self.next_check = self.items.saturating_add(ADOPT_BATCH);
            if self.deadline.is_some_and(|d| Instant::now() >= d) {
                self.out = true;
            }
        }
    }

    fn out(&self) -> bool {
        self.out
    }

    /// Something was done in this step already.
    fn started(&self) -> bool {
        self.items > 1
    }

    /// Ends the step here.
    fn end(&mut self) {
        self.out = true;
    }
}

#[derive(Debug)]
struct Abandon {
    walk: Walk,
    /// Abandoned during the stale phase: the rest of the stale walk runs
    /// as it would have (every leftover logged as released).
    stale: bool,
    logged: HashSet<BlockRef, RandomState>,
    reason: Option<BlockReleaseReason>,
    stats: ReleaseStats,
    done: bool,
    /// The unread rest of the source still goes back to the shadow
    /// (drained in budgeted pieces before the walk).
    draining: bool,
    /// The unread rest of the detached source (replicated BIBs only; never
    /// stale leftovers of this node, SEC-001).
    back: Map<(u8, u32, u16), WireBib>,
}

/// A slice takeover in progress (see the module docs). Created by
/// [`State::adopt_begin`], advanced by [`State::adopt_step`], ended by
/// `Step::Done` or [`State::adopt_abandon`]. Owned by one thread (the
/// control thread); holds no lock between steps.
#[derive(Debug)]
pub struct Adoption {
    slice: SliceId,
    meta: AdoptMeta,
    in_sync: bool,
    hold_unknown: bool,
    phase: Phase,
    /// Position within the current phase.
    pos: usize,
    blocks: Option<BlockSrc>,
    bibs: Option<BibSrc>,
    reserved_unseen: Vec<WireBlock>,
    released: Vec<(WireBlock, u64)>,
    /// Shadow BIBs still charged to `max_bibs` (dropped after import).
    charge: Option<ShadowCharge>,
    walk: Walk,
    hold_until: u64,
    plan_now: u64,
    owner: Map<BlockRef, (u128, u64)>,
    per_sub: Map<u128, Vec<BlockRef>>,
    subs_list: Vec<(u128, Vec<BlockRef>)>,
    new_subs: u64,
    new_per_agg: Map<u128, u32>,
    known: HashSet<BlockRef, RandomState>,
    held: Vec<(u64, BlockRef)>,
    cooling: Vec<(u64, BlockRef)>,
    adopted: Vec<Adopted>,
    sessions_of: Map<u128, Arc<AtomicU32>>,
    /// BIBs that passed validation (`cluster_slice_acquire.bibs_adopted`).
    validated: u64,
    acquire_logged: bool,
    /// Imported blocks logged in the current epoch.
    logged_n: u32,
    /// Highest `adopted` position ever logged, in any epoch: an abandon
    /// releases these.
    logged_hi: usize,
    stats: AdoptStats,
    abandon: Option<Abandon>,
    /// The detached shadow slice to return the state to on abandon, unless
    /// [`Adoption::discard_shadow`] was called.
    home: Option<Box<ShadowHome>>,
    /// Every block read from a detached source, kept for `home` (bounded by
    /// the slice's block count).
    orig_blocks: Vec<(u128, WireBlock, u64)>,
}

impl Adoption {
    pub fn slice(&self) -> SliceId {
        self.slice
    }

    pub fn meta(&self) -> AdoptMeta {
        self.meta
    }

    /// Current phase, for status and logs.
    pub fn phase(&self) -> &'static str {
        if self.abandon.is_some() { "abandoning" } else { self.phase.as_str() }
    }

    /// An abandon of this cursor drops the detached shadow state instead
    /// of returning it to the shadow: the slice went to another member, was
    /// handed back, or the node stops (impl-notes, fix round 1).
    pub fn discard_shadow(&mut self) {
        self.home = None;
        self.orig_blocks = Vec::new();
    }

    pub fn is_abandoning(&self) -> bool {
        self.abandon.is_some()
    }

    /// The slice was granted again (e.g. a newer view) while adopting. The
    /// imported state is kept; another epoch logs every record afresh, with
    /// the new epoch (the same rule as a refused-and-retried adoption).
    pub fn rebase(&mut self, meta: AdoptMeta) {
        if meta.epoch != self.meta.epoch {
            self.acquire_logged = false;
            self.logged_n = 0;
            if matches!(self.phase, Phase::Log | Phase::Activate) {
                self.phase = Phase::Log;
                self.pos = 0;
            }
        }
        self.meta = meta;
    }

    /// Abandon with the state kept: drains the unread rest of the detached
    /// source for the shadow, budgeted. True when done (or nothing to do).
    fn drain_unread(&mut self, b: &mut Budget) -> bool {
        let Some(ab) = self.abandon.as_mut() else { return true };
        if !ab.draining {
            return true;
        }
        while !b.out() {
            if let Some(x) = self.blocks.as_mut().and_then(BlockSrc::next) {
                self.orig_blocks.push(x);
            } else if let Some(w) = self.bibs.as_mut().and_then(BibSrc::next) {
                ab.back.insert((w.proto, w.v4, w.port4), w);
            } else {
                break;
            }
            b.spend(1);
        }
        if b.out() {
            return false;
        }
        ab.draining = false;
        self.blocks = None;
        self.bibs = None;
        true
    }

    fn drop_sources(&mut self) {
        self.blocks = None;
        self.bibs = None;
        self.charge = None;
        self.reserved_unseen = Vec::new();
        self.released = Vec::new();
        self.owner = Map::with_hasher(RandomState::new());
        self.per_sub = Map::with_hasher(RandomState::new());
        self.subs_list = Vec::new();
        self.new_per_agg = Map::with_hasher(RandomState::new());
        self.known = HashSet::with_hasher(RandomState::new());
        self.sessions_of = Map::with_hasher(RandomState::new());
    }
}

impl State {
    /// Starts taking over slice `s` (O(1)): the slice goes `Adopting` and
    /// the returned cursor holds the replicated state. Advance it with
    /// [`State::adopt_step`] until `Step::Done`.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-24 - the slice translates nothing from here until
    ///   the last step sets it Active
    pub fn adopt_begin(&self, s: SliceId, src: AdoptSource, meta: AdoptMeta) -> Result<Adoption, AdoptError> {
        let Some(c) = &self.cluster else { return Err(AdoptError::NotSliced) };
        let state = self.pool.slice_state(s).ok_or(AdoptError::BadSlice)?;
        if state == SliceState::Active {
            return Err(AdoptError::Active);
        }
        if self.slice_releasing(s) {
            return Err(AdoptError::Releasing);
        }
        c.slices.cidr(s).ok_or(AdoptError::BadSlice)?;
        self.pool.set_slice_state(s, SliceState::Adopting);
        let (blocks, bibs, reserved_unseen, released, in_sync, hold_unknown, charge, home) = match src {
            AdoptSource::Input(i) => (
                BlockSrc::Vec(i.blocks.into_iter()),
                BibSrc::Vec(i.bibs.into_iter()),
                i.reserved_unseen,
                i.released,
                i.in_sync,
                i.hold_unknown,
                None,
                None,
            ),
            AdoptSource::Detached(d) => (
                BlockSrc::Map(d.blocks.into_iter()),
                BibSrc::Map(d.bibs.into_values()),
                d.reserved_unseen,
                d.released,
                d.in_sync,
                d.hold_unknown,
                Some(d.charge),
                d.home,
            ),
        };
        let h = || self.hasher.clone();
        Ok(Adoption {
            slice: s,
            meta,
            in_sync,
            hold_unknown,
            phase: Phase::Stale,
            pos: 0,
            blocks: Some(blocks),
            bibs: Some(bibs),
            reserved_unseen,
            released,
            charge,
            walk: Walk::default(),
            hold_until: 0,
            plan_now: 0,
            owner: Map::with_hasher(h()),
            per_sub: Map::with_hasher(h()),
            subs_list: Vec::new(),
            new_subs: 0,
            new_per_agg: Map::with_hasher(h()),
            known: HashSet::with_hasher(h()),
            held: Vec::new(),
            cooling: Vec::new(),
            adopted: Vec::new(),
            sessions_of: Map::with_hasher(h()),
            validated: 0,
            acquire_logged: false,
            logged_n: 0,
            logged_hi: 0,
            stats: AdoptStats::default(),
            abandon: None,
            home,
            orig_blocks: Vec::new(),
        })
    }

    /// Advances `a` until `deadline` (read every [`ADOPT_BATCH`] items) or
    /// [`ADOPT_STEP_MAX_ITEMS`] items. `AuditUnavailable` keeps the cursor:
    /// retry later. `Interrupted`: the slice left `Adopting` or the cursor
    /// is being abandoned; abandon it.
    pub fn adopt_step(&self, a: &mut Adoption, deadline: Instant) -> Result<Step, AdoptError> {
        self.adopt_run(a, &mut Budget::new(Some(deadline), ADOPT_STEP_MAX_ITEMS))
    }

    /// Undoes an adoption that will not complete (lease lost, slice
    /// reassigned or handed back, shutdown), stepwise like
    /// [`State::adopt_step`]: removes the slice's imported BIBs, blocks and
    /// emptied subscribers, queues `nat_port_block_release` (`reason`) only
    /// for blocks whose adopt record was queued, and leaves the slice
    /// Inactive. Returns true when clean. A completed (Active) adoption is
    /// not touched.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-24 - fail in a known state: nothing of a partial
    ///   slice remains and its regain re-adopts from scratch
    /// - NIST 800-53: AU-12, AU-10 - every attribution interval opened by
    ///   a queued adopt record is closed by a release record; none is
    ///   invented for a block that was never logged
    pub fn adopt_abandon(&self, a: &mut Adoption, deadline: Instant, reason: Option<BlockReleaseReason>) -> bool {
        self.abandon_run(a, &mut Budget::new(Some(deadline), ADOPT_STEP_MAX_ITEMS), reason)
    }

    /// [`State::adopt_abandon`] to completion, without a deadline
    /// (shutdown).
    pub fn adopt_abandon_all(&self, a: &mut Adoption, reason: Option<BlockReleaseReason>) -> ReleaseStats {
        while !self.abandon_run(a, &mut Budget::unbounded(), reason) {}
        a.abandon.as_ref().map_or_else(ReleaseStats::default, |x| x.stats)
    }

    pub(super) fn abandon_run(&self, a: &mut Adoption, b: &mut Budget, reason: Option<BlockReleaseReason>) -> bool {
        if a.phase == Phase::Done && a.abandon.is_none() {
            return true;
        }
        if a.abandon.is_none() {
            self.abandon_init(a, reason);
        }
        if a.abandon.as_ref().is_none_or(|ab| ab.done) {
            return true;
        }
        if !a.drain_unread(b) {
            return false;
        }
        let Some(ab) = a.abandon.as_mut() else { return true };
        let (emit, why) = if ab.stale { (Emit::All, None) } else { (Emit::Only(&ab.logged), ab.reason) };
        if !self.walk_slice(a.slice, &mut ab.walk, b, &emit, why, &mut ab.stats) {
            return false;
        }
        self.pool.reset_slice(a.slice, &[], &[], &[]);
        if self.pool.slice_state(a.slice) != Some(SliceState::Active) {
            self.pool.set_slice_state(a.slice, SliceState::Inactive);
        }
        ab.done = true;
        a.phase = Phase::Done;
        self.restore_home(a);
        a.drop_sources();
        true
    }

    /// First abandon call: what was logged (released later), the walk to
    /// run, and what goes back to the shadow.
    fn abandon_init(&self, a: &mut Adoption, reason: Option<BlockReleaseReason>) {
        let stale = a.phase == Phase::Stale;
        let mut logged = HashSet::with_hasher(self.hasher.clone());
        logged.extend(a.adopted.iter().take(a.logged_hi).filter(|x| x.imported).map(|x| x.r));
        let mut walk = if stale { std::mem::take(&mut a.walk) } else { Walk::default() };
        // Imported BIBs go back to the shadow with the rest (stale
        // leftovers are not the shadow's).
        if a.home.is_some() && !stale {
            walk.collect = Some(Map::with_hasher(self.hasher.clone()));
        }
        a.abandon = Some(Abandon {
            walk,
            stale,
            logged,
            reason,
            stats: ReleaseStats::default(),
            done: false,
            draining: a.home.is_some(),
            back: Map::with_hasher(self.hasher.clone()),
        });
        a.adopted = Vec::new();
        a.held = Vec::new();
        a.cooling = Vec::new();
        if a.home.is_none() {
            a.drop_sources();
        }
    }

    /// The abandon is complete: returns the replicated state to the
    /// shadow, if it is kept.
    fn restore_home(&self, a: &mut Adoption) {
        let (Some(home), Some(ab)) = (a.home.take(), a.abandon.as_mut()) else { return };
        // Replicated entries only: the unread source, plus the imported
        // BIBs the walk removed (collected only outside the stale phase, so
        // this node's own leftovers never reach the shadow). A replicated
        // entry wins over any other with the same key.
        let mut bibs = std::mem::replace(&mut ab.back, Map::with_hasher(RandomState::new()));
        for (k, v) in ab.walk.collect.take().into_iter().flatten() {
            bibs.entry(k).or_insert(v);
        }
        let mut blocks = Map::with_hasher(self.hasher.clone());
        for (sub, w, wall) in std::mem::take(&mut a.orig_blocks) {
            blocks.entry((w.addr, w.block)).or_insert((sub, wall));
        }
        home.restore(blocks, bibs, a.in_sync, a.charge.take());
    }

    pub(super) fn adopt_run(&self, a: &mut Adoption, b: &mut Budget) -> Result<Step, AdoptError> {
        if a.phase == Phase::Done && a.abandon.is_none() {
            return Ok(Step::Done(a.stats));
        }
        let Some(c) = &self.cluster else { return Err(AdoptError::NotSliced) };
        if a.abandon.is_some() || self.pool.slice_state(a.slice) != Some(SliceState::Adopting) {
            return Err(AdoptError::Interrupted);
        }
        let s = a.slice;
        let mut phase = a.phase;
        loop {
            // A phase change is one unit of work: a step never runs into
            // the next phase on an empty budget.
            if a.phase != phase {
                phase = a.phase;
                b.spend(1);
                // One-shot units of O(slice blocks) (sort, free-list
                // rebuild) start on a step of their own, so they never
                // add to a full budget.
                if matches!(phase, Phase::Order | Phase::Activate) {
                    b.end();
                }
            }
            if b.out() {
                return Ok(Step::More);
            }
            match a.phase {
                Phase::Stale => {
                    if !self.walk_slice(s, &mut a.walk, b, &Emit::All, None, &mut a.stats.stale) {
                        return Ok(Step::More);
                    }
                    a.walk = Walk::default();
                    a.plan_now = self.clock.now_ms();
                    a.hold_until = a.plan_now + c.quarantine_ms;
                    a.phase = Phase::PlanBlocks;
                }
                Phase::PlanBlocks => self.plan_blocks(a, b),
                Phase::PlanRoom => self.plan_room(a, b),
                Phase::PlanOther => self.plan_other(a, b),
                Phase::HoldUnknown => self.hold_unknown(a, b),
                Phase::Order => {
                    a.adopted =
                        a.owner.iter().map(|(r, &(sub, wall))| Adopted { r: *r, sub, wall, imported: true }).collect();
                    a.adopted.sort_unstable_by_key(|x| (x.r.addr_idx, x.r.block));
                    b.spend(a.adopted.len());
                    a.pos = 0;
                    a.phase = Phase::ImportBlocks;
                }
                Phase::ImportBlocks => self.import_blocks(a, b),
                Phase::Reserve => self.reserve_tables(a, b),
                Phase::ImportBibs => self.import_bibs(a, b, c.tcp_adopt_ms),
                Phase::Log => self.adopt_log(a, b, c.slices.cidr(s).ok_or(AdoptError::BadSlice)?)?,
                Phase::Activate => {
                    let in_use: Vec<BlockRef> = a.adopted.iter().filter(|x| x.imported).map(|x| x.r).collect();
                    self.pool.reset_slice(s, &in_use, &a.held, &a.cooling);
                    // The one store that makes the slice usable, after every
                    // record is queued (AU-12).
                    self.pool.set_slice_state(s, SliceState::Active);
                    a.adopted = Vec::new();
                    a.held = Vec::new();
                    a.cooling = Vec::new();
                    a.phase = Phase::Done;
                    return Ok(Step::Done(a.stats));
                }
                Phase::Done => return Ok(Step::Done(a.stats)),
            }
        }
    }

    /// Blocks validated against the slice; first record per block wins.
    fn plan_blocks(&self, a: &mut Adoption, b: &mut Budget) {
        while !b.out() {
            let Some((sub, w, wall)) = a.blocks.as_mut().and_then(BlockSrc::next) else {
                a.blocks = None;
                a.subs_list = a.per_sub.drain().collect();
                a.pos = 0;
                a.phase = Phase::PlanRoom;
                return;
            };
            if a.home.is_some() {
                a.orig_blocks.push((sub, w, wall));
            }
            match self.block_ref(a.slice, w) {
                Some(r) if sub & self.sub_mask == sub && !a.owner.contains_key(&r) => {
                    a.owner.insert(r, (sub, wall));
                    a.per_sub.entry(sub).or_default().push(r);
                }
                _ => a.stats.rejected += 1,
            }
            b.spend(1);
        }
    }

    /// Per-subscriber block limit and subscriber/aggregate table bounds
    /// (SC-5): blocks over a limit are held back, the lowest kept.
    fn plan_room(&self, a: &mut Adoption, b: &mut Budget) {
        while !b.out() {
            let Some((sub, blocks)) = a.subs_list.get_mut(a.pos) else {
                a.subs_list = Vec::new();
                a.pos = 0;
                a.phase = Phase::PlanOther;
                return;
            };
            let sub = *sub;
            blocks.sort_unstable_by_key(|r| (r.addr_idx, r.block));
            let (have, exists) = {
                let g = self.subs.lock(&sub);
                g.get(&sub).map_or((0, false), |x| (x.blocks.len(), true))
            };
            let agg = sub & self.agg_mask;
            let planned = a.new_per_agg.get(&agg).copied().unwrap_or(0);
            let agg_room = self.aggregate_count(sub).saturating_add(planned) < self.max_per_agg;
            let room = if exists || (self.sub_count.load(Ordering::Relaxed) + a.new_subs < self.max_subs && agg_room) {
                usize::from(self.max_blocks).saturating_sub(have)
            } else {
                0
            };
            if !exists && room > 0 {
                a.new_subs += 1;
                *a.new_per_agg.entry(agg).or_insert(0) += 1;
            }
            let n = blocks.len();
            for r in blocks.drain(room.min(n)..) {
                a.owner.remove(&r);
                a.held.push((a.hold_until, r));
            }
            a.pos += 1;
            b.spend(1 + n);
        }
    }

    /// Reserved-but-unseen blocks (held back) and recent releases (finish
    /// the cool-down).
    fn plan_other(&self, a: &mut Adoption, b: &mut Budget) {
        while !b.out() {
            let nr = a.reserved_unseen.len();
            if let Some(w) = a.reserved_unseen.get(a.pos) {
                if let Some(r) = self.block_ref(a.slice, *w)
                    && !a.owner.contains_key(&r)
                {
                    a.held.push((a.hold_until, r));
                }
            } else if let Some(&(w, age)) = a.released.get(a.pos - nr) {
                if let Some(r) = self.block_ref(a.slice, w)
                    && !a.owner.contains_key(&r)
                {
                    a.cooling.push((a.plan_now + self.cooldown_ms.saturating_sub(age), r));
                }
            } else {
                a.reserved_unseen = Vec::new();
                a.released = Vec::new();
                a.pos = 0;
                a.phase = Phase::Order;
                if a.hold_unknown && self.pool.slice_range(a.slice).is_some() {
                    a.known.extend(a.owner.keys().copied());
                    a.known.extend(a.held.iter().map(|h| h.1));
                    a.known.extend(a.cooling.iter().map(|h| h.1));
                    b.spend(a.known.len());
                    a.phase = Phase::HoldUnknown;
                }
                return;
            }
            a.pos += 1;
            b.spend(1);
        }
    }

    /// An incomplete shadow: every block of the slice not otherwise known
    /// is held back (RFC 6888 REQ-8, RFC 7422), resumable by position.
    fn hold_unknown(&self, a: &mut Adoption, b: &mut Budget) {
        let Some((lo, hi)) = self.pool.slice_range(a.slice) else {
            a.phase = Phase::Order;
            return;
        };
        let bpa = usize::from(self.pool.blocks_per_addr());
        let total = (hi - lo) as usize * bpa;
        while !b.out() {
            if a.pos >= total {
                a.known = HashSet::with_hasher(RandomState::new());
                a.pos = 0;
                a.phase = Phase::Order;
                return;
            }
            let r = BlockRef { addr_idx: lo + (a.pos / bpa) as u32, block: (a.pos % bpa) as u16 };
            if !a.known.contains(&r) {
                a.held.push((a.hold_until, r));
            }
            a.pos += 1;
            b.spend(1);
        }
    }

    /// Subscriber entries and blocks (the slice is not Active: no worker
    /// allocates in it).
    fn import_blocks(&self, a: &mut Adoption, b: &mut Budget) {
        let size = self.pool.block_size();
        while !b.out() {
            let Some(x) = a.adopted.get_mut(a.pos) else {
                a.stats.blocks_adopted = a.adopted.iter().filter(|x| x.imported).count() as u32;
                a.pos = 0;
                a.phase = Phase::Reserve;
                return;
            };
            let now = self.clock.now_ms();
            let (mut g, due) = self.subs.lock_due(&x.sub);
            // An adopted block starts empty (lingering) until a BIB marks it.
            lower_due(due, now + BLOCK_LINGER_MS);
            let sx = match g.entry(x.sub) {
                Entry::Occupied(e) => Some(e.into_mut()),
                // Raced with new subscribers (or the aggregate limit,
                // POAM-013) since the plan: hold the block back. Not
                // logged, so no record is queued for it.
                Entry::Vacant(_) if self.sub_count.fetch_add(1, Ordering::Relaxed) >= self.max_subs => {
                    self.sub_count.fetch_sub(1, Ordering::Relaxed);
                    None
                }
                Entry::Vacant(_) if !self.agg_acquire(x.sub) => {
                    self.sub_count.fetch_sub(1, Ordering::Relaxed);
                    None
                }
                Entry::Vacant(e) => Some(e.insert(Subscriber {
                    blocks: Vec::new(),
                    sessions: Arc::new(AtomicU32::new(0)),
                    rng: self.seed.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed) | 1,
                })),
            };
            match sx {
                Some(sx) => {
                    sx.blocks.push(Block::new(x.r, size, x.wall, now));
                    a.sessions_of.insert(x.sub, sx.sessions.clone());
                }
                None => {
                    x.imported = false;
                    a.owner.remove(&x.r);
                    a.held.push((a.hold_until, x.r));
                }
            }
            drop(g);
            a.pos += 1;
            b.spend(1);
        }
    }

    /// Grows every `bib6` and `bib4` shard to hold its share of the BIBs to
    /// import, one shard per unit. Without
    /// it the shards cross their growth threshold within a few inserts of
    /// each other (uniform hashing), and one 64-BIB batch paid for dozens of
    /// rehashes: 13-24 ms steps in platd (POAM-047 F2). Each reserve holds
    /// one shard lock for one rehash, as an organic insert would.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - the extra capacity is bounded by the detached
    ///   BIB count (at most `max_bibs`), rounded up per shard
    fn reserve_tables(&self, a: &mut Adoption, b: &mut Budget) {
        let n = a.bibs.as_ref().map_or(0, BibSrc::len);
        let (s6, s4) = (self.bib6.shard_count(), self.bib4.shard_count());
        while !b.out() {
            let per = if a.pos < s6 { n / s6 } else { n / s4 };
            if a.pos >= s6 + s4 || per == 0 {
                a.pos = 0;
                a.phase = Phase::ImportBibs;
                return;
            }
            // `per`, not more: the map rounds capacity up to a power of two
            // anyway (PERF-002); the spread costs at most one later rehash.
            let extra = per;
            if a.pos < s6 {
                self.bib6.lock_index(a.pos).reserve(extra);
            } else {
                self.bib4.lock_index(a.pos - s6).reserve(extra);
            }
            a.pos += 1;
            // A reserve is one rehash of a whole shard (up to thousands of
            // entries on a loaded node): read the clock after each one
            // (27-30 ms steps measured with a 64-shard batch).
            b.spend(ADOPT_BATCH);
        }
    }

    /// BIBs streamed from the replicated set: validated (protocol,
    /// subscriber mask, block owned by the same subscriber in the slice),
    /// then inserted under `bib6 → bib4` (released), then the port marked
    /// under `subs`. A `k6` or `k4` already present (a duplicate in the
    /// input, or local state) is rejected: first wins.
    fn import_bibs(&self, a: &mut Adoption, b: &mut Budget, tcp_adopt_ms: u64) {
        let s = a.slice;
        while !b.out() {
            let Some(w) = a.bibs.as_mut().and_then(BibSrc::next) else {
                // Freeing the drained table (up to the shadow cap) gets a
                // step of its own too; the iterator is fused.
                if b.started() {
                    b.end();
                    return;
                }
                a.bibs = None;
                a.charge = None;
                a.owner = Map::with_hasher(RandomState::new());
                a.sessions_of = Map::with_hasher(RandomState::new());
                a.stats.blocks_held = a.held.len() as u32;
                a.stats.blocks_cooling = a.cooling.len() as u32;
                a.pos = 0;
                a.phase = Phase::Log;
                return;
            };
            b.spend(BIB_IMPORT_COST);
            let block = self.pool.index(w.v4).and_then(|i| self.pool.block_of(i, w.port4).map(|r| (i, r)));
            let ok = matches!(w.proto, proto::TCP | proto::UDP | proto::ICMP)
                && w.v6 & self.sub_mask == w.sub
                && block.is_some_and(|(_, r)| {
                    self.pool.slice_of_idx(r.addr_idx) == Some(s) && a.owner.get(&r).is_some_and(|o| o.0 == w.sub)
                });
            let (Some((idx, r)), true) = (block, ok) else {
                a.stats.rejected += 1;
                continue;
            };
            a.validated += 1;
            let Some(sub_sessions) = a.sessions_of.get(&w.sub).cloned() else {
                a.stats.rejected += 1;
                continue;
            };
            let k6 = Key6 { proto: w.proto, addr: w.v6, port: w.port6 };
            let k4 = Key4 { proto: w.proto, addr: w.v4, port: w.port4 };
            let now = self.clock.now_ms();
            let until = now + if k4.proto == proto::TCP { tcp_adopt_ms } else { self.timeout(k4.proto, None) };
            let inserted = {
                let mut g6 = self.bib6.lock(&k6);
                let (mut g4, due) = self.bib4.lock_due(&k4);
                if g6.contains_key(&k6) || g4.contains_key(&k4) {
                    false
                } else {
                    lower_due(due, now);
                    g4.insert(
                        k4,
                        Bib {
                            k6,
                            sub: w.sub,
                            created_wall_us: w.created_wall_us,
                            adopt_until_ms: until,
                            empty_since: None,
                            sub_sessions,
                            sessions: Map::with_hasher(self.hasher.clone()),
                            remotes: (self.filtering == Filtering::AddressDependent)
                                .then(|| Box::new(Map::with_hasher(self.hasher.clone()))),
                            held: None,
                        },
                    );
                    g6.insert(k6, Mapped { k4, idx });
                    true
                }
            };
            if !inserted {
                a.stats.rejected += 1;
                continue;
            }
            a.stats.bibs_adopted += 1;
            let mut g = self.subs.lock(&w.sub);
            if let Some(blk) = g.get_mut(&w.sub).and_then(|sx| sx.blocks.iter_mut().find(|x| x.r == r)) {
                blk.mark(proto_idx(k4.proto), k4.port - self.pool.port_lo(r));
            }
        }
    }

    /// Queues `cluster_slice_acquire`, then one `nat_port_block_adopt` per
    /// imported block, resumable: under `refuse_new_bindings` the step
    /// needs room for every remaining record, and a record refused by a
    /// full queue is retried by the next step (`try_emit`, not lost).
    fn adopt_log(&self, a: &mut Adoption, b: &mut Budget, cidr: plat_common::Ipv4Cidr) -> Result<(), AdoptError> {
        let todo = (a.stats.blocks_adopted - a.logged_n) as usize + usize::from(!a.acquire_logged);
        if self.refuse_on_overflow
            && (!self.audit.has_room() || self.audit.capacity().saturating_sub(self.audit.queued()) < todo)
        {
            return Err(AdoptError::AuditUnavailable);
        }
        let wall = Clock::wall_us();
        let meta = a.meta;
        if !a.acquire_logged {
            let acquire = SliceAcquire {
                slice: SliceCidr { net: cidr.network(), len: cidr.prefix_len() },
                epoch: meta.epoch,
                prev_owner: meta.prev_owner,
                reason: meta.reason,
                blocks_adopted: a.stats.blocks_adopted,
                bibs_adopted: a.validated,
                blocks_quarantined: a.stats.blocks_held,
                in_sync: a.in_sync,
            };
            if !self.adopt_emit(Event::ClusterSliceAcquire { ts_us: wall, acquire: Arc::new(acquire) }) {
                return Err(AdoptError::AuditUnavailable);
            }
            a.acquire_logged = true;
            b.spend(1);
        }
        let size = self.pool.block_size();
        while !b.out() {
            let Some(x) = a.adopted.get(a.pos) else {
                a.pos = 0;
                a.phase = Phase::Activate;
                return Ok(());
            };
            if x.imported {
                let lo = self.pool.port_lo(x.r);
                let rec = BlockAdopt {
                    sub: x.sub,
                    sub_len: self.sub_len,
                    v4: self.pool.addr(x.r.addr_idx),
                    port_lo: lo,
                    port_hi: lo + (size - 1),
                    allocated_us: x.wall,
                    prev_owner: meta.prev_owner,
                    epoch: meta.epoch,
                };
                if !self.adopt_emit(Event::PortBlockAdopt { ts_us: wall, adopt: Arc::new(rec) }) {
                    return Err(AdoptError::AuditUnavailable);
                }
                a.logged_n += 1;
            }
            a.pos += 1;
            a.logged_hi = a.logged_hi.max(a.pos);
            b.spend(1);
        }
        Ok(())
    }

    /// One budgeted pass of the removal walk of slice `s`: BIBs and their
    /// sessions shard by shard (`bib4` snapshot of one shard, released,
    /// then `bib6 → bib4` per key), then blocks and emptied subscribers
    /// (`subs` shard by shard). True when the walk is complete.
    pub(super) fn walk_slice(
        &self,
        s: SliceId,
        w: &mut Walk,
        b: &mut Budget,
        emit: &Emit<'_>,
        reason: Option<BlockReleaseReason>,
        st: &mut ReleaseStats,
    ) -> bool {
        let bib_records = matches!(emit, Emit::All) && self.audit_mode == AuditMode::Session;
        if !self.walk_slice_bibs(s, w, b, bib_records, st) {
            return false;
        }
        while w.sub_shard < self.subs.shard_count() {
            if b.out() {
                return false;
            }
            if !self.walk_sub_shard(s, w, b, emit, reason, st) {
                return false;
            }
            w.sub_shard += 1;
        }
        true
    }

    /// Bibs phase of [`Self::walk_slice`]: drains the collected dead list,
    /// then scans the next `bib4` shard. False when the budget runs out or
    /// the walk pauses.
    fn walk_slice_bibs(
        &self,
        s: SliceId,
        w: &mut Walk,
        b: &mut Budget,
        bib_records: bool,
        st: &mut ReleaseStats,
    ) -> bool {
        loop {
            if !self.walk_dead(w, b, bib_records, st) {
                return false;
            }
            w.dead.clear();
            w.dead_pos = 0;
            if w.bib_shard >= self.bib4.shard_count() {
                return true;
            }
            if b.out() {
                return false;
            }
            let scanned = {
                let g = self.bib4.lock_index(w.bib_shard);
                w.dead.extend(g.iter().filter(|(k4, _)| self.in_slice(s, k4.addr)).map(|(k4, x)| (*k4, x.k6)));
                g.len()
            };
            w.bib_shard += 1;
            b.spend(1 + scanned);
        }
    }

    /// Removes the collected BIBs from `w.dead_pos` on. False when the
    /// budget runs out or the walk pauses (the rest is kept).
    fn walk_dead(&self, w: &mut Walk, b: &mut Budget, bib_records: bool, st: &mut ReleaseStats) -> bool {
        while let Some(&(k4, k6)) = w.dead.get(w.dead_pos) {
            if b.out() || w.paused {
                return false;
            }
            w.dead_pos += 1;
            let mut rec = None;
            let x = self.remove_slice_bib(k4, k6, bib_records, st, &mut rec);
            if let (Some(x), Some(c)) = (x, w.collect.as_mut()) {
                c.insert((x.proto, x.v4, x.port4), x);
            }
            if let Some(ev) = rec
                && !self.walk_emit(w.pause_on_full, &mut w.pending, ev)
            {
                w.paused = true;
            }
            b.spend(RELEASE_ITEM_COST);
        }
        !w.paused
    }

    /// Subscribers phase of [`Self::walk_slice`] for shard `w.sub_shard`.
    /// False when the walk paused or the budget ran out mid-shard.
    fn walk_sub_shard(
        &self,
        s: SliceId,
        w: &mut Walk,
        b: &mut Budget,
        emit: &Emit<'_>,
        reason: Option<BlockReleaseReason>,
        st: &mut ReleaseStats,
    ) -> bool {
        let i = w.sub_shard;
        let c = SubRelease { s, emit, reason, pause: w.pause_on_full };
        let (pending, paused) = (&mut w.pending, &mut w.paused);
        // Budget out mid-shard (PERF-001): the subscribers not yet
        // visited are kept and the shard is walked again next step.
        let mut cut = false;
        let mut g = self.subs.lock_index(i);
        let before = g.len();
        g.retain(|sub, sx| {
            if *paused || cut {
                return true;
            }
            let sub_released = st.blocks_released;
            self.release_sub_blocks(c, *sub, sx, pending, paused, st);
            // At least one subscriber per step; the clock is read
            // every `ADOPT_BATCH` items, as in the bibs phase.
            let n = (st.blocks_released - sub_released) as usize;
            b.spend(1 + n.saturating_mul(RELEASE_ITEM_COST));
            if b.out() {
                cut = true;
            }
            let keep = !sx.blocks.is_empty() || sx.sessions.load(Ordering::Relaxed) > 0;
            if !keep {
                self.sub_count.fetch_sub(1, Ordering::Relaxed);
                self.agg_release(*sub);
                st.subscribers_removed += 1;
            }
            keep
        });
        if g.len() != before {
            self.subs.note_removal_index(i);
        }
        drop(g);
        b.spend(1);
        // Paused or cut: the shard is walked again from its start
        // (PERF-005). The subscribers already visited hold no block
        // of the slice any more, so the rescan only costs one
        // `slice_of_idx` per remaining block, and a paused rescan runs
        // at most once per tick (`rel_blocked`).
        !(w.paused || cut)
    }

    /// Drops one subscriber's blocks of slice `s`, queueing a release
    /// record for each one `emit` selects.
    fn release_sub_blocks(
        &self,
        c: SubRelease<'_>,
        sub: u128,
        sx: &mut Subscriber,
        pending: &mut Option<Event>,
        paused: &mut bool,
        st: &mut ReleaseStats,
    ) {
        sx.blocks.retain(|x| {
            // Paused: the rest of the shard is kept for the next
            // step (the shard is walked again from its start).
            if *paused || self.pool.slice_of_idx(x.r.addr_idx) != Some(c.s) {
                return true;
            }
            if matches!(c.emit, Emit::All) || matches!(c.emit, Emit::Only(l) if l.contains(&x.r)) {
                let wall = Clock::wall_us();
                let lo = self.pool.port_lo(x.r);
                let ev = Event::PortBlockRelease {
                    ts_us: wall,
                    sub,
                    sub_len: self.sub_len,
                    v4: self.pool.addr(x.r.addr_idx),
                    port_lo: lo,
                    port_hi: lo + (self.pool.block_size() - 1),
                    held_secs: (wall.saturating_sub(x.wall_us) / 1_000_000) as u32,
                    reason: c.reason,
                };
                // A refused record stays in `pending` and is queued
                // before the slice's blocks return to the pool.
                if !self.walk_emit(c.pause, pending, ev) {
                    *paused = true;
                }
            }
            st.blocks_released += 1;
            false
        });
    }

    /// Queues one release-walk record. With `pause` (a release under
    /// `refuse_new_bindings`) a full queue keeps the record in `pending`
    /// and returns false (the walk pauses; not counted as lost); a stopped
    /// logger counts it lost and the walk goes on. Otherwise `emit`.
    pub(super) fn walk_emit(&self, pause: bool, pending: &mut Option<Event>, ev: Event) -> bool {
        if !pause {
            self.audit.emit(ev);
            return true;
        }
        match self.audit.try_emit(ev.clone()) {
            TryEmit::Queued => true,
            TryEmit::Full => {
                *pending = Some(ev);
                false
            }
            TryEmit::Disconnected => {
                self.audit.count_lost();
                true
            }
        }
    }

    /// Removes one BIB of a slice being given up, with its sessions and
    /// held SYNs (dropped silently: the slice is no longer ours).
    /// The BIB delete record (session mode) is returned in `rec`.
    fn remove_slice_bib(
        &self,
        k4: Key4,
        k6: Key6,
        bib_records: bool,
        st: &mut ReleaseStats,
        rec: &mut Option<Event>,
    ) -> Option<WireBib> {
        let removed = {
            let mut g6 = self.bib6.lock(&k6);
            let mut g4 = self.bib4.lock(&k4);
            if g6.get(&k6).is_some_and(|m| m.k4 == k4) {
                g6.remove(&k6);
            }
            self.bib4.note_removal(&k4);
            let x = g4.remove(&k4);
            // The slice is already fenced in the mirror; its entries also
            // go with their sessions, in this critical section.
            if let Some(x) = &x {
                self.mirror_retire_bib(k4, x);
            }
            x
        };
        let mut bib = removed?;
        if bib.held.is_some() {
            let mut spill = None;
            self.expire_held(k4, &mut bib, self.clock.now_ms(), true, false, &mut spill);
        }
        let n = bib.sessions.len() as u64;
        self.sessions.fetch_sub(n, Ordering::Relaxed);
        bib.sub_sessions.fetch_sub(n as u32, Ordering::Relaxed);
        st.sessions_removed += n;
        st.bibs_removed += 1;
        if bib_records {
            let wall = Clock::wall_us();
            *rec = Some(Event::BibDelete {
                ts_us: wall,
                proto: k6.proto,
                v6: k6.addr,
                v6_port: k6.port,
                v4: k4.addr,
                v4_port: k4.port,
                held_secs: (wall.saturating_sub(bib.created_wall_us) / 1_000_000) as u32,
            });
        }
        Some(WireBib {
            sub: bib.sub,
            proto: k4.proto,
            v6: k6.addr,
            port6: k6.port,
            v4: k4.addr,
            port4: k4.port,
            created_wall_us: bib.created_wall_us,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::{Directory, Shadow};
    use crate::state::ClusterSetup;
    use plat_audit::{AcquireReason, AuditSink};
    use plat_cluster::{SliceMap, SnapRecord};
    use plat_common::config::SteeringMode;
    use plat_common::{Config, Counters, DropReason};

    const SUB: u128 = 0x2001_0db8_0000_0001_u128 << 64;
    /// The first pool address (slice 0 of a /30 split into /32 slices).
    const ADDR: u32 = 0xc000_0200;

    fn config(extra: &[(&str, &str)]) -> Config {
        let mut t = include_str!("../../../config/platd.example.toml")
            .replace("192.0.2.0/24", "192.0.2.0/30")
            .replace("allow_non_global_destinations = false", "allow_non_global_destinations = true");
        for (a, b) in extra {
            t = t.replace(a, b);
        }
        Config::from_toml(&t).unwrap()
    }

    fn state_with(cfg: &Config, queue: usize) -> (State, crossbeam_channel::Receiver<Event>, Clock) {
        let setup = ClusterSetup {
            slices: SliceMap::new(&cfg.nat64.pool, 32).unwrap(),
            self_id: 1,
            steering: SteeringMode::Drop,
            directory: Arc::new(Directory::new(16, 1000)),
            tcp_adopt_secs: 300,
            quarantine_secs: 600,
            reserve_ahead: 2,
        };
        let (sink, rx) = AuditSink::bounded(queue);
        let clock = Clock::new();
        (State::new_cluster(cfg, setup, sink, clock.clone()).unwrap(), rx, clock)
    }

    fn state(queue: usize) -> (State, crossbeam_channel::Receiver<Event>, Clock) {
        state_with(&config(&[]), queue)
    }

    fn meta(epoch: u64) -> AdoptMeta {
        AdoptMeta { epoch, prev_owner: Some(2), reason: AcquireReason::Takeover }
    }

    fn port_lo(block: u16) -> u16 {
        1024 + block * 512
    }

    fn bib(sub: u128, block: u16, i: u16, p: u8) -> WireBib {
        let port = port_lo(block) + i;
        WireBib { sub, proto: p, v6: sub | 1, port6: port, v4: ADDR, port4: port, created_wall_us: 1 }
    }

    /// `blocks` blocks of one subscriber each (subscriber `b`), `per`
    /// UDP BIBs per block.
    fn input(blocks: u16, per: u16) -> AdoptInput {
        // One /64 per block, each in its own /56 aggregate.
        let sub = |b: u16| SUB | (u128::from(b) << 80);
        AdoptInput {
            blocks: (0..blocks).map(|b| (sub(b), WireBlock { addr: ADDR, block: b }, 1)).collect(),
            bibs: (0..blocks).flat_map(|b| (0..per).map(move |i| bib(sub(b), b, i, proto::UDP))).collect(),
            in_sync: true,
            ..AdoptInput::default()
        }
    }

    fn past() -> Instant {
        Instant::now().checked_sub(Duration::from_secs(1)).unwrap_or_else(Instant::now)
    }

    /// Steps with an expired deadline (one batch per step) until done.
    fn step_all(st: &State, a: &mut Adoption) -> (AdoptStats, usize) {
        for n in 1.. {
            if let Step::Done(s) = st.adopt_step(a, past()).unwrap() {
                return (s, n);
            }
        }
        unreachable!()
    }

    /// Bound of the test helpers below: far more units than any test
    /// adoption needs, so a regression fails instead of hanging.
    const STEP_LIMIT: usize = 1 << 20;

    /// One unit at a time until `phase` (a full step may pass it).
    fn run_to(st: &State, a: &mut Adoption, phase: Phase) {
        for _ in 0..STEP_LIMIT {
            if a.phase == phase {
                return;
            }
            assert_eq!(st.adopt_run(a, &mut Budget::new(None, 1)), Ok(Step::More));
        }
        panic!("did not reach {phase:?}");
    }

    fn to_log(st: &State, a: &mut Adoption) {
        run_to(st, a, Phase::Log);
    }

    /// Steps with an expired deadline until at least `n` BIBs are imported.
    fn step_until_bibs(st: &State, a: &mut Adoption, n: usize) {
        for _ in 0..STEP_LIMIT {
            if st.bib4.len() >= n {
                return;
            }
            assert_eq!(st.adopt_step(a, past()), Ok(Step::More));
        }
        panic!("{n} BIBs not imported");
    }

    /// Abandons with an expired deadline per call until clean.
    fn abandon_bounded(st: &State, a: &mut Adoption, reason: Option<BlockReleaseReason>) {
        for _ in 0..STEP_LIMIT {
            if st.adopt_abandon(a, past(), reason) {
                return;
            }
        }
        panic!("abandon did not finish");
    }

    fn kinds(rx: &crossbeam_channel::Receiver<Event>) -> (usize, usize, usize) {
        rx.try_iter().fold((0, 0, 0), |(a, b, r), e| match e {
            Event::ClusterSliceAcquire { .. } => (a + 1, b, r),
            Event::PortBlockAdopt { .. } => (a, b + 1, r),
            Event::PortBlockRelease { .. } => (a, b, r + 1),
            _ => (a, b, r),
        })
    }

    /// Stepping with a tiny budget gives the same tables, stats and
    /// records as the one-shot wrapper.
    #[test]
    fn adopt_steps_match_single_shot() {
        for (blocks, per) in [(0, 0), (1, 0), (3, 5), (100, 40)] {
            let i = input(blocks, per);
            let (one, rx1, _) = state(1 << 16);
            let s1 = one.adopt_slice(0, &i, meta(7)).unwrap();
            let (two, rx2, _) = state(1 << 16);
            let mut a = two.adopt_begin(0, AdoptSource::Input(i.clone()), meta(7)).unwrap();
            let (s2, steps) = step_all(&two, &mut a);
            assert_eq!(s1, s2, "{blocks} blocks");
            assert_eq!((s2.blocks_adopted, s2.bibs_adopted), (u32::from(blocks), u64::from(blocks) * u64::from(per)));
            assert_eq!(one.bib4.len(), two.bib4.len());
            assert_eq!(one.subscriber_count(), two.subscriber_count());
            assert_eq!(kinds(&rx1), kinds(&rx2));
            assert_eq!(two.slice_state(0), Some(SliceState::Active));
            if blocks == 100 {
                assert!(steps > 4, "{steps} steps for 4000 BIBs");
            }
        }
    }

    /// With a past deadline a step stops at the first clock read: one
    /// batch (64 BIBs) at most.
    #[test]
    fn adopt_step_respects_deadline() {
        let (st, _rx, _) = state(1 << 16);
        let mut a = st.adopt_begin(0, AdoptSource::Input(input(100, 50)), meta(7)).unwrap();
        run_to(&st, &mut a, Phase::ImportBibs);
        let mut b = Budget::new(Some(past()), ADOPT_STEP_MAX_ITEMS);
        assert_eq!(st.adopt_run(&mut a, &mut b), Ok(Step::More));
        assert_eq!(b.items, ADOPT_BATCH);
        assert_eq!(st.bib4.len(), ADOPT_BATCH / BIB_IMPORT_COST);
        // The hard cap bounds a step without a deadline.
        let (st, _rx, _) = state(1 << 16);
        let mut a = st.adopt_begin(0, AdoptSource::Input(input(126, 512)), meta(7)).unwrap();
        run_to(&st, &mut a, Phase::ImportBibs);
        let mut b = Budget::new(None, 10_000);
        assert_eq!(st.adopt_run(&mut a, &mut b), Ok(Step::More));
        assert_eq!((b.items, st.bib4.len()), (10_000, 10_000 / BIB_IMPORT_COST));
    }

    /// SC-24: after every step the imported mappings exist but nothing of
    /// the slice is usable: the mapping's index is refused, no block is
    /// allocated, the slice is not Active; it is only after `Done`.
    #[test]
    fn half_adopted_slice_never_forwards() {
        let (st, rx, _) = state(1 << 16);
        let c = Counters::default();
        let i = input(4, 300);
        let k6 = Key6 { proto: proto::UDP, addr: SUB | 1, port: port_lo(0) };
        let mut a = st.adopt_begin(0, AdoptSource::Input(i), meta(7)).unwrap();
        loop {
            let r = st.adopt_step(&mut a, past()).unwrap();
            if let Step::Done(_) = r {
                break;
            }
            assert_eq!(st.slice_state(0), Some(SliceState::Adopting));
            if let Some(m) = st.lookup6(k6).and_then(|k4| st.bib6.lock(&k6).get(&k6).copied().filter(|m| m.k4 == k4)) {
                assert_eq!(st.pool.check_idx_in(true, m.idx), Err(DropReason::ClusterFenced));
            }
            assert!(st.pool.alloc_block(None, false).is_err(), "nothing allocates in an Adopting slice");
            // A new subscriber is not given a block of the slice either.
            let other = Key6 { proto: proto::UDP, addr: (SUB | (9 << 64)) | 1, port: 7 };
            assert!(st.bib_for(other, true, &c, &None).is_err());
        }
        assert_eq!(st.slice_state(0), Some(SliceState::Active));
        let m = st.bib6.lock(&k6).get(&k6).copied().unwrap();
        assert_eq!(st.pool.check_idx_in(true, m.idx), Ok(()));
        // AU-12: the acquire and every adopt record were queued before.
        assert_eq!(kinds(&rx), (1, 4, 0));
    }

    /// Abandoned before the log phase: nothing was logged, so no release
    /// record; the tables are empty again and the slice Inactive.
    #[test]
    fn abandon_before_log_emits_no_release() {
        let (st, rx, _) = state(1 << 16);
        let mut a = st.adopt_begin(0, AdoptSource::Input(input(10, 200)), meta(7)).unwrap();
        step_until_bibs(&st, &mut a, 500);
        assert!(st.subscriber_count() > 0);
        abandon_bounded(&st, &mut a, Some(BlockReleaseReason::Handover));
        assert_eq!(kinds(&rx), (0, 0, 0));
        assert_eq!((st.bib4.len(), st.bib6.len(), st.subscriber_count()), (0, 0, 0));
        assert_eq!(st.aggregate_count(SUB), 0);
        assert_eq!(st.slice_state(0), Some(SliceState::Inactive));
        assert_eq!(st.adopt_step(&mut a, past()), Err(AdoptError::Interrupted));
    }

    /// Abandoned with part of the adopt records queued: exactly those
    /// blocks get a release record (with the reason), the others none.
    #[test]
    fn abandon_after_partial_log_releases_logged_only() {
        let (st, rx, _) = state(1 << 16);
        let mut a = st.adopt_begin(0, AdoptSource::Input(input(126, 0)), meta(7)).unwrap();
        to_log(&st, &mut a);
        // Acquire plus 39 blocks, then stop.
        st.adopt_run(&mut a, &mut Budget::new(None, 40)).unwrap();
        assert_eq!(a.logged_n, 39);
        assert_eq!(kinds(&rx), (1, 39, 0));
        let rel = st.adopt_abandon_all(&mut a, Some(BlockReleaseReason::Handover));
        assert_eq!((rel.blocks_released, rel.subscribers_removed), (126, 126));
        let reasons: Vec<_> = rx
            .try_iter()
            .filter_map(|e| match e {
                Event::PortBlockRelease { port_lo: lo, reason, .. } => Some((lo, reason)),
                _ => None,
            })
            .collect();
        assert_eq!(reasons.len(), 39);
        assert!(reasons.iter().all(|&(lo, r)| lo < port_lo(39) && r == Some(BlockReleaseReason::Handover)));
        assert_eq!((st.subscriber_count(), st.slice_state(0)), (0, Some(SliceState::Inactive)));
    }

    fn shadow(st: &State) -> Shadow {
        let cfg = config(&[]);
        let n = &cfg.nat64;
        Shadow::new(st.slice_map().unwrap().clone(), n.port_min, n.port_max, n.port_block_size, 60_000, 1 << 20)
    }

    fn fill(sh: &Shadow, i: &AdoptInput) {
        sh.snapshot_begin(0).unwrap();
        let mut recs: Vec<SnapRecord> =
            i.blocks.iter().map(|&(sub, block, w)| SnapRecord::Block { sub, block, alloc_wall_us: w }).collect();
        recs.extend(i.bibs.iter().map(|b| SnapRecord::Bib(*b)));
        sh.snapshot_records(0, &recs).unwrap();
        sh.snapshot_end(0).unwrap();
    }

    /// An abandoned adoption from a detached shadow leaves nothing behind
    /// in the tables. By default the state goes back to the shadow (blocks,
    /// imported and unread BIBs, sync flag; charged to `max_bibs` again);
    /// after `discard_shadow` it is dropped and the charge returns to 0
    /// (SC-5).
    #[test]
    fn abandon_leaves_no_bibs_or_subscribers() {
        for discard in [false, true] {
            let (st, _rx, _) = state(1 << 16);
            let sh = shadow(&st);
            fill(&sh, &input(20, 100));
            let d = sh.detach(0, 0);
            assert_eq!(sh.counts(0), (0, 0));
            assert_eq!(sh.bibs_charged(), 2000, "charged until the cursor drops it");
            let mut a = st.adopt_begin(0, AdoptSource::Detached(d), meta(7)).unwrap();
            step_until_bibs(&st, &mut a, 1000);
            if discard {
                a.discard_shadow();
            }
            abandon_bounded(&st, &mut a, None);
            drop(a);
            assert_eq!((st.bib4.len(), st.bib6.len(), st.subscriber_count(), st.session_count()), (0, 0, 0, 0));
            assert_eq!(st.aggregate_count(SUB), 0);
            if discard {
                assert_eq!((sh.counts(0), sh.bibs_charged()), ((0, 0), 0));
            } else {
                assert_eq!((sh.counts(0), sh.bibs_charged()), ((20, 2000), 2000));
                assert!(sh.in_sync(0), "returned as it was detached");
            }
        }
    }

    /// SEC-001: abandoned in the stale phase while this node still holds a
    /// leftover BIB of the slice on the same `(proto, v4, port4)` as a
    /// replicated one: the leftover is removed, never returned to the
    /// shadow; the regain adopts and logs the replicated mapping.
    #[test]
    fn stale_leftover_never_reaches_the_shadow() {
        let (st, rx, _) = state(1 << 16);
        // A port whose `bib4` shard is not 0 (the hasher is random): the
        // one stale unit below walks shard 0 only, so the leftover is
        // always still ahead of the walk.
        let off = (0..512u16)
            .find(|&i| st.bib4_shard_of(Key4 { proto: proto::UDP, addr: ADDR, port: port_lo(0) + i }) != 0)
            .unwrap();
        let k4 = Key4 { proto: proto::UDP, addr: ADDR, port: port_lo(0) + off };
        let mut leftover = input(1, 1);
        leftover.bibs[0] = bib(SUB, 0, off, proto::UDP);
        st.adopt_slice(0, &leftover, meta(5)).unwrap();
        st.fence_slice(0);
        assert_eq!(st.lookup4(k4).map(|k| k.addr), Some(SUB | 1));
        let mut replicated = leftover.clone();
        replicated.bibs[0].v6 = SUB | 2;
        let sh = shadow(&st);
        fill(&sh, &replicated);
        let mut a = st.adopt_begin(0, AdoptSource::Detached(sh.detach(0, 0)), meta(7)).unwrap();
        // One unit of the stale walk: the leftover's shard is still ahead.
        st.adopt_run(&mut a, &mut Budget::new(None, 1)).unwrap();
        assert_eq!(a.phase, Phase::Stale);
        assert!(st.lookup4(k4).is_some(), "precondition: the leftover is still ahead of the stale walk");
        {
            st.adopt_abandon_all(&mut a, None);
            drop(a);
            assert_eq!(st.lookup4(k4), None, "leftover removed");
            assert_eq!(sh.counts(0), (1, 1));
            let _ = rx.try_iter().count();
            let mut a = st.adopt_begin(0, AdoptSource::Detached(sh.detach(0, 0)), meta(8)).unwrap();
            let (s, _) = step_all(&st, &mut a);
            assert_eq!((s.blocks_adopted, s.bibs_adopted), (1, 1));
            assert_eq!(st.lookup4(k4).map(|k| k.addr), Some(SUB | 2), "the replicated mapping, not the leftover");
            let acq = rx.try_iter().find_map(|e| match e {
                Event::ClusterSliceAcquire { acquire, .. } => Some((acquire.epoch, acquire.bibs_adopted)),
                _ => None,
            });
            assert_eq!(acq, Some((8, 1)), "logged");
        }
    }

    /// SEC-002 / PERF-003: a snapshot that began during the adoption is
    /// authoritative: the abandoned state is dropped (no merge), the slice
    /// keeps the snapshot's records and is marked not in sync; the charge
    /// counts only the snapshot. With no snapshot the state comes back in
    /// O(1) as detached (`abandon_leaves_no_bibs_or_subscribers`).
    #[test]
    fn restore_after_a_newer_snapshot_is_dropped() {
        let (st, _rx, _) = state(1 << 16);
        let sh = shadow(&st);
        fill(&sh, &input(20, 100));
        let mut a = st.adopt_begin(0, AdoptSource::Detached(sh.detach(0, 0)), meta(7)).unwrap();
        step_until_bibs(&st, &mut a, 500);
        fill(&sh, &input(3, 5));
        assert_eq!(sh.counts(0), (3, 15));
        st.adopt_abandon_all(&mut a, None);
        drop(a);
        assert_eq!(sh.counts(0), (3, 15), "the newer snapshot wins, nothing merged");
        assert!(!sh.in_sync(0));
        assert_eq!(sh.bibs_charged(), 15);
        // A snapshot begun and left empty still counts as newer.
        let (st, _rx, _) = state(1 << 16);
        let sh = shadow(&st);
        fill(&sh, &input(20, 100));
        let mut a = st.adopt_begin(0, AdoptSource::Detached(sh.detach(0, 0)), meta(7)).unwrap();
        st.adopt_step(&mut a, past()).unwrap();
        sh.snapshot_begin(0).unwrap();
        st.adopt_abandon_all(&mut a, None);
        drop(a);
        assert_eq!((sh.counts(0), sh.bibs_charged(), sh.in_sync(0)), ((0, 0), 0, false));
    }

    /// A completed adoption from the detached shadow releases the charge
    /// once the BIBs are imported, and matches the sorted input path.
    #[test]
    fn detach_counter_held_until_import_done() {
        let (st, rx, _) = state(1 << 16);
        let sh = shadow(&st);
        let i = input(30, 50);
        fill(&sh, &i);
        let mut a = st.adopt_begin(0, AdoptSource::Detached(sh.detach(0, 0)), meta(7)).unwrap();
        let (s, _) = step_all(&st, &mut a);
        assert_eq!((s.blocks_adopted, s.bibs_adopted, s.rejected), (30, 1500, 0));
        assert_eq!(sh.bibs_charged(), 0);
        assert_eq!(kinds(&rx), (1, 30, 0));
    }

    /// After an abandon the slice is Inactive, not Fenced: a regain
    /// adopts again from scratch instead of being taken as complete.
    #[test]
    fn regain_after_abandon_readopts() {
        let (st, rx, _) = state(1 << 16);
        let mut a = st.adopt_begin(0, AdoptSource::Input(input(5, 10)), meta(7)).unwrap();
        st.adopt_step(&mut a, past()).unwrap();
        st.adopt_abandon_all(&mut a, None);
        assert_eq!(st.slice_state(0), Some(SliceState::Inactive));
        let s = st.adopt_slice(0, &input(5, 10), meta(8)).unwrap();
        assert_eq!((s.blocks_adopted, s.bibs_adopted), (5, 50));
        assert_eq!(kinds(&rx), (1, 5, 0));
    }

    /// Re-granted with a newer epoch mid-log: everything is logged again
    /// with the new epoch; the same epoch resumes without duplicates.
    #[test]
    fn epoch_change_mid_adoption_relogs() {
        let (st, rx, _) = state(1 << 16);
        let mut a = st.adopt_begin(0, AdoptSource::Input(input(10, 0)), meta(7)).unwrap();
        to_log(&st, &mut a);
        st.adopt_run(&mut a, &mut Budget::new(None, 4)).unwrap();
        a.rebase(meta(7));
        st.adopt_run(&mut a, &mut Budget::new(None, 2)).unwrap();
        assert_eq!(kinds(&rx), (1, 5, 0), "same epoch: resumed");
        a.rebase(meta(9));
        step_all(&st, &mut a);
        let evs: Vec<_> = rx.try_iter().collect();
        assert_eq!(evs.len(), 11);
        assert!(matches!(&evs[0], Event::ClusterSliceAcquire { acquire, .. } if acquire.epoch == 9));
        assert!(evs[1..].iter().all(|e| matches!(e, Event::PortBlockAdopt { adopt, .. } if adopt.epoch == 9)));
    }

    /// Two BIBs of one IPv6 transport address: the first imported wins,
    /// the second is rejected; both count as validated (replaces `seen6`).
    #[test]
    fn duplicate_k6_first_wins() {
        let (st, rx, _) = state(1 << 16);
        let mut i = input(1, 1);
        let mut dup = i.bibs[0];
        dup.port4 += 1;
        i.bibs.push(dup);
        let s = st.adopt_slice(0, &i, meta(7)).unwrap();
        assert_eq!((s.bibs_adopted, s.rejected), (1, 1));
        let k6 = Key6 { proto: proto::UDP, addr: SUB | 1, port: port_lo(0) };
        assert_eq!(st.lookup6(k6).map(|k| k.port), Some(port_lo(0)));
        let acq = rx.try_iter().find_map(|e| match e {
            Event::ClusterSliceAcquire { acquire, .. } => Some(acquire),
            _ => None,
        });
        assert_eq!(acq.map(|x| x.bibs_adopted), Some(2), "validated count, as before");
    }

    /// The sweeper runs between steps, with far more simulated time than
    /// the 60 s block linger and the BIB pickup window: imported BIBs and
    /// lingering adopted blocks of the Adopting slice survive it, and no
    /// release precedes an adopt record (AU-12).
    #[test]
    fn sweeper_during_adoption_keeps_imported() {
        let (st, rx, clock) = state(1 << 16);
        let mut a = st.adopt_begin(0, AdoptSource::Input(input(20, 100)), meta(7)).unwrap();
        let mut sweeps = 0;
        loop {
            if let Step::Done(s) = st.adopt_step(&mut a, past()).unwrap() {
                assert_eq!(s.bibs_adopted, 2000);
                break;
            }
            clock.advance(Duration::from_secs(30));
            st.sweep();
            sweeps += 1;
        }
        assert!(sweeps * 30 > 600, "{sweeps} sweeps: past the linger and the UDP timeout");
        assert_eq!((st.bib4.len(), st.subscriber_count()), (2000, 20));
        assert_eq!(kinds(&rx), (1, 20, 0), "no release record");
    }

    /// NIST-004: a refused one-shot adoption keeps its cursor; the retry
    /// queues every record exactly once.
    #[test]
    fn refused_then_retried_adoption_logs_each_record_once() {
        let (st, rx, _) = state(64);
        for _ in 0..62 {
            assert!(st.audit.emit(foreign()));
        }
        assert_eq!(st.adopt_slice(0, &input(3, 2), meta(7)), Err(AdoptError::AuditUnavailable));
        assert_eq!(st.slice_state(0), Some(SliceState::Adopting));
        assert_eq!(rx.try_iter().count(), 62, "nothing of the adoption queued");
        let s = st.adopt_slice(0, &input(3, 2), meta(7)).unwrap();
        assert_eq!((s.blocks_adopted, s.bibs_adopted), (3, 6));
        assert_eq!(kinds(&rx), (1, 3, 0));
        assert!(st.cluster.as_ref().unwrap().adopt_stash.lock().is_empty(), "cursor dropped on success");
    }

    fn foreign() -> Event {
        Event::ClusterSliceAcquire {
            ts_us: 0,
            acquire: Arc::new(SliceAcquire {
                slice: SliceCidr { net: 0, len: 32 },
                epoch: 0,
                prev_owner: None,
                reason: AcquireReason::Startup,
                blocks_adopted: 0,
                bibs_adopted: 0,
                blocks_quarantined: 0,
                in_sync: true,
            }),
        }
    }

    /// AU-5: under `refuse_new_bindings` a queue that fills between steps
    /// pauses the log phase; room freed over several steps completes it,
    /// every record once, Active only after the last.
    #[test]
    fn chunked_log_resumes_as_queue_room_frees() {
        let (st, rx, _) = state(64);
        let mut a = st.adopt_begin(0, AdoptSource::Input(input(20, 3)), meta(7)).unwrap();
        to_log(&st, &mut a);
        // Acquire and 4 blocks, then other records fill the queue.
        st.adopt_run(&mut a, &mut Budget::new(None, 5)).unwrap();
        let mut seen: Vec<Event> = rx.try_iter().collect();
        while st.audit.emit(foreign()) && rx.len() < 64 {}
        let mut refused = 0;
        loop {
            match st.adopt_step(&mut a, past()) {
                Ok(Step::Done(_)) => break,
                Ok(Step::More) => {}
                Err(AdoptError::AuditUnavailable) => {
                    refused += 1;
                    assert_eq!(st.slice_state(0), Some(SliceState::Adopting));
                    assert!(refused < 100, "no progress");
                    // The logger drains a few records between steps.
                    seen.extend(rx.try_iter().take(3));
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        seen.extend(rx.try_iter());
        assert!(refused >= 5, "{refused} refusals");
        let acq = seen.iter().filter(|e| matches!(e, Event::ClusterSliceAcquire { acquire, .. } if acquire.epoch == 7));
        let mut lo: Vec<u16> = seen
            .iter()
            .filter_map(|e| match e {
                Event::PortBlockAdopt { adopt, .. } => Some(adopt.port_lo),
                _ => None,
            })
            .collect();
        let n = lo.len();
        lo.sort_unstable();
        lo.dedup();
        assert_eq!((acq.count(), n, lo.len()), (1, 20, 20), "every record exactly once");
        assert_eq!(st.slice_state(0), Some(SliceState::Active));
    }
    /// Plan §8 boundary (QA): the `hold_unknown` walk spans many one-item
    /// steps and gives the same held set, stats and records as one shot.
    #[test]
    fn hold_unknown_walk_spanning_steps_matches_single_shot() {
        let mut i = input(10, 3);
        (i.in_sync, i.hold_unknown) = (false, true);
        let (one, rx1, _) = state(1 << 16);
        let s1 = one.adopt_slice(0, &i, meta(7)).unwrap();
        assert_eq!((s1.blocks_adopted, s1.blocks_held), (10, 116));
        let (two, rx2, _) = state(1 << 16);
        let mut a = two.adopt_begin(0, AdoptSource::Input(i), meta(7)).unwrap();
        let mut steps = 0;
        let s2 = loop {
            steps += 1;
            if let Step::Done(s) = two.adopt_run(&mut a, &mut Budget::new(None, 1)).unwrap() {
                break s;
            }
        };
        assert!(steps > 116, "{steps} steps");
        assert_eq!(s1, s2);
        assert_eq!(kinds(&rx1), kinds(&rx2));
        assert_eq!((one.pool.free_blocks(), two.pool.free_blocks()), (0, 0), "every unknown block held");
    }

    /// Plan §8 boundary (QA): `max_subscribers` reached mid-import: the
    /// blocks of subscribers over the limit are held back, not adopted or
    /// logged, whether stepped or one shot (SC-5).
    #[test]
    fn max_subscribers_mid_import_holds_the_rest() {
        let cfg = config(&[("max_subscribers = 1000000", "max_subscribers = 4")]);
        let i = input(10, 2);
        let (one, rx1, _) = state_with(&cfg, 1 << 16);
        let s1 = one.adopt_slice(0, &i, meta(7)).unwrap();
        let (two, rx2, _) = state_with(&cfg, 1 << 16);
        let mut a = two.adopt_begin(0, AdoptSource::Input(i), meta(7)).unwrap();
        let (s2, _) = step_all(&two, &mut a);
        assert_eq!(s1, s2);
        assert_eq!((s2.blocks_adopted, s2.bibs_adopted), (4, 8));
        assert!(s2.blocks_held >= 6, "{s2:?}");
        assert_eq!(two.subscriber_count(), 4);
        assert_eq!(kinds(&rx1), (1, 4, 0));
        assert_eq!(kinds(&rx2), (1, 4, 0));
    }
}
