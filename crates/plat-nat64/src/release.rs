//! Chunked Active-slice release (POAM-048): [`State::release_slice`] as a
//! resumable cursor ([`Release`]) that the `plat-cluster-ctl` thread
//! advances one time-budgeted [`State::release_step`] at a time, between
//! its heartbeats and lease renewals, like an [`super::Adoption`].
//!
//! Phases, in order:
//!
//! 1. fence ([`State::release_begin`], O(1)): Active → Fenced (the mirror
//!    is fenced with it) and the slice marked releasing;
//! 2. bibs: `bib4` shard by shard, the in-slice keys of one shard are
//!    snapshotted under one hold, then removed one by one across steps
//!    (`bib6 → bib4` per key, with sessions, held SYNs and BIB delete
//!    records in session mode);
//! 3. blocks: `subs` shard by shard, one `nat_port_block_release` per
//!    block (`plat.release_reason`), emptied subscribers dropped;
//! 4. reset: the slice's blocks return to the pool, after every release
//!    record of the slice was queued, and the slice goes Inactive.
//!
//! A Fenced slice allocates nothing, so the set of its BIBs and blocks only
//! shrinks while it is released (the sweeper may expire some meanwhile;
//! each block leaves its subscriber once, under the `subs` shard lock, and
//! so gets exactly one release record).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CP-10, SC-5(2) - the control thread keeps its lease
//!   duties during a large release: each step is aimed at 5 ms
//!   ([`RELEASE_STEP_BUDGET`]) and capped by item count; measured tail up
//!   to 47 ms (macOS host, single frees), heartbeat gap <= 112.5 ms; Linux
//!   profile pending (POAM-048 closed)
//! - NIST 800-53: SC-5 - per-step work bounded ([`RELEASE_STEP_BUDGET`],
//!   clock read every [`super::ADOPT_BATCH`] items, at most
//!   [`super::ADOPT_STEP_MAX_ITEMS`]); cursor memory bounded by one
//!   `bib4` shard's keys
//! - NIST 800-53: SC-24 - fenced before the first step; a releasing slice
//!   is never set Active or adopted; a finished release leaves it Inactive,
//!   so a regain goes through adoption
//! - NIST 800-53: AU-12, AU-10, AU-5 - every block of the slice gets one
//!   release record before the slice's blocks return to the pool; under
//!   `refuse_new_bindings` a full queue pauses the cursor (the refused
//!   record kept and queued exactly once by a later step), a stopped
//!   logger counts the record lost; other policies `emit` as before

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use plat_audit::BlockReleaseReason;
use plat_cluster::SliceId;

use super::{ADOPT_STEP_BUDGET, ADOPT_STEP_MAX_ITEMS, Budget, Emit, ReleaseStats, State, Walk};
use crate::pool::SliceState;

/// Wall time one [`State::release_step`] aims for (the adoption budget).
pub const RELEASE_STEP_BUDGET: Duration = ADOPT_STEP_BUDGET;

/// Result of one [`State::release_step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStep {
    /// Budget used up; call again.
    More,
    /// `refuse_new_bindings` and the audit queue is full: call again once
    /// it has room (the refused record is kept in the cursor).
    Paused,
    /// Every record queued, the blocks back in the pool, the slice
    /// Inactive.
    Done(ReleaseStats),
}

/// An Active-slice release in progress (see the module docs). Created by
/// [`State::release_begin`], advanced by [`State::release_step`] or
/// [`State::release_all`]. Owned by one thread (the control thread); holds
/// no lock between steps. Never cancelled: part of its records are queued.
#[derive(Debug)]
pub struct Release {
    slice: SliceId,
    reason: Option<BlockReleaseReason>,
    walk: Walk,
    stats: ReleaseStats,
    done: bool,
}

impl Release {
    pub fn slice(&self) -> SliceId {
        self.slice
    }

    pub fn reason(&self) -> Option<BlockReleaseReason> {
        self.reason
    }

    /// Current phase, for status and logs: "bibs", "blocks" or "done".
    pub fn phase(&self, st: &State) -> &'static str {
        if self.done {
            "done"
        } else if self.walk.in_bibs(st.bib4.shard_count()) {
            "bibs"
        } else {
            "blocks"
        }
    }

    /// What was removed so far.
    pub fn stats(&self) -> ReleaseStats {
        self.stats
    }

    /// Changes `plat.release_reason` of the records still to be built
    /// (a handover joining a cursor started for another reason, SEC-002).
    /// Records already queued keep theirs, and so does a record a full
    /// queue refused (it is kept as built): one slice's records may carry
    /// two reasons, the earlier ones the first.
    pub fn set_reason(&mut self, reason: Option<BlockReleaseReason>) {
        self.reason = reason;
    }
}

impl State {
    /// Starts giving up slice `s` (O(1)): an Active slice is fenced, the
    /// slice is marked releasing, and the returned cursor removes its
    /// state. `None` on a legacy engine, a bad slice id, a slice being
    /// adopted (use [`State::adopt_abandon`]) or one already releasing.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-24 - the slice translates and allocates nothing
    ///   from here on
    pub fn release_begin(&self, s: SliceId, reason: Option<BlockReleaseReason>) -> Option<Release> {
        let c = self.cluster.as_ref()?;
        let flag = c.releasing.get(s as usize)?;
        match self.pool.slice_state(s)? {
            SliceState::Adopting => return None,
            SliceState::Active => {
                self.pool.set_slice_state(s, SliceState::Fenced);
            }
            SliceState::Fenced | SliceState::Inactive => {}
        }
        if flag.swap(true, Ordering::AcqRel) {
            return None;
        }
        // The next owner decides its own pickup mode (adoption Activate).
        self.set_strict_tcp(s, false);
        let mut walk = Walk::default();
        walk.pause_on_full = self.refuse_on_overflow;
        Some(Release { slice: s, reason, walk, stats: ReleaseStats::default(), done: false })
    }

    /// Advances `r` until `deadline` (read every [`super::ADOPT_BATCH`]
    /// items) or [`super::ADOPT_STEP_MAX_ITEMS`] items.
    pub fn release_step(&self, r: &mut Release, deadline: Instant) -> ReleaseStep {
        self.release_run(r, &mut Budget::new(Some(deadline), ADOPT_STEP_MAX_ITEMS))
    }

    /// [`State::release_step`] to completion without a deadline (shutdown,
    /// tests, the one-shot wrapper). Never waits on the audit queue: a
    /// record refused earlier and every later one is emitted (lost and
    /// counted when the queue is full).
    pub fn release_all(&self, r: &mut Release) -> ReleaseStats {
        r.walk.pause_on_full = false;
        r.walk.paused = false;
        if let Some(ev) = r.walk.pending.take() {
            self.audit.emit(ev);
        }
        loop {
            match self.release_run(r, &mut Budget::unbounded()) {
                ReleaseStep::Done(s) => return s,
                ReleaseStep::More | ReleaseStep::Paused => {}
            }
        }
    }

    /// A [`Release`] of slice `s` is in progress (control plane only).
    pub fn slice_releasing(&self, s: SliceId) -> bool {
        self.cluster.as_ref().and_then(|c| c.releasing.get(s as usize)).is_some_and(|f| f.load(Ordering::Acquire))
    }

    fn release_run(&self, r: &mut Release, b: &mut Budget) -> ReleaseStep {
        if r.done {
            return ReleaseStep::Done(r.stats);
        }
        // The record a full queue refused goes first (exactly once).
        if let Some(ev) = r.walk.pending.take() {
            let mut back = None;
            if !self.walk_emit(r.walk.pause_on_full, &mut back, ev) {
                r.walk.pending = back;
                return ReleaseStep::Paused;
            }
        }
        r.walk.paused = false;
        if !self.walk_slice(r.slice, &mut r.walk, b, &Emit::All, r.reason, &mut r.stats) {
            return if r.walk.paused { ReleaseStep::Paused } else { ReleaseStep::More };
        }
        // Every release record of the slice is queued: only now do its
        // blocks return to the pool (attribution first, rule 4).
        self.pool.reset_slice(r.slice, &[], &[], &[]);
        if self.pool.slice_state(r.slice) != Some(SliceState::Active) {
            self.pool.set_slice_state(r.slice, SliceState::Inactive);
        }
        if let Some(f) = self.cluster.as_ref().and_then(|c| c.releasing.get(r.slice as usize)) {
            f.store(false, Ordering::Release);
        }
        r.done = true;
        r.walk = Walk::default();
        ReleaseStep::Done(r.stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::{AdoptInput, Directory};
    use crate::state::{AdoptError, AdoptMeta, AdoptSource, ClusterSetup};
    use plat_audit::{AcquireReason, AuditSink, Event};
    use plat_cluster::{SliceMap, WireBib, WireBlock};
    use plat_common::config::SteeringMode;
    use plat_common::{Clock, Config};
    use plat_packet::proto;
    use std::sync::Arc;

    const SUB: u128 = 0x2001_0db8_0000_0001_u128 << 64;
    /// The first pool address (slice 0 of a /30 split into /32 slices).
    const ADDR: u32 = 0xc000_0200;
    /// Bound of the stepping loops: a regression fails instead of hanging.
    const STEP_LIMIT: usize = 1 << 20;

    fn config(extra: &[(&str, &str)]) -> Config {
        let mut t = include_str!("../../../config/platd.example.toml")
            .replace("192.0.2.0/24", "192.0.2.0/30")
            .replace("allow_non_global_destinations = false", "allow_non_global_destinations = true");
        for (a, b) in extra {
            t = t.replace(a, b);
        }
        Config::from_toml(&t).unwrap()
    }

    fn state_with(cfg: &Config, queue: usize) -> (State, crossbeam_channel::Receiver<Event>) {
        let setup = ClusterSetup {
            slices: SliceMap::new(&cfg.nat64.pool, 32).unwrap(),
            self_id: 1,
            steering: SteeringMode::Drop,
            directory: Arc::new(Directory::new(16, 1000)),
            tcp_adopt_secs: 300,
            session_hints: false,
            udp_hints: None,
            quarantine_secs: 600,
            reserve_ahead: 2,
        };
        let (sink, rx) = AuditSink::bounded(queue);
        (State::new_cluster(cfg, setup, sink, Clock::new()).unwrap(), rx)
    }

    fn meta() -> AdoptMeta {
        AdoptMeta { epoch: 7, prev_owner: Some(2), reason: AcquireReason::Takeover }
    }

    /// `blocks` blocks of one subscriber each, `per` UDP BIBs per block.
    fn input(blocks: u16, per: u16) -> AdoptInput {
        let sub = |b: u16| SUB | (u128::from(b) << 80);
        let bib = |b: u16, i: u16| {
            let port = 1024 + b * 512 + i;
            WireBib {
                sub: sub(b),
                proto: proto::UDP,
                v6: sub(b) | 1,
                port6: port,
                v4: ADDR,
                port4: port,
                created_wall_us: 1,
            }
        };
        AdoptInput {
            blocks: (0..blocks).map(|b| (sub(b), WireBlock { addr: ADDR, block: b }, 1)).collect(),
            bibs: (0..blocks).flat_map(|b| (0..per).map(move |i| bib(b, i))).collect(),
            in_sync: true,
            ..AdoptInput::default()
        }
    }

    /// Slice 0 Active with `blocks` × `per` state; the audit queue drained.
    fn loaded(cfg: &Config, queue: usize, blocks: u16, per: u16) -> (State, crossbeam_channel::Receiver<Event>) {
        let (st, rx) = state_with(cfg, queue);
        st.adopt_slice(0, &input(blocks, per), meta()).unwrap();
        rx.try_iter().for_each(drop);
        (st, rx)
    }

    /// Fills the queue until `room` slots are left.
    fn fill(st: &State, room: usize) {
        while st.audit.capacity() - st.audit.queued() > room {
            st.audit.emit(Event::ClusterSliceAcquire {
                ts_us: 0,
                acquire: Arc::new(plat_audit::SliceAcquire {
                    slice: plat_audit::SliceCidr { net: 0, len: 32 },
                    epoch: 0,
                    prev_owner: None,
                    reason: AcquireReason::Startup,
                    blocks_adopted: 0,
                    bibs_adopted: 0,
                    blocks_quarantined: 0,
                    in_sync: true,
                }),
            });
        }
    }

    fn past() -> Instant {
        Instant::now().checked_sub(Duration::from_secs(1)).unwrap_or_else(Instant::now)
    }

    fn releases(rx: &crossbeam_channel::Receiver<Event>) -> Vec<(u32, u16)> {
        let mut v: Vec<_> = rx
            .try_iter()
            .filter_map(|e| match e {
                Event::PortBlockRelease { v4, port_lo, .. } => Some((v4, port_lo)),
                _ => None,
            })
            .collect();
        v.sort_unstable();
        v
    }

    /// Stepping with expired deadlines gives the same stats, records and
    /// final tables as the one-shot wrapper.
    #[test]
    fn release_steps_match_single_shot() {
        let cfg = config(&[]);
        for (blocks, per) in [(0, 0), (1, 0), (3, 5), (100, 40)] {
            let (one, rx1) = loaded(&cfg, 1 << 16, blocks, per);
            let s1 = one.release_slice(0, Some(BlockReleaseReason::Handover));
            let (two, rx2) = loaded(&cfg, 1 << 16, blocks, per);
            let mut r = two.release_begin(0, Some(BlockReleaseReason::Handover)).unwrap();
            let mut steps = 0;
            let s2 = loop {
                steps += 1;
                assert!(steps < STEP_LIMIT);
                if let ReleaseStep::Done(s) = two.release_step(&mut r, past()) {
                    break s;
                }
            };
            assert_eq!(s1, s2);
            assert_eq!(s2.blocks_released, u64::from(blocks));
            assert_eq!(s2.bibs_removed, u64::from(blocks) * u64::from(per));
            assert_eq!(releases(&rx1), releases(&rx2));
            assert_eq!((one.bib4.len(), one.bib6.len()), (two.bib4.len(), two.bib6.len()));
            assert_eq!(two.bib4.len(), 0);
            assert_eq!(one.subscriber_count(), two.subscriber_count());
            assert_eq!(one.pool.free_blocks(), two.pool.free_blocks());
            assert_eq!(two.slice_state(0), Some(SliceState::Inactive));
            assert!(!two.slice_releasing(0));
            if per > 10 {
                assert!(steps > 2, "{steps} steps for {blocks} x {per}");
            }
        }
    }

    /// With one shard, a step removes about a batch, not the whole shard.
    #[test]
    fn release_step_respects_deadline() {
        let cfg = config(&[("table_shards = 1024", "table_shards = 1")]);
        let (st, _rx) = loaded(&cfg, 1 << 16, 100, 100);
        let mut r = st.release_begin(0, None).unwrap();
        let mut last = 0;
        let mut steps = 0;
        while !matches!(st.release_step(&mut r, past()), ReleaseStep::Done(_)) {
            let now = r.stats().bibs_removed;
            assert!(now - last <= (crate::ADOPT_BATCH as u64) * 2, "{} in one step", now - last);
            last = now;
            steps += 1;
            assert!(steps < STEP_LIMIT);
        }
        assert!(steps >= 10_000 / crate::ADOPT_BATCH, "{steps} steps");
    }

    /// Mid-release the slice is Fenced, refuses adoption and activation,
    /// and its blocks stay out of the pool until the last step.
    #[test]
    fn releasing_slice_is_never_active_or_adopted() {
        let cfg = config(&[("table_shards = 1024", "table_shards = 1")]);
        let (st, _rx) = loaded(&cfg, 1 << 16, 20, 200);
        let free = st.pool.slice_free(0);
        let mut r = st.release_begin(0, None).unwrap();
        assert_eq!(st.slice_state(0), Some(SliceState::Fenced));
        assert!(st.release_begin(0, None).is_none(), "one cursor per slice");
        assert_eq!(st.release_step(&mut r, past()), ReleaseStep::More);
        assert!(st.slice_releasing(0));
        assert_eq!(r.phase(&st), "bibs");
        assert_eq!(
            st.adopt_begin(0, AdoptSource::Input(AdoptInput::default()), meta()).err(),
            Some(AdoptError::Releasing)
        );
        assert_eq!(st.pool.slice_free(0), free);
        let done = st.release_all(&mut r);
        assert_eq!(done.blocks_released, 20);
        assert_eq!(r.phase(&st), "done");
        assert!(st.pool.slice_free(0) > free);
        assert_eq!(st.slice_state(0), Some(SliceState::Inactive));
        st.set_slice_state(0, SliceState::Active);
        assert_eq!(st.slice_state(0), Some(SliceState::Active));
    }

    /// Under `refuse_new_bindings` a full queue pauses the cursor; each
    /// record is queued exactly once, none lost, and the blocks return to
    /// the pool only after the last one.
    #[test]
    fn release_pauses_on_full_queue_and_resumes_exactly_once() {
        let cfg = config(&[]);
        assert_eq!(cfg.audit.on_overflow, plat_common::config::OverflowPolicy::RefuseNewBindings);
        let (st, rx) = loaded(&cfg, 64, 30, 0);
        fill(&st, 4);
        let free = st.pool.slice_free(0);
        let mut r = st.release_begin(0, Some(BlockReleaseReason::Handover)).unwrap();
        let mut got = Vec::new();
        let mut paused = 0;
        for _ in 0..STEP_LIMIT {
            match st.release_step(&mut r, past()) {
                ReleaseStep::Done(_) => break,
                ReleaseStep::Paused => {
                    paused += 1;
                    assert_eq!(st.pool.slice_free(0), free, "pool reset before every record");
                    got.extend(releases(&rx));
                }
                ReleaseStep::More => {}
            }
        }
        got.extend(releases(&rx));
        got.sort_unstable();
        let want: Vec<_> = (0..30).map(|b| (ADDR, 1024 + b * 512)).collect();
        assert_eq!(got, want);
        assert!(paused >= 1, "{paused}");
        assert_eq!(st.audit.stats().lost.load(Ordering::Relaxed), 0);
        assert!(st.pool.slice_free(0) > free);
    }

    /// Other policies keep `emit`: a full queue loses (and counts)
    /// records, the release never pauses.
    #[test]
    fn drop_and_alert_release_never_pauses() {
        let cfg = config(&[("on_overflow = \"refuse_new_bindings\"", "on_overflow = \"drop_and_alert\"")]);
        let (st, rx) = loaded(&cfg, 64, 30, 0);
        fill(&st, 4);
        let mut r = st.release_begin(0, None).unwrap();
        for _ in 0..STEP_LIMIT {
            match st.release_step(&mut r, past()) {
                ReleaseStep::Done(s) => {
                    assert_eq!(s.blocks_released, 30);
                    break;
                }
                ReleaseStep::Paused => panic!("paused"),
                ReleaseStep::More => {}
            }
        }
        assert_eq!(releases(&rx).len(), 4);
        assert!(st.audit.stats().lost.load(Ordering::Relaxed) >= 26);
    }

    /// The logger stopped: records are counted lost, the release goes on.
    #[test]
    fn disconnected_sink_counts_lost_and_continues() {
        let cfg = config(&[]);
        let (st, rx) = loaded(&cfg, 64, 10, 0);
        drop(rx);
        let mut r = st.release_begin(0, None).unwrap();
        let mut n = 0;
        while !matches!(st.release_step(&mut r, past()), ReleaseStep::Done(_)) {
            n += 1;
            assert!(n < STEP_LIMIT);
        }
        assert_eq!(st.audit.stats().lost.load(Ordering::Relaxed), 10);
    }

    /// The sweeper running between steps leaves one record per block.
    #[test]
    fn sweeper_during_release_records_each_block_once() {
        let cfg = config(&[("table_shards = 1024", "table_shards = 1")]);
        let (st, rx) = loaded(&cfg, 1 << 16, 40, 50);
        let mut r = st.release_begin(0, None).unwrap();
        for _ in 0..STEP_LIMIT {
            st.sweep();
            if let ReleaseStep::Done(_) = st.release_step(&mut r, past()) {
                break;
            }
        }
        let got = releases(&rx);
        let mut uniq = got.clone();
        uniq.dedup();
        assert_eq!(got, uniq, "a block released twice");
        assert_eq!(st.bib4.len(), 0);
        assert_eq!(st.subscriber_count(), 0);
    }

    /// Session mode: BIB delete records also pause and resume exactly once.
    #[test]
    fn session_mode_bib_deletes_resume_exactly_once() {
        let cfg = config(&[("mode = \"port_block\"", "mode = \"session\"")]);
        assert_eq!(cfg.audit.mode, plat_common::config::AuditMode::Session);
        let (st, rx) = loaded(&cfg, 128, 3, 20);
        fill(&st, 8);
        let mut r = st.release_begin(0, None).unwrap();
        let mut deletes = 0;
        for _ in 0..STEP_LIMIT {
            let step = st.release_step(&mut r, past());
            deletes += rx.try_iter().filter(|e| matches!(e, Event::BibDelete { .. })).count();
            if let ReleaseStep::Done(_) = step {
                break;
            }
        }
        assert_eq!(deletes, 60);
        assert_eq!(st.audit.stats().lost.load(Ordering::Relaxed), 0);
    }

    /// QA (rule 4, AU-12/AU-5): under `refuse_new_bindings` with a slow
    /// logger (one slot per step) no block of the slice is back in the pool
    /// after any step before Done, and at the step that returns Done every
    /// release record of the slice is already queued.
    #[test]
    fn qa_pool_untouched_until_every_release_record_is_queued() {
        let cfg = config(&[]);
        let (st, rx) = loaded(&cfg, 64, 40, 3);
        fill(&st, 0);
        let free = st.pool.slice_free(0);
        let mut r = st.release_begin(0, Some(BlockReleaseReason::Handover)).unwrap();
        let mut got = 0usize;
        let mut count = |rx: &crossbeam_channel::Receiver<Event>, n: usize| {
            for e in rx.try_iter().take(n) {
                if matches!(e, Event::PortBlockRelease { .. }) {
                    got += 1;
                }
            }
        };
        for _ in 0..STEP_LIMIT {
            count(&rx, 1);
            match st.release_step(&mut r, past()) {
                ReleaseStep::Done(s) => {
                    assert_eq!(s.blocks_released, 40);
                    break;
                }
                ReleaseStep::More | ReleaseStep::Paused => {
                    assert_eq!(st.pool.slice_free(0), free, "a block returned before its record was queued");
                    assert_eq!(st.slice_state(0), Some(SliceState::Fenced));
                }
            }
        }
        count(&rx, usize::MAX);
        assert_eq!(got, 40, "every release record queued once");
        assert_eq!(st.audit.stats().lost.load(Ordering::Relaxed), 0);
        assert!(st.pool.slice_free(0) > free);
    }

    /// PERF-001: with one `subs` shard a step stops inside the shard (the
    /// budget is checked per subscriber), and the rescan of the shard by
    /// the next steps releases each block once.
    #[test]
    fn blocks_phase_stops_inside_a_shard() {
        let cfg = config(&[("table_shards = 1024", "table_shards = 1")]);
        let (st, rx) = loaded(&cfg, 1 << 16, 100, 0);
        let mut r = st.release_begin(0, None).unwrap();
        let mut steps = 0;
        let mut first = None;
        while !matches!(st.release_step(&mut r, past()), ReleaseStep::Done(_)) {
            first.get_or_insert(r.stats().blocks_released);
            steps += 1;
            assert!(steps < STEP_LIMIT);
        }
        let first = first.unwrap_or(100);
        assert!(first > 0 && first < 100, "{first} blocks in the first step");
        let got = releases(&rx);
        let want: Vec<_> = (0..100).map(|b| (ADDR, 1024 + b * 512)).collect();
        assert_eq!(got, want);
        assert_eq!(st.subscriber_count(), 0);
    }

    /// SEC-002: a handover joining a cursor started without a reason
    /// switches the records still to be built; the earlier ones keep none.
    #[test]
    fn set_reason_applies_to_the_remaining_records() {
        let cfg = config(&[("table_shards = 1024", "table_shards = 1")]);
        let (st, rx) = loaded(&cfg, 1 << 16, 100, 0);
        let mut r = st.release_begin(0, None).unwrap();
        assert_eq!(st.release_step(&mut r, past()), ReleaseStep::More);
        r.set_reason(Some(BlockReleaseReason::Handover));
        assert_eq!(r.reason(), Some(BlockReleaseReason::Handover));
        st.release_all(&mut r);
        let reasons: Vec<_> = rx
            .try_iter()
            .filter_map(|e| match e {
                Event::PortBlockRelease { reason, .. } => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(reasons.len(), 100);
        let k = reasons.iter().position(Option::is_some).unwrap_or(reasons.len());
        assert!(k > 0 && k < 100, "{k} records before the switch");
        assert!(reasons[..k].iter().all(Option::is_none));
        assert!(reasons[k..].iter().all(|x| *x == Some(BlockReleaseReason::Handover)));
    }

    /// NIST-003: setting a releasing slice Active is refused with `Err`
    /// (nothing changed); other states and a finished release are not.
    #[test]
    fn try_set_active_refused_while_releasing() {
        let cfg = config(&[("table_shards = 1024", "table_shards = 1")]);
        let (st, _rx) = loaded(&cfg, 1 << 16, 20, 50);
        let mut r = st.release_begin(0, None).unwrap();
        assert_eq!(st.release_step(&mut r, past()), ReleaseStep::More);
        assert_eq!(st.try_set_slice_state(0, SliceState::Active), Err(crate::SliceReleasing(0)));
        assert_eq!(st.slice_state(0), Some(SliceState::Fenced));
        assert_eq!(st.try_set_slice_state(0, SliceState::Fenced), Ok(Some(SliceState::Fenced)));
        st.release_all(&mut r);
        assert_eq!(st.try_set_slice_state(0, SliceState::Active), Ok(Some(SliceState::Inactive)));
        assert_eq!(st.slice_state(0), Some(SliceState::Active));
    }
}
