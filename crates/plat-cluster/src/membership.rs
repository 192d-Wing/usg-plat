//! Membership, leases and slice ownership: a sans-IO state machine.
//!
//! The driver (platd's `plat-cluster-ctl` thread, or the simulation) feeds
//! monotonic milliseconds and peer messages in and executes the returned
//! [`Action`]s in order. [`Action::Persist`] must be durable (fsync) before
//! any later action of the same batch is executed. Nothing here reads a
//! clock, does I/O or uses randomness beyond the configured seed, so a run
//! is fully reproducible.
//!
//! # Protocol
//!
//! Leader election is the election half of Raft: terms (the high half of
//! the epoch) and votes are persisted, a pre-vote round keeps partitioned
//! nodes from inflating the term, and there is no log. The leader's only
//! output is the [`View`]. A view is proposed with `ViewPropose`, members
//! adopt it at once (dropping slices they lose) and ack; the leader then
//! marks it committed in its heartbeats. Members gain slices only under a
//! committed view.
//!
//! Leases are round-trip anchored so that only clock *rate* matters, never
//! the offset between nodes:
//! - the leader sends `Heartbeat{seq: n}` to each voter, resending the same
//!   `n` until the voter acks it, and only moves to `n + 1` after the ack;
//! - a member that receives `n + 1` knows the leader saw its ack of `n`, so
//!   it extends its lease to `t_ack(n) + fence` (its own clock);
//! - the leader holds the leadership lease while a majority acked a
//!   heartbeat it first sent within `fence` (its own clock), and grants
//!   (advances `n`) only while it holds it;
//! - a voter that acked a leader does not (pre-)vote for anyone for `safe`
//!   after that ack.
//!
//! With `fence = lease * (1 - m)` and `safe = lease * (1 + m) + 200 ms`,
//! where `m` is `drift_margin_pct`, a node whose lease ran out has stopped
//! serving before anyone may start, as long as no clock runs more than `m`
//! fast or slow. Gaining a slice whose previous owner is still live waits
//! `safe` after adoption (or less, on that owner's `HandoverFence`);
//! gaining from a member the leader dropped (silent for `safe`) does not
//! wait.
//!
//! # Election timing
//!
//! Only *when* a node asks for votes is tuned for a short takeover; whether
//! a vote, a lease or a slice is granted is decided by the rules above and
//! by nothing in this section:
//! - a follower campaigns `safe + j` after its last leader contact, with
//!   `j < heartbeat / 2`;
//! - a pre-candidate does not time out: it asks again every `heartbeat / 5`
//!   (with an empty grant set) until a majority grants, a leader shows up or
//!   it grants a real vote. A voter that still keeps a lease promise simply
//!   refuses until the promise has run out;
//! - a candidate round lasts `heartbeat / 2`. A round without a majority
//!   (split vote, slow voter) ends in a new campaign at the next tick; the
//!   round length doubles per consecutive timed-out round, capped at `safe`,
//!   so voters that persist slowly cannot keep every round too short;
//! - a candidate that sees a real vote request for its own term from a
//!   lower-id data member yields to it and stays quiet for four rounds;
//! - the new leader sends the next heartbeat at once when a voter's first
//!   ack of the term arrives and when a view commits, so a follower's lease
//!   follows the election by round trips, not by heartbeat periods.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-24 (Fail in Known State) - a minority or lease-less
//!   node fences its slices; CP-10 (System Recovery and Reconstitution) -
//!   takeover of a lost member's slices by their backups; the time from a
//!   leader crash to full service is asserted for simulated schedules only
//!   (`tests/sim.rs`, `leader_crash_bound_holds_across_topologies`); SI-4 - election round
//!   and expedited-heartbeat counters ([`ElectionStats`]); AU-12 - every
//!   acquire and release is an action the driver audits; SC-5 - all state is
//!   bounded by the voter count (at most 64) and the slice count (at most
//!   4096)

use crate::codec::Msg;
use crate::mix;
use crate::slices::{MAX_SLICES, MAX_WEIGHT, MemberId, SliceId};
use crate::view::{MAX_MEMBERS, View, make_epoch, term_of};

/// Fixed part of the takeover margin (scheduling and tick granularity).
pub const FIXED_MARGIN_MS: u64 = 200;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    #[error("no data members")]
    NoMembers,
    #[error("more than {MAX_MEMBERS} voters")]
    TooManyMembers,
    #[error("duplicate member id {0}")]
    DuplicateId(MemberId),
    #[error("this node's id {0} is not a member or the witness")]
    SelfUnknown(MemberId),
    #[error("weight {0} outside 1..={MAX_WEIGHT}")]
    Weight(u32),
    #[error("slice count {0} outside 1..={MAX_SLICES}")]
    Slices(usize),
    #[error("lease_ms {0} outside 1000..=30000")]
    Lease(u64),
    #[error("heartbeat_ms must be at least 10 and at most lease_ms / 4")]
    Heartbeat,
    #[error("drift_margin_pct {0} outside 1..=50")]
    Drift(u64),
    #[error("automatic failover with two members requires a witness")]
    NeedsWitness,
    #[error("only valid on the leader in automatic mode")]
    NotLeader,
    #[error("only valid in manual (auto_failover = false) mode")]
    NotManual,
    #[error("unknown member {0}")]
    UnknownMember(MemberId),
}

/// Plain configuration (WU6 maps it from `cluster.*` / `cluster.ha.*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipConfig {
    pub self_id: MemberId,
    /// Data members: (id, weight).
    pub members: Vec<(MemberId, u32)>,
    /// Witness id: votes and acks, never serves or leads.
    pub witness: Option<MemberId>,
    pub slice_count: usize,
    pub lease_ms: u64,
    pub heartbeat_ms: u64,
    pub drift_margin_pct: u64,
    /// Standby to live delay for a rejoined member; 0 = only [`Membership::promote`].
    pub failback_delay_ms: u64,
    /// `false`: no elections; every member serves its primary slices of the
    /// full member set and takeover is the operator's [`Membership::manual_takeover`].
    pub auto_failover: bool,
    /// Election jitter seed (any value; differs per node in practice).
    pub seed: u64,
}

/// State that must survive a restart (`state_dir/cluster.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Persisted {
    pub term: u32,
    pub voted_for: Option<MemberId>,
    /// Newest view epoch adopted.
    pub epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Follower,
    PreCandidate,
    Candidate,
    Leader,
    Witness,
    /// `auto_failover = false`.
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireReason {
    Startup,
    Takeover,
    Handover,
    Failback,
}

impl AcquireReason {
    pub fn as_str(self) -> &'static str {
        match self {
            AcquireReason::Startup => "startup",
            AcquireReason::Takeover => "takeover",
            AcquireReason::Handover => "handover",
            AcquireReason::Failback => "failback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseReason {
    Handover,
    Fenced,
    Shutdown,
    LeaseLost,
}

impl ReleaseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            ReleaseReason::Handover => "handover",
            ReleaseReason::Fenced => "fenced",
            ReleaseReason::Shutdown => "shutdown",
            ReleaseReason::LeaseLost => "lease_lost",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Write durably before executing the rest of the batch.
    Persist(Persisted),
    Send {
        to: MemberId,
        msg: Msg,
    },
    /// A view was adopted (audit `cluster_view_change`, recompute backups).
    ViewAdopted(View),
    /// The adopted view is committed.
    Committed(u64),
    RoleChanged(Role),
    /// The slice may be served from now on. The driver adopts replicated
    /// state and queues the audit records before setting it Active in the
    /// engine; on `Handover`, it sends `HandoverDone` to the previous owner.
    Acquire {
        slice: SliceId,
        epoch: u64,
        prev_owner: Option<MemberId>,
        reason: AcquireReason,
    },
    /// Stop serving the slice now (fence before anything else). On
    /// `Handover`, the driver flushes replication and sends
    /// `HandoverFence{final_seq}` to `new_owner`.
    Release {
        slice: SliceId,
        epoch: u64,
        new_owner: Option<MemberId>,
        reason: ReleaseReason,
    },
}

/// Election counters since this [`Membership`] was built.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-4 (System Monitoring) - exported by platd as
///   `plat_cluster_election_rounds_total{result}` and
///   `plat_cluster_heartbeats_expedited_total`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ElectionStats {
    /// Candidate rounds that ended with this node elected.
    pub won: u64,
    /// Candidate rounds that ended without a majority in time.
    pub timeout: u64,
    /// Candidate rounds given up for a lower-id candidate of the same term.
    pub yielded: u64,
    /// Heartbeat rounds sent ahead of the period (first ack of the term from
    /// a voter, or a view commit).
    pub heartbeats_expedited: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SliceState {
    Idle,
    /// Owned in the adopted view, not yet served. `ready_at = None`: waiting
    /// for a lease, then `safe`.
    Pending {
        ready_at: Option<u64>,
        prev_owner: Option<MemberId>,
        reason: AcquireReason,
    },
    Active,
}

/// Leader-side state per voter.
#[derive(Debug, Clone, Copy, Default)]
struct PeerState {
    /// Outstanding heartbeat sequence.
    n: u64,
    /// When `n` was first sent.
    first_sent: u64,
    acked: bool,
    /// `first_sent` of the newest acked heartbeat (leadership anchor).
    anchor: Option<u64>,
    last_ack_recv: u64,
    /// An ack (heartbeat or view) arrived in this term. `last_ack_recv`
    /// starts at the election time, which says nothing about the member.
    heard: bool,
    acked_epoch: u64,
    /// Since when the member is in `standby` (failback timer).
    standby_since: u64,
    /// View epoch in which the member last reported every slice it backs
    /// up in sync ([`Msg::SyncStatus`]); `None`: not in sync or unknown.
    sync_epoch: Option<u64>,
}

#[derive(Debug)]
pub struct Membership {
    cfg: MembershipConfig,
    /// Every voter id, sorted (members plus witness).
    voters: Vec<MemberId>,
    /// Weight table indexed by member id.
    weights: Vec<u32>,
    fence_ms: u64,
    safe_ms: u64,
    p: Persisted,
    role: Role,
    view: Option<View>,
    committed: u64,
    slices: Vec<SliceState>,
    lease_until: u64,
    /// Do not vote or campaign before this (lease promise and boot quiet).
    sticky_until: u64,
    // Follower.
    leader: Option<MemberId>,
    last_leader_contact: u64,
    /// Newest heartbeat seq acked, when, and under which adopted epoch.
    my_seq: u64,
    my_seq_at: u64,
    my_seq_epoch: u64,
    election_deadline: u64,
    attempt: u64,
    // Candidate.
    grants: u64,
    best_view: Option<View>,
    /// Pre-candidate: when to ask for pre-votes again.
    next_solicit_at: u64,
    /// Consecutive candidate rounds that timed out (round length doubling).
    round_timeouts: u32,
    /// Term of the last yield (C6; at most one per term).
    yielded_term: u32,
    /// Yields since this node last heard or became a leader.
    yields_in_row: u32,
    // Leader.
    peers: Vec<PeerState>,
    next_hb_at: u64,
    elected_at: u64,
    /// `base_epoch` of the view being proposed.
    proposal_base: u64,
    /// Manual mode: slices gained by a forced takeover wait until then.
    manual_hold_until: u64,
    /// Automatic failback also waits until the standby member reports its
    /// backup copies in sync ([`Membership::set_failback_needs_sync`]).
    failback_needs_sync: bool,
    /// Leader: send the next heartbeat round now instead of at `next_hb_at`.
    expedite: bool,
    stats: ElectionStats,
}

fn majority(n: usize) -> usize {
    n / 2 + 1
}

impl Membership {
    /// Build from config and the persisted state. A started node neither
    /// votes nor campaigns for `safe` (so a fast restart cannot break a
    /// promise it made before the crash) and serves nothing until it holds
    /// a lease. In manual mode it serves its primary slices at once (see
    /// the returned actions).
    pub fn new(cfg: MembershipConfig, persisted: Persisted, now: u64) -> Result<(Self, Vec<Action>), MembershipError> {
        if cfg.members.is_empty() {
            return Err(MembershipError::NoMembers);
        }
        let mut voters: Vec<MemberId> = cfg.members.iter().map(|m| m.0).chain(cfg.witness).collect();
        if voters.len() > MAX_MEMBERS {
            return Err(MembershipError::TooManyMembers);
        }
        voters.sort_unstable();
        if let Some(w) = voters.windows(2).find(|w| w[0] == w[1]) {
            return Err(MembershipError::DuplicateId(w[0]));
        }
        if voters.binary_search(&cfg.self_id).is_err() {
            return Err(MembershipError::SelfUnknown(cfg.self_id));
        }
        let mut weights = vec![1u32; usize::from(voters.last().copied().unwrap_or(0)) + 1];
        for (id, w) in &cfg.members {
            if !(1..=MAX_WEIGHT).contains(w) {
                return Err(MembershipError::Weight(*w));
            }
            weights[usize::from(*id)] = *w;
        }
        if cfg.slice_count == 0 || cfg.slice_count > MAX_SLICES {
            return Err(MembershipError::Slices(cfg.slice_count));
        }
        if !(1000..=30_000).contains(&cfg.lease_ms) {
            return Err(MembershipError::Lease(cfg.lease_ms));
        }
        if cfg.heartbeat_ms < 10 || cfg.heartbeat_ms * 4 > cfg.lease_ms {
            return Err(MembershipError::Heartbeat);
        }
        if !(1..=50).contains(&cfg.drift_margin_pct) {
            return Err(MembershipError::Drift(cfg.drift_margin_pct));
        }
        if cfg.auto_failover && cfg.members.len() == 2 && cfg.witness.is_none() {
            return Err(MembershipError::NeedsWitness);
        }
        let fence_ms = cfg.lease_ms * (100 - cfg.drift_margin_pct) / 100;
        let safe_ms = cfg.lease_ms * (100 + cfg.drift_margin_pct) / 100 + FIXED_MARGIN_MS;
        let role = if !cfg.auto_failover {
            Role::Manual
        } else if Some(cfg.self_id) == cfg.witness {
            Role::Witness
        } else {
            Role::Follower
        };
        let n = voters.len();
        let mut m = Membership {
            slices: vec![SliceState::Idle; cfg.slice_count],
            cfg,
            voters,
            weights,
            fence_ms,
            safe_ms,
            p: persisted,
            role,
            view: None,
            committed: 0,
            lease_until: 0,
            sticky_until: now + safe_ms,
            leader: None,
            last_leader_contact: now,
            my_seq: 0,
            my_seq_at: 0,
            my_seq_epoch: 0,
            election_deadline: 0,
            attempt: 0,
            grants: 0,
            best_view: None,
            next_solicit_at: 0,
            round_timeouts: 0,
            yielded_term: 0,
            yields_in_row: 0,
            peers: vec![PeerState::default(); n],
            next_hb_at: now,
            elected_at: now,
            proposal_base: 0,
            manual_hold_until: 0,
            failback_needs_sync: false,
            expedite: false,
            stats: ElectionStats::default(),
        };
        m.election_deadline = now + m.election_timeout();
        let mut out = Vec::new();
        if m.role == Role::Manual {
            let mut live: Vec<MemberId> = m.cfg.members.iter().map(|x| x.0).collect();
            live.sort_unstable();
            let leader = live.first().copied().unwrap_or(0);
            let epoch = m.p.epoch.max(make_epoch(m.p.term, 0));
            let view = View { epoch, live, standby: Vec::new(), leader };
            m.lease_until = u64::MAX;
            m.adopt(now, view, None, &mut out);
            m.committed = epoch;
            m.advance_slices(now, &mut out);
        }
        Ok((m, out))
    }

    // ------------------------------------------------------------ queries

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn term(&self) -> u32 {
        self.p.term
    }

    pub fn persisted(&self) -> Persisted {
        self.p
    }

    pub fn view(&self) -> Option<&View> {
        self.view.as_ref()
    }

    pub fn committed(&self) -> u64 {
        self.committed
    }

    pub fn leader(&self) -> Option<MemberId> {
        if self.role == Role::Leader { Some(self.cfg.self_id) } else { self.leader }
    }

    /// Weight table indexed by member id (for [`View::owners`]).
    pub fn weights(&self) -> &[u32] {
        &self.weights
    }

    /// Self-fence point after a lease anchor (`lease * (1 - m)`).
    pub fn fence_ms(&self) -> u64 {
        self.fence_ms
    }

    /// Takeover wait (`lease * (1 + m) + 200 ms`).
    pub fn safe_ms(&self) -> u64 {
        self.safe_ms
    }

    /// Lease time left (0 when fenced). Exported as
    /// `plat_cluster_lease_remaining_ms`.
    pub fn lease_remaining(&self, now: u64) -> u64 {
        self.lease_until.saturating_sub(now)
    }

    /// Whether this node may translate and allocate for `slice` at `now`:
    /// acquired and the lease has not run out. The driver must also fence
    /// the engine when [`Action::Release`] is returned; this check is exact
    /// even between ticks.
    pub fn is_serving(&self, slice: SliceId, now: u64) -> bool {
        matches!(self.slices.get(usize::from(slice)), Some(SliceState::Active)) && now < self.lease_until
    }

    /// Slices currently acquired.
    pub fn active_slices(&self) -> impl Iterator<Item = SliceId> + '_ {
        self.slices.iter().enumerate().filter(|(_, s)| **s == SliceState::Active).map(|(i, _)| i as SliceId)
    }

    /// Election counters since this instance was built (SI-4).
    pub fn election_stats(&self) -> ElectionStats {
        self.stats
    }

    /// How often the driver should call [`Membership::on_tick`].
    pub fn tick_interval_ms(&self) -> u64 {
        (self.cfg.heartbeat_ms / 10).max(5)
    }

    // ----------------------------------------------------------- helpers

    fn idx(&self, m: MemberId) -> Option<usize> {
        self.voters.binary_search(&m).ok()
    }

    fn is_data(&self, m: MemberId) -> bool {
        self.cfg.members.iter().any(|x| x.0 == m)
    }

    fn election_timeout(&self) -> u64 {
        let j = mix(self.cfg.seed ^ mix((u64::from(self.p.term) << 16) | u64::from(self.cfg.self_id)) ^ self.attempt);
        self.safe_ms + j % (self.cfg.heartbeat_ms / 2).max(1)
    }

    /// Length of the current candidate round: `heartbeat / 2`, doubled per
    /// consecutive timed-out round, at most `safe`.
    fn round_ms(&self) -> u64 {
        let base = (self.cfg.heartbeat_ms / 2).max(1);
        (base << self.round_timeouts.min(16)).min(self.safe_ms)
    }

    /// How often a pre-candidate asks again.
    fn solicit_ms(&self) -> u64 {
        (self.cfg.heartbeat_ms / 5).max(1)
    }

    /// How long a candidate that yielded stays quiet: four base rounds.
    fn yield_quiet_ms(&self) -> u64 {
        4 * (self.cfg.heartbeat_ms / 2).max(1)
    }

    fn bit(&self, m: MemberId) -> u64 {
        self.idx(m).map_or(0, |i| 1u64 << i)
    }

    fn persist(&mut self, out: &mut Vec<Action>) {
        out.push(Action::Persist(self.p));
    }

    fn set_role(&mut self, r: Role, out: &mut Vec<Action>) {
        if self.role != r {
            self.role = r;
            out.push(Action::RoleChanged(r));
        }
    }

    /// Move to `term` as a follower (a newer term was seen).
    fn observe_term(&mut self, now: u64, term: u32, out: &mut Vec<Action>) {
        if term > self.p.term {
            self.p.term = term;
            self.p.voted_for = None;
            self.persist(out);
            if matches!(self.role, Role::Leader | Role::Candidate | Role::PreCandidate) {
                if self.role == Role::Leader {
                    // Our leadership lease ends now; keep our promise to the
                    // voters that acked us.
                    self.lease_until = self.lease_until.min(now);
                    self.sticky_until = self.sticky_until.max(now + self.safe_ms);
                }
                self.set_role(Role::Follower, out);
                self.election_deadline = now + self.election_timeout();
            }
        }
    }

    fn own_view_epoch(&self) -> u64 {
        self.view.as_ref().map_or(0, |v| v.epoch)
    }

    // ------------------------------------------------------------ slices

    /// Adopt `view`. `base`: the epoch the view was derived from (`None`
    /// for manual mode); ownership carries over without a wait only when
    /// `base` is the view this node adopted last.
    fn adopt(&mut self, now: u64, view: View, base: Option<u64>, out: &mut Vec<Action>) {
        let me = self.cfg.self_id;
        let old = self.view.take();
        let continuous = old.as_ref().is_some_and(|o| Some(o.epoch) == base);
        let was_standby = old.as_ref().is_some_and(|o| o.is_standby(me));
        for s in 0..self.slices.len() {
            let slice = s as SliceId;
            let owners = view.owners(slice, &self.weights);
            let new_primary = owners.map(|o| o.0);
            let st = self.slices[s];
            if new_primary != Some(me) {
                if st == SliceState::Active {
                    let reason = if new_primary.is_some() && (view.is_live(me) || view.is_standby(me)) {
                        ReleaseReason::Handover
                    } else {
                        ReleaseReason::Fenced
                    };
                    out.push(Action::Release { slice, epoch: view.epoch, new_owner: new_primary, reason });
                }
                self.slices[s] = SliceState::Idle;
                continue;
            }
            if st == SliceState::Active && continuous {
                continue;
            }
            if st == SliceState::Active {
                // The view chain has a gap: someone else may have held the
                // slice in a view we missed. Fence and wait.
                out.push(Action::Release {
                    slice,
                    epoch: view.epoch,
                    new_owner: Some(me),
                    reason: ReleaseReason::Fenced,
                });
            }
            // A slice still pending from an earlier view of an unbroken
            // chain keeps the owner it is gained from, its reason and its
            // deadline: in the old view this node is already the primary,
            // which says nothing about who served the slice (NIST-011).
            if continuous && let SliceState::Pending { ready_at, prev_owner, reason } = st {
                let (ready_at, reason) = match prev_owner {
                    // The leader has since dropped the previous owner after
                    // `safe` of silence: its lease is over.
                    Some(p) if p != me && !view.is_live(p) && !view.is_standby(p) => {
                        (ready_at.map(|r| r.min(now)), AcquireReason::Takeover)
                    }
                    _ => (ready_at, reason),
                };
                self.slices[s] = SliceState::Pending { ready_at, prev_owner, reason };
                continue;
            }
            let prev = if continuous { old.as_ref().and_then(|o| o.primary(slice, &self.weights)) } else { None };
            let (ready_at, reason) = match prev {
                _ if self.role == Role::Manual => (
                    Some(now.max(self.manual_hold_until)),
                    if old.is_some() { AcquireReason::Takeover } else { AcquireReason::Startup },
                ),
                // First view of the cluster: nobody held it.
                None if continuous => (Some(now), AcquireReason::Startup),
                Some(p) if p == me => (Some(now + self.safe_ms), AcquireReason::Startup),
                // The leader dropped the previous owner after it was silent
                // for `safe`: its lease is over.
                Some(p) if !view.is_live(p) && !view.is_standby(p) => (Some(now), AcquireReason::Takeover),
                Some(_) if was_standby => (Some(now + self.safe_ms), AcquireReason::Failback),
                Some(_) => (Some(now + self.safe_ms), AcquireReason::Handover),
                None => (
                    Some(now + self.safe_ms),
                    if old.is_none() { AcquireReason::Startup } else { AcquireReason::Takeover },
                ),
            };
            self.slices[s] = SliceState::Pending { ready_at, prev_owner: prev, reason };
        }
        self.p.epoch = self.p.epoch.max(view.epoch);
        out.push(Action::ViewAdopted(view.clone()));
        self.view = Some(view);
    }

    /// Promote pending slices and fence on lease loss.
    fn advance_slices(&mut self, now: u64, out: &mut Vec<Action>) {
        let Some(epoch) = self.view.as_ref().map(|v| v.epoch) else { return };
        let leased = now < self.lease_until;
        let committed = self.committed >= epoch;
        for s in 0..self.slices.len() {
            let slice = s as SliceId;
            match self.slices[s] {
                SliceState::Active if !leased => {
                    out.push(Action::Release { slice, epoch, new_owner: None, reason: ReleaseReason::LeaseLost });
                    self.slices[s] = SliceState::Pending {
                        ready_at: None,
                        prev_owner: Some(self.cfg.self_id),
                        reason: AcquireReason::Startup,
                    };
                }
                // Lease back under an unbroken view chain in which we kept
                // the slice: nobody else can have been given it (a newer
                // committed view would have reached us first, or broken the
                // chain and reset the wait in `adopt`).
                SliceState::Pending { ready_at: None, prev_owner, reason } if leased => {
                    if committed {
                        // Same condition as the arm below with `ready_at =
                        // now`; no reason to wait for another pass.
                        self.slices[s] = SliceState::Active;
                        out.push(Action::Acquire { slice, epoch, prev_owner, reason });
                    } else {
                        self.slices[s] = SliceState::Pending { ready_at: Some(now), prev_owner, reason };
                    }
                }
                SliceState::Pending { ready_at: Some(r), prev_owner, reason } if leased && committed && now >= r => {
                    self.slices[s] = SliceState::Active;
                    out.push(Action::Acquire { slice, epoch, prev_owner, reason });
                }
                _ => {}
            }
        }
    }

    // ------------------------------------------------------------- input

    /// Advance timers.
    pub fn on_tick(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        match self.role {
            Role::Manual => {}
            Role::Witness => {}
            Role::Follower => {
                if now >= self.election_deadline && now >= self.sticky_until {
                    self.start_pre_vote(now, &mut out);
                }
            }
            Role::PreCandidate => {
                // No timeout: a voter that refused was keeping a lease
                // promise, which runs out; ask again until a majority
                // grants. `follow` and a granted real vote end this state.
                //
                // COMPLIANCE MAPPING:
                // - NIST 800-53: SC-24 - asking more often changes no
                //   answer: every voter still checks `may_vote` (its
                //   promise of `safe` after the last ack) on each request
                if now >= self.next_solicit_at {
                    self.start_pre_vote(now, &mut out);
                }
            }
            Role::Candidate => {
                if now >= self.election_deadline {
                    // No majority within the round (split vote or slow
                    // voters): campaign again at the next tick, through
                    // `Follower` so that `sticky_until` is checked again,
                    // with a longer round.
                    self.stats.timeout += 1;
                    self.round_timeouts = self.round_timeouts.saturating_add(1);
                    self.set_role(Role::Follower, &mut out);
                    self.attempt += 1;
                    self.election_deadline = now;
                }
            }
            Role::Leader => self.leader_tick(now, &mut out),
        }
        self.expedite_round(now, &mut out);
        self.advance_slices(now, &mut out);
        out
    }

    /// Handle one message from voter `from` (already authenticated by the
    /// driver). Messages from non-voters and data-plane messages are ignored.
    pub fn on_msg(&mut self, now: u64, from: MemberId, msg: &Msg) -> Vec<Action> {
        let mut out = Vec::new();
        if from == self.cfg.self_id || self.idx(from).is_none() || self.role == Role::Manual {
            return out;
        }
        match msg {
            Msg::Vote { epoch, pre } => self.on_vote(now, from, *epoch, *pre, &mut out),
            Msg::VoteAck { .. } => self.on_vote_ack(now, from, msg, &mut out),
            Msg::ViewPropose { base_epoch, view } => self.on_propose(now, from, *base_epoch, view, &mut out),
            Msg::ViewAck { epoch } => {
                if self.role == Role::Leader
                    && term_of(*epoch) == self.p.term
                    && let Some(i) = self.idx(from)
                {
                    self.peers[i].acked_epoch = self.peers[i].acked_epoch.max(*epoch);
                    self.peers[i].last_ack_recv = now;
                    self.peers[i].heard = true;
                    self.update_commit(&mut out);
                }
            }
            Msg::Heartbeat { .. } => self.on_heartbeat(now, from, msg, &mut out),
            Msg::HeartbeatAck { epoch, seq } => self.on_heartbeat_ack(now, from, *epoch, *seq, &mut out),
            Msg::SyncStatus { epoch, in_sync } => self.set_sync(from, *epoch, *in_sync),
            Msg::HandoverFence { slice, epoch, .. } => {
                if self.own_view_epoch() == *epoch
                    && let Some(SliceState::Pending { ready_at: Some(r), prev_owner: Some(p), reason }) =
                        self.slices.get(usize::from(*slice)).copied()
                    && p == from
                {
                    self.slices[usize::from(*slice)] =
                        SliceState::Pending { ready_at: Some(r.min(now)), prev_owner: Some(p), reason };
                }
            }
            _ => {}
        }
        self.expedite_round(now, &mut out);
        self.advance_slices(now, &mut out);
        out
    }

    // ---------------------------------------------------------- election

    fn may_vote(&self, now: u64) -> bool {
        now >= self.sticky_until && self.role != Role::Leader
    }

    fn start_pre_vote(&mut self, now: u64, out: &mut Vec<Action>) {
        if !self.is_data(self.cfg.self_id) {
            return;
        }
        self.set_role(Role::PreCandidate, out);
        // Every round starts from an empty grant set: grants do not add up
        // over many rounds.
        self.grants = self.bit(self.cfg.self_id);
        self.best_view = self.view.clone();
        self.next_solicit_at = now + self.solicit_ms();
        let epoch = make_epoch(self.p.term + 1, 0);
        self.broadcast(Msg::Vote { epoch, pre: true }, out);
        self.check_votes(now, out);
    }

    fn start_election(&mut self, now: u64, out: &mut Vec<Action>) {
        self.p.term += 1;
        self.p.voted_for = Some(self.cfg.self_id);
        self.persist(out);
        self.set_role(Role::Candidate, out);
        self.grants = self.bit(self.cfg.self_id);
        self.best_view = self.view.clone();
        self.election_deadline = now + self.round_ms();
        self.broadcast(Msg::Vote { epoch: make_epoch(self.p.term, 0), pre: false }, out);
        self.check_votes(now, out);
    }

    fn broadcast(&self, msg: Msg, out: &mut Vec<Action>) {
        for v in &self.voters {
            if *v != self.cfg.self_id {
                out.push(Action::Send { to: *v, msg: msg.clone() });
            }
        }
    }

    fn on_vote(&mut self, now: u64, from: MemberId, epoch: u64, pre: bool, out: &mut Vec<Action>) {
        let t = term_of(epoch);
        let candidate_ok = self.is_data(from);
        let granted = if pre {
            candidate_ok && t > self.p.term && self.may_vote(now)
        } else {
            if t > self.p.term && self.may_vote(now) {
                self.observe_term(now, t, out);
            }
            // Split vote: two candidates of one term. The higher id yields
            // and stays quiet, so the lower id retries alone. At most once
            // per term, and at most `data members - 1` times in a row
            // without hearing a leader (SEC-001): a lower-id peer that
            // answers every candidacy with a same-term request cannot hold
            // this node off for good. The cap is what the split-round
            // count `k <= S - 1` needs (a node yields at most once per
            // split round); past it, a split ends by the round timeout.
            //
            // COMPLIANCE MAPPING:
            // - NIST 800-53: SC-24 - giving up a candidacy grants nothing:
            //   this node keeps its own vote of the term (`voted_for`) and
            //   the request is refused below, so there is still one vote
            //   per voter and term; CP-10 - a split costs one round
            //   instead of two election timeouts
            if self.role == Role::Candidate
                && candidate_ok
                && t == self.p.term
                && from < self.cfg.self_id
                && self.yielded_term != t
                && (self.yields_in_row as usize) < self.cfg.members.len().saturating_sub(1)
            {
                self.yielded_term = t;
                self.yields_in_row += 1;
                self.stats.yielded += 1;
                self.set_role(Role::Follower, out);
                self.attempt += 1;
                self.election_deadline = now + self.yield_quiet_ms();
            }
            let ok =
                candidate_ok && t == self.p.term && self.may_vote(now) && self.p.voted_for.is_none_or(|v| v == from);
            if ok && self.p.voted_for.is_none() {
                self.p.voted_for = Some(from);
                self.persist(out);
            }
            if ok {
                self.election_deadline = now + self.election_timeout();
            }
            ok
        };
        let reply_epoch = if granted { epoch } else { make_epoch(self.p.term, 0) };
        out.push(Action::Send {
            to: from,
            msg: Msg::VoteAck { epoch: reply_epoch, pre, granted, last_view: self.view.clone() },
        });
    }

    fn on_vote_ack(&mut self, now: u64, from: MemberId, msg: &Msg, out: &mut Vec<Action>) {
        let Msg::VoteAck { epoch, pre, granted, last_view } = msg else { return };
        let (epoch, pre, granted) = (*epoch, *pre, *granted);
        let t = term_of(epoch);
        if !granted {
            // A refusal carries the voter's term; never adopt it while
            // pre-voting (that is the point of the pre-vote).
            if !pre && t > self.p.term {
                self.observe_term(now, t, out);
            }
            return;
        }
        let expected = match (self.role, pre) {
            (Role::PreCandidate, true) => self.p.term + 1,
            (Role::Candidate, false) => self.p.term,
            _ => return,
        };
        if t != expected {
            return;
        }
        self.grants |= self.bit(from);
        if let Some(v) = last_view
            && self.best_view.as_ref().is_none_or(|b| v.epoch > b.epoch)
        {
            self.best_view = Some(v.clone());
        }
        self.check_votes(now, out);
    }

    fn check_votes(&mut self, now: u64, out: &mut Vec<Action>) {
        if (self.grants.count_ones() as usize) < majority(self.voters.len()) {
            return;
        }
        match self.role {
            Role::PreCandidate => self.start_election(now, out),
            Role::Candidate => self.become_leader(now, out),
            _ => {}
        }
    }

    // ------------------------------------------------------------ leader

    fn become_leader(&mut self, now: u64, out: &mut Vec<Action>) {
        self.set_role(Role::Leader, out);
        self.stats.won += 1;
        self.round_timeouts = 0;
        self.yields_in_row = 0;
        self.leader = Some(self.cfg.self_id);
        self.elected_at = now;
        let base_seq = u64::from(self.p.term) << 32;
        self.peers.fill(PeerState {
            n: base_seq,
            first_sent: now,
            acked: false,
            anchor: None,
            last_ack_recv: now,
            heard: false,
            acked_epoch: 0,
            standby_since: now,
            sync_epoch: None,
        });
        let me = self.cfg.self_id;
        let base = self.best_view.take();
        let mut view = match &base {
            // Keep the newest known view, minus the old leader: a majority
            // stopped hearing from it for `safe`, so its lease is over.
            Some(b) => {
                let mut v = b.clone();
                if b.leader != me {
                    v.live.retain(|m| *m != b.leader);
                    v.standby.retain(|m| *m != b.leader);
                }
                if !v.is_live(me) && !v.is_standby(me) {
                    v.standby.push(me);
                }
                v
            }
            // Cold start: the full member set; members that never answer
            // are dropped after `safe` like any silent member.
            None => {
                View { epoch: 0, live: self.cfg.members.iter().map(|m| m.0).collect(), standby: Vec::new(), leader: me }
            }
        };
        view.epoch = make_epoch(self.p.term, 0);
        view.leader = me;
        view.normalize();
        if view.live.is_empty() {
            view.live = std::mem::take(&mut view.standby);
        }
        self.propose(now, view, base.map(|b| b.epoch), out);
        self.next_hb_at = now;
        self.leader_tick(now, out);
    }

    fn propose(&mut self, now: u64, view: View, base: Option<u64>, out: &mut Vec<Action>) {
        let base_epoch = base.unwrap_or(0);
        let mine = self.view.as_ref().map(|v| v.epoch);
        self.adopt(now, view.clone(), if mine == base { base } else { None }, out);
        self.persist(out);
        if let Some(i) = self.idx(self.cfg.self_id) {
            self.peers[i].acked_epoch = view.epoch;
        }
        self.proposal_base = base_epoch;
        self.broadcast(Msg::ViewPropose { base_epoch, view }, out);
    }

    fn leader_lease(&self, now: u64) -> u64 {
        let me = self.idx(self.cfg.self_id);
        let mut anchors: Vec<u64> = self
            .peers
            .iter()
            .enumerate()
            .filter_map(|(i, p)| if Some(i) == me { Some(now) } else { p.anchor })
            .collect();
        anchors.sort_unstable_by(|a, b| b.cmp(a));
        anchors.get(majority(self.voters.len()) - 1).map_or(0, |a| a + self.fence_ms)
    }

    fn update_commit(&mut self, out: &mut Vec<Action>) {
        let cur = self.own_view_epoch();
        if self.committed >= cur {
            return;
        }
        let n = self.peers.iter().filter(|p| p.acked_epoch >= cur).count();
        if n >= majority(self.voters.len()) {
            self.committed = cur;
            out.push(Action::Committed(cur));
            // Members gain slices only under a committed view: tell them
            // now.
            self.expedite = true;
        }
    }

    /// Runs a heartbeat round ahead of the period when one was asked for
    /// (first ack of the term from a voter, view commit). Only the spacing
    /// of heartbeats changes: `leader_tick` still advances a voter's
    /// sequence number only after its ack and only while this node holds
    /// the leadership lease, and the voter's lease still runs from the time
    /// it sent that ack.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: CP-10 - a surviving follower is leased again one round
    ///   trip after the new leader has its ack, not one heartbeat period
    ///   later; SC-24 - no grant without the leadership lease
    fn expedite_round(&mut self, now: u64, out: &mut Vec<Action>) {
        if !std::mem::take(&mut self.expedite) || self.role != Role::Leader {
            return;
        }
        self.stats.heartbeats_expedited += 1;
        self.next_hb_at = now;
        self.leader_tick(now, out);
        // A commit found by that tick went out with its heartbeats.
        self.expedite = false;
    }

    fn leader_tick(&mut self, now: u64, out: &mut Vec<Action>) {
        let lease = self.leader_lease(now);
        let grace = self.elected_at + self.safe_ms;
        if now >= lease && now >= grace {
            // Lost the majority: step down and fence.
            self.lease_until = self.lease_until.min(now);
            self.sticky_until = self.sticky_until.max(now + self.safe_ms);
            self.leader = None;
            self.set_role(Role::Follower, out);
            self.attempt += 1;
            self.election_deadline = now + self.election_timeout();
            return;
        }
        self.lease_until = lease;
        self.sticky_until = self.sticky_until.max(now + self.safe_ms);
        self.update_commit(out);
        if self.committed >= self.own_view_epoch() {
            self.maintain_view(now, out);
        }
        if now < self.next_hb_at {
            return;
        }
        self.next_hb_at = now + self.cfg.heartbeat_ms;
        // This round carries the commit index and every grant that is due.
        self.expedite = false;
        let Some(view) = self.view.clone() else { return };
        let granting = now < lease;
        for i in 0..self.voters.len() {
            let to = self.voters[i];
            if to == self.cfg.self_id {
                continue;
            }
            let p = &mut self.peers[i];
            if p.acked && granting {
                p.n += 1;
                p.first_sent = now;
                p.acked = false;
            }
            let seq = p.n;
            if p.acked_epoch < view.epoch {
                out.push(Action::Send {
                    to,
                    msg: Msg::ViewPropose { base_epoch: self.proposal_base, view: view.clone() },
                });
            }
            out.push(Action::Send {
                to,
                msg: Msg::Heartbeat {
                    epoch: view.epoch,
                    lease_ms: self.cfg.lease_ms as u32,
                    seq,
                    commit: self.committed,
                },
            });
        }
    }

    /// Drop silent members, add returning ones as standby, promote standby
    /// after `failback_delay_ms`. One change in flight at a time.
    fn maintain_view(&mut self, now: u64, out: &mut Vec<Action>) {
        let Some(cur) = self.view.clone() else { return };
        let me = self.cfg.self_id;
        let mut next = cur.clone();
        let silent = |s: &Self, m: MemberId| {
            m != me && s.idx(m).is_some_and(|i| now.saturating_sub(s.peers[i].last_ack_recv) >= s.safe_ms)
        };
        next.live.retain(|m| !silent(self, *m));
        next.standby.retain(|m| !silent(self, *m));
        // `heard`: `last_ack_recv` starts at the election time for every
        // voter (so that `silent` gives each one `safe` to answer), which
        // must not make a member that never answered in this term look
        // reachable; the crashed leader would come straight back as standby.
        let reachable = |s: &Self, m: MemberId| {
            m == me
                || s.idx(m).is_some_and(|i| {
                    s.peers[i].heard && now.saturating_sub(s.peers[i].last_ack_recv) < 2 * s.cfg.heartbeat_ms
                })
        };
        for (id, _) in self.cfg.members.clone() {
            if !next.is_live(id) && !next.is_standby(id) && reachable(self, id) {
                next.standby.push(id);
                if let Some(i) = self.idx(id) {
                    self.peers[i].standby_since = now;
                }
            }
        }
        next.normalize();
        if next.live.is_empty() {
            next.live = std::mem::take(&mut next.standby);
        } else if self.cfg.failback_delay_ms > 0 {
            let ready: Vec<MemberId> = next
                .standby
                .iter()
                .copied()
                .filter(|m| {
                    reachable(self, *m)
                        && self.idx(*m).is_some_and(|i| now >= self.peers[i].standby_since + self.cfg.failback_delay_ms)
                        && self.synced(*m, cur.epoch)
                })
                .collect();
            next.live.extend(ready);
        }
        next.normalize();
        if next.live != cur.live || next.standby != cur.standby {
            next.epoch = cur.epoch + 1;
            next.leader = me;
            self.propose(now, next, Some(cur.epoch), out);
        }
    }

    /// With `true`, automatic failback promotes a standby member only once
    /// it reported (or, for this node, [`Membership::set_sync`] recorded)
    /// every slice it backs up in sync in the current view.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: CP-10 - a returning member gets its slices back only
    ///   with complete replicated state (no quarantine of every block)
    pub fn set_failback_needs_sync(&mut self, on: bool) {
        self.failback_needs_sync = on;
    }

    /// Records member `m`'s backup state for view `epoch` (from its
    /// [`Msg::SyncStatus`], or this node's own replicator).
    pub fn set_sync(&mut self, m: MemberId, epoch: u64, in_sync: bool) {
        if let Some(i) = self.idx(m)
            && let Some(p) = self.peers.get_mut(i)
        {
            p.sync_epoch = in_sync.then_some(epoch);
        }
    }

    fn synced(&self, m: MemberId, epoch: u64) -> bool {
        !self.failback_needs_sync
            || self.idx(m).and_then(|i| self.peers.get(i)).is_some_and(|p| p.sync_epoch == Some(epoch))
    }

    /// Operator failback/promotion: move standby member `m` to live now
    /// (leader only). Use when `failback_delay_ms = 0`.
    pub fn promote(&mut self, now: u64, m: MemberId) -> Result<Vec<Action>, MembershipError> {
        if self.role != Role::Leader {
            return Err(MembershipError::NotLeader);
        }
        let Some(cur) = self.view.clone() else { return Err(MembershipError::NotLeader) };
        if !cur.is_standby(m) {
            return Err(MembershipError::UnknownMember(m));
        }
        let mut out = Vec::new();
        let mut next = cur.clone();
        next.live.push(m);
        next.normalize();
        next.epoch = cur.epoch + 1;
        self.propose(now, next, Some(cur.epoch), &mut out);
        self.advance_slices(now, &mut out);
        Ok(out)
    }

    fn on_heartbeat_ack(&mut self, now: u64, from: MemberId, epoch: u64, seq: u64, out: &mut Vec<Action>) {
        if term_of(epoch) > self.p.term {
            self.observe_term(now, term_of(epoch), out);
            return;
        }
        if self.role != Role::Leader {
            return;
        }
        let Some(i) = self.idx(from) else { return };
        let p = &mut self.peers[i];
        if seq != p.n {
            return;
        }
        p.last_ack_recv = now;
        p.heard = true;
        let mut first = false;
        if !p.acked {
            p.acked = true;
            first = p.anchor.is_none();
            p.anchor = Some(p.first_sent);
        }
        // The member's adopted view as of this ack; lower after a restart,
        // which makes us resend the proposal.
        p.acked_epoch = epoch;
        // First ack of the term from this voter: send its next heartbeat
        // now (it carries the lease once we hold the leadership lease).
        self.expedite |= first;
        self.update_commit(out);
    }

    // ---------------------------------------------------------- follower

    fn follow(&mut self, now: u64, from: MemberId, term: u32, out: &mut Vec<Action>) -> bool {
        if term < self.p.term {
            // Stale leader: tell it our term so it steps down.
            out.push(Action::Send { to: from, msg: Msg::HeartbeatAck { epoch: make_epoch(self.p.term, 0), seq: 0 } });
            return false;
        }
        self.observe_term(now, term, out);
        if self.role == Role::Leader {
            return false;
        }
        if matches!(self.role, Role::PreCandidate | Role::Candidate) {
            self.set_role(Role::Follower, out);
        }
        if self.leader != Some(from) {
            self.leader = Some(from);
        }
        self.last_leader_contact = now;
        self.round_timeouts = 0;
        self.yields_in_row = 0;
        self.election_deadline = now + self.election_timeout();
        true
    }

    fn on_propose(&mut self, now: u64, from: MemberId, base: u64, view: &View, out: &mut Vec<Action>) {
        if view.leader != from || !self.follow(now, from, term_of(view.epoch), out) {
            return;
        }
        let valid = view.live.iter().chain(&view.standby).all(|m| self.is_data(*m))
            && view.live.windows(2).all(|w| w[0] < w[1])
            && view.standby.windows(2).all(|w| w[0] < w[1]);
        if !valid {
            return;
        }
        if view.epoch > self.own_view_epoch() {
            self.adopt(now, view.clone(), Some(base), out);
            self.persist(out);
        }
        if view.epoch == self.own_view_epoch() {
            out.push(Action::Send { to: from, msg: Msg::ViewAck { epoch: view.epoch } });
        }
    }

    fn on_heartbeat(&mut self, now: u64, from: MemberId, msg: &Msg, out: &mut Vec<Action>) {
        let Msg::Heartbeat { epoch, lease_ms, seq, commit } = msg else { return };
        let (epoch, lease_ms, seq, commit) = (*epoch, *lease_ms, *seq, *commit);
        if !self.follow(now, from, term_of(epoch), out) {
            return;
        }
        let mine = self.own_view_epoch();
        if epoch == mine {
            if commit >= mine && self.committed < mine {
                self.committed = mine;
                out.push(Action::Committed(mine));
            }
            // `seq` follows our last ack: the leader saw that ack, so the
            // lease runs from when we sent it.
            if seq == self.my_seq + 1 && self.my_seq_epoch == mine {
                let fence = self.fence_ms.min(u64::from(lease_ms) * (100 - self.cfg.drift_margin_pct) / 100);
                self.lease_until = self.lease_until.max(self.my_seq_at + fence);
            }
        }
        if seq > self.my_seq {
            self.my_seq = seq;
            self.my_seq_at = now;
            self.my_seq_epoch = mine;
        }
        if seq == self.my_seq {
            // Acking promises not to vote for anyone else for `safe`.
            self.sticky_until = self.sticky_until.max(now + self.safe_ms);
            out.push(Action::Send { to: from, msg: Msg::HeartbeatAck { epoch: mine, seq } });
        }
    }

    // ------------------------------------------------------------ manual

    /// Manual mode: the operator declares `dead` lost; its slices move to
    /// their backups at once. The operator is responsible for having
    /// stopped `dead` (two-node clusters without a witness). `wait`: the
    /// gained slices are served only after `safe` (SEC-2); platd always
    /// passes `true`, since a partitioned `dead` may still serve until its
    /// lease lapses (SEC-R1-1).
    pub fn manual_takeover(&mut self, now: u64, dead: MemberId, wait: bool) -> Result<Vec<Action>, MembershipError> {
        if wait {
            self.manual_hold_until = now + self.safe_ms;
        }
        let r = self.manual_change(now, |v| v.live.retain(|m| *m != dead), dead);
        self.manual_hold_until = 0;
        r
    }

    /// Manual mode: return `m` to the live set.
    pub fn manual_restore(&mut self, now: u64, m: MemberId) -> Result<Vec<Action>, MembershipError> {
        self.manual_change(now, |v| v.live.push(m), m)
    }

    fn manual_change(
        &mut self,
        now: u64,
        f: impl FnOnce(&mut View),
        m: MemberId,
    ) -> Result<Vec<Action>, MembershipError> {
        if self.role != Role::Manual {
            return Err(MembershipError::NotManual);
        }
        if !self.is_data(m) {
            return Err(MembershipError::UnknownMember(m));
        }
        let Some(mut v) = self.view.clone() else { return Err(MembershipError::NotManual) };
        let base = v.epoch;
        f(&mut v);
        v.normalize();
        v.epoch = base + 1;
        let mut out = Vec::new();
        self.adopt(now, v, Some(base), &mut out);
        self.committed = self.p.epoch;
        self.persist(&mut out);
        self.advance_slices(now, &mut out);
        Ok(out)
    }

    /// Orderly stop: release every slice (`shutdown`) and stop leading.
    pub fn shutdown(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        let epoch = self.own_view_epoch();
        for s in 0..self.slices.len() {
            if self.slices[s] == SliceState::Active {
                out.push(Action::Release {
                    slice: s as SliceId,
                    epoch,
                    new_owner: None,
                    reason: ReleaseReason::Shutdown,
                });
            }
            self.slices[s] = SliceState::Idle;
        }
        self.lease_until = self.lease_until.min(now);
        self.view = None;
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn three(me: MemberId) -> Membership {
        let cfg = MembershipConfig {
            self_id: me,
            members: vec![(0, 1), (1, 1), (2, 1)],
            witness: None,
            slice_count: 64,
            lease_ms: 1000,
            heartbeat_ms: 100,
            drift_margin_pct: 10,
            failback_delay_ms: 0,
            auto_failover: true,
            seed: 1,
        };
        Membership::new(cfg, Persisted::default(), 0).unwrap().0
    }

    /// `members` data members (ids from 0) plus an optional witness with
    /// the next id; `safe` 1300, round 50, re-solicit 20, yield quiet 200.
    fn node(me: MemberId, members: u16, witness: bool) -> Membership {
        let cfg = MembershipConfig {
            self_id: me,
            members: (0..members).map(|m| (m, 1)).collect(),
            witness: witness.then_some(members),
            slice_count: 8,
            lease_ms: 1000,
            heartbeat_ms: 100,
            drift_margin_pct: 10,
            failback_delay_ms: 0,
            auto_failover: true,
            seed: 7,
        };
        Membership::new(cfg, Persisted::default(), 0).unwrap().0
    }

    fn pre_grant(term: u32) -> Msg {
        Msg::VoteAck { epoch: make_epoch(term, 0), pre: true, granted: true, last_view: None }
    }

    fn grant(term: u32) -> Msg {
        Msg::VoteAck { epoch: make_epoch(term, 0), pre: false, granted: true, last_view: None }
    }

    fn sent(out: &[Action], to: MemberId) -> impl Iterator<Item = &Msg> {
        out.iter().filter_map(move |a| match a {
            Action::Send { to: t, msg } if *t == to => Some(msg),
            _ => None,
        })
    }

    /// Past the boot quiet time and the first election deadline.
    const T0: u64 = 1400;

    /// `m` campaigns at `T0` and `voter` grants the pre-vote; with three
    /// voters that makes it a candidate of term 1.
    fn candidate(m: &mut Membership, voter: MemberId) {
        let out = m.on_tick(T0);
        assert_eq!(m.role(), Role::PreCandidate, "{out:?}");
        let _ = m.on_msg(T0, voter, &pre_grant(1));
        assert_eq!((m.role(), m.term()), (Role::Candidate, 1));
    }

    /// C6: a candidate gives way only to a real vote request for its own
    /// term from a lower-id data member, grants nothing by doing so and
    /// stays quiet for four rounds.
    #[test]
    fn candidate_yields_only_to_a_lower_id_in_its_own_term() {
        let mut m = node(1, 3, false);
        candidate(&mut m, 2);
        let vote = |term| Msg::Vote { epoch: make_epoch(term, 0), pre: false };
        // Higher id, same term.
        let _ = m.on_msg(T0 + 1, 2, &vote(1));
        assert_eq!(m.role(), Role::Candidate);
        // Lower id, older term.
        let _ = m.on_msg(T0 + 1, 0, &vote(0));
        assert_eq!(m.role(), Role::Candidate);
        // Lower id, pre-vote for the next term.
        let _ = m.on_msg(T0 + 1, 0, &Msg::Vote { epoch: make_epoch(2, 0), pre: true });
        assert_eq!(m.role(), Role::Candidate);
        assert_eq!(m.election_stats().yielded, 0);
        // Lower id, same term: yield, and refuse (this node voted for itself).
        let out = m.on_msg(T0 + 2, 0, &vote(1));
        assert_eq!(m.role(), Role::Follower);
        assert_eq!(m.election_stats(), ElectionStats { yielded: 1, ..ElectionStats::default() });
        assert!(sent(&out, 0).any(|x| matches!(x, Msg::VoteAck { pre: false, granted: false, .. })), "{out:?}");
        assert_eq!(m.persisted().voted_for, Some(1));
        // A late grant does not elect a node that yielded.
        let _ = m.on_msg(T0 + 3, 2, &grant(1));
        assert_eq!(m.role(), Role::Follower);
        // Quiet for four rounds, then it campaigns again.
        let _ = m.on_tick(T0 + 2 + 199);
        assert_eq!(m.role(), Role::Follower);
        let _ = m.on_tick(T0 + 2 + 200);
        assert_eq!(m.role(), Role::PreCandidate);

        // A vote request from the witness (never a candidate) does not
        // count, even with the lowest id.
        let cfg = MembershipConfig {
            self_id: 2,
            members: vec![(1, 1), (2, 1)],
            witness: Some(0),
            slice_count: 8,
            lease_ms: 1000,
            heartbeat_ms: 100,
            drift_margin_pct: 10,
            failback_delay_ms: 0,
            auto_failover: true,
            seed: 7,
        };
        let mut c = Membership::new(cfg, Persisted::default(), 0).unwrap().0;
        candidate(&mut c, 1);
        let _ = c.on_msg(T0 + 1, 0, &vote(1));
        assert_eq!(c.role(), Role::Candidate, "the witness cannot make a candidate yield");
        assert_eq!(c.election_stats().yielded, 0);
    }

    /// SEC-001: a lower-id peer that answers every candidacy with a
    /// same-term vote request makes this node yield at most once per term
    /// and at most `data members - 1` (here 2) times without a leader; the
    /// vote stays its own either way.
    #[test]
    fn yield_is_capped_per_term_and_without_a_leader() {
        let mut m = node(1, 3, false);
        let vote = |term| Msg::Vote { epoch: make_epoch(term, 0), pre: false };
        let mut now = T0;
        let mut yields = Vec::new();
        for term in 1..=4u32 {
            let _ = m.on_tick(now);
            assert_eq!(m.role(), Role::PreCandidate, "term {term}");
            let _ = m.on_msg(now, 2, &pre_grant(term));
            assert_eq!((m.role(), m.term()), (Role::Candidate, term));
            let _ = m.on_msg(now + 1, 0, &vote(term));
            yields.push(m.role() == Role::Follower);
            assert_eq!(m.persisted().voted_for, Some(1), "term {term}: own vote kept");
            if m.role() == Role::Candidate {
                // Not yielded: the round times out instead.
                now += m.round_ms();
                let _ = m.on_tick(now);
            } else {
                // Yielded once: a second request of the same term changes nothing.
                assert_eq!(m.election_stats().yielded as usize, yields.iter().filter(|y| **y).count());
                now += m.yield_quiet_ms();
            }
            now += 1;
        }
        assert_eq!(yields, [true, true, false, false]);
        assert_eq!(m.election_stats().yielded, 2);
        // Hearing a leader resets the run.
        let hb = Msg::Heartbeat { epoch: make_epoch(5, 0), lease_ms: 1000, seq: 1, commit: 0 };
        let _ = m.on_msg(now, 0, &hb);
        assert_eq!(m.yields_in_row, 0);

        // Same term twice: the second request finds a follower (nothing to
        // yield), and a re-campaign in that term is not possible (the term
        // moves on), so once per term holds by construction too.
        let mut c = node(2, 3, false);
        candidate(&mut c, 1);
        let _ = c.on_msg(T0 + 1, 0, &vote(1));
        let _ = c.on_msg(T0 + 2, 1, &vote(1));
        assert_eq!(c.election_stats().yielded, 1);
    }

    /// C4: a pre-candidate does not time out; it asks again every
    /// `heartbeat / 5` and every round starts from an empty grant set.
    #[test]
    fn pre_candidate_resolicits_with_an_empty_grant_set() {
        let mut m = node(0, 5, false);
        let out = m.on_tick(T0);
        assert_eq!(m.role(), Role::PreCandidate);
        assert_eq!(
            out.iter().filter(|a| matches!(a, Action::Send { msg: Msg::Vote { pre: true, .. }, .. })).count(),
            4
        );
        // One grant of the three needed.
        let _ = m.on_msg(T0 + 1, 1, &pre_grant(1));
        assert_eq!(m.role(), Role::PreCandidate);
        // Not before the round is over.
        let out = m.on_tick(T0 + 19);
        assert!(out.is_empty(), "{out:?}");
        let out = m.on_tick(T0 + 20);
        assert_eq!(
            out.iter().filter(|a| matches!(a, Action::Send { msg: Msg::Vote { pre: true, .. }, .. })).count(),
            4
        );
        // The grant of the first round no longer counts.
        let _ = m.on_msg(T0 + 21, 2, &pre_grant(1));
        assert_eq!(m.role(), Role::PreCandidate);
        // No timeout, no term change, however long nobody answers.
        let mut now = T0 + 21;
        while now < T0 + 10 * m.safe_ms() {
            now += m.tick_interval_ms();
            let _ = m.on_tick(now);
            assert_eq!((m.role(), m.term()), (Role::PreCandidate, 0));
        }
        assert_eq!(m.election_stats(), ElectionStats::default());
        // Two grants within one round make the majority.
        let _ = m.on_msg(now, 3, &pre_grant(1));
        let _ = m.on_msg(now, 4, &pre_grant(1));
        assert_eq!((m.role(), m.term()), (Role::Candidate, 1));
    }

    /// C5: a candidate round lasts `heartbeat / 2`, then doubles per
    /// consecutive timeout up to `safe`; hearing a leader resets it.
    #[test]
    fn candidate_round_doubles_up_to_safe() {
        let mut m = node(1, 3, false);
        let mut now = T0;
        let mut rounds = Vec::new();
        for term in 1..=7u32 {
            let _ = m.on_tick(now);
            assert_eq!(m.role(), Role::PreCandidate);
            let _ = m.on_msg(now, 0, &pre_grant(term));
            assert_eq!((m.role(), m.term()), (Role::Candidate, term));
            let round = m.round_ms();
            rounds.push(round);
            let _ = m.on_tick(now + round - 1);
            assert_eq!(m.role(), Role::Candidate);
            now += round;
            let _ = m.on_tick(now);
            assert_eq!(m.role(), Role::Follower, "back through follower: sticky_until is checked again");
            assert_eq!(m.election_stats().timeout, u64::from(term));
            now += 1;
        }
        assert_eq!(rounds, [50, 100, 200, 400, 800, 1300, 1300]);
        let hb = Msg::Heartbeat { epoch: make_epoch(8, 0), lease_ms: 1000, seq: 1, commit: 0 };
        let _ = m.on_msg(now, 0, &hb);
        assert_eq!(m.round_ms(), 50);
    }

    /// C2: the heartbeat round sent ahead of the period on a voter's first
    /// ack does not advance any sequence number (grants no lease) until
    /// this node holds the leadership lease.
    #[test]
    fn no_expedited_grant_without_the_leadership_lease() {
        let mut m = node(0, 5, false);
        let _ = m.on_tick(T0);
        let _ = m.on_msg(T0, 1, &pre_grant(1));
        let _ = m.on_msg(T0, 2, &pre_grant(1));
        assert_eq!(m.role(), Role::Candidate);
        let _ = m.on_msg(T0 + 1, 1, &grant(1));
        let out = m.on_msg(T0 + 1, 2, &grant(1));
        assert_eq!(m.role(), Role::Leader);
        assert_eq!(m.election_stats().won, 1);
        let n0 = 1u64 << 32;
        let seqs = |out: &[Action], to| -> Vec<u64> {
            sent(out, to).filter_map(|x| if let Msg::Heartbeat { seq, .. } = x { Some(*seq) } else { None }).collect()
        };
        assert_eq!(seqs(&out, 1), [n0]);
        let ack = Msg::HeartbeatAck { epoch: make_epoch(1, 0), seq: n0 };
        // First ack of the term: a round at once, but two of five voters
        // are not a majority, so the same number is sent again.
        let out = m.on_msg(T0 + 2, 1, &ack);
        assert_eq!(m.election_stats().heartbeats_expedited, 1);
        assert_eq!(m.lease_remaining(T0 + 2), 0);
        for to in 1..5 {
            assert_eq!(seqs(&out, to), [n0], "voter {to}: {out:?}");
        }
        // A repeated ack is not a first ack.
        let out = m.on_msg(T0 + 3, 1, &ack);
        assert!(seqs(&out, 1).is_empty(), "{out:?}");
        assert_eq!(m.election_stats().heartbeats_expedited, 1);
        // Third voter of five: leadership lease, and the two voters that
        // acked get the next number; the others do not.
        let out = m.on_msg(T0 + 4, 2, &ack);
        assert!(m.lease_remaining(T0 + 4) > 0);
        assert_eq!(seqs(&out, 1), [n0 + 1]);
        assert_eq!(seqs(&out, 2), [n0 + 1]);
        assert_eq!(seqs(&out, 3), [n0]);
        assert_eq!(seqs(&out, 4), [n0]);
    }

    /// C1: the member that never answered in this term is not put back.
    #[test]
    fn member_not_heard_in_this_term_is_not_reachable() {
        let mut m = node(0, 3, false);
        let old = View { epoch: make_epoch(0, 1), live: vec![0, 1, 2], standby: vec![], leader: 2 };
        let mut out = Vec::new();
        m.adopt(10, old.clone(), None, &mut out);
        candidate(&mut m, 1);
        let _ = m.on_msg(T0 + 1, 1, &grant(1));
        assert_eq!(m.role(), Role::Leader);
        let first = m.view().cloned().unwrap();
        assert_eq!((first.live.as_slice(), first.standby.as_slice()), ([0, 1].as_slice(), [].as_slice()));
        // Member 1 acks the view and the heartbeat: committed.
        let _ = m.on_msg(T0 + 2, 1, &Msg::ViewAck { epoch: first.epoch });
        let _ = m.on_msg(T0 + 2, 1, &Msg::HeartbeatAck { epoch: first.epoch, seq: 1u64 << 32 });
        assert_eq!(m.committed(), first.epoch);
        for now in (T0 + 3..T0 + 150).step_by(10) {
            let _ = m.on_tick(now);
            assert_eq!(m.view(), Some(&first), "t={now}");
        }
    }

    /// A slice whose primary is `prev` in `from` and `me` in `to`.
    fn moved_slice(m: &Membership, from: &View, to: &View, me: MemberId, prev: MemberId) -> SliceId {
        (0..64)
            .find(|s| from.primary(*s, &m.weights) == Some(prev) && to.primary(*s, &m.weights) == Some(me))
            .expect("a slice moving to me")
    }

    /// NIST-011: re-basing a pending slice onto a later view keeps the
    /// owner it is gained from and the reason; a later view that drops that
    /// owner turns it into a takeover that may start at once.
    #[test]
    fn rebase_keeps_previous_owner_and_reason() {
        let mut m = three(0);
        let v0 = View { epoch: make_epoch(1, 0), live: vec![0, 1, 2], standby: vec![], leader: 2 };
        let mut out = Vec::new();
        m.adopt(10, v0.clone(), None, &mut out);
        // Member 1 moves to standby: its slices are handed over.
        let v1 = View { epoch: make_epoch(1, 1), live: vec![0, 2], standby: vec![1], leader: 2 };
        let s = moved_slice(&m, &v0, &v1, 0, 1);
        m.adopt(20, v1.clone(), Some(v0.epoch), &mut out);
        let st = m.slices[usize::from(s)];
        assert!(
            matches!(st, SliceState::Pending { prev_owner: Some(1), reason: AcquireReason::Handover, ready_at: Some(r) } if r == 20 + m.safe_ms),
            "{st:?}"
        );
        // Another view (same owners for `s`) before activation.
        let v2 = View { epoch: make_epoch(1, 2), live: vec![0, 2], standby: vec![1], leader: 2 };
        m.adopt(30, v2.clone(), Some(v1.epoch), &mut out);
        assert_eq!(
            m.slices[usize::from(s)],
            SliceState::Pending {
                ready_at: Some(20 + m.safe_ms),
                prev_owner: Some(1),
                reason: AcquireReason::Handover
            }
        );
        // The leader drops member 1: takeover from 1, due now.
        let v3 = View { epoch: make_epoch(1, 3), live: vec![0, 2], standby: vec![], leader: 2 };
        m.adopt(40, v3, Some(v2.epoch), &mut out);
        assert_eq!(
            m.slices[usize::from(s)],
            SliceState::Pending { ready_at: Some(40), prev_owner: Some(1), reason: AcquireReason::Takeover }
        );
        // Nothing reported this node as the previous owner of a slice it
        // never held.
        assert!(!out.iter().any(|a| matches!(a, Action::Acquire { prev_owner: Some(0), .. })));
    }

    /// SEC-2: a forced manual takeover serves the gained slices only after
    /// `safe`; an unforced one at once.
    #[test]
    fn forced_manual_takeover_waits_safe() {
        let cfg = |me| MembershipConfig {
            self_id: me,
            members: vec![(0, 1), (1, 1)],
            witness: None,
            slice_count: 64,
            lease_ms: 1000,
            heartbeat_ms: 100,
            drift_margin_pct: 10,
            failback_delay_ms: 0,
            auto_failover: false,
            seed: 1,
        };
        for force in [false, true] {
            let (mut m, _) = Membership::new(cfg(0), Persisted::default(), 0).unwrap();
            let before = m.active_slices().count();
            let out = m.manual_takeover(100, 1, force).unwrap();
            let acquired = out.iter().filter(|a| matches!(a, Action::Acquire { .. })).count();
            if force {
                assert_eq!(acquired, 0, "nothing before safe");
                assert!(m.on_tick(100 + m.safe_ms() - 1).iter().all(|a| !matches!(a, Action::Acquire { .. })));
                let late = m.on_tick(100 + m.safe_ms());
                assert_eq!(late.iter().filter(|a| matches!(a, Action::Acquire { .. })).count(), 64 - before);
            } else {
                assert_eq!(acquired, 64 - before);
            }
            assert_eq!(m.active_slices().count(), 64);
        }
    }

    /// SEC-9: only the recorded previous owner can end the handover wait.
    #[test]
    fn handover_fence_only_from_previous_owner() {
        let mut m = three(0);
        let v0 = View { epoch: make_epoch(1, 0), live: vec![0, 1, 2], standby: vec![], leader: 2 };
        let mut out = Vec::new();
        m.adopt(10, v0.clone(), None, &mut out);
        let v1 = View { epoch: make_epoch(1, 1), live: vec![0, 2], standby: vec![1], leader: 2 };
        let s = moved_slice(&m, &v0, &v1, 0, 1);
        m.adopt(20, v1.clone(), Some(v0.epoch), &mut out);
        let before = m.slices[usize::from(s)];
        let fence = Msg::HandoverFence { slice: s, epoch: v1.epoch, final_seq: 0 };
        let _ = m.on_msg(30, 2, &fence);
        assert_eq!(m.slices[usize::from(s)], before, "a non-owner's fence is ignored");
        let _ = m.on_msg(30, 1, &fence);
        assert!(matches!(m.slices[usize::from(s)], SliceState::Pending { ready_at: Some(30), .. }));
    }
}
