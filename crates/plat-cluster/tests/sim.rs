//! Deterministic simulation of cluster membership: 2-5 members plus an
//! optional witness, per-node monotonic clocks running up to the drift
//! margin fast or slow, message delay and loss, crashes, restarts and
//! partitions.
//!
//! Safety, checked after every event: no slice is served by two nodes at the
//! same real instant, and no term has two leaders. Liveness: once a majority
//! is connected and stable, every slice is served within a bound.
//!
//! Every schedule comes from a fixed seed (splitmix64), so a run is
//! reproducible bit for bit; a failing seed is printed.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use plat_cluster::membership::{Action, ElectionStats, Membership, MembershipConfig, Persisted, Role};
use plat_cluster::{Msg, SliceId, View};

const SLICES: usize = 48;
const LEASE: u64 = 3000;
const HB: u64 = 500;
const MARGIN: u64 = 10;
const TICK: u64 = 10;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Ev {
    Tick(usize),
    Deliver(usize, usize, u64),
}

struct Node {
    m: Option<Membership>,
    cfg: MembershipConfig,
    persisted: Persisted,
    /// Clock rate in parts per million relative to real time.
    rate_ppm: i64,
    offset: u64,
    /// Real time until which the node is blocked in a state write
    /// (`Sim::persist_delay`); ticks and deliveries wait for it.
    busy_until: u64,
}

impl Node {
    fn local(&self, real: u64) -> u64 {
        self.offset + (real as i128 * (1_000_000 + self.rate_ppm) as i128 / 1_000_000) as u64
    }
}

struct Sim {
    now: u64,
    nodes: Vec<Node>,
    q: BinaryHeap<Reverse<(u64, u64, Ev)>>,
    msgs: Vec<Option<Msg>>,
    seq: u64,
    rng: Rng,
    /// `up[a][b]`: messages from a reach b.
    up: Vec<Vec<bool>>,
    last_delivery: Vec<Vec<u64>>,
    max_delay: u64,
    loss_pct: u64,
    /// Real time of the last time a slice had no server (liveness).
    unserved_since: Option<u64>,
    acquires: usize,
    /// Real time one `Action::Persist` takes (the driver's fsync). The node
    /// handles nothing meanwhile and the later sends of the batch leave
    /// when it is done. 0 by default.
    persist_delay: u64,
    /// Deliver messages a node sent before it crashed (already in the
    /// socket). Off by default: a crash drops them.
    deliver_after_crash: bool,
    /// Every view adopted: (real time, node, view).
    adopted: Vec<(u64, usize, View)>,
    /// Refused pre-votes delivered to their candidate.
    prevote_refusals: u64,
}

fn cfg(id: u16, members: u16, witness: bool, failback_ms: u64, seed: u64) -> MembershipConfig {
    MembershipConfig {
        self_id: id,
        members: (0..members).map(|m| (m, 1)).collect(),
        witness: witness.then_some(members),
        slice_count: SLICES,
        lease_ms: LEASE,
        heartbeat_ms: HB,
        drift_margin_pct: MARGIN,
        failback_delay_ms: failback_ms,
        auto_failover: true,
        seed: seed ^ u64::from(id).wrapping_mul(0x51_7cc1),
    }
}

impl Sim {
    fn new(seed: u64, members: u16, witness: bool, rates: &[i64], max_delay: u64, loss_pct: u64) -> Sim {
        let n = usize::from(members) + usize::from(witness);
        let mut rng = Rng(seed);
        let mut nodes = Vec::new();
        for id in 0..n {
            let c = cfg(id as u16, members, witness, 8_000, seed);
            let offset = rng.below(1_000_000_000);
            nodes.push(Node {
                m: None,
                cfg: c,
                persisted: Persisted::default(),
                rate_ppm: rates.get(id).copied().unwrap_or(0),
                offset,
                busy_until: 0,
            });
        }
        let mut s = Sim {
            now: 0,
            nodes,
            q: BinaryHeap::new(),
            msgs: Vec::new(),
            seq: 0,
            rng,
            up: vec![vec![true; n]; n],
            last_delivery: vec![vec![0; n]; n],
            max_delay,
            loss_pct,
            unserved_since: Some(0),
            acquires: 0,
            persist_delay: 0,
            deliver_after_crash: false,
            adopted: Vec::new(),
            prevote_refusals: 0,
        };
        for i in 0..n {
            s.start(i);
            let first = s.rng.below(TICK);
            s.push(first, Ev::Tick(i));
        }
        s
    }

    fn push(&mut self, at: u64, ev: Ev) {
        self.seq += 1;
        self.q.push(Reverse((at, self.seq, ev)));
    }

    fn start(&mut self, i: usize) {
        let local = self.nodes[i].local(self.now);
        let node = &mut self.nodes[i];
        let (m, acts) = match Membership::new(node.cfg.clone(), node.persisted, local) {
            Ok(x) => x,
            Err(e) => panic!("config: {e}"),
        };
        node.m = Some(m);
        self.apply(i, acts);
    }

    fn crash(&mut self, i: usize) {
        self.nodes[i].m = None;
        self.nodes[i].busy_until = 0;
        self.check();
    }

    fn dump(&self) -> String {
        let mut out = format!("t={}\n", self.now);
        for (i, n) in self.nodes.iter().enumerate() {
            let Some(m) = &n.m else {
                out += &format!("  {i}: down\n");
                continue;
            };
            let l = n.local(self.now);
            out += &format!(
                "  {i}: {:?} term={} leader={:?} view={:?} committed={:#x} lease_left={} serving={}\n",
                m.role(),
                m.term(),
                m.leader(),
                m.view(),
                m.committed(),
                m.lease_remaining(l),
                self.served_by(i)
            );
        }
        out
    }

    fn alive(&self, i: usize) -> bool {
        self.nodes[i].m.is_some()
    }

    fn isolate(&mut self, i: usize, cut: bool) {
        for j in 0..self.nodes.len() {
            if i != j {
                self.up[i][j] = !cut;
                self.up[j][i] = !cut;
            }
        }
        self.check();
    }

    fn cut(&mut self, a: usize, b: usize, cut: bool) {
        self.up[a][b] = !cut;
        self.up[b][a] = !cut;
        self.check();
    }

    fn heal(&mut self) {
        for row in &mut self.up {
            row.iter_mut().for_each(|x| *x = true);
        }
    }

    fn apply(&mut self, from: usize, acts: Vec<Action>) {
        // When the batch's sends leave: after every state write before them.
        let mut at = self.now;
        for a in acts {
            match a {
                Action::Persist(p) => {
                    self.nodes[from].persisted = p;
                    at += self.persist_delay;
                    self.nodes[from].busy_until = at;
                }
                Action::Send { to, msg } => self.send_at(at, from, usize::from(to), msg),
                Action::ViewAdopted(v) => self.adopted.push((self.now, from, v)),
                Action::Release {
                    slice,
                    epoch,
                    new_owner: Some(to),
                    reason: plat_cluster::ReleaseReason::Handover,
                } => {
                    // What the driver does after flushing replication.
                    self.send_at(at, from, usize::from(to), Msg::HandoverFence { slice, epoch, final_seq: 0 });
                }
                Action::Acquire { .. } => self.acquires += 1,
                _ => {}
            }
        }
    }

    fn send(&mut self, from: usize, to: usize, msg: Msg) {
        self.send_at(self.now, from, to, msg);
    }

    /// Send at real time `sent` (now, or when the sender's state write is
    /// done).
    fn send_at(&mut self, sent: u64, from: usize, to: usize, msg: Msg) {
        if to >= self.nodes.len() || !self.up[from][to] || self.rng.below(100) < self.loss_pct {
            return;
        }
        // FIFO per link, like the TLS stream.
        let at = (sent + 1 + self.rng.below(self.max_delay)).max(self.last_delivery[from][to]);
        self.last_delivery[from][to] = at;
        self.msgs.push(Some(msg));
        let id = (self.msgs.len() - 1) as u64;
        self.push(at, Ev::Deliver(from, to, id));
    }

    fn step(&mut self) {
        let Some(Reverse((at, _, ev))) = self.q.pop() else { return };
        self.now = at;
        match ev {
            Ev::Tick(i) => {
                let busy = self.nodes[i].busy_until;
                if busy > at {
                    // Blocked in a state write: the tick runs when it is done.
                    self.push(busy, Ev::Tick(i));
                    return;
                }
                self.push(at + TICK, Ev::Tick(i));
                let local = self.nodes[i].local(at);
                if let Some(m) = self.nodes[i].m.as_mut() {
                    let acts = m.on_tick(local);
                    self.apply(i, acts);
                }
            }
            Ev::Deliver(from, to, id) => {
                let busy = self.nodes[to].busy_until;
                if busy > at {
                    // Deferred events keep their order (same time, rising
                    // sequence numbers).
                    self.push(busy, Ev::Deliver(from, to, id));
                    return;
                }
                let msg = self.msgs[id as usize].take();
                // A link cut while the message was in flight drops it (the
                // connection resets).
                if let Some(msg) = msg
                    && self.up[from][to]
                    && (self.alive(from) || self.deliver_after_crash)
                {
                    if matches!(msg, Msg::VoteAck { pre: true, granted: false, .. }) {
                        self.prevote_refusals += 1;
                    }
                    let local = self.nodes[to].local(at);
                    if let Some(m) = self.nodes[to].m.as_mut() {
                        let acts = m.on_msg(local, from as u16, &msg);
                        self.apply(to, acts);
                    }
                }
            }
        }
        self.check();
    }

    /// Servers of every slice at the current real instant.
    fn servers(&self, slice: SliceId) -> Vec<usize> {
        (0..self.nodes.len())
            .filter(|i| {
                let n = &self.nodes[*i];
                n.m.as_ref().is_some_and(|m| m.is_serving(slice, n.local(self.now)))
            })
            .collect()
    }

    fn check(&mut self) {
        // Servers per slice, counted without allocating (this runs after
        // every event); the list is only built to report a violation.
        let mut count = [0u8; SLICES];
        for n in &self.nodes {
            let Some(m) = &n.m else { continue };
            let local = n.local(self.now);
            for (s, c) in count.iter_mut().enumerate() {
                *c += u8::from(m.is_serving(s as SliceId, local));
            }
        }
        let mut all = true;
        for (s, c) in count.iter().enumerate() {
            assert!(*c <= 1, "t={} slice {s} served by {:?}", self.now, self.servers(s as SliceId));
            all &= *c == 1;
        }
        let mut leaders: Vec<u32> = self
            .nodes
            .iter()
            .filter_map(|n| n.m.as_ref().filter(|m| m.role() == Role::Leader).map(|m| m.term()))
            .collect();
        leaders.sort_unstable();
        assert!(leaders.windows(2).all(|w| w[0] != w[1]), "t={} two leaders in one term: {leaders:?}", self.now);
        if all {
            self.unserved_since = None;
        } else if self.unserved_since.is_none() {
            self.unserved_since = Some(self.now);
        }
    }

    fn run_for(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.q.peek().is_some_and(|Reverse((t, ..))| *t <= end) {
            self.step();
        }
        self.now = end;
    }

    /// Run until every slice is served, at most `ms`; returns the time it
    /// took.
    fn until_all_served(&mut self, ms: u64) -> Option<u64> {
        let start = self.now;
        let end = start + ms;
        while self.now <= end {
            if self.unserved_since.is_none() {
                return Some(self.now - start);
            }
            if self.q.is_empty() {
                return None;
            }
            self.step();
        }
        None
    }

    fn leader(&self) -> Option<usize> {
        (0..self.nodes.len()).find(|i| self.nodes[*i].m.as_ref().is_some_and(|m| m.role() == Role::Leader))
    }

    fn served_by(&self, i: usize) -> usize {
        (0..SLICES as SliceId).filter(|s| self.servers(*s) == vec![i]).count()
    }

    /// Election counters summed over the running nodes.
    fn election_stats(&self) -> ElectionStats {
        let mut sum = ElectionStats::default();
        for st in self.nodes.iter().filter_map(|n| n.m.as_ref().map(Membership::election_stats)) {
            sum.won += st.won;
            sum.timeout += st.timeout;
            sum.yielded += st.yielded;
            sum.heartbeats_expedited += st.heartbeats_expedited;
        }
        sum
    }
}

// Derived bounds (see membership docs): safe = 3300 + 200.
const SAFE: u64 = LEASE * (100 + MARGIN) / 100 + 200;

#[test]
fn cold_start_serves_every_slice() {
    let mut s = Sim::new(1, 3, false, &[0, 50_000, -50_000], 20, 0);
    // Boot quiet (safe) + election timeout + first view wait (safe).
    let t = s.until_all_served(4 * SAFE).expect("all slices served after cold start");
    assert!(t <= 3 * SAFE, "took {t}");
    for i in 0..3 {
        let n = s.served_by(i);
        assert!((8..=24).contains(&n), "node {i} serves {n}");
    }
}

#[test]
fn member_crash_is_taken_over_within_bound() {
    let mut s = Sim::new(2, 3, false, &[], 20, 0);
    s.until_all_served(4 * SAFE).unwrap();
    s.run_for(5_000);
    let leader = s.leader().unwrap();
    let victim = (leader + 1) % 3;
    assert!(s.served_by(victim) > 0);
    s.crash(victim);
    s.run_for(1);
    let t = s.until_all_served(3 * SAFE).expect("takeover");
    // Leader drops after `safe` without an ack, proposes, commits on the
    // next heartbeat round.
    assert!(t <= SAFE + 2 * HB + 200, "member takeover took {t} ms");
    assert_eq!(s.served_by(victim), 0);
}

#[test]
fn leader_crash_is_taken_over_within_bound() {
    let rates = [90_000, -90_000, 0, 30_000];
    let delay = 30;
    let mut s = Sim::new(3, 4, false, &rates, delay, 0);
    s.until_all_served(4 * SAFE).unwrap();
    s.run_for(5_000);
    let leader = s.leader().unwrap();
    let t0 = s.now;
    s.crash(leader);
    s.until_all_served(4 * SAFE).expect("takeover");
    let t = s.now - t0;
    // Three surviving data members (at most two split rounds), slowest
    // clock 9 % slow: see `takeover_bound`.
    let bound = takeover_bound(2, 90_000, delay, 0);
    assert!(t <= bound, "leader takeover took {t} ms, bound {bound} ms");
    assert_ne!(s.leader(), Some(leader));
}

#[test]
fn two_nodes_with_witness_survive_either_member() {
    for victim in 0..2 {
        let mut s = Sim::new(10 + victim as u64, 2, true, &[100_000, -100_000, 0], 25, 0);
        s.until_all_served(4 * SAFE).unwrap();
        s.run_for(3_000);
        s.crash(victim);
        s.run_for(1);
        s.until_all_served(3 * SAFE).expect("survivor takes every slice");
        assert_eq!(s.served_by(1 - victim), SLICES);
    }
}

#[test]
fn peer_link_partition_with_witness_has_one_winner() {
    let mut s = Sim::new(20, 2, true, &[0, 0, 0], 20, 0);
    s.until_all_served(4 * SAFE).unwrap();
    s.run_for(2_000);
    s.cut(0, 1, true);
    // The invariant is checked on every event; afterwards exactly one
    // member serves everything or both keep serving disjoint slices.
    s.run_for(20_000);
    let a = s.served_by(0);
    let b = s.served_by(1);
    assert_eq!(a + b, SLICES, "every slice served, {a} + {b}");
    let leader = s.leader().unwrap();
    s.run_for(20_000);
    assert_eq!(s.leader(), Some(leader), "no leadership churn while the cut lasts");
}

#[test]
fn isolated_member_fences_then_fails_back() {
    let mut s = Sim::new(30, 3, false, &[0, 0, 0], 20, 0);
    s.until_all_served(4 * SAFE).unwrap();
    s.run_for(2_000);
    let leader = s.leader().unwrap();
    let victim = (leader + 2) % 3;
    let before = s.served_by(victim);
    assert!(before > 0);
    s.isolate(victim, true);
    // The isolated member stops serving on its own lease.
    s.run_for(LEASE);
    assert_eq!(s.served_by(victim), 0, "self-fenced within the lease");
    s.until_all_served(3 * SAFE).expect("takeover of the isolated member");
    s.isolate(victim, false);
    // Rejoins as standby, promoted after failback_delay (8 s), handover.
    s.run_for(8_000 + 4 * SAFE);
    assert_eq!(s.served_by(victim), before, "failback restored the original slices");
    s.until_all_served(SAFE).expect("all served after failback");
}

#[test]
fn restart_does_not_reuse_epochs() {
    let mut s = Sim::new(40, 3, false, &[], 15, 0);
    s.until_all_served(4 * SAFE).unwrap();
    let leader = s.leader().unwrap();
    let term = s.nodes[leader].persisted.term;
    s.crash(leader);
    s.run_for(2_000);
    s.start(leader);
    s.run_for(30_000);
    let p = s.nodes[leader].persisted;
    assert!(p.term > term);
    s.until_all_served(SAFE).expect("all served after restart");
}

/// Random schedules: crashes, restarts, isolations, single-link cuts,
/// loss and delay, clocks up to the margin fast or slow. Then heal and
/// require full service.
#[test]
fn random_schedules_are_safe_and_live() {
    let seeds: u64 = std::env::var("PLAT_SIM_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(48);
    for seed in 0..seeds {
        run_random(seed);
    }
}

fn run_random(seed: u64) {
    let mut r = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) ^ 0xa5a5);
    let members = 2 + r.below(4) as u16;
    let witness = members == 2 || r.below(2) == 0;
    let n = usize::from(members) + usize::from(witness);
    let rates: Vec<i64> = (0..n).map(|_| r.below(200_001) as i64 - 100_000).collect();
    let delay = 1 + r.below(80);
    let loss = r.below(4);
    let mut s = Sim::new(seed, members, witness, &rates, delay, loss);
    let schedule = std::panic::AssertUnwindSafe(|| {
        s.run_for(r.below(15_000));
        for _ in 0..(4 + r.below(8)) {
            let who = r.below(n as u64) as usize;
            match r.below(6) {
                0 => s.crash(who),
                1 if !s.alive(who) => s.start(who),
                2 => s.isolate(who, true),
                3 => s.isolate(who, false),
                4 => {
                    let other = r.below(n as u64) as usize;
                    if other != who {
                        s.cut(who, other, r.below(2) == 0);
                    }
                }
                _ => s.heal(),
            }
            s.run_for(r.below(4 * LEASE));
        }
        s.heal();
        s.loss_pct = 0;
        for i in 0..n {
            if !s.alive(i) {
                s.start(i);
            }
        }
        // Boot quiet, election, standby promotion (8 s) and handovers.
        let t = s.until_all_served(8_000 + 6 * SAFE);
        assert!(t.is_some(), "not every slice served after healing\n{}", s.dump());
        s.run_for(8_000 + 4 * SAFE);
        assert!(s.unserved_since.is_none(), "service lost while stable");
        assert!(s.leader().is_some());
    });
    if let Err(e) = std::panic::catch_unwind(schedule) {
        eprintln!("simulation seed {seed} failed (members={members} witness={witness} rates={rates:?})");
        std::panic::resume_unwind(e);
    }
}

#[test]
fn simulation_is_deterministic() {
    let run = || {
        let mut s = Sim::new(77, 3, true, &[60_000, -60_000, 0, 10_000], 40, 2);
        s.run_for(20_000);
        s.crash(0);
        s.run_for(15_000);
        s.start(0);
        s.run_for(30_000);
        (s.acquires, s.seq, (0..4).map(|i| s.nodes[i].persisted).collect::<Vec<_>>())
    };
    assert_eq!(run(), run());
}

/// Failback moves slices from a live owner to the rejoined member. When the
/// old owner stops hearing the leader right before the view change, the new
/// owner must still wait out the old owner's lease.
#[test]
fn handover_waits_for_an_unreachable_old_owner() {
    for (k, cut_at) in (6_000..10_000).step_by(200).enumerate() {
        for pick in 0..2 {
            let mut s = Sim::new(100 + k as u64, 4, false, &[0, 0, 0, 0], 10, 0);
            s.until_all_served(4 * SAFE).unwrap();
            s.run_for(2_000);
            let leader = s.leader().unwrap();
            let x = (leader + 1) % 4;
            s.isolate(x, true);
            s.run_for(2 * SAFE);
            s.until_all_served(3 * SAFE).unwrap();
            assert!(!s.nodes[leader].m.as_ref().unwrap().view().unwrap().is_live(x as u16));
            s.isolate(x, false);
            s.run_for(cut_at);
            // One old owner loses the leader around the promotion; the rest
            // still form a majority that commits the view.
            let a = (leader + 2 + pick) % 4;
            s.cut(a, leader, true);
            s.run_for(2 * SAFE);
        }
    }
}

/// B-3 (CP-10): with `failback_needs_sync`, a rejoined member stays standby
/// past `failback_delay` until it reports its backup copies in sync for the
/// current view; then it fails back.
#[test]
fn failback_waits_for_backup_sync() {
    let mut s = Sim::new(31, 3, false, &[0, 0, 0], 20, 0);
    for n in &mut s.nodes {
        if let Some(m) = n.m.as_mut() {
            m.set_failback_needs_sync(true);
        }
    }
    s.until_all_served(4 * SAFE).unwrap();
    s.run_for(2_000);
    let leader = s.leader().unwrap();
    let victim = (leader + 2) % 3;
    let before = s.served_by(victim);
    assert!(before > 0);
    s.isolate(victim, true);
    s.run_for(LEASE);
    s.until_all_served(3 * SAFE).expect("takeover of the isolated member");
    s.isolate(victim, false);
    s.run_for(8_000 + 4 * SAFE);
    assert_eq!(s.served_by(victim), 0, "no failback before the member is in sync");
    // A stale report (an older view) does not count.
    let epoch = s.nodes[victim].m.as_ref().and_then(|m| m.view().map(|v| v.epoch)).unwrap();
    s.send(victim, leader, Msg::SyncStatus { epoch: epoch - 1, in_sync: true });
    s.run_for(2_000);
    assert_eq!(s.served_by(victim), 0);
    for _ in 0..4 {
        let epoch = s.nodes[victim].m.as_ref().and_then(|m| m.view().map(|v| v.epoch)).unwrap();
        for to in 0..3 {
            if to != victim {
                s.send(victim, to, Msg::SyncStatus { epoch, in_sync: true });
            }
        }
        s.run_for(1_000);
    }
    s.run_for(4 * SAFE);
    assert_eq!(s.served_by(victim), before, "failback once in sync");
}

/// B-7: a rejoined member that reports in sync at once (every 250 ms, as
/// platd does) is promoted `failback_delay` after it became standby, within
/// one report period and a heartbeat, not after a second delay.
#[test]
fn failback_promotes_within_delay_once_in_sync() {
    const SYNC_PERIOD: u64 = 250;
    let mut s = Sim::new(37, 3, false, &[0, 0, 0], 20, 0);
    for n in &mut s.nodes {
        if let Some(m) = n.m.as_mut() {
            m.set_failback_needs_sync(true);
        }
    }
    s.until_all_served(4 * SAFE).unwrap();
    s.run_for(2_000);
    let leader = s.leader().unwrap();
    let victim = (leader + 1) % 3;
    s.isolate(victim, true);
    s.run_for(LEASE);
    s.until_all_served(3 * SAFE).expect("takeover of the isolated member");
    s.isolate(victim, false);
    let view = |s: &Sim| s.nodes[leader].m.as_ref().and_then(|m| m.view().cloned()).unwrap();
    let mut standby_at = None;
    let mut live_at = None;
    let end = s.now + 8_000 + 6 * SAFE;
    while s.now < end && live_at.is_none() {
        let v = view(&s);
        if standby_at.is_none() && v.is_standby(victim as u16) {
            standby_at = Some(s.now);
        }
        if v.is_live(victim as u16) {
            live_at = Some(s.now);
            break;
        }
        if let Some(epoch) = s.nodes[victim].m.as_ref().and_then(|m| m.view().map(|v| v.epoch)) {
            for to in 0..3 {
                if to != victim {
                    s.send(victim, to, Msg::SyncStatus { epoch, in_sync: true });
                }
            }
        }
        s.run_for(SYNC_PERIOD);
    }
    let (Some(a), Some(b)) = (standby_at, live_at) else { panic!("no failback: {}", s.dump()) };
    let took = b - a;
    assert!(took >= 8_000, "promoted before failback_delay: {took} ms");
    assert!(took <= 8_000 + SYNC_PERIOD + HB, "promotion {took} ms after standby, more than delay + one sync period");
}

// ------------------------------------------------- leader-crash takeover

/// Clock rates of a leader-crash trial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rates {
    Zero,
    /// Each node within +-100 ppm.
    Ppm100,
    /// Each node anywhere within the drift margin.
    Margin,
    /// Every node the full margin slow.
    AllSlow,
    /// Every node the full margin fast.
    AllFast,
}

const ALL_RATES: [Rates; 5] = [Rates::Zero, Rates::Ppm100, Rates::Margin, Rates::AllSlow, Rates::AllFast];
const MARGIN_PPM: u64 = MARGIN * 10_000;

/// One leader-crash trial: its parameters, all derived from the seed.
#[derive(Debug, Clone)]
struct Trial {
    seed: u64,
    members: u16,
    witness: bool,
    rates: Vec<i64>,
    delay: u64,
    /// Crash time after 5 s of stable service (phase within two heartbeats).
    phase: u64,
    persist_delay: u64,
    deliver_after_crash: bool,
}

impl Trial {
    fn new(seed: u64, members: u16, witness: bool, mode: Rates, delay: u64) -> Trial {
        let mut r = Rng(seed.wrapping_mul(0x9e37_79b9) ^ 0x51ed);
        let n = usize::from(members) + usize::from(witness);
        let rates = (0..n)
            .map(|_| match mode {
                Rates::Zero => 0,
                Rates::Ppm100 => r.below(201) as i64 - 100,
                Rates::Margin => r.below(2 * MARGIN_PPM + 1) as i64 - MARGIN_PPM as i64,
                Rates::AllSlow => -(MARGIN_PPM as i64),
                Rates::AllFast => MARGIN_PPM as i64,
            })
            .collect();
        let phase = r.below(2 * HB);
        Trial { seed, members, witness, rates, delay, phase, persist_delay: 0, deliver_after_crash: false }
    }

    /// `r` of the bound, in ppm: how slow the slowest clock of the trial is.
    fn slow_ppm(&self) -> u64 {
        self.rates.iter().map(|r| (-*r).max(0) as u64).max().unwrap_or(0)
    }

    /// `k` of the bound: surviving data members minus one.
    fn split_rounds(&self) -> u64 {
        u64::from(self.members).saturating_sub(2)
    }

    fn bound(&self) -> u64 {
        takeover_bound(self.split_rounds(), self.slow_ppm(), self.delay, self.persist_delay)
    }
}

/// What a leader-crash trial measured.
struct Outcome {
    /// Crash until every slice is served again (real ms).
    took: u64,
    /// New leader's election until every slice is served again.
    after_election: u64,
    old_leader: usize,
    new_leader: usize,
    /// Election counters of the survivors: after the crash minus before.
    timeouts: u64,
    yields: u64,
    prevote_refusals: u64,
    sim: Sim,
}

/// The bound on "leader crash until every slice is served again" in real
/// ms: plan A.5 `B_new` with the driver's adoption time `A = 0` (the
/// simulation counts a slice as served when `Membership` says so) and the
/// state-write coefficients counted from the code (fix round 0):
///
/// ```text
///   D + (safe + H/2)/(1-r) + tick      last follower fired, every promise ran out
/// + 4D + 3F                            pre-vote, vote
/// + k * (R/(1-r) + tick + 4D + 3F)     k split rounds, R = H/2
/// + 3D + 3F + tick                     view and n0 acked, expedited n0+1 with the commit
/// ```
///
/// `k`: split rounds, `r`: slowest clock in ppm, `d`: maximum one-way
/// delay, `f`: time of one state write. The sim, like `Ctl::exec`, writes
/// once per `Action::Persist` and sends the rest of the batch afterwards.
///
/// State writes on the critical path (`membership.rs`):
/// - pre-vote: none (`start_pre_vote` and a pre-vote grant persist nothing);
/// - vote, 3F: candidate `start_election` (term and own vote) 1, then the
///   voter that completes the majority, in one batch, `observe_term` (new
///   term) 1 and `on_vote` (`voted_for`) 1;
/// - each split round, 3F: the same three writes again (a new
///   `start_election`, and a voter that sees the new term);
/// - view commit and first lease, 3F: new leader `propose` (view epoch) 1
///   before `ViewPropose` and the first heartbeat leave; then a follower
///   in `on_propose` writes once (`adopt`) if it voted in this term, twice
///   (`observe_term` in `follow`, then `adopt`) if it did not, before its
///   `ViewAck`/`HeartbeatAck`. The last follower to be leased can be a
///   non-voter, so 2. The commit needs a majority of those acks, which
///   carry the same writes, and the expedited `n0+1` is sent without one
///   (`leader_tick` and the follower's `on_heartbeat` persist nothing).
///
/// The plan's version charged `2F` for the vote and `F` for the lease step;
/// seed 26 (2 + witness, zero drift, 2 ms, `F = 20`) exceeded it by 13 ms.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: CP-10 (System Recovery and Reconstitution), SC-5(2)
///   (capacity and redundancy) - the membership part of the recovery time
///   after a leader crash, simulated. It excludes the slice-adoption time
///   `A` (`State::adopt_slice` in the driver), which is not bounded at scale:
///   the `adopt_slice` bench measured more than 50 ms above about 130k BIBs
///   (PERF-001, tracked separately). Not a statement about the driver, the
///   network or routing
fn takeover_bound(k: u64, r_ppm: u64, d: u64, f: u64) -> u64 {
    // A local interval on a clock `r` slow, in real ms (rounded up).
    let real = |local: u64| (local * 1_000_000).div_ceil(1_000_000 - r_ppm);
    let fire = d + real(SAFE + HB / 2) + TICK;
    let vote = 4 * d + 3 * f;
    let split = real(HB / 2) + TICK + 4 * d + 3 * f;
    let lease = 3 * d + 3 * f + TICK;
    fire + vote + k * split + lease
}

/// Cold start, 5 s plus the phase of stable service, crash the leader,
/// run until every slice is served again (at most `12 * safe`).
fn leader_crash(t: &Trial) -> Result<Outcome, String> {
    let mut s = Sim::new(t.seed, t.members, t.witness, &t.rates, t.delay, 0);
    s.persist_delay = t.persist_delay;
    s.deliver_after_crash = t.deliver_after_crash;
    s.until_all_served(8 * SAFE).ok_or_else(|| format!("{t:?}: no service after cold start\n{}", s.dump()))?;
    s.run_for(5_000 + t.phase);
    if s.unserved_since.is_some() {
        return Err(format!("{t:?}: not stable before the crash\n{}", s.dump()));
    }
    let old_leader = s.leader().ok_or_else(|| format!("{t:?}: no leader before the crash"))?;
    let before = s.election_stats();
    let own = s.nodes[old_leader].m.as_ref().map_or(ElectionStats::default(), Membership::election_stats);
    let refusals = s.prevote_refusals;
    let t0 = s.now;
    s.crash(old_leader);
    let mut elected = None;
    while s.unserved_since.is_some() {
        if s.now > t0 + 12 * SAFE || s.q.is_empty() {
            return Err(format!("{t:?}: not every slice served {} ms after the crash\n{}", s.now - t0, s.dump()));
        }
        s.step();
        if elected.is_none() && s.leader().is_some() {
            elected = Some(s.now);
        }
    }
    let after = s.election_stats();
    let new_leader = s.leader().ok_or_else(|| format!("{t:?}: served without a leader\n{}", s.dump()))?;
    Ok(Outcome {
        took: s.now - t0,
        after_election: s.now - elected.unwrap_or(t0),
        old_leader,
        new_leader,
        timeouts: after.timeout - (before.timeout - own.timeout),
        yields: after.yielded - (before.yielded - own.yielded),
        prevote_refusals: s.prevote_refusals - refusals,
        sim: s,
    })
}

/// (members, witness, rates, delay, state-write time) of a bound-test cell.
type CellKey = (u16, bool, Rates, u64, u64);

/// State-write times (ms) of the bound test.
const PERSIST_DELAYS: [u64; 3] = [0, 20, 50];

const TOPOLOGIES: [(u16, bool); 5] = [(2, true), (3, false), (3, true), (4, false), (5, false)];

/// The takeover bound over topologies, clock rates, delays and crash
/// phases. What is asserted: with no fault other than the crash, no loss,
/// one-way delay at most `d` and clocks within the drift margin, every
/// slice is served again within `takeover_bound(k = S - 1, r, d, f)` of the
/// crash, `S` being the surviving data members, `r` the slowest clock of
/// the trial and `f` the time of one state write (`PERSIST_DELAYS`). Odd
/// seeds also deliver what the leader had sent before it crashed (the
/// leading `D` of the bound). Seeds per cell: 50 with `f = 0` and 17 with
/// `f > 0` by default (`make test`); `PLAT_SIM_SEEDS=n` raises it to `n`
/// and `n / 3` (300 or more for the nightly job).
///
/// Not covered: the driver's adoption time, a state write whose time
/// varies, loss, and a second fault. The bound itself is above 5 s in some cells
/// (4 data members at the full margin with 30 ms delay; 5 data members
/// with 30 ms delay or at the full margin): this test asserts the formula,
/// not 5 s.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: CP-10 (System Recovery and Reconstitution), SC-5(2) -
///   recovery time after a leader crash; SC-24 (Fail in Known State) - the
///   invariants of `Sim::check` hold on every event of every trial
#[test]
fn leader_crash_bound_holds_across_topologies() {
    let seeds: u64 = std::env::var("PLAT_SIM_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(0).max(50);
    let mut cells = Vec::new();
    for (members, witness) in TOPOLOGIES {
        for mode in ALL_RATES {
            for delay in [2u64, 30] {
                for f in PERSIST_DELAYS {
                    cells.push((members, witness, mode, delay, f));
                }
            }
        }
    }
    // (worst time, its seed, its bound) and the violations of one cell.
    type Cell = ((u64, u64, u64), Vec<String>);
    let run_cell = |&(members, witness, mode, delay, f): &CellKey| -> Cell {
        let mut worst = (0, 0, 0);
        let mut bad = Vec::new();
        let n = if f == 0 { seeds } else { seeds.div_ceil(3) };
        for seed in 0..n {
            let mut t = Trial::new(seed, members, witness, mode, delay);
            t.persist_delay = f;
            t.deliver_after_crash = seed % 2 == 1;
            let bound = t.bound();
            match leader_crash(&t) {
                Ok(o) => {
                    if o.took > worst.0 {
                        worst = (o.took, seed, bound);
                    }
                    if o.took > bound {
                        bad.push(format!("{t:?} ({mode:?}): took {} ms, bound {bound} ms", o.took));
                    }
                }
                Err(e) => bad.push(e),
            }
        }
        (worst, bad)
    };
    // The cells are independent simulations: spread them over the cores.
    let next = std::sync::atomic::AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map_or(1, usize::from).min(cells.len());
    let mut results: Vec<(usize, Cell)> = std::thread::scope(|sc| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                sc.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(cell) = cells.get(i) else { break done };
                        done.push((i, run_cell(cell)));
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| match h.join() {
                Ok(v) => v,
                // An invariant of `Sim::check` failed inside a trial.
                Err(e) => std::panic::resume_unwind(e),
            })
            .collect()
    });
    results.sort_by_key(|r| r.0);
    let mut bad = Vec::new();
    for (_, (_, b)) in &results {
        bad.extend(b.iter().cloned());
    }
    // Worst case per topology and state-write time; then per drift mode.
    let report = |label: &str, keep: &dyn Fn(&CellKey) -> bool| {
        let mut worst = (0, 0, 0);
        let mut at = None;
        for (i, (w, _)) in &results {
            if keep(&cells[*i]) && w.0 > worst.0 {
                worst = *w;
                at = Some(cells[*i]);
            }
        }
        println!("leader crash, {label}: worst {} ms (bound {} ms, seed {}, {at:?})", worst.0, worst.2, worst.1);
    };
    for (members, witness) in TOPOLOGIES {
        for f in PERSIST_DELAYS {
            let n = if f == 0 { seeds } else { seeds.div_ceil(3) };
            let w = if witness { " + witness" } else { "" };
            report(&format!("{members} members{w}, F {f} ms, {n} seeds per cell"), &|c| {
                (c.0, c.1, c.4) == (members, witness, f)
            });
            for mode in [Rates::Margin, Rates::AllSlow] {
                report(&format!("{members} members{w}, F {f} ms, {mode:?}"), &|c| {
                    (c.0, c.1, c.2, c.4) == (members, witness, mode, f)
                });
            }
        }
    }
    assert!(bad.is_empty(), "{} trials outside the bound:\n{}", bad.len(), bad.join("\n"));
}

/// R1: two followers that campaign within one delivery time of each other
/// split the vote. The higher id yields, the lower id's round times out
/// after `heartbeat / 2` and its next round wins: one extra round. Seed 7
/// is such a schedule; seed 99 is the one that took 13.1 s when a split
/// cost two election timeouts (plan A.3).
#[test]
fn split_vote_costs_one_round() {
    let t = Trial::new(7, 3, false, Rates::Zero, 2);
    let o = leader_crash(&t).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((o.yields, o.timeouts), (1, 1), "seed 7 no longer splits the vote: pin another seed");
    assert!(o.took <= takeover_bound(1, 0, t.delay, 0), "split vote: {} ms", o.took);

    let t = Trial::new(99, 3, false, Rates::Zero, 2);
    assert_eq!(t.phase, 191, "the trial derivation changed: seed 99 is no longer the recorded schedule");
    let o = leader_crash(&t).unwrap_or_else(|e| panic!("{e}"));
    assert!(o.took <= takeover_bound(1, 0, t.delay, 0), "seed 99: {} ms", o.took);
}

/// R2: with a witness only one member campaigns. A pre-vote that reaches
/// the other voter before its lease promise ran out (later ack, or a slower
/// clock) is refused; the pre-candidate asks again instead of backing off
/// for two election timeouts. Margin seed 168 took 11.9 s and 100 ppm seed
/// 749 took 10.9 s before (plan A.3); seed 168 and (100 ppm, 30 ms) seed 12
/// still see refusals.
#[test]
fn refused_early_prevote_recovers_with_witness() {
    for (seed, mode, delay, refused) in
        [(168, Rates::Margin, 2, true), (749, Rates::Ppm100, 2, false), (12, Rates::Ppm100, 30, true)]
    {
        let t = Trial::new(seed, 2, true, mode, delay);
        let o = leader_crash(&t).unwrap_or_else(|e| panic!("{e}"));
        if refused {
            assert!(o.prevote_refusals > 0, "seed {seed} no longer has a refused pre-vote: pin another seed");
        }
        assert_eq!((o.timeouts, o.yields), (0, 0), "seed {seed}: one campaigner cannot split the vote");
        assert!(o.took <= t.bound(), "seed {seed}: {} ms, bound {} ms", o.took, t.bound());
    }
    let t = Trial::new(168, 2, true, Rates::Margin, 2);
    assert_eq!((t.rates.as_slice(), t.phase), ([-69_495, 77_184, -92_122].as_slice(), 513), "trial derivation changed");
}

/// C1: the new leader's first view drops the crashed leader, and nothing
/// puts it back: `last_ack_recv` starting at the election time does not
/// make a member that never answered in this term reachable. Exactly one
/// view of the new term from the crash until well after `safe`.
#[test]
fn new_leader_does_not_readd_the_crashed_leader() {
    for members in [3u16, 4, 5] {
        for seed in 0..8 {
            let t = Trial::new(seed, members, false, Rates::Zero, 20);
            let mut o = leader_crash(&t).unwrap_or_else(|e| panic!("{e}"));
            o.sim.run_for(2 * SAFE);
            let term = o.sim.nodes[o.new_leader].m.as_ref().map_or(0, Membership::term);
            let views: Vec<&View> = o
                .sim
                .adopted
                .iter()
                .filter(|(_, node, v)| *node == o.new_leader && plat_cluster::term_of(v.epoch) == term)
                .map(|(_, _, v)| v)
                .collect();
            assert_eq!(views.len(), 1, "members {members} seed {seed}: {views:?}");
            let old = o.old_leader as u16;
            assert!(!views[0].is_live(old) && !views[0].is_standby(old), "{:?}", views[0]);
            assert_eq!(views[0].live.len(), usize::from(members) - 1);
            assert!(o.sim.unserved_since.is_none(), "service lost after the takeover\n{}", o.sim.dump());
        }
    }
}

/// C2 and C3: once a leader is elected, every slice (the survivors' own
/// included) is served again after the view and first heartbeat, their
/// acks, and the expedited next heartbeat: three deliveries and a tick, not
/// one or two heartbeat periods.
#[test]
fn follower_lease_follows_the_election_without_a_heartbeat_period() {
    for members in [3u16, 4, 5] {
        for delay in [2u64, 30] {
            let limit = 3 * delay + TICK;
            assert!(limit < HB);
            for seed in 0..20 {
                let t = Trial::new(seed, members, false, Rates::Zero, delay);
                let o = leader_crash(&t).unwrap_or_else(|e| panic!("{e}"));
                assert!(
                    o.after_election <= limit,
                    "members {members} delay {delay} seed {seed}: served {} ms after the election, limit {limit} ms",
                    o.after_election
                );
                let st = o.sim.nodes[o.new_leader].m.as_ref().map(Membership::election_stats).unwrap_or_default();
                assert!(st.heartbeats_expedited > 0);
            }
        }
    }
}

/// C5: with a state write of 150 ms the first candidate round (250 ms)
/// cannot finish: the candidate writes once and each voter twice before
/// the ack leaves. The round length doubles, so the second round does.
/// With a fixed round no leader is ever elected (checked by hand while
/// writing this test). `2 * safe` is a ceiling for this test, not a bound
/// that is claimed anywhere.
#[test]
fn slow_persist_does_not_livelock_the_election() {
    for members in [3u16, 4] {
        for seed in 0..10 {
            let mut t = Trial::new(seed, members, false, Rates::Zero, 2);
            t.persist_delay = 150;
            let o = leader_crash(&t).unwrap_or_else(|e| panic!("{e}"));
            assert!(o.timeouts >= 1, "members {members} seed {seed}: the first round was expected to time out");
            assert!(o.took <= 2 * SAFE, "members {members} seed {seed}: {} ms", o.took);
        }
    }
}
