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

use plat_cluster::membership::{Action, Membership, MembershipConfig, Persisted, Role};
use plat_cluster::{Msg, SliceId};

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
        for a in acts {
            match a {
                Action::Persist(p) => self.nodes[from].persisted = p,
                Action::Send { to, msg } => self.send(from, usize::from(to), msg),
                Action::Release {
                    slice,
                    epoch,
                    new_owner: Some(to),
                    reason: plat_cluster::ReleaseReason::Handover,
                } => {
                    // What the driver does after flushing replication.
                    self.send(from, usize::from(to), Msg::HandoverFence { slice, epoch, final_seq: 0 });
                }
                Action::Acquire { .. } => self.acquires += 1,
                _ => {}
            }
        }
    }

    fn send(&mut self, from: usize, to: usize, msg: Msg) {
        if to >= self.nodes.len() || !self.up[from][to] || self.rng.below(100) < self.loss_pct {
            return;
        }
        // FIFO per link, like the TLS stream.
        let at = (self.now + 1 + self.rng.below(self.max_delay)).max(self.last_delivery[from][to]);
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
                self.push(at + TICK, Ev::Tick(i));
                let local = self.nodes[i].local(at);
                if let Some(m) = self.nodes[i].m.as_mut() {
                    let acts = m.on_tick(local);
                    self.apply(i, acts);
                }
            }
            Ev::Deliver(from, to, id) => {
                let msg = self.msgs[id as usize].take();
                // A link cut while the message was in flight drops it (the
                // connection resets).
                if let Some(msg) = msg
                    && self.up[from][to]
                    && self.alive(from)
                {
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
        let mut all = true;
        for s in 0..SLICES as SliceId {
            let srv = self.servers(s);
            assert!(srv.len() <= 1, "t={} slice {s} served by {srv:?}", self.now);
            all &= srv.len() == 1;
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
    let mut s = Sim::new(3, 4, false, &[90_000, -90_000, 0, 30_000], 30, 0);
    s.until_all_served(4 * SAFE).unwrap();
    s.run_for(5_000);
    let leader = s.leader().unwrap();
    s.crash(leader);
    s.run_for(1);
    let t = s.until_all_served(4 * SAFE).expect("takeover");
    // Election timeout (safe + < 2 hb jitter) + pre-vote/vote + one lease
    // round trip + commit.
    assert!(t <= SAFE + 5 * HB + 200, "leader takeover took {t} ms");
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
