//! Incremental sweeper (POAM-012): per-shard due hints, chunked lock holds,
//! per-pass budget with a resume cursor, and expiry timing (SC-10).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::*;
use plat_common::Counters;
use plat_nat64::state::{Key4, Key6, State, SweepStats};
use plat_packet::proto;

const SERVER: u32 = 0xc633_6407; // 198.51.100.7
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const RST: u8 = 0x04;
const UDP_S: u64 = 300;
const TCP_TRANS_S: u64 = 240;

/// Few shards, so chunks and cursors cross many entries per shard.
const FOUR_SHARDS: (&str, &str) = ("table_shards = 1024", "table_shards = 4");

/// Opens `n` UDP flows of subscriber `s` (one BIB each, `per` sessions).
fn flows(st: &State, s: u16, n: u16, per: u16) -> Vec<(Key4, (u32, u16))> {
    let c = Counters::default();
    let mut out = Vec::new();
    for p in 0..n {
        let k6 = Key6 { proto: proto::UDP, addr: sub(s, 1), port: 1000 + p };
        let m = st.bib_for(k6, true, &c, &None).unwrap();
        for r in 0..per {
            st.outbound(m.k4, (SERVER, 53 + r), 0, &c).unwrap();
            out.push((m.k4, (SERVER, 53 + r)));
        }
    }
    out
}

/// Runs zero-budget passes (one shard each) until a cycle completes.
fn budgeted_cycle(st: &State) -> (SweepStats, u32) {
    let mut sum = SweepStats::default();
    for passes in 1.. {
        let s = st.sweep_budget(None, Duration::ZERO);
        sum.sessions_expired += s.sessions_expired;
        sum.bibs_removed += s.bibs_removed;
        sum.blocks_released += s.blocks_released;
        sum.shards_visited += s.shards_visited;
        sum.shards_skipped += s.shards_skipped;
        if s.complete {
            return (sum, passes);
        }
    }
    unreachable!()
}

#[test]
fn chunked_sweep_expires_every_entry_at_its_time() {
    let fx = fixture(&[FOUR_SHARDS]);
    let st = fx.nat.state();
    st.set_sweep_chunk(1);
    flows(st, 1, 200, 3);
    flows(st, 2, 100, 1);
    assert_eq!(st.session_count(), 700);
    fx.clock.advance(Duration::from_millis(UDP_S * 1000 - 1));
    assert_eq!(st.sweep().sessions_expired, 0, "not yet");
    fx.clock.advance(Duration::from_millis(1));
    let s = st.sweep();
    assert_eq!(s.sessions_expired, 700);
    assert!(s.complete);
    assert_eq!(st.session_count(), 0);
    fx.clock.advance(Duration::from_secs(2));
    assert_eq!(st.sweep().bibs_removed, 300);
    assert_eq!(st.bib6.len() + st.bib4.len(), 0);
    fx.clock.advance(Duration::from_secs(60));
    assert!(st.sweep().blocks_released >= 2);
    assert_eq!(st.subscriber_count(), 0);
    assert_eq!(st.aggregate_count(sub(1, 1)), 0);
}

#[test]
fn shards_with_nothing_due_are_skipped_without_work() {
    let fx = fixture(&[]);
    let st = fx.nat.state();
    let keys = flows(st, 1, 8, 2);
    // New BIBs and subscribers make their shards due once.
    let first = st.sweep();
    assert!(first.shards_visited > 0);
    let idle = st.sweep();
    assert_eq!(idle.shards_visited, 0);
    assert_eq!(idle.shards_skipped, st.bib4.shard_count() as u64 + 1024, "every bib4 and subs shard");
    assert_eq!(st.bib4.shard_count(), 1024 * 16);
    assert_eq!(idle.max_hold_ns, 0, "no lock taken");
    // A new session on an existing BIB is due at its expiry, not now.
    let c = Counters::default();
    let (k4, _) = keys[0];
    st.outbound(k4, (SERVER, 9999), 0, &c).unwrap();
    assert_eq!(st.sweep().shards_visited, 0);
    // Steady-state refreshes never make a shard due.
    fx.clock.advance(Duration::from_secs(100));
    for (k4, r) in &keys {
        st.outbound(*k4, *r, 0, &c).unwrap();
    }
    assert_eq!(st.sweep().shards_visited, 0);
    // The refreshed sessions now expire 100 s after the new one.
    fx.clock.advance(Duration::from_secs(UDP_S + 1 - 100));
    let s = st.sweep();
    assert_eq!(s.sessions_expired, 1);
    // Refreshes left the hints at the old expiry (a lower bound): the
    // shards are walked once and their hints recomputed.
    assert!(s.shards_visited >= 1);
    assert_eq!(st.sweep().shards_visited, 0, "hints raised to the refreshed expiry");
    fx.clock.advance(Duration::from_secs(100));
    assert_eq!(st.sweep().sessions_expired, 16);
}

#[test]
fn tcp_transition_to_a_shorter_timer_lowers_the_hint() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let out = run(&mut fx, &tcp6(s, 4000, SERVER, 443, SYN)).unwrap();
    let (a, p) = (plat_packet::be32(&out, 12), plat_packet::be16(&out, 20));
    run(&mut fx, &tcp4(SERVER, 443, a, p, SYN | ACK)).unwrap();
    run(&mut fx, &tcp6(s, 4000, SERVER, 443, ACK)).unwrap();
    let st = fx.nat.state();
    st.sweep();
    assert_eq!(st.sweep().shards_visited, 0, "ESTABLISHED: due in TCP_EST");
    // RST: established timer (7440 s) to transitory (240 s).
    run(&mut fx, &tcp6(s, 4000, SERVER, 443, RST)).unwrap();
    fx.clock.advance(Duration::from_secs(TCP_TRANS_S + 1));
    assert_eq!(fx.nat.state().sweep().sessions_expired, 1);
}

#[test]
fn budgeted_passes_resume_and_expire_everything() {
    let fx = fixture(&[FOUR_SHARDS]);
    let st = fx.nat.state();
    st.set_sweep_chunk(3);
    flows(st, 1, 50, 2);
    fx.clock.advance(Duration::from_secs(UDP_S + 1));
    let (s, passes) = budgeted_cycle(st);
    assert_eq!(s.sessions_expired, 100);
    assert_eq!(passes, 4 * 16 + 4, "one shard per zero-budget pass: 64 bib4 + 4 subs");
    assert_eq!(st.sweep_resumed_total(), 4 * 16 + 3);
    assert_eq!(st.session_count(), 0);
    fx.clock.advance(Duration::from_secs(2));
    assert_eq!(budgeted_cycle(st).0.bibs_removed, 50);
    fx.clock.advance(Duration::from_secs(60));
    assert_eq!(budgeted_cycle(st).0.blocks_released, 1);
    assert_eq!(st.subscriber_count(), 0);
    // A generous budget completes the cycle in one pass.
    let one = st.sweep_budget(None, Duration::from_secs(5));
    assert!(one.complete);
}

/// No entry escapes the hint while workers create BIBs and sessions in the
/// shards a chunked sweeper (chunk 1) is walking.
#[test]
fn concurrent_creates_are_never_lost() {
    let fx = fixture(&[FOUR_SHARDS, ("max_blocks_per_subscriber = 4", "max_blocks_per_subscriber = 16")]);
    let nat = Arc::new(fx.nat);
    let st = nat.state();
    st.set_sweep_chunk(1);
    let stop = Arc::new(AtomicBool::new(false));
    let workers: Vec<_> = (0..2u16)
        .map(|w| {
            let (nat, stop) = (nat.clone(), stop.clone());
            std::thread::spawn(move || {
                let st = nat.state();
                let c = Counters::default();
                let mut n = 0u64;
                for p in 0..1500u16 {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let k6 = Key6 { proto: proto::UDP, addr: sub(10 + w, 1), port: 1000 + p };
                    let m = st.bib_for(k6, true, &c, &None).unwrap();
                    for r in 0..=p % 3 {
                        st.outbound(m.k4, (SERVER, 53 + r), 0, &c).unwrap();
                        n += 1;
                    }
                }
                n
            })
        })
        .collect();
    let mut passes = 0;
    while workers.iter().any(|w| !w.is_finished()) {
        st.sweep_budget(None, Duration::ZERO);
        passes += 1;
    }
    // Finish the cycle in progress, so the next starts at the first shard.
    while !st.sweep_budget(None, Duration::ZERO).complete {}
    stop.store(true, Ordering::Relaxed);
    let created: u64 = workers.into_iter().map(|w| w.join().unwrap()).sum();
    assert!(passes > 0);
    assert_eq!(st.session_count(), created);
    // Everything expires and is reclaimed through the hints alone.
    fx.clock.advance(Duration::from_secs(UDP_S + 1));
    assert_eq!(budgeted_cycle(st).0.sessions_expired, created);
    fx.clock.advance(Duration::from_secs(2));
    budgeted_cycle(st);
    assert_eq!(st.bib4.len(), 0);
    assert_eq!(st.bib6.len(), 0);
    fx.clock.advance(Duration::from_secs(61));
    budgeted_cycle(st);
    assert_eq!(st.subscriber_count(), 0);
    assert_eq!(st.aggregate_count(sub(10, 1)), 0);
    assert_eq!(st.pool.free_blocks() + st.pool.cooling_blocks(), st.pool.total_blocks());
}

/// PERF-2, SEC-002: while another thread keeps removing and re-inserting
/// entries in every `bib4` shard (each churn step breaks a chunked
/// sweeper's key snapshot), every session still expires: each pass
/// resumes a due shard where the interrupted walk stopped instead of
/// re-walking its first hold, so no shard tail is starved. With chunk 1 a
/// pass makes progress of at least one BIB per due shard, so the bound is
/// the largest shard's length in full cycles.
#[test]
fn churn_cannot_starve_a_shard_tail() {
    let fx = fixture(&[("table_shards = 1024", "table_shards = 1")]);
    let nat = Arc::new(fx.nat);
    let st = nat.state();
    st.set_sweep_chunk(1);
    for s in 1..=4 {
        flows(st, s, 250, 1);
    }
    assert_eq!(st.session_count(), 1000);
    let largest = (0..st.bib4.shard_count()).map(|i| st.bib4.lock_index(i).len()).max().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let churn: Vec<_> = (0..3u64)
        .map(|t| {
            let (nat, stop) = (nat.clone(), stop.clone());
            std::thread::spawn(move || {
                let st = nat.state();
                let mut x = 0x9e37_79b9_u64 + t;
                let mut steps = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    let i = (x >> 33) as usize % st.bib4.shard_count();
                    let mut g = st.bib4.lock_index(i);
                    let n = g.len();
                    if n == 0 {
                        continue;
                    }
                    let Some(k) = g.keys().nth((x >> 40) as usize % n).copied() else { continue };
                    if let Some(v) = g.remove(&k) {
                        st.bib4.note_removal_index(i);
                        g.insert(k, v);
                    }
                    steps += 1;
                }
                steps
            })
        })
        .collect();
    fx.clock.advance(Duration::from_secs(UDP_S + 1));
    let mut cycles = 0;
    while st.session_count() > 0 && cycles <= largest {
        st.sweep();
        cycles += 1;
    }
    stop.store(true, Ordering::Relaxed);
    let steps: u64 = churn.into_iter().map(|c| c.join().unwrap()).sum();
    assert!(steps > 0);
    assert_eq!(st.session_count(), 0, "{cycles} cycles, largest shard {largest}");
    assert!(cycles <= largest, "{cycles} cycles > largest shard {largest}");
}
