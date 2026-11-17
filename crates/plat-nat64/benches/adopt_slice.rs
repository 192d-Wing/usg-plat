//! Takeover adoption time (`A` in the leader-crash bound, POAM-007 (2)):
//! one slice, from the 10 blocks seen on the test VMs up to everything a
//! slice of the example configuration can hold.
//!
//! - `adopt`: the adoption cursor run to completion from a sorted
//!   `AdoptInput` (`adopt_begin` + `adopt_step` with no effective
//!   deadline, so only the per-step item cap splits it); the input copy is
//!   made outside the timed region. Comparable to the pre-POAM-047
//!   one-shot `adopt_slice` figures.
//! - `adopt_detached`: what platd runs: `Shadow::detach` (O(1)), then
//!   `adopt_step` with the 5 ms `ADOPT_STEP_BUDGET` until done, from the
//!   unsorted detached maps. The longest step of each case is printed
//!   (`adopt_step_5ms`): that is the control thread's stall per step.
//!
//! Sizes come from the example configuration, not from literals:
//!
//! - blocks: addresses in the slice x blocks per address (`port_min`,
//!   `port_max`, `port_block_size`), one subscriber per block (the most
//!   subscriber-table inserts a slice can cause);
//! - BIBs: every port of every block for TCP, UDP and ICMP, capped by
//!   `nat64.max_sessions` (the shadow's `max_bibs` in platd);
//! - the audit queue has `audit.queue_capacity` entries and is drained
//!   between iterations (in platd the logger thread drains it).
//!
//! - `release`: the Active-slice release cursor (POAM-048) of the adopted
//!   slice, `release_begin` + `release_step` with the 5 ms
//!   `RELEASE_STEP_BUDGET` until done; the adoption before it is untimed.
//!   The longest step is printed (`release_step_5ms`).
//!
//! - `adopt_detached_hinted` (POAM-028): `adopt_detached` with
//!   `session_hints` on and one ESTABLISHED session hint per TCP BIB (a
//!   third of the BIBs), restored as `Pickup` sessions during the import.
//!
//! - `adopt_detached_hinted_udp` (QA, POAM-028 (a)): the same with
//!   `session_hints = "tcp_udp"` and 4 UDP hints per UDP BIB.
//!
//! Each case reports the time of one adoption; the throughput line is
//! records (blocks + BIBs) per second. A `blocks_only` case next to a full
//! one separates the per-block cost (subscriber insert and one
//! `nat_port_block_adopt` record) from the per-BIB cost.
//!
//! Not covered: `hold_unknown` (unsynced takeover), a non-empty slice on the
//! adopting node (stale release), a contended audit queue, and worker
//! traffic on the other slices during the adoption.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main};
use crossbeam_channel::Receiver;
use plat_audit::{AcquireReason, AuditSink, Event};
use plat_cluster::{SliceMap, SnapRecord, WireBib, WireBlock, WireHint};
use plat_common::config::SteeringMode;
use plat_common::{Clock, Config};
use plat_nat64::{
    ADOPT_STEP_BUDGET, AdoptInput, AdoptMeta, AdoptSource, AdoptStats, ClusterSetup, Directory, Nat64,
    RELEASE_STEP_BUDGET, ReleaseStats, ReleaseStep, Shadow, SliceState, Step,
};
use plat_packet::proto;

/// The slice measured (the first of the pool).
const SLICE: u16 = 0;
/// Blocks the two-member VM bed held at takeover (LINUX_VERIFICATION L19).
const VM_BLOCKS: u64 = 10;
const PROTOS: [u8; 3] = [proto::TCP, proto::UDP, proto::ICMP];

/// The example configuration, pool `192.0.2.0/24` as shipped.
fn config() -> Config {
    let t = include_str!("../../../config/platd.example.toml")
        .replace("allow_non_global_destinations = false", "allow_non_global_destinations = true");
    Config::from_toml(&t).unwrap()
}

/// One adopting node whose pool is split at `slice_len`, and the backup
/// shadow sized like platd's (`max_bibs = nat64.max_sessions`).
struct Node {
    nat: Nat64,
    rx: Receiver<Event>,
    shadow: Shadow,
    base: u32,
    port_min: u16,
    block_size: u16,
    blocks_per_addr: u64,
    /// Blocks of one slice.
    slice_blocks: u64,
    /// Most BIBs the shadow of one slice can hold.
    slice_bibs: u64,
}

fn node(cfg: &Config, slice_len: u8) -> Node {
    node_h(cfg, slice_len, false)
}

fn node_h(cfg: &Config, slice_len: u8, hints: bool) -> Node {
    node_hu(cfg, slice_len, hints, false)
}

/// [`node_h`] with `session_hints = "tcp_udp"` when `udp` (UDP hints
/// restored; the example filtering is address-dependent).
fn node_hu(cfg: &Config, slice_len: u8, hints: bool, udp: bool) -> Node {
    let n = &cfg.nat64;
    let slices = SliceMap::new(&n.pool, slice_len).unwrap();
    let cidr = slices.cidr(SLICE).unwrap();
    let setup = ClusterSetup {
        slices: slices.clone(),
        self_id: 0,
        steering: SteeringMode::Drop,
        directory: Arc::new(Directory::new(16, 1000)),
        tcp_adopt_secs: 300,
        session_hints: hints,
        udp_hints: udp.then_some(2),
        quarantine_secs: 600,
        reserve_ahead: 2,
    };
    let (sink, rx) = AuditSink::bounded(cfg.audit.queue_capacity);
    let nat = Nat64::new_cluster(cfg, setup, sink, Clock::new()).unwrap();
    let shadow = Shadow::new(
        slices,
        n.port_min,
        n.port_max,
        n.port_block_size,
        u64::from(n.block_cooldown_secs) * 1000,
        n.max_sessions,
    );
    let blocks_per_addr = n.blocks_per_addr();
    let slice_blocks = cidr.size() * blocks_per_addr;
    let slice_bibs = (slice_blocks * u64::from(n.port_block_size) * PROTOS.len() as u64).min(n.max_sessions);
    Node {
        nat,
        rx,
        shadow,
        base: cidr.network(),
        port_min: n.port_min,
        block_size: n.port_block_size,
        blocks_per_addr,
        slice_blocks,
        slice_bibs,
    }
}

/// Subscriber `i`: one /64 per block, 256 per /56 aggregate (the example's
/// `max_subscribers_per_aggregate`).
fn sub(i: u64) -> u128 {
    0x2001_0db8_0100_0000_0000_0000_0000_0000 | (u128::from(i) << 64)
}

/// Fills the shadow of [`SLICE`] with `blocks` blocks (one subscriber each)
/// and `bibs` BIBs spread evenly over them, through the snapshot path a
/// backup uses.
fn fill(n: &Node, blocks: u64, bibs: u64) {
    fill_h(n, blocks, bibs, false)
}

/// [`fill`] with one session hint (remote 198.51.100.7:443) after every
/// TCP BIB when `hints`; the snapshot ends hinted.
fn fill_h(n: &Node, blocks: u64, bibs: u64, hints: bool) {
    fill_hu(n, blocks, bibs, hints, 0)
}

/// [`fill_h`] plus `udp_remotes` (≤ 4) UDP session hints after every UDP
/// BIB (remotes 198.51.100.7:443, :444, ...).
fn fill_hu(n: &Node, blocks: u64, bibs: u64, hints: bool, udp_remotes: u16) {
    assert!(blocks <= n.slice_blocks && bibs <= n.slice_bibs, "case exceeds the slice");
    let per_block = bibs.checked_div(blocks).unwrap_or(0);
    let extra = bibs.checked_rem(blocks).unwrap_or(0);
    assert!(per_block + u64::from(extra > 0) <= u64::from(n.block_size) * PROTOS.len() as u64);
    n.shadow.snapshot_begin(SLICE).unwrap();
    let mut recs = Vec::with_capacity(1 + per_block as usize + 1);
    for i in 0..blocks {
        let addr = n.base + (i / n.blocks_per_addr) as u32;
        let block = (i % n.blocks_per_addr) as u16;
        let lo = n.port_min + block * n.block_size;
        let s = sub(i);
        recs.clear();
        recs.push(SnapRecord::Block { sub: s, block: WireBlock { addr, block }, alloc_wall_us: 1 });
        for j in 0..per_block + u64::from(i < extra) {
            let port = lo + (j / PROTOS.len() as u64) as u16;
            let proto = PROTOS[(j % PROTOS.len() as u64) as usize];
            recs.push(SnapRecord::Bib(WireBib {
                sub: s,
                proto,
                v6: s | 1,
                port6: port,
                v4: addr,
                port4: port,
                created_wall_us: 1,
            }));
            if hints && proto == proto::TCP {
                recs.push(SnapRecord::Sess(WireHint { proto, v4: addr, port4: port, raddr: 0xc633_6407, rport: 443 }));
            }
            if proto == proto::UDP {
                for r in 0..udp_remotes {
                    let h = WireHint { proto, v4: addr, port4: port, raddr: 0xc633_6407, rport: 443 + r };
                    recs.push(SnapRecord::Sess(h));
                }
            }
        }
        n.shadow.snapshot_records(SLICE, &recs).unwrap();
    }
    n.shadow.snapshot_end_hinted(SLICE, hints).unwrap();
    assert_eq!(n.shadow.counts(SLICE), (blocks as usize, bibs as usize));
}

fn take(n: &Node) -> AdoptInput {
    n.shadow.take(SLICE, n.nat.state().now_ms())
}

/// The longest step of a stepped adoption and the phase it started in
/// ("phase change" when it ended in another one).
type Longest = (Duration, &'static str);

/// Steps `src` to completion with `budget` per step; returns the stats,
/// the total time and the longest step, and appends every step's time to
/// `steps`.
fn adopt_stepped(
    n: &Node,
    src: AdoptSource,
    epoch: u64,
    budget: Duration,
    steps: &mut Vec<Duration>,
) -> (AdoptStats, Duration, Longest) {
    let st = n.nat.state();
    let meta = AdoptMeta { epoch, prev_owner: Some(1), reason: AcquireReason::Takeover };
    let t = Instant::now();
    let mut a = st.adopt_begin(SLICE, src, meta).unwrap();
    let mut longest = (Duration::ZERO, "");
    loop {
        let phase = a.phase();
        let s0 = Instant::now();
        let r = black_box(st.adopt_step(&mut a, s0 + budget)).unwrap();
        let d = s0.elapsed();
        steps.push(d);
        if d > longest.0 {
            longest = (d, if a.phase() == phase { phase } else { "phase change" });
        }
        if let Step::Done(stats) = r {
            return (stats, t.elapsed(), longest);
        }
    }
}

/// The checks after one adoption (untimed), the release of the slice and
/// the drain of the audit queue.
fn check(n: &Node, stats: AdoptStats, blocks: u64, bibs: u64) {
    let st = n.nat.state();
    assert_eq!(
        (u64::from(stats.blocks_adopted), stats.bibs_adopted, stats.rejected),
        (blocks, bibs, 0),
        "everything replicated is adopted"
    );
    assert_eq!(st.slice_state(SLICE), Some(SliceState::Active));
    // AU-12: the acquire record and one adopt record per block were queued.
    assert_eq!(n.rx.try_iter().count() as u64, blocks + 1);
    let rel = st.release_slice(SLICE, None);
    assert_eq!(rel.bibs_removed, bibs);
    let _ = n.rx.try_iter().count();
}

/// Releases the Active [`SLICE`] in steps of `budget`; returns the stats,
/// the total time and the longest step, and appends every step's time to
/// `steps`.
fn release_stepped(n: &Node, budget: Duration, steps: &mut Vec<Duration>) -> (ReleaseStats, Duration, Longest) {
    let st = n.nat.state();
    let t = Instant::now();
    let mut r = st.release_begin(SLICE, None).unwrap();
    let mut longest = (Duration::ZERO, "");
    loop {
        let phase = r.phase(st);
        let s0 = Instant::now();
        let res = black_box(st.release_step(&mut r, s0 + budget));
        let d = s0.elapsed();
        steps.push(d);
        if d > longest.0 {
            longest = (d, if r.phase(st) == phase { phase } else { "phase change" });
        }
        match res {
            ReleaseStep::Done(stats) => return (stats, t.elapsed(), longest),
            ReleaseStep::More => {}
            ReleaseStep::Paused => {
                let _ = n.rx.try_iter().count();
            }
        }
    }
}

fn print_steps(what: &str, id: &str, steps: &mut [Duration], longest: Longest, budget: Duration) {
    steps.sort_unstable();
    let q = |p: usize| steps.get((steps.len() * p / 100).min(steps.len().saturating_sub(1))).copied();
    println!(
        "{what}/{id}: {} steps, p50 {:?}, p99 {:?}, p99.9 {:?}, longest {:?} (started in: {}), budget {budget:?}",
        steps.len(),
        q(50).unwrap_or_default(),
        q(99).unwrap_or_default(),
        steps.get((steps.len() * 999 / 1000).min(steps.len().saturating_sub(1))).copied().unwrap_or_default(),
        longest.0,
        longest.1
    );
}

/// One timed adoption of a copy of `input` (copied untimed).
fn adopt_once(n: &Node, input: &AdoptInput, epoch: u64) -> Duration {
    let src = AdoptSource::Input(input.clone());
    let (stats, d, _) = adopt_stepped(n, src, epoch, Duration::from_secs(3600), &mut Vec::new());
    check(n, stats, input.blocks.len() as u64, input.bibs.len() as u64);
    d
}

/// The unhinted adopt, detached-adopt and release benches for one case.
fn bench_case(g: &mut BenchmarkGroup<'_, WallTime>, n: &Node, id: &str, blocks: u64, bibs: u64) {
    g.throughput(Throughput::Elements(blocks + bibs));

    fill(n, blocks, bibs);
    let input = take(n);
    let mut epoch = 1u64;
    g.bench_function(format!("adopt/{id}"), |b| {
        b.iter_custom(|iters| {
            (0..iters)
                .map(|_| {
                    epoch += 1;
                    adopt_once(n, &input, epoch)
                })
                .sum()
        })
    });
    drop(input);

    // What platd runs: detach, then 5 ms steps from the maps.
    let mut longest = (Duration::ZERO, "");
    let mut steps = Vec::new();
    g.bench_function(format!("adopt_detached/{id}"), |b| {
        b.iter_custom(|iters| {
            (0..iters)
                .map(|_| {
                    fill(n, blocks, bibs);
                    epoch += 1;
                    let t = Instant::now();
                    let d = n.shadow.detach(SLICE, n.nat.state().now_ms());
                    let detach = t.elapsed();
                    let (stats, took, l) =
                        adopt_stepped(n, AdoptSource::Detached(d), epoch, ADOPT_STEP_BUDGET, &mut steps);
                    if l.0 > longest.0 {
                        longest = l;
                    }
                    check(n, stats, blocks, bibs);
                    detach + took
                })
                .sum()
        })
    });
    print_steps("adopt_step_5ms", id, &mut steps, longest, ADOPT_STEP_BUDGET);

    // POAM-048: the release of the adopted slice, 5 ms steps.
    let mut longest = (Duration::ZERO, "");
    let mut steps = Vec::new();
    g.bench_function(format!("release/{id}"), |b| {
        b.iter_custom(|iters| {
            (0..iters)
                .map(|_| {
                    fill(n, blocks, bibs);
                    epoch += 1;
                    let d = n.shadow.detach(SLICE, n.nat.state().now_ms());
                    let (stats, _, _) =
                        adopt_stepped(n, AdoptSource::Detached(d), epoch, Duration::from_secs(3600), &mut Vec::new());
                    assert_eq!(stats.bibs_adopted, bibs);
                    let _ = n.rx.try_iter().count();
                    let (rel, took, l) = release_stepped(n, RELEASE_STEP_BUDGET, &mut steps);
                    assert_eq!((rel.bibs_removed, rel.blocks_released), (bibs, blocks));
                    assert_eq!(n.nat.state().slice_state(SLICE), Some(SliceState::Inactive));
                    let _ = n.rx.try_iter().count();
                    if l.0 > longest.0 {
                        longest = l;
                    }
                    took
                })
                .sum()
        })
    });
    print_steps("release_step_5ms", id, &mut steps, longest, RELEASE_STEP_BUDGET);
}

fn bench(c: &mut Criterion) {
    let cfg = config();
    let default_len = cfg.cluster.slice_prefix_len;
    // The whole example pool as a single slice: the largest slice this
    // configuration can form.
    let pool_len = cfg.nat64.pool.iter().map(|p| p.prefix_len()).min().unwrap();
    let mut g = c.benchmark_group("adopt_slice");
    g.sample_size(10).warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(5));
    for (tag, slice_len) in [("default", default_len), ("pool", pool_len)] {
        let n = node(&cfg, slice_len);
        let (max_blocks, max_bibs) = (n.slice_blocks, n.slice_bibs);
        // AU-5: under `refuse_new_bindings` the queue must have room for
        // every record of one adoption at once.
        assert!(max_blocks < cfg.audit.queue_capacity as u64, "slice /{slice_len} cannot be adopted");
        let mut cases =
            vec![("blocks_only", max_blocks, 0), ("mid", max_blocks, max_blocks * 64), ("max", max_blocks, max_bibs)];
        if slice_len == default_len {
            cases.insert(0, ("vm", VM_BLOCKS, VM_BLOCKS * 10));
        }
        for (name, blocks, bibs) in cases {
            bench_case(&mut g, &n, &format!("slice{slice_len}_{tag}/{name}_{blocks}blk_{bibs}bib"), blocks, bibs);
        }

        // POAM-028: the largest case again with one hint per TCP BIB.
        let n = node_h(&cfg, slice_len, true);
        let (blocks, bibs) = (max_blocks, max_bibs);
        let id = format!("slice{slice_len}_{tag}/max_{blocks}blk_{bibs}bib");
        let tcp = bibs.div_ceil(PROTOS.len() as u64);
        g.throughput(Throughput::Elements(blocks + bibs + tcp));
        let mut longest = (Duration::ZERO, "");
        let mut steps = Vec::new();
        let mut epoch = 1u64;
        g.bench_function(format!("adopt_detached_hinted/{id}"), |b| {
            b.iter_custom(|iters| {
                (0..iters)
                    .map(|_| {
                        fill_h(&n, blocks, bibs, true);
                        epoch += 1;
                        let t = Instant::now();
                        let d = n.shadow.detach(SLICE, n.nat.state().now_ms());
                        let detach = t.elapsed();
                        let (stats, took, l) =
                            adopt_stepped(&n, AdoptSource::Detached(d), epoch, ADOPT_STEP_BUDGET, &mut steps);
                        if l.0 > longest.0 {
                            longest = l;
                        }
                        assert_eq!(stats.sessions_restored, n.nat.state().session_count());
                        assert!(stats.sessions_restored > 0 && stats.sessions_refused.total() == 0);
                        check(&n, stats, blocks, bibs);
                        detach + took
                    })
                    .sum()
            })
        });
        print_steps("adopt_step_5ms_hinted", &id, &mut steps, longest, ADOPT_STEP_BUDGET);

        // QA, POAM-028 (a): UDP-heavy hinted mix (`tcp_udp`): one TCP hint
        // per TCP BIB and 4 UDP hints per UDP BIB; restores past
        // `max_sessions` are refused (`session_limit`) and counted.
        let n = node_hu(&cfg, slice_len, true, true);
        let udp = bibs / PROTOS.len() as u64;
        g.throughput(Throughput::Elements(blocks + bibs + tcp + 4 * udp));
        let mut longest = (Duration::ZERO, "");
        let mut steps = Vec::new();
        let mut last = (0u64, 0u64, 0u64);
        let mut extra: Vec<String> = Vec::new();
        g.bench_function(format!("adopt_detached_hinted_udp/{id}"), |b| {
            b.iter_custom(|iters| {
                (0..iters)
                    .map(|_| {
                        fill_hu(&n, blocks, bibs, true, 4);
                        epoch += 1;
                        let t = Instant::now();
                        let d = n.shadow.detach(SLICE, n.nat.state().now_ms());
                        let detach = t.elapsed();
                        let (stats, took, l) =
                            adopt_stepped(&n, AdoptSource::Detached(d), epoch, ADOPT_STEP_BUDGET, &mut steps);
                        if l.0 > longest.0 {
                            longest = l;
                        }
                        assert!(stats.udp_sessions_restored > 0);
                        assert_eq!(
                            stats.sessions_restored + stats.udp_sessions_restored,
                            n.nat.state().session_count()
                        );
                        last =
                            (stats.sessions_restored, stats.udp_sessions_restored, stats.udp_sessions_refused.total());
                        // The session cap is hit mid-restore: besides the
                        // acquire and adopt records the engine may queue
                        // another record. Count adopt records only.
                        let evs: Vec<Event> = n.rx.try_iter().collect();
                        let adopts = evs.iter().filter(|e| matches!(e, Event::PortBlockAdopt { .. })).count();
                        assert_eq!(adopts as u64, blocks);
                        for e in &evs {
                            if !matches!(e, Event::PortBlockAdopt { .. } | Event::ClusterSliceAcquire { .. }) {
                                extra.push(format!("{e:?}").chars().take(160).collect::<String>());
                            }
                        }
                        assert_eq!(stats.bibs_adopted, bibs);
                        assert_eq!(n.nat.state().release_slice(SLICE, None).bibs_removed, bibs);
                        let _ = n.rx.try_iter().count();
                        detach + took
                    })
                    .sum()
            })
        });
        println!(
            "adopt_detached_hinted_udp/{id}: tcp restored {}, udp restored {}, udp refused {}",
            last.0, last.1, last.2
        );
        extra.dedup();
        println!("adopt_detached_hinted_udp: other audit records: {:?}", &extra[..extra.len().min(3)]);
        print_steps("adopt_step_5ms_hinted_udp", &id, &mut steps, longest, ADOPT_STEP_BUDGET);
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
