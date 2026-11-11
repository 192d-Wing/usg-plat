//! Takeover adoption time (`A` in the leader-crash bound, POAM-007 (2)):
//! `State::adopt_slice` for one slice, from the 10 blocks seen on the test
//! VMs up to everything a slice of the example configuration can hold, and
//! `Shadow::take`, which builds its input. Both run inline on the
//! `plat-cluster-ctl` thread (`Ctl::acquire`), so the new owner sends no
//! heartbeat while they run.
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

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use crossbeam_channel::Receiver;
use plat_audit::{AcquireReason, AuditSink, Event};
use plat_cluster::{SliceMap, SnapRecord, WireBib, WireBlock};
use plat_common::config::SteeringMode;
use plat_common::{Clock, Config};
use plat_nat64::{AdoptInput, AdoptMeta, ClusterSetup, Directory, Nat64, Shadow, SliceState};
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
    let n = &cfg.nat64;
    let slices = SliceMap::new(&n.pool, slice_len).unwrap();
    let cidr = slices.cidr(SLICE).unwrap();
    let setup = ClusterSetup {
        slices: slices.clone(),
        self_id: 0,
        steering: SteeringMode::Drop,
        directory: Arc::new(Directory::new(16, 1000)),
        tcp_adopt_secs: 300,
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
            recs.push(SnapRecord::Bib(WireBib {
                sub: s,
                proto: PROTOS[(j % PROTOS.len() as u64) as usize],
                v6: s | 1,
                port6: port,
                v4: addr,
                port4: port,
                created_wall_us: 1,
            }));
        }
        n.shadow.snapshot_records(SLICE, &recs).unwrap();
    }
    n.shadow.snapshot_end(SLICE).unwrap();
    assert_eq!(n.shadow.counts(SLICE), (blocks as usize, bibs as usize));
}

fn take(n: &Node) -> AdoptInput {
    n.shadow.take(SLICE, n.nat.state().now_ms())
}

/// One timed adoption of `input`, then (untimed) the checks, the release of
/// the slice and the drain of the audit queue.
fn adopt_once(n: &Node, input: &AdoptInput, epoch: u64) -> Duration {
    let st = n.nat.state();
    let meta = AdoptMeta { epoch, prev_owner: Some(1), reason: AcquireReason::Takeover };
    let t = Instant::now();
    let stats = black_box(st.adopt_slice(SLICE, black_box(input), meta)).unwrap();
    let d = t.elapsed();
    assert_eq!(
        (u64::from(stats.blocks_adopted), stats.bibs_adopted, stats.rejected),
        (input.blocks.len() as u64, input.bibs.len() as u64, 0),
        "everything replicated is adopted"
    );
    assert_eq!(st.slice_state(SLICE), Some(SliceState::Active));
    // AU-12: the acquire record and one adopt record per block were queued.
    assert_eq!(n.rx.try_iter().count(), input.blocks.len() + 1);
    let rel = st.release_slice(SLICE, None);
    assert_eq!(rel.bibs_removed, input.bibs.len() as u64);
    let _ = n.rx.try_iter().count();
    d
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
            let id = format!("slice{slice_len}_{tag}/{name}_{blocks}blk_{bibs}bib");
            g.throughput(Throughput::Elements(blocks + bibs));

            fill(&n, blocks, bibs);
            let input = take(&n);
            let mut epoch = 1u64;
            g.bench_function(format!("adopt/{id}"), |b| {
                b.iter_custom(|iters| {
                    (0..iters)
                        .map(|_| {
                            epoch += 1;
                            adopt_once(&n, &input, epoch)
                        })
                        .sum()
                })
            });
            drop(input);

            // The ctl thread also builds the input (`Replicator::take`).
            g.bench_function(format!("shadow_take/{id}"), |b| {
                b.iter_custom(|iters| {
                    (0..iters)
                        .map(|_| {
                            fill(&n, blocks, bibs);
                            let t = Instant::now();
                            let input = black_box(take(&n));
                            let d = t.elapsed();
                            assert_eq!(input.bibs.len() as u64, bibs);
                            d
                        })
                        .sum()
                })
            });
        }
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
