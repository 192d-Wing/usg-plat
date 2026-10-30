//! Steady-state per-packet cost through the full engine (existing session),
//! single thread and contended multi-thread; flow setup with HA off and on.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{Fx, config, fixture, fixture_q, l4_sum4, l4_sum6, run, run_all, sub, synth, udp4, udp6};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use plat_audit::{AcquireReason, AuditSink};
use plat_cluster::SliceMap;
use plat_common::config::SteeringMode;
use plat_common::{Clock, Counters};
use plat_nat64::{AdoptInput, AdoptMeta, ClusterSetup, Directory, Nat64, ReplHub, WorkerCtx};
use plat_xlat::HEADROOM;
use plat_xlat::siit::write_v4_header;
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    let mut fx = fixture(&[]);
    let pkt = udp6(sub(1, 1), 5000, 0xc633_6407, 53, &[0u8; 512]);
    run(&mut fx, &pkt).unwrap();
    let mut g = c.benchmark_group("nat64");
    g.throughput(Throughput::Elements(1));
    let mut buf = vec![0u8; HEADROOM + 2048];
    g.bench_function("v6_to_v4_udp_existing_session", |b| {
        b.iter(|| {
            buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(&pkt);
            black_box(fx.nat.process(&mut buf, HEADROOM, pkt.len(), &mut fx.ctx));
        })
    });

    // PERF-007: the reverse direction on the same session (HA off), so the
    // inbound path's ownership/hairpin checks are gated too.
    let out = run(&mut fx, &pkt).unwrap();
    let (ia, ip) = (plat_packet::be32(&out, 12), plat_packet::be16(&out, 20));
    let reply = udp4(0xc633_6407, 53, ia, ip, &[0u8; 512]);
    assert!(run(&mut fx, &reply).is_ok(), "reply translates");
    g.bench_function("v4_to_v6_udp_existing_session", |b| {
        b.iter(|| {
            buf[HEADROOM..HEADROOM + reply.len()].copy_from_slice(&reply);
            black_box(fx.nat.process(&mut buf, HEADROOM, reply.len(), &mut fx.ctx));
        })
    });

    // PERF-104 / RFC 7915 §4: a DF=0 IPv4 UDP packet of 1428 B on an
    // existing session translates to more than `lowest_ipv6_mtu` (1280), so
    // the engine writes two IPv6 fragments into the worker's fragment buffer
    // (`Verdict::ForwardFragments`). No allocation; the extra cost is the
    // second header and copy (and, in platd, a second TUN write).
    let mut frag = fixture(&[]);
    let out = run(&mut frag, &udp6(sub(1, 2), 5000, 0xc633_6407, 53, b"q")).unwrap();
    let (fa, fp) = (plat_packet::be32(&out, 12), plat_packet::be16(&out, 20));
    let mut df0 = vec![0u8; 1428];
    write_v4_header(&mut df0, 0, 1428, 0x1234, false, false, 0, 64, plat_packet::proto::UDP, 0xc633_6407, fa);
    plat_packet::put16(&mut df0, 20, 53);
    plat_packet::put16(&mut df0, 22, fp);
    plat_packet::put16(&mut df0, 24, 1408);
    l4_sum4(&mut df0, plat_packet::proto::UDP, 6);
    assert_eq!(run_all(&mut frag, &df0).unwrap().len(), 2, "two IPv6 fragments");
    g.bench_function("v4_to_v6_df0_fragmented_1428B", |b| {
        b.iter(|| {
            buf[HEADROOM..HEADROOM + df0.len()].copy_from_slice(&df0);
            black_box(frag.nat.process(&mut buf, HEADROOM, df0.len(), &mut frag.ctx));
        })
    });

    // POAM-001: fragmented datagrams through the per-worker fragment
    // table. Each iteration is one two-fragment datagram (first fragment:
    // normal path plus a table insert; last fragment: one probe and a
    // header rewrite, no shard lock), rotating over 1024 Identifications.
    let pair4: Vec<[Vec<u8>; 2]> = (0..1024u16)
        .map(|id| {
            let full = udp4(0xc633_6407, 53, fa, fp, &[0u8; 504]);
            let mut a = full[..20 + 256].to_vec();
            write_v4_header(&mut a, 0, 276, id, false, true, 0, 64, plat_packet::proto::UDP, 0xc633_6407, fa);
            let mut b = vec![0u8; 20 + 256];
            write_v4_header(&mut b, 0, 276, id, false, false, 32, 64, plat_packet::proto::UDP, 0xc633_6407, fa);
            b[20..].copy_from_slice(&full[20 + 256..]);
            [a, b]
        })
        .collect();
    let pair6: Vec<[Vec<u8>; 2]> = (0..1024u32)
        .map(|id| {
            let full = udp6(sub(1, 2), 5000, 0xc633_6407, 53, &[0u8; 504]);
            let mk = |off: usize, more: bool| {
                let mut p = vec![0u8; 48 + 256];
                plat_xlat::siit::write_v6_header(
                    &mut p,
                    0,
                    264,
                    plat_packet::proto::FRAGMENT,
                    64,
                    sub(1, 2),
                    synth(0xc633_6407),
                );
                p[40] = plat_packet::proto::UDP;
                plat_packet::put16(&mut p, 42, ((off / 8) as u16) << 3 | u16::from(more));
                plat_packet::put32(&mut p, 44, id);
                p[48..].copy_from_slice(&full[40 + off..40 + off + 256]);
                p
            };
            [mk(0, true), mk(256, false)]
        })
        .collect();
    for (name, pairs) in [("frag_pair_v4_2x276B", &pair4), ("frag_pair_v6_2x304B", &pair6)] {
        let mut k = 0usize;
        g.bench_function(name, |b| {
            b.iter(|| {
                for f in &pairs[k & 1023] {
                    buf[HEADROOM..HEADROOM + f.len()].copy_from_slice(f);
                    black_box(frag.nat.process(&mut buf, HEADROOM, f.len(), &mut frag.ctx));
                }
                k = k.wrapping_add(1);
            })
        });
    }
    // Fragmented ICMPv6 echo: reassembly (copy into a slot) then the normal
    // path on the whole datagram.
    let echo: Vec<[Vec<u8>; 2]> = (0..1024u32)
        .map(|id| {
            let s = sub(1, 3);
            let mut e = vec![0u8; 40 + 8 + 200];
            plat_xlat::siit::write_v6_header(&mut e, 0, 208, plat_packet::proto::ICMPV6, 64, s, synth(0xc633_6407));
            e[40] = 128;
            plat_packet::put16(&mut e, 44, 9);
            l4_sum6(&mut e, s, synth(0xc633_6407), plat_packet::proto::ICMPV6, 2);
            let mk = |off: usize, len: usize, more: bool| {
                let mut p = vec![0u8; 48 + len];
                plat_xlat::siit::write_v6_header(
                    &mut p,
                    0,
                    (8 + len) as u16,
                    plat_packet::proto::FRAGMENT,
                    64,
                    s,
                    synth(0xc633_6407),
                );
                p[40] = plat_packet::proto::ICMPV6;
                plat_packet::put16(&mut p, 42, ((off / 8) as u16) << 3 | u16::from(more));
                plat_packet::put32(&mut p, 44, id);
                p[48..].copy_from_slice(&e[40 + off..40 + off + len]);
                p
            };
            [mk(0, 104, true), mk(104, 104, false)]
        })
        .collect();
    let mut k = 0usize;
    g.bench_function("reassemble_icmp_echo_2frag", |b| {
        b.iter(|| {
            for f in &echo[k & 1023] {
                buf[HEADROOM..HEADROOM + f.len()].copy_from_slice(f);
                black_box(frag.nat.process(&mut buf, HEADROOM, f.len(), &mut frag.ctx));
            }
            k = k.wrapping_add(1);
        })
    });
    // RFC 7915 §5.1 / POAM-002: a 1048-byte IPv6 packet with ipv4_mtu 576
    // becomes two IPv4 fragments.
    let mut m576 = fixture(&[("ipv4_mtu = 1500", "ipv4_mtu = 576")]);
    let p576 = udp6(sub(1, 4), 5000, 0xc633_6407, 53, &[0u8; 1000]);
    assert_eq!(run_all(&mut m576, &p576).unwrap().len(), 2);
    g.bench_function("v6_to_v4_fragments_576", |b| {
        b.iter(|| {
            buf[HEADROOM..HEADROOM + p576.len()].copy_from_slice(&p576);
            black_box(m576.nat.process(&mut buf, HEADROOM, p576.len(), &mut m576.ctx));
        })
    });

    // SEC-004 / PERF-001: unsolicited inbound packets (dropped by
    // address-dependent filtering) against a BIB holding 4000 sessions.
    // Must not grow with the number of sessions in the BIB.
    let mut big = fixture(&[]);
    let mut last = Vec::new();
    for i in 0..4000u32 {
        last = run(&mut big, &udp6(sub(1, 1), 5353, 0x0800_0000 + i, 53, b"q")).unwrap();
    }
    let (a, p) = (plat_packet::be32(&last, 12), plat_packet::be16(&last, 20));
    let unsolicited: Vec<_> = (0..256u32).map(|i| udp4(0x0b00_0000 + i, 1000, a, p, b"x")).collect();
    let mut i = 0usize;
    g.bench_function("inbound_unsolicited_large_bib", |b| {
        b.iter(|| {
            let u = &unsolicited[i & 255];
            i = i.wrapping_add(1);
            buf[HEADROOM..HEADROOM + u.len()].copy_from_slice(u);
            black_box(big.nat.process(&mut buf, HEADROOM, u.len(), &mut big.ctx));
        })
    });

    // PERF-101: one worker forwarding an existing session while 3 other
    // workers flood new-subscriber packets into a full subscriber table.
    // The flood path must be read-only on shared lines, so this should stay
    // close to `v6_to_v4_udp_existing_session`.
    let flood = fixture(&[("max_subscribers = 1000000", "max_subscribers = 1")]);
    let (fnat, _frx) = (Arc::new(flood.nat), flood.rx);
    let victim = udp6(sub(1, 1), 5000, 0xc633_6407, 53, &[0u8; 512]);
    {
        let mut ctx = WorkerCtx::new(Arc::new(Counters::default()), 0);
        let mut b = vec![0u8; HEADROOM + 2048];
        b[HEADROOM..HEADROOM + victim.len()].copy_from_slice(&victim);
        assert!(matches!(fnat.process(&mut b, HEADROOM, victim.len(), &mut ctx), plat_nat64::Verdict::Forward { .. }));
    }
    g.bench_function("v6_to_v4_existing_session_under_new_sub_flood_3t", |b| {
        b.iter_custom(|iters| {
            let stop = AtomicBool::new(false);
            let started = AtomicUsize::new(0);
            std::thread::scope(|s| {
                for t in 0..3u16 {
                    let (fnat, stop, started) = (&fnat, &stop, &started);
                    s.spawn(move || {
                        let mut ctx = WorkerCtx::new(Arc::new(Counters::default()), t + 1);
                        let pkts: Vec<_> =
                            (0..64u16).map(|i| udp6(sub(1000 + t * 64 + i, 1), 5000, 0xc633_6407, 53, b"x")).collect();
                        let mut buf = vec![0u8; HEADROOM + 2048];
                        started.fetch_add(1, Ordering::Relaxed);
                        while !stop.load(Ordering::Relaxed) {
                            for p in &pkts {
                                buf[HEADROOM..HEADROOM + p.len()].copy_from_slice(p);
                                black_box(fnat.process(&mut buf, HEADROOM, p.len(), &mut ctx));
                            }
                        }
                    });
                }
                while started.load(Ordering::Relaxed) < 3 {
                    std::hint::spin_loop();
                }
                let mut ctx = WorkerCtx::new(Arc::new(Counters::default()), 0);
                let mut buf = vec![0u8; HEADROOM + 2048];
                let start = Instant::now();
                for _ in 0..iters {
                    buf[HEADROOM..HEADROOM + victim.len()].copy_from_slice(&victim);
                    black_box(fnat.process(&mut buf, HEADROOM, victim.len(), &mut ctx));
                }
                let e = start.elapsed();
                stop.store(true, Ordering::Relaxed);
                e
            })
        })
    });

    // Multi-core scaling: N threads, distinct flows, existing sessions.
    // Keep the audit receiver alive: with it dropped, every new mapping is
    // (correctly) refused under refuse_new_bindings and the bench would
    // measure the refusal path instead of forwarding.
    let shared = fixture(&[("max_sessions_per_subscriber = 4000", "max_sessions_per_subscriber = 100000")]);
    let (nat, _rx) = (Arc::new(shared.nat), shared.rx);
    for threads in [1usize, 2, 4, 8] {
        g.bench_function(format!("v6_to_v4_parallel_{threads}t_x100k"), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                std::thread::scope(|s| {
                    for t in 0..threads {
                        let nat = nat.clone();
                        s.spawn(move || {
                            let mut ctx = WorkerCtx::new(Arc::new(Counters::default()), t as u16);
                            let pkts: Vec<_> = (0..64u16)
                                .map(|i| udp6(sub(t as u16 * 64 + i, 1), 5000, 0xc633_6407, 53, &[0u8; 512]))
                                .collect();
                            let mut buf = vec![0u8; HEADROOM + 2048];
                            for _ in 0..iters {
                                for _ in 0..(100_000 / threads / 64) {
                                    for p in &pkts {
                                        buf[HEADROOM..HEADROOM + p.len()].copy_from_slice(p);
                                        black_box(nat.process(&mut buf, HEADROOM, p.len(), &mut ctx));
                                    }
                                }
                            }
                        });
                    }
                });
                start.elapsed()
            })
        });
    }
    // Control: one private engine per thread (no shared state at all).
    for threads in [1usize, 4, 8] {
        let fxs: Vec<_> = (0..threads).map(|_| fixture(&[])).collect();
        let nats: Vec<_> = fxs.iter().map(|f| &f.nat).collect();
        g.bench_function(format!("v6_to_v4_independent_{threads}t_x100k"), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                std::thread::scope(|s| {
                    for (t, nat) in nats.iter().copied().enumerate() {
                        s.spawn(move || {
                            let mut ctx = WorkerCtx::new(Arc::new(Counters::default()), t as u16);
                            let pkts: Vec<_> =
                                (0..64u16).map(|i| udp6(sub(i, 1), 5000, 0xc633_6407, 53, &[0u8; 512])).collect();
                            let mut buf = vec![0u8; HEADROOM + 2048];
                            for _ in 0..iters {
                                for _ in 0..(100_000 / threads / 64) {
                                    for p in &pkts {
                                        buf[HEADROOM..HEADROOM + p.len()].copy_from_slice(p);
                                        black_box(nat.process(&mut buf, HEADROOM, p.len(), &mut ctx));
                                    }
                                }
                            }
                        });
                    }
                });
                start.elapsed()
            })
        });
    }
    g.finish();
}

/// Flows per freshly built engine in the flow-setup benches: 40
/// subscribers × 100 source ports, each packet a new BIB and session (and,
/// once per subscriber, a new subscriber and port block).
const FLOW_CHUNK: usize = 4000;

fn flow_pkts() -> Vec<Vec<u8>> {
    (0..FLOW_CHUNK)
        .map(|i| udp6(sub((i / 100) as u16 + 1, 1), 1000 + (i % 100) as u16, 0xc633_6407, 53, b"q"))
        .collect()
}

/// Times only the packets; engines are built and dropped untimed.
fn timed_flows<K>(iters: u64, pkts: &[Vec<u8>], mut mk: impl FnMut() -> (Fx, K)) -> Duration {
    let mut buf = vec![0u8; HEADROOM + 2048];
    let mut total = Duration::ZERO;
    let mut left = iters as usize;
    while left > 0 {
        let n = left.min(pkts.len());
        let (mut fx, keep) = mk();
        let start = Instant::now();
        for p in &pkts[..n] {
            buf[HEADROOM..HEADROOM + p.len()].copy_from_slice(p);
            black_box(fx.nat.process(&mut buf, HEADROOM, p.len(), &mut fx.ctx));
        }
        total += start.elapsed();
        drop((fx, keep));
        left -= n;
    }
    total
}

/// Cluster engine over the fixture pool (four /32 slices, all Active, no
/// backup reservation), with a replication ring on the worker.
fn ha_fixture() -> (Fx, Arc<ReplHub>) {
    ha_fixture_with(&[], 8)
}

/// `ha_fixture` with config edits and a reserve-ahead budget in blocks.
fn ha_fixture_with(edits: &[(&str, &str)], reserve_ahead: u16) -> (Fx, Arc<ReplHub>) {
    let cfg = config(edits);
    let setup = ClusterSetup {
        slices: SliceMap::new(&cfg.nat64.pool, 32).unwrap(),
        self_id: 0,
        steering: SteeringMode::Drop,
        directory: Arc::new(Directory::new(cfg.nat64.table_shards, cfg.nat64.max_subscribers)),
        tcp_adopt_secs: 300,
        quarantine_secs: 600,
        reserve_ahead,
    };
    let clock = Clock::new();
    let (sink, rx) = AuditSink::bounded(4096 * 4);
    let nat = Nat64::new_cluster(&cfg, setup, sink, clock.clone()).unwrap();
    for s in 0..4 {
        let m = AdoptMeta { epoch: 1, prev_owner: None, reason: AcquireReason::Startup };
        nat.state().adopt_slice(s, &AdoptInput::default(), m).unwrap();
    }
    let (hub, mut prods) = ReplHub::new(1, 65_536, 4);
    let ctx = WorkerCtx::new(Arc::new(Counters::default()), 1).with_repl(prods.remove(0));
    (Fx { nat, clock, rx, ctx }, hub)
}

/// Flow setup (new BIB per packet), HA off versus HA on (plan gate: HA on
/// within 8% of main's HA-off figure), and steady state with HA on.
fn bench_flows(c: &mut Criterion) {
    let pkts = flow_pkts();
    {
        let (mut fx, hub) = ha_fixture();
        for p in &pkts {
            assert!(run(&mut fx, p).is_ok());
        }
        assert_eq!(hub.dropped_total(), 0, "ring sized for a chunk");
    }
    let mut g = c.benchmark_group("nat64");
    g.throughput(Throughput::Elements(1));
    g.bench_function("flow_create_v6_to_v4", |b| b.iter_custom(|n| timed_flows(n, &pkts, || (fixture(&[]), ()))));
    g.bench_function("flow_create_ha_v6_to_v4", |b| b.iter_custom(|n| timed_flows(n, &pkts, ha_fixture)));
    g.finish();

    // PERF-007: HA steady state in its own group, so a filter on the
    // HA-off group never runs it.
    let mut g = c.benchmark_group("nat64_ha");
    g.throughput(Throughput::Elements(1));

    let (mut fx, _hub) = ha_fixture();
    let pkt = udp6(sub(1, 1), 5000, 0xc633_6407, 53, &[0u8; 512]);
    run(&mut fx, &pkt).unwrap();
    let mut buf = vec![0u8; HEADROOM + 2048];
    g.bench_function("v6_to_v4_udp_existing_session", |b| {
        b.iter(|| {
            buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(&pkt);
            black_box(fx.nat.process(&mut buf, HEADROOM, pkt.len(), &mut fx.ctx));
        })
    });
    g.finish();
}

/// Audit queue for the layout benches: well above the block records one
/// chunk writes, so `try_send` never hits a full queue (PERF-003).
const LAYOUT_QUEUE: usize = 1 << 16;

/// New-flow churn for subscribers that grow past 512 ports: 2 subscribers
/// x 2000 source ports, so each fills 4 blocks at 512 x 4 or 16 blocks at
/// 128 x 16 (same 2048-port maximum), HA off and HA on (reserve-ahead 8 at
/// 512, 32 at 128). The audit receiver is not drained, so record
/// formatting and writing are excluded.
///
/// `block_spill_*` isolates the per-block cost: every subscriber uses
/// `size` ports (1 block) or `size + 1` ports (2 blocks). The per-block
/// cost is `(spill - fill)` per subscriber minus one flow.
fn bench_block_layouts(c: &mut Criterion) {
    let pkts: Vec<Vec<u8>> = (0..FLOW_CHUNK)
        .map(|i| udp6(sub((i / 2000) as u16 + 1, 1), 1000 + (i % 2000) as u16, 0xc633_6407, 53, b"q"))
        .collect();
    let mut g = c.benchmark_group("nat64_block_layout");
    g.throughput(Throughput::Elements(1));
    for (name, size, max) in [("512x4", "512", "4"), ("128x16", "128", "16")] {
        let edits = [
            ("port_block_size = 512", &*format!("port_block_size = {size}")),
            ("max_blocks_per_subscriber = 4", &*format!("max_blocks_per_subscriber = {max}")),
        ];
        let mut fx = fixture_q(&edits, LAYOUT_QUEUE);
        for p in &pkts {
            assert!(run(&mut fx, p).is_ok(), "{name}: every flow gets a port");
        }
        drop(fx);
        g.bench_function(format!("flow_churn_{name}"), |b| {
            b.iter_custom(|n| timed_flows(n, &pkts, || (fixture_q(&edits, LAYOUT_QUEUE), ())))
        });
    }
    // HA on. `128x16_ra8` keeps the 512 x 4 reserve-ahead count, so block
    // size and reserve-ahead budget can be told apart.
    for (name, size, max, reserve) in
        [("512x4", "512", "4", 8u16), ("128x16", "128", "16", 32), ("128x16_ra8", "128", "16", 8)]
    {
        let edits = [
            ("port_block_size = 512", &*format!("port_block_size = {size}")),
            ("max_blocks_per_subscriber = 4", &*format!("max_blocks_per_subscriber = {max}")),
        ];
        {
            let (mut fx, hub) = ha_fixture_with(&edits, reserve);
            for p in &pkts {
                assert!(run(&mut fx, p).is_ok(), "ha {name}: every flow gets a port");
            }
            assert_eq!(hub.dropped_total(), 0, "ha {name}: ring sized for a chunk");
        }
        g.bench_function(format!("flow_churn_ha_{name}"), |b| {
            b.iter_custom(|n| timed_flows(n, &pkts, || ha_fixture_with(&edits, reserve)))
        });
    }
    for size in [512usize, 128] {
        let edits = [
            ("port_block_size = 512", &*format!("port_block_size = {size}")),
            ("max_blocks_per_subscriber = 4", &*format!("max_blocks_per_subscriber = {}", 2048 / size)),
        ];
        for (kind, per_sub) in [("fill", size), ("spill", size + 1)] {
            let subs = FLOW_CHUNK / per_sub;
            let pkts: Vec<Vec<u8>> = (0..subs * per_sub)
                .map(|i| udp6(sub((i / per_sub) as u16 + 1, 1), 1000 + (i % per_sub) as u16, 0xc633_6407, 53, b"q"))
                .collect();
            let mut fx = fixture_q(&edits, LAYOUT_QUEUE);
            for p in &pkts {
                assert!(run(&mut fx, p).is_ok(), "block_{kind}_{size}: every flow gets a port");
            }
            drop(fx);
            g.bench_function(format!("block_{kind}_{size}"), |b| {
                b.iter_custom(|n| timed_flows(n, &pkts, || (fixture_q(&edits, LAYOUT_QUEUE), ())))
            });
        }
    }
    g.finish();
}

criterion_group!(benches, bench, bench_flows, bench_block_layouts);
criterion_main!(benches);
