//! Steady-state per-packet cost through the full engine (existing session),
//! single thread and contended multi-thread.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use common::*;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use plat_common::Counters;
use plat_nat64::WorkerCtx;
use plat_xlat::HEADROOM;
use plat_xlat::siit::write_v4_header;

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

criterion_group!(benches, bench);
criterion_main!(benches);
