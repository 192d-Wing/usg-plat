//! Sweeper cost harness (POAM-012, PERF-006).
//!
//! Fills the tables with `SESSIONS` UDP sessions (`PER_BIB` per BIB) and
//! measures, with nothing due and with everything due:
//!
//! - the wall time of one full sweeper pass (`State::sweep`);
//! - the worst latency a worker sees on an existing-session refresh
//!   (`State::outbound`) while passes run, which is bounded by the
//!   longest shard lock hold of the sweeper.
//!
//! ```sh
//! cargo run --release -p plat-nat64 --example sweep -- 4000000 16
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use plat_audit::AuditSink;
use plat_common::{Clock, Config, Counters};
use plat_nat64::Nat64;
use plat_nat64::state::{Key4, Key6};
use plat_packet::proto;

fn config() -> Config {
    let t = include_str!("../../../config/platd.example.toml")
        .replace("max_subscribers_per_aggregate = 256", "max_subscribers_per_aggregate = 65536");
    Config::from_toml(&t).unwrap()
}

/// Latency samples of a worker refreshing existing sessions.
fn worker(nat: Arc<Nat64>, keys: Arc<Vec<(Key4, (u32, u16))>>, stop: Arc<AtomicBool>) -> (u64, u64, Vec<u64>) {
    let c = Counters::default();
    let mut lat = Vec::with_capacity(1 << 22);
    let mut i = 0usize;
    while !stop.load(Ordering::Relaxed) {
        let (k4, r) = keys[i % keys.len()];
        i = i.wrapping_add(7919);
        let t = Instant::now();
        let _ = std::hint::black_box(nat.state().outbound(k4, r, 0, &c));
        lat.push(t.elapsed().as_nanos() as u64);
    }
    lat.sort_unstable();
    let max = lat.last().copied().unwrap_or(0);
    let p = lat.get(lat.len() * 9999 / 10000).copied().unwrap_or(0);
    (max, p, lat)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let total: u64 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(1_000_000);
    let per_bib: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(16).clamp(1, 4000);
    let cfg = config();
    let clock = Clock::new();
    let (sink, rx) = AuditSink::bounded(1 << 20);
    let p = cfg.nat64.pool[0];
    let owned = (0..p.size() as u32).map(|i| p.network() + i).collect();
    let nat = Arc::new(Nat64::new(&cfg, owned, sink, clock.clone()).unwrap());
    let st = nat.state();
    if let Some(n) = std::env::var("SWEEP_CHUNK").ok().and_then(|v| v.parse().ok()) {
        st.set_sweep_chunk(n);
    }
    let c = Counters::default();
    let bibs_per_sub = (4000 / per_bib).clamp(1, 1500);
    let mut keys = Vec::new();
    let mut made = 0u64;
    let t = Instant::now();
    'fill: for s in 0u64.. {
        let sub = 0x2001_0db8_0100_0000_0000_0000_0000_0000u128 | (u128::from(s) << 64);
        for b in 0..bibs_per_sub {
            let k6 = Key6 { proto: proto::UDP, addr: sub | 1, port: 1024 + b as u16 };
            let Ok(m) = st.bib_for(k6, true, &c, &None) else { break 'fill };
            for r in 0..per_bib {
                let remote = (0xc633_6400 | (r as u32 >> 8), 1000 + (r as u16 & 0xff));
                st.outbound(m.k4, remote, 0, &c).unwrap();
                if keys.len() < 1 << 20 {
                    keys.push((m.k4, remote));
                }
                made += 1;
                if made >= total {
                    break 'fill;
                }
            }
        }
        while rx.try_recv().is_ok() {}
    }
    while rx.try_recv().is_ok() {}
    println!(
        "filled {} sessions ({per_bib}/BIB, {} subscribers) in {:.1} s",
        st.session_count(),
        st.subscriber_count(),
        t.elapsed().as_secs_f64()
    );
    let keys = Arc::new(keys);
    let filled = st.session_count();

    for (label, advance) in [("nothing due", 0u64), ("all due", 301)] {
        if advance > 0 {
            clock.advance(Duration::from_secs(advance));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let h = {
            let (nat, keys, stop) = (nat.clone(), keys.clone(), stop.clone());
            std::thread::spawn(move || worker(nat, keys, stop))
        };
        std::thread::sleep(Duration::from_millis(100));
        let mut passes = Vec::new();
        let mut last = None;
        let n = if advance > 0 { 1 } else { 10 };
        for _ in 0..n {
            let t = Instant::now();
            let s = st.sweep();
            passes.push(t.elapsed());
            last = Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
        stop.store(true, Ordering::Relaxed);
        let (max, p9999, _) = h.join().unwrap();
        passes.sort();
        if let Some(s) = last {
            println!("  last pass: {s:?}");
            // "all due": the refreshing worker starts 100 ms before the pass
            // and runs over its (at most 2^20) sessions: one it reaches before the
            // sweeper is re-armed and stays, one it reaches after is
            // re-created on its BIB. Every other session expires.
            if advance > 0 {
                let left = st.session_count();
                assert!(s.sessions_expired + left >= filled, "every session expired or was refreshed");
                assert!(left <= keys.len() as u64, "only worker-refreshed sessions remain");
                println!("  expired {} of {filled}; {left} refreshed or re-created by the worker", s.sessions_expired);
            }
        }
        println!(
            "{label}: pass median {:.3} ms max {:.3} ms; worker refresh max {:.1} us p99.99 {:.1} us",
            passes[passes.len() / 2].as_secs_f64() * 1e3,
            passes[passes.len() - 1].as_secs_f64() * 1e3,
            max as f64 / 1e3,
            p9999 as f64 / 1e3
        );
    }
}
