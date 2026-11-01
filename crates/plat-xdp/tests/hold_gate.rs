//! The WU5 lock-hold gate (POAM-016, brief "WU5 gate"): `bib4` shard hold
//! times with the real `XdpMirror` on the loader's pins versus no mirror,
//! under concurrent flow creation on distinct shards plus the sweeper
//! retiring expired sessions; and the sweep cost behind
//! `plat_nat64::state::SWEEP_RETIRE_COST`.
//!
//! Root, in the VM, after `plat-xdp-loader attach` (the program attached):
//!
//! ```text
//! PLAT_XDP_GATE_CONFIG=/path/platd.toml [PLAT_XDP_GATE_PINS=/run/plat/bpf] \
//!   [PLAT_XDP_GATE_WORKERS=4] [PLAT_XDP_GATE_FLOWS=40000] \
//!   cargo test -p plat-xdp --features xdp,hold-gate --release --test hold_gate -- --ignored --nocapture
//! ```
//!
//! Holds are measured by `plat_nat64::probe` (feature `hold-probe`): every
//! worker `bib4` critical section and every sweeper `bib4` hold.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]

#[path = "../../plat-nat64/tests/common/mod.rs"]
mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{sub, udp6};
use plat_audit::AuditSink;
use plat_cluster::SliceId;
use plat_common::{Clock, Config, Counters};
use plat_nat64::probe::{self, Holder, Summary};
use plat_nat64::{Mirror, MirrorEntry, MirrorFail, MirrorKeys, Nat64, SliceState, Verdict};
use plat_xdp::load::{LoadParams, config_record};
use plat_xdp::maps::XdpMaps;
use plat_xdp::mirror::XdpMirror;
use plat_xlat::HEADROOM;

thread_local! {
    static PUB_STOP: std::cell::RefCell<Vec<Arc<AtomicBool>>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn stop_publishers() {
    PUB_STOP.with(|s| {
        for f in s.borrow_mut().drain(..) {
            f.store(true, Ordering::Release);
        }
    });
}

const SERVER: u32 = 0x0a63_0002; // 10.99.0.2 (netns.sh upstream peer)

fn env(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

struct Setup {
    cfg: Config,
    pins: PathBuf,
}

fn setup() -> Setup {
    let path = std::env::var("PLAT_XDP_GATE_CONFIG").expect("PLAT_XDP_GATE_CONFIG");
    let cfg = Config::load(path.as_ref()).unwrap();
    let pins = PathBuf::from(std::env::var("PLAT_XDP_GATE_PINS").unwrap_or_else(|_| plat_xdp::PIN_DIR.into()));
    Setup { cfg, pins }
}

/// Times every install and retire of the real writer (the part of a
/// `bib4` hold the mirror adds).
#[derive(Debug)]
struct Timed(Arc<XdpMirror>);

impl Mirror for Timed {
    fn install(&self, e: &MirrorEntry, shard: usize) -> Result<u32, MirrorFail> {
        let t = Instant::now();
        let r = Mirror::install(&*self.0, e, shard);
        probe::record(Holder::Mirror, t.elapsed().as_nanos() as u64);
        r
    }
    fn retire(&self, slot: u32, keys: &MirrorKeys) {
        let t = Instant::now();
        Mirror::retire(&*self.0, slot, keys);
        probe::record(Holder::Mirror, t.elapsed().as_nanos() as u64);
    }
    fn seen_ms(&self, slot: u32) -> u64 {
        Mirror::seen_ms(&*self.0, slot)
    }
    fn slice_state(&self, slice: SliceId, st: SliceState, generation: u32) {
        Mirror::slice_state(&*self.0, slice, st, generation);
    }
}

fn engine(s: &Setup, mirror: bool, clock: &Clock) -> (Arc<Nat64>, Option<Arc<XdpMirror>>, AuditSink) {
    let (sink, rx) = AuditSink::bounded(1 << 20);
    std::thread::spawn(move || while rx.recv().is_ok() {});
    let mut nat = Nat64::new(&s.cfg, plat_cluster::owned(&s.cfg), sink.clone(), clock.clone()).unwrap();
    let m = mirror.then(|| {
        let mut lp = LoadParams::from_config(&s.cfg);
        let st = std::env::var("PLAT_XDP_GATE_STATE").unwrap_or_else(|_| plat_xdp::STATE_FILE.into());
        lp.nonce = plat_xdp::load::read_state(st.as_ref()).unwrap().nonce;
        let exp = config_record(&lp, &plat_xdp::object_sha256());
        let maps = XdpMaps::open_pinned(&s.pins, &exp).unwrap();
        let m = Arc::new(
            XdpMirror::new(&maps, plat_xdp::slots::PARTITIONS)
                .with_clock(clock.clone(), plat_xdp::control::engine_origin_ns(clock)),
        );
        nat.set_mirror(Arc::new(Timed(m.clone())));
        m
    });
    // The publisher thread (WU5 deferred publish/delete), as in platd.
    if let Some(m) = &m {
        let m = m.clone();
        let stop = Arc::new(AtomicBool::new(false));
        PUB_STOP.with(|s| s.borrow_mut().push(stop.clone()));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                if m.flush() == 0 {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            m.flush();
        });
    }
    (Arc::new(nat), m, sink)
}

/// One run: `workers` threads create `flows` new UDP flows each (worker
/// `w` uses its own subscribers, so its BIBs land on their own shards);
/// the clock jumps past the UDP timeout every 50 ms, so the
/// sweeper (one thread, `sweep_budget` every 20 ms) retires what was
/// created before. Returns the worker and sweeper hold summaries.
fn run(s: &Setup, mirror: bool, workers: u64, flows: u64) -> (Summary, Summary, Summary, String) {
    let clock = Clock::new();
    let (nat, m, _sink) = engine(s, mirror, &clock);
    let stop = Arc::new(AtomicBool::new(false));
    let sweeper = {
        let (nat, stop) = (nat.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut retired = 0;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(20));
                retired += nat.state().sweep_budget(None, Duration::from_millis(10)).mirror_retired;
            }
            retired
        })
    };
    let udp = Duration::from_secs(u64::from(s.cfg.timeouts.udp_secs) + 1);
    let ticker = {
        let (clock, stop) = (clock.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
                clock.advance(udp);
            }
        })
    };
    probe::reset();
    let t = Instant::now();
    let ws: Vec<_> = (0..workers)
        .map(|w| {
            let nat = nat.clone();
            std::thread::spawn(move || {
                let mut ctx = nat.new_worker(Arc::new(Counters::default()), w as u16);
                let mut buf = vec![0u8; HEADROOM + 2048];
                let mut ok = 0u64;
                for j in 0..flows {
                    let p = udp6(sub(1 + (w * 1000 + j % 1000) as u16, 1), 1024 + (j / 1000) as u16, SERVER, 53, b"g");
                    buf[HEADROOM..HEADROOM + p.len()].copy_from_slice(&p);
                    if matches!(nat.process(&mut buf, HEADROOM, p.len(), &mut ctx), Verdict::Forward { .. }) {
                        ok += 1;
                    }
                }
                ok
            })
        })
        .collect();
    let created: u64 = ws.into_iter().map(|h| h.join().unwrap()).sum();
    let secs = t.elapsed().as_secs_f64();
    // Let the sweeper retire the last expired batch.
    clock.advance(udp);
    std::thread::sleep(Duration::from_millis(500));
    stop.store(true, Ordering::Relaxed);
    let retired = sweeper.join().unwrap();
    ticker.join().unwrap();
    let (w, sw, mc) = (probe::summary(Holder::Worker), probe::summary(Holder::Sweeper), probe::summary(Holder::Mirror));
    // Empty the maps for the next run (the pins outlive this engine).
    clock.advance(udp);
    while nat.state().session_count() > 0 {
        nat.state().sweep();
    }
    std::thread::sleep(Duration::from_millis(50));
    stop_publishers();
    std::thread::sleep(Duration::from_millis(20));
    let extra = m.map_or_else(String::new, |m| {
        let c = m.counters();
        format!(
            " installs={} failures(map_full/slots/error)={}/{}/{} retires={} sweeper_retired={retired}",
            c.installs.get(),
            c.install_map_full.get(),
            c.install_slots.get(),
            c.install_error.get(),
            c.retires.get()
        )
    });
    let info = format!("created={created} in {secs:.2}s ({:.0}/s){extra}", created as f64 / secs);
    (w, sw, mc, info)
}

fn show(tag: &str, w: &Summary, s: &Summary) {
    println!(
        "{tag}: worker holds n={} p50={}ns p99={}ns p99.9={}ns max={}ns >=20us={} | sweeper holds n={} p50={}ns p99={}ns max={}ns >=20us={}",
        w.n, w.p50_ns, w.p99_ns, w.p999_ns, w.max_ns, w.over_20us, s.n, s.p50_ns, s.p99_ns, s.max_ns, s.over_20us
    );
}

#[test]
#[ignore = "root, VM, loader attached (WU5 gate)"]
fn bib4_hold_gate() {
    let s = setup();
    let workers = env("PLAT_XDP_GATE_WORKERS", 4);
    let flows = env("PLAT_XDP_GATE_FLOWS", 150_000);
    let rounds = env("PLAT_XDP_GATE_ROUNDS", 5);
    let mut res = Vec::new();
    for r in 0..rounds {
        for on in [false, true] {
            let (w, sw, mc, info) = run(&s, on, workers, flows);
            let tag = format!("round {r} mirror {}", if on { "on " } else { "off" });
            show(&tag, &w, &sw);
            if on {
                println!(
                    "{tag}: mirror calls n={} p50={}ns p99={}ns p99.9={}ns max={}ns >=20us={}",
                    mc.n, mc.p50_ns, mc.p99_ns, mc.p999_ns, mc.max_ns, mc.over_20us
                );
            }
            println!("{tag}: {info}");
            res.push((on, w, sw));
        }
    }
    let best = |on: bool, f: fn(&Summary) -> u64, k: usize| {
        let mut v: Vec<u64> = res.iter().filter(|r| r.0 == on).map(|r| f(if k == 0 { &r.1 } else { &r.2 })).collect();
        v.sort_unstable();
        v[v.len() / 2]
    };
    let (p99_off, p99_on) = (best(false, |x| x.p99_ns, 0), best(true, |x| x.p99_ns, 0));
    let (max_on, smax_on) = (best(true, |x| x.max_ns, 0), best(true, |x| x.max_ns, 1));
    println!(
        "GATE (median of {rounds} rounds): worker p99 off={p99_off}ns on={p99_on}ns delta={}ns (budget 1500); \
         worker max on={max_on}ns, sweeper max on={smax_on}ns (budget 20000)",
        p99_on as i64 - p99_off as i64
    );
    if std::env::var("PLAT_XDP_GATE_ASSERT").is_ok() {
        assert!(p99_on.saturating_sub(p99_off) <= 1500, "p99 delta");
        assert!(max_on <= 20_000 && smax_on <= 20_000, "max hold");
    }
}

/// `SWEEP_RETIRE_COST` basis: one sweep of `n` expired one-session BIBs
/// with and without the mirror (single thread, nothing else running).
#[test]
#[ignore = "root, VM, loader attached (WU5 gate)"]
fn sweep_cost() {
    let s = setup();
    let n = env("PLAT_XDP_GATE_SWEEP", 20_000);
    for on in [false, true, false, true] {
        let clock = Clock::new();
        let (nat, _m, _sink) = engine(&s, on, &clock);
        let _ = &_m;
        let mut ctx = nat.new_worker(Arc::new(Counters::default()), 1);
        let mut buf = vec![0u8; HEADROOM + 2048];
        for j in 0..n {
            let p = udp6(sub(1 + (j % 4000) as u16, 1), 1024 + (j / 4000) as u16, SERVER, 53, b"s");
            buf[HEADROOM..HEADROOM + p.len()].copy_from_slice(&p);
            nat.process(&mut buf, HEADROOM, p.len(), &mut ctx);
        }
        clock.advance(Duration::from_secs(u64::from(s.cfg.timeouts.udp_secs) + 1));
        probe::reset();
        let t = Instant::now();
        let st = nat.state().sweep();
        let ns = t.elapsed().as_nanos() as u64;
        let h = probe::summary(Holder::Sweeper);
        println!(
            "sweep mirror {}: {} sessions expired, {} retired, {} holds, {:.1} ns/session, \
             hold p99={}ns max={}ns >=20us={}",
            if on { "on " } else { "off" },
            st.sessions_expired,
            st.mirror_retired,
            st.holds,
            ns as f64 / st.sessions_expired.max(1) as f64,
            h.p99_ns,
            h.max_ns,
            h.over_20us
        );
        while nat.state().session_count() > 0 {
            nat.state().sweep();
        }
        std::thread::sleep(Duration::from_millis(50));
        stop_publishers();
        std::thread::sleep(Duration::from_millis(20));
    }
}
