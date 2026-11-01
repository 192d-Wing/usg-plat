//! QA additions to `tests/mirror.rs` (WU4): handover release ordering,
//! held-SYN paths, a mirror that fails every call, ADF inbound-created
//! sessions, the outbound seen read-back, the slice ordering rule (plan
//! §9) observed from inside the mirror, and install inside the `bib4`
//! critical section.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 - mirror consistency tests; AU-12 (release order),
//!   SC-24 (fence ordering), SC-10 (read-back), SC-7 (ADF, I3)
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use common::*;
use plat_audit::{AcquireReason, AuditSink, BlockReleaseReason, Event};
use plat_cluster::{SliceId, SliceMap};
use plat_common::config::SteeringMode;
use plat_common::{Clock, Counters, DropReason};
use plat_nat64::mirror::NO_SLOT;
use plat_nat64::state::{Key4, Key6};
use plat_nat64::{
    AdoptInput, AdoptMeta, ClusterSetup, Directory, Mirror, MirrorEntry, MirrorFail, MirrorKeys, ModelMirror, Nat64,
    SliceState, Verdict,
};
use plat_packet::{be16, be32, proto, put32};
use plat_xlat::HEADROOM;
use plat_xlat::siit::write_v4_header;

const SERVER: u32 = 0xc633_6407; // 198.51.100.7
const OTHER: u32 = 0xc633_6409; // 198.51.100.9
const UDP_MS: u64 = 300_000;

fn cluster_fx(q: usize) -> Fx {
    let cfg = config(&[]);
    let slices = SliceMap::new(&cfg.nat64.pool, 32).unwrap();
    let setup = ClusterSetup {
        slices,
        self_id: 0,
        steering: SteeringMode::Drop,
        directory: Arc::new(Directory::new(16, 1000)),
        tcp_adopt_secs: 300,
        quarantine_secs: 600,
        reserve_ahead: 2,
    };
    let clock = Clock::new();
    let (sink, rx) = AuditSink::bounded(q);
    let nat = Nat64::new_cluster(&cfg, setup, sink, clock.clone()).unwrap();
    let ctx = nat.new_worker(Arc::new(Counters::default()), 1);
    Fx { nat, clock, rx, ctx }
}

fn startup(epoch: u64) -> AdoptMeta {
    AdoptMeta { epoch, prev_owner: None, reason: AcquireReason::Startup }
}

fn adopt_all(fx: &Fx) {
    for s in 0..4 {
        fx.nat.state().adopt_slice(s, &AdoptInput::default(), startup(1)).unwrap();
    }
}

// ---------------------------------------------------------------------
// Handover release: the fast path stops (fenced) before any entry is
// retired, every entry is retired, and every retire happens before the
// block release record that ends the attribution interval (rule 4).

#[derive(Debug)]
struct ReleaseProbe {
    inner: ModelMirror,
    rx: crossbeam_channel::Receiver<Event>,
    released: Mutex<Vec<(u32, u16, u16)>>,
    bad: Mutex<Vec<String>>,
}

impl Mirror for ReleaseProbe {
    fn install(&self, e: &MirrorEntry, shard: usize) -> Result<u32, MirrorFail> {
        self.inner.install(e, shard)
    }
    fn retire(&self, slot: u32, keys: &MirrorKeys) {
        let mut rel = self.released.lock().unwrap();
        for ev in self.rx.try_iter() {
            if let Event::PortBlockRelease { v4, port_lo, port_hi, .. } = ev {
                rel.push((v4, port_lo, port_hi));
            }
        }
        let k4 = keys.k4;
        if rel.iter().any(|&(a, lo, hi)| a == k4.addr && (lo..=hi).contains(&k4.port)) {
            self.bad.lock().unwrap().push(format!("retire after the block release record: {keys:?}"));
        }
        if self.inner.usable(slot) {
            self.bad.lock().unwrap().push(format!("retire of a still usable entry (slice not fenced): {keys:?}"));
        }
        self.inner.retire(slot, keys);
    }
    fn seen_ms(&self, slot: u32) -> u64 {
        self.inner.seen_ms(slot)
    }
    fn slice_state(&self, slice: SliceId, st: SliceState, generation: u32) {
        self.inner.slice_state(slice, st, generation);
    }
}

#[test]
fn handover_release_fences_then_retires_every_entry_before_the_release_record() {
    let mut fx = cluster_fx(1 << 16);
    let probe = Arc::new(ReleaseProbe {
        inner: ModelMirror::new(1024),
        rx: fx.rx.clone(),
        released: Mutex::new(Vec::new()),
        bad: Mutex::new(Vec::new()),
    });
    fx.nat.set_mirror(probe.clone());
    fx.clock.advance(Duration::from_secs(1));
    adopt_all(&fx);
    let _ = events(&fx);
    // Many subscribers and remotes so several BIBs (and blocks) land in
    // each slice.
    for n in 1..=24u16 {
        for r in 0..3u32 {
            run(&mut fx, &udp6(sub(n, 1), 1000 + n, SERVER + r, 53, b"x")).unwrap();
        }
    }
    let total = probe.inner.len();
    assert_eq!(total, 72);
    let per_slice = |s: SliceId| probe.inner.live().iter().filter(|(_, r)| r.entry.slice == s).count();
    let sl = (0..4).max_by_key(|&s| per_slice(s)).unwrap();
    let n = per_slice(sl);
    assert!(n > 0);

    let rel = fx.nat.state().release_slice(sl, Some(BlockReleaseReason::Handover));
    assert_eq!(rel.sessions_removed, n as u64);
    assert!(rel.blocks_released > 0);
    assert_eq!(probe.inner.retires(), n as u64, "every session of the slice retired");
    assert_eq!(probe.inner.len(), total - n, "other slices untouched");
    assert!(probe.inner.live().iter().all(|(_, r)| r.entry.slice != sl));
    assert!(probe.bad.lock().unwrap().is_empty(), "{:?}", probe.bad.lock().unwrap());
    assert!(probe.inner.violations().is_empty(), "{:?}", probe.inner.violations());
    // The release records were queued (after the retires).
    let late: Vec<_> = events(&fx)
        .into_iter()
        .filter(|e| matches!(e, Event::PortBlockRelease { reason: Some(BlockReleaseReason::Handover), .. }))
        .collect();
    assert_eq!(late.len() + probe.released.lock().unwrap().len(), rel.blocks_released as usize);
    // A second release of the same slice is a no-op for the mirror.
    fx.nat.state().release_slice(sl, Some(BlockReleaseReason::Handover));
    assert_eq!(probe.inner.retires(), n as u64);
}

#[test]
fn release_slice_on_a_legacy_pool_keeps_the_mirror() {
    let mut fx = fixture(&[]);
    let m = Arc::new(ModelMirror::new(64));
    fx.nat.set_mirror(m.clone());
    fx.clock.advance(Duration::from_secs(1));
    run(&mut fx, &udp6(sub(1, 1), 1000, SERVER, 53, b"x")).unwrap();
    let rel = fx.nat.state().release_slice(0, Some(BlockReleaseReason::Handover));
    assert_eq!(rel.sessions_removed, 0);
    assert_eq!(m.len(), 1);
    assert_eq!(m.retires(), 0);
}

// ---------------------------------------------------------------------
// Held SYNs (simultaneous open) never install: they are TCP, and a hold
// creates no session.

fn syn4(src: u32, sport: u16, k4: Key4) -> Vec<u8> {
    let mut p = tcp4(src, sport, k4.addr, k4.port, 0x02);
    write_v4_header(&mut p, 0, 40, 1, true, false, 0, 64, proto::TCP, src, k4.addr);
    put32(&mut p, 24, 7);
    l4_sum4(&mut p, proto::TCP, 16);
    p
}

#[test]
fn held_syn_paths_never_install() {
    let mut fx = fixture(&[]);
    let m = Arc::new(ModelMirror::new(64));
    fx.nat.set_mirror(m.clone());
    fx.clock.advance(Duration::from_secs(1));
    let out = run(&mut fx, &tcp6(sub(1, 1), 40000, SERVER, 443, 0x02)).unwrap();
    let k4 = Key4 { proto: proto::TCP, addr: be32(&out, 12), port: be16(&out, 20) };
    // Unsolicited inbound SYN: held, consumed.
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4)).unwrap().is_empty());
    assert_eq!(fx.nat.state().held_syn_count(), 1);
    assert_eq!(m.installs(), 0);
    // Simultaneous open completes on the subscriber's SYN: a TCP session,
    // still never mirrored.
    let _ = run_all(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 5000, 0x02));
    // Expiry of any remaining hold.
    fx.clock.advance(Duration::from_millis(6_001));
    fx.nat.state().sweep();
    let _ = fx.nat.housekeep(&mut fx.ctx);
    assert_eq!(fx.nat.state().held_syn_count(), 0);
    assert_eq!((m.installs(), m.retires()), (0, 0));
    assert!(m.violations().is_empty(), "{:?}", m.violations());
}

// ---------------------------------------------------------------------
// A mirror that refuses every install: the engine is unaffected and never
// calls retire or seen for a slot it was never given.

#[derive(Debug, Default)]
struct Refuser {
    fail: Option<MirrorFail>,
    installs: AtomicU64,
    retires: AtomicU64,
    seen: AtomicU64,
    slices: AtomicU64,
}

impl Mirror for Refuser {
    fn install(&self, _: &MirrorEntry, _: usize) -> Result<u32, MirrorFail> {
        self.installs.fetch_add(1, Ordering::Relaxed);
        Err(self.fail.unwrap_or(MirrorFail::Error))
    }
    fn retire(&self, _: u32, _: &MirrorKeys) {
        self.retires.fetch_add(1, Ordering::Relaxed);
    }
    fn seen_ms(&self, _: u32) -> u64 {
        self.seen.fetch_add(1, Ordering::Relaxed);
        u64::MAX / 2
    }
    fn slice_state(&self, _: SliceId, _: SliceState, _: u32) {
        self.slices.fetch_add(1, Ordering::Relaxed);
    }
}

fn exercise(fx: &mut Fx) {
    let s = sub(1, 1);
    for i in 0..10u16 {
        let out = run(fx, &udp6(s, 1000 + i, SERVER, 53, b"x")).unwrap();
        run(fx, &udp4(SERVER, 53, be32(&out, 12), be16(&out, 20), b"r")).unwrap();
        run(fx, &udp6(s, 1000 + i, SERVER, 53, b"y")).unwrap();
    }
    fx.clock.advance(Duration::from_millis(UDP_MS + 1));
    let st = fx.nat.state().sweep();
    assert_eq!((st.sessions_expired, st.mirror_retired), (10, 0));
}

#[test]
fn a_mirror_that_fails_every_install_leaves_the_slow_path_intact() {
    for fail in [MirrorFail::Error, MirrorFail::Exists, MirrorFail::Full] {
        let mut fx = fixture(&[]);
        let m = Arc::new(Refuser { fail: Some(fail), ..Refuser::default() });
        fx.nat.set_mirror(m.clone());
        fx.clock.advance(Duration::from_secs(1));
        exercise(&mut fx);
        let installs = m.installs.load(Ordering::Relaxed);
        // PERF-002 / QA F3: every failure class backs off for a second, so
        // the whole burst (10 flows x 3 packets) costs one attempt.
        assert_eq!(installs, 1, "{fail:?}");
        let st = fx.nat.state().mirror_install_stats().map(|s| {
            (
                s.failed.load(Ordering::Relaxed),
                s.installed.load(Ordering::Relaxed),
                s.backed_off.load(Ordering::Relaxed),
            )
        });
        assert_eq!(st, Some((1, 0, 29)), "{fail:?}: failed, installed, backed off");
        assert_eq!(m.retires.load(Ordering::Relaxed), 0, "{fail:?}: retire without a slot");
        assert_eq!(m.seen.load(Ordering::Relaxed), 0, "{fail:?}: seen without a slot (would revive)");
        assert_eq!(m.slices.load(Ordering::Relaxed), 1, "legacy slice 0 published once");
    }
}

// ---------------------------------------------------------------------
// ADF: an inbound-created session from a contacted address (another port)
// is mirrored; unsolicited inbound from another address installs nothing.

#[test]
fn adf_inbound_created_session_is_mirrored_and_unsolicited_is_not() {
    let mut fx = fixture(&[]); // address_dependent in the example
    let m = Arc::new(ModelMirror::new(64));
    fx.nat.set_mirror(m.clone());
    fx.clock.advance(Duration::from_secs(1));
    let s = sub(1, 1);
    let out = run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    let (pool4, pport) = (be32(&out, 12), be16(&out, 20));
    assert_eq!(m.len(), 1);
    // Same address, other port: allowed by ADF, a new mirrored session.
    run(&mut fx, &udp4(SERVER, 9999, pool4, pport, b"in")).unwrap();
    assert_eq!(m.len(), 2);
    let slot = m.lookup_in(pool4, SERVER, pport, 9999).unwrap();
    let k = m.slot(slot).unwrap().entry.keys;
    assert_eq!((k.k6.addr, k.k6.port), (s, 1000));
    assert_eq!(k.dst6, synth(SERVER));
    // Another address: filtered, nothing installed.
    assert_eq!(run(&mut fx, &udp4(OTHER, 53, pool4, pport, b"x")).unwrap_err(), DropReason::Filtered);
    assert_eq!(m.len(), 2);
    assert!(m.violations().is_empty(), "{:?}", m.violations());
}

// ---------------------------------------------------------------------
// Seen read-back on the outbound path: a fast-path-only flow keeps its
// session and slot on the next slow-path outbound packet.

#[test]
fn outbound_read_back_keeps_the_session_and_its_slot() {
    let mut fx = fixture(&[]);
    let m = Arc::new(ModelMirror::new(64));
    fx.nat.set_mirror(m.clone());
    fx.clock.advance(Duration::from_secs(1));
    let s = sub(1, 1);
    let out = run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    let pport = be16(&out, 20);
    let slot = m.live()[0].0;
    fx.clock.advance(Duration::from_millis(UDP_MS - 1));
    m.touch(slot, fx.nat.state().now_ms());
    fx.clock.advance(Duration::from_secs(5));
    let out = run(&mut fx, &udp6(s, 1000, SERVER, 53, b"again")).unwrap();
    assert_eq!(be16(&out, 20), pport, "same mapping");
    assert_eq!((m.installs(), m.retires()), (1, 0), "revived, not dropped and recreated");
    assert_eq!(m.live()[0].0, slot);
    // A touch of 0 ("never") does not revive.
    let k4 = fx.nat.state().lookup6(Key6 { proto: proto::UDP, addr: s, port: 1000 }).unwrap();
    m.touch(slot, 0);
    fx.clock.advance(Duration::from_millis(UDP_MS + 1));
    assert!(!fx.nat.state().has_session(k4, (SERVER, 53)));
}

// ---------------------------------------------------------------------
// Slice ordering rule (plan §9), observed from inside the mirror call: a
// restricting change reaches the mirror while the engine still shows the
// old (Active) state; an activation reaches it after the engine is
// Active. Reads the engine's slice flag only (one atomic load, no lock).

#[derive(Debug, Default)]
struct OrderProbe {
    nat: OnceLock<Weak<Nat64>>,
    told: Mutex<Vec<(SliceId, SliceState, u32)>>,
    bad: Mutex<Vec<String>>,
    checked: AtomicU64,
}

impl Mirror for OrderProbe {
    fn install(&self, _: &MirrorEntry, _: usize) -> Result<u32, MirrorFail> {
        Err(MirrorFail::Error)
    }
    fn retire(&self, _: u32, _: &MirrorKeys) {}
    fn seen_ms(&self, _: u32) -> u64 {
        0
    }
    fn slice_state(&self, slice: SliceId, st: SliceState, generation: u32) {
        let mut told = self.told.lock().unwrap();
        let last = told.iter().rev().find(|t| t.0 == slice).copied();
        if let Some(nat) = self.nat.get().and_then(Weak::upgrade) {
            let engine = nat.state().slice_state(slice);
            self.checked.fetch_add(1, Ordering::Relaxed);
            if st == SliceState::Active {
                if engine != Some(SliceState::Active) {
                    self.bad
                        .lock()
                        .unwrap()
                        .push(format!("slice {slice}: mirror Active before the engine ({engine:?})"));
                }
                if last.is_some_and(|l| generation <= l.2) {
                    self.bad
                        .lock()
                        .unwrap()
                        .push(format!("slice {slice}: no generation bump ({last:?} -> {generation})"));
                }
            } else if last.is_some_and(|l| l.1 == SliceState::Active) && engine != Some(SliceState::Active) {
                self.bad
                    .lock()
                    .unwrap()
                    .push(format!("slice {slice}: engine left Active before the mirror ({engine:?} -> {st:?})"));
            }
        }
        told.push((slice, st, generation));
    }
}

#[test]
fn slice_ordering_rule_mirror_never_more_permissive_than_engine() {
    let fx = cluster_fx(1 << 16);
    let Fx { mut nat, clock, .. } = fx;
    let probe = Arc::new(OrderProbe::default());
    nat.set_mirror(probe.clone());
    clock.advance(Duration::from_secs(1));
    let nat = Arc::new(nat);
    probe.nat.set(Arc::downgrade(&nat)).unwrap();
    let st = nat.state();
    for s in 0..4 {
        st.adopt_slice(s, &AdoptInput::default(), startup(1)).unwrap();
    }
    st.fence_slice(0);
    st.set_slice_state(0, SliceState::Active);
    st.set_slice_state(0, SliceState::Inactive);
    st.set_slice_state(0, SliceState::Active);
    st.release_slice(1, Some(BlockReleaseReason::Handover));
    st.adopt_slice(1, &AdoptInput::default(), startup(2)).unwrap();
    st.fence_slice(2);
    st.adopt_slice(2, &AdoptInput::default(), startup(3)).unwrap();
    assert!(probe.checked.load(Ordering::Relaxed) >= 10);
    assert!(probe.bad.lock().unwrap().is_empty(), "{:?}", probe.bad.lock().unwrap());
}

// ---------------------------------------------------------------------
// Install runs inside the bib4 shard critical section, and the slot is
// stored in the session in that same section: a concurrent reader of the
// session blocks until install returns, then sees the slot (never a
// session without its slot while the entry is usable).

#[derive(Debug)]
struct SlowInstall {
    inner: ModelMirror,
    tx: crossbeam_channel::Sender<(Key4, (u32, u16), Instant)>,
    done: Mutex<Option<Instant>>,
    slow: AtomicBool,
}

impl Mirror for SlowInstall {
    fn install(&self, e: &MirrorEntry, shard: usize) -> Result<u32, MirrorFail> {
        let r = self.inner.install(e, shard);
        if self.slow.load(Ordering::Relaxed) {
            self.tx.send((e.keys.k4, e.keys.remote, Instant::now())).unwrap();
            std::thread::sleep(Duration::from_millis(150));
            *self.done.lock().unwrap() = Some(Instant::now());
        }
        r
    }
    fn retire(&self, slot: u32, keys: &MirrorKeys) {
        self.inner.retire(slot, keys);
    }
    fn seen_ms(&self, slot: u32) -> u64 {
        self.inner.seen_ms(slot)
    }
    fn slice_state(&self, slice: SliceId, st: SliceState, generation: u32) {
        self.inner.slice_state(slice, st, generation);
    }
}

#[test]
fn install_is_inside_the_bib4_critical_section() {
    let fx = fixture(&[]);
    let Fx { mut nat, clock, .. } = fx;
    let (tx, rx) = crossbeam_channel::bounded(1);
    let m =
        Arc::new(SlowInstall { inner: ModelMirror::new(16), tx, done: Mutex::new(None), slow: AtomicBool::new(true) });
    nat.set_mirror(m.clone());
    clock.advance(Duration::from_secs(1));
    let nat = Arc::new(nat);
    let worker = {
        let nat = nat.clone();
        std::thread::spawn(move || {
            let mut ctx = nat.new_worker(Arc::new(Counters::default()), 1);
            let p = udp6(sub(1, 1), 1000, SERVER, 53, b"x");
            let mut buf = vec![0u8; HEADROOM + 2048];
            buf[HEADROOM..HEADROOM + p.len()].copy_from_slice(&p);
            assert!(matches!(nat.process(&mut buf, HEADROOM, p.len(), &mut ctx), Verdict::Forward { .. }));
        })
    };
    let (k4, remote, _started) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let slot = nat.state().session_slot(k4, remote);
    let after = Instant::now();
    let done = m.done.lock().unwrap().expect("reader returned before install finished: bib4 not held");
    assert!(after >= done);
    assert!(slot.is_some_and(|s| s != NO_SLOT), "slot stored in the same critical section: {slot:?}");
    worker.join().unwrap();
}
