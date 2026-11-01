//! Session mirror invariants (plan §4.2, §11 "Unit and concurrency tests"),
//! asserted with `ModelMirror`, the test model of the XDP maps:
//!
//! - I1: every usable mirrored entry has a live engine session with the
//!   same keys, and no entry survives its session (expiry, `drop_expired`,
//!   release, takeover);
//! - I2: a session is expired only when neither path used it within the
//!   timeout (seen read-back in the sweeper, `filter_inbound`,
//!   `lookup4_session` and the session lookups);
//! - I3: only UDP, never a hairpin or a pool remote, never in a slice that
//!   is not Active;
//! - I4: install only after the attributing audit record is queued (none
//!   under `refuse_new_bindings` without queue room; allowed, and
//!   documented, under `drop_and_alert`);
//! - fencing and generations, install rollback and back-off, the sweeper
//!   hold budget with retire cost, and all of it under concurrency.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 - invariant tests of the fast-path index against
//!   the authoritative engine state; AU-12 (I4), SC-24 (fencing), SC-10 (I2)
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use plat_audit::{AcquireReason, AuditSink, Event};
use plat_cluster::SliceMap;
use plat_common::config::SteeringMode;
use plat_common::{Clock, Config, Counters, DropReason};
use plat_nat64::mirror::{LEGACY_GENERATION, MirrorFail, NO_SLOT};
use plat_nat64::state::{Key4, Key6};
use plat_nat64::{AdoptInput, AdoptMeta, ClusterSetup, Directory, ModelMirror, Nat64, NoMirror, SliceState};
use plat_packet::{be16, be32, proto};

const SERVER: u32 = 0xc633_6407; // 198.51.100.7
const UDP_MS: u64 = 300_000;

/// Records every attributing audit record seen on `rx`, for the I4 check.
#[derive(Default)]
struct Seen {
    blocks: Vec<(u32, u16, u16)>,
    bibs: HashSet<(u32, u16)>,
}

/// A model whose install check asserts I4: a block allocation record
/// covering the pool port (port-block mode) or the BIB's `bib_create`
/// record (session mode) was queued before the install.
fn checked_model(rx: &crossbeam_channel::Receiver<Event>, cap: usize) -> Arc<ModelMirror> {
    let rx = rx.clone();
    let seen = Mutex::new(Seen::default());
    Arc::new(ModelMirror::with_check(cap, move |e| {
        let mut s = seen.lock().unwrap();
        for ev in rx.try_iter() {
            match ev {
                Event::PortBlockAlloc { v4, port_lo, port_hi, .. } => s.blocks.push((v4, port_lo, port_hi)),
                Event::BibCreate { v4, v4_port, .. } => {
                    s.bibs.insert((v4, v4_port));
                }
                _ => {}
            }
        }
        let k4 = e.keys.k4;
        let block = s.blocks.iter().any(|&(a, lo, hi)| a == k4.addr && (lo..=hi).contains(&k4.port));
        if block || s.bibs.contains(&(k4.addr, k4.port)) {
            Ok(())
        } else {
            Err(format!("I4: no attributing record queued for {k4:?}"))
        }
    }))
}

fn mirrored(extra: &[(&str, &str)], q: usize, cap: usize) -> (Fx, Arc<ModelMirror>) {
    let mut fx = fixture_q(extra, q);
    let m = checked_model(&fx.rx, cap);
    fx.nat.set_mirror(m.clone());
    fx.clock.advance(Duration::from_secs(1));
    (fx, m)
}

/// The engine's IPv4 side of `(src6, sport)`.
fn k4_of(fx: &Fx, src6: u128, sport: u16) -> Key4 {
    fx.nat.state().lookup6(Key6 { proto: proto::UDP, addr: src6, port: sport }).unwrap()
}

/// I1 at a quiescent point: every live model entry is the mirror of an
/// engine session with the same keys and slot.
fn assert_i1(nat: &Nat64, m: &ModelMirror) {
    for (slot, s) in m.live() {
        let k = s.entry.keys;
        assert_eq!(nat.state().session_slot(k.k4, k.remote), Some(slot), "I1: entry without its session {k:?}");
        assert_eq!(nat.state().lookup4(k.k4), Some(k.k6), "I1: keys {k:?}");
        assert_eq!(k.dst6, synth(k.remote.0), "canonical dst6");
    }
    assert!(m.violations().is_empty(), "{:?}", m.violations());
}

#[test]
fn no_mirror_is_the_same_as_none() {
    let mut fx = fixture(&[]);
    assert!(!fx.nat.state().mirror_on());
    fx.nat.set_mirror(Arc::new(NoMirror));
    assert!(!fx.nat.state().mirror_on());
    let s = sub(1, 1);
    run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    assert_eq!(fx.nat.state().session_slot(k4_of(&fx, s, 1000), (SERVER, 53)), Some(NO_SLOT));
}

#[test]
fn udp_session_is_mirrored_after_its_audit_record() {
    let (mut fx, m) = mirrored(&[], 4096, 64);
    assert_eq!(m.slice(0), Some((SliceState::Active, LEGACY_GENERATION)));
    let s = sub(1, 1);
    let out = run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    let (pool4, pport) = (be32(&out, 12), be16(&out, 20));
    let live = m.live();
    assert_eq!(live.len(), 1);
    let (slot, rec) = live[0];
    let k = rec.entry.keys;
    assert_eq!((k.k6.addr, k.k6.port, k.k6.proto), (s, 1000, proto::UDP));
    assert_eq!((k.k4.addr, k.k4.port), (pool4, pport));
    assert_eq!(k.remote, (SERVER, 53));
    assert_eq!((rec.entry.slice, rec.entry.generation), (0, LEGACY_GENERATION));
    assert!(m.usable(slot));
    assert_eq!(m.lookup_out(s, 1000, synth(SERVER), 53), Some(slot));
    assert_eq!(m.lookup_in(pool4, SERVER, pport, 53), Some(slot));
    // A slow-path hit does not install twice; the reply neither.
    run(&mut fx, &udp6(s, 1000, SERVER, 53, b"y")).unwrap();
    run(&mut fx, &udp4(SERVER, 53, pool4, pport, b"r")).unwrap();
    assert_eq!(m.installs(), 1);
    assert_i1(&fx.nat, &m);
}

#[test]
fn session_mode_install_follows_bib_create() {
    let (mut fx, m) = mirrored(&[("mode = \"port_block\"", "mode = \"session\"")], 4096, 64);
    run(&mut fx, &udp6(sub(1, 1), 1000, SERVER, 53, b"x")).unwrap();
    assert_eq!(m.len(), 1);
    assert_i1(&fx.nat, &m);
}

#[test]
fn only_eligible_udp_is_mirrored() {
    let (mut fx, m) = mirrored(&[], 4096, 64);
    let s = sub(1, 1);
    // TCP and ICMP sessions.
    run(&mut fx, &tcp6(s, 1000, SERVER, 80, 0x02)).unwrap();
    run(&mut fx, &echo6(s, 7, SERVER)).unwrap();
    // Own-node hairpin: the destination is in the pool.
    let _ = run_all(&mut fx, &udp6(s, 2000, POOL_BASE + 1, 53, b"hairpin"));
    assert!(m.is_empty(), "{:?}", m.live());
    assert_eq!(m.installs(), 0);
    // An ordinary UDP flow is.
    run(&mut fx, &udp6(s, 3000, SERVER, 53, b"x")).unwrap();
    assert_eq!(m.len(), 1);
    assert!(m.violations().is_empty(), "{:?}", m.violations());
}

#[test]
fn inbound_created_session_is_mirrored_except_pool_remotes() {
    let (mut fx, m) =
        mirrored(&[("filtering = \"address_dependent\"", "filtering = \"endpoint_independent\"")], 4096, 64);
    let s = sub(1, 1);
    let out = run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    let (pool4, pport) = (be32(&out, 12), be16(&out, 20));
    // EIF: another remote opens a session inbound.
    let other = 0xcb00_7105;
    run(&mut fx, &udp4(other, 4000, pool4, pport, b"in")).unwrap();
    assert_eq!(m.len(), 2);
    assert!(m.lookup_in(pool4, other, pport, 4000).is_some());
    assert_i1(&fx.nat, &m);
}

#[test]
fn expiry_retires_and_seen_read_back_extends() {
    let (mut fx, m) = mirrored(&[], 4096, 64);
    let s = sub(1, 1);
    let out = run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    let (pool4, pport) = (be32(&out, 12), be16(&out, 20));
    let k4 = Key4 { proto: proto::UDP, addr: pool4, port: pport };
    let slot = m.live()[0].0;

    // The fast path carries the flow; the slow path sees nothing.
    fx.clock.advance(Duration::from_millis(UDP_MS - 1_000));
    m.touch(slot, fx.nat.state().now_ms());
    fx.clock.advance(Duration::from_secs(200));
    // I2: expired by the slow path's refresh alone, live through `seen`,
    // in every lookup that checks expiry.
    assert!(fx.nat.state().has_session(k4, (SERVER, 53)), "lookup4_session read-back");
    assert!(fx.nat.state().filter_inbound(k4, (SERVER, 53)).is_ok(), "filter_inbound read-back");
    let st = fx.nat.state().sweep();
    assert_eq!((st.sessions_expired, st.mirror_retired), (0, 0));
    assert_eq!(m.len(), 1);

    // No packet on either path for a whole timeout: expired and retired
    // in the same sweeper hold.
    fx.clock.advance(Duration::from_millis(UDP_MS));
    assert!(!fx.nat.state().has_session(k4, (SERVER, 53)));
    let st = fx.nat.state().sweep();
    assert_eq!((st.sessions_expired, st.mirror_retired), (1, 1));
    assert!(m.is_empty());
    assert_eq!(fx.nat.state().session_slot(k4, (SERVER, 53)), None);
    assert!(m.violations().is_empty(), "{:?}", m.violations());
}

#[test]
fn read_back_on_the_packet_path_and_drop_expired_retires() {
    let (mut fx, m) = mirrored(&[], 4096, 64);
    let s = sub(1, 1);
    let out = run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    let (pool4, pport) = (be32(&out, 12), be16(&out, 20));
    let slot = m.live()[0].0;
    // Fast path only, then a slow-path reply after the slow-path expiry:
    // the session is live (read-back in the inbound lookup).
    fx.clock.advance(Duration::from_millis(UDP_MS - 1));
    m.touch(slot, fx.nat.state().now_ms());
    fx.clock.advance(Duration::from_secs(10));
    run(&mut fx, &udp4(SERVER, 53, pool4, pport, b"r")).unwrap();
    assert_eq!(m.live()[0].0, slot);

    // Expired on both paths: the next packet drops it (`drop_expired`)
    // and its mirror entry with it, then creates a fresh, mirrored one.
    fx.clock.advance(Duration::from_millis(UDP_MS + 1));
    run(&mut fx, &udp6(s, 1000, SERVER, 53, b"again")).unwrap();
    assert_eq!(m.retires(), 1);
    assert_eq!(m.len(), 1);
    assert_i1(&fx.nat, &m);

    // Inbound on an expired session: refused (ADF index forgotten) and
    // retired.
    fx.clock.advance(Duration::from_millis(UDP_MS + 1));
    assert_eq!(run(&mut fx, &udp4(SERVER, 53, pool4, pport, b"late")).unwrap_err(), DropReason::Filtered);
    assert!(m.is_empty());
    assert!(m.violations().is_empty(), "{:?}", m.violations());
}

#[test]
fn install_rollback_and_back_off() {
    let (mut fx, m) = mirrored(&[], 4096, 64);
    let s = sub(1, 1);
    let k = |fx: &Fx| fx.nat.state().session_slot(k4_of(fx, s, 1000), (SERVER, 53));
    // Refused (key exists): stays slow path, retried on the next hit.
    m.fail_next(MirrorFail::Exists, 1);
    run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    assert_eq!(k(&fx), Some(NO_SLOT));
    run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    assert_ne!(k(&fx), Some(NO_SLOT));

    // Full: no install for INSTALL_BACKOFF_MS, then the next hit installs.
    m.fail_next(MirrorFail::Full, 1);
    run(&mut fx, &udp6(s, 2000, SERVER, 53, b"x")).unwrap();
    let k2 = |fx: &Fx| fx.nat.state().session_slot(k4_of(fx, s, 2000), (SERVER, 53));
    assert_eq!(k2(&fx), Some(NO_SLOT));
    let n = m.installs();
    run(&mut fx, &udp6(s, 2000, SERVER, 53, b"x")).unwrap();
    assert_eq!((k2(&fx), m.installs()), (Some(NO_SLOT), n), "backed off");
    fx.clock.advance(Duration::from_millis(plat_nat64::mirror::INSTALL_BACKOFF_MS));
    run(&mut fx, &udp6(s, 2000, SERVER, 53, b"x")).unwrap();
    assert_ne!(k2(&fx), Some(NO_SLOT));

    // A real capacity limit: the model is full, the flow is still
    // translated by the slow path.
    let (mut fx, m) = mirrored(&[], 4096, 1);
    run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    run(&mut fx, &udp6(s, 1001, SERVER, 53, b"x")).unwrap();
    assert_eq!(m.len(), 1);
    assert_i1(&fx.nat, &m);
}

#[test]
fn no_install_under_refuse_new_bindings_without_queue_room() {
    // Queue of one record, never drained by the test.
    let mut fx = fixture_q(&[NO_UNREACH], 1);
    let m = Arc::new(ModelMirror::new(64));
    fx.nat.set_mirror(m.clone());
    fx.clock.advance(Duration::from_secs(1));
    // The first block record fills the queue.
    run(&mut fx, &udp6(sub(1, 1), 1000, SERVER, 53, b"x")).unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(run_all(&mut fx, &udp6(sub(2, 1), 1000, SERVER, 53, b"x")).unwrap_err(), DropReason::AuditUnavailable);
    assert_eq!(m.len(), 1, "I4: no session, so no install");
}

#[test]
fn drop_and_alert_installs_even_when_the_record_is_lost() {
    // Documented: with `drop_and_alert` a mapping may be used although its
    // record was lost (rule 4 exception); the mirror follows the engine.
    let mut fx = fixture_q(&[("on_overflow = \"refuse_new_bindings\"", "on_overflow = \"drop_and_alert\"")], 1);
    let m = Arc::new(ModelMirror::new(64));
    fx.nat.set_mirror(m.clone());
    fx.clock.advance(Duration::from_secs(1));
    run(&mut fx, &udp6(sub(1, 1), 1000, SERVER, 53, b"x")).unwrap();
    run(&mut fx, &udp6(sub(2, 1), 1000, SERVER, 53, b"x")).unwrap();
    assert_eq!(m.len(), 2);
}

#[test]
fn sweeper_hold_budget_counts_retire_cost() {
    // Many one-session BIBs expiring at once: each retire adds
    // SWEEP_RETIRE_COST work units, so the same chunk takes more holds.
    let holds = |with_mirror: bool| {
        let mut fx = fixture(&[
            ("port_block_size = 512", "port_block_size = 32256"),
            ("table_shards = 1024", "table_shards = 1"),
        ]);
        let m = Arc::new(ModelMirror::new(4096));
        if with_mirror {
            fx.nat.set_mirror(m.clone());
        }
        fx.clock.advance(Duration::from_secs(1));
        for i in 0..400u16 {
            run(&mut fx, &udp6(sub(1, 1), 1000 + i, SERVER, 53, b"x")).unwrap();
        }
        fx.nat.state().set_sweep_chunk(65);
        fx.clock.advance(Duration::from_millis(UDP_MS + 1));
        let st = fx.nat.state().sweep();
        assert_eq!(st.sessions_expired, 400);
        assert_eq!(st.mirror_retired, if with_mirror { 400 } else { 0 });
        assert!(m.is_empty());
        st.holds
    };
    let (off, on) = (holds(false), holds(true));
    assert!(on > off, "retire cost must shorten holds: {on} holds with the mirror vs {off} without");
}

// ---------------------------------------------------------------------
// Cluster: slice state, generation, fencing, release and takeover.

fn cluster_fx(q: usize) -> (Fx, Config) {
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
    (Fx { nat, clock, rx, ctx }, cfg)
}

fn startup(epoch: u64) -> AdoptMeta {
    AdoptMeta { epoch, prev_owner: None, reason: AcquireReason::Startup }
}

fn slice_of(a: u32) -> u16 {
    (a - POOL_BASE) as u16
}

#[test]
fn fencing_stops_the_mirror_at_once_and_generations_retire_stale_entries() {
    let (mut fx, _) = cluster_fx(1 << 16);
    let m = checked_model(&fx.rx, 256);
    fx.nat.set_mirror(m.clone());
    for s in 0..4 {
        assert_eq!(m.slice(s), Some((SliceState::Inactive, 0)), "published at attach");
    }
    fx.clock.advance(Duration::from_secs(1));
    for s in 0..4 {
        fx.nat.state().adopt_slice(s, &AdoptInput::default(), startup(1)).unwrap();
        assert_eq!(m.slice(s), Some((SliceState::Active, 1)));
    }
    let out = run(&mut fx, &udp6(sub(1, 1), 1000, SERVER, 53, b"x")).unwrap();
    let pool4 = be32(&out, 12);
    let sl = slice_of(pool4);
    let (slot, rec) = m.live()[0];
    assert_eq!((rec.entry.slice, rec.entry.generation), (sl, 1));
    assert!(m.usable(slot));

    // Fence: the mirror is not usable before the engine even drops.
    fx.nat.state().fence_slice(sl);
    assert_eq!(m.slice(sl), Some((SliceState::Fenced, 1)));
    assert!(!m.usable(slot));
    assert_eq!(run(&mut fx, &udp6(sub(1, 1), 1000, SERVER, 53, b"x")).unwrap_err(), DropReason::ClusterFenced);

    // Re-activation bumps the generation: the old entry never matches
    // again, though its session (and so the entry) still exists.
    fx.nat.state().set_slice_state(sl, SliceState::Active);
    assert_eq!(m.slice(sl), Some((SliceState::Active, 2)));
    assert!(!m.usable(slot));
    assert_i1(&fx.nat, &m);

    // Handover: release removes the sessions and their entries.
    let rel = fx.nat.state().release_slice(sl, None);
    assert_eq!(rel.sessions_removed, 1);
    assert_eq!(m.slice(sl), Some((SliceState::Fenced, 2)), "release fences");
    assert!(m.is_empty());

    // Takeover again: a new generation; new sessions mirror with it.
    fx.nat.state().adopt_slice(sl, &AdoptInput::default(), startup(2)).unwrap();
    assert_eq!(m.slice(sl), Some((SliceState::Active, 3)));
    for i in 0..16u16 {
        let _ = run(&mut fx, &udp6(sub(1, 1), 2000 + i, SERVER, 53, b"x"));
    }
    for (slot, rec) in m.live() {
        let gen_now = m.slice(rec.entry.slice).unwrap().1;
        assert_eq!(rec.entry.generation, gen_now);
        assert!(m.usable(slot));
    }
    assert_i1(&fx.nat, &m);
}

#[test]
fn adopt_slice_releases_previous_entries() {
    let (mut fx, _) = cluster_fx(1 << 16);
    let m = Arc::new(ModelMirror::new(256));
    fx.nat.set_mirror(m.clone());
    fx.clock.advance(Duration::from_secs(1));
    for s in 0..4 {
        fx.nat.state().adopt_slice(s, &AdoptInput::default(), startup(1)).unwrap();
    }
    let out = run(&mut fx, &udp6(sub(1, 1), 1000, SERVER, 53, b"x")).unwrap();
    let sl = slice_of(be32(&out, 12));
    assert_eq!(m.len(), 1);
    fx.nat.state().fence_slice(sl);
    // A takeover of a slice this node had fenced: adopt releases the stale
    // local state first (and its mirror entries).
    fx.nat.state().adopt_slice(sl, &AdoptInput::default(), startup(2)).unwrap();
    assert!(m.is_empty());
    assert!(m.violations().is_empty(), "{:?}", m.violations());
}

// ---------------------------------------------------------------------
// Concurrency: workers, sweeper, slice churn and an I1 checker at once.

/// I1 under concurrency: an entry seen live whose session is gone must
/// have been retired (or its slot reused) by the time we look again,
/// because retire runs in the critical section that removes the session.
fn check_i1_live(nat: &Nat64, m: &ModelMirror) -> Result<(), String> {
    for (slot, s) in m.live() {
        let k = s.entry.keys;
        if nat.state().session_slot(k.k4, k.remote) == Some(slot) {
            continue;
        }
        if m.slot(slot).is_some_and(|now| now.seq == s.seq) {
            return Err(format!("I1: slot {slot} live without its session {k:?}"));
        }
    }
    Ok(())
}

fn stress(nat: Arc<Nat64>, clock: Clock, m: Arc<ModelMirror>, churn: bool) {
    let stop = Arc::new(AtomicBool::new(false));
    let mut hs = Vec::new();
    for w in 0..8u16 {
        let (nat, m) = (nat.clone(), m.clone());
        hs.push(std::thread::spawn(move || {
            let mut fx_ctx = nat.new_worker(Arc::new(Counters::default()), w + 1);
            let mut buf = vec![0u8; plat_xlat::HEADROOM + 2048];
            for i in 0..3_000u32 {
                let s = sub(w + 1, (i % 16) as u16 + 1);
                let p = udp6(s, 1000 + (i % 64) as u16, SERVER + (i % 3), 53, b"x");
                buf[plat_xlat::HEADROOM..plat_xlat::HEADROOM + p.len()].copy_from_slice(&p);
                let _ = nat.process(&mut buf, plat_xlat::HEADROOM, p.len(), &mut fx_ctx);
                // The fast path touches a random live entry now and then.
                if i % 97 == 0
                    && let Some((slot, _)) = m.live().first().copied()
                {
                    m.touch(slot, nat.state().now_ms());
                }
            }
        }));
    }
    {
        let (nat, clock, stop) = (nat.clone(), clock.clone(), stop.clone());
        hs.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                clock.advance(Duration::from_secs(20));
                nat.state().sweep();
            }
        }));
    }
    if churn {
        let (nat, stop) = (nat.clone(), stop.clone());
        hs.push(std::thread::spawn(move || {
            let mut epoch = 10;
            while !stop.load(Ordering::Relaxed) {
                epoch += 1;
                let st = nat.state();
                st.fence_slice(0);
                st.set_slice_state(0, SliceState::Active);
                st.release_slice(1, None);
                let _ = st.adopt_slice(1, &AdoptInput::default(), startup(epoch));
            }
        }));
    }
    let checker = {
        let (nat, m, stop) = (nat.clone(), m.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut rounds = 0;
            while !stop.load(Ordering::Relaxed) {
                check_i1_live(&nat, &m).unwrap();
                rounds += 1;
            }
            rounds
        })
    };
    let workers: Vec<_> = hs.drain(..8).collect();
    for h in workers {
        h.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    for h in hs {
        h.join().unwrap();
    }
    assert!(checker.join().unwrap() > 0);
    assert!(m.installs() > 0);
    // Quiescent: exact I1, then everything expires and nothing survives.
    assert_i1(&nat, &m);
    clock.advance(Duration::from_millis(2 * UDP_MS + 1));
    nat.state().sweep();
    assert!(m.is_empty(), "no entry survives its session: {:?}", m.live().len());
    assert!(m.violations().is_empty(), "{:?}", m.violations());
}

#[test]
fn concurrent_workers_and_sweeper_keep_the_invariants() {
    let fx = fixture(&[("port_block_size = 512", "port_block_size = 4032")]);
    let Fx { mut nat, clock, rx, .. } = fx;
    let m = checked_model(&rx, 1 << 14);
    nat.set_mirror(m.clone());
    clock.advance(Duration::from_secs(1));
    stress(Arc::new(nat), clock, m, false);
}

#[test]
fn concurrent_slice_churn_keeps_the_invariants() {
    let (fx, _) = cluster_fx(1 << 20);
    let Fx { mut nat, clock, rx, .. } = fx;
    let m = checked_model(&rx, 1 << 14);
    nat.set_mirror(m.clone());
    clock.advance(Duration::from_secs(1));
    for s in 0..4 {
        nat.state().adopt_slice(s, &AdoptInput::default(), startup(1)).unwrap();
    }
    stress(Arc::new(nat), clock, m.clone(), true);
    // Every live entry at the end carried its slice's generation or an
    // older one (never a future one).
    for (_, rec) in m.live() {
        assert!(rec.entry.generation <= m.slice(rec.entry.slice).unwrap().1);
    }
}
