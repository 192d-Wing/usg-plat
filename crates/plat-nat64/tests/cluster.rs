//! Cluster HA engine behaviour (`cluster.partition = "slices"`): slice
//! ownership, replication export/import, takeover adoption and its audit
//! order, hold-back, the TCP pickup window, cool-down, ring overflow and
//! mis-steering.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use plat_audit::{AcquireReason, AuditSink, BlockReleaseReason, Event};
use plat_cluster::{SliceMap, SnapRecord};
use plat_common::config::SteeringMode;
use plat_common::{Clock, Config, Counter, Counters, DropReason};
use plat_nat64::state::{Key4, Key6};
use plat_nat64::{
    AdoptError, AdoptInput, AdoptMeta, ClusterSetup, Directory, ExportCursor, Home, Nat64, ReplHub, ReplProducer,
    ReplRecord, Shadow, SliceState, WorkerCtx,
};
use plat_packet::{be16, be32, proto};
use proptest::prelude::*;

const SERVER: u32 = 0xc633_6407; // 198.51.100.7
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const RST: u8 = 0x04;
/// Two blocks of 32256 ports per address.
const BIG_BLOCKS: (&str, &str) = ("port_block_size = 512", "port_block_size = 32256");

/// One cluster node over the /30 fixture pool, split into four /32
/// slices (slice `i` is `192.0.2.i`).
struct Node {
    fx: Fx,
    hub: Arc<ReplHub>,
    sweeper: ReplProducer,
    dir: Arc<Directory>,
    cfg: Config,
}

fn node_with(extra: &[(&str, &str)], ring: usize, steering: SteeringMode, id: u16, q: usize) -> Node {
    let cfg = config(extra);
    let slices = SliceMap::new(&cfg.nat64.pool, 32).unwrap();
    assert_eq!(slices.len(), 4);
    let dir = Arc::new(Directory::new(16, 1000));
    let setup = ClusterSetup {
        slices,
        self_id: id,
        steering,
        directory: dir.clone(),
        tcp_adopt_secs: 300,
        quarantine_secs: 600,
        reserve_ahead: 2,
    };
    let clock = Clock::new();
    let (sink, rx) = AuditSink::bounded(q);
    let nat = Nat64::new_cluster(&cfg, setup, sink, clock.clone()).unwrap();
    let (hub, mut prods) = ReplHub::new(2, ring, 4);
    let sweeper = prods.pop().unwrap();
    let worker = prods.pop().unwrap();
    let ctx = WorkerCtx::new(Arc::new(Counters::default()), 1).with_repl(worker);
    Node { fx: Fx { nat, clock, rx, ctx }, hub, sweeper, dir, cfg }
}

fn node(extra: &[(&str, &str)]) -> Node {
    node_with(extra, 1024, SteeringMode::Drop, 0, 4096)
}

fn meta(reason: AcquireReason) -> AdoptMeta {
    AdoptMeta { epoch: 7, prev_owner: Some(1), reason }
}

/// Activates every slice of `n` as a fresh owner (startup: nothing to hold).
fn start_all(n: &Node) {
    for s in 0..4 {
        let st = n.fx.nat.state();
        st.adopt_slice(
            s,
            &AdoptInput::default(),
            AdoptMeta { epoch: 1, prev_owner: None, reason: AcquireReason::Startup },
        )
        .unwrap();
    }
    let _ = events(&n.fx);
}

fn tuple4(p: &[u8]) -> (u32, u16) {
    (be32(p, 12), be16(p, 20))
}

fn shadow_for(n: &Node) -> Shadow {
    let c = &n.cfg.nat64;
    Shadow::new(SliceMap::new(&c.pool, 32).unwrap(), c.port_min, c.port_max, c.port_block_size, 120_000, 1 << 20)
}

fn drain(n: &Node) -> Vec<ReplRecord> {
    let mut v = Vec::new();
    while n.hub.drain(1024, &mut v) > 0 {}
    v
}

/// SC-24: a slice fenced between the first and a later fragment drops the
/// rest of the datagram in both directions (the stored mapping is never
/// used once the slice is no longer served).
#[test]
fn fragments_respect_slice_fencing() {
    use plat_packet::{put16, put32};
    use plat_xlat::siit::{write_v4_header, write_v6_header};
    let mut a = node(&[]);
    start_all(&a);
    let s = sub(1, 1);
    let full = udp6(s, 1000, SERVER, 53, &[1; 200]);
    let frag = |off: usize, len: usize, id: u32| {
        let mut p = vec![0u8; 48 + len];
        write_v6_header(&mut p, 0, (8 + len) as u16, proto::FRAGMENT, 64, s, synth(SERVER));
        p[40] = proto::UDP;
        put16(&mut p, 42, ((off / 8) as u16) << 3 | u16::from(off + len < 208));
        put32(&mut p, 44, id);
        p[48..].copy_from_slice(&full[40 + off..40 + off + len]);
        p
    };
    let out = run(&mut a.fx, &frag(0, 104, 1)).unwrap();
    let (v4, p4) = tuple4(&out);
    // Inbound first fragment from the server, then fence.
    let back = udp4(SERVER, 53, v4, p4, &[2; 200]);
    let mut f1 = back[..20 + 104].to_vec();
    write_v4_header(&mut f1, 0, 124, 9, false, true, 0, 64, proto::UDP, SERVER, v4);
    let mut f2 = vec![0u8; 20 + 104];
    write_v4_header(&mut f2, 0, 124, 9, false, false, 13, 64, proto::UDP, SERVER, v4);
    f2[20..].copy_from_slice(&back[124..]);
    assert!(run(&mut a.fx, &f1).is_ok());
    a.fx.nat.state().fence_slice((v4 & 3) as u16);
    assert_eq!(run_all(&mut a.fx, &frag(104, 104, 1)).unwrap_err(), DropReason::ClusterFenced);
    assert_eq!(run_all(&mut a.fx, &f2).unwrap_err(), DropReason::ClusterFenced);
}

/// POAM-034 (accepted risk, documented behaviour): the fragment entry keeps
/// the first fragment's mapping without a BIB generation. If the BIB is
/// released and the slice served again within `timeout_ms`, the remaining
/// fragments still use the old mapping; after `timeout_ms` they are not
/// translated.
#[test]
fn poam_034_stale_fragment_mapping_within_timeout() {
    use plat_packet::{put16, put32};
    use plat_xlat::siit::write_v6_header;
    let mut a = node(&[]);
    start_all(&a);
    let s = sub(1, 1);
    let full = udp6(s, 1000, SERVER, 53, &[1; 300]);
    let frag = |off: usize, len: usize, id: u32| {
        let mut p = vec![0u8; 48 + len];
        write_v6_header(&mut p, 0, (8 + len) as u16, proto::FRAGMENT, 64, s, synth(SERVER));
        p[40] = proto::UDP;
        put16(&mut p, 42, ((off / 8) as u16) << 3 | u16::from(off + len < 308));
        put32(&mut p, 44, id);
        p[48..].copy_from_slice(&full[40 + off..40 + off + len]);
        p
    };
    let out = run(&mut a.fx, &frag(0, 104, 1)).unwrap();
    let (v4, p4) = tuple4(&out);
    let slice = (v4 & 3) as u16;
    // Explicit release of the slice (handover): the BIB is gone.
    a.fx.nat.state().release_slice(slice, Some(BlockReleaseReason::Handover));
    assert!(a.fx.nat.state().lookup4(Key4 { proto: proto::UDP, addr: v4, port: p4 }).is_none());
    // While fenced, the per-fragment slice check refuses it (SC-24).
    assert_eq!(run_all(&mut a.fx, &frag(208, 100, 1)).unwrap_err(), DropReason::ClusterFenced);
    // Served again within timeout_ms: the stale mapping is still used.
    a.fx.nat.state().set_slice_state(slice, SliceState::Active);
    let out = run(&mut a.fx, &frag(104, 104, 1)).unwrap();
    let h = plat_packet::parse_v4(&out).unwrap();
    assert_eq!(h.src, v4, "POAM-034: old mapping reused without a BIB");
    // After timeout_ms the entry is gone: the last fragment is no longer
    // translated (it is only held, waiting for a first fragment).
    a.fx.clock.advance(Duration::from_millis(2_001));
    assert!(run_all(&mut a.fx, &frag(208, 100, 1)).unwrap().is_empty());
}

#[test]
fn fenced_slice_drops_and_never_allocates() {
    let mut a = node(&[]);
    start_all(&a);
    let s = sub(1, 1);
    let out = run(&mut a.fx, &udp6(s, 1000, SERVER, 53, b"q")).unwrap();
    let (v4, p4) = tuple4(&out);
    let slice = (v4 & 3) as u16;
    assert!(run(&mut a.fx, &udp4(SERVER, 53, v4, p4, b"r")).is_ok());

    assert_eq!(a.fx.nat.state().fence_slice(slice), Some(SliceState::Active));
    assert_eq!(run(&mut a.fx, &udp4(SERVER, 53, v4, p4, b"r")).unwrap_err(), DropReason::ClusterFenced);
    assert_eq!(run(&mut a.fx, &udp6(s, 1000, SERVER, 53, b"q")).unwrap_err(), DropReason::ClusterFenced);
    assert_eq!(a.fx.ctx.counters.drops(DropReason::ClusterFenced), 2);
    // A new flow of the same subscriber allocates in another (Active) slice.
    let out = run(&mut a.fx, &udp6(s, 1001, SERVER, 53, b"q")).unwrap();
    assert_ne!(tuple4(&out).0 & 3, u32::from(slice));

    // Nothing is Active: nothing allocates, inbound is fenced or wrong node.
    for x in 0..4 {
        a.fx.nat.state().fence_slice(x);
    }
    a.fx.nat.state().set_slice_state(3, SliceState::Inactive);
    assert_eq!(run(&mut a.fx, &udp6(sub(9, 1), 1, SERVER, 53, b"q")).unwrap_err(), DropReason::PortExhausted);
    assert_eq!(a.fx.nat.state().pool.total_blocks(), 0);
    assert_eq!(run(&mut a.fx, &udp4(SERVER, 53, POOL_BASE + 3, 2000, b"r")).unwrap_err(), DropReason::WrongNode);
}

#[test]
fn inactive_engine_translates_nothing() {
    let mut a = node(&[]);
    assert_eq!(run(&mut a.fx, &udp6(sub(1, 1), 1, SERVER, 53, b"q")).unwrap_err(), DropReason::PortExhausted);
    assert_eq!(run(&mut a.fx, &udp4(SERVER, 53, POOL_BASE, 2000, b"r")).unwrap_err(), DropReason::WrongNode);
    assert!(
        !events(&a.fx).iter().any(|e| matches!(e, Event::PortBlockAlloc { .. } | Event::BibCreate { .. })),
        "no attribution record without an owned slice"
    );
}

/// Runs `flows` on `a` and returns `(k6, k4)` for each.
fn make_flows(a: &mut Node, flows: &[(u16, u16, u8)]) -> Vec<(Key6, (u32, u16))> {
    let mut out = Vec::new();
    for &(n, port, p) in flows {
        let s = sub(n, 1);
        let pkt = if p == proto::TCP { tcp6(s, port, SERVER, 443, SYN) } else { udp6(s, port, SERVER, 53, b"q") };
        let o = run(&mut a.fx, &pkt).unwrap();
        out.push((Key6 { proto: p, addr: s, port }, tuple4(&o)));
    }
    out
}

fn adopt_from(b: &Node, shadow: &Shadow) {
    for s in 0..4 {
        let input = shadow.take(s, b.fx.nat.state().now_ms());
        b.fx.nat.state().adopt_slice(s, &input, meta(AcquireReason::Takeover)).unwrap();
    }
}

fn check_same(b: &mut Node, flows: &[(Key6, (u32, u16))]) {
    for (k6, k4) in flows {
        assert_eq!(b.fx.nat.state().lookup6(*k6).map(|k| (k.addr, k.port)), Some(*k4), "{k6:?}");
        if k6.proto == proto::UDP {
            let o = run(&mut b.fx, &udp6(k6.addr, k6.port, SERVER, 53, b"again")).unwrap();
            assert_eq!(tuple4(&o), *k4, "same mapping after takeover");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Export (snapshot, small budget so the cursor is exercised) → import
    /// → translate gives the same `k6 → k4` and the same blocks per
    /// subscriber; so does the streamed ring path.
    #[test]
    fn export_import_round_trip(
        flows in prop::collection::vec((0u16..6, 1000u16..1100, prop::sample::select(vec![proto::UDP, proto::TCP])), 1..30),
        budget in 1usize..8,
    ) {
        let mut flows = flows;
        flows.sort_unstable();
        flows.dedup_by_key(|f| (f.0, f.1, f.2));
        let mut a = node(&[]);
        start_all(&a);
        let _ = drain(&a);
        let made = make_flows(&mut a, &flows);

        // Snapshot path.
        let mut b = node(&[]);
        let shadow = shadow_for(&b);
        for s in 0..4 {
            shadow.snapshot_begin(s).unwrap();
            let mut cur = Some(ExportCursor::default());
            while let Some(c) = cur {
                let (recs, next) = a.fx.nat.state().export_slice(s, c, budget);
                shadow.snapshot_records(s, &recs).unwrap();
                cur = next;
            }
            shadow.snapshot_end(s).unwrap();
        }
        let blocks_a: usize = (0..4).map(|s| shadow.counts(s).0).sum();
        adopt_from(&b, &shadow);
        let evs = events(&b.fx);
        let adopts = evs.iter().filter(|e| matches!(e, Event::PortBlockAdopt { .. })).count();
        prop_assert_eq!(adopts, blocks_a);
        check_same(&mut b, &made);

        // Streamed path (ring records only, no snapshot).
        let mut c = node(&[]);
        let shadow = shadow_for(&c);
        for r in drain(&a) {
            shadow.apply(&r, 0).unwrap();
        }
        for s in 0..4 {
            shadow.snapshot_end(s).unwrap();
        }
        adopt_from(&c, &shadow);
        check_same(&mut c, &made);
    }
}

#[test]
fn adoption_is_logged_before_use_and_refused_without_queue_room() {
    let mut a = node(&[]);
    start_all(&a);
    let made = make_flows(&mut a, &[(1, 1000, proto::UDP), (2, 1000, proto::UDP), (3, 1000, proto::UDP)]);
    let shadow = shadow_for(&a);
    for r in drain(&a) {
        shadow.apply(&r, 0).unwrap();
    }
    let (v4, p4) = made[0].1;
    let slice = (v4 & 3) as u16;
    shadow.snapshot_end(slice).unwrap();
    let input = shadow.take(slice, 0);
    assert!(!input.blocks.is_empty());

    // Queue of 1 under refuse_new_bindings: no room for acquire + adopts.
    let mut b = node_with(&[], 1024, SteeringMode::Drop, 1, 1);
    let st = b.fx.nat.state();
    assert_eq!(st.adopt_slice(slice, &input, meta(AcquireReason::Takeover)), Err(AdoptError::AuditUnavailable));
    assert_eq!(st.slice_state(slice), Some(SliceState::Adopting));
    assert!(events(&b.fx).is_empty(), "nothing queued when it cannot all be queued");
    assert_eq!(run(&mut b.fx, &udp4(SERVER, 53, v4, p4, b"r")).unwrap_err(), DropReason::ClusterFenced);

    // Room again: acquire first, then one adopt per block, then Active.
    let mut b = node_with(&[], 1024, SteeringMode::Drop, 1, 4096);
    let stats = b.fx.nat.state().adopt_slice(slice, &input, meta(AcquireReason::Takeover)).unwrap();
    assert_eq!(stats.blocks_adopted as usize, input.blocks.len());
    let evs = events(&b.fx);
    let Event::ClusterSliceAcquire { acquire, .. } = &evs[0] else { panic!("acquire first: {evs:?}") };
    assert_eq!((acquire.epoch, acquire.prev_owner, acquire.in_sync), (7, Some(1), true));
    assert_eq!(acquire.blocks_adopted, stats.blocks_adopted);
    assert_eq!(acquire.slice.net, v4);
    assert!(evs[1..].iter().all(|e| matches!(e, Event::PortBlockAdopt { adopt, .. } if adopt.epoch == 7)));
    assert_eq!(evs.len(), 1 + input.blocks.len());
    assert_eq!(b.fx.nat.state().slice_state(slice), Some(SliceState::Active));
    // The adopted UDP BIB answers the subscriber's next outbound packet.
    let k6 = made[0].0;
    assert_eq!(tuple4(&run(&mut b.fx, &udp6(k6.addr, k6.port, SERVER, 53, b"q")).unwrap()), (v4, p4));
    assert!(run(&mut b.fx, &udp4(SERVER, 53, v4, p4, b"r")).is_ok());
}

#[test]
fn reserved_unseen_blocks_are_held_back() {
    let mut b = node(&[BIG_BLOCKS]);
    let addr = POOL_BASE;
    let held = plat_cluster::WireBlock { addr, block: 0 };
    let input = AdoptInput { reserved_unseen: vec![held], in_sync: true, ..AdoptInput::default() };
    let st = b.fx.nat.state().adopt_slice(0, &input, meta(AcquireReason::Takeover)).unwrap();
    assert_eq!(st.blocks_held, 1);
    let evs = events(&b.fx);
    assert!(matches!(&evs[0], Event::ClusterSliceAcquire { acquire, .. } if acquire.blocks_quarantined == 1));

    let o = run(&mut b.fx, &udp6(sub(1, 1), 1, SERVER, 53, b"q")).unwrap();
    assert!(tuple4(&o).1 >= 1024 + 32256, "only block 1 is usable");
    assert_eq!(run(&mut b.fx, &udp6(sub(2, 1), 1, SERVER, 53, b"q")).unwrap_err(), DropReason::PortExhausted);
    b.fx.clock.advance(Duration::from_secs(599));
    b.fx.nat.state().sweep();
    assert_eq!(run(&mut b.fx, &udp6(sub(2, 1), 1, SERVER, 53, b"q")).unwrap_err(), DropReason::PortExhausted);
    b.fx.clock.advance(Duration::from_secs(1));
    b.fx.nat.state().sweep();
    let o = run(&mut b.fx, &udp6(sub(2, 1), 1, SERVER, 53, b"q")).unwrap();
    assert!(tuple4(&o).1 < 1024 + 32256, "held block usable after 600 s");

    // An incomplete shadow holds back every block not adopted.
    let c = node(&[BIG_BLOCKS]);
    let input = AdoptInput { in_sync: false, hold_unknown: true, ..AdoptInput::default() };
    let st = c.fx.nat.state().adopt_slice(1, &input, meta(AcquireReason::Takeover)).unwrap();
    assert_eq!((st.blocks_held, c.fx.nat.state().pool.free_blocks()), (2, 0));
}

#[test]
fn recent_releases_finish_their_cooldown_after_takeover() {
    let mut b = node(&[BIG_BLOCKS]);
    let w = plat_cluster::WireBlock { addr: POOL_BASE, block: 0 };
    let input = AdoptInput { released: vec![(w, 100_000)], in_sync: true, ..AdoptInput::default() };
    let st = b.fx.nat.state().adopt_slice(0, &input, meta(AcquireReason::Takeover)).unwrap();
    assert_eq!(st.blocks_cooling, 1);
    run(&mut b.fx, &udp6(sub(1, 1), 1, SERVER, 53, b"q")).unwrap();
    assert_eq!(run(&mut b.fx, &udp6(sub(2, 1), 1, SERVER, 53, b"q")).unwrap_err(), DropReason::PortExhausted);
    b.fx.clock.advance(Duration::from_secs(20));
    b.fx.nat.state().sweep();
    run(&mut b.fx, &udp6(sub(2, 1), 1, SERVER, 53, b"q")).unwrap();
}

#[test]
fn block_cooldown_in_sliced_mode_and_release_is_replicated() {
    let mut a = node(&[BIG_BLOCKS, ("max_blocks_per_subscriber = 4", "max_blocks_per_subscriber = 1")]);
    a.fx.nat.state().adopt_slice(0, &AdoptInput::default(), meta(AcquireReason::Startup)).unwrap();
    run(&mut a.fx, &udp6(sub(1, 1), 1, SERVER, 53, b"q")).unwrap();
    run(&mut a.fx, &udp6(sub(2, 1), 1, SERVER, 53, b"q")).unwrap();
    let _ = drain(&a);
    let st = a.fx.nat.state();
    a.fx.clock.advance(Duration::from_secs(301));
    st.sweep_with(Some(&a.sweeper));
    a.fx.clock.advance(Duration::from_secs(3));
    st.sweep_with(Some(&a.sweeper));
    a.fx.clock.advance(Duration::from_secs(61));
    assert_eq!(st.sweep_with(Some(&a.sweeper)).blocks_released, 2);
    let recs = drain(&a);
    assert_eq!(recs.iter().filter(|r| matches!(r, ReplRecord::BibDelete { .. })).count(), 2);
    assert_eq!(recs.iter().filter(|r| matches!(r, ReplRecord::BlockRelease { .. })).count(), 2);
    assert_eq!(recs.iter().filter(|r| matches!(r, ReplRecord::SubGone { .. })).count(), 2);
    assert_eq!(run(&mut a.fx, &udp6(sub(3, 1), 1, SERVER, 53, b"q")).unwrap_err(), DropReason::PortExhausted);
    a.fx.clock.advance(Duration::from_secs(120));
    a.fx.nat.state().sweep_with(Some(&a.sweeper));
    run(&mut a.fx, &udp6(sub(3, 1), 1, SERVER, 53, b"q")).unwrap();
}

#[test]
fn tcp_pickup_window_only_on_adopted_bibs() {
    let mut a = node(&[]);
    start_all(&a);
    let s = sub(1, 1);
    let made = make_flows(&mut a, &[(1, 4000, proto::TCP), (1, 4001, proto::TCP)]);
    let shadow = shadow_for(&a);
    for r in drain(&a) {
        shadow.apply(&r, 0).unwrap();
    }
    for x in 0..4 {
        shadow.snapshot_end(x).unwrap();
    }
    let mut b = node_with(&[], 1024, SteeringMode::Drop, 1, 4096);
    adopt_from(&b, &shadow);
    let _ = events(&b.fx);

    // Non-SYN on an adopted BIB inside the window: ESTABLISHED pickup.
    let o = run(&mut b.fx, &tcp6(s, 4000, SERVER, 443, ACK)).unwrap();
    assert_eq!(tuple4(&o), made[0].1);
    let (v4, p4) = made[0].1;
    assert!(run(&mut b.fx, &tcp4(SERVER, 443, v4, p4, ACK)).is_ok(), "return traffic flows");
    // RST never creates state.
    assert_eq!(run(&mut b.fx, &tcp6(s, 4001, SERVER, 443, RST | ACK)).unwrap_err(), DropReason::TcpNoState);
    // A locally created BIB is never picked up.
    run(&mut b.fx, &tcp6(s, 4002, SERVER, 443, SYN)).unwrap();
    assert_eq!(run(&mut b.fx, &tcp6(s, 4002, SERVER, 444, ACK)).unwrap_err(), DropReason::TcpNoState);
    // After the window the adopted BIB behaves like any other.
    b.fx.clock.advance(Duration::from_secs(301));
    assert_eq!(run(&mut b.fx, &tcp6(s, 4001, SERVER, 443, ACK)).unwrap_err(), DropReason::TcpNoState);
}

#[test]
fn tcp_pickup_is_transitory_until_the_v4_side_answers() {
    let mut a = node(&[]);
    start_all(&a);
    let s = sub(1, 1);
    let made = make_flows(&mut a, &[(1, 4000, proto::TCP), (1, 4001, proto::TCP), (1, 4002, proto::TCP)]);
    let shadow = shadow_for(&a);
    for r in drain(&a) {
        shadow.apply(&r, 0).unwrap();
    }
    for x in 0..4 {
        shadow.snapshot_end(x).unwrap();
    }
    let mut b = node_with(&[], 1024, SteeringMode::Drop, 1, 4096);
    adopt_from(&b, &shadow);
    let _ = events(&b.fx);
    // RFC-002 / SEC-8: the IPv6 side alone (ACK, or FIN) keeps a picked-up
    // session on the transitory timer; an IPv4 answer establishes it.
    run(&mut b.fx, &tcp6(s, 4000, SERVER, 443, ACK)).unwrap();
    run(&mut b.fx, &tcp6(s, 4000, SERVER, 443, ACK)).unwrap();
    run(&mut b.fx, &tcp6(s, 4001, SERVER, 443, ACK)).unwrap();
    let (v4, p4) = made[1].1;
    run(&mut b.fx, &tcp4(SERVER, 443, v4, p4, ACK)).unwrap();
    run(&mut b.fx, &tcp6(s, 4002, SERVER, 443, 0x01 | ACK)).unwrap();
    b.fx.clock.advance(Duration::from_secs(241));
    let st = b.fx.nat.state();
    st.sweep();
    let alive: Vec<bool> = made
        .iter()
        .map(|(_, (v4, p4))| st.has_session(Key4 { proto: proto::TCP, addr: *v4, port: *p4 }, (SERVER, 443)))
        .collect();
    assert_eq!(alive, [false, true, false]);
}

#[test]
fn adopted_bibs_outlive_the_bib_grace_until_the_window_ends() {
    let mut a = node(&[]);
    start_all(&a);
    make_flows(&mut a, &[(1, 4000, proto::TCP)]);
    let shadow = shadow_for(&a);
    for r in drain(&a) {
        shadow.apply(&r, 0).unwrap();
    }
    let b = node(&[]);
    adopt_from(&b, &shadow);
    let st = b.fx.nat.state();
    for _ in 0..3 {
        b.fx.clock.advance(Duration::from_secs(99));
        assert_eq!(st.sweep().bibs_removed, 0);
    }
    b.fx.clock.advance(Duration::from_secs(4));
    assert_eq!(st.sweep().bibs_removed, 1);
}

#[test]
fn ring_overflow_counts_marks_dirty_and_never_blocks() {
    let mut a = node_with(&[], 2, SteeringMode::Drop, 0, 4096);
    start_all(&a);
    for i in 0..8u16 {
        run(&mut a.fx, &udp6(sub(i, 1), 1000, SERVER, 53, b"q")).unwrap();
    }
    assert_eq!(a.hub.backlog(), 2);
    assert!(a.hub.dropped_total() > 0);
    assert_eq!(a.hub.pushed_total(), 2);
    let dirty = a.hub.take_dirty();
    assert!(!dirty.is_empty() && dirty.iter().all(|&s| s < 4));
    assert!(a.hub.take_dir_dirty(), "lost SubHome records flag a directory resync");

    // Resync of a dirty slice by snapshot gives the backup the full state.
    let shadow = shadow_for(&a);
    for &s in &dirty {
        shadow.snapshot_begin(s).unwrap();
        let (recs, next) = a.fx.nat.state().export_slice(s, ExportCursor::default(), usize::MAX);
        assert!(next.is_none());
        assert!(recs.iter().any(|r| matches!(r, SnapRecord::Bib(_))));
        shadow.snapshot_records(s, &recs).unwrap();
        shadow.snapshot_end(s).unwrap();
        assert!(shadow.in_sync(s));
    }
}

#[test]
fn missteered_new_subscriber_drop_and_count_modes() {
    for (mode, dropped) in [(SteeringMode::Drop, true), (SteeringMode::Count, false)] {
        let mut a = node_with(&[], 1024, mode, 0, 4096);
        start_all(&a);
        let s = sub(5, 1);
        let prefix = s & !0xffff_ffff_ffff_ffff;
        assert!(a.dir.insert(prefix, Home { node: 2, slice: 1 }));
        let r = run(&mut a.fx, &udp6(s, 1, SERVER, 53, b"q"));
        assert_eq!(r.is_err(), dropped, "{mode:?}");
        if dropped {
            assert_eq!(r.unwrap_err(), DropReason::Missteered);
            assert_eq!(a.fx.ctx.counters.drops(DropReason::Missteered), 1);
            assert_eq!(a.fx.nat.state().subscriber_count(), 0, "nothing created");
        }
        assert_eq!(a.fx.ctx.counters.get(Counter::ClusterSteerMissteered), 1);
        // Homed on this node (or unknown): no check fires.
        assert!(a.dir.insert(prefix, Home { node: 0, slice: 1 }));
        assert!(run(&mut a.fx, &udp6(s, 2, SERVER, 53, b"q")).is_ok());
        assert!(run(&mut a.fx, &udp6(sub(6, 1), 1, SERVER, 53, b"q")).is_ok());
        assert_eq!(a.fx.ctx.counters.get(Counter::ClusterSteerMissteered), 1);
        // New subscribers are announced for the directory.
        let homes = drain(&a).iter().filter(|r| matches!(r, ReplRecord::SubHome { .. })).count();
        assert_eq!(homes, 2);
    }
}

#[test]
fn reservation_gates_block_handout() {
    let mut a = node(&[BIG_BLOCKS]);
    let st = a.fx.nat.state();
    st.set_reserve_required(0, true);
    st.adopt_slice(0, &AdoptInput::default(), meta(AcquireReason::Startup)).unwrap();
    assert_eq!(run(&mut a.fx, &udp6(sub(1, 1), 1, SERVER, 53, b"q")).unwrap_err(), DropReason::PortExhausted);
    assert_eq!(a.fx.ctx.counters.get(Counter::ClusterReserveStarved), 1);
    let st = a.fx.nat.state();
    let r = st.reserve_topup(0);
    assert_eq!(r.len(), 2);
    assert_eq!(st.reserve_deficit(0), 0);
    assert_eq!(st.reserve_acked(0, &r[1..]), 1);
    let o = run(&mut a.fx, &udp6(sub(1, 1), 1, SERVER, 53, b"q")).unwrap();
    let (v4, p4) = tuple4(&o);
    let lo = 1024 + 32256 * u32::from(r[1].block);
    assert!(v4 == r[1].addr && (lo..lo + 32256).contains(&u32::from(p4)), "the acknowledged block is used");
    let recs = drain(&a);
    assert!(recs.iter().any(|x| matches!(x, ReplRecord::BlockAlloc { block, .. } if *block == r[1])));
}

#[test]
fn handover_release_logs_and_clears_the_slice() {
    let mut a = node(&[]);
    start_all(&a);
    let made = make_flows(&mut a, &[(1, 1000, proto::UDP)]);
    let (v4, p4) = made[0].1;
    let slice = (v4 & 3) as u16;
    let _ = events(&a.fx);
    let st = a.fx.nat.state().release_slice(slice, Some(BlockReleaseReason::Handover));
    assert_eq!((st.bibs_removed, st.sessions_removed, st.blocks_released, st.subscribers_removed), (1, 1, 1, 1));
    let evs = events(&a.fx);
    assert!(matches!(&evs[..], [Event::PortBlockRelease { reason: Some(BlockReleaseReason::Handover), .. }]));
    assert_eq!(a.fx.nat.state().slice_state(slice), Some(SliceState::Fenced));
    assert_eq!(a.fx.nat.state().session_count(), 0);
    assert_eq!(run(&mut a.fx, &udp4(SERVER, 53, v4, p4, b"r")).unwrap_err(), DropReason::ClusterFenced);
    a.fx.nat.state().set_slice_state(slice, SliceState::Inactive);
    assert_eq!(run(&mut a.fx, &udp4(SERVER, 53, v4, p4, b"r")).unwrap_err(), DropReason::WrongNode);
}

#[test]
fn shadow_refuses_records_outside_the_slice() {
    let a = node(&[]);
    let shadow = shadow_for(&a);
    let wb = plat_cluster::WireBlock { addr: POOL_BASE + 1, block: 0 };
    assert!(shadow.apply(&ReplRecord::BlockAlloc { slice: 0, sub: 1, block: wb, wall_us: 0 }, 0).is_err());
    let input = AdoptInput {
        blocks: vec![(1 << 64, wb, 0)],
        bibs: vec![plat_cluster::WireBib {
            sub: 1 << 64,
            proto: 17,
            v6: (1 << 64) | 5,
            port6: 1,
            v4: POOL_BASE + 2,
            port4: 2000,
            created_wall_us: 0,
        }],
        in_sync: true,
        ..AdoptInput::default()
    };
    // Engine side: a block and a BIB of another slice are rejected, not
    // imported.
    let st = a.fx.nat.state().adopt_slice(0, &input, meta(AcquireReason::Takeover)).unwrap();
    assert_eq!((st.blocks_adopted, st.bibs_adopted, st.rejected), (0, 0, 2));
}

#[test]
fn ring_memory_is_capped() {
    // (workers + 1) x entries x 64 B (PERF-004).
    assert_eq!(plat_nat64::check_ring_memory(3, 1024), Ok(4 * 1024 * 64));
    assert!(plat_nat64::check_ring_memory(63, 1 << 20).is_err(), "4 GiB of rings");
    assert!(plat_nat64::check_ring_memory(7, 1 << 20).is_ok(), "512 MiB");
}

/// B-2 (SI-4): after an unsynced adoption every unknown block is held
/// back; a new subscriber then finds no free block. That drop is reserve
/// starvation (`cluster_reserve_starved`), not a pool that is too small.
#[test]
fn quarantined_pool_counts_reserve_starvation() {
    let mut a = node(&[]);
    for s in 0..4 {
        let st = a.fx.nat.state();
        st.adopt_slice(
            s,
            &AdoptInput { in_sync: false, hold_unknown: true, ..AdoptInput::default() },
            meta(AcquireReason::Takeover),
        )
        .unwrap();
    }
    let _ = events(&a.fx);
    let st = a.fx.nat.state();
    assert_eq!(st.pool.free_blocks(), 0);
    assert!(st.pool.held_blocks() > 0);
    assert_eq!(run(&mut a.fx, &udp6(sub(1, 1), 1, SERVER, 53, b"q")).unwrap_err(), DropReason::PortExhausted);
    assert_eq!(a.fx.ctx.counters.get(Counter::ClusterReserveStarved), 1);
}

/// B-8 (three-VM F8/F9): many new connections from a few strictly paired
/// subscribers. Each fills its first block and needs more on the same
/// address while the reservation target is held by blocks on addresses no
/// subscriber is paired to. They must get blocks once the replicator tops
/// up, and every refusal while blocks are free must be counted
/// (`cluster_reserve_starved` or `pool_paired_exhausted`), never a bare
/// `pool_exhausted`.
#[test]
fn paired_subscribers_under_connection_load_get_reserved_blocks() {
    // One /30 slice of four addresses, 64-port blocks, reserve_ahead 1:
    // fewer reserved blocks than addresses, as on the VMs (8 of 16).
    let cfg = config(&[("port_block_size = 512", "port_block_size = 64")]);
    assert!(cfg.nat64.paired_pooling);
    let slices = SliceMap::new(&cfg.nat64.pool, 30).unwrap();
    let setup = ClusterSetup {
        slices,
        self_id: 0,
        steering: SteeringMode::Drop,
        directory: Arc::new(Directory::new(16, 1000)),
        tcp_adopt_secs: 300,
        quarantine_secs: 600,
        reserve_ahead: 1,
    };
    let clock = Clock::new();
    let (sink, rx) = AuditSink::bounded(1 << 16);
    let nat = Nat64::new_cluster(&cfg, setup, sink, clock.clone()).unwrap();
    let ctx = WorkerCtx::new(Arc::new(Counters::default()), 1);
    let mut fx = Fx { nat, clock, rx, ctx };
    let pump = |fx: &Fx| {
        let st = fx.nat.state();
        let r = st.reserve_topup(0);
        st.reserve_acked(0, &r);
    };
    let st = fx.nat.state();
    st.set_reserve_required(0, true);
    st.adopt_slice(0, &AdoptInput::default(), meta(AcquireReason::Startup)).unwrap();
    pump(&fx);
    let subs = 2u16;
    let mut ok = vec![0u32; usize::from(subs)];
    let mut refused = 0u64;
    for round in 0..40u16 {
        for n in 0..subs {
            // 16 new flows per subscriber per round: a 64-port block lasts
            // four rounds.
            for f in 0..16u16 {
                match run(&mut fx, &udp6(sub(n + 1, 1), 1000 + round * 16 + f, SERVER, 53, b"q")) {
                    // max_blocks_per_subscriber reached: ICMPv6 Destination
                    // Unreachable back to the subscriber (POAM-002).
                    Ok(p) if p[0] >> 4 == 6 => {}
                    Ok(_) => ok[usize::from(n)] += 1,
                    Err(DropReason::PortExhausted) => refused += 1,
                    // max_blocks_per_subscriber reached: the goal.
                    Err(DropReason::SubscriberLimit) => {}
                    Err(e) => panic!("unexpected drop {e:?}"),
                }
            }
        }
        pump(&fx);
        let _ = events(&fx);
    }
    let c = &fx.ctx.counters;
    let counted = c.get(Counter::ClusterReserveStarved) + c.get(Counter::PoolPairedExhausted);
    assert_eq!(counted, refused, "every refusal with free blocks is counted by cause");
    assert!(fx.nat.state().pool.free_blocks() > 0);
    // Every subscriber reaches its block limit in the end.
    let limit = u32::from(cfg.nat64.max_blocks_per_subscriber) * 64;
    assert!(ok.iter().all(|n| *n == limit), "paired subscribers starved for good: {ok:?}");
}

/// POAM-013: per-aggregate subscriber counts stay consistent across
/// adoption (limit applied, over-limit blocks held back) and handover
/// release (slots freed).
#[test]
fn aggregate_counts_survive_adoption_and_handover() {
    const AGG3: (&str, &str) = ("max_subscribers_per_aggregate = 256", "max_subscribers_per_aggregate = 3");
    const AGG2: (&str, &str) = ("max_subscribers_per_aggregate = 256", "max_subscribers_per_aggregate = 2");
    let mut a = node(&[AGG3, NO_UNREACH]);
    start_all(&a);
    let _ = drain(&a);
    // sub(1..=3) share one /56.
    make_flows(&mut a, &[(1, 1000, proto::UDP), (2, 1000, proto::UDP), (3, 1000, proto::UDP)]);
    assert_eq!(a.fx.nat.state().aggregate_count(sub(1, 1)), 3);
    assert_eq!(
        run(&mut a.fx, &udp6(sub(4, 1), 1000, SERVER, 53, b"q")).unwrap_err(),
        DropReason::AggregateSubscriberLimit
    );

    // Takeover by a node with the same limit: counts carried over, still full.
    let records = drain(&a);
    let mut b = node(&[AGG3, NO_UNREACH]);
    let shadow = shadow_for(&b);
    for r in &records {
        shadow.apply(r, 0).unwrap();
    }
    for s in 0..4 {
        shadow.snapshot_end(s).unwrap();
    }
    adopt_from(&b, &shadow);
    assert_eq!(b.fx.nat.state().subscriber_count(), 3);
    assert_eq!(b.fx.nat.state().aggregate_count(sub(1, 1)), 3);
    assert_eq!(
        run(&mut b.fx, &udp6(sub(4, 1), 1000, SERVER, 53, b"q")).unwrap_err(),
        DropReason::AggregateSubscriberLimit
    );

    // Takeover by a node with a lower limit: only two subscribers adopted.
    let c = node(&[AGG2, NO_UNREACH]);
    let shadow = shadow_for(&c);
    for r in &records {
        shadow.apply(r, 0).unwrap();
    }
    for s in 0..4 {
        shadow.snapshot_end(s).unwrap();
    }
    adopt_from(&c, &shadow);
    assert_eq!(c.fx.nat.state().subscriber_count(), 2);
    assert_eq!(c.fx.nat.state().aggregate_count(sub(1, 1)), 2);

    // Handover release of every slice frees the aggregate on the old owner.
    for s in 0..4 {
        a.fx.nat.state().release_slice(s, Some(BlockReleaseReason::Handover));
    }
    assert_eq!(a.fx.nat.state().subscriber_count(), 0);
    assert_eq!(a.fx.nat.state().aggregate_count(sub(1, 1)), 0);
    // The freed aggregate admits new subscribers once the slices are back.
    for s in 0..4 {
        a.fx.nat.state().set_slice_state(s, SliceState::Inactive);
        a.fx.nat.state().adopt_slice(s, &AdoptInput::default(), meta(AcquireReason::Failback)).unwrap();
    }
    run(&mut a.fx, &udp6(sub(4, 1), 1000, SERVER, 53, b"q")).unwrap();
    assert_eq!(a.fx.nat.state().aggregate_count(sub(1, 1)), 1);
}
