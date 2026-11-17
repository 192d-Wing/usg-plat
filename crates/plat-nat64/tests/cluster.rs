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
    node_full(extra, ring, steering, id, q, false)
}

/// A node with `cluster.ha.session_hints = "tcp"` (`hints`) or `"off"`.
fn node_h(extra: &[(&str, &str)], id: u16, hints: bool) -> Node {
    node_full(extra, 1024, SteeringMode::Drop, id, 4096, hints)
}

fn node_full(extra: &[(&str, &str)], ring: usize, steering: SteeringMode, id: u16, q: usize, hints: bool) -> Node {
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
        session_hints: hints,
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
    // Released (Inactive, POAM-048 Q2): the per-fragment slice check
    // refuses it (SC-24).
    assert_eq!(run_all(&mut a.fx, &frag(208, 100, 1)).unwrap_err(), DropReason::WrongNode);
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
    // A finished release leaves the slice Inactive (POAM-048 Q2): a regain
    // goes through adoption, never the no-import fenced path.
    assert_eq!(a.fx.nat.state().slice_state(slice), Some(SliceState::Inactive));
    assert!(!a.fx.nat.state().slice_releasing(slice));
    assert_eq!(a.fx.nat.state().session_count(), 0);
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
        session_hints: false,
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

/// POAM-012: adopted BIBs and blocks go through the chunked, hinted and
/// budgeted sweeper like local ones: the adopt window is honoured, every
/// release is replicated after its record, and the subscriber and
/// aggregate counts return to zero.
#[test]
fn chunked_budgeted_sweep_of_adopted_state() {
    let mut a = node(&[]);
    start_all(&a);
    make_flows(&mut a, &[(1, 4000, proto::UDP), (1, 4001, proto::UDP), (2, 4000, proto::UDP), (3, 4000, proto::TCP)]);
    let shadow = shadow_for(&a);
    for r in drain(&a) {
        shadow.apply(&r, 0).unwrap();
    }
    let b = node(&[]);
    adopt_from(&b, &shadow);
    let _ = drain(&b);
    let _ = events(&b.fx);
    let st = b.fx.nat.state();
    st.set_sweep_chunk(1);
    assert_eq!(st.subscriber_count(), 3);
    assert_eq!(st.aggregate_count(sub(1, 1)), 3);
    // Budgeted passes until the cycle completes (zero budget: one shard
    // per pass).
    let full = |b: &Node| {
        let mut sum = (0, 0);
        loop {
            let s = b.fx.nat.state().sweep_budget(Some(&b.sweeper), Duration::ZERO);
            sum.0 += s.bibs_removed;
            sum.1 += s.blocks_released;
            if s.complete {
                return sum;
            }
        }
    };
    // Inside the adopt window (UDP timeout 300 s, TCP pickup 300 s).
    b.fx.clock.advance(Duration::from_secs(250));
    assert_eq!(full(&b), (0, 0));
    b.fx.clock.advance(Duration::from_secs(51));
    assert_eq!(full(&b), (4, 0), "adopted BIBs leave when the window ends");
    assert!(st.sweep_resumed_total() > 0);
    b.fx.clock.advance(Duration::from_secs(61));
    assert_eq!(full(&b), (0, 3), "blocks linger, then go");
    assert_eq!(st.subscriber_count(), 0);
    assert_eq!(st.aggregate_count(sub(1, 1)), 0);
    assert_eq!(st.bib4.len(), 0);
    let recs = drain(&b);
    let n = |f: fn(&ReplRecord) -> bool| recs.iter().filter(|r| f(r)).count();
    assert_eq!(n(|r| matches!(r, ReplRecord::BibDelete { .. })), 4);
    assert_eq!(n(|r| matches!(r, ReplRecord::BlockRelease { .. })), 3);
    assert_eq!(n(|r| matches!(r, ReplRecord::SubGone { .. })), 3);
    let evs = events(&b.fx);
    assert_eq!(evs.iter().filter(|e| matches!(e, Event::PortBlockRelease { .. })).count(), 3);
}

/// RFC 6146 §3.5.2.2 held SYN (POAM-008): a slice fenced while the SYN is
/// held sends no Port Unreachable at expiry (SC-24). The Active case is in
/// `simopen.rs::expiry_port_unreachable_quotes_the_stored_syn`.
#[test]
fn held_syn_expiry_icmp_only_from_an_active_slice() {
    const OTHER: u32 = 0xc633_6409;
    let mut a = node(&[("held_syn_unreachable = false", "held_syn_unreachable = true")]);
    start_all(&a);
    let mut keys = Vec::new();
    for port in 0..2u16 {
        let out = run(&mut a.fx, &tcp6(sub(1, 1), 40000 + port, SERVER, 443, SYN)).unwrap();
        keys.push(tuple4(&out));
    }
    for (v4, p4) in &keys {
        assert!(run_all(&mut a.fx, &tcp4(OTHER, 5000, *v4, *p4, SYN)).unwrap().is_empty());
    }
    assert_eq!(a.fx.nat.state().held_syn_count(), 2);
    let slice = (keys[0].0 & 3) as u16;
    assert_eq!(a.fx.nat.state().fence_slice(slice), Some(SliceState::Active));
    a.fx.clock.advance(Duration::from_millis(6_001));
    a.fx.nat.state().sweep();
    let n = a.fx.nat.housekeep(&mut a.fx.ctx);
    let fenced = a.fx.ctx.counters.drops(DropReason::ClusterFenced);
    // Both mappings share the subscriber's (paired) address, so both
    // expiries are for the fenced slice.
    assert_eq!(keys[0].0, keys[1].0);
    assert_eq!((n, fenced), (0, 2));
    assert_eq!(a.fx.ctx.counters.get(plat_common::Counter::IcmpUnreachableSent), 0);
}

/// QA (POAM-008, SC-24): an inbound SYN for a fenced slice is never held
/// (no attacker state on a slice this node does not own).
#[test]
fn qa_fenced_slice_never_holds_a_syn() {
    const OTHER: u32 = 0xc633_6409;
    let mut a = node(&[]);
    start_all(&a);
    let out = run(&mut a.fx, &tcp6(sub(1, 1), 40000, SERVER, 443, SYN)).unwrap();
    let (v4, p4) = tuple4(&out);
    a.fx.nat.state().fence_slice((v4 & 3) as u16);
    assert!(run_all(&mut a.fx, &tcp4(OTHER, 5000, v4, p4, SYN)).is_err());
    assert_eq!(a.fx.nat.state().held_syn_count(), 0);
    assert_eq!(a.fx.ctx.counters.get(Counter::TcpSynHeld), 0);
}

/// QA (POAM-008, CP-10): after takeover, an inbound SYN to an adopted BIB
/// is held on the new owner and the subscriber's SYN promotes it.
#[test]
fn qa_held_syn_on_adopted_bib_after_takeover() {
    const OTHER: u32 = 0xc633_6409;
    let mut a = node(&[]);
    start_all(&a);
    let s = sub(1, 1);
    let made = make_flows(&mut a, &[(1, 4000, proto::TCP)]);
    let shadow = shadow_for(&a);
    for r in drain(&a) {
        shadow.apply(&r, 0).unwrap();
    }
    for x in 0..4 {
        shadow.snapshot_end(x).unwrap();
    }
    let mut b = node_with(&[], 1024, SteeringMode::Drop, 1, 4096);
    adopt_from(&b, &shadow);
    let (v4, p4) = made[0].1;
    assert!(run_all(&mut b.fx, &tcp4(OTHER, 5000, v4, p4, SYN)).unwrap().is_empty());
    assert_eq!(b.fx.nat.state().held_syn_count(), 1);
    let o = run(&mut b.fx, &tcp6(s, 4000, OTHER, 5000, SYN)).unwrap();
    assert_eq!(tuple4(&o), (v4, p4), "same mapping (EIM) on the new owner");
    assert_eq!(b.fx.nat.state().held_syn_count(), 0);
    assert_eq!(b.fx.ctx.counters.get(Counter::TcpSynHeldMatched), 1);
    assert!(run(&mut b.fx, &tcp4(OTHER, 5000, v4, p4, SYN | ACK)).is_ok());
}

// ------------------------------------------------- POAM-047 chunked adoption (QA)

/// `(k6, (v4, port4))` of one flow.
type Flow = (Key6, (u32, u16));

/// A node with `subs` subscribers on every slice (`ports` UDP flows each),
/// its replicated state in a shadow (snapshot complete), and the slice
/// holding the most subscribers with its flows.
fn loaded(subs: u16, ports: u16) -> (Shadow, u16, Vec<Flow>) {
    let mut a = node(&[]);
    start_all(&a);
    let _ = drain(&a);
    let mut flows = Vec::new();
    for n in 1..=subs {
        flows.extend((0..ports).map(|p| (n, 1000 + p, proto::UDP)));
    }
    let made = make_flows(&mut a, &flows);
    // Snapshot export (the ring may overflow at this load).
    let shadow = shadow_for(&a);
    for s in 0..4 {
        shadow.snapshot_begin(s).unwrap();
        let mut cur = Some(ExportCursor::default());
        while let Some(c) = cur {
            let (recs, next) = a.fx.nat.state().export_slice(s, c, 256);
            shadow.snapshot_records(s, &recs).unwrap();
            cur = next;
        }
        shadow.snapshot_end(s).unwrap();
    }
    let slice = (0..4u16).max_by_key(|&s| made.iter().filter(|m| (m.1.0 & 3) as u16 == s).count()).unwrap();
    let mine: Vec<_> = made.into_iter().filter(|m| (m.1.0 & 3) as u16 == slice).collect();
    assert!(mine.len() >= usize::from(ports) * 3, "{} flows on slice {slice}", mine.len());
    (shadow, slice, mine)
}

fn past() -> std::time::Instant {
    let now = std::time::Instant::now();
    now.checked_sub(Duration::from_secs(1)).unwrap_or(now)
}

/// A record queued by someone else (fills the audit queue).
fn foreign() -> Event {
    Event::ClusterSliceAcquire {
        ts_us: 0,
        acquire: Arc::new(plat_audit::SliceAcquire {
            slice: plat_audit::SliceCidr { net: 0, len: 32 },
            epoch: 0,
            prev_owner: None,
            reason: AcquireReason::Startup,
            blocks_adopted: 0,
            bibs_adopted: 0,
            blocks_quarantined: 0,
            in_sync: true,
        }),
    }
}

fn is_foreign(e: &Event) -> bool {
    matches!(e, Event::ClusterSliceAcquire { acquire, .. } if acquire.epoch == 0)
}

/// `(v4, port_lo)` of every adopt / release record.
fn adopts(evs: &[Event]) -> Vec<(u32, u16)> {
    let mut v: Vec<_> = evs
        .iter()
        .filter_map(|e| match e {
            Event::PortBlockAdopt { adopt, .. } => Some((adopt.v4, adopt.port_lo)),
            _ => None,
        })
        .collect();
    v.sort_unstable();
    v
}

fn releases(evs: &[Event]) -> Vec<(u32, u16, Option<BlockReleaseReason>)> {
    let mut v: Vec<_> = evs
        .iter()
        .filter_map(|e| match e {
            Event::PortBlockRelease { v4, port_lo, reason, .. } => Some((*v4, *port_lo, *reason)),
            _ => None,
        })
        .collect();
    v.sort_unstable_by_key(|x| (x.0, x.1));
    v
}

/// Nothing of `slice` serves: inbound to every imported mapping and the
/// subscribers' outbound are dropped, and `want` is the drop for inbound.
fn serves_nothing(b: &mut Node, flows: &[(Key6, (u32, u16))], want: DropReason) {
    for (k6, (v4, p4)) in flows {
        assert_eq!(run(&mut b.fx, &udp4(SERVER, 53, *v4, *p4, b"r")).unwrap_err(), want, "inbound {v4:x}:{p4}");
        if let Ok(o) = run(&mut b.fx, &udp6(k6.addr, k6.port, SERVER, 53, b"q")) {
            assert_ne!(tuple4(&o).0 & 3, v4 & 3, "outbound used the adopting slice");
        }
    }
}

/// POAM-047, AU-12, AU-5 (plan §8): the chunked variant of
/// `adoption_is_logged_before_use_and_refused_without_queue_room`. Under
/// `refuse_new_bindings` the queue is full when the log phase is reached
/// and is drained a little between steps: every refused step leaves the
/// slice Adopting and serving nothing; the acquire record and one adopt
/// record per block are queued exactly once, the acquire first; the slice
/// is Active, with the same mappings, only after the last of them.
#[test]
fn chunked_adoption_logged_before_use_with_queue_room_freed_between_steps() {
    let (shadow, slice, flows) = loaded(24, 3);
    let input = shadow.take(slice, 0);
    let mut b = node_with(&[], 1024, SteeringMode::Drop, 1, 64);
    let st = b.fx.nat.state();
    while st.audit().emit(foreign()) && b.fx.rx.len() < 64 {}
    let mut a =
        st.adopt_begin(slice, plat_nat64::AdoptSource::Input(input.clone()), meta(AcquireReason::Takeover)).unwrap();
    let mut seen: Vec<Event> = Vec::new();
    let (mut steps, mut refused) = (0, 0);
    loop {
        steps += 1;
        assert!(steps < 10_000, "no progress");
        let r = b.fx.nat.state().adopt_step(&mut a, past());
        match r {
            Ok(plat_nat64::Step::Done(s)) => {
                assert_eq!(s.blocks_adopted as usize, input.blocks.len());
                break;
            }
            Ok(plat_nat64::Step::More) => {}
            Err(AdoptError::AuditUnavailable) => {
                refused += 1;
                assert_eq!(a.phase(), "log");
                // Slow logger: three records per refused step.
                seen.extend(b.fx.rx.try_iter().take(3));
            }
            Err(e) => panic!("{e:?}"),
        }
        if b.fx.nat.state().slice_state(slice) == Some(SliceState::Adopting) {
            serves_nothing(&mut b, &flows, DropReason::ClusterFenced);
        }
    }
    let after_done = b.fx.rx.len();
    seen.extend(b.fx.rx.try_iter());
    assert!(refused >= 3, "{refused} refused steps: the queue was not full across steps");
    let ours: Vec<Event> = seen.into_iter().filter(|e| !is_foreign(e)).collect();
    let Event::ClusterSliceAcquire { acquire, .. } = &ours[0] else { panic!("acquire first: {ours:?}") };
    assert_eq!((acquire.epoch, acquire.blocks_adopted as usize), (7, input.blocks.len()));
    assert_eq!(ours.iter().filter(|e| matches!(e, Event::ClusterSliceAcquire { .. })).count(), 1);
    let ad = adopts(&ours);
    let mut dedup = ad.clone();
    dedup.dedup();
    assert_eq!((ad.len(), dedup.len()), (input.blocks.len(), input.blocks.len()), "every adopt record once");
    assert!(after_done >= ours.len(), "every record of the adoption was queued before the slice went Active");
    assert_eq!(b.fx.nat.state().slice_state(slice), Some(SliceState::Active));
    check_same(&mut b, &flows);
}

/// Steps `a` until `stop` holds (the slice still Adopting).
fn step_until(b: &Node, a: &mut plat_nat64::Adoption, mut stop: impl FnMut(&Node) -> bool) {
    for _ in 0..100_000 {
        if stop(b) {
            return;
        }
        assert_eq!(b.fx.nat.state().adopt_step(a, past()), Ok(plat_nat64::Step::More));
    }
    panic!("condition not reached");
}

/// SC-24, AU-12 (plan §5 abandon rows: lease lost / reassigned): abandoned
/// while importing BIBs, before any record: no release record, nothing of
/// the slice is left or served, the slice ends Inactive (`WrongNode`, not
/// Fenced) and a new adoption of the same data is complete.
#[test]
fn abandon_mid_import_logs_nothing_and_readopts_in_full() {
    let (shadow, slice, flows) = loaded(24, 3);
    let input = shadow.take(slice, 0);
    let mut b = node(&[]);
    let mut a =
        b.fx.nat
            .state()
            .adopt_begin(slice, plat_nat64::AdoptSource::Input(input.clone()), meta(AcquireReason::Takeover))
            .unwrap();
    let k6 = flows[0].0;
    step_until(&b, &mut a, |b| b.fx.nat.state().lookup6(k6).is_some());
    assert_eq!(a.phase(), "import_bibs");
    serves_nothing(&mut b, &flows, DropReason::ClusterFenced);
    assert!(b.fx.nat.state().adopt_abandon(&mut a, std::time::Instant::now() + Duration::from_secs(5), None));
    assert!(events(&b.fx).is_empty(), "nothing was logged, so nothing is released");
    let st = b.fx.nat.state();
    assert_eq!((st.subscriber_count(), st.session_count()), (0, 0));
    assert!(flows.iter().all(|(k6, _)| st.lookup6(*k6).is_none()));
    assert_eq!(st.slice_state(slice), Some(SliceState::Inactive));
    serves_nothing(&mut b, &flows, DropReason::WrongNode);
    // Regain: adopted again in full, not taken as complete.
    let s = b.fx.nat.state().adopt_slice(slice, &input, meta(AcquireReason::Takeover)).unwrap();
    assert_eq!((s.blocks_adopted as usize, s.bibs_adopted as usize), (input.blocks.len(), input.bibs.len()));
    assert_eq!(adopts(&events(&b.fx)).len(), input.blocks.len());
    check_same(&mut b, &flows);
}

/// AU-12, AU-10 (plan §5 handover row, decision 2): abandoned after every
/// adopt record was queued but before the slice went Active: each logged
/// block gets exactly one release record with the handover reason, the
/// set of released blocks equals the set of adopted ones, nothing served
/// in between, and the slice ends Inactive and re-adopts in full.
#[test]
fn abandon_after_log_releases_exactly_the_logged_blocks() {
    let (shadow, slice, flows) = loaded(24, 3);
    let input = shadow.take(slice, 0);
    let mut b = node(&[]);
    let mut a =
        b.fx.nat
            .state()
            .adopt_begin(slice, plat_nat64::AdoptSource::Input(input.clone()), meta(AcquireReason::Handover))
            .unwrap();
    let mut evs = Vec::new();
    step_until(&b, &mut a, |b| {
        evs.extend(events(&b.fx));
        adopts(&evs).len() == input.blocks.len()
    });
    assert_eq!(a.phase(), "activate", "the activation runs in a step of its own");
    serves_nothing(&mut b, &flows, DropReason::ClusterFenced);
    let rel = b.fx.nat.state().adopt_abandon_all(&mut a, Some(BlockReleaseReason::Handover));
    assert_eq!(rel.blocks_released as usize, input.blocks.len());
    let r = releases(&events(&b.fx));
    let logged: Vec<_> = adopts(&evs).into_iter().map(|(v, p)| (v, p, Some(BlockReleaseReason::Handover))).collect();
    assert_eq!(r, logged, "one release (handover) per logged block, none other");
    assert_eq!(b.fx.nat.state().slice_state(slice), Some(SliceState::Inactive));
    serves_nothing(&mut b, &flows, DropReason::WrongNode);
    let s = b.fx.nat.state().adopt_slice(slice, &input, meta(AcquireReason::Takeover)).unwrap();
    assert_eq!(s.bibs_adopted as usize, input.bibs.len());
    check_same(&mut b, &flows);
}

/// Plan §5 "newer snapshot for the slice": once detached, a snapshot that
/// reaches the shadow for the same slice does not reach the cursor. The
/// adoption completes with exactly the detached state; the new snapshot
/// stays in the shadow, charged to `max_bibs` alone once the cursor is done
/// (SC-5).
#[test]
fn newer_snapshot_during_adoption_does_not_reach_the_cursor() {
    let (shadow, slice, flows) = loaded(24, 3);
    let (blocks, bibs) = shadow.counts(slice);
    let mut b = node(&[]);
    let d = shadow.detach(slice, 0);
    let mut a =
        b.fx.nat
            .state()
            .adopt_begin(slice, plat_nat64::AdoptSource::Detached(d), meta(AcquireReason::Takeover))
            .unwrap();
    step_until(&b, &mut a, |b| b.fx.nat.state().lookup6(flows[0].0).is_some());
    // A newer snapshot of the slice: one subscriber, one block, one BIB.
    let w = plat_cluster::WireBlock { addr: POOL_BASE | u32::from(slice), block: 125 };
    let s9 = sub(900, 0);
    let bib = plat_cluster::WireBib {
        sub: s9,
        proto: proto::UDP,
        v6: s9 | 1,
        port6: 7,
        v4: w.addr,
        port4: 1024 + 125 * 512,
        created_wall_us: 1,
    };
    shadow.snapshot_begin(slice).unwrap();
    shadow
        .snapshot_records(slice, &[SnapRecord::Block { sub: s9, block: w, alloc_wall_us: 1 }, SnapRecord::Bib(bib)])
        .unwrap();
    shadow.snapshot_end(slice).unwrap();
    let s = loop {
        if let plat_nat64::Step::Done(s) = b.fx.nat.state().adopt_step(&mut a, past()).unwrap() {
            break s;
        }
    };
    assert_eq!((s.blocks_adopted as usize, s.bibs_adopted as usize), (blocks, bibs));
    assert!(b.fx.nat.state().lookup6(Key6 { proto: proto::UDP, addr: s9 | 1, port: 7 }).is_none());
    assert_eq!(shadow.counts(slice), (1, 1));
    assert_eq!(shadow.bibs_charged(), (0..4).map(|s| shadow.counts(s).1 as u64).sum::<u64>());
    check_same(&mut b, &flows);
}

/// Decision 1, SI-10: across step boundaries, `cluster_slice_acquire`
/// carries the validated count (proto, subscriber mask, block owned by the
/// same subscriber in the slice), which includes an in-input duplicate
/// `k6` (rejected at insert); `AdoptStats.bibs_adopted` is the inserted
/// count. Invalid records spread through a large set are rejected, never
/// imported, and do not stop the adoption.
#[test]
fn bibs_adopted_is_the_validated_count_across_steps() {
    let (shadow, slice, flows) = loaded(40, 60);
    let mut input = shadow.take(slice, 0);
    let good = input.bibs.len();
    assert!(good > 64 * 4, "{good} BIBs: several steps of import");
    let mut bad = Vec::new();
    for (i, x) in input.bibs.iter().enumerate().step_by(97) {
        let mut d = *x;
        match i % 3 {
            0 => d.proto = 47,                                    // GRE: invalid
            1 => d.v6 ^= 1 << 100,                                // outside the subscriber
            _ => d.v4 = POOL_BASE | ((u32::from(slice) + 1) & 3), // other slice
        }
        d.port6 = d.port6.wrapping_add(5000);
        bad.push(d);
    }
    // In-input duplicate k6 (malformed peer input): validated, then refused.
    // Same k6, another port of the same block (blocks are 512-aligned).
    let mut dup = input.bibs[3];
    dup.port4 ^= 1;
    // Same k6 and k4: a duplicate on both sides.
    let dup2 = input.bibs[3];
    input.bibs.splice(good / 2..good / 2, bad.iter().copied().chain([dup, dup2]));
    let b = node(&[]);
    let mut a =
        b.fx.nat
            .state()
            .adopt_begin(slice, plat_nat64::AdoptSource::Input(input.clone()), meta(AcquireReason::Takeover))
            .unwrap();
    let (s, steps) = (1..)
        .find_map(|n| match b.fx.nat.state().adopt_step(&mut a, past()).unwrap() {
            plat_nat64::Step::Done(s) => Some((s, n)),
            plat_nat64::Step::More => None,
        })
        .unwrap();
    assert!(steps > 4, "{steps} steps");
    assert_eq!(s.bibs_adopted as usize, good, "inserted count");
    assert_eq!(s.rejected as usize, bad.len() + 2);
    let acq = events(&b.fx).into_iter().find_map(|e| match e {
        Event::ClusterSliceAcquire { acquire, .. } => Some(acquire.bibs_adopted),
        _ => None,
    });
    assert_eq!(acq, Some((good + 2) as u64), "validated count, including the duplicates");
    for d in &bad {
        assert!(b.fx.nat.state().lookup6(Key6 { proto: d.proto, addr: d.v6, port: d.port6 }).is_none());
    }
    let _ = flows;
}

/// POAM-047 regression (plan §5, lease-lost row: "a regain re-adopts from
/// scratch"; task: "the slice ends Inactive and re-adopts in full"): the
/// cursor owns the detached shadow slice, and an abandon drops it. After a
/// lease loss with no new owner (the previous owner is dead and this node
/// is its only backup), the regain detaches an empty, out-of-sync shadow
/// slice, so every subscriber mapping of the slice is lost and every block
/// is held back, where the inline path kept them (Fenced regain). The
/// replicated state must survive an abandon that hands the slice to nobody.
#[test]
fn regain_after_lease_lost_abandon_readopts_in_full() {
    let (shadow, slice, flows) = loaded(24, 3);
    let before = shadow.counts(slice);
    let mut b = node(&[]);
    let d = shadow.detach(slice, 0);
    let mut a =
        b.fx.nat
            .state()
            .adopt_begin(slice, plat_nat64::AdoptSource::Detached(d), meta(AcquireReason::Takeover))
            .unwrap();
    step_until(&b, &mut a, |b| b.fx.nat.state().lookup6(flows[0].0).is_some());
    // Lease lost, no new owner (ctl: Release { reason: LeaseLost, new_owner: None }).
    b.fx.nat.state().adopt_abandon_all(&mut a, None);
    drop(a);
    assert_eq!(b.fx.nat.state().slice_state(slice), Some(SliceState::Inactive));
    // Regain in the next view: the ctl detaches the shadow again.
    let d = shadow.detach(slice, 0);
    let mut a =
        b.fx.nat
            .state()
            .adopt_begin(
                slice,
                plat_nat64::AdoptSource::Detached(d),
                AdoptMeta { epoch: 8, ..meta(AcquireReason::Takeover) },
            )
            .unwrap();
    let s = loop {
        if let plat_nat64::Step::Done(s) = b.fx.nat.state().adopt_step(&mut a, past()).unwrap() {
            break s;
        }
    };
    assert_eq!(
        (s.blocks_adopted as usize, s.bibs_adopted as usize, s.blocks_held),
        (before.0, before.1, 0),
        "the regain re-adopts the replicated state in full (shadow before: {before:?})"
    );
    check_same(&mut b, &flows);
}

// ------------------------------------------- POAM-048 chunked release (QA)

/// Snapshot export of every slice of `a` into a fresh shadow.
fn snapshot(a: &Node) -> Shadow {
    let shadow = shadow_for(a);
    for s in 0..4 {
        shadow.snapshot_begin(s).unwrap();
        let mut cur = Some(ExportCursor::default());
        while let Some(c) = cur {
            let (recs, next) = a.fx.nat.state().export_slice(s, c, 256);
            shadow.snapshot_records(s, &recs).unwrap();
            cur = next;
        }
        shadow.snapshot_end(s).unwrap();
    }
    shadow
}

/// `subs` subscribers with `ports` UDP mappings each on a fresh node; the
/// slice holding most of them and its mappings.
fn release_fixture(extra: &[(&str, &str)], subs: u16, ports: u16) -> (Node, u16, Vec<Flow>) {
    let mut a = node(extra);
    start_all(&a);
    let _ = drain(&a);
    let mut flows = Vec::new();
    for n in 1..=subs {
        flows.extend((0..ports).map(|p| (n, 1000 + p, proto::UDP)));
    }
    let made = make_flows(&mut a, &flows);
    let slice = (0..4u16).max_by_key(|&s| made.iter().filter(|m| (m.1.0 & 3) as u16 == s).count()).unwrap();
    let mine: Vec<_> = made.into_iter().filter(|m| (m.1.0 & 3) as u16 == slice).collect();
    let _ = events(&a.fx);
    (a, slice, mine)
}

/// Steps `r` with expired deadlines until Done; `each` runs after every
/// non-final step. Returns the stats and the step count.
fn step_release(
    n: &mut Node,
    r: &mut plat_nat64::Release,
    mut each: impl FnMut(&mut Node),
) -> (plat_nat64::ReleaseStats, usize) {
    for steps in 1..100_000 {
        match n.fx.nat.state().release_step(r, past()) {
            plat_nat64::ReleaseStep::Done(s) => return (s, steps),
            plat_nat64::ReleaseStep::More | plat_nat64::ReleaseStep::Paused => each(n),
        }
    }
    panic!("release made no progress");
}

/// Distinct `(v4, port_lo)` blocks of `flows`.
fn blocks_of(n: &Node, flows: &[(Key6, (u32, u16))]) -> Vec<(u32, u16)> {
    let size = n.cfg.nat64.port_block_size;
    let lo = n.cfg.nat64.port_min;
    let mut v: Vec<_> = flows.iter().map(|(_, (v4, p))| (*v4, lo + (p - lo) / size * size)).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// POAM-048, AU-10/AU-12, SC-24 (plan §8): a handover release stepped
/// with expired deadlines fences the slice from the first step (inbound
/// `ClusterFenced` throughout, `WrongNode` once Inactive), queues exactly
/// one `handover` release record per block, and the peer that adopts the
/// replicated slice logs one adopt record for exactly those blocks and
/// serves the same mappings: attribution is continuous across nodes.
#[test]
fn chunked_handover_release_then_adopt_on_peer() {
    let (mut a, slice, mine) = release_fixture(&[], 40, 30);
    let shadow = snapshot(&a);
    let want = blocks_of(&a, &mine);
    let mut r = a.fx.nat.state().release_begin(slice, Some(BlockReleaseReason::Handover)).unwrap();
    assert_eq!(a.fx.nat.state().slice_state(slice), Some(SliceState::Fenced));
    let probe = mine[0].1;
    let (stats, steps) = step_release(&mut a, &mut r, |n| {
        assert!(n.fx.nat.state().slice_releasing(slice));
        assert_eq!(
            run(&mut n.fx, &udp4(SERVER, 53, probe.0, probe.1, b"r")).unwrap_err(),
            DropReason::ClusterFenced,
            "a releasing slice forwards nothing"
        );
    });
    assert!(steps > 2, "{steps} steps: the release was not chunked");
    assert_eq!(stats.blocks_released as usize, want.len());
    assert_eq!(stats.bibs_removed as usize, mine.len());
    assert_eq!(a.fx.nat.state().slice_state(slice), Some(SliceState::Inactive));
    assert!(!a.fx.nat.state().slice_releasing(slice));
    let rel = releases(&events(&a.fx));
    assert!(rel.iter().all(|x| x.2 == Some(BlockReleaseReason::Handover)), "{rel:?}");
    let got: Vec<_> = rel.iter().map(|x| (x.0, x.1)).collect();
    assert_eq!(got, want, "one handover release record per block");
    for (_, (v4, p4)) in &mine {
        assert_eq!(run(&mut a.fx, &udp4(SERVER, 53, *v4, *p4, b"r")).unwrap_err(), DropReason::WrongNode);
    }

    let mut b = node_with(&[], 1024, SteeringMode::Drop, 1, 4096);
    let input = shadow.take(slice, b.fx.nat.state().now_ms());
    b.fx.nat.state().adopt_slice(slice, &input, meta(AcquireReason::Failback)).unwrap();
    assert_eq!(adopts(&events(&b.fx)), want, "the peer adopts exactly the released blocks");
    check_same(&mut b, &mine);
}

/// POAM-048 (plan §8, Q2/Q5): a regain of a slice that is still being
/// released waits: adoption (stepped and one-shot) is refused with
/// `Releasing`, a second cursor is refused, and the slice stays Fenced.
/// After the release is Done (Inactive, blocks back in the pool) the same
/// state is adopted in full and served with the same mappings.
#[test]
fn reacquire_mid_release_waits_and_readopts() {
    let (mut a, slice, mine) = release_fixture(&[], 40, 30);
    let shadow = snapshot(&a);
    let input = shadow.take(slice, a.fx.nat.state().now_ms());
    let want = blocks_of(&a, &mine);
    let st = a.fx.nat.state();
    let mut r = st.release_begin(slice, Some(BlockReleaseReason::Handover)).unwrap();
    assert_eq!(st.release_step(&mut r, past()), plat_nat64::ReleaseStep::More);
    let m = meta(AcquireReason::Failback);
    assert_eq!(
        st.adopt_begin(slice, plat_nat64::AdoptSource::Input(input.clone()), m).err(),
        Some(AdoptError::Releasing)
    );
    assert_eq!(st.adopt_slice(slice, &input, m).err(), Some(AdoptError::Releasing));
    assert!(st.release_begin(slice, None).is_none(), "one cursor per slice");
    assert_eq!(st.slice_state(slice), Some(SliceState::Fenced));
    assert!(st.slice_releasing(slice));
    let (stats, _) = step_release(&mut a, &mut r, |_| {});
    assert_eq!(stats.blocks_released as usize, want.len());
    let st = a.fx.nat.state();
    assert_eq!(st.slice_state(slice), Some(SliceState::Inactive));
    let rel: Vec<_> = releases(&events(&a.fx)).iter().map(|x| (x.0, x.1)).collect();
    assert_eq!(rel, want);
    let s = st.adopt_slice(slice, &input, m).unwrap();
    assert_eq!(s.blocks_adopted as usize, want.len());
    assert_eq!(st.slice_state(slice), Some(SliceState::Active));
    assert_eq!(adopts(&events(&a.fx)), want);
    check_same(&mut a, &mine);
}

/// POAM-048, SC-5 (plan §8): the per-aggregate subscriber count drops by
/// exactly the subscribers whose blocks a chunked release removed, never
/// early (mid-release the aggregate is still full) and never twice; after
/// every slice is released it is zero and admits a new subscriber again.
#[test]
fn aggregate_counts_survive_chunked_release() {
    const AGG3: (&str, &str) = ("max_subscribers_per_aggregate = 256", "max_subscribers_per_aggregate = 3");
    let (mut a, _, _) = release_fixture(&[AGG3, NO_UNREACH], 3, 1);
    // Many BIBs per subscriber so each release takes several steps.
    let mut flows = Vec::new();
    for n in 1..=3 {
        flows.extend((1..300).map(|p| (n, 1000 + p, proto::UDP)));
    }
    let made = make_flows(&mut a, &flows);
    let _ = events(&a.fx);
    let st = a.fx.nat.state();
    assert_eq!(st.aggregate_count(sub(1, 1)), 3);
    let slice_of = |n: u16| made.iter().find(|m| m.0.addr == sub(n, 1)).map(|m| (m.1.0 & 3) as u16).unwrap();
    let mut left = 3;
    for s in 0..4u16 {
        let gone = (1..=3).filter(|&n| slice_of(n) == s).count() as u32;
        let mut r = a.fx.nat.state().release_begin(s, None).unwrap();
        let before = left;
        let (stats, steps) = step_release(&mut a, &mut r, |n| {
            let c = n.fx.nat.state().aggregate_count(sub(1, 1));
            assert!(c <= before && c + gone >= before, "mid-release count {c}, from {before} removing {gone}");
        });
        left -= gone;
        assert_eq!(stats.subscribers_removed, u64::from(gone), "slice {s}");
        if gone > 0 {
            assert!(steps > 1, "slice {s}: {steps} steps");
        }
        assert_eq!(a.fx.nat.state().aggregate_count(sub(1, 1)), left, "after slice {s}");
    }
    assert_eq!(a.fx.nat.state().subscriber_count(), 0);
    for s in 0..4 {
        a.fx.nat.state().adopt_slice(s, &AdoptInput::default(), meta(AcquireReason::Failback)).unwrap();
    }
    run(&mut a.fx, &udp6(sub(4, 1), 1000, SERVER, 53, b"q")).unwrap();
    assert_eq!(a.fx.nat.state().aggregate_count(sub(1, 1)), 1);
}

/// POAM-048, AU-12/AU-5 (rule 4, Q1), engine level: under
/// `refuse_new_bindings` with a full queue the release pauses and never
/// gets past it, the slice stays Fenced and releasing (its blocks are not
/// back in the pool: adoption of the slice is refused), and freeing one
/// slot lets exactly one more record through; at Done every block has one
/// record and none was lost.
#[test]
fn full_queue_pauses_release_and_blocks_stay_out_of_the_pool() {
    let (a, slice, mine) = release_fixture(&[], 40, 2);
    let want = blocks_of(&a, &mine);
    assert!(want.len() > 4, "{} blocks", want.len());
    let st = a.fx.nat.state();
    assert_eq!(st.audit().capacity(), 4096);
    while st.audit().emit(foreign()) {}
    let lost0 = st.audit().stats().lost.load(std::sync::atomic::Ordering::Relaxed);
    let mut r = st.release_begin(slice, Some(BlockReleaseReason::Handover)).unwrap();
    // The bibs phase queues nothing (BIB records off): it runs until the
    // first release record is refused.
    let mut n = 0;
    while st.release_step(&mut r, past()) == plat_nat64::ReleaseStep::More {
        n += 1;
        assert!(n < 100_000);
    }
    for _ in 0..5 {
        assert_eq!(st.release_step(&mut r, past()), plat_nat64::ReleaseStep::Paused);
        assert!(st.slice_releasing(slice));
        assert_eq!(st.slice_state(slice), Some(SliceState::Fenced));
        assert_eq!(
            st.adopt_slice(slice, &AdoptInput::default(), meta(AcquireReason::Failback)).err(),
            Some(AdoptError::Releasing)
        );
    }
    let mut seen = Vec::new();
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 100_000);
        // Slow logger: one slot per step.
        seen.extend(a.fx.rx.try_recv().ok());
        match a.fx.nat.state().release_step(&mut r, past()) {
            plat_nat64::ReleaseStep::Done(s) => {
                assert_eq!(s.blocks_released as usize, want.len());
                break;
            }
            plat_nat64::ReleaseStep::Paused | plat_nat64::ReleaseStep::More => {
                assert_eq!(a.fx.nat.state().slice_state(slice), Some(SliceState::Fenced));
            }
        }
    }
    seen.extend(a.fx.rx.try_iter());
    let got: Vec<_> = releases(&seen).iter().map(|x| (x.0, x.1)).collect();
    assert_eq!(got, want, "each block's record queued exactly once");
    assert_eq!(a.fx.nat.state().audit().stats().lost.load(std::sync::atomic::Ordering::Relaxed), lost0);
    assert_eq!(a.fx.nat.state().slice_state(slice), Some(SliceState::Inactive));
}

// ------------------------------------------------------------ session hints

fn hints_of(recs: &[ReplRecord]) -> Vec<ReplRecord> {
    recs.iter().copied().filter(|r| matches!(r, ReplRecord::SessHint { .. })).collect()
}

/// TCP handshake from subscriber `n` port `port` to `SERVER:443`; returns
/// the IPv4 side of the mapping.
fn establish(a: &mut Node, n: u16, port: u16) -> (u32, u16) {
    let s = sub(n, 1);
    let o = run(&mut a.fx, &tcp6(s, port, SERVER, 443, SYN)).unwrap();
    let (v4, p4) = tuple4(&o);
    run(&mut a.fx, &tcp4(SERVER, 443, v4, p4, SYN | ACK)).unwrap();
    run(&mut a.fx, &tcp6(s, port, SERVER, 443, ACK)).unwrap();
    (v4, p4)
}

/// Streams `a`'s ring into a fresh shadow; every slice in sync, hinted as
/// given (the primary's `SnapshotEnd.hints`).
fn stream_shadow(a: &Node, hinted: bool) -> Shadow {
    let shadow = shadow_for(a);
    for r in drain(a) {
        shadow.apply(&r, 0).unwrap();
    }
    for x in 0..4 {
        shadow.snapshot_end_hinted(x, hinted).unwrap();
    }
    shadow
}

/// CP-10, SC-5: a hint is emitted once per connection, when it first
/// becomes ESTABLISHED; ACK traffic and TRANS → ESTABLISHED never emit.
#[test]
fn hint_emitted_once_on_establish() {
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let _ = drain(&a);
    let (v4, p4) = establish(&mut a, 1, 4000);
    let s = sub(1, 1);
    for _ in 0..5 {
        run(&mut a.fx, &tcp6(s, 4000, SERVER, 443, ACK)).unwrap();
        run(&mut a.fx, &tcp4(SERVER, 443, v4, p4, ACK)).unwrap();
    }
    let h = hints_of(&drain(&a));
    let slice = (v4 & 3) as u16;
    assert_eq!(h, vec![ReplRecord::SessHint { slice, v4, port4: p4, raddr: SERVER, rport: 443 }]);
    // RST then ACK: TRANS → ESTABLISHED, no new hint (T3).
    run(&mut a.fx, &tcp4(SERVER, 443, v4, p4, RST | ACK)).unwrap();
    run(&mut a.fx, &tcp6(s, 4000, SERVER, 443, ACK)).unwrap();
    run(&mut a.fx, &tcp4(SERVER, 443, v4, p4, ACK)).unwrap();
    assert!(hints_of(&drain(&a)).is_empty());
    // UDP never emits.
    run(&mut a.fx, &udp6(s, 5000, SERVER, 53, b"q")).unwrap();
    assert!(hints_of(&drain(&a)).is_empty());
}

/// Off mode is today: no hint reaches the ring, no `Sess` is exported.
#[test]
fn off_mode_emits_and_exports_no_hints() {
    let mut a = node_h(&[], 0, false);
    start_all(&a);
    let _ = drain(&a);
    let (v4, _) = establish(&mut a, 1, 4000);
    assert!(hints_of(&drain(&a)).is_empty());
    let (recs, _) = a.fx.nat.state().export_slice((v4 & 3) as u16, ExportCursor::default(), 1 << 20);
    assert!(!recs.iter().any(|r| matches!(r, SnapRecord::Sess(_))));
    assert!(!a.fx.nat.state().strict_tcp((v4 & 3) as u16));
}

/// The snapshot carries ESTABLISHED sessions only, each right after its BIB.
#[test]
fn export_includes_established_only() {
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let (v4, p4) = establish(&mut a, 1, 4000);
    // Same BIB, a second remote left in V6 INIT (no answer).
    run(&mut a.fx, &tcp6(sub(1, 1), 4000, SERVER + 1, 443, SYN)).unwrap();
    let (recs, _) = a.fx.nat.state().export_slice((v4 & 3) as u16, ExportCursor::default(), 1 << 20);
    let i = recs.iter().position(|r| matches!(r, SnapRecord::Bib(b) if b.v4 == v4 && b.port4 == p4)).unwrap();
    let sess: Vec<_> = recs.iter().filter(|r| matches!(r, SnapRecord::Sess(_))).collect();
    assert_eq!(sess.len(), 1);
    assert_eq!(
        recs.get(i + 1),
        Some(&SnapRecord::Sess(plat_cluster::WireHint { proto: 6, v4, port4: p4, raddr: SERVER, rport: 443 }))
    );
}

/// CP-10, SC-7(5): after an in-sync, hinted takeover a restored session
/// accepts the server's packet first under ADF (and APDF); other remotes
/// stay filtered; un-hinted non-SYN outbound segments are refused
/// (RFC 6146 §3.5.2.2 strict again).
#[test]
fn hinted_tcp_session_accepts_inbound_first_after_takeover() {
    for filtering in ["address_dependent", "address_port_dependent"] {
        let f = ("filtering = \"address_dependent\"", &*format!("filtering = \"{filtering}\""));
        let mut a = node_h(&[f], 0, true);
        start_all(&a);
        let (v4, p4) = establish(&mut a, 1, 4000);
        // A second TCP BIB that never reached ESTABLISHED.
        let o = run(&mut a.fx, &tcp6(sub(1, 1), 4001, SERVER, 443, SYN)).unwrap();
        let (v4b, p4b) = tuple4(&o);
        let shadow = stream_shadow(&a, true);
        assert_eq!(shadow.hint_count((v4 & 3) as u16), 1);
        let mut b = node_h(&[f], 1, true);
        let slice = (v4 & 3) as u16;
        let input = shadow.take(slice, 0);
        assert!(input.hinted && input.in_sync);
        let st = b.fx.nat.state().adopt_slice(slice, &input, meta(AcquireReason::Takeover)).unwrap();
        assert_eq!((st.sessions_restored, st.sessions_refused.total()), (1, 0), "{filtering}");
        assert!(b.fx.nat.state().strict_tcp(slice));
        let _ = events(&b.fx);
        // Server speaks first.
        let o = run(&mut b.fx, &tcp4(SERVER, 443, v4, p4, ACK)).unwrap();
        assert_eq!(be16(&o, 42), 4000, "{filtering}: delivered to the subscriber port");
        // Another port of the same server: filtered (APDF), or (ADF) the
        // address is known, so it passes the filter but needs a SYN.
        let other = run(&mut b.fx, &tcp4(SERVER, 444, v4, p4, ACK));
        assert!(other.is_err(), "{filtering}: {other:?}");
        assert_eq!(
            run(&mut b.fx, &tcp4(SERVER + 9, 443, v4, p4, ACK)).unwrap_err(),
            DropReason::Filtered,
            "{filtering}: unknown remote"
        );
        if v4b & 3 == v4 & 3 {
            // Strict: an un-hinted non-SYN outbound segment is refused, a
            // SYN still opens.
            assert_eq!(run(&mut b.fx, &tcp6(sub(1, 1), 4001, SERVER, 443, ACK)).unwrap_err(), DropReason::TcpNoState);
            assert!(run(&mut b.fx, &tcp6(sub(1, 1), 4001, SERVER, 443, SYN)).is_ok());
            let _ = p4b;
        }
    }
}

/// POAM-028 decision B4: pickup stays where hints were not active (the
/// primary had hints off, the shadow lost a hint, or this node has hints
/// off), so those configurations behave as before.
#[test]
fn not_in_sync_or_unhinted_adoption_keeps_pickup() {
    // (primary hints, shadow hinted, adopter hints)
    for (pa, hinted, pb) in [(false, false, true), (true, false, true), (true, true, false)] {
        let mut a = node_h(&[], 0, pa);
        start_all(&a);
        let (v4, _) = establish(&mut a, 1, 4000);
        let shadow = stream_shadow(&a, hinted);
        let slice = (v4 & 3) as u16;
        let mut b = node_h(&[], 1, pb);
        let st = b.fx.nat.state().adopt_slice(slice, &shadow.take(slice, 0), meta(AcquireReason::Takeover)).unwrap();
        let restored = pa && hinted && pb;
        assert_eq!(st.sessions_restored, u64::from(restored), "{pa} {hinted} {pb}");
        assert!(!b.fx.nat.state().strict_tcp(slice));
        let _ = events(&b.fx);
        // The un-hinted pickup of an outbound ACK works as today.
        assert!(run(&mut b.fx, &tcp6(sub(1, 1), 4000, SERVER, 443, ACK)).is_ok(), "{pa} {hinted} {pb}");
    }
    // Not in sync: hinted is false whatever the primary sent.
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let (v4, _) = establish(&mut a, 1, 4000);
    let shadow = stream_shadow(&a, true);
    let slice = (v4 & 3) as u16;
    shadow.mark_gap(slice);
    let input = shadow.take(slice, 0);
    assert!(!input.hinted && !input.in_sync);
}

/// The restored session lives for the pickup window and the IPv6 side
/// alone does not extend it; the IPv4 side makes it ESTABLISHED.
#[test]
fn restored_session_needs_the_v4_side() {
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let (v4, p4) = establish(&mut a, 1, 4000);
    let (v4b, p4b) = establish(&mut a, 1, 4001);
    let shadow = stream_shadow(&a, true);
    let mut b = node_h(&[], 1, true);
    adopt_from(&b, &shadow);
    let _ = drain(&b);
    let _ = events(&b.fx);
    for _ in 0..3 {
        run(&mut b.fx, &tcp6(sub(1, 1), 4000, SERVER, 443, ACK)).unwrap();
    }
    run(&mut b.fx, &tcp4(SERVER, 443, v4b, p4b, ACK)).unwrap();
    // The promoted session re-emits its hint for the new backup.
    assert_eq!(hints_of(&drain(&b)).len(), 1);
    b.fx.clock.advance(Duration::from_secs(301));
    let st = b.fx.nat.state();
    st.sweep();
    let k = |v4, p4| Key4 { proto: proto::TCP, addr: v4, port: p4 };
    assert!(!st.has_session(k(v4, p4), (SERVER, 443)), "IPv6-only: gone at the window end");
    assert!(st.has_session(k(v4b, p4b), (SERVER, 443)), "confirmed: TCP_EST");
}

/// SC-5: restore passes the node session cap; the BIB is still imported.
#[test]
fn restore_respects_session_caps() {
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let (v4, _) = establish(&mut a, 1, 4000);
    let slice = (v4 & 3) as u16;
    let mut flows = 1;
    for port in 4001..4020 {
        let (x, _) = establish(&mut a, 1, port);
        flows += usize::from(x & 3 == v4 & 3);
    }
    let shadow = stream_shadow(&a, true);
    let b = node_h(&[("max_sessions = 4000000", "max_sessions = 3")], 1, true);
    let st = b.fx.nat.state().adopt_slice(slice, &shadow.take(slice, 0), meta(AcquireReason::Takeover)).unwrap();
    assert_eq!(st.bibs_adopted as usize, flows);
    assert_eq!(st.sessions_restored, 3.min(flows as u64));
    assert_eq!(st.sessions_refused.session_limit, flows.saturating_sub(3) as u64);
    assert_eq!(b.fx.nat.state().session_count(), st.sessions_restored);
}

/// SC-7: a restored remote passes the outbound destination policy.
#[test]
fn restore_checks_destination_policy() {
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let (v4, _) = establish(&mut a, 1, 4000);
    let slice = (v4 & 3) as u16;
    let shadow = stream_shadow(&a, true);
    // The adopter denies non-global destinations (SERVER is TEST-NET-2).
    let cfg = config_strict(&[]);
    let setup = ClusterSetup {
        slices: SliceMap::new(&cfg.nat64.pool, 32).unwrap(),
        self_id: 1,
        steering: SteeringMode::Drop,
        directory: Arc::new(Directory::new(16, 1000)),
        tcp_adopt_secs: 300,
        session_hints: true,
        quarantine_secs: 600,
        reserve_ahead: 2,
    };
    let (sink, _rx) = AuditSink::bounded(4096);
    let nat = Nat64::new_cluster(&cfg, setup, sink, Clock::new()).unwrap();
    let st = nat.state().adopt_slice(slice, &shadow.take(slice, 0), meta(AcquireReason::Takeover)).unwrap();
    assert_eq!((st.bibs_adopted, st.sessions_restored, st.sessions_refused.policy), (1, 0, 1));
}

/// SC-24: an abandoned adoption with restored sessions frees them all.
#[test]
fn abandon_after_restore_frees_sessions() {
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let (v4, _) = establish(&mut a, 1, 4000);
    let slice = (v4 & 3) as u16;
    let shadow = stream_shadow(&a, true);
    let b = node_h(&[], 1, true);
    let st = b.fx.nat.state();
    let mut ad = st
        .adopt_begin(slice, plat_nat64::AdoptSource::Detached(shadow.detach(slice, 0)), meta(AcquireReason::Takeover))
        .unwrap();
    step_until(&b, &mut ad, |b| b.fx.nat.state().session_count() == 1);
    assert_eq!(st.slice_state(slice), Some(SliceState::Adopting));
    st.adopt_abandon_all(&mut ad, None);
    assert_eq!(st.session_count(), 0);
    assert_eq!(st.slice_state(slice), Some(SliceState::Inactive));
    // The hints went back to the shadow with the BIB.
    assert_eq!(shadow.hint_count(slice), 1);
    assert!(shadow.hinted(slice));
}

/// A TCP BIB of subscriber 1 in `slice`, left in V6 INIT towards
/// `SERVER:443` (no hint): `(port6, v4, port4)`.
fn syn_bib_in_slice(a: &mut Node, slice: u16, from: u16) -> (u16, u32, u16) {
    for port in from..from + 64 {
        let (v4, p4) = tuple4(&run(&mut a.fx, &tcp6(sub(1, 1), port, SERVER, 443, SYN)).unwrap());
        if (v4 & 3) as u16 == slice {
            return (port, v4, p4);
        }
    }
    panic!("no BIB in slice {slice}");
}

/// Runs a chunked adoption of `d` on `b` to the end.
fn adopt_detached(b: &Node, slice: u16, d: plat_nat64::Detached) -> plat_nat64::AdoptStats {
    let st = b.fx.nat.state();
    let mut ad = st.adopt_begin(slice, plat_nat64::AdoptSource::Detached(d), meta(AcquireReason::Takeover)).unwrap();
    loop {
        if let plat_nat64::Step::Done(x) = st.adopt_step(&mut ad, past()).unwrap() {
            return x;
        }
    }
}

/// SEC-002 / RFC-02, SC-5, CP-10: five ESTABLISHED sessions on one TCP BIB.
/// The fifth hint evicts the oldest (counted); the BIB is adopted
/// hint-incomplete, so under strict mode the evicted (live) flow is still
/// picked up on that BIB, while a complete BIB of the same slice refuses
/// an ACK-only segment. RFC-03: a FIN segment is picked up under strict
/// mode (V6 FIN RCV), a RST never.
#[test]
fn evicted_hint_keeps_pickup_on_its_bib_and_fin_is_picked_up() {
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let s = sub(1, 1);
    let (v4, p4) = establish(&mut a, 1, 4000);
    for i in 1..5u32 {
        run(&mut a.fx, &tcp6(s, 4000, SERVER + i, 443, SYN)).unwrap();
        run(&mut a.fx, &tcp4(SERVER + i, 443, v4, p4, SYN | ACK)).unwrap();
        run(&mut a.fx, &tcp6(s, 4000, SERVER + i, 443, ACK)).unwrap();
    }
    let slice = (v4 & 3) as u16;
    let (cport, cv4, cp4) = syn_bib_in_slice(&mut a, slice, 5000);
    let shadow = stream_shadow(&a, true);
    assert_eq!(shadow.hint_stats().evicted.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(shadow.hint_count(slice), plat_nat64::repl::MAX_HINTS);
    let input = shadow.take(slice, 0);
    assert_eq!(input.hints_lossy, vec![(v4, p4)]);
    assert!(input.hinted, "an eviction does not un-hint the slice");
    let mut b = node_h(&[], 1, true);
    let st = b.fx.nat.state().adopt_slice(slice, &input, meta(AcquireReason::Takeover)).unwrap();
    assert_eq!(st.sessions_restored, 4);
    assert!(b.fx.nat.state().strict_tcp(slice));
    let _ = events(&b.fx);
    // A restored remote: server speaks first.
    assert!(run(&mut b.fx, &tcp4(SERVER + 4, 443, v4, p4, ACK)).is_ok());
    // The evicted remote (SERVER): picked up on its hint-incomplete BIB.
    assert!(run(&mut b.fx, &tcp6(s, 4000, SERVER, 443, ACK)).is_ok());
    // The complete BIB: ACK-only and RST refused, FIN picked up.
    let _ = (cv4, cp4);
    assert_eq!(run(&mut b.fx, &tcp6(s, cport, SERVER, 443, ACK)).unwrap_err(), DropReason::TcpNoState);
    assert_eq!(run(&mut b.fx, &tcp6(s, cport, SERVER + 7, 443, RST | ACK)).unwrap_err(), DropReason::TcpNoState);
    assert!(run(&mut b.fx, &tcp6(s, cport, SERVER, 443, 0x01 | ACK)).is_ok());
    let k = Key4 { proto: proto::TCP, addr: cv4, port: cp4 };
    assert!(b.fx.nat.state().has_session(k, (SERVER, 443)));
    // V6 FIN RCV runs on the transitory timer (240 s) and the IPv6 side
    // alone does not extend it.
    b.fx.clock.advance(Duration::from_secs(241));
    b.fx.nat.state().sweep();
    assert!(!b.fx.nat.state().has_session(k, (SERVER, 443)));
}

/// SEC-004, SC-10: a FIN picked up under strict mode stays on TCP_TRANS
/// while only the IPv6 side sends; an IPv4 packet promotes it to V6 FIN
/// RCV on TCP_EST as before.
#[test]
fn strict_fin_pickup_needs_the_v4_side_to_reach_tcp_est() {
    for v4_speaks in [false, true] {
        let mut a = node_h(&[], 0, true);
        start_all(&a);
        let s = sub(1, 1);
        let (v4, _) = establish(&mut a, 1, 4000);
        let slice = (v4 & 3) as u16;
        let (cport, cv4, cp4) = syn_bib_in_slice(&mut a, slice, 5000);
        let shadow = stream_shadow(&a, true);
        let input = shadow.take(slice, 0);
        let mut b = node_h(&[], 1, true);
        b.fx.nat.state().adopt_slice(slice, &input, meta(AcquireReason::Takeover)).unwrap();
        assert!(b.fx.nat.state().strict_tcp(slice));
        let _ = events(&b.fx);
        let k = Key4 { proto: proto::TCP, addr: cv4, port: cp4 };
        assert!(run(&mut b.fx, &tcp6(s, cport, SERVER, 443, 0x01 | ACK)).is_ok());
        b.fx.clock.advance(Duration::from_secs(120));
        if v4_speaks {
            assert!(run(&mut b.fx, &tcp4(SERVER, 443, cv4, cp4, ACK)).is_ok());
        }
        // The IPv6 side keeps sending (ACK, FIN retransmit) past TCP_TRANS.
        for f in [ACK, 0x01 | ACK, ACK] {
            assert!(run(&mut b.fx, &tcp6(s, cport, SERVER, 443, f)).is_ok());
            b.fx.clock.advance(Duration::from_secs(50));
        }
        b.fx.clock.advance(Duration::from_secs(1));
        b.fx.nat.state().sweep();
        assert_eq!(b.fx.nat.state().has_session(k, (SERVER, 443)), v4_speaks, "v4_speaks {v4_speaks}");
    }
}

/// SEC-001, SC-10: a hint learned more than TCP_EST (7440 s here) before
/// the takeover is not restored (counted `aged`) and its BIB keeps
/// pickup; one exactly TCP_EST old is restored. Chunked (detached) path.
#[test]
fn hints_older_than_tcp_est_are_not_restored() {
    for (age_s, restored) in [(7440u64, 1u64), (7441, 0)] {
        let mut a = node_h(&[], 0, true);
        start_all(&a);
        let (v4, p4) = establish(&mut a, 1, 4000);
        let slice = (v4 & 3) as u16;
        let shadow = stream_shadow(&a, true);
        let mut b = node_h(&[], 1, true);
        let st = adopt_detached(&b, slice, shadow.detach(slice, age_s * 1000));
        assert_eq!((st.sessions_restored, st.sessions_refused.aged), (restored, 1 - restored), "age {age_s}");
        assert!(b.fx.nat.state().strict_tcp(slice));
        let _ = events(&b.fx);
        let inbound = run(&mut b.fx, &tcp4(SERVER, 443, v4, p4, ACK));
        assert_eq!(inbound.is_ok(), restored == 1, "age {age_s}: {inbound:?}");
        // Either way the flow continues from the IPv6 side.
        assert!(run(&mut b.fx, &tcp6(sub(1, 1), 4000, SERVER, 443, ACK)).is_ok(), "age {age_s}");
    }
}

/// SEC-001: a completed snapshot replaces a BIB's hints (no merge with the
/// hints streamed before it).
#[test]
fn resync_snapshot_replaces_streamed_hints() {
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let (v4, p4) = establish(&mut a, 1, 4000);
    let slice = (v4 & 3) as u16;
    let shadow = stream_shadow(&a, true);
    assert_eq!(shadow.hint_count(slice), 1);
    // The flow ends on the primary (RST): no longer ESTABLISHED.
    run(&mut a.fx, &tcp4(SERVER, 443, v4, p4, RST | ACK)).unwrap();
    let (recs, _) = a.fx.nat.state().export_slice(slice, ExportCursor::default(), 1 << 20);
    assert!(!recs.iter().any(|r| matches!(r, SnapRecord::Sess(_))));
    // Snapshot records over the existing copy (no begin): the BIB's hints
    // are replaced by the (empty) exported set.
    shadow.snapshot_records(slice, &recs).unwrap();
    shadow.snapshot_end_hinted(slice, true).unwrap();
    assert_eq!(shadow.hint_count(slice), 0);
}

/// The chunked restore (expired deadline: one batch per step) gives the
/// same sessions as the one-shot adoption.
#[test]
fn chunked_restore_matches_single_shot() {
    let mut a = node_h(&[BIG_BLOCKS], 0, true);
    start_all(&a);
    for port in 4000..4100 {
        establish(&mut a, 1 + port % 7, port);
    }
    let shadow = stream_shadow(&a, true);
    let one = shadow_for(&a);
    for s in 0..4 {
        let input = shadow.take(s, 0);
        for b in &input.bibs {
            one.apply(&ReplRecord::BibCreate { slice: s, bib: *b }, 0).unwrap();
        }
        for h in &input.hints {
            one.apply(&ReplRecord::SessHint { slice: s, v4: h.v4, port4: h.port4, raddr: h.raddr, rport: h.rport }, 0)
                .unwrap();
        }
        for x in &input.blocks {
            one.apply(&ReplRecord::BlockAlloc { slice: s, sub: x.0, block: x.1, wall_us: x.2 }, 0).unwrap();
        }
        one.snapshot_end_hinted(s, true).unwrap();
        let b1 = node_h(&[BIG_BLOCKS], 1, true);
        let r1 = b1.fx.nat.state().adopt_slice(s, &input, meta(AcquireReason::Takeover)).unwrap();
        let b2 = node_h(&[BIG_BLOCKS], 1, true);
        let mut ad = b2
            .fx
            .nat
            .state()
            .adopt_begin(s, plat_nat64::AdoptSource::Detached(one.detach(s, 0)), meta(AcquireReason::Takeover))
            .unwrap();
        let r2 = loop {
            if let plat_nat64::Step::Done(x) = b2.fx.nat.state().adopt_step(&mut ad, past()).unwrap() {
                break x;
            }
        };
        assert_eq!((r1.sessions_restored, r1.bibs_adopted), (r2.sessions_restored, r2.bibs_adopted));
        assert_eq!(b1.fx.nat.state().session_count(), b2.fx.nat.state().session_count());
        assert_eq!(r1.sessions_restored as usize, input.hints.len());
    }
}

/// The snapshot path carries the hints too (export → `Sess` → shadow →
/// adoption), and the restored set equals the exported ESTABLISHED set.
#[test]
fn snapshot_hints_round_trip() {
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let mut est = Vec::new();
    for port in 4000..4012 {
        est.push((establish(&mut a, 1 + port % 3, port), port));
    }
    let shadow = shadow_for(&a);
    for s in 0..4 {
        shadow.snapshot_begin(s).unwrap();
        let mut cur = Some(ExportCursor::default());
        while let Some(c) = cur {
            let (recs, next) = a.fx.nat.state().export_slice(s, c, 3);
            shadow.snapshot_records(s, &recs).unwrap();
            cur = next;
        }
        shadow.snapshot_end_hinted(s, true).unwrap();
    }
    let b = node_h(&[], 1, true);
    adopt_from(&b, &shadow);
    let st = b.fx.nat.state();
    assert_eq!(st.session_count(), est.len() as u64);
    for ((v4, p4), _) in est {
        assert!(st.has_session(Key4 { proto: proto::TCP, addr: v4, port: p4 }, (SERVER, 443)));
    }
}

/// Q1: a hint drained before its `BibCreate` (another ring) is refused
/// with `NoBib`, and the slice is no longer hinted until a resync.
#[test]
fn no_bib_hint_marks_gap() {
    let mut a = node_h(&[], 0, true);
    start_all(&a);
    let _ = drain(&a);
    let (v4, _) = establish(&mut a, 1, 4000);
    let slice = (v4 & 3) as u16;
    let shadow = shadow_for(&a);
    shadow.snapshot_end_hinted(slice, true).unwrap();
    let recs = drain(&a);
    for r in hints_of(&recs) {
        assert_eq!(shadow.apply(&r, 0), Err(plat_nat64::ShadowError::NoBib));
    }
    assert!(!shadow.hinted(slice));
    for r in recs.iter().filter(|r| !matches!(r, ReplRecord::SessHint { .. })) {
        shadow.apply(r, 0).unwrap();
    }
    let input = shadow.take(slice, 0);
    assert!(input.in_sync && !input.hinted, "un-hinted pickup stays for this adoption");
}

// ------------------------------------------------------- QA: session hints

/// Counters of `n` as (drops, counters) vectors, in `ALL` order.
fn counter_snapshot(n: &Node) -> (Vec<u64>, Vec<u64>) {
    let c = &n.fx.ctx.counters;
    (DropReason::ALL.iter().map(|&r| c.drops(r)).collect(), Counter::ALL.iter().map(|&k| c.get(k)).collect())
}

/// A fixed mixed sequence: TCP handshakes, data, RST, a half-open SYN, a
/// SYN/ACK from an unknown server, UDP both ways, and unsolicited inbound.
fn mixed_traffic(n: &mut Node) -> Vec<Result<Vec<u8>, DropReason>> {
    let mut out = Vec::new();
    for i in 0..6u16 {
        let s = sub(1 + i % 3, 1);
        let port = 4000 + i;
        let o = run(&mut n.fx, &tcp6(s, port, SERVER, 443, SYN));
        let (v4, p4) = o.as_ref().map(|p| tuple4(p)).unwrap_or((0, 0));
        out.push(o);
        out.push(run(&mut n.fx, &tcp4(SERVER, 443, v4, p4, SYN | ACK)));
        out.push(run(&mut n.fx, &tcp6(s, port, SERVER, 443, ACK)));
        out.push(run(&mut n.fx, &tcp4(SERVER, 443, v4, p4, ACK)));
        out.push(run(&mut n.fx, &tcp4(SERVER + 1, 443, v4, p4, ACK)));
        if i % 2 == 0 {
            out.push(run(&mut n.fx, &tcp4(SERVER, 443, v4, p4, RST | ACK)));
        }
        out.push(run(&mut n.fx, &tcp6(s, port, SERVER + 2, 80, SYN)));
        let u = run(&mut n.fx, &udp6(s, 5000 + i, SERVER, 53, b"q"));
        let (u4, up4) = u.as_ref().map(|p| tuple4(p)).unwrap_or((0, 0));
        out.push(u);
        out.push(run(&mut n.fx, &udp4(SERVER, 53, u4, up4, b"r")));
        out.push(run(&mut n.fx, &udp4(SERVER + 5, 53, u4, up4, b"r")));
    }
    out
}

/// Off mode is today (plan §1.9, brief acceptance): the same traffic on a
/// node with `session_hints = "off"` and one with `"tcp"` gives identical
/// verdicts, bytes, counters, audit records and snapshots, except that only
/// `"tcp"` emits `SessHint` and exports `Sess`; an off adopter of a hinted
/// shadow restores nothing and is never strict, as before.
#[test]
fn qa_off_mode_equivalent_except_for_hints() {
    let mut off = node_h(&[], 0, false);
    let mut on = node_h(&[], 0, true);
    start_all(&off);
    start_all(&on);
    let r_off = mixed_traffic(&mut off);
    let r_on = mixed_traffic(&mut on);
    // Ports and IP IDs are randomised per node: compare the verdict, the
    // family and the length of every output.
    let shape = |r: &[Result<Vec<u8>, DropReason>]| -> Vec<Result<(u8, usize), DropReason>> {
        r.iter().map(|x| x.as_ref().map(|p| (p[0] >> 4, p.len())).map_err(|e| *e)).collect()
    };
    assert_eq!(shape(&r_off), shape(&r_on), "verdicts");
    assert_eq!(counter_snapshot(&off), counter_snapshot(&on));
    let (e_off, e_on) = (events(&off.fx), events(&on.fx));
    assert_eq!(e_off.len(), e_on.len(), "no new audit record kinds with hints on (Q4)");
    for (a, b) in e_off.iter().zip(&e_on) {
        assert_eq!(std::mem::discriminant(a), std::mem::discriminant(b));
    }
    let (rec_off, rec_on) = (drain(&off), drain(&on));
    assert!(hints_of(&rec_off).is_empty(), "off emits no SessHint");
    assert!(!hints_of(&rec_on).is_empty());
    let no_hints: Vec<_> = rec_on.iter().copied().filter(|r| !matches!(r, ReplRecord::SessHint { .. })).collect();
    let kind = |r: &ReplRecord| std::mem::discriminant(r);
    assert_eq!(rec_off.iter().map(kind).collect::<Vec<_>>(), no_hints.iter().map(kind).collect::<Vec<_>>());
    for s in 0..4 {
        let (x_off, _) = off.fx.nat.state().export_slice(s, ExportCursor::default(), 1 << 20);
        let (x_on, _) = on.fx.nat.state().export_slice(s, ExportCursor::default(), 1 << 20);
        assert!(!x_off.iter().any(|r| matches!(r, SnapRecord::Sess(_))));
        let stripped: Vec<_> = x_on.into_iter().filter(|r| !matches!(r, SnapRecord::Sess(_))).collect();
        let kind = |r: &SnapRecord| std::mem::discriminant(r);
        assert_eq!(
            x_off.iter().map(kind).collect::<Vec<_>>(),
            stripped.iter().map(kind).collect::<Vec<_>>(),
            "slice {s}"
        );
    }
    // Takeover by an off adopter from a hinted, in-sync shadow: as today.
    let shadow = shadow_for(&on);
    for r in &rec_on {
        shadow.apply(r, 0).unwrap();
    }
    for s in 0..4 {
        shadow.snapshot_end_hinted(s, true).unwrap();
    }
    let mut b = node_h(&[], 1, false);
    for s in 0..4 {
        let st = b.fx.nat.state().adopt_slice(s, &shadow.take(s, 0), meta(AcquireReason::Takeover)).unwrap();
        assert_eq!(st.sessions_restored, 0);
        assert_eq!(st.sessions_refused.total(), 0);
        assert!(!b.fx.nat.state().strict_tcp(s));
    }
    assert_eq!(b.fx.nat.state().session_count(), 0);
    let _ = events(&b.fx);
    assert!(run(&mut b.fx, &tcp6(sub(2, 1), 4001, SERVER, 443, ACK)).is_ok(), "un-hinted pickup as today");
    assert!(hints_of(&drain(&b)).is_empty());
}

/// Plan §8 boundary: a connection burst that overflows the ring never
/// blocks or panics; the losses are counted, the slices are dirty, and a
/// backup that saw the gap is neither in sync nor hinted, so its adoption
/// keeps the un-hinted pickup. A resync snapshot then restores every
/// ESTABLISHED session.
#[test]
fn qa_ring_full_connection_burst_is_bounded_and_keeps_pickup() {
    let mut a = node_full(&[BIG_BLOCKS], 4, SteeringMode::Drop, 0, 1 << 16, true);
    start_all(&a);
    let _ = drain(&a);
    let shadow = shadow_for(&a);
    for s in 0..4 {
        shadow.snapshot_begin(s).unwrap();
        shadow.snapshot_end_hinted(s, true).unwrap();
    }
    let mut flows = Vec::new();
    for port in 4000..4200u16 {
        flows.push(establish(&mut a, 1 + port % 5, port));
    }
    assert!(a.hub.backlog() <= 4, "ring bounded: {}", a.hub.backlog());
    let lost = a.hub.dropped_total();
    assert!(lost > 0);
    assert_eq!(a.hub.pushed_total(), 4);
    let dirty = a.hub.take_dirty();
    assert!(!dirty.is_empty());
    // The backup: what arrived, then the replicator's gap handling.
    for r in drain(&a) {
        if shadow.apply(&r, 0).is_err()
            && let ReplRecord::SessHint { slice, .. } = r
        {
            shadow.mark_gap(slice);
        }
    }
    for &s in &dirty {
        shadow.mark_gap(s);
    }
    for &s in &dirty {
        let input = shadow.take(s, 0);
        assert!(!input.in_sync && !input.hinted, "slice {s}");
        let mut b = node_h(&[BIG_BLOCKS], 1, true);
        let st = b.fx.nat.state().adopt_slice(s, &input, meta(AcquireReason::Takeover)).unwrap();
        assert_eq!(st.sessions_restored, 0);
        assert!(!b.fx.nat.state().strict_tcp(s));
        let _ = events(&b.fx);
        // Any flow of this slice whose BIB reached the backup is picked up.
        for (i, &(v4, _)) in flows.iter().enumerate() {
            if (v4 & 3) as u16 == s && input.bibs.iter().any(|x| x.v4 == v4) {
                let port = 4000 + i as u16;
                let _ = run(&mut b.fx, &tcp6(sub(1 + port % 5, 1), port, SERVER, 443, ACK));
            }
        }
    }
    // Resync by snapshot: hinted again, every ESTABLISHED flow restored.
    let fresh = shadow_for(&a);
    let mut b = node_h(&[BIG_BLOCKS], 1, true);
    for s in 0..4 {
        fresh.snapshot_begin(s).unwrap();
        let mut cur = Some(ExportCursor::default());
        while let Some(c) = cur {
            let (recs, next) = a.fx.nat.state().export_slice(s, c, 64);
            fresh.snapshot_records(s, &recs).unwrap();
            cur = next;
        }
        fresh.snapshot_end_hinted(s, true).unwrap();
        let input = fresh.take(s, 0);
        assert!(input.in_sync && input.hinted);
        b.fx.nat.state().adopt_slice(s, &input, meta(AcquireReason::Takeover)).unwrap();
    }
    assert_eq!(b.fx.nat.state().session_count(), flows.len() as u64);
    let _ = events(&b.fx);
    for &(v4, p4) in &flows {
        assert!(run(&mut b.fx, &tcp4(SERVER, 443, v4, p4, ACK)).is_ok(), "{v4:#x}:{p4}");
    }
}

/// SC-24, extends `half_adopted_slice_never_forwards` (plan §8): while a
/// hinted slice is Adopting, its restored sessions exist but forward
/// nothing in either direction; only after `Done` does the server's packet
/// reach the subscriber.
#[test]
fn qa_half_adopted_slice_never_forwards_restored_sessions() {
    let mut a = node_h(&[BIG_BLOCKS], 0, true);
    start_all(&a);
    let mut flows = Vec::new();
    for port in 4000..4300u16 {
        flows.push((establish(&mut a, 1 + port % 7, port), port));
    }
    let slice = (flows[0].0.0 & 3) as u16;
    let mine: Vec<_> = flows.iter().copied().filter(|f| (f.0.0 & 3) as u16 == slice).collect();
    let shadow = stream_shadow(&a, true);
    let mut b = node_h(&[BIG_BLOCKS], 1, true);
    let st = b.fx.nat.state();
    let mut ad = st
        .adopt_begin(slice, plat_nat64::AdoptSource::Detached(shadow.detach(slice, 0)), meta(AcquireReason::Takeover))
        .unwrap();
    let mut seen_restored = 0;
    let mut reasons = std::collections::HashSet::new();
    let done = loop {
        if let plat_nat64::Step::Done(x) = b.fx.nat.state().adopt_step(&mut ad, past()).unwrap() {
            break x;
        }
        let st = b.fx.nat.state();
        assert_eq!(st.slice_state(slice), Some(SliceState::Adopting));
        assert!(!st.strict_tcp(slice), "strict only once Active");
        let n = st.session_count();
        seen_restored = seen_restored.max(n);
        for &((v4, p4), port) in mine.iter().step_by(7) {
            let k = Key4 { proto: proto::TCP, addr: v4, port: p4 };
            if !b.fx.nat.state().has_session(k, (SERVER, 443)) {
                continue;
            }
            let i = run(&mut b.fx, &tcp4(SERVER, 443, v4, p4, ACK)).expect_err("inbound on Adopting");
            let o = run(&mut b.fx, &tcp6(sub(1 + port % 7, 1), port, SERVER, 443, ACK)).expect_err("outbound");
            reasons.insert((i, o));
        }
    };
    assert!(seen_restored > 0, "some step ended with restored sessions on the Adopting slice");
    assert_eq!(done.sessions_restored as usize, mine.len());
    eprintln!("half-adopted drop reasons (inbound, outbound): {reasons:?}");
    assert!(
        reasons.iter().all(|&(i, o)| i == DropReason::ClusterFenced && o == DropReason::ClusterFenced),
        "{reasons:?}"
    );
    assert!(b.fx.nat.state().strict_tcp(slice));
    let _ = events(&b.fx);
    for &((v4, p4), port) in &mine {
        let o = run(&mut b.fx, &tcp4(SERVER, 443, v4, p4, ACK)).unwrap();
        assert_eq!(be16(&o, 42), port);
    }
}

fn env_or(name: &str, d: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

/// Q1 measurement harness (plan §1.7, §8): 8 workers open TCP connections
/// at full speed; each SYN is handled by one worker (its `BibCreate` goes
/// to that worker's ring) and the SYN/ACK by the next worker (the hint goes
/// to another ring), as with RSS on the two address families. A drainer
/// thread empties the hub like the replicator (batch 4096, round-robin)
/// and applies to a shadow, counting `NoBib` refusals. Prints the rate.
///
/// Scale with `QA_RACE_CONNS` (per worker, default 2000), `QA_RACE_RING`
/// (default 65536), `QA_RACE_DRAIN_US` (pause between drains, default 0)
/// `QA_RACE_GAP_US` (per-worker pause between SYNs, default 0) and
/// `QA_RACE_RTT_US` (delay from a SYN to its SYN/ACK, default 0) and
/// `QA_RACE_HINTS` (0: hints off, the control run) and `QA_RACE_ROUNDS`
/// (drain rounds per pump, default 8 like platd; 1: one round). Asserts
/// only that nothing panics, nothing is lost silently and every hint is
/// either applied or refused `NoBib`.
/// Workers in the Q1 race harness.
const RACE_W: usize = 8;

/// Q1 harness knobs (`QA_RACE_*`, see the test doc).
#[derive(Clone, Copy)]
struct RaceParams {
    conns: usize,
    ring: usize,
    pause: Duration,
    gap: Duration,
    hints_on: bool,
    rtt: Duration,
    rounds: usize,
}

impl RaceParams {
    fn from_env() -> Self {
        Self {
            conns: env_or("QA_RACE_CONNS", 2000),
            ring: env_or("QA_RACE_RING", 65_536),
            pause: Duration::from_micros(env_or("QA_RACE_DRAIN_US", 0) as u64),
            gap: Duration::from_micros(env_or("QA_RACE_GAP_US", 0) as u64),
            hints_on: env_or("QA_RACE_HINTS", 1) != 0,
            rtt: Duration::from_micros(env_or("QA_RACE_RTT_US", 0) as u64),
            // Drain rounds per pump while a round is cut (platd `DRAIN_ROUNDS`).
            rounds: env_or("QA_RACE_ROUNDS", 8),
        }
    }
}

/// A SYN/ACK due at `.0` for the translated tuple of its SYN (`None`: the
/// SYN was dropped); a `None` message closes the channel.
type RaceMsg = (std::time::Instant, Option<Option<(u32, u16)>>);

/// Drainer result: hints, `NoBib` refusals, other refusals, non-empty drains.
type DrainStats = (u64, u64, u64, u64);

/// Cluster engine with slices 0..4 Active, a hinted shadow of them and a
/// thread draining the audit channel (ends once the engine is dropped).
fn race_setup(p: &RaceParams) -> (Arc<Nat64>, Arc<Shadow>, std::thread::JoinHandle<()>) {
    let cfg = config(&[("max_sessions = 4000000", "max_sessions = 4000000")]);
    let setup = ClusterSetup {
        slices: SliceMap::new(&cfg.nat64.pool, 32).unwrap(),
        self_id: 0,
        steering: SteeringMode::Drop,
        directory: Arc::new(Directory::new(16, 1000)),
        tcp_adopt_secs: 300,
        session_hints: p.hints_on,
        quarantine_secs: 600,
        reserve_ahead: 2,
    };
    let (sink, rx) = AuditSink::bounded(1 << 20);
    let nat = Arc::new(Nat64::new_cluster(&cfg, setup, sink, Clock::new()).unwrap());
    for s in 0..4 {
        nat.state()
            .adopt_slice(
                s,
                &AdoptInput::default(),
                AdoptMeta { epoch: 1, prev_owner: None, reason: AcquireReason::Startup },
            )
            .unwrap();
    }
    let c = &cfg.nat64;
    let shadow = Arc::new(Shadow::new(
        SliceMap::new(&c.pool, 32).unwrap(),
        c.port_min,
        c.port_max,
        c.port_block_size,
        120_000,
        1 << 22,
    ));
    for s in 0..4 {
        shadow.snapshot_begin(s).unwrap();
        shadow.snapshot_end_hinted(s, true).unwrap();
    }
    let audit_drain = std::thread::spawn(move || while rx.recv().is_ok() {});
    (nat, shadow, audit_drain)
}

/// Replicator stand-in: drains the hub into the shadow until `done` and empty.
fn spawn_race_drainer(
    hub: Arc<ReplHub>,
    shadow: Arc<Shadow>,
    done: Arc<std::sync::atomic::AtomicBool>,
    p: RaceParams,
) -> std::thread::JoinHandle<DrainStats> {
    use std::sync::atomic::Ordering;
    std::thread::spawn(move || {
        let (mut buf, mut hints, mut no_bib, mut other, mut drains) = (Vec::new(), 0u64, 0u64, 0u64, 0u64);
        loop {
            let fin = done.load(Ordering::Acquire);
            buf.clear();
            let n = hub.drain_rounds(4096, p.rounds, &mut buf);
            drains += u64::from(n > 0);
            for r in &buf {
                let h = matches!(r, ReplRecord::SessHint { .. });
                hints += u64::from(h);
                match shadow.apply(r, 0) {
                    Ok(()) => {}
                    Err(plat_nat64::ShadowError::NoBib) if h => no_bib += 1,
                    Err(_) => other += 1,
                }
            }
            if n == 0 && fin {
                return (hints, no_bib, other, drains);
            }
            if !p.pause.is_zero() {
                std::thread::sleep(p.pause);
            }
        }
    })
}

/// One race worker: sends its SYNs (to `next` for the SYN/ACK) and answers
/// the previous worker's SYN/ACKs one emulated RTT after their SYN.
/// Returns (answered, SYN drops, counters).
fn race_worker(
    i: usize,
    nat: &Nat64,
    prod: ReplProducer,
    inbox: &std::sync::mpsc::Receiver<RaceMsg>,
    next: &std::sync::mpsc::Sender<RaceMsg>,
    p: &RaceParams,
) -> (usize, usize, Arc<Counters>) {
    let mut ctx = nat.new_worker(Arc::new(Counters::default()), i as u16 + 1).with_repl(prod);
    let mut buf = vec![0u8; plat_xlat::HEADROOM + 2048];
    let mut go = |pkt: &[u8], ctx: &mut WorkerCtx| {
        buf[plat_xlat::HEADROOM..plat_xlat::HEADROOM + pkt.len()].copy_from_slice(pkt);
        match nat.process(&mut buf, plat_xlat::HEADROOM, pkt.len(), ctx) {
            plat_nat64::Verdict::Forward { start, len } => Some(tuple4(&buf[start..start + len])),
            _ => None,
        }
    };
    let (mut sent, mut answered, mut open, mut syn_drops) = (0usize, 0usize, true, 0usize);
    let mut pending = std::collections::VecDeque::new();
    while open || sent < p.conns || !pending.is_empty() {
        if sent < p.conns {
            let s = sub((i * 40 + sent % 40) as u16, 1);
            let port = 1024 + (sent / 40) as u16;
            let r = go(&tcp6(s, port, SERVER, 443, SYN), &mut ctx);
            syn_drops += usize::from(r.is_none());
            let _ = next.send((std::time::Instant::now() + p.rtt, Some(r)));
            sent += 1;
            spin_for(p.gap);
            if sent == p.conns {
                let _ = next.send((std::time::Instant::now(), None));
            }
        }
        open = race_recv(inbox, &mut pending) && open;
        let now = std::time::Instant::now();
        while pending.front().is_some_and(|q: &(std::time::Instant, _)| q.0 <= now) {
            if let Some((_, Some((v4, p4)))) = pending.pop_front() {
                answered += usize::from(go(&tcp4(SERVER, 443, v4, p4, SYN | ACK), &mut ctx).is_some());
            }
        }
        if sent >= p.conns {
            std::thread::yield_now();
        }
    }
    (answered, syn_drops, ctx.counters.clone())
}

/// Busy-wait `d` (a sleep is far too coarse for SYN gaps).
fn spin_for(d: Duration) {
    if d.is_zero() {
        return;
    }
    let t = std::time::Instant::now();
    while t.elapsed() < d {
        std::hint::spin_loop();
    }
}

/// Move queued SYN/ACKs into `pending`; false once the sender closed.
fn race_recv(
    inbox: &std::sync::mpsc::Receiver<RaceMsg>,
    pending: &mut std::collections::VecDeque<(std::time::Instant, Option<(u32, u16)>)>,
) -> bool {
    use std::sync::mpsc::TryRecvError;
    loop {
        match inbox.try_recv() {
            Ok((_, None)) | Err(TryRecvError::Disconnected) => return false,
            Ok((due, Some(m))) => pending.push_back((due, m)),
            Err(TryRecvError::Empty) => return true,
        }
    }
}

/// Q1 measurement harness (plan §1.7, §8): 8 workers open TCP connections
/// at full speed; each SYN is handled by one worker (its `BibCreate` goes
/// to that worker's ring) and the SYN/ACK by the next worker (the hint goes
/// to another ring), as with RSS on the two address families. A drainer
/// thread empties the hub like the replicator (batch 4096, round-robin)
/// and applies to a shadow, counting `NoBib` refusals. Prints the rate.
///
/// Scale with `QA_RACE_CONNS` (per worker, default 2000), `QA_RACE_RING`
/// (default 65536), `QA_RACE_DRAIN_US` (pause between drains, default 0)
/// `QA_RACE_GAP_US` (per-worker pause between SYNs, default 0) and
/// `QA_RACE_RTT_US` (delay from a SYN to its SYN/ACK, default 0) and
/// `QA_RACE_HINTS` (0: hints off, the control run) and `QA_RACE_ROUNDS`
/// (drain rounds per pump, default 8 like platd; 1: one round). Asserts
/// only that nothing panics, nothing is lost silently and every hint is
/// either applied or refused `NoBib`.
#[test]
fn qa_no_bib_race_rate_with_8_workers() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    const W: usize = RACE_W;
    let p = RaceParams::from_env();
    let RaceParams { conns, ring, pause, gap, hints_on, rtt, rounds } = p;
    let (nat, shadow, audit_drain) = race_setup(&p);
    let (hub, prods) = ReplHub::new(W + 1, ring, 4);
    let done = Arc::new(AtomicBool::new(false));
    let drainer = spawn_race_drainer(hub.clone(), shadow.clone(), done.clone(), p);
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..W).map(|_| mpsc::channel::<RaceMsg>()).unzip();
    let t0 = std::time::Instant::now();
    let workers: Vec<_> = prods
        .into_iter()
        .take(W)
        .zip(rxs)
        .enumerate()
        .map(|(i, (prod, inbox))| {
            let nat = nat.clone();
            let next = txs[(i + 1) % W].clone();
            std::thread::spawn(move || race_worker(i, &nat, prod, &inbox, &next, &p))
        })
        .collect();
    drop(txs);
    let res: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    let answered: usize = res.iter().map(|r| r.0).sum();
    let syn_drops: usize = res.iter().map(|r| r.1).sum();
    let reasons: Vec<_> = DropReason::ALL
        .iter()
        .map(|&d| (d, res.iter().map(|r| r.2.drops(d)).sum::<u64>()))
        .filter(|x| x.1 > 0)
        .collect();
    let starved: u64 = res.iter().map(|r| r.2.get(Counter::ClusterReserveStarved)).sum();
    let paired: u64 = res.iter().map(|r| r.2.get(Counter::PoolPairedExhausted)).sum();
    let elapsed = t0.elapsed();
    done.store(true, Ordering::Release);
    let (hints, no_bib, other, drains) = drainer.join().unwrap();
    let dropped = hub.dropped_total();
    eprintln!(
        "QA no_bib race: workers {W}, conns {} ({answered} established) in {elapsed:?} ({:.0} conn/s), ring {ring}, \
         drain pause {pause:?}, SYN gap {gap:?}, RTT {rtt:?}: hints {hints}, no_bib {no_bib} ({:.4} %), other refusals {other}, ring drops {dropped}, \
         non-empty drains {drains}, truncated drains {}, rounds {rounds}",
        W * conns,
        (W * conns) as f64 / elapsed.as_secs_f64(),
        100.0 * no_bib as f64 / hints.max(1) as f64,
        hub.drains_truncated(),
    );
    assert_eq!(
        (answered, syn_drops),
        (W * conns, 0),
        "every connection established; drops {reasons:?}, reserve starved {starved}, paired exhausted {paired}, subscribers {}",
        nat.state().subscriber_count()
    );
    assert_eq!(dropped, 0, "measurement needs a loss-free ring");
    assert_eq!(hints, if hints_on { answered as u64 } else { 0 }, "one hint per connection");
    assert_eq!(other, 0);
    // Hints follow the BIB records of their drain (decision Q1 revised), so
    // only a drain cut at its limit can still split a SYN's `BibCreate`
    // from its SYN/ACK's hint.
    let truncated = hub.drains_truncated();
    if hints_on && truncated == 0 {
        assert_eq!(no_bib, 0, "no truncated drain, yet {no_bib} hints arrived before their BIB");
    }
    if no_bib > 0 {
        assert!((0..4).any(|s| !shadow.hinted(s)), "a no_bib refusal must leave its slice un-hinted");
    }
    drop(nat);
    let _ = audit_drain.join();
}
