//! QA edge cases through the full engine: TCP state machine timers, sweeper
//! and limit accounting, ICMPv6→ICMPv4 error translation, first-fragment
//! translation, and pool exhaustion. Every output checksum is recomputed
//! from scratch.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::*;
use plat_audit::{Event, LimitKind};
use plat_common::DropReason;
use plat_nat64::pool::Pool;
use plat_nat64::state::Key6;
use plat_packet::{L4, be16, be32, checksum as ck, parse_l4, parse_v4, parse_v6, proto, put16, put32};
use plat_xlat::siit::{write_v4_header, write_v6_header};

const SERVER: u32 = 0xc633_6407; // 198.51.100.7
const OTHER: u32 = 0xcb00_7105; // 203.0.113.5

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;
const RST: u8 = 0x04;

const TCP_TRANS_S: u64 = 240;
const TCP_EST_S: u64 = 7440;
const UDP_S: u64 = 300;

/// Parses an IPv4 packet and verifies the header and transport checksums
/// from scratch.
fn v4_ok(p: &[u8]) -> plat_packet::Ipv4Hdr {
    let h = parse_v4(p).expect("valid IPv4 header incl. checksum");
    let l4 = &p[h.hdr_len..h.total_len];
    if h.frag.is_none() {
        let s = match h.proto {
            proto::ICMP => ck::sum(l4),
            pr => ck::pseudo_v4(h.src, h.dst, pr, l4.len() as u16) + ck::sum(l4),
        };
        assert_eq!(ck::fold(s), 0xffff, "IPv4 transport checksum");
    }
    h
}

fn v6_ok(p: &[u8]) -> plat_packet::Ipv6Hdr {
    let h = parse_v6(p).unwrap();
    if h.frag.is_none() {
        let l4 = &p[h.l4_off..h.total_len()];
        let s = ck::pseudo_v6(h.src, h.dst, h.proto, l4.len() as u32) + ck::sum(l4);
        assert_eq!(ck::fold(s), 0xffff, "IPv6 transport checksum");
    }
    h
}

fn tuple4(p: &[u8]) -> (u32, u16) {
    let h = v4_ok(p);
    (h.src, be16(p, h.hdr_len))
}

fn sweep_n(fx: &Fx) -> u64 {
    fx.nat.state().sweep().sessions_expired
}

/// Opens a TCP session sub:sport -> SERVER:443 through SYN / SYN-ACK.
fn tcp_established(fx: &mut Fx, s: u128, sport: u16) -> (u32, u16) {
    let out = run(fx, &tcp6(s, sport, SERVER, 443, SYN)).unwrap();
    let (a, p) = tuple4(&out);
    v6_ok(&run(fx, &tcp4(SERVER, 443, a, p, SYN | ACK)).unwrap());
    (a, p)
}

// ---------------------------------------------------------------- TCP FSM

#[test]
fn tcp_v6_init_uses_transitory_timer() {
    let mut fx = fixture(&[]);
    run(&mut fx, &tcp6(sub(1, 1), 40000, SERVER, 443, SYN)).unwrap();
    fx.clock.advance(Duration::from_secs(TCP_TRANS_S - 1));
    assert_eq!(sweep_n(&fx), 0, "V6 INIT alive before TCP_TRANS");
    fx.clock.advance(Duration::from_secs(2));
    assert_eq!(sweep_n(&fx), 1, "V6 INIT expires after TCP_TRANS");
    assert_eq!(fx.nat.state().session_count(), 0);
}

#[test]
fn tcp_established_uses_established_timer() {
    let mut fx = fixture(&[]);
    tcp_established(&mut fx, sub(1, 1), 40000);
    fx.clock.advance(Duration::from_secs(TCP_EST_S - 1));
    assert_eq!(sweep_n(&fx), 0, "ESTABLISHED alive before TCP_EST");
    fx.clock.advance(Duration::from_secs(2));
    assert_eq!(sweep_n(&fx), 1);
    assert_eq!(fx.nat.state().session_count(), 0);
}

#[test]
fn tcp_rst_from_v4_moves_to_transitory() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = tcp_established(&mut fx, s, 40000);
    // RST is still translated (the subscriber must learn about it).
    v6_ok(&run(&mut fx, &tcp4(SERVER, 443, a, p, RST)).unwrap());
    fx.clock.advance(Duration::from_secs(TCP_TRANS_S + 1));
    assert_eq!(sweep_n(&fx), 1, "RST -> TRANS -> TCP_TRANS lifetime");
}

#[test]
fn tcp_rst_from_v6_then_traffic_returns_to_established() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = tcp_established(&mut fx, s, 40000);
    run(&mut fx, &tcp6(s, 40000, SERVER, 443, RST)).unwrap();
    // RFC 6146 §3.5.2.2: a non-RST packet in TRANS returns to ESTABLISHED.
    fx.clock.advance(Duration::from_secs(10));
    v6_ok(&run(&mut fx, &tcp4(SERVER, 443, a, p, ACK)).unwrap());
    fx.clock.advance(Duration::from_secs(TCP_TRANS_S + 1));
    assert_eq!(sweep_n(&fx), 0, "back on the established timer");
}

#[test]
fn tcp_fin_both_sides_goes_transitory_and_is_not_extended() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = tcp_established(&mut fx, s, 40000);
    run(&mut fx, &tcp6(s, 40000, SERVER, 443, FIN | ACK)).unwrap();
    v6_ok(&run(&mut fx, &tcp4(SERVER, 443, a, p, FIN | ACK)).unwrap());
    // Final ACK and late segments in BOTH FIN RCV do not refresh the timer.
    fx.clock.advance(Duration::from_secs(200));
    run(&mut fx, &tcp6(s, 40000, SERVER, 443, ACK)).unwrap();
    assert_eq!(sweep_n(&fx), 0);
    fx.clock.advance(Duration::from_secs(TCP_TRANS_S - 200 + 1));
    assert_eq!(sweep_n(&fx), 1, "expires TCP_TRANS after the second FIN");
    assert_eq!(fx.nat.state().session_count(), 0);
}

#[test]
fn tcp_fin_one_side_keeps_established_timer() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = tcp_established(&mut fx, s, 40000);
    // V4 FIN first (server closes), then only data from the subscriber.
    v6_ok(&run(&mut fx, &tcp4(SERVER, 443, a, p, FIN | ACK)).unwrap());
    run(&mut fx, &tcp6(s, 40000, SERVER, 443, ACK)).unwrap();
    fx.clock.advance(Duration::from_secs(TCP_TRANS_S + 1));
    assert_eq!(sweep_n(&fx), 0, "half-closed stays on TCP_EST");
    fx.clock.advance(Duration::from_secs(TCP_EST_S));
    assert_eq!(sweep_n(&fx), 1);
}

#[test]
fn tcp_inbound_rst_without_session_is_dropped_under_eif() {
    let mut fx = fixture(&[("filtering = \"address_dependent\"", "filtering = \"endpoint_independent\"")]);
    let (a, p) = tcp_established(&mut fx, sub(1, 1), 40000);
    // EIF lets OTHER reach the binding, but only a SYN can create a session.
    assert_eq!(run(&mut fx, &tcp4(OTHER, 80, a, p, RST)).unwrap_err(), DropReason::TcpNoState);
    assert_eq!(run(&mut fx, &tcp4(OTHER, 80, a, p, ACK)).unwrap_err(), DropReason::TcpNoState);
    assert_eq!(fx.nat.state().session_count(), 1);
}

#[test]
fn tcp_non_syn_creates_no_binding() {
    let mut fx = fixture(&[("mode = \"port_block\"", "mode = \"session\"")]);
    assert_eq!(run(&mut fx, &tcp6(sub(1, 1), 40000, SERVER, 443, ACK)).unwrap_err(), DropReason::TcpNoState);
    // RFC 6146 §3.5.2.2: non-SYN packets without state are dropped; no
    // BIB entry, port or attribution record should result.
    assert_eq!(fx.nat.state().bib6.len(), 0, "BIB created for a dropped non-SYN");
    let evs = events(&fx);
    assert!(
        !evs.iter().any(|e| matches!(e, Event::BibCreate { .. } | Event::PortBlockAlloc { .. })),
        "attribution records for a binding that never carried traffic: {evs:?}"
    );
}

// ---------------------------------------------------- sweeper / limits

#[test]
fn subscriber_session_counter_returns_to_zero_after_expiry() {
    let mut fx = fixture(&[("max_sessions_per_subscriber = 4000", "max_sessions_per_subscriber = 4"), NO_UNREACH]);
    let s = sub(1, 1);
    for d in 0..4u16 {
        run(&mut fx, &udp6(s, 1000, SERVER, 53 + d, b"x")).unwrap();
    }
    assert_eq!(run(&mut fx, &udp6(s, 1000, SERVER, 99, b"x")).unwrap_err(), DropReason::SubscriberLimit);
    assert_eq!(fx.nat.state().session_count(), 4);
    fx.clock.advance(Duration::from_secs(UDP_S + 1));
    assert_eq!(sweep_n(&fx), 4);
    assert_eq!(fx.nat.state().session_count(), 0);
    // Per-subscriber counter is back at zero: four new sessions fit again.
    for d in 0..4u16 {
        run(&mut fx, &udp6(s, 1000, SERVER, 200 + d, b"x")).unwrap();
    }
    assert_eq!(run(&mut fx, &udp6(s, 1000, SERVER, 300, b"x")).unwrap_err(), DropReason::SubscriberLimit);
    let evs = events(&fx);
    assert!(evs.iter().any(|e| matches!(e, Event::Limit { kind: LimitKind::SubscriberSessions, .. })));
}

#[test]
fn global_session_limit_and_recovery() {
    let mut fx = fixture(&[("max_sessions = 4000000", "max_sessions = 3"), NO_UNREACH]);
    for i in 0..3u16 {
        run(&mut fx, &udp6(sub(i, 1), 1000, SERVER, 53, b"x")).unwrap();
    }
    assert_eq!(run(&mut fx, &udp6(sub(9, 1), 1000, SERVER, 53, b"x")).unwrap_err(), DropReason::SessionLimit);
    assert_eq!(fx.nat.state().session_count(), 3, "refused session not counted");
    assert!(events(&fx).iter().any(|e| matches!(e, Event::Limit { kind: LimitKind::GlobalSessions, .. })));
    fx.clock.advance(Duration::from_secs(UDP_S + 1));
    assert_eq!(sweep_n(&fx), 3);
    assert_eq!(fx.nat.state().session_count(), 0);
    run(&mut fx, &udp6(sub(9, 1), 1000, SERVER, 53, b"x")).unwrap();
}

#[test]
fn limit_events_are_rate_limited_per_kind() {
    let mut fx = fixture(&[("max_sessions_per_subscriber = 4000", "max_sessions_per_subscriber = 1")]);
    let s = sub(1, 1);
    run(&mut fx, &udp6(s, 1000, SERVER, 53, b"x")).unwrap();
    for d in 0..50u16 {
        let _ = run(&mut fx, &udp6(s, 1000, SERVER, 100 + d, b"x"));
    }
    let n = events(&fx).iter().filter(|e| matches!(e, Event::Limit { .. })).count();
    assert_eq!(n, 1, "at most one limit record per second per kind");
    fx.clock.advance(Duration::from_millis(1001));
    let _ = run(&mut fx, &udp6(s, 1000, SERVER, 999, b"x"));
    assert_eq!(events(&fx).iter().filter(|e| matches!(e, Event::Limit { .. })).count(), 1);
}

#[test]
fn full_teardown_removes_subscriber_and_new_flow_logs_new_block() {
    let mut fx = fixture(&[]);
    let s = sub(4, 1);
    let total = fx.nat.state().pool.total_blocks();
    run(&mut fx, &tcp6(s, 1, SERVER, 443, SYN)).unwrap();
    run(&mut fx, &udp6(s, 2, SERVER, 53, b"x")).unwrap();
    run(&mut fx, &echo6(s, 3, SERVER)).unwrap();
    assert_eq!(fx.nat.state().pool.free_blocks(), total - 1, "TCP, UDP, ICMP share one block");
    let _ = events(&fx);

    // Session expiry, BIB grace, block linger.
    fx.clock.advance(Duration::from_secs(UDP_S + 1));
    let st = fx.nat.state().sweep();
    assert_eq!(st.sessions_expired, 3);
    fx.clock.advance(Duration::from_secs(3));
    assert_eq!(fx.nat.state().sweep().bibs_removed, 3);
    assert_eq!(fx.nat.state().bib6.len(), 0);
    assert_eq!(fx.nat.state().bib4.len(), 0);
    fx.clock.advance(Duration::from_secs(61));
    assert_eq!(fx.nat.state().sweep().blocks_released, 1);
    assert_eq!(fx.nat.state().pool.free_blocks(), total - 1, "cooling down (POAM-010)");
    fx.clock.advance(Duration::from_secs(120));
    fx.nat.state().sweep();
    assert_eq!(fx.nat.state().pool.free_blocks(), total);
    assert_eq!(fx.nat.state().session_count(), 0);

    // A later flow is a fresh subscriber entry: a new allocation record.
    run(&mut fx, &udp6(s, 5, SERVER, 53, b"x")).unwrap();
    let evs = events(&fx);
    assert_eq!(evs.iter().filter(|e| matches!(e, Event::PortBlockRelease { .. })).count(), 1);
    assert_eq!(evs.iter().filter(|e| matches!(e, Event::PortBlockAlloc { .. })).count(), 1);
    // Idempotent: nothing more to do.
    assert_eq!(fx.nat.state().sweep(), Default::default());
}

#[test]
fn traffic_during_bib_grace_keeps_binding() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let out = run(&mut fx, &udp6(s, 7, SERVER, 53, b"x")).unwrap();
    let (a, p) = tuple4(&out);
    fx.clock.advance(Duration::from_secs(UDP_S + 1));
    assert_eq!(sweep_n(&fx), 1);
    // New outbound flow from the same source within the grace period
    // reuses the same mapping (endpoint-independent mapping).
    fx.clock.advance(Duration::from_secs(1));
    let out = run(&mut fx, &udp6(s, 7, SERVER, 53, b"again")).unwrap();
    assert_eq!(tuple4(&out), (a, p));
    fx.clock.advance(Duration::from_secs(3));
    assert_eq!(fx.nat.state().sweep().bibs_removed, 0);
    v6_ok(&run(&mut fx, &udp4(SERVER, 53, a, p, b"reply")).unwrap());
}

// ------------------------------------------------- pool boundaries

fn small_pool_fixture() -> Fx {
    // 4 addresses x 2 blocks of 32256 ports (1024..=65535).
    fixture(&[
        ("port_block_size = 512", "port_block_size = 32256"),
        ("max_blocks_per_subscriber = 4", "max_blocks_per_subscriber = 1"),
        NO_UNREACH,
    ])
}

#[test]
fn pool_exhaustion_is_reported_and_recovers() {
    let mut fx = small_pool_fixture();
    assert_eq!(fx.nat.state().pool.total_blocks(), 8);
    for i in 0..8u16 {
        run(&mut fx, &udp6(sub(i, 1), 1, SERVER, 53, b"x")).unwrap();
    }
    assert_eq!(fx.nat.state().pool.free_blocks(), 0);
    assert_eq!(run(&mut fx, &udp6(sub(8, 1), 1, SERVER, 53, b"x")).unwrap_err(), DropReason::PortExhausted);
    let evs = events(&fx);
    assert!(evs.iter().any(|e| matches!(e, Event::Limit { kind: LimitKind::PoolExhausted, .. })));
    for e in &evs {
        if let Event::PortBlockAlloc { port_lo, port_hi, .. } = *e {
            assert!(port_lo >= 1024 && (port_lo - 1024) % 32256 == 0, "aligned block {port_lo}");
            assert_eq!(u32::from(port_hi) - u32::from(port_lo) + 1, 32256);
        }
    }
    // An existing subscriber still has ports inside its block.
    run(&mut fx, &udp6(sub(0, 1), 2, SERVER, 53, b"x")).unwrap();

    fx.clock.advance(Duration::from_secs(UDP_S + 1));
    fx.nat.state().sweep();
    fx.clock.advance(Duration::from_secs(3));
    fx.nat.state().sweep();
    fx.clock.advance(Duration::from_secs(61));
    assert_eq!(fx.nat.state().sweep().blocks_released, 8);
    // POAM-010: released blocks are not reusable during the cool-down.
    assert_eq!(run(&mut fx, &udp6(sub(8, 1), 1, SERVER, 53, b"x")).unwrap_err(), DropReason::PortExhausted);
    fx.clock.advance(Duration::from_secs(120));
    fx.nat.state().sweep();
    run(&mut fx, &udp6(sub(8, 1), 1, SERVER, 53, b"x")).unwrap();
}

#[test]
fn top_of_port_range_maps_and_returns() {
    // One block per address covering exactly 65472..=65535.
    let mut fx = fixture(&[("port_min = 1024", "port_min = 65472"), ("port_block_size = 512", "port_block_size = 64")]);
    let s = sub(1, 1);
    let mut seen = Vec::new();
    for sp in 0..64u16 {
        let out = run(&mut fx, &udp6(s, 1000 + sp, SERVER, 53, b"x")).unwrap();
        let (a, p) = tuple4(&out);
        assert!(p >= 65472);
        let back = run(&mut fx, &udp4(SERVER, 53, a, p, b"r")).unwrap();
        assert_eq!(be16(&back, 42), 1000 + sp);
        seen.push(p);
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 64, "every port of the block used once, including 65535");
    assert_eq!(*seen.last().unwrap(), 65535);
}

#[test]
fn engine_refuses_an_empty_pool_slice() {
    let (sink, _rx) = plat_audit::AuditSink::bounded(8);
    let r = plat_nat64::Nat64::new(&config(&[]), Vec::new(), sink, plat_common::Clock::new());
    assert!(r.is_err(), "a node that owns no pool addresses must not start");
}

#[test]
fn pool_unit_boundaries() {
    // Range not a multiple of the block size: trailing ports are unused.
    let p = Pool::new(vec![7], 1024, 65535, 1000);
    assert_eq!(p.total_blocks(), 64);
    let last = plat_nat64::pool::BlockRef { addr_idx: 0, block: 63 };
    assert_eq!(p.port_lo(last), 64024);
    assert_eq!(p.block_of(0, 65023), Some(last));
    assert_eq!(p.block_of(0, 65024), None);
    assert_eq!(p.block_of(0, 65535), None);
    assert_eq!(p.block_of(0, 1023), None);
    for _ in 0..64 {
        assert!(p.alloc(None, true).is_some());
    }
    assert!(p.alloc(None, true).is_none());
    assert!(p.alloc(Some(0), false).is_none());
    assert_eq!(p.free_blocks(), 0);

    // Duplicates collapse; strict paired pooling never spills over.
    let p = Pool::new(vec![3, 1, 3, 2], 65472, 65535, 64);
    assert_eq!(p.total_blocks(), 3);
    let a = p.alloc(Some(1), true).unwrap();
    assert_eq!(a.addr_idx, 1);
    assert!(p.alloc(Some(1), true).is_none());
    let b = p.alloc(Some(1), false).unwrap();
    assert_ne!(b.addr_idx, 1);
    assert_eq!(p.port_lo(a), 65472);
}

// ------------------------------------------ ICMPv6 errors (v6 -> v4)

/// ICMP (type, code, rest-of-header).
type Icmp = (u8, u8, u32);

fn icmp6_err(src: u128, dst: u128, ty: u8, code: u8, rest: u32, quoted: &[u8]) -> Vec<u8> {
    let l = 8 + quoted.len();
    let mut p = vec![0u8; 40 + l];
    write_v6_header(&mut p, 0, l as u16, proto::ICMPV6, 64, src, dst);
    p[40] = ty;
    p[41] = code;
    put32(&mut p, 44, rest);
    p[48..].copy_from_slice(quoted);
    l4_sum6(&mut p, src, dst, proto::ICMPV6, 2);
    p
}

/// A UDP flow sub:5353 <-> SERVER:53 and the IPv6 reply the subscriber got.
fn udp_flow(fx: &mut Fx, s: u128) -> (u32, u16, Vec<u8>) {
    let out = run(fx, &udp6(s, 5353, SERVER, 53, b"query")).unwrap();
    let (a, p) = tuple4(&out);
    let back = run(fx, &udp4(SERVER, 53, a, p, b"answer")).unwrap();
    (a, p, back)
}

/// Checks the ICMPv4 error and its quoted IPv4 packet; returns (type, code, rest).
fn check_v4_err(out: &[u8], pool: u32, port: u16) -> (u8, u8, u32) {
    let h = v4_ok(out);
    assert_eq!(h.proto, proto::ICMP);
    assert_eq!((h.src, h.dst), (pool, SERVER), "error from the pool address to the server");
    assert!(out.len() <= 576);
    let inner = &out[28..];
    let ih = plat_packet::ip::parse_v4_inner(inner).unwrap();
    assert_eq!(ck::fold(ck::sum(&inner[..20])), 0xffff, "inner IPv4 header checksum");
    assert_eq!((ih.src, ih.dst, ih.proto), (SERVER, pool, proto::UDP));
    assert_eq!((be16(inner, 20), be16(inner, 22)), (53, port));
    (out[20], out[21], be32(out, 24))
}

#[test]
fn icmp6_errors_translate_to_icmp4() {
    let s = sub(1, 1);
    let cpe = sub(1, 0xfffe); // CPE/CLAT router, not in the NAT64 prefix
    // (ICMPv6 type, code, rest) -> (ICMPv4 type, code, rest), RFC 7915 §5.2.
    let cases: [(Icmp, Icmp); 8] = [
        ((1, 0, 0), (3, 1, 0)),
        ((1, 1, 0), (3, 10, 0)),
        ((1, 3, 0), (3, 1, 0)),
        ((1, 4, 0), (3, 3, 0)),
        ((2, 0, 1280), (3, 4, 1260)),
        ((3, 0, 0), (11, 0, 0)),
        ((4, 0, 24), (12, 0, 16 << 24)),
        ((4, 1, 6), (3, 2, 0)),
    ];
    for (i, ((t6, c6, r6), want)) in cases.into_iter().enumerate() {
        let mut fx = fixture(&[]);
        let (a, p, back) = udp_flow(&mut fx, s);
        let err = icmp6_err(cpe, synth(SERVER), t6, c6, r6, &back);
        let out = run(&mut fx, &err).unwrap_or_else(|e| panic!("case {i} ({t6},{c6}): {e:?}"));
        assert_eq!(check_v4_err(&out, a, p), want, "case {i} ({t6},{c6})");
        // Inner UDP checksum stays valid for the IPv4 view of the quote.
        let inner = &out[28..];
        let s4 = ck::pseudo_v4(SERVER, a, proto::UDP, (inner.len() - 20) as u16) + ck::sum(&inner[20..]);
        assert_eq!(ck::fold(s4), 0xffff, "case {i}: inner UDP checksum");
    }
}

#[test]
fn icmp6_error_with_truncated_quote_translates() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p, back) = udp_flow(&mut fx, s);
    // Only the IPv6 header and the 8-byte UDP header are quoted.
    let err = icmp6_err(sub(1, 0xfffe), synth(SERVER), 1, 4, 0, &back[..48]);
    let out = run(&mut fx, &err).unwrap();
    assert_eq!(check_v4_err(&out, a, p), (3, 3, 0));
    let inner = &out[28..];
    assert_eq!(be16(inner, 2) as usize, 20 + 8 + 6, "inner total length reflects the original datagram");
}

#[test]
fn icmp6_error_about_tcp_and_echo() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = tcp_established(&mut fx, s, 40000);
    let back = run(&mut fx, &tcp4(SERVER, 443, a, p, ACK)).unwrap();
    let out = run(&mut fx, &icmp6_err(s, synth(SERVER), 1, 4, 0, &back)).unwrap();
    let h = v4_ok(&out);
    assert_eq!((h.src, h.dst, out[20], out[21]), (a, SERVER, 3, 3));
    assert_eq!((be16(&out, 48), be16(&out, 50)), (443, p));

    // Echo: the quoted echo reply carries the subscriber's identifier; the
    // IPv4 quote must carry the pool identifier.
    let req = run(&mut fx, &echo6(s, 0x4242, SERVER)).unwrap();
    let rh = parse_v4(&req).unwrap();
    let L4::Icmp { id: pool_id, .. } = parse_l4(&req, 20, req.len(), proto::ICMP).unwrap() else { panic!() };
    let mut rep = vec![0u8; req.len()];
    rep[20..].copy_from_slice(&req[20..]);
    write_v4_header(&mut rep, 0, req.len() as u16, 0, false, false, 0, 64, proto::ICMP, SERVER, rh.src);
    rep[20] = 0;
    l4_sum4(&mut rep, proto::ICMP, 2);
    let rep6 = run(&mut fx, &rep).unwrap();
    let out = run(&mut fx, &icmp6_err(s, synth(SERVER), 3, 0, 0, &rep6)).unwrap();
    let h = v4_ok(&out);
    assert_eq!((h.src, out[20], out[21]), (rh.src, 11, 0));
    assert_eq!(out[48], 0, "quoted echo reply type 0");
    assert_eq!(be16(&out, 52), pool_id);
}

#[test]
fn icmp6_error_negative_cases() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (_, _, back) = udp_flow(&mut fx, s);
    let cpe = sub(1, 0xfffe);
    // Quote shorter than an IPv6 header + 8 bytes.
    assert_eq!(run(&mut fx, &icmp6_err(cpe, synth(SERVER), 1, 4, 0, &back[..44])).unwrap_err(), DropReason::Malformed);
    // Quote about a flow with no binding.
    let mut stray = back.clone();
    put16(&mut stray, 42, 9999);
    assert_eq!(run(&mut fx, &icmp6_err(cpe, synth(SERVER), 1, 4, 0, &stray)).unwrap_err(), DropReason::NoBinding);
    // Untranslatable type/code.
    assert_eq!(
        run(&mut fx, &icmp6_err(cpe, synth(SERVER), 1, 5, 0, &back)).unwrap_err(),
        DropReason::IcmpUntranslatable
    );
    assert_eq!(
        run(&mut fx, &icmp6_err(cpe, synth(SERVER), 4, 0, 41, &back)).unwrap_err(),
        DropReason::IcmpUntranslatable,
        "parameter-problem pointer with no IPv4 equivalent"
    );
    // Error about an error.
    let inner = icmp6_err(synth(SERVER), s, 1, 4, 0, &back[..48]);
    assert_eq!(
        run(&mut fx, &icmp6_err(cpe, synth(SERVER), 1, 4, 0, &inner)).unwrap_err(),
        DropReason::IcmpUntranslatable
    );
}

/// RFC-001: routers outside the client prefixes (BNG, CPE WAN, the PLAT host
/// itself) must be able to report errors, or PMTUD and traceroute break.
#[test]
fn icmp6_error_from_router_outside_client_prefixes_is_translated() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p, back) = udp_flow(&mut fx, s);
    let outsider = 0x2001_0db8_ffff_0000_0000_0000_0000_0001u128;
    let out = run(&mut fx, &icmp6_err(outsider, synth(SERVER), 2, 0, 1400, &back)).unwrap();
    assert_eq!(check_v4_err(&out, a, p), (3, 4, 1380), "PTB 1400 -> Frag Needed 1380");
}

#[test]
fn icmp6_error_cannot_target_another_subscribers_mapping() {
    let mut fx = fixture(&[]);
    let victim = sub(1, 1);
    let attacker = sub(2, 1);
    let (_, _, back) = udp_flow(&mut fx, victim);
    // The attacker forges a Packet Too Big quoting the victim's flow.
    let err = icmp6_err(attacker, synth(SERVER), 2, 0, 1280, &back);
    assert!(run(&mut fx, &err).is_err(), "cross-subscriber ICMP error was translated");
}

// ------------------------------------------------- ICMPv4 errors (v4 -> v6)

#[test]
fn icmp4_error_source_policy_and_spoofed_quote() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let out = run(&mut fx, &udp6(s, 5353, SERVER, 53, b"query")).unwrap();
    // Private router address: allowed for errors (common on transit paths).
    let v6 = run(&mut fx, &icmp4_err(0x0a00_0001, 3, 3, 0, &out)).unwrap();
    let h = v6_ok(&v6);
    assert_eq!((h.dst, v6[40], v6[41]), (s, 1, 4));
    assert!(v6.len() <= 1280);
    // Loopback source: never.
    assert_eq!(run(&mut fx, &icmp4_err(0x7f00_0001, 3, 3, 0, &out)).unwrap_err(), DropReason::SrcNotAllowed);
    // Time exceeded.
    let v6 = run(&mut fx, &icmp4_err(0xcb00_7101, 11, 0, 0, &out)).unwrap();
    assert_eq!((v6[40], v6[41]), (3, 0));
    // Quoted source is not the pool address the error was sent to.
    let mut spoof = out.clone();
    spoof[12..16].copy_from_slice(&(POOL_BASE + 3).to_be_bytes());
    let mut err = icmp4_err(0xcb00_7101, 3, 3, 0, &spoof);
    err[16..20].copy_from_slice(&tuple4(&out).0.to_be_bytes());
    put16(&mut err, 10, 0);
    let c = ck::finish(ck::sum(&err[..20]));
    put16(&mut err, 10, c);
    assert!(run(&mut fx, &err).is_err());
}

// ---------------------------------------------------- fragments

/// IPv6 UDP datagram split in two fragments at `cut` bytes of L4 data.
fn udp6_fragments(src: u128, sport: u16, dst4: u32, dport: u16, payload: &[u8], cut: usize) -> (Vec<u8>, Vec<u8>) {
    let full = udp6(src, sport, dst4, dport, payload);
    let l4 = &full[40..];
    assert_eq!(cut % 8, 0);
    let mk = |data: &[u8], off: usize, more: bool| {
        let mut p = vec![0u8; 48 + data.len()];
        write_v6_header(&mut p, 0, (8 + data.len()) as u16, proto::FRAGMENT, 64, src, synth(dst4));
        p[40] = proto::UDP;
        put16(&mut p, 42, ((off / 8) as u16) << 3 | u16::from(more));
        put32(&mut p, 44, 0xabcd_1234);
        p[48..].copy_from_slice(data);
        p
    };
    (mk(&l4[..cut], 0, true), mk(&l4[cut..], cut, false))
}

#[test]
fn ipv6_first_fragment_translates_with_mf_and_valid_checksum() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let payload: Vec<u8> = (0..100u8).collect();
    let (f1, f2) = udp6_fragments(s, 5353, SERVER, 53, &payload, 56);
    let out = run(&mut fx, &f1).unwrap();
    let h = v4_ok(&out);
    let f = h.frag.expect("IPv4 fragment");
    assert!(f.more && f.offset == 0, "MF=1 offset 0");
    assert!(!h.df, "RFC 7915 §5.1.1: DF clear on translated fragments");
    // RFC-004: a fresh IPv4 ID per datagram, shared by its fragments.
    let id4 = h.id;
    assert_eq!(h.total_len, 20 + 56);
    assert_eq!(be16(&out, 22), 53);
    // Reassembled transport checksum (first fragment + untouched rest) is valid.
    let mut l4 = out[20..].to_vec();
    l4.extend_from_slice(&f2[48..]);
    let s4 = ck::pseudo_v4(h.src, h.dst, proto::UDP, l4.len() as u16) + ck::sum(&l4);
    assert_eq!(ck::fold(s4), 0xffff, "UDP checksum over the reassembled datagram");
    // Non-first fragment: header-only translation with the first
    // fragment's mapping (RFC 6146 §3.4, POAM-001).
    let out2 = run(&mut fx, &f2).unwrap();
    let h2 = v4_ok(&out2);
    assert_eq!(h2.frag, Some(plat_packet::ip::Frag { id: u32::from(id4), offset: 7, more: false }));
    assert_eq!((h2.src, h2.dst, h2.proto), (h.src, h.dst, proto::UDP));
    assert_eq!(&out2[20..], &f2[48..], "payload untouched");
}

#[test]
fn ipv4_first_fragment_reply_gets_fragment_header() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let out = run(&mut fx, &udp6(s, 5353, SERVER, 53, b"q")).unwrap();
    let (a, p) = tuple4(&out);
    let payload: Vec<u8> = (0..100u8).collect();
    let full = udp4(SERVER, 53, a, p, &payload);
    // First fragment: IP header + first 56 bytes of L4, MF=1, id 0x7777.
    let mut f1 = vec![0u8; 20 + 56];
    f1[20..].copy_from_slice(&full[20..76]);
    write_v4_header(&mut f1, 0, 76, 0x7777, false, true, 0, 64, proto::UDP, SERVER, a);
    let back = run(&mut fx, &f1).unwrap();
    let h = v6_ok(&back);
    assert_eq!(back[6], proto::FRAGMENT);
    assert_eq!(h.frag, Some(plat_packet::ip::Frag { id: 0x7777, offset: 0, more: true }));
    assert_eq!((h.dst, be16(&back, 50)), (s, 5353));
    let mut l4 = back[48..].to_vec();
    l4.extend_from_slice(&full[76..]);
    let s6 = ck::pseudo_v6(h.src, h.dst, proto::UDP, l4.len() as u32) + ck::sum(&l4);
    assert_eq!(ck::fold(s6), 0xffff, "UDP checksum over the reassembled IPv6 datagram");
}

#[test]
fn fragmented_icmpv6_echo_waits_for_reassembly() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let e = echo6(s, 1, SERVER);
    // A non-last fragment carries a multiple of 8 bytes.
    let mut p = vec![0u8; 48 + 16];
    write_v6_header(&mut p, 0, 24, proto::FRAGMENT, 64, s, synth(SERVER));
    p[40] = proto::ICMPV6;
    put16(&mut p, 42, 1);
    put32(&mut p, 44, 9);
    p[48..60].copy_from_slice(&e[40..]);
    // Held in a reassembly slot (the ICMPv6 checksum needs the whole
    // message); nothing is sent until the datagram completes.
    assert_eq!(run_all(&mut fx, &p).unwrap(), Vec::<Vec<u8>>::new());
    assert_eq!(fx.ctx.fragment_entries(), 1);
}

#[test]
fn dropped_after_mapping_leaves_no_state() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let e = echo6(s, 1, SERVER);
    // A non-last fragment carries a multiple of 8 bytes.
    let mut p = vec![0u8; 48 + 16];
    write_v6_header(&mut p, 0, 24, proto::FRAGMENT, 64, s, synth(SERVER));
    p[40] = proto::ICMPV6;
    put16(&mut p, 42, 1);
    put32(&mut p, 44, 9);
    p[48..60].copy_from_slice(&e[40..]);
    assert!(run_all(&mut fx, &p).unwrap().is_empty());
    assert!(
        fx.nat.state().lookup6(Key6 { proto: proto::ICMP, addr: s, port: 1 }).is_none(),
        "BIB for a dropped packet"
    );
    assert_eq!(fx.nat.state().session_count(), 0, "session for a dropped packet");
}
