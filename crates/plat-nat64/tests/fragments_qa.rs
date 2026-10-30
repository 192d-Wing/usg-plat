//! QA additions for POAM-001/002/011/023: fragment edge cases, ICMP
//! generation gating, IPv4 Identification unpredictability, POAM-023 session
//! non-refresh, and never-panic properties on the fragment paths.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::*;
use plat_audit::Event;
use plat_common::{Counter, DropReason};
use plat_packet::{be16, checksum as ck, parse_v4, parse_v6, proto, put16, put32};
use plat_xlat::siit::{write_v4_header, write_v6_header};
use proptest::prelude::*;

const SERVER: u32 = 0xc633_6407; // 198.51.100.7
const ROUTER4: u32 = 0xcb00_7101; // 203.0.113.1
const EIF: (&str, &str) = ("filtering = \"address_dependent\"", "filtering = \"endpoint_independent\"");
const CUTS3: [(usize, usize); 3] = [(0, 104), (104, 104), (208, 100)];

fn frag6_raw(full: &[u8], id: u32, off: usize, len: usize, more: bool) -> Vec<u8> {
    let h = parse_v6(full).unwrap();
    let l4 = &full[40..];
    let mut p = vec![0u8; 48 + len];
    write_v6_header(&mut p, 0, (8 + len) as u16, proto::FRAGMENT, full[7], h.src, h.dst);
    p[40] = h.proto;
    put16(&mut p, 42, ((off / 8) as u16) << 3 | u16::from(more));
    put32(&mut p, 44, id);
    let n = len.min(l4.len().saturating_sub(off));
    if n > 0 {
        p[48..48 + n].copy_from_slice(&l4[off..off + n]);
    }
    p
}

fn frag6(full: &[u8], id: u32, cuts: &[(usize, usize)]) -> Vec<Vec<u8>> {
    let total = full.len() - 40;
    cuts.iter().map(|&(o, l)| frag6_raw(full, id, o, l, o + l < total)).collect()
}

fn frag4(full: &[u8], id: u16, cuts: &[(usize, usize)], ttl: u8) -> Vec<Vec<u8>> {
    let h = parse_v4(full).unwrap();
    let l4 = &full[20..];
    cuts.iter()
        .map(|&(off, len)| {
            let mut p = vec![0u8; 20 + len];
            let more = off + len < l4.len();
            write_v4_header(
                &mut p,
                0,
                (20 + len) as u16,
                id,
                false,
                more,
                (off / 8) as u16,
                ttl,
                h.proto,
                h.src,
                h.dst,
            );
            p[20..].copy_from_slice(&l4[off..off + len]);
            p
        })
        .collect()
}

fn udp_flow(fx: &mut Fx, s: u128) -> (u32, u16) {
    let out = run(fx, &udp6(s, 5353, SERVER, 53, b"query")).unwrap();
    (parse_v4(&out).unwrap().src, be16(&out, 20))
}

fn echo6_big(s: u128, data: usize) -> Vec<u8> {
    let mut e = vec![0u8; 48 + data];
    write_v6_header(&mut e, 0, (8 + data) as u16, proto::ICMPV6, 64, s, synth(SERVER));
    e[40] = 128;
    put16(&mut e, 44, 77);
    l4_sum6(&mut e, s, synth(SERVER), proto::ICMPV6, 2);
    e
}

fn allocs(evs: &[Event]) -> usize {
    evs.iter().filter(|e| matches!(e, Event::PortBlockAlloc { .. })).count()
}

// ------------------------------------------------------------ fragments

#[test]
fn last_fragment_first_v6_and_v4() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let full = udp6(s, 5353, SERVER, 53, &[1; 300]);
    let fr = frag6(&full, 5, &CUTS3);
    assert!(run_all(&mut fx, &fr[2]).unwrap().is_empty());
    let mut out = run_all(&mut fx, &fr[0]).unwrap();
    out.extend(run_all(&mut fx, &fr[1]).unwrap());
    assert_eq!(out.len(), 3);
    // v4: last first, then middle, then first.
    let (a, p) = udp_flow(&mut fx, s);
    let full4 = udp4(SERVER, 53, a, p, &[2; 300]);
    let fr = frag4(&full4, 6, &CUTS3, 64);
    assert!(run_all(&mut fx, &fr[2]).unwrap().is_empty());
    assert!(run_all(&mut fx, &fr[1]).unwrap().is_empty());
    assert_eq!(run_all(&mut fx, &fr[0]).unwrap().len(), 3);
}

#[test]
fn misaligned_non_last_fragment_is_dropped() {
    let mut fx = fixture(&[]);
    let full = udp6(sub(1, 1), 5353, SERVER, 53, &[1; 300]);
    // 100 bytes with MF set: not a multiple of 8.
    let f = frag6_raw(&full, 8, 0, 100, true);
    assert_eq!(run_all(&mut fx, &f).unwrap_err(), DropReason::Malformed);
    // v4 counterpart, inbound.
    let (a, p) = udp_flow(&mut fx, sub(1, 1));
    let full4 = udp4(SERVER, 53, a, p, &[2; 300]);
    let f = &frag4(&full4, 9, &[(0, 100)], 64)[0];
    assert_eq!(run_all(&mut fx, f).unwrap_err(), DropReason::Malformed);
    // Non-first, misaligned and not last.
    let f = frag6_raw(&full, 8, 104, 100, true);
    assert_eq!(run_all(&mut fx, &f).unwrap_err(), DropReason::Malformed);
}

#[test]
fn v4_teardrop_and_duplicate_poison_inbound() {
    let mut fx = fixture(&[]);
    let (a, p) = udp_flow(&mut fx, sub(1, 1));
    let full = udp4(SERVER, 53, a, p, &[3; 300]);
    let fr = frag4(&full, 10, &[(0, 104), (96, 104)], 64);
    assert_eq!(run_all(&mut fx, &fr[0]).unwrap().len(), 1);
    assert_eq!(run_all(&mut fx, &fr[1]).unwrap_err(), DropReason::FragmentOverlap);
    let fr = frag4(&full, 11, &CUTS3, 64);
    run_all(&mut fx, &fr[0]).unwrap();
    run_all(&mut fx, &fr[2]).unwrap();
    assert_eq!(run_all(&mut fx, &fr[2]).unwrap_err(), DropReason::FragmentOverlap);
    assert_eq!(run_all(&mut fx, &fr[1]).unwrap_err(), DropReason::FragmentOverlap);
    // Buffered-overlap (before the first fragment): the held slot is freed.
    let fr = frag4(&full, 12, &[(104, 104), (200, 108)], 64);
    assert!(run_all(&mut fx, &fr[0]).unwrap().is_empty());
    assert_eq!(run_all(&mut fx, &fr[1]).unwrap_err(), DropReason::FragmentOverlap);
}

#[test]
fn fragment_past_65535_is_dropped() {
    let mut fx = fixture(&[]);
    let full = udp6(sub(1, 1), 5353, SERVER, 53, &[1; 300]);
    let f = frag6_raw(&full, 13, 65472, 72, false);
    assert_eq!(run_all(&mut fx, &f).unwrap_err(), DropReason::Malformed);
    assert_eq!(fx.ctx.fragment_entries(), 0, "no state for an impossible datagram");
}

#[test]
fn too_many_fragments_per_datagram() {
    let mut fx = fixture(&[("max_fragments_per_datagram = 64", "max_fragments_per_datagram = 2")]);
    let full = udp6(sub(1, 1), 5353, SERVER, 53, &[1; 300]);
    let fr = frag6(&full, 14, &CUTS3);
    run_all(&mut fx, &fr[0]).unwrap();
    run_all(&mut fx, &fr[1]).unwrap();
    assert_eq!(run_all(&mut fx, &fr[2]).unwrap_err(), DropReason::FragmentTooMany);
}

#[test]
fn pass_through_entry_expires_after_timeout() {
    let mut fx = fixture(&[("max_buffered_fragments = 64", "max_buffered_fragments = 0")]);
    let full = udp6(sub(1, 1), 5353, SERVER, 53, &[1; 300]);
    let fr = frag6(&full, 15, &CUTS3);
    run_all(&mut fx, &fr[0]).unwrap();
    fx.clock.advance(Duration::from_millis(2100));
    for _ in 0..1024 {
        fx.nat.housekeep(&mut fx.ctx);
    }
    assert_eq!(run_all(&mut fx, &fr[1]).unwrap_err(), DropReason::FragmentUnmatched);
}

#[test]
fn reassembly_limits() {
    // Disabled: fragmented echo is dropped as `fragment`.
    let mut fx = fixture(&[("reassembly_slots = 4", "reassembly_slots = 0")]);
    let e = echo6_big(sub(1, 1), 200);
    let fr = frag6(&e, 16, &[(0, 104), (104, 104)]);
    let r: Vec<_> = fr.iter().map(|f| run_all(&mut fx, f)).collect();
    assert!(r.iter().any(|x| x.as_ref().err() == Some(&DropReason::Fragment)), "{r:?}");
    assert!(r.iter().all(|x| x.as_ref().map_or(true, Vec::is_empty)));
    // One slot, two concurrent datagrams: the second is refused.
    let mut fx = fixture(&[("reassembly_slots = 4", "reassembly_slots = 1")]);
    let a = frag6(&e, 17, &[(0, 104), (104, 104)]);
    let b = frag6(&e, 18, &[(0, 104), (104, 104)]);
    assert!(run_all(&mut fx, &a[0]).unwrap().is_empty());
    assert_eq!(run_all(&mut fx, &b[0]).unwrap_err(), DropReason::ReassemblyFull);
    assert_eq!(run_all(&mut fx, &a[1]).unwrap().len(), 1, "slot holder completes");
    // Size cap.
    let mut fx = fixture(&[("max_reassembly_bytes = 65535", "max_reassembly_bytes = 1280")]);
    let big = echo6_big(sub(1, 1), 1600);
    let fr = frag6(&big, 19, &[(0, 808), (808, 800)]);
    let r: Vec<_> = fr.iter().map(|f| run_all(&mut fx, f)).collect();
    assert!(r.iter().any(|x| x.as_ref().err() == Some(&DropReason::ReassemblyTooBig)), "{r:?}");
}

#[test]
fn non_first_fragments_create_no_audit_or_state() {
    let mut fx = fixture(&[]);
    let full = udp6(sub(4, 1), 5353, SERVER, 53, &[1; 300]);
    let fr = frag6(&full, 20, &CUTS3);
    run_all(&mut fx, &fr[0]).unwrap();
    let first = events(&fx);
    assert_eq!(allocs(&first), 1, "attribution recorded by the first fragment");
    let sessions = fx.nat.state().session_count();
    run_all(&mut fx, &fr[1]).unwrap();
    run_all(&mut fx, &fr[2]).unwrap();
    assert!(events(&fx).is_empty(), "no audit from non-first fragments");
    assert_eq!(fx.nat.state().session_count(), sessions);
}

// ------------------------------------------------------------ ICMP generation

#[test]
fn port_exhaustion_sends_unreachable_without_binding_or_audit() {
    let mut fx = fixture(&[
        ("port_block_size = 512", "port_block_size = 32256"),
        ("max_blocks_per_subscriber = 4", "max_blocks_per_subscriber = 1"),
    ]);
    for i in 0..8u16 {
        run(&mut fx, &udp6(sub(i, 1), 1, SERVER, 53, b"x")).unwrap();
    }
    let _ = events(&fx);
    let n = fx.nat.state().session_count();
    let e = run(&mut fx, &udp6(sub(8, 1), 1, SERVER, 53, b"x")).unwrap();
    let h = parse_v6(&e).unwrap();
    assert_eq!((h.dst, e[40], e[41]), (sub(8, 1), 1, 3));
    let s = ck::pseudo_v6(h.src, h.dst, proto::ICMPV6, (e.len() - 40) as u32) + ck::sum(&e[40..]);
    assert_eq!(ck::fold(s), 0xffff);
    assert_eq!(fx.ctx.counters.drops(DropReason::PortExhausted), 1);
    assert_eq!(fx.nat.state().session_count(), n);
    assert_eq!(allocs(&events(&fx)), 0, "no block, no attribution record");
}

#[test]
fn time_exceeded_can_be_disabled() {
    let mut fx = fixture(&[("send_time_exceeded = true", "send_time_exceeded = false")]);
    let mut p = udp6(sub(1, 1), 1, SERVER, 53, b"x");
    p[7] = 1;
    assert_eq!(run(&mut fx, &p).unwrap_err(), DropReason::HopLimit);
    assert_eq!(fx.ctx.counters.get(Counter::IcmpTimeExceededSent), 0);
}

#[test]
fn inbound_ttl_one_on_icmp_error_or_non_first_fragment_is_silent() {
    let mut fx = fixture(&[]);
    let (a, p) = udp_flow(&mut fx, sub(1, 1));
    // ICMPv4 error (TTL 1) quoting our flow: no error about an error.
    let mut q = udp4(a, p, SERVER, 53, b"query");
    q.truncate(28);
    let mut e = icmp4_err(ROUTER4, 3, 3, 0, &q);
    e[8] = 1;
    put16(&mut e, 10, 0);
    let c = ck::finish(ck::sum(&e[..20]));
    put16(&mut e, 10, c);
    assert!(run(&mut fx, &e).is_err());
    // Non-first IPv4 fragment with TTL 1.
    let full = udp4(SERVER, 53, a, p, &[1; 300]);
    let f = &frag4(&full, 21, &CUTS3, 1)[1];
    assert!(run_all(&mut fx, f).is_err());
    assert_eq!(fx.ctx.counters.get(Counter::IcmpTimeExceededSent), 0);
}

#[test]
fn token_bucket_refills() {
    let mut fx = fixture(&[("icmp_errors_per_sec = 100", "icmp_errors_per_sec = 4")]);
    let mut p = udp6(sub(1, 1), 1, SERVER, 53, b"x");
    p[7] = 1;
    // Rate 4 keeps a reserve of 1 for PMTU errors: three Time Exceeded.
    for _ in 0..3 {
        assert!(run(&mut fx, &p).is_ok());
    }
    assert!(run(&mut fx, &p).is_err());
    fx.clock.advance(Duration::from_millis(1100));
    assert!(run(&mut fx, &p).is_ok(), "bucket refilled after one second");
}

// ------------------------------------------------------------ POAM-011

#[test]
fn ipv4_ids_across_flows_look_random() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let ids: Vec<u16> =
        (0..256u32).map(|i| parse_v4(&run(&mut fx, &udp6(s, 9, SERVER + i, 53, b"x")).unwrap()).unwrap().id).collect();
    let distinct: HashSet<_> = ids.iter().collect();
    // 256 draws from 2^16: expected collisions ~0.5.
    assert!(distinct.len() >= 248, "{}", distinct.len());
    let seq = ids.windows(2).filter(|w| w[1] == w[0].wrapping_add(1)).count();
    assert!(seq <= 2, "global counter leak: {seq}");
    let hi_bits: HashSet<_> = ids.iter().map(|i| i >> 12).collect();
    assert!(hi_bits.len() >= 12, "offsets cover the ID space");
}

// ------------------------------------------------------------ POAM-023

#[test]
fn too_big_packet_does_not_refresh_session() {
    let mut fx = fixture(&[EIF, ("ipv6_mtu = 1500", "ipv6_mtu = 1280")]);
    let (a, p) = udp_flow(&mut fx, sub(1, 1));
    // Keep sending too-big DF packets from both the known server and an
    // unknown remote while the session idles out.
    for _ in 0..4 {
        fx.clock.advance(Duration::from_secs(80));
        for src in [SERVER, ROUTER4] {
            let big = udp4(src, 53, a, p, &[0; 1400]);
            let out = run(&mut fx, &big).unwrap();
            assert_eq!((out[20], out[21]), (3, 4));
        }
        assert_eq!(fx.nat.state().session_count(), 1);
    }
    fx.clock.advance(Duration::from_secs(1));
    fx.nat.state().sweep();
    assert_eq!(fx.nat.state().session_count(), 0, "too-big packets never refreshed last_seen");
}

// ------------------------------------------------------------ properties

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary IPv6 fragments (random offset, MF, ID, length, content,
    /// next header) for a live subscriber never panic.
    #[test]
    fn v6_fragment_fields_never_panic(
        frags in proptest::collection::vec(
            (0u16..8192, any::<bool>(), 0u32..4, proptest::collection::vec(any::<u8>(), 0..200),
             prop_oneof![Just(proto::UDP), Just(proto::TCP), Just(proto::ICMPV6), Just(proto::FRAGMENT), any::<u8>()]),
            1..16),
        hop in 0u8..3,
    ) {
        let mut fx = fixture(&[]);
        let s = sub(1, 1);
        for (off, more, id, body, nh) in frags {
            let mut p = vec![0u8; 48 + body.len()];
            write_v6_header(&mut p, 0, (8 + body.len()) as u16, proto::FRAGMENT, if hop == 0 { 64 } else { hop }, s, synth(SERVER));
            p[40] = nh;
            put16(&mut p, 42, off << 3 | u16::from(more));
            put32(&mut p, 44, id);
            p[48..].copy_from_slice(&body);
            let _ = run_all(&mut fx, &p);
        }
        fx.clock.advance(Duration::from_secs(3));
        for _ in 0..1024 { fx.nat.housekeep(&mut fx.ctx); }
        prop_assert_eq!(fx.ctx.fragment_entries(), 0);
    }

    /// Arbitrary IPv4 fragments toward a live binding never panic.
    #[test]
    fn v4_fragment_fields_never_panic(
        frags in proptest::collection::vec(
            (0u16..8192, any::<bool>(), 0u16..4, proptest::collection::vec(any::<u8>(), 0..200),
             prop_oneof![Just(proto::UDP), Just(proto::TCP), Just(proto::ICMP), any::<u8>()], 0u8..3),
            1..16),
    ) {
        let mut fx = fixture(&[]);
        let (a, _) = udp_flow(&mut fx, sub(1, 1));
        for (off, more, id, body, pr, ttl) in frags {
            let mut p = vec![0u8; 20 + body.len()];
            write_v4_header(&mut p, 0, (20 + body.len()) as u16, id, false, more, off, if ttl == 0 { 64 } else { ttl }, pr, SERVER, a);
            p[20..].copy_from_slice(&body);
            let _ = run_all(&mut fx, &p);
        }
        fx.clock.advance(Duration::from_secs(3));
        for _ in 0..1024 { fx.nat.housekeep(&mut fx.ctx); }
        prop_assert_eq!(fx.ctx.fragment_entries(), 0);
    }

    /// Byte-level mutation of a valid fragment never panics.
    #[test]
    fn mutated_fragments_never_panic(i in 0usize..3, pos in 0usize..160, v in any::<u8>(), cut in 0usize..160) {
        let mut fx = fixture(&[]);
        let full = udp6(sub(1, 1), 5353, SERVER, 53, &[1; 300]);
        let fr = frag6(&full, 22, &CUTS3);
        let mut f = fr[i].clone();
        let n = f.len();
        f[pos % n] = v;
        f.truncate(n - cut.min(n));
        let _ = run_all(&mut fx, &f);
        for g in &fr { let _ = run_all(&mut fx, g); }
    }
}

// ------------------------------------------------------- round 1 fixes

/// An inbound IPv4 UDP packet with DF set, `n` bytes of payload and `ttl`.
fn udp4_df(src: u32, sport: u16, dst: u32, dport: u16, n: usize, ttl: u8) -> Vec<u8> {
    let mut p = udp4(src, sport, dst, dport, &vec![0; n]);
    p[6] |= 0x40;
    p[8] = ttl;
    put16(&mut p, 10, 0);
    let c = ck::finish(ck::sum(&p[..20]));
    put16(&mut p, 10, c);
    p
}

/// NIST-002: Fragmentation Needed only for a packet the filter would
/// admit; under ADF a remote without a session gets nothing.
#[test]
fn frag_needed_requires_filter_admission() {
    let mut fx = fixture(&[("ipv6_mtu = 1500", "ipv6_mtu = 1280")]);
    let (a, p) = udp_flow(&mut fx, sub(1, 1));
    let out = run(&mut fx, &udp4_df(SERVER, 53, a, p, 1400, 64)).unwrap();
    assert_eq!((out[20], out[21]), (3, 4), "session remote: Frag Needed");
    assert_eq!(run(&mut fx, &udp4_df(ROUTER4, 53, a, p, 1400, 64)).unwrap_err(), DropReason::Filtered);
    assert_eq!(run(&mut fx, &udp4_df(SERVER, 53, a, p + 1, 1400, 64)).unwrap_err(), DropReason::NoBinding);
    assert_eq!(fx.ctx.counters.get(Counter::IcmpErrorsGenerated), 1);
}

/// NIST-004 / SEC-005: inbound Time Exceeded only for an admitted packet.
#[test]
fn inbound_time_exceeded_requires_filter_admission() {
    let mut fx = fixture(&[]);
    let (a, p) = udp_flow(&mut fx, sub(1, 1));
    let out = run(&mut fx, &udp4_df(SERVER, 53, a, p, 8, 1)).unwrap();
    assert_eq!((out[20], out[21]), (11, 0));
    assert_eq!(run(&mut fx, &udp4_df(ROUTER4, 53, a, p, 8, 1)).unwrap_err(), DropReason::Filtered);
    assert_eq!(run(&mut fx, &udp4_df(SERVER, 53, a, p + 1, 8, 1)).unwrap_err(), DropReason::NoBinding);
    assert_eq!(fx.ctx.counters.get(Counter::IcmpTimeExceededSent), 1);
}

/// NIST-002 / SEC-005: a quarter of the ICMP error bucket is reserved for
/// Packet Too Big, so a Time Exceeded flood cannot starve PMTUD.
#[test]
fn pmtu_errors_keep_a_reserved_share_of_the_bucket() {
    let mut fx =
        fixture(&[("icmp_errors_per_sec = 100", "icmp_errors_per_sec = 4"), ("ipv4_mtu = 1500", "ipv4_mtu = 1280")]);
    let mut te = udp6(sub(1, 1), 1, SERVER, 53, b"x");
    te[7] = 1;
    let sent = (0..10).filter(|_| run(&mut fx, &te).is_ok()).count();
    assert_eq!(sent, 3, "other errors stop at the reserve");
    let big = udp6(sub(1, 1), 1, SERVER, 53, &[0; 1400]);
    let out = run(&mut fx, &big).unwrap();
    assert_eq!(out[40], 2, "Packet Too Big still sent");
}

/// SEC-001: reassembly is only spent on authorised datagrams.
#[test]
fn reassembly_requires_authorisation() {
    let mut fx = fixture(&[]);
    let (a, _) = udp_flow(&mut fx, sub(1, 1));
    // Inbound fragmented echo request to an unbound identifier.
    let mut echo = vec![0u8; 8 + 300];
    echo[0] = 8;
    put16(&mut echo, 4, 4242);
    let mut full = vec![0u8; 20 + echo.len()];
    let n = full.len() as u16;
    write_v4_header(&mut full, 0, n, 1, false, false, 0, 64, proto::ICMP, SERVER, a);
    full[20..].copy_from_slice(&echo);
    let f = &frag4(&full, 5, &[(0, 104)], 64)[0];
    assert_eq!(run_all(&mut fx, f).unwrap_err(), DropReason::NoBinding);
    // Inbound fragmented ICMP error quoting a packet not sent from `a`.
    let q = udp4(a ^ 1, 1, SERVER, 53, &[0; 200]);
    let mut e = vec![0u8; 28 + q.len()];
    let n = e.len() as u16;
    write_v4_header(&mut e, 0, n, 2, false, false, 0, 64, proto::ICMP, ROUTER4, a);
    e[20] = 3;
    e[21] = 3;
    e[28..].copy_from_slice(&q);
    let f = &frag4(&e, 6, &[(0, 104)], 64)[0];
    assert_eq!(run_all(&mut fx, f).unwrap_err(), DropReason::Filtered);
    // Outbound non-first ICMPv6 fragment from outside the client prefixes.
    let outside = 0x2001_0db8_ffff_0000_0000_0000_0000_0001u128;
    let full6 = echo6_big(outside, 300);
    let f = frag6_raw(&full6, 7, 104, 104, true);
    assert_eq!(run_all(&mut fx, &f).unwrap_err(), DropReason::SrcNotAllowed);
    assert_eq!(fx.ctx.fragment_entries(), 0);
}

/// SEC-001 / SEC-003: one subscriber flooding out-of-order fragments holds
/// at most its share of the buffer; another subscriber still gets slots.
#[test]
fn fragment_flood_from_one_subscriber_does_not_block_another() {
    let mut fx = fixture(&[]);
    let full = udp6(sub(1, 1), 5353, SERVER, 53, &[1; 300]);
    let held = (0..64u32).filter(|&id| run_all(&mut fx, &frag6_raw(&full, id, 104, 104, true)).is_ok()).count();
    assert_eq!(held, 16, "a quarter of 64 buffer slots");
    assert!(fx.ctx.counters.drops(DropReason::FragmentBufferFull) >= 48);
    let other = udp6(sub(2, 1), 5353, SERVER, 53, &[1; 300]);
    assert!(run_all(&mut fx, &frag6_raw(&other, 1, 104, 104, true)).unwrap().is_empty());
    // And its datagram completes.
    let fr = frag6(&other, 1, &CUTS3);
    assert_eq!(run_all(&mut fx, &fr[0]).unwrap().len(), 2);
}

/// RFC-004: every datagram gets a fresh IPv4 Identification, even when the
/// subscriber reuses its IPv6 Identification.
#[test]
fn v6_fragments_get_a_fresh_ipv4_id_per_datagram() {
    let mut fx = fixture(&[]);
    let full = udp6(sub(1, 1), 5353, SERVER, 53, &[1; 300]);
    let mut ids = Vec::new();
    for _ in 0..2 {
        let out: Vec<Vec<u8>> =
            frag6(&full, 0xabcd, &CUTS3).iter().flat_map(|f| run_all(&mut fx, f).unwrap()).collect();
        let v: HashSet<u16> = out.iter().map(|p| parse_v4(p).unwrap().id).collect();
        assert_eq!(v.len(), 1, "one ID per datagram");
        ids.extend(v);
    }
    assert_ne!(ids[0], ids[1]);
}

/// RFC-001: `translation.icmp_source_v6` sources local ICMPv6 errors and
/// is validated.
#[test]
fn icmp_source_v6_is_used_and_validated() {
    let key = ("# icmp_source_v6 = \"2001:db8:ffff::1\"", "icmp_source_v6 = \"2001:db8:ffff::1\"");
    let mut fx = fixture(&[key]);
    let mut te = udp6(sub(1, 1), 1, SERVER, 53, b"x");
    te[7] = 1;
    let out = run(&mut fx, &te).unwrap();
    assert_eq!(parse_v6(&out).unwrap().src, 0x2001_0db8_ffff_0000_0000_0000_0000_0001);
    // Default: the synthesized destination.
    let mut fx = fixture(&[]);
    assert_eq!(parse_v6(&run(&mut fx, &te).unwrap()).unwrap().src, synth(SERVER));
    // Inside a client prefix or the NAT64 prefix: refused.
    let mut t = include_str!("../../../config/platd.example.toml").to_string();
    t = t.replace(key.0, "icmp_source_v6 = \"64:ff9b:1::1\"");
    assert!(plat_common::Config::from_toml(&t).is_err()); // RFC-R1-1: link-local and IPv4-mapped refused; unique-local accepted.
    let ex = include_str!("../../../config/platd.example.toml");
    for (src, ok) in [("fe80::1", false), ("febf::1", false), ("::ffff:192.0.2.1", false), ("fd00:1::1", true)] {
        let t = ex.replace(key.0, &format!("icmp_source_v6 = \"{src}\""));
        assert_eq!(plat_common::Config::from_toml(&t).is_ok(), ok, "{src}");
    }
}

/// SEC-006: a non-zero ICMP error rate below 4 would leave no PMTU reserve.
#[test]
fn icmp_rate_below_four_is_refused() {
    let ex = include_str!("../../../config/platd.example.toml");
    for (rate, ok) in [(0, true), (1, false), (3, false), (4, true)] {
        let t = ex.replace("icmp_errors_per_sec = 100", &format!("icmp_errors_per_sec = {rate}"));
        assert_eq!(plat_common::Config::from_toml(&t).is_ok(), ok, "{rate}");
    }
}
