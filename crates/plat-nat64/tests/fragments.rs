//! Fragment handling (POAM-001), locally generated ICMP errors (POAM-002),
//! IPv4 Identification (POAM-011) and the Fragmentation Needed ordering
//! (POAM-023).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::*;
use plat_common::{Counter, DropReason};
use plat_nat64::state::Key4;
use plat_packet::{be16, be32, checksum as ck, parse_v4, parse_v6, proto, put16, put32};
use plat_xlat::siit::{write_v4_header, write_v6_header};
use proptest::prelude::*;

const SERVER: u32 = 0xc633_6407; // 198.51.100.7
const ROUTER4: u32 = 0xcb00_7101; // 203.0.113.1
const EIF: (&str, &str) = ("filtering = \"address_dependent\"", "filtering = \"endpoint_independent\"");

/// Splits the upper-layer part of the unfragmented IPv6 packet `full` into
/// fragments `[(offset, len)]` with Identification `id`.
fn frag6(full: &[u8], id: u32, cuts: &[(usize, usize)]) -> Vec<Vec<u8>> {
    let h = parse_v6(full).unwrap();
    let l4 = &full[40..];
    cuts.iter()
        .map(|&(off, len)| {
            let mut p = vec![0u8; 48 + len];
            write_v6_header(&mut p, 0, (8 + len) as u16, proto::FRAGMENT, full[7], h.src, h.dst);
            p[40] = h.proto;
            let more = off + len < l4.len();
            put16(&mut p, 42, ((off / 8) as u16) << 3 | u16::from(more));
            put32(&mut p, 44, id);
            p[48..].copy_from_slice(&l4[off..off + len]);
            p
        })
        .collect()
}

/// IPv4 counterpart of [`frag6`].
fn frag4(full: &[u8], id: u16, cuts: &[(usize, usize)]) -> Vec<Vec<u8>> {
    let h = parse_v4(full).unwrap();
    let l4 = &full[20..];
    cuts.iter()
        .map(|&(off, len)| {
            let mut p = vec![0u8; 20 + len];
            let more = off + len < l4.len();
            write_v4_header(&mut p, 0, (20 + len) as u16, id, false, more, (off / 8) as u16, 64, h.proto, h.src, h.dst);
            p[20..].copy_from_slice(&l4[off..off + len]);
            p
        })
        .collect()
}

/// Reassembles IPv4 fragments; returns (header of the first, upper layer).
fn reasm4(frags: &[Vec<u8>]) -> (plat_packet::Ipv4Hdr, Vec<u8>) {
    let mut parts = BTreeMap::new();
    let mut first = None;
    for f in frags {
        let h = parse_v4(f).unwrap();
        let off = h.frag.map_or(0, |x| usize::from(x.offset) * 8);
        if off == 0 {
            first = Some(h);
        }
        parts.insert(off, f[h.hdr_len..h.total_len].to_vec());
    }
    let mut out = Vec::new();
    for (off, p) in parts {
        assert_eq!(off, out.len(), "contiguous");
        out.extend_from_slice(&p);
    }
    (first.unwrap(), out)
}

/// Reassembles IPv6 fragments (Fragment Header directly after the header).
fn reasm6(frags: &[Vec<u8>]) -> (plat_packet::Ipv6Hdr, Vec<u8>) {
    let mut parts = BTreeMap::new();
    let mut first = None;
    for f in frags {
        let h = parse_v6(f).unwrap();
        let off = h.frag.map_or(0, |x| usize::from(x.offset) * 8);
        if off == 0 {
            first = Some(h);
        }
        parts.insert(off, f[h.l4_off..h.total_len()].to_vec());
    }
    let mut out = Vec::new();
    for (off, p) in parts {
        assert_eq!(off, out.len(), "contiguous");
        out.extend_from_slice(&p);
    }
    (first.unwrap(), out)
}

fn csum4_ok(h: &plat_packet::Ipv4Hdr, p: u8, l4: &[u8]) {
    let s = if p == proto::ICMP { ck::sum(l4) } else { ck::pseudo_v4(h.src, h.dst, p, l4.len() as u16) + ck::sum(l4) };
    assert_eq!(ck::fold(s), 0xffff, "IPv4 upper-layer checksum");
}

fn csum6_ok(h: &plat_packet::Ipv6Hdr, p: u8, l4: &[u8]) {
    let s = ck::pseudo_v6(h.src, h.dst, p, l4.len() as u32) + ck::sum(l4);
    assert_eq!(ck::fold(s), 0xffff, "IPv6 upper-layer checksum");
}

fn udp_flow(fx: &mut Fx, s: u128) -> (u32, u16) {
    let out = run(fx, &udp6(s, 5353, SERVER, 53, b"query")).unwrap();
    let h = parse_v4(&out).unwrap();
    (h.src, be16(&out, 20))
}

const CUTS3: [(usize, usize); 3] = [(0, 104), (104, 104), (208, 100)];

// ------------------------------------------------------------ POAM-001

#[test]
fn udp6_three_fragments_in_order() {
    let mut fx = fixture(&[]);
    let full = udp6(sub(1, 1), 5353, SERVER, 53, &[0x5a; 300]);
    let mut out = Vec::new();
    for f in frag6(&full, 0xabcd_1234, &CUTS3) {
        out.extend(run_all(&mut fx, &f).unwrap());
    }
    assert_eq!(out.len(), 3);
    let (h, l4) = reasm4(&out);
    assert_eq!(l4.len(), 308);
    csum4_ok(&h, proto::UDP, &l4);
    // RFC-004: one fresh IPv4 ID for the datagram, on every fragment.
    assert!(out.iter().all(|p| parse_v4(p).unwrap().id == h.id && !parse_v4(p).unwrap().df));
    let c = &fx.ctx.counters;
    assert_eq!((c.get(Counter::FragmentsInV6), c.get(Counter::FragmentsForwarded)), (3, 2));
    // Completed datagram: its entry is gone (only the quote alias stays).
    assert_eq!(fx.ctx.fragment_entries(), 1);
}

#[test]
fn udp6_fragments_out_of_order_are_held_then_flushed() {
    for order in [[2usize, 1, 0], [2, 0, 1], [1, 2, 0]] {
        let mut fx = fixture(&[]);
        let full = udp6(sub(1, 1), 5353, SERVER, 53, &[7; 300]);
        let fr = frag6(&full, 77, &CUTS3);
        let mut out = Vec::new();
        for &i in &order {
            out.extend(run_all(&mut fx, &fr[i]).unwrap());
        }
        assert_eq!(out.len(), 3, "{order:?}");
        let (h, l4) = reasm4(&out);
        csum4_ok(&h, proto::UDP, &l4);
        assert!(fx.ctx.counters.get(Counter::FragmentsBuffered) >= 1);
    }
}

#[test]
fn udp4_fragments_reverse_order_reach_the_subscriber() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    let full = udp4(SERVER, 53, a, p, &[3; 300]);
    let fr = frag4(&full, 0x4242, &CUTS3);
    let mut out = Vec::new();
    for f in fr.iter().rev() {
        out.extend(run_all(&mut fx, f).unwrap());
    }
    assert_eq!(out.len(), 3);
    let (h, l4) = reasm6(&out);
    assert_eq!((h.dst, h.frag.unwrap().id), (s, 0x4242));
    csum6_ok(&h, proto::UDP, &l4);
    assert_eq!(be16(&l4, 2), 5353);
}

#[test]
fn large_ipv4_non_first_fragment_is_resplit_for_ipv6() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    let full = udp4(SERVER, 53, a, p, &[9; 2800]);
    let fr = frag4(&full, 5, &[(0, 1400), (1400, 1408)]);
    let mut out = run_all(&mut fx, &fr[0]).unwrap();
    out.extend(run_all(&mut fx, &fr[1]).unwrap());
    assert!(out.len() >= 3 && out.iter().all(|f| f.len() <= 1280));
    let (h, l4) = reasm6(&out);
    csum6_ok(&h, proto::UDP, &l4);
}

#[test]
fn duplicate_and_overlapping_fragments_poison_the_datagram() {
    let mut fx = fixture(&[]);
    let full = udp6(sub(1, 1), 5353, SERVER, 53, &[1; 300]);
    let fr = frag6(&full, 1, &CUTS3);
    assert_eq!(run_all(&mut fx, &fr[0]).unwrap().len(), 1);
    assert_eq!(run_all(&mut fx, &fr[1]).unwrap().len(), 1);
    assert_eq!(run_all(&mut fx, &fr[1]).unwrap_err(), DropReason::FragmentOverlap);
    assert_eq!(run_all(&mut fx, &fr[2]).unwrap_err(), DropReason::FragmentOverlap, "poisoned");
    // Teardrop: [0, 104) then [96, 200).
    let fr = frag6(&full, 2, &[(0, 104), (96, 104)]);
    run_all(&mut fx, &fr[0]).unwrap();
    assert_eq!(run_all(&mut fx, &fr[1]).unwrap_err(), DropReason::FragmentOverlap);
}

#[test]
fn tiny_fragments_are_refused() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, _) = udp_flow(&mut fx, s);
    // RFC 1858: IPv4 TCP fragment at offset 1 (8 bytes) rewrites the flags.
    let t = tcp4(SERVER, 443, a, 2000, 0x02);
    let mut f = vec![0u8; 20 + 8];
    write_v4_header(&mut f, 0, 28, 3, false, false, 1, 64, proto::TCP, SERVER, a);
    f[20..].copy_from_slice(&t[28..36]);
    assert_eq!(run_all(&mut fx, &f).unwrap_err(), DropReason::FragmentTiny);
    // First fragment holding 4 bytes of the UDP header.
    let u = udp4(SERVER, 53, a, 2000, &[0; 20]);
    let mut f = vec![0u8; 24];
    write_v4_header(&mut f, 0, 24, 4, false, true, 0, 64, proto::UDP, SERVER, a);
    f[20..].copy_from_slice(&u[20..24]);
    assert_eq!(run_all(&mut fx, &f).unwrap_err(), DropReason::FragmentTiny);
    // IPv6 first fragment whose header chain runs past its end (RFC 7112).
    let mut p = vec![0u8; 40 + 8 + 8];
    write_v6_header(&mut p, 0, 16, proto::FRAGMENT, 64, s, synth(SERVER));
    p[40] = proto::DSTOPTS;
    put16(&mut p, 42, 1);
    p[48] = proto::UDP;
    p[49] = 2; // 24-byte Destination Options header in 8 bytes
    assert_eq!(run_all(&mut fx, &p).unwrap_err(), DropReason::FragmentTiny);
}

#[test]
fn unmatched_non_first_fragment_times_out() {
    let mut fx = fixture(&[]);
    let full = udp6(sub(1, 1), 5353, SERVER, 53, &[1; 300]);
    let fr = frag6(&full, 9, &CUTS3);
    assert!(run_all(&mut fx, &fr[1]).unwrap().is_empty());
    assert_eq!(fx.ctx.fragment_entries(), 1);
    fx.clock.advance(Duration::from_millis(2100));
    for _ in 0..1024 {
        fx.nat.housekeep(&mut fx.ctx);
    }
    assert_eq!(fx.ctx.counters.drops(DropReason::FragmentTimeout), 1);
    assert_eq!((fx.ctx.fragment_entries(), fx.ctx.counters.fragment_entries()), (0, 0));
    // With buffering off, an unmatched fragment is dropped at once.
    let mut fx = fixture(&[("max_buffered_fragments = 64", "max_buffered_fragments = 0")]);
    assert_eq!(run_all(&mut fx, &fr[1]).unwrap_err(), DropReason::FragmentUnmatched);
}

#[test]
fn fragmented_icmp_echo_is_reassembled_both_ways() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    // ICMPv6 echo request with 200 bytes of data, in two fragments.
    let mut e = vec![0u8; 40 + 8 + 200];
    write_v6_header(&mut e, 0, 208, proto::ICMPV6, 64, s, synth(SERVER));
    e[40] = 128;
    put16(&mut e, 44, 77);
    for (i, b) in e[48..].iter_mut().enumerate() {
        *b = i as u8;
    }
    l4_sum6(&mut e, s, synth(SERVER), proto::ICMPV6, 2);
    let fr = frag6(&e, 31, &[(0, 104), (104, 104)]);
    assert!(run_all(&mut fx, &fr[1]).unwrap().is_empty());
    let out = run_all(&mut fx, &fr[0]).unwrap();
    assert_eq!(out.len(), 1);
    let h = parse_v4(&out[0]).unwrap();
    assert!(h.frag.is_none());
    assert_eq!((out[0][20], h.total_len), (8, 228));
    csum4_ok(&h, proto::ICMP, &out[0][20..]);
    assert_eq!(fx.ctx.counters.get(Counter::DatagramsReassembled), 1);
    let (a, id) = (h.src, be16(&out[0], 24));

    // The IPv4 reply, fragmented, comes back as one ICMPv6 echo reply.
    let mut r = out[0].clone();
    write_v4_header(&mut r[..20], 0, 228, 0, false, false, 0, 64, proto::ICMP, SERVER, a);
    r[20] = 0;
    l4_sum4(&mut r, proto::ICMP, 2);
    let fr = frag4(&r, 99, &[(0, 104), (104, 104)]);
    assert!(run_all(&mut fx, &fr[0]).unwrap().is_empty());
    let back = run_all(&mut fx, &fr[1]).unwrap();
    assert_eq!(back.len(), 1);
    let h6 = parse_v6(&back[0]).unwrap();
    assert_eq!((h6.dst, back[0][40], be16(&back[0], 44)), (s, 129, 77));
    csum6_ok(&h6, proto::ICMPV6, &back[0][40..]);
    let _ = id;
}

#[test]
fn fragmented_zero_checksum_udp4_is_reassembled_or_dropped() {
    for policy in ["reassemble", "drop"] {
        let mut fx = fixture(&[("udp_zero_checksum = \"reassemble\"", &format!("udp_zero_checksum = \"{policy}\""))]);
        let s = sub(1, 1);
        let (a, p) = udp_flow(&mut fx, s);
        let mut full = udp4(SERVER, 53, a, p, &[0x33; 1600]);
        put16(&mut full, 26, 0);
        let fr = frag4(&full, 11, &[(0, 808), (808, 800)]);
        let r0 = run_all(&mut fx, &fr[0]);
        if policy == "drop" {
            assert_eq!(r0.unwrap_err(), DropReason::Fragment);
            continue;
        }
        assert!(r0.unwrap().is_empty());
        let out = run_all(&mut fx, &fr[1]).unwrap();
        // 1608 bytes of UDP, refragmented at 1280 with Fragment Headers.
        assert_eq!(out.len(), 2);
        let (h, l4) = reasm6(&out);
        assert_ne!(be16(&l4, 6), 0, "checksum computed (RFC 7915 §4.5)");
        csum6_ok(&h, proto::UDP, &l4);
    }
}

#[test]
fn fragmented_icmpv6_error_is_reassembled_and_translated() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, _) = udp_flow(&mut fx, s);
    // Packet Too Big quoting a 1232-byte packet, split in two fragments.
    let q = {
        let mut q = vec![0x41u8; 1232];
        write_v6_header(&mut q, 0, 1192, proto::UDP, 64, synth(SERVER), s);
        put16(&mut q, 40, 53);
        put16(&mut q, 42, 5353);
        put16(&mut q, 44, 1192);
        l4_sum6(&mut q, synth(SERVER), s, proto::UDP, 6);
        q
    };
    let l = 8 + q.len();
    let mut e = vec![0u8; 40 + l];
    write_v6_header(&mut e, 0, l as u16, proto::ICMPV6, 64, s, synth(SERVER));
    e[40] = 2;
    put32(&mut e, 44, 1280);
    e[48..].copy_from_slice(&q);
    l4_sum6(&mut e, s, synth(SERVER), proto::ICMPV6, 2);
    let fr = frag6(&e, 5, &[(0, 704), (704, l - 704)]);
    assert!(run_all(&mut fx, &fr[0]).unwrap().is_empty());
    let out = run_all(&mut fx, &fr[1]).unwrap();
    assert_eq!(out.len(), 1);
    let h = parse_v4(&out[0]).unwrap();
    assert_eq!((h.src, h.dst, out[0][20], out[0][21]), (a, SERVER, 3, 4));
    csum4_ok(&h, proto::ICMP, &out[0][20..h.total_len]);
}

#[test]
fn icmp_errors_quoting_sent_non_first_fragments_translate() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let full = udp6(s, 5353, SERVER, 53, &[1; 300]);
    let mut out = Vec::new();
    for f in frag6(&full, 0x0102_0304, &CUTS3) {
        out.extend(run_all(&mut fx, &f).unwrap());
    }
    // A router reports a problem with the second IPv4 fragment we sent.
    let quoted = &out[1];
    let err = icmp4_err(ROUTER4, 11, 1, 0, quoted);
    let back = run(&mut fx, &err).unwrap();
    let h = parse_v6(&back).unwrap();
    assert_eq!((h.dst, back[40], back[41]), (s, 3, 1));
    // Quoted packet: IPv6 header + Fragment Header with the original ID.
    let ih = &back[48..];
    assert_eq!((ih[6], plat_packet::be128(ih, 8), plat_packet::be128(ih, 24)), (proto::FRAGMENT, s, synth(SERVER)));
    assert_eq!((ih[40], be32(ih, 44)), (proto::UDP, 0x0102_0304));
    assert_eq!(be16(ih, 42) >> 3, 13);
    csum6_ok(&h, proto::ICMPV6, &back[40..]);

    // The IPv6 side: a subscriber's error quoting a non-first fragment we
    // translated v4->v6.
    let (a, p) = (parse_v4(&out[0]).unwrap().src, be16(&out[0], 20));
    let r = udp4(SERVER, 53, a, p, &[2; 300]);
    let mut back = Vec::new();
    for f in frag4(&r, 0x0777, &CUTS3) {
        back.extend(run_all(&mut fx, &f).unwrap());
    }
    let q6 = &back[2];
    let l = 8 + q6.len();
    let mut e = vec![0u8; 40 + l];
    write_v6_header(&mut e, 0, l as u16, proto::ICMPV6, 64, s, synth(SERVER));
    e[40] = 1;
    e[41] = 4;
    e[48..].copy_from_slice(q6);
    l4_sum6(&mut e, s, synth(SERVER), proto::ICMPV6, 2);
    let o = run(&mut fx, &e).unwrap();
    let h4 = parse_v4(&o).unwrap();
    assert_eq!((h4.src, h4.dst, o[20], o[21]), (a, SERVER, 3, 3));
    assert_eq!((be32(&o, 28 + 12), be32(&o, 28 + 16), be16(&o, 28 + 4)), (SERVER, a, 0x0777));
}

#[test]
fn hairpinned_fragments() {
    let mut fx = fixture(&[EIF]);
    let (s1, s2) = (sub(1, 1), sub(2, 1));
    let (a1, p1) = udp_flow(&mut fx, s1);
    let full = udp6(s2, 4000, a1, p1, &[4; 300]);
    let mut out = Vec::new();
    for f in frag6(&full, 0x55, &CUTS3) {
        out.extend(run_all(&mut fx, &f).unwrap());
    }
    assert_eq!(out.len(), 3);
    let (h, l4) = reasm6(&out);
    assert_eq!(h.dst, s1);
    csum6_ok(&h, proto::UDP, &l4);
    assert!(fx.ctx.counters.get(Counter::Hairpin) >= 3);
}

#[test]
fn fragment_flood_is_bounded_and_counted() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let full = udp6(s, 5353, SERVER, 53, &[1; 300]);
    let mut drops = 0u64;
    for id in 0..100_000u32 {
        let f = &frag6(&full, id, &[(104, 104)])[0];
        if run_all(&mut fx, f).is_err() {
            drops += 1;
        }
    }
    assert!(fx.ctx.fragment_entries() <= 4096);
    assert!(drops > 90_000, "{drops}");
    let c = &fx.ctx.counters;
    assert_eq!(c.drops(DropReason::FragmentBufferFull) + c.drops(DropReason::FragmentTableFull), drops);
    assert_eq!(fx.nat.state().session_count(), 0, "no state from non-first fragments");
}

// ------------------------------------------------------------ POAM-002

#[test]
fn hop_limit_one_gets_time_exceeded() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let mut p = udp6(s, 1, SERVER, 53, b"x");
    p[7] = 1;
    let out = run(&mut fx, &p).unwrap();
    let h = parse_v6(&out).unwrap();
    assert_eq!((h.src, h.dst, out[40], out[41]), (synth(SERVER), s, 3, 0));
    csum6_ok(&h, proto::ICMPV6, &out[40..]);
    assert_eq!(fx.ctx.counters.get(Counter::IcmpTimeExceededSent), 1);
    assert_eq!(fx.ctx.counters.drops(DropReason::HopLimit), 1);
    assert!(events(&fx).is_empty(), "no binding");
    // Never about an ICMP error.
    let mut e = echo6(s, 1, SERVER);
    e[40] = 1;
    l4_sum6(&mut e, s, synth(SERVER), proto::ICMPV6, 2);
    e[7] = 1;
    assert_eq!(run(&mut fx, &e).unwrap_err(), DropReason::HopLimit);
    // Never about a non-first fragment.
    let full = udp6(s, 5353, SERVER, 53, &[1; 300]);
    let mut f = frag6(&full, 3, &CUTS3).remove(1);
    f[7] = 1;
    assert_eq!(run_all(&mut fx, &f).unwrap_err(), DropReason::HopLimit);
    assert_eq!(fx.ctx.counters.get(Counter::IcmpTimeExceededSent), 1);
}

#[test]
fn ttl_one_inbound_gets_time_exceeded_from_the_pool() {
    let mut fx = fixture(&[]);
    let (a, p) = udp_flow(&mut fx, sub(1, 1));
    let mut r = udp4(SERVER, 53, a, p, b"x");
    r[8] = 1;
    put16(&mut r, 10, 0);
    let c = ck::finish(ck::sum(&r[..20]));
    put16(&mut r, 10, c);
    let out = run(&mut fx, &r).unwrap();
    let h = parse_v4(&out).unwrap();
    assert_eq!((h.src, h.dst, out[20], out[21]), (a, SERVER, 11, 0));
    csum4_ok(&h, proto::ICMP, &out[20..]);
}

#[test]
fn active_routing_header_gets_parameter_problem() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let u = udp6(s, 1, SERVER, 53, b"abcdefgh");
    let mut p = vec![0u8; 40 + 8 + (u.len() - 40)];
    let pl = (p.len() - 40) as u16;
    write_v6_header(&mut p, 0, pl, proto::ROUTING, 64, s, synth(SERVER));
    p[40] = proto::UDP;
    p[43] = 1; // Segments Left
    p[48..].copy_from_slice(&u[40..]);
    let out = run(&mut fx, &p).unwrap();
    assert_eq!((out[40], out[41], be32(&out, 44)), (4, 0, 43));
    assert_eq!(fx.ctx.counters.get(Counter::IcmpParamProblemSent), 1);
    let mut fx = fixture(&[("send_param_problem = true", "send_param_problem = false")]);
    assert_eq!(run(&mut fx, &p).unwrap_err(), DropReason::UnsupportedProto);
}

#[test]
fn inbound_unreachable_is_off_by_default_and_gated() {
    let mut fx = fixture(&[]);
    let (a, p) = udp_flow(&mut fx, sub(1, 1));
    assert_eq!(run(&mut fx, &udp4(SERVER, 53, a, p + 1, b"x")).unwrap_err(), DropReason::NoBinding);
    let mut fx = fixture(&[("send_inbound_unreachable = false", "send_inbound_unreachable = true")]);
    let (a, p) = udp_flow(&mut fx, sub(1, 1));
    let out = run(&mut fx, &udp4(SERVER, 53, a, p + 1, b"x")).unwrap();
    assert_eq!((parse_v4(&out).unwrap().src, out[20], out[21]), (a, 3, 1));
    // ADF refusal: Communication Administratively Prohibited.
    let out = run(&mut fx, &udp4(ROUTER4, 53, a, p, b"x")).unwrap();
    assert_eq!((out[20], out[21]), (3, 13));
    // TCP stays silent.
    assert_eq!(run(&mut fx, &tcp4(SERVER, 80, a, p + 7, 0x02)).unwrap_err(), DropReason::NoBinding);
}

#[test]
fn local_errors_share_the_token_bucket() {
    let mut fx = fixture(&[("icmp_errors_per_sec = 100", "icmp_errors_per_sec = 4")]);
    let s = sub(1, 1);
    let mut p = udp6(s, 1, SERVER, 53, b"x");
    p[7] = 1;
    // Rate 4 keeps a reserve of 1 for PMTU errors: three Time Exceeded.
    for _ in 0..3 {
        assert!(run(&mut fx, &p).is_ok());
    }
    assert_eq!(run(&mut fx, &p).unwrap_err(), DropReason::HopLimit);
    assert_eq!(fx.ctx.counters.get(Counter::IcmpErrorsRateLimited), 1);
}

// ------------------------------------------------------------ POAM-011

#[test]
fn ipv4_identification_uses_a_randomized_counter_table() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let id = |fx: &mut Fx, port: u16| parse_v4(&run(fx, &udp6(s, port, SERVER, 53, b"x")).unwrap()).unwrap().id;
    // RFC 7739 §5.3: one flow's IDs advance by a random step of 1..=8.
    let mut prev = id(&mut fx, 1);
    let mut steps = Vec::new();
    for _ in 0..64 {
        let n = id(&mut fx, 1);
        steps.push(n.wrapping_sub(prev));
        prev = n;
    }
    assert!(steps.iter().all(|s| (1..=8).contains(s)), "{steps:?}");
    assert!(steps.iter().any(|&s| s != steps[0]), "random step, not a fixed increment");
    // Different destinations: offsets differ, so consecutive packets of
    // different flows are not consecutive IDs (8 tries, ~2^-128 to fail).
    let ids: Vec<u16> = (0..8u32)
        .map(|i| {
            let out = run(&mut fx, &udp6(s, 1, SERVER + i + 1, 53, b"x")).unwrap();
            parse_v4(&out).unwrap().id
        })
        .collect();
    assert!(ids.windows(2).any(|w| w[1] != w[0].wrapping_add(1)), "{ids:?}");
    // Two engines use different keys.
    let per_dst = |fx: &mut Fx| -> Vec<u16> {
        (0..8u32).map(|i| parse_v4(&run(fx, &udp6(s, 7, SERVER + 10 + i, 53, b"x")).unwrap()).unwrap().id).collect()
    };
    let (mut fx2, mut fx3) = (fixture(&[]), fixture(&[]));
    assert_ne!(per_dst(&mut fx2), per_dst(&mut fx3));
}

// ------------------------------------------------------------ POAM-023

#[test]
fn frag_needed_comes_before_the_session_update() {
    let mut fx = fixture(&[EIF, ("ipv6_mtu = 1500", "ipv6_mtu = 1280")]);
    let (a, p) = udp_flow(&mut fx, sub(1, 1));
    assert_eq!(fx.nat.state().session_count(), 1);
    // An unknown remote, too big with DF: Frag Needed (BIB exists), but no
    // EIF session is created.
    let big = udp4(ROUTER4, 99, a, p, &[0; 1400]);
    let out = run(&mut fx, &big).unwrap();
    assert_eq!((out[20], out[21], be16(&out, 26)), (3, 4, 1260));
    assert_eq!(fx.nat.state().session_count(), 1, "POAM-023: no session for a too-big packet");
    // No BIB: no ICMP oracle.
    assert_eq!(run(&mut fx, &udp4(ROUTER4, 99, a, p + 1, &[0; 1400])).unwrap_err(), DropReason::NoBinding);
    assert!(fx.nat.state().lookup4(Key4 { proto: proto::UDP, addr: a, port: p }).is_some());
}

// ------------------------------------------------------------ property

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    /// Any order, duplicates and random cuts: no panic, every fragment is
    /// emitted or counted, and buffer slots never leak.
    #[test]
    fn arbitrary_fragment_sequences(
        order in proptest::collection::vec(0usize..6, 1..12),
        len in 64usize..600,
        ids in 0u32..3,
    ) {
        let mut fx = fixture(&[]);
        let full = udp6(sub(1, 1), 5353, SERVER, 53, &vec![1u8; len]);
        let l4 = len + 8;
        let step = (l4 / 4).max(8) & !7;
        let cuts: Vec<(usize, usize)> =
            (0..l4.div_ceil(step)).map(|i| (i * step, step.min(l4 - i * step))).collect();
        let fr = frag6(&full, ids, &cuts);
        for &i in &order {
            if let Some(f) = fr.get(i % fr.len()) {
                let _ = run_all(&mut fx, f);
            }
        }
        fx.clock.advance(Duration::from_secs(3));
        for _ in 0..1024 {
            fx.nat.housekeep(&mut fx.ctx);
        }
        prop_assert_eq!(fx.ctx.fragment_entries(), 0);
        // All 64 buffer slots are free again: 64 distinct held fragments fit
        // (16 subscribers, each within its per-source share of 16).
        for id in 0..64u32 {
            let f = udp6(sub(2 + (id / 4) as u16, 1), 5353, SERVER, 53, &vec![1u8; len]);
            let f = &frag6(&f, 1000 + id, &cuts[1..2])[0];
            prop_assert!(run_all(&mut fx, f).unwrap().is_empty());
        }
    }

    /// Round trip: fragment → translate → reassemble equals the translation
    /// of the unfragmented packet's upper layer (UDP).
    #[test]
    fn fragmented_translation_matches_whole(len in 16usize..1200, cut in 1usize..8) {
        let mut fx = fixture(&[]);
        let s = sub(1, 1);
        let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let whole = run(&mut fx, &udp6(s, 5353, SERVER, 53, &payload)).unwrap();
        let full = udp6(s, 5353, SERVER, 53, &payload);
        let l4 = len + 8;
        let c = ((l4 * cut / 8) & !7).clamp(8, (l4 - 1) & !7);
        let mut out = Vec::new();
        for f in frag6(&full, 42, &[(0, c), (c, l4 - c)]) {
            out.extend(run_all(&mut fx, &f).unwrap());
        }
        let (_, l4b) = reasm4(&out);
        prop_assert_eq!(&l4b[..], &whole[20..]);
    }
}
