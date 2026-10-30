//! Regression tests for the round-1 review fixes (work unit 1): ICMP error
//! validation in both directions, locally generated Packet Too Big /
//! Fragmentation Needed, translator fragmentation (RFC 7915 §4), source
//! routes, bounded subscriber table, O(1) address-dependent filtering, and
//! the RFC 6052 §3.1 WKP deviation switch. Every output checksum is
//! recomputed from scratch.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::*;
use plat_common::{Counter, DropReason};
use plat_nat64::state::Key6;
use plat_packet::{be16, be32, checksum as ck, parse_v4, parse_v6, proto, put16, put32};
use plat_xlat::siit::{write_v4_header, write_v6_header};

const SERVER: u32 = 0xc633_6407; // 198.51.100.7
const OTHER: u32 = 0xcb00_7105; // 203.0.113.5
const ROUTER4: u32 = 0xcb00_7101; // 203.0.113.1

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

/// A forged "packet from `from` to `to`:5353" quote with chosen payload.
fn quote6(from: u128, to: u128, sport: u16, payload_len: usize) -> Vec<u8> {
    let l = 8 + payload_len;
    let mut q = vec![0x41u8; 40 + l];
    write_v6_header(&mut q, 0, l as u16, proto::UDP, 64, from, to);
    put16(&mut q, 40, sport);
    put16(&mut q, 42, 5353);
    put16(&mut q, 44, l as u16);
    l4_sum6(&mut q, from, to, proto::UDP, 6);
    q
}

fn v4_ok(p: &[u8]) -> plat_packet::Ipv4Hdr {
    let h = parse_v4(p).expect("valid IPv4 header");
    if h.frag.is_none() {
        let l4 = &p[h.hdr_len..h.total_len];
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

/// Opens UDP sub:5353 -> SERVER:53 and returns (pool addr, pool port).
fn udp_flow(fx: &mut Fx, s: u128) -> (u32, u16) {
    let out = run(fx, &udp6(s, 5353, SERVER, 53, b"query")).unwrap();
    let h = v4_ok(&out);
    (h.src, be16(&out, 20))
}

/// IPv4 UDP packet SERVER:53 -> `a`:`p` with an explicit DF/MF/id.
fn udp4_frag(a: u32, p: u16, payload: &[u8], df: bool, mf: bool, id: u16) -> Vec<u8> {
    let mut pkt = udp4(SERVER, 53, a, p, payload);
    let l = pkt.len() as u16;
    write_v4_header(&mut pkt[..20], 0, l, id, df, mf, 0, 64, proto::UDP, SERVER, a);
    pkt
}

// ------------------------------------------------- U1-A: ICMPv6 errors

/// SEC-001 / NIST-001: a quoted "server" in forbidden IPv4 space must never
/// become the destination of a translated ICMPv4 error.
#[test]
fn icmp6_error_cannot_reach_forbidden_ipv4_destinations() {
    for target in [0x7f00_0001u32, 0x0000_0000, 0xffff_ffff, 0xe000_0001, 0xa9fe_a9fe, 0xf000_0001] {
        let mut fx = fixture(&[]);
        let s = sub(1, 1);
        udp_flow(&mut fx, s);
        let err = icmp6_err(s, synth(target), 1, 4, 0, &quote6(synth(target), s, 53, 400));
        assert_eq!(run(&mut fx, &err).unwrap_err(), DropReason::DstForbidden, "{target:08x}");
    }
    // Under the WKP, non-global space (RFC 1918, shared, documentation) too.
    let mut fx = fixture(&[USE_WKP, WKP_POOL]);
    let s = sub(1, 1);
    for target in [0x0a00_0005u32, 0x6440_0001, 0xc0a8_0101, 0xc633_6407] {
        let t6 = WKP | u128::from(target);
        let err = icmp6_err(s, t6, 1, 4, 0, &quote6(t6, s, 53, 400));
        assert_eq!(run(&mut fx, &err).unwrap_err(), DropReason::DstForbidden, "WKP {target:08x}");
    }
}

/// The error must be addressed to the quoted source, and the quoted flow
/// must be a live session (not only a BIB entry).
#[test]
fn icmp6_error_requires_matching_live_session() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    udp_flow(&mut fx, s);
    // Outer destination differs from the quoted source.
    let err = icmp6_err(s, synth(OTHER), 1, 4, 0, &quote6(synth(SERVER), s, 53, 16));
    assert_eq!(run(&mut fx, &err).unwrap_err(), DropReason::Filtered);
    // Quoted server never contacted through this BIB (BIB exists).
    let err = icmp6_err(s, synth(OTHER), 1, 4, 0, &quote6(synth(OTHER), s, 53, 16));
    assert_eq!(run(&mut fx, &err).unwrap_err(), DropReason::Filtered);
    // Right server, wrong port.
    let err = icmp6_err(s, synth(SERVER), 1, 4, 0, &quote6(synth(SERVER), s, 54, 16));
    assert_eq!(run(&mut fx, &err).unwrap_err(), DropReason::Filtered);
    // Quoted destination outside the client prefixes.
    let outsider = 0x2001_0db8_ffff_0000_0000_0000_0000_0001u128;
    let err = icmp6_err(outsider, synth(SERVER), 1, 4, 0, &quote6(synth(SERVER), outsider, 53, 16));
    assert_eq!(run(&mut fx, &err).unwrap_err(), DropReason::SrcNotAllowed);
    // Quoted source outside the NAT64 prefix.
    let native = 0x2001_0db8_aaaa_0000_0000_0000_0000_0001u128;
    let err = icmp6_err(s, native, 1, 4, 0, &quote6(native, s, 53, 16));
    assert_eq!(run(&mut fx, &err).unwrap_err(), DropReason::DstNotTranslatable);
    // The legitimate error still translates.
    let err = icmp6_err(s, synth(SERVER), 1, 4, 0, &quote6(synth(SERVER), s, 53, 16));
    assert!(run(&mut fx, &err).is_ok());
    // After the session expires (BIB still in grace), the error is refused.
    fx.clock.advance(Duration::from_secs(301));
    fx.nat.state().sweep();
    assert_eq!(run(&mut fx, &err).unwrap_err(), DropReason::Filtered);
}

/// QA-003 / SEC-002: another host in the *same* subscriber prefix (the CPE)
/// may report; a different subscriber may not.
#[test]
fn icmp6_error_subscriber_scope() {
    let mut fx = fixture(&[]);
    let victim = sub(1, 1);
    udp_flow(&mut fx, victim);
    let q = quote6(synth(SERVER), victim, 53, 16);
    assert_eq!(run(&mut fx, &icmp6_err(sub(2, 1), synth(SERVER), 2, 0, 1280, &q)).unwrap_err(), DropReason::Filtered);
    assert!(run(&mut fx, &icmp6_err(sub(1, 0xfffe), synth(SERVER), 2, 0, 1280, &q)).is_ok());
}

/// SEC-002: a forged PTB with a tiny MTU cannot push the server below the
/// IPv6 minimum (1280 − 20 = 1260; RFC-009: 1280 − 28 with a Fragment Header).
#[test]
fn icmp6_ptb_mtu_floor() {
    for (mtu6, want) in [(0u32, 1260u32), (68, 1260), (1279, 1260), (1280, 1260), (1300, 1280)] {
        let mut fx = fixture(&[]);
        let s = sub(1, 1);
        udp_flow(&mut fx, s);
        let out = run(&mut fx, &icmp6_err(s, synth(SERVER), 2, 0, mtu6, &quote6(synth(SERVER), s, 53, 16))).unwrap();
        v4_ok(&out);
        assert_eq!((out[20], out[21], be32(&out, 24)), (3, 4, want), "PTB {mtu6}");
    }
    // Quoted packet with a Fragment Header: −28.
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    udp_flow(&mut fx, s);
    let q = quote6(synth(SERVER), s, 53, 16);
    let mut fq = vec![0u8; q.len() + 8];
    fq[..40].copy_from_slice(&q[..40]);
    fq[6] = proto::FRAGMENT;
    put16(&mut fq, 4, (q.len() - 40 + 8) as u16);
    fq[40] = proto::UDP;
    put16(&mut fq, 42, 1); // offset 0, M=1
    put32(&mut fq, 44, 7);
    fq[48..].copy_from_slice(&q[40..]);
    let out = run(&mut fx, &icmp6_err(s, synth(SERVER), 2, 0, 1400, &fq)).unwrap();
    assert_eq!(be32(&out, 24), 1372, "1400 - 28");
}

/// SEC-101 / NIST-103 / RFC-101: an ICMPv6 error whose source is inside the
/// NAT64 prefix is spoofed (stateful NAT64 has no IPv4 hosts on the IPv6
/// side) and dropped; every translated error leaves from the mapping's pool
/// address, never from an address the sender chose.
#[test]
fn icmp6_error_outer_source() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, _) = udp_flow(&mut fx, s);
    let q = quote6(synth(SERVER), s, 53, 16);
    // Global, private, own-pool, loopback and multicast "router" sources.
    for spoof in [ROUTER4, 0x0102_0304, 0x0808_0808, 0x0a00_0001, POOL_BASE + 1, 0x7f00_0001, 0xe000_0001] {
        let r = run(&mut fx, &icmp6_err(synth(spoof), synth(SERVER), 3, 0, 0, &q));
        assert_eq!(r.unwrap_err(), DropReason::SrcNotAllowed, "synth({spoof:08x})");
    }
    // A router outside the client prefixes and the subscriber itself: the
    // error is sent from the pool address.
    let router6 = 0x2001_0db8_ffff_0000_0000_0000_0000_0001u128;
    for src in [router6, s] {
        let out = run(&mut fx, &icmp6_err(src, synth(SERVER), 3, 0, 0, &q)).unwrap();
        assert_eq!((v4_ok(&out).src, v4_ok(&out).dst, out[20]), (a, SERVER, 11), "{src:032x}");
    }
}

/// RFC-103: an error quoting a non-first fragment has no ports to match.
#[test]
fn icmp_errors_quoting_non_first_fragments_are_dropped() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    let q = quote6(synth(SERVER), s, 53, 16);
    let mut fq = vec![0u8; q.len() + 8];
    fq[..40].copy_from_slice(&q[..40]);
    fq[6] = proto::FRAGMENT;
    put16(&mut fq, 4, (q.len() - 40 + 8) as u16);
    fq[40] = proto::UDP;
    put16(&mut fq, 42, 160 << 3); // offset 1280 bytes, M=0
    put32(&mut fq, 44, 7);
    fq[48..].copy_from_slice(&q[40..]);
    assert_eq!(run(&mut fx, &icmp6_err(s, synth(SERVER), 1, 4, 0, &fq)).unwrap_err(), DropReason::Fragment);
    let mut q4 = udp4(a, p, SERVER, 53, b"xxxxxxxx");
    let l = q4.len() as u16;
    write_v4_header(&mut q4[..20], 0, l, 9, false, false, 185, 64, proto::UDP, a, SERVER);
    assert_eq!(run(&mut fx, &icmp4_err(ROUTER4, 3, 3, 0, &q4)).unwrap_err(), DropReason::Fragment);
    // The same errors about first fragments / whole packets translate.
    assert!(run(&mut fx, &icmp6_err(s, synth(SERVER), 1, 4, 0, &q)).is_ok());
    assert!(run(&mut fx, &icmp4_err(ROUTER4, 3, 3, 0, &udp4(a, p, SERVER, 53, b"xxxxxxxx"))).is_ok());
}

// ------------------------------------------------- U1-B: ICMPv4 errors

/// SEC-003: an off-path IPv4 host cannot quote a server the subscriber never
/// contacted (ADF/APDF); EIF keeps BIB-only validation.
#[test]
fn icmp4_error_requires_session_unless_eif() {
    let fake_server = 0xc633_644d; // 198.51.100.77, never contacted
    for (filtering, ok) in
        [("address_dependent", false), ("address_port_dependent", false), ("endpoint_independent", true)]
    {
        let edit = format!("filtering = \"{filtering}\"");
        let mut fx = fixture(&[("filtering = \"address_dependent\"", &edit)]);
        let s = sub(1, 1);
        let (a, p) = udp_flow(&mut fx, s);
        let err = icmp4_err(ROUTER4, 3, 3, 0, &udp4(a, p, fake_server, 4444, b"xxxxxxxx"));
        let r = run(&mut fx, &err);
        if ok {
            assert!(r.is_ok(), "{filtering}");
        } else {
            assert_eq!(r.unwrap_err(), DropReason::Filtered, "{filtering}");
        }
        // The real flow's error is always translated.
        let err = icmp4_err(ROUTER4, 3, 3, 0, &udp4(a, p, SERVER, 53, b"xxxxxxxx"));
        assert!(run(&mut fx, &err).is_ok(), "{filtering}: legitimate error");
    }
}

// ------------------------------------------------- U1-J: WKP deviation switch

#[test]
fn wkp_non_global_icmp_error_source_needs_switch() {
    let global = 0xc000_0009; // 192.0.0.9, globally reachable (RFC 7723)
    for (flag, ok) in [(false, false), (true, true)] {
        let edit = format!("wkp_non_global_icmp_errors = {flag}");
        let mut fx = fixture(&[USE_WKP, WKP_POOL, ("wkp_non_global_icmp_errors = false", &edit)]);
        let s = sub(1, 1);
        let mut pkt = udp6(s, 5353, global, 53, b"q");
        let d6 = WKP | u128::from(global);
        pkt[24..40].copy_from_slice(&d6.to_be_bytes());
        l4_sum6(&mut pkt, s, d6, proto::UDP, 6);
        let out = run(&mut fx, &pkt).unwrap();
        let r = run(&mut fx, &icmp4_err(0x0a00_0001, 11, 0, 0, &out));
        assert_eq!(r.is_ok(), ok, "flag {flag}: {r:?}");
        if !ok {
            assert_eq!(r.unwrap_err(), DropReason::SrcNotAllowed);
        }
        // Never-translatable sources stay refused either way.
        assert_eq!(run(&mut fx, &icmp4_err(0x7f00_0001, 11, 0, 0, &out)).unwrap_err(), DropReason::SrcNotAllowed);
    }
}

// ------------------------------------------------- U1-F: local ICMP errors

/// RFC-002: a DF IPv4 packet that does not fit the IPv6 MTU gets a
/// Fragmentation Needed with MTU = ipv6_mtu − 20 from the pool address.
#[test]
fn df_too_big_v4_gets_frag_needed() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    // 1480-byte IPv4 → 1500-byte IPv6: fits.
    let fits = udp4(SERVER, 53, a, p, &[7u8; 1452]);
    assert_eq!(run(&mut fx, &fits).unwrap().len(), 1500);
    // 1481 → 1501: Fragmentation Needed.
    let big = udp4(SERVER, 53, a, p, &[7u8; 1453]);
    let out = run(&mut fx, &big).unwrap();
    let h = v4_ok(&out);
    assert_eq!((h.src, h.dst, h.proto), (a, SERVER, proto::ICMP));
    assert_eq!((out[20], out[21], be16(&out, 26)), (3, 4, 1480));
    assert!(out.len() <= 576);
    assert_eq!(&out[28..48], &big[..20], "quotes the original IPv4 header");
    assert_eq!(fx.ctx.counters.drops(DropReason::TooBig), 1);
    assert_eq!(fx.ctx.counters.get(Counter::IcmpErrorsGenerated), 1);
}

/// RFC-002: an IPv6 packet whose translation exceeds the IPv4 MTU gets a
/// Packet Too Big (MTU = ipv4_mtu + 20) and creates no state (QA-002).
#[test]
fn too_big_v6_gets_ptb_and_no_state() {
    let mut fx = fixture(&[("ipv4_mtu = 1500", "ipv4_mtu = 1400")]);
    let s = sub(1, 1);
    let pkt = udp6(s, 5353, SERVER, 53, &[1u8; 1452]); // 1500 bytes, 1480 as IPv4
    let out = run(&mut fx, &pkt).unwrap();
    let h = v6_ok(&out);
    assert_eq!((h.src, h.dst, h.proto), (synth(SERVER), s, proto::ICMPV6));
    assert_eq!((out[40], out[41], be32(&out, 44)), (2, 0, 1420));
    assert_eq!(out.len(), 1280, "quote truncated to the IPv6 minimum MTU");
    assert_eq!(&out[48..88], &pkt[..40]);
    assert!(fx.nat.state().lookup6(Key6 { proto: proto::UDP, addr: s, port: 5353 }).is_none());
    assert!(events(&fx).is_empty(), "no attribution record for a dropped packet");
    // A packet within 1280 bytes that would need IPv4 fragmentation is
    // dropped without a PTB (POAM-002).
    let mut fx = fixture(&[("ipv4_mtu = 1500", "ipv4_mtu = 576")]);
    assert_eq!(run(&mut fx, &udp6(s, 5353, SERVER, 53, &[1u8; 1000])).unwrap_err(), DropReason::TooBig);
}

#[test]
fn local_icmp_errors_are_rate_limited_per_worker() {
    let mut fx = fixture(&[("icmp_errors_per_sec = 100", "icmp_errors_per_sec = 2")]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    let big = udp4(SERVER, 53, a, p, &[7u8; 1453]);
    assert!(run(&mut fx, &big).is_ok());
    assert!(run(&mut fx, &big).is_ok());
    assert_eq!(run(&mut fx, &big).unwrap_err(), DropReason::TooBig);
    assert_eq!(fx.ctx.counters.get(Counter::IcmpErrorsRateLimited), 1);
    fx.clock.advance(Duration::from_millis(600));
    assert!(run(&mut fx, &big).is_ok(), "refilled at 2/s");
    let mut fx = fixture(&[("icmp_errors_per_sec = 100", "icmp_errors_per_sec = 0")]);
    let (a, p) = udp_flow(&mut fx, s);
    assert_eq!(run(&mut fx, &udp4(SERVER, 53, a, p, &[7u8; 1453])).unwrap_err(), DropReason::TooBig);
}

// ------------------------------------------------- U1-G: fragmentation

/// RFC-003 / RFC 7915 §4: DF=0 packets larger than lowest-ipv6-mtu (1280)
/// are split into IPv6 fragments; the reassembled datagram is intact.
#[test]
fn df0_packets_are_fragmented_to_1280() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    let payload: Vec<u8> = (0..1400u32).map(|i| i as u8).collect();
    let pkt = udp4_frag(a, p, &payload, false, false, 0x4321);
    let frags = run_all(&mut fx, &pkt).unwrap();
    assert_eq!(frags.len(), 2);
    assert_eq!(frags[0].len(), 1280);
    let mut l4 = Vec::new();
    for (i, f) in frags.iter().enumerate() {
        let h = parse_v6(f).unwrap();
        assert!(f.len() <= 1280);
        assert_eq!((h.src, h.dst, h.proto), (synth(SERVER), s, proto::UDP));
        let fr = h.frag.unwrap();
        assert_eq!(fr.id, 0x4321, "Identification = IPv4 id, high bits zero");
        assert_eq!(usize::from(fr.offset) * 8, l4.len(), "fragment {i} offset");
        assert_eq!(fr.more, i == 0);
        l4.extend_from_slice(&f[h.l4_off..]);
    }
    assert_eq!(l4.len(), 8 + payload.len());
    assert_eq!(&l4[8..], &payload[..]);
    assert_eq!(be16(&l4, 2), 5353);
    let sum = ck::pseudo_v6(synth(SERVER), s, proto::UDP, l4.len() as u32) + ck::sum(&l4);
    assert_eq!(ck::fold(sum), 0xffff, "UDP checksum over the reassembled datagram");
    assert_eq!(fx.ctx.counters.get(Counter::FragmentedV4ToV6), 1);

    // Small DF=0 packets pass unfragmented.
    let small = udp4_frag(a, p, b"tiny", false, false, 1);
    assert_eq!(run(&mut fx, &small).unwrap()[6], proto::UDP);
    // An IPv4 first fragment keeps M=1 on its last IPv6 fragment.
    let mut first = udp4_frag(a, p, &payload, false, true, 0x99);
    let l = first.len() as u16;
    write_v4_header(&mut first[..20], 0, l, 0x99, false, true, 0, 64, proto::UDP, SERVER, a);
    let frags = run_all(&mut fx, &first).unwrap();
    assert!(frags.iter().all(|f| parse_v6(f).unwrap().frag.unwrap().more));
}

#[test]
fn lowest_ipv6_mtu_raises_the_fragmentation_threshold() {
    let mut fx = fixture(&[("lowest_ipv6_mtu = 1280", "lowest_ipv6_mtu = 1500")]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    let pkt = udp4_frag(a, p, &[3u8; 1400], false, false, 5);
    let out = run(&mut fx, &pkt).unwrap();
    v6_ok(&out);
    assert_eq!(out.len(), 1448);
}

// ------------------------------------------------- U1-H: source routes

#[test]
fn unexpired_source_route_is_dropped() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    for ty in [131u8, 137] {
        let base = udp4(SERVER, 53, a, p, b"x");
        let mut pkt = base[..20].to_vec();
        pkt.extend_from_slice(&[ty, 7, 4, 10, 0, 0, 1, 0]);
        pkt.extend_from_slice(&base[20..]);
        pkt[0] = 0x47;
        let l = pkt.len() as u16;
        put16(&mut pkt, 2, l);
        put16(&mut pkt, 10, 0);
        let c = ck::finish(ck::sum(&pkt[..28]));
        put16(&mut pkt, 10, c);
        assert_eq!(run(&mut fx, &pkt).unwrap_err(), DropReason::SourceRoute, "option {ty}");
    }
}

// ------------------------------------------------- U1-D: subscriber table

#[test]
fn subscriber_table_is_bounded() {
    let mut fx = fixture(&[("max_subscribers = 1000000", "max_subscribers = 2")]);
    run(&mut fx, &udp6(sub(1, 1), 1, SERVER, 53, b"x")).unwrap();
    run(&mut fx, &udp6(sub(2, 1), 1, SERVER, 53, b"x")).unwrap();
    assert_eq!(run(&mut fx, &udp6(sub(3, 1), 1, SERVER, 53, b"x")).unwrap_err(), DropReason::SubscriberTableFull);
    // Existing subscribers keep allocating.
    run(&mut fx, &udp6(sub(1, 2), 9, SERVER, 53, b"x")).unwrap();
    assert_eq!(fx.nat.state().subscriber_count(), 2);
    // Full teardown frees the slots.
    fx.clock.advance(Duration::from_secs(301));
    fx.nat.state().sweep();
    fx.clock.advance(Duration::from_secs(3));
    fx.nat.state().sweep();
    fx.clock.advance(Duration::from_secs(61));
    fx.nat.state().sweep();
    assert_eq!(fx.nat.state().subscriber_count(), 0);
    run(&mut fx, &udp6(sub(3, 1), 1, SERVER, 53, b"x")).unwrap();
}

/// SEC-005: a failed allocation leaves no empty subscriber entry behind.
#[test]
fn failed_allocation_leaves_no_subscriber_entry() {
    let mut fx = fixture(&[
        ("port_block_size = 512", "port_block_size = 32256"),
        ("max_blocks_per_subscriber = 4", "max_blocks_per_subscriber = 1"),
    ]);
    for i in 0..8u16 {
        run(&mut fx, &udp6(sub(i, 1), 1, SERVER, 53, b"x")).unwrap();
    }
    for i in 100..200u16 {
        assert_eq!(run(&mut fx, &udp6(sub(i, 1), 1, SERVER, 53, b"x")).unwrap_err(), DropReason::PortExhausted);
    }
    assert_eq!(fx.nat.state().subscriber_count(), 8);
}

// ------------------------------------------------- U1-C: ADF index

#[test]
fn adf_remote_index_follows_session_expiry() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    fx.clock.advance(Duration::from_secs(200));
    run(&mut fx, &udp6(s, 5353, OTHER, 53, b"q")).unwrap();
    fx.clock.advance(Duration::from_secs(101));
    assert_eq!(fx.nat.state().sweep().sessions_expired, 1, "SERVER session expired");
    assert_eq!(run(&mut fx, &udp4(SERVER, 99, a, p, b"x")).unwrap_err(), DropReason::Filtered);
    assert!(run(&mut fx, &udp4(OTHER, 99, a, p, b"x")).is_ok(), "OTHER still contacted");
}

// ------------------------------------------------- NIST-015: wrong node

#[test]
fn traffic_for_another_nodes_pool_address_counts_wrong_node() {
    let mut fx = fixture(&[("pool = [\"192.0.2.0/30\"]", "pool = [\"192.0.2.0/29\"]")]);
    assert_eq!(run(&mut fx, &udp4(SERVER, 53, POOL_BASE + 6, 1024, b"x")).unwrap_err(), DropReason::WrongNode);
    assert_eq!(run(&mut fx, &udp4(SERVER, 53, 0xc000_0301, 1024, b"x")).unwrap_err(), DropReason::NoBinding);
}

// ------------------------------------------------- RFC-011: copy_tos

#[test]
fn copy_tos_switch() {
    for (flag, want) in [(true, 0xb8u8), (false, 0)] {
        let edit = format!("copy_tos = {flag}");
        let mut fx = fixture(&[("copy_tos = true", &edit)]);
        let s = sub(1, 1);
        let mut pkt = udp6(s, 5353, SERVER, 53, b"q");
        pkt[0] = 0x6b;
        pkt[1] = 0x80; // traffic class 0xb8 (EF)
        assert_eq!(v4_ok(&run(&mut fx, &pkt).unwrap()).tos, want, "copy_tos = {flag}");
    }
}

/// RFC-104: `copy_tos = false` also zeroes TOS / Traffic Class of translated
/// ICMP errors (outer and quoted headers).
#[test]
fn copy_tos_switch_applies_to_icmp_errors() {
    for (flag, want) in [(true, 0xb8u8), (false, 0)] {
        let edit = format!("copy_tos = {flag}");
        let mut fx = fixture(&[("copy_tos = true", &edit)]);
        let s = sub(1, 1);
        let (a, p) = udp_flow(&mut fx, s);
        // ICMPv6 -> ICMPv4: TC 0xb8 on the error and on the quoted packet.
        let mut q = quote6(synth(SERVER), s, 53, 16);
        q[0] = 0x6b;
        q[1] = 0x80;
        let mut e = icmp6_err(s, synth(SERVER), 1, 4, 0, &q);
        e[0] = 0x6b;
        e[1] = 0x80;
        let out = run(&mut fx, &e).unwrap();
        assert_eq!((v4_ok(&out).tos, out[29]), (want, want), "v6->v4 copy_tos = {flag}");
        // ICMPv4 -> ICMPv6: TOS 0xb8 on the error and on the quoted packet.
        let mut q4 = udp4(a, p, SERVER, 53, b"xxxxxxxx");
        let l = q4.len() as u16;
        write_v4_header(&mut q4[..20], 0xb8, l, 0, true, false, 0, 64, proto::UDP, a, SERVER);
        let mut e4 = icmp4_err(ROUTER4, 3, 3, 0, &q4);
        let l = e4.len() as u16;
        write_v4_header(&mut e4[..20], 0xb8, l, 0, false, false, 0, 64, proto::ICMP, ROUTER4, a);
        let out = run(&mut fx, &e4).unwrap();
        let inner_tc = ((out[48] & 0x0f) << 4) | (out[49] >> 4);
        assert_eq!((v6_ok(&out).traffic_class, inner_tc), (want, want), "v4->v6 copy_tos = {flag}");
    }
}

// ------------------------------------------------- SEC-106: non-global space

/// SEC-106: with the default `allow_non_global_destinations = false`, a
/// network-specific prefix cannot reach RFC 6890 non-global IPv4 space,
/// neither with data packets nor through ICMPv6 errors. (The WKP denies it
/// even with the opt-in: `engine.rs::wkp_refuses_every_non_global_destination`
/// runs on an opted-in fixture.)
#[test]
fn non_global_destinations_are_denied_by_default() {
    let mut fx = fixture_strict(&[]);
    let s = sub(1, 1);
    for dst in [
        0x0a00_000au32, // 10/8
        0x6440_0001,    // 100.64/10
        0xac10_0001,    // 172.16/12
        0xc0a8_0101,    // 192.168/16
        0xc000_0001,    // 192.0.0/24
        0xc612_0001,    // 198.18/15
        SERVER,         // 198.51.100/24
        OTHER,          // 203.0.113/24
    ] {
        assert_eq!(run(&mut fx, &udp6(s, 1, dst, 53, b"x")).unwrap_err(), DropReason::DstForbidden, "{dst:08x}");
        let err = icmp6_err(s, synth(dst), 1, 4, 0, &quote6(synth(dst), s, 53, 16));
        assert_eq!(run(&mut fx, &err).unwrap_err(), DropReason::DstForbidden, "error to {dst:08x}");
    }
    assert_eq!(fx.nat.state().session_count(), 0, "nothing was created");
    // Global destinations (incl. 192.0.0.9, RFC 7723) are translated.
    for dst in [0x0808_0808u32, 0xc000_0009] {
        assert!(run(&mut fx, &udp6(s, 2, dst, 53, b"x")).is_ok(), "{dst:08x}");
    }
    // The explicit opt-in allows non-global space; never-translatable space
    // stays denied.
    let mut fx = fixture(&[]);
    assert!(run(&mut fx, &udp6(s, 1, 0x0a00_000a, 53, b"x")).is_ok());
    assert_eq!(run(&mut fx, &udp6(s, 1, 0x7f00_0001, 53, b"x")).unwrap_err(), DropReason::DstForbidden);
}

// ------------------------------------------------- RFC-102: lazy expiry

/// RFC-102: an expired session that the sweeper has not reached yet neither
/// admits inbound traffic nor is revived by it.
#[test]
fn expired_unswept_session_is_not_revived() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    assert_eq!(fx.nat.state().session_count(), 1);
    fx.clock.advance(Duration::from_secs(301)); // udp_secs = 300, no sweep
    assert_eq!(run(&mut fx, &udp4(SERVER, 53, a, p, b"late")).unwrap_err(), DropReason::Filtered);
    assert_eq!(fx.nat.state().session_count(), 0, "expired session removed, not refreshed");
    // An outbound packet creates a fresh session on the same mapping.
    assert_eq!(udp_flow(&mut fx, s), (a, p));
    assert_eq!(fx.nat.state().session_count(), 1);
    assert!(run(&mut fx, &udp4(SERVER, 53, a, p, b"reply")).is_ok());
    fx.clock.advance(Duration::from_secs(301));
    assert_eq!(fx.nat.state().sweep().sessions_expired, 1);
    assert_eq!(fx.nat.state().session_count(), 0);
}

// ------------------------------------------------- NIST-006a: release records

/// NIST-401: with a disconnected audit sink (logger stopped) a quarantined
/// block's release record is abandoned and counted as lost exactly once,
/// not once per sweep pass; the block stays quarantined.
#[test]
fn disconnected_sink_counts_quarantined_release_once() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let total = fx.nat.state().pool.free_blocks();
    udp_flow(&mut fx, s);
    let Fx { nat, clock, rx, .. } = fx;
    drop(rx);
    let lost = || nat.state().audit().stats().lost.load(std::sync::atomic::Ordering::Relaxed);
    clock.advance(Duration::from_secs(301));
    // Expires the session/BIB (the BIB delete is lost); the block lingers.
    assert_eq!(nat.state().sweep().releases_deferred, 0);
    let base = lost();
    let mut deferred = 0;
    let mut first_pass = true;
    for secs in [3, 61, 61, 61, 61] {
        clock.advance(Duration::from_secs(secs));
        let st = nat.state().sweep();
        assert_eq!(st.blocks_released, 0);
        deferred += st.releases_deferred;
        if st.releases_deferred > 0 && first_pass {
            first_pass = false;
            assert_eq!(lost(), base + 1, "abandoned release counted on first attempt");
        }
    }
    assert!(deferred >= 3, "release retried on several passes ({deferred})");
    assert_eq!(lost(), base + 1, "abandoned release counted exactly once");
    assert_eq!(nat.state().pool.free_blocks(), total - 1, "block stays quarantined");
}

/// NIST-006a: a block whose release record cannot be queued stays with its
/// subscriber (quarantined) and is released on a later pass once the record
/// is queued, so attribution windows never overlap in the queued stream.
/// NIST-201 / PERF-203: the deferred release is not counted as a lost
/// record on each retry.
#[test]
fn block_is_not_reused_before_its_release_record_is_queued() {
    let mut fx = fixture_q(&[], 1);
    let s = sub(1, 1);
    let total = fx.nat.state().pool.free_blocks();
    udp_flow(&mut fx, s); // allocation record fills the 1-slot queue
    assert_eq!(fx.nat.state().pool.free_blocks(), total - 1);
    let lost = || fx.nat.state().audit().stats().lost.load(std::sync::atomic::Ordering::Relaxed);
    fx.clock.advance(Duration::from_secs(301));
    let first = fx.nat.state().sweep();
    assert_eq!(first.blocks_released, 0);
    // Only the BIB delete (not retried) is a real loss.
    let lost_after_first = lost();
    let mut deferred = 0;
    for secs in [3, 61, 61, 61] {
        fx.clock.advance(Duration::from_secs(secs));
        let st = fx.nat.state().sweep();
        assert_eq!(st.blocks_released, 0);
        deferred += st.releases_deferred;
    }
    assert!(deferred >= 2, "release retried on several passes ({deferred})");
    // SEC-302: the cumulative count (exported to /metrics) tracks every pass.
    assert_eq!(fx.nat.state().releases_deferred_total(), deferred + first.releases_deferred);
    assert_eq!(lost(), lost_after_first, "deferred releases are not counted as lost");
    assert_eq!(fx.nat.state().pool.free_blocks(), total - 1, "quarantined while the queue is full");
    assert_eq!(fx.nat.state().subscriber_count(), 1);
    assert!(matches!(events(&fx)[..], [plat_audit::Event::PortBlockAlloc { .. }]));
    assert_eq!(fx.nat.state().sweep().blocks_released, 1);
    assert_eq!(fx.nat.state().pool.free_blocks(), total - 1, "cool-down after the release (POAM-010)");
    assert_eq!(fx.nat.state().subscriber_count(), 0);
    assert!(matches!(events(&fx)[..], [plat_audit::Event::PortBlockRelease { .. }]));
    fx.clock.advance(Duration::from_secs(120));
    fx.nat.state().sweep();
    assert_eq!(fx.nat.state().pool.free_blocks(), total);
}

// ------------------------------------------------- PERF-106: token refill

/// PERF-106: refill keeps the fractional remainder, so 150/s is not
/// truncated to one token per 10 ms clock tick (100/s).
#[test]
fn icmp_token_refill_keeps_the_remainder() {
    let mut fx = fixture(&[("icmp_errors_per_sec = 100", "icmp_errors_per_sec = 150")]);
    let s = sub(1, 1);
    let (a, p) = udp_flow(&mut fx, s);
    let big = udp4(SERVER, 53, a, p, &[7u8; 1453]);
    while run(&mut fx, &big).is_ok() {}
    let mut sent = 0;
    for _ in 0..100 {
        fx.clock.advance(Duration::from_millis(10));
        for _ in 0..3 {
            sent += usize::from(run(&mut fx, &big).is_ok());
        }
    }
    assert!((140..=151).contains(&sent), "{sent} errors in 1 s at 150/s");
}

// ------------------------------------------------- round 3: RFC-201..203

const EIF: (&str, &str) = ("filtering = \"address_dependent\"", "filtering = \"endpoint_independent\"");
/// A global destination for the default-policy fixtures.
const GLOBAL: u32 = 0x0808_0808;

/// RFC-201: hairpinning (RFC 6146 §3.8, RFC 4787 REQ-9) works with the
/// default destination policy and the example's non-global (TEST-NET-1)
/// pool: the pool is exempt from the non-global test in both directions.
#[test]
fn hairpin_with_non_global_pool_under_default_policy() {
    let mut fx = fixture_strict(&[EIF]);
    let (a, b) = (sub(1, 1), sub(2, 1));
    let out = run(&mut fx, &udp6(b, 6000, GLOBAL, 53, b"x")).unwrap();
    let (b4, bp) = (v4_ok(&out).src, be16(&out, 20));
    assert_eq!(b4 & 0xffff_fffc, POOL_BASE);
    let back = run(&mut fx, &udp6(a, 7000, b4, bp, b"hi B")).unwrap();
    let h = v6_ok(&back);
    assert_eq!((h.dst, be16(&back, 42)), (b, 6000));
    let a4 = fx.nat.state().lookup6(Key6 { proto: proto::UDP, addr: a, port: 7000 }).unwrap();
    assert_eq!((h.src, be16(&back, 40)), (synth(a4.addr), a4.port));
    // B answers A through A's mapping.
    let reply = run(&mut fx, &udp6(b, 6000, a4.addr, a4.port, b"hi A")).unwrap();
    assert_eq!(v6_ok(&reply).dst, a);
    // Other non-global destinations stay denied.
    assert_eq!(run(&mut fx, &udp6(a, 7001, 0x0a00_0001, 53, b"x")).unwrap_err(), DropReason::DstForbidden);
}

/// RFC-202 / SEC-203: with non-global destinations denied (the default),
/// non-global IPv4 *sources* of data packets are refused too, so EIF does
/// not admit remotes the subscriber could never answer. ICMP errors from
/// non-global routers are still translated (PMTUD), and the opt-in restores
/// the old behaviour.
#[test]
fn non_global_sources_are_refused_under_default_policy() {
    let mut fx = fixture_strict(&[EIF]);
    let b = sub(2, 1);
    let out = run(&mut fx, &udp6(b, 6000, GLOBAL, 53, b"x")).unwrap();
    let (b4, bp) = (v4_ok(&out).src, be16(&out, 20));
    for src in [0x0a00_0005u32, 0x6440_0001, 0xc0a8_0001, 0xac10_0001, SERVER] {
        let r = run(&mut fx, &udp4(src, 9999, b4, bp, b"unsolicited"));
        assert_eq!(r.unwrap_err(), DropReason::SrcNotAllowed, "{src:08x}");
        let r = run(&mut fx, &tcp4(src, 9999, b4, bp, 0x02));
        assert_eq!(r.unwrap_err(), DropReason::SrcNotAllowed, "tcp {src:08x}");
    }
    // A global remote is admitted under EIF.
    assert!(run(&mut fx, &udp4(0x0909_0909, 9999, b4, bp, b"ok")).is_ok());
    // An ICMP error from a non-global router about the real flow passes.
    let err = icmp4_err(0x0a00_0001, 3, 4, 1400, &out);
    assert!(run(&mut fx, &err).is_ok(), "non-global router error");
    // With the explicit opt-in, non-global sources are accepted again.
    let mut fx = fixture(&[EIF]);
    let out = run(&mut fx, &udp6(b, 6000, GLOBAL, 53, b"x")).unwrap();
    let (b4, bp) = (v4_ok(&out).src, be16(&out, 20));
    assert!(run(&mut fx, &udp4(0x0a00_0005, 9999, b4, bp, b"opt-in")).is_ok());
}

/// RFC-203: an ICMPv6 error whose source is inside the NAT64 prefix is
/// dropped even when its u-octet (bits 64..71) is non-zero.
#[test]
fn in_prefix_error_source_with_nonzero_u_octet_is_dropped() {
    let p64: u128 = 0x0064_ff9b_0001_0000_0000_0000_0000_0000;
    let s64 = |v4: u32| p64 | (u128::from(v4) << 24);
    let mut fx = fixture(&[("nat64_prefix = \"64:ff9b:1::/96\"", "nat64_prefix = \"64:ff9b:1::/64\"")]);
    let s = sub(1, 1);
    let mut pkt = udp6(s, 5353, SERVER, 53, b"q");
    pkt[24..40].copy_from_slice(&s64(SERVER).to_be_bytes());
    l4_sum6(&mut pkt, s, s64(SERVER), proto::UDP, 6);
    run(&mut fx, &pkt).unwrap();
    let q = quote6(s64(SERVER), s, 53, 16);
    let clean = s64(0x0102_0304);
    for src in [clean, clean | (1u128 << 56), clean | (0xffu128 << 56)] {
        let r = run(&mut fx, &icmp6_err(src, s64(SERVER), 1, 0, 0, &q));
        assert_eq!(r.unwrap_err(), DropReason::SrcNotAllowed, "{src:032x}");
    }
    // A router outside the prefix is still translated.
    let router6 = 0x2001_0db8_ffff_0000_0000_0000_0000_0001u128;
    let r = run(&mut fx, &icmp6_err(router6, s64(SERVER), 1, 0, 0, &q));
    assert!(r.is_ok(), "{r:?}");
}

// ------------------------------------------------- SEC-301: own-slice spoof

/// The example pool as a /24 cluster pool; the fixture node owns .0-.3.
const CLUSTER_24: (&str, &str) = ("192.0.2.0/30", "192.0.2.0/24");

/// SEC-301 (SC-7(5), BCP 38): under EIF, a wire packet whose source is in
/// this node's own pool slice (e.g. subscriber B's live mapping) is spoofed,
/// because own-node hairpins are looped back in-process. It is refused;
/// the own-node hairpin and sources in other nodes' slices still work.
#[test]
fn wire_source_in_own_pool_slice_is_refused() {
    let mut fx = fixture_strict(&[CLUSTER_24, EIF]);
    let (a, b) = (sub(1, 1), sub(2, 1));
    let oa = run(&mut fx, &udp6(a, 5353, GLOBAL, 53, b"q")).unwrap();
    let (a4, ap) = (be32(&oa, 12), be16(&oa, 20));
    let ob = run(&mut fx, &udp6(b, 6000, GLOBAL, 53, b"q")).unwrap();
    let (b4, bp) = (be32(&ob, 12), be16(&ob, 20));
    // Spoof of B's mapping, an arbitrary own-slice port, and src = dst = A.
    for (src, sp) in [(b4, bp), (a4, 1), (a4, ap)] {
        let r = run(&mut fx, &udp4(src, sp, a4, ap, b"spoof"));
        assert_eq!(r.unwrap_err(), DropReason::SrcNotAllowed, "{src:08x}:{sp}");
    }
    // Another node's slice (cross-node hairpin) is still accepted.
    let other = 0xc000_0264; // 192.0.2.100
    let r = run(&mut fx, &udp4(other, 4444, a4, ap, b"peer")).unwrap();
    assert_eq!(v6_ok(&r).src, synth(other));
    // The own-node hairpin A -> B's mapping is still forwarded.
    let hp = run(&mut fx, &udp6(a, 7000, b4, bp, b"hp")).unwrap();
    assert_eq!((v6_ok(&hp).dst, be16(&hp, 42)), (b, 6000));
}
