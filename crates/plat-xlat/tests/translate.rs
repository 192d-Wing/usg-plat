//! Translation correctness: every output checksum is re-verified from
//! scratch, independent of the incremental update used by the translator.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use plat_packet::{L4, be16, checksum as ck, parse_l4, parse_v4, parse_v6, proto, put16, put32, put128};
use plat_xlat::icmp::{icmp4_err_to_v6, icmp6_err_to_v4, quoted_v4, quoted_v6};
use plat_xlat::siit::{write_v4_header, write_v6_header};
use plat_xlat::{HEADROOM, Map4, Map6, Prefix6052, XlatError, v4_to_v6, v6_to_v4};
use proptest::prelude::*;

const SUB: u128 = 0x2001_0db8_0100_0001_0000_0000_0000_0001;
const SERVER4: u32 = 0xc633_6407; // 198.51.100.7
const POOL4: u32 = 0xc000_020a; // 192.0.2.10

fn pfx() -> Prefix6052 {
    Prefix6052::new(plat_xlat::rfc6052::WKP, 96).unwrap()
}

/// Builds an IPv6 packet with a valid transport checksum.
fn pkt6(p: u8, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let hl = match p {
        proto::TCP => 20,
        _ => 8,
    };
    let l4_len = hl + payload.len();
    let mut v = vec![0u8; 40 + l4_len];
    write_v6_header(&mut v, 0x28, l4_len as u16, p, 61, SUB, pfx().embed(SERVER4));
    let l4 = &mut v[40..];
    match p {
        proto::TCP => {
            put16(l4, 0, sport);
            put16(l4, 2, dport);
            put32(l4, 4, 1000);
            l4[12] = 5 << 4;
            l4[13] = 0x02; // SYN
            put16(l4, 14, 65535);
        }
        proto::UDP => {
            put16(l4, 0, sport);
            put16(l4, 2, dport);
            put16(l4, 4, l4_len as u16);
        }
        _ => {
            l4[0] = 128;
            put16(l4, 4, sport);
            put16(l4, 6, 1);
        }
    }
    l4[hl..].copy_from_slice(payload);
    let off = match p {
        proto::TCP => 16,
        proto::UDP => 6,
        _ => 2,
    };
    let c = ck::finish(ck::pseudo_v6(SUB, pfx().embed(SERVER4), p, l4_len as u32) + ck::sum(&v[40..]));
    put16(&mut v, 40 + off, if p == proto::UDP { ck::udp_nonzero(c) } else { c });
    v
}

fn verify_v4(pkt: &[u8]) -> (plat_packet::Ipv4Hdr, L4) {
    let h = parse_v4(pkt).expect("valid IPv4 header incl. header checksum");
    let l4 = &pkt[h.hdr_len..h.total_len];
    let s = match h.proto {
        proto::ICMP => ck::sum(l4),
        p => ck::pseudo_v4(h.src, h.dst, p, l4.len() as u16) + ck::sum(l4),
    };
    assert_eq!(ck::fold(s), 0xffff, "IPv4 transport checksum");
    (h, parse_l4(pkt, h.hdr_len, h.total_len, h.proto).unwrap())
}

fn verify_v6(pkt: &[u8]) -> (plat_packet::Ipv6Hdr, L4) {
    let h = parse_v6(pkt).expect("valid IPv6");
    let l4 = &pkt[h.l4_off..h.total_len()];
    let s = ck::pseudo_v6(h.src, h.dst, h.proto, l4.len() as u32) + ck::sum(l4);
    assert_eq!(ck::fold(s), 0xffff, "IPv6 transport checksum");
    (h, parse_l4(pkt, h.l4_off, h.total_len(), h.proto).unwrap())
}

fn run_6to4(pkt: &[u8], m: &Map4) -> Result<Vec<u8>, XlatError> {
    let mut buf = vec![0u8; HEADROOM + pkt.len()];
    buf[HEADROOM..].copy_from_slice(pkt);
    let h = parse_v6(&buf[HEADROOM..]).unwrap();
    let (s, l) = v6_to_v4(&mut buf, HEADROOM, &h, m, 0x1234, 1500)?;
    Ok(buf[s..s + l].to_vec())
}

fn run_4to6(pkt: &[u8], m: &Map6) -> Result<Vec<u8>, XlatError> {
    let mut buf = vec![0u8; HEADROOM + pkt.len()];
    buf[HEADROOM..].copy_from_slice(pkt);
    let h = parse_v4(&buf[HEADROOM..]).unwrap();
    let (s, l) = v4_to_v6(&mut buf, HEADROOM, &h, m, 1500)?;
    Ok(buf[s..s + l].to_vec())
}

#[test]
fn tcp_v6_to_v4_and_back() {
    let p6 = pkt6(proto::TCP, 40000, 443, b"hello");
    let m4 = Map4 { src: POOL4, dst: SERVER4, sport: 2048, dport: 443 };
    let p4 = run_6to4(&p6, &m4).unwrap();
    let (h, l4) = verify_v4(&p4);
    assert_eq!((h.src, h.dst, h.ttl, h.tos, h.proto), (POOL4, SERVER4, 61, 0x28, proto::TCP));
    assert!(matches!(l4, L4::Tcp { sport: 2048, dport: 443, flags: 0x02 }));
    assert_eq!(&p4[p4.len() - 5..], b"hello");

    // Reply direction: swap roles.
    let mut r = p4.clone();
    put32(&mut r, 12, SERVER4);
    put32(&mut r, 16, POOL4);
    put16(&mut r, 20, 443);
    put16(&mut r, 22, 2048);
    put16(&mut r, 10, 0);
    let c = ck::finish(ck::sum(&r[..20]));
    put16(&mut r, 10, c);
    put16(&mut r, 36, 0);
    let c = ck::finish(ck::pseudo_v4(SERVER4, POOL4, 6, (r.len() - 20) as u16) + ck::sum(&r[20..]));
    put16(&mut r, 36, c);
    let m6 = Map6 { src: pfx().embed(SERVER4), dst: SUB, sport: 443, dport: 40000 };
    let back = run_4to6(&r, &m6).unwrap();
    let (h6, l4) = verify_v6(&back);
    assert_eq!((h6.src, h6.dst, h6.hop_limit, h6.flow_label), (pfx().embed(SERVER4), SUB, 61, 0));
    assert!(matches!(l4, L4::Tcp { sport: 443, dport: 40000, .. }));
}

#[test]
fn icmp_echo_both_ways() {
    let p6 = pkt6(proto::ICMPV6, 0x77, 0, b"ping-payload");
    let p4 = run_6to4(&p6, &Map4 { src: POOL4, dst: SERVER4, sport: 3000, dport: 0 }).unwrap();
    let (h, l4) = verify_v4(&p4);
    assert_eq!(h.proto, proto::ICMP);
    assert_eq!(l4, L4::Icmp { ty: 8, code: 0, id: 3000 });
    let back = run_4to6(&p4, &Map6 { src: SUB, dst: SUB, sport: 0, dport: 0x77 }).unwrap();
    let (_, l4) = verify_v6(&back);
    assert_eq!(l4, L4::Icmp { ty: 128, code: 0, id: 0x77 });
}

#[test]
fn small_packets_clear_df_large_set_df() {
    let m4 = Map4 { src: POOL4, dst: SERVER4, sport: 2048, dport: 53 };
    let p4 = run_6to4(&pkt6(proto::UDP, 1, 53, &[0; 100]), &m4).unwrap();
    assert_eq!(be16(&p4, 6) & 0x4000, 0, "DF clear when <= 1260");
    assert_eq!(be16(&p4, 4), 0x1234, "ident used when DF clear");
    let p4 = run_6to4(&pkt6(proto::UDP, 1, 53, &[0; 1300]), &m4).unwrap();
    assert_ne!(be16(&p4, 6) & 0x4000, 0, "DF set when > 1260");
}

#[test]
fn zero_udp_checksum_v4_is_computed_for_v6() {
    let m4 = Map4 { src: SERVER4, dst: POOL4, sport: 53, dport: 2048 };
    let mut p4 = run_6to4(&pkt6(proto::UDP, 53, 2048, b"dns"), &m4).unwrap();
    put16(&mut p4, 26, 0);
    let back = run_4to6(&p4, &Map6 { src: SUB, dst: SUB, sport: 53, dport: 4000 }).unwrap();
    let (_, l4) = verify_v6(&back);
    assert!(matches!(l4, L4::Udp { csum, .. } if csum != 0));
}

#[test]
fn zero_udp_checksum_v6_rejected() {
    let mut p6 = pkt6(proto::UDP, 1, 2, b"x");
    put16(&mut p6, 46, 0);
    let r = run_6to4(&p6, &Map4 { src: 1, dst: 2, sport: 3, dport: 4 });
    assert_eq!(r.unwrap_err(), XlatError::ZeroUdpChecksum);
}

#[test]
fn ipv4_options_are_dropped() {
    let m4 = Map4 { src: SERVER4, dst: POOL4, sport: 53, dport: 2048 };
    let p4 = run_6to4(&pkt6(proto::UDP, 53, 2048, b"opts"), &m4).unwrap();
    // Re-wrap with 4 bytes of NOP options (IHL=6).
    let mut o = vec![0u8; p4.len() + 4];
    o[..20].copy_from_slice(&p4[..20]);
    o[0] = 0x46;
    o[20..24].copy_from_slice(&[1, 1, 1, 0]);
    o[24..].copy_from_slice(&p4[20..]);
    let ol = o.len() as u16;
    put16(&mut o, 2, ol);
    put16(&mut o, 10, 0);
    let c = ck::finish(ck::sum(&o[..24]));
    put16(&mut o, 10, c);
    let back = run_4to6(&o, &Map6 { src: SUB, dst: SUB, sport: 53, dport: 4000 }).unwrap();
    let (h, _) = verify_v6(&back);
    assert_eq!(h.l4_off, 40);
}

#[test]
fn too_big_for_mtu() {
    let p6 = pkt6(proto::UDP, 1, 2, &[0; 1600]);
    let r = run_6to4(&p6, &Map4 { src: 1, dst: 2, sport: 3, dport: 4 });
    assert_eq!(r.unwrap_err(), XlatError::TooBig);
}

#[test]
fn packet_too_big_v6_to_frag_needed_v4() {
    // A v4-originated TCP segment (server -> subscriber) as seen on the v6 side.
    let inner = {
        let mut p = pkt6(proto::TCP, 443, 40000, &[0xaa; 64]);
        put128(&mut p, 8, pfx().embed(SERVER4));
        put128(&mut p, 24, SUB);
        p
    };
    let router6: u128 = 0x2001_0db8_ffff_0000_0000_0000_0000_0001;
    let icmp_len = 8 + inner.len();
    let mut e = vec![0u8; 40 + icmp_len];
    write_v6_header(&mut e, 0, icmp_len as u16, proto::ICMPV6, 64, router6, pfx().embed(SERVER4));
    e[40] = 2;
    put32(&mut e, 44, 1400);
    e[48..].copy_from_slice(&inner);
    let c = ck::finish(ck::pseudo_v6(router6, pfx().embed(SERVER4), 58, icmp_len as u32) + ck::sum(&e[40..]));
    put16(&mut e, 42, c);

    let h = parse_v6(&e).unwrap();
    let (ih, il4) = quoted_v6(&e, &h).unwrap();
    assert!(matches!(il4, L4::Tcp { sport: 443, dport: 40000, .. }));
    let mut out = [0u8; 1500];
    let inner_map = Map4 { src: SERVER4, dst: POOL4, sport: 443, dport: 2048 };
    let n = icmp6_err_to_v4(&e, &h, &ih, (0x0a00_0001, SERVER4), &inner_map, 7, 1500, 1500, &mut out).unwrap();
    let (oh, l4) = verify_v4(&out[..n]);
    assert_eq!(oh.dst, SERVER4);
    assert_eq!(l4, L4::Icmp { ty: 3, code: 4, id: 0 });
    assert_eq!(be16(&out, 26), 1380, "MTU adjusted by -20");
    let q = parse_v4(&out[28..n]);
    // Quoted header has original total length (may exceed what is quoted).
    assert!(q.is_err() || q.unwrap().src == SERVER4);
    assert_eq!(be16(&out, 48 + 2), 2048, "quoted dport mapped to pool port");
}

#[test]
fn frag_needed_v4_to_ptb_v6_with_plateau() {
    let m4 = Map4 { src: POOL4, dst: SERVER4, sport: 2048, dport: 443 };
    let inner4 = run_6to4(&pkt6(proto::TCP, 40000, 443, &[0; 1400]), &m4).unwrap();
    let quote = &inner4[..28];
    let icmp_len = 8 + quote.len();
    let mut e = vec![0u8; 20 + icmp_len];
    write_v4_header(&mut e, 0, (20 + icmp_len) as u16, 9, false, false, 0, 60, proto::ICMP, 0xcb00_7101, POOL4);
    e[20] = 3;
    e[21] = 4; // MTU field left 0: old router -> plateau
    e[28..].copy_from_slice(quote);
    let c = ck::finish(ck::sum(&e[20..]));
    put16(&mut e, 22, c);

    let h = parse_v4(&e).unwrap();
    let (ih, _) = quoted_v4(&e, &h).unwrap();
    let mut out = [0u8; 1500];
    let inner = Map6 { src: SUB, dst: pfx().embed(SERVER4), sport: 40000, dport: 443 };
    let n = icmp4_err_to_v6(&e, &h, &ih, (pfx().embed(0xcb00_7101), SUB), &inner, 1500, 1500, &mut out).unwrap();
    let (_, l4) = verify_v6(&out[..n]);
    assert_eq!(l4, L4::Icmp { ty: 2, code: 0, id: 0 });
    // Inner total 1440 -> plateau 1006 -> +20 = 1026 -> clamped to 1280.
    assert_eq!(plat_packet::be32(&out, 44), 1280);
}

#[test]
fn icmp_error_about_error_is_dropped() {
    let mut inner = pkt6(proto::ICMPV6, 0, 0, &[0; 8]);
    inner[40] = 1; // quoted dest-unreachable
    let mut e = vec![0u8; 48 + inner.len()];
    write_v6_header(&mut e, 0, (8 + inner.len()) as u16, proto::ICMPV6, 64, 1, 2);
    e[40] = 1;
    e[48..].copy_from_slice(&inner);
    let h = parse_v6(&e).unwrap();
    assert_eq!(quoted_v6(&e, &h).unwrap_err(), XlatError::Untranslatable);
}

proptest! {
    #[test]
    fn roundtrip_preserves_payload_and_checksums(
        payload in proptest::collection::vec(any::<u8>(), 0..1200),
        sport in 1u16.., dport in 1u16.., pport in 1024u16.., tcp in any::<bool>(),
    ) {
        let p = if tcp { proto::TCP } else { proto::UDP };
        let p6 = pkt6(p, sport, dport, &payload);
        let p4 = run_6to4(&p6, &Map4 { src: POOL4, dst: SERVER4, sport: pport, dport }).unwrap();
        let (_, l4) = verify_v4(&p4);
        let ok = matches!(l4, L4::Tcp { sport: s, .. } | L4::Udp { sport: s, .. } if s == pport);
        prop_assert!(ok);
        let back = run_4to6(&p4, &Map6 { src: SUB, dst: pfx().embed(SERVER4), sport, dport }).unwrap();
        let (_, _) = verify_v6(&back);
        prop_assert_eq!(&back[back.len() - payload.len()..], &payload[..]);
    }

    #[test]
    fn arbitrary_icmp_errors_never_panic(body in proptest::collection::vec(any::<u8>(), 0..300), ty in 0u8..20, code in 0u8..16) {
        let mut e = vec![0u8; 28 + body.len()];
        write_v4_header(&mut e, 0, (28 + body.len()) as u16, 0, false, false, 0, 9, proto::ICMP, 1, 2);
        e[20] = ty;
        e[21] = code;
        e[28..].copy_from_slice(&body);
        let h = parse_v4(&e).unwrap();
        if let Ok((ih, _)) = quoted_v4(&e, &h) {
            let mut out = [0u8; 1500];
            let _ = icmp4_err_to_v6(&e, &h, &ih, (1, 2), &Map6 { src: 3, dst: 4, sport: 5, dport: 6 }, 1500, 1500, &mut out);
        }
    }
}
