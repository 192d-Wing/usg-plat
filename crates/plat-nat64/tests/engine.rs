#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use plat_audit::{Event, LimitKind};
use plat_common::{Counters, DropReason};
use plat_nat64::WorkerCtx;
use plat_packet::{L4, be16, be32, be128, checksum as ck, parse_l4, parse_v4, parse_v6, proto};

const SERVER: u32 = 0xc633_6407; // 198.51.100.7
const OTHER: u32 = 0xcb00_7105; // 203.0.113.5

fn v4_tuple(p: &[u8]) -> (u32, u16, u32, u16) {
    let h = parse_v4(p).unwrap();
    assert_eq!(ck::fold(ck::sum(&p[..h.hdr_len])), 0xffff);
    (h.src, be16(p, h.hdr_len), h.dst, be16(p, h.hdr_len + 2))
}

fn v6_ok(p: &[u8]) -> plat_packet::Ipv6Hdr {
    let h = parse_v6(p).unwrap();
    let l4 = &p[h.l4_off..];
    assert_eq!(ck::fold(ck::pseudo_v6(h.src, h.dst, h.proto, l4.len() as u32) + ck::sum(l4)), 0xffff, "v6 checksum");
    h
}

#[test]
fn udp_mapping_reply_and_block_log() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let out = run(&mut fx, &udp6(s, 5353, SERVER, 53, b"query")).unwrap();
    let (src4, sport4, dst4, dport) = v4_tuple(&out);
    assert_eq!((dst4, dport), (SERVER, 53));
    assert!((POOL_BASE..POOL_BASE + 4).contains(&src4));
    assert!(sport4 >= 1024);

    // Endpoint-independent mapping: same source to another server reuses it.
    let out2 = run(&mut fx, &udp6(s, 5353, OTHER, 53, b"q2")).unwrap();
    assert_eq!(v4_tuple(&out2).0..=v4_tuple(&out2).0, src4..=src4);
    assert_eq!(v4_tuple(&out2).1, sport4);

    // Reply.
    let back = run(&mut fx, &udp4(SERVER, 53, src4, sport4, b"answer")).unwrap();
    let h = v6_ok(&back);
    assert_eq!((h.src, h.dst), (synth(SERVER), s));
    assert!(matches!(parse_l4(&back, 40, back.len(), proto::UDP).unwrap(), L4::Udp { sport: 53, dport: 5353, .. }));
    assert_eq!(&back[back.len() - 6..], b"answer");

    let evs = events(&fx);
    let blocks: Vec<_> = evs.iter().filter(|e| matches!(e, Event::PortBlockAlloc { .. })).collect();
    assert_eq!(blocks.len(), 1, "one block, logged once: {evs:?}");
    if let Event::PortBlockAlloc { sub: sp, sub_len, v4, port_lo, port_hi, .. } = *blocks[0] {
        assert_eq!((sp, sub_len, v4), (s & !0xffff_ffff_ffff_ffff, 64, src4));
        assert!((port_lo..=port_hi).contains(&sport4));
    }
}

#[test]
fn address_dependent_filtering() {
    let mut fx = fixture(&[]);
    let out = run(&mut fx, &udp6(sub(1, 1), 1000, SERVER, 53, b"x")).unwrap();
    let (src4, sport4, ..) = v4_tuple(&out);
    assert_eq!(run(&mut fx, &udp4(OTHER, 53, src4, sport4, b"spoof")).unwrap_err(), DropReason::Filtered);
    // Same address, different port: allowed under ADF.
    assert!(run(&mut fx, &udp4(SERVER, 5000, src4, sport4, b"ok")).is_ok());
    // Unknown pool port.
    assert_eq!(run(&mut fx, &udp4(SERVER, 53, src4, 9, b"x")).unwrap_err(), DropReason::NoBinding);
    // Not our address.
    assert_eq!(run(&mut fx, &udp4(SERVER, 53, 0x0808_0808, 9, b"x")).unwrap_err(), DropReason::NoBinding);
}

#[test]
fn endpoint_independent_filtering_option() {
    let mut fx = fixture(&[("filtering = \"address_dependent\"", "filtering = \"endpoint_independent\"")]);
    let out = run(&mut fx, &udp6(sub(1, 1), 1000, SERVER, 53, b"x")).unwrap();
    let (src4, sport4, ..) = v4_tuple(&out);
    assert!(run(&mut fx, &udp4(OTHER, 53, src4, sport4, b"ok")).is_ok());
}

#[test]
fn tcp_requires_syn() {
    let mut fx = fixture(&[]);
    assert_eq!(run(&mut fx, &tcp6(sub(1, 1), 40000, SERVER, 443, 0x10)).unwrap_err(), DropReason::TcpNoState);
    let out = run(&mut fx, &tcp6(sub(1, 1), 40000, SERVER, 443, 0x02)).unwrap();
    let (src4, sport4, ..) = v4_tuple(&out);
    let back = run(&mut fx, &tcp4(SERVER, 443, src4, sport4, 0x12)).unwrap();
    v6_ok(&back);
    // An unsolicited inbound SYN from another host is held for simultaneous
    // open (RFC 6146 §3.5.2.2): consumed, never forwarded.
    assert!(run_all(&mut fx, &tcp4(OTHER, 443, src4, sport4, 0x02)).unwrap().is_empty());
    // Anything else from it is filtered.
    assert_eq!(run(&mut fx, &tcp4(OTHER, 443, src4, sport4, 0x10)).unwrap_err(), DropReason::Filtered);
    // With simultaneous open off, the SYN is filtered as before.
    let mut fx = fixture(&[("tcp_simultaneous_open = true", "tcp_simultaneous_open = false")]);
    let out = run(&mut fx, &tcp6(sub(1, 1), 40000, SERVER, 443, 0x02)).unwrap();
    let (src4, sport4, ..) = v4_tuple(&out);
    assert_eq!(run(&mut fx, &tcp4(OTHER, 443, src4, sport4, 0x02)).unwrap_err(), DropReason::Filtered);
}

#[test]
fn icmp_echo_roundtrip() {
    let mut fx = fixture(&[]);
    let s = sub(2, 9);
    let out = run(&mut fx, &echo6(s, 0x4242, SERVER)).unwrap();
    let h = parse_v4(&out).unwrap();
    let L4::Icmp { ty: 8, id, .. } = parse_l4(&out, 20, out.len(), proto::ICMP).unwrap() else { panic!() };
    // Echo reply from server.
    let mut rep = out.clone();
    rep[12..16].copy_from_slice(&SERVER.to_be_bytes());
    rep[16..20].copy_from_slice(&h.src.to_be_bytes());
    plat_xlat::siit::write_v4_header(&mut rep, 0, out.len() as u16, 0, false, false, 0, 64, proto::ICMP, SERVER, h.src);
    rep[20] = 0;
    l4_sum4(&mut rep, proto::ICMP, 2);
    let back = run(&mut fx, &rep).unwrap();
    v6_ok(&back);
    assert_eq!(back[40], 129);
    assert_eq!(be16(&back, 44), 0x4242, "identifier mapped back (pool id {id})");
}

#[test]
fn source_and_destination_policy() {
    let mut fx = fixture(&[]);
    let outsider = 0x2001_0db8_ffff_0000_0000_0000_0000_0001u128;
    assert_eq!(run(&mut fx, &udp6(outsider, 1, SERVER, 53, b"x")).unwrap_err(), DropReason::SrcNotAllowed);
    // With the explicit `allow_non_global_destinations` opt-in (the fixture
    // default), a network-specific prefix may reach private space; the
    // default policy is in `hardening.rs::non_global_destinations_are_denied_by_default`.
    // Never-translatable space is always refused.
    assert!(run(&mut fx, &udp6(sub(1, 1), 1, 0x0a00_0001, 53, b"x")).is_ok());
    let mut strict = fixture_strict(&[]);
    assert_eq!(run(&mut strict, &udp6(sub(1, 1), 1, 0x0a00_0001, 53, b"x")).unwrap_err(), DropReason::DstForbidden);
    for dst in [0x7f00_0001u32, 0x0000_0001, 0xa9fe_a9fe, 0xe000_0001, 0xffff_ffff] {
        assert_eq!(run(&mut fx, &udp6(sub(1, 1), 1, dst, 53, b"x")).unwrap_err(), DropReason::DstForbidden);
    }
    let mut not_prefix = udp6(sub(1, 1), 1, SERVER, 53, b"x");
    not_prefix[24] = 0x20;
    assert_eq!(run(&mut fx, &not_prefix).unwrap_err(), DropReason::DstNotTranslatable);
    assert_eq!(run(&mut fx, &[0x45, 0, 0]).unwrap_err(), DropReason::Malformed);
    assert_eq!(run(&mut fx, &[]).unwrap_err(), DropReason::Malformed);
}

#[test]
fn per_subscriber_port_limit_and_paired_pooling() {
    let mut fx = fixture(&[
        ("port_block_size = 512", "port_block_size = 64"),
        ("max_blocks_per_subscriber = 4", "max_blocks_per_subscriber = 2"),
    ]);
    let s = sub(3, 1);
    let mut addrs = std::collections::HashSet::new();
    for port in 0..128u16 {
        let out = run(&mut fx, &udp6(s, 10_000 + port, SERVER, 53, b"x")).unwrap();
        addrs.insert(v4_tuple(&out).0);
    }
    assert_eq!(addrs.len(), 1, "paired pooling keeps one IPv4 address");
    // Limit reached: ICMPv6 Destination Unreachable / Address Unreachable
    // back to the subscriber (RFC 6146 §3.5.1.1, POAM-002), still counted
    // as a subscriber_limit drop.
    let e = run(&mut fx, &udp6(s, 20_000, SERVER, 53, b"x")).unwrap();
    assert_eq!((e[0] >> 4, e[6], e[40], e[41]), (6, proto::ICMPV6, 1, 3));
    assert_eq!(plat_packet::be128(&e, 24), s);
    // TCP has its own port space within the same blocks.
    assert!(run(&mut fx, &tcp6(s, 20_000, SERVER, 443, 0x02)).is_ok());
    // A different host in the same /64 is the same subscriber.
    let e = run(&mut fx, &udp6(sub(3, 2), 1, SERVER, 53, b"x")).unwrap();
    assert_eq!((e[40], e[41]), (1, 3));
    assert_eq!(fx.ctx.counters.drops(DropReason::SubscriberLimit), 2);
    assert_eq!(fx.ctx.counters.get(plat_common::Counter::IcmpUnreachableSent), 2);
    let evs = events(&fx);
    assert_eq!(evs.iter().filter(|e| matches!(e, Event::PortBlockAlloc { .. })).count(), 2);
    assert!(evs.iter().any(|e| matches!(e, Event::Limit { kind: LimitKind::SubscriberBlocks, .. })));
}

#[test]
fn expiry_releases_bib_and_block() {
    let mut fx = fixture(&[]);
    let out = run(&mut fx, &udp6(sub(1, 1), 7, SERVER, 53, b"x")).unwrap();
    let (src4, sport4, ..) = v4_tuple(&out);
    assert_eq!(fx.nat.state().session_count(), 1);
    fx.clock.advance(Duration::from_secs(301));
    let st = fx.nat.state().sweep();
    assert_eq!(st.sessions_expired, 1);
    assert_eq!(run(&mut fx, &udp4(SERVER, 53, src4, sport4, b"late")).unwrap_err(), DropReason::Filtered);
    fx.clock.advance(Duration::from_secs(3));
    assert_eq!(fx.nat.state().sweep().bibs_removed, 1);
    assert_eq!(run(&mut fx, &udp4(SERVER, 53, src4, sport4, b"late")).unwrap_err(), DropReason::NoBinding);
    fx.clock.advance(Duration::from_secs(61));
    assert_eq!(fx.nat.state().sweep().blocks_released, 1);
    let evs = events(&fx);
    assert!(evs.iter().any(|e| matches!(e, Event::PortBlockRelease { v4, .. } if *v4 == src4)));
    // POAM-010: the released block cools down before it is free again.
    let total = fx.nat.state().pool.total_blocks();
    assert_eq!(fx.nat.state().pool.free_blocks(), total - 1);
    fx.clock.advance(Duration::from_secs(120));
    fx.nat.state().sweep();
    assert_eq!(fx.nat.state().pool.free_blocks(), total);
}

#[test]
fn session_mode_logs_bindings() {
    let mut fx = fixture(&[("mode = \"port_block\"", "mode = \"session\"")]);
    run(&mut fx, &tcp6(sub(1, 1), 5555, SERVER, 443, 0x02)).unwrap();
    let evs = events(&fx);
    assert!(evs.iter().any(|e| matches!(e, Event::BibCreate { proto: 6, v6_port: 5555, .. })));
}

#[test]
fn refuse_new_bindings_when_audit_full() {
    let mut fx = fixture_q(&[], 1);
    assert!(run(&mut fx, &udp6(sub(1, 1), 1, SERVER, 53, b"x")).is_ok()); // block record fills the queue
    // Existing subscriber's block still has ports, but a new BIB requires room.
    assert_eq!(run(&mut fx, &udp6(sub(1, 1), 2, SERVER, 53, b"x")).unwrap_err(), DropReason::AuditUnavailable);
    // Established mapping keeps working (no new attribution needed).
    assert!(run(&mut fx, &udp6(sub(1, 1), 1, OTHER, 53, b"x")).is_ok());
    let _ = events(&fx);
    assert!(run(&mut fx, &udp6(sub(1, 1), 2, SERVER, 53, b"x")).is_ok());
}

#[test]
fn hairpinning() {
    let mut fx = fixture(&[("filtering = \"address_dependent\"", "filtering = \"endpoint_independent\"")]);
    let (a, b) = (sub(1, 1), sub(2, 1));
    let out = run(&mut fx, &udp6(b, 6000, SERVER, 53, b"x")).unwrap();
    let (b4, b_port, ..) = v4_tuple(&out);
    // A sends to B's public transport address via the NAT64 prefix.
    let back = run(&mut fx, &udp6(a, 7000, b4, b_port, b"hi B")).unwrap();
    let h = v6_ok(&back);
    assert_eq!(h.dst, b);
    assert_eq!(be16(&back, 42), 6000);
    let a4 = fx.nat.state().lookup6(plat_nat64::state::Key6 { proto: 17, addr: a, port: 7000 }).unwrap();
    assert_eq!(h.src, synth(a4.addr));
    assert_eq!(be16(&back, 40), a4.port);
}

#[test]
fn icmp_frag_needed_reaches_subscriber() {
    let mut fx = fixture(&[]);
    let s = sub(1, 1);
    let out = run(&mut fx, &tcp6(s, 40000, SERVER, 443, 0x02)).unwrap();
    let router = 0xcb00_7101;
    let err = icmp4_err(router, 3, 4, 1400, &out);
    let v6 = run(&mut fx, &err).unwrap();
    let h = v6_ok(&v6);
    assert_eq!((h.src, h.dst, v6[40]), (synth(router), s, 2));
    assert_eq!(be32(&v6, 44), 1420);
    // Quoted packet is the original IPv6 view.
    assert_eq!(be128(&v6, 48 + 8), s);
    assert_eq!(be16(&v6, 88), 40000);
}

#[test]
fn concurrent_workers_never_share_a_port() {
    let fx = fixture(&[("max_sessions_per_subscriber = 4000", "max_sessions_per_subscriber = 100000")]);
    let nat = Arc::new(fx.nat);
    let rx = fx.rx;
    let threads: Vec<_> = (0..8u16)
        .map(|t| {
            let nat = nat.clone();
            std::thread::spawn(move || {
                let mut ctx = WorkerCtx::new(Arc::new(Counters::default()), t);
                let mut seen = Vec::new();
                for i in 0..400u16 {
                    // 50 subscribers, contended across threads.
                    let p = udp6(sub(i % 50, 1), 1024 + t * 1000 + i, SERVER, 53, b"x");
                    let mut buf = vec![0u8; 2048];
                    buf[64..64 + p.len()].copy_from_slice(&p);
                    if let plat_nat64::Verdict::Forward { start, len } = nat.process(&mut buf, 64, p.len(), &mut ctx) {
                        let o = &buf[start..start + len];
                        seen.push((be32(o, 12), be16(o, 20)));
                    }
                }
                seen
            })
        })
        .collect();
    let mut all = Vec::new();
    for t in threads {
        all.extend(t.join().unwrap());
    }
    let n = all.len();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), n, "every flow got a unique (addr, port)");
    assert_eq!(n, 3200);
    assert_eq!(nat.state().bib6.len(), 3200);
    drop(rx);
}

/// RFC 6052 §3.1 with the Well-Known Prefix: no non-global IPv4 destination
/// (RFC 6890 Global = False), and documentation ranges are non-global.
#[test]
fn wkp_refuses_every_non_global_destination() {
    let mut fx = fixture(&[USE_WKP, WKP_POOL]);
    let s = sub(1, 1);
    let wkp = |v4: u32| WKP | u128::from(v4);
    let mk = |dst4: u32| {
        let mut p = udp6(s, 1, dst4, 53, b"x");
        p[24..40].copy_from_slice(&wkp(dst4).to_be_bytes());
        l4_sum6(&mut p, s, wkp(dst4), proto::UDP, 6);
        p
    };
    for dst in [
        0x0a00_0001u32, // 10/8
        0x6440_0001,    // 100.64/10
        0xac10_0001,    // 172.16/12
        0xc000_0001,    // 192.0.0/24
        0xc000_0201,    // 192.0.2/24
        0xc0a8_0001,    // 192.168/16
        0xc612_0001,    // 198.18/15
        0xc633_6407,    // 198.51.100/24
        0xcb00_7105,    // 203.0.113/24
        0x7f00_0001,
        0xffff_ffff,
    ] {
        assert_eq!(run(&mut fx, &mk(dst)).unwrap_err(), DropReason::DstForbidden, "{dst:08x}");
    }
    // Global, including the 192.0.0.9/.10 anycast exceptions.
    for dst in [0x0808_0808u32, 0xc000_0009, 0xc000_000a] {
        let out = run(&mut fx, &mk(dst)).unwrap_or_else(|e| panic!("{dst:08x}: {e:?}"));
        assert_eq!(v4_tuple(&out).2, dst);
    }
}
