//! Hostile input (plan §11 "Malformed packets"): arbitrary bytes never
//! panic and are always declined; every header byte mutated, truncation at
//! every offset, trailing bytes and Ethernet padding, VLAN, multicast MACs,
//! IHL ≠ 5, version mismatch, `payload_len` 0 and too large, UDP length
//! mismatch, fragments and extension headers. Every case also runs the
//! safety check against the reference (`support::differential`): whatever
//! is still redirected must equal the slow path's output.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-10 (Information Input Validation) - malformed input
//!   is declined and counted, never a panic; SA-11 - property testing

mod support;

use plat_xdp_core::abi::PassReason;
use plat_xdp_core::{HDR4, HDR6, decide_frame, decide_v4, decide_v6};
use proptest::prelude::*;
use support::*;

const ETH6: [u8; 2] = [0x86, 0xdd];
const ETH4: [u8; 2] = [0x08, 0x00];

struct Fx {
    r: Reference,
    env: HostEnv,
    s: Session,
}

fn fx() -> Fx {
    let mut r = Reference::new(&Knobs::default());
    let mut env = HostEnv::new(&r.cfg, Net::default());
    let s = ok(establish(&mut r, &mut env, client(0x1_0000_0000_0007), 5353, server(0, 9), 4500));
    Fx { r, env, s }
}

impl Fx {
    fn out_l3(&self, payload: &[u8]) -> Vec<u8> {
        udp6(&U6::new(self.s.src6, self.s.sport, self.r.prefix.embed(self.s.dst4), self.s.dport), payload)
    }

    fn in_l3(&self, payload: &[u8]) -> Vec<u8> {
        udp4(&U4::new(self.s.dst4, self.s.dport, self.s.pool4, self.s.pool_port), payload)
    }

    fn out(&self, payload: &[u8]) -> Vec<u8> {
        eth(ACCESS_MAC, CLIENT_MAC, ETH6, &self.out_l3(payload))
    }

    fn inb(&self, payload: &[u8]) -> Vec<u8> {
        eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &self.in_l3(payload))
    }

    fn diff(&mut self, frame: &[u8], ingress: u32) -> Option<PassReason> {
        ok(differential(&mut self.r, &mut self.env, frame, ingress))
    }
}

fn config() -> ProptestConfig {
    ProptestConfig { cases: cases(), ..ProptestConfig::default() }
}

thread_local! {
    static FX: std::cell::RefCell<Option<Fx>> = const { std::cell::RefCell::new(None) };
}

/// The thread's fixture (one established session), rebuilt periodically.
fn with_fx<R>(f: impl FnOnce(&mut Fx) -> R) -> R {
    FX.with(|c| {
        let mut c = c.borrow_mut();
        if c.as_ref().is_none_or(|x| x.r.uses > FIXTURE_USES) {
            *c = Some(fx());
        }
        f(some(c.as_mut(), "fixture"))
    })
}

proptest! {
    #![proptest_config(config())]

    /// Arbitrary bytes on either interface: no panic, always declined.
    #[test]
    fn arbitrary_bytes_always_decline(
        bytes in proptest::collection::vec(any::<u8>(), 0..300),
        ingress in prop_oneof![Just(ACCESS_IF), Just(UPSTREAM_IF), any::<u32>()],
    ) {
        let reason = with_fx(|f| decide_frame(&mut f.env, ingress, &bytes).pass_reason());
        prop_assert!(reason.is_some());
    }

    /// Arbitrary bytes behind a valid Ethernet header for the interface and
    /// each Ethertype, so the IP checks are reached: always declined, and
    /// the safety check holds.
    #[test]
    fn arbitrary_ip_headers_always_decline(
        l3 in proptest::collection::vec(any::<u8>(), 0..200), v6 in any::<bool>(),
    ) {
        let res = with_fx(|f| {
            let (frame, ingress) = if v6 {
                (eth(ACCESS_MAC, CLIENT_MAC, ETH6, &l3), ACCESS_IF)
            } else {
                (eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &l3), UPSTREAM_IF)
            };
            differential(&mut f.r, &mut f.env, &frame, ingress)
        });
        prop_assert!(matches!(res, Ok(Some(_))), "{:?}", res);
    }

    /// The per-direction entry points with any header block and any
    /// claimed frame length (including lengths shorter than the block):
    /// no panic, and a redirect only for a block that is a valid packet of
    /// the installed session.
    #[test]
    fn header_blocks_with_any_frame_length_never_panic(
        b6 in proptest::collection::vec(any::<u8>(), HDR6), b4 in proptest::collection::vec(any::<u8>(), HDR4),
        len6 in any::<u32>(), len4 in any::<u32>(),
    ) {
        let (h6, h4): ([u8; HDR6], [u8; HDR4]) = (ok(b6.try_into()), ok(b4.try_into()));
        let (a, b) = with_fx(|f| {
            (decide_v6(&mut f.env, ACCESS_IF, &h6, len6), decide_v4(&mut f.env, UPSTREAM_IF, &h4, len4))
        });
        prop_assert!(matches!(a, plat_xdp_core::Verdict::Pass(_)));
        prop_assert!(matches!(b, plat_xdp_core::Verdict::Pass(_)));
    }
}

/// Every byte of the fixed header block XORed with every non-zero value:
/// the safety check holds for all of them, and the fields that select or
/// validate the session always decline.
#[test]
fn every_header_byte_mutated() {
    let mut f = fx();
    let out = f.out(b"0123456789abcdef");
    let inb = f.inb(b"0123456789abcdef");
    let mut redirected = [0u32; HDR6];
    for i in 0..HDR6 {
        for x in 1..=255u8 {
            let mut m = out.clone();
            m[i] ^= x;
            if f.diff(&m, ACCESS_IF).is_none() {
                redirected[i] += 1;
            }
        }
    }
    // Destination MAC, Ethertype, Payload Length, next header, addresses,
    // ports and UDP length: never redirected after any change.
    for i in (0..6).chain(12..14).chain(18..21).chain(22..60) {
        assert_eq!(redirected[i], 0, "v6 offset {i}");
    }
    // The version nibble: only changes confined to the traffic class's
    // high nibble (XOR < 16) still redirect.
    assert_eq!(redirected[14], 15);
    // Source MAC, traffic class / flow label: nothing the session depends
    // on; the hop limit declines only for the new values 0, 1 and 2.
    assert_eq!(redirected[6], 255);
    assert_eq!(redirected[15], 255);
    assert_eq!(redirected[21], 255 - 3);

    let mut redirected = [0u32; HDR4];
    for i in 0..HDR4 {
        for x in 1..=255u8 {
            let mut m = inb.clone();
            m[i] ^= x;
            if f.diff(&m, UPSTREAM_IF).is_none() {
                redirected[i] += 1;
            }
        }
    }
    // Any single-byte change of the IPv4 header breaks its checksum.
    for i in (0..6).chain(12..34).chain(34..40) {
        assert_eq!(redirected[i], 0, "v4 offset {i}");
    }
    assert_eq!(redirected[6], 255);
}

#[test]
fn truncation_at_every_offset_declines() {
    let mut f = fx();
    for (frame, ingress) in [(f.out(b"truncate me"), ACCESS_IF), (f.inb(b"truncate me"), UPSTREAM_IF)] {
        for n in 0..frame.len() {
            assert!(f.diff(&frame[..n], ingress).is_some(), "length {n} of {}", frame.len());
        }
        assert_eq!(f.diff(&frame, ingress), None);
    }
}

#[test]
fn trailing_bytes_are_trimmed() {
    let mut f = fx();
    for extra in [1usize, 2, 7, 8, 64, 400] {
        let pad = vec![0xeeu8; extra];
        let mut o = f.out(b"trailer");
        o.extend_from_slice(&pad);
        let mut i = f.inb(b"trailer");
        i.extend_from_slice(&pad);
        assert_eq!(f.diff(&o, ACCESS_IF), None, "v6 + {extra}");
        assert_eq!(f.diff(&i, UPSTREAM_IF), None, "v4 + {extra}");
    }
}

#[test]
fn ethernet_padding_to_60_bytes_is_trimmed() {
    let mut f = fx();
    for n in 0..=18usize {
        let mut i = f.inb(&vec![0x42; n]);
        assert!(i.len() <= 60);
        i.resize(60, 0);
        assert_eq!(f.diff(&i, UPSTREAM_IF), None, "payload {n} padded to 60");
    }
}

#[test]
fn vlan_tagged_frames_are_not_ip() {
    let mut f = fx();
    for (frame, ingress) in [(f.out(b"vlan"), ACCESS_IF), (f.inb(b"vlan"), UPSTREAM_IF)] {
        for tpid in [[0x81, 0x00], [0x88, 0xa8]] {
            let mut v = frame[..12].to_vec();
            v.extend_from_slice(&tpid);
            v.extend_from_slice(&[0x00, 0x05]);
            v.extend_from_slice(&frame[12..]);
            assert_eq!(f.diff(&v, ingress), Some(PassReason::NotIp));
        }
    }
}

#[test]
fn multicast_and_broadcast_macs_are_not_for_us() {
    let mut f = fx();
    for mac in [[0xff; 6], [0x33, 0x33, 0xff, 0, 0, 1], [0x01, 0x00, 0x5e, 0x7f, 0, 1]] {
        let mut o = f.out(b"m");
        o[..6].copy_from_slice(&mac);
        let mut i = f.inb(b"m");
        i[..6].copy_from_slice(&mac);
        assert_eq!(f.diff(&o, ACCESS_IF), Some(PassReason::NotForUs));
        assert_eq!(f.diff(&i, UPSTREAM_IF), Some(PassReason::NotForUs));
    }
}

#[test]
fn ihl_other_than_5() {
    let mut f = fx();
    let base = f.in_l3(b"options");
    // IHL 6 with a valid NOP option word and checksum: the engine strips
    // options (RFC 7915 §4.1), the fast path leaves them to it.
    let mut l3 = base[..20].to_vec();
    l3.extend_from_slice(&[1, 1, 1, 0]);
    l3.extend_from_slice(&base[20..]);
    l3[0] = 0x46;
    let total = (l3.len() as u16).to_be_bytes();
    l3[2..4].copy_from_slice(&total);
    fix_v4_csum(&mut l3);
    let frame = eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &l3);
    let net = f.env.net;
    assert!(matches!(f.r.wire(&frame, UPSTREAM_IF, &net), RefOut::Frame(_)));
    assert_eq!(f.diff(&frame, UPSTREAM_IF), Some(PassReason::Ipv4Options));
    for ihl in [0u8, 1, 4, 7, 15] {
        let mut l3 = base.clone();
        l3[0] = 0x40 | ihl;
        fix_v4_csum(&mut l3);
        let want = if ihl < 5 { PassReason::BadL3 } else { PassReason::Ipv4Options };
        assert_eq!(f.diff(&eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &l3), UPSTREAM_IF), Some(want), "ihl {ihl}");
    }
}

#[test]
fn version_mismatch_is_malformed() {
    let mut f = fx();
    for v in [0u8, 4, 5, 7, 15] {
        let mut o = f.out(b"v");
        o[14] = (o[14] & 0x0f) | (v << 4);
        assert_eq!(f.diff(&o, ACCESS_IF), Some(PassReason::BadL3), "v6 frame, version {v}");
    }
    for v in [0u8, 5, 6, 15] {
        let mut l3 = f.in_l3(b"v");
        l3[0] = (v << 4) | 5;
        fix_v4_csum(&mut l3);
        assert_eq!(f.diff(&eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &l3), UPSTREAM_IF), Some(PassReason::BadL3));
    }
    // The other family's Ethertype.
    let mut o = f.out(b"v");
    o[12..14].copy_from_slice(&ETH4);
    assert_eq!(f.diff(&o, ACCESS_IF), Some(PassReason::Role));
}

#[test]
fn ipv6_payload_length_zero_too_large_or_short() {
    let mut f = fx();
    let o = f.out(b"plen");
    let plen = u16::from_be_bytes([o[18], o[19]]);
    for bad in [0u16, 1, 7, plen + 1, plen + 100, u16::MAX] {
        let mut m = o.clone();
        m[18..20].copy_from_slice(&bad.to_be_bytes());
        assert_eq!(f.diff(&m, ACCESS_IF), Some(PassReason::BadL3), "payload_len {bad}");
    }
    // Shorter than the UDP datagram: what is left is not one datagram.
    let mut m = o.clone();
    m[18..20].copy_from_slice(&(plen - 1).to_be_bytes());
    assert_eq!(f.diff(&m, ACCESS_IF), Some(PassReason::UdpLen));
}

#[test]
fn ipv4_total_length_wrong() {
    let mut f = fx();
    let base = f.in_l3(b"total");
    for bad in [0u16, 19, 20, 27, base.len() as u16 + 1, u16::MAX] {
        let mut l3 = base.clone();
        l3[2..4].copy_from_slice(&bad.to_be_bytes());
        fix_v4_csum(&mut l3);
        assert_eq!(f.diff(&eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &l3), UPSTREAM_IF), Some(PassReason::BadL3));
    }
}

#[test]
fn udp_length_mismatch() {
    let mut f = fx();
    for ulen in [0u16, 7, 8, 12, 999, u16::MAX] {
        let mut o = f.out(b"udp length");
        if u16::from_be_bytes([o[58], o[59]]) == ulen {
            continue;
        }
        o[58..60].copy_from_slice(&ulen.to_be_bytes());
        assert_eq!(f.diff(&o, ACCESS_IF), Some(PassReason::UdpLen), "v6 udp len {ulen}");
        let mut i = f.inb(b"udp length");
        i[38..40].copy_from_slice(&ulen.to_be_bytes());
        assert_eq!(f.diff(&i, UPSTREAM_IF), Some(PassReason::UdpLen), "v4 udp len {ulen}");
    }
}

#[test]
fn fragments_extension_headers_and_other_protocols() {
    let mut f = fx();
    for (ff, want) in
        [(0x2000u16, PassReason::Fragment), (0x0001, PassReason::Fragment), (0x6000, PassReason::Fragment)]
    {
        let mut l3 = f.in_l3(b"frag");
        l3[6..8].copy_from_slice(&ff.to_be_bytes());
        fix_v4_csum(&mut l3);
        assert_eq!(f.diff(&eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &l3), UPSTREAM_IF), Some(want), "flags {ff:#x}");
    }
    // The reserved flag bit alone is ignored (as by the kernel and the
    // engine): still forwarded identically.
    let mut l3 = f.in_l3(b"evil");
    l3[6] |= 0x80;
    fix_v4_csum(&mut l3);
    assert_eq!(f.diff(&eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &l3), UPSTREAM_IF), None);
    for p in [1u8, 6, 58, 0, 255] {
        let mut l3 = f.in_l3(b"proto");
        l3[9] = p;
        fix_v4_csum(&mut l3);
        assert_eq!(f.diff(&eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &l3), UPSTREAM_IF), Some(PassReason::NotUdp));
    }
    for (nh, want) in [
        (0u8, PassReason::ExtHeader),
        (43, PassReason::ExtHeader),
        (44, PassReason::ExtHeader),
        (60, PassReason::ExtHeader),
        (50, PassReason::ExtHeader),
        (6, PassReason::NotUdp),
        (58, PassReason::NotUdp),
        (59, PassReason::NotUdp),
    ] {
        let mut o = f.out(b"next header");
        o[20] = nh;
        assert_eq!(f.diff(&o, ACCESS_IF), Some(want), "next header {nh}");
    }
}

#[test]
fn short_frames() {
    let mut f = fx();
    let o = f.out(b"");
    for n in 0..14 {
        assert_eq!(decide_frame(&mut f.env, ACCESS_IF, &o[..n]).pass_reason(), Some(PassReason::NotIp));
    }
    for n in 14..HDR6 {
        assert_eq!(decide_frame(&mut f.env, ACCESS_IF, &o[..n]).pass_reason(), Some(PassReason::BadL3));
    }
    let i = f.inb(b"");
    for n in 14..HDR4 {
        assert_eq!(decide_frame(&mut f.env, UPSTREAM_IF, &i[..n]).pass_reason(), Some(PassReason::BadL3));
    }
}
