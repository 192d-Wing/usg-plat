//! Map ABI: byte images match the `#[repr(C)]` layouts (whose size and
//! offset asserts are compile-time), word views, counter indices and pass
//! reason names (plan §4.1, §4.7), and the RFC 7739 ident step against
//! `plat_nat64::ident`'s `u128` arithmetic.

mod support;

use std::mem::size_of;

use plat_xdp_core::abi::*;
use plat_xdp_core::ident::{self, IdentKey};
use proptest::prelude::*;
use support::{cases, ok};

fn config() -> ProptestConfig {
    ProptestConfig { cases: cases().min(10_000), ..ProptestConfig::default() }
}

#[test]
fn sizes() {
    assert_eq!(size_of::<Key6>(), 40);
    assert_eq!(size_of::<Key4>(), 12);
    assert_eq!(size_of::<SlotRec>(), 64);
    assert_eq!(size_of::<Control>(), 24);
    assert_eq!(size_of::<SliceEnt>(), 8);
    assert_eq!(size_of::<ConfigRec>(), 40);
    assert_eq!(size_of::<IfaceEnt>(), 12);
    assert_eq!(size_of::<EgressEnt>(), 8);
    assert_eq!(size_of::<FibParams>(), 64);
    assert_eq!(size_of::<IdentEnt>(), 16);
    assert_eq!(size_of::<IdentKey>(), 16);
}

/// PERF-001 host guard: the verdict carries no header block, so returning
/// it through `Result` and `Action` copies a few words, not 42–62 bytes.
/// (The eBPF stack itself is measured from the verifier log in WU2/WU3.)
#[test]
fn verdict_is_small() {
    use plat_xdp_core::{Action, Verdict};
    assert!(size_of::<Verdict>() <= 32, "Verdict is {} bytes", size_of::<Verdict>());
    assert!(size_of::<Action>() <= 40, "Action is {} bytes", size_of::<Action>());
}

#[test]
fn pass_reasons_are_stable() {
    // Plan §4.7, in index order.
    let names = [
        "not_ip",
        "not_for_us",
        "role",
        "bad_l3",
        "ipv4_options",
        "fragment",
        "ext_header",
        "not_udp",
        "udp_len",
        "udp_zero_csum",
        "hop_limit",
        "disabled",
        "deadline",
        "no_session",
        "slot_dead",
        "slice_inactive",
        "too_big",
        "fib_fwd_disabled",
        "fib_no_neigh",
        "fib_frag_needed",
        "fib_other",
        "egress_not_allowed",
        "headroom",
    ];
    assert_eq!(PassReason::ALL.len(), names.len());
    for (i, (r, n)) in PassReason::ALL.iter().zip(names).enumerate() {
        assert_eq!(*r as usize, i);
        assert_eq!(r.as_str(), n);
        assert_eq!(r.stat_idx(), STAT_PASS_BASE + i as u32);
        assert!(r.stat_idx() < STATS_LEN);
    }
    for (i, s) in StatIdx::ALL.iter().enumerate() {
        assert_eq!(*s as usize, i);
        assert!((*s as u32) < STAT_PASS_BASE);
    }
    let stat_names: Vec<_> = StatIdx::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(stat_names, ["packets_v6_to_v4", "packets_v4_to_v6", "bytes_v6_to_v4", "bytes_v4_to_v6", "aborted"]);
}

#[test]
fn ident_key_debug_is_redacted() {
    let k = IdentKey::new(0x1111_2222_3333_4444, 0x5555_6666_7777_8888);
    assert_eq!(format!("{k:?}"), "IdentKey(<redacted>)");
    let b = k.to_bytes();
    assert_eq!(u64::from_ne_bytes(ok(b[8..].try_into())) & 1, 1, "k1 forced odd");
    assert_eq!(IdentKey::from_bytes(&b), k);
    assert_eq!(IdentKey::from_bytes(&[0; 16]), IdentKey::new(0, 0));
}

/// `plat_nat64::ident::IdentKey::mix` on `u128` (its fields are private,
/// so the formula is restated here).
fn mix_u128(k0: u64, k1: u64, src: u128, dst: u32, proto: u8) -> u64 {
    let x = (src as u64) ^ ((src >> 64) as u64).rotate_left(29) ^ ((u64::from(dst) << 8) | u64::from(proto));
    let m = (x ^ k0).wrapping_mul(k1);
    (m ^ (m >> 29)).wrapping_mul(k1)
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn slot_record_bytes_and_words(
        state in any::<u8>(), slice in any::<u16>(), generation in any::<u32>(), seen in any::<u64>(),
        src6 in any::<[u8; 16]>(), dst6 in any::<[u8; 16]>(), p in any::<[u8; 6]>(),
        pool4 in any::<[u8; 4]>(), dst4 in any::<[u8; 4]>(),
    ) {
        let r = SlotRec {
            state, slice, generation, seen_ns: seen, src6, dst6,
            sport6: [p[0], p[1]], dport: [p[2], p[3]], pool_port4: [p[4], p[5]], pool4, dst4,
            ..SlotRec::default()
        };
        let b = r.to_bytes();
        prop_assert_eq!(SlotRec::from_bytes(&b), r);
        prop_assert_eq!(b[0], state);
        prop_assert_eq!(&b[2..4], &slice.to_ne_bytes());
        prop_assert_eq!(&b[4..8], &generation.to_ne_bytes());
        prop_assert_eq!(&b[8..16], &seen.to_ne_bytes());
        prop_assert_eq!(&b[16..32], &src6);
        prop_assert_eq!(&b[32..48], &dst6);
        prop_assert_eq!(&b[48..54], &p);
        prop_assert_eq!(&b[56..60], &pool4);
        prop_assert_eq!(&b[60..64], &dst4);
        let w = r.to_words();
        prop_assert_eq!(w[SLOT_WORD_HDR], SlotRec::hdr_word(state, slice, generation));
        prop_assert_eq!(w[SLOT_WORD_SEEN], seen);
    }

    #[test]
    fn other_records_round_trip(
        a in any::<[u8; 16]>(), b in any::<[u8; 16]>(), p in any::<[u8; 4]>(), n in any::<u32>(), d in any::<u64>(),
        digest in any::<[u8; 32]>(), m in any::<u16>(), x in any::<u8>(),
    ) {
        let k6 = Key6::new(a, b, [p[0], p[1]], [p[2], p[3]]);
        let kb = k6.to_bytes();
        prop_assert_eq!(Key6::from_bytes(&kb), k6);
        prop_assert_eq!(&kb[..16], &a);
        prop_assert_eq!(&kb[36..], &[0u8; 4]);
        let k4 = Key4::new([a[0], a[1], a[2], a[3]], [b[0], b[1], b[2], b[3]], [p[0], p[1]], [p[2], p[3]]);
        prop_assert_eq!(Key4::from_bytes(&k4.to_bytes()), k4);
        let c = Control { enabled: n, tun_ifindex: n.rotate_left(7), deadline_ns: d, tun_mtu: n ^ 5, pad: 0 };
        let cb = c.to_bytes();
        prop_assert_eq!(Control::from_bytes(&cb), c);
        prop_assert_eq!(&cb[8..16], &d.to_ne_bytes());
        let s = SliceEnt { state: x, pad: [0; 3], generation: n };
        prop_assert_eq!(SliceEnt::from_bytes(&s.to_bytes()), s);
        prop_assert_eq!(u64::from_ne_bytes(s.to_bytes()), SliceEnt::word(x, n));
        let cfg = ConfigRec { mtu4: m, mtu6: m ^ 1, frag6: m ^ 2, copy_tos: x & 1, sliced: x >> 7, digest };
        prop_assert_eq!(ConfigRec::from_bytes(&cfg.to_bytes()), cfg);
        prop_assert_eq!(cfg.xlat().copy_tos, x & 1 == 1);
        let i = IfaceEnt { ifindex: n, mac: [a[0], a[1], a[2], a[3], a[4], a[5]], role: x, pad: 0 };
        prop_assert_eq!(IfaceEnt::from_bytes(&i.to_bytes()), i);
        let e = EgressEnt { ifindex: n, allowed: x, role: x.rotate_left(3), pad: [0; 2] };
        prop_assert_eq!(EgressEnt::from_bytes(&e.to_bytes()), e);
    }

    #[test]
    fn ident_matches_the_engine_scheme(
        k0 in any::<u64>(), k1 in any::<u64>(), src in any::<u128>(), dst in any::<u32>(), rng in 1..u64::MAX,
        counter in any::<u16>(),
    ) {
        let k = IdentKey::new(k0, k1);
        let m = k.mix(&src.to_be_bytes(), &dst.to_be_bytes(), 17);
        prop_assert_eq!(m, mix_u128(k0, k1 | 1, src, dst, 17));
        prop_assert!(ident::index(m) < ident::TABLE);
        prop_assert_eq!(ident::index(m) as usize, (m as usize) & (ident::TABLE as usize - 1));
        let r = ident::xorshift(rng);
        prop_assert_ne!(r, 0);
        let step = ident::step(r);
        prop_assert!((1..=ident::MAX_STEP).contains(&step));
        prop_assert_eq!(step, 1 + (r >> 61) as u16);
        let (c, id) = ident::advance(counter, step, m);
        prop_assert_eq!(c, counter.wrapping_add(step));
        prop_assert_eq!(id, c.wrapping_add((m >> 48) as u16));
        // `next` is one generator step plus `advance`, stored back in the
        // IDENT entry.
        let mut e = IdentEnt { rng, counter, pad: [0; 6] };
        prop_assert_eq!(ident::next(&mut e, m), id);
        prop_assert_eq!((e.rng, e.counter), (r, c));
        prop_assert_eq!(IdentEnt::from_bytes(&e.to_bytes()), e);
    }
}
