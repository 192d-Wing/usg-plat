//! `plat_xdp_core::csum` is bit-exact with `plat_packet::checksum` (plan
//! §3 WU1 acceptance 5), including the `0x0000` / `0xFFFF` encodings of
//! one's-complement zero (RFC 1624 §3, RFC 768).
//!
//! COMPLIANCE MAPPING:
//! - RFC 1071, RFC 1624, RFC 768 - checksum arithmetic equivalence
//! - NIST 800-53: SA-11 - property tests

mod support;

use plat_packet::checksum as ck;
use plat_xdp_core::csum;
use proptest::prelude::*;
use support::{cases, ok};

fn config() -> ProptestConfig {
    ProptestConfig { cases: cases(), ..ProptestConfig::default() }
}

/// `fold`'s documented input bound (PERF-003): exact below `2^48`.
const FOLD_BOUND: u64 = 1 << 48;

/// Partial sums the translator can produce (a few hundred header words at
/// most) up to far beyond, but below the `2^47` bound of `adjust`.
fn partial_sum() -> impl Strategy<Value = u64> {
    prop_oneof![0..=0x3_ffffu64, 0..=u64::from(u32::MAX), 0..(1u64 << 47)]
}

fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    ok(<[u8; N]>::try_from(v))
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn fold_and_finish_match(s in prop_oneof![0..=0x3_ffffu64, 0..FOLD_BOUND]) {
        prop_assert_eq!(csum::fold(s), ck::fold(s));
        prop_assert_eq!(csum::finish(s), ck::finish(s));
    }

    #[test]
    fn adjust_matches(c in any::<u16>(), old in partial_sum(), new in partial_sum()) {
        prop_assert_eq!(csum::adjust(c, old, new), ck::adjust(c, old, new));
        prop_assert_eq!(
            csum::udp_nonzero(csum::adjust(c, old, new)),
            ck::udp_nonzero(ck::adjust(c, old, new))
        );
    }

    /// Partial sums may differ in representation (`plat-packet` adds
    /// 32-bit words), never in value: equal after folding, and zero only
    /// for all-zero input in both.
    #[test]
    fn sums_match(b in proptest::collection::vec(prop_oneof![Just(0u8), Just(0xff), any::<u8>()], 40)) {
        fn same(core: u64, pp: u64) -> Result<(), TestCaseError> {
            prop_assert_eq!(csum::fold(core), ck::fold(pp));
            prop_assert_eq!(core == 0, pp == 0);
            Ok(())
        }
        same(csum::sum(&arr::<2>(&b[..2])), ck::sum(&b[..2]))?;
        same(csum::sum(&arr::<3>(&b[..3])), ck::sum(&b[..3]))?;
        same(csum::sum(&arr::<4>(&b[..4])), ck::sum(&b[..4]))?;
        same(csum::sum(&arr::<16>(&b[..16])), ck::sum(&b[..16]))?;
        same(csum::sum(&arr::<20>(&b[..20])), ck::sum(&b[..20]))?;
        same(csum::sum(&arr::<40>(&b)), ck::sum(&b))?;
        let b40 = arr::<40>(&b);
        prop_assert_eq!(csum::sum_at(&b40, 8, 32), csum::sum(&arr::<32>(&b[8..])));
        prop_assert_eq!(csum::sum_at(&b40, 12, 8), csum::sum(&arr::<8>(&b[12..20])));
        // The address forms the translator uses are exactly equal.
        let a16 = arr::<16>(&b[..16]);
        prop_assert_eq!(csum::sum(&a16), ck::sum_u128(u128::from_be_bytes(a16)));
        let a4 = arr::<4>(&b[..4]);
        prop_assert_eq!(csum::sum(&a4), ck::sum_u32(u32::from_be_bytes(a4)));
    }

    /// The IPv4 header checksum equals `write_v4_header`'s for any header,
    /// whatever the checksum field held before.
    #[test]
    fn ipv4_header_csum_matches_write_v4_header(
        tos in any::<u8>(), total in any::<u16>(), id in any::<u16>(), df in any::<bool>(),
        ttl in any::<u8>(), proto in any::<u8>(), src in any::<u32>(), dst in any::<u32>(), junk in any::<u16>(),
    ) {
        let mut h = [0u8; 20];
        plat_xlat::siit::write_v4_header(&mut h, tos, total, id, df, false, 0, ttl, proto, src, dst);
        let want = u16::from_be_bytes([h[10], h[11]]);
        prop_assert!(csum::ipv4_header_ok(&h));
        h[10..12].copy_from_slice(&junk.to_be_bytes());
        prop_assert_eq!(csum::ipv4_header_csum(&h), want);
        prop_assert_eq!(csum::ipv4_header_ok(&h), junk == want);
    }
}

#[test]
fn fold_edges() {
    for s in [
        0,
        1,
        0xffff,
        0x1_0000,
        0x1_fffe,
        0x1_ffff,
        0x2_0000,
        0xffff_ffff,
        0x1_0000_fffe,
        0x1_0000_ffff,
        0xffff_fffe_ffff,
        FOLD_BOUND - 1,
        FOLD_BOUND - 2,
    ] {
        assert_eq!(csum::fold(s), ck::fold(s), "{s:#x}");
    }
    // The largest sum a caller can produce: `adjust` with every input at
    // its bound.
    let s = 0xffff + 0xffff + (1u64 << 47) - 1;
    assert_eq!(csum::fold(s), ck::fold(s));
}

#[test]
fn udp_nonzero_exhaustive() {
    for c in 0..=u16::MAX {
        assert_eq!(csum::udp_nonzero(c), ck::udp_nonzero(c));
    }
}

#[test]
fn rfc1624_edge_vectors() {
    // RFC 1624 §3: HC = 0xDD2F, m = 0x5555 -> m' = 0x3285. Eqn. 3 gives
    // 0x0000 (eqn. 2 would give 0xFFFF).
    assert_eq!(csum::adjust(0xdd2f, 0x5555, 0x3285), 0x0000);
    assert_eq!(ck::adjust(0xdd2f, 0x5555, 0x3285), 0x0000);
    // As a UDP checksum the zero is sent as 0xFFFF (RFC 768).
    assert_eq!(csum::udp_nonzero(csum::adjust(0xdd2f, 0x5555, 0x3285)), 0xffff);
    // All-zero sum: the result is 0xFFFF in both.
    assert_eq!(csum::adjust(0xffff, 0xffff, 0), 0xffff);
    assert_eq!(ck::adjust(0xffff, 0xffff, 0), 0xffff);
    // Removing and adding the same field leaves the checksum alone, for
    // every encoding of zero.
    for c in [0x0000, 0xffff, 0x1234] {
        for m in [0u64, 0xffff, 0x8000] {
            assert_eq!(csum::adjust(c, m, m), ck::adjust(c, m, m), "{c:#x} {m:#x}");
        }
    }
}
