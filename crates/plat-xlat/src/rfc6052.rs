//! RFC 6052 IPv4-embedded IPv6 addresses.

use plat_packet::be32;

/// Well-Known Prefix 64:ff9b::/96 (RFC 6052 §2.1).
pub const WKP: u128 = 0x0064_ff9b_0000_0000_0000_0000_0000_0000;

/// A validated RFC 6052 prefix (length 32, 40, 48, 56, 64 or 96).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix6052 {
    prefix: u128,
    len: u8,
    mask: u128,
}

impl Prefix6052 {
    /// Returns `None` for an invalid length, host bits set, or a non-zero
    /// u-octet (bits 64–71, RFC 6052 §2.2).
    pub fn new(prefix: u128, len: u8) -> Option<Self> {
        if ![32, 40, 48, 56, 64, 96].contains(&len) {
            return None;
        }
        let mask = u128::MAX << (128 - len);
        if prefix & !mask != 0 || (prefix >> 56) & 0xff != 0 {
            return None;
        }
        Some(Self { prefix, len, mask })
    }

    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    #[inline]
    pub fn is_wkp(&self) -> bool {
        self.len == 96 && self.prefix == WKP
    }

    #[inline]
    pub fn contains(&self, a: u128) -> bool {
        a & self.mask == self.prefix
    }

    /// Synthesizes the IPv6 address for `v4` (RFC 6052 §2.2 Figure 1).
    #[inline]
    pub fn embed(&self, v4: u32) -> u128 {
        let mut b = self.prefix.to_be_bytes();
        let v = v4.to_be_bytes();
        match self.len {
            32 => b[4..8].copy_from_slice(&v),
            40 => {
                b[5..8].copy_from_slice(&v[..3]);
                b[9] = v[3];
            }
            48 => {
                b[6..8].copy_from_slice(&v[..2]);
                b[9..11].copy_from_slice(&v[2..]);
            }
            56 => {
                b[7] = v[0];
                b[9..12].copy_from_slice(&v[1..]);
            }
            64 => b[9..13].copy_from_slice(&v),
            _ => b[12..16].copy_from_slice(&v),
        }
        u128::from_be_bytes(b)
    }

    /// Extracts the embedded IPv4 address, or `None` if `a` is not inside
    /// this prefix or its u-octet is non-zero.
    #[inline]
    pub fn extract(&self, a: u128) -> Option<u32> {
        if !self.contains(a) {
            return None;
        }
        let b = a.to_be_bytes();
        if self.len != 96 && b[8] != 0 {
            return None;
        }
        Some(match self.len {
            32 => be32(&b, 4),
            40 => u32::from_be_bytes([b[5], b[6], b[7], b[9]]),
            48 => u32::from_be_bytes([b[6], b[7], b[9], b[10]]),
            56 => u32::from_be_bytes([b[7], b[9], b[10], b[11]]),
            64 => be32(&b, 9),
            _ => be32(&b, 12),
        })
    }
}

#[inline]
fn in4(a: u32, net: u32, len: u32) -> bool {
    a >> (32 - len) == net >> (32 - len)
}

/// Destinations that are never translated: "this network", loopback,
/// link-local, multicast, reserved and limited broadcast.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-7 (Boundary Protection)
#[inline]
pub fn is_never_translatable_v4(a: u32) -> bool {
    in4(a, 0x0000_0000, 8)
        || in4(a, 0x7f00_0000, 8)
        || in4(a, 0xa9fe_0000, 16)
        || in4(a, 0xe000_0000, 4)
        || in4(a, 0xf000_0000, 4)
}

/// Non-global IPv4 space that must not be represented with the WKP
/// (RFC 6052 §3.1): every RFC 6890 special-purpose block with
/// Global = False, plus the never-translatable set.
///
/// COMPLIANCE MAPPING:
/// - RFC 6052 §3.1, RFC 6890 §2.2.2 (IPv4 Special-Purpose Address Registry)
/// - NIST 800-53: SC-7 (Boundary Protection)
#[inline]
pub fn is_non_global_v4(a: u32) -> bool {
    if is_never_translatable_v4(a) {
        return true;
    }
    // 192.0.0.0/24 IETF Protocol Assignments is non-global except the
    // globally reachable PCP anycast (192.0.0.9) and TURN anycast
    // (192.0.0.10) addresses (RFC 7723, RFC 8155).
    if in4(a, 0xc000_0000, 24) {
        return a != 0xc000_0009 && a != 0xc000_000a;
    }
    in4(a, 0x0a00_0000, 8) // 10/8 private (RFC 1918)
        || in4(a, 0x6440_0000, 10) // 100.64/10 shared (RFC 6598)
        || in4(a, 0xac10_0000, 12) // 172.16/12 private
        || in4(a, 0xc000_0200, 24) // 192.0.2/24 TEST-NET-1 (RFC 5737)
        || in4(a, 0xc0a8_0000, 16) // 192.168/16 private
        || in4(a, 0xc612_0000, 15) // 198.18/15 benchmarking (RFC 2544)
        || in4(a, 0xc633_6400, 24) // 198.51.100/24 TEST-NET-2
        || in4(a, 0xcb00_7100, 24) // 203.0.113/24 TEST-NET-3
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v6(s: &str) -> u128 {
        u128::from(s.parse::<Ipv6Addr>().unwrap())
    }

    /// RFC 6052 §2.4 Table 1 vectors for 192.0.2.33.
    #[test]
    fn rfc6052_table1() {
        let v4 = u32::from(Ipv4Addr::new(192, 0, 2, 33));
        let cases = [
            ("2001:db8::", 32, "2001:db8:c000:221::"),
            ("2001:db8:100::", 40, "2001:db8:1c0:2:21::"),
            ("2001:db8:122::", 48, "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::", 56, "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::", 64, "2001:db8:122:344:c0:2:2100:0"),
            ("2001:db8:122:344::", 96, "2001:db8:122:344::192.0.2.33"),
            ("64:ff9b::", 96, "64:ff9b::192.0.2.33"),
        ];
        for (p, l, want) in cases {
            let pf = Prefix6052::new(v6(p), l).unwrap();
            assert_eq!(pf.embed(v4), v6(want), "/{l}");
            assert_eq!(pf.extract(v6(want)), Some(v4), "/{l}");
        }
    }

    #[test]
    fn rejects_bad_prefixes() {
        assert!(Prefix6052::new(v6("2001:db8::"), 80).is_none());
        assert!(Prefix6052::new(v6("2001:db8:0:0:ff00::"), 96).is_none());
    }

    /// RFC 6890 table-driven check: (address, non-global?, never-translatable?).
    #[test]
    fn non_global_table() {
        let cases: &[([u8; 4], bool, bool)] = &[
            ([0, 0, 0, 0], true, true),
            ([0, 255, 255, 255], true, true),
            ([9, 255, 255, 255], false, false),
            ([10, 0, 0, 0], true, false),
            ([10, 255, 255, 255], true, false),
            ([11, 0, 0, 0], false, false),
            ([100, 63, 255, 255], false, false),
            ([100, 64, 0, 0], true, false),
            ([100, 127, 255, 255], true, false),
            ([100, 128, 0, 0], false, false),
            ([127, 0, 0, 1], true, true),
            ([169, 254, 169, 254], true, true),
            ([172, 15, 255, 255], false, false),
            ([172, 16, 0, 0], true, false),
            ([172, 31, 255, 255], true, false),
            ([172, 32, 0, 0], false, false),
            ([192, 0, 0, 0], true, false),
            ([192, 0, 0, 8], true, false),
            ([192, 0, 0, 9], false, false),
            ([192, 0, 0, 10], false, false),
            ([192, 0, 0, 11], true, false),
            ([192, 0, 0, 170], true, false),
            ([192, 0, 0, 255], true, false),
            ([192, 0, 1, 0], false, false),
            ([192, 0, 2, 0], true, false),
            ([192, 0, 2, 255], true, false),
            ([192, 0, 3, 0], false, false),
            ([192, 88, 99, 1], false, false),
            ([192, 168, 0, 0], true, false),
            ([192, 168, 255, 255], true, false),
            ([198, 17, 255, 255], false, false),
            ([198, 18, 0, 0], true, false),
            ([198, 19, 255, 255], true, false),
            ([198, 20, 0, 0], false, false),
            ([198, 51, 100, 0], true, false),
            ([198, 51, 100, 255], true, false),
            ([198, 51, 101, 0], false, false),
            ([203, 0, 113, 0], true, false),
            ([203, 0, 113, 255], true, false),
            ([203, 0, 114, 0], false, false),
            ([8, 8, 8, 8], false, false),
            ([223, 255, 255, 255], false, false),
            ([224, 0, 0, 1], true, true),
            ([239, 1, 1, 1], true, true),
            ([240, 0, 0, 1], true, true),
            ([255, 255, 255, 255], true, true),
        ];
        for &(a, ng, nt) in cases {
            let v = u32::from(Ipv4Addr::from(a));
            assert_eq!(is_non_global_v4(v), ng, "non-global {a:?}");
            assert_eq!(is_never_translatable_v4(v), nt, "never-translatable {a:?}");
        }
    }

    proptest! {
        #[test]
        fn roundtrip_all_lengths(v4 in any::<u32>(), li in 0usize..6) {
            let len = [32u8, 40, 48, 56, 64, 96][li];
            let pf = Prefix6052::new(v6("2001:db8::"), len).unwrap();
            prop_assert_eq!(pf.extract(pf.embed(v4)), Some(v4));
        }
    }
}
