//! Internet checksum (RFC 1071) with incremental update (RFC 1624).
//!
//! Partial sums are carried unfolded in a `u64` so callers can add pieces
//! (pseudo-header, header, payload) and fold once at the end.

/// Sums `data` as big-endian 16-bit words (odd trailing byte zero-padded).
#[inline]
pub fn sum(data: &[u8]) -> u64 {
    let mut acc: u64 = 0;
    let (chunks, rest) = data.as_chunks::<8>();
    for c in chunks {
        // Two 32-bit big-endian words per step; one's-complement addition is
        // associative, so folding 32-bit word sums to 16 bits is equivalent.
        acc += u64::from(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
        acc += u64::from(u32::from_be_bytes([c[4], c[5], c[6], c[7]]));
    }
    let (pairs, last) = rest.as_chunks::<2>();
    for p in pairs {
        acc += u64::from(u16::from_be_bytes(*p));
    }
    if let [last] = last {
        acc += u64::from(*last) << 8;
    }
    acc
}

/// Folds a partial sum to 16 bits (no complement).
#[inline]
pub fn fold(mut s: u64) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

/// Final checksum value to store in a header.
#[inline]
pub fn finish(s: u64) -> u16 {
    !fold(s)
}

#[inline]
pub fn sum_u128(v: u128) -> u64 {
    sum_u64((v >> 64) as u64) + sum_u64(v as u64)
}

#[inline]
pub fn sum_u64(v: u64) -> u64 {
    (v >> 48) + ((v >> 32) & 0xffff) + ((v >> 16) & 0xffff) + (v & 0xffff)
}

#[inline]
pub fn sum_u32(v: u32) -> u64 {
    u64::from(v >> 16) + u64::from(v & 0xffff)
}

/// IPv4 pseudo-header sum (RFC 768/793).
#[inline]
pub fn pseudo_v4(src: u32, dst: u32, proto: u8, len: u16) -> u64 {
    sum_u32(src) + sum_u32(dst) + u64::from(proto) + u64::from(len)
}

/// IPv6 pseudo-header sum (RFC 8200 §8.1).
#[inline]
pub fn pseudo_v6(src: u128, dst: u128, next: u8, len: u32) -> u64 {
    sum_u128(src) + sum_u128(dst) + sum_u32(len) + u64::from(next)
}

/// RFC 1624 eqn. 3: `HC' = ~(~HC + ~m + m')`, where `old`/`new` are
/// (unfolded) sums of the fields removed and added.
#[inline]
pub fn adjust(csum: u16, old: u64, new: u64) -> u16 {
    let s = u64::from(!csum) + u64::from(!fold(old)) + new;
    !fold(s)
}

/// UDP transmits a computed checksum of 0 as 0xffff (RFC 768).
#[inline]
pub fn udp_nonzero(c: u16) -> u16 {
    if c == 0 { 0xffff } else { c }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn naive(data: &[u8]) -> u16 {
        let mut s: u32 = 0;
        for i in (0..data.len()).step_by(2) {
            let hi = u32::from(data[i]) << 8;
            let lo = data.get(i + 1).copied().map(u32::from).unwrap_or(0);
            s += hi | lo;
        }
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }

    #[test]
    fn rfc1071_example() {
        // RFC 1071 §3 example bytes: sum = 0xddf2.
        let d = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(fold(sum(&d)), 0xddf2);
    }

    proptest! {
        #[test]
        fn fast_sum_matches_naive(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            prop_assert_eq!(finish(sum(&data)), naive(&data));
        }

        #[test]
        fn incremental_matches_full(mut data in proptest::collection::vec(any::<u8>(), 8..200),
                                    a in any::<u16>(), idx in 0usize..3) {
            let off = idx * 2;
            let before = finish(sum(&data));
            let old = u16::from_be_bytes([data[off], data[off + 1]]);
            data[off..off + 2].copy_from_slice(&a.to_be_bytes());
            let after = finish(sum(&data));
            let inc = adjust(before, u64::from(old), u64::from(a));
            // 0x0000 and 0xffff are both encodings of one's-complement zero.
            prop_assert!(inc == after || (inc ^ after) == 0xffff && (inc == 0 || after == 0));
        }
    }
}
