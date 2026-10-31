//! Internet checksum arithmetic: bit-exact ports of
//! `plat_packet::checksum` (`fold`, `finish`, `adjust`, `udp_nonzero`) for
//! fixed-size inputs, so the fast path produces the same `0x0000` / `0xFFFF`
//! encodings as the slow path (`tests/csum_equiv.rs` proves equality).
//!
//! Partial sums are carried unfolded in a `u64`, as in `plat-packet`.
//! [`fold`] is unrolled to a constant number of steps (no data-dependent
//! loop for the eBPF verifier).
//!
//! COMPLIANCE MAPPING:
//! - RFC 1071 - Internet checksum
//! - RFC 1624 eqn. 3 - incremental update `HC' = ~(~HC + ~m + m')`
//! - RFC 768 - a computed UDP checksum of 0 is transmitted as 0xFFFF

/// Sums `b` as big-endian 16-bit words (`M` even at every call site; an odd
/// trailing byte is zero-padded, as in `plat_packet::checksum::sum`).
#[inline(always)]
pub fn sum<const M: usize>(b: &[u8; M]) -> u64 {
    let (pairs, rest) = b.as_chunks::<2>();
    let mut acc: u64 = 0;
    for p in pairs {
        acc += u64::from(u16::from_be_bytes(*p));
    }
    if let [last] = rest {
        acc += u64::from(*last) << 8;
    }
    acc
}

/// Folds a partial sum to 16 bits (no complement). Five unrolled steps
/// reach the fixed point of `plat_packet::checksum::fold`'s loop for every
/// `u64`: after three steps the value is at most `0x2_0000`, and two more
/// bring that below `0x1_0000`, where a step is the identity.
#[inline(always)]
pub fn fold(s: u64) -> u16 {
    let s = (s & 0xffff) + (s >> 16);
    let s = (s & 0xffff) + (s >> 16);
    let s = (s & 0xffff) + (s >> 16);
    let s = (s & 0xffff) + (s >> 16);
    let s = (s & 0xffff) + (s >> 16);
    s as u16
}

/// Final checksum value to store in a header.
#[inline(always)]
pub fn finish(s: u64) -> u16 {
    !fold(s)
}

/// RFC 1624 eqn. 3, where `old` / `new` are (unfolded) sums of the fields
/// removed and added. `new` must stay below `2^63` (true for any sum of a
/// few header words).
#[inline(always)]
pub fn adjust(csum: u16, old: u64, new: u64) -> u16 {
    let s = u64::from(!csum) + u64::from(!fold(old)) + new;
    !fold(s)
}

/// UDP transmits a computed checksum of 0 as 0xFFFF (RFC 768).
#[inline(always)]
pub fn udp_nonzero(c: u16) -> u16 {
    if c == 0 { 0xffff } else { c }
}

/// Header checksum of the IPv4 header `h` (no options), computed with the
/// checksum field taken as zero, as `plat_xlat::siit::write_v4_header` does.
#[inline(always)]
pub fn ipv4_header_csum(h: &[u8; 20]) -> u16 {
    let [_, _, _, _, _, _, _, _, _, _, c0, c1, ..] = *h;
    finish(sum(h) - u64::from(u16::from_be_bytes([c0, c1])))
}

/// True when the IPv4 header `h` (no options) has a valid checksum.
#[inline(always)]
pub fn ipv4_header_ok(h: &[u8; 20]) -> bool {
    fold(sum(h)) == 0xffff
}
