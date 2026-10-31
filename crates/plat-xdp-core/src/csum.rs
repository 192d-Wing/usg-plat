//! Internet checksum arithmetic: bit-exact ports of
//! `plat_packet::checksum` (`fold`, `finish`, `adjust`, `udp_nonzero`) for
//! fixed-size inputs, so the fast path produces the same `0x0000` / `0xFFFF`
//! encodings as the slow path (`tests/csum_equiv.rs` proves equality).
//!
//! Partial sums are carried unfolded in a `u64`, as in `plat-packet`.
//! [`fold`] is unrolled to a constant number of steps (no data-dependent
//! loop for the eBPF verifier), which is exact for sums below `2^48`.
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

/// [`sum`] of the `len` bytes of `b` at `off` (`len` even at every call
/// site), read in place instead of copied out. Bytes past the end of `b`
/// read as zero. `off` and `len` are constants at every call site, so the
/// word loop has a constant trip count and is fully unrolled in the eBPF
/// object (PERF-009: no back-edge).
#[inline(always)]
pub fn sum_at<const N: usize>(b: &[u8; N], off: usize, len: usize) -> u64 {
    let s = b.get(off..).unwrap_or(&[]);
    let s = s.get(..len).unwrap_or(s);
    let (pairs, rest) = s.as_chunks::<2>();
    let mut acc: u64 = 0;
    for p in pairs {
        acc += u64::from(u16::from_be_bytes(*p));
    }
    if let [last] = rest {
        acc += u64::from(*last) << 8;
    }
    acc
}

/// Folds a partial sum to 16 bits (no complement). Input bound:
/// `s < 2^48`. Three unrolled steps then reach the fixed point of
/// `plat_packet::checksum::fold`'s loop: the first leaves at most
/// `0x1_0000_fffe`, the second at most `0x1_fffe`, the third at most
/// `0xffff`. Every caller stays far below the bound: a sum of the 62-byte
/// header block is under `2^21`, and [`adjust`] adds two 16-bit values to
/// one (PERF-003).
#[inline(always)]
pub fn fold(s: u64) -> u16 {
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
/// removed and added. `old` and `new` must stay below `2^47` (the
/// [`fold`] bound; true for any sum of a few header words).
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
