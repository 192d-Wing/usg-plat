//! Bounds-checked packet header views and Internet checksum arithmetic.
//!
//! Every function here treats its input as attacker-controlled: lengths are
//! checked before any field is read, and malformed input returns
//! [`ParseError`] rather than panicking.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - RFC 791, RFC 8200, RFC 1071, RFC 1624

pub mod checksum;
pub mod ip;

pub use ip::{
    Frag, Ipv4Hdr, Ipv6Hdr, L4, ParseError, parse_l4, parse_l4_inner, parse_v4, parse_v4_ignore_source_route,
    parse_v4_inner, parse_v6, parse_v6_ignore_routing, parse_v6_inner,
};

/// IP protocol numbers used by the translator.
pub mod proto {
    pub const HOPOPT: u8 = 0;
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const ICMPV6: u8 = 58;
    pub const NONE: u8 = 59;
    pub const DSTOPTS: u8 = 60;
}

#[inline(always)]
pub fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

#[inline(always)]
pub fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline(always)]
pub fn be128(b: &[u8], off: usize) -> u128 {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[off..off + 16]);
    u128::from_be_bytes(a)
}

#[inline(always)]
pub fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

#[inline(always)]
pub fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

#[inline(always)]
pub fn put128(b: &mut [u8], off: usize, v: u128) {
    b[off..off + 16].copy_from_slice(&v.to_be_bytes());
}
