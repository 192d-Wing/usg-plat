//! Fixed-layout header checks. Each function reads one fixed header block
//! (62 bytes for Ethernet + IPv6 + UDP, 42 for Ethernet + IPv4 + UDP) at
//! constant offsets and compares lengths as scalars against the frame
//! length, never as pointer arithmetic (plan §2.5 rule 1).
//!
//! What is accepted is a strict subset of what `plat-packet` accepts, with
//! identical field values (property-tested in `tests/diff_engine.rs`):
//! no IPv6 extension headers, no IPv4 options, no fragments, UDP only, the
//! UDP length equal to the IP payload length (`plat-packet` ignores it),
//! a non-zero UDP checksum, and a TTL / hop limit above 2. The payload is
//! never read. Bytes after the IP length (Ethernet padding, trailers) are
//! allowed and reported, so the caller can trim them as the kernel does.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-10 (Information Input Validation) - every field is
//!   bounds-checked by construction (fixed arrays); malformed input yields
//!   a [`PassReason`], never a panic
//! - RFC 8200 §3, §4 - IPv6 header; no extension headers on the fast path
//! - RFC 791 §3.1 - IPv4 header, header checksum, no options or fragments
//! - RFC 768 - UDP length and checksum
//! - RFC 7915 §4.5 / §5.1 - zero-checksum UDP is left to the slow path
//! - RFC 1812 §5.3.1, RFC-007 two-hop model - TTL / hop limit ≤ 2 declined

use crate::abi::PassReason;
use crate::csum;
use crate::take;
use crate::{ETH, HDR4, HDR6, IP4, IP6};

/// Ethertype IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
/// Ethertype IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// IP protocol number of UDP.
pub const PROTO_UDP: u8 = 17;
/// Lowest TTL / hop limit the fast path forwards (output = input − 2).
pub const MIN_HOP: u8 = 3;

/// IPv6 next-header values that are extension headers (RFC 8200 §4, the
/// IANA IPv6 Extension Header Types registry): Hop-by-Hop, Routing,
/// Fragment, ESP, AH, Destination Options, Mobility, HIP, Shim6, and the
/// two experimental values.
#[inline(always)]
fn is_ext_header(nh: u8) -> bool {
    matches!(nh, 0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140 | 253 | 254)
}

/// Fields of an accepted Ethernet + IPv6 + UDP frame that the decision
/// uses (the rewrite reads the rest from the header block). Addresses and
/// ports are in network order, as in the packet and the map keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V6Meta {
    pub traffic_class: u8,
    /// IPv6 Payload Length (= UDP length, at least 8).
    pub payload_len: u16,
    pub src6: [u8; 16],
    pub dst6: [u8; 16],
    pub sport: [u8; 2],
    pub dport: [u8; 2],
    /// Frame bytes after the IPv6 packet (to trim).
    pub trailing: u32,
}

/// Fields of an accepted Ethernet + IPv4 + UDP frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4Meta {
    pub tos: u8,
    pub df: bool,
    /// IPv4 Total Length (= 20 + UDP length, at least 28).
    pub total_len: u16,
    pub src4: [u8; 4],
    pub dst4: [u8; 4],
    pub sport: [u8; 2],
    pub dport: [u8; 2],
    /// Frame bytes after the IPv4 packet (Ethernet padding, to trim).
    pub trailing: u32,
}

#[inline(always)]
fn be16(b: [u8; 2]) -> u16 {
    u16::from_be_bytes(b)
}

/// The Ethertype of a header block. [`classify_v6`] / [`classify_v4`]
/// check it; [`crate::decide_frame`] reads it only to dispatch (PERF-007).
#[inline(always)]
pub fn ethertype<const N: usize>(h: &[u8; N]) -> u16 {
    be16(take(h, 12))
}

/// Checks the Ethernet + IPv6 + UDP header block `h` of a frame of
/// `frame_len` bytes (`frame_len` is what the caller measured, never a
/// header field).
///
/// Order: Ethertype, version, Payload Length (≥ 8 and inside the frame;
/// 0, a jumbogram, is declined), next header, UDP length, UDP checksum,
/// hop limit.
#[inline(always)]
pub fn classify_v6(h: &[u8; HDR6], frame_len: u32) -> Result<V6Meta, PassReason> {
    if ethertype(h) != ETHERTYPE_IPV6 {
        return Err(PassReason::NotIp);
    }
    let vtf = u32::from_be_bytes(take(h, ETH));
    if vtf >> 28 != 6 {
        return Err(PassReason::BadL3);
    }
    let plen = be16(take(h, ETH + 4));
    // Scalars only: 54 + plen is at most 65589, no overflow in u32.
    let end = (ETH + IP6) as u32 + u32::from(plen);
    if plen < 8 || end > frame_len {
        return Err(PassReason::BadL3);
    }
    let [nh, hop] = take(h, ETH + 6);
    if nh != PROTO_UDP {
        return Err(if is_ext_header(nh) { PassReason::ExtHeader } else { PassReason::NotUdp });
    }
    let u = ETH + IP6;
    if be16(take(h, u + 4)) != plen {
        return Err(PassReason::UdpLen);
    }
    if be16(take(h, u + 6)) == 0 {
        return Err(PassReason::UdpZeroCsum);
    }
    if hop < MIN_HOP {
        return Err(PassReason::HopLimit);
    }
    Ok(V6Meta {
        traffic_class: (vtf >> 20) as u8,
        payload_len: plen,
        src6: take(h, ETH + 8),
        dst6: take(h, ETH + 24),
        sport: take(h, u),
        dport: take(h, u + 2),
        trailing: frame_len - end,
    })
}

/// Checks the Ethernet + IPv4 + UDP header block `h` of a frame of
/// `frame_len` bytes.
///
/// Order: Ethertype, version, IHL (< 5 malformed, > 5 options), Total
/// Length (≥ 28 and inside the frame), header checksum, fragment fields,
/// protocol, UDP length, UDP checksum, TTL.
#[inline(always)]
pub fn classify_v4(h: &[u8; HDR4], frame_len: u32) -> Result<V4Meta, PassReason> {
    if ethertype(h) != ETHERTYPE_IPV4 {
        return Err(PassReason::NotIp);
    }
    let ip: [u8; IP4] = take(h, ETH);
    let [vihl, tos, t0, t1, _, _, f0, f1, ttl, proto, ..] = ip;
    if vihl >> 4 != 4 {
        return Err(PassReason::BadL3);
    }
    match vihl & 0x0f {
        5 => {}
        0..=4 => return Err(PassReason::BadL3),
        _ => return Err(PassReason::Ipv4Options),
    }
    let total = be16([t0, t1]);
    let end = ETH as u32 + u32::from(total);
    if total < (IP4 + 8) as u16 || end > frame_len {
        return Err(PassReason::BadL3);
    }
    if !csum::ipv4_header_ok(&ip) {
        return Err(PassReason::BadL3);
    }
    let ff = be16([f0, f1]);
    // MF or a non-zero offset; the reserved bit is ignored, as by the
    // kernel and `plat-packet`.
    if ff & 0x3fff != 0 {
        return Err(PassReason::Fragment);
    }
    if proto != PROTO_UDP {
        return Err(PassReason::NotUdp);
    }
    let u = ETH + IP4;
    if be16(take(h, u + 4)) != total - IP4 as u16 {
        return Err(PassReason::UdpLen);
    }
    if be16(take(h, u + 6)) == 0 {
        return Err(PassReason::UdpZeroCsum);
    }
    if ttl < MIN_HOP {
        return Err(PassReason::HopLimit);
    }
    Ok(V4Meta {
        tos,
        df: ff & 0x4000 != 0,
        total_len: total,
        src4: take(&ip, 12),
        dst4: take(&ip, 16),
        sport: take(h, u),
        dport: take(h, u + 2),
        trailing: frame_len - end,
    })
}
