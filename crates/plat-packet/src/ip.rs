//! IPv4 / IPv6 / transport header parsing.

use crate::{be16, be32, be128, checksum, proto};

/// Upper bound on IPv6 extension headers walked per packet (SC-5: bounded
/// work per packet; RFC 7045 lets intermediate nodes limit processing).
pub const MAX_EXT_HEADERS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    BadVersion,
    BadHeaderLen,
    BadTotalLen,
    BadHeaderChecksum,
    TooManyExtHeaders,
    UnsupportedExtHeader,
    /// Routing header with Segments Left != 0. `ptr` is the offset of the
    /// Segments Left field from the start of the packet (the ICMPv6
    /// Parameter Problem pointer, RFC 7915 §5.1 / RFC 4443 §3.4).
    RoutingHeaderActive {
        ptr: u16,
    },
    UnsupportedProto,
    /// First fragment that does not hold the whole extension-header chain
    /// (RFC 7112, RFC 8200 §4.5).
    TinyFragment,
    /// Malformed IPv4 option list (bad length, overruns the header).
    BadOptions,
    /// IPv4 Loose/Strict Source Route option with an unexpired route.
    SourceRouteActive,
}

/// IPv4 option types (RFC 791).
const OPT_EOL: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_LSRR: u8 = 131;
const OPT_SSRR: u8 = 137;

/// Walks the IPv4 option list in `opts` (the header bytes after the fixed
/// 20). The walk is bounded by the option area (at most 40 bytes).
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §4.1 - a packet with an unexpired LSRR/SSRR option MUST NOT be
///   translated.
/// - NIST 800-53: SI-10 (Information Input Validation), SC-7
fn check_v4_options(opts: &[u8], allow_srr: bool) -> Result<(), ParseError> {
    let mut i = 0;
    while let Some(&ty) = opts.get(i) {
        match ty {
            OPT_EOL => return Ok(()),
            OPT_NOP => i += 1,
            _ => {
                let len = usize::from(*opts.get(i + 1).ok_or(ParseError::BadOptions)?);
                if len < 2 || i + len > opts.len() {
                    return Err(ParseError::BadOptions);
                }
                if ty == OPT_LSRR || ty == OPT_SSRR {
                    if len < 3 {
                        return Err(ParseError::BadOptions);
                    }
                    // RFC 791: the route is exhausted once the pointer
                    // (1-based, minimum 4) exceeds the option length.
                    let ptr = usize::from(*opts.get(i + 2).ok_or(ParseError::BadOptions)?);
                    if ptr <= len && !allow_srr {
                        return Err(ParseError::SourceRouteActive);
                    }
                }
                i += len;
            }
        }
    }
    Ok(())
}

/// Fragment information common to both families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frag {
    pub id: u32,
    /// Offset in 8-octet units.
    pub offset: u16,
    pub more: bool,
}

impl Frag {
    #[inline]
    pub fn is_first(&self) -> bool {
        self.offset == 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Hdr {
    pub hdr_len: usize,
    pub total_len: usize,
    pub tos: u8,
    pub id: u16,
    pub df: bool,
    pub ttl: u8,
    pub proto: u8,
    pub src: u32,
    pub dst: u32,
    /// `Some` when MF is set or the offset is non-zero.
    pub frag: Option<Frag>,
}

impl Ipv4Hdr {
    #[inline]
    pub fn payload_len(&self) -> usize {
        self.total_len - self.hdr_len
    }
}

/// Parses and validates an IPv4 header. `pkt` may carry trailing padding
/// beyond Total Length; callers use `total_len`.
#[inline]
pub fn parse_v4(pkt: &[u8]) -> Result<Ipv4Hdr, ParseError> {
    parse_v4_impl(pkt, false)
}

/// [`parse_v4`] that accepts an unexpired source route option, for building
/// the ICMPv4 Source Route Failed reply about the packet (RFC 1812
/// §5.2.4.1). Every other check still applies.
pub fn parse_v4_ignore_source_route(pkt: &[u8]) -> Result<Ipv4Hdr, ParseError> {
    parse_v4_impl(pkt, true)
}

#[inline(always)]
fn parse_v4_impl(pkt: &[u8], allow_srr: bool) -> Result<Ipv4Hdr, ParseError> {
    if pkt.len() < 20 {
        return Err(ParseError::Truncated);
    }
    if pkt[0] >> 4 != 4 {
        return Err(ParseError::BadVersion);
    }
    let hdr_len = usize::from(pkt[0] & 0x0f) * 4;
    if hdr_len < 20 || hdr_len > pkt.len() {
        return Err(ParseError::BadHeaderLen);
    }
    let total_len = usize::from(be16(pkt, 2));
    if total_len < hdr_len || total_len > pkt.len() {
        return Err(ParseError::BadTotalLen);
    }
    if checksum::fold(checksum::sum(&pkt[..hdr_len])) != 0xffff {
        return Err(ParseError::BadHeaderChecksum);
    }
    if hdr_len > 20 {
        check_v4_options(&pkt[20..hdr_len], allow_srr)?;
    }
    let ff = be16(pkt, 6);
    let offset = ff & 0x1fff;
    let more = ff & 0x2000 != 0;
    let id = be16(pkt, 4);
    Ok(Ipv4Hdr {
        hdr_len,
        total_len,
        tos: pkt[1],
        id,
        df: ff & 0x4000 != 0,
        ttl: pkt[8],
        proto: pkt[9],
        src: be32(pkt, 12),
        dst: be32(pkt, 16),
        frag: (more || offset != 0).then_some(Frag { id: u32::from(id), offset, more }),
    })
}

/// Lenient IPv4 parse for packets quoted inside ICMP errors: the quoted copy
/// may be truncated, so Total Length is not checked against the buffer and
/// the header checksum is not verified (RFC 7915 §4.3 translates it anyway).
pub fn parse_v4_inner(pkt: &[u8]) -> Result<Ipv4Hdr, ParseError> {
    if pkt.len() < 20 {
        return Err(ParseError::Truncated);
    }
    if pkt[0] >> 4 != 4 {
        return Err(ParseError::BadVersion);
    }
    let hdr_len = usize::from(pkt[0] & 0x0f) * 4;
    if hdr_len < 20 || hdr_len > pkt.len() {
        return Err(ParseError::BadHeaderLen);
    }
    let total_len = usize::from(be16(pkt, 2));
    if total_len < hdr_len {
        return Err(ParseError::BadTotalLen);
    }
    let ff = be16(pkt, 6);
    let offset = ff & 0x1fff;
    let more = ff & 0x2000 != 0;
    let id = be16(pkt, 4);
    Ok(Ipv4Hdr {
        hdr_len,
        total_len,
        tos: pkt[1],
        id,
        df: ff & 0x4000 != 0,
        ttl: pkt[8],
        proto: pkt[9],
        src: be32(pkt, 12),
        dst: be32(pkt, 16),
        frag: (more || offset != 0).then_some(Frag { id: u32::from(id), offset, more }),
    })
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv6Hdr {
    pub traffic_class: u8,
    pub flow_label: u32,
    /// Payload Length from the fixed header (bytes after the 40-byte header).
    pub payload_len: usize,
    pub hop_limit: u8,
    pub src: u128,
    pub dst: u128,
    /// Upper-layer protocol after walking extension headers.
    pub proto: u8,
    /// Offset of the upper-layer header from the start of the packet.
    pub l4_off: usize,
    pub frag: Option<Frag>,
    /// Offset just past the Fragment Header (0 without one). For a
    /// non-first fragment this equals `l4_off`.
    pub frag_end: usize,
}

impl Ipv6Hdr {
    #[inline]
    pub fn total_len(&self) -> usize {
        40 + self.payload_len
    }

    /// Length of the upper-layer data (what the pseudo-header covers).
    #[inline]
    pub fn l4_len(&self) -> usize {
        self.total_len() - self.l4_off
    }
}

#[inline(always)]
fn parse_v6_impl(pkt: &[u8], strict_len: bool, allow_routing: bool) -> Result<Ipv6Hdr, ParseError> {
    if pkt.len() < 40 {
        return Err(ParseError::Truncated);
    }
    if pkt[0] >> 4 != 6 {
        return Err(ParseError::BadVersion);
    }
    let payload_len = usize::from(be16(pkt, 4));
    // The quoted packet inside an ICMPv6 error may be truncated.
    let avail = if strict_len {
        if 40 + payload_len > pkt.len() {
            return Err(ParseError::BadTotalLen);
        }
        40 + payload_len
    } else {
        pkt.len().min(40 + payload_len)
    };
    let mut next = pkt[6];
    let mut off = 40;
    let mut frag: Option<Frag> = None;
    let mut frag_end = 0;
    // RFC 7112: once past a Fragment Header, running out of bytes means the
    // first fragment did not carry the whole header chain.
    let short = |frag: Option<Frag>| {
        if strict_len && frag.is_some() { ParseError::TinyFragment } else { ParseError::Truncated }
    };
    // PERF-001: a nested fn (not a closure capturing the slice) so the
    // header is built directly in the return slot.
    #[inline(always)]
    fn hdr(pkt: &[u8], payload_len: usize, next: u8, off: usize, frag: Option<Frag>, frag_end: usize) -> Ipv6Hdr {
        let vtf = be32(pkt, 0);
        Ipv6Hdr {
            traffic_class: (vtf >> 20) as u8,
            flow_label: vtf & 0x000f_ffff,
            payload_len,
            hop_limit: pkt[7],
            src: be128(pkt, 8),
            dst: be128(pkt, 24),
            proto: next,
            l4_off: off,
            frag,
            frag_end,
        }
    }
    for _ in 0..=MAX_EXT_HEADERS {
        match next {
            proto::HOPOPT | proto::DSTOPTS | proto::ROUTING => {
                // RFC 8200 §4.1: Hop-by-Hop Options may only follow the
                // fixed header.
                if next == proto::HOPOPT && off != 40 {
                    return Err(ParseError::UnsupportedExtHeader);
                }
                if off + 8 > avail {
                    return Err(short(frag));
                }
                // RFC 7915 §5.1: a Routing header with Segments Left != 0
                // must not be translated.
                if next == proto::ROUTING && pkt[off + 3] != 0 && !allow_routing {
                    return Err(ParseError::RoutingHeaderActive { ptr: (off + 3) as u16 });
                }
                let len = (usize::from(pkt[off + 1]) + 1) * 8;
                next = pkt[off];
                off += len;
            }
            proto::FRAGMENT => {
                if off + 8 > avail || frag.is_some() {
                    return Err(ParseError::UnsupportedExtHeader);
                }
                let fo = be16(pkt, off + 2);
                frag = Some(Frag { id: be32(pkt, off + 4), offset: fo >> 3, more: fo & 1 != 0 });
                next = pkt[off];
                off += 8;
                frag_end = off;
                // A non-first fragment carries no header chain after the
                // Fragment Header: its payload continues the first
                // fragment's (RFC 8200 §4.5), so the walk stops and `proto`
                // is the upper layer the Fragment Header names.
                if fo >> 3 != 0 {
                    return match next {
                        proto::TCP | proto::UDP | proto::ICMPV6 => Ok(hdr(pkt, payload_len, next, off, frag, frag_end)),
                        _ => Err(ParseError::UnsupportedProto),
                    };
                }
            }
            proto::TCP | proto::UDP | proto::ICMPV6 => {
                if off > avail {
                    return Err(short(frag));
                }
                return Ok(hdr(pkt, payload_len, next, off, frag, frag_end));
            }
            _ => return Err(ParseError::UnsupportedProto),
        }
    }
    Err(ParseError::TooManyExtHeaders)
}

/// Parses an IPv6 header and walks its extension-header chain.
pub fn parse_v6(pkt: &[u8]) -> Result<Ipv6Hdr, ParseError> {
    parse_v6_impl(pkt, true, false)
}

/// [`parse_v6`] that walks past a Routing header with Segments Left != 0,
/// for building the ICMPv6 Parameter Problem reply about the packet
/// (RFC 7915 §5.1). Every other check still applies.
pub fn parse_v6_ignore_routing(pkt: &[u8]) -> Result<Ipv6Hdr, ParseError> {
    parse_v6_impl(pkt, true, true)
}

/// Lenient variant for packets quoted inside ICMPv6 errors.
pub fn parse_v6_inner(pkt: &[u8]) -> Result<Ipv6Hdr, ParseError> {
    parse_v6_impl(pkt, false, false)
}

/// Transport identifiers used for mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    Tcp {
        sport: u16,
        dport: u16,
        flags: u8,
    },
    Udp {
        sport: u16,
        dport: u16,
        csum: u16,
    },
    /// ICMP / ICMPv6 message; `id` is meaningful only for queries.
    Icmp {
        ty: u8,
        code: u8,
        id: u16,
    },
}

/// Reads the transport identifiers at `pkt[off..]`. `avail` bounds the read.
pub fn parse_l4(pkt: &[u8], off: usize, avail: usize, proto_num: u8) -> Result<L4, ParseError> {
    let need = match proto_num {
        proto::TCP => 20,
        proto::UDP | proto::ICMP | proto::ICMPV6 => 8,
        _ => return Err(ParseError::UnsupportedProto),
    };
    let end = avail.min(pkt.len());
    if off + need > end {
        return Err(ParseError::Truncated);
    }
    Ok(match proto_num {
        proto::TCP => L4::Tcp { sport: be16(pkt, off), dport: be16(pkt, off + 2), flags: pkt[off + 13] },
        proto::UDP => L4::Udp { sport: be16(pkt, off), dport: be16(pkt, off + 2), csum: be16(pkt, off + 6) },
        _ => L4::Icmp { ty: pkt[off], code: pkt[off + 1], id: be16(pkt, off + 4) },
    })
}

/// TCP sequence number of the segment at `pkt[off..]`, or `None` when
/// fewer than 8 bytes are available within `avail`.
pub fn tcp_seq(pkt: &[u8], off: usize, avail: usize) -> Option<u32> {
    let b = pkt.get(..avail.min(pkt.len()))?.get(off.checked_add(4)?..off.checked_add(8)?)?;
    Some(u32::from_be_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]))
}

/// Lenient transport read for quoted packets: only the first 8 bytes are
/// guaranteed (RFC 792), so TCP flags are reported as 0 when absent.
pub fn parse_l4_inner(pkt: &[u8], off: usize, proto_num: u8) -> Result<L4, ParseError> {
    if off + 8 > pkt.len() {
        return Err(ParseError::Truncated);
    }
    Ok(match proto_num {
        proto::TCP => L4::Tcp { sport: be16(pkt, off), dport: be16(pkt, off + 2), flags: 0 },
        proto::UDP => L4::Udp { sport: be16(pkt, off), dport: be16(pkt, off + 2), csum: be16(pkt, off + 6) },
        proto::ICMP | proto::ICMPV6 => L4::Icmp { ty: pkt[off], code: pkt[off + 1], id: be16(pkt, off + 4) },
        _ => return Err(ParseError::UnsupportedProto),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn tcp_seq_is_bounds_checked() {
        let p = [0u8, 1, 0, 2, 0xde, 0xad, 0xbe, 0xef, 9];
        assert_eq!(tcp_seq(&p, 0, p.len()), Some(0xdead_beef));
        assert_eq!(tcp_seq(&p, 0, 7), None);
        assert_eq!(tcp_seq(&p, 2, 100), None);
        assert_eq!(tcp_seq(&p, usize::MAX - 2, 100), None);
    }

    proptest! {
        #[test]
        fn tcp_seq_never_panics(p in proptest::collection::vec(any::<u8>(), 0..64), off in 0usize..80, avail in 0usize..80) {
            let _ = tcp_seq(&p, off, avail);
        }
    }

    fn v4_udp() -> Vec<u8> {
        let mut p = vec![
            0x45, 0, 0, 28, 0x12, 0x34, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 7, //
            0x04, 0x00, 0x00, 0x35, 0, 8, 0, 0,
        ];
        let c = checksum::finish(checksum::sum(&p[..20]));
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p
    }

    #[test]
    fn v4_ok() {
        let p = v4_udp();
        let h = parse_v4(&p).unwrap();
        assert_eq!((h.hdr_len, h.total_len, h.proto, h.ttl, h.df), (20, 28, 17, 64, true));
        assert!(h.frag.is_none());
        assert!(matches!(parse_l4(&p, 20, 28, 17).unwrap(), L4::Udp { sport: 1024, dport: 53, .. }));
    }

    #[test]
    fn v4_rejects_bad_checksum_and_lengths() {
        let mut p = v4_udp();
        p[10] ^= 1;
        assert_eq!(parse_v4(&p).unwrap_err(), ParseError::BadHeaderChecksum);
        let mut p = v4_udp();
        p[0] = 0x44;
        assert_eq!(parse_v4(&p).unwrap_err(), ParseError::BadHeaderLen);
        let p = v4_udp();
        assert_eq!(parse_v4(&p[..27]).unwrap_err(), ParseError::BadTotalLen);
    }

    #[test]
    fn v6_walks_ext_headers_and_frag() {
        let mut p = vec![0u8; 40 + 8 + 8 + 8];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&24u16.to_be_bytes());
        p[6] = proto::HOPOPT;
        p[7] = 64;
        p[40] = proto::FRAGMENT; // HBH -> FRAG
        p[48] = proto::UDP; // FRAG -> UDP, offset 0, M=1
        p[50..52].copy_from_slice(&1u16.to_be_bytes());
        p[52..56].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        let h = parse_v6(&p).unwrap();
        assert_eq!((h.proto, h.l4_off), (proto::UDP, 56));
        assert_eq!(h.frag, Some(Frag { id: 0xdead_beef, offset: 0, more: true }));
    }

    #[test]
    fn v6_rejects_active_routing_header() {
        let mut p = vec![0u8; 56];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&16u16.to_be_bytes());
        p[6] = proto::ROUTING;
        p[40] = proto::UDP;
        p[43] = 1;
        assert_eq!(parse_v6(&p).unwrap_err(), ParseError::RoutingHeaderActive { ptr: 43 });
        assert_eq!(parse_v6_ignore_routing(&p).unwrap().proto, proto::UDP);
    }

    #[test]
    fn v6_bounds_ext_header_chain() {
        let n = MAX_EXT_HEADERS + 2;
        let mut p = vec![0u8; 40 + 8 * n];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((8 * n) as u16).to_be_bytes());
        p[6] = proto::DSTOPTS;
        for i in 0..n {
            p[40 + 8 * i] = proto::DSTOPTS;
        }
        assert_eq!(parse_v6(&p).unwrap_err(), ParseError::TooManyExtHeaders);
    }

    fn v4_with_opts(opts: &[u8]) -> Vec<u8> {
        let mut p = v4_udp();
        let hl = 20 + opts.len();
        assert_eq!(hl % 4, 0);
        p.splice(20..20, opts.iter().copied());
        p[0] = 0x40 | (hl / 4) as u8;
        p[2..4].copy_from_slice(&((hl + 8) as u16).to_be_bytes());
        p[10..12].copy_from_slice(&[0, 0]);
        let c = checksum::finish(checksum::sum(&p[..hl]));
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p
    }

    #[test]
    fn v4_source_route_options() {
        // Unexpired LSRR / SSRR (pointer 4 <= length 7): not translatable.
        for ty in [131u8, 137] {
            let p = v4_with_opts(&[ty, 7, 4, 10, 0, 0, 1, 0]);
            assert_eq!(parse_v4(&p).unwrap_err(), ParseError::SourceRouteActive, "type {ty}");
        }
        // Expired route (pointer 8 > length 7) behind a NOP: allowed.
        let p = v4_with_opts(&[1, 131, 7, 8, 10, 0, 0, 1]);
        assert_eq!(parse_v4(&p).unwrap().hdr_len, 28);
        // Record Route, then EOL: allowed; option bytes after EOL ignored.
        let p = v4_with_opts(&[7, 3, 4, 0, 131, 7, 4, 0]);
        assert!(parse_v4(&p).is_ok());
        // Length 0/1, overrunning the header, or a source route too short
        // to carry a pointer: malformed.
        for opts in [[7u8, 0, 0, 0], [7, 1, 0, 0], [7, 9, 4, 0], [131, 2, 0, 0], [1, 1, 1, 7]] {
            assert_eq!(parse_v4(&v4_with_opts(&opts)).unwrap_err(), ParseError::BadOptions, "{opts:?}");
        }
    }

    #[test]
    fn v6_hop_by_hop_only_first() {
        let mut p = vec![0u8; 40 + 8 + 8 + 8];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&24u16.to_be_bytes());
        p[6] = proto::DSTOPTS;
        p[40] = proto::HOPOPT;
        p[48] = proto::UDP;
        assert_eq!(parse_v6(&p).unwrap_err(), ParseError::UnsupportedExtHeader);
    }

    #[test]
    fn v6_non_first_fragment_stops_at_fragment_header() {
        // FRAG (offset 8 units, next = DSTOPTS in the first fragment's chain
        // would be unsupported here): payload bytes are not walked.
        let mut p = vec![0u8; 40 + 8 + 16];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&24u16.to_be_bytes());
        p[6] = proto::FRAGMENT;
        p[40] = proto::UDP;
        p[42..44].copy_from_slice(&(8u16 << 3).to_be_bytes());
        p[48] = 0xff; // garbage that would fail a header walk
        let h = parse_v6(&p).unwrap();
        assert_eq!((h.proto, h.l4_off, h.frag_end), (proto::UDP, 48, 48));
        assert_eq!(h.frag, Some(Frag { id: 0, offset: 8, more: false }));
        p[40] = proto::DSTOPTS;
        assert_eq!(parse_v6(&p).unwrap_err(), ParseError::UnsupportedProto);
    }

    #[test]
    fn v6_first_fragment_must_hold_header_chain() {
        // RFC 7112: FRAG (first, M=1) -> DSTOPTS that runs past the packet.
        let mut p = vec![0u8; 40 + 8 + 4];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&12u16.to_be_bytes());
        p[6] = proto::FRAGMENT;
        p[40] = proto::DSTOPTS;
        p[43] = 1;
        assert_eq!(parse_v6(&p).unwrap_err(), ParseError::TinyFragment);
        // Without a Fragment Header the same shortfall is plain truncation.
        p[6] = proto::DSTOPTS;
        assert_eq!(parse_v6(&p).unwrap_err(), ParseError::Truncated);
    }

    #[test]
    fn v4_source_route_can_be_parsed_for_the_error_reply() {
        let p = v4_with_opts(&[131, 7, 4, 10, 0, 0, 1, 0]);
        assert_eq!(parse_v4(&p).unwrap_err(), ParseError::SourceRouteActive);
        let h = parse_v4_ignore_source_route(&p).unwrap();
        assert_eq!((h.hdr_len, h.dst), (28, 0xc633_6407));
        // Malformed options are still refused.
        assert_eq!(parse_v4_ignore_source_route(&v4_with_opts(&[7u8, 0, 0, 0])).unwrap_err(), ParseError::BadOptions);
    }

    proptest! {
        // SI-10: arbitrary bytes never panic the parsers.
        #[test]
        fn parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..200)) {
            let _ = parse_v4(&data);
            let _ = parse_v4_inner(&data);
            let _ = parse_v6(&data);
            let _ = parse_v6_inner(&data);
            let _ = parse_v4_ignore_source_route(&data);
            let _ = parse_v6_ignore_routing(&data);
            for p in [6u8, 17, 1, 58] {
                let _ = parse_l4(&data, 20, data.len(), p);
                let _ = parse_l4_inner(&data, 40, p);
            }
        }
    }
}
