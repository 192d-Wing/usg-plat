//! In-place IPv6⇄IPv4 header translation for TCP, UDP and ICMP queries
//! (RFC 7915 §4.1, §5.1). ICMP errors are handled in [`crate::icmp`].
//!
//! Addresses and ports in the output come from the caller ([`Map4`] /
//! [`Map6`]); this module does not know about NAT state.

use plat_packet::{Ipv4Hdr, Ipv6Hdr, be16, checksum as ck, proto, put16, put32, put128};

/// Translated IPv4 addressing. For ICMP queries `sport` is the identifier
/// and `dport` is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Map4 {
    pub src: u32,
    pub dst: u32,
    pub sport: u16,
    pub dport: u16,
}

/// Translated IPv6 addressing. For ICMP queries `dport` is the identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Map6 {
    pub src: u128,
    pub dst: u128,
    pub sport: u16,
    pub dport: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XlatError {
    /// Not enough headroom in front of the packet to grow the header.
    Headroom,
    Truncated,
    /// IPv6 UDP datagram with a zero checksum (invalid per RFC 8200 §8.1).
    ZeroUdpChecksum,
    /// Fragmented datagram whose checksum cannot be fixed without reassembly.
    FragmentNeedsReassembly,
    /// Non-first fragment (no transport header to map).
    NonFirstFragment,
    /// ICMP type/code with no translation (RFC 7915 §4.2/§5.2: drop).
    Untranslatable,
    /// Result exceeds 65535 or the egress MTU.
    TooBig,
}

pub const ICMP4_ECHO_REPLY: u8 = 0;
pub const ICMP4_ECHO_REQUEST: u8 = 8;
pub const ICMP6_ECHO_REQUEST: u8 = 128;
pub const ICMP6_ECHO_REPLY: u8 = 129;

/// Maps an ICMPv6 query type to ICMPv4.
#[inline]
pub fn icmp6_query_to_4(ty: u8) -> Option<u8> {
    match ty {
        ICMP6_ECHO_REQUEST => Some(ICMP4_ECHO_REQUEST),
        ICMP6_ECHO_REPLY => Some(ICMP4_ECHO_REPLY),
        _ => None,
    }
}

#[inline]
pub fn icmp4_query_to_6(ty: u8) -> Option<u8> {
    match ty {
        ICMP4_ECHO_REQUEST => Some(ICMP6_ECHO_REQUEST),
        ICMP4_ECHO_REPLY => Some(ICMP6_ECHO_REPLY),
        _ => None,
    }
}

/// Writes a 20-byte IPv4 header with no options and computes its checksum.
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn write_v4_header(
    b: &mut [u8],
    tos: u8,
    total_len: u16,
    ident: u16,
    df: bool,
    more: bool,
    frag_off: u16,
    ttl: u8,
    proto_num: u8,
    src: u32,
    dst: u32,
) {
    b[0] = 0x45;
    b[1] = tos;
    put16(b, 2, total_len);
    put16(b, 4, ident);
    let ff = (u16::from(df) << 14) | (u16::from(more) << 13) | (frag_off & 0x1fff);
    put16(b, 6, ff);
    b[8] = ttl;
    b[9] = proto_num;
    put16(b, 10, 0);
    put32(b, 12, src);
    put32(b, 16, dst);
    let c = ck::finish(ck::sum(&b[..20]));
    put16(b, 10, c);
}

/// Writes a 40-byte IPv6 header (flow label 0, RFC 7915 §4.1).
#[inline]
pub fn write_v6_header(b: &mut [u8], tc: u8, payload_len: u16, next: u8, hop: u8, src: u128, dst: u128) {
    put32(b, 0, (6u32 << 28) | (u32::from(tc) << 20));
    put16(b, 4, payload_len);
    b[6] = next;
    b[7] = hop;
    put128(b, 8, src);
    put128(b, 24, dst);
}

/// Rewrites transport ports and fixes the checksum for a v6→v4 move.
/// `l4` must hold at least the transport header (checked by the caller).
/// Returns the IPv4 protocol number.
/// With `quoted` (the packet inside an ICMP error), the transport header may
/// be truncated: checksums outside the available bytes are left alone.
pub(crate) fn l4_6to4(l4: &mut [u8], h: &Ipv6Hdr, m: &Map4, quoted: bool) -> Result<u8, XlatError> {
    if l4.len() < 8 {
        return Err(XlatError::Truncated);
    }
    let old_addr = ck::sum_u128(h.src) + ck::sum_u128(h.dst);
    let new_addr = ck::sum_u32(m.src) + ck::sum_u32(m.dst);
    match h.proto {
        proto::TCP | proto::UDP => {
            let off = if h.proto == proto::TCP { 16 } else { 6 };
            let old = old_addr + u64::from(be16(l4, 0)) + u64::from(be16(l4, 2));
            let new = new_addr + u64::from(m.sport) + u64::from(m.dport);
            put16(l4, 0, m.sport);
            put16(l4, 2, m.dport);
            if l4.len() < off + 2 {
                return if quoted { Ok(h.proto) } else { Err(XlatError::Truncated) };
            }
            let old_c = be16(l4, off);
            if h.proto == proto::UDP && old_c == 0 {
                if quoted {
                    return Ok(h.proto);
                }
                return Err(XlatError::ZeroUdpChecksum);
            }
            // The pseudo-header length and protocol are identical in both
            // families, so only addresses and ports enter the adjustment.
            let c = ck::adjust(old_c, old, new);
            put16(l4, off, if h.proto == proto::UDP { ck::udp_nonzero(c) } else { c });
            Ok(h.proto)
        }
        proto::ICMPV6 => {
            if h.frag.is_some() && !quoted {
                // The ICMPv6 pseudo-header needs the full upper-layer length.
                return Err(XlatError::FragmentNeedsReassembly);
            }
            let ty4 = icmp6_query_to_4(l4[0]).ok_or(XlatError::Untranslatable)?;
            let old_tc = u16::from_be_bytes([l4[0], l4[1]]);
            let old = ck::pseudo_v6(h.src, h.dst, proto::ICMPV6, h.l4_len() as u32)
                + u64::from(old_tc)
                + u64::from(be16(l4, 4));
            l4[0] = ty4;
            put16(l4, 4, m.sport);
            let new = u64::from(u16::from_be_bytes([l4[0], l4[1]])) + u64::from(m.sport);
            let c = ck::adjust(be16(l4, 2), old, new);
            put16(l4, 2, c);
            Ok(proto::ICMP)
        }
        _ => Err(XlatError::Untranslatable),
    }
}

/// Translates the IPv6 packet at `buf[start..start+len]` to IPv4 in place.
/// Returns the `(start, len)` of the IPv4 packet in `buf`.
///
/// `ident` is the IPv4 Identification for unfragmented packets
/// (RFC 7915 §5.1); fragments reuse the low 16 bits of the IPv6 id.
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §5.1 - IPv6-to-IPv4 header translation
/// - RFC 1624 - incremental transport checksum update
#[inline]
pub fn v6_to_v4(
    buf: &mut [u8],
    start: usize,
    h: &Ipv6Hdr,
    m: &Map4,
    ident: u16,
    mtu4: u16,
) -> Result<(usize, usize), XlatError> {
    if h.frag.is_some_and(|f| !f.is_first()) {
        return Err(XlatError::NonFirstFragment);
    }
    let l4_len = h.l4_len();
    let total = 20 + l4_len;
    if total > usize::from(mtu4) {
        return Err(XlatError::TooBig);
    }
    let l4_start = start + h.l4_off;
    let l4 = &mut buf[l4_start..start + h.total_len()];
    let p4 = l4_6to4(l4, h, m, false)?;
    let (df, more, off, id) = match h.frag {
        Some(f) => (false, f.more, f.offset, f.id as u16),
        // RFC 7915 §5.1: DF=0 when the result is ≤ 1260 bytes.
        None => (total > 1260, false, 0, if total > 1260 { 0 } else { ident }),
    };
    let new_start = l4_start - 20;
    write_v4_header(
        &mut buf[new_start..l4_start],
        h.traffic_class,
        total as u16,
        id,
        df,
        more,
        off,
        h.hop_limit,
        p4,
        m.src,
        m.dst,
    );
    Ok((new_start, total))
}

pub(crate) fn l4_4to6(l4: &mut [u8], h: &Ipv4Hdr, m: &Map6, quoted: bool) -> Result<u8, XlatError> {
    if l4.len() < 8 {
        return Err(XlatError::Truncated);
    }
    let old_addr = ck::sum_u32(h.src) + ck::sum_u32(h.dst);
    let new_addr = ck::sum_u128(m.src) + ck::sum_u128(m.dst);
    match h.proto {
        proto::TCP => {
            let old = old_addr + u64::from(be16(l4, 0)) + u64::from(be16(l4, 2));
            put16(l4, 0, m.sport);
            put16(l4, 2, m.dport);
            if l4.len() < 18 {
                return if quoted { Ok(proto::TCP) } else { Err(XlatError::Truncated) };
            }
            let new = new_addr + u64::from(m.sport) + u64::from(m.dport);
            let c = ck::adjust(be16(l4, 16), old, new);
            put16(l4, 16, c);
            Ok(proto::TCP)
        }
        proto::UDP => {
            let old_c = be16(l4, 6);
            let old = old_addr + u64::from(be16(l4, 0)) + u64::from(be16(l4, 2));
            put16(l4, 0, m.sport);
            put16(l4, 2, m.dport);
            if old_c == 0 && quoted {
                // Cannot compute over a truncated quote; leave it unchecksummed.
            } else if old_c == 0 {
                // RFC 7915 §4.5: compute a checksum for unchecksummed IPv4
                // UDP; impossible for fragments without reassembly.
                if h.frag.is_some() {
                    return Err(XlatError::FragmentNeedsReassembly);
                }
                let s = ck::pseudo_v6(m.src, m.dst, proto::UDP, l4.len() as u32) + ck::sum(l4);
                put16(l4, 6, ck::udp_nonzero(ck::finish(s)));
            } else {
                let new = new_addr + u64::from(m.sport) + u64::from(m.dport);
                put16(l4, 6, ck::udp_nonzero(ck::adjust(old_c, old, new)));
            }
            Ok(proto::UDP)
        }
        proto::ICMP => {
            if h.frag.is_some() && !quoted {
                return Err(XlatError::FragmentNeedsReassembly);
            }
            let ty6 = icmp4_query_to_6(l4[0]).ok_or(XlatError::Untranslatable)?;
            let old = u64::from(u16::from_be_bytes([l4[0], l4[1]])) + u64::from(be16(l4, 4));
            l4[0] = ty6;
            put16(l4, 4, m.dport);
            let new = ck::pseudo_v6(m.src, m.dst, proto::ICMPV6, h.payload_len() as u32)
                + u64::from(u16::from_be_bytes([l4[0], l4[1]]))
                + u64::from(m.dport);
            let c = ck::adjust(be16(l4, 2), old, new);
            put16(l4, 2, c);
            Ok(proto::ICMPV6)
        }
        _ => Err(XlatError::Untranslatable),
    }
}

/// Translates the IPv4 packet at `buf[start..start+h.total_len]` to IPv6 in
/// place, writing the new header into the headroom. Returns `(start, len)`.
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §4.1 - IPv4-to-IPv6 header translation (options dropped,
///   flow label 0, Fragment Header only for fragmented IPv4 packets)
#[inline]
pub fn v4_to_v6(buf: &mut [u8], start: usize, h: &Ipv4Hdr, m: &Map6, mtu6: u16) -> Result<(usize, usize), XlatError> {
    if h.frag.is_some_and(|f| !f.is_first()) {
        return Err(XlatError::NonFirstFragment);
    }
    let fh = if h.frag.is_some() { 8 } else { 0 };
    let l4_start = start + h.hdr_len;
    let l4_len = h.payload_len();
    let total = 40 + fh + l4_len;
    if total > usize::from(mtu6) || 40 + fh + l4_len > 40 + 65535 {
        return Err(XlatError::TooBig);
    }
    let new_start = l4_start.checked_sub(40 + fh).ok_or(XlatError::Headroom)?;
    let l4 = &mut buf[l4_start..l4_start + l4_len];
    let p6 = l4_4to6(l4, h, m, false)?;
    let next = if fh > 0 { proto::FRAGMENT } else { p6 };
    write_v6_header(&mut buf[new_start..new_start + 40], h.tos, (fh + l4_len) as u16, next, h.ttl, m.src, m.dst);
    if let Some(f) = h.frag {
        let fb = &mut buf[new_start + 40..new_start + 48];
        fb[0] = p6;
        fb[1] = 0;
        put16(fb, 2, (f.offset << 3) | u16::from(f.more));
        put32(fb, 4, f.id);
    }
    Ok((new_start, total))
}

/// Layout of the fragments written by [`v4_to_v6_fragments`]: `count`
/// packets back to back, each `frag_len` bytes except the last
/// (`last_len`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Frags {
    pub count: usize,
    pub frag_len: usize,
    pub last_len: usize,
}

/// Bytes of IPv6 + Fragment Header in front of each fragment.
pub const FRAG6_HDR: usize = 48;

/// Translates an IPv4 packet with DF=0 (or an IPv4 first fragment) to IPv6
/// and splits it into IPv6 fragments of at most `max_len` bytes, written back
/// to back into `out`. The transport checksum is updated over the whole
/// datagram before splitting. The packet in `buf` is modified (transport
/// header rewritten) but not moved.
///
/// The Fragment Header Identification is the IPv4 Identification (high 16
/// bits zero); offsets continue the IPv4 fragment's offset; the last
/// fragment's M flag copies the IPv4 MF flag.
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §4 - IPv4 packets with DF=0 that exceed lowest-ipv6-mtu are
///   fragmented by the translator; §4.1 Fragment Header fields
pub fn v4_to_v6_fragments(
    buf: &mut [u8],
    start: usize,
    h: &Ipv4Hdr,
    m: &Map6,
    max_len: u16,
    out: &mut [u8],
) -> Result<Frags, XlatError> {
    if h.frag.is_some_and(|f| !f.is_first()) {
        return Err(XlatError::NonFirstFragment);
    }
    let chunk = usize::from(max_len).saturating_sub(FRAG6_HDR) & !7;
    if chunk == 0 {
        return Err(XlatError::TooBig);
    }
    let l4_start = start + h.hdr_len;
    let l4_len = h.payload_len();
    let count = l4_len.div_ceil(chunk).max(1);
    if count * FRAG6_HDR + l4_len > out.len() {
        return Err(XlatError::TooBig);
    }
    let l4 = buf.get_mut(l4_start..l4_start + l4_len).ok_or(XlatError::Truncated)?;
    let p6 = l4_4to6(l4, h, m, false)?;
    let id = u32::from(h.id);
    let more_last = h.frag.is_some_and(|f| f.more);
    let mut o = 0;
    for i in 0..count {
        let off = i * chunk;
        let len = chunk.min(l4_len - off);
        let more = i + 1 < count || more_last;
        let f = &mut out[o..o + FRAG6_HDR + len];
        write_v6_header(f, h.tos, (8 + len) as u16, proto::FRAGMENT, h.ttl, m.src, m.dst);
        f[40] = p6;
        f[41] = 0;
        put16(f, 42, (((off / 8) as u16) << 3) | u16::from(more));
        put32(f, 44, id);
        f[FRAG6_HDR..].copy_from_slice(&l4[off..off + len]);
        o += FRAG6_HDR + len;
    }
    Ok(Frags { count, frag_len: FRAG6_HDR + chunk, last_len: FRAG6_HDR + (l4_len - (count - 1) * chunk) })
}
