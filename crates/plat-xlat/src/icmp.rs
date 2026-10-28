//! ICMP error translation (RFC 7915 §4.2–4.3, §5.2–5.3).
//!
//! Errors are rare and their quoted packet changes size, so they are built
//! into a separate output buffer instead of in place. The caller first reads
//! the quoted tuple with [`quoted_v6`] / [`quoted_v4`], resolves the NAT
//! mapping for it, then calls the translate function.

use plat_packet::ip::{parse_l4_inner, parse_v4_inner, parse_v6_inner};
use plat_packet::{Ipv4Hdr, Ipv6Hdr, L4, be16, be32, checksum as ck, proto, put16, put32};

use crate::siit::{Map4, Map6, XlatError, l4_4to6, l4_6to4, write_v4_header, write_v6_header};

/// RFC 1812 §4.3.2.3: ICMPv4 errors carry at most 576 bytes in total.
pub const ICMP4_ERR_MAX: usize = 576;
/// RFC 4443 §2.4(c): ICMPv6 errors must not exceed the minimum MTU.
pub const ICMP6_ERR_MAX: usize = 1280;

/// Is this ICMPv6 type an error message (RFC 4443 §2.1)?
#[inline]
pub fn is_icmp6_error(ty: u8) -> bool {
    ty < 128
}

#[inline]
pub fn is_icmp4_error(ty: u8) -> bool {
    matches!(ty, 3 | 4 | 5 | 11 | 12)
}

/// Parses the packet quoted in an ICMPv6 error.
pub fn quoted_v6(pkt: &[u8], h: &Ipv6Hdr) -> Result<(Ipv6Hdr, L4), XlatError> {
    let inner = pkt.get(h.l4_off + 8..h.total_len()).ok_or(XlatError::Truncated)?;
    let ih = parse_v6_inner(inner).map_err(|_| XlatError::Truncated)?;
    if ih.frag.is_some_and(|f| !f.is_first()) {
        // A non-first fragment carries no transport header (RFC-103).
        return Err(XlatError::NonFirstFragment);
    }
    let l4 = parse_l4_inner(inner, ih.l4_off, ih.proto).map_err(|_| XlatError::Truncated)?;
    if matches!(l4, L4::Icmp { ty, .. } if is_icmp6_error(ty)) {
        // Never translate an error about an error (RFC 4443 §2.4(e)).
        return Err(XlatError::Untranslatable);
    }
    Ok((ih, l4))
}

/// Parses the packet quoted in an ICMPv4 error.
pub fn quoted_v4(pkt: &[u8], h: &Ipv4Hdr) -> Result<(Ipv4Hdr, L4), XlatError> {
    let inner = pkt.get(h.hdr_len + 8..h.total_len).ok_or(XlatError::Truncated)?;
    let ih = parse_v4_inner(inner).map_err(|_| XlatError::Truncated)?;
    if ih.frag.is_some_and(|f| !f.is_first()) {
        return Err(XlatError::NonFirstFragment);
    }
    let l4 = parse_l4_inner(inner, ih.hdr_len, ih.proto).map_err(|_| XlatError::Truncated)?;
    if matches!(l4, L4::Icmp { ty, .. } if is_icmp4_error(ty)) {
        return Err(XlatError::Untranslatable);
    }
    Ok((ih, l4))
}

/// RFC 7915 §5.2 Figure 6: IPv6 Parameter Problem pointer → IPv4 pointer.
fn ptr_6to4(p: u32) -> Option<u32> {
    Some(match p {
        0 => 0,
        1 => 1,
        4 | 5 => 2,
        6 => 9,
        7 => 8,
        8..=23 => 12,
        24..=39 => 16,
        _ => return None,
    })
}

/// RFC 7915 §4.2 Figure 3: IPv4 Parameter Problem pointer → IPv6 pointer.
fn ptr_4to6(p: u32) -> Option<u32> {
    Some(match p {
        0 => 0,
        1 => 1,
        2 | 3 => 4,
        8 => 7,
        9 => 6,
        12..=15 => 8,
        16..=19 => 24,
        _ => return None,
    })
}

/// RFC 1191 §7 plateau table, used when an IPv4 router reports MTU 0.
const PLATEAUS: [u32; 10] = [65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296];

/// Translates an ICMPv6 error to ICMPv4 into `out`; returns the length.
///
/// `outer` is the IPv4 (src, dst) of the error itself, `inner` the mapping
/// of the quoted packet.
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §5.2 (type/code/pointer/MTU mapping), §5.3 (quoted packet)
#[allow(clippy::too_many_arguments)]
pub fn icmp6_err_to_v4(
    pkt: &[u8],
    h: &Ipv6Hdr,
    ih: &Ipv6Hdr,
    outer: (u32, u32),
    inner: &Map4,
    ident: u16,
    mtu4: u16,
    mtu6: u16,
    out: &mut [u8],
) -> Result<usize, XlatError> {
    let icmp = pkt.get(h.l4_off..h.total_len()).ok_or(XlatError::Truncated)?;
    if icmp.len() < 8 {
        return Err(XlatError::Truncated);
    }
    let (ty, code, rest) = (icmp[0], icmp[1], be32(icmp, 4));
    let (ty4, code4, rest4) = match (ty, code) {
        (1, 0 | 2 | 3) => (3, 1, 0),
        (1, 1) => (3, 10, 0),
        (1, 4) => (3, 3, 0),
        (2, _) => {
            // RFC 7915 §5.2: subtract the header size difference (28 when the
            // packet in error carried a Fragment Header). An IPv6 PTB below
            // the IPv6 minimum MTU (RFC 8200 §5) is raised to 1280 first, so a
            // forged "MTU 0" cannot push the IPv4 sender to 68.
            let diff = if ih.frag.is_some() { 28 } else { 20 };
            let adv = rest.max(1280) - diff;
            let mtu = adv.min(u32::from(mtu4)).min(u32::from(mtu6).saturating_sub(diff));
            (3, 4, mtu.clamp(68, 65535))
        }
        (3, c) => (11, c, 0),
        (4, 0) => (12, 0, ptr_6to4(rest).ok_or(XlatError::Untranslatable)? << 24),
        (4, 1) => (3, 2, 0),
        _ => return Err(XlatError::Untranslatable),
    };

    let quoted = &icmp[8..];
    let iq_l4 = quoted.get(ih.l4_off..quoted.len().min(ih.total_len())).ok_or(XlatError::Truncated)?;
    let room = ICMP4_ERR_MAX.min(out.len()).saturating_sub(48);
    let copy = iq_l4.len().min(room);
    let body = out.get_mut(48..48 + copy).ok_or(XlatError::Truncated)?;
    body.copy_from_slice(&iq_l4[..copy]);
    let ip4 = l4_6to4(body, ih, inner, true)?;

    let (more, off, id) = match ih.frag {
        Some(f) => (f.more, f.offset, f.id as u16),
        None => (false, 0, 0),
    };
    let inner_total = (20 + ih.l4_len()).min(65535) as u16;
    write_v4_header(
        &mut out[28..48],
        ih.traffic_class,
        inner_total,
        id,
        false,
        more,
        off,
        ih.hop_limit,
        ip4,
        inner.src,
        inner.dst,
    );

    let total = 48 + copy;
    out[20] = ty4;
    out[21] = code4;
    put16(out, 22, 0);
    put32(out, 24, rest4);
    let c = ck::finish(ck::sum(&out[20..total]));
    put16(out, 22, c);

    write_v4_header(
        &mut out[..20],
        h.traffic_class,
        total as u16,
        ident,
        false,
        false,
        0,
        h.hop_limit,
        proto::ICMP,
        outer.0,
        outer.1,
    );
    Ok(total)
}

/// Translates an ICMPv4 error to ICMPv6 into `out`; returns the length.
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §4.2 (type/code/pointer/MTU mapping), §4.3 (quoted packet)
#[allow(clippy::too_many_arguments)]
pub fn icmp4_err_to_v6(
    pkt: &[u8],
    h: &Ipv4Hdr,
    ih: &Ipv4Hdr,
    outer: (u128, u128),
    inner: &Map6,
    mtu4: u16,
    mtu6: u16,
    out: &mut [u8],
) -> Result<usize, XlatError> {
    let icmp = pkt.get(h.hdr_len..h.total_len).ok_or(XlatError::Truncated)?;
    if icmp.len() < 8 {
        return Err(XlatError::Truncated);
    }
    let (ty, code, rest) = (icmp[0], icmp[1], be32(icmp, 4));
    let (ty6, code6, rest6) = match (ty, code) {
        (3, 0 | 1 | 5 | 6 | 7 | 8 | 11 | 12) => (1, 0, 0),
        (3, 2) => (4, 1, 6),
        (3, 3) => (1, 4, 0),
        (3, 4) => {
            let adv = u32::from(be16(icmp, 6));
            let adv = if adv == 0 {
                let t = ih.total_len as u32;
                PLATEAUS.iter().copied().find(|&p| p < t).unwrap_or(68)
            } else {
                adv
            };
            // RFC 7915 §4.2: +20, or +28 when the IPv6 packet carries a
            // Fragment Header (the quoted IPv4 packet is a fragment). An
            // IPv6 atomic fragment (RFC 8021, deprecated) translates to an
            // unfragmented IPv4 packet and gets +20, 8 bytes too generous.
            let diff = if ih.frag.is_some() { 28 } else { 20 };
            let mtu = (adv + diff).min(u32::from(mtu6)).min(u32::from(mtu4) + diff);
            (2, 0, mtu.max(1280))
        }
        (3, 9 | 10 | 13 | 15) => (1, 1, 0),
        (11, c) => (3, c, 0),
        (12, 0 | 2) => (4, 0, ptr_4to6(rest >> 24).ok_or(XlatError::Untranslatable)?),
        _ => return Err(XlatError::Untranslatable),
    };

    let quoted = &icmp[8..];
    let end = quoted.len().min(ih.total_len);
    let iq_l4 = quoted.get(ih.hdr_len..end).ok_or(XlatError::Truncated)?;
    let room = ICMP6_ERR_MAX.min(out.len()).saturating_sub(88);
    let copy = iq_l4.len().min(room);
    let body = out.get_mut(88..88 + copy).ok_or(XlatError::Truncated)?;
    body.copy_from_slice(&iq_l4[..copy]);
    let ip6 = l4_4to6(body, ih, inner, true)?;

    let inner_payload = ih.payload_len().min(65535) as u16;
    write_v6_header(&mut out[48..88], ih.tos, inner_payload, ip6, ih.ttl, inner.src, inner.dst);

    let total = 88 + copy;
    let icmp_len = (total - 40) as u32;
    out[40] = ty6;
    out[41] = code6;
    put16(out, 42, 0);
    put32(out, 44, rest6);
    let c = ck::finish(ck::pseudo_v6(outer.0, outer.1, proto::ICMPV6, icmp_len) + ck::sum(&out[40..total]));
    put16(out, 42, c);

    write_v6_header(&mut out[..40], h.tos, icmp_len as u16, proto::ICMPV6, h.ttl, outer.0, outer.1);
    Ok(total)
}

/// Builds a locally generated ICMPv4 error about the IPv4 packet `pkt` into
/// `out` (sent from `src` back to the packet's source). The quote is the
/// original header and as much data as fits in 576 bytes (RFC 1812
/// §4.3.2.3). Returns the length.
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §4 / RFC 1191 - Fragmentation Needed for DF packets that do
///   not fit the IPv6 MTU
#[allow(clippy::too_many_arguments)]
pub fn icmp4_error_local(
    pkt: &[u8],
    h: &Ipv4Hdr,
    src: u32,
    ty: u8,
    code: u8,
    rest: u32,
    ident: u16,
    out: &mut [u8],
) -> Result<usize, XlatError> {
    let q = h.total_len.min(pkt.len()).min(ICMP4_ERR_MAX - 28);
    let total = 28 + q;
    let o = out.get_mut(..total).ok_or(XlatError::Truncated)?;
    o[28..].copy_from_slice(pkt.get(..q).ok_or(XlatError::Truncated)?);
    o[20] = ty;
    o[21] = code;
    put16(o, 22, 0);
    put32(o, 24, rest);
    let c = ck::finish(ck::sum(&o[20..]));
    put16(o, 22, c);
    write_v4_header(&mut o[..20], 0, total as u16, ident, false, false, 0, 64, proto::ICMP, src, h.src);
    Ok(total)
}

/// Builds a locally generated ICMPv6 error about the IPv6 packet `pkt` into
/// `out` (sent from `src` back to the packet's source), quoting as much as
/// fits in 1280 bytes (RFC 4443 §2.4(c)). Returns the length.
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §5 / RFC 4443 §3.2 - Packet Too Big for IPv6 packets whose
///   translation does not fit the IPv4 MTU
pub fn icmp6_error_local(
    pkt: &[u8],
    h: &Ipv6Hdr,
    src: u128,
    ty: u8,
    code: u8,
    rest: u32,
    out: &mut [u8],
) -> Result<usize, XlatError> {
    let q = h.total_len().min(pkt.len()).min(ICMP6_ERR_MAX - 48);
    let total = 48 + q;
    let o = out.get_mut(..total).ok_or(XlatError::Truncated)?;
    o[48..].copy_from_slice(pkt.get(..q).ok_or(XlatError::Truncated)?);
    let icmp_len = (total - 40) as u32;
    o[40] = ty;
    o[41] = code;
    put16(o, 42, 0);
    put32(o, 44, rest);
    let c = ck::finish(ck::pseudo_v6(src, h.src, proto::ICMPV6, icmp_len) + ck::sum(&o[40..]));
    put16(o, 42, c);
    write_v6_header(&mut o[..40], 0, icmp_len as u16, proto::ICMPV6, 64, src, h.src);
    Ok(total)
}
