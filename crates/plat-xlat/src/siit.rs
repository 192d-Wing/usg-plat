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

/// Upper bound on packets one [`Frags`] can describe: a 65535-byte IPv6
/// datagram split for a 576-byte IPv4 MTU is 119 fragments.
pub const MAX_OUT: usize = 128;

/// Packets written back to back into a caller-owned output buffer (the
/// worker's preallocated fragment area). `lens[i]` is the length of packet
/// `i`; `used` the bytes written so far. Appending never allocates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frags {
    pub count: usize,
    pub used: usize,
    pub lens: [u16; MAX_OUT],
}

impl Default for Frags {
    fn default() -> Self {
        Self { count: 0, used: 0, lens: [0; MAX_OUT] }
    }
}

impl Frags {
    #[inline]
    pub fn clear(&mut self) {
        self.count = 0;
        self.used = 0;
    }

    /// Reserves the next packet of `len` bytes in `out`.
    pub fn push<'a>(&mut self, out: &'a mut [u8], len: usize) -> Result<&'a mut [u8], XlatError> {
        if self.count == MAX_OUT || len > usize::from(u16::MAX) {
            return Err(XlatError::TooBig);
        }
        let s = self.used;
        let o = out.get_mut(s..s + len).ok_or(XlatError::TooBig)?;
        self.lens[self.count] = len as u16;
        self.count += 1;
        self.used += len;
        Ok(o)
    }

    /// Copies `pkt` in as the next packet.
    pub fn push_copy(&mut self, out: &mut [u8], pkt: &[u8]) -> Result<(), XlatError> {
        self.push(out, pkt.len())?.copy_from_slice(pkt);
        Ok(())
    }

    /// The packets, in order.
    pub fn iter<'a>(&self, out: &'a [u8]) -> impl Iterator<Item = &'a [u8]> + 'a {
        let f = *self;
        let mut s = 0usize;
        (0..f.count).filter_map(move |i| {
            let l = usize::from(f.lens[i]);
            let p = out.get(s..s + l);
            s += l;
            p
        })
    }
}

/// Where translator-generated packets go: the layout and the buffer it
/// describes (the worker's preallocated fragment area).
#[derive(Debug)]
pub struct FragSink<'a> {
    pub frags: &'a mut Frags,
    pub out: &'a mut [u8],
}

impl FragSink<'_> {
    #[inline]
    fn push(&mut self, len: usize) -> Result<&mut [u8], XlatError> {
        self.frags.push(self.out, len)
    }
}

/// Bytes of IPv6 + Fragment Header in front of each fragment.
pub const FRAG6_HDR: usize = 48;

/// IPv6 header fields shared by every fragment of one datagram.
#[derive(Debug, Clone, Copy)]
pub struct Hdr6 {
    pub tc: u8,
    pub hop: u8,
    /// Upper-layer protocol (Fragment Header Next Header).
    pub next: u8,
    pub id: u32,
    pub src: u128,
    pub dst: u128,
}

/// IPv4 header fields shared by every fragment of one datagram.
#[derive(Debug, Clone, Copy)]
pub struct Hdr4 {
    pub tos: u8,
    pub ttl: u8,
    pub proto: u8,
    pub id: u16,
    pub src: u32,
    pub dst: u32,
}

/// Splits `payload` (the fragmentable part, starting `base` bytes into the
/// original datagram; `base` is a multiple of 8) into IPv6 fragments of at
/// most `max_len` bytes appended to `sink`. The last fragment's M
/// flag is `more_last`.
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §4.1 - Fragment Header fields (Identification, offset, M)
pub fn split_v6(
    payload: &[u8],
    base: usize,
    more_last: bool,
    h: &Hdr6,
    max_len: u16,
    sink: &mut FragSink<'_>,
) -> Result<(), XlatError> {
    let chunk = usize::from(max_len).saturating_sub(FRAG6_HDR) & !7;
    if chunk == 0 || !base.is_multiple_of(8) || base + payload.len() > 65535 {
        return Err(XlatError::TooBig);
    }
    let count = payload.len().div_ceil(chunk).max(1);
    for i in 0..count {
        let off = i * chunk;
        let len = chunk.min(payload.len() - off);
        let more = i + 1 < count || more_last;
        let f = sink.push(FRAG6_HDR + len)?;
        write_v6_header(f, h.tc, (8 + len) as u16, proto::FRAGMENT, h.hop, h.src, h.dst);
        f[40] = h.next;
        f[41] = 0;
        put16(f, 42, ((((base + off) / 8) as u16) << 3) | u16::from(more));
        put32(f, 44, h.id);
        f[FRAG6_HDR..].copy_from_slice(&payload[off..off + len]);
    }
    Ok(())
}

/// Splits `payload` into IPv4 fragments (DF=0) of at most `mtu4` bytes
/// appended to `sink`; see [`split_v6`].
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §5.1 - IPv6 packets of up to 1280 bytes are fragmented as
///   IPv4 when the IPv4 MTU is smaller; fragments keep DF=0
pub fn split_v4(
    payload: &[u8],
    base: usize,
    more_last: bool,
    h: &Hdr4,
    mtu4: u16,
    sink: &mut FragSink<'_>,
) -> Result<(), XlatError> {
    let chunk = usize::from(mtu4).saturating_sub(20) & !7;
    if chunk == 0 || !base.is_multiple_of(8) || base + payload.len() > 65535 - 20 {
        return Err(XlatError::TooBig);
    }
    let count = payload.len().div_ceil(chunk).max(1);
    for i in 0..count {
        let off = i * chunk;
        let len = chunk.min(payload.len() - off);
        let more = i + 1 < count || more_last;
        let f = sink.push(20 + len)?;
        let fo = ((base + off) / 8) as u16;
        write_v4_header(f, h.tos, (20 + len) as u16, h.id, false, more, fo, h.ttl, h.proto, h.src, h.dst);
        f[20..].copy_from_slice(&payload[off..off + len]);
    }
    Ok(())
}

/// Translates an IPv4 packet with DF=0 (or an IPv4 first fragment) to IPv6
/// and splits it into IPv6 fragments of at most `max_len` bytes appended to
/// `sink`. The transport checksum is updated over the whole datagram
/// before splitting. The packet in `buf` is modified (transport header
/// rewritten) but not moved.
///
/// The Fragment Header Identification is the IPv4 Identification (high 16
/// bits zero); the last fragment's M flag copies the IPv4 MF flag.
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
    sink: &mut FragSink<'_>,
) -> Result<(), XlatError> {
    if h.frag.is_some_and(|f| !f.is_first()) {
        return Err(XlatError::NonFirstFragment);
    }
    let l4_start = start + h.hdr_len;
    let l4_len = h.payload_len();
    let l4 = buf.get_mut(l4_start..l4_start + l4_len).ok_or(XlatError::Truncated)?;
    let p6 = l4_4to6(l4, h, m, false)?;
    let h6 = Hdr6 { tc: h.tos, hop: h.ttl, next: p6, id: u32::from(h.id), src: m.src, dst: m.dst };
    split_v6(l4, 0, h.frag.is_some_and(|f| f.more), &h6, max_len, sink)
}

/// Translates an IPv6 packet (unfragmented, or a first fragment) to IPv4
/// and splits it into IPv4 fragments of at most `mtu4` bytes, DF=0. The
/// packet in `buf` is modified (transport header rewritten) but not moved.
/// `ident` is used for an unfragmented packet; a fragment keeps the low 16
/// bits of its Identification (RFC 7915 §5.1).
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §5.1 - translator fragmentation of packets ≤ 1280 bytes
pub fn v6_to_v4_fragments(
    buf: &mut [u8],
    start: usize,
    h: &Ipv6Hdr,
    m: &Map4,
    ident: u16,
    mtu4: u16,
    sink: &mut FragSink<'_>,
) -> Result<(), XlatError> {
    if h.frag.is_some_and(|f| !f.is_first()) {
        return Err(XlatError::NonFirstFragment);
    }
    let l4 = buf.get_mut(start + h.l4_off..start + h.total_len()).ok_or(XlatError::Truncated)?;
    let p4 = l4_6to4(l4, h, m, false)?;
    let (id, more) = match h.frag {
        Some(f) => (f.id as u16, f.more),
        None => (ident, false),
    };
    let h4 = Hdr4 { tos: h.traffic_class, ttl: h.hop_limit, proto: p4, id, src: m.src, dst: m.dst };
    split_v4(l4, 0, more, &h4, mtu4, sink)
}

/// IPv4 protocol number for an IPv6 upper-layer protocol.
#[inline]
pub fn proto_6to4(p: u8) -> u8 {
    if p == proto::ICMPV6 { proto::ICMP } else { p }
}

/// IPv6 upper-layer protocol for an IPv4 protocol number.
#[inline]
pub fn proto_4to6(p: u8) -> u8 {
    if p == proto::ICMP { proto::ICMPV6 } else { p }
}

/// Header-only translation of an IPv6 **non-first** fragment to IPv4, in
/// place: the payload (no transport header) is untouched. Returns the
/// `(start, len)` of the IPv4 fragment, or `TooBig` when it exceeds `mtu4`
/// (use [`v6_frag_to_v4_split`]).
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §5.1 - Fragment Header → IPv4 Identification (low 16 bits),
///   offset and MF; DF=0
/// - RFC 6146 §3.4 - non-first fragments use the first fragment's mapping
pub fn v6_frag_to_v4(
    buf: &mut [u8],
    start: usize,
    h: &Ipv6Hdr,
    src: u32,
    dst: u32,
    mtu4: u16,
) -> Result<(usize, usize), XlatError> {
    let f = h.frag.ok_or(XlatError::Untranslatable)?;
    let total = 20 + h.l4_len();
    if total > usize::from(mtu4) {
        return Err(XlatError::TooBig);
    }
    let new_start = (start + h.l4_off).checked_sub(20).ok_or(XlatError::Headroom)?;
    let hdr = buf.get_mut(new_start..new_start + 20).ok_or(XlatError::Truncated)?;
    let p4 = proto_6to4(h.proto);
    write_v4_header(
        hdr,
        h.traffic_class,
        total as u16,
        f.id as u16,
        false,
        f.more,
        f.offset,
        h.hop_limit,
        p4,
        src,
        dst,
    );
    Ok((new_start, total))
}

/// [`v6_frag_to_v4`] for a fragment larger than `mtu4`: re-split into
/// IPv4 fragments appended to `sink` (`pkt` is the IPv6 fragment).
pub fn v6_frag_to_v4_split(
    pkt: &[u8],
    h: &Ipv6Hdr,
    src: u32,
    dst: u32,
    mtu4: u16,
    sink: &mut FragSink<'_>,
) -> Result<(), XlatError> {
    let f = h.frag.ok_or(XlatError::Untranslatable)?;
    let payload = pkt.get(h.l4_off..h.total_len()).ok_or(XlatError::Truncated)?;
    let h4 = Hdr4 { tos: h.traffic_class, ttl: h.hop_limit, proto: proto_6to4(h.proto), id: f.id as u16, src, dst };
    split_v4(payload, usize::from(f.offset) * 8, f.more, &h4, mtu4, sink)
}

/// Header-only translation of an IPv4 **non-first** fragment to IPv6 with a
/// Fragment Header, in place (the 48-byte header is written into the
/// headroom). Returns `TooBig` when the result exceeds `max_len` (use
/// [`v4_frag_to_v6_split`]).
///
/// COMPLIANCE MAPPING:
/// - RFC 7915 §4.1 - IPv4 fragment → Fragment Header (Identification =
///   IPv4 Identification, offset, M = MF); options dropped
/// - RFC 6146 §3.4 - non-first fragments use the first fragment's mapping
pub fn v4_frag_to_v6(
    buf: &mut [u8],
    start: usize,
    h: &Ipv4Hdr,
    src: u128,
    dst: u128,
    max_len: u16,
) -> Result<(usize, usize), XlatError> {
    let f = h.frag.ok_or(XlatError::Untranslatable)?;
    let len = h.payload_len();
    let total = FRAG6_HDR + len;
    if total > usize::from(max_len) {
        return Err(XlatError::TooBig);
    }
    let l4_start = start + h.hdr_len;
    let new_start = l4_start.checked_sub(FRAG6_HDR).ok_or(XlatError::Headroom)?;
    let o = buf.get_mut(new_start..l4_start).ok_or(XlatError::Truncated)?;
    write_v6_header(o, h.tos, (8 + len) as u16, proto::FRAGMENT, h.ttl, src, dst);
    o[40] = proto_4to6(h.proto);
    o[41] = 0;
    put16(o, 42, (f.offset << 3) | u16::from(f.more));
    put32(o, 44, f.id);
    Ok((new_start, total))
}

/// [`v4_frag_to_v6`] for a fragment larger than `max_len`: re-split into
/// IPv6 fragments appended to `sink` (`pkt` is the IPv4 fragment).
pub fn v4_frag_to_v6_split(
    pkt: &[u8],
    h: &Ipv4Hdr,
    src: u128,
    dst: u128,
    max_len: u16,
    sink: &mut FragSink<'_>,
) -> Result<(), XlatError> {
    let f = h.frag.ok_or(XlatError::Untranslatable)?;
    let payload = pkt.get(h.hdr_len..h.total_len).ok_or(XlatError::Truncated)?;
    let h6 = Hdr6 { tc: h.tos, hop: h.ttl, next: proto_4to6(h.proto), id: f.id, src, dst };
    split_v6(payload, usize::from(f.offset) * 8, f.more, &h6, max_len, sink)
}
