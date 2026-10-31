//! The RFC 7915 header rewrite for one established UDP packet, as pure
//! functions from the input header block to the output header block. The
//! payload is not touched: the eBPF program moves the packet start by
//! ±20 bytes (`bpf_xdp_adjust_head`) and writes the returned block in front
//! of it.
//!
//! The output equals the slow path's wire output (plan §2.4):
//! `plat_xlat::siit::{v6_to_v4, v4_to_v6}` with the session's addresses and
//! ports, the kernel's TTL / hop-limit decrement on the way into the TUN and
//! again on egress (the two-hop model, so output = input − 2), and the
//! Ethernet header the kernel builds from the FIB result. Addresses come
//! precomputed from the session record (no RFC 6052 code here).
//!
//! COMPLIANCE MAPPING:
//! - RFC 7915 §5.1 - IPv6→IPv4: DF set iff the result exceeds 1260 bytes,
//!   ID 0 when DF is set, TOS from the traffic class (`copy_tos`), no
//!   options
//! - RFC 7915 §4.1 - IPv4→IPv6: traffic class from TOS (`copy_tos`), flow
//!   label 0, no Fragment Header (fragments never reach the fast path)
//! - RFC 6146 §3.5.1 - addresses and ports from the session (BIB + remote)
//! - RFC 1624 - incremental UDP checksum update; RFC 768 - 0 sent as 0xFFFF
//! - RFC 1812 §5.3.1, RFC-007 - TTL / hop limit decremented once per hop,
//!   twice through the PLAT

use crate::csum;
use crate::{ETH, HDR4, HDR6, IP4, IP6};
use crate::{put, take};

/// RFC 7915 §5.1: an IPv4 result larger than this gets DF = 1.
pub const DF_THRESHOLD: u32 = 1260;

/// IPv6 → IPv4 output parameters, resolved by the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Out4Params {
    /// Next-hop MAC (FIB `dmac`).
    pub dmac: [u8; 6],
    /// Egress interface MAC (FIB `smac`).
    pub smac: [u8; 6],
    /// IPv4 TOS (the traffic class with `copy_tos`, else 0).
    pub tos: u8,
    /// Identification used when DF = 0 (ignored, and 0 sent, when DF = 1).
    pub ident: u16,
    pub pool4: [u8; 4],
    pub dst4: [u8; 4],
    pub pool_port4: [u8; 2],
}

/// IPv4 → IPv6 output parameters, resolved by the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Out6Params {
    pub dmac: [u8; 6],
    pub smac: [u8; 6],
    /// IPv6 traffic class (the TOS with `copy_tos`, else 0).
    pub traffic_class: u8,
    /// New source: the canonical RFC 6052 embedding of the remote.
    pub src6: [u8; 16],
    /// New destination: the subscriber.
    pub dst6: [u8; 16],
    /// New destination port: the subscriber's port.
    pub dport6: [u8; 2],
}

/// IPv4 total length of the translation of an IPv6 UDP packet with this
/// Payload Length.
#[inline(always)]
pub fn v4_total(payload_len: u16) -> u32 {
    IP4 as u32 + u32::from(payload_len)
}

/// Rewrites an accepted Ethernet + IPv6 + UDP header block (see
/// [`crate::classify_v6`]) to Ethernet + IPv4 + UDP. The caller guarantees
/// hop limit > 2 and a total length ≤ 65535 (both checked by the
/// decision); outside that the result is well-defined but meaningless.
#[inline(always)]
pub fn rewrite_v6_to_v4(h: &[u8; HDR6], p: &Out4Params) -> [u8; HDR4] {
    let [plen0, plen1, _, hop] = take::<HDR6, 4>(h, ETH + 4);
    let src6: [u8; 16] = take(h, ETH + 8);
    let dst6: [u8; 16] = take(h, ETH + 24);
    let u = ETH + IP6;
    let sport: [u8; 2] = take(h, u);
    let dport: [u8; 2] = take(h, u + 2);
    let ulen: [u8; 2] = take(h, u + 4);
    let old_c = u16::from_be_bytes(take(h, u + 6));

    let total = v4_total(u16::from_be_bytes([plen0, plen1]));
    let df = total > DF_THRESHOLD;
    let ident = if df { 0 } else { p.ident };

    let mut ip = [0u8; IP4];
    put(&mut ip, 0, &[0x45, p.tos]);
    put(&mut ip, 2, &(total as u16).to_be_bytes());
    put(&mut ip, 4, &ident.to_be_bytes());
    put(&mut ip, 6, &[if df { 0x40 } else { 0 }, 0, hop.saturating_sub(2), crate::classify::PROTO_UDP]);
    put(&mut ip, 12, &p.pool4);
    put(&mut ip, 16, &p.dst4);
    let hc = csum::ipv4_header_csum(&ip);
    put(&mut ip, 10, &hc.to_be_bytes());

    // The pseudo-header length and protocol are identical in both
    // families, so only addresses and ports enter the adjustment
    // (`plat_xlat::siit::l4_6to4`).
    let old = csum::sum(&src6) + csum::sum(&dst6) + csum::sum(&sport) + csum::sum(&dport);
    let new = csum::sum(&p.pool4) + csum::sum(&p.dst4) + csum::sum(&p.pool_port4) + csum::sum(&dport);
    let c = csum::udp_nonzero(csum::adjust(old_c, old, new));

    let mut o = [0u8; HDR4];
    put(&mut o, 0, &p.dmac);
    put(&mut o, 6, &p.smac);
    put(&mut o, 12, &[0x08, 0x00]);
    put(&mut o, ETH, &ip);
    let u4 = ETH + IP4;
    put(&mut o, u4, &p.pool_port4);
    put(&mut o, u4 + 2, &dport);
    put(&mut o, u4 + 4, &ulen);
    put(&mut o, u4 + 6, &c.to_be_bytes());
    o
}

/// Rewrites an accepted Ethernet + IPv4 + UDP header block (see
/// [`crate::classify_v4`]) to Ethernet + IPv6 + UDP. The caller guarantees
/// TTL > 2 and a non-zero UDP checksum.
#[inline(always)]
pub fn rewrite_v4_to_v6(h: &[u8; HDR4], p: &Out6Params) -> [u8; HDR6] {
    let ip: [u8; IP4] = take(h, ETH);
    let [_, _, t0, t1, _, _, _, _, ttl, ..] = ip;
    let src4: [u8; 4] = take(&ip, 12);
    let dst4: [u8; 4] = take(&ip, 16);
    let u = ETH + IP4;
    let sport: [u8; 2] = take(h, u);
    let dport: [u8; 2] = take(h, u + 2);
    let ulen: [u8; 2] = take(h, u + 4);
    let old_c = u16::from_be_bytes(take(h, u + 6));
    let payload_len = u16::from_be_bytes([t0, t1]).saturating_sub(IP4 as u16);

    let mut ip6 = [0u8; IP6];
    put(&mut ip6, 0, &((6u32 << 28) | (u32::from(p.traffic_class) << 20)).to_be_bytes());
    put(&mut ip6, 4, &payload_len.to_be_bytes());
    put(&mut ip6, 6, &[crate::classify::PROTO_UDP, ttl.saturating_sub(2)]);
    put(&mut ip6, 8, &p.src6);
    put(&mut ip6, 24, &p.dst6);

    // `plat_xlat::siit::l4_4to6`, non-zero checksum case.
    let old = csum::sum(&src4) + csum::sum(&dst4) + csum::sum(&sport) + csum::sum(&dport);
    let new = csum::sum(&p.src6) + csum::sum(&p.dst6) + csum::sum(&sport) + csum::sum(&p.dport6);
    let c = csum::udp_nonzero(csum::adjust(old_c, old, new));

    let mut o = [0u8; HDR6];
    put(&mut o, 0, &p.dmac);
    put(&mut o, 6, &p.smac);
    put(&mut o, 12, &[0x86, 0xdd]);
    put(&mut o, ETH, &ip6);
    let u6 = ETH + IP6;
    put(&mut o, u6, &sport);
    put(&mut o, u6 + 2, &p.dport6);
    put(&mut o, u6 + 4, &ulen);
    put(&mut o, u6 + 6, &c.to_be_bytes());
    o
}
