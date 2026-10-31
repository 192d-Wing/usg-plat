//! The RFC 7915 header rewrite for one established UDP packet, as pure
//! functions from the input header block to an output header block the
//! caller provides (one per-packet stack buffer, every byte overwritten;
//! no intermediate IPv4/IPv6 header copies, PERF-001). The payload is not
//! touched: the eBPF program moves the packet start by ±20 bytes
//! (`bpf_xdp_adjust_head`) and copies the block in front of it.
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

use crate::abi::{FibParams, SlotRec};
use crate::classify::PROTO_UDP;
use crate::csum;
use crate::{ETH, HDR4, HDR6, IP4, IP6};
use crate::{put, take};

/// RFC 7915 §5.1: an IPv4 result larger than this gets DF = 1.
pub const DF_THRESHOLD: u32 = 1260;

/// IPv4 total length of the translation of an IPv6 UDP packet with this
/// Payload Length.
#[inline(always)]
pub fn v4_total(payload_len: u16) -> u32 {
    IP4 as u32 + u32::from(payload_len)
}

/// Rewrites an accepted Ethernet + IPv6 + UDP header block `h` (see
/// [`crate::classify_v6`]) to Ethernet + IPv4 + UDP in `o`, with the MACs
/// of the FIB result `fib`, the addresses and pool port of the session
/// `rec`, the IPv4 `tos` and the Identification `ident` (used only when
/// DF = 0; ID 0 is sent with DF = 1). The caller guarantees hop limit > 2
/// and a total length ≤ 65535 (both checked by the decision); outside that
/// the result is well-defined but meaningless.
#[inline(always)]
pub fn rewrite_v6_to_v4(h: &[u8; HDR6], o: &mut [u8; HDR4], fib: &FibParams, rec: &SlotRec, tos: u8, ident: u16) {
    let [plen0, plen1, _, hop] = take::<HDR6, 4>(h, ETH + 4);
    let u = ETH + IP6;
    let sport: [u8; 2] = take(h, u);
    let dport: [u8; 2] = take(h, u + 2);
    let ulen: [u8; 2] = take(h, u + 4);
    let old_c = u16::from_be_bytes(take(h, u + 6));

    let total = v4_total(u16::from_be_bytes([plen0, plen1])) as u16;
    let df = u32::from(total) > DF_THRESHOLD;
    let ident = if df { 0 } else { ident };
    let flags = if df { 0x40 } else { 0 };
    let ttl = hop.saturating_sub(2);

    // The header checksum from the scalar fields: equal to
    // `csum::ipv4_header_csum` of the header written below.
    let hs = csum::sum(&[0x45, tos])
        + u64::from(total)
        + u64::from(ident)
        + csum::sum(&[flags, 0])
        + csum::sum(&[ttl, PROTO_UDP])
        + csum::sum(&rec.pool4)
        + csum::sum(&rec.dst4);
    let hc = csum::finish(hs);

    // The pseudo-header length and protocol are identical in both
    // families, so only addresses and ports enter the adjustment
    // (`plat_xlat::siit::l4_6to4`). Source and destination are the 32
    // contiguous bytes at ETH + 8.
    let old = csum::sum_at(h, ETH + 8, 32) + csum::sum(&sport) + csum::sum(&dport);
    let new = csum::sum(&rec.pool4) + csum::sum(&rec.dst4) + csum::sum(&rec.pool_port4) + csum::sum(&dport);
    let c = csum::udp_nonzero(csum::adjust(old_c, old, new));

    put(o, 0, &fib.dmac);
    put(o, 6, &fib.smac);
    put(o, 12, &[0x08, 0x00]);
    put(o, ETH, &[0x45, tos]);
    put(o, ETH + 2, &total.to_be_bytes());
    put(o, ETH + 4, &ident.to_be_bytes());
    put(o, ETH + 6, &[flags, 0, ttl, PROTO_UDP]);
    put(o, ETH + 10, &hc.to_be_bytes());
    put(o, ETH + 12, &rec.pool4);
    put(o, ETH + 16, &rec.dst4);
    let u4 = ETH + IP4;
    put(o, u4, &rec.pool_port4);
    put(o, u4 + 2, &dport);
    put(o, u4 + 4, &ulen);
    put(o, u4 + 6, &c.to_be_bytes());
}

/// Rewrites an accepted Ethernet + IPv4 + UDP header block `h` (see
/// [`crate::classify_v4`]) to Ethernet + IPv6 + UDP in `o`: source the
/// canonical embedding `rec.dst6`, destination the subscriber `rec.src6`
/// and port `rec.sport6`, MACs from `fib`, traffic class `traffic_class`,
/// flow label 0. The caller guarantees TTL > 2.
///
/// Precondition (RFC 7915 §4.5): the UDP checksum is non-zero. An IPv4 UDP
/// checksum of 0 means "none computed"; the incremental update below would
/// turn it into a value that is not the packet's checksum (0xFFFF when it
/// computes to zero), so the output would be an IPv6 UDP datagram with an
/// invalid checksum. [`crate::classify_v4`] declines such packets
/// (`udp_zero_csum`) and the slow path computes the full checksum.
#[inline(always)]
pub fn rewrite_v4_to_v6(h: &[u8; HDR4], o: &mut [u8; HDR6], fib: &FibParams, rec: &SlotRec, traffic_class: u8) {
    let [_, _, t0, t1, _, _, _, _, ttl] = take::<HDR4, 9>(h, ETH);
    let u = ETH + IP4;
    let sport: [u8; 2] = take(h, u);
    let dport: [u8; 2] = take(h, u + 2);
    let ulen: [u8; 2] = take(h, u + 4);
    let old_c = u16::from_be_bytes(take(h, u + 6));
    let payload_len = u16::from_be_bytes([t0, t1]).saturating_sub(IP4 as u16);

    // `plat_xlat::siit::l4_4to6`, non-zero checksum case. Source and
    // destination are the 8 contiguous bytes at ETH + 12.
    let old = csum::sum_at(h, ETH + 12, 8) + csum::sum(&sport) + csum::sum(&dport);
    let new = csum::sum(&rec.dst6) + csum::sum(&rec.src6) + csum::sum(&sport) + csum::sum(&rec.sport6);
    let c = csum::udp_nonzero(csum::adjust(old_c, old, new));

    put(o, 0, &fib.dmac);
    put(o, 6, &fib.smac);
    put(o, 12, &[0x86, 0xdd]);
    put(o, ETH, &((6u32 << 28) | (u32::from(traffic_class) << 20)).to_be_bytes());
    put(o, ETH + 4, &payload_len.to_be_bytes());
    put(o, ETH + 6, &[PROTO_UDP, ttl.saturating_sub(2)]);
    put(o, ETH + 8, &rec.dst6);
    put(o, ETH + 24, &rec.src6);
    let u6 = ETH + IP6;
    put(o, u6, &sport);
    put(o, u6 + 2, &rec.sport6);
    put(o, u6 + 4, &ulen);
    put(o, u6 + 6, &c.to_be_bytes());
}
