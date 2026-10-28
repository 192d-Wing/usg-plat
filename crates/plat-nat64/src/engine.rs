//! Per-packet processing: validate → policy → state → translate.

use std::sync::Arc;

use plat_audit::AuditSink;
use plat_common::config::Filtering;
use plat_common::{Clock, Config, Counter, Counters, DropReason, Ipv4Cidr, Ipv6Cidr};
use plat_packet::{Ipv4Hdr, Ipv6Hdr, L4, ParseError, parse_l4, parse_v4, parse_v6, proto};
use plat_xlat::icmp::{
    self, icmp4_err_to_v6, icmp4_error_local, icmp6_err_to_v4, icmp6_error_local, quoted_v4, quoted_v6,
};
use plat_xlat::rfc6052::{is_never_translatable_v4, is_non_global_v4};
use plat_xlat::siit::FRAG6_HDR;
use plat_xlat::{Frags, Map4, Map6, Prefix6052, XlatError, v4_to_v6, v4_to_v6_fragments, v6_to_v4};

use crate::state::{Key4, Key6, State};
use crate::tcp::{self, Side};

/// Result of processing one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Transmit `buf[start..start + len]`.
    Forward {
        start: usize,
        len: usize,
    },
    /// Transmit each packet of [`WorkerCtx::fragments`], in order (RFC 7915
    /// §4 translator fragmentation). `count` is at most [`MAX_FRAGMENTS`].
    ForwardFragments {
        count: usize,
    },
    Drop(DropReason),
}

/// Bytes reserved per worker for translator-generated IPv6 fragments: a
/// 65535-byte IPv4 datagram split at the 1280-byte minimum is 54 fragments,
/// 65515 bytes of payload plus 54 × 48 bytes of headers.
pub const FRAG_OUT_BYTES: usize = 72 * 1024;
/// Upper bound on fragments per packet (at `lowest_ipv6_mtu` = 1280).
pub const MAX_FRAGMENTS: usize = 65535_usize.div_ceil(1280 - FRAG6_HDR);

/// Per-worker scratch state. Owned by exactly one thread.
#[derive(Debug)]
pub struct WorkerCtx {
    pub counters: Arc<Counters>,
    ident: u16,
    scratch: Box<[u8]>,
    frag_out: Box<[u8]>,
    frags: Frags,
    /// Token bucket for locally generated ICMP errors.
    icmp_tokens: u32,
    icmp_last_ms: u64,
}

impl WorkerCtx {
    pub fn new(counters: Arc<Counters>, seed: u16) -> Self {
        Self {
            counters,
            ident: seed,
            scratch: vec![0u8; 2048].into_boxed_slice(),
            frag_out: vec![0u8; FRAG_OUT_BYTES].into_boxed_slice(),
            frags: Frags::default(),
            icmp_tokens: 0,
            icmp_last_ms: u64::MAX,
        }
    }

    #[inline]
    // POAM: POAM-011 the IPv4 Identification is a sequential per-worker
    // counter, so a remote observer can infer a worker's packet rate.
    fn next_ident(&mut self) -> u16 {
        self.ident = self.ident.wrapping_add(1);
        self.ident
    }

    /// The fragments of the last [`Verdict::ForwardFragments`].
    pub fn fragments(&self) -> impl Iterator<Item = &[u8]> + '_ {
        let f = self.frags;
        (0..f.count).filter_map(move |i| {
            let s = i * f.frag_len;
            let l = if i + 1 == f.count { f.last_len } else { f.frag_len };
            self.frag_out.get(s..s + l)
        })
    }

    /// Takes one token for a locally generated ICMP error (`rate` per
    /// second, burst `rate`). No allocation, no shared state. The bucket is
    /// per worker, so the node-wide ceiling is `workers × rate`.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 4443 §2.4(f), RFC 1812 §4.3.2.8 - ICMP error rate limiting
    /// - NIST 800-53: SC-5 - bounded reflection volume
    fn icmp_token(&mut self, now_ms: u64, rate: u32) -> bool {
        if rate == 0 {
            return false;
        }
        if self.icmp_last_ms == u64::MAX {
            self.icmp_tokens = rate;
            self.icmp_last_ms = now_ms;
        }
        let add = now_ms.saturating_sub(self.icmp_last_ms).saturating_mul(u64::from(rate)) / 1000;
        if add > 0 {
            let tokens = (u64::from(self.icmp_tokens) + add).min(u64::from(rate));
            self.icmp_tokens = tokens as u32;
            // PERF-106: advance only by the time the added tokens represent,
            // so the remainder carries over (a full bucket restarts at now).
            self.icmp_last_ms = if tokens == u64::from(rate) {
                now_ms
            } else {
                self.icmp_last_ms + (add * 1000).div_ceil(u64::from(rate))
            };
        }
        if self.icmp_tokens > 0 {
            self.icmp_tokens -= 1;
            true
        } else {
            false
        }
    }
}

fn from_parse(e: ParseError) -> DropReason {
    match e {
        ParseError::BadHeaderChecksum => DropReason::BadChecksum,
        ParseError::UnsupportedProto | ParseError::UnsupportedExtHeader | ParseError::RoutingHeaderActive => {
            DropReason::UnsupportedProto
        }
        ParseError::SourceRouteActive => DropReason::SourceRoute,
        _ => DropReason::Malformed,
    }
}

fn from_xlat(e: XlatError) -> DropReason {
    match e {
        XlatError::Headroom | XlatError::Truncated => DropReason::Malformed,
        XlatError::ZeroUdpChecksum => DropReason::BadChecksum,
        XlatError::FragmentNeedsReassembly | XlatError::NonFirstFragment => DropReason::Fragment,
        XlatError::Untranslatable => DropReason::IcmpUntranslatable,
        XlatError::TooBig => DropReason::TooBig,
    }
}

/// What a processing step produced.
enum Out {
    Pkt(usize, usize),
    Frags(usize),
}

type R = Result<Out, DropReason>;

/// The stateful NAT64 translator.
#[derive(Debug)]
pub struct Nat64 {
    state: State,
    prefix: Prefix6052,
    clients: Vec<Ipv6Cidr>,
    /// The whole cluster pool (for `WrongNode` accounting).
    cluster_pool: Vec<Ipv4Cidr>,
    sub_mask: u128,
    filtering: Filtering,
    mtu4: u16,
    mtu6: u16,
    /// RFC 7915 §4 lowest-ipv6-mtu, capped at `mtu6`.
    frag6: u16,
    icmp_rate: u32,
    copy_tos: bool,
    wkp_non_global_icmp: bool,
    /// Non-global IPv4 destinations are refused (WKP: always; NSP: unless
    /// `translation.allow_non_global_destinations`).
    deny_non_global_dst: bool,
}

impl Nat64 {
    /// `owned` is this node's slice of the IPv4 pool.
    pub fn new(cfg: &Config, owned: Vec<u32>, audit: AuditSink, clock: Clock) -> Result<Self, String> {
        let t = &cfg.translation;
        let prefix = Prefix6052::new(t.nat64_prefix.network(), t.nat64_prefix.prefix_len())
            .ok_or_else(|| format!("invalid RFC 6052 prefix {}", t.nat64_prefix))?;
        if owned.is_empty() {
            return Err("this node owns no pool addresses".into());
        }
        Ok(Self {
            state: State::new(cfg, owned, audit, clock),
            clients: t.client_prefixes.clone(),
            cluster_pool: cfg.nat64.pool.clone(),
            sub_mask: Ipv6Cidr::mask_of(cfg.nat64.subscriber_prefix_len),
            filtering: cfg.nat64.filtering,
            mtu4: t.ipv4_mtu,
            mtu6: t.ipv6_mtu,
            frag6: t.lowest_ipv6_mtu.min(t.ipv6_mtu),
            icmp_rate: t.icmp_errors_per_sec,
            copy_tos: t.copy_tos,
            wkp_non_global_icmp: t.wkp_non_global_icmp_errors,
            deny_non_global_dst: prefix.is_wkp() || !t.allow_non_global_destinations,
            prefix,
        })
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// Processes the packet at `buf[start..start + len]`. `start` must leave
    /// at least [`plat_xlat::HEADROOM`] bytes in front of the packet.
    #[inline]
    pub fn process(&self, buf: &mut [u8], start: usize, len: usize, ctx: &mut WorkerCtx) -> Verdict {
        let r = match buf.get(start).map(|b| b >> 4) {
            Some(6) => self.outbound_v6(buf, start, len, ctx),
            Some(4) => self.inbound_v4(buf, start, len, false, ctx),
            _ => Err(DropReason::Malformed),
        };
        match r {
            Ok(Out::Pkt(start, len)) => Verdict::Forward { start, len },
            Ok(Out::Frags(count)) => Verdict::ForwardFragments { count },
            Err(d) => {
                ctx.counters.record_drop(d);
                Verdict::Drop(d)
            }
        }
    }

    #[inline]
    fn is_client(&self, a: u128) -> bool {
        self.clients.iter().any(|c| c.contains(a))
    }

    /// IPv4 destinations a subscriber may not reach.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-7, SC-7(5) - never-translatable space is
    ///   unreachable; non-global space is denied by default under every
    ///   prefix (`translation.allow_non_global_destinations` opts out for a
    ///   network-specific prefix)
    /// - RFC 6052 §3.1 - the WKP must not reach non-global IPv4 space
    ///
    /// The cluster's own pool is exempt from the non-global test, so a
    /// non-global pool (TEST-NET, 100.64/10, RFC 1918) still hairpins
    /// (RFC 6146 §3.8, RFC 4787 REQ-9). Config validation rejects
    /// never-translatable pools and the WKP with a non-global pool.
    #[inline]
    fn dst_forbidden(&self, a: u32) -> bool {
        is_never_translatable_v4(a) || (self.deny_non_global_dst && self.non_global_foreign(a))
    }

    /// Non-global IPv4 address (RFC 6890) outside the cluster pool. The pool
    /// test only runs for non-global addresses, so global traffic pays one
    /// table check.
    #[inline]
    fn non_global_foreign(&self, a: u32) -> bool {
        is_non_global_v4(a) && !self.cluster_pool.iter().any(|c| c.contains(a))
    }

    /// IPv6 → IPv4 (outbound from the CLAT side).
    fn outbound_v6(&self, buf: &mut [u8], start: usize, len: usize, ctx: &mut WorkerCtx) -> R {
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let h = parse_v6(pkt).map_err(from_parse)?;
        if h.hop_limit <= 1 {
            // POAM: POAM-002 generate ICMPv6 Time Exceeded (rate-limited).
            return Err(DropReason::HopLimit);
        }
        if h.frag.is_some_and(|f| !f.is_first()) {
            // POAM: POAM-001 fragment tracking/reassembly (RFC 6146 §3.4).
            return Err(DropReason::Fragment);
        }
        let l4 = parse_l4(pkt, h.l4_off, h.total_len(), h.proto).map_err(from_parse)?;
        if let L4::Icmp { ty, .. } = l4
            && icmp::is_icmp6_error(ty)
        {
            // Errors come from routers that need not be inside the client
            // prefixes (BNG, CPE WAN); icmp6_error applies its own checks.
            return self.icmp6_error(buf, start, len, ctx);
        }
        // COMPLIANCE MAPPING:
        // - NIST 800-53: SC-7 - only configured client prefixes may translate
        if !self.is_client(h.src) {
            return Err(DropReason::SrcNotAllowed);
        }
        let dst4 = self.prefix.extract(h.dst).ok_or(DropReason::DstNotTranslatable)?;
        if self.dst_forbidden(dst4) {
            return Err(DropReason::DstForbidden);
        }
        // Everything that can still reject the packet is checked before
        // `bib_for`, so a dropped packet creates no BIB, port or audit record
        // (QA-002 / RFC 6146 §3.5.2.2).
        let (p, sport, dport, flags) = match l4 {
            L4::Tcp { sport, dport, flags } => (proto::TCP, sport, dport, flags),
            L4::Udp { csum: 0, .. } => return Err(DropReason::BadChecksum),
            L4::Udp { sport, dport, .. } => (proto::UDP, sport, dport, 0),
            L4::Icmp { ty: 128 | 129, .. } if h.frag.is_some() => return Err(DropReason::Fragment),
            L4::Icmp { ty: 128 | 129, id, .. } => (proto::ICMP, id, 0, 0),
            L4::Icmp { .. } => return Err(DropReason::UnsupportedProto),
        };
        if 20 + h.l4_len() > usize::from(self.mtu4) {
            return self.too_big_v6(buf, start, len, &h, ctx);
        }

        let k6 = Key6 { proto: p, addr: h.src, port: sport };
        let create = p != proto::TCP || tcp::initial(Side::V6, flags).is_some();
        let mut k4 = self.state.bib_for(k6, create, &ctx.counters)?;
        if let Err(e) = self.state.outbound(k4, (dst4, dport), flags, &ctx.counters) {
            if e != DropReason::NoBinding {
                return Err(e);
            }
            // BIB expired between lookup and session update; recreate once.
            k4 = self.state.bib_for(k6, create, &ctx.counters)?;
            self.state.outbound(k4, (dst4, dport), flags, &ctx.counters)?;
        }

        let m = Map4 { src: k4.addr, dst: dst4, sport: k4.port, dport };
        let ident = ctx.next_ident();
        let mut h = h;
        if !self.copy_tos {
            h.traffic_class = 0;
        }
        let (s, l) = v6_to_v4(buf, start, &h, &m, ident, self.mtu4).map_err(from_xlat)?;
        ctx.counters.inc(Counter::V6ToV4);
        if self.state.pool.index(dst4).is_some() {
            // RFC 6146 §3.8 hairpinning: loop the IPv4 result back inbound.
            ctx.counters.inc(Counter::Hairpin);
            return self.inbound_v4(buf, s, l, true, ctx);
        }
        Ok(Out::Pkt(s, l))
    }

    /// An IPv6 packet whose translation exceeds the IPv4 MTU: answer with a
    /// rate-limited ICMPv6 Packet Too Big (IPv6 never fragments en route).
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7915 §5 / RFC 4443 §3.2 - Packet Too Big for oversize packets
    fn too_big_v6(&self, buf: &mut [u8], start: usize, len: usize, h: &Ipv6Hdr, ctx: &mut WorkerCtx) -> R {
        if h.total_len() <= 1280 {
            // POAM: POAM-002 a packet within the IPv6 minimum MTU must be
            // fragmented as IPv4 (RFC 7915 §5.1) when ipv4_mtu < 1260.
            return Err(DropReason::TooBig);
        }
        if !ctx.icmp_token(self.state.now_ms(), self.icmp_rate) {
            ctx.counters.inc(Counter::IcmpErrorsRateLimited);
            return Err(DropReason::TooBig);
        }
        // Largest IPv6 packet whose IPv4 translation (20-byte header replaces
        // the IPv6 header and extension headers) fits `mtu4`.
        let mtu = (u32::from(self.mtu4) - 20 + h.l4_off as u32).max(1280);
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let n = icmp6_error_local(pkt, h, h.dst, 2, 0, mtu, &mut ctx.scratch).map_err(from_xlat)?;
        ctx.counters.record_drop(DropReason::TooBig);
        Self::emit_scratch(buf, start, n, ctx, Counter::IcmpErrorsGenerated)
    }

    /// An IPv4 DF packet whose translation exceeds the IPv6 MTU: answer with
    /// a rate-limited ICMPv4 Fragmentation Needed from the pool address.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7915 §4 / RFC 1191 - Fragmentation Needed, MTU = IPv6 MTU − 20
    ///   (− 28 when a Fragment Header is added)
    fn frag_needed_v4(&self, buf: &mut [u8], start: usize, h: &Ipv4Hdr, fh: usize, ctx: &mut WorkerCtx) -> R {
        if !ctx.icmp_token(self.state.now_ms(), self.icmp_rate) {
            ctx.counters.inc(Counter::IcmpErrorsRateLimited);
            return Err(DropReason::TooBig);
        }
        let mtu = (usize::from(self.mtu6) - 20 - fh).max(68) as u32;
        let ident = ctx.next_ident();
        let pkt = buf.get(start..start + h.total_len).ok_or(DropReason::Malformed)?;
        let n = icmp4_error_local(pkt, h, h.dst, 3, 4, mtu, ident, &mut ctx.scratch).map_err(from_xlat)?;
        ctx.counters.record_drop(DropReason::TooBig);
        Self::emit_scratch(buf, start, n, ctx, Counter::IcmpErrorsGenerated)
    }

    /// IPv4 → IPv6 (inbound to the CLAT side). `hairpin` is true only for
    /// an own-node hairpin looped back in-process by `outbound_v6`; packets
    /// read from the wire pass `false`.
    fn inbound_v4(&self, buf: &mut [u8], start: usize, len: usize, hairpin: bool, ctx: &mut WorkerCtx) -> R {
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let h = parse_v4(pkt).map_err(from_parse)?;
        if h.ttl <= 1 {
            return Err(DropReason::HopLimit);
        }
        if h.frag.is_some_and(|f| !f.is_first()) {
            // POAM: POAM-001 fragment tracking/reassembly (RFC 6146 §3.4).
            return Err(DropReason::Fragment);
        }
        if self.state.pool.index(h.dst).is_none() {
            // SI-4: another cluster node owns it (mis-steered return
            // traffic), or it was never pooled.
            return Err(if self.cluster_pool.iter().any(|c| c.contains(h.dst)) {
                DropReason::WrongNode
            } else {
                DropReason::NoBinding
            });
        }
        let l4 = parse_l4(pkt, h.hdr_len, h.total_len, h.proto).map_err(from_parse)?;
        let is_err = matches!(l4, L4::Icmp { ty, .. } if icmp::is_icmp4_error(ty));
        // COMPLIANCE MAPPING:
        // - NIST 800-53: SC-7 - never-translatable sources are refused; with
        //   non-global destinations denied (the default), non-global data
        //   sources are refused too, so EIF admits no remote the subscriber
        //   could not answer (RFC-202 / SEC-203). ICMP errors from
        //   non-global routers stay accepted under an NSP (PMTUD).
        // - RFC 6052 §3.1 - under the WKP, non-global sources are refused;
        //   ICMP errors from such routers only with the explicit
        //   `translation.wkp_non_global_icmp_errors` deviation switch.
        // - RFC 6146 §3.8 - the cluster pool is exempt, so hairpinned
        //   packets (source = a pool address) pass.
        let src_refused = is_never_translatable_v4(h.src)
            || (self.deny_non_global_dst
                && self.non_global_foreign(h.src)
                && if self.prefix.is_wkp() { !(is_err && self.wkp_non_global_icmp) } else { !is_err });
        if src_refused {
            return Err(DropReason::SrcNotAllowed);
        }
        // COMPLIANCE MAPPING:
        // - NIST 800-53: SC-7, SC-7(5) - BCP 38 / RFC 2827: own-node
        //   hairpins never touch the wire (`outbound_v6` loops them back
        //   in-process), so a wire packet claiming this node's own pool slice
        //   as its source is spoofed and refused (SEC-301). Other nodes'
        //   slices stay accepted for cross-node hairpinning; the cluster edge
        //   must filter the pool prefix as a source on external ingress.
        if !hairpin && self.state.pool.index(h.src).is_some() {
            return Err(DropReason::SrcNotAllowed);
        }
        let (p, sport, dport, flags) = match l4 {
            L4::Tcp { sport, dport, flags } => (proto::TCP, sport, dport, flags),
            L4::Udp { sport, dport, .. } => (proto::UDP, sport, dport, 0),
            L4::Icmp { .. } if is_err => return self.icmp4_error(buf, start, len, ctx),
            L4::Icmp { ty: 0 | 8, .. } if h.frag.is_some() => return Err(DropReason::Fragment),
            L4::Icmp { ty: 0 | 8, id, .. } => (proto::ICMP, 0, id, 0),
            L4::Icmp { .. } => return Err(DropReason::UnsupportedProto),
        };
        let k4 = Key4 { proto: p, addr: h.dst, port: dport };
        let k6 = self.state.inbound(k4, (h.src, sport), flags, &ctx.counters)?;
        let m = Map6 { src: self.prefix.embed(h.src), dst: k6.addr, sport, dport: k6.port };
        let mut h = h;
        if !self.copy_tos {
            h.tos = 0;
        }
        let fh = if h.frag.is_some() { 8 } else { 0 };
        let out_len = 40 + fh + h.payload_len();
        if out_len > usize::from(self.mtu6) || (!h.df && out_len > usize::from(self.frag6)) {
            if h.df {
                // POAM: POAM-023 the session lookup above runs before this
                // Fragmentation Needed decision, so a too-big DF packet
                // refreshes (or, under EIF, creates) a session it never uses.
                return self.frag_needed_v4(buf, start, &h, fh, ctx);
            }
            // COMPLIANCE MAPPING:
            // - RFC 7915 §4 - DF=0 packets are fragmented to lowest-ipv6-mtu
            let f = v4_to_v6_fragments(buf, start, &h, &m, self.frag6, &mut ctx.frag_out).map_err(from_xlat)?;
            ctx.frags = f;
            ctx.counters.inc(Counter::V4ToV6);
            ctx.counters.inc(Counter::FragmentedV4ToV6);
            return Ok(Out::Frags(f.count));
        }
        let (s, l) = v4_to_v6(buf, start, &h, &m, self.mtu6).map_err(from_xlat)?;
        ctx.counters.inc(Counter::V4ToV6);
        Ok(Out::Pkt(s, l))
    }

    /// Copies a packet built in scratch back into `buf`.
    fn emit_scratch(buf: &mut [u8], start: usize, n: usize, ctx: &WorkerCtx, c: Counter) -> R {
        let dest = start.saturating_sub(40);
        let out = buf.get_mut(dest..dest + n).ok_or(DropReason::Malformed)?;
        out.copy_from_slice(ctx.scratch.get(..n).ok_or(DropReason::Malformed)?);
        ctx.counters.inc(c);
        Ok(Out::Pkt(dest, n))
    }

    /// ICMPv6 error about a packet we previously translated v4→v6.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-7 - the quoted packet must match a live session of
    ///   the subscriber it names, and its IPv4 destination passes the same
    ///   policy as ordinary outbound traffic (no relay to forbidden space)
    /// - NIST 800-53: SC-7, AU-10 - every translated error leaves from the
    ///   affected mapping's pool address; the sender cannot choose it
    /// - RFC 6146 §3.5.3, RFC 7915 §5.2, RFC 6791 (source of errors from
    ///   non-translatable IPv6 addresses)
    fn icmp6_error(&self, buf: &mut [u8], start: usize, len: usize, ctx: &mut WorkerCtx) -> R {
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let h = parse_v6(pkt).map_err(from_parse)?;
        if h.frag.is_some() {
            return Err(DropReason::Fragment);
        }
        // Stateful NAT64: IPv4 hosts never sit on the IPv6 side, so an IPv6
        // source inside the NAT64 prefix is spoofed (hairpins are refused
        // below). SEC-101 / NIST-103 / RFC-101.
        // `contains`, not `extract`: a non-zero u-octet must not bypass this
        // (RFC-203).
        if self.prefix.contains(h.src) {
            return Err(DropReason::SrcNotAllowed);
        }
        let (ih, il4) = quoted_v6(pkt, &h).map_err(from_xlat)?;
        // Quoted: src = synthesized server, dst = subscriber. The error must
        // be addressed to the quoted packet's source.
        if ih.src != h.dst {
            return Err(DropReason::Filtered);
        }
        let server4 = self.prefix.extract(ih.src).ok_or(DropReason::DstNotTranslatable)?;
        if self.dst_forbidden(server4) {
            return Err(DropReason::DstForbidden);
        }
        if self.state.pool.index(server4).is_some() {
            // Errors about hairpinned flows are not translated.
            return Err(DropReason::Filtered);
        }
        if !self.is_client(ih.dst) {
            return Err(DropReason::SrcNotAllowed);
        }
        // A subscriber may only report errors about its own flows; routers
        // outside the client prefixes may report about any subscriber.
        if self.is_client(h.src) && (h.src ^ ih.dst) & self.sub_mask != 0 {
            return Err(DropReason::Filtered);
        }
        let (p, q_sport, q_dport) = match il4 {
            L4::Tcp { sport, dport, .. } => (proto::TCP, sport, dport),
            L4::Udp { sport, dport, .. } => (proto::UDP, sport, dport),
            L4::Icmp { id, .. } => (proto::ICMP, id, id),
        };
        let k4 = self.state.lookup6(Key6 { proto: p, addr: ih.dst, port: q_dport }).ok_or(DropReason::NoBinding)?;
        let remote = if p == proto::ICMP { (server4, 0) } else { (server4, q_sport) };
        if !self.state.has_session(k4, remote) {
            return Err(DropReason::Filtered);
        }
        let inner = if p == proto::ICMP {
            Map4 { src: server4, dst: k4.addr, sport: k4.port, dport: 0 }
        } else {
            Map4 { src: server4, dst: k4.addr, sport: q_sport, dport: k4.port }
        };
        // RFC 6791: the error is sent from the pool address of the affected
        // mapping (the IPv6 source is never translatable here, see above).
        let (mut h, mut ih) = (h, ih);
        if !self.copy_tos {
            // RFC-104: the switch applies to translated errors too.
            h.traffic_class = 0;
            ih.traffic_class = 0;
        }
        let ident = ctx.next_ident();
        let n =
            icmp6_err_to_v4(pkt, &h, &ih, (k4.addr, server4), &inner, ident, self.mtu4, self.mtu6, &mut ctx.scratch)
                .map_err(from_xlat)?;
        Self::emit_scratch(buf, start, n, ctx, Counter::IcmpErrorsTranslated)
    }

    /// ICMPv4 error about a packet we previously translated v6→v4.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-7 - the quoted flow must pass the configured
    ///   filtering (a live session under ADF/APDF; the BIB under EIF)
    /// - RFC 6146 §3.5.1.2 / §3.5.3, RFC 7915 §4.2
    fn icmp4_error(&self, buf: &mut [u8], start: usize, len: usize, ctx: &mut WorkerCtx) -> R {
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let h = parse_v4(pkt).map_err(from_parse)?;
        let (ih, il4) = quoted_v4(pkt, &h).map_err(from_xlat)?;
        // Quoted: src = our pool address, dst = server.
        if ih.src != h.dst {
            return Err(DropReason::Filtered);
        }
        let (p, q_sport, q_dport) = match il4 {
            L4::Tcp { sport, dport, .. } => (proto::TCP, sport, dport),
            L4::Udp { sport, dport, .. } => (proto::UDP, sport, dport),
            L4::Icmp { id, .. } => (proto::ICMP, id, id),
        };
        let remote = match self.filtering {
            Filtering::EndpointIndependent => None,
            _ => Some(if p == proto::ICMP { (ih.dst, 0) } else { (ih.dst, q_dport) }),
        };
        let k6 = self.state.lookup4_session(Key4 { proto: p, addr: ih.src, port: q_sport }, remote)?;
        let inner = if p == proto::ICMP {
            Map6 { src: k6.addr, dst: self.prefix.embed(ih.dst), sport: 0, dport: k6.port }
        } else {
            Map6 { src: k6.addr, dst: self.prefix.embed(ih.dst), sport: k6.port, dport: q_dport }
        };
        let outer = (self.prefix.embed(h.src), k6.addr);
        let (mut h, mut ih) = (h, ih);
        if !self.copy_tos {
            h.tos = 0;
            ih.tos = 0;
        }
        let n =
            icmp4_err_to_v6(pkt, &h, &ih, outer, &inner, self.mtu4, self.mtu6, &mut ctx.scratch).map_err(from_xlat)?;
        Self::emit_scratch(buf, start, n, ctx, Counter::IcmpErrorsTranslated)
    }
}
