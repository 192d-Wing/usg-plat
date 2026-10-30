//! Per-packet processing: validate → policy → state → translate.

use std::sync::Arc;

use plat_audit::AuditSink;
use plat_common::config::{Filtering, FragmentsConfig, UdpZeroChecksum};
use plat_common::{Clock, Config, Counter, Counters, DropReason, Ipv4Cidr, Ipv6Cidr};
use plat_packet::{
    Frag, Ipv4Hdr, Ipv6Hdr, L4, ParseError, parse_l4, parse_v4, parse_v4_ignore_source_route, parse_v6,
    parse_v6_ignore_routing, proto,
};
use plat_xlat::icmp::{
    self, icmp4_err_to_v6, icmp4_error_local, icmp6_err_to_v4, icmp6_error_local, quoted_v4, quoted_v6,
};
use plat_xlat::rfc6052::{is_never_translatable_v4, is_non_global_v4};
use plat_xlat::siit::{
    FRAG6_HDR, FragSink, proto_4to6, v4_frag_to_v6, v4_frag_to_v6_split, v6_frag_to_v4, v6_frag_to_v4_split,
    write_v6_header,
};
use plat_xlat::{
    Frags, HEADROOM, Map4, Map6, Prefix6052, XlatError, v4_to_v6, v4_to_v6_fragments, v6_to_v4, v6_to_v4_fragments,
};

use crate::frag::{Acct, FragKey, FragTable, Fwd, Kind, Reassembled, St};
use crate::ident::{IdentKey, IdentState};
use crate::repl::ReplProducer;
use crate::state::{ClusterSetup, Key4, Key6, Mapped, State};
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
    /// §4 translator fragmentation, fragments flushed from the out-of-order
    /// buffer, or a reassembled datagram). `count` is at most
    /// [`plat_xlat::siit::MAX_OUT`].
    ForwardFragments {
        count: usize,
    },
    /// Held in the worker's fragment state (an out-of-order fragment, or
    /// part of a datagram being reassembled); nothing to send yet.
    Consumed,
    Drop(DropReason),
}

/// Bytes reserved per worker for translator-generated fragments: a
/// 65535-byte IPv4 datagram split at the 1280-byte minimum is 54 fragments,
/// 65515 bytes of payload plus 54 × 48 bytes of headers.
pub const FRAG_OUT_BYTES: usize = 72 * 1024;
/// Upper bound on fragments per packet (at `lowest_ipv6_mtu` = 1280).
pub const MAX_FRAGMENTS: usize = 65535_usize.div_ceil(1280 - FRAG6_HDR);
/// Fragment-table sets scanned per housekeeping call.
const HOUSEKEEP_SETS: usize = 8;

/// Per-worker scratch state. Owned by exactly one thread.
#[derive(Debug)]
pub struct WorkerCtx {
    pub counters: Arc<Counters>,
    /// IPv4 Identification counter table (RFC 7739 §5.3, see
    /// [`crate::ident`]).
    ident: IdentState,
    scratch: Box<[u8]>,
    frag_out: Box<[u8]>,
    frags: Frags,
    /// Token bucket for locally generated ICMP errors.
    icmp_tokens: u32,
    icmp_last_ms: u64,
    /// This worker's replication ring (HA only).
    pub repl: Option<ReplProducer>,
    /// Fragment table, out-of-order buffer and reassembly slots.
    ftab: FragTable,
    /// Processing a reassembled datagram (translator fragmentation instead
    /// of Packet Too Big).
    reassembled: bool,
    /// Replaying a held fragment that was already accounted.
    replay: bool,
}

impl WorkerCtx {
    /// A worker context with the default `[translation.fragments]` limits.
    /// Daemon workers use [`Nat64::new_worker`].
    pub fn new(counters: Arc<Counters>, seed: u16) -> Self {
        Self::with_fragments(counters, seed, &FragmentsConfig::default())
    }

    /// Preallocates every per-worker buffer (SC-5: nothing is allocated
    /// per packet).
    pub fn with_fragments(counters: Arc<Counters>, seed: u16, f: &FragmentsConfig) -> Self {
        Self {
            counters,
            ident: IdentState::new(seed),
            scratch: vec![0u8; 2048.max(HEADROOM + usize::from(f.buffer_slot_bytes) + 64)].into_boxed_slice(),
            frag_out: vec![0u8; FRAG_OUT_BYTES].into_boxed_slice(),
            frags: Frags::default(),
            icmp_tokens: 0,
            icmp_last_ms: u64::MAX,
            repl: None,
            ftab: FragTable::new(f),
            reassembled: false,
            replay: false,
        }
    }

    /// Attaches this worker's replication ring (HA).
    pub fn with_repl(mut self, repl: ReplProducer) -> Self {
        self.repl = Some(repl);
        self
    }

    #[inline]
    fn sink(&mut self) -> FragSink<'_> {
        FragSink { frags: &mut self.frags, out: &mut self.frag_out }
    }

    /// The packets of the last [`Verdict::ForwardFragments`].
    pub fn fragments(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.frags.iter(&self.frag_out)
    }

    /// Live fragment-table entries.
    pub fn fragment_entries(&self) -> u32 {
        self.ftab.len()
    }

    /// Takes one token for a locally generated ICMP error (`rate` per
    /// second, burst `rate`). No allocation, no shared state. The bucket is
    /// per worker, so the node-wide ceiling is `workers × rate`.
    ///
    /// A quarter of the bucket is reserved for Packet Too Big /
    /// Fragmentation Needed (`pmtu`): other errors stop at the reserve, so
    /// a flood that triggers them cannot starve path MTU discovery.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 4443 §2.4(f), RFC 1812 §4.3.2.8 - ICMP error rate limiting
    /// - RFC 1191, RFC 8201 - PMTUD errors keep a reserved share
    /// - NIST 800-53: SC-5 - bounded reflection volume
    fn icmp_token(&mut self, now_ms: u64, rate: u32, pmtu: bool) -> bool {
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
        let floor = if pmtu { 0 } else { rate / 4 };
        if self.icmp_tokens > floor {
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
        ParseError::UnsupportedProto | ParseError::UnsupportedExtHeader | ParseError::RoutingHeaderActive { .. } => {
            DropReason::UnsupportedProto
        }
        ParseError::SourceRouteActive => DropReason::SourceRoute,
        ParseError::TinyFragment => DropReason::FragmentTiny,
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

/// A transport-header parse failure; for a first fragment, a header cut
/// short is a tiny fragment (RFC 1858, RFC 3128, RFC 7112).
fn l4_err(e: ParseError, frag: bool) -> DropReason {
    if frag && e == ParseError::Truncated { DropReason::FragmentTiny } else { from_parse(e) }
}

/// Size rules for every fragment: a non-last fragment carries a multiple of
/// 8 bytes, none is empty, and none reaches past 65535 bytes.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-10 - fragment offset/length validation
/// - RFC 791, RFC 8200 §4.5
fn frag_bounds(f: Frag, len: usize) -> Result<(), DropReason> {
    if len == 0 || (f.more && !len.is_multiple_of(8)) || usize::from(f.offset) * 8 + len > 65535 {
        return Err(DropReason::Malformed);
    }
    Ok(())
}

fn key6(h: &Ipv6Hdr, f: Frag) -> FragKey {
    FragKey { src: h.src, dst: h.dst, id: f.id, proto: h.proto, kind: Kind::V6In }
}

fn key4(h: &Ipv4Hdr, f: Frag) -> FragKey {
    FragKey { src: u128::from(h.src), dst: u128::from(h.dst), id: f.id, proto: h.proto, kind: Kind::V4In }
}

/// What a processing step produced.
enum Out {
    Pkt(usize, usize),
    Frags(usize),
    Held,
}

type R = Result<Out, DropReason>;

/// Engine mode, fixed at construction and dispatched once per packet in
/// [`Nat64::process`] (PERF-001): the legacy and sliced packet paths are
/// compiled separately, so HA-off code carries no ownership checks.
trait Mode {
    const SLICED: bool;
}

/// Legacy (static partition, no HA).
struct Legacy;
/// Sliced cluster pool (`cluster.partition = "slices"`).
struct SlicedPool;

impl Mode for Legacy {
    const SLICED: bool = false;
}

impl Mode for SlicedPool {
    const SLICED: bool = true;
}

/// A locally generated ICMP error: `(type, code, rest-of-header)`, the drop
/// reason recorded for the packet that triggered it, and the per-type
/// counter.
#[derive(Debug, Clone, Copy)]
struct LocalErr {
    msg: (u8, u8, u32),
    reason: DropReason,
    sent: Option<Counter>,
}

/// Which locally generated ICMP errors are enabled.
#[derive(Debug, Clone, Copy)]
struct IcmpGen {
    time_exceeded: bool,
    unreachable: bool,
    inbound_unreachable: bool,
    param_problem: bool,
    source_route_failed: bool,
}

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
    /// Sliced cluster pool: per-slice ownership checks apply.
    sliced: bool,
    icmp_rate: u32,
    icmp_gen: IcmpGen,
    copy_tos: bool,
    wkp_non_global_icmp: bool,
    /// Non-global IPv4 destinations are refused (WKP: always; NSP: unless
    /// `translation.allow_non_global_destinations`).
    deny_non_global_dst: bool,
    /// Boot-random key of the IPv4 Identification counter table (RFC 7739 §5.3).
    ident_key: IdentKey,
    frag_cfg: FragmentsConfig,
    udp_zero_reassemble: bool,
    /// `translation.cross_node_hairpin`: other nodes' pool slices are
    /// accepted as wire sources (the host guard limits them to the
    /// cluster-internal interfaces).
    cross_node_hairpin: bool,
    /// Source of locally generated ICMPv6 errors (`None`: the packet's
    /// synthesized destination).
    icmp_src6: Option<u128>,
}

impl Nat64 {
    /// `owned` is this node's slice of the IPv4 pool.
    pub fn new(cfg: &Config, owned: Vec<u32>, audit: AuditSink, clock: Clock) -> Result<Self, String> {
        if owned.is_empty() {
            return Err("this node owns no pool addresses".into());
        }
        Self::build(cfg, State::new(cfg, owned, audit, clock), false)
    }

    /// Cluster engine (`cluster.partition = "slices"`): the whole cluster
    /// pool is indexed and every slice starts Inactive; the control plane
    /// activates slices through [`State::adopt_slice`] /
    /// [`State::set_slice_state`].
    pub fn new_cluster(cfg: &Config, setup: ClusterSetup, audit: AuditSink, clock: Clock) -> Result<Self, String> {
        Self::build(cfg, State::new_cluster(cfg, setup, audit, clock)?, true)
    }

    fn build(cfg: &Config, state: State, sliced: bool) -> Result<Self, String> {
        let t = &cfg.translation;
        let prefix = Prefix6052::new(t.nat64_prefix.network(), t.nat64_prefix.prefix_len())
            .ok_or_else(|| format!("invalid RFC 6052 prefix {}", t.nat64_prefix))?;
        Ok(Self {
            state,
            clients: t.client_prefixes.clone(),
            cluster_pool: cfg.nat64.pool.clone(),
            cross_node_hairpin: t.cross_node_hairpin,
            sub_mask: Ipv6Cidr::mask_of(cfg.nat64.subscriber_prefix_len),
            filtering: cfg.nat64.filtering,
            mtu4: t.ipv4_mtu,
            mtu6: t.ipv6_mtu,
            frag6: t.lowest_ipv6_mtu.min(t.ipv6_mtu),
            sliced,
            icmp_rate: t.icmp_errors_per_sec,
            icmp_gen: IcmpGen {
                time_exceeded: t.send_time_exceeded,
                unreachable: t.send_unreachable,
                inbound_unreachable: t.send_inbound_unreachable,
                param_problem: t.send_param_problem,
                source_route_failed: t.send_source_route_failed,
            },
            copy_tos: t.copy_tos,
            wkp_non_global_icmp: t.wkp_non_global_icmp_errors,
            deny_non_global_dst: prefix.is_wkp() || !t.allow_non_global_destinations,
            prefix,
            ident_key: IdentKey::new(),
            frag_cfg: t.fragments.clone(),
            udp_zero_reassemble: t.fragments.udp_zero_checksum == UdpZeroChecksum::Reassemble,
            icmp_src6: t.icmp_source_v6.map(u128::from),
        })
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// A worker context sized by this engine's `[translation.fragments]`.
    pub fn new_worker(&self, counters: Arc<Counters>, seed: u16) -> WorkerCtx {
        let mut ctx = WorkerCtx::with_fragments(counters, seed, &self.frag_cfg);
        ctx.ftab.set_src_mask(self.sub_mask);
        ctx
    }

    /// Per-worker housekeeping, called by the worker between packets (every
    /// batch and when idle): incremental fragment expiry and the
    /// `plat_fragment_entries` gauge. Never blocks.
    pub fn housekeep(&self, ctx: &mut WorkerCtx) {
        ctx.ftab.housekeep(self.state.now_ms(), HOUSEKEEP_SETS, &ctx.counters);
        ctx.counters.set_fragment_entries(u64::from(ctx.ftab.len()));
    }

    /// Processes the packet at `buf[start..start + len]`. `start` must leave
    /// at least [`plat_xlat::HEADROOM`] bytes in front of the packet.
    #[inline]
    pub fn process(&self, buf: &mut [u8], start: usize, len: usize, ctx: &mut WorkerCtx) -> Verdict {
        if ctx.frags.count != 0 {
            ctx.frags.clear();
        }
        let r = if self.sliced {
            self.dispatch::<SlicedPool>(buf, start, len, ctx)
        } else {
            self.dispatch::<Legacy>(buf, start, len, ctx)
        };
        match r {
            Ok(Out::Pkt(start, len)) => Verdict::Forward { start, len },
            Ok(Out::Frags(count)) => Verdict::ForwardFragments { count },
            Ok(Out::Held) => Verdict::Consumed,
            Err(d) => {
                ctx.counters.record_drop(d);
                Verdict::Drop(d)
            }
        }
    }

    #[inline]
    fn dispatch<M: Mode>(&self, buf: &mut [u8], start: usize, len: usize, ctx: &mut WorkerCtx) -> R {
        match buf.get(start).map(|b| b >> 4) {
            Some(6) => self.outbound_v6::<M>(buf, start, len, ctx),
            Some(4) => self.inbound_v4::<M>(buf, start, len, false, ctx),
            _ => Err(DropReason::Malformed),
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

    /// A wire IPv4 source that only a spoofer can send: this node's own
    /// slice always (own-node hairpins are looped back in-process), and any
    /// pool address unless cross-node hairpinning is enabled.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-7, SC-7(5), AC-4 - BCP 38 / RFC 2827 ingress
    ///   filtering of the translator's own address space (SEC-301, POAM-024)
    #[inline]
    fn spoofed_pool_src<M: Mode>(&self, a: u32) -> bool {
        if self.cross_node_hairpin {
            self.state.pool.local_in(M::SLICED, a).is_some()
        } else {
            self.cluster_pool.iter().any(|c| c.contains(a))
        }
    }

    /// Non-global IPv4 address (RFC 6890) outside the cluster pool. The pool
    /// test only runs for non-global addresses, so global traffic pays one
    /// table check.
    #[inline]
    fn non_global_foreign(&self, a: u32) -> bool {
        is_non_global_v4(a) && !self.cluster_pool.iter().any(|c| c.contains(a))
    }

    /// IPv6 → IPv4 (outbound from the CLAT side).
    #[inline(never)]
    fn outbound_v6<M: Mode>(&self, buf: &mut [u8], start: usize, len: usize, ctx: &mut WorkerCtx) -> R {
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        // PERF-001: one header copy; `h` is adjusted in place below.
        let mut h = match parse_v6(pkt) {
            Ok(h) => h,
            Err(e) => return self.v6_unparsed(buf, start, len, e, ctx),
        };
        if h.frag.is_some_and(|f| !f.is_first()) {
            return self.outbound_nonfirst::<M>(buf, start, len, &h, ctx);
        }
        let l4 = parse_l4(pkt, h.l4_off, h.total_len(), h.proto).map_err(|e| l4_err(e, h.frag.is_some()))?;
        let is_err = matches!(l4, L4::Icmp { ty, .. } if icmp::is_icmp6_error(ty));
        if h.hop_limit <= 1 {
            return self.time_exceeded_v6(buf, start, len, &h, is_err, ctx);
        }
        if is_err {
            if h.frag.is_some() {
                return self.reasm_error_v6::<M>(buf, start, len, &h, ctx);
            }
            // Errors come from routers that need not be inside the client
            // prefixes (BNG, CPE WAN); icmp6_error applies its own checks.
            return self.icmp6_error::<M>(buf, start, len, ctx);
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
            L4::Icmp { ty: 128 | 129, .. } if h.frag.is_some() => {
                return self.reasm_first_v6::<M>(buf, start, len, &h, ctx);
            }
            L4::Icmp { ty: 128 | 129, id, .. } => (proto::ICMP, id, 0, 0),
            L4::Icmp { .. } => return Err(DropReason::UnsupportedProto),
        };
        if h.frag.is_some() {
            return self.outbound_first_frag::<M>(buf, start, &h, (p, sport, dport, flags), dst4, ctx);
        }
        // RFC 7915 §5.1: a packet of at most 1280 bytes (or one this worker
        // reassembled) is fragmented as IPv4; larger ones get Packet Too Big.
        let split = 20 + h.l4_len() > usize::from(self.mtu4);
        if split && h.total_len() > 1280 && !ctx.reassembled {
            return self.too_big_v6(buf, start, len, &h, ctx);
        }

        let k6 = Key6 { proto: p, addr: h.src, port: sport };
        let create = p != proto::TCP || tcp::initial(Side::V6, flags).is_some();
        let m4 = match self.map_out::<M>(k6, create, dst4, dport, flags, ctx) {
            Ok(m) => m,
            Err(e) => return self.no_mapping_v6::<M>(buf, start, len, &h, e, ctx),
        };
        let k4 = m4.k4;

        let m = Map4 { src: k4.addr, dst: dst4, sport: k4.port, dport };
        let ident = self.ident_key.next(&mut ctx.ident, h.src, dst4, p);
        if !self.copy_tos {
            h.traffic_class = 0;
        }
        if split {
            return self.split_out::<M>(buf, start, &h, &m, ident, ctx);
        }
        let (s, l) = v6_to_v4(buf, start, &h, &m, ident, self.mtu4).map_err(from_xlat)?;
        ctx.counters.inc(Counter::V6ToV4);
        let own = self.state.pool.local_in(M::SLICED, dst4);
        if own.is_some() {
            // RFC 6146 §3.8 hairpinning: loop the IPv4 result back inbound.
            ctx.counters.inc(Counter::Hairpin);
            return self.inbound_v4::<M>(buf, s, l, true, ctx);
        }
        Ok(Out::Pkt(s, l))
    }

    /// BIB lookup/creation plus the session update for an outbound flow.
    #[inline(always)]
    fn map_out<M: Mode>(
        &self,
        k6: Key6,
        create: bool,
        dst4: u32,
        dport: u16,
        flags: u8,
        ctx: &mut WorkerCtx,
    ) -> Result<Mapped, DropReason> {
        let mut m4 = self.state.bib_for(k6, create, &ctx.counters, &ctx.repl)?;
        // A mapping in a slice this node no longer serves (fenced, or
        // handed over) is never used (SC-24). The mapping carries its pool
        // index, so this is one load (PERF-002); no code in legacy mode.
        self.state.pool.check_idx_in(M::SLICED, m4.idx)?;
        if let Err(e) = self.state.outbound(m4.k4, (dst4, dport), flags, &ctx.counters) {
            if e != DropReason::NoBinding {
                return Err(e);
            }
            // BIB expired between lookup and session update; recreate once.
            m4 = self.state.bib_for(k6, create, &ctx.counters, &ctx.repl)?;
            self.state.pool.check_idx_in(M::SLICED, m4.idx)?;
            self.state.outbound(m4.k4, (dst4, dport), flags, &ctx.counters)?;
        }
        Ok(m4)
    }

    /// An IPv6 packet of at most 1280 bytes (or a reassembled datagram)
    /// whose IPv4 translation exceeds `ipv4_mtu`: fragment it as IPv4 with
    /// DF=0. Own-node hairpins never reach an IPv4 link and are looped back
    /// whole.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7915 §5.1 - the translator fragments packets ≤ 1280 bytes when
    ///   the IPv4 MTU is smaller (closes the POAM-002 item)
    #[cold]
    #[inline(never)]
    fn split_out<M: Mode>(
        &self,
        buf: &mut [u8],
        start: usize,
        h: &Ipv6Hdr,
        m: &Map4,
        ident: u16,
        ctx: &mut WorkerCtx,
    ) -> R {
        if self.state.pool.local_in(M::SLICED, m.dst).is_some() {
            let (s, l) = v6_to_v4(buf, start, h, m, ident, u16::MAX).map_err(from_xlat)?;
            ctx.counters.inc(Counter::V6ToV4);
            ctx.counters.inc(Counter::Hairpin);
            return self.inbound_v4::<M>(buf, s, l, true, ctx);
        }
        v6_to_v4_fragments(buf, start, h, m, ident, self.mtu4, &mut ctx.sink()).map_err(from_xlat)?;
        ctx.counters.inc(Counter::V6ToV4);
        ctx.counters.inc(Counter::FragmentedV6ToV4);
        Ok(Out::Frags(ctx.frags.count))
    }

    /// An IPv6 packet whose translation exceeds the IPv4 MTU: answer with a
    /// rate-limited ICMPv6 Packet Too Big (IPv6 never fragments en route).
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7915 §5 / RFC 4443 §3.2 - Packet Too Big for oversize packets
    #[cold]
    #[inline(never)]
    fn too_big_v6(&self, buf: &mut [u8], start: usize, len: usize, h: &Ipv6Hdr, ctx: &mut WorkerCtx) -> R {
        // Largest IPv6 packet whose IPv4 translation (20-byte header replaces
        // the IPv6 header and extension headers) fits `mtu4`.
        let mtu = (u32::from(self.mtu4) - 20 + h.l4_off as u32).max(1280);
        self.local_error_v6(
            buf,
            start,
            len,
            h,
            LocalErr { msg: (2, 0, mtu), reason: DropReason::TooBig, sent: None },
            ctx,
        )
    }

    /// An IPv4 DF packet whose translation exceeds the IPv6 MTU: answer with
    /// a rate-limited ICMPv4 Fragmentation Needed from the pool address.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7915 §4 / RFC 1191 - Fragmentation Needed, MTU = IPv6 MTU − 20
    #[cold]
    #[inline(never)]
    fn frag_needed_v4(&self, buf: &mut [u8], start: usize, h: &Ipv4Hdr, ctx: &mut WorkerCtx) -> R {
        let mtu = (usize::from(self.mtu6) - 20).max(68) as u32;
        self.local_error_v4(buf, start, h, LocalErr { msg: (3, 4, mtu), reason: DropReason::TooBig, sent: None }, ctx)
    }

    /// Builds a rate-limited ICMPv6 error `(type, code, rest)` about the
    /// IPv6 packet in `buf`, sent back to its source from
    /// `translation.icmp_source_v6` when set, else from the packet's
    /// (synthesized) destination. Without a token the packet is dropped
    /// with `reason`.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 4443 §2.2 - the source is an address of the translator when
    ///   one is configured (RFC-001); the default keeps the synthesized
    ///   destination, so the error names the IPv4 path it is about
    #[cold]
    #[inline(never)]
    fn local_error_v6(
        &self,
        buf: &mut [u8],
        start: usize,
        len: usize,
        h: &Ipv6Hdr,
        e: LocalErr,
        ctx: &mut WorkerCtx,
    ) -> R {
        let LocalErr { msg: (ty, code, rest), reason, sent } = e;
        if !ctx.icmp_token(self.state.now_ms(), self.icmp_rate, ty == 2) {
            ctx.counters.inc(Counter::IcmpErrorsRateLimited);
            return Err(reason);
        }
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let src = self.icmp_src6.unwrap_or(h.dst);
        let n = icmp6_error_local(pkt, h, src, ty, code, rest, &mut ctx.scratch).map_err(from_xlat)?;
        ctx.counters.record_drop(reason);
        if let Some(c) = sent {
            ctx.counters.inc(c);
        }
        Self::emit_scratch(buf, start, n, ctx, Counter::IcmpErrorsGenerated)
    }

    /// IPv4 counterpart of [`Nat64::local_error_v6`], sent from the pool
    /// address the packet was addressed to.
    #[cold]
    #[inline(never)]
    fn local_error_v4(&self, buf: &mut [u8], start: usize, h: &Ipv4Hdr, e: LocalErr, ctx: &mut WorkerCtx) -> R {
        let LocalErr { msg: (ty, code, rest), reason, sent } = e;
        if !ctx.icmp_token(self.state.now_ms(), self.icmp_rate, (ty, code) == (3, 4)) {
            ctx.counters.inc(Counter::IcmpErrorsRateLimited);
            return Err(reason);
        }
        let ident = self.ident_key.next(&mut ctx.ident, u128::from(h.dst), h.src, proto::ICMP);
        let pkt = buf.get(start..start + h.total_len).ok_or(DropReason::Malformed)?;
        let n = icmp4_error_local(pkt, h, h.dst, ty, code, rest, ident, &mut ctx.scratch).map_err(from_xlat)?;
        ctx.counters.record_drop(reason);
        if let Some(c) = sent {
            ctx.counters.inc(c);
        }
        Self::emit_scratch(buf, start, n, ctx, Counter::IcmpErrorsGenerated)
    }

    /// Hop Limit ≤ 1: ICMPv6 Time Exceeded (in transit) to a subscriber.
    /// Never about an ICMP error, a non-first fragment (handled before this
    /// point) or a source outside the client prefixes.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7915 §5.1, RFC 4443 §3.3 / §2.4(e) - Time Exceeded
    /// - NIST 800-53: SC-5 - rate-limited, client sources only
    #[cold]
    #[inline(never)]
    fn time_exceeded_v6(
        &self,
        buf: &mut [u8],
        start: usize,
        len: usize,
        h: &Ipv6Hdr,
        is_err: bool,
        ctx: &mut WorkerCtx,
    ) -> R {
        if !self.icmp_gen.time_exceeded || is_err || !self.is_client(h.src) || self.prefix.extract(h.dst).is_none() {
            return Err(DropReason::HopLimit);
        }
        self.local_error_v6(
            buf,
            start,
            len,
            h,
            LocalErr { msg: (3, 0, 0), reason: DropReason::HopLimit, sent: Some(Counter::IcmpTimeExceededSent) },
            ctx,
        )
    }

    /// No mapping could be created for a subscriber's packet: ICMPv6
    /// Destination Unreachable (Address Unreachable). No BIB, port or audit
    /// record was created.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 6146 §3.5.1.1 / §3.5.2.1 - Destination Unreachable when no
    ///   mapping can be created
    ///
    /// In a sliced cluster pool, `port_exhausted` is also what a node with
    /// no active or no reserve-backed slice reports during failover; that is
    /// transient, so it stays a silent drop and the sender retransmits.
    #[cold]
    #[inline(never)]
    fn no_mapping_v6<M: Mode>(
        &self,
        buf: &mut [u8],
        start: usize,
        len: usize,
        h: &Ipv6Hdr,
        e: DropReason,
        ctx: &mut WorkerCtx,
    ) -> R {
        let exhausted = match e {
            DropReason::PortExhausted => !M::SLICED,
            DropReason::SubscriberLimit | DropReason::SubscriberTableFull | DropReason::SessionLimit => true,
            _ => false,
        };
        if !self.icmp_gen.unreachable || !exhausted {
            return Err(e);
        }
        self.local_error_v6(
            buf,
            start,
            len,
            h,
            LocalErr { msg: (1, 3, 0), reason: e, sent: Some(Counter::IcmpUnreachableSent) },
            ctx,
        )
    }

    /// An IPv6 header that does not parse. An active Routing header gets an
    /// ICMPv6 Parameter Problem pointing at Segments Left, under the usual
    /// rules (client source, translatable destination, not about an ICMP
    /// error or a non-first fragment).
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7915 §5.1, RFC 4443 §3.4 - Parameter Problem, code 0
    #[cold]
    #[inline(never)]
    fn v6_unparsed(&self, buf: &mut [u8], start: usize, len: usize, e: ParseError, ctx: &mut WorkerCtx) -> R {
        let ParseError::RoutingHeaderActive { ptr } = e else {
            return Err(from_parse(e));
        };
        let reason = from_parse(e);
        if !self.icmp_gen.param_problem {
            return Err(reason);
        }
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let Ok(h) = parse_v6_ignore_routing(pkt) else {
            return Err(reason);
        };
        let quiet = h.frag.is_some_and(|f| !f.is_first())
            || !matches!(parse_l4(pkt, h.l4_off, h.total_len(), h.proto),
                Ok(l4) if !matches!(l4, L4::Icmp { ty, .. } if icmp::is_icmp6_error(ty)))
            || !self.is_client(h.src)
            || self.prefix.extract(h.dst).is_none();
        if quiet {
            return Err(reason);
        }
        self.local_error_v6(
            buf,
            start,
            len,
            &h,
            LocalErr { msg: (4, 0, u32::from(ptr)), reason, sent: Some(Counter::IcmpParamProblemSent) },
            ctx,
        )
    }

    /// An IPv4 header that does not parse. An unexpired source route to an
    /// owned, active pool address gets ICMPv4 Source Route Failed when
    /// enabled (off by default) and the filter would admit the packet.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7915 §4.1, RFC 1812 §5.2.4.1 - Source Route Failed (3/5)
    #[cold]
    #[inline(never)]
    fn v4_unparsed<M: Mode>(
        &self,
        buf: &mut [u8],
        start: usize,
        len: usize,
        e: ParseError,
        hairpin: bool,
        ctx: &mut WorkerCtx,
    ) -> R {
        let reason = from_parse(e);
        if e != ParseError::SourceRouteActive || !self.icmp_gen.source_route_failed || hairpin {
            return Err(reason);
        }
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let Ok(h) = parse_v4_ignore_source_route(pkt) else {
            return Err(reason);
        };
        let owned = self.state.pool.index(h.dst).is_some_and(|i| self.state.pool.check_idx_in(M::SLICED, i).is_ok());
        if !owned || h.frag.is_some_and(|f| !f.is_first()) || is_never_translatable_v4(h.src) {
            return Err(reason);
        }
        // Not about an ICMP error, and only for a packet the filter would
        // admit (SEC-005: no answer to spoofed sources without a binding).
        let admitted = parse_l4(pkt, h.hdr_len, h.total_len, h.proto)
            .ok()
            .and_then(|l4| self.inbound_key(&h, l4))
            .is_some_and(|(k4, remote)| self.state.filter_inbound(k4, remote).is_ok());
        if !admitted {
            return Err(reason);
        }
        self.local_error_v4(
            buf,
            start,
            &h,
            LocalErr { msg: (3, 5, 0), reason, sent: Some(Counter::IcmpUnreachableSent) },
            ctx,
        )
    }

    /// IPv4 → IPv6 (inbound to the CLAT side). `hairpin` is true only for
    /// an own-node hairpin looped back in-process by `outbound_v6`; packets
    /// read from the wire pass `false`.
    #[inline(never)]
    fn inbound_v4<M: Mode>(&self, buf: &mut [u8], start: usize, len: usize, hairpin: bool, ctx: &mut WorkerCtx) -> R {
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let h = match parse_v4(pkt) {
            Ok(h) => h,
            Err(e) => return self.v4_unparsed::<M>(buf, start, len, e, hairpin, ctx),
        };
        if h.frag.is_some_and(|f| !f.is_first()) {
            return self.inbound_nonfirst::<M>(buf, start, len, &h, hairpin, ctx);
        }
        let Some(di) = self.state.pool.index(h.dst) else {
            // SI-4: another cluster node owns it (mis-steered return
            // traffic), or it was never pooled.
            return Err(if self.cluster_pool.iter().any(|c| c.contains(h.dst)) {
                DropReason::WrongNode
            } else {
                DropReason::NoBinding
            });
        };
        // Sliced pool: only an Active slice translates (`wrong_node` for
        // another member's slice, `cluster_fenced` while fenced/adopting).
        self.state.pool.check_idx_in(M::SLICED, di)?;
        let l4 = parse_l4(pkt, h.hdr_len, h.total_len, h.proto).map_err(|e| l4_err(e, h.frag.is_some()))?;
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
        //   slices are refused too unless `translation.cross_node_hairpin`
        //   is on, which requires the host guard limiting pool sources to the
        //   cluster-internal interfaces (POAM-024).
        if !hairpin && self.spoofed_pool_src::<M>(h.src) {
            return Err(DropReason::SrcNotAllowed);
        }
        if h.ttl <= 1 {
            return self.time_exceeded_v4(buf, start, &h, l4, is_err || hairpin, ctx);
        }
        let (p, sport, dport, flags) = match l4 {
            L4::Tcp { sport, dport, flags } => (proto::TCP, sport, dport, flags),
            L4::Udp { csum: 0, .. } if h.frag.is_some() => {
                // COMPLIANCE MAPPING:
                // - RFC 7915 §4.5, RFC 6146 §3.4 - a fragmented
                //   zero-checksum UDP datagram is reassembled so its
                //   checksum can be computed, or dropped by policy
                if !self.udp_zero_reassemble {
                    return Err(DropReason::Fragment);
                }
                return self.reasm_first_v4::<M>(buf, start, &h, l4, ctx);
            }
            L4::Udp { sport, dport, .. } => (proto::UDP, sport, dport, 0),
            L4::Icmp { .. } if is_err && h.frag.is_some() => return self.reasm_first_v4::<M>(buf, start, &h, l4, ctx),
            L4::Icmp { .. } if is_err => return self.icmp4_error::<M>(buf, start, len, ctx),
            L4::Icmp { ty: 0 | 8, .. } if h.frag.is_some() => {
                return self.reasm_first_v4::<M>(buf, start, &h, l4, ctx);
            }
            L4::Icmp { ty: 0 | 8, id, .. } => (proto::ICMP, 0, id, 0),
            L4::Icmp { .. } => return Err(DropReason::UnsupportedProto),
        };
        let k4 = Key4 { proto: p, addr: h.dst, port: dport };
        if h.frag.is_some() {
            return self.inbound_first_frag::<M>(buf, start, &h, k4, (sport, flags, di), ctx);
        }
        // COMPLIANCE MAPPING:
        // - RFC 7915 §4, RFC 1191 - the size decision comes before the
        //   session lookup, so a too-big DF packet never refreshes or (EIF)
        //   creates a session it cannot use (closes POAM-023).
        // - NIST 800-53: SC-7, SC-5 - Frag Needed only for a packet the
        //   filter would admit (read-only check, NIST-002): unbound ports
        //   and remotes refused by ADF/APDF get no answer, so it is no
        //   binding-activity oracle and cannot steer the PMTU of others.
        let out_len = 40 + h.payload_len();
        let too_big = out_len > usize::from(self.mtu6) || (!h.df && out_len > usize::from(self.frag6));
        if too_big && h.df {
            self.state.filter_inbound(k4, (h.src, sport))?;
            return self.frag_needed_v4(buf, start, &h, ctx);
        }
        let k6 = match self.state.inbound(k4, (h.src, sport), flags, &ctx.counters) {
            Ok(k6) => k6,
            Err(e) => return self.inbound_refused(buf, start, &h, hairpin || p == proto::TCP, e, ctx),
        };
        let m = Map6 { src: self.prefix.embed(h.src), dst: k6.addr, sport, dport: k6.port };
        let mut h = h;
        if !self.copy_tos {
            h.tos = 0;
        }
        if too_big {
            // COMPLIANCE MAPPING:
            // - RFC 7915 §4 - DF=0 packets are fragmented to lowest-ipv6-mtu
            v4_to_v6_fragments(buf, start, &h, &m, self.frag6, &mut ctx.sink()).map_err(from_xlat)?;
            ctx.counters.inc(Counter::V4ToV6);
            ctx.counters.inc(Counter::FragmentedV4ToV6);
            return Ok(Out::Frags(ctx.frags.count));
        }
        let (s, l) = v4_to_v6(buf, start, &h, &m, self.mtu6).map_err(from_xlat)?;
        ctx.counters.inc(Counter::V4ToV6);
        Ok(Out::Pkt(s, l))
    }

    /// TTL ≤ 1 on an inbound packet that passed the pool, slice and source
    /// checks: ICMPv4 Time Exceeded from the pool address (never about an
    /// ICMP error or a hairpinned packet), only when the filter would admit
    /// the packet.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7915 §4.1, RFC 1812 §5.3.1 / §4.3.2.7 - Time Exceeded
    /// - NIST 800-53: SC-7, SC-5 - read-only filter check first (NIST-004,
    ///   SEC-005): no oracle and no reflection toward spoofed remotes
    #[cold]
    #[inline(never)]
    fn time_exceeded_v4(
        &self,
        buf: &mut [u8],
        start: usize,
        h: &Ipv4Hdr,
        l4: L4,
        quiet: bool,
        ctx: &mut WorkerCtx,
    ) -> R {
        if !self.icmp_gen.time_exceeded || quiet {
            return Err(DropReason::HopLimit);
        }
        let (k4, remote) = self.inbound_key(h, l4).ok_or(DropReason::HopLimit)?;
        self.state.filter_inbound(k4, remote)?;
        self.local_error_v4(
            buf,
            start,
            h,
            LocalErr { msg: (11, 0, 0), reason: DropReason::HopLimit, sent: Some(Counter::IcmpTimeExceededSent) },
            ctx,
        )
    }

    /// The BIB key and remote of an inbound TCP/UDP/ICMP echo packet.
    fn inbound_key(&self, h: &Ipv4Hdr, l4: L4) -> Option<(Key4, (u32, u16))> {
        match l4 {
            L4::Tcp { sport, dport, .. } => {
                Some((Key4 { proto: proto::TCP, addr: h.dst, port: dport }, (h.src, sport)))
            }
            L4::Udp { sport, dport, .. } => {
                Some((Key4 { proto: proto::UDP, addr: h.dst, port: dport }, (h.src, sport)))
            }
            L4::Icmp { ty: 0 | 8, id, .. } => Some((Key4 { proto: proto::ICMP, addr: h.dst, port: id }, (h.src, 0))),
            L4::Icmp { .. } => None,
        }
    }

    /// Inbound UDP/ICMP with no binding (Host Unreachable) or refused by
    /// filtering (Communication Administratively Prohibited), only with
    /// `translation.send_inbound_unreachable`. TCP stays a silent drop.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 6146 §3.5.2.2 / §3.5.4 - ICMP for unsolicited inbound (off by
    ///   default: documented deviation, no scanning oracle)
    /// - NIST 800-53: SC-5, SC-7 - owned active slices only, rate-limited
    #[cold]
    #[inline(never)]
    fn inbound_refused(
        &self,
        buf: &mut [u8],
        start: usize,
        h: &Ipv4Hdr,
        quiet: bool,
        e: DropReason,
        ctx: &mut WorkerCtx,
    ) -> R {
        let code = match e {
            DropReason::NoBinding => 1,
            DropReason::Filtered => 13,
            _ => return Err(e),
        };
        // `quiet`: a hairpinned packet, or TCP (always a silent drop).
        if !self.icmp_gen.inbound_unreachable || quiet {
            return Err(e);
        }
        self.local_error_v4(
            buf,
            start,
            h,
            LocalErr { msg: (3, code, 0), reason: e, sent: Some(Counter::IcmpUnreachableSent) },
            ctx,
        )
    }

    /// Copies a packet built in scratch back into `buf`.
    fn emit_scratch(buf: &mut [u8], start: usize, n: usize, ctx: &WorkerCtx, c: Counter) -> R {
        let dest = start.saturating_sub(40);
        let out = buf.get_mut(dest..dest + n).ok_or(DropReason::Malformed)?;
        out.copy_from_slice(ctx.scratch.get(..n).ok_or(DropReason::Malformed)?);
        ctx.counters.inc(c);
        Ok(Out::Pkt(dest, n))
    }

    // ---- Fragments (RFC 6146 §3.4, RFC 7915 §4/§5) ----------------------

    /// First fragment of an outbound TCP/UDP datagram: the normal mapping
    /// path, then the result is stored for the non-first fragments and any
    /// held fragments are flushed after it.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 6146 §3.4 - the first fragment creates/uses the mapping; later
    ///   fragments reuse it
    /// - NIST 800-53: SC-7 - every filter ran on the first fragment before
    ///   this point; non-first fragments inherit its verdict
    #[cold]
    #[inline(never)]
    fn outbound_first_frag<M: Mode>(
        &self,
        buf: &mut [u8],
        start: usize,
        h: &Ipv6Hdr,
        (p, sport, dport, flags): (u8, u16, u16, u8),
        dst4: u32,
        ctx: &mut WorkerCtx,
    ) -> R {
        let f = h.frag.ok_or(DropReason::Malformed)?;
        // Extension headers after the Fragment Header would shift every
        // later fragment's offset in the IPv4 result.
        if h.l4_off != h.frag_end {
            return Err(DropReason::UnsupportedProto);
        }
        frag_bounds(f, h.l4_len())?;
        ctx.counters.inc(Counter::FragmentsInV6);
        let now = self.state.now_ms();
        let i = ctx.ftab.get_or_insert(&key6(h, f), now, &ctx.counters)?;
        let acct = ctx.ftab.account(i, 0, h.l4_len(), f.more, &ctx.counters)?;
        let r = (|| {
            let k6 = Key6 { proto: p, addr: h.src, port: sport };
            let create = p != proto::TCP || tcp::initial(Side::V6, flags).is_some();
            let m4 = self.map_out::<M>(k6, create, dst4, dport, flags, ctx)?;
            let m = Map4 { src: m4.k4.addr, dst: dst4, sport: m4.k4.port, dport };
            // COMPLIANCE MAPPING:
            // - RFC 6864, RFC 4963 - a fresh IPv4 Identification per
            //   datagram, shared by all its fragments (RFC-004): subscribers
            //   sharing a pool address never collide on a truncated IPv6 ID
            let id4 = self.ident_key.next(&mut ctx.ident, h.src, dst4, p);
            let mut h = *h;
            h.frag = Some(Frag { id: u32::from(id4), ..f });
            if !self.copy_tos {
                h.traffic_class = 0;
            }
            let own = self.state.pool.local_in(M::SLICED, dst4).is_some();
            let out = if own || 20 + h.l4_len() <= usize::from(self.mtu4) {
                let (s, l) =
                    v6_to_v4(buf, start, &h, &m, 0, if own { u16::MAX } else { self.mtu4 }).map_err(from_xlat)?;
                ctx.counters.inc(Counter::V6ToV4);
                if own {
                    ctx.counters.inc(Counter::Hairpin);
                    self.inbound_v4::<M>(buf, s, l, true, ctx)?
                } else {
                    Out::Pkt(s, l)
                }
            } else {
                v6_to_v4_fragments(buf, start, &h, &m, 0, self.mtu4, &mut ctx.sink()).map_err(from_xlat)?;
                ctx.counters.inc(Counter::V6ToV4);
                Out::Frags(ctx.frags.count)
            };
            Ok((out, Fwd::To4 { src: m4.k4.addr, dst: dst4, idx: m4.idx, hairpin: own, id4 }, m4.k4.port, own))
        })();
        let (out, fwd, port4, own) = match r {
            Ok(v) => v,
            Err(d) => {
                ctx.ftab.abandon(i, d, &ctx.counters);
                return Err(d);
            }
        };
        ctx.ftab.set_pass(i, fwd);
        if let (false, Fwd::To4 { src, dst, idx, id4, .. }) = (own, fwd) {
            let alias =
                FragKey { src: u128::from(src), dst: u128::from(dst), id: u32::from(id4), proto: p, kind: Kind::Sent4 };
            let sent = Fwd::Sent4 { sub: h.src, id: f.id, idx, sport: port4, dport };
            ctx.ftab.alias(&alias, sent, now, &ctx.counters);
        }
        let r = self.flush::<M>(i, out, buf, ctx);
        if acct == Acct::Complete {
            ctx.ftab.remove(i);
        }
        r
    }

    /// First fragment of an inbound TCP/UDP datagram; see
    /// [`Nat64::outbound_first_frag`]. Fragments are never answered with
    /// Fragmentation Needed: they are translated with a Fragment Header and
    /// re-split to `lowest_ipv6_mtu` when needed (RFC 7915 §4).
    #[cold]
    #[inline(never)]
    fn inbound_first_frag<M: Mode>(
        &self,
        buf: &mut [u8],
        start: usize,
        h: &Ipv4Hdr,
        k4: Key4,
        (sport, flags, di): (u16, u8, u32),
        ctx: &mut WorkerCtx,
    ) -> R {
        let f = h.frag.ok_or(DropReason::Malformed)?;
        frag_bounds(f, h.payload_len())?;
        ctx.counters.inc(Counter::FragmentsInV4);
        let now = self.state.now_ms();
        let i = ctx.ftab.get_or_insert(&key4(h, f), now, &ctx.counters)?;
        let acct = ctx.ftab.account(i, 0, h.payload_len(), f.more, &ctx.counters)?;
        let r = (|| {
            let k6 = self.state.inbound(k4, (h.src, sport), flags, &ctx.counters)?;
            let m = Map6 { src: self.prefix.embed(h.src), dst: k6.addr, sport, dport: k6.port };
            let mut h = *h;
            if !self.copy_tos {
                h.tos = 0;
            }
            let out = if FRAG6_HDR + h.payload_len() <= usize::from(self.frag6) {
                let (s, l) = v4_to_v6(buf, start, &h, &m, self.mtu6).map_err(from_xlat)?;
                Out::Pkt(s, l)
            } else {
                v4_to_v6_fragments(buf, start, &h, &m, self.frag6, &mut ctx.sink()).map_err(from_xlat)?;
                ctx.counters.inc(Counter::FragmentedV4ToV6);
                Out::Frags(ctx.frags.count)
            };
            ctx.counters.inc(Counter::V4ToV6);
            Ok((out, m))
        })();
        let (out, m) = match r {
            Ok(v) => v,
            Err(d) => {
                ctx.ftab.abandon(i, d, &ctx.counters);
                return Err(d);
            }
        };
        ctx.ftab.set_pass(i, Fwd::To6 { dst: m.dst, idx: di });
        let alias = FragKey { src: m.src, dst: m.dst, id: f.id, proto: proto_4to6(k4.proto), kind: Kind::Sent6 };
        ctx.ftab.alias(&alias, Fwd::Sent6 { pool: h.dst, idx: di }, now, &ctx.counters);
        let r = self.flush::<M>(i, out, buf, ctx);
        if acct == Acct::Complete {
            ctx.ftab.remove(i);
        }
        r
    }

    /// Emits `first` followed by the fragments entry `i` held before its
    /// first fragment arrived, each translated with the now-known mapping.
    fn flush<M: Mode>(&self, i: usize, first: Out, buf: &[u8], ctx: &mut WorkerCtx) -> R {
        if !ctx.ftab.has_buffered(i) {
            return Ok(first);
        }
        if let Out::Pkt(s, l) = first {
            let p = buf.get(s..s + l).ok_or(DropReason::Malformed)?;
            ctx.frags.push_copy(&mut ctx.frag_out, p).map_err(from_xlat)?;
        }
        let mut scratch = std::mem::take(&mut ctx.scratch);
        while let Some(slot) = ctx.ftab.pop_buffered(i) {
            let held = ctx.ftab.slot(slot);
            let n = held.len();
            let copied = scratch.get_mut(HEADROOM..HEADROOM + n).map(|d| d.copy_from_slice(held));
            ctx.ftab.free_slot(slot);
            if copied.is_none() {
                ctx.counters.record_drop(DropReason::FragmentBufferFull);
                continue;
            }
            ctx.replay = true;
            let r = self.dispatch::<M>(&mut scratch, HEADROOM, n, ctx);
            ctx.replay = false;
            let r = match r {
                Ok(Out::Pkt(s, l)) => match scratch.get(s..s + l) {
                    Some(p) => ctx.frags.push_copy(&mut ctx.frag_out, p).map_err(|_| DropReason::FragmentBufferFull),
                    None => Err(DropReason::Malformed),
                },
                Ok(_) => Ok(()),
                Err(d) => Err(d),
            };
            if let Err(d) = r {
                ctx.counters.record_drop(d);
            }
        }
        ctx.scratch = scratch;
        Ok(Out::Frags(ctx.frags.count))
    }

    /// Holds a non-first fragment whose first fragment has not arrived
    /// (RFC 6146 §3.4 MAY buffer), within the buffer pool's bounds.
    fn hold(
        &self,
        key: &FragKey,
        f: Frag,
        len: usize,
        pkt_range: (usize, usize),
        buf: &[u8],
        ctx: &mut WorkerCtx,
    ) -> R {
        if self.frag_cfg.max_buffered_fragments == 0 {
            return Err(DropReason::FragmentUnmatched);
        }
        let now = self.state.now_ms();
        let i = ctx.ftab.get_or_insert(key, now, &ctx.counters)?;
        Self::hold_on(i, f, len, pkt_range, buf, ctx)
    }

    fn hold_on(i: usize, f: Frag, len: usize, (s, e): (usize, usize), buf: &[u8], ctx: &mut WorkerCtx) -> R {
        ctx.ftab.account(i, f.offset, len, f.more, &ctx.counters)?;
        let pkt = buf.get(s..e).ok_or(DropReason::Malformed)?;
        if let Err(d) = ctx.ftab.buffer(i, pkt, &ctx.counters) {
            if !ctx.ftab.has_buffered(i) && ctx.ftab.state(i) == Some(St::Pending) {
                ctx.ftab.remove(i);
            }
            return Err(d);
        }
        ctx.counters.inc(Counter::FragmentsBuffered);
        Ok(Out::Held)
    }

    /// Non-first IPv6 fragment: translated by header rewrite with its first
    /// fragment's mapping (no shard lock, no session refresh), held until
    /// the first fragment arrives, or added to a reassembly.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 6146 §3.4, RFC 7915 §5.1 - non-first fragment translation
    /// - RFC 4443 §2.4(e) - no ICMP error is generated for it
    /// - NIST 800-53: SC-24 - the slice is re-checked per fragment
    #[cold]
    #[inline(never)]
    fn outbound_nonfirst<M: Mode>(
        &self,
        buf: &mut [u8],
        start: usize,
        len: usize,
        h: &Ipv6Hdr,
        ctx: &mut WorkerCtx,
    ) -> R {
        let f = h.frag.ok_or(DropReason::Malformed)?;
        let replay = std::mem::take(&mut ctx.replay);
        if !replay {
            ctx.counters.inc(Counter::FragmentsInV6);
        }
        if h.hop_limit <= 1 {
            return Err(DropReason::HopLimit);
        }
        let plen = h.l4_len();
        frag_bounds(f, plen)?;
        let key = key6(h, f);
        let now = self.state.now_ms();
        let Some(i) = ctx.ftab.find(&key, now, &ctx.counters) else {
            if replay {
                return Err(DropReason::FragmentUnmatched);
            }
            // Hold only what a first fragment could make translatable, and
            // only from client sources (SEC-001): a fragmented ICMPv6 error
            // from a router outside the client prefixes is reassembled when
            // its first fragment comes first, but its early fragments are
            // not held.
            if !self.is_client(h.src) {
                return Err(DropReason::SrcNotAllowed);
            }
            if self.prefix.extract(h.dst).is_none() {
                return Err(DropReason::DstNotTranslatable);
            }
            return self.hold(&key, f, plen, (start, start + len), buf, ctx);
        };
        match ctx.ftab.state(i) {
            Some(St::Poisoned(d)) => Err(d),
            Some(St::Pending) => Self::hold_on(i, f, plen, (start, start + len), buf, ctx),
            Some(St::Reasm(_)) => {
                let acct = ctx.ftab.account(i, f.offset, plen, f.more, &ctx.counters)?;
                let payload = buf.get(start + h.l4_off..start + h.total_len()).ok_or(DropReason::Malformed)?;
                if let Err(d) = ctx.ftab.reasm_put(i, f.offset, payload) {
                    ctx.ftab.poison(i, d, &ctx.counters);
                    return Err(d);
                }
                if acct == Acct::Complete { self.finish_reasm::<M>(i, ctx) } else { Ok(Out::Held) }
            }
            // POAM: POAM-034 the stored mapping carries no BIB generation:
            // if the BIB is released (TCP RST, admin flush) and its port
            // reassigned within `timeout_ms` of the first fragment, the
            // remaining fragments use the old mapping. Slice changes are
            // re-checked per fragment (SC-24).
            Some(St::Pass(Fwd::To4 { src, dst, idx, hairpin, id4 })) => {
                let acct =
                    if replay { Acct::Partial } else { ctx.ftab.account(i, f.offset, plen, f.more, &ctx.counters)? };
                self.state.pool.check_idx_in(M::SLICED, idx)?;
                let mut h = *h;
                h.frag = Some(Frag { id: u32::from(id4), ..f });
                if !self.copy_tos {
                    h.traffic_class = 0;
                }
                let r = if hairpin {
                    let (s, l) = v6_frag_to_v4(buf, start, &h, src, dst, u16::MAX).map_err(from_xlat)?;
                    ctx.counters.inc(Counter::Hairpin);
                    self.inbound_v4::<M>(buf, s, l, true, ctx)
                } else {
                    match v6_frag_to_v4(buf, start, &h, src, dst, self.mtu4) {
                        Ok((s, l)) => Ok(Out::Pkt(s, l)),
                        Err(XlatError::TooBig) => {
                            let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
                            v6_frag_to_v4_split(pkt, &h, src, dst, self.mtu4, &mut ctx.sink())
                                .map_err(from_xlat)
                                .map(|()| Out::Frags(ctx.frags.count))
                        }
                        Err(e) => Err(from_xlat(e)),
                    }
                };
                if r.is_ok() {
                    ctx.counters.inc(Counter::V6ToV4);
                    ctx.counters.inc(Counter::FragmentsForwarded);
                }
                if acct == Acct::Complete {
                    ctx.ftab.remove(i);
                }
                r
            }
            _ => Err(DropReason::FragmentUnmatched),
        }
    }

    /// Non-first IPv4 fragment; see [`Nat64::outbound_nonfirst`]. Pool,
    /// slice and source checks run on every fragment.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 6146 §3.4, RFC 7915 §4.1 - non-first fragment translation
    /// - RFC 1858 / RFC 3128 - an offset-1 TCP fragment is refused
    /// - RFC 1812 §4.3.2.7 - no ICMP error is generated for it
    /// - NIST 800-53: SC-7, SC-24
    #[cold]
    #[inline(never)]
    fn inbound_nonfirst<M: Mode>(
        &self,
        buf: &mut [u8],
        start: usize,
        len: usize,
        h: &Ipv4Hdr,
        hairpin: bool,
        ctx: &mut WorkerCtx,
    ) -> R {
        let f = h.frag.ok_or(DropReason::Malformed)?;
        let replay = std::mem::take(&mut ctx.replay);
        if !replay {
            ctx.counters.inc(Counter::FragmentsInV4);
        }
        let Some(di) = self.state.pool.index(h.dst) else {
            return Err(if self.cluster_pool.iter().any(|c| c.contains(h.dst)) {
                DropReason::WrongNode
            } else {
                DropReason::NoBinding
            });
        };
        self.state.pool.check_idx_in(M::SLICED, di)?;
        if f.offset == 1 && h.proto == proto::TCP {
            return Err(DropReason::FragmentTiny);
        }
        if is_never_translatable_v4(h.src) || (!hairpin && self.spoofed_pool_src::<M>(h.src)) {
            return Err(DropReason::SrcNotAllowed);
        }
        if h.ttl <= 1 {
            return Err(DropReason::HopLimit);
        }
        let plen = h.payload_len();
        frag_bounds(f, plen)?;
        let key = key4(h, f);
        let now = self.state.now_ms();
        let Some(i) = ctx.ftab.find(&key, now, &ctx.counters) else {
            if replay {
                return Err(DropReason::FragmentUnmatched);
            }
            return self.hold(&key, f, plen, (start, start + h.total_len), buf, ctx);
        };
        match ctx.ftab.state(i) {
            Some(St::Poisoned(d)) => Err(d),
            Some(St::Pending) => Self::hold_on(i, f, plen, (start, start + h.total_len), buf, ctx),
            Some(St::Reasm(_)) => {
                let acct = ctx.ftab.account(i, f.offset, plen, f.more, &ctx.counters)?;
                let payload = buf.get(start + h.hdr_len..start + h.total_len).ok_or(DropReason::Malformed)?;
                if let Err(d) = ctx.ftab.reasm_put(i, f.offset, payload) {
                    ctx.ftab.poison(i, d, &ctx.counters);
                    return Err(d);
                }
                if acct == Acct::Complete { self.finish_reasm::<M>(i, ctx) } else { Ok(Out::Held) }
            }
            Some(St::Pass(Fwd::To6 { dst, idx })) => {
                let acct =
                    if replay { Acct::Partial } else { ctx.ftab.account(i, f.offset, plen, f.more, &ctx.counters)? };
                self.state.pool.check_idx_in(M::SLICED, idx)?;
                let mut h = *h;
                if !self.copy_tos {
                    h.tos = 0;
                }
                let src = self.prefix.embed(h.src);
                let r = match v4_frag_to_v6(buf, start, &h, src, dst, self.frag6) {
                    Ok((s, l)) => Ok(Out::Pkt(s, l)),
                    Err(XlatError::TooBig) => {
                        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
                        v4_frag_to_v6_split(pkt, &h, src, dst, self.frag6, &mut ctx.sink())
                            .map_err(from_xlat)
                            .map(|()| Out::Frags(ctx.frags.count))
                    }
                    Err(e) => Err(from_xlat(e)),
                };
                if r.is_ok() {
                    ctx.counters.inc(Counter::V4ToV6);
                    ctx.counters.inc(Counter::FragmentsForwarded);
                }
                if acct == Acct::Complete {
                    ctx.ftab.remove(i);
                }
                r
            }
            _ => Err(DropReason::FragmentUnmatched),
        }
    }

    /// First fragment of an IPv6 datagram that must be reassembled (ICMPv6
    /// echo, whose pseudo-header needs the whole length, and ICMPv6 errors).
    /// The reassembled datagram goes through the normal path.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7915 §5.1 / §5.3, RFC 6146 §3.4 - reassembly where the checksum
    ///   cannot be fixed per fragment
    /// - NIST 800-53: SC-5 - `reassembly_slots` × `max_reassembly_bytes`
    #[cold]
    #[inline(never)]
    fn reasm_first_v6<M: Mode>(&self, buf: &mut [u8], start: usize, len: usize, h: &Ipv6Hdr, ctx: &mut WorkerCtx) -> R {
        let f = h.frag.ok_or(DropReason::Malformed)?;
        if !ctx.ftab.reassembly_enabled() {
            return Err(DropReason::Fragment);
        }
        if h.l4_off != h.frag_end {
            return Err(DropReason::UnsupportedProto);
        }
        // Stateful NAT64: an IPv6 source inside the NAT64 prefix is spoofed.
        if self.prefix.contains(h.src) {
            return Err(DropReason::SrcNotAllowed);
        }
        frag_bounds(f, h.l4_len())?;
        ctx.counters.inc(Counter::FragmentsInV6);
        let mut hdr = [0u8; 40];
        write_v6_header(&mut hdr, h.traffic_class, 0, h.proto, h.hop_limit, h.src, h.dst);
        let payload = (start + h.l4_off, start + len.min(h.total_len()));
        self.reasm_first::<M>(key6(h, f), f, &hdr, payload, buf, ctx)
    }

    /// First fragment of a fragmented ICMPv6 error: reassembled only when it
    /// quotes a packet sent to a client address, and a client sender only
    /// reports about its own subscriber prefix (the checks
    /// [`Nat64::icmp6_error`] applies to the whole datagram).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5, SC-7 - authorise before reassembly (SEC-001)
    #[cold]
    #[inline(never)]
    fn reasm_error_v6<M: Mode>(&self, buf: &mut [u8], start: usize, len: usize, h: &Ipv6Hdr, ctx: &mut WorkerCtx) -> R {
        // Quoted IPv6 destination: ICMPv6 header (8) + offset 24.
        let q = start + h.l4_off + 8 + 24;
        let idst = buf.get(q..q + 16).and_then(|b| <[u8; 16]>::try_from(b).ok()).map(u128::from_be_bytes);
        let Some(idst) = idst.filter(|&a| self.is_client(a)) else {
            return Err(DropReason::SrcNotAllowed);
        };
        if self.is_client(h.src) && (h.src ^ idst) & self.sub_mask != 0 {
            return Err(DropReason::Filtered);
        }
        self.reasm_first_v6::<M>(buf, start, len, h, ctx)
    }

    /// First fragment of an IPv4 datagram that must be reassembled (ICMP
    /// echo, ICMP errors, zero-checksum UDP). A reassembly slot is only
    /// spent on a datagram that could be translated: echo and UDP must pass
    /// the filter (read-only), and an ICMP error must quote a packet sent
    /// from the pool address it is addressed to.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5, SC-7 - authorise before reassembly (SEC-001)
    #[cold]
    #[inline(never)]
    fn reasm_first_v4<M: Mode>(&self, buf: &mut [u8], start: usize, h: &Ipv4Hdr, l4: L4, ctx: &mut WorkerCtx) -> R {
        let f = h.frag.ok_or(DropReason::Malformed)?;
        if !ctx.ftab.reassembly_enabled() {
            return Err(DropReason::Fragment);
        }
        match self.inbound_key(h, l4) {
            Some((k4, remote)) => {
                self.state.filter_inbound(k4, remote)?;
            }
            None => {
                // ICMP error: quoted IPv4 source at ICMP header + 12.
                let q = h.hdr_len + 8 + 12;
                let pkt = buf.get(start..start + h.total_len).ok_or(DropReason::Malformed)?;
                let isrc = pkt.get(q..q + 4).and_then(|b| <[u8; 4]>::try_from(b).ok()).map(u32::from_be_bytes);
                if isrc != Some(h.dst) {
                    return Err(DropReason::Filtered);
                }
            }
        }
        frag_bounds(f, h.payload_len())?;
        ctx.counters.inc(Counter::FragmentsInV4);
        let mut hdr = [0u8; 60];
        let hb = buf.get(start..start + h.hdr_len).ok_or(DropReason::Malformed)?;
        hdr[..h.hdr_len].copy_from_slice(hb);
        let payload = (start + h.hdr_len, start + h.total_len);
        self.reasm_first::<M>(key4(h, f), f, &hdr[..h.hdr_len], payload, buf, ctx)
    }

    /// Opens (or joins) the reassembly of `key` with its first fragment.
    fn reasm_first<M: Mode>(
        &self,
        key: FragKey,
        f: Frag,
        hdr: &[u8],
        (ps, pe): (usize, usize),
        buf: &[u8],
        ctx: &mut WorkerCtx,
    ) -> R {
        let now = self.state.now_ms();
        let i = ctx.ftab.get_or_insert(&key, now, &ctx.counters)?;
        let plen = pe.saturating_sub(ps);
        let acct = ctx.ftab.account(i, 0, plen, f.more, &ctx.counters)?;
        if ctx.ftab.state(i) == Some(St::Pending)
            && let Err(d) = ctx.ftab.start_reasm(i, hdr, hdr.first().is_some_and(|b| b >> 4 == 6), &ctx.counters)
        {
            ctx.ftab.abandon(i, d, &ctx.counters);
            return Err(d);
        }
        let payload = buf.get(ps..pe).ok_or(DropReason::Malformed)?;
        if let Err(d) = ctx.ftab.reasm_put(i, 0, payload) {
            ctx.ftab.poison(i, d, &ctx.counters);
            return Err(d);
        }
        if acct == Acct::Complete { self.finish_reasm::<M>(i, ctx) } else { Ok(Out::Held) }
    }

    /// Runs a complete reassembled datagram through the normal path and
    /// copies the result into the fragment output.
    fn finish_reasm<M: Mode>(&self, i: usize, ctx: &mut WorkerCtx) -> R {
        let Reassembled { slot, buf: mut b, start: s, len: l } = match ctx.ftab.take_reasm(i) {
            Ok(v) => v,
            Err(d) => {
                ctx.ftab.abandon(i, d, &ctx.counters);
                return Err(d);
            }
        };
        ctx.counters.inc(Counter::DatagramsReassembled);
        let prev = std::mem::replace(&mut ctx.reassembled, true);
        let r = self.dispatch::<M>(&mut b, s, l, ctx);
        ctx.reassembled = prev;
        let r = match r {
            Ok(Out::Pkt(s, l)) => match b.get(s..s + l) {
                Some(p) => {
                    ctx.frags.push_copy(&mut ctx.frag_out, p).map(|()| Out::Frags(ctx.frags.count)).map_err(from_xlat)
                }
                None => Err(DropReason::Malformed),
            },
            o => o,
        };
        ctx.ftab.return_reasm(slot, b);
        r
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
    /// - RFC 7915 §5.3 - a quoted non-first fragment is mapped through this
    ///   worker's record of the fragments it sent
    fn icmp6_error<M: Mode>(&self, buf: &mut [u8], start: usize, len: usize, ctx: &mut WorkerCtx) -> R {
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let mut h = parse_v6(pkt).map_err(from_parse)?;
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
        let (mut ih, il4) = quoted_v6(pkt, &h).map_err(from_xlat)?;
        // Quoted: src = synthesized server, dst = subscriber. The error must
        // be addressed to the quoted packet's source.
        if ih.src != h.dst {
            return Err(DropReason::Filtered);
        }
        let server4 = self.prefix.extract(ih.src).ok_or(DropReason::DstNotTranslatable)?;
        if self.dst_forbidden(server4) {
            return Err(DropReason::DstForbidden);
        }
        if self.state.pool.local_in(M::SLICED, server4).is_some() {
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
        let (k4, inner) = match il4 {
            Some(il4) => {
                let (p, q_sport, q_dport) = match il4 {
                    L4::Tcp { sport, dport, .. } => (proto::TCP, sport, dport),
                    L4::Udp { sport, dport, .. } => (proto::UDP, sport, dport),
                    L4::Icmp { id, .. } => (proto::ICMP, id, id),
                };
                let k4 =
                    self.state.lookup6(Key6 { proto: p, addr: ih.dst, port: q_dport }).ok_or(DropReason::NoBinding)?;
                self.state.pool.check_addr(k4.addr)?;
                let remote = if p == proto::ICMP { (server4, 0) } else { (server4, q_sport) };
                if !self.state.has_session(k4, remote) {
                    return Err(DropReason::Filtered);
                }
                let inner = if p == proto::ICMP {
                    Map4 { src: server4, dst: k4.addr, sport: k4.port, dport: 0 }
                } else {
                    Map4 { src: server4, dst: k4.addr, sport: q_sport, dport: k4.port }
                };
                (k4.addr, inner)
            }
            None => {
                let f = ih.frag.ok_or(DropReason::Malformed)?;
                let key = FragKey { src: ih.src, dst: ih.dst, id: f.id, proto: ih.proto, kind: Kind::Sent6 };
                let now = self.state.now_ms();
                let i = ctx.ftab.find(&key, now, &ctx.counters).ok_or(DropReason::IcmpQuoteUnmatched)?;
                let Some(St::Pass(Fwd::Sent6 { pool, idx })) = ctx.ftab.state(i) else {
                    return Err(DropReason::IcmpQuoteUnmatched);
                };
                self.state.pool.check_idx_in(M::SLICED, idx)?;
                (pool, Map4 { src: server4, dst: pool, sport: 0, dport: 0 })
            }
        };
        // RFC 6791: the error is sent from the pool address of the affected
        // mapping (the IPv6 source is never translatable here, see above).
        if !self.copy_tos {
            // RFC-104: the switch applies to translated errors too.
            h.traffic_class = 0;
            ih.traffic_class = 0;
        }
        let ident = self.ident_key.next(&mut ctx.ident, h.src, k4, proto::ICMP);
        let n = icmp6_err_to_v4(pkt, &h, &ih, (k4, server4), &inner, ident, self.mtu4, self.mtu6, &mut ctx.scratch)
            .map_err(from_xlat)?;
        Self::emit_scratch(buf, start, n, ctx, Counter::IcmpErrorsTranslated)
    }

    /// ICMPv4 error about a packet we previously translated v6→v4.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-7 - the quoted flow must pass the configured
    ///   filtering (a live session under ADF/APDF; the BIB under EIF)
    /// - RFC 6146 §3.5.1.2 / §3.5.3, RFC 7915 §4.2
    /// - RFC 7915 §4.3 - a quoted non-first fragment is mapped through this
    ///   worker's record of the fragments it sent
    fn icmp4_error<M: Mode>(&self, buf: &mut [u8], start: usize, len: usize, ctx: &mut WorkerCtx) -> R {
        let pkt = buf.get(start..start + len).ok_or(DropReason::Malformed)?;
        let mut h = parse_v4(pkt).map_err(from_parse)?;
        let (mut ih, il4) = quoted_v4(pkt, &h).map_err(from_xlat)?;
        // Quoted: src = our pool address, dst = server.
        if ih.src != h.dst {
            return Err(DropReason::Filtered);
        }
        let (sub, inner) = match il4 {
            Some(il4) => {
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
                (k6.addr, inner)
            }
            None => {
                let f = ih.frag.ok_or(DropReason::Malformed)?;
                let key = FragKey {
                    src: u128::from(ih.src),
                    dst: u128::from(ih.dst),
                    id: u32::from(ih.id),
                    proto: ih.proto,
                    kind: Kind::Sent4,
                };
                let now = self.state.now_ms();
                let i = ctx.ftab.find(&key, now, &ctx.counters).ok_or(DropReason::IcmpQuoteUnmatched)?;
                let Some(St::Pass(Fwd::Sent4 { sub, id, idx, sport, dport })) = ctx.ftab.state(i) else {
                    return Err(DropReason::IcmpQuoteUnmatched);
                };
                // COMPLIANCE MAPPING:
                // - NIST 800-53: SC-7, SC-24 - the quoted fragment's mapping
                //   must still be served here and pass the configured filter
                //   (a live session under ADF/APDF, the BIB under EIF) for
                //   the same subscriber (SEC-004): a guessed 16-bit ID alone
                //   reaches no one
                self.state.pool.check_idx_in(M::SLICED, idx)?;
                let k6 =
                    self.state.filter_inbound(Key4 { proto: ih.proto, addr: ih.src, port: sport }, (ih.dst, dport))?;
                if k6.addr != sub {
                    return Err(DropReason::Filtered);
                }
                // The quoted fragment carried the original 32-bit ID.
                ih.frag = Some(Frag { id, ..f });
                (sub, Map6 { src: sub, dst: self.prefix.embed(ih.dst), sport: 0, dport: 0 })
            }
        };
        let outer = (self.prefix.embed(h.src), sub);
        if !self.copy_tos {
            h.tos = 0;
            ih.tos = 0;
        }
        let n =
            icmp4_err_to_v6(pkt, &h, &ih, outer, &inner, self.mtu4, self.mtu6, &mut ctx.scratch).map_err(from_xlat)?;
        Self::emit_scratch(buf, start, n, ctx, Counter::IcmpErrorsTranslated)
    }
}
