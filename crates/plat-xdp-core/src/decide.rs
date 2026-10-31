//! The per-packet decision of the fast path, generic over [`Env`] (map
//! lookups, `bpf_fib_lookup`, clock, IPv4 ID counters), which the eBPF
//! program implements with Aya maps and helpers and the host tests with
//! in-memory tables.
//!
//! Every check runs on values copied to the stack before anything is
//! written: the decision only returns the output header block, and the
//! caller writes it after its last decline point (plan §2.5 rule 3). Any
//! failed check returns [`Verdict::Pass`] with the reason, and the frame
//! goes to the slow path unmodified.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-7, SC-7(5) - forward only an exact 5-tuple match of a
//!   session `platd` installed after its own policy checks (client prefix,
//!   RFC 6052 §3.1, non-global IPv4, filtering); anything else passes into
//!   the host policy; interface roles and the egress allow-list are
//!   enforced here (plan §6)
//! - NIST 800-53: SC-24 (Fail in Known State) - the record's slice must be
//!   Active with the record's generation, `CONTROL.enabled` set and the
//!   `platd` dead-man deadline in the future; `bpf_fib_lookup` from the TUN
//!   fails with `FWD_DISABLED` when `plat-fwguard` turns forwarding off
//! - NIST 800-53: SC-5 - no state is created per packet
//! - RFC 6146 §3.5.1 - UDP session lookup and lifetime refresh (`seen`)
//! - RFC 7915 §4, §5 - oversize packets are left to the slow path, which
//!   fragments or sends Packet Too Big / Fragmentation Needed

use crate::abi::{
    AF_INET, AF_INET6, Control, EgressEnt, FIB_RET_FRAG_NEEDED, FIB_RET_FWD_DISABLED, FIB_RET_NO_NEIGH,
    FIB_RET_SUCCESS, FibParams, IfaceEnt, Key4, Key6, PassReason, ROLE_ACCESS, ROLE_UPSTREAM, SEEN_GRANULARITY_NS,
    SLICE_ACTIVE, SLOT_LIVE, SliceEnt, SlotRec, XlatConfig,
};
use crate::classify::{self, ETHERTYPE_IPV4, ETHERTYPE_IPV6, PROTO_UDP, V4Meta, V6Meta};
use crate::rewrite::{self, Out4Params, Out6Params};
use crate::take;
use crate::{ETH, HDR4, HDR6, IP4, IP6};

/// What the decision reads from (and the few things it asks of) the
/// environment. The eBPF program implements it with map lookups and
/// helpers; the host tests with tables filled from the `plat-nat64` engine.
pub trait Env {
    /// `IFACES[iface_slot(ifindex)]`.
    fn iface(&self, ifindex: u32) -> Option<IfaceEnt>;
    /// `CONTROL[0]`.
    fn control(&self) -> Option<Control>;
    /// The per-packet fields of `CONFIG[0]`.
    fn config(&self) -> Option<XlatConfig>;
    /// `bpf_ktime_get_coarse_ns` (the clock of `deadline_ns` and `seen_ns`).
    fn now_ns(&self) -> u64;
    /// `OUT6[key]` → slot index.
    fn out6(&self, key: &Key6) -> Option<u32>;
    /// `IN4[key]` → slot index.
    fn in4(&self, key: &Key4) -> Option<u32>;
    /// A copy of `SLOT[idx]`.
    fn slot(&self, idx: u32) -> Option<SlotRec>;
    /// `SLICE[idx]`.
    fn slice(&self, idx: u16) -> Option<SliceEnt>;
    /// `bpf_fib_lookup(ctx, p, 64, 0)`: fills the egress ifindex and MACs
    /// on success and returns a `FIB_RET_*` code (negative on error).
    fn fib(&mut self, p: &mut FibParams) -> i64;
    /// `EGRESS[iface_slot(ifindex)]`.
    fn egress(&self, ifindex: u32) -> Option<EgressEnt>;
    /// Next IPv4 Identification for `(src6, dst4, UDP)` (see
    /// [`crate::ident`]); called only for DF = 0 packets that will be
    /// forwarded.
    fn ident(&mut self, src6: &[u8; 16], dst4: &[u8; 4]) -> u16;
}

/// Result of a decision for one direction. `H` is the output header block:
/// `[u8; 42]` (Ethernet + IPv4 + UDP) or `[u8; 62]` (Ethernet + IPv6 + UDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<H> {
    /// Translate and transmit: move the packet start by the header-size
    /// difference, write `hdr` at the new start, trim `trim` trailing bytes
    /// (so the frame is `new_len` bytes), store `touch` in
    /// `SLOT[slot].seen_ns` if set, and redirect to `ifindex`.
    Redirect { ifindex: u32, hdr: H, new_len: u32, trim: u32, slot: u32, touch: Option<u64> },
    /// Hand the unmodified frame to the kernel (`XDP_PASS`).
    Pass(PassReason),
}

/// [`decide_frame`]'s result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// IPv6 → IPv4: replace the first [`HDR6`] bytes with the [`HDR4`]
    /// header.
    V6ToV4(Verdict<[u8; HDR4]>),
    /// IPv4 → IPv6: replace the first [`HDR4`] bytes with the [`HDR6`]
    /// header.
    V4ToV6(Verdict<[u8; HDR6]>),
    /// Declined before a direction was chosen (short frame, not IP).
    Pass(PassReason),
}

impl Action {
    /// The pass reason, or `None` for a redirect.
    pub fn pass_reason(&self) -> Option<PassReason> {
        match self {
            Self::V6ToV4(Verdict::Pass(r)) | Self::V4ToV6(Verdict::Pass(r)) | Self::Pass(r) => Some(*r),
            _ => None,
        }
    }
}

/// Decides a whole frame received on `ingress`: dispatches on the Ethertype
/// to [`decide_v6`] / [`decide_v4`]. A frame shorter than the direction's
/// fixed header block is `bad_l3`; one without an Ethernet header, or with
/// any other Ethertype (VLAN included), is `not_ip`.
#[inline(always)]
pub fn decide_frame<E: Env>(env: &mut E, ingress: u32, frame: &[u8]) -> Action {
    let Ok(frame_len) = u32::try_from(frame.len()) else {
        return Action::Pass(PassReason::BadL3);
    };
    let Some(eth) = frame.first_chunk::<ETH>() else {
        return Action::Pass(PassReason::NotIp);
    };
    match classify::ethertype(eth) {
        ETHERTYPE_IPV6 => match frame.first_chunk::<HDR6>() {
            Some(h) => Action::V6ToV4(decide_v6(env, ingress, h, frame_len)),
            None => Action::Pass(PassReason::BadL3),
        },
        ETHERTYPE_IPV4 => match frame.first_chunk::<HDR4>() {
            Some(h) => Action::V4ToV6(decide_v4(env, ingress, h, frame_len)),
            None => Action::Pass(PassReason::BadL3),
        },
        _ => Action::Pass(PassReason::NotIp),
    }
}

/// The ingress interface entry, its role and the destination MAC.
#[inline(always)]
fn check_iface<E: Env, const N: usize>(env: &E, ingress: u32, h: &[u8; N], role: u8) -> Result<(), PassReason> {
    let ent = env.iface(ingress).ok_or(PassReason::Role)?;
    // IFACES is indexed by `ifindex % IFACE_SLOTS`: the stored ifindex
    // tells a configured interface from one that shares its slot.
    if ent.ifindex != ingress || ent.role & role == 0 {
        return Err(PassReason::Role);
    }
    let dmac: [u8; 6] = take(h, 0);
    if dmac != ent.mac {
        return Err(PassReason::NotForUs);
    }
    Ok(())
}

/// `CONTROL` gate: enabled and before the dead-man deadline. Returns the
/// control record and the clock reading.
#[inline(always)]
fn check_control<E: Env>(env: &E) -> Result<(Control, u64), PassReason> {
    let c = env.control().ok_or(PassReason::Disabled)?;
    if c.enabled != 1 || c.tun_ifindex == 0 {
        return Err(PassReason::Disabled);
    }
    let now = env.now_ns();
    if now >= c.deadline_ns {
        return Err(PassReason::Deadline);
    }
    Ok((c, now))
}

/// The record's slice must be Active with the record's generation.
#[inline(always)]
fn check_slice<E: Env>(env: &E, rec: &SlotRec) -> Result<(), PassReason> {
    let s = env.slice(rec.slice).ok_or(PassReason::SliceInactive)?;
    if s.state != SLICE_ACTIVE || s.generation != rec.generation {
        return Err(PassReason::SliceInactive);
    }
    Ok(())
}

/// `bpf_fib_lookup` from the TUN, then the egress allow-list. Returns the
/// FIB result (egress ifindex and MACs).
#[inline(always)]
fn route<E: Env>(env: &mut E, mut fib: FibParams) -> Result<FibParams, PassReason> {
    match env.fib(&mut fib) {
        FIB_RET_SUCCESS => {}
        FIB_RET_FWD_DISABLED => return Err(PassReason::FibFwdDisabled),
        FIB_RET_NO_NEIGH => return Err(PassReason::FibNoNeigh),
        FIB_RET_FRAG_NEEDED => return Err(PassReason::FibFragNeeded),
        _ => return Err(PassReason::FibOther),
    }
    match env.egress(fib.ifindex) {
        Some(e) if e.ifindex == fib.ifindex && e.allowed == 1 => Ok(fib),
        _ => Err(PassReason::EgressNotAllowed),
    }
}

#[inline(always)]
fn touch(now: u64, seen: u64) -> Option<u64> {
    (now.wrapping_sub(seen) >= SEEN_GRANULARITY_NS).then_some(now)
}

/// IPv6 → IPv4 on an `access` (or `both`) interface: plan §2.3 steps 1–9.
#[inline(always)]
pub fn decide_v6<E: Env>(env: &mut E, ingress: u32, h: &[u8; HDR6], frame_len: u32) -> Verdict<[u8; HDR4]> {
    match try_v6(env, ingress, h, frame_len) {
        Ok(v) => v,
        Err(r) => Verdict::Pass(r),
    }
}

#[inline(always)]
fn try_v6<E: Env>(
    env: &mut E,
    ingress: u32,
    h: &[u8; HDR6],
    frame_len: u32,
) -> Result<Verdict<[u8; HDR4]>, PassReason> {
    if classify::ethertype(h) != ETHERTYPE_IPV6 {
        return Err(PassReason::NotIp);
    }
    check_iface(env, ingress, h, ROLE_ACCESS)?;
    let m: V6Meta = classify::classify_v6(h, frame_len)?;
    let (ctl, now) = check_control(env)?;

    let slot = env.out6(&Key6::new(m.src6, m.dst6, m.sport, m.dport)).ok_or(PassReason::NoSession)?;
    let rec = env.slot(slot).ok_or(PassReason::SlotDead)?;
    if rec.state != SLOT_LIVE
        || rec.src6 != m.src6
        || rec.sport6 != m.sport
        || rec.dst6 != m.dst6
        || rec.dport != m.dport
    {
        return Err(PassReason::SlotDead);
    }
    check_slice(env, &rec)?;

    // Size: the IPv6 packet must fit the TUN (else the kernel answers
    // Packet Too Big and `platd` never sees it), and its translation must
    // fit `ipv4_mtu` (else `platd` fragments it or sends Packet Too Big).
    let cfg = env.config().ok_or(PassReason::Disabled)?;
    let total = rewrite::v4_total(m.payload_len);
    if IP6 as u32 + u32::from(m.payload_len) > ctl.tun_mtu || total > u32::from(cfg.mtu4) {
        return Err(PassReason::TooBig);
    }
    let tos = if cfg.copy_tos { m.traffic_class } else { 0 };

    let mut fib = FibParams {
        family: AF_INET,
        l4_protocol: PROTO_UDP,
        sport: rec.pool_port4,
        dport: m.dport,
        tot_len: total as u16,
        ifindex: ctl.tun_ifindex,
        tos: [tos, 0, 0, 0],
        ..FibParams::default()
    };
    crate::put(&mut fib.src, 0, &rec.pool4);
    crate::put(&mut fib.dst, 0, &rec.dst4);
    let fib = route(env, fib)?;

    // Last decline point passed: only now draw an ID (DF = 0 only).
    let ident = if total > rewrite::DF_THRESHOLD { 0 } else { env.ident(&m.src6, &rec.dst4) };
    let p = Out4Params {
        dmac: fib.dmac,
        smac: fib.smac,
        tos,
        ident,
        pool4: rec.pool4,
        dst4: rec.dst4,
        pool_port4: rec.pool_port4,
    };
    Ok(Verdict::Redirect {
        ifindex: fib.ifindex,
        hdr: rewrite::rewrite_v6_to_v4(h, &p),
        new_len: ETH as u32 + total,
        trim: m.trailing,
        slot,
        touch: touch(now, rec.seen_ns),
    })
}

/// IPv4 → IPv6 on an `upstream` (or `both`) interface: the mirror image of
/// [`decide_v6`].
#[inline(always)]
pub fn decide_v4<E: Env>(env: &mut E, ingress: u32, h: &[u8; HDR4], frame_len: u32) -> Verdict<[u8; HDR6]> {
    match try_v4(env, ingress, h, frame_len) {
        Ok(v) => v,
        Err(r) => Verdict::Pass(r),
    }
}

#[inline(always)]
fn try_v4<E: Env>(
    env: &mut E,
    ingress: u32,
    h: &[u8; HDR4],
    frame_len: u32,
) -> Result<Verdict<[u8; HDR6]>, PassReason> {
    if classify::ethertype(h) != ETHERTYPE_IPV4 {
        return Err(PassReason::NotIp);
    }
    check_iface(env, ingress, h, ROLE_UPSTREAM)?;
    let m: V4Meta = classify::classify_v4(h, frame_len)?;
    let (ctl, now) = check_control(env)?;

    let slot = env.in4(&Key4::new(m.dst4, m.src4, m.dport, m.sport)).ok_or(PassReason::NoSession)?;
    let rec = env.slot(slot).ok_or(PassReason::SlotDead)?;
    if rec.state != SLOT_LIVE
        || rec.pool4 != m.dst4
        || rec.dst4 != m.src4
        || rec.pool_port4 != m.dport
        || rec.dport != m.sport
    {
        return Err(PassReason::SlotDead);
    }
    check_slice(env, &rec)?;

    // Size, in `plat_nat64` `inbound_v4` order: the IPv4 packet must reach
    // the TUN whole; the translation must fit `ipv6_mtu`, and with DF = 0
    // the lowest IPv6 MTU (else `platd` fragments it or sends Frag Needed).
    let cfg = env.config().ok_or(PassReason::Disabled)?;
    let payload = u32::from(m.total_len) - IP4 as u32;
    let out = IP6 as u32 + payload;
    if u32::from(m.total_len) > ctl.tun_mtu || out > u32::from(cfg.mtu6) || (!m.df && out > u32::from(cfg.frag6)) {
        return Err(PassReason::TooBig);
    }
    let tc = if cfg.copy_tos { m.tos } else { 0 };

    let mut fib = FibParams {
        family: AF_INET6,
        l4_protocol: PROTO_UDP,
        sport: m.sport,
        dport: rec.sport6,
        tot_len: out as u16,
        ifindex: ctl.tun_ifindex,
        // flowinfo (__be32): traffic class, flow label 0.
        tos: (u32::from(tc) << 20).to_be_bytes(),
        src: rec.dst6,
        dst: rec.src6,
        ..FibParams::default()
    };
    fib = route(env, fib)?;

    let p = Out6Params {
        dmac: fib.dmac,
        smac: fib.smac,
        traffic_class: tc,
        src6: rec.dst6,
        dst6: rec.src6,
        dport6: rec.sport6,
    };
    Ok(Verdict::Redirect {
        ifindex: fib.ifindex,
        hdr: rewrite::rewrite_v4_to_v6(h, &p),
        new_len: ETH as u32 + out,
        trim: m.trailing,
        slot,
        touch: touch(now, rec.seen_ns),
    })
}
