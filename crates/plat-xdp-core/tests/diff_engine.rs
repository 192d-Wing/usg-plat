//! Level-1 differential harness (plan §11): the same frames through
//! `plat-xdp-core` (over a host `Env` filled from engine state) and through
//! the full `plat-nat64` engine between the modelled kernel hops, compared
//! byte for byte (IPv4 ID substituted, plan §2.4).
//!
//! Properties (`PROPTEST_CASES`, default 10 000; CI sets 1 000 000):
//! - safety: a candidate redirect implies the reference emits exactly that
//!   frame;
//! - liveness: every packet of the canonical eligible class is redirected;
//! - subset: a classifier accept implies a `plat-packet` accept with
//!   identical fields;
//! - never-redirect cases, and the fixed vectors of `tests/vectors/`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11, SA-11(1) - differential testing of the fast path
//!   against the slow path; SI-10 - subset property against `plat-packet`

mod support;

use std::cell::RefCell;
use std::collections::HashMap;

use plat_nat64::SliceState;
use plat_packet::{L4, parse_l4, parse_v4, parse_v6};
use plat_xdp_core::abi::{
    ROLE_BOTH, SLICE_ACTIVE, SLICE_ADOPTING, SLICE_FENCED, SLICE_INACTIVE, SLOT_DEAD, SlotRec, iface_slot,
};
use plat_xdp_core::decide::{Action, Verdict};
use plat_xdp_core::{HDR4, HDR6, PassReason, classify_v4, classify_v6, decide_frame};
use proptest::prelude::*;
use support::*;

// ---------------------------------------------------------------------
// Fixtures

thread_local! {
    static FX: RefCell<HashMap<(usize, bool), Reference>> = RefCell::new(HashMap::new());
}

fn knobs(prefix: usize, copy_tos: bool) -> Knobs {
    Knobs { prefix: PREFIXES[prefix % PREFIXES.len()], copy_tos, ..Knobs::default() }
}

/// Runs `f` on the cached reference for `(prefix, copy_tos)`, rebuilt
/// after [`FIXTURE_USES`] packets.
fn with_fx<R>(prefix: usize, copy_tos: bool, f: impl FnOnce(&mut Reference) -> R) -> R {
    FX.with(|m| {
        let mut m = m.borrow_mut();
        let r = m.entry((prefix, copy_tos)).or_insert_with(|| Reference::new(&knobs(prefix, copy_tos)));
        if r.uses > FIXTURE_USES {
            *r = Reference::new(&knobs(prefix, copy_tos));
        }
        f(r)
    })
}

fn config() -> ProptestConfig {
    ProptestConfig { cases: cases(), ..ProptestConfig::default() }
}

const ETH6: [u8; 2] = [0x86, 0xdd];
const ETH4: [u8; 2] = [0x08, 0x00];

/// A subscriber packet of the session `s`.
fn out_frame(r: &Reference, s: &Session, payload: &[u8], f: impl FnOnce(&mut U6)) -> Vec<u8> {
    let mut h = U6::new(s.src6, s.sport, r.prefix.embed(s.dst4), s.dport);
    f(&mut h);
    eth(ACCESS_MAC, CLIENT_MAC, ETH6, &udp6(&h, payload))
}

/// A remote packet of the session `s`.
fn in_frame(s: &Session, payload: &[u8], f: impl FnOnce(&mut U4)) -> Vec<u8> {
    let mut h = U4::new(s.dst4, s.dport, s.pool4, s.pool_port);
    f(&mut h);
    eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &udp4(&h, payload))
}

// ---------------------------------------------------------------------
// Proptest inputs

#[derive(Debug, Clone)]
struct Flow {
    prefix: usize,
    copy_tos: bool,
    host: u128,
    sport: u16,
    net: u8,
    srv: u8,
    dport: u16,
}

fn flow() -> impl Strategy<Value = Flow> {
    (0..PREFIXES.len(), any::<bool>(), any::<u128>(), any::<u16>(), 0..2u8, 1..=254u8, any::<u16>()).prop_map(
        |(prefix, copy_tos, host, sport, net, srv, dport)| Flow { prefix, copy_tos, host, sport, net, srv, dport },
    )
}

/// Per-packet fields. `edge`: 0 none, 1 input checksum field 0xFFFF, 2
/// output checksum computes to 0 (sent as 0xFFFF).
#[derive(Debug, Clone)]
struct Pkt {
    payload: Vec<u8>,
    hop: u8,
    tc: u8,
    flow_label: u32,
    id: u16,
    df: bool,
    edge: u8,
}

fn pkt(max_payload: usize) -> impl Strategy<Value = Pkt> {
    (
        proptest::collection::vec(any::<u8>(), 0..=max_payload),
        3..=255u8,
        any::<u8>(),
        0..0x10_0000u32,
        any::<u16>(),
        any::<bool>(),
        0..3u8,
    )
        .prop_map(|(payload, hop, tc, flow_label, id, df, edge)| Pkt {
            payload,
            hop,
            tc,
            flow_label,
            id,
            df,
            edge,
        })
}

/// Largest UDP payload of the canonical class: a 1500-byte IPv6 packet
/// (TUN and ipv6_mtu 1500).
const MAX_PAYLOAD: usize = 1452;
/// Largest DF = 0 inbound payload: lowest_ipv6_mtu 1280 − 48.
const MAX_PAYLOAD_DF0: usize = 1232;

fn establish_flow(r: &mut Reference, env: &mut HostEnv, f: &Flow) -> Result<Session, String> {
    establish(r, env, client(f.host), f.sport, server(f.net, f.srv), f.dport)
}

/// Outbound packet of the canonical class for `p`.
fn canonical_out(r: &Reference, s: &Session, p: &Pkt) -> Vec<u8> {
    let dst6 = r.prefix.embed(s.dst4);
    let mut payload = p.payload.clone();
    let n = payload.len();
    match p.edge {
        1 => force_zero_csum(&mut payload, base_sum6(s.src6, dst6, s.sport, s.dport, n)),
        2 => force_zero_csum(&mut payload, base_sum4(s.pool4, s.dst4, s.pool_port, s.dport, n)),
        _ => {}
    }
    out_frame(r, s, &payload, |h| {
        h.hop = p.hop;
        h.tc = p.tc;
        h.flow = p.flow_label;
    })
}

/// Inbound packet of the canonical class for `p`.
fn canonical_in(r: &Reference, s: &Session, p: &Pkt) -> Vec<u8> {
    let mut payload = p.payload.clone();
    let n = payload.len();
    match p.edge {
        1 => force_zero_csum(&mut payload, base_sum4(s.dst4, s.pool4, s.dport, s.pool_port, n)),
        2 => force_zero_csum(&mut payload, base_sum6(r.prefix.embed(s.dst4), s.src6, s.dport, s.sport, n)),
        _ => {}
    }
    in_frame(s, &payload, |h| {
        h.ttl = p.hop;
        h.tos = p.tc;
        h.id = p.id;
        h.df = p.df;
    })
}

/// Safety and liveness for one canonical packet in one direction.
fn live(f: &Flow, p: &Pkt, outbound: bool) -> Result<(), String> {
    with_fx(f.prefix, f.copy_tos, |r| {
        let mut env = HostEnv::new(&r.cfg, Net::default());
        let s = establish_flow(r, &mut env, f)?;
        let (frame, ingress) = if outbound {
            (canonical_out(r, &s, p), ACCESS_IF)
        } else {
            // The canonical class: DF = 0 packets fit the lowest IPv6 MTU.
            let mut p = p.clone();
            if !p.df {
                p.payload.truncate(MAX_PAYLOAD_DF0);
            }
            (canonical_in(r, &s, &p), UPSTREAM_IF)
        };
        match differential(r, &mut env, &frame, ingress)? {
            None => Ok(()),
            Some(reason) => Err(format!("liveness: canonical packet passed ({}): {}", reason.as_str(), hex(&frame))),
        }
    })
}

/// A packet mutated after construction: XOR at offsets (taken modulo the
/// frame length), then a cut from the end, then trailing bytes.
#[derive(Debug, Clone)]
struct Mutation {
    xors: Vec<(usize, u8)>,
    cut: usize,
    extra: Vec<u8>,
    /// Restrict the XOR offsets to the fixed header block.
    header_only: bool,
}

fn mutation() -> impl Strategy<Value = Mutation> {
    (
        proptest::collection::vec((any::<usize>(), 1..=255u8), 0..4),
        prop_oneof![3 => Just(0usize), 1 => 0..16usize],
        prop_oneof![3 => Just(Vec::new()), 1 => proptest::collection::vec(any::<u8>(), 0..24)],
        any::<bool>(),
    )
        .prop_map(|(xors, cut, extra, header_only)| Mutation { xors, cut, extra, header_only })
}

fn mutate(mut frame: Vec<u8>, m: &Mutation, hdr: usize) -> Vec<u8> {
    for &(i, x) in &m.xors {
        let span = if m.header_only { hdr.min(frame.len()) } else { frame.len() };
        if span > 0 {
            frame[i % span] ^= x;
        }
    }
    let keep = frame.len().saturating_sub(m.cut);
    frame.truncate(keep);
    frame.extend_from_slice(&m.extra);
    frame
}

proptest! {
    #![proptest_config(config())]

    /// Liveness + safety, IPv6 → IPv4: addresses, ports, payload 0–1452,
    /// traffic class, flow label, hop limit 3–255, checksum edges, every
    /// RFC 6052 prefix length, `copy_tos` on and off.
    #[test]
    fn canonical_outbound_is_redirected_identically(f in flow(), p in pkt(MAX_PAYLOAD)) {
        let r = live(&f, &p, true);
        prop_assert!(r.is_ok(), "{}", r.err().unwrap_or_default());
    }

    /// Liveness + safety, IPv4 → IPv6: as above, plus TOS, ID and DF
    /// (payload ≤ 1232 with DF = 0).
    #[test]
    fn canonical_inbound_is_redirected_identically(f in flow(), p in pkt(MAX_PAYLOAD)) {
        let r = live(&f, &p, false);
        prop_assert!(r.is_ok(), "{}", r.err().unwrap_or_default());
    }

    /// Safety under arbitrary header and length mutations of established
    /// session packets, both directions: whatever is redirected equals the
    /// reference.
    #[test]
    fn mutated_packets_are_never_mistranslated(
        f in flow(), p in pkt(96), m in mutation(), outbound in any::<bool>(),
    ) {
        let res = with_fx(f.prefix, f.copy_tos, |r| {
            let mut env = HostEnv::new(&r.cfg, Net::default());
            let s = establish_flow(r, &mut env, &f)?;
            let (frame, ingress, hdr) = if outbound {
                (canonical_out(r, &s, &p), ACCESS_IF, HDR6)
            } else {
                (canonical_in(r, &s, &p), UPSTREAM_IF, HDR4)
            };
            let frame = mutate(frame, &m, hdr);
            differential(r, &mut env, &frame, ingress).map(|_| ())
        });
        prop_assert!(res.is_ok(), "{}", res.err().unwrap_or_default());
    }

    /// Subset: whatever the IPv6 classifier accepts, `plat-packet` accepts
    /// with identical field values.
    #[test]
    fn v6_accept_implies_plat_packet_accept(
        host in any::<u128>(), dst in any::<u128>(), sport in any::<u16>(), dport in any::<u16>(),
        p in pkt(64), m in mutation(),
    ) {
        let h = U6 { src: client(host), sport, dst, dport, hop: p.hop, tc: p.tc, flow: p.flow_label };
        let frame = mutate(eth(ACCESS_MAC, CLIENT_MAC, ETH6, &udp6(&h, &p.payload)), &m, HDR6);
        let Some(block) = frame.first_chunk::<HDR6>() else { return Ok(()) };
        let Ok(c) = classify_v6(block, frame.len() as u32) else { return Ok(()) };
        let l3 = &frame[14..];
        let ph = parse_v6(l3);
        prop_assert!(ph.is_ok(), "plat-packet refused an accepted frame: {:?}", ph);
        let Ok(ph) = ph else { return Ok(()) };
        prop_assert_eq!(ph.traffic_class, c.traffic_class);
        prop_assert_eq!(ph.flow_label, c.flow_label);
        prop_assert_eq!(ph.hop_limit, c.hop_limit);
        prop_assert_eq!(ph.payload_len, usize::from(c.payload_len));
        prop_assert_eq!(ph.src, u128::from_be_bytes(c.src6));
        prop_assert_eq!(ph.dst, u128::from_be_bytes(c.dst6));
        prop_assert_eq!((ph.proto, ph.l4_off, ph.frag), (17, 40, None));
        prop_assert_eq!(14 + ph.total_len() + c.trailing as usize, frame.len());
        let l4 = parse_l4(l3, ph.l4_off, ph.total_len(), ph.proto);
        prop_assert_eq!(l4, Ok(L4::Udp {
            sport: u16::from_be_bytes(c.sport), dport: u16::from_be_bytes(c.dport), csum: c.csum,
        }));
    }

    /// Subset, IPv4.
    #[test]
    fn v4_accept_implies_plat_packet_accept(
        src in any::<u32>(), dst in any::<u32>(), sport in any::<u16>(), dport in any::<u16>(),
        p in pkt(64), m in mutation(),
    ) {
        let h = U4 { src, sport, dst, dport, ttl: p.hop, tos: p.tc, id: p.id, df: p.df };
        let frame = mutate(eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &udp4(&h, &p.payload)), &m, HDR4);
        let Some(block) = frame.first_chunk::<HDR4>() else { return Ok(()) };
        let Ok(c) = classify_v4(block, frame.len() as u32) else { return Ok(()) };
        let l3 = &frame[14..];
        let ph = parse_v4(l3);
        prop_assert!(ph.is_ok(), "plat-packet refused an accepted frame: {:?}", ph);
        let Ok(ph) = ph else { return Ok(()) };
        prop_assert_eq!((ph.hdr_len, ph.total_len), (20, usize::from(c.total_len)));
        prop_assert_eq!((ph.tos, ph.id, ph.df, ph.ttl, ph.proto), (c.tos, c.id, c.df, c.ttl, 17));
        prop_assert_eq!(ph.src, u32::from_be_bytes(c.src4));
        prop_assert_eq!(ph.dst, u32::from_be_bytes(c.dst4));
        prop_assert!(ph.frag.is_none());
        prop_assert_eq!(14 + ph.total_len + c.trailing as usize, frame.len());
        let l4 = parse_l4(l3, ph.hdr_len, ph.total_len, ph.proto);
        prop_assert_eq!(l4, Ok(L4::Udp {
            sport: u16::from_be_bytes(c.sport), dport: u16::from_be_bytes(c.dport), csum: c.csum,
        }));
    }
}

// ---------------------------------------------------------------------
// Never redirect

struct Fx {
    r: Reference,
    env: HostEnv,
    s: Session,
}

fn fx_with(k: &Knobs, net: Net) -> Fx {
    let mut r = Reference::new(k);
    let mut env = HostEnv::new(&r.cfg, net);
    let s = ok(establish(&mut r, &mut env, client(0x5_0000_0000_0001), 40_000, server(1, 5), 53));
    Fx { r, env, s }
}

fn fx() -> Fx {
    fx_with(&Knobs::default(), Net::default())
}

impl Fx {
    fn out(&self) -> Vec<u8> {
        out_frame(&self.r, &self.s, b"payload", |_| {})
    }

    fn inb(&self) -> Vec<u8> {
        in_frame(&self.s, b"payload", |_| {})
    }

    /// Both directions' decisions (and the safety check).
    fn both(&mut self) -> (Option<PassReason>, Option<PassReason>) {
        let (o, i) = (self.out(), self.inb());
        let a = ok(differential(&mut self.r, &mut self.env, &o, ACCESS_IF));
        let b = ok(differential(&mut self.r, &mut self.env, &i, UPSTREAM_IF));
        (a, b)
    }
}

#[test]
fn baseline_redirects_both_directions() {
    assert_eq!(fx().both(), (None, None));
}

#[test]
fn slice_not_active_or_stale_generation_never_redirects() {
    for st in [SLICE_INACTIVE, SLICE_FENCED, SLICE_ADOPTING, 9] {
        let mut f = fx();
        f.env.slices[0].state = st;
        assert_eq!(f.both(), (Some(PassReason::SliceInactive), Some(PassReason::SliceInactive)), "state {st}");
    }
    let mut f = fx();
    f.env.slices[0].generation += 1;
    assert_eq!(f.both(), (Some(PassReason::SliceInactive), Some(PassReason::SliceInactive)));
    // A record naming a slice the map does not have.
    let mut f = fx();
    f.env.slots[f.s.slot as usize].slice = 1;
    assert_eq!(f.both(), (Some(PassReason::SliceInactive), Some(PassReason::SliceInactive)));
}

#[test]
fn slice_state_values_match_the_engine() {
    assert_eq!(SliceState::Inactive as u8, SLICE_INACTIVE);
    assert_eq!(SliceState::Active as u8, SLICE_ACTIVE);
    assert_eq!(SliceState::Fenced as u8, SLICE_FENCED);
    assert_eq!(SliceState::Adopting as u8, SLICE_ADOPTING);
}

#[test]
fn disabled_or_deadline_passed_never_redirects() {
    let mut f = fx();
    f.env.now = f.env.control.deadline_ns;
    assert_eq!(f.both(), (Some(PassReason::Deadline), Some(PassReason::Deadline)));
    let mut f = fx();
    f.env.now = u64::MAX;
    assert_eq!(f.both(), (Some(PassReason::Deadline), Some(PassReason::Deadline)));
    for en in [0, 2, u32::MAX] {
        let mut f = fx();
        f.env.control.enabled = en;
        assert_eq!(f.both(), (Some(PassReason::Disabled), Some(PassReason::Disabled)));
    }
    let mut f = fx();
    f.env.control.tun_ifindex = 0;
    assert_eq!(f.both(), (Some(PassReason::Disabled), Some(PassReason::Disabled)));
}

#[test]
fn hop_limit_two_or_less_never_redirects() {
    for hop in 0..=2u8 {
        let mut f = fx();
        let o = out_frame(&f.r, &f.s, b"x", |h| h.hop = hop);
        let i = in_frame(&f.s, b"x", |h| h.ttl = hop);
        assert_eq!(ok(differential(&mut f.r, &mut f.env, &o, ACCESS_IF)), Some(PassReason::HopLimit));
        assert_eq!(ok(differential(&mut f.r, &mut f.env, &i, UPSTREAM_IF)), Some(PassReason::HopLimit));
    }
}

#[test]
fn wrong_role_or_interface_never_redirects() {
    let mut f = fx();
    // IPv6 on the upstream interface, IPv4 on the access interface (frames
    // addressed to that interface's MAC).
    let mut o = f.out();
    o[..6].copy_from_slice(&UPSTREAM_MAC);
    let mut i = f.inb();
    i[..6].copy_from_slice(&ACCESS_MAC);
    assert_eq!(ok(differential(&mut f.r, &mut f.env, &o, UPSTREAM_IF)), Some(PassReason::Role));
    assert_eq!(ok(differential(&mut f.r, &mut f.env, &i, ACCESS_IF)), Some(PassReason::Role));
    // An unconfigured interface, and one sharing a configured one's slot.
    for ifindex in [9, ACCESS_IF + 64, UPSTREAM_IF + 128] {
        let (fo, fi) = (f.out(), f.inb());
        assert_eq!(decide_frame(&mut f.env, ifindex, &fo).pass_reason(), Some(PassReason::Role));
        assert_eq!(decide_frame(&mut f.env, ifindex, &fi).pass_reason(), Some(PassReason::Role));
    }
    // `both` accepts either direction.
    for ifindex in [ACCESS_IF, UPSTREAM_IF] {
        if let Some(e) = f.env.ifaces.get_mut(&iface_slot(ifindex)) {
            e.role = ROLE_BOTH;
        }
    }
    assert_eq!(decide_frame(&mut f.env, UPSTREAM_IF, &o).pass_reason(), None);
    assert_eq!(decide_frame(&mut f.env, ACCESS_IF, &i).pass_reason(), None);
}

#[test]
fn frames_not_for_this_interface_never_redirect() {
    let mut f = fx();
    for mac in [[0xff; 6], [0x33, 0x33, 0, 0, 0, 1], [0x01, 0x00, 0x5e, 0, 0, 1], CLIENT_MAC] {
        let mut o = f.out();
        o[..6].copy_from_slice(&mac);
        let mut i = f.inb();
        i[..6].copy_from_slice(&mac);
        assert_eq!(ok(differential(&mut f.r, &mut f.env, &o, ACCESS_IF)), Some(PassReason::NotForUs));
        assert_eq!(ok(differential(&mut f.r, &mut f.env, &i, UPSTREAM_IF)), Some(PassReason::NotForUs));
    }
}

#[test]
fn non_canonical_destination_never_redirects() {
    // /64: bits after the embedded address are ignored by `extract`, so the
    // engine translates; the fast-path key is the canonical embedding only.
    let mut f = fx_with(&Knobs { prefix: "2001:db8:122:344::/64", ..Knobs::default() }, Net::default());
    let canon = f.r.prefix.embed(f.s.dst4);
    let suffix = eth(ACCESS_MAC, CLIENT_MAC, ETH6, &udp6(&U6::new(f.s.src6, f.s.sport, canon | 1, f.s.dport), b"x"));
    let net = f.env.net;
    assert!(matches!(f.r.wire(&suffix, ACCESS_IF, &net), RefOut::Frame(_)), "the slow path translates it");
    assert_eq!(decide_frame(&mut f.env, ACCESS_IF, &suffix).pass_reason(), Some(PassReason::NoSession));
    // A non-zero u-octet: the engine refuses it, the fast path misses.
    let uoct = canon | (1u128 << 56);
    let frame = eth(ACCESS_MAC, CLIENT_MAC, ETH6, &udp6(&U6::new(f.s.src6, f.s.sport, uoct, f.s.dport), b"x"));
    assert_eq!(ok(differential(&mut f.r, &mut f.env, &frame, ACCESS_IF)), Some(PassReason::NoSession));
}

#[test]
fn zero_udp_checksum_never_redirects() {
    let mut f = fx();
    let mut o = f.out();
    o[60] = 0;
    o[61] = 0;
    assert_eq!(ok(differential(&mut f.r, &mut f.env, &o, ACCESS_IF)), Some(PassReason::UdpZeroCsum));
    // IPv4 zero checksum: the engine computes a full checksum (RFC 7915
    // §4.5); the fast path cannot without reading the payload.
    let mut i = f.inb();
    i[40] = 0;
    i[41] = 0;
    let net = f.env.net;
    assert!(matches!(f.r.wire(&i, UPSTREAM_IF, &net), RefOut::Frame(_)));
    assert_eq!(decide_frame(&mut f.env, UPSTREAM_IF, &i).pass_reason(), Some(PassReason::UdpZeroCsum));
}

#[test]
fn hairpin_is_never_installed() {
    let mut r = Reference::new(&Knobs::default());
    let mut env = HostEnv::new(&r.cfg, Net::default());
    let (src6, pool_dst) = (client(0x77_0000_0000_0001), POOL_NET | 200);
    let frame =
        eth(ACCESS_MAC, CLIENT_MAC, ETH6, &udp6(&U6::new(src6, 1000, r.prefix.embed(pool_dst), 53), b"hairpin"));
    let net = env.net;
    // The engine loops it back in-process; nothing leaves translated.
    assert!(matches!(r.wire(&frame, ACCESS_IF, &net), RefOut::Not(_)));
    let (pool4, pool_port) = some(r.mapping(src6, 1000), "hairpin BIB");
    assert!(
        r.nat.state().has_session(plat_nat64::state::Key4 { proto: 17, addr: pool4, port: pool_port }, (pool_dst, 53))
    );
    assert_eq!(r.install(&mut env, src6, 1000, pool_dst, 53), None, "I3 refuses hairpins");
    assert_eq!(ok(differential(&mut r, &mut env, &frame, ACCESS_IF)), Some(PassReason::NoSession));
}

#[test]
fn dead_slot_or_echo_mismatch_never_redirects() {
    let mut f = fx();
    f.env.slots[f.s.slot as usize].state = SLOT_DEAD;
    assert_eq!(f.both(), (Some(PassReason::SlotDead), Some(PassReason::SlotDead)));
    // A reused hash element: the key leads to another session's slot.
    let mut f = fx();
    let other = SlotRec { dport: [0, 54], ..f.env.slots[f.s.slot as usize] };
    f.env.slots[f.s.slot as usize] = other;
    assert_eq!(f.both(), (Some(PassReason::SlotDead), Some(PassReason::SlotDead)));
    // A slot index past the array.
    let mut f = fx();
    for v in f.env.out6.values_mut().chain(f.env.in4.values_mut()) {
        *v = 1_000_000;
    }
    assert_eq!(f.both(), (Some(PassReason::SlotDead), Some(PassReason::SlotDead)));
}

#[test]
fn routing_failures_never_redirect() {
    let mut f = fx();
    f.env.net.forwarding = false;
    assert_eq!(f.both(), (Some(PassReason::FibFwdDisabled), Some(PassReason::FibFwdDisabled)));
    let mut f = fx();
    f.env.net.neigh = false;
    assert_eq!(f.both(), (Some(PassReason::FibNoNeigh), Some(PassReason::FibNoNeigh)));
    let mut f = fx();
    f.env.egress.clear();
    assert_eq!(f.both(), (Some(PassReason::EgressNotAllowed), Some(PassReason::EgressNotAllowed)));
    let mut f = fx();
    for e in f.env.egress.values_mut() {
        e.allowed = 0;
    }
    assert_eq!(f.both(), (Some(PassReason::EgressNotAllowed), Some(PassReason::EgressNotAllowed)));
    let mut f = fx();
    f.env.control.tun_ifindex = 55;
    assert_eq!(f.both(), (Some(PassReason::FibOther), Some(PassReason::FibOther)));
    let mut f = fx();
    f.env.control.tun_mtu = 0;
    assert_eq!(f.both(), (Some(PassReason::TooBig), Some(PassReason::TooBig)));
}

#[test]
fn seen_is_refreshed_at_most_once_a_second() {
    let mut f = fx();
    let slot = f.s.slot as usize;
    let touch = |f: &mut Fx| {
        let o = f.out();
        match decide_frame(&mut f.env, ACCESS_IF, &o) {
            Action::V6ToV4(Verdict::Redirect { touch, slot: s, .. }) => {
                assert_eq!(s, f.s.slot);
                touch
            }
            other => panic!("{other:?}"),
        }
    };
    f.env.slots[slot].seen_ns = f.env.now - 999_999_999;
    assert_eq!(touch(&mut f), None);
    f.env.slots[slot].seen_ns = f.env.now - 1_000_000_000;
    assert_eq!(touch(&mut f), Some(f.env.now));
    f.env.slots[slot].seen_ns = 0;
    assert_eq!(touch(&mut f), Some(f.env.now));
}

#[test]
fn ipv4_id_comes_from_the_counter_only_without_df() {
    let mut f = fx();
    let mut ids = Vec::new();
    for _ in 0..64 {
        let o = f.out();
        let Action::V6ToV4(Verdict::Redirect { hdr, .. }) = decide_frame(&mut f.env, ACCESS_IF, &o) else {
            panic!("redirect expected");
        };
        assert_eq!(hdr[20] & 0x40, 0, "small packet: DF = 0");
        ids.push(u16::from_be_bytes([hdr[18], hdr[19]]));
    }
    let steps: Vec<u16> = ids.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
    assert!(steps.iter().all(|s| (1..=8).contains(s)), "{steps:?}");
    let big = out_frame(&f.r, &f.s, &[0u8; 1300], |_| {});
    let Action::V6ToV4(Verdict::Redirect { hdr, .. }) = decide_frame(&mut f.env, ACCESS_IF, &big) else {
        panic!("redirect expected");
    };
    assert_eq!((hdr[18], hdr[19], hdr[20] & 0x40), (0, 0, 0x40));
}

// ---------------------------------------------------------------------
// Fixed vectors

/// The spike's session (plan §18 Q4) in a host environment.
fn spike_env() -> HostEnv {
    let r = Reference::new(&Knobs::default());
    let mut env = HostEnv::new(&r.cfg, Net::default());
    for (ifindex, mac) in [(ACCESS_IF, [0xaa; 6]), (UPSTREAM_IF, [0xcc; 6])] {
        if let Some(e) = env.ifaces.get_mut(&iface_slot(ifindex)) {
            e.mac = mac;
        }
    }
    env.fib_macs = Some(([2, 0, 0, 0, 1, 1], [2, 0, 0, 0, 1, 0xfe]));
    env.install(SlotRec {
        state: plat_xdp_core::abi::SLOT_LIVE,
        generation: GEN,
        src6: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10],
        dst6: [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 5],
        sport6: 40_000u16.to_be_bytes(),
        dport: 53u16.to_be_bytes(),
        pool_port4: 61_000u16.to_be_bytes(),
        pool4: [198, 51, 100, 10],
        dst4: [203, 0, 113, 5],
        ..SlotRec::default()
    });
    env
}

/// Parses `key=value` fields of a `case` line.
fn fields(rest: &[&str]) -> HashMap<String, String> {
    rest.iter()
        .map(|kv| {
            let (k, v) = some(kv.split_once('='), "key=value");
            (k.to_string(), v.to_string())
        })
        .collect()
}

fn num<T: std::str::FromStr>(f: &HashMap<String, String>, k: &str, d: T) -> T
where
    T::Err: std::fmt::Debug,
{
    f.get(k).map(|v| ok(v.parse())).unwrap_or(d)
}

fn reason(name: &str) -> Option<PassReason> {
    if name == "redirect" {
        return None;
    }
    Some(*some(PassReason::ALL.iter().find(|r| r.as_str() == name), name))
}

/// One `case` line through the candidate and the reference.
fn run_case(outbound: bool, name: &str, f: &HashMap<String, String>) -> Result<(), String> {
    let k = Knobs {
        prefix: PREFIXES
            .iter()
            .copied()
            .find(|p| Some(*p) == f.get("prefix").map(String::as_str))
            .unwrap_or(PREFIXES[0]),
        copy_tos: num(f, "copy_tos", 1u8) == 1,
        mtu4: num(f, "mtu4", 1500),
        mtu6: num(f, "mtu6", 1500),
        lowest6: num(f, "lowest6", 1280),
    };
    if let Some(p) = f.get("prefix") {
        assert_eq!(k.prefix, p, "{name}: prefix not in PREFIXES");
    }
    let link = num(f, "link_mtu", 1500u32);
    let net = Net { tun_mtu: num(f, "tun_mtu", 1500), link_mtu4: link, link_mtu6: link, ..Net::default() };
    let mut r = Reference::new(&k);
    let mut env = HostEnv::new(&r.cfg, net);
    let s = establish(&mut r, &mut env, client(0x9_0000_0000_0042), 40_000, server(1, 5), 53)?;
    let p = Pkt {
        payload: (0..num(f, "payload", 5usize)).map(|i| i as u8 ^ 0xa5).collect(),
        hop: num(f, "hop", 64),
        tc: num(f, "tc", 0),
        flow_label: 0,
        id: 0x1234,
        df: num(f, "df", 1u8) == 1,
        edge: match f.get("csum").map(String::as_str) {
            None | Some("none") => 0,
            Some("in_ffff") => 1,
            Some("out_ffff") => 2,
            Some(o) => return Err(format!("{name}: csum={o}")),
        },
    };
    let (frame, ingress) =
        if outbound { (canonical_out(&r, &s, &p), ACCESS_IF) } else { (canonical_in(&r, &s, &p), UPSTREAM_IF) };
    if p.edge == 1 {
        let off = if outbound { 60 } else { 40 };
        assert_eq!(frame[off..off + 2], [0xff, 0xff], "{name}: input checksum edge");
    }
    let want = reason(f.get("expect").map_or("redirect", String::as_str));
    let (got, reference) = differential_full(&mut r, &mut env, &frame, ingress).map_err(|e| format!("{name}: {e}"))?;
    if got != want {
        return Err(format!("{name}: expected {want:?}, got {got:?}"));
    }
    if want.is_some()
        && let RefOut::Frame(_) = reference
    {
        return Err(format!("{name}: declined, but the slow path translates it as one frame"));
    }
    if p.edge == 2 && want.is_none() {
        let a = decide_frame(&mut env, ingress, &frame);
        let out = some(apply(&frame, &a), "redirect");
        let off = if outbound { 40 } else { 60 };
        if out[off..off + 2] != [0xff, 0xff] {
            return Err(format!("{name}: output checksum edge not hit"));
        }
    }
    Ok(())
}

fn run_vectors(file: &str, outbound: bool) {
    let mut n = 0;
    let mut failures = Vec::new();
    for (lineno, line) in file.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let res = match parts.as_slice() {
            ["hex", name, input, expected] => {
                let (input, expected) = (unhex(input), unhex(expected));
                let mut env = spike_env();
                let ingress = if outbound { ACCESS_IF } else { UPSTREAM_IF };
                let a = decide_frame(&mut env, ingress, &input);
                match apply(&input, &a) {
                    Some(out) => same_frame(&out, &expected).map_err(|e| format!("{name}: {e}")),
                    None => Err(format!("{name}: passed ({:?})", a.pass_reason())),
                }
            }
            ["case", name, rest @ ..] => run_case(outbound, name, &fields(rest)),
            _ => Err(format!("line {}: unparsed", lineno + 1)),
        };
        n += 1;
        if let Err(e) = res {
            failures.push(e);
        }
    }
    assert!(n >= 20, "only {n} vectors");
    assert!(failures.is_empty(), "{} of {n} vectors failed:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn fixed_vectors_v6_to_v4() {
    run_vectors(include_str!("vectors/v6_to_v4.txt"), true);
}

#[test]
fn fixed_vectors_v4_to_v6() {
    run_vectors(include_str!("vectors/v4_to_v6.txt"), false);
}

#[test]
fn spike_vector_is_byte_identical_including_id() {
    // The spike's program wrote ID 0; with ID 0 from the counter the output
    // is the recorded test-run frame exactly (no substitution).
    let line = some(
        include_str!("vectors/v6_to_v4.txt").lines().find(|l| l.starts_with("hex spike_5b_payload ")),
        "spike vector",
    );
    let parts: Vec<&str> = line.split_whitespace().collect();
    let (input, expected) = (unhex(parts[2]), unhex(parts[3]));
    assert_eq!(
        hex(&expected),
        "0200000001fe020000000101080045000021000000003e111689c633640acb007105ee480035000d674068656c6c6f"
    );
    let mut env = spike_env();
    let i = plat_xdp_core::ident::index(env.ident_key.mix(&env.slots[0].src6, &env.slots[0].dst4, 17)) as usize;
    // Pick the counter so the next ID is 0: ID = counter + step + offset.
    let m = env.ident_key.mix(&env.slots[0].src6, &env.slots[0].dst4, 17);
    let step = plat_xdp_core::ident::step(plat_xdp_core::ident::xorshift(env.rng));
    env.ident_table[i] = 0u16.wrapping_sub(step).wrapping_sub((m >> 48) as u16);
    let a = decide_frame(&mut env, ACCESS_IF, &input);
    assert_eq!(some(apply(&input, &a), "redirect"), expected);
}
