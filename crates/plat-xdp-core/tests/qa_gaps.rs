//! QA additions to the level-1 harness (plan §11): every pass reason is
//! reachable and reported exactly, non-canonical destinations for every
//! RFC 6052 prefix length, flow label and reserved-flag handling, table
//! entry slot collisions, and a slice / slot generation race model.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 - developer testing of the fast path; SI-10 -
//!   hostile input declines with an exact, counted reason; SC-24 - a
//!   fenced or re-generated slice never forwards

mod support;

use std::cell::RefCell;
use std::collections::BTreeSet;

use plat_xdp_core::abi::{
    SLICE_ACTIVE, SLICE_ADOPTING, SLICE_FENCED, SLICE_INACTIVE, SLOT_DEAD, SLOT_LIVE, SliceEnt, iface_slot,
};
use plat_xdp_core::decide::{Action, Verdict};
use plat_xdp_core::{PassReason, decide_frame};
use proptest::prelude::*;
use support::*;

const ETH6: [u8; 2] = [0x86, 0xdd];
const ETH4: [u8; 2] = [0x08, 0x00];

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
    fn out_with(&self, payload: &[u8], f: impl FnOnce(&mut U6)) -> Vec<u8> {
        let mut h = U6::new(self.s.src6, self.s.sport, self.r.prefix.embed(self.s.dst4), self.s.dport);
        f(&mut h);
        eth(ACCESS_MAC, CLIENT_MAC, ETH6, &udp6(&h, payload))
    }

    fn in_with(&self, payload: &[u8], f: impl FnOnce(&mut U4)) -> Vec<u8> {
        let mut h = U4::new(self.s.dst4, self.s.dport, self.s.pool4, self.s.pool_port);
        f(&mut h);
        eth(UPSTREAM_MAC, SERVER_MAC, ETH4, &udp4(&h, payload))
    }

    fn out(&self) -> Vec<u8> {
        self.out_with(b"payload", |_| {})
    }

    fn inb(&self) -> Vec<u8> {
        self.in_with(b"payload", |_| {})
    }

    fn diff(&mut self, frame: &[u8], ingress: u32) -> Option<PassReason> {
        ok(differential(&mut self.r, &mut self.env, frame, ingress))
    }
}

// ---------------------------------------------------------------------
// Decline-reason accuracy

/// Every reason the core can return (all but `Headroom`, which only the
/// eBPF program produces) is reached by a specific frame or table state,
/// in both directions where the reason applies, and reported exactly. Each
/// case also runs the safety check against the engine.
#[test]
fn every_pass_reason_is_reachable_and_exact() {
    let mut seen = BTreeSet::new();
    let mut check = |name: &str, got: Option<PassReason>, want: PassReason| {
        assert_eq!(got, Some(want), "{name}");
        seen.insert(want as u32);
    };

    // Frame-shape reasons.
    let mut f = fx();
    let mut o = f.out();
    o[12..14].copy_from_slice(&[0x81, 0x00]);
    check("vlan v6", f.diff(&o, ACCESS_IF), PassReason::NotIp);
    let mut o = f.out();
    o[..6].copy_from_slice(&[0xff; 6]);
    check("broadcast v6", f.diff(&o, ACCESS_IF), PassReason::NotForUs);
    let i = f.inb();
    check("unconfigured if", decide_frame(&mut f.env, 9, &i).pass_reason(), PassReason::Role);
    let mut o = f.out();
    o[14] = 0x40 | (o[14] & 0x0f);
    check("v6 version 4", f.diff(&o, ACCESS_IF), PassReason::BadL3);
    let mut i = f.inb();
    i[14] = 0x46;
    check("ihl 6", f.diff(&i, UPSTREAM_IF), PassReason::Ipv4Options);
    let mut i = f.inb();
    i[20] |= 0x20;
    fix_v4_csum(&mut i[14..]);
    check("mf", f.diff(&i, UPSTREAM_IF), PassReason::Fragment);
    let mut i = f.inb();
    i[21] = 1;
    fix_v4_csum(&mut i[14..]);
    check("offset", f.diff(&i, UPSTREAM_IF), PassReason::Fragment);
    let mut o = f.out();
    o[20] = 0;
    check("hop-by-hop", f.diff(&o, ACCESS_IF), PassReason::ExtHeader);
    let mut o = f.out();
    o[20] = 44;
    check("fragment header", f.diff(&o, ACCESS_IF), PassReason::ExtHeader);
    let mut o = f.out();
    o[20] = 6;
    check("tcp v6", f.diff(&o, ACCESS_IF), PassReason::NotUdp);
    let mut i = f.inb();
    i[23] = 1;
    fix_v4_csum(&mut i[14..]);
    check("icmp v4", f.diff(&i, UPSTREAM_IF), PassReason::NotUdp);
    let mut o = f.out();
    o[59] = o[59].wrapping_sub(1);
    check("udp len v6", f.diff(&o, ACCESS_IF), PassReason::UdpLen);
    let mut i = f.inb();
    i[39] = i[39].wrapping_add(1);
    check("udp len v4", f.diff(&i, UPSTREAM_IF), PassReason::UdpLen);
    let mut o = f.out();
    o[60] = 0;
    o[61] = 0;
    check("zero csum v6", f.diff(&o, ACCESS_IF), PassReason::UdpZeroCsum);
    let o = f.out_with(b"x", |h| h.hop = 2);
    check("hop 2", f.diff(&o, ACCESS_IF), PassReason::HopLimit);
    let o = f.out_with(b"x", |h| h.sport = 40_001);
    check("other sport", f.diff(&o, ACCESS_IF), PassReason::NoSession);
    let i = f.in_with(b"x", |h| h.sport = 54);
    check("other rport", f.diff(&i, UPSTREAM_IF), PassReason::NoSession);

    // Table-state reasons, both directions.
    type Mutator = fn(&mut Fx);
    let cases: [(&str, Mutator, PassReason); 10] = [
        ("disabled", |f| f.env.control.enabled = 0, PassReason::Disabled),
        ("deadline", |f| f.env.now = f.env.control.deadline_ns + 1, PassReason::Deadline),
        ("dead slot", |f| f.env.slots[f.s.slot as usize].state = SLOT_DEAD, PassReason::SlotDead),
        ("fenced", |f| f.env.slices[0].state = SLICE_FENCED, PassReason::SliceInactive),
        ("tun mtu", |f| f.env.control.tun_mtu = 10, PassReason::TooBig),
        ("forwarding", |f| f.env.net.forwarding = false, PassReason::FibFwdDisabled),
        ("neigh", |f| f.env.net.neigh = false, PassReason::FibNoNeigh),
        (
            "link mtu",
            |f| {
                f.env.net.link_mtu4 = 30;
                f.env.net.link_mtu6 = 50;
            },
            PassReason::FibFragNeeded,
        ),
        ("fib other", |f| f.env.control.tun_ifindex = 55, PassReason::FibOther),
        ("egress", |f| f.env.egress.clear(), PassReason::EgressNotAllowed),
    ];
    for (name, m, want) in cases {
        let mut f = fx();
        m(&mut f);
        let (o, i) = (f.out(), f.inb());
        let a = f.diff(&o, ACCESS_IF);
        check(&format!("{name} out"), a, want);
        let b = f.diff(&i, UPSTREAM_IF);
        check(&format!("{name} in"), b, want);
    }

    let missing: Vec<&str> = PassReason::ALL
        .iter()
        .filter(|r| **r != PassReason::Headroom && !seen.contains(&(**r as u32)))
        .map(|r| r.as_str())
        .collect();
    assert!(missing.is_empty(), "reasons never produced: {missing:?}");
}

// ---------------------------------------------------------------------
// RFC 6052, every prefix length

/// For every prefix length the canonical embedding redirects both ways
/// with the right addresses, and a non-zero u-octet or suffix (where the
/// length has one) never redirects.
#[test]
fn every_prefix_length_canonical_only() {
    for p in PREFIXES {
        let mut f = fx_with(&Knobs { prefix: p, ..Knobs::default() }, Net::default());
        let canon = f.r.prefix.embed(f.s.dst4);
        assert_eq!(f.diff(&f.out(), ACCESS_IF), None, "{p} out");
        let i = f.inb();
        match decide_frame(&mut f.env, UPSTREAM_IF, &i) {
            Action::V4ToV6(Verdict::Redirect { hdr, .. }) => {
                assert_eq!(hdr[22..38], canon.to_be_bytes(), "{p}: source is the canonical embedding");
                assert_eq!(hdr[38..54], f.s.src6.to_be_bytes(), "{p}: destination is the subscriber");
            }
            other => panic!("{p}: {other:?}"),
        }
        assert_eq!(f.diff(&i, UPSTREAM_IF), None, "{p} in");

        let len: u32 = some(p.rsplit('/').next().and_then(|l| l.parse().ok()), "len");
        let mut bad = vec![canon | (1u128 << 56) | (0xffu128 << 56)];
        if len < 96 {
            bad.push(canon | 1);
            bad.push(canon | (1u128 << 16));
        }
        for d in bad {
            let o = f.out_with(b"x", |h| h.dst = d);
            assert_eq!(f.diff(&o, ACCESS_IF), Some(PassReason::NoSession), "{p} dst {d:032x}");
        }
    }
}

// ---------------------------------------------------------------------
// Header fields the translator must not carry over

#[test]
fn flow_label_is_ignored_outbound_and_zero_inbound() {
    let mut f = fx();
    let o = f.out_with(b"flow", |h| {
        h.flow = 0xf_ffff;
        h.tc = 0xff;
    });
    assert_eq!(f.diff(&o, ACCESS_IF), None);
    let i = f.in_with(b"flow", |h| h.tos = 0xff);
    match decide_frame(&mut f.env, UPSTREAM_IF, &i) {
        Action::V4ToV6(Verdict::Redirect { hdr, .. }) => {
            assert_eq!(hdr[14..18], [0x6f, 0xf0, 0, 0], "version 6, TC 0xff, flow label 0");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(f.diff(&i, UPSTREAM_IF), None);
}

/// The IPv4 reserved flag (and DF with it) never makes the fast path
/// differ from the engine.
#[test]
fn ipv4_reserved_flag_is_safe() {
    for flags in [0x80u8, 0xc0] {
        let mut f = fx();
        let mut i = f.inb();
        i[20] = flags;
        fix_v4_csum(&mut i[14..]);
        let _ = f.diff(&i, UPSTREAM_IF);
    }
}

/// `IFACES` / `EGRESS` entries are found by slot; an entry whose stored
/// ifindex differs (another interface hashing to the slot) is not used.
#[test]
fn table_slot_collisions_are_rejected() {
    let mut f = fx();
    if let Some(e) = f.env.ifaces.get_mut(&iface_slot(ACCESS_IF)) {
        e.ifindex = ACCESS_IF + 64;
    }
    let o = f.out();
    assert_eq!(f.diff(&o, ACCESS_IF), Some(PassReason::Role));

    let mut f = fx();
    for e in f.env.egress.values_mut() {
        e.ifindex += 64;
    }
    let (o, i) = (f.out(), f.inb());
    assert_eq!(f.diff(&o, ACCESS_IF), Some(PassReason::EgressNotAllowed));
    assert_eq!(f.diff(&i, UPSTREAM_IF), Some(PassReason::EgressNotAllowed));
}

// ---------------------------------------------------------------------
// Slice / slot generation race model

#[derive(Debug, Clone)]
enum Op {
    /// `release_slice` / `adopt_slice` style state write.
    SetState(u8),
    /// Generation bump (takeover).
    Bump,
    /// The record is re-installed at the slice's current generation.
    Reinstall,
    /// Retire (state DEAD) or revive (LIVE) the slot.
    Slot(bool),
    /// The record is re-homed to the other slice (stale `slice` index).
    Rehome(u16),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        prop_oneof![Just(SLICE_INACTIVE), Just(SLICE_ACTIVE), Just(SLICE_FENCED), Just(SLICE_ADOPTING), Just(9u8)]
            .prop_map(Op::SetState),
        Just(Op::Bump),
        Just(Op::Reinstall),
        any::<bool>().prop_map(Op::Slot),
        (0u16..3).prop_map(Op::Rehome),
    ]
}

thread_local! {
    static RACE: RefCell<Option<Fx>> = const { RefCell::new(None) };
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases().min(20_000), ..ProptestConfig::default() })]

    /// After any interleaving of slice-state writes, generation bumps,
    /// re-installs and slot retirement, a packet redirects exactly when the
    /// slot is LIVE and its slice is Active at the record's generation; the
    /// reason otherwise is the first failing check.
    #[test]
    fn slice_generation_races(ops in proptest::collection::vec(op(), 1..24)) {
        RACE.with(|c| -> Result<(), TestCaseError> {
            let mut c = c.borrow_mut();
            let f = c.get_or_insert_with(fx);
            let slot = f.s.slot as usize;
            f.env.slices = vec![SliceEnt { state: SLICE_ACTIVE, pad: [0; 3], generation: GEN }; 2];
            f.env.slots[slot].state = SLOT_LIVE;
            f.env.slots[slot].slice = 0;
            f.env.slots[slot].generation = GEN;
            let (o, i) = (f.out(), f.inb());
            for op in &ops {
                let rec = &mut f.env.slots[slot];
                match *op {
                    Op::SetState(s) => {
                        if let Some(e) = f.env.slices.get_mut(usize::from(rec.slice)) {
                            e.state = s;
                        }
                    }
                    Op::Bump => {
                        if let Some(e) = f.env.slices.get_mut(usize::from(rec.slice)) {
                            e.generation = e.generation.wrapping_add(1);
                        }
                    }
                    Op::Reinstall => {
                        if let Some(e) = f.env.slices.get(usize::from(rec.slice)) {
                            rec.generation = e.generation;
                        }
                    }
                    Op::Slot(live) => rec.state = if live { SLOT_LIVE } else { SLOT_DEAD },
                    Op::Rehome(s) => rec.slice = s,
                }
                let rec = f.env.slots[slot];
                let want = if rec.state != SLOT_LIVE {
                    Some(PassReason::SlotDead)
                } else {
                    match f.env.slices.get(usize::from(rec.slice)) {
                        Some(e) if e.state == SLICE_ACTIVE && e.generation == rec.generation => None,
                        _ => Some(PassReason::SliceInactive),
                    }
                };
                prop_assert_eq!(decide_frame(&mut f.env, ACCESS_IF, &o).pass_reason(), want, "out after {:?}", op);
                prop_assert_eq!(decide_frame(&mut f.env, UPSTREAM_IF, &i).pass_reason(), want, "in after {:?}", op);
            }
            Ok(())
        })?;
    }
}
