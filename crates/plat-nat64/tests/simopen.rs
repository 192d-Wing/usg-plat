//! TCP simultaneous open (RFC 6146 §3.5.2.2, POAM-008): held inbound SYNs,
//! promotion by the subscriber's SYN, expiry, the optional Port
//! Unreachable, and the SC-5 / SC-7 bounds on attacker-created state.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use plat_common::{Counter, Counters, DropReason};
use plat_nat64::state::Key4;
use plat_nat64::{Verdict, WorkerCtx};
use plat_packet::{be16, be32, checksum as ck, parse_v4, proto, put16, put32};
use plat_xlat::HEADROOM;
use plat_xlat::siit::write_v4_header;
use proptest::prelude::*;

const SERVER: u32 = 0xc633_6407; // 198.51.100.7
const OTHER: u32 = 0xc633_6409; // 198.51.100.9 (the simultaneous-open peer)
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const RST: u8 = 0x04;
const FIN: u8 = 0x01;
const ICMP_ON: (&str, &str) = ("held_syn_unreachable = false", "held_syn_unreachable = true");
const APDF: (&str, &str) = ("filtering = \"address_dependent\"", "filtering = \"address_port_dependent\"");
const EIF: (&str, &str) = ("filtering = \"address_dependent\"", "filtering = \"endpoint_independent\"");

/// Opens a TCP flow `sub(1, 1):40000 → SERVER:443`; returns its mapping.
fn bind(fx: &mut Fx) -> Key4 {
    let out = run(fx, &tcp6(sub(1, 1), 40000, SERVER, 443, SYN)).unwrap();
    Key4 { proto: proto::TCP, addr: be32(&out, 12), port: be16(&out, 20) }
}

/// An inbound SYN with a chosen sequence number, Identification and TTL.
fn syn4(src: u32, sport: u16, k4: Key4, seq: u32, ident: u16, ttl: u8) -> Vec<u8> {
    let mut p = tcp4(src, sport, k4.addr, k4.port, SYN);
    write_v4_header(&mut p, 0, 40, ident, true, false, 0, ttl, proto::TCP, src, k4.addr);
    put32(&mut p, 24, seq);
    l4_sum4(&mut p, proto::TCP, 16);
    p
}

fn held(fx: &Fx) -> u64 {
    fx.nat.state().held_syn_count()
}

fn get(ctx: &WorkerCtx, c: Counter) -> u64 {
    ctx.counters.get(c)
}

/// Runs one packet on another worker context.
fn run_on(fx: &Fx, ctx: &mut WorkerCtx, pkt: &[u8]) -> Result<Vec<u8>, DropReason> {
    let mut buf = vec![0u8; HEADROOM + 2048];
    buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(pkt);
    match fx.nat.process(&mut buf, HEADROOM, pkt.len(), ctx) {
        Verdict::Forward { start, len } => Ok(buf[start..start + len].to_vec()),
        Verdict::Drop(d) => Err(d),
        v => panic!("unexpected {v:?}"),
    }
}

/// Packets produced by one housekeeping call.
fn housekeep(fx: &mut Fx) -> Vec<Vec<u8>> {
    let n = fx.nat.housekeep(&mut fx.ctx);
    let v: Vec<Vec<u8>> = fx.ctx.fragments().map(<[u8]>::to_vec).collect();
    assert_eq!(v.len(), n);
    v
}

fn expire(fx: &Fx) {
    fx.clock.advance(Duration::from_millis(6_001));
    fx.nat.state().sweep();
}

#[test]
fn held_syn_is_consumed_and_opens_nothing() {
    for f in [None, Some(APDF)] {
        let mut fx = fixture(f.as_slice());
        let k4 = bind(&mut fx);
        let _ = events(&fx);
        let sessions = fx.nat.state().session_count();
        assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
        let st = fx.nat.state();
        assert_eq!(held(&fx), 1);
        assert_eq!(get(&fx.ctx, Counter::TcpSynHeld), 1);
        // Not a session: no count, no filter opening, no forwarding of
        // anything else from that remote.
        assert_eq!(st.session_count(), sessions);
        assert!(!st.has_session(k4, (OTHER, 5000)));
        assert_eq!(st.filter_inbound(k4, (OTHER, 5000)).unwrap_err(), DropReason::Filtered);
        assert_eq!(st.filter_inbound(k4, (OTHER, 5001)).unwrap_err(), DropReason::Filtered);
        assert_eq!(run(&mut fx, &tcp4(OTHER, 5000, k4.addr, k4.port, ACK)).unwrap_err(), DropReason::Filtered);
        assert_eq!(run(&mut fx, &udp4(OTHER, 5000, k4.addr, k4.port, b"x")).unwrap_err(), DropReason::NoBinding);
        // No audit record for a hold (no BIB, block or session).
        assert!(events(&fx).is_empty());
        assert_eq!(fx.ctx.counters.drops(DropReason::Filtered), 1);
    }
}

#[test]
fn eif_translates_the_syn_and_holds_nothing() {
    let mut fx = fixture(&[EIF]);
    let k4 = bind(&mut fx);
    let out = run(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap();
    assert_eq!(out[0] >> 4, 6);
    assert_eq!(held(&fx), 0);
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeld), 0);
}

#[test]
fn no_bib_and_non_syn_are_never_held() {
    let mut fx = fixture(&[]);
    let k4 = bind(&mut fx);
    let unbound = Key4 { port: k4.port ^ 1, ..k4 };
    assert_eq!(run(&mut fx, &syn4(OTHER, 5000, unbound, 1, 1, 64)).unwrap_err(), DropReason::NoBinding);
    for flags in [SYN | ACK, SYN | RST, RST, FIN, ACK, FIN | ACK, SYN | FIN | ACK] {
        let p = tcp4(OTHER, 5000, k4.addr, k4.port, flags);
        assert_eq!(run(&mut fx, &p).unwrap_err(), DropReason::Filtered, "flags {flags:#x}");
    }
    assert_eq!(held(&fx), 0);
    // Disabled: a SYN is filtered as before.
    let mut off = fixture(&[("tcp_simultaneous_open = true", "tcp_simultaneous_open = false")]);
    let k4 = bind(&mut off);
    assert_eq!(run(&mut off, &syn4(OTHER, 5000, k4, 1, 1, 64)).unwrap_err(), DropReason::Filtered);
    assert_eq!(held(&off), 0);
    // A zero cap disables holding too.
    let mut zero = fixture(&[("max_held_syns = 16384", "max_held_syns = 0")]);
    let k4 = bind(&mut zero);
    assert_eq!(run(&mut zero, &syn4(OTHER, 5000, k4, 1, 1, 64)).unwrap_err(), DropReason::Filtered);
}

/// The inbound and outbound SYNs of one connection hash to different TUN
/// queues; the hold lives in the shared BIB, so any worker matches it.
#[test]
fn simultaneous_open_across_workers() {
    let mut fx = fixture(&[]);
    let k4 = bind(&mut fx);
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    let mut b = fx.nat.new_worker(Arc::new(Counters::default()), 2);
    let sessions = fx.nat.state().session_count();
    let out = run_on(&fx, &mut b, &tcp6(sub(1, 1), 40000, OTHER, 5000, SYN)).unwrap();
    let h = parse_v4(&out).unwrap();
    assert_eq!((h.src, be16(&out, 20), h.dst, be16(&out, 22)), (k4.addr, k4.port, OTHER, 5000));
    assert_eq!(get(&b, Counter::TcpSynHeldMatched), 1);
    assert_eq!(held(&fx), 0);
    assert_eq!(fx.nat.state().session_count(), sessions + 1);
    // The peer answers our SYN with SYN-ACK: the filter admits it now.
    let back = run(&mut fx, &tcp4(OTHER, 5000, k4.addr, k4.port, SYN | ACK)).unwrap();
    assert_eq!(back[0] >> 4, 6);
    // ESTABLISHED (TCP_EST, not TCP_TRANS): alive past the 240 s
    // transitory timer.
    fx.clock.advance(Duration::from_secs(300));
    fx.nat.state().sweep();
    assert!(fx.nat.state().has_session(k4, (OTHER, 5000)));
}

#[test]
fn duplicate_does_not_extend_and_expired_slot_never_promotes() {
    let mut fx = fixture(&[]);
    let k4 = bind(&mut fx);
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    fx.clock.advance(Duration::from_secs(3));
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 2, 64)).unwrap().is_empty());
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeldDup), 1);
    assert_eq!(held(&fx), 1);
    // 6.1 s after the first SYN: expired (not swept), so no promotion.
    fx.clock.advance(Duration::from_millis(3_100));
    let out = run(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 5000, SYN)).unwrap();
    assert_eq!(out[0] >> 4, 4);
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeldMatched), 0);
    // The new session is V6 INIT on the transitory timer (240 s).
    fx.clock.advance(Duration::from_secs(241));
    fx.nat.state().sweep();
    assert!(!fx.nat.state().has_session(k4, (OTHER, 5000)));
    assert_eq!(held(&fx), 0);
}

#[test]
fn other_remote_does_not_match() {
    let mut fx = fixture(&[]);
    let k4 = bind(&mut fx);
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    assert!(run(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 5001, SYN)).is_ok());
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeldMatched), 0);
    assert_eq!(held(&fx), 1);
    // A non-SYN from the subscriber creates nothing and keeps the slot.
    assert_eq!(run(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 5000, ACK)).unwrap_err(), DropReason::TcpNoState);
    assert_eq!(held(&fx), 1);
}

#[test]
fn promotion_refused_by_session_quota_clears_the_slot() {
    let mut fx = fixture(&[NO_UNREACH, ("max_sessions_per_subscriber = 4000", "max_sessions_per_subscriber = 1")]);
    let k4 = bind(&mut fx);
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    assert_eq!(run(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 5000, SYN)).unwrap_err(), DropReason::SubscriberLimit);
    assert_eq!(held(&fx), 0);
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeldMatched), 1);
    assert!(!fx.nat.state().has_session(k4, (OTHER, 5000)));
}

#[test]
fn expiry_is_silent_by_default() {
    let mut fx = fixture(&[]);
    let k4 = bind(&mut fx);
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    fx.clock.advance(Duration::from_millis(5_900));
    fx.nat.state().sweep();
    assert_eq!(held(&fx), 1, "held at least TCP_INCOMING_SYN");
    fx.clock.advance(Duration::from_millis(200));
    fx.nat.state().sweep();
    assert_eq!(held(&fx), 0);
    assert_eq!(fx.nat.state().held_syn_expired_total(), 1);
    assert!(!fx.nat.state().held_icmp_enabled());
    assert!(housekeep(&mut fx).is_empty());
    assert_eq!(get(&fx.ctx, Counter::IcmpUnreachableSent), 0);
}

#[test]
fn expiry_port_unreachable_quotes_the_stored_syn() {
    let mut fx = fixture(&[ICMP_ON]);
    let k4 = bind(&mut fx);
    let syn = syn4(OTHER, 5000, k4, 0xdead_beef, 0x4321, 57);
    assert!(run_all(&mut fx, &syn).unwrap().is_empty());
    expire(&fx);
    let out = housekeep(&mut fx);
    assert_eq!(out.len(), 1);
    let p = &out[0];
    assert_eq!(p.len(), 56);
    let h = parse_v4(p).unwrap();
    assert_eq!((h.src, h.dst, h.proto, h.total_len), (k4.addr, OTHER, proto::ICMP, 56));
    assert_eq!(ck::fold(ck::sum(&p[..20])), 0xffff, "IPv4 header checksum");
    assert_eq!((p[20], p[21]), (3, 3));
    assert_eq!(ck::fold(ck::sum(&p[20..])), 0xffff, "ICMP checksum");
    // Quoted IPv4 header: rebuilt from the slot, identical to the SYN's
    // (DF restored, RFC-004), and the first 8 bytes of TCP.
    let q = &p[28..];
    assert_eq!(ck::fold(ck::sum(&q[..20])), 0xffff, "quoted header checksum");
    assert_eq!(q[6] & 0x40, 0x40, "DF restored");
    assert_eq!(&q[..20], &syn[..20], "whole IPv4 header");
    assert_eq!(&q[20..28], &syn[20..28], "ports and sequence number");
    assert_eq!(get(&fx.ctx, Counter::IcmpUnreachableSent), 1);
    assert_eq!(get(&fx.ctx, Counter::IcmpErrorsGenerated), 1);
    assert!(housekeep(&mut fx).is_empty());
}

#[test]
fn expiry_icmp_is_rate_limited() {
    let mut fx = fixture(&[ICMP_ON, ("icmp_errors_per_sec = 100", "icmp_errors_per_sec = 0")]);
    let k4 = bind(&mut fx);
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    expire(&fx);
    assert!(housekeep(&mut fx).is_empty());
    assert_eq!(get(&fx.ctx, Counter::IcmpErrorsRateLimited), 1);
    assert_eq!(get(&fx.ctx, Counter::IcmpUnreachableSent), 0);
    // A burst of expiries is capped by the non-PMTU share of the bucket.
    let mut fx = fixture(&[ICMP_ON, ("icmp_errors_per_sec = 100", "icmp_errors_per_sec = 4")]);
    let k4 = bind(&mut fx);
    for i in 0..4u32 {
        assert!(run_all(&mut fx, &syn4(OTHER + i, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    }
    expire(&fx);
    assert_eq!(housekeep(&mut fx).len(), 3, "4 tokens, 1 reserved for PMTU");
    assert_eq!(get(&fx.ctx, Counter::IcmpErrorsRateLimited), 1);
}

#[test]
fn no_icmp_when_a_session_was_opened_meanwhile() {
    // ADF: once the subscriber talks to OTHER on another port, OTHER's SYN
    // passes the filter; a slot held before that must not answer later.
    let mut fx = fixture(&[ICMP_ON]);
    let k4 = bind(&mut fx);
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    assert!(run(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 6000, SYN)).is_ok());
    assert!(run(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).is_ok());
    expire(&fx);
    assert!(housekeep(&mut fx).is_empty());
    assert_eq!(held(&fx), 0);
}

#[test]
fn per_bib_and_global_caps() {
    let mut fx = fixture(&[]);
    let k4 = bind(&mut fx);
    for i in 0..1000u32 {
        let r = run_all(&mut fx, &syn4(0xcb00_7100 | (i & 0xff), 1024 + i as u16, k4, i, 1, 64));
        if i < 4 {
            assert!(r.unwrap().is_empty());
        } else {
            assert_eq!(r.unwrap_err(), DropReason::HeldSynLimit);
        }
    }
    assert_eq!(held(&fx), 4);
    assert_eq!(fx.ctx.counters.drops(DropReason::HeldSynLimit), 996);
    // The established flow on that BIB is unaffected.
    assert!(run(&mut fx, &tcp4(SERVER, 443, k4.addr, k4.port, SYN | ACK)).is_ok());

    let mut fx = fixture(&[("max_held_syns = 16384", "max_held_syns = 6")]);
    let mut bibs = Vec::new();
    for port in 0..3u16 {
        let out = run(&mut fx, &tcp6(sub(1, 1), 41000 + port, SERVER, 443, SYN)).unwrap();
        bibs.push(Key4 { proto: proto::TCP, addr: be32(&out, 12), port: be16(&out, 20) });
    }
    let mut ok = 0;
    for (j, k4) in bibs.iter().enumerate() {
        for i in 0..4u16 {
            if run_all(&mut fx, &syn4(OTHER + 10 * j as u32 + u32::from(i), 2000, *k4, 1, 1, 64)).is_ok() {
                ok += 1;
            }
        }
    }
    assert_eq!((ok, held(&fx)), (6, 6));
    assert_eq!(fx.ctx.counters.drops(DropReason::HeldSynLimit), 6);
    // Expiry returns the capacity.
    expire(&fx);
    assert_eq!(held(&fx), 0);
    assert!(run_all(&mut fx, &syn4(OTHER, 3000, bibs[0], 1, 1, 64)).unwrap().is_empty());
}

#[test]
fn held_syns_never_keep_a_bib_alive() {
    let mut fx = fixture(&[ICMP_ON]);
    let k4 = bind(&mut fx);
    let mut gone_at = None;
    // A fresh SYN every 5 s for longer than the BIB's lifetime (its V6 INIT
    // session ends after 240 s).
    for i in 0..60u16 {
        fx.clock.advance(Duration::from_secs(5));
        let r = run_all(&mut fx, &syn4(OTHER, 7000 + i, k4, 1, 1, 64));
        fx.nat.state().sweep();
        let _ = housekeep(&mut fx);
        if fx.nat.state().lookup4(k4).is_none() {
            gone_at.get_or_insert(i);
        }
        if gone_at.is_some_and(|g| g < i) {
            assert_eq!(r.unwrap_err(), DropReason::NoBinding);
        }
    }
    assert!(gone_at.is_some_and(|g| g < 55), "BIB reaped at its normal time: {gone_at:?}");
    assert_eq!(held(&fx), 0);
    // The block release followed (its record is queued first).
    fx.clock.advance(Duration::from_secs(61));
    fx.nat.state().sweep();
    assert!(events(&fx).iter().any(|e| matches!(e, plat_audit::Event::PortBlockRelease { .. })));
}

#[test]
fn full_ring_counts_lost_and_never_blocks() {
    let mut fx = fixture(&[ICMP_ON, ("max_held_syns = 16384", "max_held_syns = 2")]);
    let k4 = bind(&mut fx);
    for round in 0..2u16 {
        for i in 0..2u16 {
            let src = OTHER + u32::from(10 * round + i);
            assert!(run_all(&mut fx, &syn4(src, 5000, k4, 1, 1, 64)).unwrap().is_empty());
        }
        expire(&fx);
    }
    // Ring capacity = min(max_held_syns, 4096) = 2; workers never drained.
    assert_eq!(fx.nat.state().held_syn_icmp_lost_total(), 2);
    assert_eq!(fx.nat.state().held_syn_expired_total(), 4);
    assert_eq!(housekeep(&mut fx).len(), 2);
}

#[test]
fn hairpinned_and_fragmented_syns_are_not_held() {
    let mut fx = fixture(&[]);
    let k4 = bind(&mut fx);
    // A first fragment SYN goes through the fragment path: filtered.
    let mut p = syn4(OTHER, 5000, k4, 1, 1, 64);
    write_v4_header(&mut p, 0, 40, 9, false, true, 0, 64, proto::TCP, OTHER, k4.addr);
    let r = run_all(&mut fx, &p);
    assert!(r.is_err() || r.as_ref().is_ok_and(Vec::is_empty));
    assert_eq!(held(&fx), 0);
    // Another subscriber hairpins a SYN to the binding: not held.
    let r = run_all(&mut fx, &tcp6(sub(2, 1), 30000, k4.addr, k4.port, SYN));
    assert_eq!(r.unwrap_err(), DropReason::Filtered);
    assert_eq!(held(&fx), 0);
}

#[derive(Debug, Clone)]
enum Op {
    Hold(u16),
    Out(u16),
    Wait(u64),
    Sweep,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u16..6).prop_map(Op::Hold),
        (0u16..6).prop_map(Op::Out),
        (0u64..4000).prop_map(Op::Wait),
        Just(Op::Sweep),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every held SYN ends exactly once: matched, expired, or still held.
    #[test]
    fn held_accounting_is_exact(ops in proptest::collection::vec(op(), 1..80)) {
        let mut fx = fixture(&[ICMP_ON, ("max_held_syns_per_bib = 4", "max_held_syns_per_bib = 3")]);
        let k4 = bind(&mut fx);
        for o in ops {
            match o {
                Op::Hold(r) => { let _ = run_all(&mut fx, &syn4(OTHER, 5000 + r, k4, 1, 1, 64)); }
                Op::Out(r) => { let _ = run_all(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 5000 + r, SYN)); }
                Op::Wait(ms) => fx.clock.advance(Duration::from_millis(ms)),
                Op::Sweep => { fx.nat.state().sweep(); let _ = housekeep(&mut fx); }
            }
            prop_assert!(held(&fx) <= 3);
            let st = fx.nat.state();
            prop_assert_eq!(
                get(&fx.ctx, Counter::TcpSynHeld),
                get(&fx.ctx, Counter::TcpSynHeldMatched) + st.held_syn_expired_total() + held(&fx)
            );
        }
        fx.clock.advance(Duration::from_secs(61));
        fx.nat.state().sweep();
        prop_assert_eq!(held(&fx), 0);
    }

    /// Mutated inbound SYNs on the hold path never panic.
    #[test]
    fn mutated_syns_never_panic(edits in proptest::collection::vec((0usize..40, any::<u8>()), 0..8), cut in 0usize..41) {
        let mut fx = fixture(&[ICMP_ON]);
        let k4 = bind(&mut fx);
        let mut p = syn4(OTHER, 5000, k4, 1, 1, 64);
        for (i, b) in edits { p[i] = b; }
        // Keep the header checksum valid half of the time so the parse
        // reaches the hold path.
        if cut % 2 == 0 { put16(&mut p, 10, 0); let c = ck::finish(ck::sum(&p[..20])); put16(&mut p, 10, c); }
        let _ = run_all(&mut fx, &p[..cut.max(1)]);
        let _ = run_all(&mut fx, &p);
        expire(&fx);
        let _ = housekeep(&mut fx);
    }
}

// ---- QA additions (POAM-008) ----

/// An inbound SYN with `opt` bytes of TCP options and a payload.
fn syn4_opts(src: u32, sport: u16, k4: Key4, opt: usize, payload: &[u8]) -> Vec<u8> {
    let tcp_len = 20 + opt + payload.len();
    let total = 20 + tcp_len;
    let mut p = vec![0u8; total];
    write_v4_header(&mut p, 0, total as u16, 0x1111, true, false, 0, 64, proto::TCP, src, k4.addr);
    put16(&mut p, 20, sport);
    put16(&mut p, 22, k4.port);
    put32(&mut p, 24, 0x0102_0304);
    p[32] = (((20 + opt) / 4) as u8) << 4;
    p[33] = SYN;
    // MSS, then NOPs, then EOL padding.
    if opt >= 4 {
        p[40..44].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        for b in &mut p[44..40 + opt] {
            *b = 1;
        }
    }
    p[40 + opt..].copy_from_slice(payload);
    l4_sum4(&mut p, proto::TCP, 16);
    p
}

/// RFC 6146 §3.5.2.2 with a SYN carrying options and data (TFO-style):
/// still held, never forwarded, and the expiry ICMP quotes only the IPv4
/// header + 8 bytes (RFC 792) with the original total length.
#[test]
fn qa_syn_with_options_and_payload_is_held_and_quoted() {
    for (opt, payload) in [(4usize, &b""[..]), (20, &b"hello"[..]), (40, &[0xaa; 200][..])] {
        let mut fx = fixture(&[ICMP_ON]);
        let k4 = bind(&mut fx);
        let syn = syn4_opts(OTHER, 5000, k4, opt, payload);
        assert!(run_all(&mut fx, &syn).unwrap().is_empty(), "opt {opt}");
        assert_eq!(held(&fx), 1);
        expire(&fx);
        let out = housekeep(&mut fx);
        assert_eq!(out.len(), 1);
        let p = &out[0];
        assert_eq!(p.len(), 56, "quote is header + 8 bytes regardless of options/payload");
        assert_eq!(ck::fold(ck::sum(&p[20..])), 0xffff);
        let q = &p[28..];
        assert_eq!(be16(q, 2) as usize, syn.len(), "quoted total length is the original");
        assert_eq!(&q[20..28], &syn[20..28]);
    }
}

/// Odd SYN flag combinations. The hold predicate is `SYN && !ACK && !RST`,
/// so SYN+FIN / SYN+URG / SYN+PSH / SYN+ECE+CWR are held (never forwarded),
/// while any combination with ACK or RST is a plain filtered drop.
#[test]
fn qa_odd_syn_flag_combinations() {
    const PSH: u8 = 0x08;
    const URG: u8 = 0x20;
    const ECE: u8 = 0x40;
    const CWR: u8 = 0x80;
    for flags in [SYN | URG, SYN | PSH, SYN | ECE | CWR, SYN | URG | PSH | ECE] {
        let mut fx = fixture(&[]);
        let k4 = bind(&mut fx);
        let r = run_all(&mut fx, &tcp4(OTHER, 5000, k4.addr, k4.port, flags));
        assert!(r.unwrap().is_empty(), "flags {flags:#x} consumed");
        assert_eq!(held(&fx), 1, "flags {flags:#x}");
        // Nothing opens: a follow-up ACK from the same remote is filtered.
        assert_eq!(run(&mut fx, &tcp4(OTHER, 5000, k4.addr, k4.port, ACK)).unwrap_err(), DropReason::Filtered);
        // The subscriber's SYN still promotes it.
        assert!(run(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 5000, SYN)).is_ok());
        assert_eq!(held(&fx), 0);
        assert_eq!(get(&fx.ctx, Counter::TcpSynHeldMatched), 1);
    }
    // RFC-003: SYN+FIN is never a valid open and is not held.
    for flags in [SYN | FIN, SYN | FIN | URG | PSH, SYN | ACK | URG, SYN | RST | FIN, 0xff, 0x00] {
        let mut fx = fixture(&[]);
        let k4 = bind(&mut fx);
        assert!(run_all(&mut fx, &tcp4(OTHER, 5000, k4.addr, k4.port, flags)).is_err(), "flags {flags:#x}");
        assert_eq!(held(&fx), 0, "flags {flags:#x}");
    }
}

/// `max_held_syns = 0` with the ICMP on: nothing held, no ring, no ICMP.
#[test]
fn qa_zero_cap_with_icmp_on_is_inert() {
    let mut fx = fixture(&[ICMP_ON, ("max_held_syns = 16384", "max_held_syns = 0")]);
    let k4 = bind(&mut fx);
    for i in 0..50u16 {
        assert_eq!(run(&mut fx, &syn4(OTHER, 5000 + i, k4, 1, 1, 64)).unwrap_err(), DropReason::Filtered);
    }
    assert_eq!(held(&fx), 0);
    expire(&fx);
    assert!(housekeep(&mut fx).is_empty());
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeld), 0);
    assert_eq!(fx.ctx.counters.drops(DropReason::HeldSynLimit), 0);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// SI-10: arbitrary TCP bytes (any length, data offset, flags) behind a
    /// valid IPv4 header aimed at a bound port never panic, and the hold
    /// caps hold.
    #[test]
    fn qa_random_tcp_on_bound_port_never_panics(
        tcp in proptest::collection::vec(any::<u8>(), 0..120),
        total_delta in -8i32..8,
        src in any::<u32>(),
    ) {
        let mut fx = fixture(&[ICMP_ON]);
        let k4 = bind(&mut fx);
        let mut p = vec![0u8; 20 + tcp.len()];
        let tl = (p.len() as i32 + total_delta).clamp(0, 0xffff) as u16;
        write_v4_header(&mut p, 0, tl, 7, true, false, 0, 64, proto::TCP, src, k4.addr);
        p[20..].copy_from_slice(&tcp);
        if tcp.len() >= 4 { put16(&mut p, 22, k4.port); }
        let _ = run_all(&mut fx, &p);
        prop_assert!(held(&fx) <= 4);
        fx.clock.advance(Duration::from_millis(6_001));
        fx.nat.state().sweep();
        let _ = housekeep(&mut fx);
        prop_assert_eq!(held(&fx), 0);
    }
}

// ---- Fix round 1 ----

/// RFC-001: a BIB reaped while a SYN is held for less than
/// TCP_INCOMING_SYN sends no Port Unreachable for it (RFC 5382 REQ-4) and
/// does not count it as expired.
#[test]
fn reaping_a_bib_never_answers_a_young_held_syn() {
    let mut fx = fixture(&[ICMP_ON]);
    let k4 = bind(&mut fx);
    // The BIB's only session is V6 INIT (240 s transitory): hold a SYN
    // just before it ends.
    fx.clock.advance(Duration::from_secs(239));
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    assert_eq!(held(&fx), 1);
    let mut waited = 0;
    while fx.nat.state().lookup4(k4).is_some() {
        fx.clock.advance(Duration::from_millis(500));
        waited += 500;
        fx.nat.state().sweep();
    }
    assert!(waited < 6_000, "BIB reaped {waited} ms after the hold");
    assert_eq!(held(&fx), 0);
    assert!(housekeep(&mut fx).is_empty());
    assert_eq!(get(&fx.ctx, Counter::IcmpUnreachableSent), 0);
    assert_eq!(fx.nat.state().held_syn_expired_total(), 0);
}

/// SEC-001: one slot per remote IPv4 address per BIB; a SYN from another
/// port of a held remote is refused, a retransmission is a duplicate.
#[test]
fn one_slot_per_remote_address() {
    let mut fx = fixture(&[]);
    let k4 = bind(&mut fx);
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    for p in 5001..5010u16 {
        assert_eq!(run_all(&mut fx, &syn4(OTHER, p, k4, 7, 1, 64)).unwrap_err(), DropReason::HeldSynLimit);
    }
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 2, 64)).unwrap().is_empty());
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeldDup), 1);
    assert_eq!(held(&fx), 1);
    // Other remotes still get the BIB's remaining slots.
    for i in 1..4u32 {
        assert!(run_all(&mut fx, &syn4(OTHER + i, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    }
    assert_eq!(held(&fx), 4);
    // The refused port does not promote; the held one does.
    assert!(run(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 5001, SYN)).is_ok());
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeldMatched), 0);
    assert!(run(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 5000, SYN)).is_ok());
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeldMatched), 1);
}

/// NIST-005: an expired, unswept slot of the same remote is reused in
/// place (no second slot, no extra capacity used).
#[test]
fn expired_unswept_slot_is_reused_in_place() {
    let mut fx = fixture(&[ICMP_ON, ("max_held_syns_per_bib = 4", "max_held_syns_per_bib = 1")]);
    let k4 = bind(&mut fx);
    assert!(run_all(&mut fx, &syn4(OTHER, 5000, k4, 7, 1, 64)).unwrap().is_empty());
    fx.clock.advance(Duration::from_millis(6_100));
    // Not swept: the slot is expired but still occupies the only slot.
    assert!(run_all(&mut fx, &syn4(OTHER, 5001, k4, 8, 1, 64)).unwrap().is_empty());
    assert_eq!(held(&fx), 1);
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeld), 2);
    assert_eq!(fx.nat.state().held_syn_expired_total(), 1);
    // The new hold is live and promotes; the old one was answered at reuse
    // (RFC-005), not again by the sweeper.
    fx.nat.state().sweep();
    assert_eq!(housekeep(&mut fx).len(), 1);
    assert!(housekeep(&mut fx).is_empty());
    assert!(run(&mut fx, &tcp6(sub(1, 1), 40000, OTHER, 5001, SYN)).is_ok());
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeldMatched), 1);
    assert_eq!(held(&fx), 0);
}

// ---- Fix round 2 ----

/// RFC-005: reusing an expired, unswept slot queues the old SYN's Port
/// Unreachable at once (no dependence on sweep timing).
#[test]
fn reuse_in_place_answers_the_expired_syn() {
    let mut fx = fixture(&[ICMP_ON]);
    let k4 = bind(&mut fx);
    let old = syn4(OTHER, 5000, k4, 0x1111_2222, 0x0101, 60);
    assert!(run_all(&mut fx, &old).unwrap().is_empty());
    fx.clock.advance(Duration::from_millis(6_100));
    assert!(run_all(&mut fx, &syn4(OTHER, 5001, k4, 0x3333_4444, 0x0202, 60)).unwrap().is_empty());
    let out = housekeep(&mut fx);
    assert_eq!(out.len(), 1);
    let q = &out[0][28..];
    assert_eq!(&q[..20], &old[..20], "quotes the port 5000 SYN");
    assert_eq!(&q[20..28], &old[20..28]);
    assert_eq!(held(&fx), 1);
}

/// PERF-006: a slot array exists only while it holds a live slot, so the
/// arrays never exceed `max_held_syns` however many long-lived BIBs ever
/// held a SYN, and return to zero after expiry or matching.
#[test]
fn slot_arrays_bounded_by_max_held_syns() {
    let mut fx = fixture(&[("max_held_syns = 16384", "max_held_syns = 4")]);
    // 12 BIBs, each kept alive by an established session.
    let bibs: Vec<(u16, Key4)> = (0..12u16)
        .map(|i| {
            let port = 41000 + i;
            let out = run(&mut fx, &tcp6(sub(1, 1), port, SERVER, 443, SYN)).unwrap();
            let k4 = Key4 { proto: proto::TCP, addr: be32(&out, 12), port: be16(&out, 20) };
            assert!(run(&mut fx, &tcp4(SERVER, 443, k4.addr, k4.port, SYN | ACK)).is_ok());
            assert!(run(&mut fx, &tcp6(sub(1, 1), port, SERVER, 443, ACK)).is_ok());
            (port, k4)
        })
        .collect();
    let arrays = |fx: &Fx| fx.nat.state().held_syn_arrays();
    // Expiry, rotating over the BIBs.
    for round in 0..3usize {
        for (_, k4) in &bibs[4 * round..4 * round + 4] {
            assert!(run_all(&mut fx, &syn4(OTHER, 5000, *k4, 1, 1, 64)).unwrap().is_empty());
            assert!(arrays(&fx) <= 4);
        }
        assert_eq!(
            run_all(&mut fx, &syn4(OTHER, 5000, bibs[(4 * round + 4) % 12].1, 1, 1, 64)).unwrap_err(),
            DropReason::HeldSynLimit
        );
        assert_eq!(arrays(&fx), 4);
        expire(&fx);
        assert_eq!((arrays(&fx), held(&fx)), (0, 0));
    }
    // Matching.
    for (port, k4) in &bibs[..4] {
        assert!(run_all(&mut fx, &syn4(OTHER, 6000, *k4, 1, 1, 64)).unwrap().is_empty());
        assert!(run(&mut fx, &tcp6(sub(1, 1), *port, OTHER, 6000, SYN)).is_ok());
        assert_eq!(arrays(&fx), 0);
    }
    assert_eq!(get(&fx.ctx, Counter::TcpSynHeldMatched), 4);
    // Every BIB is still there (the sessions keep them alive).
    assert!(bibs.iter().all(|(_, k4)| fx.nat.state().lookup4(*k4).is_some()));
}
