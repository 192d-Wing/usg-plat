//! Packet builders and engine fixtures shared by tests and benches.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use plat_audit::{AuditSink, Event};
use plat_common::{Clock, Config, Counters};
use plat_nat64::{Nat64, Verdict, WorkerCtx};
use plat_packet::{checksum as ck, proto, put16, put32};
use plat_xlat::HEADROOM;
use plat_xlat::siit::{write_v4_header, write_v6_header};
use std::sync::Arc;

/// NAT64 prefix of the example config: 64:ff9b:1::/96 (RFC 8215 local use).
/// The fixtures use documentation IPv4 ranges (non-global, RFC 6890) as
/// servers, so [`config`] opts in to `allow_non_global_destinations`; the
/// default-deny policy is tested through [`config_strict`] /
/// [`fixture_strict`], and WKP behaviour has dedicated tests.
pub const PREFIX: u128 = 0x0064_ff9b_0001_0000_0000_0000_0000_0000;
/// Well-Known Prefix 64:ff9b::/96.
pub const WKP: u128 = 0x0064_ff9b_0000_0000_0000_0000_0000_0000;
/// Fixture edit that switches the engine to the Well-Known Prefix. Use it
/// together with [`WKP_POOL`]: config validation rejects the WKP with a
/// non-global pool (RFC 6052 §3.1).
pub const USE_WKP: (&str, &str) = ("nat64_prefix = \"64:ff9b:1::/96\"", "nat64_prefix = \"64:ff9b::/96\"");
/// Fixture edit: a global /30 pool (outside every RFC 6890 special-purpose
/// block) for WKP tests only.
pub const WKP_POOL: (&str, &str) = ("192.0.2.0/30", "198.20.0.0/30");
pub const POOL_BASE: u32 = 0xc000_0200; // 192.0.2.0/30

pub fn sub(n: u16, host: u16) -> u128 {
    0x2001_0db8_0100_0000_0000_0000_0000_0000 | (u128::from(n) << 64) | u128::from(host)
}

pub fn synth(v4: u32) -> u128 {
    PREFIX | u128::from(v4)
}

/// Fixture edit: no ICMPv6 Destination Unreachable when a mapping cannot be
/// created (limit tests that assert the drop itself).
pub const NO_UNREACH: (&str, &str) = ("send_unreachable = true", "send_unreachable = false");

/// Fixture edit: let servers in documentation ranges be reached.
pub const ALLOW_NON_GLOBAL: (&str, &str) =
    ("allow_non_global_destinations = false", "allow_non_global_destinations = true");

/// Example config with a /30 pool, `extra` edits, and the explicit
/// [`ALLOW_NON_GLOBAL`] opt-in.
pub fn config(extra: &[(&str, &str)]) -> Config {
    let mut e = vec![ALLOW_NON_GLOBAL];
    e.extend_from_slice(extra);
    config_strict(&e)
}

/// Example config with a /30 pool and `extra` edits only (default policy).
pub fn config_strict(extra: &[(&str, &str)]) -> Config {
    let mut t = include_str!("../../../../config/platd.example.toml").to_string();
    t = t.replace("192.0.2.0/24", "192.0.2.0/30");
    for (a, b) in extra {
        assert!(t.contains(a), "fixture key {a}");
        t = t.replace(a, b);
    }
    Config::from_toml(&t).unwrap()
}

pub struct Fx {
    pub nat: Nat64,
    pub clock: Clock,
    pub rx: crossbeam_channel::Receiver<Event>,
    pub ctx: WorkerCtx,
}

pub fn fixture(extra: &[(&str, &str)]) -> Fx {
    fixture_q(extra, 4096)
}

pub fn fixture_q(extra: &[(&str, &str)], q: usize) -> Fx {
    fixture_cfg(&config(extra), q)
}

/// Fixture with the example's default destination policy (no opt-in).
pub fn fixture_strict(extra: &[(&str, &str)]) -> Fx {
    fixture_cfg(&config_strict(extra), 4096)
}

pub fn fixture_cfg(cfg: &Config, q: usize) -> Fx {
    let clock = Clock::new();
    let (sink, rx) = AuditSink::bounded(q);
    // The first (up to) four addresses of the configured pool.
    let p = cfg.nat64.pool[0];
    let owned = (0..p.size().min(4) as u32).map(|i| p.network() + i).collect();
    let nat = Nat64::new(cfg, owned, sink, clock.clone()).unwrap();
    let ctx = nat.new_worker(Arc::new(Counters::default()), 1);
    Fx { nat, clock, rx, ctx }
}

pub fn l4_sum6(p: &mut [u8], src: u128, dst: u128, pr: u8, off: usize) {
    let len = p.len() - 40;
    put16(p, 40 + off, 0);
    let c = ck::finish(ck::pseudo_v6(src, dst, pr, len as u32) + ck::sum(&p[40..]));
    put16(p, 40 + off, if pr == proto::UDP { ck::udp_nonzero(c) } else { c });
}

pub fn udp6(src: u128, sport: u16, dst4: u32, dport: u16, payload: &[u8]) -> Vec<u8> {
    let l = 8 + payload.len();
    let mut p = vec![0u8; 40 + l];
    write_v6_header(&mut p, 0, l as u16, proto::UDP, 64, src, synth(dst4));
    put16(&mut p, 40, sport);
    put16(&mut p, 42, dport);
    put16(&mut p, 44, l as u16);
    p[48..].copy_from_slice(payload);
    l4_sum6(&mut p, src, synth(dst4), proto::UDP, 6);
    p
}

pub fn tcp6(src: u128, sport: u16, dst4: u32, dport: u16, flags: u8) -> Vec<u8> {
    let mut p = vec![0u8; 60];
    write_v6_header(&mut p, 0, 20, proto::TCP, 64, src, synth(dst4));
    put16(&mut p, 40, sport);
    put16(&mut p, 42, dport);
    p[52] = 5 << 4;
    p[53] = flags;
    l4_sum6(&mut p, src, synth(dst4), proto::TCP, 16);
    p
}

pub fn echo6(src: u128, id: u16, dst4: u32) -> Vec<u8> {
    let mut p = vec![0u8; 48 + 4];
    write_v6_header(&mut p, 0, 12, proto::ICMPV6, 64, src, synth(dst4));
    p[40] = 128;
    put16(&mut p, 44, id);
    l4_sum6(&mut p, src, synth(dst4), proto::ICMPV6, 2);
    p
}

pub fn l4_sum4(p: &mut [u8], pr: u8, off: usize) {
    let (src, dst) = (plat_packet::be32(p, 12), plat_packet::be32(p, 16));
    put16(p, 20 + off, 0);
    let s = if pr == proto::ICMP { 0 } else { ck::pseudo_v4(src, dst, pr, (p.len() - 20) as u16) };
    let c = ck::finish(s + ck::sum(&p[20..]));
    put16(p, 20 + off, c);
}

pub fn udp4(src: u32, sport: u16, dst: u32, dport: u16, payload: &[u8]) -> Vec<u8> {
    let l = 28 + payload.len();
    let mut p = vec![0u8; l];
    write_v4_header(&mut p, 0, l as u16, 0, true, false, 0, 64, proto::UDP, src, dst);
    put16(&mut p, 20, sport);
    put16(&mut p, 22, dport);
    put16(&mut p, 24, (8 + payload.len()) as u16);
    p[28..].copy_from_slice(payload);
    l4_sum4(&mut p, proto::UDP, 6);
    p
}

pub fn tcp4(src: u32, sport: u16, dst: u32, dport: u16, flags: u8) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    write_v4_header(&mut p, 0, 40, 0, true, false, 0, 64, proto::TCP, src, dst);
    put16(&mut p, 20, sport);
    put16(&mut p, 22, dport);
    p[32] = 5 << 4;
    p[33] = flags;
    l4_sum4(&mut p, proto::TCP, 16);
    p
}

/// ICMPv4 error from `router` quoting the first 28 bytes of `quoted`.
pub fn icmp4_err(router: u32, ty: u8, code: u8, rest: u32, quoted: &[u8]) -> Vec<u8> {
    let q = &quoted[..quoted.len().min(28)];
    let l = 28 + q.len();
    let dst = plat_packet::be32(quoted, 12);
    let mut p = vec![0u8; l];
    write_v4_header(&mut p, 0, l as u16, 0, false, false, 0, 64, proto::ICMP, router, dst);
    p[20] = ty;
    p[21] = code;
    put32(&mut p, 24, rest);
    p[28..].copy_from_slice(q);
    l4_sum4(&mut p, proto::ICMP, 2);
    p
}

/// Runs one packet through the engine; returns every output packet or the
/// drop.
pub fn run_all(fx: &mut Fx, pkt: &[u8]) -> Result<Vec<Vec<u8>>, plat_common::DropReason> {
    let mut buf = vec![0u8; HEADROOM + 65536];
    buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(pkt);
    match fx.nat.process(&mut buf, HEADROOM, pkt.len(), &mut fx.ctx) {
        Verdict::Forward { start, len } => Ok(vec![buf[start..start + len].to_vec()]),
        Verdict::ForwardFragments { count } => {
            let v: Vec<Vec<u8>> = fx.ctx.fragments().map(<[u8]>::to_vec).collect();
            assert_eq!(v.len(), count);
            Ok(v)
        }
        Verdict::Consumed => Ok(Vec::new()),
        Verdict::Drop(d) => Err(d),
    }
}

/// Runs one packet through the engine; returns the single output packet or
/// the drop.
pub fn run(fx: &mut Fx, pkt: &[u8]) -> Result<Vec<u8>, plat_common::DropReason> {
    let mut v = run_all(fx, pkt)?;
    assert_eq!(v.len(), 1, "expected one output packet");
    Ok(v.remove(0))
}

pub fn events(fx: &Fx) -> Vec<Event> {
    fx.rx.try_iter().collect()
}
