//! Host cost of the fast-path decision (PERF-006): `decide_v6` /
//! `decide_v4` for an established session (redirect, header rewrite and
//! checksums included) and a `no_session` pass, over an in-memory `Env`
//! shaped like the level-2 namespace. Indicative only: the eBPF build adds
//! map lookups, `bpf_fib_lookup` and the redirect (plan §8; `make
//! bench-xdp` measures the object in a VM).

use std::cell::Cell;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use plat_xdp_core::abi::{
    AF_INET, Control, EgressEnt, FIB_RET_SUCCESS, FibParams, IdentEnt, IfaceEnt, Key4, Key6, ROLE_ACCESS,
    ROLE_UPSTREAM, SLICE_ACTIVE, SLOT_LIVE, SliceEnt, SlotRec, XlatConfig,
};
use plat_xdp_core::decide::{Env, Verdict};
use plat_xdp_core::ident::IdentKey;
use plat_xdp_core::{FrameEnv, HDR4, HDR6, decide_v4, decide_v6};

const VECTORS: &str = include_str!("../../../deploy/tests/xdp/level2-vectors.txt");
const ACC: u32 = 1;
const UP: u32 = 2;
const TUN: u32 = 3;

struct BenchEnv {
    ifaces: [IfaceEnt; 2],
    egress: [EgressEnt; 2],
    control: Control,
    rec: SlotRec,
    k6: Key6,
    k4: Key4,
    slice: SliceEnt,
    key: IdentKey,
    ident: Cell<IdentEnt>,
}

impl BenchEnv {
    fn new() -> Self {
        let mut src6 = [0u8; 16];
        src6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        src6[15] = 0x10;
        let mut dst6 = [0u8; 16];
        dst6[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
        dst6[12..].copy_from_slice(&[203, 0, 113, 5]);
        let rec = SlotRec {
            state: SLOT_LIVE,
            generation: 1,
            src6,
            dst6,
            sport6: 40000u16.to_be_bytes(),
            dport: 53u16.to_be_bytes(),
            pool_port4: 61000u16.to_be_bytes(),
            pool4: [198, 51, 100, 10],
            dst4: [203, 0, 113, 5],
            ..SlotRec::default()
        };
        Self {
            ifaces: [
                IfaceEnt { ifindex: ACC, mac: [0xaa; 6], role: ROLE_ACCESS, pad: 0 },
                IfaceEnt { ifindex: UP, mac: [0xcc; 6], role: ROLE_UPSTREAM, pad: 0 },
            ],
            egress: [
                EgressEnt { ifindex: ACC, allowed: 1, role: ROLE_ACCESS, pad: [0; 2] },
                EgressEnt { ifindex: UP, allowed: 1, role: ROLE_UPSTREAM, pad: [0; 2] },
            ],
            control: Control { enabled: 1, tun_ifindex: TUN, deadline_ns: u64::MAX, tun_mtu: 1500, pad: 0 },
            k6: Key6::new(rec.src6, rec.dst6, rec.sport6, rec.dport),
            k4: Key4::new(rec.pool4, rec.dst4, rec.pool_port4, rec.dport),
            rec,
            slice: SliceEnt { state: SLICE_ACTIVE, pad: [0; 3], generation: 1 },
            key: IdentKey::new(0x0123_4567_89ab_cdef, 0x0fed_cba9_8765_4321),
            ident: Cell::new(IdentEnt { rng: 0x9e37_79b9_7f4a_7c15, counter: 7, pad: [0; 6] }),
        }
    }
}

impl Env for BenchEnv {
    fn iface(&self, ifindex: u32) -> Option<&IfaceEnt> {
        self.ifaces.iter().find(|e| e.ifindex == ifindex)
    }
    fn control(&self) -> Option<&Control> {
        Some(&self.control)
    }
    fn config(&self) -> Option<XlatConfig> {
        Some(XlatConfig { mtu4: 1500, mtu6: 1500, frag6: 1280, copy_tos: true })
    }
    fn now_ns(&self) -> u64 {
        5_000_000_000
    }
    fn out6(&self, key: &Key6) -> Option<u32> {
        (*key == self.k6).then_some(7)
    }
    fn in4(&self, key: &Key4) -> Option<u32> {
        (*key == self.k4).then_some(7)
    }
    fn slot(&self, idx: u32) -> Option<&SlotRec> {
        (idx == 7).then_some(&self.rec)
    }
    fn slice(&self, idx: u16) -> Option<&SliceEnt> {
        (idx == 0).then_some(&self.slice)
    }
    fn fib(&self, p: &mut FibParams) -> i64 {
        let (out, smac, dmac) = if p.family == AF_INET {
            (UP, [2, 0, 0, 0, 1, 1], [2, 0, 0, 0, 1, 0xfe])
        } else {
            (ACC, [2, 0, 0, 0, 2, 1], [2, 0, 0, 0, 2, 0xfe])
        };
        p.ifindex = out;
        p.smac = smac;
        p.dmac = dmac;
        FIB_RET_SUCCESS
    }
    fn egress(&self, ifindex: u32) -> Option<&EgressEnt> {
        self.egress.iter().find(|e| e.ifindex == ifindex)
    }
    fn ident_key(&self) -> Option<&IdentKey> {
        Some(&self.key)
    }
    /// No frame here: the harness decides through `FrameEnv`, whose
    /// `udp_csum_ok` reads the frame.
    fn udp_csum_ok(&self, _v6: bool, _len: u32) -> bool {
        false
    }

    fn with_ident<F: FnOnce(&mut IdentEnt) -> u16>(&self, _idx: u32, f: F) -> Option<u16> {
        let mut e = self.ident.get();
        let id = f(&mut e);
        self.ident.set(e);
        Some(id)
    }
}

/// The input frame of level-2 vector `name`.
fn frame(name: &str) -> Vec<u8> {
    let l = VECTORS
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some(name) && l.starts_with("frame "))
        .unwrap_or_else(|| panic!("no vector {name}"));
    let f: Vec<&str> = l.split_whitespace().collect();
    // redirect: frame NAME DEV redirect EGRESS SLOT IN OUT; pass: frame NAME DEV pass REASON STAT IN
    let h = f[6];
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}"))).collect()
}

fn bench(c: &mut Criterion) {
    let base = BenchEnv::new();
    let v6 = frame("v6_spike_5b_payload_df0");
    let v4 = frame("v4_in_5b_payload");
    let miss = frame("v6_no_session");
    // RFC-001: the decision verifies the UDP checksum over the frame.
    let (e6, e4, em) = (FrameEnv::new(&base, &v6), FrameEnv::new(&base, &v4), FrameEnv::new(&base, &miss));
    let h6: &[u8; HDR6] = v6.first_chunk().unwrap_or_else(|| panic!("short frame"));
    let h4: &[u8; HDR4] = v4.first_chunk().unwrap_or_else(|| panic!("short frame"));
    let hm: &[u8; HDR6] = miss.first_chunk().unwrap_or_else(|| panic!("short frame"));
    let mut o4 = [0u8; HDR4];
    let mut o6 = [0u8; HDR6];
    assert!(matches!(decide_v6(&e6, ACC, h6, v6.len() as u32, &mut o4), Verdict::Redirect { .. }));
    assert!(matches!(decide_v4(&e4, UP, h4, v4.len() as u32, &mut o6), Verdict::Redirect { .. }));
    assert!(matches!(decide_v6(&em, ACC, hm, miss.len() as u32, &mut o4), Verdict::Pass(_)));

    let mut g = c.benchmark_group("xdp_decide");
    g.throughput(Throughput::Elements(1));
    g.bench_function("v6_to_v4_redirect_df0", |b| {
        b.iter(|| black_box(decide_v6(&e6, ACC, black_box(h6), v6.len() as u32, &mut o4)))
    });
    g.bench_function("v4_to_v6_redirect", |b| {
        b.iter(|| black_box(decide_v4(&e4, UP, black_box(h4), v4.len() as u32, &mut o6)))
    });
    g.bench_function("v6_pass_no_session", |b| {
        b.iter(|| black_box(decide_v6(&em, ACC, black_box(hm), miss.len() as u32, &mut o4)))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
