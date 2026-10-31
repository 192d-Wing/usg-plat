//! Level-2 smoke vectors (WU2; the full level-2 harness is WU3, plan §11).
//!
//! `deploy/tests/xdp/level2-vectors.txt` holds a map state and frames with
//! the action and output the compiled program must produce under
//! `BPF_PROG_TEST_RUN` (`deploy/tests/xdp/obj-gate.py testrun`, inside the
//! `netns.sh` namespace). This test derives every expected output from
//! `plat-xdp-core`'s `decide_frame` with an [`Env`] that models that
//! namespace (FIB result MACs, egress interfaces) and fails when the file
//! differs, so the VM compares the eBPF object with the host core byte for
//! byte. `PLAT_XDP_BLESS=1 cargo test -p plat-xdp-ebpf` rewrites the file.
//!
//! Frames: the spike's IPv6 → IPv4 vectors and their IPv4 → IPv6 mirror
//! images from `plat-xdp-core/tests/vectors/` (one session, both
//! directions; DF = 0 and DF = 1; Ethernet padding, so `adjust_tail`
//! runs), and declines (no session, hop limit, wrong interface role, not
//! IP, short frame) that must pass unmodified.
//!
//! Also the PERF-010 interim guard: the `Env` lookups the program
//! implements return references into map memory (a by-value signature
//! would copy map values to the eBPF stack).

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Write as _;

use plat_xdp_core::abi::{
    AF_INET, AF_INET6, ConfigRec, Control, EgressEnt, FIB_RET_SUCCESS, FibParams, IdentEnt, IfaceEnt, Key4, Key6,
    PassReason, ROLE_ACCESS, ROLE_UPSTREAM, SLICE_ACTIVE, SLOT_LIVE, SliceEnt, SlotRec, XlatConfig,
};
use plat_xdp_core::decide::{Action, Env, Verdict};
use plat_xdp_core::ident::{self, IdentKey};
use plat_xdp_core::{HDR4, HDR6};

const VECTORS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/tests/xdp/level2-vectors.txt");
const CORE_V6: &str = include_str!("../../plat-xdp-core/tests/vectors/v6_to_v4.txt");
const CORE_V4: &str = include_str!("../../plat-xdp-core/tests/vectors/v4_to_v6.txt");

// Host stand-ins for the namespace's ifindexes; the file names interfaces
// and obj-gate.py resolves them with if_nametoindex.
const ACC: u32 = 1;
const UP: u32 = 2;
const TUN: u32 = 3;

/// `deploy/tests/xdp/netns.sh`: up0 / its permanent neighbour, acc0 / its
/// permanent neighbour (bpf_fib_lookup's smac / dmac).
const UP0_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x01, 0x01];
const UP0_NH: [u8; 6] = [0x02, 0, 0, 0, 0x01, 0xfe];
const ACC0_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x02, 0x01];
const ACC0_NH: [u8; 6] = [0x02, 0, 0, 0, 0x02, 0xfe];
/// Destination MACs of the core vectors' input frames (the IFACES MACs).
const ACC_IN_MAC: [u8; 6] = [0xaa; 6];
const UP_IN_MAC: [u8; 6] = [0xcc; 6];
const LINK_MTU: u32 = 1500;

const SLOT: u32 = 7;
const GEN: u32 = 1;
const NOW_NS: u64 = 5_000_000_000;

/// The spike's session (plat-xdp-core vectors): 2001:db8::10 port 40000 ->
/// 64:ff9b::203.0.113.5 port 53, pool 198.51.100.10 port 61000.
fn session() -> SlotRec {
    let mut src6 = [0u8; 16];
    src6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    src6[15] = 0x10;
    let mut dst6 = [0u8; 16];
    dst6[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
    dst6[12..].copy_from_slice(&[203, 0, 113, 5]);
    SlotRec {
        state: SLOT_LIVE,
        slice: 0,
        generation: GEN,
        seen_ns: 0,
        src6,
        dst6,
        sport6: 40000u16.to_be_bytes(),
        dport: 53u16.to_be_bytes(),
        pool_port4: 61000u16.to_be_bytes(),
        pool4: [198, 51, 100, 10],
        dst4: [203, 0, 113, 5],
        ..SlotRec::default()
    }
}

fn config() -> ConfigRec {
    ConfigRec { mtu4: 1500, mtu6: 1500, frag6: 1280, copy_tos: 1, sliced: 0, digest: [0; 32] }
}

fn ident_key() -> IdentKey {
    IdentKey::new(0x0123_4567_89ab_cdef, 0x0fed_cba9_8765_4321)
}

/// The `IDENT` entry the harness writes for index `i` (every CPU).
fn ident_init(i: u32) -> IdentEnt {
    IdentEnt {
        rng: (0x9e37_79b9_7f4a_7c15 ^ u64::from(i).wrapping_mul(0x2545_f491_4f6c_dd1d)) | 1,
        counter: (i as u16).wrapping_mul(40_503),
        pad: [0; 6],
    }
}

/// The namespace as the program sees it, for one frame (fresh `IDENT`).
struct NsEnv {
    ifaces: [IfaceEnt; 2],
    egress: [EgressEnt; 2],
    control: Control,
    config: ConfigRec,
    rec: SlotRec,
    slice: SliceEnt,
    key: IdentKey,
    ident: RefCell<Vec<(u32, IdentEnt)>>,
}

impl NsEnv {
    fn new() -> Self {
        Self {
            ifaces: [
                IfaceEnt { ifindex: ACC, mac: ACC_IN_MAC, role: ROLE_ACCESS, pad: 0 },
                IfaceEnt { ifindex: UP, mac: UP_IN_MAC, role: ROLE_UPSTREAM, pad: 0 },
            ],
            egress: [
                EgressEnt { ifindex: ACC, allowed: 1, role: ROLE_ACCESS, pad: [0; 2] },
                EgressEnt { ifindex: UP, allowed: 1, role: ROLE_UPSTREAM, pad: [0; 2] },
            ],
            control: Control { enabled: 1, tun_ifindex: TUN, deadline_ns: u64::MAX, tun_mtu: LINK_MTU, pad: 0 },
            config: config(),
            rec: session(),
            slice: SliceEnt { state: SLICE_ACTIVE, pad: [0; 3], generation: GEN },
            key: ident_key(),
            ident: RefCell::new(Vec::new()),
        }
    }

    fn rec_key6(&self) -> Key6 {
        Key6::new(self.rec.src6, self.rec.dst6, self.rec.sport6, self.rec.dport)
    }

    fn rec_key4(&self) -> Key4 {
        Key4::new(self.rec.pool4, self.rec.dst4, self.rec.pool_port4, self.rec.dport)
    }
}

impl Env for NsEnv {
    fn iface(&self, ifindex: u32) -> Option<&IfaceEnt> {
        self.ifaces.iter().find(|e| e.ifindex == ifindex)
    }
    fn control(&self) -> Option<&Control> {
        Some(&self.control)
    }
    fn config(&self) -> Option<XlatConfig> {
        Some(self.config.xlat())
    }
    fn now_ns(&self) -> u64 {
        NOW_NS
    }
    fn out6(&self, key: &Key6) -> Option<u32> {
        (*key == self.rec_key6()).then_some(SLOT)
    }
    fn in4(&self, key: &Key4) -> Option<u32> {
        (*key == self.rec_key4()).then_some(SLOT)
    }
    fn slot(&self, idx: u32) -> Option<&SlotRec> {
        (idx == SLOT).then_some(&self.rec)
    }
    fn slice(&self, idx: u16) -> Option<&SliceEnt> {
        (idx == 0).then_some(&self.slice)
    }
    /// The namespace's routes (netns.sh): IPv4 via up0, the subscriber
    /// prefixes via acc0, both through permanent neighbours; MTU 1500.
    fn fib(&self, p: &mut FibParams) -> i64 {
        assert_eq!(p.ifindex, TUN, "FIB lookups start at the TUN");
        let (out, smac, dmac) = match p.family {
            AF_INET => (UP, UP0_MAC, UP0_NH),
            AF_INET6 => (ACC, ACC0_MAC, ACC0_NH),
            f => panic!("family {f}"),
        };
        assert!(u32::from(p.tot_len) <= LINK_MTU, "vectors stay below the link MTU");
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
    fn with_ident<F: FnOnce(&mut IdentEnt) -> u16>(&self, idx: u32, f: F) -> Option<u16> {
        assert!(idx < ident::TABLE);
        let mut used = self.ident.borrow_mut();
        let mut e = ident_init(idx);
        let id = f(&mut e);
        used.push((idx, e));
        Some(id)
    }
}

/// PERF-010 (interim, until the level-2 stack gate covers every change):
/// the lookups return references tied to the environment, never copies.
/// Fails to compile if a signature changes to return a value.
fn env_returns_references<E: Env>() -> usize {
    let iface: for<'a> fn(&'a E, u32) -> Option<&'a IfaceEnt> = E::iface;
    let control: for<'a> fn(&'a E) -> Option<&'a Control> = E::control;
    let slot: for<'a> fn(&'a E, u32) -> Option<&'a SlotRec> = E::slot;
    let slice: for<'a> fn(&'a E, u16) -> Option<&'a SliceEnt> = E::slice;
    let egress: for<'a> fn(&'a E, u32) -> Option<&'a EgressEnt> = E::egress;
    let key: for<'a> fn(&'a E) -> Option<&'a IdentKey> = E::ident_key;
    let fib: for<'a, 'b> fn(&'a E, &'b mut FibParams) -> i64 = E::fib;
    [iface as usize, control as usize, slot as usize, slice as usize, egress as usize, key as usize, fib as usize].len()
}

#[test]
fn env_lookups_return_references() {
    assert_eq!(env_returns_references::<NsEnv>(), 7);
    // `config` is the one by-value accessor: 8 bytes of scalars, not a map
    // value (the eBPF `Env` reads them through a reference to CONFIG[0]).
    assert!(std::mem::size_of::<XlatConfig>() <= 8);
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}"))).collect()
}

/// The input frame of a `hex` vector in a plat-xdp-core vector file.
fn core_input(file: &str, name: &str) -> Vec<u8> {
    let line = file
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some(name) && l.starts_with("hex "))
        .unwrap_or_else(|| panic!("no core vector {name}"));
    unhex(line.split_whitespace().nth(2).unwrap_or_else(|| panic!("{name}: no input")))
}

/// The redirected frame: the output header block, then the payload,
/// trimmed to `new_len`.
fn apply(frame: &[u8], out: &[u8; HDR6], action: &Action) -> Option<(u32, Vec<u8>)> {
    let (hdr, in_hdr, ifindex, new_len, trim) = match *action {
        Action::V6ToV4(Verdict::Redirect { ifindex, new_len, trim, .. }) => {
            (&out[..HDR4], HDR6, ifindex, new_len, trim)
        }
        Action::V4ToV6(Verdict::Redirect { ifindex, new_len, trim, .. }) => (&out[..], HDR4, ifindex, new_len, trim),
        _ => return None,
    };
    let body = new_len as usize - hdr.len();
    assert_eq!(in_hdr + body + trim as usize, frame.len());
    let mut o = hdr.to_vec();
    o.extend_from_slice(&frame[in_hdr..in_hdr + body]);
    Some((ifindex, o))
}

enum Want {
    Redirect,
    Pass(PassReason),
}

fn ifname(i: u32) -> &'static str {
    match i {
        ACC => "acc0",
        UP => "up0",
        _ => panic!("ifindex {i}"),
    }
}

fn generate() -> String {
    let spike5 = core_input(CORE_V6, "spike_5b_payload");
    let in5 = core_input(CORE_V4, "in_5b_payload");
    let mut no_session6 = spike5.clone();
    no_session6[54] ^= 1; // UDP source port
    let mut hop2 = spike5.clone();
    hop2[21] = 2;
    let mut no_session4 = in5.clone();
    no_session4[36] ^= 1; // UDP destination port (the pool port)
    let mut arp = vec![0xff; 6];
    arp.extend_from_slice(&[0x02, 0, 0, 0, 0x02, 0xfe, 0x08, 0x06]);
    arp.resize(42, 0);

    let frames: Vec<(&str, u32, Vec<u8>, Want)> = vec![
        ("v6_spike_5b_payload_df0", ACC, spike5.clone(), Want::Redirect),
        ("v6_spike_1300b_df", ACC, core_input(CORE_V6, "spike_1300b_df"), Want::Redirect),
        ("v6_spike_3b_odd_length_df0", ACC, core_input(CORE_V6, "spike_3b_odd_length"), Want::Redirect),
        ("v4_in_5b_payload", UP, in5.clone(), Want::Redirect),
        ("v4_in_3b_odd_length_df0", UP, core_input(CORE_V4, "in_3b_odd_length_df0"), Want::Redirect),
        ("v4_in_ethernet_padding_60", UP, core_input(CORE_V4, "in_ethernet_padding_60"), Want::Redirect),
        ("v6_no_session", ACC, no_session6, Want::Pass(PassReason::NoSession)),
        ("v6_hop_limit_2", ACC, hop2, Want::Pass(PassReason::HopLimit)),
        ("v6_on_upstream_role", UP, spike5.clone(), Want::Pass(PassReason::Role)),
        ("v4_no_session", UP, no_session4, Want::Pass(PassReason::NoSession)),
        ("arp_not_ip", ACC, arp, Want::Pass(PassReason::NotIp)),
        ("v6_short_bad_l3", ACC, spike5[..40].to_vec(), Want::Pass(PassReason::BadL3)),
    ];

    let mut idents = BTreeSet::new();
    let mut lines = String::new();
    for (name, ingress, frame, want) in &frames {
        let env = NsEnv::new();
        let mut out = [0xa5u8; HDR6];
        let action = plat_xdp_core::decide_frame(&env, *ingress, frame, &mut out);
        match (want, action.pass_reason()) {
            (Want::Redirect, None) => {
                let (eg, o) = apply(frame, &out, &action).unwrap_or_else(|| panic!("{name}: no redirect"));
                writeln!(
                    lines,
                    "frame {name} {} redirect {} {SLOT} {} {}",
                    ifname(*ingress),
                    ifname(eg),
                    hex(frame),
                    hex(&o)
                )
                .unwrap_or_else(|e| panic!("{e}"));
            }
            (Want::Pass(r), Some(got)) if *r == got => {
                writeln!(
                    lines,
                    "frame {name} {} pass {} {} {}",
                    ifname(*ingress),
                    r.as_str(),
                    r.stat_idx(),
                    hex(frame)
                )
                .unwrap_or_else(|e| panic!("{e}"));
            }
            _ => panic!("{name}: plat-xdp-core decided {action:?}"),
        }
        for (i, _) in env.ident.borrow().iter() {
            idents.insert(*i);
        }
    }

    let env = NsEnv::new();
    let mut s = String::new();
    s.push_str(HEADER);
    let le = |i: u32| hex(&i.to_le_bytes());
    let mut state = |l: String| {
        s.push_str(&l);
        s.push('\n');
    };
    state(format!("map CONFIG {} {}", le(0), hex(&env.config.to_bytes())));
    state(format!("map SLICE {} {}", le(0), hex(&env.slice.to_bytes())));
    state(format!("map SLOT {} {}", le(SLOT), hex(&env.rec.to_bytes())));
    state(format!("map OUT6 {} {}", hex(&env.rec_key6().to_bytes()), le(SLOT)));
    state(format!("map IN4 {} {}", hex(&env.rec_key4().to_bytes()), le(SLOT)));
    state(format!("map IDENT_KEY {} {}", le(0), hex(&env.key.to_bytes())));
    for i in &idents {
        state(format!("percpu IDENT {} {}", le(*i), hex(&ident_init(*i).to_bytes())));
    }
    state(format!("iface acc0 {ROLE_ACCESS} {}", hex(&ACC_IN_MAC)));
    state(format!("iface up0 {ROLE_UPSTREAM} {}", hex(&UP_IN_MAC)));
    state(format!("egress up0 {ROLE_UPSTREAM}"));
    state(format!("egress acc0 {ROLE_ACCESS}"));
    state(format!("control tun0 {LINK_MTU}"));
    s.push('\n');
    s.push_str(&lines);
    s
}

const HEADER: &str = "\
# Level-2 smoke vectors for the plat-xdp-ebpf object (WU2), run by
# `obj-gate.py testrun` inside the netns.sh namespace. GENERATED by
# crates/plat-xdp-ebpf/tests/level2_vectors.rs from plat-xdp-core (`cargo
# test` fails when this file is stale; PLAT_XDP_BLESS=1 rewrites it).
#
# State, re-applied before every frame (integers little-endian):
#   map NAME KEY VALUE        BPF_MAP_UPDATE_ELEM with raw bytes
#   percpu NAME KEY VALUE     the same value for every CPU
#   iface DEV ROLE MAC        IFACES[ifindex % 64] = {ifindex, MAC, ROLE}
#   egress DEV ROLE           EGRESS[ifindex % 64] = {ifindex, 1, ROLE}; TX[ifindex]
#   control DEV MTU           CONTROL[0] = {1, ifindex(DEV), u64::MAX, MTU}
# Frames (ingress_ifindex = DEV):
#   frame NAME DEV redirect EGRESS SLOT IN OUT    XDP_REDIRECT, output == OUT,
#                                                 SLOT[SLOT].seen_ns touched
#   frame NAME DEV pass REASON STAT IN            XDP_PASS, frame unmodified,
#                                                 STATS[STAT] + 1
# Session: the plat-xdp-core spike vectors' (slot 7, slice 0 generation 1).

";

#[test]
fn level2_vectors_match_plat_xdp_core() {
    let want = generate();
    if std::env::var_os("PLAT_XDP_BLESS").is_some() {
        std::fs::write(VECTORS_PATH, &want).unwrap_or_else(|e| panic!("{VECTORS_PATH}: {e}"));
        return;
    }
    let have = std::fs::read_to_string(VECTORS_PATH).unwrap_or_else(|e| panic!("{VECTORS_PATH}: {e}"));
    assert!(have == want, "{VECTORS_PATH} is stale: run PLAT_XDP_BLESS=1 cargo test -p plat-xdp-ebpf");
}

#[test]
fn vectors_cover_both_directions_and_declines() {
    let v = generate();
    let n = |p: &str| v.lines().filter(|l| l.starts_with(p)).count();
    assert!(n("frame v6_") >= 3 && n("frame v4_") >= 3);
    assert!(v.lines().any(|l| l.starts_with("frame v6_no_session ") && l.contains(" pass no_session ")));
    assert!(v.lines().any(|l| l.starts_with("percpu IDENT ")), "a DF = 0 IPv6 vector draws an ID");
}
