//! Level 2 (plan §11): the embedded object, loaded, seeded, frozen, pinned
//! and attached by [`Loader::attach`], driven through `BPF_PROG_TEST_RUN`
//! with its map state written by this crate's writer (`XdpMirror`,
//! `XdpControl`) through the pins `platd` uses.
//!
//! Root, Linux, `--features xdp`, inside the `deploy/tests/xdp/netns.sh`
//! namespace (`bpf_fib_lookup` resolves there), one thread:
//!
//! ```text
//! nsenter --net=/run/netns/platxdp target/.../test_run-* --ignored --test-threads=1
//! ```
//!
//! (`deploy/tests/xdp/guest.sh` runs it as its level-2 step.) Covers:
//!
//! - every `deploy/tests/xdp/level2-vectors.txt` frame (the WU2 smoke set,
//!   expected outputs from `plat-xdp-core`), with the IPv4 ID of DF = 0
//!   outputs substituted (plan §2.4: the loader seeds `IDENT` at random);
//!   the one vector that needs another `CONFIG` checks that `CONFIG` is
//!   frozen instead;
//! - the paths WU2's fixed state could not reach: `TX` miss after the
//!   rewrite (`XDP_ABORTED`, `aborted` counted) and every `bpf_fib_lookup`
//!   result class from real namespace changes (forwarding off on the TUN,
//!   neighbour removed, egress MTU below the packet, route removed);
//! - the writer's own transitions: fence, generation bump, deadline,
//!   disable, retire;
//! - loader postconditions: no `BPF_F_ZERO_SEED`, `CONFIG` and `IDENT_KEY`
//!   frozen, `IDENT` seeded non-zero on every CPU, read-only pins refuse
//!   writes, and the embedded object equals the gated one
//!   (`target/xdp/plat-xdp-ebpf.sha256` from `build-object.sh`).
//!
//! Not reachable here (recorded in the WU3 notes): `headroom` (every XDP
//! mode, test runs included, gives at least `XDP_PACKET_HEADROOM` = 256 B
//! before the frame, so `adjust_head(-20)` cannot fail) and the post-adjust
//! re-check / `adjust_tail` failures (the core computes `trim` so the
//! frame is exactly `new_len ≥ HDR4`, and the helpers cannot fail on those
//! arguments; the branches exist because the verifier requires them).
#![cfg(all(target_os = "linux", feature = "xdp"))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use aya::programs::{TestRun, TestRunOptions, Xdp};
use aya_obj::programs::XdpAttachType;
use plat_io::bpf_obj::{Access, BPF_ANY, BPF_F_ZERO_SEED, BpfMap};
use plat_xdp::control::XdpControl;
use plat_xdp::load::{LoadParams, Loader, Mode, Role, XdpInterface, XdpSettings, config_record};
use plat_xdp::maps::XdpMaps;
use plat_xdp::mirror::{SessionEntry, XdpMirror};
use plat_xdp_core::abi::{
    EgressEnt, IdentEnt, IfaceEnt, PassReason, SLICE_ACTIVE, SLICE_FENCED, SlotRec, StatIdx, iface_slot,
};

const VECTORS: &str = include_str!("../../../deploy/tests/xdp/level2-vectors.txt");
const XDP_ABORTED: u32 = 0;
const XDP_PASS: u32 = 2;
const XDP_REDIRECT: u32 = 4;

struct Fx {
    dir: PathBuf,
    p: LoadParams,
    maps: XdpMaps,
    mirror: XdpMirror,
    control: XdpControl,
    prog: Xdp,
    /// Root read-write handles for state the writer does not own.
    slot_rw: BpfMap,
    slice_rw: BpfMap,
    control_rw: BpfMap,
    egress_rw: BpfMap,
    tx_rw: BpfMap,
    stats: BpfMap,
    tun: u32,
    acc: u32,
    up: u32,
    entry: SessionEntry,
    slot: u32,
    /// The writer retired the session (keys deleted): re-install.
    retired: bool,
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}"))).collect()
}

fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    r.unwrap_or_else(|e| panic!("{what}: {e}"))
}

fn ifindex(name: &str) -> u32 {
    ok(plat_io::netdev::index(name), &format!("{name} (run inside the netns.sh namespace)"))
}

fn sh(args: &[&str]) {
    let st = ok(Command::new(args[0]).args(&args[1..]).status(), args[0]);
    assert!(st.success(), "{args:?} failed");
}

fn write_sysctl(path: &str, v: &str) {
    ok(std::fs::write(path, v), path);
}

/// The session of the vectors (`map SLOT 07000000 ...`).
fn vector_session() -> SessionEntry {
    let line = VECTORS.lines().find(|l| l.starts_with("map SLOT ")).unwrap_or_else(|| panic!("no SLOT line"));
    let v = hex(line.split_whitespace().nth(3).unwrap_or_default());
    let r = SlotRec::from_bytes(v.first_chunk::<64>().unwrap_or_else(|| panic!("SLOT value")));
    SessionEntry::from_record(&r)
}

fn params() -> LoadParams {
    let mode =
        if std::env::var("PLAT_XDP_L2_MODE").is_ok_and(|m| m == "generic") { Mode::Generic } else { Mode::Native };
    LoadParams {
        xdp: XdpSettings {
            enabled: true,
            mode,
            allow_generic: true,
            max_sessions: 4096,
            interfaces: vec![
                XdpInterface { name: "acc0".into(), role: Role::Access },
                XdpInterface { name: "up0".into(), role: Role::Upstream },
            ],
            ..XdpSettings::default()
        },
        // The vectors' CONFIG: mtu4 = mtu6 = 1500, frag6 1280, copy_tos.
        mtu4: 1500,
        mtu6: 1500,
        frag6: 1280,
        copy_tos: true,
        sliced: false,
    }
}

fn fixture() -> MutexGuard<'static, Fx> {
    static FX: OnceLock<Mutex<Fx>> = OnceLock::new();
    let m = FX.get_or_init(|| Mutex::new(setup()));
    let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
    base_state(&mut g);
    g
}

fn setup() -> Fx {
    assert!(!plat_xdp::object().is_empty(), "built with AYA_BUILD_SKIP: no object to test");
    let dir = PathBuf::from(std::env::var("PLAT_XDP_L2_PIN_DIR").unwrap_or_else(|_| "/sys/fs/bpf/plat-l2".into()));
    ok(std::fs::create_dir_all(&dir), "pin dir");
    let p = params();
    let r = ok(Loader::attach(&p, &dir, None), "Loader::attach");
    eprintln!("level2: attached prog {} tag {} ({} interfaces)", r.prog_id, r.prog_tag, r.interfaces.len());
    let maps = ok(XdpMaps::open_pinned(&dir, &config_record(&p, &plat_xdp::object_sha256())), "open_pinned");
    let mirror = XdpMirror::new(&maps, 4);
    let control = XdpControl::new(&maps);
    let prog = ok(Xdp::from_pin(dir.join("prog"), XdpAttachType::Interface), "program pin");
    let rw = |n: &str| ok(BpfMap::open(&dir.join(n), Access::ReadWrite), n);
    let (acc, up, tun) = (ifindex("acc0"), ifindex("up0"), ifindex("tun0"));

    // The vector frames are addressed to the IFACES MACs the core vectors
    // use, not the veths' own: overwrite the MACs (root only; platd's pin
    // is read-only), keeping the loader's ifindex and role.
    let ifaces = rw("IFACES");
    for (line, idx) in [("iface acc0 ", acc), ("iface up0 ", up)] {
        let l = VECTORS.lines().find(|l| l.starts_with(line)).unwrap_or_else(|| panic!("{line}"));
        let f: Vec<&str> = l.split_whitespace().collect();
        let mac = hex(f[3]);
        let role: u8 = ok(f[2].parse(), "role");
        let e = IfaceEnt { ifindex: idx, mac: *mac.first_chunk().unwrap_or(&[0; 6]), role, pad: 0 };
        ok(ifaces.update(&iface_slot(idx).to_ne_bytes(), &e.to_bytes(), BPF_ANY), "IFACES");
    }

    let entry = vector_session();
    let mut fx = Fx {
        slot_rw: rw("SLOT"),
        slice_rw: rw("SLICE"),
        control_rw: rw("CONTROL"),
        egress_rw: rw("EGRESS"),
        tx_rw: rw("TX"),
        stats: ok(BpfMap::open(&dir.join("STATS"), Access::ReadOnly), "STATS"),
        dir,
        p,
        maps,
        mirror,
        control,
        prog,
        tun,
        acc,
        up,
        entry,
        slot: u32::MAX,
        retired: false,
    };
    assert_eq!(fx.mirror.activate_slice(0), Some(1), "fresh SLICE starts at generation 0");
    fx.slot = ok(fx.mirror.install(&fx.entry, 0), "install");
    fx
}

/// The shared state of the vectors: CONTROL enabled with no deadline,
/// slice 0 Active generation 1, the session LIVE, EGRESS from the loader.
fn base_state(fx: &mut Fx) {
    assert!(fx.control.enable(fx.tun, 1500, u64::MAX));
    fx.mirror.set_slice(0, SLICE_ACTIVE, 1);
    if fx.retired {
        // The writer retired it (keys deleted, slot quarantined): install
        // afresh, in another slot.
        fx.slot = ok(fx.mirror.install(&fx.entry, 1), "re-install");
        fx.retired = false;
    } else {
        // Undo raw overrides of the record (keys still in OUT6 / IN4).
        let r = fx.entry.record(plat_xdp_core::abi::SLOT_LIVE, 1);
        ok(fx.slot_rw.update(&fx.slot.to_ne_bytes(), &r.to_bytes(), BPF_ANY), "SLOT restore");
    }
    for (i, role) in [(fx.acc, 1u8), (fx.up, 2u8)] {
        let e = EgressEnt { ifindex: i, allowed: 1, role, pad: [0; 2] };
        ok(fx.egress_rw.update(&iface_slot(i).to_ne_bytes(), &e.to_bytes(), BPF_ANY), "EGRESS");
        let mut v = vec![0u8; fx.tx_rw.info().value_size as usize];
        v[..4].copy_from_slice(&i.to_ne_bytes());
        ok(fx.tx_rw.update(&i.to_ne_bytes(), &v, BPF_ANY), "TX");
    }
}

fn stat(fx: &Fx, idx: u32) -> u64 {
    let mut b = vec![0u8; fx.stats.value_len()];
    assert!(ok(fx.stats.lookup(&idx.to_ne_bytes(), &mut b), "STATS"));
    plat_xdp::stats::sum_u64(&b)
}

/// Runs `frame` on `ingress`; returns (action, output).
fn run(fx: &Fx, frame: &[u8], ingress: u32) -> (u32, Vec<u8>) {
    let mut out = vec![0u8; frame.len() + 256];
    // struct xdp_md: data, data_end, data_meta, ingress_ifindex, rx_queue_index, egress_ifindex.
    let mut ctx = Vec::with_capacity(24);
    for v in [0u32, frame.len() as u32, 0, ingress, 0, 0] {
        ctx.extend_from_slice(&v.to_ne_bytes());
    }
    let r = ok(
        fx.prog.test_run(TestRunOptions {
            data_in: Some(frame),
            data_out: Some(&mut out),
            ctx_in: Some(&ctx),
            ..TestRunOptions::default()
        }),
        "BPF_PROG_TEST_RUN",
    );
    out.truncate(r.data_size_out as usize);
    (r.return_value, out)
}

/// IPv4 header checksum over `h` (20 bytes, checksum field zeroed).
fn ipv4_csum(h: &[u8]) -> u16 {
    let mut s: u32 = h.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// Plan §2.4: copy the program's IPv4 ID into the expected IPv4 frame and
/// recompute its header checksum. DF = 1 outputs keep ID 0 (asserted).
fn substitute_id(expected: &mut [u8], got: &[u8]) {
    if expected.len() < 34 || got.len() < 34 || expected[12..14] != [0x08, 0x00] {
        return;
    }
    let df = expected[20] & 0x40 != 0;
    if df {
        assert_eq!(&got[18..20], &[0, 0], "DF = 1 must send ID 0");
        return;
    }
    expected[18..20].copy_from_slice(&got[18..20]);
    expected[24..26].fill(0);
    let c = ipv4_csum(&expected[14..34]);
    expected[24..26].copy_from_slice(&c.to_be_bytes());
}

fn devname(fx: &Fx, n: &str) -> u32 {
    match n {
        "acc0" => fx.acc,
        "up0" => fx.up,
        "tun0" => fx.tun,
        o => panic!("device {o}"),
    }
}

/// Applies one `with` override line (raw root writes); `false` when the
/// override cannot be applied by design (CONFIG is frozen).
fn apply_override(fx: &Fx, f: &[&str]) -> bool {
    match f[0] {
        "control" => {
            let mtu: u32 = ok(f[2].parse(), "mtu");
            let en: u32 = f.get(3).map_or(1, |v| ok(v.parse(), "en"));
            let dl: u64 = f.get(4).map_or(u64::MAX, |v| ok(v.parse(), "dl"));
            let c = plat_xdp_core::abi::Control {
                enabled: en,
                tun_ifindex: devname(fx, f[1]),
                deadline_ns: dl,
                tun_mtu: mtu,
                pad: 0,
            };
            ok(fx.control_rw.update(&0u32.to_ne_bytes(), &c.to_bytes(), BPF_ANY), "CONTROL");
        }
        "egress" => {
            let i = devname(fx, f[1]);
            let role: u8 = ok(f[2].parse(), "role");
            let e = EgressEnt { ifindex: i, allowed: 1, role, pad: [0; 2] };
            ok(fx.egress_rw.update(&iface_slot(i).to_ne_bytes(), &e.to_bytes(), BPF_ANY), "EGRESS");
        }
        "map" => match f[1] {
            "SLICE" => ok(fx.slice_rw.update(&hex(f[2]), &hex(f[3]), BPF_ANY), "SLICE"),
            // The vectors' slot 7 is this fixture's slot.
            "SLOT" => ok(fx.slot_rw.update(&fx.slot.to_ne_bytes(), &hex(f[3]), BPF_ANY), "SLOT"),
            "CONFIG" => {
                let c = ok(BpfMap::open(&fx.dir.join("CONFIG"), Access::ReadWrite), "CONFIG rw");
                let e = c.update(&hex(f[2]), &hex(f[3]), BPF_ANY);
                assert_eq!(e.err().and_then(|e| e.raw_os_error()), Some(libc_eperm()), "CONFIG must be frozen");
                return false;
            }
            o => panic!("override of {o}"),
        },
        o => panic!("override {o}"),
    }
    true
}

const fn libc_eperm() -> i32 {
    1
}

#[test]
#[ignore = "root, Linux VM, netns.sh namespace (plan §11 level 2)"]
fn level2_vectors() {
    let mut fx = fixture();
    let (mut redirects, mut passes, mut frozen) = (0, 0, 0);
    let mut seen_checked = false;
    let names: Vec<&str> = VECTORS.lines().filter(|l| l.starts_with("frame ")).collect();
    for line in names {
        base_state(&mut fx);
        let f: Vec<&str> = line.split_whitespace().collect();
        let (name, dev, verdict) = (f[1], f[2], f[3]);
        let overrides: Vec<Vec<&str>> = VECTORS
            .lines()
            .filter_map(|l| l.strip_prefix("with "))
            .filter_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(' ')))
            .map(|l| l.split_whitespace().collect())
            .collect();
        if !overrides.iter().all(|o| apply_override(&fx, o)) {
            frozen += 1;
            eprintln!("level2: {name}: needs another CONFIG; checked CONFIG is frozen instead");
            continue;
        }
        let ingress = devname(&fx, dev);
        match verdict {
            "redirect" => {
                let input = hex(f[6]);
                let mut want = hex(f[7]);
                let (act, got) = run(&fx, &input, ingress);
                assert_eq!(act, XDP_REDIRECT, "{name}: action");
                substitute_id(&mut want, &got);
                assert_eq!(hex_of(&got), hex_of(&want), "{name}: output");
                if !seen_checked {
                    assert_ne!(fx.mirror.seen_ns(fx.slot), 0, "{name}: seen_ns not touched");
                    seen_checked = true;
                }
                redirects += 1;
            }
            "pass" => {
                let stat_idx: u32 = ok(f[5].parse(), "stat");
                let input = hex(f[6]);
                let before = stat(&fx, stat_idx);
                let (act, got) = run(&fx, &input, ingress);
                assert_eq!(act, XDP_PASS, "{name}: action");
                assert_eq!(got, input, "{name}: a passed frame must be unmodified");
                assert_eq!(stat(&fx, stat_idx), before + 1, "{name}: STATS[{stat_idx}] ({})", f[4]);
                passes += 1;
            }
            v => panic!("{name}: verdict {v}"),
        }
    }
    eprintln!("level2: vectors ok: {redirects} redirects, {passes} passes, {frozen} CONFIG-frozen checks");
    assert!(redirects >= 6 && passes >= 20);
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn frame(name: &str) -> (Vec<u8>, u32) {
    let l = VECTORS
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some(name) && l.starts_with("frame "))
        .unwrap_or_else(|| panic!("no vector {name}"));
    let f: Vec<&str> = l.split_whitespace().collect();
    (hex(f[6]), if f[2] == "acc0" { 0 } else { 1 })
}

fn ingress(fx: &Fx, which: u32) -> u32 {
    if which == 0 { fx.acc } else { fx.up }
}

/// Runs a known-redirecting vector and expects `reason` instead.
fn expect_pass(fx: &Fx, name: &str, reason: PassReason) {
    let (input, w) = frame(name);
    let before = stat(fx, reason.stat_idx());
    let (act, got) = run(fx, &input, ingress(fx, w));
    assert_eq!(act, XDP_PASS, "{name}: expected pass {}", reason.as_str());
    assert_eq!(got, input, "{name}: unmodified");
    assert_eq!(stat(fx, reason.stat_idx()), before + 1, "{name}: {}", reason.as_str());
}

fn expect_redirect(fx: &Fx, name: &str) {
    let (input, w) = frame(name);
    assert_eq!(run(fx, &input, ingress(fx, w)).0, XDP_REDIRECT, "{name}: redirect");
}

#[test]
#[ignore = "root, Linux VM, netns.sh namespace (plan §11 level 2)"]
fn tx_miss_after_rewrite_aborts() {
    let fx = fixture();
    expect_redirect(&fx, "v6_spike_5b_payload_df0");
    assert!(ok(fx.tx_rw.delete(&fx.up.to_ne_bytes()), "TX delete"));
    let before = stat(&fx, StatIdx::Aborted as u32);
    let (input, _) = frame("v6_spike_5b_payload_df0");
    let (act, _) = run(&fx, &input, fx.acc);
    assert_eq!(act, XDP_ABORTED, "EGRESS allows up0 but TX has no entry: the rewritten frame is dropped");
    assert_eq!(stat(&fx, StatIdx::Aborted as u32), before + 1);
}

#[test]
#[ignore = "root, Linux VM, netns.sh namespace (plan §11 level 2)"]
fn fib_result_codes_from_namespace_state() {
    let fx = fixture();
    let v6 = "v6_spike_5b_payload_df0";
    let v4 = "v4_in_5b_payload";

    // FWD_DISABLED: plat-fwguard's fail-closed action (forwarding off on the TUN).
    write_sysctl("/proc/sys/net/ipv4/conf/tun0/forwarding", "0");
    expect_pass(&fx, v6, PassReason::FibFwdDisabled);
    write_sysctl("/proc/sys/net/ipv4/conf/tun0/forwarding", "1");
    expect_redirect(&fx, v6);
    write_sysctl("/proc/sys/net/ipv6/conf/tun0/forwarding", "0");
    expect_pass(&fx, v4, PassReason::FibFwdDisabled);
    write_sysctl("/proc/sys/net/ipv6/conf/tun0/forwarding", "1");
    expect_redirect(&fx, v4);

    // NO_NEIGH: the next hop is unresolved.
    sh(&["ip", "neigh", "del", "192.0.2.254", "dev", "up0"]);
    expect_pass(&fx, v6, PassReason::FibNoNeigh);
    sh(&["ip", "neigh", "replace", "192.0.2.254", "lladdr", "02:00:00:00:01:fe", "dev", "up0", "nud", "permanent"]);
    expect_redirect(&fx, v6);

    // FRAG_NEEDED: egress MTU below the 1320-byte DF output.
    sh(&["ip", "link", "set", "up0", "mtu", "1280"]);
    expect_pass(&fx, "v6_spike_1300b_df", PassReason::FibFragNeeded);
    sh(&["ip", "link", "set", "up0", "mtu", "1500"]);
    expect_redirect(&fx, "v6_spike_1300b_df");

    // Anything else (no route: NOT_FWDED / unreachable).
    sh(&["ip", "route", "del", "203.0.113.0/24"]);
    expect_pass(&fx, v6, PassReason::FibOther);
    sh(&["ip", "route", "add", "203.0.113.0/24", "via", "192.0.2.254", "dev", "up0"]);
    expect_redirect(&fx, v6);
}

#[test]
#[ignore = "root, Linux VM, netns.sh namespace (plan §11 level 2)"]
fn writer_transitions_stop_the_fast_path() {
    let mut fx = fixture();
    let v6 = "v6_spike_5b_payload_df0";
    let v4 = "v4_in_5b_payload";
    expect_redirect(&fx, v6);

    assert!(fx.mirror.deactivate_slice(0, SLICE_FENCED));
    expect_pass(&fx, v6, PassReason::SliceInactive);
    expect_pass(&fx, v4, PassReason::SliceInactive);
    assert_eq!(fx.mirror.activate_slice(0), Some(2), "Active again with a new generation");
    expect_pass(&fx, v6, PassReason::SliceInactive);
    let mut stale = Vec::new();
    fx.mirror.stale_scan(0, fx.maps.slots(), &mut stale);
    assert!(stale.iter().any(|(s, _)| *s == fx.slot), "stale generation found by the scan");
    base_state(&mut fx);
    expect_redirect(&fx, v6);

    fx.control.heartbeat(1);
    expect_pass(&fx, v4, PassReason::Deadline);
    fx.control.heartbeat(u64::MAX);
    fx.control.disable();
    expect_pass(&fx, v6, PassReason::Disabled);
    base_state(&mut fx);

    let e = fx.entry;
    assert!(fx.mirror.retire(fx.slot, &e).is_ok());
    fx.retired = true;
    expect_pass(&fx, v6, PassReason::NoSession);
    expect_pass(&fx, v4, PassReason::NoSession);
    base_state(&mut fx);
    expect_redirect(&fx, v4);
}

#[test]
#[ignore = "root, Linux VM, netns.sh namespace (plan §11 level 2)"]
fn loader_postconditions() {
    let fx = fixture();
    for n in ["OUT6", "IN4"] {
        let m = ok(BpfMap::open(&fx.dir.join(n), Access::ReadOnly), n);
        assert_eq!(m.info().map_flags & BPF_F_ZERO_SEED, 0, "{n}: BPF_F_ZERO_SEED must never be set");
        assert_eq!(m.info().max_entries, fx.p.xdp.max_sessions);
    }
    // Read-only pins refuse writes even for root (fd mode, not DAC).
    let ro = ok(BpfMap::open(&fx.dir.join("EGRESS"), Access::ReadOnly), "EGRESS ro");
    let e = ro.update(&0u32.to_ne_bytes(), &[0u8; 8], BPF_ANY);
    assert_eq!(e.err().and_then(|e| e.raw_os_error()), Some(libc_eperm()));
    // CONFIG frozen.
    let c = ok(BpfMap::open(&fx.dir.join("CONFIG"), Access::ReadWrite), "CONFIG rw");
    let e = c.update(&0u32.to_ne_bytes(), &[0u8; 40], BPF_ANY);
    assert_eq!(e.err().and_then(|e| e.raw_os_error()), Some(libc_eperm()), "CONFIG frozen");
    // Pin modes.
    for m in plat_xdp::maps::MAPS {
        let path = fx.dir.join(m.name);
        match m.access.mode() {
            Some(mode) => {
                let md = ok(std::fs::metadata(&path), m.name);
                assert_eq!(std::os::unix::fs::PermissionsExt::mode(&md.permissions()) & 0o777, mode, "{}", m.name);
            }
            None => assert!(!path.exists(), "{} must not be pinned", m.name),
        }
    }

    // The unpinned maps, through the program's map ids.
    let info = ok(fx.prog.info(), "prog info");
    let ids = ok(info.map_ids(), "map ids").unwrap_or_default();
    let mut found = 0;
    for id in ids {
        let md = ok(aya::maps::MapData::from_id(id), "map by id");
        let name = ok(md.info(), "map info").name_as_str().unwrap_or_default().to_string();
        let fd = ok(std::os::fd::AsFd::as_fd(md.fd()).try_clone_to_owned(), "dup");
        let m = ok(BpfMap::from_fd(fd, Access::ReadWrite), &name);
        match name.as_str() {
            "IDENT_KEY" => {
                let e = m.update(&0u32.to_ne_bytes(), &[0u8; 16], BPF_ANY);
                assert_eq!(e.err().and_then(|e| e.raw_os_error()), Some(libc_eperm()), "IDENT_KEY frozen");
                let mut k = [0u8; 16];
                assert!(ok(m.lookup(&0u32.to_ne_bytes(), &mut k), "IDENT_KEY"));
                assert_ne!(k, [0u8; 16], "IDENT_KEY seeded");
                found += 1;
            }
            "IDENT" => {
                let mut v = vec![0u8; m.value_len()];
                let mut counters = std::collections::BTreeSet::new();
                for idx in [0u32, 1, 4095] {
                    assert!(ok(m.lookup(&idx.to_ne_bytes(), &mut v), "IDENT"));
                    for c in v.as_chunks::<16>().0 {
                        let e = IdentEnt::from_bytes(c);
                        assert_ne!(e.rng, 0, "IDENT[{idx}] step generator zero on a CPU");
                        counters.insert(e.counter);
                    }
                }
                assert!(counters.len() > 1, "IDENT counters look unseeded");
                found += 1;
            }
            "SCRATCH" => found += 1,
            _ => {}
        }
    }
    assert_eq!(found, 3, "IDENT, IDENT_KEY and SCRATCH created by the loader");
    // Unprivileged program load must be off (AC-6(10)); the loader checked it.
    assert!(plat_xdp::load::check_unprivileged_bpf().is_ok());
}

#[test]
#[ignore = "needs make xdp (target/xdp/plat-xdp-ebpf.sha256); run with the level-2 suite"]
fn embedded_object_is_the_gated_object() {
    let f = std::env::var("PLAT_XDP_GATED_SHA256")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/xdp/plat-xdp-ebpf.sha256"));
    let t = ok(std::fs::read_to_string(&f), &f.display().to_string());
    let gated = t.split_whitespace().next().unwrap_or_default();
    assert_eq!(plat_xdp::object_sha256_hex(), gated, "embedded object differs from build-object.sh's");
}

#[test]
#[ignore = "root, Linux VM, netns.sh namespace (plan §11 level 2)"]
fn ident_ids_are_random_and_df_is_zero() {
    let fx = fixture();
    let (input, _) = frame("v6_spike_5b_payload_df0");
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let (act, got) = run(&fx, &input, fx.acc);
        assert_eq!(act, XDP_REDIRECT);
        ids.insert([got[18], got[19]]);
        // Header checksum of the program's output is valid.
        assert_eq!(ipv4_csum(&got[14..34]), 0);
    }
    assert!(ids.len() > 1, "DF = 0 IDs must advance");
    let (input, _) = frame("v6_spike_1300b_df");
    let (act, got) = run(&fx, &input, fx.acc);
    assert_eq!(act, XDP_REDIRECT);
    assert_eq!(&got[18..20], &[0, 0], "DF = 1: ID 0");
}
