//! `platd`'s view of the loader's pins, run as an unprivileged user in the
//! `platd.service` sandbox (plan §7, spike Q6, LINUX_VERIFICATION L25):
//! after `plat-xdp-loader attach -c CONFIG` (root) pinned everything under
//! the dedicated bpffs mount, this test, started with no capabilities,
//! `NoNewPrivileges` and `SystemCallFilter=@system-service bpf`, must
//!
//! - open every pin it needs (read-only pins with `BPF_F_RDONLY`), verify
//!   the shapes and the `CONFIG` digest of its own configuration and
//!   embedded object (`XdpMaps::open_pinned`);
//! - install and retire a session, write `SLICE` and `CONTROL` through
//!   `mmap`, and read the counters;
//! - be refused the root-only pins (`TX`, the program, the links), and
//!   writes through read-only pins.
//!
//! ```text
//! systemd-run --wait --pipe --uid=… --gid=plat … \
//!   -E PLAT_XDP_UNPRIV_CONFIG=/path/platd.toml target/.../unprivileged-* --ignored
//! ```
#![cfg(all(target_os = "linux", feature = "xdp"))]

use std::path::PathBuf;

use plat_io::bpf_obj::{Access, BPF_ANY, BpfMap};
use plat_xdp::control::{XdpControl, coarse_now_ns};
use plat_xdp::load::{LoadParams, config_record};
use plat_xdp::maps::XdpMaps;
use plat_xdp::mirror::{SessionEntry, XdpMirror};
use plat_xdp::stats::XdpStats;
use plat_xdp_core::abi::SLICE_FENCED;

fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    r.unwrap_or_else(|e| panic!("{what}: {e}"))
}

#[test]
#[ignore = "unprivileged, in a sandboxed unit after the loader ran (LINUX_VERIFICATION L25)"]
fn platd_view_of_the_pins() {
    assert_ne!(rustix_uid(), 0, "must run unprivileged");
    let dir = PathBuf::from(std::env::var("PLAT_XDP_UNPRIV_PIN_DIR").unwrap_or_else(|_| plat_xdp::PIN_DIR.into()));
    let cfg = ok(std::env::var("PLAT_XDP_UNPRIV_CONFIG"), "PLAT_XDP_UNPRIV_CONFIG");
    let c = ok(plat_common::Config::from_toml(&ok(std::fs::read_to_string(&cfg), &cfg)), "config");
    let mut p = LoadParams::from_config(&c);
    // SEC-001: the attach's nonce from the loader's state file.
    let state = PathBuf::from(std::env::var("PLAT_XDP_UNPRIV_STATE").unwrap_or_else(|_| plat_xdp::STATE_FILE.into()));
    p.nonce = ok(plat_xdp::load::read_state(&state), "state file").nonce;
    let maps = ok(XdpMaps::open_pinned(&dir, &config_record(&p, &plat_xdp::object_sha256())), "open_pinned");
    // SEC-001: the first claim of fresh maps succeeds, a second (another
    // platd on the same pins) is refused.
    ok(maps.claim_fresh(), "claim fresh maps");
    assert_eq!(maps.claim_fresh(), Err(plat_xdp::control::Stale::ControlUsed), "attach twice");
    assert_eq!(maps.sessions(), p.xdp.max_sessions);

    // Root-only pins.
    for n in ["TX", "prog"] {
        let e = BpfMap::open(&dir.join(n), Access::ReadOnly).err().and_then(|e| e.raw_os_error());
        assert_eq!(e, Some(13), "{n}: expected EACCES");
    }
    // Read-only pins refuse writes.
    let ro = ok(BpfMap::open(&dir.join("IFACES"), Access::ReadOnly), "IFACES ro");
    assert_eq!(ro.update(&0u32.to_ne_bytes(), &[0u8; 12], BPF_ANY).err().and_then(|e| e.raw_os_error()), Some(1));
    // ... and cannot be opened read-write (0640: group read only).
    let e = BpfMap::open(&dir.join("IFACES"), Access::ReadWrite).err().and_then(|e| e.raw_os_error());
    assert_eq!(e, Some(13), "IFACES read-write: expected EACCES");

    let m = XdpMirror::new(&maps, 4);
    let ctl = XdpControl::new(&maps);
    let generation = m.activate_slice(0);
    assert_eq!(generation.map(|g| g > 0), Some(true));
    let generation = generation.unwrap_or(1);
    let e = SessionEntry {
        src6: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99],
        sport6: 41000,
        dst6: [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9],
        dst4: [203, 0, 113, 9],
        dport: 123,
        pool4: [198, 51, 100, 10],
        pool_port4: 62000,
        slice: 0,
    };
    let slot = ok(m.install(&e, generation, 0), "install");
    assert_eq!(m.record(slot).map(|r| SessionEntry::from_record(&r)), Some(e));
    // The deferred publish and delete run unprivileged too.
    m.flush();
    assert_eq!(m.counters().installs.get(), 1, "published by an unprivileged writer");
    assert_eq!(m.record(slot).map(|r| r.state), Some(plat_xdp_core::abi::SLOT_LIVE));
    ok(m.retire(slot, &e), "retire");
    m.flush();
    assert_eq!(m.counters().retire_error.get(), 0, "deferred deletes succeeded");
    assert!(m.deactivate_slice(0, SLICE_FENCED));
    assert!(ctl.enable(1, 1500, coarse_now_ns() + 1_000_000_000));
    ctl.disable();
    assert_eq!(ctl.read().enabled, 0);
    ok(plat_xdp::control::probe_grace_period(), "membarrier(GLOBAL) in the sandbox");
    let s = ok(XdpStats::new(&maps).snapshot(), "STATS / FWD read-only");
    eprintln!("unprivileged: ok (slots {}, aborted {})", maps.slots(), s.aborted);
}

fn rustix_uid() -> u32 {
    // /proc/self/status "Uid:\t<real> <effective> ..." (no extra dependency).
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}
