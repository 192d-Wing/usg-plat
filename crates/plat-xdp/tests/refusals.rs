//! QA (WU3): loader refusals, pin shape checks and `plat-io` `BpfMap`
//! buffer-length checks against real kernel maps.
//!
//! Root, Linux, needs `bpftool` and `ip` (pins are crafted with
//! `bpftool map create`). The attach refusals also need `--features xdp`
//! (an embedded object; `attach` refuses `NoObject` first otherwise).
//!
//! ```text
//! sudo target/.../refusals-* --ignored --test-threads=1
//! ```
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 - negative tests of AC-6(10) (unprivileged BPF
//!   off), SI-7 (pin shapes), SC-5 / rule 3 (no `BPF_F_ZERO_SEED`), SI-10
//!   (buffer lengths checked before every syscall)
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use plat_io::bpf_obj::{Access, BPF_ANY, BPF_F_MMAPABLE, BPF_F_ZERO_SEED, BpfMap};
use plat_xdp::maps::{OpenError, XdpMaps};
use plat_xdp_core::abi::ConfigRec;

fn sh(args: &[&str]) -> bool {
    Command::new(args[0]).args(&args[1..]).status().is_ok_and(|s| s.success())
}

fn root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).map(|l| l.split_whitespace().nth(1) == Some("0")))
        .unwrap_or(false)
}

/// A fresh pin directory on the default bpffs.
fn pin_dir(name: &str) -> PathBuf {
    let d = PathBuf::from(format!("/sys/fs/bpf/plat-qa-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn create(dir: &Path, name: &str, ty: &str, key: u32, value: u32, entries: u32, flags: u32) {
    let p = dir.join(name);
    let (k, v, e, f) = (key.to_string(), value.to_string(), entries.to_string(), flags.to_string());
    assert!(
        sh(&[
            "bpftool",
            "map",
            "create",
            p.to_str().unwrap(),
            "type",
            ty,
            "key",
            &k,
            "value",
            &v,
            "entries",
            &e,
            "name",
            name,
            "flags",
            &f,
        ]),
        "bpftool map create {name} {ty} flags {f}"
    );
}

fn shape_of(r: Result<XdpMaps, OpenError>) -> String {
    match r {
        Err(OpenError::Shape { name, what }) => format!("{name}: {what}"),
        Err(e) => format!("other: {e}"),
        Ok(_) => "accepted".into(),
    }
}

#[test]
#[ignore = "root + bpftool (VM)"]
fn bpf_map_checks_buffer_lengths_before_the_syscall() {
    assert!(root());
    let d = pin_dir("len");
    create(&d, "H", "hash", 12, 4, 8, 0);
    create(&d, "P", "percpu_array", 4, 12, 2, 0);
    let m = BpfMap::open(&d.join("H"), Access::ReadWrite).unwrap();
    assert_eq!((m.info().key_size, m.info().value_size, m.value_len()), (12, 4, 4));
    let inval = |r: std::io::Result<()>| r.err().map(|e| e.kind());
    for k in [0usize, 11, 13, 64] {
        let key = vec![0u8; k];
        assert_eq!(inval(m.update(&key, &[0; 4], BPF_ANY)), Some(ErrorKind::InvalidInput), "key {k}");
        assert_eq!(m.lookup(&key, &mut [0; 4]).err().map(|e| e.kind()), Some(ErrorKind::InvalidInput));
        assert_eq!(m.delete(&key).err().map(|e| e.kind()), Some(ErrorKind::InvalidInput));
    }
    for v in [0usize, 3, 5, 8] {
        assert_eq!(inval(m.update(&[1; 12], &vec![0; v], BPF_ANY)), Some(ErrorKind::InvalidInput), "value {v}");
        assert_eq!(m.lookup(&[1; 12], &mut vec![0; v]).err().map(|e| e.kind()), Some(ErrorKind::InvalidInput));
    }
    // Correct sizes reach the kernel.
    m.update(&[1; 12], &7u32.to_ne_bytes(), BPF_ANY).unwrap();
    let mut out = [0u8; 4];
    assert!(m.lookup(&[1; 12], &mut out).unwrap());
    assert_eq!(u32::from_ne_bytes(out), 7);
    assert!(m.delete(&[1; 12]).unwrap());
    assert!(!m.delete(&[1; 12]).unwrap(), "absent is Ok(false)");
    // Per-CPU: value_len = round_up(12, 8) × possible CPUs.
    let p = BpfMap::open(&d.join("P"), Access::ReadOnly).unwrap();
    let cpus = plat_io::bpf_obj::possible_cpus().unwrap();
    assert_eq!(p.value_len(), 16 * cpus);
    assert_eq!(p.lookup(&0u32.to_ne_bytes(), &mut [0; 12]).err().map(|e| e.kind()), Some(ErrorKind::InvalidInput));
    assert!(p.lookup(&0u32.to_ne_bytes(), &mut vec![0; 16 * cpus]).unwrap());
    // A read-only open refuses writes in the kernel (EPERM).
    let ro = BpfMap::open(&d.join("H"), Access::ReadOnly).unwrap();
    assert_eq!(ro.update(&[2; 12], &[0; 4], BPF_ANY).err().and_then(|e| e.raw_os_error()), Some(1));
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
#[ignore = "root + bpftool (VM)"]
fn open_pinned_refuses_substituted_pins() {
    assert!(root());
    let cfg = ConfigRec::default();
    // Missing pins.
    let d = pin_dir("shape0");
    assert!(matches!(XdpMaps::open_pinned(&d, &cfg), Err(OpenError::Pin(..))));
    // OUT6 with BPF_F_ZERO_SEED (rule 3).
    create(&d, "OUT6", "hash", 40, 4, 16, BPF_F_ZERO_SEED);
    let s = shape_of(XdpMaps::open_pinned(&d, &cfg));
    assert!(s.starts_with("OUT6: flags"), "{s}");
    std::fs::remove_dir_all(&d).unwrap();
    // OUT6 with the wrong key size.
    let d = pin_dir("shape1");
    create(&d, "OUT6", "hash", 36, 4, 16, 0);
    let s = shape_of(XdpMaps::open_pinned(&d, &cfg));
    assert!(s.starts_with("OUT6: key/value 36/4"), "{s}");
    std::fs::remove_dir_all(&d).unwrap();
    // OUT6 as an array.
    let d = pin_dir("shape2");
    create(&d, "OUT6", "array", 4, 4, 16, 0);
    let s = shape_of(XdpMaps::open_pinned(&d, &cfg));
    assert!(s.starts_with("OUT6: type"), "{s}");
    std::fs::remove_dir_all(&d).unwrap();
    // OUT6 fine, IN4 with BPF_F_ZERO_SEED.
    let d = pin_dir("shape3");
    create(&d, "OUT6", "hash", 40, 4, 16, 0);
    create(&d, "IN4", "hash", 12, 4, 16, BPF_F_ZERO_SEED);
    let s = shape_of(XdpMaps::open_pinned(&d, &cfg));
    assert!(s.starts_with("IN4: flags"), "{s}");
    std::fs::remove_dir_all(&d).unwrap();
    // OUT6 / IN4 sized differently.
    let d = pin_dir("shape4");
    create(&d, "OUT6", "hash", 40, 4, 16, 0);
    create(&d, "IN4", "hash", 12, 4, 32, 0);
    let s = shape_of(XdpMaps::open_pinned(&d, &cfg));
    assert!(s.starts_with("IN4: max_entries"), "{s}");
    std::fs::remove_dir_all(&d).unwrap();
    // SLOT without BPF_F_MMAPABLE.
    let d = pin_dir("shape5");
    create(&d, "OUT6", "hash", 40, 4, 16, 0);
    create(&d, "IN4", "hash", 12, 4, 16, 0);
    create(&d, "SLOT", "array", 4, 64, 20, 0);
    let s = shape_of(XdpMaps::open_pinned(&d, &cfg));
    assert!(s.starts_with("SLOT: flags"), "{s}");
    std::fs::remove_dir_all(&d).unwrap();
    // SEC-009: SLOT sized other than slot_count(OUT6 entries) = 20.
    let d = pin_dir("shape6");
    create(&d, "OUT6", "hash", 40, 4, 16, 0);
    create(&d, "IN4", "hash", 12, 4, 16, 0);
    create(&d, "SLOT", "array", 4, 64, 21, BPF_F_MMAPABLE);
    let s = shape_of(XdpMaps::open_pinned(&d, &cfg));
    assert!(s.starts_with("SLOT: max_entries 21 (want 20)"), "{s}");
    std::fs::remove_dir_all(&d).unwrap();
}

/// SEC-003: a per-CPU hash (or any type `BpfMap` cannot size) is refused at
/// open, so its lookup can never overflow the caller's buffer.
#[test]
#[ignore = "root + bpftool (VM)"]
fn unsupported_map_types_are_refused_at_open() {
    assert!(root());
    let d = pin_dir("types");
    create(&d, "PH", "percpu_hash", 4, 8, 4, 0);
    create(&d, "LPH", "lru_percpu_hash", 4, 8, 4, 0);
    create(&d, "LH", "lru_hash", 4, 8, 4, 0);
    for n in ["PH", "LPH", "LH"] {
        let e = BpfMap::open(&d.join(n), Access::ReadOnly).err().map(|e| e.kind());
        assert_eq!(e, Some(ErrorKind::InvalidInput), "{n}");
    }
    std::fs::remove_dir_all(&d).unwrap();
}

#[cfg(feature = "xdp")]
mod attach {
    use super::*;
    use plat_xdp::load::{LoadError, LoadParams, Loader, Mode, Role, XdpInterface, XdpSettings};

    fn params(ifaces: &[&str]) -> LoadParams {
        LoadParams {
            xdp: XdpSettings {
                enabled: true,
                mode: Mode::Generic,
                allow_generic: true,
                max_sessions: 4096,
                interfaces: ifaces
                    .iter()
                    .enumerate()
                    .map(|(i, n)| XdpInterface {
                        name: (*n).into(),
                        role: if i == 0 { Role::Access } else { Role::Upstream },
                    })
                    .collect(),
                ..XdpSettings::default()
            },
            mtu4: 1500,
            mtu6: 1500,
            frag6: 1280,
            copy_tos: true,
            sliced: false,
            // RFC 6052 well-known prefix 64:ff9b::/96.
            prefix: 0x0064_ff9b_u128 << 96,
            prefix_len: 96,
            allow_non_global: false,
        }
    }

    #[test]
    fn disabled_is_refused_before_any_privileged_step() {
        let mut p = params(&["lo"]);
        p.xdp.enabled = false;
        assert!(matches!(Loader::attach(&p, Path::new("/nonexistent"), None), Err(LoadError::Disabled)));
    }

    #[test]
    #[ignore = "root (VM)"]
    fn not_bpffs_is_refused() {
        assert!(root());
        let d = std::env::temp_dir().join("plat-qa-not-bpffs");
        std::fs::create_dir_all(&d).unwrap();
        let r = Loader::attach(&params(&["lo"]), &d, None);
        assert!(matches!(r, Err(LoadError::NotBpffs(_))), "{r:?}");
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "nothing written");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    #[ignore = "root (VM)"]
    fn ifindex_slot_collision_is_refused() {
        assert!(root());
        // 129 % 64 == 193 % 64 == 1.
        let _ = sh(&["ip", "link", "del", "qacol0"]);
        let _ = sh(&["ip", "link", "del", "qacol1"]);
        assert!(sh(&["ip", "link", "add", "qacol0", "index", "129", "type", "dummy"]));
        assert!(sh(&["ip", "link", "add", "qacol1", "index", "193", "type", "dummy"]));
        let d = pin_dir("col");
        let r = Loader::attach(&params(&["qacol0", "qacol1"]), &d, None);
        let _ = sh(&["ip", "link", "del", "qacol0"]);
        let _ = sh(&["ip", "link", "del", "qacol1"]);
        match r {
            Err(LoadError::SlotCollision(a, b, 1)) => assert_eq!((a.as_str(), b.as_str()), ("qacol0", "qacol1")),
            other => panic!("expected SlotCollision: {other:?}"),
        }
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "refused before anything is pinned");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    #[ignore = "root (VM); toggles kernel.unprivileged_bpf_disabled 2 -> 0 -> 2"]
    fn unprivileged_bpf_enabled_is_refused() {
        assert!(root());
        let path = "/proc/sys/kernel/unprivileged_bpf_disabled";
        let was = std::fs::read_to_string(path).unwrap().trim().to_string();
        if was == "1" {
            eprintln!("unprivileged_bpf_disabled = 1 is sticky until reboot: only the accept side is checked");
            assert!(plat_xdp::load::check_unprivileged_bpf().is_ok());
            return;
        }
        std::fs::write(path, "0").unwrap();
        let d = pin_dir("unpriv");
        let r = Loader::attach(&params(&["lo"]), &d, None);
        let c = plat_xdp::load::check_unprivileged_bpf();
        std::fs::write(path, &was).unwrap();
        assert!(matches!(r, Err(LoadError::UnprivilegedBpf(ref v)) if v == "0"), "{r:?}");
        assert!(matches!(c, Err(LoadError::UnprivilegedBpf(_))));
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
        std::fs::remove_dir_all(&d).unwrap();
        assert!(plat_xdp::load::check_unprivileged_bpf().is_ok(), "restored to {was}");
    }
}
