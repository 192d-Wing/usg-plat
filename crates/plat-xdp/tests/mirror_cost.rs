//! PERF-001 / PERF-006: the cost of a real [`XdpMirror::install`] and
//! [`XdpMirror::retire`] against kernel `OUT6` / `IN4` hash maps (two
//! `BPF_MAP_UPDATE_ELEM` / two `BPF_MAP_DELETE_ELEM` syscalls), which WU5
//! will call inside the `bib4` shard critical section.
//!
//! Root, Linux, `bpftool` (the maps are created with `bpftool map create`
//! on the default bpffs; `SLOT` / `SLICE` are heap words, whose cost is a
//! few stores next to the syscalls). Prints µs per operation (mean, p50,
//! p99) with the maps half full; it measures, it does not gate:
//!
//! ```text
//! sudo target/.../mirror_cost-* --ignored --nocapture
//! ```
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing) - measured lock-hold input for
//!   the WU5 decision on publishing hash entries outside `bib4`
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use plat_io::bpf_obj::{Access, BPF_NOEXIST, BpfMap};
use plat_xdp::maps::HeapWords;
use plat_xdp::mirror::{SessionEntry, SessionTables, XdpMirror};
use plat_xdp_core::abi::{MAX_SLICES, SLOT_WORDS};

const SESSIONS: u32 = 65_536;
const OPS: usize = 20_000;

#[derive(Debug)]
struct Tables {
    out6: BpfMap,
    in4: BpfMap,
}

impl SessionTables for Tables {
    fn insert_out6(&self, key: &[u8; 40], slot: u32) -> io::Result<()> {
        self.out6.update(key, &slot.to_ne_bytes(), BPF_NOEXIST)
    }
    fn insert_in4(&self, key: &[u8; 12], slot: u32) -> io::Result<()> {
        self.in4.update(key, &slot.to_ne_bytes(), BPF_NOEXIST)
    }
    fn delete_out6(&self, key: &[u8; 40]) -> io::Result<bool> {
        self.out6.delete(key)
    }
    fn delete_in4(&self, key: &[u8; 12]) -> io::Result<bool> {
        self.in4.delete(key)
    }
}

fn create(dir: &std::path::Path, name: &str, key: u32) -> BpfMap {
    let p = dir.join(name);
    let ok = Command::new("bpftool")
        .args(["map", "create", p.to_str().unwrap(), "type", "hash", "key", &key.to_string(), "value", "4"])
        .args(["entries", &SESSIONS.to_string(), "name", name, "flags", "0"])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "bpftool map create {name}");
    BpfMap::open(&p, Access::ReadWrite).unwrap()
}

fn entry(n: u32) -> SessionEntry {
    let mut src6 = [0u8; 16];
    src6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    src6[12..].copy_from_slice(&n.to_be_bytes());
    let dst4 = [203, 0, 113, (n % 251) as u8];
    let mut dst6 = [0u8; 16];
    dst6[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
    dst6[12..].copy_from_slice(&dst4);
    SessionEntry {
        src6,
        sport6: 1024 + (n % 60_000) as u16,
        dst6,
        dst4,
        dport: 53,
        pool4: [198, 51, 100, (n >> 16) as u8],
        pool_port4: (n & 0xffff) as u16,
        slice: 0,
    }
}

fn report(what: &str, mut ns: Vec<u64>) {
    ns.sort_unstable();
    let mean = ns.iter().sum::<u64>() as f64 / ns.len() as f64 / 1000.0;
    let at = |q: f64| ns[((ns.len() - 1) as f64 * q) as usize] as f64 / 1000.0;
    eprintln!(
        "mirror_cost: {what}: mean {mean:.2} us, p50 {:.2} us, p99 {:.2} us ({} ops)",
        at(0.5),
        at(0.99),
        ns.len()
    );
}

#[test]
#[ignore = "root + bpftool (VM); prints µs/op"]
fn install_and_retire_cost() {
    let dir = PathBuf::from("/sys/fs/bpf/plat-qa-mirror-cost");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let tables = Arc::new(Tables { out6: create(&dir, "OUT6", 40), in4: create(&dir, "IN4", 12) });
    let slots = SESSIONS + SESSIONS / 4;
    let m = XdpMirror::with_parts(
        tables,
        Arc::new(HeapWords::new(slots as usize * SLOT_WORDS)),
        Arc::new(HeapWords::new(MAX_SLICES as usize)),
        slots,
        1024,
    );
    // Half full, as under steady load.
    let mut live = Vec::new();
    for n in 0..SESSIONS / 2 {
        let e = entry(n);
        live.push((m.install(&e, n as usize).unwrap(), e));
    }
    let (mut ins, mut ret) = (Vec::with_capacity(OPS), Vec::with_capacity(OPS));
    for i in 0..OPS {
        let n = SESSIONS / 2 + i as u32;
        let e = entry(n);
        let t = Instant::now();
        let s = m.install(&e, n as usize).unwrap();
        ins.push(t.elapsed().as_nanos() as u64);
        let (os, oe) = live.swap_remove(i % live.len());
        let t = Instant::now();
        m.retire(os, &oe).unwrap();
        ret.push(t.elapsed().as_nanos() as u64);
        live.push((s, e));
        // Recycle quarantined slots now and then (no program is attached,
        // so no grace period is needed for this measurement).
        if i % 1024 == 0 {
            m.slot_allocator().advance_epoch();
            m.slot_allocator().advance_epoch();
            m.slot_allocator().recycle();
        }
    }
    report("install (SLOT + IN4 + OUT6)", ins);
    report("retire (DEAD + OUT6 + IN4 deletes)", ret);
    std::fs::remove_dir_all(&dir).unwrap();
}
