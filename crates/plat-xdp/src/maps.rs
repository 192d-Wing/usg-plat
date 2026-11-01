//! The fast path's BPF maps as user space sees them (plan §4.1): names, pin
//! modes and access, and (Linux) [`XdpMaps`], the pins `platd` opens
//! without privileges.
//!
//! | Map | Pin | `platd` opens |
//! |---|---|---|
//! | `OUT6`, `IN4` | 0660 | read-write (insert / delete) |
//! | `SLOT`, `SLICE`, `CONTROL` | 0660 | read-write, `mmap` |
//! | `CONFIG`, `STATS`, `FWD`, `IFACES`, `EGRESS` | 0640 | read-only (`BPF_F_RDONLY`) |
//! | `TX` | 0600 root | not at all |
//! | `IDENT`, `IDENT_KEY`, `SCRATCH` | not pinned | - |
//!
//! Every pin's type, key size, value size and flags are checked on open, so
//! a substituted or stale pin is refused rather than written.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-6 (Least Privilege), AC-3 (Access Enforcement) -
//!   `platd` gets write access only to the session, slice and control
//!   maps; interface roles, egress allow-list, counters and `CONFIG` are
//!   read-only pins (CM-6). `platd` opens the pins this way since WU5
//!   (`services/platd/src/xdp.rs`; the WU6 units add the sandbox); backed
//!   by the pin-mode tests
//!   (`tests::pin_access_is_least_privilege`, `tests/unprivileged.rs`) and
//!   by `XdpMaps::open_pinned` opening each pin with its [`MapSpec`]
//!   access only
//! - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//!   shape checks on every pin; `CONFIG` digest check (object SHA-256 and
//!   translation parameters) before the fast path may be enabled
//! - CLAUDE.md rule 3 - `OUT6` / `IN4` must not carry `BPF_F_ZERO_SEED`
//!   (the kernel's random `hashrnd` keys them); checked here and by the
//!   loader

use std::fmt;
use std::sync::atomic::AtomicU64;

/// How `platd` may open a pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAccess {
    /// 0660 root:plat, opened read-write.
    ReadWrite,
    /// 0640 root:plat, opened `BPF_F_RDONLY`.
    ReadOnly,
    /// 0600 root: the loader only.
    RootOnly,
    /// Not pinned (lives only as long as the program).
    Unpinned,
}

impl PinAccess {
    /// The pin's file mode (`None`: not pinned).
    pub const fn mode(self) -> Option<u32> {
        match self {
            Self::ReadWrite => Some(0o660),
            Self::ReadOnly => Some(0o640),
            Self::RootOnly => Some(0o600),
            Self::Unpinned => None,
        }
    }
}

/// One map of the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSpec {
    pub name: &'static str,
    pub access: PinAccess,
}

/// Every map of the `plat-xdp-ebpf` object (`crates/plat-xdp-ebpf/src/maps.rs`).
pub const MAPS: [MapSpec; 14] = [
    MapSpec { name: "OUT6", access: PinAccess::ReadWrite },
    MapSpec { name: "IN4", access: PinAccess::ReadWrite },
    MapSpec { name: "SLOT", access: PinAccess::ReadWrite },
    MapSpec { name: "SLICE", access: PinAccess::ReadWrite },
    MapSpec { name: "CONTROL", access: PinAccess::ReadWrite },
    MapSpec { name: "CONFIG", access: PinAccess::ReadOnly },
    MapSpec { name: "STATS", access: PinAccess::ReadOnly },
    MapSpec { name: "FWD", access: PinAccess::ReadOnly },
    MapSpec { name: "IFACES", access: PinAccess::ReadOnly },
    MapSpec { name: "EGRESS", access: PinAccess::ReadOnly },
    MapSpec { name: "TX", access: PinAccess::RootOnly },
    MapSpec { name: "IDENT", access: PinAccess::Unpinned },
    MapSpec { name: "IDENT_KEY", access: PinAccess::Unpinned },
    MapSpec { name: "SCRATCH", access: PinAccess::Unpinned },
];

/// Pin name of the program (0600 root).
pub const PROG_PIN: &str = "prog";

/// Prefix of the XDP link pins.
pub const LINK_PIN_PREFIX: &str = "link_";

/// Pin name of the XDP link on the interface with `ifindex` (0600 root).
/// By index, not name: bpffs refuses `.` in names (reserved), and
/// interface names may contain one (`eth0.100`).
pub fn link_pin(ifindex: u32) -> String {
    format!("{LINK_PIN_PREFIX}{ifindex}")
}

/// Bytes of the `SLOT` mmap for `slots` records (64 B each).
pub const fn slot_bytes(slots: u32) -> usize {
    slots as usize * size_of::<plat_xdp_core::abi::SlotRec>()
}

/// `SLOT` entries for `max_sessions`: ⌈1.25 × max_sessions⌉ (plan §4.1).
pub const fn slot_count(max_sessions: u32) -> u32 {
    max_sessions.saturating_add(max_sessions.div_ceil(4))
}

/// Shared 64-bit words of an mmapable array (`SLOT`, `SLICE`, `CONTROL`):
/// the `mmap` of the real map on Linux, plain memory in host tests.
pub trait Words: Send + Sync + fmt::Debug {
    fn words(&self) -> &[AtomicU64];
}

/// [`Words`] in ordinary memory (tests and the host model).
#[derive(Debug)]
pub struct HeapWords(Box<[AtomicU64]>);

impl HeapWords {
    pub fn new(words: usize) -> Self {
        Self((0..words).map(|_| AtomicU64::new(0)).collect())
    }
}

impl Words for HeapWords {
    fn words(&self) -> &[AtomicU64] {
        &self.0
    }
}

#[cfg(target_os = "linux")]
impl Words for plat_io::bpf_mmap::MmapRegion {
    fn words(&self) -> &[AtomicU64] {
        plat_io::bpf_mmap::MmapRegion::words(self)
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::AsFd;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use plat_io::bpf_mmap::MmapRegion;
    use plat_io::bpf_obj::{
        Access, BPF_F_MMAPABLE, BPF_F_RDONLY_PROG, BPF_F_ZERO_SEED, BPF_NOEXIST, BpfMap, MAP_TYPE_ARRAY, MAP_TYPE_HASH,
        MAP_TYPE_PERCPU_ARRAY,
    };
    use plat_xdp_core::abi::{ConfigRec, Control, FWD_DIRS, FwdCounters, MAX_SLICES, STATS_LEN, SliceEnt, SlotRec};

    use super::PinAccess;

    use crate::mirror::SessionTables;

    /// Why the pins cannot be used.
    #[derive(Debug, thiserror::Error)]
    pub enum OpenError {
        #[error("opening pin {0}: {1}")]
        Pin(PathBuf, io::Error),
        #[error("pin {name} has the wrong shape: {what}")]
        Shape { name: &'static str, what: String },
        #[error("mapping {0}: {1}")]
        Mmap(&'static str, io::Error),
        #[error("reading CONFIG: {0}")]
        Config(io::Error),
        /// The frozen `CONFIG` was written for another object or other
        /// translation parameters (`config_mismatch` / `object_mismatch`).
        #[error("CONFIG digest mismatch: the loaded program was set up for another object or configuration")]
        ConfigMismatch,
    }

    /// Expected kernel shape of a pin.
    struct Shape {
        map_type: u32,
        key: u32,
        value: u32,
        /// Flags that must be set.
        set: u32,
        /// Flags that must be clear.
        clear: u32,
        /// `max_entries`, when fixed by the object.
        entries: Option<u32>,
    }

    /// SEC-009: opens `name` with the access its [`super::MapSpec`] grants
    /// `platd` (a root-only or unpinned map is never opened) and checks it
    /// against `s`.
    fn open(dir: &Path, name: &'static str, s: &Shape) -> Result<BpfMap, OpenError> {
        let shape = |what: &str| OpenError::Shape { name, what: what.into() };
        let access = match super::MAPS.iter().find(|m| m.name == name).map(|m| m.access) {
            Some(PinAccess::ReadWrite) => Access::ReadWrite,
            Some(PinAccess::ReadOnly) => Access::ReadOnly,
            Some(PinAccess::RootOnly | PinAccess::Unpinned) => return Err(shape("not a platd pin")),
            None => return Err(shape("not in MAPS")),
        };
        let p = dir.join(name);
        let m = BpfMap::open(&p, access).map_err(|e| OpenError::Pin(p, e))?;
        check(name, &m, s)?;
        Ok(m)
    }

    fn check(name: &'static str, m: &BpfMap, s: &Shape) -> Result<(), OpenError> {
        let i = m.info();
        let bad = |what: String| Err(OpenError::Shape { name, what });
        if i.map_type != s.map_type {
            return bad(format!("type {} (want {})", i.map_type, s.map_type));
        }
        if i.key_size != s.key || i.value_size != s.value {
            return bad(format!("key/value {}/{} (want {}/{})", i.key_size, i.value_size, s.key, s.value));
        }
        if i.map_flags & s.set != s.set || i.map_flags & s.clear != 0 {
            return bad(format!("flags {:#x}", i.map_flags));
        }
        if let Some(n) = s.entries
            && i.max_entries != n
        {
            return bad(format!("max_entries {} (want {n})", i.max_entries));
        }
        Ok(())
    }

    const fn sz<T>() -> u32 {
        size_of::<T>() as u32
    }

    /// `OUT6` / `IN4` pins: hash maps with the kernel's random seed.
    #[derive(Debug)]
    pub struct BpfTables {
        out6: BpfMap,
        in4: BpfMap,
    }

    impl SessionTables for BpfTables {
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

    /// The pins `platd` uses, opened with the least access each needs.
    #[derive(Debug)]
    pub struct XdpMaps {
        pub(crate) tables: Arc<BpfTables>,
        pub(crate) slot: Arc<MmapRegion>,
        pub(crate) slice: Arc<MmapRegion>,
        pub(crate) control: Arc<MmapRegion>,
        pub(crate) stats: BpfMap,
        pub(crate) fwd: BpfMap,
        config_map: BpfMap,
        config: ConfigRec,
        slots: u32,
        sessions: u32,
        /// Kernel map ids of the pins as opened (integrity check).
        ids: [(&'static str, u32); 5],
    }

    impl XdpMaps {
        /// Opens every pin under `dir` (normally [`crate::PIN_DIR`]), checks
        /// each map's shape, and refuses unless the frozen `CONFIG` equals
        /// `expected` (built with [`crate::load::config_record`] from the
        /// same configuration and this binary's object).
        pub fn open_pinned(dir: &Path, expected: &ConfigRec) -> Result<Self, OpenError> {
            let hash =
                |key| Shape { map_type: MAP_TYPE_HASH, key, value: 4, set: 0, clear: BPF_F_ZERO_SEED, entries: None };
            let mm = |value, entries| Shape {
                map_type: MAP_TYPE_ARRAY,
                key: 4,
                value,
                set: BPF_F_MMAPABLE,
                clear: 0,
                entries,
            };
            let out6 = open(dir, "OUT6", &hash(40))?;
            let sessions = out6.info().max_entries;
            let in4 = open(dir, "IN4", &Shape { entries: Some(sessions), ..hash(12) })?;
            let slot = open(dir, "SLOT", &mm(sz::<SlotRec>(), Some(crate::maps::slot_count(sessions))))?;
            let slice = open(dir, "SLICE", &mm(sz::<SliceEnt>(), Some(MAX_SLICES)))?;
            let control = open(dir, "CONTROL", &mm(sz::<Control>(), Some(1)))?;
            let config = open(
                dir,
                "CONFIG",
                &Shape {
                    map_type: MAP_TYPE_ARRAY,
                    key: 4,
                    value: sz::<ConfigRec>(),
                    set: BPF_F_RDONLY_PROG,
                    clear: 0,
                    entries: Some(1),
                },
            )?;
            let pcpu = |value, entries| Shape {
                map_type: MAP_TYPE_PERCPU_ARRAY,
                key: 4,
                value,
                set: 0,
                clear: 0,
                entries: Some(entries),
            };
            let stats = open(dir, "STATS", &pcpu(8, STATS_LEN))?;
            let fwd = open(dir, "FWD", &pcpu(sz::<FwdCounters>(), FWD_DIRS))?;

            let mut b = [0u8; 40];
            if !config.lookup(&0u32.to_ne_bytes(), &mut b).map_err(OpenError::Config)? {
                return Err(OpenError::ConfigMismatch);
            }
            let got = ConfigRec::from_bytes(&b);
            if got != *expected {
                return Err(OpenError::ConfigMismatch);
            }

            let slots = slot.info().max_entries;
            let ids = [
                ("OUT6", out6.info().id),
                ("IN4", in4.info().id),
                ("SLOT", slot.info().id),
                ("CONTROL", control.info().id),
                ("CONFIG", config.info().id),
            ];
            let map = |name: &'static str, m: &BpfMap, len: usize| {
                MmapRegion::from_fd(m.as_fd(), len).map_err(|e| OpenError::Mmap(name, e))
            };
            let slot_mm = map("SLOT", &slot, crate::maps::slot_bytes(slots))?;
            let slice_mm = map("SLICE", &slice, MAX_SLICES as usize * 8)?;
            // CONTROL's 24-byte value is stored in an 8-byte-rounded slot.
            let control_mm = map("CONTROL", &control, size_of::<Control>())?;
            Ok(Self {
                tables: Arc::new(BpfTables { out6, in4 }),
                slot: Arc::new(slot_mm),
                slice: Arc::new(slice_mm),
                control: Arc::new(control_mm),
                stats,
                fwd,
                config_map: config,
                config: got,
                slots,
                sessions,
                ids,
            })
        }

        /// The periodic integrity check (plan §9, every 10 s): every pin
        /// `platd` writes or relies on still names the map it opened (a
        /// re-run loader creates fresh maps, so writes into the old ones
        /// would no longer reach the program: `maps_unavailable`), and the
        /// frozen `CONFIG` still holds `expected` (`config_mismatch`).
        /// Control path only (one `BPF_OBJ_GET` and one info call per pin).
        pub fn verify(&self, dir: &Path, expected: &ConfigRec) -> Result<(), crate::control::Fault> {
            use crate::control::Fault;
            for (name, id) in self.ids {
                let access = super::MAPS.iter().find(|m| m.name == name).map(|m| m.access);
                let access = if access == Some(PinAccess::ReadOnly) { Access::ReadOnly } else { Access::ReadWrite };
                match BpfMap::open(&dir.join(name), access) {
                    Ok(m) if m.info().id == id => {}
                    _ => return Err(Fault::MapsUnavailable),
                }
            }
            let mut b = [0u8; 40];
            match self.config_map.lookup(&0u32.to_ne_bytes(), &mut b) {
                Ok(true) if ConfigRec::from_bytes(&b) == *expected => Ok(()),
                Ok(_) => Err(Fault::ConfigMismatch),
                Err(_) => Err(Fault::MapsUnavailable),
            }
        }

        /// The frozen `CONFIG` record.
        pub fn config(&self) -> &ConfigRec {
            &self.config
        }

        /// `SLOT` entries.
        pub fn slots(&self) -> u32 {
            self.slots
        }

        /// `OUT6` / `IN4` entries (`xdp.max_sessions`).
        pub fn sessions(&self) -> u32 {
            self.sessions
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_matches_the_object() {
        // Every map the program declares, exactly once.
        let mut names: Vec<_> = MAPS.iter().map(|m| m.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), MAPS.len());
        let src = include_str!("../../plat-xdp-ebpf/src/maps.rs");
        let declared = src.matches("#[map(name = ").count();
        assert_eq!(declared, MAPS.len(), "plat-xdp-ebpf/src/maps.rs and MAPS disagree");
        for m in MAPS {
            assert!(src.contains(&format!("#[map(name = \"{}\")]", m.name)), "{} not in the object", m.name);
        }
    }

    #[test]
    fn modes() {
        let mode = |n: &str| MAPS.iter().find(|m| m.name == n).and_then(|m| m.access.mode());
        assert_eq!(mode("OUT6"), Some(0o660));
        assert_eq!(mode("CONFIG"), Some(0o640));
        assert_eq!(mode("STATS"), Some(0o640));
        assert_eq!(mode("TX"), Some(0o600));
        assert_eq!(mode("IDENT_KEY"), None);
        assert_eq!(mode("SCRATCH"), None);
    }

    #[test]
    fn sizes() {
        assert_eq!(slot_count(1024), 1280);
        assert_eq!(slot_count(4097), 4097 + 1025);
        assert_eq!(slot_bytes(2), 128);
        assert_eq!(link_pin(7), "link_7");
        assert!(MAPS.iter().all(|m| !m.name.contains('.')), "bpffs refuses dots");
    }

    // ---- QA (WU3): pin table ----

    #[test]
    fn pin_access_is_least_privilege() {
        let acc = |n: &str| MAPS.iter().find(|m| m.name == n).map(|m| m.access);
        // platd writes only the session, slot, slice and control maps.
        let rw: Vec<_> = MAPS.iter().filter(|m| m.access == PinAccess::ReadWrite).map(|m| m.name).collect();
        assert_eq!(rw, ["OUT6", "IN4", "SLOT", "SLICE", "CONTROL"]);
        for n in ["CONFIG", "STATS", "FWD", "IFACES", "EGRESS"] {
            assert_eq!(acc(n), Some(PinAccess::ReadOnly), "{n}");
        }
        assert_eq!(acc("TX"), Some(PinAccess::RootOnly));
        for n in ["IDENT", "IDENT_KEY", "SCRATCH"] {
            assert_eq!(acc(n), Some(PinAccess::Unpinned), "{n} (secret or per-CPU scratch must never be pinned)");
        }
        // No pin is world-accessible.
        for m in MAPS {
            if let Some(mode) = m.access.mode() {
                assert_eq!(mode & 0o007, 0, "{} world bits", m.name);
                assert_eq!(mode & 0o111, 0, "{} exec bits", m.name);
            }
        }
        assert!(!MAPS.iter().any(|m| m.name == PROG_PIN || m.name.starts_with(LINK_PIN_PREFIX)));
    }

    #[test]
    fn slot_sizing_saturates_and_link_pins_are_unique() {
        assert_eq!(slot_count(0), 0);
        assert_eq!(slot_count(1), 2, "ceil(1.25)");
        assert_eq!(slot_count(4), 5);
        assert_eq!(slot_count(u32::MAX), u32::MAX, "saturates, never wraps");
        assert!(slot_count(u32::MAX - 3) >= u32::MAX - 3);
        assert_eq!(slot_bytes(1), 64, "SlotRec is one cache line");
        let mut pins: Vec<String> = [1u32, 10, 100, 65, 129].iter().map(|&i| link_pin(i)).collect();
        pins.sort();
        pins.dedup();
        assert_eq!(pins.len(), 5);
        assert!(pins.iter().all(|p| !p.contains('.') && !p.contains('/') && p.len() < 64));
    }

    #[test]
    fn heap_words_are_zeroed_and_sized() {
        let w = HeapWords::new(17);
        assert_eq!(w.words().len(), 17);
        assert!(w.words().iter().all(|x| x.load(std::sync::atomic::Ordering::Relaxed) == 0));
    }
}
