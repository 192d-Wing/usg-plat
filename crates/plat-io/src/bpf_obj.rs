//! BPF objects through the raw `bpf(2)` syscall (Linux): opening pinned
//! maps read-only or read-write, freezing, element lookup, update and
//! delete, and the map's kernel information.
//!
//! Aya's `MapData::from_pin` always opens pins read-write (`file_flags =
//! 0`), which cannot open the 0640 read-only pins `platd` is given (plan
//! §4.1, spike Q6), and Aya has no public `BPF_MAP_FREEZE`. Its typed maps
//! also need `&mut self` to update, so concurrent `platd` workers would
//! need a lock around every map handle. [`BpfMap`] is the small
//! lock-free alternative: the kernel serialises element operations itself
//! (bucket locks inside the syscall, never held across user code), so a
//! shared `&BpfMap` is enough.
//!
//! Every `bpf_attr` is built on the stack and every key or value buffer is
//! checked against the sizes the kernel reported for the map, so the kernel
//! never reads or writes past a caller's slice.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-6 (Least Privilege), AC-3 (Access Enforcement) - pins
//!   opened with `BPF_F_RDONLY` when the caller only reads, so DAC on the
//!   0640 pins (`CONFIG`, `STATS`, `FWD`, `IFACES`, `EGRESS`) is honoured
//! - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//!   `BPF_MAP_FREEZE` makes `CONFIG` / `IDENT_KEY` immutable from user space
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - no allocation per
//!   element operation; buffers are the caller's

#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
const BPF_MAP_DELETE_ELEM: libc::c_long = 3;
const BPF_OBJ_GET: libc::c_long = 7;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;
const BPF_MAP_FREEZE: libc::c_long = 22;

/// `file_flags` of `BPF_OBJ_GET`: read-only descriptor.
const BPF_F_RDONLY: u32 = 1 << 3;

/// `BPF_MAP_UPDATE_ELEM` flags.
pub const BPF_ANY: u64 = 0;
/// Insert only if the key is absent (`EEXIST` otherwise).
pub const BPF_NOEXIST: u64 = 1;
/// Update only if the key exists.
pub const BPF_EXIST: u64 = 2;

/// `map_flags`: hash maps hashed with a zero seed (`htab->hashrnd = 0`).
/// The loader never sets it (CLAUDE.md rule 3); [`MapInfo::map_flags`]
/// lets it and `platd` verify that.
pub const BPF_F_ZERO_SEED: u32 = 1 << 6;
/// `map_flags`: the program may only read the map.
pub const BPF_F_RDONLY_PROG: u32 = 1 << 7;
/// `map_flags`: the array may be `mmap`ed.
pub const BPF_F_MMAPABLE: u32 = 1 << 10;

/// `BPF_MAP_TYPE_HASH`.
pub const MAP_TYPE_HASH: u32 = 1;
/// `BPF_MAP_TYPE_ARRAY`.
pub const MAP_TYPE_ARRAY: u32 = 2;
/// `BPF_MAP_TYPE_PERCPU_ARRAY`.
pub const MAP_TYPE_PERCPU_ARRAY: u32 = 6;
/// `BPF_MAP_TYPE_DEVMAP_HASH`.
pub const MAP_TYPE_DEVMAP_HASH: u32 = 25;

/// How a pin is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `BPF_F_RDONLY`: lookups only (0640 pins).
    ReadOnly,
    /// Lookups, updates and deletes (0660 pins).
    ReadWrite,
}

/// `bpf_attr` for `BPF_OBJ_GET`.
#[repr(C)]
struct ObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

/// `bpf_attr` for the element commands.
#[repr(C)]
struct ElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// `bpf_attr` for `BPF_OBJ_GET_INFO_BY_FD`.
#[repr(C)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// `bpf_attr` for `BPF_MAP_FREEZE`.
#[repr(C)]
struct FreezeAttr {
    map_fd: u32,
    _pad: u32,
}

/// The leading fields of the kernel's `struct bpf_map_info` (stable ABI;
/// the kernel copies at most `info_len` bytes).
#[repr(C)]
#[derive(Default)]
struct RawMapInfo {
    map_type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [u8; 16],
}

/// `bpf(cmd, attr, size_of::<A>())`.
///
/// # Safety
///
/// `attr` must be the `bpf_attr` layout of `cmd`, and every pointer in it
/// must be valid for the reads and writes `cmd` performs.
unsafe fn sys_bpf<A>(cmd: libc::c_long, attr: &mut A) -> io::Result<libc::c_long> {
    // SAFETY: per the caller's contract; the kernel reads at most
    // `size_of::<A>()` bytes of `attr` and zero-extends the rest.
    let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, std::ptr::from_mut(attr), size_of::<A>()) };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

/// `BPF_OBJ_GET`: opens the pinned object at `path` (`BPF_F_RDONLY` for
/// [`Access::ReadOnly`]). The descriptor is close-on-exec.
pub fn obj_get(path: &Path, access: Access) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut attr = ObjAttr {
        pathname: c.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: match access {
            Access::ReadOnly => BPF_F_RDONLY,
            Access::ReadWrite => 0,
        },
    };
    // SAFETY: `attr` is the BPF_OBJ_GET layout; `pathname` points to `c`,
    // a NUL-terminated string that outlives the call.
    let fd = unsafe { sys_bpf(BPF_OBJ_GET, &mut attr) }?;
    let fd = i32::try_from(fd).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: the kernel returned a new descriptor that nothing else owns
    // (bpf object descriptors are created O_CLOEXEC).
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `BPF_MAP_FREEZE`: user space can no longer write the map (the program
/// still reads it). Irreversible.
pub fn map_freeze(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut attr = FreezeAttr { map_fd: raw(fd)?, _pad: 0 };
    // SAFETY: `attr` is the BPF_MAP_FREEZE layout; no pointers.
    unsafe { sys_bpf(BPF_MAP_FREEZE, &mut attr) }.map(drop)
}

fn raw(fd: BorrowedFd<'_>) -> io::Result<u32> {
    u32::try_from(fd.as_raw_fd()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// What the kernel reports about a map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapInfo {
    pub map_type: u32,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    /// The kernel's (truncated, NUL-padded) map name.
    pub name: [u8; 16],
}

impl MapInfo {
    /// The name up to the first NUL.
    pub fn name(&self) -> &[u8] {
        let n = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        self.name.get(..n).unwrap_or(&[])
    }
}

/// `BPF_OBJ_GET_INFO_BY_FD` for a map descriptor.
pub fn map_info(fd: BorrowedFd<'_>) -> io::Result<MapInfo> {
    let mut info = RawMapInfo::default();
    let mut attr = InfoAttr {
        bpf_fd: raw(fd)?,
        info_len: size_of::<RawMapInfo>() as u32,
        info: std::ptr::from_mut(&mut info) as u64,
    };
    // SAFETY: `attr` is the BPF_OBJ_GET_INFO_BY_FD layout; `info` points to
    // a writable `RawMapInfo` of `info_len` bytes that outlives the call.
    unsafe { sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr) }?;
    Ok(MapInfo {
        map_type: info.map_type,
        id: info.id,
        key_size: info.key_size,
        value_size: info.value_size,
        max_entries: info.max_entries,
        map_flags: info.map_flags,
        name: info.name,
    })
}

/// Number of possible CPUs from a `/sys/devices/system/cpu/possible` list
/// (`0-3`, `0,2-5`): the highest listed CPU + 1, as the kernel sizes
/// per-CPU map values (`num_possible_cpus()` for a contiguous mask).
pub fn parse_possible_cpus(text: &str) -> Option<usize> {
    let mut max: Option<usize> = None;
    for part in text.trim().split(',') {
        let hi = match part.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi) = (lo.parse::<usize>().ok()?, hi.parse::<usize>().ok()?);
                if lo > hi {
                    return None;
                }
                hi
            }
            None => part.parse::<usize>().ok()?,
        };
        max = Some(max.map_or(hi, |m| m.max(hi)));
    }
    max.and_then(|m| m.checked_add(1))
}

/// The number of possible CPUs (`/sys/devices/system/cpu/possible`).
pub fn possible_cpus() -> io::Result<usize> {
    let t = std::fs::read_to_string("/sys/devices/system/cpu/possible")?;
    parse_possible_cpus(&t).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cpu/possible"))
}

/// The map types [`BpfMap`] accepts: exactly those of the `plat-xdp-ebpf`
/// object (`HashMap` for `OUT6` / `IN4`, `Array` for `SLOT`, `SLICE`,
/// `CONTROL`, `CONFIG`, `IDENT_KEY`, `IFACES`, `EGRESS`, `PerCpuArray` for
/// `IDENT`, `STATS`, `FWD`, `SCRATCH`, `DevMapHash` for `TX`).
pub const SUPPORTED_TYPES: [u32; 4] = [MAP_TYPE_HASH, MAP_TYPE_ARRAY, MAP_TYPE_PERCPU_ARRAY, MAP_TYPE_DEVMAP_HASH];

/// Bytes one lookup copies for a map of `info` (`cpus` is called only for
/// the per-CPU type): `value_size`, or `round_up(value_size, 8) × possible
/// CPUs` for `PERCPU_ARRAY`. Errors on an unsupported type or an overflow.
fn value_len(info: &MapInfo, cpus: impl FnOnce() -> io::Result<usize>) -> io::Result<usize> {
    let v = info.value_size as usize;
    match info.map_type {
        MAP_TYPE_PERCPU_ARRAY => v
            .next_multiple_of(8)
            .checked_mul(cpus()?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "per-CPU value size overflows")),
        MAP_TYPE_HASH | MAP_TYPE_ARRAY | MAP_TYPE_DEVMAP_HASH => Ok(v),
        t => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unsupported BPF map type {t}"))),
    }
}

/// Whether `fd` is a BPF map: the kernel names its anonymous inode
/// `bpf-map` (`bpf_map_new_fd`); programs are `bpf-prog`, links `bpf_link`.
fn is_map_fd(fd: BorrowedFd<'_>) -> io::Result<bool> {
    let l = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    Ok(l.as_os_str().as_bytes() == b"anon_inode:bpf-map")
}

/// A map descriptor with the sizes the kernel reported, so every element
/// operation can check its buffers. `Sync`: element operations are
/// independent syscalls.
#[derive(Debug)]
pub struct BpfMap {
    fd: OwnedFd,
    info: MapInfo,
    /// Bytes of one value as the syscalls copy it: `value_size`, or for
    /// per-CPU maps `round_up(value_size, 8) × possible CPUs`.
    value_len: usize,
    access: Access,
}

impl BpfMap {
    /// Opens the pin at `path`.
    pub fn open(path: &Path, access: Access) -> io::Result<Self> {
        Self::from_fd(obj_get(path, access)?, access)
    }

    /// Wraps a map descriptor (queries its information).
    ///
    /// SEC-003 / SEC-009: refuses a descriptor that is not a BPF map (a
    /// program or link pin also answers `BPF_OBJ_GET_INFO_BY_FD`, with a
    /// different layout) and every map type other than [`SUPPORTED_TYPES`].
    /// The lookup buffer length is derived from the type; a per-CPU type
    /// sized as a plain one would let the kernel write past `out`, so
    /// unknown types are refused rather than guessed.
    pub fn from_fd(fd: OwnedFd, access: Access) -> io::Result<Self> {
        if !is_map_fd(fd.as_fd())? {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "descriptor is not a BPF map"));
        }
        let info = map_info(fd.as_fd())?;
        let value_len = value_len(&info, possible_cpus)?;
        Ok(Self { fd, info, value_len, access })
    }

    pub fn info(&self) -> &MapInfo {
        &self.info
    }

    /// Bytes [`BpfMap::lookup`] writes (see the field).
    pub fn value_len(&self) -> usize {
        self.value_len
    }

    pub fn access(&self) -> Access {
        self.access
    }

    fn check(&self, key: &[u8], value: Option<usize>) -> io::Result<()> {
        if key.len() != self.info.key_size as usize || value.is_some_and(|v| v != self.value_len) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "BPF map key or value size mismatch"));
        }
        Ok(())
    }

    /// Copies the value of `key` into `out` (exactly [`BpfMap::value_len`]
    /// bytes). `Ok(false)` when the key is absent.
    pub fn lookup(&self, key: &[u8], out: &mut [u8]) -> io::Result<bool> {
        self.check(key, Some(out.len()))?;
        let mut attr = ElemAttr {
            map_fd: raw(self.fd.as_fd())?,
            _pad: 0,
            key: key.as_ptr() as u64,
            value: out.as_mut_ptr() as u64,
            flags: 0,
        };
        // SAFETY: element layout; `key` is `key_size` readable bytes and
        // `out` is `value_len` writable bytes (checked above), both
        // outliving the call.
        match unsafe { sys_bpf(BPF_MAP_LOOKUP_ELEM, &mut attr) } {
            Ok(_) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Writes `value` (exactly [`BpfMap::value_len`] bytes) for `key` with
    /// `flags` ([`BPF_ANY`], [`BPF_NOEXIST`], [`BPF_EXIST`]).
    pub fn update(&self, key: &[u8], value: &[u8], flags: u64) -> io::Result<()> {
        self.check(key, Some(value.len()))?;
        let mut attr = ElemAttr {
            map_fd: raw(self.fd.as_fd())?,
            _pad: 0,
            key: key.as_ptr() as u64,
            value: value.as_ptr() as u64,
            flags,
        };
        // SAFETY: element layout; `key` and `value` are readable buffers of
        // the map's key and value sizes (checked above).
        unsafe { sys_bpf(BPF_MAP_UPDATE_ELEM, &mut attr) }.map(drop)
    }

    /// Deletes `key`. `Ok(false)` when it was absent.
    pub fn delete(&self, key: &[u8]) -> io::Result<bool> {
        self.check(key, None)?;
        let mut attr =
            ElemAttr { map_fd: raw(self.fd.as_fd())?, _pad: 0, key: key.as_ptr() as u64, value: 0, flags: 0 };
        // SAFETY: element layout; `key` is `key_size` readable bytes.
        match unsafe { sys_bpf(BPF_MAP_DELETE_ELEM, &mut attr) } {
            Ok(_) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

impl AsFd for BpfMap {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn possible_cpu_lists() {
        assert_eq!(parse_possible_cpus("0\n"), Some(1));
        assert_eq!(parse_possible_cpus("0-3\n"), Some(4));
        assert_eq!(parse_possible_cpus("0,2-5"), Some(6));
        assert_eq!(parse_possible_cpus("0-127"), Some(128));
        assert_eq!(parse_possible_cpus(""), None);
        assert_eq!(parse_possible_cpus("3-1"), None);
        assert_eq!(parse_possible_cpus("x"), None);
    }

    #[test]
    fn attr_layouts() {
        // linux/bpf.h: the element commands' attr is 32 bytes, obj/info 16.
        assert_eq!(size_of::<ElemAttr>(), 32);
        assert_eq!(size_of::<ObjAttr>(), 16);
        assert_eq!(size_of::<InfoAttr>(), 16);
        assert_eq!(size_of::<RawMapInfo>(), 40);
    }

    fn info(map_type: u32, value_size: u32) -> MapInfo {
        MapInfo { map_type, id: 1, key_size: 4, value_size, max_entries: 1, map_flags: 0, name: [0; 16] }
    }

    #[test]
    fn value_len_by_type() {
        let four = || Ok(4);
        assert_eq!(value_len(&info(MAP_TYPE_HASH, 4), four).ok(), Some(4));
        assert_eq!(value_len(&info(MAP_TYPE_ARRAY, 64), four).ok(), Some(64));
        assert_eq!(value_len(&info(MAP_TYPE_DEVMAP_HASH, 8), four).ok(), Some(8));
        assert_eq!(value_len(&info(MAP_TYPE_PERCPU_ARRAY, 12), four).ok(), Some(64), "rounded to 8 x CPUs");
        assert!(value_len(&info(MAP_TYPE_PERCPU_ARRAY, u32::MAX), || Ok(usize::MAX)).is_err());
        // SEC-003: per-CPU hash, LRU per-CPU hash, per-CPU cgroup storage,
        // LRU hash and anything else are refused, never sized as plain.
        for t in [5, 9, 10, 21, 0, 99] {
            assert!(value_len(&info(t, 8), four).is_err(), "type {t} accepted");
        }
        for t in SUPPORTED_TYPES {
            assert!(value_len(&info(t, 8), four).is_ok());
        }
    }

    #[test]
    fn a_non_bpf_descriptor_is_not_a_map() {
        let f = std::fs::File::open("/dev/null").unwrap_or_else(|e| panic!("{e}"));
        assert!(!is_map_fd(f.as_fd()).unwrap_or(true));
        assert!(BpfMap::from_fd(OwnedFd::from(f), Access::ReadOnly).is_err());
    }

    #[test]
    fn missing_pin_is_an_error() {
        let p = Path::new("/nonexistent/plat-io-bpf-obj-test");
        assert!(obj_get(p, Access::ReadOnly).is_err());
    }
}
