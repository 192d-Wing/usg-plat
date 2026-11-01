//! Loader library (plan §4.4, §7): the `[xdp]` settings, the frozen
//! `CONFIG` record with its digest, and (Linux) [`Loader`], the privileged
//! one-shot step `plat-xdp-loader` runs.
//!
//! `[xdp]` is not yet part of `plat_common::Config` (WU5 adds it there);
//! until then [`split_config`] takes the `[xdp]` table out of the `platd`
//! configuration file and validates the rest with `plat_common`, so the
//! loader and `platd` read one file with the same validation.
//!
//! **Digest.** `CONFIG.digest` is SHA-256 over a version tag, the embedded
//! object's SHA-256, the translation parameters, the map sizes and the
//! interface list. `platd` recomputes it from its own configuration and
//! embedded object and refuses the pins on any difference
//! ([`crate::maps::XdpMaps::open_pinned`]), which covers both
//! `config_mismatch` and `object_mismatch`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-6 (Configuration Settings), CM-7 (Least Functionality)
//!   - `[xdp]` validated (`deny_unknown_fields`, ranges), off by default,
//!     generic mode refused unless `allow_generic`, fixed pin directory
//! - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//!   `CONFIG` and `IDENT_KEY` frozen; digest binds object and parameters
//! - NIST 800-53: AC-6 (Least Privilege), AC-6(10) - the loader refuses
//!   unless `kernel.unprivileged_bpf_disabled ≥ 1`; pins get the narrowest
//!   mode (`maps::MAPS`); the program, links and `TX` are root 0600
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - map sizes from
//!   `xdp.max_sessions` (4096..=`nat64.max_sessions`)
//! - CLAUDE.md rule 3 - `BPF_F_ZERO_SEED` is never set on `OUT6` / `IN4`;
//!   the loader verifies the created maps and refuses otherwise
//! - RFC 7739 §5.3 - `IDENT_KEY` and every per-CPU `IDENT` counter and step
//!   generator seeded from `getrandom` (generators never zero)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use plat_common::config::{Config, Partition};
use plat_xdp_core::abi::{ConfigRec, ROLE_ACCESS, ROLE_BOTH, ROLE_UPSTREAM};

/// Most interfaces in `[xdp]` (plan §4.5).
pub const MAX_INTERFACES: usize = 32;
/// `xdp.max_sessions` range floor.
pub const MIN_SESSIONS: u32 = 4096;

/// Attach mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Driver XDP.
    #[default]
    Native,
    /// SKB-mode XDP (testing only; needs `allow_generic`).
    Generic,
}

impl Mode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Generic => "generic",
        }
    }
}

/// Interface role (decision Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// IPv6 → IPv4 only.
    Access,
    /// IPv4 → IPv6 only.
    Upstream,
    Both,
}

impl Role {
    /// `ROLE_*` bits.
    pub const fn bits(self) -> u8 {
        match self {
            Self::Access => ROLE_ACCESS,
            Self::Upstream => ROLE_UPSTREAM,
            Self::Both => ROLE_BOTH,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Upstream => "upstream",
            Self::Both => "both",
        }
    }
}

/// One `[[xdp.interfaces]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdpInterface {
    pub name: String,
    pub role: Role,
}

/// `[xdp]` (plan §4.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdpSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub allow_generic: bool,
    #[serde(default = "d_sessions")]
    pub max_sessions: u32,
    #[serde(default = "d_heartbeat")]
    pub heartbeat_ms: u32,
    #[serde(default = "d_deadline")]
    pub deadline_ms: u32,
    #[serde(default)]
    pub interfaces: Vec<XdpInterface>,
}

fn d_sessions() -> u32 {
    1 << 20
}
fn d_heartbeat() -> u32 {
    250
}
fn d_deadline() -> u32 {
    1000
}

impl Default for XdpSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: Mode::Native,
            allow_generic: false,
            max_sessions: d_sessions(),
            heartbeat_ms: d_heartbeat(),
            deadline_ms: d_deadline(),
            interfaces: Vec::new(),
        }
    }
}

/// A rejected `[xdp]` section or configuration file.
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("xdp: {0}")]
    Invalid(String),
    #[error(transparent)]
    Config(#[from] plat_common::config::ConfigError),
    #[error("parsing config: {0}")]
    Toml(String),
}

fn invalid<T>(m: impl Into<String>) -> Result<T, SettingsError> {
    Err(SettingsError::Invalid(m.into()))
}

fn valid_ifname(n: &str) -> bool {
    (1..=15).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl XdpSettings {
    /// The plan §4.5 rules against the rest of the configuration.
    pub fn validate(&self, cfg: &Config) -> Result<(), SettingsError> {
        if !self.enabled {
            return Ok(());
        }
        if self.interfaces.is_empty() || self.interfaces.len() > MAX_INTERFACES {
            return invalid(format!("interfaces: 1..={MAX_INTERFACES} entries required"));
        }
        for (i, f) in self.interfaces.iter().enumerate() {
            if !valid_ifname(&f.name) {
                return invalid(format!("interfaces[{i}].name must be 1..=15 chars [A-Za-z0-9_.-]"));
            }
            if f.name == cfg.dataplane.interface {
                return invalid(format!("interfaces[{i}].name must not be the TUN (dataplane.interface)"));
            }
            if self.interfaces.iter().take(i).any(|g| g.name == f.name) {
                return invalid(format!("interfaces[{i}].name {} is listed twice", f.name));
            }
        }
        if self.mode == Mode::Generic && !self.allow_generic {
            return invalid("mode = \"generic\" needs allow_generic = true (testing only)");
        }
        let cap = u32::try_from(cfg.nat64.max_sessions).unwrap_or(u32::MAX);
        if self.max_sessions < MIN_SESSIONS || self.max_sessions > cap {
            return invalid(format!("max_sessions must be {MIN_SESSIONS}..=nat64.max_sessions ({cap})"));
        }
        if !(50..=1000).contains(&self.heartbeat_ms) {
            return invalid("heartbeat_ms must be 50..=1000");
        }
        if u64::from(self.deadline_ms) < 4 * u64::from(self.heartbeat_ms) {
            return invalid("deadline_ms must be >= 4 x heartbeat_ms");
        }
        if let Some(ha) = cfg.cluster.ha.as_ref().filter(|h| h.enabled) {
            let cap = ha.lease_ms.saturating_mul(100 - u64::from(ha.drift_margin_pct.min(100))) / 100;
            if u64::from(self.deadline_ms) > cap {
                return invalid(format!("deadline_ms must be <= lease_ms x (1 - drift_margin_pct/100) = {cap}"));
            }
        }
        Ok(())
    }
}

/// Splits a `platd` configuration file into the validated
/// `plat_common::Config` and the validated `[xdp]` section (default when
/// absent). Interim until WU5 moves `[xdp]` into `plat_common`.
pub fn split_config(text: &str) -> Result<(Config, XdpSettings), SettingsError> {
    let mut t: toml::Table = toml::from_str(text).map_err(|e| SettingsError::Toml(e.to_string()))?;
    let xdp = match t.remove("xdp") {
        Some(v) => v.try_into::<XdpSettings>().map_err(|e| SettingsError::Toml(format!("[xdp]: {e}")))?,
        None => XdpSettings::default(),
    };
    let rest = toml::to_string(&t).map_err(|e| SettingsError::Toml(e.to_string()))?;
    let cfg = Config::from_toml(&rest)?;
    xdp.validate(&cfg)?;
    Ok((cfg, xdp))
}

/// What the loader and `platd` derive from the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadParams {
    pub xdp: XdpSettings,
    /// `translation.ipv4_mtu`.
    pub mtu4: u16,
    /// `translation.ipv6_mtu`.
    pub mtu6: u16,
    /// `min(translation.lowest_ipv6_mtu, ipv6_mtu)`.
    pub frag6: u16,
    pub copy_tos: bool,
    /// `cluster.partition = "slices"`.
    pub sliced: bool,
    /// `translation.nat64_prefix` network (RFC 6052 §2.2), host order.
    pub prefix: u128,
    /// `translation.nat64_prefix` length (32, 40, 48, 56, 64 or 96).
    pub prefix_len: u8,
    /// `translation.allow_non_global_destinations` (SC-7).
    pub allow_non_global: bool,
}

impl LoadParams {
    pub fn new(cfg: &Config, xdp: XdpSettings) -> Self {
        let t = &cfg.translation;
        Self {
            xdp,
            mtu4: t.ipv4_mtu,
            mtu6: t.ipv6_mtu,
            frag6: t.lowest_ipv6_mtu.min(t.ipv6_mtu),
            copy_tos: t.copy_tos,
            sliced: cfg.cluster.partition == Partition::Slices,
            prefix: t.nat64_prefix.network(),
            prefix_len: t.nat64_prefix.prefix_len(),
            allow_non_global: t.allow_non_global_destinations,
        }
    }
}

/// Version tag of the digest input; bump on any change to [`digest`].
///
/// v2 (RFC-004): adds the RFC 6052 prefix, its length and
/// `allow_non_global_destinations`, so `platd` refuses pins set up for
/// another prefix or SC-7 policy.
const DIGEST_TAG: &[u8] = b"usg-plat xdp CONFIG v2\0";

/// The `CONFIG` digest over `object_sha256` and `p` (module docs).
pub fn digest(p: &LoadParams, object_sha256: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DIGEST_TAG);
    h.update(object_sha256);
    h.update(p.mtu4.to_le_bytes());
    h.update(p.mtu6.to_le_bytes());
    h.update(p.frag6.to_le_bytes());
    h.update([u8::from(p.copy_tos), u8::from(p.sliced)]);
    h.update(p.prefix.to_be_bytes());
    h.update([p.prefix_len, u8::from(p.allow_non_global)]);
    h.update(p.xdp.max_sessions.to_le_bytes());
    h.update([p.xdp.mode as u8]);
    h.update((p.xdp.interfaces.len() as u32).to_le_bytes());
    for f in &p.xdp.interfaces {
        h.update([f.name.len() as u8]);
        h.update(f.name.as_bytes());
        h.update([f.role.bits()]);
    }
    h.finalize().into()
}

/// The frozen `CONFIG` record for `p` and the given object.
pub fn config_record(p: &LoadParams, object_sha256: &[u8; 32]) -> ConfigRec {
    ConfigRec {
        mtu4: p.mtu4,
        mtu6: p.mtu6,
        frag6: p.frag6,
        copy_tos: u8::from(p.copy_tos),
        sliced: u8::from(p.sliced),
        digest: digest(p, object_sha256),
    }
}

/// The `IDENT` value for one CPU and index from 10 random bytes: a
/// non-zero xorshift state and a random counter (RFC 7739 §5.3).
pub fn ident_seed(r: &[u8; 10]) -> plat_xdp_core::abi::IdentEnt {
    let (s, c) = r.split_at(8);
    let mut rng = s.first_chunk::<8>().map_or(0, |b| u64::from_ne_bytes(*b));
    if rng == 0 {
        // Probability 2^-64; any fixed non-zero state keeps the step valid.
        rng = 0x9e37_79b9_7f4a_7c15;
    }
    let counter = c.first_chunk::<2>().map_or(0, |b| u16::from_ne_bytes(*b));
    plat_xdp_core::abi::IdentEnt { rng, counter, pad: [0; 6] }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;
    use std::fs;
    use std::io;
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use aya::maps::{Map, MapData};
    use aya::programs::links::{FdLink, PinnedLink};
    use aya::programs::xdp::XdpLink;
    use aya::programs::{Xdp, XdpMode};
    use aya::{Ebpf, EbpfLoader};
    use plat_io::bpf_obj::{self, Access, BPF_ANY, BPF_F_ZERO_SEED, BpfMap};
    use plat_xdp_core::abi::{EgressEnt, IFACE_SLOTS, IfaceEnt, iface_slot};
    use plat_xdp_core::ident::{IdentKey, TABLE};

    use super::{LoadParams, Mode, Role, config_record, ident_seed};
    use crate::maps::{LINK_PIN_PREFIX, MAPS, PROG_PIN, PinAccess, link_pin, slot_count};

    /// `statfs` magic of bpffs.
    const BPF_FS_MAGIC: u64 = 0xcafe_4a11;

    /// Why the loader refused or failed.
    #[derive(Debug, thiserror::Error)]
    pub enum LoadError {
        #[error("built without the eBPF object (enable the `xdp` feature; AYA_BUILD_SKIP builds cannot attach)")]
        NoObject,
        #[error("[xdp] is not enabled in the configuration")]
        Disabled,
        #[error(
            "kernel.unprivileged_bpf_disabled must be 1 or 2 (is {0}); unprivileged program load must be off (AC-6(10))"
        )]
        UnprivilegedBpf(String),
        #[error("{0} is not a bpffs mount (expected the dedicated run-plat-bpf.mount)")]
        NotBpffs(PathBuf),
        #[error("interface {0}: {1}")]
        Interface(String, io::Error),
        #[error("interfaces {0} and {1} share IFACES slot {2} (ifindex mod {IFACE_SLOTS})")]
        SlotCollision(String, String, u32),
        #[error("map {0}: BPF_F_ZERO_SEED is set; refusing (CLAUDE.md rule 3)")]
        ZeroSeed(&'static str),
        #[error("program {0}: multi-buffer XDP (section xdp.frags, BPF_F_XDP_HAS_FRAGS) is refused")]
        Frags(String),
        #[error("state directory {0}: {1}")]
        StateDir(PathBuf, &'static str),
        #[error("eBPF: {0}")]
        Ebpf(String),
        #[error("{0}: {1}")]
        Io(String, io::Error),
    }

    /// An Aya error with its whole source chain (Aya's `Display` omits
    /// the errno).
    fn ebpf<E: std::error::Error>(what: &str) -> impl FnOnce(E) -> LoadError + '_ {
        move |e| {
            let mut m = format!("{what}: {e}");
            let mut src = e.source();
            while let Some(s) = src {
                let _ = write!(m, ": {s}");
                src = s.source();
            }
            LoadError::Ebpf(m)
        }
    }

    fn io_err(what: impl Into<String>) -> impl FnOnce(io::Error) -> LoadError {
        let w = what.into();
        move |e| LoadError::Io(w, e)
    }

    /// One attached interface.
    #[derive(Debug, Clone)]
    pub struct AttachedIface {
        pub name: String,
        pub ifindex: u32,
        pub role: Role,
        /// The pinned link existed and its program was replaced atomically.
        pub replaced: bool,
    }

    /// What [`Loader::attach`] did.
    #[derive(Debug, Clone)]
    pub struct AttachReport {
        pub object_sha256: String,
        pub prog_id: u32,
        pub prog_tag: String,
        pub mode: Mode,
        pub interfaces: Vec<AttachedIface>,
    }

    impl AttachReport {
        /// The state file (`key=value` lines, for `plat-fwguard` and
        /// `status`).
        pub fn state_text(&self) -> String {
            let mut s = String::new();
            let _ = writeln!(s, "object_sha256={}", self.object_sha256);
            let _ = writeln!(s, "prog_id={}", self.prog_id);
            let _ = writeln!(s, "prog_tag={}", self.prog_tag);
            let _ = writeln!(s, "mode={}", self.mode.as_str());
            for i in &self.interfaces {
                let _ = writeln!(s, "interface={} {} {}", i.name, i.ifindex, i.role.as_str());
            }
            s
        }
    }

    /// The privileged loader (plan §7). Stateless: every call works on the
    /// pin directory.
    #[derive(Debug)]
    pub struct Loader;

    /// `kernel.unprivileged_bpf_disabled` must be 1 or 2.
    pub fn check_unprivileged_bpf() -> Result<(), LoadError> {
        let v = fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
            .map_err(io_err("/proc/sys/kernel/unprivileged_bpf_disabled"))?;
        match v.trim() {
            "1" | "2" => Ok(()),
            o => Err(LoadError::UnprivilegedBpf(o.into())),
        }
    }

    fn check_bpffs(dir: &Path) -> Result<(), LoadError> {
        let s = rustix::fs::statfs(dir).map_err(|e| LoadError::Io(dir.display().to_string(), e.into()))?;
        if u64::try_from(s.f_type).ok() != Some(BPF_FS_MAGIC) {
            return Err(LoadError::NotBpffs(dir.into()));
        }
        Ok(())
    }

    fn map_data(m: &Map) -> Option<&MapData> {
        match m {
            Map::Array(d) | Map::HashMap(d) | Map::PerCpuArray(d) | Map::DevMapHash(d) => Some(d),
            _ => None,
        }
    }

    /// A `plat_io` handle (duplicated descriptor) on a map of `e`.
    fn handle(e: &Ebpf, name: &'static str) -> Result<BpfMap, LoadError> {
        let d = e.map(name).and_then(map_data).ok_or_else(|| LoadError::Ebpf(format!("map {name} missing")))?;
        let fd = d.fd().as_fd().try_clone_to_owned().map_err(io_err(name))?;
        BpfMap::from_fd(fd, Access::ReadWrite).map_err(io_err(name))
    }

    fn random<const N: usize>() -> Result<[u8; N], LoadError> {
        let mut b = [0u8; N];
        let mut got = 0;
        while got < N {
            let rest = b.get_mut(got..).unwrap_or_default();
            got += rustix::rand::getrandom(rest, rustix::rand::GetRandomFlags::empty())
                .map_err(|e| LoadError::Io("getrandom".into(), e.into()))?;
        }
        Ok(b)
    }

    /// SEC-001: the program must not be loaded with `BPF_F_XDP_HAS_FRAGS`
    /// (Aya sets it for an `xdp.frags` section). Its frame length is
    /// `bpf_xdp_get_buff_len`, which equals `data_end - data` only for a
    /// linear buffer, and its parser reads only the linear part.
    pub fn check_no_frags(object: &[u8]) -> Result<(), LoadError> {
        let obj = aya_obj::Object::parse(object).map_err(|e| LoadError::Ebpf(format!("parsing the object: {e}")))?;
        if obj.programs.is_empty() {
            return Err(LoadError::Ebpf("the object has no program".into()));
        }
        for (name, prog) in &obj.programs {
            match prog.section {
                aya_obj::ProgramSection::Xdp { frags: false, .. } => {}
                aya_obj::ProgramSection::Xdp { frags: true, .. } => return Err(LoadError::Frags(name.clone())),
                _ => return Err(LoadError::Ebpf(format!("program {name} is not an XDP program"))),
            }
        }
        Ok(())
    }

    /// The directory of the state file, opened once (SEC-002).
    ///
    /// The loader runs as root and writes into `/run/plat`, a directory
    /// `platd` may share. Every operation goes through this descriptor:
    /// the directory must be owned by the loader's effective uid (root in
    /// production) and not group- or other-writable, so no other user can
    /// plant a symlink or file there; files are created with
    /// `O_CREAT | O_EXCL | O_NOFOLLOW` under a unique temporary name,
    /// `fchmod`ed, `fsync`ed and `renameat`ed; only the loader's own names
    /// (the state file and its temporary) are ever unlinked.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AC-6 (Least Privilege), SI-7 (Integrity) - a root
    ///   process never follows a link or writes a file another user could
    ///   have placed
    #[derive(Debug)]
    pub struct StateDir {
        dir: std::os::fd::OwnedFd,
        path: PathBuf,
        name: std::ffi::OsString,
    }

    impl StateDir {
        /// Opens the parent directory of `state_file` and checks it.
        pub fn open(state_file: &Path) -> Result<Self, LoadError> {
            use rustix::fs::{Mode as FsMode, OFlags};
            let name = state_file
                .file_name()
                .filter(|n| !n.is_empty() && *n != "." && *n != "..")
                .ok_or_else(|| LoadError::StateDir(state_file.into(), "no file name"))?
                .to_os_string();
            let path = match state_file.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            let dir = rustix::fs::open(
                &path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                FsMode::empty(),
            )
            .map_err(|e| LoadError::Io(path.display().to_string(), e.into()))?;
            let st = rustix::fs::fstat(&dir).map_err(|e| LoadError::Io(path.display().to_string(), e.into()))?;
            Self::check(&path, st.st_uid, st.st_mode, rustix::process::geteuid().as_raw())?;
            Ok(Self { dir, path, name })
        }

        /// The ownership and mode rule, separate for tests.
        pub(crate) fn check(path: &Path, uid: u32, mode: u32, euid: u32) -> Result<(), LoadError> {
            if uid != euid {
                return Err(LoadError::StateDir(path.into(), "not owned by the loader's user (root)"));
            }
            if mode & 0o022 != 0 {
                return Err(LoadError::StateDir(path.into(), "group- or other-writable"));
            }
            Ok(())
        }

        fn err(&self, e: rustix::io::Errno) -> LoadError {
            LoadError::Io(self.path.join(&self.name).display().to_string(), e.into())
        }

        /// Writes the state file atomically (mode 0644).
        pub fn write(&self, text: &str) -> Result<(), LoadError> {
            use rustix::fs::{Mode as FsMode, OFlags};
            let r: [u8; 8] = random()?;
            let mut tmp = std::ffi::OsString::from(".");
            tmp.push(&self.name);
            tmp.push(format!(".{}.{}.tmp", std::process::id(), hex::encode(r)));
            let fd = rustix::fs::openat(
                &self.dir,
                &tmp,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                FsMode::from_raw_mode(0o600),
            )
            .map_err(|e| self.err(e))?;
            let done = (|| {
                let mut rest = text.as_bytes();
                while !rest.is_empty() {
                    let n = rustix::io::write(&fd, rest)?;
                    rest = rest.get(n..).unwrap_or_default();
                }
                rustix::fs::fchmod(&fd, FsMode::from_raw_mode(0o644))?;
                rustix::fs::fsync(&fd)?;
                rustix::fs::renameat(&self.dir, &tmp, &self.dir, &self.name)?;
                rustix::fs::fsync(&self.dir)
            })();
            if let Err(e) = done {
                let _ = rustix::fs::unlinkat(&self.dir, &tmp, rustix::fs::AtFlags::empty());
                return Err(self.err(e));
            }
            Ok(())
        }

        /// Removes the state file (its own name only); `false` if absent.
        pub fn remove(&self) -> Result<bool, LoadError> {
            match rustix::fs::unlinkat(&self.dir, &self.name, rustix::fs::AtFlags::empty()) {
                Ok(()) => Ok(true),
                Err(rustix::io::Errno::NOENT) => Ok(false),
                Err(e) => Err(self.err(e)),
            }
        }

        /// Reads the state file without following a link; `None` if absent.
        pub fn read(&self) -> Result<Option<String>, LoadError> {
            use rustix::fs::{Mode as FsMode, OFlags};
            let fd = match rustix::fs::openat(
                &self.dir,
                &self.name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                FsMode::empty(),
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(e) => return Err(self.err(e)),
            };
            let mut t = String::new();
            io::Read::read_to_string(&mut fs::File::from(fd), &mut t)
                .map_err(io_err(self.path.join(&self.name).display().to_string()))?;
            Ok(Some(t))
        }
    }

    fn chmod(p: &Path, mode: u32) -> Result<(), LoadError> {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).map_err(io_err(p.display().to_string()))
    }

    fn remove_pin(p: &Path) -> Result<bool, LoadError> {
        match fs::remove_file(p) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(LoadError::Io(p.display().to_string(), e)),
        }
    }

    /// Resolved interface: name, ifindex, MAC, role.
    struct Iface {
        name: String,
        ifindex: u32,
        mac: [u8; 6],
        role: Role,
    }

    impl Loader {
        /// Creates fresh maps, seeds and freezes them, loads and pins the
        /// program, and attaches it to every `[xdp]` interface under `dir`
        /// (an existing pinned link is updated atomically, so traffic never
        /// sees a detached interface). Writes `state_file` when given.
        pub fn attach(p: &LoadParams, dir: &Path, state_file: Option<&Path>) -> Result<AttachReport, LoadError> {
            let object = crate::object();
            if object.is_empty() {
                return Err(LoadError::NoObject);
            }
            if !p.xdp.enabled {
                return Err(LoadError::Disabled);
            }
            check_unprivileged_bpf()?;
            check_bpffs(dir)?;
            check_no_frags(object)?;
            let state = state_file.map(StateDir::open).transpose()?;
            let ifaces = resolve(p)?;

            let sessions = p.xdp.max_sessions;
            let mut e = EbpfLoader::new()
                .map_max_entries("OUT6", sessions)
                .map_max_entries("IN4", sessions)
                .map_max_entries("SLOT", slot_count(sessions))
                .load(object)
                .map_err(ebpf("loading the object"))?;

            for name in ["OUT6", "IN4"] {
                let h = handle(&e, name)?;
                if h.info().map_flags & BPF_F_ZERO_SEED != 0 {
                    return Err(LoadError::ZeroSeed(name));
                }
            }
            seed(&e, p, &ifaces)?;

            let xdp: &mut Xdp = e
                .program_mut(crate::PROGRAM)
                .ok_or_else(|| LoadError::Ebpf("program plat_xdp missing".into()))?
                .try_into()
                .map_err(ebpf("program type"))?;
            xdp.load().map_err(ebpf("verifier"))?;
            let info = xdp.info().map_err(ebpf("program info"))?;

            // Fresh maps: drop the previous run's pins (a running program
            // keeps its own maps until its link is updated below).
            for m in MAPS {
                remove_pin(&dir.join(m.name))?;
            }
            remove_pin(&dir.join(PROG_PIN))?;
            let mut created = Vec::new();
            // Fail closed with nothing half-published: platd finds no pins
            // (maps_unavailable) and the new links are gone. A link that was
            // already replaced keeps the new program until the next attach
            // or detach. The previous state file is stale either way.
            let rollback = |created: Vec<PathBuf>| {
                for path in MAPS.iter().map(|m| dir.join(m.name)).chain([dir.join(PROG_PIN)]).chain(created) {
                    let _ = remove_pin(&path);
                }
                if let Some(s) = &state {
                    let _ = s.remove();
                }
            };
            let attached = match publish(&mut e, p, dir, &ifaces, &mut created) {
                Ok(a) => a,
                Err(err) => {
                    rollback(created);
                    return Err(err);
                }
            };

            let report = AttachReport {
                object_sha256: crate::object_sha256_hex(),
                prog_id: info.id(),
                prog_tag: format!("{:016x}", info.tag()),
                mode: p.xdp.mode,
                interfaces: attached,
            };
            // QA F2: an attach whose state file cannot be written is rolled
            // back, so a failed unit never leaves the fast path live.
            if let Some(s) = &state
                && let Err(err) = s.write(&report.state_text())
            {
                rollback(created);
                return Err(err);
            }
            Ok(report)
        }

        /// Detaches (unpins every link) and removes every pin under `dir`
        /// and the state file. Returns the removed pin names.
        pub fn detach(dir: &Path, state_file: Option<&Path>) -> Result<Vec<String>, LoadError> {
            let state = state_file.map(StateDir::open).transpose()?;
            let mut gone = Vec::new();
            for l in link_pins(dir)? {
                if remove_pin(&dir.join(&l))? {
                    gone.push(l);
                }
            }
            for n in MAPS.iter().map(|m| m.name).chain([PROG_PIN]) {
                if remove_pin(&dir.join(n))? {
                    gone.push(n.to_string());
                }
            }
            if let Some(s) = &state {
                s.remove()?;
            }
            Ok(gone)
        }

        /// Pins present under `dir` and the state file's content.
        pub fn status(dir: &Path, state_file: Option<&Path>) -> Result<String, LoadError> {
            let mut s = String::new();
            for n in MAPS.iter().filter(|m| m.access != PinAccess::Unpinned).map(|m| m.name).chain([PROG_PIN]) {
                let present = dir.join(n).exists();
                let _ = writeln!(s, "pin {n} {}", if present { "present" } else { "absent" });
            }
            for l in link_pins(dir)? {
                let _ = writeln!(s, "pin {l} present");
            }
            if let Some(sf) = state_file {
                match StateDir::open(sf)?.read()? {
                    Some(t) => s.push_str(&t),
                    None => s.push_str("state absent\n"),
                }
            }
            Ok(s)
        }
    }

    /// Pins maps and program, then attaches (or atomically replaces) the
    /// link of every interface; records each newly created link pin in
    /// `created` for the caller's rollback.
    fn publish(
        e: &mut Ebpf,
        p: &LoadParams,
        dir: &Path,
        ifaces: &[Iface],
        created: &mut Vec<PathBuf>,
    ) -> Result<Vec<AttachedIface>, LoadError> {
        for m in MAPS {
            let Some(mode) = m.access.mode() else { continue };
            let path = dir.join(m.name);
            let map = e.map(m.name).ok_or_else(|| LoadError::Ebpf(format!("map {} missing", m.name)))?;
            map.pin(&path).map_err(ebpf(m.name))?;
            chmod(&path, mode)?;
        }
        let xdp: &mut Xdp = e
            .program_mut(crate::PROGRAM)
            .ok_or_else(|| LoadError::Ebpf("program plat_xdp missing".into()))?
            .try_into()
            .map_err(ebpf("program type"))?;
        let prog = dir.join(PROG_PIN);
        xdp.pin(&prog).map_err(ebpf("pin program"))?;
        chmod(&prog, 0o600)?;

        let mode = match p.xdp.mode {
            Mode::Native => XdpMode::Driver,
            Mode::Generic => XdpMode::Skb,
        };
        let mut attached = Vec::new();
        for f in ifaces {
            let lp = dir.join(link_pin(f.ifindex));
            let replaced = lp.exists();
            let id = if replaced {
                let old = PinnedLink::from_pin(&lp).map_err(ebpf("open pinned link"))?;
                let old = XdpLink::try_from(FdLink::from(old)).map_err(ebpf("pinned link"))?;
                xdp.attach_to_link(old).map_err(ebpf("replace program"))?
            } else {
                xdp.attach(f.ifindex, mode).map_err(ebpf(&f.name))?
            };
            let link = xdp.take_link(id).map_err(ebpf("link"))?;
            let link = FdLink::try_from(link).map_err(ebpf("bpf_link (kernel 5.9+)"))?;
            if replaced {
                remove_pin(&lp)?;
            } else {
                created.push(lp.clone());
            }
            link.pin(&lp).map_err(ebpf("pin link"))?;
            chmod(&lp, 0o600)?;
            attached.push(AttachedIface { name: f.name.clone(), ifindex: f.ifindex, role: f.role, replaced });
        }
        // Links of interfaces no longer configured: unpinning detaches.
        for stale in link_pins(dir)? {
            if !ifaces.iter().any(|f| link_pin(f.ifindex) == stale) {
                remove_pin(&dir.join(&stale))?;
            }
        }
        Ok(attached)
    }

    fn link_pins(dir: &Path) -> Result<Vec<String>, LoadError> {
        let mut v = Vec::new();
        let rd = match fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(v),
            Err(e) => return Err(LoadError::Io(dir.display().to_string(), e)),
        };
        for ent in rd {
            let n = ent.map_err(io_err(dir.display().to_string()))?.file_name();
            if let Some(n) = n.to_str().filter(|n| n.starts_with(LINK_PIN_PREFIX)) {
                v.push(n.to_string());
            }
        }
        v.sort();
        Ok(v)
    }

    fn resolve(p: &LoadParams) -> Result<Vec<Iface>, LoadError> {
        let mut v: Vec<Iface> = Vec::new();
        let mut slots = BTreeMap::new();
        for f in &p.xdp.interfaces {
            let ifindex = plat_io::netdev::index(&f.name).map_err(|e| LoadError::Interface(f.name.clone(), e))?;
            let mac = plat_io::netdev::hw_addr(&f.name).map_err(|e| LoadError::Interface(f.name.clone(), e))?;
            if let Some(other) = slots.insert(iface_slot(ifindex), f.name.clone()) {
                return Err(LoadError::SlotCollision(other, f.name.clone(), iface_slot(ifindex)));
            }
            v.push(Iface { name: f.name.clone(), ifindex, mac, role: f.role });
        }
        Ok(v)
    }

    /// Writes and freezes `CONFIG` and `IDENT_KEY`, seeds `IDENT` for every
    /// CPU, and fills `IFACES`, `EGRESS` and `TX`.
    fn seed(e: &Ebpf, p: &LoadParams, ifaces: &[Iface]) -> Result<(), LoadError> {
        let zero = 0u32.to_ne_bytes();
        let config = handle(e, "CONFIG")?;
        let rec = config_record(p, &crate::object_sha256());
        config.update(&zero, &rec.to_bytes(), BPF_ANY).map_err(io_err("CONFIG"))?;
        bpf_obj::map_freeze(config.as_fd()).map_err(io_err("freeze CONFIG"))?;

        let key = handle(e, "IDENT_KEY")?;
        let r: [u8; 16] = random()?;
        let (a, b) = r.split_at(8);
        let k = IdentKey::new(
            a.first_chunk::<8>().map_or(0, |c| u64::from_ne_bytes(*c)),
            b.first_chunk::<8>().map_or(0, |c| u64::from_ne_bytes(*c)),
        );
        key.update(&zero, &k.to_bytes(), BPF_ANY).map_err(io_err("IDENT_KEY"))?;
        bpf_obj::map_freeze(key.as_fd()).map_err(io_err("freeze IDENT_KEY"))?;

        let ident = handle(e, "IDENT")?;
        let cpus = ident.value_len() / 16;
        let mut v = vec![0u8; ident.value_len()];
        for idx in 0..TABLE {
            for c in v.as_chunks_mut::<16>().0.iter_mut().take(cpus) {
                *c = ident_seed(&random::<10>()?).to_bytes();
            }
            ident.update(&idx.to_ne_bytes(), &v, BPF_ANY).map_err(io_err("IDENT"))?;
        }

        let ifm = handle(e, "IFACES")?;
        let eg = handle(e, "EGRESS")?;
        let tx = handle(e, "TX")?;
        for f in ifaces {
            let slot = iface_slot(f.ifindex).to_ne_bytes();
            let role = f.role.bits();
            ifm.update(&slot, &IfaceEnt { ifindex: f.ifindex, mac: f.mac, role, pad: 0 }.to_bytes(), BPF_ANY)
                .map_err(io_err("IFACES"))?;
            // An interface's role is also the direction whose output may
            // leave by it (upstream: IPv4 from v6->v4; access: IPv6).
            eg.update(&slot, &EgressEnt { ifindex: f.ifindex, allowed: 1, role, pad: [0; 2] }.to_bytes(), BPF_ANY)
                .map_err(io_err("EGRESS"))?;
            tx.update(&f.ifindex.to_ne_bytes(), &devmap_val(tx.info().value_size, f.ifindex), BPF_ANY)
                .map_err(io_err("TX"))?;
        }
        Ok(())
    }

    /// A `DEVMAP_HASH` value: `ifindex` alone (4 B) or `struct
    /// bpf_devmap_val` (8 B, no chained program).
    fn devmap_val(size: u32, ifindex: u32) -> Vec<u8> {
        let mut v = vec![0u8; size as usize];
        if let Some(d) = v.first_chunk_mut::<4>() {
            *d = ifindex.to_ne_bytes();
        }
        v
    }
}

#[cfg(all(test, target_os = "linux"))]
mod state_tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    use super::{LoadError, StateDir};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("plat-xdp-state-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir(&d).unwrap_or_else(|e| panic!("{e}"));
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap_or_else(|e| panic!("{e}"));
        d
    }

    #[test]
    fn writes_atomically_with_mode_0644_and_removes_only_its_name() {
        let d = tmpdir("write");
        let sf = d.join("xdp.state");
        let s = StateDir::open(&sf).unwrap_or_else(|e| panic!("{e}"));
        s.write("a=1\n").unwrap_or_else(|e| panic!("{e}"));
        s.write("a=2\n").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(fs::read_to_string(&sf).ok().as_deref(), Some("a=2\n"));
        let m = fs::metadata(&sf).map(|m| m.permissions().mode() & 0o7777).unwrap_or(0);
        assert_eq!(m, 0o644);
        // No temporary is left behind.
        assert_eq!(fs::read_dir(&d).map(Iterator::count).unwrap_or(0), 1);
        fs::write(d.join("other"), "x").unwrap_or_else(|e| panic!("{e}"));
        assert!(s.remove().unwrap_or_else(|e| panic!("{e}")));
        assert!(!s.remove().unwrap_or_else(|e| panic!("{e}")));
        assert!(d.join("other").exists(), "only the state file's own name is unlinked");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_planted_symlink_is_replaced_not_followed() {
        let d = tmpdir("link");
        let victim = d.join("victim");
        fs::write(&victim, "keep").unwrap_or_else(|e| panic!("{e}"));
        let sf = d.join("xdp.state");
        symlink(&victim, &sf).unwrap_or_else(|e| panic!("{e}"));
        let s = StateDir::open(&sf).unwrap_or_else(|e| panic!("{e}"));
        assert!(s.read().is_err(), "read follows no link (O_NOFOLLOW)");
        s.write("a=1\n").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(fs::read_to_string(&victim).ok().as_deref(), Some("keep"));
        assert!(!fs::symlink_metadata(&sf).map(|m| m.file_type().is_symlink()).unwrap_or(true));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn refuses_writable_or_foreign_or_linked_directories() {
        let d = tmpdir("mode");
        for mode in [0o775, 0o757, 0o777] {
            fs::set_permissions(&d, fs::Permissions::from_mode(mode)).unwrap_or_else(|e| panic!("{e}"));
            assert!(
                matches!(StateDir::open(&d.join("xdp.state")), Err(LoadError::StateDir(..))),
                "mode {mode:o} accepted"
            );
        }
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap_or_else(|e| panic!("{e}"));
        let euid = rustix::process::geteuid().as_raw();
        assert!(StateDir::check(&d, euid, 0o40755, euid).is_ok());
        assert!(matches!(StateDir::check(&d, euid + 1, 0o40755, euid), Err(LoadError::StateDir(..))));
        // The directory itself must not be a symlink.
        let l = d.with_extension("lnk");
        let _ = fs::remove_file(&l);
        symlink(&d, &l).unwrap_or_else(|e| panic!("{e}"));
        assert!(StateDir::open(&l.join("xdp.state")).is_err());
        let _ = fs::remove_file(&l);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn the_embedded_object_has_no_frags_section() {
        let o = crate::object();
        if !o.is_empty() {
            super::check_no_frags(o).unwrap_or_else(|e| panic!("{e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = include_str!("../../../config/platd.example.toml");

    fn xdp(extra: &str) -> String {
        format!(
            "{BASE}\n[xdp]\nenabled = true\nmax_sessions = 4096\n{extra}\n[[xdp.interfaces]]\nname = \"eth0\"\nrole = \"access\"\n[[xdp.interfaces]]\nname = \"eth1\"\nrole = \"upstream\"\n"
        )
    }

    #[test]
    fn absent_section_is_off() {
        let (_c, x) = split_config(BASE).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(x, XdpSettings::default());
        assert!(!x.enabled);
    }

    #[test]
    fn section_parses_and_validates() {
        let (c, x) = split_config(&xdp("")).unwrap_or_else(|e| panic!("{e}"));
        assert!(x.enabled);
        assert_eq!(x.interfaces.len(), 2);
        assert_eq!(x.interfaces[1].role, Role::Upstream);
        let p = LoadParams::new(&c, x);
        assert_eq!((p.mtu4, p.mtu6, p.frag6, p.sliced), (1500, 1500, 1280, false));
    }

    #[test]
    fn rejections() {
        for extra in
            ["mode = \"generic\"", "heartbeat_ms = 10", "deadline_ms = 100", "max_sessions_typo = 1", "mode = \"hw\""]
        {
            assert!(split_config(&xdp(extra)).is_err(), "accepted {extra}");
        }
        assert!(split_config(&xdp("mode = \"generic\"\nallow_generic = true")).is_ok());
        let dup = format!("{}[[xdp.interfaces]]\nname = \"eth0\"\nrole = \"both\"\n", xdp(""));
        assert!(split_config(&dup).is_err());
        let tun = xdp("").replace("name = \"eth1\"", "name = \"plat0\"");
        assert!(split_config(&tun).is_err());
        let bad = xdp("").replace("name = \"eth1\"", "name = \"eth/1\"");
        assert!(split_config(&bad).is_err());
        let few = xdp("").replace("max_sessions = 4096", "max_sessions = 4095");
        assert!(split_config(&few).is_err());
        let none = format!("{BASE}\n[xdp]\nenabled = true\n");
        assert!(split_config(&none).is_err());
    }

    #[test]
    fn digest_binds_object_and_parameters() {
        let (c, x) = split_config(&xdp("")).unwrap_or_else(|e| panic!("{e}"));
        let p = LoadParams::new(&c, x);
        let a = config_record(&p, &[1; 32]);
        assert_eq!(a, config_record(&p, &[1; 32]));
        assert_ne!(a.digest, config_record(&p, &[2; 32]).digest, "object change");
        let mut q = p.clone();
        q.mtu4 = 1400;
        assert_ne!(a.digest, config_record(&q, &[1; 32]).digest);
        let mut q = p.clone();
        q.xdp.interfaces[0].role = Role::Both;
        assert_ne!(a.digest, config_record(&q, &[1; 32]).digest);
        let mut q = p.clone();
        q.xdp.max_sessions += 1;
        assert_ne!(a.digest, config_record(&q, &[1; 32]).digest);
        // RFC-004: the RFC 6052 prefix, its length and the SC-7 non-global
        // policy are bound too.
        let mut q = p.clone();
        q.prefix ^= 1 << 100;
        assert_ne!(a.digest, config_record(&q, &[1; 32]).digest, "prefix");
        let mut q = p.clone();
        q.prefix_len = if q.prefix_len == 96 { 64 } else { 96 };
        assert_ne!(a.digest, config_record(&q, &[1; 32]).digest, "prefix length");
        let mut q = p.clone();
        q.allow_non_global = !q.allow_non_global;
        assert_ne!(a.digest, config_record(&q, &[1; 32]).digest, "allow_non_global_destinations");
        assert_eq!(
            (p.prefix, p.prefix_len),
            (c.translation.nat64_prefix.network(), c.translation.nat64_prefix.prefix_len())
        );
        assert_eq!((a.mtu4, a.copy_tos, a.sliced), (c.translation.ipv4_mtu, u8::from(c.translation.copy_tos), 0));
    }

    #[test]
    fn ident_seeds_never_zero() {
        assert_ne!(ident_seed(&[0; 10]).rng, 0);
        let e = ident_seed(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(e.rng, u64::from_ne_bytes([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(e.counter, u16::from_ne_bytes([9, 10]));
    }

    #[test]
    fn roles() {
        assert_eq!(Role::Access.bits(), ROLE_ACCESS);
        assert_eq!(Role::Upstream.bits(), ROLE_UPSTREAM);
        assert_eq!(Role::Both.bits(), ROLE_BOTH);
    }
}
