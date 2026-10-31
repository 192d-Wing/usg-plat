//! Memory sizing: the memory a configuration needs, and the limits the host
//! imposes (cgroup v2 `memory.max`, physical RAM).
//!
//! `platd check-config` prints [`required_bytes`]; `platd run` refuses to
//! start when it exceeds the cgroup limit or 90 % of RAM ([`check`]). An OOM
//! kill under a session flood would drop every mapping of the node with no
//! release records (POAM-009), so a configuration that cannot fit is refused
//! at start instead of failing later under load.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - the configured
//!   table limits are checked against the memory actually available, so the
//!   limits hold before the kernel OOM killer would act (POAM-021).
//! - NIST 800-53: CP-10 (System Recovery and Reconstitution) - a node that
//!   would be OOM-killed and restart-loop under load fails its start instead,
//!   with a clear error.

use std::path::Path;

use crate::Config;

/// Bytes per configured session (BIB, session and subscriber share). Measured
/// on Linux (L9): about 780 B at 3.9 M sessions, so 800 B is conservative.
pub const SESSION_BYTES: u64 = 800;
/// Bytes per audit queue slot (record hand-off, upper bound).
pub const AUDIT_SLOT_BYTES: u64 = 64;
/// Bytes per replication ring slot (`plat_nat64::repl::REPL_SLOT_BYTES`).
pub const REPL_SLOT_BYTES: u64 = 64;
/// Fixed headroom: binary, thread stacks, TLS, logger buffers, allocator slack.
pub const HEADROOM_BYTES: u64 = 256 << 20;
/// Bytes per table shard header (a cache-line-padded mutex, map header and
/// due hint; 128 B on aarch64/x86_64 with `CachePadded`).
pub const SHARD_HEADER_BYTES: u64 = 128;
/// `bib4` shard multiplier and cap (`plat_nat64::state::BIB4_SHARD_FACTOR`,
/// `BIB4_MAX_SHARDS`): at the 65536 cap the `bib4` headers alone take 8 MiB.
pub const BIB4_SHARD_FACTOR: u64 = 16;
/// See [`BIB4_SHARD_FACTOR`].
pub const BIB4_MAX_SHARDS: u64 = 1 << 16;
/// Share of physical RAM the requirement may use, in percent.
pub const RAM_PERCENT: u64 = 90;

/// Workers `platd run` starts: `dataplane.workers`, or one per CPU minus one
/// (at least one) when 0.
pub fn worker_count(cfg: &Config) -> usize {
    match cfg.dataplane.workers {
        0 => std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1).max(1)),
        n => n,
    }
}

/// Memory the configuration needs with `workers` workers, in bytes:
///
/// `max_sessions × 800 + queue_capacity × 64
///  + workers × fragment memory per worker
///  + (workers + 1) × repl_ring_entries × 64 (HA only)
///  + held-SYN worst case (`Nat64Config::held_syn_memory`)
///  + shard headers + 256 MiB`,
///
/// where the shard headers are 128 B × (4 × `table_shards` for `bib6`,
/// `subs`, `aggs` and the cluster directory, + min(16 × `table_shards`, 65536) for
/// `bib4`), each count rounded up to a power of two (PERF-1, POAM-012).
///
/// Every term is an upper bound on preallocated or table memory; the sum
/// saturates instead of overflowing.
pub fn required_bytes(cfg: &Config, workers: usize) -> u64 {
    let w = workers as u64;
    let ring = cfg.cluster.ha_active().map_or(0, |h| {
        (w + 1).saturating_mul(u64::from(h.repl_ring_entries).next_power_of_two()).saturating_mul(REPL_SLOT_BYTES)
    });
    cfg.nat64
        .max_sessions
        .saturating_mul(SESSION_BYTES)
        .saturating_add((cfg.audit.queue_capacity as u64).saturating_mul(AUDIT_SLOT_BYTES))
        .saturating_add(w.saturating_mul(cfg.translation.fragments.memory_per_worker()))
        .saturating_add(ring)
        .saturating_add(cfg.nat64.held_syn_memory())
        .saturating_add(shard_header_bytes(cfg.nat64.table_shards))
        .saturating_add(HEADROOM_BYTES)
}

/// Shard header memory of the NAT64 tables for `table_shards`.
pub fn shard_header_bytes(table_shards: u32) -> u64 {
    let base = u64::from(table_shards.max(1)).next_power_of_two();
    let bib4 = base.saturating_mul(BIB4_SHARD_FACTOR).min(BIB4_MAX_SHARDS);
    base.saturating_mul(4).saturating_add(bib4).saturating_mul(SHARD_HEADER_BYTES)
}

/// The cgroup v2 path from `/proc/self/cgroup` (the `0::<path>` line), or
/// `None` on a cgroup v1-only host.
pub fn parse_proc_cgroup(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("0::")).map(str::trim).filter(|p| p.starts_with('/'))
}

/// A `memory.max` value: `Ok(None)` for `max` (unlimited).
pub fn parse_memory_max(text: &str) -> Result<Option<u64>, String> {
    match text.trim() {
        "max" => Ok(None),
        v => v.parse().map(Some).map_err(|_| format!("unparsable memory.max value {v:?}")),
    }
}

/// `MemTotal` in bytes from `/proc/meminfo`, or the sum of the per-node
/// `Node <n> MemTotal:` lines from `/sys/devices/system/node/node*/meminfo`.
pub fn parse_mem_total(text: &str) -> Option<u64> {
    let mut total: Option<u64> = None;
    for l in text.lines() {
        let Some((_, rest)) = l.split_once("MemTotal:") else { continue };
        let mut it = rest.split_whitespace();
        let kb: u64 = it.next()?.parse().ok()?;
        if it.next() != Some("kB") {
            return None;
        }
        total = Some(total.unwrap_or(0).saturating_add(kb.saturating_mul(1024)));
    }
    total
}

/// The last `MemoryMax=` in a systemd unit or drop-in: `Ok(None)` when absent
/// or `infinity`; percentages are not resolved (`Ok(None)`).
pub fn parse_unit_memory_max(text: &str) -> Result<Option<u64>, String> {
    let Some(v) = text.lines().filter_map(|l| l.trim().strip_prefix("MemoryMax=")).next_back() else {
        return Ok(None);
    };
    let v = v.trim();
    if v.is_empty() || v == "infinity" || v.ends_with('%') {
        return Ok(None);
    }
    let (num, shift) = match v.as_bytes()[v.len() - 1] {
        b'K' => (&v[..v.len() - 1], 10),
        b'M' => (&v[..v.len() - 1], 20),
        b'G' => (&v[..v.len() - 1], 30),
        b'T' => (&v[..v.len() - 1], 40),
        _ => (v, 0),
    };
    num.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(1 << shift))
        .map(Some)
        .ok_or_else(|| format!("unparsable MemoryMax value {v:?}"))
}

/// Host memory limits; `None` means unknown or unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostLimits {
    /// Smallest `memory.max` of this process's cgroup and its ancestors.
    pub cgroup_max: Option<u64>,
    /// Physical RAM.
    pub ram: Option<u64>,
}

impl HostLimits {
    /// Reads the limits under the given roots (`/proc`, `/sys/fs/cgroup`,
    /// `/sys/devices/system/node` in production; test directories in tests).
    /// `/proc/meminfo` is hidden by the unit's `ProcSubset=pid`, so RAM falls
    /// back to the per-NUMA-node `meminfo` files in sysfs.
    pub fn read(proc_root: &Path, cgroup_root: &Path, node_root: &Path) -> Result<Self, String> {
        let mut cgroup_max = None;
        if let Some(path) =
            std::fs::read_to_string(proc_root.join("self/cgroup")).ok().as_deref().and_then(parse_proc_cgroup)
        {
            // SEC-003: the path comes from the kernel, but a ".." would walk
            // out of the cgroup root; fail closed instead.
            let mut parts: Vec<&str> = path.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
            if parts.contains(&"..") {
                return Err(format!("/proc/self/cgroup path {path:?} contains \"..\": refusing to start"));
            }
            // Walk from this cgroup up to and including the root. On the host
            // root has no memory.max; inside a cgroup namespace ("0::/") the
            // namespace root is the container's own cgroup and carries its
            // limit (SEC-001). A level without the file has no memory
            // controller.
            loop {
                let file = cgroup_root.join(parts.join("/")).join("memory.max");
                if let Ok(t) = std::fs::read_to_string(&file)
                    && let Some(v) = parse_memory_max(&t).map_err(|e| format!("{}: {e}", file.display()))?
                {
                    cgroup_max = Some(cgroup_max.map_or(v, |c: u64| c.min(v)));
                }
                if parts.pop().is_none() {
                    break;
                }
            }
        }
        let ram = std::fs::read_to_string(proc_root.join("meminfo")).ok().as_deref().and_then(parse_mem_total).or_else(
            || {
                let mut text = String::new();
                for e in std::fs::read_dir(node_root).ok()?.flatten() {
                    if e.file_name().to_string_lossy().starts_with("node") {
                        text.push_str(&std::fs::read_to_string(e.path().join("meminfo")).ok()?);
                    }
                }
                parse_mem_total(&text)
            },
        );
        Ok(Self { cgroup_max, ram })
    }
}

/// Refuses a requirement above the cgroup limit or [`RAM_PERCENT`] of RAM.
/// Fails closed when RAM cannot be determined; no cgroup v2 limit is not an
/// error (the RAM check still applies).
pub fn check(required: u64, limits: HostLimits) -> Result<(), String> {
    let hint = "lower nat64.max_sessions / audit.queue_capacity / [translation.fragments] / \
                dataplane.workers, or raise MemoryMax (POAM-021)";
    if let Some(max) = limits.cgroup_max
        && required > max
    {
        return Err(format!(
            "the configuration needs {required} B of memory but the cgroup memory.max is {max} B: {hint}"
        ));
    }
    let Some(ram) = limits.ram else {
        return Err(
            "cannot determine physical memory (/proc/meminfo, /sys/devices/system/node): refusing to start".into()
        );
    };
    let cap = u64::try_from(u128::from(ram) * u128::from(RAM_PERCENT) / 100).unwrap_or(u64::MAX);
    if required > cap {
        return Err(format!(
            "the configuration needs {required} B of memory, above {RAM_PERCENT} % of RAM ({cap} of {ram} B): {hint}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HaConfig;

    const EXAMPLE: &str = include_str!("../../../config/platd.example.toml");

    /// A fresh scratch directory under the system temp dir.
    fn scratch() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "plat-memory-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn formula_matches_documented_terms() {
        let mut c = Config::from_toml(EXAMPLE).unwrap();
        c.cluster.ha = None;
        let frag = c.translation.fragments.memory_per_worker();
        let hdr = shard_header_bytes(c.nat64.table_shards);
        assert_eq!(shard_header_bytes(1024), (4 * 1024 + 16 * 1024) * 128);
        assert_eq!(shard_header_bytes(65536), (4 * 65536 + 65536) * 128);
        // Held SYNs (defaults, ICMP off): 16384 x (8 x 32 + 16).
        let held = 16_384 * (8 * 32 + 16);
        assert_eq!(c.nat64.held_syn_memory(), held);
        let base = 4_000_000 * 800 + 1_048_576 * 64 + held + hdr + (256 << 20);
        assert_eq!(required_bytes(&c, 4), base + 4 * frag);
        assert_eq!(required_bytes(&c, 1), base + frag);
        c.nat64.max_sessions = u64::MAX;
        assert_eq!(required_bytes(&c, 4), u64::MAX);
    }

    #[test]
    fn formula_adds_ring_memory_with_ha() {
        let mut c = Config::from_toml(EXAMPLE).unwrap();
        let mut ha: HaConfig = toml::from_str(
            "enabled = true\nlisten = \"192.0.2.1:7000\"\nrepl_ring_entries = 65536\n\
             [tls]\ncert_file = \"/c\"\nkey_file = \"/k\"\nca_file = \"/a\"\n",
        )
        .unwrap();
        c.cluster.ha = Some(ha.clone());
        let mut no_ha = c.clone();
        no_ha.cluster.ha = None;
        ha.enabled = false;
        let mut off = c.clone();
        off.cluster.ha = Some(ha);
        assert_eq!(required_bytes(&off, 3), required_bytes(&no_ha, 3));
        assert_eq!(required_bytes(&c, 3) - required_bytes(&no_ha, 3), 4 * 65536 * 64);
    }

    #[test]
    fn cgroup_and_meminfo_parsing() {
        assert_eq!(parse_proc_cgroup("0::/system.slice/platd.service\n"), Some("/system.slice/platd.service"));
        assert_eq!(parse_proc_cgroup("12:memory:/foo\n1:name=systemd:/foo\n"), None);
        assert_eq!(parse_memory_max("max\n"), Ok(None));
        assert_eq!(parse_memory_max("8589934592\n"), Ok(Some(8 << 30)));
        assert!(parse_memory_max("8G").is_err());
        assert_eq!(parse_mem_total("MemTotal:       16384 kB\nMemFree: 1 kB\n"), Some(16384 * 1024));
        assert_eq!(parse_mem_total("Node 0 MemTotal: 1024 kB\nNode 1 MemTotal: 1024 kB\n"), Some(2 << 20));
        assert_eq!(parse_mem_total("MemFree: 1 kB\n"), None);
        assert_eq!(parse_unit_memory_max("MemoryMax=8G\n"), Ok(Some(8 << 30)));
        assert_eq!(parse_unit_memory_max("MemoryMax=8G\nMemoryMax=512M\n"), Ok(Some(512 << 20)));
        assert_eq!(parse_unit_memory_max("MemoryMax=infinity\n"), Ok(None));
        assert_eq!(parse_unit_memory_max("TasksMax=1\n"), Ok(None));
        assert!(parse_unit_memory_max("MemoryMax=lots\n").is_err());
    }

    fn tree(cgroup: Option<&str>, levels: &[(&str, &str)], meminfo: Option<&str>, node: Option<&str>) -> HostLimits {
        let d = scratch();
        let (p, cg, n) = (d.join("proc"), d.join("cg"), d.join("node"));
        std::fs::create_dir_all(p.join("self")).unwrap();
        if let Some(c) = cgroup {
            std::fs::write(p.join("self/cgroup"), c).unwrap();
        }
        for (dir, v) in levels {
            std::fs::create_dir_all(cg.join(dir)).unwrap();
            std::fs::write(cg.join(dir).join("memory.max"), v).unwrap();
        }
        if let Some(m) = meminfo {
            std::fs::write(p.join("meminfo"), m).unwrap();
        }
        if let Some(m) = node {
            std::fs::create_dir_all(n.join("node0")).unwrap();
            std::fs::write(n.join("node0/meminfo"), m).unwrap();
        }
        HostLimits::read(&p, &cg, &n).unwrap()
    }

    #[test]
    fn host_limits_from_files() {
        let gib = 1u64 << 30;
        // Unit limit below an unlimited slice; the smallest level wins.
        let l = tree(
            Some("0::/system.slice/platd.service\n"),
            &[("system.slice", "max\n"), ("system.slice/platd.service", "8589934592\n")],
            Some("MemTotal: 16777216 kB\n"),
            None,
        );
        assert_eq!(l, HostLimits { cgroup_max: Some(8 * gib), ram: Some(16 * gib) });
        let l =
            tree(Some("0::/a/b\n"), &[("a", "1073741824\n"), ("a/b", "max\n")], Some("MemTotal: 16777216 kB\n"), None);
        assert_eq!(l.cgroup_max, Some(gib));
        // Missing /proc/self/cgroup and memory.max: no limit, not an error;
        // /proc/meminfo hidden: RAM from sysfs.
        let l = tree(None, &[], None, Some("Node 0 MemTotal: 2097152 kB\n"));
        assert_eq!(l, HostLimits { cgroup_max: None, ram: Some(2 * gib) });
        // Cgroup namespace: the path is "/" and the limit is on the
        // namespace root (SEC-001); a root limit also caps a leaf.
        let l = tree(Some("0::/\n"), &[("", "1073741824\n")], Some("MemTotal: 16777216 kB\n"), None);
        assert_eq!(l.cgroup_max, Some(gib));
        let l = tree(Some("0::/a\n"), &[("", "1073741824\n"), ("a", "max\n")], Some("MemTotal: 1 kB\n"), None);
        assert_eq!(l.cgroup_max, Some(gib));
        let l = tree(Some("0::/x\n"), &[], None, None);
        assert_eq!(l, HostLimits { cgroup_max: None, ram: None });
    }

    #[test]
    fn unparsable_memory_max_is_an_error() {
        let d = scratch();
        std::fs::create_dir_all(d.join("proc/self")).unwrap();
        std::fs::write(d.join("proc/self/cgroup"), "0::/x\n").unwrap();
        std::fs::create_dir_all(d.join("cg/x")).unwrap();
        std::fs::write(d.join("cg/x/memory.max"), "garbage\n").unwrap();
        assert!(HostLimits::read(&d.join("proc"), &d.join("cg"), &d).is_err());
    }

    #[test]
    fn dotdot_in_cgroup_path_fails_closed() {
        for p in ["0::/a/../b\n", "0::/..\n", "0::/a/..\n"] {
            let d = scratch();
            std::fs::create_dir_all(d.join("proc/self")).unwrap();
            std::fs::write(d.join("proc/self/cgroup"), p).unwrap();
            let e = HostLimits::read(&d.join("proc"), &d.join("cg"), &d).unwrap_err();
            assert!(e.contains(".."), "{e}");
        }
    }

    #[test]
    fn refusal() {
        let gib = 1u64 << 30;
        let ok = HostLimits { cgroup_max: Some(8 * gib), ram: Some(16 * gib) };
        assert!(check(4 * gib, ok).is_ok());
        let e = check(9 * gib, ok).unwrap_err();
        assert!(e.contains("memory.max") && e.contains("POAM-021"), "{e}");
        // Unlimited cgroup: 90 % of RAM is the bound.
        let unl = HostLimits { cgroup_max: None, ram: Some(10 * gib) };
        assert!(check(9 * gib, unl).is_ok());
        assert!(check(9 * gib + 1, unl).unwrap_err().contains("90 % of RAM"));
        // Unknown RAM fails closed.
        assert!(check(1, HostLimits { cgroup_max: Some(8 * gib), ram: None }).is_err());
    }
}
