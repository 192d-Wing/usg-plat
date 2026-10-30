//! Start gate for `translation.cross_node_hairpin` (POAM-024).
//!
//! With the switch on, the engine accepts wire IPv4 packets sourced from
//! other nodes' pool slices. That is only safe when the host drops pool
//! sources arriving anywhere but the cluster-internal interfaces, which
//! `plat-tun-setup.sh` installs as a commented rule. platd runs without
//! `CAP_NET_ADMIN`, so it reads the snapshot of the live table the script
//! writes (`plat.nft.expected`; `plat-fwguard` keeps the live table equal to
//! it) and refuses to start when the guard is missing or names other
//! interfaces.
//!
//! Fail closed rather than warn: the switch is opt-in, a warning in the
//! journal leaves the spoofing path open silently, and the script installs
//! the guard on every start, so the only way to trip the gate is a host
//! policy that does not match the configuration.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-7, SC-7(5), AC-4 - pool-sourced IPv4 is admitted only
//!   from the cluster-internal network; CM-6 - the host policy is checked
//!   against the configuration at start

use std::io::Read;
use std::path::Path;

use plat_common::Config;

/// Snapshot of the installed forward policy written by `plat-tun-setup.sh`.
pub const SNAPSHOT: &str = "/etc/nftables.d/plat.nft.expected";
/// nft comment carried by the pool-source guard rule.
pub const GUARD_COMMENT: &str = "plat-pool-source-guard";
/// The snapshot is a few kilobytes; anything larger is not ours (SC-5).
const MAX_SNAPSHOT: u64 = 1 << 20;

/// `Ok` when cross-node hairpinning is off, or the guard rule in `path`
/// matches the configured TUN and cluster interfaces.
pub fn check(cfg: &Config, path: &Path) -> Result<(), String> {
    let t = &cfg.translation;
    if !t.cross_node_hairpin {
        return Ok(());
    }
    let fail = |why: String| {
        format!(
            "translation.cross_node_hairpin = true but {why}; the host must drop pool-sourced IPv4 \
             arriving outside translation.cluster_interfaces (run plat-tun-setup.sh, POAM-024)"
        )
    };
    let text = read_bounded(path).map_err(|e| fail(format!("cannot read {}: {e}", path.display())))?;
    let tun = format!("oifname \"{}\"", cfg.dataplane.interface);
    let ok = text.lines().any(|l| {
        l.contains(&format!("comment \"{GUARD_COMMENT}\""))
            && l.contains(&tun)
            && l.contains("iifname != ")
            && l.contains("ip saddr ")
            && l.contains(" drop ")
            && t.cluster_interfaces.iter().all(|i| l.contains(&format!("\"{i}\"")))
    });
    if ok { Ok(()) } else { Err(fail(format!("{} has no matching pool-source guard rule", path.display()))) }
}

fn read_bounded(path: &Path) -> std::io::Result<String> {
    #[cfg(feature = "tls")]
    let f = plat_tls::load::open_regular(path)?;
    #[cfg(not(feature = "tls"))]
    let f = {
        let f = std::fs::File::open(path)?;
        if !f.metadata()?.is_file() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"));
        }
        f
    };
    let mut s = String::new();
    f.take(MAX_SNAPSHOT + 1).read_to_string(&mut s)?;
    if s.len() as u64 > MAX_SNAPSHOT {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "larger than 1 MiB"));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(on: bool) -> Config {
        let mut t = include_str!("../../../config/platd.example.toml").to_string();
        if on {
            t = t.replace(
                "cross_node_hairpin = false\n# cluster_interfaces = [\"eth1\"]",
                "cross_node_hairpin = true\ncluster_interfaces = [\"eth1\", \"eth2\"]",
            );
        }
        Config::from_toml(&t).unwrap()
    }

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("platd-hairpin-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn snapshot(d: &Path, rule: &str) -> std::path::PathBuf {
        let p = d.join("plat.nft.expected");
        std::fs::write(&p, format!("table inet plat {{\n\tchain forward {{\n\t\t{rule}\n\t}}\n}}\n")).unwrap();
        p
    }

    const GOOD: &str = "oifname \"plat0\" iifname != { \"eth1\", \"eth2\" } ip saddr { 192.0.2.0/24 } \
                        counter packets 0 bytes 0 drop comment \"plat-pool-source-guard\"";

    #[test]
    fn off_needs_nothing() {
        assert!(check(&cfg(false), Path::new("/nonexistent/plat.nft.expected")).is_ok());
    }

    #[test]
    fn on_requires_matching_guard() {
        let c = cfg(true);
        let missing = check(&c, Path::new("/nonexistent/plat.nft.expected")).unwrap_err();
        assert!(missing.contains("cannot read"), "{missing}");
        let d = dir("on");
        assert!(check(&c, &snapshot(&d, GOOD)).is_ok());
        for bad in [
            GOOD.replace("comment \"plat-pool-source-guard\"", ""),
            GOOD.replace(", \"eth2\"", ""),
            GOOD.replace("plat0", "plat1"),
            GOOD.replace(" drop ", " accept "),
            "oifname \"plat0\" ip saddr { 192.0.2.0/24 } accept".to_string(),
        ] {
            assert!(check(&c, &snapshot(&d, &bad)).unwrap_err().contains("no matching"), "{bad}");
        }
        assert!(check(&c, &d).is_err(), "a directory is not a snapshot");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
