//! Start gate for `translation.cross_node_hairpin` (POAM-024).
//!
//! With the switch on, the engine accepts wire IPv4 packets sourced from
//! other nodes' pool slices. That is only safe when the host drops pool
//! sources arriving anywhere but the cluster-internal interfaces, which
//! `plat-tun-setup.sh` installs as a commented rule. platd runs without
//! `CAP_NET_ADMIN`, so it reads the snapshot of the live table the script
//! writes (`plat.nft.expected`; `plat-fwguard` keeps the live table equal to
//! it) and refuses to start when the guard is missing or names other
//! interfaces, does not cover every `nat64.pool` CIDR, or comes after a
//! rule that accepts IPv4 (and would shadow it).
//!
//! Residual (POAM-024): this checks the snapshot, not the live table; the
//! two are kept equal by `plat-fwguard`, and changing either needs root.
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
use std::net::Ipv4Addr;
use std::path::Path;

use plat_common::{Config, Ipv4Cidr};

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
    let tun_name = format!("\"{}\"", cfg.dataplane.interface);
    let tun = format!("oifname {tun_name}");
    let mut guard_seen = false;
    for l in text.lines().map(str::trim) {
        if l.starts_with('#') || l.contains("hook ") {
            continue;
        }
        let words: Vec<&str> = l.split_whitespace().collect();
        if !guard_seen && is_guard(l, &tun, &t.cluster_interfaces, &cfg.nat64.pool) {
            guard_seen = true;
        } else if !guard_seen && words.contains(&"accept") && !words.contains(&"ip6") && may_reach_tun(l, &tun_name) {
            // An accept that can match IPv4 towards the TUN before the
            // guard shadows it.
            return Err(fail(format!("{} accepts IPv4 before the pool-source guard: {l}", path.display())));
        }
    }
    if guard_seen { Ok(()) } else { Err(fail(format!("{} has no matching pool-source guard rule", path.display()))) }
}

/// The guard rule: our comment, towards the TUN, from anywhere but every
/// cluster interface, dropping a source set that covers all of `nat64.pool`.
fn is_guard(l: &str, tun: &str, ifaces: &[String], pool: &[Ipv4Cidr]) -> bool {
    l.contains(&format!("comment \"{GUARD_COMMENT}\""))
        && l.contains(tun)
        && l.contains("iifname != ")
        && l.contains(" drop ")
        && ifaces.iter().all(|i| l.contains(&format!("\"{i}\"")))
        && saddr_set(l).is_some_and(|set| pool.iter().all(|c| covered(c, &set)))
}

/// Whether a rule can match traffic forwarded to the TUN (`tun` is the
/// quoted interface name), and so shadow the guard (which matches
/// `oifname <tun>`): it names the TUN or a negation as output interface,
/// or it has no output restriction and does not match only traffic
/// arriving from the TUN (`iifname <tun> ... accept`, the outbound rule
/// `plat-tun-setup.sh` writes, cannot).
fn may_reach_tun(l: &str, tun: &str) -> bool {
    let Some(rest) = l.split_once("oifname ").map(|x| x.1.trim_start()) else {
        let from_tun = l.split_once("iifname ").is_some_and(|x| x.1.split_whitespace().next() == Some(tun));
        return !from_tun;
    };
    if rest.starts_with("!=") {
        return true;
    }
    let value = match rest.strip_prefix('{') {
        Some(r) => r.split_once('}').map_or(r, |x| x.0),
        None => rest.split_whitespace().next().unwrap_or(""),
    };
    value.split(',').any(|v| v.trim() == tun)
}

/// The `ip saddr { ... }` (or single-element) source set of a rule, as
/// inclusive address ranges. nft renders prefixes as `a/n`, host routes as
/// `a`, and may merge adjacent prefixes into ranges `a-b`.
fn saddr_set(l: &str) -> Option<Vec<(u32, u32)>> {
    let rest = l.split_once("ip saddr ")?.1.trim_start();
    let body = match rest.strip_prefix('{') {
        Some(r) => r.split_once('}')?.0,
        None => rest.split_whitespace().next()?,
    };
    body.split(',').map(|e| element(e.trim())).collect()
}

fn element(e: &str) -> Option<(u32, u32)> {
    if let Some((a, b)) = e.split_once('-') {
        let (a, b) = (u32::from(a.trim().parse::<Ipv4Addr>().ok()?), u32::from(b.trim().parse::<Ipv4Addr>().ok()?));
        return (a <= b).then_some((a, b));
    }
    let c: Ipv4Cidr = if e.contains('/') { e.parse().ok()? } else { format!("{e}/32").parse().ok()? };
    let host = u32::MAX.checked_shr(u32::from(c.prefix_len())).unwrap_or(0);
    Some((c.network(), c.network() | host))
}

/// `c` lies inside the union of `set`.
fn covered(c: &Ipv4Cidr, set: &[(u32, u32)]) -> bool {
    let host = u32::MAX.checked_shr(u32::from(c.prefix_len())).unwrap_or(0);
    let (mut next, end) = (u64::from(c.network()), u64::from(c.network() | host));
    // Each pass extends the covered prefix by one range; at most |set| passes.
    for _ in 0..=set.len() {
        if next > end {
            return true;
        }
        match set.iter().find(|&&(a, b)| u64::from(a) <= next && next <= u64::from(b)) {
            Some(&(_, b)) => next = u64::from(b) + 1,
            None => return false,
        }
    }
    next > end
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
            let e = check(&c, &snapshot(&d, &bad)).unwrap_err();
            assert!(e.contains("no matching") || e.contains("before the pool-source guard"), "{bad}: {e}");
        }
        assert!(check(&c, &d).is_err(), "a directory is not a snapshot");
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn two_pools() -> Config {
        let mut c = cfg(true);
        c.nat64.pool = vec!["192.0.2.0/24".parse().unwrap(), "198.51.100.0/25".parse().unwrap()];
        c
    }

    #[test]
    fn guard_must_cover_the_whole_pool() {
        let c = two_pools();
        let d = dir("pool");
        let rule = |set: &str| GOOD.replace("{ 192.0.2.0/24 }", set);
        for ok in [
            "{ 192.0.2.0/24, 198.51.100.0/25 }",
            // nft may merge adjacent prefixes or render a wider set.
            "{ 192.0.2.0/25, 192.0.2.128-192.0.2.255, 198.51.100.0/24 }",
        ] {
            assert!(check(&c, &snapshot(&d, &rule(ok))).is_ok(), "{ok}");
        }
        for bad in [
            // Stale (only the old pool) and partial sets.
            "{ 192.0.2.0/24 }",
            "{ 192.0.2.0/24, 198.51.100.0/26 }",
            "{ 192.0.2.0/25, 198.51.100.0/25 }",
            "{ 192.0.2.0/24, garbage }",
        ] {
            assert!(check(&c, &snapshot(&d, &rule(bad))).unwrap_err().contains("no matching"), "{bad}");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Lines as `nft list table inet plat` printed them on Linux 6.8 /
    /// nftables 1.0.9 (deploy/tests/nftguard/report.md): a /32 loses its
    /// prefix length, a one-element interface set its braces, adjacent
    /// prefixes merge into a range, and live tables carry counters.
    const OUT_V4: &str = "iifname \"plat0\" ip saddr { 192.0.2.0/24, 203.0.113.7 } accept";

    fn real(pool: &[&str], ifaces: &str, guard: &str) -> (Config, String) {
        let mut c = cfg(true);
        c.nat64.pool = pool.iter().map(|p| p.parse().unwrap()).collect();
        c.translation.cluster_interfaces = ifaces.split(',').map(str::to_string).collect();
        (c, guard.to_string())
    }

    #[test]
    fn real_nft_rendering_passes() {
        let d = dir("real");
        for (c, guard) in [
            real(
                &["192.0.2.0/24", "203.0.113.7/32"],
                "cl0",
                "oifname \"plat0\" iifname != \"cl0\" ip saddr { 192.0.2.0/24, 203.0.113.7 } \
                 counter packets 2 bytes 91 drop comment \"plat-pool-source-guard\" # handle 7",
            ),
            real(
                &["192.0.2.0/24", "192.0.3.0/25"],
                "cl0",
                "oifname \"plat0\" iifname != \"cl0\" ip saddr { 192.0.2.0-192.0.3.127 } \
                 counter packets 1 bytes 45 drop comment \"plat-pool-source-guard\"",
            ),
            real(
                &["192.0.2.0/24", "203.0.113.7/32"],
                "cl0,bond1.40",
                "oifname \"plat0\" iifname != { \"cl0\", \"bond1.40\" } ip saddr { 192.0.2.0/24, 203.0.113.7 } \
                 counter packets 0 bytes 0 drop comment \"plat-pool-source-guard\"",
            ),
        ] {
            let p = snapshot(&d, &format!("{guard}\n\t\t{OUT_V4}\n\t\tcounter packets 0 bytes 0 drop"));
            assert!(check(&c, &p).is_ok(), "{guard}");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn missing_guard_is_reported_as_missing_not_shadowed() {
        let (c, guard) = real(
            &["192.0.2.0/24", "203.0.113.7/32"],
            "cl0",
            "oifname \"plat0\" iifname != \"cl0\" ip saddr { 192.0.2.0/24, 203.0.113.7 } \
             counter packets 0 bytes 0 drop comment \"plat-pool-source-guard\"",
        );
        let d = dir("msg");
        // The outbound accept from the TUN follows; it cannot shadow a rule
        // for traffic towards the TUN, so a missing or mismatched guard is
        // reported as such.
        for bad in [
            String::new(),
            guard.replace("\"cl0\"", "\"ext0\""),
            guard.replace("203.0.113.7", "198.51.100.1"),
            "oifname \"plat0\" ip saddr { 192.0.2.0/24, 203.0.113.7 } counter packets 0 bytes 0 drop \
             comment \"plat-pool-source-guard\""
                .to_string(),
        ] {
            let e = check(&c, &snapshot(&d, &format!("{bad}\n\t\t{OUT_V4}"))).unwrap_err();
            assert!(e.contains("has no matching pool-source guard rule"), "{bad}: {e}");
        }
        // Accepts that can reach the TUN still shadow it.
        for shadow in [
            "oifname \"plat0\" ip saddr 192.0.2.1 accept",
            "oifname { \"eth9\", \"plat0\" } accept",
            "oifname != \"eth0\" accept",
            "iifname \"eth0\" accept",
        ] {
            let e = check(&c, &snapshot(&d, &format!("{shadow}\n\t\t{guard}"))).unwrap_err();
            assert!(e.contains("accepts IPv4 before the pool-source guard"), "{shadow}: {e}");
        }
        // Accepts towards other interfaces do not.
        let other = "oifname \"eth0\" ip saddr 192.0.2.1 accept";
        assert!(check(&c, &snapshot(&d, &format!("{other}\n\t\t{OUT_V4}\n\t\t{guard}"))).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn guard_must_precede_ipv4_accepts() {
        let c = cfg(true);
        let d = dir("order");
        let v6 = "oifname \"plat0\" ip6 saddr { 2001:db8::/32 } ip6 daddr 64:ff9b:1::/96 accept";
        let v4 = "iifname \"plat0\" ip saddr { 192.0.2.0/24 } accept";
        assert!(check(&c, &snapshot(&d, &format!("{v6}\n\t\t{GOOD}\n\t\t{v4}"))).is_ok());
        for shadow in ["ct state established,related accept", "oifname \"plat0\" accept"] {
            let e = check(&c, &snapshot(&d, &format!("{shadow}\n\t\t{GOOD}"))).unwrap_err();
            assert!(e.contains("before the pool-source guard"), "{shadow}: {e}");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
}
