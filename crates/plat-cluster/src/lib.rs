//! Scale-out without shared state.
//!
//! Every node computes, from the same configuration, a disjoint and
//! contiguous slice of the IPv4 pool. A node only allocates from its slice
//! and announces it upstream (BGP/static routes), so IPv4 return traffic
//! always reaches the node that holds the session, and no session state
//! crosses the cluster on the packet path.
//!
//! On the IPv6 side, ECMP must keep a subscriber on one node: hash on the
//! IPv6 source (L3-only hashing) or steer by subscriber prefix.
//! [`owner_of_subscriber`] gives a deterministic rendezvous-hash assignment
//! for load balancers that can use it.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5(2) (Capacity, Bandwidth, and Redundancy), CP-10
//!   (node loss affects only that node's subscribers; survivors are unchanged)

use plat_common::{Config, Ipv4Cidr};

/// Every pool address, sorted and de-duplicated.
pub fn pool_addrs(pool: &[Ipv4Cidr]) -> Vec<u32> {
    let mut v: Vec<u32> = pool.iter().flat_map(|p| p.addrs()).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Node `id`'s contiguous slice of `addrs` (sizes differ by at most one).
pub fn partition(addrs: &[u32], node_count: u16, id: u16) -> Vec<u32> {
    let n = usize::from(node_count.max(1));
    let id = usize::from(id);
    if id >= n {
        return Vec::new();
    }
    let base = addrs.len() / n;
    let extra = addrs.len() % n;
    let start = id * base + id.min(extra);
    let len = base + usize::from(id < extra);
    addrs[start..start + len].to_vec()
}

/// The addresses this node owns: the explicit `cluster.owned_pool`
/// override, or its computed partition of `nat64.pool`.
pub fn owned(cfg: &Config) -> Vec<u32> {
    if cfg.cluster.owned_pool.is_empty() {
        partition(&pool_addrs(&cfg.nat64.pool), cfg.cluster.node_count, cfg.node.id)
    } else {
        pool_addrs(&cfg.cluster.owned_pool)
    }
}

/// Minimal set of CIDR prefixes covering exactly `addrs` (sorted), for the
/// route announcements of this node.
pub fn cover(addrs: &[u32]) -> Vec<Ipv4Cidr> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < addrs.len() {
        // Extend a run of consecutive addresses.
        let mut j = i;
        while j + 1 < addrs.len() && addrs[j + 1] == addrs[j].wrapping_add(1) {
            j += 1;
        }
        let (mut lo, hi) = (u64::from(addrs[i]), u64::from(addrs[j]));
        while lo <= hi {
            let mut len = 32u8;
            // Largest aligned block starting at lo that fits in [lo, hi].
            while len > 0 {
                let size = 1u64 << (33 - len);
                if lo % size != 0 || lo + size - 1 > hi {
                    break;
                }
                len -= 1;
            }
            if let Ok(c) = Ipv4Cidr::new(std::net::Ipv4Addr::from(lo as u32), len) {
                out.push(c);
            }
            lo += 1u64 << (32 - len);
        }
        i = j + 1;
    }
    out
}

fn mix(mut x: u64) -> u64 {
    // splitmix64 finalizer: stable across nodes and releases.
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Rendezvous (highest-random-weight) owner of a subscriber prefix. Adding
/// or removing a node moves only ~1/N of subscribers.
pub fn owner_of_subscriber(sub: u128, node_count: u16) -> u16 {
    let k = mix((sub >> 64) as u64 ^ mix(sub as u64));
    (0..node_count.max(1)).max_by_key(|n| mix(k ^ mix(u64::from(*n) + 1))).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn c(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
    }

    #[test]
    fn partitions_are_disjoint_and_complete() {
        let all = pool_addrs(&[c("192.0.2.0/24"), c("198.51.100.0/28")]);
        assert_eq!(all.len(), 272);
        let mut seen = Vec::new();
        for id in 0..5 {
            let p = partition(&all, 5, id);
            assert!(p.len() == 54 || p.len() == 55);
            seen.extend(p);
        }
        assert_eq!(seen, all);
    }

    #[test]
    fn covers_are_minimal() {
        let all = pool_addrs(&[c("192.0.2.0/24")]);
        assert_eq!(cover(&partition(&all, 4, 1)), vec![c("192.0.2.64/26")]);
        assert_eq!(cover(&all), vec![c("192.0.2.0/24")]);
        let odd = partition(&all, 3, 0); // 86 addresses
        assert_eq!(cover(&odd), vec![c("192.0.2.0/26"), c("192.0.2.64/28"), c("192.0.2.80/30"), c("192.0.2.84/31")]);
    }

    #[test]
    fn rendezvous_is_stable_under_growth() {
        let moved =
            (0..10_000u128).filter(|s| owner_of_subscriber(s << 64, 4) != owner_of_subscriber(s << 64, 5)).count();
        assert!((1_500..2_500).contains(&moved), "~1/5 should move, got {moved}");
    }

    proptest! {
        #[test]
        fn cover_is_exact(start in 0u32..u32::MAX - 5000, len in 1u32..5000) {
            let addrs: Vec<u32> = (start..start + len).collect();
            let got: Vec<u32> = cover(&addrs).iter().flat_map(|p| p.addrs()).collect();
            prop_assert_eq!(got, addrs);
        }
    }
}
