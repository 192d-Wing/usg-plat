//! QA boundary cases for pool partitioning, route covers and subscriber
//! ownership.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use plat_cluster::{cover, owned, owner_of_subscriber, partition, pool_addrs};
use plat_common::{Config, Ipv4Cidr};

const EXAMPLE: &str = include_str!("../../../config/platd.example.toml");

fn c(s: &str) -> Ipv4Cidr {
    s.parse().unwrap()
}

fn cfg(edits: &[(&str, &str)]) -> Config {
    let mut t = EXAMPLE.to_string();
    for (a, b) in edits {
        assert!(t.contains(a), "fixture key {a}");
        t = t.replace(a, b);
    }
    Config::from_toml(&t).unwrap()
}

#[test]
fn more_nodes_than_addresses() {
    let addrs = [10, 11, 12];
    let parts: Vec<Vec<u32>> = (0..5).map(|id| partition(&addrs, 5, id)).collect();
    assert_eq!(parts.iter().map(Vec::len).collect::<Vec<_>>(), vec![1, 1, 1, 0, 0]);
    assert_eq!(parts.concat(), addrs);
}

#[test]
fn partition_degenerate_inputs() {
    assert!(partition(&[1, 2, 3], 3, 3).is_empty(), "id out of range");
    assert!(partition(&[1, 2, 3], 3, u16::MAX).is_empty());
    assert_eq!(partition(&[1, 2, 3], 0, 0), vec![1, 2, 3], "node_count 0 behaves as 1");
    assert!(partition(&[], 4, 0).is_empty());
}

#[test]
fn partition_large_pool_is_disjoint_and_contiguous() {
    let all = pool_addrs(&[c("10.0.0.0/14")]);
    assert_eq!(all.len(), 1 << 18);
    let mut next = all[0];
    for id in 0..7 {
        let p = partition(&all, 7, id);
        assert_eq!(p[0], next, "contiguous with the previous node");
        assert!(p.windows(2).all(|w| w[1] == w[0] + 1));
        next = p[p.len() - 1] + 1;
    }
    assert_eq!(next, all[all.len() - 1] + 1);
}

#[test]
fn pool_addrs_dedups_overlapping_prefixes() {
    let a = pool_addrs(&[c("192.0.2.0/30"), c("192.0.2.0/31"), c("192.0.2.2/32")]);
    assert_eq!(a, vec![0xc000_0200, 0xc000_0201, 0xc000_0202, 0xc000_0203]);
}

#[test]
fn cover_edges_of_address_space() {
    assert!(cover(&[]).is_empty());
    assert_eq!(cover(&[0]), vec![c("0.0.0.0/32")]);
    assert_eq!(cover(&[0, 1, 2, 3]), vec![c("0.0.0.0/30")]);
    assert_eq!(cover(&[u32::MAX]), vec![c("255.255.255.255/32")]);
    assert_eq!(cover(&[u32::MAX - 3, u32::MAX - 2, u32::MAX - 1, u32::MAX]), vec![c("255.255.255.252/30")]);
    let top: Vec<u32> = (u32::MAX - 255..=u32::MAX).collect();
    assert_eq!(cover(&top), vec![c("255.255.255.0/24")]);
    // Unaligned run and gaps.
    assert_eq!(cover(&[1, 2, 3]), vec![c("0.0.0.1/32"), c("0.0.0.2/31")]);
    assert_eq!(cover(&[1, 3]), vec![c("0.0.0.1/32"), c("0.0.0.3/32")]);
}

#[test]
fn covers_of_all_nodes_are_exact_and_disjoint() {
    let all = pool_addrs(&[c("198.51.100.0/24"), c("203.0.113.0/25")]);
    let mut got = Vec::new();
    for id in 0..6 {
        let p = partition(&all, 6, id);
        let addrs: Vec<u32> = cover(&p).iter().flat_map(|x| x.addrs()).collect();
        assert_eq!(addrs, p, "node {id} announces exactly its slice");
        got.extend(addrs);
    }
    assert_eq!(got, all);
}

#[test]
fn owned_uses_override_or_partition() {
    let one = cfg(&[("node_count = 1", "node_count = 4"), ("id = 0", "id = 3")]);
    let o = owned(&one);
    assert_eq!(o.len(), 64);
    assert_eq!(o[0], 0xc000_02c0, "node 3 of 4 owns 192.0.2.192/26");

    let ov = cfg(&[("node_count = 1", "node_count = 2\nowned_pool = [\"192.0.2.16/28\"]")]);
    assert_eq!(owned(&ov), (0xc000_0210..=0xc000_021f).collect::<Vec<_>>());
}

#[test]
fn node_with_empty_slice_owns_nothing() {
    // 300 nodes for 256 addresses: config validates, but the last nodes own
    // nothing; plat-nat64 `Nat64::new` then refuses to start (tested in
    // plat-nat64/tests/engine_edges.rs).
    let c = cfg(&[("node_count = 1", "node_count = 300"), ("id = 0", "id = 299")]);
    assert!(owned(&c).is_empty());
}

#[test]
fn subscriber_owner_is_in_range_and_deterministic() {
    assert_eq!(owner_of_subscriber(12345, 0), 0);
    assert_eq!(owner_of_subscriber(12345, 1), 0);
    for n in [2u16, 3, 7, 64] {
        let mut counts = vec![0u32; usize::from(n)];
        for s in 0..4000u128 {
            let o = owner_of_subscriber(s << 64, n);
            assert!(o < n);
            assert_eq!(o, owner_of_subscriber(s << 64, n));
            counts[usize::from(o)] += 1;
        }
        let expect = 4000 / u32::from(n);
        assert!(counts.iter().all(|&k| k > expect / 2 && k < expect * 2), "balanced for {n}: {counts:?}");
    }
    // Removing a node moves only that node's subscribers.
    for s in 0..2000u128 {
        let before = owner_of_subscriber(s << 64, 5);
        let after = owner_of_subscriber(s << 64, 4);
        if before != 4 {
            assert_eq!(before, after, "subscriber moved although its node survived");
        }
    }
}
