//! QA validation edges for the daemon configuration (CM-6).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use plat_common::Config;
use plat_common::config::{ConfigError, MAX_POOL_ADDRS};

const EXAMPLE: &str = include_str!("../../../config/platd.example.toml");

fn with(edits: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let mut t = EXAMPLE.to_string();
    for (a, b) in edits {
        assert!(t.contains(a), "fixture key {a}");
        t = t.replacen(a, b, 1);
    }
    Config::from_toml(&t)
}

#[track_caller]
fn invalid(edits: &[(&str, &str)]) {
    match with(edits) {
        Err(ConfigError::Invalid(_)) => {}
        other => panic!("expected Invalid for {edits:?}, got {other:?}"),
    }
}

#[track_caller]
fn valid(edits: &[(&str, &str)]) {
    if let Err(e) = with(edits) {
        panic!("expected valid for {edits:?}: {e}");
    }
}

const NC: &str = "node_count = 1";

#[test]
fn owned_pool_must_be_inside_pool() {
    valid(&[(NC, "node_count = 2\nowned_pool = [\"192.0.2.128/25\"]")]);
    valid(&[(NC, "node_count = 1\nowned_pool = [\"192.0.2.0/24\"]")]);
    valid(&[(NC, "node_count = 1\nowned_pool = [\"192.0.2.255/32\"]")]);
    invalid(&[(NC, "node_count = 1\nowned_pool = [\"198.51.100.0/30\"]")]);
    // Wider than the pool, though it contains the pool's network address.
    invalid(&[(NC, "node_count = 1\nowned_pool = [\"192.0.0.0/22\"]")]);
    // One good entry does not excuse a bad one.
    invalid(&[(NC, "node_count = 1\nowned_pool = [\"192.0.2.0/25\", \"192.0.3.0/25\"]")]);
    // Straddles two pool entries without being inside either.
    invalid(&[
        ("pool = [\"192.0.2.0/24\"]", "pool = [\"192.0.2.0/25\", \"192.0.2.128/25\"]"),
        (NC, "node_count = 1\nowned_pool = [\"192.0.2.0/24\"]"),
    ]);
}

#[test]
fn owned_pool_with_host_bits_is_a_parse_error() {
    assert!(matches!(with(&[(NC, "node_count = 1\nowned_pool = [\"192.0.2.1/24\"]")]), Err(ConfigError::Parse(_))));
}

#[test]
fn pool_size_limit_boundary() {
    assert_eq!(MAX_POOL_ADDRS, 1 << 18);
    valid(&[("pool = [\"192.0.2.0/24\"]", "pool = [\"10.0.0.0/14\"]")]);
    invalid(&[("pool = [\"192.0.2.0/24\"]", "pool = [\"10.0.0.0/13\"]")]);
    invalid(&[("pool = [\"192.0.2.0/24\"]", "pool = [\"10.0.0.0/14\", \"10.4.0.0/32\"]")]);
    invalid(&[("pool = [\"192.0.2.0/24\"]", "pool = [\"0.0.0.0/0\"]")]);
    invalid(&[("pool = [\"192.0.2.0/24\"]", "pool = []")]);
}

#[test]
fn port_range_and_block_edges() {
    valid(&[("port_min = 1024", "port_min = 65472"), ("port_block_size = 512", "port_block_size = 64")]);
    invalid(&[("port_min = 1024", "port_min = 65473"), ("port_block_size = 512", "port_block_size = 64")]);
    invalid(&[("port_min = 1024", "port_min = 1023")]);
    invalid(&[("port_max = 65535", "port_max = 1000")]);
    invalid(&[("port_block_size = 512", "port_block_size = 63")]);
    valid(&[("port_block_size = 512", "port_block_size = 64512")]);
    invalid(&[("port_block_size = 512", "port_block_size = 64513")]);
    invalid(&[("max_blocks_per_subscriber = 4", "max_blocks_per_subscriber = 0")]);
}

#[test]
fn node_and_cluster_edges() {
    invalid(&[(NC, "node_count = 0")]);
    invalid(&[("id = 0", "id = 1")]);
    valid(&[(NC, "node_count = 2"), ("id = 0", "id = 1")]);
    invalid(&[("name = \"plat-01\"", "name = \"\"")]);
    invalid(&[("name = \"plat-01\"", "name = \"plat 01\"")]);
    invalid(&[("name = \"plat-01\"", "name = \"plat\\\"01\"")]);
    valid(&[("name = \"plat-01\"", &format!("name = \"{}\"", "a".repeat(64)))]);
    invalid(&[("name = \"plat-01\"", &format!("name = \"{}\"", "a".repeat(65)))]);
}

#[test]
fn translation_edges() {
    // RFC 6052 §2.2 u-octet (bits 64-71) must be zero.
    invalid(&[("64:ff9b:1::/96", "64:ff9b:1:0:100::/96")]);
    valid(&[("64:ff9b:1::/96", "2001:db8:64::/48")]);
    // RFC 6052 §3.1 / RFC-201: the WKP only with a global pool.
    invalid(&[("64:ff9b:1::/96", "64:ff9b::/96")]);
    valid(&[("64:ff9b:1::/96", "64:ff9b::/96"), ("192.0.2.0/24", "198.20.0.0/24")]);
    for pool in ["10.1.0.0/24", "100.64.0.0/24", "172.16.0.0/24", "192.168.1.0/24", "198.18.0.0/24", "192.0.0.8/31"] {
        invalid(&[("64:ff9b:1::/96", "64:ff9b::/96"), ("192.0.2.0/24", pool)]);
    }
    // A supernet that covers non-global space is refused too.
    invalid(&[("64:ff9b:1::/96", "64:ff9b::/96"), ("192.0.2.0/24", "8.0.0.0/6")]);
    // The globally reachable 192.0.0.9/.10 anycast addresses are allowed.
    valid(&[("64:ff9b:1::/96", "64:ff9b::/96"), ("192.0.2.0/24", "192.0.0.9/32")]);
    // A network-specific prefix may use a non-global pool.
    valid(&[("192.0.2.0/24", "100.64.0.0/24")]);
    invalid(&[("client_prefixes = [\"2001:db8:100::/40\"]", "client_prefixes = []")]);
    invalid(&[("ipv6_mtu = 1500", "ipv6_mtu = 1279")]);
    valid(&[("ipv6_mtu = 1500", "ipv6_mtu = 1280")]);
    invalid(&[("ipv4_mtu = 1500", "ipv4_mtu = 575")]);
    valid(&[("ipv4_mtu = 1500", "ipv4_mtu = 576")]);
    // RFC 7915 §4 lowest-ipv6-mtu: 1280..=ipv6_mtu.
    invalid(&[("lowest_ipv6_mtu = 1280", "lowest_ipv6_mtu = 1279")]);
    valid(&[("lowest_ipv6_mtu = 1280", "lowest_ipv6_mtu = 1500")]);
    invalid(&[("lowest_ipv6_mtu = 1280", "lowest_ipv6_mtu = 1501")]);
    valid(&[("icmp_errors_per_sec = 100", "icmp_errors_per_sec = 0")]);
    invalid(&[("icmp_errors_per_sec = 100", "icmp_errors_per_sec = 100001")]);
    // SC-7: client prefixes are bounded aggregates outside the NAT64 prefix.
    valid(&[("client_prefixes = [\"2001:db8:100::/40\"]", "client_prefixes = [\"2001::/16\"]")]);
    invalid(&[("client_prefixes = [\"2001:db8:100::/40\"]", "client_prefixes = [\"2000::/15\"]")]);
    invalid(&[("client_prefixes = [\"2001:db8:100::/40\"]", "client_prefixes = [\"64:ff9b:1::/48\"]")]);
    invalid(&[("client_prefixes = [\"2001:db8:100::/40\"]", "client_prefixes = [\"64:ff9b:1::1:0/112\"]")]);
}

#[test]
fn pool_must_avoid_never_translatable_space() {
    for p in ["127.0.0.0/30", "0.0.0.0/30", "169.254.1.0/24", "224.0.0.0/24", "255.255.255.252/30", "64.0.0.0/2"] {
        invalid(&[("pool = [\"192.0.2.0/24\"]", &format!("pool = [\"{p}\"]"))]);
    }
    valid(&[("pool = [\"192.0.2.0/24\"]", "pool = [\"100.64.0.0/24\"]")]);
}

#[test]
fn subscriber_table_limit() {
    invalid(&[("max_subscribers = 1000000", "max_subscribers = 0")]);
    valid(&[("max_subscribers = 1000000", "max_subscribers = 16777216")]);
    invalid(&[("max_subscribers = 1000000", "max_subscribers = 16777217")]);
}

#[test]
fn limits_and_timers_edges() {
    invalid(&[("subscriber_prefix_len = 64", "subscriber_prefix_len = 31")]);
    valid(&[("subscriber_prefix_len = 64", "subscriber_prefix_len = 128")]);
    invalid(&[("subscriber_prefix_len = 64", "subscriber_prefix_len = 129")]);
    invalid(&[("max_sessions = 4000000", "max_sessions = 0")]);
    invalid(&[("max_sessions_per_subscriber = 4000", "max_sessions_per_subscriber = 0")]);
    invalid(&[("table_shards = 1024", "table_shards = 0")]);
    valid(&[("table_shards = 1024", "table_shards = 65536")]);
    invalid(&[("table_shards = 1024", "table_shards = 65537")]);
    valid(&[("udp_secs = 300", "udp_secs = 120")]);
    invalid(&[("udp_secs = 300", "udp_secs = 119")]);
    invalid(&[("tcp_established_secs = 7440", "tcp_established_secs = 7439")]);
    invalid(&[("tcp_transitory_secs = 240", "tcp_transitory_secs = 239")]);
    invalid(&[("icmp_secs = 60", "icmp_secs = 0")]);
    invalid(&[("icmp_secs = 60", "icmp_secs = 59")]);
    valid(&[("udp_secs = 300", "udp_secs = 86400")]);
    invalid(&[("udp_secs = 300", "udp_secs = 86401")]);
    invalid(&[("tcp_established_secs = 7440", "tcp_established_secs = 86401")]);
    invalid(&[("tcp_transitory_secs = 240", "tcp_transitory_secs = 86401")]);
    invalid(&[("icmp_secs = 60", "icmp_secs = 86401")]);
    invalid(&[("sweep_interval_ms = 1000", "sweep_interval_ms = 0")]);
    valid(&[("sweep_interval_ms = 1000", "sweep_interval_ms = 60000")]);
    invalid(&[("sweep_interval_ms = 1000", "sweep_interval_ms = 60001")]);
}

#[test]
fn audit_edges() {
    invalid(&[("queue_capacity = 1048576", "queue_capacity = 1023")]);
    valid(&[("queue_capacity = 1048576", "queue_capacity = 1024")]);
    valid(&[("queue_capacity = 1048576", "queue_capacity = 67108864")]);
    invalid(&[("queue_capacity = 1048576", "queue_capacity = 67108865")]);
    invalid(&[("batch_max = 4096", "batch_max = 0")]);
    invalid(&[("flush_interval_ms = 100", "flush_interval_ms = 0")]);
    invalid(&[("max_bytes = 1073741824", "max_bytes = 1048575")]);
    valid(&[("max_bytes = 1073741824", "max_bytes = 1048576")]);
    valid(&[("max_files = 0", "max_files = 1")]);
    valid(&[("max_files = 0", "max_files = 100000")]);
    invalid(&[("max_files = 0", "max_files = 100001")]);
    assert!(with(&[("max_files = 0", "max_files = -1")]).is_err(), "negative max_files");
    // Default when omitted: keep every file.
    let c = with(&[("max_files = 0\n", "")]).unwrap();
    assert_eq!(c.audit.file.unwrap().max_files, 0);
    // AU-5(1) free-space threshold: 0 (off) or at least 1 MiB.
    valid(&[("min_free_bytes = 2147483648", "min_free_bytes = 0")]);
    valid(&[("min_free_bytes = 2147483648", "min_free_bytes = 1048576")]);
    invalid(&[("min_free_bytes = 2147483648", "min_free_bytes = 1048575")]);
    let c = with(&[("min_free_bytes = 2147483648\n", "")]).unwrap();
    assert_eq!(c.audit.file.unwrap().min_free_bytes, 0, "disabled when omitted");
    valid(&[("app_name = \"platd\"", &format!("app_name = \"{}\"", "a".repeat(48)))]);
    for bad in ["", "plat d", "\\u00e9t", &"a".repeat(49)] {
        invalid(&[("app_name = \"platd\"", &format!("app_name = \"{bad}\""))]);
    }
    // AU-12: at least one destination.
    let no_dest = EXAMPLE
        .split("[audit.file]")
        .next()
        .map(|head| format!("{head}\n[management]\nlisten = \"127.0.0.1:9464\"\n"))
        .unwrap();
    assert!(matches!(Config::from_toml(&no_dest), Err(ConfigError::Invalid(_))), "no audit destination");
    // SEC-104 / NIST-008e: AU-5 fail-closed needs the local file, so a
    // syslog-only config must use drop_and_alert.
    let file_section = EXAMPLE
        .split("[audit.file]")
        .nth(1)
        .and_then(|rest| rest.split("[[audit.syslog]]").next())
        .map(|body| format!("[audit.file]{body}"))
        .unwrap();
    let syslog_only = EXAMPLE.replacen(&file_section, "", 1);
    assert!(!syslog_only.contains("[audit.file]") && syslog_only.contains("[[audit.syslog]]"));
    assert!(
        matches!(Config::from_toml(&syslog_only), Err(ConfigError::Invalid(_))),
        "refuse_new_bindings without [audit.file]"
    );
    let c = Config::from_toml(
        &syslog_only.replace("on_overflow = \"refuse_new_bindings\"", "on_overflow = \"drop_and_alert\""),
    )
    .unwrap();
    assert!(c.audit.file.is_none());
    // Default policy (key omitted) is refuse_new_bindings, so it needs the file too.
    let omitted = syslog_only.replace("on_overflow = \"refuse_new_bindings\"\n", "");
    assert!(matches!(Config::from_toml(&omitted), Err(ConfigError::Invalid(_))), "default policy without file");
}

#[test]
fn non_global_destination_switch() {
    let c = with(&[]).unwrap();
    assert!(!c.translation.allow_non_global_destinations, "example denies non-global space");
    let c = with(&[("allow_non_global_destinations = false\n", "")]).unwrap();
    assert!(!c.translation.allow_non_global_destinations, "default when omitted is false");
    valid(&[("allow_non_global_destinations = false", "allow_non_global_destinations = true")]);
    assert!(with(&[("allow_non_global_destinations = false", "allow_non_global_destinations = 1")]).is_err());
}

#[test]
fn management_listen_edges() {
    valid(&[("127.0.0.1:9464", "[::1]:9464")]);
    invalid(&[("127.0.0.1:9464", "[::]:9464")]);
    invalid(&[("127.0.0.1:9464", "192.0.2.1:9464")]);
}
