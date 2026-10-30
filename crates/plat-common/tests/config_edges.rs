//! QA validation edges for the daemon configuration (CM-6).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use plat_common::Config;
use plat_common::config::{ConfigError, MAX_POOL_ADDRS, Partition, SteeringMode};

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

// ---- Cluster HA (WU2) ----

/// A valid two-node HA cluster section (node 0) with a witness.
fn ha_section(members: usize, ha_extra: &str, cluster_extra: &str) -> String {
    let mut s = format!("node_count = {members}\npartition = \"slices\"\n{cluster_extra}\n");
    for i in 0..members {
        let name = if i == 0 { "plat-01".to_string() } else { format!("plat-{:02}", i + 1) };
        s.push_str(&format!(
            "[[cluster.members]]\nid = {i}\nname = \"{name}\"\npeer_addr = \"198.51.100.{}:7946\"\n\
             identity = \"dns:{name}.cluster.example\"\n",
            11 + i
        ));
    }
    s.push_str(&format!(
        "[cluster.ha]\nenabled = true\nlisten = \"198.51.100.11:7946\"\n{ha_extra}\n\
         [cluster.ha.tls]\ncert_file = \"/etc/plat/tls/peer.pem\"\nkey_file = \"/etc/plat/tls/peer.key\"\n\
         ca_file = \"/etc/plat/tls/cluster-ca.pem\"\n"
    ));
    s
}

const WITNESS: &str = "witness = { addr = \"198.51.100.20:7946\", identity = \"dns:witness.cluster.example\" }";

fn ha(members: usize, ha_extra: &str) -> Result<Config, ConfigError> {
    with(&[(NC, &ha_section(members, ha_extra, ""))])
}

#[track_caller]
fn ha_invalid(members: usize, ha_extra: &str, want: &str) {
    match ha(members, ha_extra) {
        Err(ConfigError::Invalid(m)) => assert!(m.contains(want), "{ha_extra}: {m}"),
        other => panic!("expected Invalid for {ha_extra:?}, got {other:?}"),
    }
}

#[track_caller]
fn ha_valid(members: usize, ha_extra: &str) -> Config {
    ha(members, ha_extra).unwrap_or_else(|e| panic!("expected valid for {ha_extra:?}: {e}"))
}

#[test]
fn ha_off_by_default() {
    let c = with(&[]).unwrap();
    assert!(!c.cluster.ha_enabled() && !c.cluster.auto_failover());
    assert_eq!(c.cluster.partition, Partition::Contiguous);
    assert_eq!(c.cluster.slice_prefix_len, 28);
    assert_eq!(c.cluster.steering_mode(), SteeringMode::Count);
    assert_eq!(c.nat64.block_cooldown_secs, 120);
    // Present but not enabled: HA stays off, legacy partition still allowed.
    let off = ha_section(2, "", "").replace("enabled = true\n", "").replace("partition = \"slices\"\n", "");
    let c = with(&[(NC, &off)]).unwrap();
    assert!(!c.cluster.ha_enabled() && c.cluster.ha_active().is_none());
}

#[test]
fn ha_defaults_and_auto_failover() {
    let c = ha_valid(2, WITNESS);
    let h = c.cluster.ha_active().unwrap();
    assert_eq!((h.lease_ms, h.heartbeat_ms, h.drift_margin_pct), (3000, 500, 10));
    assert_eq!((h.tcp_adopt_secs, h.takeover_quarantine_secs, h.reserve_ahead_blocks), (300, 600, 8));
    assert_eq!((h.failback_delay_secs, h.max_concurrent_handovers, h.repl_ring_entries), (60, 4, 65_536));
    assert_eq!((h.peer_queue_bytes, h.max_frame_bytes, h.hook_timeout_ms), (64 << 20, 1 << 20, 5000));
    assert_eq!(h.shutdown_handover_ms, 10_000);
    assert_eq!(h.state_dir.to_str(), Some("/var/lib/plat/cluster"));
    assert!(c.cluster.auto_failover());
    assert_eq!(c.cluster.steering_mode(), SteeringMode::Drop, "drop is the HA default");
    // Two members, no witness: auto failover is off and cannot be forced on.
    let c = ha_valid(2, "");
    assert!(!c.cluster.auto_failover());
    ha_invalid(2, "auto_failover = true", "witness");
    ha_valid(2, "auto_failover = false");
    // Three members form a quorum without a witness.
    assert!(ha_valid(3, "").cluster.auto_failover());
    ha_valid(3, "auto_failover = true");
    assert!(!ha_valid(3, "auto_failover = false").cluster.auto_failover());
    // Steering can be relaxed to count explicitly; forward is phase 2.
    let s = format!("{}[cluster.steering]\nmode = \"count\"\n", ha_section(2, "", ""));
    assert_eq!(with(&[(NC, &s)]).unwrap().cluster.steering_mode(), SteeringMode::Count);
    let s = format!("{}[cluster.steering]\nmode = \"forward\"\n", ha_section(2, "", ""));
    assert!(matches!(with(&[(NC, &s)]), Err(ConfigError::Invalid(m)) if m.contains("forward")));
    let s = format!("{}[cluster.steering]\nmode = \"bogus\"\n", ha_section(2, "", ""));
    assert!(matches!(with(&[(NC, &s)]), Err(ConfigError::Parse(_))));
}

#[test]
fn ha_numeric_edges() {
    for (accept, reject, want) in [
        ("lease_ms = 1000\nheartbeat_ms = 250", "lease_ms = 999\nheartbeat_ms = 50", "lease_ms"),
        ("lease_ms = 30000", "lease_ms = 30001", "lease_ms"),
        ("heartbeat_ms = 750", "heartbeat_ms = 751", "heartbeat_ms"),
        ("heartbeat_ms = 50", "heartbeat_ms = 49", "heartbeat_ms"),
        ("drift_margin_pct = 1", "drift_margin_pct = 0", "drift_margin_pct"),
        ("drift_margin_pct = 50", "drift_margin_pct = 51", "drift_margin_pct"),
        ("tcp_adopt_secs = 0", "tcp_adopt_secs = 3601", "tcp_adopt_secs"),
        ("tcp_adopt_secs = 3600", "tcp_adopt_secs = 3601", "tcp_adopt_secs"),
        // Longest of udp 300 / tcp_trans 240 / icmp 60 in the example.
        ("takeover_quarantine_secs = 300", "takeover_quarantine_secs = 299", "takeover_quarantine_secs"),
        ("takeover_quarantine_secs = 86400", "takeover_quarantine_secs = 86401", "takeover_quarantine_secs"),
        ("reserve_ahead_blocks = 1", "reserve_ahead_blocks = 0", "reserve_ahead_blocks"),
        ("reserve_ahead_blocks = 64", "reserve_ahead_blocks = 65", "reserve_ahead_blocks"),
        ("failback_delay_secs = 0", "failback_delay_secs = 86401", "failback_delay_secs"),
        ("max_concurrent_handovers = 1", "max_concurrent_handovers = 0", "max_concurrent_handovers"),
        ("max_concurrent_handovers = 64", "max_concurrent_handovers = 65", "max_concurrent_handovers"),
        ("repl_ring_entries = 1024", "repl_ring_entries = 512", "repl_ring_entries"),
        ("repl_ring_entries = 1048576", "repl_ring_entries = 2097152", "repl_ring_entries"),
        ("repl_ring_entries = 4096", "repl_ring_entries = 5000", "repl_ring_entries"),
        ("peer_queue_bytes = 1073741824", "peer_queue_bytes = 1073741825", "peer_queue_bytes"),
        (
            "peer_queue_bytes = 1048576\nmax_frame_bytes = 262144",
            "peer_queue_bytes = 1048575\nmax_frame_bytes = 65536",
            "peer_queue_bytes",
        ),
        ("max_frame_bytes = 65536", "max_frame_bytes = 65535", "max_frame_bytes"),
        (
            "peer_queue_bytes = 67108864\nmax_frame_bytes = 16777216",
            "peer_queue_bytes = 67108864\nmax_frame_bytes = 16777217",
            "max_frame_bytes",
        ),
        (
            "peer_queue_bytes = 4194304\nmax_frame_bytes = 1048576",
            "peer_queue_bytes = 4194303\nmax_frame_bytes = 1048576",
            "peer_queue_bytes / 4",
        ),
        ("hook_timeout_ms = 100", "hook_timeout_ms = 99", "hook_timeout_ms"),
        ("hook_timeout_ms = 60000", "hook_timeout_ms = 60001", "hook_timeout_ms"),
        ("shutdown_handover_ms = 1000", "shutdown_handover_ms = 999", "shutdown_handover_ms"),
        ("shutdown_handover_ms = 60000", "shutdown_handover_ms = 60001", "shutdown_handover_ms"),
    ] {
        ha_valid(2, accept);
        ha_invalid(2, reject, want);
    }
    // Quarantine follows the configured timeouts.
    let s = ha_section(2, "takeover_quarantine_secs = 600", "");
    invalid(&[(NC, &s), ("udp_secs = 300", "udp_secs = 601")]);
    valid(&[(NC, &s), ("udp_secs = 300", "udp_secs = 600")]);
    // Negative or wrong-typed values are parse errors.
    for bad in ["lease_ms = -1", "repl_ring_entries = \"big\"", "auto_failover = 1"] {
        assert!(matches!(ha(2, bad), Err(ConfigError::Parse(_))), "{bad}");
    }
}

#[test]
fn ha_structure_rules() {
    // HA needs slices, two or more members, and no owned_pool.
    let s = ha_section(2, "", "").replace("partition = \"slices\"", "partition = \"contiguous\"");
    invalid(&[(NC, &s)]);
    let s = ha_section(2, "", "owned_pool = [\"192.0.2.0/25\"]");
    invalid(&[(NC, &s)]);
    assert!(matches!(ha(1, ""), Err(ConfigError::Invalid(m)) if m.contains("two")));
    // Listener: no wildcard unless allowed, no port 0.
    let wild = ha_section(2, "", "").replace("listen = \"198.51.100.11:7946\"", "listen = \"0.0.0.0:7946\"");
    invalid(&[(NC, &wild)]);
    let wild6 = ha_section(2, "", "").replace("listen = \"198.51.100.11:7946\"", "listen = \"[::]:7946\"");
    invalid(&[(NC, &wild6)]);
    let allowed = wild.replace("enabled = true\n", "enabled = true\nallow_wildcard = true\n");
    valid(&[(NC, &allowed)]);
    let p0 = ha_section(2, "", "").replace("listen = \"198.51.100.11:7946\"", "listen = \"198.51.100.11:0\"");
    invalid(&[(NC, &p0)]);
    // Witness identity/address must be typed and distinct from members.
    ha_invalid(2, "witness = { addr = \"198.51.100.20:7946\", identity = \"witness\" }", "witness.identity");
    ha_invalid(
        2,
        "witness = { addr = \"198.51.100.20:7946\", identity = \"dns:plat-02.cluster.example\" }",
        "witness.identity",
    );
    ha_invalid(2, "witness = { addr = \"198.51.100.12:7946\", identity = \"dns:w.example\" }", "witness.addr");
    ha_invalid(2, "witness = { addr = \"0.0.0.0:7946\", identity = \"dns:w.example\" }", "witness.addr");
    // Paths absolute; revocation override validated under its own prefix.
    for (from, what) in [
        ("/etc/plat/tls/peer.pem", "cert_file"),
        ("/etc/plat/tls/peer.key", "key_file"),
        ("/etc/plat/tls/cluster-ca.pem", "ca_file"),
    ] {
        let s = ha_section(2, "", "").replace(from, "rel.pem");
        assert!(matches!(with(&[(NC, &s)]), Err(ConfigError::Invalid(m)) if m.contains(what)), "{what}");
    }
    ha_invalid(2, "state_dir = \"cluster\"", "state_dir");
    ha_invalid(2, "[cluster.ha.hooks]\nannounce = \"frr.sh\"", "hooks.announce");
    ha_invalid(2, "[cluster.ha.hooks]\nwithdraw = \"frr.sh\"", "hooks.withdraw");
    ha_valid(2, "[cluster.ha.hooks]\nannounce = \"/usr/libexec/plat/a.sh\"\nwithdraw = \"/usr/libexec/plat/w.sh\"");
    let rev = format!("{}[cluster.ha.tls.revocation]\nbudget_ms = 100\n", ha_section(2, "", ""));
    assert!(matches!(with(&[(NC, &rev)]), Err(ConfigError::Invalid(m)) if m.contains("cluster.ha.tls.revocation")));
    // Unknown keys in every new table.
    for t in [
        ha_section(2, "bogus = 1", ""),
        format!("{}[cluster.ha.tls.revocation]\nbogus = 1\n", ha_section(2, "", "")),
        format!("{}[cluster.steering]\nbogus = 1\n", ha_section(2, "", "")),
        ha_section(2, "[cluster.ha.hooks]\nbogus = \"/x\"", ""),
        ha_section(2, "witness = { addr = \"198.51.100.20:7946\", identity = \"dns:w.example\", x = 1 }", ""),
        ha_section(2, "", "").replacen("id = 1\n", "id = 1\nbogus = 1\n", 1),
    ] {
        assert!(matches!(with(&[(NC, &t)]), Err(ConfigError::Parse(_))), "{t}");
    }
}

#[test]
fn slice_partition_edges() {
    let slices = |extra: &str| format!("node_count = 1\npartition = \"slices\"\n{extra}");
    let c = with(&[(NC, &slices(""))]).unwrap();
    assert_eq!(c.cluster.slice_count(&c.nat64.pool), 16, "/24 at /28");
    valid(&[(NC, &slices("slice_prefix_len = 24"))]);
    valid(&[(NC, &slices("slice_prefix_len = 32"))]);
    invalid(&[(NC, &slices("slice_prefix_len = 33"))]);
    invalid(&[(NC, &slices("slice_prefix_len = 15"))]);
    // A pool entry narrower than a slice is rejected.
    invalid(&[(NC, &slices("slice_prefix_len = 23"))]);
    // 4096-slice cap: a /16 at /28 is 4096 slices, a /15 is 8192.
    valid(&[("pool = [\"192.0.2.0/24\"]", "pool = [\"10.0.0.0/16\"]"), (NC, &slices(""))]);
    invalid(&[("pool = [\"192.0.2.0/24\"]", "pool = [\"10.0.0.0/15\"]"), (NC, &slices(""))]);
    valid(&[("pool = [\"192.0.2.0/24\"]", "pool = [\"10.0.0.0/15\"]"), (NC, &slices("slice_prefix_len = 27"))]);
    // Contiguous mode ignores the slice length.
    valid(&[(NC, "node_count = 1\nslice_prefix_len = 99")]);
    invalid(&[(NC, &slices("owned_pool = [\"192.0.2.0/25\"]"))]);
    assert!(matches!(with(&[(NC, &slices("partition = \"mesh\""))]), Err(ConfigError::Parse(_))));
}

#[test]
fn member_list_rules() {
    let base = ha_section(3, "", "");
    let edit = |a: &str, b: &str| base.replacen(a, b, 1);
    valid(&[(NC, &base)]);
    // node_count must match; ids unique and in range.
    invalid(&[(NC, &edit("node_count = 3", "node_count = 4"))]);
    invalid(&[(NC, &edit("id = 2", "id = 1"))]);
    invalid(&[(NC, &edit("id = 2", "id = 3"))]);
    // Names, identities and peer addresses unique and well formed.
    invalid(&[(NC, &edit("name = \"plat-03\"", "name = \"plat-02\""))]);
    invalid(&[(NC, &edit("name = \"plat-03\"", "name = \"plat 03\""))]);
    invalid(&[(NC, &edit("dns:plat-03.cluster.example", "dns:plat-02.cluster.example"))]);
    invalid(&[(NC, &edit("dns:plat-03.cluster.example", "plat-03"))]);
    invalid(&[(NC, &edit("dns:plat-03.cluster.example", "dns:*.cluster.example"))]);
    invalid(&[(NC, &edit("198.51.100.13:7946", "198.51.100.12:7946"))]);
    invalid(&[(NC, &edit("198.51.100.13:7946", "198.51.100.13:0"))]);
    invalid(&[(NC, &edit("198.51.100.13:7946", "0.0.0.0:7946"))]);
    invalid(&[(NC, &edit("198.51.100.13:7946", "224.0.0.1:7946"))]);
    // This node's entry must carry node.name.
    invalid(&[(NC, &edit("name = \"plat-01\"", "name = \"plat-00\""))]);
    // Weight 1..=100.
    let w = |v: &str| edit("id = 1\n", &format!("id = 1\nweight = {v}\n"));
    valid(&[(NC, &w("1"))]);
    valid(&[(NC, &w("100"))]);
    invalid(&[(NC, &w("0"))]);
    invalid(&[(NC, &w("101"))]);
    // steer_addr only with forward mode (phase 2), so always rejected now.
    invalid(&[(NC, &edit("id = 1\n", "id = 1\nsteer_addr = \"2001:db8::11\"\n"))]);
    // A member list without HA still has to be consistent.
    let legacy = base.split("[cluster.ha]").next().unwrap().replace("partition = \"slices\"\n", "");
    valid(&[(NC, &legacy)]);
    invalid(&[(NC, &legacy.replacen("node_count = 3", "node_count = 2", 1))]);
}

#[test]
fn block_cooldown_edges() {
    valid(&[("block_cooldown_secs = 120", "block_cooldown_secs = 3600")]);
    invalid(&[("block_cooldown_secs = 120", "block_cooldown_secs = 119")]);
    invalid(&[("block_cooldown_secs = 120", "block_cooldown_secs = 3601")]);
    assert_eq!(with(&[("block_cooldown_secs = 120\n", "")]).unwrap().nat64.block_cooldown_secs, 120);
}
