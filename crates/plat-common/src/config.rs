//! Daemon configuration (TOML), with validation at load time.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-6 (Configuration Settings) - secure defaults, every
//!   value range-checked before the data plane starts.
//! - NIST 800-53: CM-7 (Least Functionality) - management plane is loopback-only.
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - every table has a
//!   limit: subscribers (`nat64.max_subscribers`), port blocks per subscriber,
//!   sessions (global and per subscriber), pool size, audit queue. BIB
//!   entries are bounded by the ports those limits allow.
//! - NIST 800-53: SC-10 (Network Disconnect) - idle timers have RFC minimums.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::net::{Ipv4Cidr, Ipv6Cidr};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("parsing config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Upper bound on pool size (bounded memory for per-address block lists).
pub const MAX_POOL_ADDRS: u64 = 1 << 18;

/// Largest accepted idle timeout (24 h; RFC 6146 TCP_EST default is ~2 h).
pub const MAX_TIMEOUT_SECS: u32 = 86_400;
/// Largest accepted sweeper interval.
pub const MAX_SWEEP_INTERVAL_MS: u64 = 60_000;
/// Smallest accepted audit file rotation size.
pub const MIN_FILE_BYTES: u64 = 1 << 20;

/// IPv4 space that can never be a pool address (network, length): "this
/// network", loopback, link-local, multicast, reserved/broadcast.
const NEVER_TRANSLATABLE_V4: [(u32, u8); 5] =
    [(0x0000_0000, 8), (0x7f00_0000, 8), (0xa9fe_0000, 16), (0xe000_0000, 4), (0xf000_0000, 4)];

/// RFC 6890 Global=False IPv4 blocks beyond [`NEVER_TRANSLATABLE_V4`]
/// (mirrors `plat_xlat::rfc6052::is_non_global_v4`). 192.0.0.0/24 is
/// handled separately because .9 and .10 are global.
const NON_GLOBAL_V4: [(u32, u8); 8] = [
    (0x0a00_0000, 8),
    (0x6440_0000, 10),
    (0xac10_0000, 12),
    (0xc000_0200, 24),
    (0xc0a8_0000, 16),
    (0xc612_0000, 15),
    (0xc633_6400, 24),
    (0xcb00_7100, 24),
];

/// The RFC 6052 Well-Known Prefix 64:ff9b::/96.
const WKP: u128 = 0x0064_ff9b_0000_0000_0000_0000_0000_0000;

/// True if `p` holds any RFC 6890 non-global address.
fn has_non_global4(p: &Ipv4Cidr) -> bool {
    if NEVER_TRANSLATABLE_V4.iter().chain(&NON_GLOBAL_V4).any(|&(net, len)| overlaps4(p, net, len)) {
        return true;
    }
    // 192.0.0.0/24 is non-global except the PCP/TURN anycast /32s.
    overlaps4(p, 0xc000_0000, 24)
        && !(p.prefix_len() == 32 && (p.network() == 0xc000_0009 || p.network() == 0xc000_000a))
}

fn overlaps4(p: &Ipv4Cidr, net: u32, len: u8) -> bool {
    let common = p.prefix_len().min(len);
    let m = if common == 0 { 0 } else { u32::MAX << (32 - common) };
    p.network() & m == net & m
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(msg.into()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub node: NodeConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
    pub translation: TranslationConfig,
    pub nat64: Nat64Config,
    #[serde(default)]
    pub timeouts: Timeouts,
    #[serde(default)]
    pub dataplane: DataplaneConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub management: ManagementConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Cluster node index, `0 .. cluster.node_count`.
    #[serde(default)]
    pub id: u16,
    /// Name written to every audit record (`observer.name`).
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfig {
    /// Number of PLAT nodes sharing `nat64.pool`. Each node owns a disjoint,
    /// contiguous slice of the pool so return traffic is routed to the owner
    /// without any cross-node state.
    pub node_count: u16,
    /// Explicit override of the pool slice this node owns.
    #[serde(default)]
    pub owned_pool: Vec<Ipv4Cidr>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self { node_count: 1, owned_pool: Vec::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationConfig {
    /// RFC 6052 prefix; length one of 32, 40, 48, 56, 64, 96.
    pub nat64_prefix: Ipv6Cidr,
    /// IPv6 source prefixes allowed to use the translator (CLAT/customer space).
    pub client_prefixes: Vec<Ipv6Cidr>,
    #[serde(default = "default_mtu")]
    pub ipv6_mtu: u16,
    #[serde(default = "default_mtu")]
    pub ipv4_mtu: u16,
    /// RFC 7915 §4 "lowest-ipv6-mtu": IPv4 packets with DF=0 whose IPv6
    /// translation is larger than this are fragmented to fit. Default 1280
    /// (the IPv6 minimum MTU); raise only if the IPv6 path MTU is known.
    #[serde(default = "d_lowest_ipv6_mtu")]
    pub lowest_ipv6_mtu: u16,
    /// Locally generated ICMP errors (Packet Too Big / Fragmentation Needed)
    /// per second per worker; 0 disables generation.
    #[serde(default = "d_icmp_rate")]
    pub icmp_errors_per_sec: u32,
    /// RFC 7915 §4.1/§5.1: copy TOS / Traffic Class (default) or zero it.
    #[serde(default = "d_true")]
    pub copy_tos: bool,
    /// Translate ICMPv4 errors whose source is non-global IPv4 space (e.g. a
    /// router with an RFC 1918 address) while using the Well-Known Prefix.
    /// RFC 6052 §3.1 forbids this, so the default is `false`; enabling it is
    /// a documented deviation that keeps traceroute/PMTUD hops visible.
    #[serde(default)]
    pub wkp_non_global_icmp_errors: bool,
    /// Let subscribers reach non-global IPv4 destinations (RFC 6890
    /// Global=False: RFC 1918, 100.64/10, 198.18/15, documentation ranges,
    /// ...) through a network-specific prefix. Default `false`: denied
    /// under every prefix. The Well-Known Prefix always denies them (RFC
    /// 6052 §3.1), and never-translatable space is always denied.
    ///
    /// While denied, non-global IPv4 *sources* of inbound data packets are
    /// refused too (ICMP errors from non-global routers are still
    /// translated under a network-specific prefix). The cluster's own
    /// `nat64.pool` is exempt in both directions, so a non-global pool still
    /// hairpins (RFC 6146 §3.8); the WKP cannot be combined with a
    /// non-global pool.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-7, SC-7(5) - deny by default at the boundary
    #[serde(default)]
    pub allow_non_global_destinations: bool,
}

fn default_mtu() -> u16 {
    1500
}
fn d_lowest_ipv6_mtu() -> u16 {
    1280
}
fn d_icmp_rate() -> u32 {
    100
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Filtering {
    /// RFC 4787 EIF: any IPv4 host may reach an existing binding.
    EndpointIndependent,
    /// RFC 4787 ADF (RFC 6146 default): only addresses the client contacted.
    AddressDependent,
    /// RFC 4787 APDF: only exact address+port the client contacted.
    AddressPortDependent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nat64Config {
    pub pool: Vec<Ipv4Cidr>,
    #[serde(default = "d_port_min")]
    pub port_min: u16,
    #[serde(default = "d_port_max")]
    pub port_max: u16,
    /// Ports per bulk allocation (RFC 6888 / RFC 7422 port block).
    #[serde(default = "d_block")]
    pub port_block_size: u16,
    #[serde(default = "d_max_blocks")]
    pub max_blocks_per_subscriber: u16,
    /// IPv6 prefix length that identifies one subscriber (CLAT).
    #[serde(default = "d_sub_len")]
    pub subscriber_prefix_len: u8,
    /// RFC 4787 REQ-2: keep every block of a subscriber on one IPv4 address.
    #[serde(default = "d_true")]
    pub paired_pooling: bool,
    #[serde(default = "d_filtering")]
    pub filtering: Filtering,
    #[serde(default = "d_max_sessions")]
    pub max_sessions: u64,
    #[serde(default = "d_max_sessions_sub")]
    pub max_sessions_per_subscriber: u32,
    /// Upper bound on distinct subscribers (subscriber-table entries).
    #[serde(default = "d_max_subs")]
    pub max_subscribers: u32,
    /// Lock shards per table; rounded up to a power of two.
    #[serde(default = "d_shards")]
    pub table_shards: u32,
}

fn d_port_min() -> u16 {
    1024
}
fn d_port_max() -> u16 {
    65535
}
fn d_block() -> u16 {
    512
}
fn d_max_blocks() -> u16 {
    4
}
fn d_sub_len() -> u8 {
    64
}
fn d_true() -> bool {
    true
}
fn d_filtering() -> Filtering {
    Filtering::AddressDependent
}
fn d_max_sessions() -> u64 {
    4_000_000
}
fn d_max_sessions_sub() -> u32 {
    4000
}
fn d_max_subs() -> u32 {
    1_000_000
}
/// Upper bound accepted for `nat64.max_subscribers`.
pub const MAX_SUBSCRIBERS: u32 = 1 << 24;
fn d_shards() -> u32 {
    1024
}

/// Idle timers. Minimums follow RFC 6146 §4.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timeouts {
    pub udp_secs: u32,
    pub tcp_established_secs: u32,
    pub tcp_transitory_secs: u32,
    pub icmp_secs: u32,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { udp_secs: 300, tcp_established_secs: 7440, tcp_transitory_secs: 240, icmp_secs: 60 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataplaneConfig {
    pub interface: String,
    /// Worker threads; 0 = one per available CPU.
    pub workers: usize,
    pub pin_cpus: bool,
    pub sweep_interval_ms: u64,
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self { interface: "plat0".into(), workers: 0, pin_cpus: true, sweep_interval_ms: 1000 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    /// One record per port-block allocate/release (RFC 6888 §4 / RFC 7422).
    PortBlock,
    /// Port-block records plus one record per BIB create/delete.
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverflowPolicy {
    /// Keep forwarding; count lost records and raise an alert record.
    DropAndAlert,
    /// Refuse new bindings while attribution records cannot be queued.
    RefuseNewBindings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Json,
    Cef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyslogTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default = "d_audit_mode")]
    pub mode: AuditMode,
    #[serde(default = "d_queue")]
    pub queue_capacity: usize,
    #[serde(default = "d_overflow")]
    pub on_overflow: OverflowPolicy,
    #[serde(default = "d_batch")]
    pub batch_max: usize,
    #[serde(default = "d_flush")]
    pub flush_interval_ms: u64,
    /// Interval for drop/counter summary records (0 disables).
    #[serde(default = "d_summary")]
    pub summary_interval_secs: u64,
    pub file: Option<AuditFileConfig>,
    #[serde(default)]
    pub syslog: Vec<SyslogConfig>,
}

fn d_audit_mode() -> AuditMode {
    AuditMode::PortBlock
}
fn d_queue() -> usize {
    1 << 20
}
fn d_overflow() -> OverflowPolicy {
    OverflowPolicy::RefuseNewBindings
}
fn d_batch() -> usize {
    4096
}
fn d_flush() -> u64 {
    100
}
fn d_summary() -> u64 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFileConfig {
    pub path: PathBuf,
    #[serde(default = "d_max_bytes")]
    pub max_bytes: u64,
    /// Rotated files kept next to the live file (`<path>.<µs>`); the oldest
    /// are deleted beyond this. 0 keeps every file (archive externally).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-4 (Audit Log Storage Capacity), AU-11 (Retention)
    #[serde(default)]
    pub max_files: u32,
    /// Free space (bytes) the log volume must keep. Below it the pipeline
    /// is degraded (new bindings refused under `refuse_new_bindings`,
    /// `/healthz` 503) and an `audit_storage_threshold` record is written,
    /// while records keep being written. 0 disables the check. If free
    /// space cannot be determined (`statvfs` fails), the check fails closed
    /// the same way (state `unknown`).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-5(1) (Storage Capacity Warning), AU-4
    // POAM: POAM-020 defaults to 0 (storage-capacity warning off); the SSP
    // must require a non-zero value.
    #[serde(default)]
    pub min_free_bytes: u64,
}

fn d_max_bytes() -> u64 {
    1 << 30
}

/// Largest accepted `audit.file.max_files`.
pub const MAX_AUDIT_FILES: u32 = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogConfig {
    pub address: SocketAddr,
    #[serde(default = "d_transport")]
    pub transport: SyslogTransport,
    #[serde(default = "d_format")]
    pub format: LogFormat,
    #[serde(default = "d_app")]
    pub app_name: String,
}

fn d_transport() -> SyslogTransport {
    SyslogTransport::Udp
}
fn d_format() -> LogFormat {
    LogFormat::Json
}
fn d_app() -> String {
    "platd".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementConfig {
    /// Read-only metrics/health listener. Must be a loopback address.
    pub listen: Option<SocketAddr>,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self { listen: Some(SocketAddr::from(([127, 0, 0, 1], 9464))) }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.into(), e))?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let t = &self.translation;
        let n = &self.nat64;

        if self.node.name.is_empty() || self.node.name.len() > 64 {
            return invalid("node.name must be 1..=64 characters");
        }
        if !self.node.name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
            return invalid("node.name may only contain [A-Za-z0-9-_.]");
        }
        if self.cluster.node_count == 0 || self.node.id >= self.cluster.node_count {
            return invalid("node.id must be < cluster.node_count");
        }

        // RFC 6052 §2.2 prefix lengths; bits 64..71 must be zero.
        if ![32, 40, 48, 56, 64, 96].contains(&t.nat64_prefix.prefix_len()) {
            return invalid("translation.nat64_prefix length must be 32/40/48/56/64/96");
        }
        if (t.nat64_prefix.network() >> 56) & 0xff != 0 {
            return invalid("translation.nat64_prefix bits 64-71 (u-octet) must be zero");
        }
        if t.client_prefixes.is_empty() {
            return invalid("translation.client_prefixes must list at least one prefix (SC-7)");
        }
        if t.ipv6_mtu < 1280 || t.ipv4_mtu < 576 {
            return invalid("translation MTUs must be >= 1280 (IPv6) and >= 576 (IPv4)");
        }
        if t.lowest_ipv6_mtu < 1280 || t.lowest_ipv6_mtu > t.ipv6_mtu {
            return invalid("translation.lowest_ipv6_mtu must be 1280..=ipv6_mtu");
        }
        if t.icmp_errors_per_sec > 100_000 {
            return invalid("translation.icmp_errors_per_sec must be <= 100000");
        }
        // SC-7: a client prefix is a subscriber aggregate, never "everything",
        // and must not overlap the NAT64 prefix (which would let synthesized
        // addresses act as clients).
        for c in &t.client_prefixes {
            if c.prefix_len() < 16 {
                return invalid(format!("translation.client_prefixes entry {c} is shorter than /16"));
            }
            let common = c.prefix_len().min(t.nat64_prefix.prefix_len());
            let m = Ipv6Cidr::mask_of(common);
            if c.network() & m == t.nat64_prefix.network() & m {
                return invalid(format!("translation.client_prefixes entry {c} overlaps nat64_prefix"));
            }
        }

        if n.pool.is_empty() {
            return invalid("nat64.pool must not be empty");
        }
        for p in &n.pool {
            if NEVER_TRANSLATABLE_V4.iter().any(|&(net, len)| overlaps4(p, net, len)) {
                return invalid(format!("nat64.pool {p} intersects never-translatable IPv4 space"));
            }
        }
        // COMPLIANCE MAPPING:
        // - RFC 6052 §3.1 - the WKP must not represent non-global IPv4
        //   space, so a non-global pool cannot be used with it (hairpinning
        //   would need exactly that representation; RFC-201).
        if t.nat64_prefix.prefix_len() == 96
            && t.nat64_prefix.network() == WKP
            && let Some(p) = n.pool.iter().find(|p| has_non_global4(p))
        {
            return invalid(format!(
                "nat64.pool {p} holds non-global IPv4 space, which the Well-Known Prefix must not represent \
                 (RFC 6052 §3.1); use a network-specific prefix"
            ));
        }
        let pool_size: u64 = n.pool.iter().map(|p| p.size()).sum();
        if pool_size > MAX_POOL_ADDRS {
            return invalid(format!("nat64.pool has {pool_size} addresses; maximum is {MAX_POOL_ADDRS}"));
        }
        for c in &self.cluster.owned_pool {
            if !n.pool.iter().any(|p| p.prefix_len() <= c.prefix_len() && p.contains(c.network())) {
                return invalid(format!("cluster.owned_pool {c} is not inside nat64.pool"));
            }
        }
        if n.port_min < 1024 || n.port_min > n.port_max {
            return invalid("nat64.port_min must be >= 1024 and <= port_max");
        }
        let range = u32::from(n.port_max) - u32::from(n.port_min) + 1;
        if n.port_block_size < 64 || u32::from(n.port_block_size) > range {
            return invalid("nat64.port_block_size must be in 64..=port range");
        }
        if n.max_blocks_per_subscriber == 0 {
            return invalid("nat64.max_blocks_per_subscriber must be > 0");
        }
        if !(32..=128).contains(&n.subscriber_prefix_len) {
            return invalid("nat64.subscriber_prefix_len must be 32..=128");
        }
        if n.max_sessions == 0 || n.max_sessions_per_subscriber == 0 {
            return invalid("nat64 session limits must be > 0");
        }
        if n.max_subscribers == 0 || n.max_subscribers > MAX_SUBSCRIBERS {
            return invalid(format!("nat64.max_subscribers must be 1..={MAX_SUBSCRIBERS}"));
        }
        if n.table_shards == 0 || n.table_shards > 1 << 16 {
            return invalid("nat64.table_shards must be 1..=65536");
        }

        let to = &self.timeouts;
        if to.udp_secs < 120 || to.tcp_established_secs < 7440 || to.tcp_transitory_secs < 240 {
            return invalid("timeouts below RFC 6146 minimums (udp 120, tcp_est 7440, tcp_trans 240)");
        }
        // RFC 6146 §4: ICMP query timeout minimum 60 s.
        if to.icmp_secs < 60 {
            return invalid("timeouts.icmp_secs must be >= 60 (RFC 6146)");
        }
        // SC-5: upper bounds keep idle state from being held indefinitely.
        if to.udp_secs > MAX_TIMEOUT_SECS
            || to.tcp_established_secs > MAX_TIMEOUT_SECS
            || to.tcp_transitory_secs > MAX_TIMEOUT_SECS
            || to.icmp_secs > MAX_TIMEOUT_SECS
        {
            return invalid(format!("timeouts must be <= {MAX_TIMEOUT_SECS} s"));
        }

        let a = &self.audit;
        if !(1024..=1 << 26).contains(&a.queue_capacity) {
            return invalid("audit.queue_capacity must be 1024..=67108864");
        }
        if a.batch_max == 0 || a.flush_interval_ms == 0 {
            return invalid("audit.batch_max and flush_interval_ms must be > 0");
        }
        if a.file.is_none() && a.syslog.is_empty() {
            return invalid("audit requires at least one destination (file or syslog) (AU-12)");
        }
        // COMPLIANCE MAPPING:
        // - NIST 800-53: AU-5, AU-9 - fail-closed is driven by the local file
        //   (syslog delivery is best-effort), so refuse_new_bindings without
        //   a file would never refuse anything.
        if a.on_overflow == OverflowPolicy::RefuseNewBindings && a.file.is_none() {
            return invalid("audit.on_overflow = \"refuse_new_bindings\" requires [audit.file] (AU-5)");
        }
        if a.file.as_ref().is_some_and(|f| f.max_bytes < MIN_FILE_BYTES) {
            return invalid("audit.file.max_bytes must be >= 1048576");
        }
        if a.file.as_ref().is_some_and(|f| f.max_files > MAX_AUDIT_FILES) {
            return invalid(format!("audit.file.max_files must be 0 (keep all) or 1..={MAX_AUDIT_FILES}"));
        }
        if a.file.as_ref().is_some_and(|f| f.min_free_bytes != 0 && f.min_free_bytes < MIN_FILE_BYTES) {
            return invalid("audit.file.min_free_bytes must be 0 (disabled) or >= 1048576");
        }
        // RFC 5424 §6.2.5 APP-NAME: 1*48PRINTUSASCII.
        for sl in &a.syslog {
            if sl.app_name.is_empty()
                || sl.app_name.len() > 48
                || !sl.app_name.bytes().all(|b| (b'!'..=b'~').contains(&b))
            {
                return invalid("audit.syslog.app_name must be 1..=48 printable US-ASCII characters, no spaces");
            }
        }

        // POAM: POAM-004 remote management requires mTLS (AC-17, SC-8); until it
        // exists the listener is restricted to loopback.
        if self.management.listen.is_some_and(|l| !l.ip().is_loopback()) {
            return invalid("management.listen must be a loopback address");
        }
        if self.dataplane.sweep_interval_ms == 0 || self.dataplane.sweep_interval_ms > MAX_SWEEP_INTERVAL_MS {
            return invalid(format!("dataplane.sweep_interval_ms must be 1..={MAX_SWEEP_INTERVAL_MS}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const EXAMPLE: &str = include_str!("../../../config/platd.example.toml");

    #[test]
    fn example_config_validates() {
        let c = Config::from_toml(EXAMPLE).unwrap();
        assert_eq!(c.nat64.filtering, Filtering::AddressDependent);
        assert_eq!(c.audit.on_overflow, OverflowPolicy::RefuseNewBindings);
    }

    #[test]
    fn rejects_short_udp_timeout() {
        let bad = EXAMPLE.replace("udp_secs = 300", "udp_secs = 30");
        assert!(matches!(Config::from_toml(&bad), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_remote_management() {
        let bad = EXAMPLE.replace("127.0.0.1:9464", "0.0.0.0:9464");
        assert!(matches!(Config::from_toml(&bad), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_unknown_keys() {
        let bad = format!("{EXAMPLE}\n[bogus]\nx = 1\n");
        assert!(matches!(Config::from_toml(&bad), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn rejects_bad_prefix_len() {
        let bad = EXAMPLE.replace("64:ff9b:1::/96", "64:ff9b:1::/80");
        assert!(matches!(Config::from_toml(&bad), Err(ConfigError::Invalid(_))));
    }
}
