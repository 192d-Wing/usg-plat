//! Daemon configuration (TOML), with validation at load time.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-6 (Configuration Settings) - secure defaults, every
//!   value range-checked before the data plane starts.
//! - NIST 800-53: CM-7 (Least Functionality) - plaintext management only on
//!   loopback; any other address requires `[management.tls]` (mutual TLS).
//! - NIST 800-53: SC-8, SC-13, IA-5(2) - TLS settings (`[tls]`,
//!   `[audit.syslog.tls]`, `[management.tls]`) are statically validated
//!   here; certificate/key files are loaded and permission-checked by
//!   `plat-tls` in `check-config` and at start.
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - every table has a
//!   limit: subscribers (`nat64.max_subscribers`), port blocks per subscriber,
//!   sessions (global and per subscriber), pool size, audit queue. BIB
//!   entries are bounded by the ports those limits allow.
//! - NIST 800-53: SC-10 (Network Disconnect) - idle timers have RFC minimums.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::net::{HttpUrl, Ipv4Cidr, Ipv6Cidr, is_dns_name};

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
    /// Process-wide TLS policy (FIPS, key exchange, revocation).
    #[serde(default)]
    pub tls: TlsConfig,
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
    /// `contiguous` (default, legacy) or `slices` (required for HA).
    #[serde(default = "d_partition")]
    pub partition: Partition,
    /// Slice size for `partition = "slices"` (16..=32).
    #[serde(default = "d_slice_len")]
    pub slice_prefix_len: u8,
    /// Full member list; required for HA. `node_count` must equal its length.
    #[serde(default)]
    pub members: Vec<ClusterMember>,
    #[serde(default)]
    pub ha: Option<HaConfig>,
    #[serde(default)]
    pub steering: SteeringConfig,
}

fn d_partition() -> Partition {
    Partition::Contiguous
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_count: 1,
            owned_pool: Vec::new(),
            partition: Partition::Contiguous,
            slice_prefix_len: d_slice_len(),
            members: Vec::new(),
            ha: None,
            steering: SteeringConfig::default(),
        }
    }
}

impl ClusterConfig {
    /// True if `[cluster.ha]` is present and `enabled = true`.
    pub fn ha_enabled(&self) -> bool {
        self.ha.as_ref().is_some_and(|h| h.enabled)
    }

    /// The HA settings when HA is enabled.
    pub fn ha_active(&self) -> Option<&HaConfig> {
        self.ha.as_ref().filter(|h| h.enabled)
    }

    /// Steering mode in effect: the configured one, else `drop` with HA and
    /// `count` (legacy) without.
    pub fn steering_mode(&self) -> SteeringMode {
        self.steering.mode.unwrap_or(if self.ha_enabled() { SteeringMode::Drop } else { SteeringMode::Count })
    }

    /// Automatic failover in effect. Off without HA. With HA: the configured
    /// value, else on when a quorum can be formed without the failed node
    /// (three or more members, or two members plus a witness).
    pub fn auto_failover(&self) -> bool {
        match self.ha_active() {
            None => false,
            Some(h) => h.auto_failover.unwrap_or_else(|| self.quorum_tolerates_loss()),
        }
    }

    /// True if a majority of voters (members plus witness) survives the loss
    /// of one member.
    pub fn quorum_tolerates_loss(&self) -> bool {
        let witness = self.ha.as_ref().is_some_and(|h| h.witness.is_some());
        let voters = self.members.len() + usize::from(witness);
        voters >= 3
    }

    /// Number of slices `pool` splits into at `slice_prefix_len` (0 if a pool
    /// entry is narrower than a slice).
    pub fn slice_count(&self, pool: &[Ipv4Cidr]) -> u64 {
        pool.iter()
            .map(|p| {
                if p.prefix_len() > self.slice_prefix_len {
                    0
                } else {
                    1u64 << (self.slice_prefix_len - p.prefix_len())
                }
            })
            .sum()
    }
}

/// How `nat64.pool` is divided among the nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Partition {
    /// Legacy: each node owns one contiguous share (or `owned_pool`).
    Contiguous,
    /// Aligned slices of `slice_prefix_len`, assigned by rendezvous hashing
    /// over the live members (required for HA).
    Slices,
}

impl Partition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contiguous => "contiguous",
            Self::Slices => "slices",
        }
    }
}

fn d_slice_len() -> u8 {
    28
}

/// Largest accepted slice count (`nat64.pool` split at `slice_prefix_len`).
pub const MAX_SLICES: u64 = 4096;
/// Largest accepted `[[cluster.members]]` list.
pub const MAX_CLUSTER_MEMBERS: usize = 64;

/// One cluster member (all nodes carry the same list).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: IA-3 (Device Identification and Authentication) - the peer
///   certificate must match `identity`, and the claimed `id` must match it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterMember {
    /// Node id, `0 .. members.len()`; equals that node's `node.id`.
    pub id: u16,
    /// That node's `node.name`.
    pub name: String,
    /// Address the member's peer listener is reached at (source IP of its
    /// connections is pinned to it).
    pub peer_addr: SocketAddr,
    /// Typed certificate identity (`cn:`, `dns:`, `uri:`, `sha256:`).
    pub identity: String,
    /// Rendezvous weight, 1..=100.
    #[serde(default = "d_weight")]
    pub weight: u16,
    /// IPv6 address for mis-steer forwarding (`steering.mode = "forward"`,
    /// phase 2; rejected until then).
    #[serde(default)]
    pub steer_addr: Option<std::net::Ipv6Addr>,
}

fn d_weight() -> u16 {
    1
}

/// Tie-breaking voter for two-node clusters (`platd witness`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessConfig {
    pub addr: SocketAddr,
    /// Typed certificate identity; distinct from every member identity.
    pub identity: String,
}

/// Cluster high availability: replication, leases and failover. Absent or
/// `enabled = false`: no replication and no peer listener.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: CP-7, CP-10 (alternate processing within the cluster)
/// - NIST 800-53: SC-5 - rings, queues and frames are bounded
/// - NIST 800-53: SC-24 - leases with a drift margin; minority self-fences
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Peer listener. Not a wildcard address unless `allow_wildcard`.
    pub listen: SocketAddr,
    #[serde(default)]
    pub allow_wildcard: bool,
    #[serde(default)]
    pub witness: Option<WitnessConfig>,
    /// Unset: on when a quorum survives one member loss (see
    /// [`ClusterConfig::auto_failover`]). `true` is rejected without one.
    #[serde(default)]
    pub auto_failover: Option<bool>,
    #[serde(default = "d_lease")]
    pub lease_ms: u64,
    #[serde(default = "d_heartbeat")]
    pub heartbeat_ms: u64,
    /// Clock-rate drift margin applied to leases (plus 200 ms).
    #[serde(default = "d_drift")]
    pub drift_margin_pct: u8,
    /// TCP pickup window on adopted BIBs after takeover (0 disables).
    #[serde(default = "d_tcp_adopt")]
    pub tcp_adopt_secs: u32,
    /// Hold-back for reserved-but-unlogged blocks after takeover.
    #[serde(default = "d_quarantine")]
    pub takeover_quarantine_secs: u32,
    #[serde(default = "d_reserve")]
    pub reserve_ahead_blocks: u16,
    /// Automatic failback delay (0 = manual failback).
    #[serde(default = "d_failback")]
    pub failback_delay_secs: u32,
    #[serde(default = "d_handovers")]
    pub max_concurrent_handovers: u16,
    /// Per-worker replication ring entries (power of two).
    #[serde(default = "d_ring")]
    pub repl_ring_entries: u32,
    #[serde(default = "d_peer_queue")]
    pub peer_queue_bytes: u64,
    #[serde(default = "d_frame")]
    pub max_frame_bytes: u32,
    /// Persistent epoch/vote state (absolute; 0700, checked at start).
    #[serde(default = "d_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "d_hook_timeout")]
    pub hook_timeout_ms: u64,
    /// Bound on the coordinated handover at shutdown.
    #[serde(default = "d_shutdown_handover")]
    pub shutdown_handover_ms: u64,
    #[serde(default)]
    pub hooks: HooksConfig,
    pub tls: ClusterTlsConfig,
}

fn d_lease() -> u64 {
    3000
}
fn d_heartbeat() -> u64 {
    500
}
fn d_drift() -> u8 {
    10
}
fn d_tcp_adopt() -> u32 {
    300
}
fn d_quarantine() -> u32 {
    600
}
fn d_reserve() -> u16 {
    8
}
fn d_failback() -> u32 {
    60
}
fn d_handovers() -> u16 {
    4
}
fn d_ring() -> u32 {
    65_536
}
fn d_peer_queue() -> u64 {
    64 << 20
}
fn d_frame() -> u32 {
    1 << 20
}
fn d_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/plat/cluster")
}
fn d_hook_timeout() -> u64 {
    5000
}
fn d_shutdown_handover() -> u64 {
    10_000
}

/// Largest accepted `cluster.ha.repl_ring_entries`.
pub const MAX_REPL_RING_ENTRIES: u32 = 1 << 20;
/// Largest accepted `cluster.ha.peer_queue_bytes`.
pub const MAX_PEER_QUEUE_BYTES: u64 = 1 << 30;
/// Largest accepted `cluster.ha.max_frame_bytes`.
pub const MAX_FRAME_BYTES: u32 = 16 << 20;

/// Out-of-process route hooks, run as `<hook> <slice-cidr> <epoch> <reason>`.
/// Ownership and mode are checked at start like key files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksConfig {
    pub announce: Option<PathBuf>,
    pub withdraw: Option<PathBuf>,
}

/// Mutual TLS for the peer channel: one identity for the server and client
/// roles, one CA, client certificate always required. FIPS policy from `[tls]`.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-8, SC-8(1), SC-13, IA-3, IA-5(2)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterTlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub ca_file: PathBuf,
    /// Replaces `[tls.revocation]` for peer chains.
    #[serde(default)]
    pub revocation: Option<RevocationConfig>,
}

/// What to do with a new subscriber homed on another node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SteeringMode {
    /// Count and allocate locally (legacy; subscriber becomes dual-homed).
    Count,
    /// Count and drop (`missteered`).
    Drop,
    /// Forward to the owner (phase 2; rejected by validation).
    Forward,
}

impl SteeringMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Drop => "drop",
            Self::Forward => "forward",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SteeringConfig {
    /// Unset: `drop` with HA, `count` without.
    #[serde(default)]
    pub mode: Option<SteeringMode>,
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
    /// ICMPv6/ICMPv4 Time Exceeded for packets arriving with Hop Limit/TTL
    /// ≤ 1 (RFC 7915 §4.1/§5.1).
    #[serde(default = "d_true")]
    pub send_time_exceeded: bool,
    /// ICMPv6 Destination Unreachable (Address Unreachable) to a subscriber
    /// when no mapping can be created (RFC 6146 §3.5.1.1).
    #[serde(default = "d_true")]
    pub send_unreachable: bool,
    /// ICMPv4 Host Unreachable / Communication Administratively Prohibited
    /// to IPv4 remotes for inbound UDP/ICMP with no binding or refused by
    /// filtering (RFC 6146 §3.5.2.2 SHOULD). Default `false`: a documented
    /// deviation that keeps the pool from acting as a scanning oracle or
    /// reflector (SC-5, SC-7).
    #[serde(default)]
    pub send_inbound_unreachable: bool,
    /// ICMPv6 Parameter Problem for an active Routing header (RFC 7915 §5.1).
    #[serde(default = "d_true")]
    pub send_param_problem: bool,
    /// ICMPv4 Source Route Failed for an unexpired LSRR/SSRR option
    /// (RFC 7915 §4.1, RFC 1812 §5.2.4.1), only for packets the filter
    /// would admit. Default `false`: source-routed packets are almost always
    /// hostile, so they are dropped silently (SC-5, SC-7).
    #[serde(default)]
    pub send_source_route_failed: bool,
    /// Source address of locally generated ICMPv6 errors (Time Exceeded,
    /// Destination Unreachable, Packet Too Big, Parameter Problem). Unset:
    /// the synthesized destination of the packet the error is about, so a
    /// traceroute hop shows the IPv4 destination's mapped address. Must not
    /// be inside a client prefix or the NAT64 prefix.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 4443 §2.2 - errors sourced from an address of the translator
    #[serde(default)]
    pub icmp_source_v6: Option<std::net::Ipv6Addr>,
    /// Accept wire IPv4 packets whose source is inside another cluster
    /// node's pool slice (cross-node hairpinning, RFC 6146 §3.8). Default
    /// `false`: any source inside `nat64.pool` arriving on the wire is
    /// spoofed (own-node hairpins never touch the wire) and refused as
    /// `src_not_allowed`. When `true`, `cluster_interfaces` must name the
    /// cluster-internal interfaces; `plat-tun-setup.sh` then drops pool
    /// sources arriving on any other interface, and platd refuses to start
    /// unless that guard is in the installed forward policy.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-7, SC-7(5), AC-4 - pool sources accepted only from
    ///   the cluster-internal network (POAM-024)
    #[serde(default)]
    pub cross_node_hairpin: bool,
    /// Interfaces on which pool-sourced IPv4 from peer nodes may arrive
    /// (required, at most 16, when `cross_node_hairpin` is on).
    #[serde(default)]
    pub cluster_interfaces: Vec<String>,
    #[serde(default)]
    pub fragments: FragmentsConfig,
}

/// Policy for fragmented IPv4 UDP datagrams with a zero checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpZeroChecksum {
    /// Reassemble, compute the checksum, translate (RFC 7915 §4.5).
    Reassemble,
    /// Drop (RFC 7915 §4.5 allows it; `fragment` drop reason).
    Drop,
}

/// Per-worker fragment handling limits (`[translation.fragments]`).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - every fragment structure is preallocated at
///   worker start and bounded by these limits
/// - RFC 6146 §3.4 - FRAGMENT_MIN (2 s) is the lowest accepted timeout
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentsConfig {
    /// Fragment-table entries per worker (rounded up to a power of two).
    #[serde(default = "d_frag_entries")]
    pub max_entries: u32,
    #[serde(default = "d_frag_timeout")]
    pub timeout_ms: u32,
    #[serde(default = "d_frag_per_dgram")]
    pub max_fragments_per_datagram: u16,
    /// Out-of-order buffer slots (non-first fragments seen before their
    /// first fragment); 0 disables buffering.
    #[serde(default = "d_frag_buffered")]
    pub max_buffered_fragments: u16,
    #[serde(default = "d_frag_slot")]
    pub buffer_slot_bytes: u16,
    /// Concurrent reassemblies (fragmented ICMP and zero-checksum UDP); 0
    /// drops those classes as `fragment`.
    #[serde(default = "d_reasm_slots")]
    pub reassembly_slots: u16,
    #[serde(default = "d_reasm_bytes")]
    pub max_reassembly_bytes: u32,
    #[serde(default = "d_udp_zero")]
    pub udp_zero_checksum: UdpZeroChecksum,
}

impl Default for FragmentsConfig {
    fn default() -> Self {
        Self {
            max_entries: d_frag_entries(),
            timeout_ms: d_frag_timeout(),
            max_fragments_per_datagram: d_frag_per_dgram(),
            max_buffered_fragments: d_frag_buffered(),
            buffer_slot_bytes: d_frag_slot(),
            reassembly_slots: d_reasm_slots(),
            max_reassembly_bytes: d_reasm_bytes(),
            udp_zero_checksum: d_udp_zero(),
        }
    }
}

/// Upper bound on one fragment-table entry, used for the memory estimate
/// (the table asserts its entry fits).
pub const FRAG_ENTRY_BYTES: u64 = 160;
/// Bytes in front of and around each reassembly slot (headroom and the
/// largest IPv4 header).
pub const REASM_SLOT_OVERHEAD: u64 = 128;
/// Ceiling on fragment memory per worker (SC-5).
pub const MAX_FRAG_BYTES_PER_WORKER: u64 = 64 << 20;

impl FragmentsConfig {
    /// Entries after power-of-two rounding.
    pub fn entries(&self) -> u32 {
        self.max_entries.next_power_of_two()
    }

    /// Preallocated fragment memory per worker, in bytes.
    pub fn memory_per_worker(&self) -> u64 {
        u64::from(self.entries()) * FRAG_ENTRY_BYTES
            + u64::from(self.max_buffered_fragments) * u64::from(self.buffer_slot_bytes)
            + u64::from(self.reassembly_slots) * (u64::from(self.max_reassembly_bytes) + REASM_SLOT_OVERHEAD)
    }
}

fn d_frag_entries() -> u32 {
    4096
}
fn d_frag_timeout() -> u32 {
    2000
}
fn d_frag_per_dgram() -> u16 {
    64
}
fn d_frag_buffered() -> u16 {
    64
}
fn d_frag_slot() -> u16 {
    1536
}
fn d_reasm_slots() -> u16 {
    4
}
fn d_reasm_bytes() -> u32 {
    65535
}
fn d_udp_zero() -> UdpZeroChecksum {
    UdpZeroChecksum::Reassemble
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
    /// Minimum time a released port block is held back before it can be
    /// allocated again (120..=3600 s).
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 6888 REQ-12, RFC 7422 §2 - attribution windows never abut
    ///   (POAM-010)
    #[serde(default = "d_cooldown")]
    pub block_cooldown_secs: u32,
}

fn d_cooldown() -> u32 {
    120
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
    /// RFC 5425 syslog over TLS 1.3 with octet-counted framing; requires
    /// `[audit.syslog.tls]`.
    Tls,
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
#[serde(from = "RawAuditFileConfig")]
pub struct AuditFileConfig {
    pub path: PathBuf,
    pub max_bytes: u64,
    /// Rotated files kept next to the live file (`<path>.<µs>`); the oldest
    /// are deleted beyond this. 0 keeps every file (archive externally).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-4 (Audit Log Storage Capacity), AU-11 (Retention)
    pub max_files: u32,
    /// Free space (bytes) the log volume must keep. Below it the pipeline
    /// is degraded (new bindings refused under `refuse_new_bindings`,
    /// `/healthz` 503) and an `audit_storage_threshold` record is written,
    /// while records keep being written. If free space cannot be determined
    /// (`statvfs` fails), the check fails closed the same way (state
    /// `unknown`). When omitted it defaults to
    /// [`default_min_free_bytes`]; an explicit 0 is refused by validation
    /// (the warning cannot be switched off).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-5(1) (Storage Capacity Warning), AU-4, CM-6
    pub min_free_bytes: u64,
}

/// On-disk form of [`AuditFileConfig`]: `min_free_bytes` stays optional so
/// its default can depend on `max_bytes`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuditFileConfig {
    path: PathBuf,
    #[serde(default = "d_max_bytes")]
    max_bytes: u64,
    #[serde(default)]
    max_files: u32,
    #[serde(default)]
    min_free_bytes: Option<u64>,
}

impl From<RawAuditFileConfig> for AuditFileConfig {
    fn from(r: RawAuditFileConfig) -> Self {
        let min_free_bytes = r.min_free_bytes.unwrap_or_else(|| default_min_free_bytes(r.max_bytes));
        Self { path: r.path, max_bytes: r.max_bytes, max_files: r.max_files, min_free_bytes }
    }
}

fn d_max_bytes() -> u64 {
    1 << 30
}

/// Default `audit.file.min_free_bytes`: max(2 × `max_bytes`, 1 GiB), so one
/// full rotation still fits after the warning fires (saturating).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-5(1) (Storage Capacity Warning) - on by default
pub fn default_min_free_bytes(max_bytes: u64) -> u64 {
    max_bytes.saturating_mul(2).max(1 << 30)
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
    /// Required when `transport = "tls"`, rejected otherwise.
    #[serde(default)]
    pub tls: Option<SyslogTlsConfig>,
}

/// TLS client settings for one syslog collector (RFC 5425).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-8 (Transmission Confidentiality and Integrity), AU-9(2)
/// - NIST 800-53: IA-3 (Device Identification and Authentication) - the
///   collector certificate is verified against `ca_file` and `server_name`;
///   the optional client certificate authenticates this node to it.
/// - RFC 5425 §5.2 - subject name matching against `server_name`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogTlsConfig {
    /// DNS name or IP address the collector certificate must carry (SAN).
    pub server_name: String,
    /// Trust anchors for the collector chain (PEM). System roots are never used.
    pub ca_file: PathBuf,
    /// Client certificate chain (PEM) for mutual TLS; both or neither with `key_file`.
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// Replaces `[tls.revocation]` for this collector. Gets its own caches
    /// and no background refresher (fetch on demand only).
    pub revocation: Option<RevocationConfig>,
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
    /// Read-only metrics/health listener. Without `tls` it must be a
    /// loopback address (plaintext); with `tls` it may be any address and
    /// is mutual TLS only (no plaintext listener alongside it).
    pub listen: Option<SocketAddr>,
    #[serde(default)]
    pub tls: Option<ManagementTlsConfig>,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self { listen: Some(SocketAddr::from(([127, 0, 0, 1], 9464))), tls: None }
    }
}

/// Mutual-TLS management listener.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-17, AC-17(2) (Remote Access, protection by encryption)
/// - NIST 800-53: IA-3, IA-5(2)(b)(1) - client certificate REQUIRED, chained to
///   `client_ca_file`; AC-3 - identity must be in `allowed_clients`
/// - NIST 800-53: SC-5 - `max_connections`, `max_connections_per_ip`,
///   `handshake_timeout_ms`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementTlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub client_ca_file: PathBuf,
    /// Exact, typed identities allowed to connect: `cn:<subject CN>`,
    /// `dns:<DNS SAN>`, `uri:<URI SAN>` or `sha256:<hex DER fingerprint>`.
    /// No wildcards; untyped entries are a configuration error.
    pub allowed_clients: Vec<String>,
    #[serde(default = "d_mgmt_conns")]
    pub max_connections: u32,
    /// Concurrent connections from one source IP (1..=64; the effective
    /// limit is the smaller of this and `max_connections`).
    #[serde(default = "d_mgmt_conns_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "d_mgmt_handshake")]
    pub handshake_timeout_ms: u64,
}

fn d_mgmt_conns() -> u32 {
    4
}
fn d_mgmt_conns_per_ip() -> u32 {
    2
}
fn d_mgmt_handshake() -> u64 {
    5000
}

/// Largest accepted `management.tls.allowed_clients` list.
pub const MAX_ALLOWED_CLIENTS: usize = 256;
/// Longest accepted `allowed_clients` entry (bytes).
pub const MAX_ALLOWED_CLIENT_LEN: usize = 255;

/// Process-wide TLS policy.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-13 (Cryptographic Protection) - `require_fips`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Offer X25519MLKEM768 first (then P-256, P-384). `false`: P-256/P-384 only.
    #[serde(default = "d_true")]
    pub pq_hybrid: bool,
    /// Refuse to start unless the FIPS module is active (default `true`).
    /// `false` is an explicit operator override, recorded in `service_start`.
    #[serde(default = "d_true")]
    pub require_fips: bool,
    #[serde(default)]
    pub revocation: RevocationConfig,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self { pq_hybrid: true, require_fips: true, revocation: RevocationConfig::default() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationMode {
    /// No conclusive status: reject the chain.
    HardFail,
    /// No status obtainable at all: accept and audit (`source = none`).
    /// Stale data still rejects.
    SoftFail,
    /// Not checked (`status = not_checked`; `check-config` warns).
    Off,
}

impl RevocationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HardFail => "hard_fail",
            Self::SoftFail => "soft_fail",
            Self::Off => "off",
        }
    }
}

/// Certificate revocation checking for every non-root certificate of
/// management client chains and syslog collector chains.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: IA-5(2)(b)(1) (PKI-Based Authentication - path and
///   status validation); IA-5(2)(b)(2) - `cache_dir`, cache sizes
/// - RFC 6960 (OCSP), RFC 5280 §5, §6.3 (CRL)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationConfig {
    #[serde(default = "d_rev_mode")]
    pub mode: RevocationMode,
    #[serde(default = "d_skew")]
    pub clock_skew_secs: u32,
    /// Time budget for the whole chain, per handshake.
    #[serde(default = "d_budget")]
    pub budget_ms: u64,
    /// Optional on-disk CRL cache (absolute, 0700, owned by the service user).
    pub cache_dir: Option<PathBuf>,
    #[serde(default)]
    pub ocsp: OcspConfig,
    #[serde(default)]
    pub crl: CrlConfig,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            mode: d_rev_mode(),
            clock_skew_secs: d_skew(),
            budget_ms: d_budget(),
            cache_dir: None,
            ocsp: OcspConfig::default(),
            crl: CrlConfig::default(),
        }
    }
}

fn d_rev_mode() -> RevocationMode {
    RevocationMode::HardFail
}
fn d_skew() -> u32 {
    300
}
fn d_budget() -> u64 {
    4000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcspMethod {
    Post,
    Get,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcspCertIdHash {
    Sha256,
    /// RFC 5019 lightweight responders.
    Sha1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcspConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// Leaf only; overrides the leaf's AIA responder.
    pub responder_url: Option<String>,
    #[serde(default = "d_true")]
    pub use_aia: bool,
    #[serde(default = "d_ocsp_method")]
    pub method: OcspMethod,
    #[serde(default = "d_ocsp_hash")]
    pub cert_id_hash: OcspCertIdHash,
    #[serde(default = "d_true")]
    pub nonce: bool,
    #[serde(default)]
    pub require_nonce: bool,
    #[serde(default = "d_ocsp_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "d_ocsp_max_age")]
    pub max_age_secs: u32,
    #[serde(default = "d_ocsp_entries")]
    pub cache_entries: u32,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            responder_url: None,
            use_aia: true,
            method: d_ocsp_method(),
            cert_id_hash: d_ocsp_hash(),
            nonce: true,
            require_nonce: false,
            timeout_ms: d_ocsp_timeout(),
            max_age_secs: d_ocsp_max_age(),
            cache_entries: d_ocsp_entries(),
        }
    }
}

fn d_ocsp_method() -> OcspMethod {
    OcspMethod::Post
}
fn d_ocsp_hash() -> OcspCertIdHash {
    OcspCertIdHash::Sha256
}
fn d_ocsp_timeout() -> u64 {
    2000
}
fn d_ocsp_max_age() -> u32 {
    3600
}
fn d_ocsp_entries() -> u32 {
    1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrlConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// Use `http://` fullName URIs from CRL Distribution Points.
    #[serde(default = "d_true")]
    pub use_cdp: bool,
    #[serde(default)]
    pub urls: Vec<String>,
    /// Absolute paths, DER or PEM.
    #[serde(default)]
    pub files: Vec<PathBuf>,
    #[serde(default = "d_crl_timeout")]
    pub timeout_ms: u64,
    /// Per CRL.
    #[serde(default = "d_crl_max_bytes")]
    pub max_bytes: u64,
    /// Estimated memory of all parsed CRLs.
    #[serde(default = "d_crl_cache_bytes")]
    pub cache_bytes: u64,
    #[serde(default = "d_crl_max")]
    pub max_crls: u32,
    #[serde(default = "d_crl_margin")]
    pub refresh_margin_secs: u32,
}

impl Default for CrlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            use_cdp: true,
            urls: Vec::new(),
            files: Vec::new(),
            timeout_ms: d_crl_timeout(),
            max_bytes: d_crl_max_bytes(),
            cache_bytes: d_crl_cache_bytes(),
            max_crls: d_crl_max(),
            refresh_margin_secs: d_crl_margin(),
        }
    }
}

fn d_crl_timeout() -> u64 {
    5000
}
fn d_crl_max_bytes() -> u64 {
    10 << 20
}
fn d_crl_cache_bytes() -> u64 {
    64 << 20
}
fn d_crl_max() -> u32 {
    64
}
fn d_crl_margin() -> u32 {
    3600
}

/// Largest accepted `crl.max_bytes` (one CRL).
pub const MAX_CRL_BYTES: u64 = 64 << 20;
/// Largest accepted `crl.cache_bytes`.
pub const MAX_CRL_CACHE_BYTES: u64 = 1 << 30;

fn check_abs(what: &str, p: &Path) -> Result<(), ConfigError> {
    if p.is_absolute() { Ok(()) } else { invalid(format!("{what} must be an absolute path")) }
}

fn check_url(what: &str, u: &str) -> Result<(), ConfigError> {
    HttpUrl::parse(u).map(|_| ()).map_err(|e| ConfigError::Invalid(format!("{what} {u:?}: {e}")))
}

impl RevocationConfig {
    /// Static checks; `cache_dir` ownership/mode and CRL files are checked
    /// by `plat-tls` at start.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - every cache and fetch is bounded
    pub fn validate(&self, at: &str) -> Result<(), ConfigError> {
        let (o, c) = (&self.ocsp, &self.crl);
        if self.mode != RevocationMode::Off && !o.enabled && !c.enabled {
            return invalid(format!(
                "{at}: ocsp.enabled and crl.enabled are both false; set mode = \"off\" explicitly"
            ));
        }
        if self.clock_skew_secs > 3600 {
            return invalid(format!("{at}.clock_skew_secs must be 0..=3600"));
        }
        if !(500..=20_000).contains(&self.budget_ms) {
            return invalid(format!("{at}.budget_ms must be 500..=20000"));
        }
        if let Some(d) = &self.cache_dir {
            check_abs(&format!("{at}.cache_dir"), d)?;
        }
        if !(200..=10_000).contains(&o.timeout_ms) {
            return invalid(format!("{at}.ocsp.timeout_ms must be 200..=10000"));
        }
        if o.enabled && self.budget_ms < o.timeout_ms {
            return invalid(format!("{at}.budget_ms must be >= ocsp.timeout_ms"));
        }
        if !(60..=604_800).contains(&o.max_age_secs) {
            return invalid(format!("{at}.ocsp.max_age_secs must be 60..=604800"));
        }
        if !(1..=65_536).contains(&o.cache_entries) {
            return invalid(format!("{at}.ocsp.cache_entries must be 1..=65536"));
        }
        if let Some(u) = &o.responder_url {
            check_url(&format!("{at}.ocsp.responder_url"), u)?;
        }
        if o.require_nonce && !o.nonce {
            return invalid(format!("{at}.ocsp.require_nonce needs ocsp.nonce = true"));
        }
        if !(500..=30_000).contains(&c.timeout_ms) {
            return invalid(format!("{at}.crl.timeout_ms must be 500..=30000"));
        }
        if !(1024..=MAX_CRL_BYTES).contains(&c.max_bytes) {
            return invalid(format!("{at}.crl.max_bytes must be 1024..={MAX_CRL_BYTES}"));
        }
        if c.cache_bytes < c.max_bytes || c.cache_bytes > MAX_CRL_CACHE_BYTES {
            return invalid(format!("{at}.crl.cache_bytes must be max_bytes..={MAX_CRL_CACHE_BYTES}"));
        }
        if !(1..=1024).contains(&c.max_crls) {
            return invalid(format!("{at}.crl.max_crls must be 1..=1024"));
        }
        if c.refresh_margin_secs > 604_800 {
            return invalid(format!("{at}.crl.refresh_margin_secs must be 0..=604800"));
        }
        // SC-5: configured sources must fit in the cache they feed.
        if c.urls.len() + c.files.len() > c.max_crls as usize {
            return invalid(format!("{at}.crl: urls + files must not exceed max_crls"));
        }
        for u in &c.urls {
            check_url(&format!("{at}.crl.urls entry"), u)?;
        }
        for f in &c.files {
            check_abs(&format!("{at}.crl.files entry"), f)?;
        }
        Ok(())
    }
}

/// Allow-list entry: printable ASCII or UTF-8 without control characters,
/// no wildcard (matching is exact).
fn check_identity(at: &str, e: &str) -> Result<(), ConfigError> {
    if e.is_empty() || e.len() > MAX_ALLOWED_CLIENT_LEN {
        return invalid(format!("{at} entries must be 1..={MAX_ALLOWED_CLIENT_LEN} bytes"));
    }
    if e.chars().any(char::is_control) || e.trim() != e {
        return invalid(format!("{at} entry {e:?} has control characters or surrounding spaces"));
    }
    if e.contains('*') {
        return invalid(format!("{at} entry {e:?}: wildcards are not supported (exact match)"));
    }
    // Typed entries only: a bare value could match a CN where a SAN was
    // meant (or the reverse).
    let Some((kind, value)) = e.split_once(':') else {
        return invalid(format!("{at} entry {e:?} must be typed: cn:, dns:, uri: or sha256:"));
    };
    if value.is_empty() {
        return invalid(format!("{at} entry {e:?} has an empty value"));
    }
    match kind {
        "cn" | "dns" | "uri" => Ok(()),
        "sha256" if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(()),
        "sha256" => invalid(format!("{at} entry {e:?}: sha256: needs 64 hex digits (certificate DER fingerprint)")),
        _ => invalid(format!("{at} entry {e:?} must be typed: cn:, dns:, uri: or sha256:")),
    }
}

fn check_node_name(at: &str, name: &str) -> Result<(), ConfigError> {
    if name.is_empty() || name.len() > 64 {
        return invalid(format!("{at} must be 1..=64 characters"));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        return invalid(format!("{at} may only contain [A-Za-z0-9-_.]"));
    }
    Ok(())
}

/// A peer address: concrete IP and non-zero port.
fn check_peer_addr(at: &str, a: SocketAddr) -> Result<(), ConfigError> {
    if a.ip().is_unspecified() || a.ip().is_multicast() || a.port() == 0 {
        return invalid(format!("{at} {a} must be a unicast address with a non-zero port"));
    }
    Ok(())
}

fn check_allowed_client(e: &str) -> Result<(), ConfigError> {
    check_identity("management.tls.allowed_clients", e)
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

        check_node_name("node.name", &self.node.name)?;
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
        // SC-5: a quarter of the bucket is reserved for PMTU errors
        // (see the engine token bucket); below 4 it would round to zero.
        if (1..4).contains(&t.icmp_errors_per_sec) {
            return invalid("translation.icmp_errors_per_sec must be 0 (off) or >= 4");
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

        if let Some(a) = t.icmp_source_v6 {
            let v = u128::from(a);
            if a.is_unspecified() || a.is_loopback() || a.is_multicast() {
                return invalid("translation.icmp_source_v6 must be a unicast address");
            }
            // COMPLIANCE MAPPING:
            // - NIST 800-53: SC-7 (Boundary Protection)
            // - RFC 4291 §2.5.5.2/§2.5.6 - link-local and IPv4-mapped
            //   addresses are not valid sources on the wire
            if a.is_unicast_link_local() || a.to_ipv4_mapped().is_some() {
                return invalid("translation.icmp_source_v6 must not be link-local or IPv4-mapped");
            }
            if t.nat64_prefix.contains(v) || t.client_prefixes.iter().any(|c| c.contains(v)) {
                return invalid("translation.icmp_source_v6 must be outside nat64_prefix and client_prefixes");
            }
        }

        // COMPLIANCE MAPPING:
        // - NIST 800-53: SC-7(5), AC-4 - cross-node hairpin needs a named
        //   cluster-internal ingress for the host pool-source guard (POAM-024)
        if t.cross_node_hairpin && t.cluster_interfaces.is_empty() {
            return invalid("translation.cross_node_hairpin requires translation.cluster_interfaces");
        }
        if !t.cross_node_hairpin && !t.cluster_interfaces.is_empty() {
            return invalid("translation.cluster_interfaces is only valid with cross_node_hairpin = true");
        }
        if t.cluster_interfaces.len() > 16 {
            return invalid("translation.cluster_interfaces must list at most 16 interfaces");
        }
        for i in &t.cluster_interfaces {
            if i.is_empty() || i.len() > 15 || !i.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) {
                return invalid(format!("translation.cluster_interfaces entry {i:?} is not a valid interface name"));
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

        self.validate_fragments()?;

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
        if a.file.as_ref().is_some_and(|f| f.min_free_bytes < MIN_FILE_BYTES) {
            // AU-5(1): the storage-capacity warning cannot be disabled.
            return invalid("audit.file.min_free_bytes must be >= 1048576 (0 is refused; omit it for the default)");
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

        for sl in &a.syslog {
            match (sl.transport, &sl.tls) {
                (SyslogTransport::Tls, None) => {
                    return invalid(format!(
                        "audit.syslog {}: transport = \"tls\" requires [audit.syslog.tls]",
                        sl.address
                    ));
                }
                (SyslogTransport::Udp | SyslogTransport::Tcp, Some(_)) => {
                    return invalid(format!(
                        "audit.syslog {}: [audit.syslog.tls] is only valid with transport = \"tls\"",
                        sl.address
                    ));
                }
                (SyslogTransport::Tls, Some(t)) => {
                    // RFC 5425 §5.2: the collector is identified by name.
                    if !is_dns_name(&t.server_name) && t.server_name.parse::<std::net::IpAddr>().is_err() {
                        return invalid(format!(
                            "audit.syslog.tls.server_name {:?} must be a DNS name or IP address",
                            t.server_name
                        ));
                    }
                    check_abs("audit.syslog.tls.ca_file", &t.ca_file)?;
                    match (&t.cert_file, &t.key_file) {
                        (Some(c), Some(k)) => {
                            check_abs("audit.syslog.tls.cert_file", c)?;
                            check_abs("audit.syslog.tls.key_file", k)?;
                        }
                        (None, None) => {}
                        _ => return invalid("audit.syslog.tls.cert_file and key_file must be set together"),
                    }
                    if let Some(r) = &t.revocation {
                        r.validate("audit.syslog.tls.revocation")?;
                    }
                }
                _ => {}
            }
        }

        self.tls.revocation.validate("tls.revocation")?;

        // COMPLIANCE MAPPING:
        // - NIST 800-53: AC-17, SC-8, CM-7 - plaintext management only on
        //   loopback; any other address only with mutual TLS. With
        //   [management.tls] the single listener is mTLS (no plaintext
        //   listener alongside it).
        let m = &self.management;
        match (&m.listen, &m.tls) {
            (Some(l), None) if !l.ip().is_loopback() => {
                return invalid("management.listen must be a loopback address unless [management.tls] is configured");
            }
            (None, Some(_)) => return invalid("[management.tls] requires management.listen"),
            (Some(_), Some(t)) => {
                check_abs("management.tls.cert_file", &t.cert_file)?;
                check_abs("management.tls.key_file", &t.key_file)?;
                check_abs("management.tls.client_ca_file", &t.client_ca_file)?;
                if t.allowed_clients.is_empty() || t.allowed_clients.len() > MAX_ALLOWED_CLIENTS {
                    return invalid(format!(
                        "management.tls.allowed_clients must list 1..={MAX_ALLOWED_CLIENTS} identities"
                    ));
                }
                for e in &t.allowed_clients {
                    check_allowed_client(e)?;
                }
                if !(1..=64).contains(&t.max_connections) {
                    return invalid("management.tls.max_connections must be 1..=64");
                }
                if !(1..=64).contains(&t.max_connections_per_ip) {
                    return invalid("management.tls.max_connections_per_ip must be 1..=64");
                }
                if !(500..=30_000).contains(&t.handshake_timeout_ms) {
                    return invalid("management.tls.handshake_timeout_ms must be 500..=30000");
                }
                let r = &self.tls.revocation;
                if r.mode != RevocationMode::Off && t.handshake_timeout_ms < r.budget_ms + 1000 {
                    return invalid("management.tls.handshake_timeout_ms must be >= tls.revocation.budget_ms + 1000");
                }
            }
            _ => {}
        }
        if self.dataplane.sweep_interval_ms == 0 || self.dataplane.sweep_interval_ms > MAX_SWEEP_INTERVAL_MS {
            return invalid(format!("dataplane.sweep_interval_ms must be 1..={MAX_SWEEP_INTERVAL_MS}"));
        }
        if !(120..=3600).contains(&n.block_cooldown_secs) {
            return invalid("nat64.block_cooldown_secs must be 120..=3600 (RFC 6888 REQ-12)");
        }
        self.validate_cluster()
    }

    /// `[translation.fragments]` ranges and the timeout ordering.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5, CM-6 - bounded, validated fragment limits
    /// - RFC 6146 §3.4 - fragment timeout at least FRAGMENT_MIN (2 s) and
    ///   below the UDP/ICMP session timeouts, so a cached first-fragment
    ///   mapping never outlives an idle session
    fn validate_fragments(&self) -> Result<(), ConfigError> {
        let f = &self.translation.fragments;
        if !(64..=65536).contains(&f.max_entries) {
            return invalid("translation.fragments.max_entries must be 64..=65536");
        }
        if !(2000..=60_000).contains(&f.timeout_ms) {
            return invalid("translation.fragments.timeout_ms must be 2000..=60000 (RFC 6146 FRAGMENT_MIN)");
        }
        let min_session_ms = u64::from(self.timeouts.udp_secs.min(self.timeouts.icmp_secs)) * 1000;
        if u64::from(f.timeout_ms) >= min_session_ms {
            return invalid("translation.fragments.timeout_ms must be below timeouts.udp_secs and icmp_secs");
        }
        if !(2..=128).contains(&f.max_fragments_per_datagram) {
            return invalid("translation.fragments.max_fragments_per_datagram must be 2..=128");
        }
        if f.max_buffered_fragments > 1024 {
            return invalid("translation.fragments.max_buffered_fragments must be 0..=1024");
        }
        if !(1280..=9216).contains(&f.buffer_slot_bytes) {
            return invalid("translation.fragments.buffer_slot_bytes must be 1280..=9216");
        }
        if f.reassembly_slots > 64 {
            return invalid("translation.fragments.reassembly_slots must be 0..=64");
        }
        if !(1280..=65535).contains(&f.max_reassembly_bytes) {
            return invalid("translation.fragments.max_reassembly_bytes must be 1280..=65535");
        }
        let mem = f.memory_per_worker();
        if mem > MAX_FRAG_BYTES_PER_WORKER {
            return invalid(format!(
                "translation.fragments needs {mem} bytes per worker; maximum is {MAX_FRAG_BYTES_PER_WORKER}"
            ));
        }
        Ok(())
    }

    /// Partition, member list, HA and steering rules.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: CM-6 - every cluster value range-checked; HA off unless
    ///   configured
    /// - NIST 800-53: SC-5 - slice count, rings, queues and frames bounded
    /// - NIST 800-53: IA-3, AC-3 - typed, unique peer identities
    /// - NIST 800-53: SC-24 - automatic failover only with a quorum that
    ///   survives one member loss
    fn validate_cluster(&self) -> Result<(), ConfigError> {
        let c = &self.cluster;
        let n = &self.nat64;

        if c.partition == Partition::Slices {
            if !(16..=32).contains(&c.slice_prefix_len) {
                return invalid("cluster.slice_prefix_len must be 16..=32");
            }
            if let Some(p) = n.pool.iter().find(|p| p.prefix_len() > c.slice_prefix_len) {
                return invalid(format!(
                    "nat64.pool {p} is narrower than cluster.slice_prefix_len /{}",
                    c.slice_prefix_len
                ));
            }
            let slices = c.slice_count(&n.pool);
            if slices > MAX_SLICES {
                return invalid(format!(
                    "nat64.pool splits into {slices} slices at /{}; maximum is {MAX_SLICES} \
                     (use a shorter cluster.slice_prefix_len)",
                    c.slice_prefix_len
                ));
            }
            if !c.owned_pool.is_empty() {
                return invalid("cluster.owned_pool cannot be combined with partition = \"slices\"");
            }
        }

        if !c.members.is_empty() {
            if c.members.len() > MAX_CLUSTER_MEMBERS {
                return invalid(format!("cluster.members must list at most {MAX_CLUSTER_MEMBERS} members"));
            }
            if usize::from(c.node_count) != c.members.len() {
                return invalid("cluster.node_count must equal the number of [[cluster.members]]");
            }
            let mut seen = vec![false; c.members.len()];
            for (i, m) in c.members.iter().enumerate() {
                let Some(slot) = seen.get_mut(usize::from(m.id)) else {
                    return invalid(format!("cluster.members id {} must be < {}", m.id, c.members.len()));
                };
                if std::mem::replace(slot, true) {
                    return invalid(format!("cluster.members id {} is listed twice", m.id));
                }
                check_node_name("cluster.members.name", &m.name)?;
                check_identity("cluster.members.identity", &m.identity)?;
                check_peer_addr("cluster.members.peer_addr", m.peer_addr)?;
                if !(1..=100).contains(&m.weight) {
                    return invalid("cluster.members.weight must be 1..=100");
                }
                if m.steer_addr.is_some() && c.steering_mode() != SteeringMode::Forward {
                    return invalid(
                        "cluster.members.steer_addr is only valid with cluster.steering.mode = \"forward\"",
                    );
                }
                for o in &c.members[..i] {
                    if o.name == m.name {
                        return invalid(format!("cluster.members name {:?} is listed twice", m.name));
                    }
                    if o.identity == m.identity {
                        return invalid(format!("cluster.members identity {:?} is listed twice", m.identity));
                    }
                    if o.peer_addr == m.peer_addr {
                        return invalid(format!("cluster.members peer_addr {} is listed twice", m.peer_addr));
                    }
                }
            }
            match c.members.iter().find(|m| m.id == self.node.id) {
                Some(me) if me.name == self.node.name => {}
                _ => return invalid("cluster.members entry for node.id must carry node.name"),
            }
        }

        if c.steering.mode == Some(SteeringMode::Forward) {
            return invalid("cluster.steering.mode = \"forward\" is not supported yet (use \"drop\" or \"count\")");
        }

        let Some(h) = c.ha_active() else {
            return Ok(());
        };
        if c.partition != Partition::Slices {
            return invalid("[cluster.ha] requires cluster.partition = \"slices\"");
        }
        if c.members.len() < 2 {
            return invalid("[cluster.ha] requires at least two [[cluster.members]]");
        }
        if h.listen.port() == 0 {
            return invalid("cluster.ha.listen needs a non-zero port");
        }
        if h.listen.ip().is_unspecified() && !h.allow_wildcard {
            return invalid("cluster.ha.listen must not be a wildcard address unless allow_wildcard = true");
        }
        if let Some(w) = &h.witness {
            check_identity("cluster.ha.witness.identity", &w.identity)?;
            check_peer_addr("cluster.ha.witness.addr", w.addr)?;
            if c.members.iter().any(|m| m.identity == w.identity) {
                return invalid("cluster.ha.witness.identity must differ from every member identity");
            }
            if c.members.iter().any(|m| m.peer_addr == w.addr) {
                return invalid("cluster.ha.witness.addr must differ from every member peer_addr");
            }
        }
        // SC-24: without a third voter a partition cannot be told apart from a
        // peer failure, so both sides would take over.
        if h.auto_failover == Some(true) && !c.quorum_tolerates_loss() {
            return invalid(
                "cluster.ha.auto_failover = true needs three or more members, or two members and a witness",
            );
        }
        if !(1000..=30_000).contains(&h.lease_ms) {
            return invalid("cluster.ha.lease_ms must be 1000..=30000");
        }
        if h.heartbeat_ms < 50 || h.heartbeat_ms > h.lease_ms / 4 {
            return invalid("cluster.ha.heartbeat_ms must be 50..=lease_ms/4");
        }
        if !(1..=50).contains(&h.drift_margin_pct) {
            return invalid("cluster.ha.drift_margin_pct must be 1..=50");
        }
        if h.tcp_adopt_secs > 3600 {
            return invalid("cluster.ha.tcp_adopt_secs must be 0..=3600");
        }
        let to = &self.timeouts;
        let longest = to.udp_secs.max(to.tcp_transitory_secs).max(to.icmp_secs);
        if h.takeover_quarantine_secs < longest || h.takeover_quarantine_secs > MAX_TIMEOUT_SECS {
            return invalid(format!(
                "cluster.ha.takeover_quarantine_secs must be {longest}..={MAX_TIMEOUT_SECS} \
                 (at least the longest udp/tcp_transitory/icmp timeout)"
            ));
        }
        if !(1..=64).contains(&h.reserve_ahead_blocks) {
            return invalid("cluster.ha.reserve_ahead_blocks must be 1..=64");
        }
        if h.failback_delay_secs > 86_400 {
            return invalid("cluster.ha.failback_delay_secs must be 0..=86400");
        }
        if !(1..=64).contains(&h.max_concurrent_handovers) {
            return invalid("cluster.ha.max_concurrent_handovers must be 1..=64");
        }
        if !h.repl_ring_entries.is_power_of_two() || !(1024..=MAX_REPL_RING_ENTRIES).contains(&h.repl_ring_entries) {
            return invalid(format!(
                "cluster.ha.repl_ring_entries must be a power of two in 1024..={MAX_REPL_RING_ENTRIES}"
            ));
        }
        if !(1 << 20..=MAX_PEER_QUEUE_BYTES).contains(&h.peer_queue_bytes) {
            return invalid(format!("cluster.ha.peer_queue_bytes must be 1048576..={MAX_PEER_QUEUE_BYTES}"));
        }
        if !(64 << 10..=MAX_FRAME_BYTES).contains(&h.max_frame_bytes) {
            return invalid(format!("cluster.ha.max_frame_bytes must be 65536..={MAX_FRAME_BYTES}"));
        }
        // A snapshot keeps peer_queue_bytes / 4 in flight; a frame must fit.
        if u64::from(h.max_frame_bytes) > h.peer_queue_bytes / 4 {
            return invalid("cluster.ha.max_frame_bytes must be <= peer_queue_bytes / 4");
        }
        check_abs("cluster.ha.state_dir", &h.state_dir)?;
        if !(100..=60_000).contains(&h.hook_timeout_ms) {
            return invalid("cluster.ha.hook_timeout_ms must be 100..=60000");
        }
        if !(1000..=60_000).contains(&h.shutdown_handover_ms) {
            return invalid("cluster.ha.shutdown_handover_ms must be 1000..=60000");
        }
        if let Some(p) = &h.hooks.announce {
            check_abs("cluster.ha.hooks.announce", p)?;
        }
        if let Some(p) = &h.hooks.withdraw {
            check_abs("cluster.ha.hooks.withdraw", p)?;
        }
        check_abs("cluster.ha.tls.cert_file", &h.tls.cert_file)?;
        check_abs("cluster.ha.tls.key_file", &h.tls.key_file)?;
        check_abs("cluster.ha.tls.ca_file", &h.tls.ca_file)?;
        if let Some(r) = &h.tls.revocation {
            r.validate("cluster.ha.tls.revocation")?;
        }
        Ok(())
    }

    /// True if any TLS endpoint is configured (syslog `transport = "tls"`,
    /// `[management.tls]`, or the cluster peer channel of `[cluster.ha]`).
    /// Builds without the `tls` feature refuse such a config.
    pub fn uses_tls(&self) -> bool {
        self.management.tls.is_some()
            || self.audit.syslog.iter().any(|s| s.transport == SyslogTransport::Tls)
            || self.cluster.ha_enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const EXAMPLE: &str = include_str!("../../../config/platd.example.toml");

    #[test]
    fn cross_node_hairpin_needs_cluster_interfaces() {
        let on = base().replace("cross_node_hairpin = false", "cross_node_hairpin = true");
        assert!(invalid_msg(&on).contains("requires translation.cluster_interfaces"));
        let iface =
            |list: &str| on.replace("# cluster_interfaces = [\"eth1\"]", &format!("cluster_interfaces = [{list}]"));
        let c = Config::from_toml(&iface("\"eth1\", \"bond0.20\"")).unwrap();
        assert!(c.translation.cross_node_hairpin);
        assert_eq!(c.translation.cluster_interfaces, ["eth1", "bond0.20"]);
        assert!(invalid_msg(&iface("\"eth1; drop\"")).contains("not a valid interface name"));
        assert!(invalid_msg(&iface("\"\"")).contains("not a valid interface name"));
        let many = (0..17).map(|i| format!("\"e{i}\"")).collect::<Vec<_>>().join(",");
        assert!(invalid_msg(&iface(&many)).contains("at most 16"));
        let off = base().replace("# cluster_interfaces = [\"eth1\"]", "cluster_interfaces = [\"eth1\"]");
        assert!(invalid_msg(&off).contains("only valid with cross_node_hairpin"));
        assert!(!Config::from_toml(&base()).unwrap().translation.cross_node_hairpin);
    }

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
    fn fragment_limits_are_validated() {
        let c = Config::from_toml(EXAMPLE).unwrap();
        let f = &c.translation.fragments;
        assert_eq!((f.entries(), f.timeout_ms, f.udp_zero_checksum), (4096, 2000, UdpZeroChecksum::Reassemble));
        assert!(f.memory_per_worker() < 2 << 20);
        assert!(!c.translation.send_inbound_unreachable && c.translation.send_time_exceeded);
        for (a, b) in [
            ("max_entries = 4096", "max_entries = 63"),
            ("max_entries = 4096", "max_entries = 65537"),
            ("timeout_ms = 2000", "timeout_ms = 1999"),
            ("timeout_ms = 2000", "timeout_ms = 60001"),
            ("max_fragments_per_datagram = 64", "max_fragments_per_datagram = 1"),
            ("max_fragments_per_datagram = 64", "max_fragments_per_datagram = 129"),
            ("max_buffered_fragments = 64", "max_buffered_fragments = 1025"),
            ("buffer_slot_bytes = 1536", "buffer_slot_bytes = 1279"),
            ("buffer_slot_bytes = 1536", "buffer_slot_bytes = 9217"),
            ("reassembly_slots = 4", "reassembly_slots = 65"),
            ("max_reassembly_bytes = 65535", "max_reassembly_bytes = 1279"),
            ("udp_zero_checksum = \"reassemble\"", "udp_zero_checksum = \"maybe\""),
            ("udp_zero_checksum = \"reassemble\"", "udp_zero_checksum = \"drop\"\nbogus = 1"),
        ] {
            assert!(EXAMPLE.contains(a), "{a}");
            assert!(Config::from_toml(&EXAMPLE.replace(a, b)).is_err(), "{b}");
        }
        // Boundaries accepted; 0 disables buffering / reassembly.
        for (a, b) in [
            ("max_entries = 4096", "max_entries = 65536"),
            ("max_buffered_fragments = 64", "max_buffered_fragments = 0"),
            ("reassembly_slots = 4", "reassembly_slots = 0"),
            ("udp_zero_checksum = \"reassemble\"", "udp_zero_checksum = \"drop\""),
        ] {
            Config::from_toml(&EXAMPLE.replace(a, b)).unwrap();
        }
        // Timeout below the shortest session timeout (icmp 60 s).
        assert!(Config::from_toml(&EXAMPLE.replace("timeout_ms = 2000", "timeout_ms = 60000")).is_err());
        // Every key at its maximum still fits the per-worker ceiling, which
        // stays as a backstop if a range is ever widened.
        let big = EXAMPLE
            .replace("reassembly_slots = 4", "reassembly_slots = 64")
            .replace("max_buffered_fragments = 64", "max_buffered_fragments = 1024")
            .replace("buffer_slot_bytes = 1536", "buffer_slot_bytes = 9216")
            .replace("max_entries = 4096", "max_entries = 65536");
        let m = Config::from_toml(&big).unwrap().translation.fragments.memory_per_worker();
        assert!(m <= MAX_FRAG_BYTES_PER_WORKER && m > 20 << 20, "{m}");
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

    const SYSLOG_UDP: &str = "transport = \"udp\"";
    const SYSLOG_TAIL: &str = "app_name = \"platd\"\n";
    const MGMT: &str = "listen = \"127.0.0.1:9464\"";

    /// The example without its `[tls]` tables, so tests can append their own.
    fn base() -> String {
        EXAMPLE[..EXAMPLE.find("\n[tls]\n").unwrap() + 1].to_owned()
    }

    fn invalid_msg(text: &str) -> String {
        match Config::from_toml(text) {
            Err(ConfigError::Invalid(m)) => m,
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    fn syslog_tls(extra: &str) -> String {
        EXAMPLE.replace(SYSLOG_UDP, "transport = \"tls\"").replace(
            SYSLOG_TAIL,
            &format!(
                "{SYSLOG_TAIL}[audit.syslog.tls]\nserver_name = \"siem.example.net\"\n\
                 ca_file = \"/etc/plat/tls/ca.pem\"\n{extra}\n"
            ),
        )
    }

    fn mgmt_tls(listen: &str, extra: &str) -> String {
        EXAMPLE.replace(
            MGMT,
            &format!(
                "listen = \"{listen}\"\n[management.tls]\ncert_file = \"/etc/plat/tls/m.pem\"\n\
                 key_file = \"/etc/plat/tls/m.key\"\nclient_ca_file = \"/etc/plat/tls/ca.pem\"\n{extra}"
            ),
        )
    }

    fn base_mgmt_tls(listen: &str, extra: &str) -> String {
        let m = mgmt_tls(listen, extra);
        m[..m.find("\n[tls]\n").unwrap() + 1].to_owned()
    }

    #[test]
    fn tls_defaults() {
        let c = Config::from_toml(EXAMPLE).unwrap();
        assert!(c.tls.require_fips && c.tls.pq_hybrid);
        let r = &c.tls.revocation;
        assert_eq!(r.mode, RevocationMode::HardFail);
        assert!(r.ocsp.enabled && r.crl.enabled && r.ocsp.nonce && !r.ocsp.require_nonce);
        assert_eq!((r.budget_ms, r.ocsp.timeout_ms, r.crl.max_crls), (4000, 2000, 64));
        assert!(!c.uses_tls());
        let c = Config::from_toml(&format!("{}\n[tls]\n", base())).unwrap();
        assert!(c.tls.require_fips);
    }

    #[test]
    fn syslog_tls_block_required_iff_tls() {
        let c = Config::from_toml(&syslog_tls("")).unwrap();
        assert_eq!(c.audit.syslog[0].transport, SyslogTransport::Tls);
        assert!(c.uses_tls());
        let m = invalid_msg(&EXAMPLE.replace(SYSLOG_UDP, "transport = \"tls\""));
        assert!(m.contains("requires [audit.syslog.tls]"), "{m}");
        let m = invalid_msg(&syslog_tls("").replace("transport = \"tls\"", "transport = \"tcp\""));
        assert!(m.contains("only valid with transport"), "{m}");
    }

    #[test]
    fn syslog_tls_fields() {
        let ok = syslog_tls("cert_file = \"/etc/plat/c.pem\"\nkey_file = \"/etc/plat/c.key\"");
        Config::from_toml(&ok).unwrap();
        assert!(invalid_msg(&syslog_tls("cert_file = \"/etc/plat/c.pem\"")).contains("set together"));
        assert!(invalid_msg(&syslog_tls("key_file = \"/etc/plat/c.key\"")).contains("set together"));
        let rel = syslog_tls("").replace("/etc/plat/tls/ca.pem", "ca.pem");
        assert!(invalid_msg(&rel).contains("absolute"));
        for bad in ["", "siem example", "-x.example", "a..b"] {
            let t = syslog_tls("").replace("siem.example.net", bad);
            assert!(invalid_msg(&t).contains("server_name"), "{bad}");
        }
        Config::from_toml(&syslog_tls("").replace("siem.example.net", "2001:db8::10")).unwrap();
        let unknown = syslog_tls("bogus = 1");
        assert!(matches!(Config::from_toml(&unknown), Err(ConfigError::Parse(_))));
        // Per-destination revocation override is validated with the same rules.
        let ov = syslog_tls("[audit.syslog.tls.revocation]\nbudget_ms = 100");
        assert!(invalid_msg(&ov).contains("audit.syslog.tls.revocation.budget_ms"));
        let ov = syslog_tls("[audit.syslog.tls.revocation]\nmode = \"soft_fail\"");
        let c = Config::from_toml(&ov).unwrap();
        assert_eq!(c.audit.syslog[0].tls.as_ref().unwrap().revocation.as_ref().unwrap().mode, RevocationMode::SoftFail);
    }

    #[test]
    fn management_tls_rules() {
        let allow = "allowed_clients = [\"dns:prom-01.ops.example.net\", \"uri:spiffe://ops/prom\"]";
        let c = Config::from_toml(&mgmt_tls("[2001:db8::10]:9464", allow)).unwrap();
        let t = c.management.tls.as_ref().unwrap();
        assert_eq!((t.max_connections, t.handshake_timeout_ms, t.allowed_clients.len()), (4, 5000, 2));
        assert_eq!(t.max_connections_per_ip, 2);
        assert!(c.uses_tls());
        // mTLS on loopback is allowed too (single listener, mTLS only).
        Config::from_toml(&mgmt_tls("127.0.0.1:9464", allow)).unwrap();
        // Non-loopback without TLS is refused.
        let m = invalid_msg(&EXAMPLE.replace("127.0.0.1:9464", "[2001:db8::10]:9464"));
        assert!(m.contains("unless [management.tls]"), "{m}");
        assert!(invalid_msg(&mgmt_tls("0.0.0.0:9464", "allowed_clients = []")).contains("allowed_clients"));
        assert!(
            invalid_msg(&mgmt_tls("0.0.0.0:9464", "allowed_clients = [\"dns:*.example.net\"]")).contains("wildcard")
        );
        assert!(invalid_msg(&mgmt_tls("0.0.0.0:9464", "allowed_clients = [\" a\"]")).contains("spaces"));
        let long = format!("allowed_clients = [\"cn:{}\"]", "a".repeat(253));
        assert!(invalid_msg(&mgmt_tls("0.0.0.0:9464", &long)).contains("bytes"));
        let many = format!("allowed_clients = [{}]", vec!["\"cn:a\""; 257].join(","));
        assert!(invalid_msg(&mgmt_tls("0.0.0.0:9464", &many)).contains("allowed_clients"));
        for (extra, want) in [
            ("max_connections = 0", "max_connections"),
            ("max_connections = 65", "max_connections"),
            ("max_connections_per_ip = 0", "max_connections_per_ip"),
            ("max_connections_per_ip = 65", "max_connections_per_ip"),
            ("handshake_timeout_ms = 499", "handshake_timeout_ms"),
            ("handshake_timeout_ms = 30001", "handshake_timeout_ms"),
            // budget 4000 + 1000
            ("handshake_timeout_ms = 4999", "budget_ms + 1000"),
        ] {
            let m = invalid_msg(&mgmt_tls("0.0.0.0:9464", &format!("{allow}\n{extra}")));
            assert!(m.contains(want), "{extra}: {m}");
        }
        // With revocation off the budget does not constrain the timeout.
        let off = format!(
            "{}\n[tls.revocation]\nmode = \"off\"\n",
            base_mgmt_tls("0.0.0.0:9464", &format!("{allow}\nhandshake_timeout_ms = 500"))
        );
        Config::from_toml(&off).unwrap();
        let unknown = mgmt_tls("0.0.0.0:9464", &format!("{allow}\nlisten_local = \"127.0.0.1:1\""));
        assert!(matches!(Config::from_toml(&unknown), Err(ConfigError::Parse(_))));
        // SEC-004: typed entries only.
        for bad in ["prom", "host:prom", "cn:", "sha256:abc", &format!("sha256:{}", "g".repeat(64))] {
            let m = invalid_msg(&mgmt_tls("0.0.0.0:9464", &format!("allowed_clients = [\"{bad}\"]")));
            assert!(m.contains("allowed_clients"), "{bad}: {m}");
        }
        let fp = format!("allowed_clients = [\"sha256:{}\", \"cn:prom\"]", "aB".repeat(32));
        Config::from_toml(&mgmt_tls("0.0.0.0:9464", &fp)).unwrap();
        let nolisten = mgmt_tls("0.0.0.0:9464", allow).replace("listen = \"0.0.0.0:9464\"\n", "");
        assert!(invalid_msg(&nolisten).contains("requires management.listen"));
    }

    #[test]
    fn revocation_rules() {
        let with = |body: &str| format!("{}\n[tls.revocation]\n{body}\n", base());
        let c = Config::from_toml(&with(
            "mode = \"soft_fail\"\ncache_dir = \"/var/lib/plat/revocation\"\n[tls.revocation.ocsp]\n\
             responder_url = \"http://192.0.2.20/ocsp\"\nmethod = \"get\"\ncert_id_hash = \"sha1\"\n\
             [tls.revocation.crl]\nurls = [\"http://crl.example.net/ca.crl\"]\nfiles = [\"/etc/plat/ca.crl\"]",
        ))
        .unwrap();
        let r = &c.tls.revocation;
        assert_eq!(
            (r.mode, r.ocsp.method, r.ocsp.cert_id_hash),
            (RevocationMode::SoftFail, OcspMethod::Get, OcspCertIdHash::Sha1)
        );
        for (body, want) in [
            ("[tls.revocation.ocsp]\nenabled = false\n[tls.revocation.crl]\nenabled = false", "both false"),
            ("clock_skew_secs = 3601", "clock_skew_secs"),
            ("budget_ms = 499", "budget_ms"),
            ("budget_ms = 1000", "budget_ms must be >= ocsp.timeout_ms"),
            ("cache_dir = \"rel\"", "cache_dir"),
            ("[tls.revocation.ocsp]\ntimeout_ms = 199", "ocsp.timeout_ms"),
            ("[tls.revocation.ocsp]\nmax_age_secs = 59", "max_age_secs"),
            ("[tls.revocation.ocsp]\ncache_entries = 0", "cache_entries"),
            ("[tls.revocation.ocsp]\nresponder_url = \"https://x.example/\"", "responder_url"),
            ("[tls.revocation.ocsp]\nresponder_url = \"http://u@x.example/\"", "responder_url"),
            ("[tls.revocation.ocsp]\nnonce = false\nrequire_nonce = true", "require_nonce"),
            ("[tls.revocation.crl]\ntimeout_ms = 30001", "crl.timeout_ms"),
            ("[tls.revocation.crl]\nmax_bytes = 67108865", "crl.max_bytes"),
            ("[tls.revocation.crl]\ncache_bytes = 1073741825", "cache_bytes"),
            ("[tls.revocation.crl]\nmax_bytes = 2097152\ncache_bytes = 1048576", "cache_bytes"),
            ("[tls.revocation.crl]\nmax_crls = 0", "max_crls"),
            ("[tls.revocation.crl]\nmax_crls = 1\nfiles = [\"/a.crl\", \"/b.crl\"]", "exceed max_crls"),
            ("[tls.revocation.crl]\nurls = [\"ldap://x.example/\"]", "crl.urls"),
            ("[tls.revocation.crl]\nfiles = [\"a.crl\"]", "crl.files"),
        ] {
            let m = invalid_msg(&with(body));
            assert!(m.contains(want), "{body}: {m}");
        }
        // Both sources off is fine once checking is explicitly off.
        Config::from_toml(&with(
            "mode = \"off\"\n[tls.revocation.ocsp]\nenabled = false\n[tls.revocation.crl]\nenabled = false",
        ))
        .unwrap();
        assert!(matches!(Config::from_toml(&with("mode = \"maybe\"")), Err(ConfigError::Parse(_))));
        assert!(matches!(Config::from_toml(&with("[tls.revocation.crl]\nbogus = 1")), Err(ConfigError::Parse(_))));
        assert!(matches!(Config::from_toml(&format!("{}\n[tls]\nbogus = 1\n", base())), Err(ConfigError::Parse(_))));
    }

    /// QA: every new numeric key at both edges (accepted) and one past
    /// (rejected), plus path/URL/unknown-key rules not covered above.
    #[test]
    fn qa_tls_key_boundaries() {
        let with = |body: &str| format!("{}\n[tls.revocation]\n{body}\n", base());
        let ok = |t: &str| {
            if let Err(e) = Config::from_toml(t) {
                panic!("expected ok: {e:?}\n{t}");
            }
        };
        for (accept, reject) in [
            ("clock_skew_secs = 0", "clock_skew_secs = 3601"),
            ("clock_skew_secs = 3600", "clock_skew_secs = 3601"),
            ("budget_ms = 20000", "budget_ms = 20001"),
            ("budget_ms = 500\n[tls.revocation.ocsp]\ntimeout_ms = 500", "budget_ms = 499"),
            ("[tls.revocation.ocsp]\ntimeout_ms = 200", "[tls.revocation.ocsp]\ntimeout_ms = 199"),
            (
                "budget_ms = 10000\n[tls.revocation.ocsp]\ntimeout_ms = 10000",
                "budget_ms = 20000\n[tls.revocation.ocsp]\ntimeout_ms = 10001",
            ),
            ("[tls.revocation.ocsp]\nmax_age_secs = 60", "[tls.revocation.ocsp]\nmax_age_secs = 59"),
            ("[tls.revocation.ocsp]\nmax_age_secs = 604800", "[tls.revocation.ocsp]\nmax_age_secs = 604801"),
            ("[tls.revocation.ocsp]\ncache_entries = 1", "[tls.revocation.ocsp]\ncache_entries = 0"),
            ("[tls.revocation.ocsp]\ncache_entries = 65536", "[tls.revocation.ocsp]\ncache_entries = 65537"),
            ("[tls.revocation.crl]\ntimeout_ms = 500", "[tls.revocation.crl]\ntimeout_ms = 499"),
            ("[tls.revocation.crl]\ntimeout_ms = 30000", "[tls.revocation.crl]\ntimeout_ms = 30001"),
            ("[tls.revocation.crl]\nmax_bytes = 1024", "[tls.revocation.crl]\nmax_bytes = 1023"),
            ("[tls.revocation.crl]\nmax_bytes = 67108864", "[tls.revocation.crl]\nmax_bytes = 67108865"),
            ("[tls.revocation.crl]\ncache_bytes = 1073741824", "[tls.revocation.crl]\ncache_bytes = 1073741825"),
            ("[tls.revocation.crl]\nmax_crls = 1024", "[tls.revocation.crl]\nmax_crls = 1025"),
            (
                "[tls.revocation.crl]\nrefresh_margin_secs = 604800",
                "[tls.revocation.crl]\nrefresh_margin_secs = 604801",
            ),
            // budget >= ocsp.timeout only when OCSP is on.
            ("budget_ms = 500\n[tls.revocation.ocsp]\nenabled = false\ntimeout_ms = 2000", "budget_ms = 500"),
        ] {
            ok(&with(accept));
            assert!(matches!(Config::from_toml(&with(reject)), Err(ConfigError::Invalid(_))), "{reject}");
        }
        // Negative / wrong-typed values are parse errors, never wrap-around.
        for bad in ["budget_ms = -1", "clock_skew_secs = \"300\"", "[tls.revocation.crl]\nmax_bytes = -1"] {
            assert!(Config::from_toml(&with(bad)).is_err(), "{bad}");
        }
        // URLs: length cap, userinfo, fragment, port 0, IPv6 literal.
        let long = format!("[tls.revocation.ocsp]\nresponder_url = \"http://x.example/{}\"", "a".repeat(2048));
        assert!(invalid_msg(&with(&long)).contains("responder_url"));
        for u in [
            "http://u:p@x.example/c.crl",
            "http://x.example/c.crl#f",
            "http://x.example:0/",
            "http://x.example/a b",
            "file:///etc/x.crl",
        ] {
            let m = invalid_msg(&with(&format!("[tls.revocation.crl]\nurls = [\"{u}\"]")));
            assert!(m.contains("crl.urls"), "{u}: {m}");
        }
        ok(&with("[tls.revocation.crl]\nurls = [\"http://[2001:db8::1]:8080/c.crl\"]"));
        // Unknown keys in every new table.
        for t in [
            with("[tls.revocation.ocsp]\nbogus = 1"),
            with("bogus = 1"),
            syslog_tls("[audit.syslog.tls.revocation]\nbogus = 1"),
            syslog_tls("[audit.syslog.tls.revocation.crl]\nbogus = 1"),
            mgmt_tls("0.0.0.0:9464", "allowed_clients = [\"cn:a\"]\nbogus = 1"),
        ] {
            assert!(matches!(Config::from_toml(&t), Err(ConfigError::Parse(_))), "{t}");
        }
        // Management paths must be absolute.
        let allow = "allowed_clients = [\"cn:a\"]";
        for (from, what) in [
            ("/etc/plat/tls/m.pem", "cert_file"),
            ("/etc/plat/tls/m.key", "key_file"),
            ("/etc/plat/tls/ca.pem", "client_ca_file"),
        ] {
            let t = mgmt_tls("0.0.0.0:9464", allow).replace(from, "rel.pem");
            let m = invalid_msg(&t);
            assert!(m.contains(what) && m.contains("absolute"), "{what}: {m}");
        }
        // Allow-list entries: control chars and 255-byte edge.
        assert!(invalid_msg(&mgmt_tls("0.0.0.0:9464", "allowed_clients = [\"cn:a\\u0000b\"]")).contains("control"));
        assert!(invalid_msg(&mgmt_tls("0.0.0.0:9464", "allowed_clients = [\"cn:a\\nb\"]")).contains("control"));
        ok(&mgmt_tls("0.0.0.0:9464", &format!("allowed_clients = [\"cn:{}\"]", "a".repeat(252))));
        ok(&mgmt_tls("0.0.0.0:9464", &format!("allowed_clients = [{}]", vec!["\"cn:a\""; 256].join(","))));
        ok(&mgmt_tls("0.0.0.0:9464", &format!("{allow}\nmax_connections = 1\nhandshake_timeout_ms = 30000")));
        ok(&mgmt_tls("0.0.0.0:9464", &format!("{allow}\nmax_connections = 64\nhandshake_timeout_ms = 5000")));
        ok(&mgmt_tls("0.0.0.0:9464", &format!("{allow}\nmax_connections_per_ip = 1")));
        ok(&mgmt_tls("0.0.0.0:9464", &format!("{allow}\nmax_connections_per_ip = 64")));
        // Syslog TLS paths absolute; override validated under its own prefix.
        let t = syslog_tls("cert_file = \"c.pem\"\nkey_file = \"/etc/plat/c.key\"");
        assert!(invalid_msg(&t).contains("absolute"));
        let ov = syslog_tls("[audit.syslog.tls.revocation.crl]\nfiles = [\"rel.crl\"]");
        assert!(invalid_msg(&ov).contains("audit.syslog"), "override prefix");
        // Global [tls] booleans.
        let c = Config::from_toml(&format!("{}\n[tls]\npq_hybrid = false\nrequire_fips = false\n", base())).unwrap();
        assert!(!c.tls.pq_hybrid && !c.tls.require_fips);
        assert!(Config::from_toml(&format!("{}\n[tls]\npq_hybrid = \"no\"\n", base())).is_err());
    }
}
