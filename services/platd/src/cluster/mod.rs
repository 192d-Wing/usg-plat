//! Cluster high availability (`[cluster.ha]`): peer channel, membership
//! driver, replicator, route hooks, witness and the operator commands.
//!
//! ```text
//!  plat-peer-accept ──▶ plat-peer-in (TLS server, Hello) ─┐
//!  plat-peer-<id>   ──▶ (TLS client, Hello) ──────────────┤ one connection
//!                                                          │ per member pair
//!       control frames ──▶ plat-cluster-ctl (Membership, leases, views,
//!                          acquire/adopt, fence/release, state file)
//!       data frames    ──▶ Replicator::on_data (backup: Shadow, Directory)
//!  workers / sweeper ──▶ ReplHub rings ──▶ plat-repl (sequence, snapshot,
//!                          reservations) ──▶ peer data queues
//!  plat-cluster-hook: announce/withdraw hooks, state_dir/announce.d
//!  plat-cluster-cli:  state_dir/ctl.sock (`platd cluster ...`)
//! ```
//!
//! The functions in this file are the configuration-derived parts that
//! every build needs (`check-config`, `service_start`); the runtime needs
//! the `tls` feature (the peer channel is mutual TLS only).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CP-7, CP-10 (alternate processing and recovery within the
//!   cluster); SC-24 (fail in known state); SC-5, SC-5(2)
//! - NIST 800-53: CM-2, CM-3, CM-6 - the cluster configuration digest is
//!   cross-checked between peers and recorded on `service_start`

#[cfg(feature = "tls")]
pub mod control;
#[cfg(feature = "tls")]
pub mod hooks;
#[cfg(feature = "tls")]
pub mod peer;
#[cfg(feature = "tls")]
pub mod replicator;
#[cfg(all(test, feature = "tls"))]
mod tests;
#[cfg(feature = "tls")]
pub mod witness;

use std::sync::Arc;

use plat_audit::{ClusterStart, SliceCidr};
use plat_cluster::{DigestInput, DigestMember, MemberId, PartitionScheme, SliceId, SliceMap};
use plat_common::config::Partition;
use plat_common::{Config, Ipv4Cidr};

#[cfg(feature = "tls")]
pub use control::{ClusterHandle, start};

/// Audit form of a slice CIDR.
pub fn slice_cidr(c: Ipv4Cidr) -> SliceCidr {
    SliceCidr { net: c.network(), len: c.prefix_len() }
}

fn scheme(p: Partition) -> PartitionScheme {
    match p {
        Partition::Contiguous => PartitionScheme::Contiguous,
        Partition::Slices => PartitionScheme::Slices,
    }
}

/// The inputs of the cluster configuration digest (WU1 mapping): pool and
/// block layout, partition, members, witness identity and lease timing (0
/// without HA).
pub fn digest_input(cfg: &Config) -> DigestInput {
    let ha = cfg.cluster.ha_active();
    DigestInput {
        pool: cfg.nat64.pool.clone(),
        port_min: cfg.nat64.port_min,
        port_max: cfg.nat64.port_max,
        port_block_size: cfg.nat64.port_block_size,
        subscriber_prefix_len: cfg.nat64.subscriber_prefix_len,
        paired_pooling: cfg.nat64.paired_pooling,
        partition: scheme(cfg.cluster.partition),
        slice_prefix_len: cfg.cluster.slice_prefix_len,
        members: cfg
            .cluster
            .members
            .iter()
            .map(|m| DigestMember { id: m.id, identity: m.identity.clone(), weight: u32::from(m.weight) })
            .collect(),
        witness: ha.and_then(|h| h.witness.as_ref()).map(|w| w.identity.clone()),
        lease_ms: ha.map_or(0, |h| u32::try_from(h.lease_ms).unwrap_or(u32::MAX)),
        heartbeat_ms: ha.map_or(0, |h| u32::try_from(h.heartbeat_ms).unwrap_or(u32::MAX)),
        drift_margin_pct: ha.map_or(0, |h| h.drift_margin_pct),
    }
}

/// The digest the witness and the members exchange: the voting inputs only
/// (members, witness identity, lease timing), because the witness has no
/// pool. Members and witness compute it from their own files.
#[cfg(feature = "tls")]
pub fn voting_digest(members: &[DigestMember], witness: &str, lease_ms: u64, heartbeat_ms: u64, drift: u8) -> [u8; 32] {
    plat_cluster::config_digest(&DigestInput {
        pool: Vec::new(),
        port_min: 0,
        port_max: 0,
        port_block_size: 0,
        subscriber_prefix_len: 0,
        paired_pooling: false,
        partition: PartitionScheme::Slices,
        slice_prefix_len: 0,
        members: members.to_vec(),
        witness: Some(witness.to_string()),
        lease_ms: u32::try_from(lease_ms).unwrap_or(u32::MAX),
        heartbeat_ms: u32::try_from(heartbeat_ms).unwrap_or(u32::MAX),
        drift_margin_pct: drift,
    })
}

/// Member ids and the weight table (indexed by id) of `cluster.members`,
/// or ids `0..node_count` with weight 1 when no members are listed.
pub fn member_weights(cfg: &Config) -> (Vec<MemberId>, Vec<u32>) {
    if cfg.cluster.members.is_empty() {
        let n = cfg.cluster.node_count.max(1);
        return ((0..n).collect(), vec![1; usize::from(n)]);
    }
    let mut ids: Vec<MemberId> = cfg.cluster.members.iter().map(|m| m.id).collect();
    ids.sort_unstable();
    let mut w = vec![1u32; ids.last().map_or(0, |m| usize::from(*m) + 1)];
    for m in &cfg.cluster.members {
        if let Some(x) = w.get_mut(usize::from(m.id)) {
            *x = u32::from(m.weight);
        }
    }
    (ids, w)
}

/// `partition = "slices"`: the slice map and this node's primary and
/// backup slices for the full member set (the steady state with every
/// member live). `None` in contiguous mode.
pub fn home_slices(cfg: &Config) -> Option<(SliceMap, Vec<SliceId>, Vec<SliceId>)> {
    if cfg.cluster.partition != Partition::Slices {
        return None;
    }
    let map = SliceMap::new(&cfg.nat64.pool, cfg.cluster.slice_prefix_len).ok()?;
    let (ids, w) = member_weights(cfg);
    let (mut primary, mut backup) = (Vec::new(), Vec::new());
    for (s, _) in map.iter() {
        match plat_cluster::rank(s, &ids, &w) {
            Some((p, _)) if p == cfg.node.id => primary.push(s),
            Some((_, Some(b))) if b == cfg.node.id => backup.push(s),
            _ => {}
        }
    }
    Some((map, primary, backup))
}

/// The addresses this node announces in steady state: its contiguous share
/// (or `owned_pool`), or with slices the addresses of its primary slices.
pub fn owned_addrs(cfg: &Config) -> Vec<u32> {
    match home_slices(cfg) {
        None => plat_cluster::owned(cfg),
        Some((map, primary, _)) => {
            let mut v: Vec<u32> = primary.iter().filter_map(|s| map.cidr(*s)).flat_map(|c| c.addrs()).collect();
            v.sort_unstable();
            v
        }
    }
}

/// `cluster.mode` of `service_start`.
pub fn mode(cfg: &Config) -> &'static str {
    match (cfg.cluster.partition, cfg.cluster.ha_enabled()) {
        (_, true) => "ha",
        (Partition::Slices, false) => "slices",
        (Partition::Contiguous, false) => "contiguous",
    }
}

/// The cluster fields of `service_start`: node id, mode, configuration
/// digest, the CIDRs owned at start (none with HA: `cluster_slice_acquire`
/// records follow) and the member count.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: CM-2, CM-3, AU-3 - the digest identifies the cluster
///   configuration each node started with (POAM-017c)
pub fn cluster_start(cfg: &Config) -> Arc<ClusterStart> {
    let slices = if cfg.cluster.ha_enabled() {
        Vec::new()
    } else {
        plat_cluster::cover(&owned_addrs(cfg)).into_iter().map(slice_cidr).collect()
    };
    let member_count = if cfg.cluster.members.is_empty() {
        cfg.cluster.node_count
    } else {
        u16::try_from(cfg.cluster.members.len()).unwrap_or(u16::MAX)
    };
    Arc::new(ClusterStart {
        node_id: cfg.node.id,
        mode: mode(cfg),
        config_digest: plat_cluster::config_digest(&digest_input(cfg)),
        slices,
        member_count,
    })
}

/// Lower-case hex of a digest.
pub fn hex(d: &[u8]) -> String {
    use std::fmt::Write as _;
    d.iter().fold(String::with_capacity(d.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The `check-config` cluster section: mode, digest, the slice table and
/// this node's steady-state primary and backup slices.
pub fn summary(cfg: &Config) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let d = plat_cluster::config_digest(&digest_input(cfg));
    let _ = writeln!(o, "cluster: mode {}, config digest {}", mode(cfg), hex(&d));
    if let Some((map, primary, backup)) = home_slices(cfg) {
        let (ids, w) = member_weights(cfg);
        let _ = writeln!(o, "  slices: {} of /{}", map.len(), map.slice_len());
        for (s, c) in map.iter() {
            let (p, b) = plat_cluster::rank(s, &ids, &w).unwrap_or((0, None));
            let _ = writeln!(
                o,
                "    slice {s:>4} {c:<18} primary {p} backup {}",
                b.map_or_else(|| "-".to_string(), |b| b.to_string())
            );
        }
        let _ = writeln!(o, "  this node: {} primary, {} backup slice(s)", primary.len(), backup.len());
    }
    if let Some(h) = cfg.cluster.ha_active() {
        let _ = writeln!(
            o,
            "  ha: listen {}, auto_failover {}, lease {} ms, heartbeat {} ms, witness {}",
            h.listen,
            cfg.cluster.auto_failover(),
            h.lease_ms,
            h.heartbeat_ms,
            h.witness.as_ref().map_or_else(|| "none".to_string(), |w| w.identity.clone())
        );
    }
    o
}
