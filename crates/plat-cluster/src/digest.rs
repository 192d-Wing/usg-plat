//! Cluster configuration digest.
//!
//! Every member must agree on the inputs that decide slice ownership and
//! block layout. The digest is exchanged in `Hello` (a mismatch refuses the
//! peer) and logged in `service_start`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-6 (Configuration Settings) - cluster-relevant settings
//!   cross-checked between members; CM-2/CM-3 - digest recorded at start

use plat_common::Ipv4Cidr;
use sha2::{Digest, Sha256};

use crate::slices::MemberId;

/// Pool partition scheme (`cluster.partition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PartitionScheme {
    /// Legacy contiguous split by `node_count` (or explicit `owned_pool`).
    #[default]
    Contiguous,
    /// Fixed slices with rendezvous ownership (required for HA).
    Slices,
}

impl PartitionScheme {
    pub fn code(self) -> u8 {
        match self {
            PartitionScheme::Contiguous => 0,
            PartitionScheme::Slices => 1,
        }
    }

    pub fn from_code(c: u8) -> Option<Self> {
        match c {
            0 => Some(PartitionScheme::Contiguous),
            1 => Some(PartitionScheme::Slices),
            _ => None,
        }
    }
}

/// One member as seen by the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestMember {
    pub id: MemberId,
    /// Typed allow-list identity, e.g. `dns:plat-1.cluster.example`.
    pub identity: String,
    pub weight: u32,
}

/// The cluster-relevant configuration, decoupled from `plat_common::Config`
/// (WU6 fills it from the validated config; see impl notes for the field
/// mapping).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DigestInput {
    pub pool: Vec<Ipv4Cidr>,
    pub port_min: u16,
    pub port_max: u16,
    pub port_block_size: u16,
    pub subscriber_prefix_len: u8,
    pub paired_pooling: bool,
    pub partition: PartitionScheme,
    pub slice_prefix_len: u8,
    pub members: Vec<DigestMember>,
    /// Witness identity, when configured.
    pub witness: Option<String>,
    pub lease_ms: u32,
    pub heartbeat_ms: u32,
    pub drift_margin_pct: u8,
}

const DOMAIN: &[u8] = b"usg-plat cluster config digest v1\0";

fn put_str(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
}

/// SHA-256 over a canonical, length-prefixed encoding of `cfg`. Sets (pool,
/// members) are sorted first, so their order in the file does not matter;
/// every field changes the result.
pub fn config_digest(cfg: &DigestInput) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    let mut pool: Vec<(u32, u8)> = cfg.pool.iter().map(|c| (c.network(), c.prefix_len())).collect();
    pool.sort_unstable();
    pool.dedup();
    h.update((pool.len() as u64).to_le_bytes());
    for (net, len) in pool {
        h.update(net.to_le_bytes());
        h.update([len]);
    }
    h.update(cfg.port_min.to_le_bytes());
    h.update(cfg.port_max.to_le_bytes());
    h.update(cfg.port_block_size.to_le_bytes());
    h.update([cfg.subscriber_prefix_len, u8::from(cfg.paired_pooling), cfg.partition.code(), cfg.slice_prefix_len]);
    let mut members: Vec<&DigestMember> = cfg.members.iter().collect();
    members.sort_unstable_by(|a, b| (a.id, &a.identity, a.weight).cmp(&(b.id, &b.identity, b.weight)));
    h.update((members.len() as u64).to_le_bytes());
    for m in members {
        h.update(m.id.to_le_bytes());
        put_str(&mut h, &m.identity);
        h.update(m.weight.to_le_bytes());
    }
    match &cfg.witness {
        Some(w) => {
            h.update([1]);
            put_str(&mut h, w);
        }
        None => h.update([0]),
    }
    h.update(cfg.lease_ms.to_le_bytes());
    h.update(cfg.heartbeat_ms.to_le_bytes());
    h.update([cfg.drift_margin_pct]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> DigestInput {
        DigestInput {
            pool: vec!["192.0.2.0/24".parse().unwrap(), "198.51.100.0/24".parse().unwrap()],
            port_min: 1024,
            port_max: 65535,
            port_block_size: 512,
            subscriber_prefix_len: 56,
            paired_pooling: true,
            partition: PartitionScheme::Slices,
            slice_prefix_len: 28,
            members: vec![
                DigestMember { id: 0, identity: "dns:plat-1.example".into(), weight: 1 },
                DigestMember { id: 1, identity: "dns:plat-2.example".into(), weight: 1 },
            ],
            witness: Some("dns:witness.example".into()),
            lease_ms: 3000,
            heartbeat_ms: 500,
            drift_margin_pct: 10,
        }
    }

    #[test]
    fn order_insensitive_for_sets() {
        let a = base();
        let mut b = base();
        b.pool.reverse();
        b.members.reverse();
        assert_eq!(config_digest(&a), config_digest(&b));
    }

    #[test]
    fn sensitive_to_every_field() {
        let d = config_digest(&base());
        type Edit = Box<dyn Fn(&mut DigestInput)>;
        let edits: Vec<Edit> = vec![
            Box::new(|c| c.pool.pop().map(drop).unwrap_or(())),
            Box::new(|c| c.port_min += 1),
            Box::new(|c| c.port_max -= 1),
            Box::new(|c| c.port_block_size = 256),
            Box::new(|c| c.subscriber_prefix_len = 64),
            Box::new(|c| c.paired_pooling = false),
            Box::new(|c| c.partition = PartitionScheme::Contiguous),
            Box::new(|c| c.slice_prefix_len = 27),
            Box::new(|c| c.members[0].id = 2),
            Box::new(|c| c.members[0].identity.push('x')),
            Box::new(|c| c.members[0].weight = 2),
            Box::new(|c| c.members.pop().map(drop).unwrap_or(())),
            Box::new(|c| c.witness = None),
            Box::new(|c| c.witness = Some("dns:other.example".into())),
            Box::new(|c| c.lease_ms = 4000),
            Box::new(|c| c.heartbeat_ms = 400),
            Box::new(|c| c.drift_margin_pct = 11),
        ];
        let mut seen = std::collections::HashSet::new();
        for (i, e) in edits.iter().enumerate() {
            let mut c = base();
            e(&mut c);
            let x = config_digest(&c);
            assert_ne!(x, d, "edit {i} not covered");
            assert!(seen.insert(x), "edit {i} collides");
        }
    }

    #[test]
    fn identity_strings_are_length_prefixed() {
        let mut a = base();
        a.members[0].identity = "ab".into();
        a.members[1].identity = "c".into();
        let mut b = base();
        b.members[0].identity = "a".into();
        b.members[1].identity = "bc".into();
        assert_ne!(config_digest(&a), config_digest(&b));
    }
}
