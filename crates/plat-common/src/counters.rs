//! Per-worker data-plane counters.
//!
//! Each worker owns one cache-line-padded `Counters` block and increments it
//! with relaxed atomics, so there is no cross-core contention; the metrics
//! endpoint sums the blocks.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-4 (System Monitoring) - every drop class is counted.

use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_utils::CachePadded;

macro_rules! define_enum {
    ($(#[$m:meta])* $name:ident { $($v:ident => $s:literal),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum $name { $($v),* }
        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$v),*];
            pub const COUNT: usize = Self::ALL.len();
            pub fn as_str(self) -> &'static str {
                match self { $($name::$v => $s),* }
            }
        }
    };
}

define_enum!(
    /// Why a packet was dropped. Exposed as `plat_drops_total{reason=...}`.
    DropReason {
        Malformed => "malformed",
        UnsupportedProto => "unsupported_proto",
        BadChecksum => "bad_checksum",
        SrcNotAllowed => "src_not_allowed",
        DstNotTranslatable => "dst_not_translatable",
        DstForbidden => "dst_forbidden",
        NoBinding => "no_binding",
        Filtered => "filtered",
        TcpNoState => "tcp_no_state",
        PortExhausted => "port_exhausted",
        SubscriberLimit => "subscriber_limit",
        SessionLimit => "session_limit",
        AuditUnavailable => "audit_unavailable",
        Fragment => "fragment",
        TooBig => "too_big",
        HopLimit => "hop_limit",
        IcmpUntranslatable => "icmp_untranslatable",
        WrongNode => "wrong_node",
        SourceRoute => "source_route",
        SubscriberTableFull => "subscriber_table_full",
        // Inbound for a slice this node does not hold a valid lease for.
        ClusterFenced => "cluster_fenced",
        // New subscriber homed on another node (`cluster.steering.mode = "drop"`).
        Missteered => "missteered",
    }
);

define_enum!(
    /// Non-drop events.
    Counter {
        RxPackets => "rx_packets",
        TxPackets => "tx_packets",
        RxBytes => "rx_bytes",
        TxBytes => "tx_bytes",
        V6ToV4 => "v6_to_v4",
        V4ToV6 => "v4_to_v6",
        Hairpin => "hairpin",
        IcmpErrorsTranslated => "icmp_errors_translated",
        IcmpErrorsGenerated => "icmp_errors_generated",
        IcmpErrorsRateLimited => "icmp_errors_rate_limited",
        FragmentedV4ToV6 => "fragmented_v4_to_v6",
        BibCreated => "bib_created",
        SessionCreated => "session_created",
        IoErrors => "io_errors",
        TxQueueFull => "tx_queue_full",
        // New subscriber found homed on another node (any steering mode).
        ClusterSteerMissteered => "cluster_steer_missteered",
        // Block allocation skipped: no backup-acked reservation left.
        ClusterReserveStarved => "cluster_reserve_starved",
        // Strict paired pooling refused: the subscriber's address is full
        // while other addresses have free blocks.
        PoolPairedExhausted => "pool_paired_exhausted",
    }
);

/// One worker's counters. Padded so adjacent workers never share a line.
#[derive(Debug)]
pub struct Counters {
    drops: [CachePadded<AtomicU64>; DropReason::COUNT],
    events: [CachePadded<AtomicU64>; Counter::COUNT],
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            drops: std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0))),
            events: std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0))),
        }
    }
}

impl Counters {
    #[inline]
    pub fn record_drop(&self, r: DropReason) {
        self.drops[r as usize].fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add(&self, c: Counter, n: u64) {
        self.events[c as usize].fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc(&self, c: Counter) {
        self.add(c, 1);
    }

    pub fn drops(&self, r: DropReason) -> u64 {
        self.drops[r as usize].load(Ordering::Relaxed)
    }

    pub fn get(&self, c: Counter) -> u64 {
        self.events[c as usize].load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_cluster_classes_exist() {
        let mut d: Vec<_> = DropReason::ALL.iter().map(|r| r.as_str()).collect();
        d.sort_unstable();
        d.dedup();
        assert_eq!(d.len(), DropReason::COUNT);
        assert!(d.contains(&"cluster_fenced") && d.contains(&"missteered"));
        let mut e: Vec<_> = Counter::ALL.iter().map(|c| c.as_str()).collect();
        e.sort_unstable();
        e.dedup();
        assert_eq!(e.len(), Counter::COUNT);
        let c = Counters::default();
        c.record_drop(DropReason::Missteered);
        c.inc(Counter::ClusterSteerMissteered);
        assert_eq!((c.drops(DropReason::Missteered), c.get(Counter::ClusterSteerMissteered)), (1, 1));
    }
}
