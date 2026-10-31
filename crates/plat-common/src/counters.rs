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
        // New subscriber refused: its aggregate prefix
        // (nat64.aggregate_prefix_len) already holds
        // nat64.max_subscribers_per_aggregate subscribers (POAM-013).
        AggregateSubscriberLimit => "aggregate_subscriber_limit",
        // Inbound for a slice this node does not hold a valid lease for.
        ClusterFenced => "cluster_fenced",
        // New subscriber homed on another node (`cluster.steering.mode = "drop"`).
        Missteered => "missteered",
        // Fragments (RFC 6146 §3.4, translation.fragments): incomplete
        // datagram expired; overlap or duplicate (RFC 5722); first fragment
        // short of the transport header or IPv4 offset 1 TCP (RFC 1858,
        // RFC 3128, RFC 7112); more than max_fragments_per_datagram.
        FragmentTimeout => "fragment_timeout",
        FragmentOverlap => "fragment_overlap",
        FragmentTiny => "fragment_tiny",
        FragmentTooMany => "fragment_too_many",
        // No fragment-table entry could be made (every way of the set holds
        // buffered data), or a pass-through entry was evicted.
        FragmentTableFull => "fragment_table_full",
        FragmentBufferFull => "fragment_buffer_full",
        ReassemblyFull => "reassembly_full",
        ReassemblyTooBig => "reassembly_too_big",
        // Non-first fragment with no entry while buffering is off or full.
        FragmentUnmatched => "fragment_unmatched",
        // ICMP error quoting a non-first fragment this worker cannot map.
        IcmpQuoteUnmatched => "icmp_quote_unmatched",
        // Unsolicited inbound SYN on a bound port not held for simultaneous
        // open: the BIB's held-SYN slots (nat64.max_held_syns_per_bib) or
        // the node-wide cap (nat64.max_held_syns) are full (RFC 6146
        // §3.5.2.2, SC-5).
        HeldSynLimit => "held_syn_limit",
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
        FragmentsInV6 => "fragments_in_v6",
        FragmentsInV4 => "fragments_in_v4",
        // Non-first fragments translated with a first fragment's mapping.
        FragmentsForwarded => "fragments_forwarded",
        FragmentsBuffered => "fragments_buffered",
        DatagramsReassembled => "datagrams_reassembled",
        // IPv6 packets ≤ 1280 bytes fragmented as IPv4 (RFC 7915 §5.1).
        FragmentedV6ToV4 => "fragmented_v6_to_v4",
        IcmpTimeExceededSent => "icmp_time_exceeded_sent",
        IcmpUnreachableSent => "icmp_unreachable_sent",
        IcmpParamProblemSent => "icmp_param_problem_sent",
        // Unsolicited inbound SYN held for simultaneous open (RFC 6146
        // §3.5.2.2); consumed, not forwarded.
        TcpSynHeld => "tcp_syn_held",
        // Retransmitted SYN for a remote already held (deadline unchanged).
        TcpSynHeldDup => "tcp_syn_held_dup",
        // A subscriber SYN matched a held SYN: session opened ESTABLISHED.
        TcpSynHeldMatched => "tcp_syn_held_matched",
    }
);

/// One worker's counters. Padded so adjacent workers never share a line.
#[derive(Debug)]
pub struct Counters {
    drops: [CachePadded<AtomicU64>; DropReason::COUNT],
    events: [CachePadded<AtomicU64>; Counter::COUNT],
    /// Gauge: live fragment-table entries of this worker, written by the
    /// worker once per housekeeping pass (`plat_fragment_entries`).
    fragment_entries: CachePadded<AtomicU64>,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            drops: std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0))),
            events: std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0))),
            fragment_entries: CachePadded::new(AtomicU64::new(0)),
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

    /// Records `n` drops of one reason.
    #[inline]
    pub fn record_drops(&self, r: DropReason, n: u64) {
        if n > 0 {
            self.drops[r as usize].fetch_add(n, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn set_fragment_entries(&self, n: u64) {
        self.fragment_entries.store(n, Ordering::Relaxed);
    }

    pub fn fragment_entries(&self) -> u64 {
        self.fragment_entries.load(Ordering::Relaxed)
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
