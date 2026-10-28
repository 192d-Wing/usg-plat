//! Audit event payloads. Small and `Copy` so the hot path never allocates.

use std::net::IpAddr;

/// Why a resource limit fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    PoolExhausted,
    SubscriberBlocks,
    SubscriberSessions,
    GlobalSessions,
    /// `nat64.max_subscribers` reached (SC-5).
    SubscriberTable,
}

impl LimitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolExhausted => "pool_exhausted",
            Self::SubscriberBlocks => "subscriber_block_limit",
            Self::SubscriberSessions => "subscriber_session_limit",
            Self::GlobalSessions => "global_session_limit",
            Self::SubscriberTable => "subscriber_table_limit",
        }
    }
}

/// State reported by `audit_storage_threshold` (AU-5(1)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageState {
    /// Free space fell below `min_free_bytes`: degraded.
    Below,
    /// Free space is back above the threshold plus 10 %.
    Recovered,
    /// Free space cannot be determined (`statvfs` failed): treated as below
    /// the threshold, fail closed (SEC-204).
    Unknown,
}

impl StorageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Below => "below_threshold",
            Self::Recovered => "recovered",
            Self::Unknown => "unknown",
        }
    }
}

/// Phase reported by `audit_retention_prune` (AU-9, AU-11). A deletion is
/// first recorded as `Scheduled` (synced before the file is touched), then
/// its result as `Deleted` or `Failed` in a later batch (NIST-202).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneState {
    Scheduled,
    Deleted,
    Failed,
}

impl PruneState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Deleted => "deleted",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    Start,
    Stop,
}

/// One audit record. Times are UTC microseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A port block was assigned to a subscriber (RFC 7422 bulk allocation).
    PortBlockAlloc {
        ts_us: u64,
        sub: u128,
        sub_len: u8,
        v4: u32,
        port_lo: u16,
        port_hi: u16,
    },
    /// A port block was returned to the pool.
    PortBlockRelease {
        ts_us: u64,
        sub: u128,
        sub_len: u8,
        v4: u32,
        port_lo: u16,
        port_hi: u16,
        held_secs: u32,
    },
    /// BIB entry created (session-mode logging).
    BibCreate {
        ts_us: u64,
        proto: u8,
        v6: u128,
        v6_port: u16,
        v4: u32,
        v4_port: u16,
    },
    /// BIB entry removed (session-mode logging).
    BibDelete {
        ts_us: u64,
        proto: u8,
        v6: u128,
        v6_port: u16,
        v4: u32,
        v4_port: u16,
        held_secs: u32,
    },
    /// A resource limit refused a mapping (rate-limited by the emitter).
    Limit {
        ts_us: u64,
        kind: LimitKind,
        sub: u128,
        sub_len: u8,
    },
    Lifecycle {
        ts_us: u64,
        kind: LifecycleKind,
    },
    /// Counter snapshot (drops etc.), emitted by the logger itself.
    Counter {
        ts_us: u64,
        name: &'static str,
        value: u64,
    },
    /// Records lost because the queue was full (AU-5 alert).
    QueueOverflow {
        ts_us: u64,
        lost: u64,
    },
    /// The local audit file (the authoritative AU-9 copy) could not be
    /// written (`recovered == false`, sent to the remaining destinations)
    /// or is being written again (`recovered == true`, first record of the
    /// new file). `lost` records were not written to the file. Emitted by
    /// the logger itself (AU-5).
    OutputFailure {
        ts_us: u64,
        lost: u64,
        recovered: bool,
    },
    /// Records not delivered to a syslog collector (queue full, connection
    /// failure, reconnect back-off). Emitted by the logger itself into the
    /// local file (AU-5, AU-9(2)).
    RemoteLoss {
        ts_us: u64,
        ip: IpAddr,
        port: u16,
        lost: u64,
    },
    /// Free space on the log volume crossed `audit.file.min_free_bytes`
    /// (`Below`/`Unknown`: pipeline degraded, new bindings refused;
    /// `Recovered`: back above the threshold plus 10 %). `available` is 0
    /// and not formatted for `Unknown`. Emitted by the logger (AU-5(1)).
    StorageThreshold {
        ts_us: u64,
        available: u64,
        threshold: u64,
        state: StorageState,
    },
    /// Retention (`audit.file.max_files`) of a rotated audit file. The
    /// `Scheduled` record is written to the live chain and synced before
    /// the file is deleted; the result (`Deleted` / `Failed`) follows in a
    /// later batch (AU-9, AU-11). The file is `<path>.<rotated_us>`; it held
    /// records `seq_first..=seq_last` and its last checkpoint chain starts
    /// with `chain_prefix` (the next file's header names the full chain
    /// value).
    RetentionPrune {
        ts_us: u64,
        rotated_us: u64,
        seq_first: u64,
        seq_last: u64,
        chain_prefix: u64,
        state: PruneState,
    },
}

impl Event {
    pub fn ts_us(&self) -> u64 {
        match *self {
            Event::PortBlockAlloc { ts_us, .. }
            | Event::PortBlockRelease { ts_us, .. }
            | Event::BibCreate { ts_us, .. }
            | Event::BibDelete { ts_us, .. }
            | Event::Limit { ts_us, .. }
            | Event::Lifecycle { ts_us, .. }
            | Event::Counter { ts_us, .. }
            | Event::QueueOverflow { ts_us, .. }
            | Event::OutputFailure { ts_us, .. }
            | Event::RemoteLoss { ts_us, .. }
            | Event::StorageThreshold { ts_us, .. }
            | Event::RetentionPrune { ts_us, .. } => ts_us,
        }
    }

    /// `event.action` value; also used as the syslog MSGID.
    pub fn action(&self) -> &'static str {
        match self {
            Event::PortBlockAlloc { .. } => "nat_port_block_allocate",
            Event::PortBlockRelease { .. } => "nat_port_block_release",
            Event::BibCreate { .. } => "nat_binding_create",
            Event::BibDelete { .. } => "nat_binding_delete",
            Event::Limit { .. } => "nat_resource_limit",
            Event::Lifecycle { kind: LifecycleKind::Start, .. } => "service_start",
            Event::Lifecycle { kind: LifecycleKind::Stop, .. } => "service_stop",
            Event::Counter { .. } => "dataplane_counter",
            Event::QueueOverflow { .. } => "audit_queue_overflow",
            Event::OutputFailure { .. } => "audit_output_failure",
            Event::RemoteLoss { .. } => "audit_remote_loss",
            Event::StorageThreshold { .. } => "audit_storage_threshold",
            Event::RetentionPrune { .. } => "audit_retention_prune",
        }
    }

    /// Syslog severity (RFC 5424): 3 error, 4 warning, 5 notice,
    /// 6 informational.
    pub fn severity(&self) -> u8 {
        match self {
            Event::OutputFailure { recovered: false, .. } => 3,
            Event::Limit { .. }
            | Event::QueueOverflow { .. }
            | Event::OutputFailure { .. }
            | Event::RemoteLoss { .. }
            | Event::StorageThreshold { state: StorageState::Below | StorageState::Unknown, .. }
            | Event::RetentionPrune { state: PruneState::Failed, .. } => 4,
            Event::Lifecycle { .. } | Event::StorageThreshold { .. } | Event::RetentionPrune { .. } => 5,
            _ => 6,
        }
    }

    /// `event.outcome` (ECS) / CEF `outcome`; `None` for counter snapshots.
    pub fn outcome(&self) -> Option<&'static str> {
        match self {
            Event::PortBlockAlloc { .. }
            | Event::PortBlockRelease { .. }
            | Event::BibCreate { .. }
            | Event::BibDelete { .. }
            | Event::Lifecycle { .. }
            | Event::StorageThreshold { state: StorageState::Recovered, .. }
            | Event::RetentionPrune { state: PruneState::Deleted, .. } => Some("success"),
            // The deletion has not happened yet (NIST-202).
            Event::RetentionPrune { state: PruneState::Scheduled, .. } => Some("unknown"),
            Event::Limit { .. }
            | Event::QueueOverflow { .. }
            | Event::OutputFailure { .. }
            | Event::RemoteLoss { .. }
            | Event::StorageThreshold { .. }
            | Event::RetentionPrune { .. } => Some("failure"),
            Event::Counter { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The data plane copies events into the queue; keep them small.
    #[test]
    fn event_stays_small() {
        assert!(std::mem::size_of::<Event>() <= 48, "{}", std::mem::size_of::<Event>());
    }

    #[test]
    fn limit_reasons() {
        assert_eq!(LimitKind::SubscriberTable.as_str(), "subscriber_table_limit");
        assert_eq!(LimitKind::PoolExhausted.as_str(), "pool_exhausted");
    }
}
