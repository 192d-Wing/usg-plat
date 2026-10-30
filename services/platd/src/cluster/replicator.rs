//! Replication: primary → backup for port blocks and BIBs of every slice,
//! all → all for the subscriber directory.
//!
//! Primary side (the `plat-repl` thread calls [`Replicator::pump`]):
//! - drains the workers' and the sweeper's `ReplHub` rings, numbers every
//!   record per slice and queues it to the slice's backup (or, while a
//!   slice is being handed over, to its new owner);
//! - brings a new backup in sync with a snapshot (`SnapshotBegin`, chunks
//!   from `State::export_slice`, `SnapshotEnd`), throttled to a quarter of
//!   the peer queue in flight; the backup's `Ack` of the end marks it in
//!   sync;
//! - while in sync, keeps `reserve_ahead_blocks` blocks reserved with the
//!   backup (`Reserve` / `Ack`), so no block is handed out before the
//!   backup knows it may be;
//! - a ring or peer-queue loss marks the slice dirty: it is resynced by
//!   snapshot and a rate-limited `cluster_replication_gap` is recorded.
//!
//! Backup side ([`Replicator::on_data`], on the connection thread): checks
//! the sender and the per-slice sequence, applies records to the `Shadow`
//! (validated against the slice; a refusal closes the connection), acks
//! reservations and snapshot ends, and applies peers' directory records.
//! Slice data is accepted only from the slice's primary in this node's
//! view (this node backs it up) or from the member it is being handed over
//! from (this node is the new primary); anything else is refused and
//! audited without touching the shadow. Subscribers and BIB addresses
//! must lie in `translation.client_prefixes`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CP-10, AU-10 - replicated blocks and BIBs let the backup
//!   keep every subscriber's mapping and attribution on takeover
//! - NIST 800-53: SC-5 - workers never wait: bounded rings and peer queues,
//!   counted loss, resync by snapshot; snapshot in flight is throttled
//! - NIST 800-53: SI-4, AU-2 - `plat_cluster_repl_*` metrics and
//!   `cluster_replication_gap` records (one per slice per 10 s)
//! - NIST 800-53: SI-10 - replicated input validated by `Shadow` and
//!   against the client prefixes; AC-3 - slice data only from its owner
//!   (SEC-1, SEC-3), refusals audited (`cluster_peer_rejected`)
//! - NIST 800-53: AU-2 - `cluster_member_state` `syncing` / `in_sync` per
//!   backup peer (NIST-006)

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use plat_audit::{AuditSink, AuditText, ClusterMemberChange, Event, MemberState};
use plat_cluster::{MemberId, Msg, RejectReason, SliceId, SliceMap, SnapRecord, View, WireBib, WireBlock};
use plat_common::Ipv6Cidr;
use plat_nat64::{AdoptInput, Directory, ExportCursor, Home, Nat64, ReplHub, ReplRecord, Shadow, SliceState};

use super::peer::{Net, Refusal};
use super::slice_cidr;

/// Records drained per pump.
const DRAIN_BATCH: usize = 4096;
/// Concurrent snapshots per node.
const MAX_SNAPSHOTS: usize = 4;
/// Upper bound on records per snapshot chunk (a record is at most ~52
/// bytes on the wire; the chunk also fits `max_frame_bytes`).
const CHUNK_RECORDS: usize = 1024;
/// One `cluster_replication_gap` record per slice per this interval.
const GAP_AUDIT_INTERVAL: Duration = Duration::from_secs(10);
/// An awaited ack (snapshot end, reservation) is given up, and the slice
/// snapshotted again, after this long with the peer's data queue empty
/// (B-2: the backup dropped the input, e.g. under a lagging view).
const ACK_TIMEOUT: Duration = Duration::from_secs(3);
/// A backup with a gap asks the primary for a snapshot at most this often
/// per slice (B-4).
const RESYNC_REQ_INTERVAL: Duration = Duration::from_secs(1);
/// Subscriber homes re-announced to one peer per pump (B-9).
const HOMES_PER_PUMP: usize = 1024;

/// Process-wide monotonic milliseconds (shadow ages and adoption agree).
pub fn mono_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Ack timer step for one slice. `since` is when the peer's data queue was
/// first seen empty after the awaited message was queued: the queue is
/// FIFO, so the message was written by then. Later traffic does not restart
/// the timer (B-7: under steady load the queue is rarely empty, and a timer
/// reset by every non-empty sample delayed a rejoining backup's resync, and
/// so its failback, by minutes). `true` once the ack is [`ACK_TIMEOUT`]
/// overdue (the timer is cleared).
fn ack_overdue(since: &mut Option<Instant>, queued: bool, now: Instant) -> bool {
    match *since {
        None => {
            if !queued {
                *since = Some(now);
            }
            false
        }
        Some(t) if now.duration_since(t) >= ACK_TIMEOUT => {
            *since = None;
            true
        }
        Some(_) => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// No target.
    Idle,
    /// Snapshot due.
    Start,
    Snap(ExportCursor),
    /// `SnapshotEnd{seq}` sent, waiting for its ack.
    AwaitEnd(u64),
    InSync,
}

#[derive(Debug, Clone, Copy)]
struct SyncState {
    target: Option<MemberId>,
    phase: Phase,
}

/// Encoded data frames for one peer, queued once per pump
/// ([`Net::send_batch`]).
#[derive(Debug, Default)]
struct Batch {
    buf: Vec<u8>,
    frames: usize,
    /// Slices with records in `buf` (marked dirty if the batch is lost).
    slices: Vec<SliceId>,
    /// Directory records in `buf`.
    dir: u64,
}

/// A data member as configured (for `cluster_member_state` records).
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: MemberId,
    pub name: String,
    pub identity: String,
    pub ip: IpAddr,
}

/// Replication counters.
#[derive(Debug, Default)]
pub struct ReplStats {
    pub resync_total: AtomicU64,
    /// Directory records lost on a full ring (not resent: POAM below).
    pub dir_lost: AtomicU64,
    /// Replication records refused or ignored from peers.
    pub rx_ignored: AtomicU64,
    /// Backup side: sequence gaps seen (records lost on the way, or
    /// refused): `plat_cluster_repl_dropped_total{reason="gap"}`.
    pub rx_gaps: AtomicU64,
    /// Primary side: awaited acks given up ([`ACK_TIMEOUT`]).
    pub ack_timeouts: AtomicU64,
}

pub struct Replicator {
    me: MemberId,
    nat: Arc<Nat64>,
    hub: Arc<ReplHub>,
    net: Arc<Net>,
    pub shadow: Arc<Shadow>,
    dir: Arc<Directory>,
    map: SliceMap,
    data_members: Vec<MemberId>,
    /// (primary, backup) per slice in the adopted view.
    owners: Vec<(Option<MemberId>, Option<MemberId>)>,
    has_view: bool,
    /// Last sequence number sent per slice.
    seq: Vec<u64>,
    sync: Vec<SyncState>,
    /// Outstanding reservation per slice: (seq, blocks).
    pending: Vec<Option<(u64, Vec<WireBlock>)>>,
    /// Backup side: last sequence received per slice, and from whom.
    rx_seq: Vec<u64>,
    rx_from: Vec<Option<MemberId>>,
    /// New-primary side: the member this node gains the slice from (its
    /// primary in the last view that did not give it to this node).
    handover_src: Vec<Option<MemberId>>,
    clients: Vec<Ipv6Cidr>,
    /// Per peer (indexed by member id).
    batches: Vec<Batch>,
    in_batch: Vec<bool>,
    peers: Vec<PeerInfo>,
    /// Last `syncing`/`in_sync` state recorded per peer.
    peer_sync: Vec<Option<MemberState>>,
    gap_last: Vec<Option<Instant>>,
    /// Sequence number of the newest `SnapshotBegin` sent per slice.
    snap_seq: Vec<u64>,
    /// Since when an ack has been awaited with the peer's queue empty.
    wait_since: Vec<Option<Instant>>,
    /// Per peer: next subscriber shard of a pending home re-announcement
    /// (B-9; `None`: nothing due).
    homes_due: Vec<Option<usize>>,
    homes: Vec<(u128, SliceId)>,
    homes_buf: Vec<u8>,
    /// Backup side: the shadow has a gap; last resync request sent.
    gapped: Vec<bool>,
    resync_req: Vec<Option<Instant>>,
    snapshots: usize,
    chunk_records: usize,
    snap_window: usize,
    last_dropped: u64,
    buf: Vec<ReplRecord>,
    audit: AuditSink,
    pub stats: Arc<ReplStats>,
}

impl std::fmt::Debug for Replicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replicator").field("me", &self.me).finish_non_exhaustive()
    }
}

/// Settings of [`Replicator::new`].
#[derive(Debug, Clone)]
pub struct ReplSettings {
    pub me: MemberId,
    pub data_members: Vec<MemberId>,
    pub max_frame: usize,
    pub queue_bytes: usize,
    /// `translation.client_prefixes` (replicated subscribers must match).
    pub clients: Vec<Ipv6Cidr>,
    /// Every other data member.
    pub peers: Vec<PeerInfo>,
}

impl Replicator {
    pub fn new(
        s: ReplSettings,
        nat: Arc<Nat64>,
        hub: Arc<ReplHub>,
        net: Arc<Net>,
        shadow: Arc<Shadow>,
        audit: AuditSink,
    ) -> Result<Self, String> {
        let st = nat.state();
        let map = st.slice_map().cloned().ok_or("HA needs the sliced engine")?;
        let dir = st.directory().cloned().ok_or("HA needs the cluster directory")?;
        let n = map.len();
        let ids = s.data_members.iter().map(|m| usize::from(*m) + 1).max().unwrap_or(0).max(usize::from(s.me) + 1);
        Ok(Self {
            me: s.me,
            nat: nat.clone(),
            hub,
            net,
            shadow,
            dir,
            map,
            data_members: s.data_members,
            owners: vec![(None, None); n],
            has_view: false,
            seq: vec![0; n],
            sync: vec![SyncState { target: None, phase: Phase::Idle }; n],
            pending: vec![None; n],
            rx_seq: vec![0; n],
            rx_from: vec![None; n],
            handover_src: vec![None; n],
            clients: s.clients,
            batches: (0..ids).map(|_| Batch::default()).collect(),
            in_batch: vec![false; n],
            peers: s.peers,
            peer_sync: vec![None; ids],
            gap_last: vec![None; n],
            snap_seq: vec![0; n],
            wait_since: vec![None; n],
            homes_due: vec![None; ids],
            homes: Vec::new(),
            homes_buf: Vec::new(),
            gapped: vec![false; n],
            resync_req: vec![None; n],
            snapshots: 0,
            chunk_records: (s.max_frame / 64).clamp(16, CHUNK_RECORDS),
            snap_window: (s.queue_bytes / 4).max(1),
            last_dropped: 0,
            buf: Vec::with_capacity(DRAIN_BATCH),
            audit,
            stats: Arc::new(ReplStats::default()),
        })
    }

    /// A new view: recompute primary and backup per slice; forget shadows
    /// of slices this node neither owns nor backs up any more.
    pub fn set_view(&mut self, v: &View, weights: &[u32]) {
        self.has_view = true;
        // A peer accepts a home only for a slice the sender owns in its
        // view: announce again under the new one.
        self.announce_homes(None);
        for (s, o) in self.owners.iter_mut().enumerate() {
            let next = v.owners(s as SliceId, weights).map_or((None, None), |(p, b)| (Some(p), b));
            let was_mine = o.0 == Some(self.me) || o.1 == Some(self.me);
            let mine = next.0 == Some(self.me) || next.1 == Some(self.me);
            if was_mine && !mine {
                self.shadow.clear(s as SliceId);
                if let Some(r) = self.rx_from.get_mut(s) {
                    *r = None;
                }
            }
            if let Some(h) = self.handover_src.get_mut(s) {
                if next.0 != Some(self.me) {
                    *h = None;
                } else if o.0 != Some(self.me) {
                    // Gained in this view: from its previous primary.
                    *h = o.0;
                }
                // Still ours in this view: the source stays recorded.
            }
            *o = next;
        }
    }

    /// Re-announces every local subscriber's home to `peer` (link up), or
    /// to every data member (`None`: new view, slice acquired). The
    /// directory is otherwise learnt only from new subscribers, so a
    /// restarted member, or one that missed records, would have no entry
    /// for long-lived subscribers and give a mis-steered one a second home
    /// (B-9, POAM-029).
    pub fn announce_homes(&mut self, peer: Option<MemberId>) {
        for m in self.data_members.clone() {
            if m != self.me
                && peer.is_none_or(|p| p == m)
                && let Some(d) = self.homes_due.get_mut(usize::from(m))
            {
                *d = Some(0);
            }
        }
    }

    /// Sends the next chunk of every due re-announcement (bounded per
    /// pump; a full peer queue retries the chunk later).
    fn announce_step(&mut self) {
        for i in 0..self.homes_due.len() {
            let Some(Some(shard)) = self.homes_due.get(i).copied() else { continue };
            let m = i as MemberId;
            if !self.net.is_up(m) {
                continue;
            }
            if self.net.data_bytes(m) >= self.snap_window {
                continue;
            }
            let mut homes = std::mem::take(&mut self.homes);
            homes.clear();
            let next = self.nat.state().local_homes(shard, HOMES_PER_PUMP, &mut homes);
            let mut buf = std::mem::take(&mut self.homes_buf);
            buf.clear();
            let mut frames = 0;
            for &(sub, slice) in &homes {
                if self.net.encode_into(&ReplRecord::SubHome { sub, slice }.to_msg(0), &mut buf) {
                    frames += 1;
                }
            }
            if self.net.send_batch(m, &mut buf, frames) {
                if let Some(d) = self.homes_due.get_mut(i) {
                    *d = next;
                }
            } else {
                buf.clear();
            }
            self.homes = homes;
            self.homes_buf = buf;
        }
    }

    pub fn owners(&self, s: SliceId) -> (Option<MemberId>, Option<MemberId>) {
        self.owners.get(usize::from(s)).copied().unwrap_or((None, None))
    }

    /// Where records of an Active slice go: its backup, or, once the view
    /// gave it to another member, that member (handover).
    fn want_target(&self, s: SliceId) -> Option<MemberId> {
        if self.nat.state().slice_state(s) != Some(SliceState::Active) {
            return None;
        }
        let (p, b) = self.owners(s);
        let t = if p == Some(self.me) { b } else { p };
        t.filter(|t| *t != self.me && self.data_members.contains(t) && self.net.is_up(*t))
    }

    fn reset_reservations(&mut self, s: SliceId) {
        let st = self.nat.state();
        st.set_reserve_required(s, false);
        st.reserve_reset(s);
        if let Some(p) = self.pending.get_mut(usize::from(s)) {
            *p = None;
        }
    }

    fn set_phase(&mut self, s: SliceId, phase: Phase) {
        let Some(cur) = self.sync.get(usize::from(s)).copied() else { return };
        if matches!(cur.phase, Phase::Snap(_)) && !matches!(phase, Phase::Snap(_)) {
            self.snapshots = self.snapshots.saturating_sub(1);
        }
        if cur.phase == Phase::InSync && phase != Phase::InSync {
            self.reset_reservations(s);
        }
        if let Some(x) = self.sync.get_mut(usize::from(s)) {
            x.phase = phase;
        }
        if let Some(w) = self.wait_since.get_mut(usize::from(s)) {
            *w = None;
        }
    }

    fn next_seq(&mut self, s: SliceId) -> u64 {
        match self.seq.get_mut(usize::from(s)) {
            Some(q) => {
                *q += 1;
                *q
            }
            None => 0,
        }
    }

    /// One round of primary-side work. Returns the records and snapshot
    /// messages moved (0: idle).
    pub fn pump(&mut self) -> usize {
        let moved = self.route_records();
        self.announce_step();
        self.handle_dirty();
        let sent = self.maintain();
        self.member_sync_states();
        self.request_resyncs();
        moved + sent
    }

    /// Drains the rings into one batch per peer, then queues each batch
    /// with one push (PERF-003: no per-record allocation or lock).
    fn route_records(&mut self) -> usize {
        let mut buf = std::mem::take(&mut self.buf);
        buf.clear();
        let n = self.hub.drain(DRAIN_BATCH, &mut buf);
        for r in &buf {
            match r.slice() {
                None => {
                    for i in 0..self.data_members.len() {
                        let m = self.data_members[i];
                        if m != self.me && self.net.is_up(m) {
                            self.batch_dir(m, r);
                        }
                    }
                }
                Some(s) => {
                    let Some(st) = self.sync.get(usize::from(s)).copied() else { continue };
                    let Some(t) = st.target else { continue };
                    if matches!(st.phase, Phase::Idle | Phase::Start) {
                        continue; // the snapshot will carry it
                    }
                    let seq = self.next_seq(s);
                    self.batch_slice(t, s, &r.to_msg(seq));
                }
            }
        }
        self.buf = buf;
        self.flush_batches();
        n
    }

    fn batch_slice(&mut self, t: MemberId, s: SliceId, msg: &Msg) {
        let Some(b) = self.batches.get_mut(usize::from(t)) else {
            self.hub.mark_dirty(s);
            return;
        };
        if !self.net.encode_into(msg, &mut b.buf) {
            self.hub.mark_dirty(s);
            return;
        }
        b.frames += 1;
        if let Some(f) = self.in_batch.get_mut(usize::from(s))
            && !*f
        {
            *f = true;
            b.slices.push(s);
        }
    }

    fn batch_dir(&mut self, m: MemberId, r: &ReplRecord) {
        let Some(b) = self.batches.get_mut(usize::from(m)) else { return };
        if self.net.encode_into(&r.to_msg(0), &mut b.buf) {
            b.frames += 1;
            b.dir += 1;
        } else {
            self.stats.dir_lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Queues every peer's batch; a lost batch marks its slices dirty.
    fn flush_batches(&mut self) {
        for i in 0..self.batches.len() {
            let Some(b) = self.batches.get_mut(i) else { continue };
            if b.frames == 0 {
                continue;
            }
            let sent = self.net.send_batch(i as MemberId, &mut b.buf, b.frames);
            if !sent {
                b.buf.clear();
                self.stats.dir_lost.fetch_add(b.dir, Ordering::Relaxed);
            }
            for s in b.slices.drain(..) {
                if let Some(f) = self.in_batch.get_mut(usize::from(s)) {
                    *f = false;
                }
                if !sent {
                    self.hub.mark_dirty(s);
                }
            }
            b.frames = 0;
            b.dir = 0;
        }
    }

    fn handle_dirty(&mut self) {
        let dropped = self.hub.dropped_total();
        let lost = dropped.saturating_sub(self.last_dropped);
        self.last_dropped = dropped;
        if self.hub.take_dir_dirty() {
            // Lost homes are re-announced in full (B-9).
            // POAM: POAM-029 - a lost SubGone is not resent: the peer keeps
            // a stale home until the slice moves or the peer restarts.
            self.stats.dir_lost.fetch_add(1, Ordering::Relaxed);
            self.announce_homes(None);
        }
        for s in self.hub.take_dirty() {
            let Some(st) = self.sync.get(usize::from(s)).copied() else { continue };
            if st.target.is_none() {
                continue;
            }
            self.stats.resync_total.fetch_add(1, Ordering::Relaxed);
            self.set_phase(s, Phase::Start);
            let now = Instant::now();
            let due =
                self.gap_last.get(usize::from(s)).copied().flatten().is_none_or(|t| now - t >= GAP_AUDIT_INTERVAL);
            if due && let Some(c) = self.map.cidr(s) {
                if let Some(g) = self.gap_last.get_mut(usize::from(s)) {
                    *g = Some(now);
                }
                self.audit.emit(Event::ClusterReplicationGap {
                    ts_us: plat_common::Clock::wall_us(),
                    slice: slice_cidr(c),
                    lost,
                });
            }
        }
    }

    /// Target changes, snapshots and reservation top-up for every slice.
    /// Returns the snapshot messages queued.
    fn maintain(&mut self) -> usize {
        let before: u64 = self.seq.iter().sum();
        for i in 0..self.map.len() {
            let s = i as SliceId;
            let want = self.want_target(s);
            let Some(cur) = self.sync.get(i).copied() else { continue };
            if want != cur.target {
                self.set_phase(s, Phase::Idle);
                self.reset_reservations(s);
                if let Some(x) = self.sync.get_mut(i) {
                    *x = SyncState { target: want, phase: if want.is_some() { Phase::Start } else { Phase::Idle } };
                }
            }
            let Some(st) = self.sync.get(i).copied() else { continue };
            let Some(t) = st.target else { continue };
            match st.phase {
                Phase::Start => {
                    if self.snapshots < MAX_SNAPSHOTS && self.net.data_bytes(t) < self.snap_window {
                        let seq = self.next_seq(s);
                        if self.net.send(t, &Msg::SnapshotBegin { slice: s, seq }) {
                            if let Some(q) = self.snap_seq.get_mut(i) {
                                *q = seq;
                            }
                            self.snapshots += 1;
                            if let Some(x) = self.sync.get_mut(i) {
                                x.phase = Phase::Snap(ExportCursor::default());
                            }
                        }
                    }
                }
                Phase::Snap(cur) => self.snapshot_step(s, t, cur),
                Phase::InSync => {
                    self.topup(s, t);
                    if self.pending.get(i).is_some_and(Option::is_some) {
                        self.ack_timer(s, t);
                    }
                }
                Phase::AwaitEnd(_) => self.ack_timer(s, t),
                Phase::Idle => {}
            }
        }
        let after: u64 = self.seq.iter().sum();
        usize::try_from(after.wrapping_sub(before)).unwrap_or(usize::MAX)
    }

    /// B-2: an ack that does not come once everything queued for `t` was
    /// written (the backup refused or lost the input) restarts the slice's
    /// snapshot instead of waiting forever. Counted, and the gap audited.
    fn ack_timer(&mut self, s: SliceId, t: MemberId) {
        let queued = self.net.data_bytes(t) > 0;
        let Some(w) = self.wait_since.get_mut(usize::from(s)) else { return };
        if ack_overdue(w, queued, Instant::now()) {
            self.stats.ack_timeouts.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(slice = s, peer = t, "replication ack timed out: resync");
            self.hub.mark_dirty(s);
        }
    }

    /// Backup side: asks the primary of every gapped slice for a new
    /// snapshot (rate-limited; repeated until a `SnapshotBegin` arrives).
    fn request_resyncs(&mut self) {
        let now = Instant::now();
        for i in 0..self.gapped.len() {
            if !self.gapped.get(i).copied().unwrap_or(false) {
                continue;
            }
            let s = i as SliceId;
            let (p, b) = self.owners(s);
            let (Some(p), true) = (p, b == Some(self.me)) else {
                if let Some(g) = self.gapped.get_mut(i) {
                    *g = false;
                }
                continue;
            };
            let due =
                self.resync_req.get(i).copied().flatten().is_none_or(|t| now.duration_since(t) >= RESYNC_REQ_INTERVAL);
            if !due || self.serving(s) {
                continue;
            }
            let seq = self.rx_seq.get(i).copied().unwrap_or(0);
            if self.net.send(p, &Msg::Resync { slice: s, seq })
                && let Some(r) = self.resync_req.get_mut(i)
            {
                *r = Some(now);
            }
        }
    }

    /// Primary side: the backup reports a gap at `seq`. A gap older than
    /// the newest snapshot is already being repaired.
    fn on_resync(&mut self, from: MemberId, s: SliceId, seq: u64) {
        let Some(st) = self.sync.get(usize::from(s)).copied() else { return };
        if st.target != Some(from) || matches!(st.phase, Phase::Idle | Phase::Start) {
            return;
        }
        if seq < self.snap_seq.get(usize::from(s)).copied().unwrap_or(0) {
            return;
        }
        self.hub.mark_dirty(s);
    }

    /// `cluster_member_state` `syncing` / `in_sync` for each backup peer
    /// this node streams to: `syncing` while any of its slices is being
    /// snapshotted, `in_sync` once all are (NIST-006).
    fn member_sync_states(&mut self) {
        for i in 0..self.peers.len() {
            let Some(p) = self.peers.get(i) else { continue };
            let id = p.id;
            let mut any = false;
            let mut syncing = false;
            for x in self.sync.iter().filter(|x| x.target == Some(id)) {
                any = true;
                syncing |= x.phase != Phase::InSync;
            }
            let state = match (any, syncing) {
                (false, _) => None,
                (true, true) => Some(MemberState::Syncing),
                (true, false) => Some(MemberState::InSync),
            };
            let Some(last) = self.peer_sync.get_mut(usize::from(id)) else { continue };
            if state.is_none() || *last == state {
                if state.is_none() {
                    *last = None;
                }
                continue;
            }
            *last = state;
            let (Some(state), Some(p)) = (state, self.peers.get(i)) else { continue };
            self.audit.emit(Event::ClusterMemberState {
                ts_us: plat_common::Clock::wall_us(),
                member: Arc::new(ClusterMemberChange {
                    peer_id: p.id,
                    name: AuditText::new(&p.name, AuditText::SUBJECT_MAX),
                    identity: AuditText::new(&p.identity, AuditText::SUBJECT_MAX),
                    ip: p.ip,
                    state,
                    epoch: self.net.epoch.load(Ordering::Relaxed),
                }),
            });
        }
    }

    fn snapshot_step(&mut self, s: SliceId, t: MemberId, mut cur: ExportCursor) {
        while self.net.data_bytes(t) < self.snap_window {
            let (recs, next) = self.nat.state().export_slice(s, cur, self.chunk_records);
            for chunk in recs.chunks(self.chunk_records) {
                let seq = self.next_seq(s);
                let msg = Msg::SnapshotChunk { slice: s, seq, records: chunk.to_vec() };
                if !self.net.send(t, &msg) {
                    self.set_phase(s, Phase::Start);
                    return;
                }
            }
            match next {
                Some(n) => cur = n,
                None => {
                    let seq = self.next_seq(s);
                    if self.net.send(t, &Msg::SnapshotEnd { slice: s, seq }) {
                        self.set_phase(s, Phase::AwaitEnd(seq));
                    } else {
                        self.set_phase(s, Phase::Start);
                    }
                    return;
                }
            }
        }
        if let Some(x) = self.sync.get_mut(usize::from(s)) {
            x.phase = Phase::Snap(cur);
        }
    }

    /// Keeps `reserve_ahead_blocks` blocks reserved with the in-sync backup.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-10 - a block is handed out only after the backup
    ///   acked its reservation, so a takeover never reuses a block the old
    ///   owner may have used without the backup knowing
    fn topup(&mut self, s: SliceId, t: MemberId) {
        let nat = self.nat.clone();
        let st = nat.state();
        if self.pending.get(usize::from(s)).is_some_and(Option::is_some) || st.reserve_deficit(s) == 0 {
            return;
        }
        let blocks = st.reserve_topup(s);
        if blocks.is_empty() {
            return;
        }
        let seq = self.next_seq(s);
        if self.net.send(t, &Msg::Reserve { slice: s, seq, blocks: blocks.clone() }) {
            if let Some(p) = self.pending.get_mut(usize::from(s)) {
                *p = Some((seq, blocks));
            }
        } else {
            st.reserve_reset(s);
            self.set_phase(s, Phase::Start);
        }
    }

    fn on_ack(&mut self, from: MemberId, s: SliceId, seq: u64) {
        let Some(st) = self.sync.get(usize::from(s)).copied() else { return };
        if st.target != Some(from) {
            return;
        }
        if st.phase == Phase::AwaitEnd(seq) {
            self.set_phase(s, Phase::InSync);
            self.nat.state().set_reserve_required(s, true);
            self.topup(s, from);
            return;
        }
        if let Some(p) = self.pending.get_mut(usize::from(s))
            && p.as_ref().is_some_and(|(q, _)| *q == seq)
            && let Some((_, blocks)) = p.take()
        {
            self.nat.state().reserve_acked(s, &blocks);
            if let Some(w) = self.wait_since.get_mut(usize::from(s)) {
                *w = None;
            }
        }
    }

    /// Drains every ring and returns the last sequence number sent for
    /// `s` (`HandoverFence.final_seq`).
    pub fn flush(&mut self, s: SliceId) -> u64 {
        for _ in 0..64 {
            if self.route_records() == 0 {
                break;
            }
        }
        self.seq.get(usize::from(s)).copied().unwrap_or(0)
    }

    /// The backup's state of `s` for adoption (cleared).
    pub fn take(&mut self, s: SliceId) -> AdoptInput {
        if let Some(r) = self.rx_from.get_mut(usize::from(s)) {
            *r = None;
        }
        self.shadow.take(s, mono_ms())
    }

    /// Whether the target of an Active slice is in sync.
    pub fn protected(&self, s: SliceId) -> bool {
        self.sync.get(usize::from(s)).is_some_and(|x| x.phase == Phase::InSync)
    }

    /// The member that is in sync for `s`, if any.
    pub fn in_sync_target(&self, s: SliceId) -> Option<MemberId> {
        self.sync.get(usize::from(s)).filter(|x| x.phase == Phase::InSync).and_then(|x| x.target)
    }

    /// A link went down: reset every slice that streamed to it.
    pub fn link_down(&mut self, peer: MemberId) {
        for i in 0..self.sync.len() {
            if self.sync.get(i).is_some_and(|x| x.target == Some(peer)) {
                let s = i as SliceId;
                self.set_phase(s, Phase::Idle);
                self.reset_reservations(s);
                if let Some(x) = self.sync.get_mut(i) {
                    x.target = None;
                }
            }
        }
        // Backup side: what was received stays valid (a dead primary is
        // exactly when the shadow is needed); a reconnect starts with a
        // new snapshot, and a sequence gap marks the shadow anyway.
    }

    /// Whether `from` may send records of slice `s` to this node: `from`
    /// is the slice's primary and this node its backup, or this node is the
    /// new primary and `from` the member it gains the slice from; this node
    /// does not serve the slice yet. Refused input never touches the
    /// shadow (SEC-1, SEC-9).
    fn accepts(&self, from: MemberId, s: SliceId) -> Result<(), Refusal> {
        if from == self.me || !self.has_view {
            return Err(Refusal::drop(RejectReason::NotAllowed, format!("slice {s}: no view")));
        }
        let (p, b) = self.owners(s);
        let src = self.handover_src.get(usize::from(s)).copied().flatten();
        let owner = (b == Some(self.me) && p == Some(from)) || (p == Some(self.me) && src == Some(from));
        if !owner {
            return Err(Refusal::drop(RejectReason::NotAllowed, format!("slice {s}: member {from} is not its owner")));
        }
        Ok(())
    }

    /// Whether this node already serves `s` (trailing records of a
    /// handover are ignored, not refused).
    fn serving(&self, s: SliceId) -> bool {
        self.nat.state().slice_state(s) == Some(SliceState::Active)
    }

    /// SI-10: replicated subscribers and BIB addresses must lie in the
    /// client prefixes.
    fn sub_ok(&self, sub: u128) -> bool {
        self.clients.iter().any(|c| c.contains(sub))
    }

    fn bib_ok(&self, b: &WireBib) -> bool {
        self.sub_ok(b.sub) && self.sub_ok(b.v6)
    }

    fn record_ok(&self, r: &ReplRecord) -> bool {
        match r {
            ReplRecord::BlockAlloc { sub, .. }
            | ReplRecord::BlockRelease { sub, .. }
            | ReplRecord::SubHome { sub, .. }
            | ReplRecord::SubGone { sub } => self.sub_ok(*sub),
            ReplRecord::BibCreate { bib, .. } => self.bib_ok(bib),
            ReplRecord::BibDelete { .. } => true,
        }
    }

    fn invalid(what: impl std::fmt::Debug) -> Refusal {
        Refusal::close(RejectReason::InvalidInput, format!("{what:?}"))
    }

    /// Per-slice sequence check; a gap or a new sender needs a snapshot,
    /// which the backup requests ([`Replicator::request_resyncs`], B-4).
    fn check_seq(&mut self, from: MemberId, s: SliceId, seq: u64) {
        let i = usize::from(s);
        let same = self.rx_from.get(i).copied().flatten() == Some(from);
        let prev = self.rx_seq.get(i).copied().unwrap_or(0);
        if !same || seq != prev.wrapping_add(1) {
            self.shadow.mark_gap(s);
            self.stats.rx_gaps.fetch_add(1, Ordering::Relaxed);
            if let Some(g) = self.gapped.get_mut(i) {
                *g = true;
            }
        }
        if let Some(r) = self.rx_seq.get_mut(i) {
            *r = seq;
        }
        if let Some(r) = self.rx_from.get_mut(i) {
            *r = Some(from);
        }
    }

    /// One replication message from member `from` (connection thread).
    /// `Err`: refused (audited by the caller; closes the connection when
    /// the input itself is invalid).
    pub fn on_data(&mut self, from: MemberId, msg: Msg) -> Result<(), Refusal> {
        let err = Self::invalid;
        match msg {
            Msg::SubHome { sub, slice } => {
                // SEC-3: a member announces homes only in its own slices.
                if !self.sub_ok(sub) {
                    return Err(err("SubHome outside the client prefixes"));
                }
                if !self.has_view || self.owners(slice).0 != Some(from) {
                    return Err(Refusal::drop(
                        RejectReason::NotAllowed,
                        format!("SubHome for slice {slice} not owned by member {from}"),
                    ));
                }
                self.dir.insert(sub, Home { node: from, slice });
            }
            Msg::SubGone { sub } => {
                if !self.sub_ok(sub) {
                    return Err(err("SubGone outside the client prefixes"));
                }
                // Removes only a home that `from` itself announced.
                self.dir.remove(sub, from);
            }
            Msg::Ack { slice, seq } => self.on_ack(from, slice, seq),
            Msg::Resync { slice, seq } => self.on_resync(from, slice, seq),
            Msg::Reserve { slice, seq, blocks } => {
                if self.serving(slice) {
                    self.stats.rx_ignored.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                self.accepts(from, slice)?;
                self.check_seq(from, slice, seq);
                self.shadow.reserve(slice, &blocks).map_err(Self::invalid)?;
                self.net.send(from, &Msg::Ack { slice, seq });
            }
            Msg::SnapshotBegin { slice, seq } => {
                if self.serving(slice) {
                    self.stats.rx_ignored.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                self.accepts(from, slice)?;
                self.shadow.snapshot_begin(slice).map_err(Self::invalid)?;
                if let Some(g) = self.gapped.get_mut(usize::from(slice)) {
                    *g = false;
                }
                if let Some(r) = self.rx_seq.get_mut(usize::from(slice)) {
                    *r = seq;
                }
                if let Some(r) = self.rx_from.get_mut(usize::from(slice)) {
                    *r = Some(from);
                }
            }
            Msg::SnapshotChunk { slice, seq, records } => {
                if self.serving(slice) {
                    self.stats.rx_ignored.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                self.accepts(from, slice)?;
                let valid = records.iter().all(|r| match r {
                    SnapRecord::Block { sub, .. } => self.sub_ok(*sub),
                    SnapRecord::Bib(b) => self.bib_ok(b),
                });
                if !valid {
                    return Err(err("snapshot record outside the client prefixes"));
                }
                self.check_seq(from, slice, seq);
                self.shadow.snapshot_records(slice, &records).map_err(Self::invalid)?;
            }
            Msg::SnapshotEnd { slice, seq } => {
                if self.serving(slice) {
                    self.stats.rx_ignored.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                self.accepts(from, slice)?;
                let i = usize::from(slice);
                let ok = self.rx_from.get(i).copied().flatten() == Some(from)
                    && self.rx_seq.get(i).copied().unwrap_or(0).wrapping_add(1) == seq;
                self.check_seq(from, slice, seq);
                if ok {
                    self.shadow.snapshot_end(slice).map_err(Self::invalid)?;
                    self.net.send(from, &Msg::Ack { slice, seq });
                }
            }
            m => {
                let Some((rec, seq)) = ReplRecord::from_msg(&m) else {
                    self.stats.rx_ignored.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                };
                let Some(s) = rec.slice() else { return Ok(()) };
                if self.serving(s) {
                    self.stats.rx_ignored.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                self.accepts(from, s)?;
                if !self.record_ok(&rec) {
                    return Err(err("record outside the client prefixes"));
                }
                self.check_seq(from, s, seq);
                self.shadow.apply(&rec, mono_ms()).map_err(Self::invalid)?;
            }
        }
        Ok(())
    }

    /// `(active, fenced, backup_in_sync, backup_syncing, unprotected)`.
    pub fn slice_counts(&self) -> [u64; 5] {
        let st = self.nat.state();
        let mut c = [0u64; 5];
        for i in 0..self.map.len() {
            let s = i as SliceId;
            match st.slice_state(s) {
                Some(SliceState::Active) => {
                    c[0] += 1;
                    if !self.protected(s) {
                        c[4] += 1;
                    }
                }
                Some(SliceState::Fenced | SliceState::Adopting) if self.owners(s).1 != Some(self.me) => c[1] += 1,
                _ => {
                    if self.owners(s).1 == Some(self.me) {
                        if self.shadow.in_sync(s) {
                            c[2] += 1;
                        } else {
                            c[3] += 1;
                        }
                    }
                }
            }
        }
        c
    }

    /// Whether every slice this node backs up in the current view is in
    /// sync (`Msg::SyncStatus`, failback gate B-3). `None` without a view.
    pub fn backup_in_sync(&self) -> Option<bool> {
        self.has_view.then(|| self.slice_counts()[3] == 0)
    }

    /// Snapshot records of `s` (tests).
    #[cfg(test)]
    pub fn shadow_counts(&self, s: SliceId) -> (usize, usize) {
        self.shadow.counts(s)
    }
}

#[cfg(test)]
mod ack_tests {
    use super::*;

    /// B-7: steady traffic to the backup (the queue is non-empty at most
    /// samples) does not keep restarting the ack timer.
    #[test]
    fn ack_timer_fires_under_steady_traffic() {
        let t0 = Instant::now();
        let mut since = None;
        let step = Duration::from_millis(10);
        let mut fired = None;
        for i in 0..2_000u32 {
            let now = t0 + step * i;
            // Empty only at one sample in ten.
            if ack_overdue(&mut since, i % 10 != 5, now) {
                fired = Some(now - t0);
                break;
            }
        }
        let fired = fired.expect("ack timer never fired under steady traffic");
        assert!(fired <= ACK_TIMEOUT + Duration::from_millis(100), "fired after {fired:?}");
        assert!(since.is_none());
    }

    #[test]
    fn ack_timer_waits_for_the_queue_to_drain() {
        let t0 = Instant::now();
        let mut since = None;
        assert!(!ack_overdue(&mut since, true, t0 + ACK_TIMEOUT * 2));
        assert!(since.is_none());
        assert!(!ack_overdue(&mut since, false, t0 + ACK_TIMEOUT * 2));
        assert!(!ack_overdue(&mut since, true, t0 + ACK_TIMEOUT * 3 - Duration::from_millis(1)));
        assert!(ack_overdue(&mut since, true, t0 + ACK_TIMEOUT * 3));
    }
}
