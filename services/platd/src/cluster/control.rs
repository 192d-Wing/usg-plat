//! Membership driver (`plat-cluster-ctl`), cluster state file, operator
//! socket (`plat-cluster-cli`), status for `/metrics` and `/cluster`.
//!
//! The driver feeds monotonic time and peer messages into the sans-IO
//! `Membership` and executes its actions in order:
//! - `Persist`: `state_dir/cluster.state` written, fsynced and renamed
//!   before anything later in the batch; if that fails the rest of the
//!   batch sends nothing and acquires nothing (fencing still runs);
//! - `Acquire`: replicated state detached from the shadow (an incomplete
//!   shadow holds back every unknown block) into an adoption cursor; one
//!   adoption at a time, in order, stepped by the run loop between its
//!   message and tick work (`ADOPT_STEP_BUDGET` per step, POAM-047). The
//!   last step queues `cluster_slice_acquire` and the adopt records, then
//!   sets the slice Active; then the announce hook, and a handover answers
//!   `HandoverDone`. Handover/failback adoptions start at most
//!   `max_concurrent_handovers` per call; `refuse_new_bindings` without
//!   audit room pauses the cursor until the next tick;
//! - `Release`: fence first, `cluster_slice_release`, withdraw hook; on a
//!   handover the slice's replication is flushed, then a release cursor
//!   (one per slice, FIFO, stepped like an adoption and alternating with
//!   it, POAM-048) removes its state and releases its blocks with
//!   `plat.release_reason = handover`; only when it is done is
//!   `HandoverFence{final_seq}` sent. An adoption of a slice still being
//!   released waits for it. A slice still being adopted is abandoned
//!   instead (stepwise, release records only for blocks already logged)
//!   and nothing is handed over.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-24 - persisted epochs and votes (fsync before use);
//!   lease loss fences; CP-10 - takeover by in-sync backups
//! - NIST 800-53: AU-2, AU-3, AU-12 - view changes, member state, slice
//!   acquire/release and adopt records (logged before use, AU-10)
//! - NIST 800-53: AC-3, AC-6 - operator socket 0600 in the 0700 state
//!   directory; peer credentials checked (uid 0 or the daemon's uid);
//!   manual takeover only with `auto_failover = false`, refused while the
//!   member's peer link is up unless forced; gained slices are always
//!   held for `safe` (SEC-2, SEC-R1-1)
//! - NIST 800-53: AU-2, AU-3, AU-12 - `cluster_operator_command` before an
//!   accepted command acts and for every refusal (SEC-5, NIST-002)

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write as _};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use plat_audit::{
    AcquireReason as AuditAcquire, AuditSink, AuditText, BlockReleaseReason, ClusterMemberChange, ClusterView, Event,
    MemberState, OperatorCommand, OperatorCommandKind, OperatorRefusal, SliceAcquire, SliceReleaseReason, TryEmit,
    ViewReason,
};
use plat_cluster::membership::ElectionStats;
use plat_cluster::{
    AcquireReason, Action, MemberId, Membership, MembershipConfig, Msg, Persisted, ReleaseReason, Role, SliceId,
    SliceMap, View,
};
use plat_common::{Clock, Config};
use plat_nat64::{
    ADOPT_STEP_BUDGET, AdoptError, AdoptInput, AdoptMeta, AdoptSource, Adoption, Nat64, RELEASE_STEP_BUDGET, Release,
    ReleaseStep, ReplHub, Shadow, SliceState, Step,
};
use plat_tls::{AllowList, PeerConfigs};

use super::hooks::{HookJob, Hooks, check_hook};
use plat_io::cred::PeerCred;

use super::peer::{Inbound, Net, NetConfig, PeerSpec, Refusal};
use super::replicator::{PeerInfo, ReplSettings, Replicator, mono_ms};
use super::{digest_input, slice_cidr, voting_digest};

/// Bound of the control channel (peer messages and commands).
const CTL_QUEUE: usize = 4096;
/// Operator socket name in `state_dir`.
pub const CTL_SOCK: &str = "ctl.sock";
const STATE_FILE: &str = "cluster.state";

// ---------------------------------------------------------------- state file

/// Checks (or creates) the state directory: a real directory, not a
/// symlink, mode 0700 (nothing for group or others). Returns its owner uid
/// (the daemon user).
pub fn check_state_dir(d: &Path) -> Result<u32, String> {
    if std::fs::symlink_metadata(d).is_err() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let m = std::fs::symlink_metadata(d).map_err(|e| format!("{}: {e}", d.display()))?;
    if !m.file_type().is_dir() {
        return Err(format!("{}: state_dir must be a directory (not a symlink)", d.display()));
    }
    if m.permissions().mode() & 0o077 != 0 {
        return Err(format!("{}: state_dir must be mode 0700", d.display()));
    }
    Ok(m.uid())
}

/// Reads `cluster.state`; absent = fresh node. A malformed file refuses
/// the start (an epoch must never be reused, SC-24).
pub fn load_state(dir: &Path) -> Result<Persisted, String> {
    let p = dir.join(STATE_FILE);
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Persisted::default()),
        Err(e) => return Err(format!("{}: {e}", p.display())),
    };
    let mut st = Persisted::default();
    let bad = || format!("{}: malformed cluster state", p.display());
    for line in text.lines() {
        let (k, v) = line.split_once('=').ok_or_else(bad)?;
        match k {
            "term" => st.term = v.parse().map_err(|_| bad())?,
            "voted_for" if v == "none" => st.voted_for = None,
            "voted_for" => st.voted_for = Some(v.parse().map_err(|_| bad())?),
            "epoch" => st.epoch = v.parse().map_err(|_| bad())?,
            _ => return Err(bad()),
        }
    }
    Ok(st)
}

/// Writes `cluster.state` durably: temp file, fsync, rename, fsync dir.
pub fn save_state(dir: &Path, st: &Persisted) -> std::io::Result<()> {
    let tmp = dir.join(format!("{STATE_FILE}.tmp"));
    let body = format!(
        "term={}\nvoted_for={}\nepoch={}\n",
        st.term,
        st.voted_for.map_or_else(|| "none".to_string(), |v| v.to_string()),
        st.epoch
    );
    {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(STATE_FILE))?;
    std::fs::File::open(dir)?.sync_all()
}

// ---------------------------------------------------------------- shared

/// Operator commands (`platd cluster ...`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `force`: although the member's peer link is up (SEC-2).
    Takeover(MemberId, bool),
    Restore(MemberId),
}

impl Command {
    fn audit(self) -> (OperatorCommandKind, Option<MemberId>, bool) {
        match self {
            Command::Takeover(m, f) => (OperatorCommandKind::Takeover, Some(m), f),
            Command::Restore(m) => (OperatorCommandKind::Restore, Some(m), false),
        }
    }
}

enum In {
    Msg(MemberId, Msg),
    Cmd(Command, Option<PeerCred>, SyncSender<String>),
}

/// `cluster_operator_command` (AU-2, AU-3: who, what, outcome). `true`
/// when queued (or, with `strict` off, handed to `emit`).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-5, AU-12 - with `refuse_new_bindings` (`strict`) the
///   record is offered with `try_emit` and an accepted command does not act
///   unless it was queued (NIST-R1-01)
fn audit_operator(
    audit: &AuditSink,
    strict: bool,
    (command, member, force): (OperatorCommandKind, Option<MemberId>, bool),
    cred: Option<PeerCred>,
    refused: Option<OperatorRefusal>,
) -> bool {
    let ev = Event::ClusterOperatorCommand {
        ts_us: Clock::wall_us(),
        cmd: Arc::new(OperatorCommand {
            command,
            member,
            force,
            peer_uid: cred.map(|c| c.uid),
            peer_pid: cred.and_then(|c| c.pid),
            refused,
        }),
    };
    if strict {
        matches!(audit.try_emit(ev), TryEmit::Queued)
    } else {
        audit.emit(ev);
        true
    }
}

/// One voter as configured.
#[derive(Debug, Clone)]
pub struct Voter {
    pub id: MemberId,
    pub name: String,
    pub identity: String,
    pub addr: std::net::SocketAddr,
    pub witness: bool,
}

#[derive(Debug, Default, Clone)]
struct Snap {
    role: Option<Role>,
    view: Option<View>,
    committed: u64,
    leader: Option<MemberId>,
    lease_remaining: u64,
    weights: Vec<u32>,
    /// Election counters of this process's `Membership`.
    election: ElectionStats,
}

/// State shared by the cluster threads, `/metrics` and `/cluster`.
pub struct Shared {
    pub me: MemberId,
    pub voters: Vec<Voter>,
    pub net: Arc<Net>,
    pub repl: Option<Arc<Mutex<Replicator>>>,
    pub hub: Option<Arc<ReplHub>>,
    pub nat: Option<Arc<Nat64>>,
    map: Option<SliceMap>,
    snap: Mutex<Snap>,
    /// [startup, takeover, handover, failback, manual]
    takeovers: [AtomicU64; 5],
    handovers: AtomicU64,
    persist_failures: AtomicU64,
    adopt: AdoptMetrics,
    release: ReleaseMetrics,
    hook_stats: Option<Arc<super::hooks::HookStats>>,
    /// Control thread input (operator commands).
    ctl: SyncSender<In>,
    audit: AuditSink,
    /// The daemon's effective uid (allowed on the operator socket besides
    /// root).
    daemon_uid: u32,
    /// `CLOCK_MONOTONIC_COARSE` ns at which this member self-fences (lease
    /// end), refreshed every control step: the XDP dead-man deadline is
    /// capped by it (plan §9, SC-24).
    #[cfg(all(feature = "xdp", target_os = "linux"))]
    lease_fence_ns: AtomicU64,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").field("me", &self.me).finish_non_exhaustive()
    }
}

const TAKEOVER_LABELS: [&str; 5] = ["startup", "takeover", "handover", "failback", "manual"];

/// `plat_cluster_adoptions_abandoned_total` labels; "epoch": the slice left
/// `Adopting` under the cursor (`AdoptError::Interrupted`).
const ABANDON_LABELS: [&str; 5] = ["lease_lost", "reassigned", "handover", "shutdown", "epoch"];
const ABANDON_EPOCH: usize = 4;
/// Window of `plat_cluster_adopt_step_seconds_max`.
const STEP_MAX_WINDOW_MS: u64 = 60_000;

fn abandon_ix(r: ReleaseReason) -> usize {
    match r {
        ReleaseReason::LeaseLost => 0,
        ReleaseReason::Fenced => 1,
        ReleaseReason::Handover => 2,
        ReleaseReason::Shutdown => 3,
    }
}

/// Whether an abandoned adoption returns its detached state to the shadow
/// (POAM-047 fix round 1): only when the slice went to nobody else (lease
/// lost or fenced with no other owner), so a regain adopts it in full. A
/// slice given to another member or handed back is that member's state,
/// and a stopping node keeps nothing.
fn keeps_shadow(reason: ReleaseReason, new_owner: Option<MemberId>, me: MemberId) -> bool {
    matches!(reason, ReleaseReason::LeaseLost | ReleaseReason::Fenced) && new_owner.is_none_or(|n| n == me)
}

/// A pending job that needs no import (the slice is already Active or
/// gone, or a complete fenced slice of this node is regained with one
/// record) runs ahead of the adoption in progress (POAM-047 F3): decision 3
/// orders imports only.
/// A slice being released never runs ahead: its job waits until the
/// release is done (POAM-048).
fn runs_ahead(state: Option<SliceState>, releasing: bool, prev_owner: Option<MemberId>, me: MemberId) -> bool {
    if releasing {
        return false;
    }
    match state {
        Some(SliceState::Active) | None => true,
        Some(SliceState::Fenced) => prev_owner == Some(me),
        Some(_) => false,
    }
}

/// How `shutdown` releases one slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownRelease {
    /// The slice was being adopted and was just abandoned: it never served,
    /// so it is not fenced or handed over (no `HandoverFence`, like
    /// decision 2); only its `cluster_slice_release` record.
    NeverServed,
    HandOver(MemberId),
    Release,
}

fn shutdown_release(
    slice: SliceId,
    abandoned: Option<SliceId>,
    auto_failover: bool,
    backup: Option<MemberId>,
) -> ShutdownRelease {
    if abandoned == Some(slice) {
        return ShutdownRelease::NeverServed;
    }
    match backup {
        Some(b) if auto_failover => ShutdownRelease::HandOver(b),
        _ => ShutdownRelease::Release,
    }
}

/// Chunked adoption on the control thread (SI-4, POAM-047).
#[derive(Debug, Default)]
struct AdoptMetrics {
    steps: AtomicU64,
    /// Longest step (ns) in the window starting at `max_since_ms`.
    step_max_ns: AtomicU64,
    max_since_ms: AtomicU64,
    abandoned: [AtomicU64; 5],
    /// 1 while an adoption (or its abandon) is in progress.
    adopting: AtomicU64,
}

/// Notes one step of `d` in a windowed maximum (`max_ns` since `since_ms`).
fn note_step(max_ns: &AtomicU64, since_ms: &AtomicU64, d: Duration) {
    let now = mono_ms();
    let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
    if now.saturating_sub(since_ms.load(Ordering::Relaxed)) >= STEP_MAX_WINDOW_MS {
        since_ms.store(now, Ordering::Relaxed);
        max_ns.store(ns, Ordering::Relaxed);
    } else {
        max_ns.fetch_max(ns, Ordering::Relaxed);
    }
}

/// The windowed maximum, 0 once the window has passed.
fn step_max(max_ns: &AtomicU64, since_ms: &AtomicU64) -> u64 {
    let fresh = mono_ms().saturating_sub(since_ms.load(Ordering::Relaxed)) < STEP_MAX_WINDOW_MS;
    if fresh { max_ns.load(Ordering::Relaxed) } else { 0 }
}

impl AdoptMetrics {
    fn step(&self, d: Duration) {
        self.steps.fetch_add(1, Ordering::Relaxed);
        note_step(&self.step_max_ns, &self.max_since_ms, d);
    }

    fn render(&self, o: &mut String) {
        use std::fmt::Write as _;
        let max = step_max(&self.step_max_ns, &self.max_since_ms);
        let _ = write!(
            o,
            "# TYPE plat_cluster_adopt_steps_total counter\nplat_cluster_adopt_steps_total {}\n\
             # TYPE plat_cluster_adopt_step_seconds_max gauge\nplat_cluster_adopt_step_seconds_max {:.6}\n\
             # TYPE plat_cluster_adopting_slices gauge\nplat_cluster_adopting_slices {}\n\
             # TYPE plat_cluster_adoptions_abandoned_total counter\n",
            self.steps.load(Ordering::Relaxed),
            max as f64 / 1e9,
            self.adopting.load(Ordering::Relaxed)
        );
        for (l, c) in ABANDON_LABELS.iter().zip(&self.abandoned) {
            let _ =
                writeln!(o, "plat_cluster_adoptions_abandoned_total{{reason=\"{l}\"}} {}", c.load(Ordering::Relaxed));
        }
    }
}

/// Chunked Active-slice release on the control thread (SI-4, POAM-048).
#[derive(Debug)]
struct ReleaseMetrics {
    steps: AtomicU64,
    /// Longest step (ns) in the window starting at `max_since_ms`.
    step_max_ns: AtomicU64,
    max_since_ms: AtomicU64,
    /// Slices with a release cursor (in progress or queued).
    releasing: AtomicU64,
    /// Steps that stopped on a full audit queue (`refuse_new_bindings`).
    audit_paused: AtomicU64,
    /// `mono_ms` at which the oldest queued release started
    /// (`u64::MAX`: none). A stalled-but-connected logger shows as a
    /// growing age (SEC-003).
    oldest_started_ms: AtomicU64,
}

impl Default for ReleaseMetrics {
    fn default() -> Self {
        Self {
            steps: AtomicU64::new(0),
            step_max_ns: AtomicU64::new(0),
            max_since_ms: AtomicU64::new(0),
            releasing: AtomicU64::new(0),
            audit_paused: AtomicU64::new(0),
            oldest_started_ms: AtomicU64::new(u64::MAX),
        }
    }
}

impl ReleaseMetrics {
    /// Age (s) of the oldest queued release at `now_ms`, 0 if none.
    fn oldest_age(&self, now_ms: u64) -> f64 {
        match self.oldest_started_ms.load(Ordering::Relaxed) {
            u64::MAX => 0.0,
            t => now_ms.saturating_sub(t) as f64 / 1e3,
        }
    }

    fn step(&self, d: Duration) {
        self.steps.fetch_add(1, Ordering::Relaxed);
        note_step(&self.step_max_ns, &self.max_since_ms, d);
    }

    fn render(&self, o: &mut String) {
        use std::fmt::Write as _;
        let max = step_max(&self.step_max_ns, &self.max_since_ms);
        let _ = write!(
            o,
            "# TYPE plat_cluster_release_steps_total counter\nplat_cluster_release_steps_total {}\n\
             # TYPE plat_cluster_release_step_seconds_max gauge\nplat_cluster_release_step_seconds_max {:.6}\n\
             # TYPE plat_cluster_releasing_slices gauge\nplat_cluster_releasing_slices {}\n\
             # TYPE plat_cluster_release_audit_paused_total counter\nplat_cluster_release_audit_paused_total {}\n\
             # TYPE plat_cluster_release_oldest_age_seconds gauge\nplat_cluster_release_oldest_age_seconds {:.3}\n",
            self.steps.load(Ordering::Relaxed),
            max as f64 / 1e9,
            self.releasing.load(Ordering::Relaxed),
            self.audit_paused.load(Ordering::Relaxed),
            self.oldest_age(mono_ms())
        );
    }
}

fn takeover_ix(r: AuditAcquire) -> usize {
    match r {
        AuditAcquire::Startup => 0,
        AuditAcquire::Takeover => 1,
        AuditAcquire::Handover => 2,
        AuditAcquire::Failback => 3,
        AuditAcquire::Manual => 4,
    }
}

/// Election counters of this process's `Membership` (zero on a witness and
/// in manual mode, which never campaign). `result`: `won` (elected),
/// `timeout` (no majority within the candidate round: split vote or slow
/// voters), `yield` (gave way to a lower-id candidate of the same term).
/// Rounds that end because another leader or a newer term shows up are not
/// counted.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-4 (System Monitoring) - repeated `timeout` or `yield`
///   rounds show an election that is not converging; CP-10 - shows how many
///   split or timed-out rounds a takeover took (the `k` term of the bound in
///   `plat-cluster/tests/sim.rs`). The counters record round outcomes, not
///   time; they do not measure how long a takeover took
fn render_election(o: &mut String, e: &ElectionStats) {
    use std::fmt::Write as _;
    let _ = write!(
        o,
        "# TYPE plat_cluster_election_rounds_total counter\n\
         plat_cluster_election_rounds_total{{result=\"won\"}} {}\n\
         plat_cluster_election_rounds_total{{result=\"timeout\"}} {}\n\
         plat_cluster_election_rounds_total{{result=\"yield\"}} {}\n\
         # TYPE plat_cluster_heartbeats_expedited_total counter\n\
         plat_cluster_heartbeats_expedited_total {}\n",
        e.won, e.timeout, e.yielded, e.heartbeats_expedited
    );
}

fn role_str(r: Option<Role>) -> &'static str {
    match r {
        Some(Role::Follower) => "follower",
        Some(Role::PreCandidate) => "pre_candidate",
        Some(Role::Candidate) => "candidate",
        Some(Role::Leader) => "leader",
        Some(Role::Witness) => "witness",
        Some(Role::Manual) => "manual",
        None => "stopped",
    }
}

fn ids(v: &[MemberId]) -> String {
    v.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
}

impl Shared {
    #[cfg(test)]
    /// Current view (tests, status).
    pub fn view(&self) -> Option<View> {
        self.snap.lock().view.clone()
    }

    #[cfg(test)]
    /// Active slices in the engine.
    pub fn active_slices(&self) -> usize {
        let Some(nat) = &self.nat else { return 0 };
        let n = self.map.as_ref().map_or(0, SliceMap::len);
        (0..n).filter(|s| nat.state().slice_state(*s as SliceId) == Some(SliceState::Active)).count()
    }

    #[cfg(test)]
    pub fn daemon_uid(&self) -> u32 {
        self.daemon_uid
    }

    #[cfg(test)]
    pub fn takeovers(&self, label: &str) -> u64 {
        TAKEOVER_LABELS.iter().position(|l| *l == label).map_or(0, |i| self.takeovers[i].load(Ordering::Relaxed))
    }

    /// `CLOCK_MONOTONIC_COARSE` ns of this member's lease self-fence (0
    /// before the first control step: no lease, nothing may be forwarded).
    #[cfg(all(feature = "xdp", target_os = "linux"))]
    pub fn lease_fence_ns(&self) -> u64 {
        self.lease_fence_ns.load(Ordering::Acquire)
    }

    /// `/healthz` problem, if any (duplicate member id seen recently).
    pub fn health_problem(&self) -> Option<&'static str> {
        self.net.duplicate_seen().then_some("cluster duplicate member id refused")
    }

    /// `plat_cluster_*` metrics (SI-4).
    pub fn render_metrics(&self, o: &mut String) {
        use std::fmt::Write as _;
        let s = self.snap.lock().clone();
        let epoch = s.view.as_ref().map_or(0, |v| v.epoch);
        let leader = s.leader.map_or(-1, i64::from);
        let _ = write!(
            o,
            "# TYPE plat_cluster_epoch gauge\nplat_cluster_epoch {epoch}\n\
             # TYPE plat_cluster_leader gauge\nplat_cluster_leader {leader}\n\
             # TYPE plat_cluster_lease_remaining_ms gauge\nplat_cluster_lease_remaining_ms {}\n\
             # TYPE plat_cluster_peer_up gauge\n",
            s.lease_remaining
        );
        for v in &self.voters {
            if v.id != self.me {
                let _ = writeln!(o, "plat_cluster_peer_up{{peer=\"{}\"}} {}", v.id, u8::from(self.net.is_up(v.id)));
            }
        }
        if let Some(r) = &self.repl {
            let c = r.lock().slice_counts();
            o.push_str("# TYPE plat_cluster_slices gauge\n");
            for (name, v) in ["active", "fenced", "backup_in_sync", "backup_syncing", "unprotected"].iter().zip(c) {
                let _ = writeln!(o, "plat_cluster_slices{{state=\"{name}\"}} {v}");
            }
            let st = r.lock().stats.clone();
            let _ = write!(
                o,
                "# TYPE plat_cluster_resync_total counter\nplat_cluster_resync_total {}\n\
                 # TYPE plat_cluster_repl_ack_timeouts_total counter\nplat_cluster_repl_ack_timeouts_total {}\n",
                st.resync_total.load(Ordering::Relaxed),
                st.ack_timeouts.load(Ordering::Relaxed)
            );
        }
        if let Some(h) = &self.hub {
            let _ = write!(
                o,
                "# TYPE plat_cluster_repl_events_total counter\nplat_cluster_repl_events_total {}\n\
                 # TYPE plat_cluster_repl_dropped_total counter\n\
                 plat_cluster_repl_dropped_total{{reason=\"ring\"}} {}\n\
                 plat_cluster_repl_dropped_total{{reason=\"peer_queue\"}} {}\n\
                 plat_cluster_repl_dropped_total{{reason=\"link\"}} {}\n\
                 plat_cluster_repl_dropped_total{{reason=\"gap\"}} {}\n\
                 # TYPE plat_cluster_repl_lag_records gauge\n",
                h.pushed_total(),
                h.dropped_total(),
                self.net.stats.queue_dropped.load(Ordering::Relaxed),
                self.net.stats.link_dropped.load(Ordering::Relaxed),
                self.repl.as_ref().map_or(0, |r| r.lock().stats.rx_gaps.load(Ordering::Relaxed))
            );
            for v in self.voters.iter().filter(|v| v.id != self.me && !v.witness) {
                let _ =
                    writeln!(o, "plat_cluster_repl_lag_records{{peer=\"{}\"}} {}", v.id, self.net.data_frames(v.id));
            }
        }
        o.push_str("# TYPE plat_cluster_takeovers_total counter\n");
        for (i, l) in TAKEOVER_LABELS.iter().enumerate() {
            let _ = writeln!(
                o,
                "plat_cluster_takeovers_total{{reason=\"{l}\"}} {}",
                self.takeovers[i].load(Ordering::Relaxed)
            );
        }
        let _ = write!(
            o,
            "# TYPE plat_cluster_handovers_total counter\nplat_cluster_handovers_total {}\n\
             # TYPE plat_cluster_state_persist_failures_total counter\nplat_cluster_state_persist_failures_total {}\n",
            self.handovers.load(Ordering::Relaxed),
            self.persist_failures.load(Ordering::Relaxed)
        );
        render_election(o, &s.election);
        self.adopt.render(o);
        self.release.render(o);
        o.push_str("# TYPE plat_cluster_peer_rejected_total counter\n");
        for r in super::peer::REJECT_REASONS {
            let _ = writeln!(
                o,
                "plat_cluster_peer_rejected_total{{reason=\"{}\"}} {}",
                r.as_str(),
                self.net.stats.rejected(r)
            );
        }
        if let Some(h) = &self.hook_stats {
            o.push_str("# TYPE plat_cluster_hook_failures_total counter\n");
            for (i, k) in ["announce", "withdraw"].iter().enumerate() {
                let _ = writeln!(
                    o,
                    "plat_cluster_hook_failures_total{{hook=\"{k}\"}} {}",
                    h.failures[i].load(Ordering::Relaxed)
                );
            }
        }
        if let Some(d) = self.nat.as_ref().and_then(|n| n.state().directory().cloned()) {
            let _ =
                writeln!(o, "# TYPE plat_cluster_directory_entries gauge\nplat_cluster_directory_entries {}", d.len());
        }
    }

    /// `/cluster` (and `platd cluster status`): the view and slice owners
    /// as JSON. No subscriber data; names are validated config text.
    pub fn view_json(&self) -> String {
        use std::fmt::Write as _;
        let s = self.snap.lock().clone();
        let mut o = String::with_capacity(1024);
        let (epoch, live, standby) =
            s.view.as_ref().map_or((0, String::new(), String::new()), |v| (v.epoch, ids(&v.live), ids(&v.standby)));
        let _ = write!(
            o,
            "{{\"node_id\":{},\"role\":\"{}\",\"epoch\":{epoch},\"committed\":{},\"leader\":{},\"live\":[{live}],\
             \"standby\":[{standby}],\"lease_remaining_ms\":{},\"peers\":[",
            self.me,
            role_str(s.role),
            s.committed,
            s.leader.map_or_else(|| "null".to_string(), |l| l.to_string()),
            s.lease_remaining
        );
        let mut first = true;
        for v in self.voters.iter().filter(|v| v.id != self.me) {
            let _ = write!(
                o,
                "{}{{\"id\":{},\"name\":\"{}\",\"up\":{},\"witness\":{}}}",
                if first { "" } else { "," },
                v.id,
                v.name,
                self.net.is_up(v.id),
                v.witness
            );
            first = false;
        }
        o.push_str("],\"slices\":[");
        if let (Some(map), Some(view)) = (&self.map, &s.view) {
            for (s_id, c) in map.iter() {
                let (p, b) = view.owners(s_id, &s.weights).map_or((None, None), |(p, b)| (Some(p), b));
                let releasing = self.nat.as_ref().is_some_and(|n| n.state().slice_releasing(s_id));
                let state = match self.nat.as_ref().and_then(|n| n.state().slice_state(s_id)) {
                    _ if releasing => "releasing",
                    Some(SliceState::Active) => "active",
                    Some(SliceState::Fenced) => "fenced",
                    Some(SliceState::Adopting) => "adopting",
                    _ => "inactive",
                };
                let opt = |x: Option<MemberId>| x.map_or_else(|| "null".to_string(), |x| x.to_string());
                let _ = write!(
                    o,
                    "{}{{\"slice\":\"{c}\",\"primary\":{},\"backup\":{},\"state\":\"{state}\"}}",
                    if s_id == 0 { "" } else { "," },
                    opt(p),
                    opt(b)
                );
            }
        }
        o.push_str("]}\n");
        o
    }
}

// ---------------------------------------------------------------- glue

struct Glue {
    tx: SyncSender<In>,
    /// Weak: `Net` holds this handler and the replicator holds `Net`; a
    /// strong reference here is a cycle that keeps every `AuditSink` clone
    /// (and so the logger) alive after shutdown (B-1).
    repl: Option<std::sync::Weak<Mutex<Replicator>>>,
    dropped: AtomicU64,
    wake: Arc<ReplWake>,
}

/// Parks the idle `plat-repl` thread; unparked by link changes, acks and
/// new views (PERF-006). Worker records are picked up within the idle
/// back-off (at most [`REPL_IDLE_MAX`]); workers never wake it (their push
/// stays lock- and syscall-free).
#[derive(Debug, Default)]
pub struct ReplWake {
    thread: std::sync::OnceLock<std::thread::Thread>,
}

impl ReplWake {
    pub fn wake(&self) {
        if let Some(t) = self.thread.get() {
            t.unpark();
        }
    }
}

/// Longest park of an idle replicator (doubling from 1 ms).
const REPL_IDLE_MAX: Duration = Duration::from_millis(16);

impl Inbound for Glue {
    fn control(&self, from: MemberId, msg: Msg) {
        if self.tx.try_send(In::Msg(from, msg)).is_err() {
            // Like a lost message: membership tolerates loss.
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn data(&self, from: MemberId, msg: Msg) -> Result<(), Refusal> {
        let wake = matches!(msg, Msg::Ack { .. } | Msg::Resync { .. });
        let r = match self.repl.as_ref().and_then(std::sync::Weak::upgrade) {
            Some(r) => r.lock().on_data(from, msg),
            None => Ok(()),
        };
        if wake {
            // An acked snapshot end or reservation may have work for the
            // replicator (top-up, next snapshot).
            self.wake.wake();
        }
        r
    }

    fn link(&self, peer: MemberId, up: bool) {
        if let Some(r) = self.repl.as_ref().and_then(std::sync::Weak::upgrade) {
            if up {
                r.lock().announce_homes(Some(peer));
            } else {
                r.lock().link_down(peer);
            }
        }
        self.wake.wake();
    }
}

// ---------------------------------------------------------------- driver

struct Job {
    slice: SliceId,
    epoch: u64,
    prev_owner: Option<MemberId>,
    reason: AcquireReason,
    manual: bool,
}

/// The one slice adoption in progress on this node (POAM-047): stepped by
/// [`Ctl::run`] between its message and tick work.
enum Cur {
    Adopt(Job, Box<Adoption>),
    /// Undoing an adoption that will not complete; block release records
    /// carry the reason.
    Abandon(Box<Adoption>, Option<BlockReleaseReason>),
}

impl Cur {
    fn slice(&self) -> SliceId {
        match self {
            Self::Adopt(_, a) | Self::Abandon(a, _) => a.slice(),
        }
    }
}

/// An Active-slice release in progress or queued (POAM-048).
struct Rel {
    cur: Box<Release>,
    epoch: u64,
    /// Handover: the new owner and the flushed final sequence number;
    /// `HandoverFence` is sent when the cursor is done.
    fence: Option<(Option<MemberId>, u64)>,
    started: Instant,
    /// `started` as `mono_ms` (the oldest-release gauge).
    started_ms: u64,
}

/// What starting a pending job did.
enum Start {
    /// Nothing (more) to do for it.
    Done,
    /// Retry at the next tick.
    Retry,
    Adopting(Box<Adoption>),
}

struct Ctl {
    m: Membership,
    sh: Arc<Shared>,
    state_dir: PathBuf,
    audit: AuditSink,
    hooks: Option<Hooks>,
    pending: Vec<Job>,
    /// At most one adoption at a time, FIFO over `pending` (SC-5).
    cur: Option<Cur>,
    /// The log phase was refused for lack of audit queue room
    /// (`refuse_new_bindings`): retried at the next tick, not every pass.
    cur_blocked: bool,
    /// Release cursors, one per slice (bounded by the slice count), FIFO;
    /// the front one is stepped (POAM-048).
    releases: VecDeque<Rel>,
    /// The front release paused on a full audit queue: retried at the
    /// next tick.
    rel_blocked: bool,
    /// With both an adoption and a release to step, whose turn it is.
    rel_turn: bool,
    max_handovers: usize,
    auto_failover: bool,
    shutdown_ms: u64,
    prev_view: Option<View>,
    manual_cmd: bool,
    up: Vec<bool>,
    /// `audit.on_overflow = "refuse_new_bindings"`: a slice is not served
    /// before its acquire record is queued.
    refuse_on_overflow: bool,
    repl_wake: Arc<ReplWake>,
    /// Last `SyncStatus` sent: (epoch, in_sync, when).
    sync_sent: Option<(u64, bool, Instant)>,
}

/// A standby member repeats its `SyncStatus` this often (a lost report or
/// a new leader is covered by the next one).
const SYNC_STATUS_EVERY: Duration = Duration::from_millis(250);

/// At shutdown, a release paused on a full audit queue retries this often.
const SHUTDOWN_AUDIT_POLL: Duration = Duration::from_millis(5);

fn audit_acquire(r: AcquireReason, manual: bool) -> AuditAcquire {
    if manual {
        return AuditAcquire::Manual;
    }
    match r {
        AcquireReason::Startup => AuditAcquire::Startup,
        AcquireReason::Takeover => AuditAcquire::Takeover,
        AcquireReason::Handover => AuditAcquire::Handover,
        AcquireReason::Failback => AuditAcquire::Failback,
    }
}

fn audit_release(r: ReleaseReason) -> SliceReleaseReason {
    match r {
        ReleaseReason::Handover => SliceReleaseReason::Handover,
        ReleaseReason::Fenced => SliceReleaseReason::Fenced,
        ReleaseReason::Shutdown => SliceReleaseReason::Shutdown,
        ReleaseReason::LeaseLost => SliceReleaseReason::LeaseLost,
    }
}

impl Ctl {
    fn view_reason(&self, v: &View) -> ViewReason {
        if self.manual_cmd {
            return ViewReason::Manual;
        }
        let Some(p) = &self.prev_view else { return ViewReason::Election };
        let all = |x: &View| x.live.iter().chain(&x.standby).copied().collect::<Vec<_>>();
        let (old, new) = (all(p), all(v));
        if p.leader != v.leader && !new.contains(&p.leader) {
            return ViewReason::LeaderLost;
        }
        if old.iter().any(|m| !new.contains(m)) {
            return ViewReason::MemberLost;
        }
        if new.iter().any(|m| !old.contains(m)) || v.live.len() > p.live.len() {
            return ViewReason::MemberJoined;
        }
        ViewReason::Election
    }

    fn exec(&mut self, actions: Vec<Action>) {
        let mut persist_failed = false;
        for a in actions {
            match a {
                Action::Persist(p) => {
                    if let Err(e) = save_state(&self.state_dir, &p) {
                        tracing::error!("cluster state not persisted ({e}): not acting on this batch");
                        self.sh.persist_failures.fetch_add(1, Ordering::Relaxed);
                        persist_failed = true;
                    }
                }
                Action::Send { to, msg } => {
                    if !persist_failed {
                        self.sh.net.send(to, &msg);
                    }
                }
                Action::ViewAdopted(v) => {
                    let reason = self.view_reason(&v);
                    self.audit.emit(Event::ClusterViewChange {
                        ts_us: Clock::wall_us(),
                        view: Arc::new(ClusterView {
                            epoch: v.epoch,
                            leader: v.leader,
                            members_live: v.live.iter().copied().take(ClusterView::MEMBERS_MAX).collect(),
                            reason,
                        }),
                    });
                    self.sh.net.epoch.store(v.epoch, Ordering::Relaxed);
                    if let Some(r) = &self.sh.repl {
                        r.lock().set_view(&v, self.m.weights());
                        self.repl_wake.wake();
                    }
                    tracing::info!(epoch = v.epoch, leader = v.leader, live = ?v.live, standby = ?v.standby, "cluster view");
                    self.prev_view = Some(v);
                }
                Action::Committed(_) | Action::RoleChanged(_) => {}
                Action::Acquire { slice, epoch, prev_owner, reason } => {
                    if !persist_failed {
                        // In manual mode a takeover only follows an operator
                        // command; it may run ticks later, after the `safe`
                        // hold (SEC-R1-1).
                        let manual =
                            self.manual_cmd || (!self.auto_failover && matches!(reason, AcquireReason::Takeover));
                        match &mut self.cur {
                            // Granted again (a newer view) while adopting:
                            // keep the imported state, log with the new
                            // epoch (records not yet queued are re-queued).
                            Some(Cur::Adopt(j, a)) if j.slice == slice => {
                                j.epoch = epoch;
                                a.rebase(AdoptMeta { epoch, ..a.meta() });
                            }
                            _ => self.pending.push(Job { slice, epoch, prev_owner, reason, manual }),
                        }
                    }
                }
                Action::Release { slice, epoch, new_owner, reason } => self.release(slice, epoch, new_owner, reason),
            }
        }
        self.run_pending();
        self.refresh();
    }

    fn hook(&self, kind: plat_audit::HookKind, slice: SliceId, epoch: u64, reason: &'static str) {
        let (Some(h), Some(c)) = (&self.hooks, self.sh.map.as_ref().and_then(|m| m.cidr(slice))) else { return };
        h.submit(HookJob { kind, slice: c, epoch, reason });
    }

    /// Starts the next adoption when none is in progress: pending jobs in
    /// order (every startup/takeover, at most `max_concurrent_handovers`
    /// handovers/failbacks per call). A job that needs no import completes
    /// here; the first that does becomes [`Ctl::cur`] and later ones wait.
    fn run_pending(&mut self) {
        // POAM: POAM-017(a) the limit is per member and per tick; a leader
        // that hands over many slices at once to several members still
        // causes a cluster-wide adoption burst (no global rate limit).
        let mut handovers = 0;
        let jobs = std::mem::take(&mut self.pending);
        for mut j in jobs {
            let graceful = matches!(j.reason, AcquireReason::Handover | AcquireReason::Failback);
            let (releasing, ahead) = self.sh.nat.as_ref().map_or((false, false), |n| {
                let st = n.state();
                let rel = st.slice_releasing(j.slice);
                (rel, runs_ahead(st.slice_state(j.slice), rel, j.prev_owner, self.sh.me))
            });
            // A slice being released is adopted only after its release
            // is done (SC-24, POAM-048).
            if releasing || (self.cur.is_some() && !ahead) || (graceful && handovers >= self.max_handovers) {
                self.pending.push(j);
                continue;
            }
            handovers += usize::from(graceful);
            match self.start(&mut j) {
                Start::Done => {}
                Start::Retry => self.pending.push(j),
                Start::Adopting(a) => {
                    self.cur = Some(Cur::Adopt(j, a));
                    self.cur_blocked = false;
                }
            }
        }
        self.sh.adopt.adopting.store(u64::from(self.cur.is_some()), Ordering::Relaxed);
    }

    /// Starts job `j`: an adoption cursor (O(1); the shadow is detached,
    /// not copied), or the regain of a complete fenced slice at once.
    fn start(&mut self, j: &mut Job) -> Start {
        let Some(nat) = self.sh.nat.clone() else { return Start::Done };
        let st = nat.state();
        let me = self.sh.me;
        let areason = audit_acquire(j.reason, j.manual);
        let cidr = self.sh.map.as_ref().and_then(|m| m.cidr(j.slice));
        match st.slice_state(j.slice) {
            Some(SliceState::Active) | None => Start::Done,
            Some(SliceState::Fenced) if j.prev_owner == Some(me) => {
                // Regained after a lease loss with an unbroken view chain
                // (membership reports this node as the previous owner):
                // nobody else held it, the fenced state is complete. Same
                // log-before-use gate as an adoption (NIST-001). Only a
                // slice that was Active is Fenced: an abandoned adoption
                // ends Inactive and is adopted again in full (SC-24).
                if let Some(c) = cidr {
                    let ev = Event::ClusterSliceAcquire {
                        ts_us: Clock::wall_us(),
                        acquire: Arc::new(SliceAcquire {
                            slice: slice_cidr(c),
                            epoch: j.epoch,
                            prev_owner: j.prev_owner,
                            reason: areason,
                            blocks_adopted: 0,
                            bibs_adopted: 0,
                            blocks_quarantined: 0,
                            in_sync: true,
                        }),
                    };
                    if self.refuse_on_overflow {
                        match self.audit.try_emit(ev) {
                            TryEmit::Queued => {}
                            // Not queued, so nothing is logged twice on the
                            // retry; the slice stays fenced until then.
                            TryEmit::Full | TryEmit::Disconnected => return Start::Retry,
                        }
                    } else {
                        self.audit.emit(ev);
                    }
                }
                st.set_slice_state(j.slice, SliceState::Active);
                self.finish(j);
                Start::Done
            }
            Some(state) => {
                let src = match (j.prev_owner, &self.sh.repl) {
                    (Some(_), Some(r)) => AdoptSource::Detached(r.lock().detach(j.slice)),
                    // Fenced here, but the view chain broke (no previous
                    // owner known): another member may have served it in a
                    // view this node missed. The local state is not known
                    // to be current: hold back every block not adopted.
                    (None, _) if state == SliceState::Fenced => {
                        AdoptSource::Input(AdoptInput { in_sync: false, hold_unknown: true, ..AdoptInput::default() })
                    }
                    // Nobody owned it: nothing to inherit, complete.
                    _ => AdoptSource::Input(AdoptInput { in_sync: true, ..AdoptInput::default() }),
                };
                let meta = AdoptMeta { epoch: j.epoch, prev_owner: j.prev_owner, reason: areason };
                match st.adopt_begin(j.slice, src, meta) {
                    Ok(a) => Start::Adopting(Box::new(a)),
                    Err(AdoptError::Active) => Start::Done,
                    Err(e) => {
                        tracing::error!(slice = j.slice, "adopt: {e:?}");
                        Start::Done
                    }
                }
            }
        }
    }

    /// One bounded step of the adoption (or abandon) in progress, until
    /// `deadline`; the next pending job starts when it ends.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: CP-10, SC-5(2) - heartbeats and lease renewals run
    ///   between steps, so a large takeover cannot cost this node its own
    ///   lease (POAM-047)
    /// - NIST 800-53: AU-12, AU-5 - the slice goes Active in the step that
    ///   queued its last record; a full queue under `refuse_new_bindings`
    ///   pauses the cursor until the next tick
    fn step(&mut self, deadline: Instant) {
        let Some(nat) = self.sh.nat.clone() else {
            self.cur = None;
            return;
        };
        let st = nat.state();
        let t = Instant::now();
        let mut ended = false;
        self.cur = match self.cur.take() {
            Some(Cur::Adopt(j, mut a)) => match st.adopt_step(&mut a, deadline) {
                Ok(Step::More) => Some(Cur::Adopt(j, a)),
                Ok(Step::Done(s)) => {
                    tracing::info!(
                        slice = j.slice,
                        reason = a.meta().reason.as_str(),
                        blocks = s.blocks_adopted,
                        bibs = s.bibs_adopted,
                        held = s.blocks_held,
                        "slice acquired"
                    );
                    self.finish(&j);
                    ended = true;
                    None
                }
                Err(AdoptError::AuditUnavailable) => {
                    self.cur_blocked = true;
                    Some(Cur::Adopt(j, a))
                }
                Err(e) => {
                    tracing::warn!(slice = j.slice, phase = a.phase(), "adoption abandoned: {e:?}");
                    if let Some(c) = self.sh.adopt.abandoned.get(ABANDON_EPOCH) {
                        c.fetch_add(1, Ordering::Relaxed);
                    }
                    Some(Cur::Abandon(a, None))
                }
            },
            Some(Cur::Abandon(mut a, why)) => {
                if st.adopt_abandon(&mut a, deadline, why) {
                    ended = true;
                    None
                } else {
                    Some(Cur::Abandon(a, why))
                }
            }
            None => None,
        };
        self.sh.adopt.step(t.elapsed());
        if ended {
            self.run_pending();
            self.refresh();
        }
        self.sh.adopt.adopting.store(u64::from(self.cur.is_some()), Ordering::Relaxed);
    }

    /// After the slice of `j` is Active: directory, homes, announce hook,
    /// `HandoverDone`, counters.
    fn finish(&self, j: &Job) {
        let Some(nat) = self.sh.nat.as_ref() else { return };
        let me = self.sh.me;
        let areason = audit_acquire(j.reason, j.manual);
        if let Some(d) = nat.state().directory() {
            d.rehome_slice(j.slice, me, me);
        }
        // B-9: peers learn the adopted subscribers' new home.
        if let Some(r) = &self.sh.repl {
            r.lock().announce_homes(None);
        }
        self.hook(plat_audit::HookKind::Announce, j.slice, j.epoch, areason.as_str());
        if matches!(j.reason, AcquireReason::Handover | AcquireReason::Failback)
            && let Some(p) = j.prev_owner
        {
            self.sh.net.send(p, &Msg::HandoverDone { slice: j.slice, epoch: j.epoch });
        }
        if let Some(c) = self.sh.takeovers.get(takeover_ix(areason)) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Fence first, then audit, withdraw, and hand state over or drop it.
    ///
    /// A slice still being adopted is abandoned instead (SC-24): it never
    /// served, so it is not fenced (an abandoned adoption ends Inactive),
    /// and a handover of it sends nothing: no flush, no `HandoverFence`,
    /// no `HandoverDone`; the requester waits `safe` as for any
    /// unconfirmed handover.
    fn release(&mut self, slice: SliceId, epoch: u64, new_owner: Option<MemberId>, reason: ReleaseReason) {
        self.pending.retain(|j| j.slice != slice);
        let Some(nat) = self.sh.nat.clone() else { return };
        let st = nat.state();
        let adopting = self.cur.as_ref().is_some_and(|c| c.slice() == slice);
        if adopting {
            // Already abandoning: the cleanup goes on as it is.
            if let Some(Cur::Adopt(j, mut a)) = self.cur.take_if(|c| matches!(c, Cur::Adopt(..))) {
                tracing::warn!(slice, phase = a.phase(), reason = ?reason, epoch = j.epoch, "adoption abandoned");
                if !keeps_shadow(reason, new_owner, self.sh.me) {
                    a.discard_shadow();
                }
                if let Some(c) = self.sh.adopt.abandoned.get(abandon_ix(reason)) {
                    c.fetch_add(1, Ordering::Relaxed);
                }
                let why = (reason == ReleaseReason::Handover).then_some(BlockReleaseReason::Handover);
                self.cur = Some(Cur::Abandon(a, why));
            }
        } else {
            st.fence_slice(slice);
        }
        if let Some(c) = self.sh.map.as_ref().and_then(|m| m.cidr(slice)) {
            self.audit.emit(Event::ClusterSliceRelease {
                ts_us: Clock::wall_us(),
                slice: slice_cidr(c),
                epoch,
                new_owner,
                reason: audit_release(reason),
            });
        }
        self.hook(plat_audit::HookKind::Withdraw, slice, epoch, audit_release(reason).as_str());
        let me = self.sh.me;
        match reason {
            _ if adopting => {}
            ReleaseReason::Handover => self.hand_over(slice, epoch, new_owner),
            ReleaseReason::Fenced | ReleaseReason::LeaseLost | ReleaseReason::Shutdown => {
                // Given to another member: end the attribution intervals
                // here now. A lease loss with no new owner keeps the fenced
                // state for a regain.
                if new_owner.is_some_and(|n| n != me) || reason == ReleaseReason::Shutdown {
                    self.queue_release(slice, epoch, None, None);
                }
            }
        }
    }

    /// Flush the slice's replication, then release its blocks (handover
    /// records) stepwise; the new owner is told the final sequence number
    /// when the release is done ([`Ctl::release_done`]).
    fn hand_over(&mut self, slice: SliceId, epoch: u64, to: Option<MemberId>) {
        if self.sh.nat.is_none() {
            return;
        }
        let final_seq = self.sh.repl.as_ref().map_or(0, |r| r.lock().flush(slice));
        self.queue_release(slice, epoch, Some(BlockReleaseReason::Handover), Some((to, final_seq)));
    }

    /// Starts (O(1): the slice is fenced and marked releasing) or joins the
    /// release cursor of `slice`. One cursor per slice: a slice already
    /// being released keeps its cursor (part of its records are queued); a
    /// handover of it still gets its `HandoverFence` at the end.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-5 - at most one cursor per slice (queue bounded
    ///   by the slice count)
    /// - NIST 800-53: SC-24 - fenced before the first step; never Active
    ///   again until a fresh adoption
    fn queue_release(
        &mut self,
        slice: SliceId,
        epoch: u64,
        reason: Option<BlockReleaseReason>,
        fence: Option<(Option<MemberId>, u64)>,
    ) {
        let Some(nat) = self.sh.nat.clone() else { return };
        if let Some(r) = self.releases.iter_mut().find(|r| r.cur.slice() == slice) {
            if fence.is_some() && r.fence.is_none() {
                r.fence = fence;
                r.epoch = epoch;
                // SEC-002: the records still to be built carry the
                // handover reason; those already queued keep theirs, so a
                // slice's records may mix (earlier ones first).
                r.cur.set_reason(reason);
            }
            return;
        }
        let st = nat.state();
        match st.release_begin(slice, reason) {
            Some(cur) => {
                self.releases.push_back(Rel {
                    cur: Box::new(cur),
                    epoch,
                    fence,
                    started: Instant::now(),
                    started_ms: mono_ms(),
                });
            }
            None => {
                // SEC-004: nothing to release only when unsliced (no state)
                // or already Inactive; a handover then confirms at once. An
                // Adopting slice never gets here (`release` abandons it),
                // and one released elsewhere is not confirmed early.
                let state = st.slice_state(slice);
                debug_assert_ne!(state, Some(SliceState::Adopting), "slice {slice} released while Adopting");
                if matches!(state, None | Some(SliceState::Inactive)) {
                    self.send_fence(slice, epoch, fence);
                }
            }
        }
        self.note_releases();
    }

    /// Updates the release gauges after `releases` changed.
    fn note_releases(&self) {
        let m = &self.sh.release;
        m.releasing.store(self.releases.len() as u64, Ordering::Relaxed);
        let oldest = self.releases.iter().map(|r| r.started_ms).min().unwrap_or(u64::MAX);
        m.oldest_started_ms.store(oldest, Ordering::Relaxed);
    }

    fn send_fence(&self, slice: SliceId, epoch: u64, fence: Option<(Option<MemberId>, u64)>) {
        if let Some((to, final_seq)) = fence {
            if let Some(n) = to {
                self.sh.net.send(n, &Msg::HandoverFence { slice, epoch, final_seq });
            }
            self.sh.handovers.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A release cursor reached Done: every release record of the slice is
    /// queued and its blocks are back in the pool; only now does a
    /// handover's new owner get `HandoverFence`.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-12, AU-10 - the new owner stops waiting `safe`
    ///   only after this node closed every attribution interval of the
    ///   slice (POAM-048 Q3)
    fn release_done(&self, r: &Rel, s: plat_nat64::ReleaseStats) {
        let slice = r.cur.slice();
        tracing::info!(
            slice,
            reason = r.cur.reason().map_or("none", BlockReleaseReason::as_str),
            bibs = s.bibs_removed,
            blocks = s.blocks_released,
            subscribers = s.subscribers_removed,
            ms = r.started.elapsed().as_millis() as u64,
            "slice released"
        );
        self.send_fence(slice, r.epoch, r.fence);
    }

    /// One bounded step of the front release cursor, until `deadline`.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: CP-10, SC-5(2) - heartbeats and lease renewals run
    ///   between steps, so a large release cannot cost this node its own
    ///   lease (POAM-048)
    /// - NIST 800-53: AU-5 - a full queue under `refuse_new_bindings`
    ///   pauses the cursor until the next tick, nothing lost
    fn step_release(&mut self, deadline: Instant) {
        let Some(nat) = self.sh.nat.clone() else {
            self.releases.clear();
            return;
        };
        let Some(r) = self.releases.front_mut() else { return };
        let t = Instant::now();
        let res = nat.state().release_step(&mut r.cur, deadline);
        self.sh.release.step(t.elapsed());
        match res {
            ReleaseStep::More => {}
            ReleaseStep::Paused => {
                self.rel_blocked = true;
                self.sh.release.audit_paused.fetch_add(1, Ordering::Relaxed);
            }
            ReleaseStep::Done(s) => {
                if let Some(r) = self.releases.pop_front() {
                    self.release_done(&r, s);
                }
                self.note_releases();
                self.run_pending();
                self.refresh();
            }
        }
    }

    /// Every queued release to completion (shutdown). Returns the slices
    /// released. Under `refuse_new_bindings` a full queue is waited on in
    /// bounded steps until `deadline` (the `shutdown_handover_ms` budget);
    /// past it the rest is emitted (`State::release_all`): refused records
    /// are counted lost and the logger reports them in
    /// `audit_queue_overflow`.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-5, AU-12 - release records at shutdown get queue
    ///   room for as long as the shutdown budget allows; only then is a
    ///   record lost, and it is counted (SEC-001)
    fn finish_releases(&mut self, deadline: Instant) -> Vec<SliceId> {
        let mut out = Vec::new();
        let Some(nat) = self.sh.nat.clone() else {
            self.releases.clear();
            self.note_releases();
            return out;
        };
        let st = nat.state();
        while let Some(mut r) = self.releases.pop_front() {
            let s = loop {
                if Instant::now() >= deadline {
                    break st.release_all(&mut r.cur);
                }
                let t = Instant::now();
                let res = st.release_step(&mut r.cur, (t + RELEASE_STEP_BUDGET).min(deadline));
                self.sh.release.step(t.elapsed());
                match res {
                    ReleaseStep::Done(s) => break s,
                    ReleaseStep::More => {}
                    ReleaseStep::Paused => {
                        self.sh.release.audit_paused.fetch_add(1, Ordering::Relaxed);
                        std::thread::sleep(SHUTDOWN_AUDIT_POLL.min(deadline.saturating_duration_since(Instant::now())));
                    }
                }
            };
            self.release_done(&r, s);
            out.push(r.cur.slice());
            self.note_releases();
        }
        out
    }

    fn refresh(&mut self) {
        let now = mono_ms();
        let mut s = self.sh.snap.lock();
        s.role = Some(self.m.role());
        s.view = self.m.view().cloned();
        s.committed = self.m.committed();
        s.leader = self.m.leader();
        s.lease_remaining = self.m.lease_remaining(now).min(3_600_000);
        s.election = self.m.election_stats();
        #[cfg(all(feature = "xdp", target_os = "linux"))]
        self.sh
            .lease_fence_ns
            .store(plat_xdp::control::coarse_now_ns().saturating_add(s.lease_remaining * 1_000_000), Ordering::Release);
        s.weights = self.m.weights().to_vec();
    }

    /// `cluster_member_state` up/down records on link changes.
    fn member_states(&mut self) {
        let epoch = self.m.view().map_or(0, |v| v.epoch);
        for v in self.sh.voters.clone() {
            if v.id == self.sh.me {
                continue;
            }
            let i = usize::from(v.id);
            let up = self.sh.net.is_up(v.id);
            if self.up.get(i).copied() == Some(up) {
                continue;
            }
            if let Some(x) = self.up.get_mut(i) {
                *x = up;
            }
            self.audit.emit(Event::ClusterMemberState {
                ts_us: Clock::wall_us(),
                member: Arc::new(ClusterMemberChange {
                    peer_id: v.id,
                    name: AuditText::new(&v.name, AuditText::SUBJECT_MAX),
                    identity: AuditText::new(&v.identity, AuditText::SUBJECT_MAX),
                    ip: v.addr.ip(),
                    state: if up { MemberState::Up } else { MemberState::Down },
                    epoch,
                }),
            });
        }
    }

    /// B-3: while this member is standby (rejoined, waiting for failback),
    /// reports to every voter whether all slices it backs up are in sync
    /// in the current view; the leader promotes it only then.
    fn sync_status(&mut self) {
        let Some(r) = &self.sh.repl else { return };
        let Some(v) = self.m.view().cloned() else { return };
        let me = self.sh.me;
        if !v.is_standby(me) {
            self.sync_sent = None;
            return;
        }
        let in_sync = r.lock().backup_in_sync().unwrap_or(false);
        self.m.set_sync(me, v.epoch, in_sync);
        let now = Instant::now();
        if self
            .sync_sent
            .is_some_and(|(e, x, t)| e == v.epoch && x == in_sync && now.duration_since(t) < SYNC_STATUS_EVERY)
        {
            return;
        }
        self.sync_sent = Some((v.epoch, in_sync, now));
        for p in self.sh.voters.iter().filter(|p| p.id != me && !p.witness) {
            self.sh.net.send(p.id, &Msg::SyncStatus { epoch: v.epoch, in_sync });
        }
    }

    /// Checks, audits (before acting) and runs an operator command.
    fn command(&mut self, c: Command, cred: Option<PeerCred>) -> String {
        let now = mono_ms();
        let refuse = |me: &Self, why: OperatorRefusal, text: &str| {
            audit_operator(&me.audit, false, c.audit(), cred, Some(why));
            tracing::warn!(?c, "operator cluster command refused: {text}");
            format!("error: {text}\n")
        };
        if self.auto_failover {
            return refuse(self, OperatorRefusal::AutoFailover, "commands need cluster.ha.auto_failover = false");
        }
        let (Command::Takeover(m, _) | Command::Restore(m)) = c;
        if !self.sh.voters.iter().any(|v| v.id == m && !v.witness) {
            return refuse(self, OperatorRefusal::UnknownMember, &format!("unknown member {m}"));
        }
        // SEC-2: a member whose peer link is up is not lost.
        if let Command::Takeover(m, false) = c
            && self.sh.net.is_up(m)
        {
            return refuse(
                self,
                OperatorRefusal::MemberUp,
                &format!("member {m} is connected; stop it first or use --force"),
            );
        }
        if !audit_operator(&self.audit, self.refuse_on_overflow, c.audit(), cred, None) {
            // NIST-R1-01: attribution first; nothing acts unrecorded.
            tracing::warn!(?c, "operator cluster command refused: audit queue full");
            return "error: audit queue full, command not run; retry\n".to_owned();
        }
        let r = match c {
            // SEC-R1-1: the gained slices are always held for `safe`, also
            // when the link is down without --force: a partitioned member
            // may still be serving until its own lease lapses.
            Command::Takeover(m, _) => self.m.manual_takeover(now, m, true),
            Command::Restore(m) => self.m.manual_restore(now, m),
        };
        match r {
            Ok(actions) => {
                tracing::warn!(?c, "operator cluster command");
                self.manual_cmd = true;
                self.exec(actions);
                self.manual_cmd = false;
                format!("ok: epoch {}\n", self.m.view().map_or(0, |v| v.epoch))
            }
            Err(e) => refuse(self, OperatorRefusal::Rejected, &e.to_string()),
        }
    }

    fn adopt_ready(&self) -> bool {
        self.cur.is_some() && !self.cur_blocked
    }

    fn release_ready(&self) -> bool {
        !self.releases.is_empty() && !self.rel_blocked
    }

    fn run(mut self, rx: &Receiver<In>, stop: &AtomicBool, killed: &AtomicBool) {
        let tick = Duration::from_millis(self.m.tick_interval_ms());
        let mut next = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            // While adopting, poll: one message (if any), the tick when due,
            // then one bounded adoption step (POAM-047).
            let stepping = self.adopt_ready() || self.release_ready();
            let wait = if stepping { Duration::ZERO } else { next.saturating_duration_since(Instant::now()) };
            match rx.recv_timeout(wait) {
                Ok(In::Msg(from, msg)) => {
                    let a = self.m.on_msg(mono_ms(), from, &msg);
                    self.exec(a);
                }
                Ok(In::Cmd(c, cred, reply)) => {
                    let r = self.command(c, cred);
                    let _ = reply.try_send(r);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if Instant::now() >= next {
                next = Instant::now() + tick;
                let a = self.m.on_tick(mono_ms());
                self.exec(a);
                self.member_states();
                self.sync_status();
                self.cur_blocked = false;
                self.rel_blocked = false;
            }
            // Never past the next tick: the stall between two ticks is at
            // most one step (ADOPT_STEP_BUDGET plus one batch). With both
            // an adoption and a release, they alternate (POAM-048 Q4), so
            // a crash takeover is not starved by releases.
            let (adopt, rel) = (self.adopt_ready(), self.release_ready());
            if adopt && (!rel || !self.rel_turn) {
                self.step((Instant::now() + ADOPT_STEP_BUDGET).min(next));
            } else if rel {
                self.step_release((Instant::now() + RELEASE_STEP_BUDGET).min(next));
            }
            if adopt && rel {
                self.rel_turn = !self.rel_turn;
            }
        }
        if !killed.load(Ordering::Relaxed) {
            self.shutdown(rx);
        }
    }

    /// Orderly stop: every owned slice is fenced and released; with
    /// automatic failover a slice with an in-sync backup is flushed and
    /// handed to it (release records `handover`, `HandoverFence`), then the
    /// node waits (up to `shutdown_handover_ms`) until the cluster adopted
    /// a view without it, so the backups take over at once.
    fn shutdown(&mut self, rx: &Receiver<In>) {
        // POAM: POAM-030 - plat-cluster has no leave message: the backups
        // take over when the leader drops this silent node (about
        // lease * (1 + margin)), not by a leader-coordinated handover view.
        // A partial slice is undone before anything is handed over: it
        // never served, so it is released without a handover of its own.
        // One budget (`shutdown_handover_ms`) for the release waits and the
        // view wait together (SEC-001).
        let budget = Instant::now() + Duration::from_millis(self.shutdown_ms);
        let abandoned = self.shutdown_abandon();
        self.pending.clear();
        // Releases in progress complete first (their `HandoverFence` is
        // sent); membership's shutdown never releases them twice.
        let released = self.finish_releases(budget);
        let now = mono_ms();
        let actions = self.m.shutdown(now);
        let mut handed = false;
        for a in actions {
            let Action::Release { slice, epoch, reason, .. } = a else { continue };
            if released.contains(&slice) {
                continue;
            }
            let backup = self.sh.repl.as_ref().and_then(|r| r.lock().in_sync_target(slice));
            let how = shutdown_release(slice, abandoned, self.auto_failover, backup);
            if how == ShutdownRelease::NeverServed {
                if let Some(c) = self.sh.map.as_ref().and_then(|m| m.cidr(slice)) {
                    self.audit.emit(Event::ClusterSliceRelease {
                        ts_us: Clock::wall_us(),
                        slice: slice_cidr(c),
                        epoch,
                        new_owner: None,
                        reason: SliceReleaseReason::Shutdown,
                    });
                }
                self.hook(plat_audit::HookKind::Withdraw, slice, epoch, "shutdown");
            } else if let ShutdownRelease::HandOver(backup) = how {
                let backup = Some(backup);
                let Some(nat) = self.sh.nat.clone() else { continue };
                nat.state().fence_slice(slice);
                if let Some(c) = self.sh.map.as_ref().and_then(|m| m.cidr(slice)) {
                    self.audit.emit(Event::ClusterSliceRelease {
                        ts_us: Clock::wall_us(),
                        slice: slice_cidr(c),
                        epoch,
                        new_owner: backup,
                        reason: SliceReleaseReason::Shutdown,
                    });
                }
                self.hook(plat_audit::HookKind::Withdraw, slice, epoch, "shutdown");
                self.hand_over(slice, epoch, backup);
                handed = true;
            } else {
                self.release(slice, epoch, None, reason);
            }
        }
        // Done before the wait: the backups get `HandoverFence` now.
        self.finish_releases(budget);
        self.refresh();
        let peers_up = || self.sh.voters.iter().any(|v| v.id != self.sh.me && !v.witness && self.sh.net.is_up(v.id));
        if handed && peers_up() {
            self.shutdown_wait(rx, budget);
        }
        if let Some(mut h) = self.hooks.take() {
            h.join();
        }
    }

    /// Undoes an adoption (or abandon) in progress at shutdown; returns
    /// its slice, which never served.
    fn shutdown_abandon(&mut self) -> Option<SliceId> {
        let c = self.cur.take()?;
        let nat = self.sh.nat.clone()?;
        let slice = c.slice();
        let (mut a, why) = match c {
            Cur::Adopt(_, a) => {
                if let Some(x) = self.sh.adopt.abandoned.get(abandon_ix(ReleaseReason::Shutdown)) {
                    x.fetch_add(1, Ordering::Relaxed);
                }
                (a, None)
            }
            Cur::Abandon(a, why) => (a, why),
        };
        a.discard_shadow();
        nat.state().adopt_abandon_all(&mut a, why);
        self.sh.adopt.adopting.store(0, Ordering::Relaxed);
        Some(slice)
    }

    /// Waits (until `deadline`) for a view that no longer has this node
    /// live or standby, while a peer is up; operator commands are refused.
    fn shutdown_wait(&self, rx: &Receiver<In>, deadline: Instant) {
        let peers_up = || self.sh.voters.iter().any(|v| v.id != self.sh.me && !v.witness && self.sh.net.is_up(v.id));
        while Instant::now() < deadline && peers_up() {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(In::Msg(_, Msg::ViewPropose { view, .. }))
                    if !view.is_live(self.sh.me) && !view.is_standby(self.sh.me) =>
                {
                    break;
                }
                Ok(In::Cmd(c, cred, reply)) => {
                    audit_operator(&self.audit, false, c.audit(), cred, Some(OperatorRefusal::Rejected));
                    let _ = reply.try_send("error: shutting down\n".into());
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------- start

/// What [`launch`] needs (member or witness).
pub struct Core {
    pub mcfg: MembershipConfig,
    pub voters: Vec<Voter>,
    pub net: NetConfig,
    pub tls: PeerConfigs,
    pub state_dir: PathBuf,
    pub audit: AuditSink,
    pub nat: Option<Arc<Nat64>>,
    pub hub: Option<Arc<ReplHub>>,
    pub shadow: Option<Arc<Shadow>>,
    pub hooks: Option<Hooks>,
    pub max_handovers: usize,
    pub shutdown_ms: u64,
    /// `translation.client_prefixes` (replication input validation).
    pub clients: Vec<plat_common::Ipv6Cidr>,
    /// `audit.on_overflow = "refuse_new_bindings"`.
    pub refuse_on_overflow: bool,
}

/// Running cluster threads.
pub struct ClusterHandle {
    pub shared: Arc<Shared>,
    repl_wake: Arc<ReplWake>,
    ctl_stop: Arc<AtomicBool>,
    net_stop: Arc<AtomicBool>,
    killed: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for ClusterHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterHandle").field("me", &self.shared.me).finish_non_exhaustive()
    }
}

impl ClusterHandle {
    #[cfg(test)]
    /// Runs an operator command on the control thread (as this process).
    pub fn command(&self, c: Command) -> String {
        let me = PeerCred { uid: self.shared.daemon_uid, pid: Some(std::process::id() as i32) };
        command_via(&self.shared.ctl, c, Some(me))
    }

    /// Graceful stop (handover, bounded by `shutdown_handover_ms`), then
    /// every cluster thread is joined.
    pub fn shutdown(mut self) {
        if self.killed.load(Ordering::Relaxed) {
            return;
        }
        self.ctl_stop.store(true, Ordering::Relaxed);
        if !self.threads.is_empty() {
            let _ = self.threads.remove(0).join();
        }
        self.net_stop.store(true, Ordering::Relaxed);
        self.shared.net.wake_all();
        self.repl_wake.wake();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        self.shared.net.join();
    }

    #[cfg(test)]
    /// Simulated crash (tests): connections cut, nothing handed over, the
    /// engine left as it is.
    pub fn kill(mut self) {
        self.killed.store(true, Ordering::Relaxed);
        self.shared.net.kill();
        self.ctl_stop.store(true, Ordering::Relaxed);
        self.net_stop.store(true, Ordering::Relaxed);
        self.repl_wake.wake();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        self.shared.net.join();
    }
}

fn command_via(tx: &SyncSender<In>, c: Command, cred: Option<PeerCred>) -> String {
    let (rtx, rrx) = std::sync::mpsc::sync_channel(1);
    if tx.try_send(In::Cmd(c, cred, rtx)).is_err() {
        return "error: control queue full\n".into();
    }
    rrx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|_| "error: no reply\n".into())
}

/// Starts the cluster threads for a member or the witness.
pub fn launch(core: Core) -> Result<ClusterHandle, String> {
    let persisted = load_state(&core.state_dir)?;
    let (m, initial) = Membership::new(core.mcfg.clone(), persisted, mono_ms()).map_err(|e| format!("cluster: {e}"))?;
    let net_stop = Arc::new(AtomicBool::new(false));
    let net = Net::new(core.net.clone(), core.tls, core.audit.clone(), net_stop.clone())
        .map_err(|e| format!("cluster peer channel: {e}"))?;
    let repl_wake = Arc::new(ReplWake::default());
    let repl = match (&core.nat, &core.hub, &core.shadow) {
        (Some(nat), Some(hub), Some(shadow)) => {
            let s = ReplSettings {
                me: core.mcfg.self_id,
                data_members: core.mcfg.members.iter().map(|x| x.0).collect(),
                max_frame: core.net.max_frame,
                queue_bytes: core.net.queue_bytes,
                clients: core.clients.clone(),
                peers: core
                    .voters
                    .iter()
                    .filter(|v| !v.witness && v.id != core.mcfg.self_id)
                    .map(|v| PeerInfo { id: v.id, name: v.name.clone(), identity: v.identity.clone(), ip: v.addr.ip() })
                    .collect(),
            };
            Some(Arc::new(Mutex::new(Replicator::new(
                s,
                nat.clone(),
                hub.clone(),
                net.clone(),
                shadow.clone(),
                core.audit.clone(),
            )?)))
        }
        _ => None,
    };
    let map = core.nat.as_ref().and_then(|n| n.state().slice_map().cloned());
    let (tx, rx) = std::sync::mpsc::sync_channel(CTL_QUEUE);
    let shared = Arc::new(Shared {
        me: core.mcfg.self_id,
        voters: core.voters,
        net: net.clone(),
        repl: repl.clone(),
        hub: core.hub,
        nat: core.nat,
        map,
        snap: Mutex::new(Snap::default()),
        takeovers: Default::default(),
        handovers: AtomicU64::new(0),
        persist_failures: AtomicU64::new(0),
        adopt: AdoptMetrics::default(),
        release: ReleaseMetrics::default(),
        hook_stats: core.hooks.as_ref().map(|h| h.stats.clone()),
        ctl: tx.clone(),
        audit: core.audit.clone(),
        daemon_uid: rustix::process::geteuid().as_raw(),
        #[cfg(all(feature = "xdp", target_os = "linux"))]
        lease_fence_ns: AtomicU64::new(0),
    });
    net.set_inbound(Arc::new(Glue {
        tx: tx.clone(),
        repl: repl.as_ref().map(Arc::downgrade),

        dropped: AtomicU64::new(0),
        wake: repl_wake.clone(),
    }));
    let max_id = shared.voters.iter().map(|v| usize::from(v.id) + 1).max().unwrap_or(1);
    let mut ctl = Ctl {
        m,
        sh: shared.clone(),
        state_dir: core.state_dir.clone(),
        audit: core.audit,
        hooks: core.hooks,
        pending: Vec::new(),
        cur: None,
        cur_blocked: false,
        releases: VecDeque::new(),
        rel_blocked: false,
        rel_turn: false,
        max_handovers: core.max_handovers.max(1),
        auto_failover: core.mcfg.auto_failover,
        shutdown_ms: core.shutdown_ms,
        prev_view: None,
        manual_cmd: false,
        up: vec![false; max_id],
        refuse_on_overflow: core.refuse_on_overflow,
        repl_wake: repl_wake.clone(),
        sync_sent: None,
    };
    // B-3 / CP-10: with replication, failback waits for the returning
    // member's backup copies to be in sync.
    if ctl.sh.repl.is_some() {
        ctl.m.set_failback_needs_sync(true);
    }
    ctl.exec(initial);
    net.spawn().map_err(|e| format!("cluster.ha.listen {}: {e}", core.net.listen))?;
    let ctl_stop = Arc::new(AtomicBool::new(false));
    let killed = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();
    {
        let (stop, killed) = (ctl_stop.clone(), killed.clone());
        threads.push(
            std::thread::Builder::new()
                .name("plat-cluster-ctl".into())
                .spawn(move || ctl.run(&rx, &stop, &killed))
                .map_err(|e| e.to_string())?,
        );
    }
    if let Some(r) = repl {
        let (stop, wake) = (net_stop.clone(), repl_wake.clone());
        let h = std::thread::Builder::new()
            .name("plat-repl".into())
            .spawn(move || {
                // PERF-006: no fixed polling; park with a doubling back-off
                // while idle, unparked by acks, link changes and views.
                let mut idle = Duration::from_millis(1);
                while !stop.load(Ordering::Relaxed) {
                    if r.lock().pump() > 0 {
                        idle = Duration::from_millis(1);
                    } else {
                        std::thread::park_timeout(idle);
                        idle = (idle * 2).min(REPL_IDLE_MAX);
                    }
                }
                r.lock().pump();
            })
            .map_err(|e| e.to_string())?;
        let _ = wake.thread.set(h.thread().clone());
        threads.push(h);
    }
    match cli_listener(&core.state_dir) {
        Ok(l) => {
            let (sh, stop) = (shared.clone(), net_stop.clone());
            threads.push(
                std::thread::Builder::new()
                    .name("plat-cluster-cli".into())
                    .spawn(move || cli_loop(&l, &sh, &stop))
                    .map_err(|e| e.to_string())?,
            );
        }
        Err(e) => tracing::warn!("cluster operator socket unavailable: {e}"),
    }
    drop(tx);
    Ok(ClusterHandle { shared, repl_wake, ctl_stop, net_stop, killed, threads })
}

/// Starts HA for a member from the validated config.
pub fn start(
    cfg: &Config,
    nat: Arc<Nat64>,
    hub: Arc<ReplHub>,
    audit: AuditSink,
    tls: PeerConfigs,
) -> Result<ClusterHandle, String> {
    let ha = cfg.cluster.ha_active().ok_or("HA is not enabled")?;
    let uid = check_state_dir(&ha.state_dir)?;
    for p in [&ha.hooks.announce, &ha.hooks.withdraw].into_iter().flatten() {
        check_hook(p, uid)?;
    }
    let me = cfg.node.id;
    let n = u16::try_from(cfg.cluster.members.len()).map_err(|_| "too many members")?;
    let witness_id = ha.witness.as_ref().map(|_| n);
    let mut voters: Vec<Voter> = cfg
        .cluster
        .members
        .iter()
        .map(|m| Voter {
            id: m.id,
            name: m.name.clone(),
            identity: m.identity.clone(),
            addr: m.peer_addr,
            witness: false,
        })
        .collect();
    if let (Some(w), Some(id)) = (&ha.witness, witness_id) {
        voters.push(Voter { id, name: "witness".into(), identity: w.identity.clone(), addr: w.addr, witness: true });
    }
    let members: Vec<plat_cluster::DigestMember> = digest_input(cfg).members;
    let digest_vote = ha
        .witness
        .as_ref()
        .map_or([0; 32], |w| voting_digest(&members, &w.identity, ha.lease_ms, ha.heartbeat_ms, ha.drift_margin_pct));
    let net = NetConfig {
        me,
        name: cfg.node.name.clone(),
        listen: ha.listen,
        i_am_witness: false,
        peers: peer_specs(&voters, me)?,
        digest_full: plat_cluster::config_digest(&digest_input(cfg)),
        digest_vote,
        max_frame: ha.max_frame_bytes as usize,
        queue_bytes: usize::try_from(ha.peer_queue_bytes).unwrap_or(usize::MAX),
        keepalive: Duration::from_millis(ha.heartbeat_ms),
        idle_timeout: Duration::from_millis(ha.lease_ms * 2),
    };
    let map = nat.state().slice_map().cloned().ok_or("HA needs the sliced engine")?;
    let shadow = Arc::new(Shadow::new(
        map.clone(),
        cfg.nat64.port_min,
        cfg.nat64.port_max,
        cfg.nat64.port_block_size,
        u64::from(cfg.nat64.block_cooldown_secs) * 1000,
        cfg.nat64.max_sessions,
    ));
    let hooks = Hooks::spawn(
        ha.hooks.announce.clone(),
        ha.hooks.withdraw.clone(),
        ha.state_dir.clone(),
        uid,
        Duration::from_millis(ha.hook_timeout_ms),
        map.len() * 2,
        audit.clone(),
    )
    .map_err(|e| format!("cluster hooks: {e}"))?;
    let mcfg = MembershipConfig {
        self_id: me,
        members: cfg.cluster.members.iter().map(|m| (m.id, u32::from(m.weight))).collect(),
        witness: witness_id,
        slice_count: map.len(),
        lease_ms: ha.lease_ms,
        heartbeat_ms: ha.heartbeat_ms,
        drift_margin_pct: u64::from(ha.drift_margin_pct),
        failback_delay_ms: u64::from(ha.failback_delay_secs) * 1000,
        auto_failover: cfg.cluster.auto_failover(),
        seed: random_seed(),
    };
    launch(Core {
        mcfg,
        voters,
        net,
        tls,
        state_dir: ha.state_dir.clone(),
        audit,
        nat: Some(nat),
        hub: Some(hub),
        shadow: Some(shadow),
        hooks: Some(hooks),
        max_handovers: usize::from(ha.max_concurrent_handovers),
        shutdown_ms: ha.shutdown_handover_ms,
        clients: cfg.translation.client_prefixes.clone(),
        refuse_on_overflow: cfg.audit.on_overflow == plat_common::config::OverflowPolicy::RefuseNewBindings,
    })
}

/// Peer specs (allow-list per voter) for every voter but `me`.
pub fn peer_specs(voters: &[Voter], me: MemberId) -> Result<Vec<PeerSpec>, String> {
    voters
        .iter()
        .filter(|v| v.id != me)
        .map(|v| {
            Ok(PeerSpec {
                id: v.id,
                addr: v.addr,
                identity: v.identity.clone(),
                allow: AllowList::new(std::slice::from_ref(&v.identity)).map_err(|e| format!("{}: {e}", v.identity))?,
                witness: v.witness,
            })
        })
        .collect()
}

/// Election jitter seed (any value; randomly keyed per process).
pub fn random_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(Clock::wall_us());
    h.finish()
}

// ---------------------------------------------------------------- operator socket

fn cli_listener(dir: &Path) -> std::io::Result<UnixListener> {
    let p = dir.join(CTL_SOCK);
    if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_socket_like()) {
        std::fs::remove_file(&p)?;
    }
    let l = UnixListener::bind(&p)?;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

trait SocketLike {
    fn is_socket_like(&self) -> bool;
}

impl SocketLike for std::fs::FileType {
    fn is_socket_like(&self) -> bool {
        use std::os::unix::fs::FileTypeExt;
        self.is_socket()
    }
}

fn cli_loop(l: &UnixListener, sh: &Shared, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        let Ok((s, _)) = l.accept() else {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };
        let _ = s.set_nonblocking(false);
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
        let mut line = String::new();
        let mut r = BufReader::new(&s).take(256);
        if r.read_line(&mut line).is_err() {
            continue;
        }
        let reply = cli_handle(sh, line.trim(), plat_io::cred::peer_cred(&s).ok());
        let mut w = &s;
        let _ = w.write_all(reply.as_bytes());
    }
}

/// AC-3: one request from a peer with credentials `cred`. Only root and
/// the daemon's own uid may use the socket (it is 0600 in a 0700
/// directory already; this also covers a socket reached by other means).
pub(super) fn cli_handle(sh: &Shared, line: &str, cred: Option<PeerCred>) -> String {
    let parsed = parse_cli(line);
    let what = match &parsed {
        Ok(None) => (OperatorCommandKind::Status, None, false),
        Ok(Some(c)) => c.audit(),
        Err(_) => (OperatorCommandKind::Invalid, None, false),
    };
    let Some(c) = cred else {
        audit_operator(&sh.audit, false, what, None, Some(OperatorRefusal::NoCredentials));
        return "error: peer credentials unavailable\n".into();
    };
    if c.uid != 0 && c.uid != sh.daemon_uid {
        audit_operator(&sh.audit, false, what, cred, Some(OperatorRefusal::NotAuthorized));
        return "error: not authorized\n".into();
    }
    match parsed {
        Ok(None) => sh.view_json(),
        Ok(Some(cmd)) => command_via(&sh.ctl, cmd, cred),
        Err(e) => {
            audit_operator(&sh.audit, false, what, cred, Some(OperatorRefusal::Invalid));
            format!("error: {e}\n")
        }
    }
}

use std::io::Read as _;

/// `status` → `None`; `takeover <id> [--force]` / `restore <id>`.
fn parse_cli(line: &str) -> Result<Option<Command>, String> {
    let mut it = line.split_ascii_whitespace();
    let cmd = it.next().unwrap_or("");
    let id = it.next().and_then(|x| x.parse::<MemberId>().ok()).ok_or("member id required");
    let force = match it.next() {
        None => false,
        Some("--force") if cmd == "takeover" => true,
        Some(_) => return Err("unexpected argument".into()),
    };
    if it.next().is_some() {
        return Err("unexpected argument".into());
    }
    match cmd {
        "status" => Ok(None),
        "takeover" => Ok(Some(Command::Takeover(id?, force))),
        "restore" => Ok(Some(Command::Restore(id?))),
        _ => Err("unknown command".into()),
    }
}

/// Client side of `platd cluster ...`: one request on the daemon's
/// operator socket.
pub fn cli_request(state_dir: &Path, line: &str) -> Result<String, String> {
    let p = state_dir.join(CTL_SOCK);
    let mut s =
        UnixStream::connect(&p).map_err(|e| format!("{}: {e} (is platd running with [cluster.ha]?)", p.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    s.write_all(format!("{line}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.take(1 << 20).read_to_string(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

#[cfg(test)]
mod metric_tests {
    use super::{
        ElectionStats, ReleaseMetrics, ReleaseReason, ShutdownRelease, SliceState, keeps_shadow, render_election,
        runs_ahead, shutdown_release,
    };
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    /// F1: the detached state goes back to the shadow only when the slice
    /// went to nobody else.
    #[test]
    fn abandon_keeps_the_shadow_only_without_another_owner() {
        assert!(keeps_shadow(ReleaseReason::LeaseLost, None, 1));
        assert!(keeps_shadow(ReleaseReason::Fenced, Some(1), 1));
        assert!(!keeps_shadow(ReleaseReason::LeaseLost, Some(2), 1));
        assert!(!keeps_shadow(ReleaseReason::Fenced, Some(2), 1));
        assert!(!keeps_shadow(ReleaseReason::Handover, None, 1));
        assert!(!keeps_shadow(ReleaseReason::Shutdown, None, 1));
    }

    /// F3: a regain of this node's complete fenced slice (and a job with
    /// nothing to do) runs ahead of the adoption in progress; imports wait.
    #[test]
    fn no_import_jobs_run_ahead_of_the_cursor() {
        assert!(runs_ahead(Some(SliceState::Fenced), false, Some(1), 1));
        assert!(runs_ahead(Some(SliceState::Active), false, Some(2), 1));
        assert!(runs_ahead(None, false, None, 1));
        assert!(!runs_ahead(Some(SliceState::Fenced), false, Some(2), 1));
        assert!(!runs_ahead(Some(SliceState::Fenced), false, None, 1));
        assert!(!runs_ahead(Some(SliceState::Inactive), false, Some(1), 1));
        assert!(!runs_ahead(Some(SliceState::Adopting), false, Some(1), 1));
        // POAM-048: a slice being released never runs ahead, whatever its
        // state.
        assert!(!runs_ahead(Some(SliceState::Fenced), true, Some(1), 1));
        assert!(!runs_ahead(Some(SliceState::Inactive), true, None, 1));
    }

    /// F5: at shutdown the slice whose adoption was just abandoned is never
    /// handed over (no `HandoverFence`), even with an in-sync backup.
    #[test]
    fn shutdown_never_hands_over_an_abandoned_slice() {
        assert_eq!(shutdown_release(3, Some(3), true, Some(2)), ShutdownRelease::NeverServed);
        assert_eq!(shutdown_release(3, Some(3), false, None), ShutdownRelease::NeverServed);
        assert_eq!(shutdown_release(4, Some(3), true, Some(2)), ShutdownRelease::HandOver(2));
        assert_eq!(shutdown_release(4, Some(3), false, Some(2)), ShutdownRelease::Release);
        assert_eq!(shutdown_release(4, None, true, None), ShutdownRelease::Release);
    }

    /// SI-4: the election counters render under their documented names.
    #[test]
    fn election_metrics_render() {
        let mut o = String::new();
        render_election(&mut o, &ElectionStats { won: 3, timeout: 2, yielded: 1, heartbeats_expedited: 7 });
        assert_eq!(
            o,
            "# TYPE plat_cluster_election_rounds_total counter\n\
             plat_cluster_election_rounds_total{result=\"won\"} 3\n\
             plat_cluster_election_rounds_total{result=\"timeout\"} 2\n\
             plat_cluster_election_rounds_total{result=\"yield\"} 1\n\
             # TYPE plat_cluster_heartbeats_expedited_total counter\n\
             plat_cluster_heartbeats_expedited_total 7\n"
        );
    }

    /// SI-4 (POAM-048, QA): the release series render under their
    /// documented names, types and units (the step maximum in seconds,
    /// the largest step of the window).
    #[test]
    fn metrics_render_release_series() {
        let m = ReleaseMetrics::default();
        let mut o = String::new();
        m.render(&mut o);
        assert_eq!(
            o,
            "# TYPE plat_cluster_release_steps_total counter\nplat_cluster_release_steps_total 0\n\
             # TYPE plat_cluster_release_step_seconds_max gauge\nplat_cluster_release_step_seconds_max 0.000000\n\
             # TYPE plat_cluster_releasing_slices gauge\nplat_cluster_releasing_slices 0\n\
             # TYPE plat_cluster_release_audit_paused_total counter\nplat_cluster_release_audit_paused_total 0\n\
             # TYPE plat_cluster_release_oldest_age_seconds gauge\nplat_cluster_release_oldest_age_seconds 0.000\n"
        );
        m.step(Duration::from_millis(3));
        m.step(Duration::from_micros(7250));
        m.step(Duration::from_millis(1));
        m.releasing.store(2, Ordering::Relaxed);
        m.audit_paused.store(5, Ordering::Relaxed);
        let mut o = String::new();
        m.render(&mut o);
        assert!(o.contains("plat_cluster_release_steps_total 3\n"), "{o}");
        assert!(o.contains("plat_cluster_release_step_seconds_max 0.007250\n"), "{o}");
        assert!(o.contains("plat_cluster_releasing_slices 2\n"), "{o}");
        assert!(o.contains("plat_cluster_release_audit_paused_total 5\n"), "{o}");
        // SEC-003: the oldest queued release's age (fixed `now` for the test).
        m.oldest_started_ms.store(10_000, Ordering::Relaxed);
        assert_eq!(m.oldest_age(12_500), 2.5);
        assert_eq!(m.oldest_age(9_000), 0.0);
        let mut o = String::new();
        m.render(&mut o);
        assert!(o.contains("# TYPE plat_cluster_release_oldest_age_seconds gauge\n"), "{o}");
        m.oldest_started_ms.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(m.oldest_age(12_500), 0.0);
    }
}
