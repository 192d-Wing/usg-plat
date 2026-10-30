//! Cluster peer channel: mutual TLS 1.3 (FIPS) between members and the
//! witness, one connection per pair, threads only.
//!
//! ```text
//!  plat-peer-accept (non-blocking, 100 ms poll)
//!     │  source IP not a lower-id voter, or over voters + 1 connections
//!     │                       ─▶ close before TLS, audit not_allowed
//!     └─▶ plat-peer-in: ClientHello ≤ 2 s, handshake ≤ 5 s (client cert
//!           required, cluster CA, revocation) ─▶ Hello exchange
//!  plat-peer-<id> (lower id dials higher id and the witness): connect,
//!           handshake (server cert must match members[id].identity) ─▶ Hello
//!  Hello checks: version, certificate identity bound to the claimed id
//!  (and the source IP to its peer_addr), config digest, duplicate id,
//!  overlapping owned pool ─▶ HelloAck; any refusal closes and is audited
//!  (`cluster_peer_rejected`, token bucket, `cluster_peer_suppressed`).
//!  Established: one thread per connection, non-blocking socket loop;
//!  control queue (membership) strictly before the data queue
//!  (replication), both bounded.
//! ```
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8, SC-8(1), SC-13 - TLS 1.3 with the FIPS provider
//!   (plat-tls peer configs), no resumption
//! - NIST 800-53: IA-3, IA-5(2)(a)(2), AC-3 - certificate identity bound to
//!   the member id (typed allow-list entry), source IP pinned to the
//!   member's peer_addr; the witness may only vote
//! - NIST 800-53: CM-6 - config digest cross-checked (POAM-017c);
//!   duplicate ids refused and reported degraded
//! - NIST 800-53: AU-2, AU-12, SC-5 - refusals audited through a token
//!   bucket with a suppressed summary; connection cap, handshake deadlines,
//!   bounded queues and frames (`max_frame_bytes`, `peer_queue_bytes`)

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::ops::DerefMut;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use plat_audit::{AuditSink, AuditText, Event, PeerRejectReason, PeerRejected};
use plat_cluster::codec::{self, HEADER_LEN};
use plat_cluster::{Hello, MemberId, Msg, PROTO_VERSION, PartitionScheme, RejectReason, SliceId};
use plat_common::Clock;
use plat_tls::stream;
use plat_tls::{AllowList, PeerConfigs, PeerIdentity, peer_identity, peer_server_name};
use rustls::{ConnectionCommon, SideData};

use crate::mgmt::RejectLimiter;

/// `Ack` on this slice id is a keepalive (slice ids are below 4096), so
/// an idle link between two followers is still checked for liveness.
pub const KEEPALIVE_SLICE: SliceId = SliceId::MAX;
/// Accept poll interval when idle.
const ACCEPT_POLL: Duration = Duration::from_millis(100);
/// Time from accept to a complete ClientHello.
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(2);
/// Handshake plus Hello exchange.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Dial timeout and the pause between dial attempts.
const DIAL_TIMEOUT: Duration = Duration::from_secs(1);
const DIAL_BACKOFF: Duration = Duration::from_millis(300);
/// Control frames are tiny; this bounds a stalled peer's control backlog.
const CTRL_QUEUE_BYTES: usize = 1 << 20;
/// Plaintext pushed into TLS per loop turn (fairness between read/write).
const WRITE_BUDGET: usize = 256 << 10;
/// Longest poll(2) of an idle connection thread (it also wakes for
/// socket input, queued frames and its keepalive/idle deadlines).
const IDLE_WAIT: Duration = Duration::from_millis(500);
/// Pending (pre-Hello) inbound handshakes per source address and per
/// configured voter at that address (SC-5).
const PENDING_PER_SOURCE: usize = 2;
/// Emptied frame buffers kept per peer for reuse.
const SPARE_BUFFERS: usize = 8;
/// How long a duplicate-id refusal keeps the node reported degraded.
const DUPLICATE_DEGRADED: Duration = Duration::from_secs(60);
const CLOSE_LIMIT: Duration = Duration::from_millis(200);

/// Every refusal reason, in metric order.
pub const REJECT_REASONS: [RejectReason; 10] = [
    RejectReason::NotAllowed,
    RejectReason::IdMismatch,
    RejectReason::DuplicateId,
    RejectReason::DigestMismatch,
    RejectReason::Version,
    RejectReason::Overlap,
    RejectReason::Handshake,
    RejectReason::Protocol,
    RejectReason::InvalidInput,
    RejectReason::Capacity,
];

fn audit_reason(r: RejectReason) -> PeerRejectReason {
    match r {
        RejectReason::NotAllowed => PeerRejectReason::NotAllowed,
        RejectReason::IdMismatch => PeerRejectReason::IdMismatch,
        RejectReason::DuplicateId => PeerRejectReason::DuplicateId,
        RejectReason::DigestMismatch => PeerRejectReason::DigestMismatch,
        RejectReason::Version => PeerRejectReason::Version,
        RejectReason::Overlap => PeerRejectReason::Overlap,
        RejectReason::Handshake => PeerRejectReason::Handshake,
        RejectReason::Protocol => PeerRejectReason::Protocol,
        RejectReason::InvalidInput => PeerRejectReason::InvalidInput,
        RejectReason::Capacity => PeerRejectReason::Capacity,
    }
}

/// One other voter.
#[derive(Debug, Clone)]
pub struct PeerSpec {
    pub id: MemberId,
    pub addr: SocketAddr,
    /// Typed identity (`dns:`, `cn:`, `uri:`, `sha256:`).
    pub identity: String,
    pub allow: AllowList,
    pub witness: bool,
}

/// Static settings of the peer channel.
#[derive(Debug, Clone)]
pub struct NetConfig {
    pub me: MemberId,
    pub name: String,
    pub listen: SocketAddr,
    pub i_am_witness: bool,
    /// Every other voter.
    pub peers: Vec<PeerSpec>,
    /// Digest exchanged between members.
    pub digest_full: [u8; 32],
    /// Digest exchanged with the witness (voting inputs only).
    pub digest_vote: [u8; 32],
    pub max_frame: usize,
    pub queue_bytes: usize,
    /// Keepalive interval and the silence after which a link is dropped.
    pub keepalive: Duration,
    pub idle_timeout: Duration,
}

/// Receives what established connections deliver.
pub trait Inbound: Send + Sync {
    /// Membership traffic (and `HandoverFence`/`HandoverDone`).
    fn control(&self, from: MemberId, msg: Msg);
    /// Replication traffic from a member. `Err`: refused and audited
    /// (`cluster_peer_rejected`); the connection is closed if
    /// [`Refusal::close`].
    fn data(&self, from: MemberId, msg: Msg) -> Result<(), Refusal>;
    /// A connection to `peer` came up or went down.
    fn link(&self, peer: MemberId, up: bool);
}

/// Outgoing frames of one peer. A data entry is one buffer of one or more
/// encoded frames (the replicator queues one buffer per peer per pump).
#[derive(Debug, Default)]
struct Queues {
    ctrl: VecDeque<Vec<u8>>,
    data: VecDeque<(Vec<u8>, usize)>,
    ctrl_bytes: usize,
    data_bytes: usize,
    data_frames: usize,
    /// Emptied buffers for reuse (at most [`SPARE_BUFFERS`]).
    spare: Vec<Vec<u8>>,
    /// The connection thread is (about to be) blocked in poll(2): a push
    /// must wake it.
    sleeping: bool,
}

impl Queues {
    fn clear(&mut self) {
        let spare = std::mem::take(&mut self.spare);
        *self = Queues { spare, ..Queues::default() };
    }

    fn is_empty(&self) -> bool {
        self.ctrl.is_empty() && self.data.is_empty()
    }

    fn recycle(&mut self, mut b: Vec<u8>) {
        if self.spare.len() < SPARE_BUFFERS {
            b.clear();
            self.spare.push(b);
        }
    }

    /// Moves queued frames (control first) into `out` until it holds
    /// `budget` bytes or the queues are empty. Returns the frames moved.
    fn drain_into(&mut self, out: &mut Vec<u8>, budget: usize) -> usize {
        let mut frames = 0;
        while out.len() < budget {
            if let Some(f) = self.ctrl.pop_front() {
                self.ctrl_bytes -= f.len();
                out.extend_from_slice(&f);
                frames += 1;
                self.recycle(f);
                continue;
            }
            let Some((f, n)) = self.data.pop_front() else { break };
            self.data_bytes -= f.len();
            self.data_frames -= n;
            out.extend_from_slice(&f);
            frames += n;
            self.recycle(f);
        }
        frames
    }
}

/// Wakes a connection thread blocked in poll(2): one byte on a
/// non-blocking socket pair.
#[derive(Debug)]
struct Waker {
    rx: UnixStream,
    tx: UnixStream,
}

impl Waker {
    fn new() -> io::Result<Self> {
        let (rx, tx) = UnixStream::pair()?;
        rx.set_nonblocking(true)?;
        tx.set_nonblocking(true)?;
        Ok(Self { rx, tx })
    }

    fn wake(&self) {
        // A full pair already holds a pending wake-up.
        let _ = (&self.tx).write(&[1]);
    }

    fn drain(&self) {
        let mut b = [0u8; 64];
        while matches!((&self.rx).read(&mut b), Ok(n) if n > 0) {}
    }
}

/// Replication input refused by the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: RejectReason,
    /// Misbehaving peer: close the connection. Otherwise only the message
    /// is dropped (e.g. a sender whose view lags ours).
    pub close: bool,
    pub detail: String,
}

impl Refusal {
    /// Drop the message, keep the connection.
    pub fn drop(reason: RejectReason, detail: impl Into<String>) -> Self {
        Self { reason, close: false, detail: detail.into() }
    }

    /// Drop the message and close the connection.
    pub fn close(reason: RejectReason, detail: impl Into<String>) -> Self {
        Self { reason, close: true, detail: detail.into() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnInfo {
    ip: IpAddr,
    cert: [u8; 32],
}

#[derive(Debug)]
struct Slot {
    q: Mutex<Queues>,
    waker: Waker,
    up: AtomicBool,
    /// Current connection generation (a connection thread exits when it no
    /// longer matches its own).
    gen_: AtomicU64,
    info: Mutex<Option<ConnInfo>>,
}

impl Slot {
    fn new() -> io::Result<Self> {
        Ok(Self {
            q: Mutex::default(),
            waker: Waker::new()?,
            up: AtomicBool::new(false),
            gen_: AtomicU64::new(0),
            info: Mutex::new(None),
        })
    }
}

/// Peer channel counters.
#[derive(Debug, Default)]
pub struct NetStats {
    rejected: [AtomicU64; REJECT_REASONS.len()],
    /// Data frames dropped on a full peer queue.
    pub queue_dropped: AtomicU64,
    /// Data frames still queued when a connection ended (B-4: lost with
    /// the link; the replicator resyncs the slices).
    pub link_dropped: AtomicU64,
    pub frames_rx: AtomicU64,
    pub frames_tx: AtomicU64,
}

impl NetStats {
    fn count(&self, r: RejectReason) {
        if let Some(i) = REJECT_REASONS.iter().position(|x| *x == r)
            && let Some(a) = self.rejected.get(i)
        {
            a.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn rejected(&self, r: RejectReason) -> u64 {
        REJECT_REASONS
            .iter()
            .position(|x| *x == r)
            .and_then(|i| self.rejected.get(i))
            .map_or(0, |a| a.load(Ordering::Relaxed))
    }
}

/// The peer channel. Shared by the control, replicator and connection
/// threads.
pub struct Net {
    cfg: NetConfig,
    tls: PeerConfigs,
    /// Indexed by member id (`slots[me]` unused).
    slots: Vec<Slot>,
    inbound: OnceLock<Arc<dyn Inbound>>,
    audit: AuditSink,
    limiter: RejectLimiter,
    pub stats: NetStats,
    /// Newest adopted epoch (sent in `Hello`).
    pub epoch: AtomicU64,
    stop: Arc<AtomicBool>,
    /// Hard stop of every connection (tests: simulated crash).
    killed: AtomicBool,
    inbound_conns: AtomicUsize,
    /// Pending inbound handshakes per source address.
    pending: Mutex<Vec<(IpAddr, usize)>>,
    degraded_until: Mutex<Option<Instant>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Net").field("me", &self.cfg.me).finish_non_exhaustive()
    }
}

/// Why a connection ended or was refused.
#[derive(Debug)]
enum Fail {
    Reject(RejectReason, Option<MemberId>, Option<String>),
    Closed(String),
}

fn io_fail(e: impl std::fmt::Display) -> Fail {
    Fail::Closed(e.to_string())
}

/// Typed identity text of a certificate for the audit record: the allow
/// entry it matched, else its first DNS SAN, URI SAN or CN.
fn identity_text(id: &PeerIdentity, matched: Option<&str>) -> String {
    if let Some(m) = matched {
        return m.to_string();
    }
    id.dns_sans
        .first()
        .map(|d| format!("dns:{d}"))
        .or_else(|| id.uri_sans.first().map(|u| format!("uri:{u}")))
        .or_else(|| id.subject_cn.as_ref().map(|c| format!("cn:{c}")))
        .unwrap_or_default()
}

impl Net {
    pub fn new(cfg: NetConfig, tls: PeerConfigs, audit: AuditSink, stop: Arc<AtomicBool>) -> io::Result<Arc<Self>> {
        let n = cfg.peers.iter().map(|p| usize::from(p.id) + 1).max().unwrap_or(0).max(usize::from(cfg.me) + 1);
        Ok(Arc::new(Self {
            slots: (0..n).map(|_| Slot::new()).collect::<io::Result<_>>()?,
            cfg,
            tls,
            inbound: OnceLock::new(),
            audit,
            limiter: RejectLimiter::standard(),
            stats: NetStats::default(),
            epoch: AtomicU64::new(0),
            stop,
            killed: AtomicBool::new(false),
            inbound_conns: AtomicUsize::new(0),
            pending: Mutex::new(Vec::new()),
            degraded_until: Mutex::new(None),
            threads: Mutex::new(Vec::new()),
        }))
    }

    pub fn set_inbound(&self, h: Arc<dyn Inbound>) {
        let _ = self.inbound.set(h);
    }

    fn spec(&self, id: MemberId) -> Option<&PeerSpec> {
        self.cfg.peers.iter().find(|p| p.id == id)
    }

    fn running(&self) -> bool {
        !self.stop.load(Ordering::Relaxed) && !self.killed.load(Ordering::Relaxed)
    }

    /// Whether a connection to `id` is established.
    pub fn is_up(&self, id: MemberId) -> bool {
        self.slots.get(usize::from(id)).is_some_and(|s| s.up.load(Ordering::Acquire))
    }

    /// Bytes waiting in `id`'s data queue (`plat_cluster_repl_lag_records`
    /// counts frames, see [`Net::data_frames`]).
    pub fn data_bytes(&self, id: MemberId) -> usize {
        self.slots.get(usize::from(id)).map_or(0, |s| s.q.lock().data_bytes)
    }

    pub fn data_frames(&self, id: MemberId) -> usize {
        self.slots.get(usize::from(id)).map_or(0, |s| s.q.lock().data_frames)
    }

    /// True while a duplicate-id refusal is recent (health degraded).
    pub fn duplicate_seen(&self) -> bool {
        self.degraded_until.lock().is_some_and(|t| Instant::now() < t)
    }

    /// Queues `msg` for `to`: membership messages on the control queue,
    /// everything else (replication, and `HandoverFence`, which must follow
    /// the slice's last records) on the data queue. `false` when `to` is
    /// not connected or its queue is full (counted; the caller resyncs).
    pub fn send(&self, to: MemberId, msg: &Msg) -> bool {
        let ctrl = msg.is_control() && !matches!(msg, Msg::HandoverFence { .. });
        self.enqueue(to, msg, ctrl)
    }

    fn enqueue(&self, to: MemberId, msg: &Msg, ctrl: bool) -> bool {
        let Some(slot) = self.slots.get(usize::from(to)) else { return false };
        if to == self.cfg.me || !slot.up.load(Ordering::Acquire) {
            return false;
        }
        let mut frame = Vec::new();
        if let Err(e) = codec::encode(msg, self.cfg.max_frame, &mut frame) {
            tracing::warn!(peer = to, "cluster frame not sent: {e}");
            return false;
        }
        let mut q = slot.q.lock();
        if ctrl {
            if q.ctrl_bytes + frame.len() > CTRL_QUEUE_BYTES {
                return false;
            }
            q.ctrl_bytes += frame.len();
            q.ctrl.push_back(frame);
        } else {
            // SC-5: drop the newest data frame on a full queue; the
            // replicator marks the slice dirty and resyncs it.
            if q.data_bytes + frame.len() > self.cfg.queue_bytes {
                self.stats.queue_dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            q.data_bytes += frame.len();
            q.data_frames += 1;
            q.data.push_back((frame, 1));
        }
        let wake = q.sleeping;
        drop(q);
        if wake {
            slot.waker.wake();
        }
        true
    }

    /// Queues `frames` already-encoded data frames in `buf` for `to` as one
    /// entry (one lock, at most one wake-up). On success `buf` is swapped
    /// for an empty reused buffer; on failure (not connected, queue full:
    /// counted) it is left untouched for the caller to clear.
    pub fn send_batch(&self, to: MemberId, buf: &mut Vec<u8>, frames: usize) -> bool {
        if buf.is_empty() {
            return true;
        }
        let Some(slot) = self.slots.get(usize::from(to)) else { return false };
        if to == self.cfg.me || !slot.up.load(Ordering::Acquire) {
            return false;
        }
        let mut q = slot.q.lock();
        if q.data_bytes + buf.len() > self.cfg.queue_bytes {
            self.stats.queue_dropped.fetch_add(frames as u64, Ordering::Relaxed);
            return false;
        }
        let fresh = q.spare.pop().unwrap_or_default();
        let b = std::mem::replace(buf, fresh);
        q.data_bytes += b.len();
        q.data_frames += frames;
        q.data.push_back((b, frames));
        let wake = q.sleeping;
        drop(q);
        if wake {
            slot.waker.wake();
        }
        true
    }

    /// Encodes one data message onto a batch buffer (see
    /// [`Net::send_batch`]). `false` if it cannot be encoded.
    pub fn encode_into(&self, msg: &Msg, buf: &mut Vec<u8>) -> bool {
        codec::encode(msg, self.cfg.max_frame, buf).is_ok()
    }

    /// Audits one refusal (token bucket; every refusal is counted).
    fn reject(&self, peer: SocketAddr, identity: Option<&str>, claimed: Option<MemberId>, r: RejectReason) {
        self.stats.count(r);
        tracing::debug!(%peer, reason = r.as_str(), "cluster peer refused");
        if !self.limiter.admit() {
            return;
        }
        let rejected = PeerRejected {
            ip: peer.ip(),
            port: peer.port(),
            identity: identity.filter(|s| !s.is_empty()).map(|s| AuditText::new(s, AuditText::SUBJECT_MAX)),
            claimed_id: claimed,
            reason: audit_reason(r),
        };
        self.audit.emit(Event::ClusterPeerRejected { ts_us: Clock::wall_us(), rejected: Arc::new(rejected) });
    }

    /// Emits the suppressed-refusals summary when its window ended.
    pub fn flush_suppressed(&self, flush: bool) {
        if let Some((suppressed, window_secs)) = self.limiter.take_suppressed(flush) {
            self.audit.emit(Event::ClusterPeerSuppressed { ts_us: Clock::wall_us(), suppressed, window_secs });
        }
    }

    fn my_hello(&self, peer_is_witness: bool) -> Msg {
        let witness_link = peer_is_witness || self.cfg.i_am_witness;
        Msg::Hello(Hello {
            proto_version: PROTO_VERSION,
            node_id: self.cfg.me,
            name: self.cfg.name.clone(),
            config_digest: if witness_link { self.cfg.digest_vote } else { self.cfg.digest_full },
            epoch: self.epoch.load(Ordering::Relaxed),
            scheme: PartitionScheme::Slices,
            owned: Vec::new(),
        })
    }

    /// Checks a peer's `Hello` (both sides). `expect`: the member dialed
    /// (dialing side) or `None` (accepting side, any lower id).
    fn check_hello(
        &self,
        hello: &Hello,
        id: &PeerIdentity,
        ip: IpAddr,
        expect: Option<MemberId>,
    ) -> Result<&PeerSpec, (RejectReason, Option<String>)> {
        let any = self.cfg.peers.iter().find_map(|p| p.allow.matched(id).map(|m| m.to_string()));
        if hello.proto_version != PROTO_VERSION {
            return Err((RejectReason::Version, any));
        }
        // S-1 (IA-3): a peer that claims this node's own id, or the id of a
        // member that is connected right now, from another certificate or
        // address is a duplicate id (misconfiguration or impersonation):
        // refused as `duplicate_id` and health reports degraded. The live
        // connection is kept (it is the authenticated one).
        if hello.node_id == self.cfg.me && any.is_some() {
            self.mark_duplicate();
            return Err((RejectReason::DuplicateId, any));
        }
        let Some(spec) = self.spec(hello.node_id) else {
            return Err((if any.is_some() { RejectReason::IdMismatch } else { RejectReason::NotAllowed }, any));
        };
        let live_elsewhere = |net: &Self| {
            any.is_some()
                && net.is_up(spec.id)
                && (spec.allow.matched(id).is_none()
                    || (expect.is_none() && spec.addr.ip().to_canonical() != ip.to_canonical()))
        };
        if live_elsewhere(self) {
            self.mark_duplicate();
            return Err((RejectReason::DuplicateId, any));
        }
        // IA-3: the certificate must be the claimed member's.
        let Some(matched) = spec.allow.matched(id) else {
            return Err((if any.is_some() { RejectReason::IdMismatch } else { RejectReason::NotAllowed }, any));
        };
        let matched = Some(matched.to_string());
        if expect.is_some_and(|e| e != spec.id) {
            return Err((RejectReason::IdMismatch, matched));
        }
        // Exactly one connection per pair: the lower id dials.
        if expect.is_none() && spec.id > self.cfg.me {
            return Err((RejectReason::NotAllowed, matched));
        }
        // SC-7: the source address is pinned to the member's peer_addr.
        if expect.is_none() && spec.addr.ip().to_canonical() != ip.to_canonical() {
            return Err((RejectReason::NotAllowed, matched));
        }
        if spec.witness && self.cfg.i_am_witness {
            return Err((RejectReason::NotAllowed, matched));
        }
        let want = if spec.witness || self.cfg.i_am_witness { self.cfg.digest_vote } else { self.cfg.digest_full };
        if hello.config_digest != want {
            return Err((RejectReason::DigestMismatch, matched));
        }
        if hello.scheme != PartitionScheme::Slices && !hello.owned.is_empty() {
            return Err((RejectReason::Overlap, matched));
        }
        Ok(spec)
    }

    /// Registers an authenticated connection for `id`. A live connection
    /// for the same id from another address or certificate is a duplicate
    /// id: both are refused and health reports degraded.
    fn register(&self, id: MemberId, info: ConnInfo) -> Result<u64, RejectReason> {
        let slot = self.slots.get(usize::from(id)).ok_or(RejectReason::NotAllowed)?;
        let mut cur = slot.info.lock();
        if let Some(old) = *cur
            && slot.up.load(Ordering::Acquire)
            && old != info
        {
            self.mark_duplicate();
            slot.gen_.fetch_add(1, Ordering::AcqRel);
            slot.up.store(false, Ordering::Release);
            *cur = None;
            slot.waker.wake();
            return Err(RejectReason::DuplicateId);
        }
        *cur = Some(info);
        self.clear_queue(slot);
        let g = slot.gen_.fetch_add(1, Ordering::AcqRel) + 1;
        slot.up.store(true, Ordering::Release);
        slot.waker.wake();
        Ok(g)
    }

    /// `/healthz` degraded for [`DUPLICATE_DEGRADED`].
    fn mark_duplicate(&self) {
        *self.degraded_until.lock() = Some(Instant::now() + DUPLICATE_DEGRADED);
    }

    fn unregister(&self, id: MemberId, g: u64) {
        let Some(slot) = self.slots.get(usize::from(id)) else { return };
        let mut cur = slot.info.lock();
        if slot.gen_.load(Ordering::Acquire) == g {
            slot.up.store(false, Ordering::Release);
            *cur = None;
            self.clear_queue(slot);
        }
    }

    /// Empties a peer queue; data frames still in it are counted lost.
    fn clear_queue(&self, slot: &Slot) {
        let mut q = slot.q.lock();
        self.stats.link_dropped.fetch_add(q.data_frames as u64, Ordering::Relaxed);
        q.clear();
    }

    /// Starts the accept thread and one dialer per higher-id voter.
    pub fn spawn(self: &Arc<Self>) -> io::Result<()> {
        let l = TcpListener::bind(self.cfg.listen)?;
        l.set_nonblocking(true)?;
        let net = self.clone();
        let h = std::thread::Builder::new().name("plat-peer-accept".into()).spawn(move || net.accept_loop(&l))?;
        self.threads.lock().push(h);
        for p in self.cfg.peers.iter().filter(|p| p.id > self.cfg.me) {
            let (net, id) = (self.clone(), p.id);
            let h = std::thread::Builder::new().name(format!("plat-peer-{id}")).spawn(move || net.dial_loop(id))?;
            self.threads.lock().push(h);
        }
        Ok(())
    }

    /// Stops every connection at once (no close_notify): a simulated crash
    /// in tests.
    #[cfg(test)]
    pub fn kill(&self) {
        self.killed.store(true, Ordering::Relaxed);
        self.wake_all();
    }

    /// Wakes every connection thread (after `stop` is set).
    pub fn wake_all(&self) {
        for s in &self.slots {
            s.waker.wake();
        }
    }

    /// Waits for the network threads (after `stop` or [`Net::kill`]).
    pub fn join(&self) {
        let hs: Vec<_> = std::mem::take(&mut *self.threads.lock());
        for h in hs {
            let _ = h.join();
        }
        self.flush_suppressed(true);
    }

    /// Voters allowed to dial us from `ip` (lower ids at that address).
    fn dialers_at(&self, ip: IpAddr) -> usize {
        self.cfg.peers.iter().filter(|p| p.id < self.cfg.me && p.addr.ip().to_canonical() == ip.to_canonical()).count()
    }

    /// Claims a pending-handshake slot for `ip`: at most
    /// [`PENDING_PER_SOURCE`] per voter configured at that address, so one
    /// source cannot use up the slots of the others (SC-5).
    fn claim_pending(&self, ip: IpAddr) -> bool {
        let cap = PENDING_PER_SOURCE * self.dialers_at(ip);
        let ip = ip.to_canonical();
        let mut p = self.pending.lock();
        match p.iter_mut().find(|(a, _)| *a == ip) {
            Some((_, n)) if *n >= cap => false,
            Some((_, n)) => {
                *n += 1;
                true
            }
            None if cap == 0 => false,
            None => {
                p.push((ip, 1));
                true
            }
        }
    }

    fn release_pending(&self, ip: IpAddr) {
        let ip = ip.to_canonical();
        let mut p = self.pending.lock();
        if let Some(i) = p.iter().position(|(a, _)| *a == ip) {
            if p[i].1 <= 1 {
                p.swap_remove(i);
            } else {
                p[i].1 -= 1;
            }
        }
    }

    fn accept_loop(self: &Arc<Self>, l: &TcpListener) {
        // Established connections (one per lower-id voter) plus every
        // source's pending handshakes: each voter keeps its own share.
        let lower = self.cfg.peers.iter().filter(|p| p.id < self.cfg.me).count();
        let max = lower * (1 + PENDING_PER_SOURCE);
        let mut conns: Vec<JoinHandle<()>> = Vec::new();
        while self.running() {
            self.flush_suppressed(false);
            conns.retain(|h| !h.is_finished());
            let Ok((sock, peer)) = l.accept() else {
                std::thread::sleep(ACCEPT_POLL);
                continue;
            };
            // SC-7: only lower-id voters dial us; anything else is closed
            // before any TLS work.
            let known = self
                .cfg
                .peers
                .iter()
                .any(|p| p.id < self.cfg.me && p.addr.ip().to_canonical() == peer.ip().to_canonical());
            if !known {
                drop(sock);
                self.reject(peer, None, None, RejectReason::NotAllowed);
                continue;
            }
            // SC-5: connection cap and per-source pending handshakes.
            if self.inbound_conns.load(Ordering::Acquire) >= max || !self.claim_pending(peer.ip()) {
                drop(sock);
                self.reject(peer, None, None, RejectReason::Capacity);
                continue;
            }
            self.inbound_conns.fetch_add(1, Ordering::AcqRel);
            let net = self.clone();
            match std::thread::Builder::new().name("plat-peer-in".into()).spawn(move || {
                net.serve_inbound(sock, peer);
                net.inbound_conns.fetch_sub(1, Ordering::AcqRel);
            }) {
                Ok(h) => conns.push(h),
                Err(e) => {
                    self.inbound_conns.fetch_sub(1, Ordering::AcqRel);
                    self.release_pending(peer.ip());
                    tracing::warn!("cluster peer {peer}: no connection thread: {e}");
                }
            }
        }
        for h in conns {
            let _ = h.join();
        }
    }

    fn serve_inbound(self: &Arc<Self>, mut sock: TcpStream, peer: SocketAddr) {
        let mut pending = Pending { net: self, ip: Some(peer.ip()) };
        let _ = sock.set_nonblocking(false);
        let _ = sock.set_nodelay(true);
        let start = Instant::now();
        let Ok(mut conn) = rustls::ServerConnection::new(self.tls.server.clone()) else {
            self.reject(peer, None, None, RejectReason::Handshake);
            return;
        };
        if let Err(e) = stream::await_client_hello(&mut conn, &mut sock, start + CLIENT_HELLO_TIMEOUT) {
            tracing::debug!("cluster peer {peer}: {e}");
            self.reject(peer, None, None, RejectReason::Handshake);
            return;
        }
        if let Err(e) = stream::handshake(&mut conn, &mut sock, start + HANDSHAKE_TIMEOUT) {
            let id = conn.peer_certificates().and_then(|c| c.first()).map(peer_identity);
            let text = id.as_ref().map(|i| identity_text(i, None));
            tracing::debug!("cluster peer {peer}: {e}");
            self.reject(peer, text.as_deref(), None, RejectReason::Handshake);
            return;
        }
        self.established(conn, sock, peer, None, start + HANDSHAKE_TIMEOUT, &mut pending);
    }

    fn dial_loop(self: &Arc<Self>, id: MemberId) {
        let Some(spec) = self.spec(id).cloned() else { return };
        while self.running() {
            if self.is_up(id) {
                std::thread::sleep(DIAL_BACKOFF);
                continue;
            }
            match self.dial_once(&spec) {
                Ok(()) => {}
                Err(Fail::Closed(r)) => tracing::debug!(peer = id, "cluster dial: {r}"),
                Err(Fail::Reject(r, claimed, text)) => {
                    self.reject(spec.addr, text.as_deref(), claimed, r);
                }
            }
            let t = Instant::now();
            while self.running() && t.elapsed() < DIAL_BACKOFF {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    fn dial_once(self: &Arc<Self>, spec: &PeerSpec) -> Result<(), Fail> {
        let mut sock = TcpStream::connect_timeout(&spec.addr, DIAL_TIMEOUT).map_err(io_fail)?;
        let _ = sock.set_nodelay(true);
        let start = Instant::now();
        let name = peer_server_name(&spec.identity, spec.addr.ip()).map_err(io_fail)?;
        let mut conn = rustls::ClientConnection::new(self.tls.client.clone(), name).map_err(io_fail)?;
        if let Err(e) = stream::handshake(&mut conn, &mut sock, start + HANDSHAKE_TIMEOUT) {
            tracing::debug!("cluster peer {}: {e}", spec.addr);
            let id = conn.peer_certificates().and_then(|c| c.first()).map(peer_identity);
            return Err(Fail::Reject(RejectReason::Handshake, None, id.map(|i| identity_text(&i, None))));
        }
        let mut pending = Pending { net: self, ip: None };
        self.established(conn, sock, spec.addr, Some(spec.id), start + HANDSHAKE_TIMEOUT, &mut pending);
        Ok(())
    }

    /// Hello exchange on a completed handshake, then the connection loop.
    fn established<C, D>(
        self: &Arc<Self>,
        mut conn: C,
        mut sock: TcpStream,
        peer: SocketAddr,
        expect: Option<MemberId>,
        deadline: Instant,
        pending: &mut Pending<'_>,
    ) where
        C: DerefMut<Target = ConnectionCommon<D>>,
        D: SideData,
    {
        let Some(id) = conn.peer_certificates().and_then(|c| c.first()).map(peer_identity) else {
            self.reject(peer, None, None, RejectReason::NotAllowed);
            return;
        };
        // Dialing side: the server must be the member we dialed.
        if let Some(e) = expect.and_then(|e| self.spec(e))
            && !e.allow.permits(&id)
        {
            self.reject(peer, Some(&identity_text(&id, None)), None, RejectReason::NotAllowed);
            stream::close(&mut conn, &mut sock, CLOSE_LIMIT);
            return;
        }
        let peer_is_witness = expect.and_then(|e| self.spec(e)).is_some_and(|s| s.witness);
        let mut rbuf = Vec::new();
        let hello = self.my_hello(peer_is_witness);
        let theirs = match self
            .write_msg(&mut conn, &mut sock, &hello, deadline)
            .and_then(|()| read_msg(&mut conn, &mut sock, &mut rbuf, self.cfg.max_frame, deadline))
        {
            Ok(Msg::Hello(h)) => h,
            Ok(_) => {
                self.reject(peer, Some(&identity_text(&id, None)), None, RejectReason::Version);
                return;
            }
            Err(e) => {
                tracing::debug!("cluster peer {peer}: hello: {e:?}");
                self.reject(peer, Some(&identity_text(&id, None)), None, RejectReason::Handshake);
                return;
            }
        };
        let claimed = Some(theirs.node_id);
        let checked = self.check_hello(&theirs, &id, peer.ip(), expect).map(|s| (s.id, s.identity.clone()));
        let (pid, text) = match checked {
            Ok(v) => v,
            Err((r, text)) => {
                let text = text.unwrap_or_else(|| identity_text(&id, None));
                let _ = self.write_msg(&mut conn, &mut sock, &Msg::HelloAck(Some(r)), deadline);
                stream::close(&mut conn, &mut sock, CLOSE_LIMIT);
                self.reject(peer, Some(&text), claimed, r);
                return;
            }
        };
        if let Err(r) = self.register(pid, ConnInfo { ip: peer.ip(), cert: id.sha256 }) {
            let _ = self.write_msg(&mut conn, &mut sock, &Msg::HelloAck(Some(r)), deadline);
            stream::close(&mut conn, &mut sock, CLOSE_LIMIT);
            self.reject(peer, Some(&text), claimed, r);
            return;
        }
        // From here the slot is ours; any exit unregisters it.
        let g = self.slots.get(usize::from(pid)).map_or(0, |s| s.gen_.load(Ordering::Acquire));
        let ack = self
            .write_msg(&mut conn, &mut sock, &Msg::HelloAck(None), deadline)
            .and_then(|()| read_msg(&mut conn, &mut sock, &mut rbuf, self.cfg.max_frame, deadline));
        match ack {
            Ok(Msg::HelloAck(None)) => {}
            Ok(Msg::HelloAck(Some(r))) => {
                tracing::warn!(peer = pid, reason = r.as_str(), "cluster peer refused this node");
                self.unregister(pid, g);
                return;
            }
            Ok(_) | Err(_) => {
                self.unregister(pid, g);
                return;
            }
        }
        pending.done();
        tracing::info!(peer = pid, addr = %peer, "cluster peer connected");
        if let Some(h) = self.inbound.get() {
            h.link(pid, true);
        }
        let end = self.conn_loop(&mut conn, &mut sock, pid, g, rbuf);
        self.unregister(pid, g);
        if let Some(h) = self.inbound.get() {
            h.link(pid, false);
        }
        match end {
            Err(Fail::Reject(r, _, _)) => {
                self.reject(peer, Some(&text), claimed, r);
            }
            Err(Fail::Closed(r)) => tracing::info!(peer = pid, "cluster peer disconnected: {r}"),
            Ok(()) => {}
        }
        if !self.killed.load(Ordering::Relaxed) {
            let _ = sock.set_nonblocking(false);
            stream::close(&mut conn, &mut sock, CLOSE_LIMIT);
        }
    }

    fn write_msg<C, D>(&self, conn: &mut C, sock: &mut TcpStream, m: &Msg, deadline: Instant) -> Result<(), Fail>
    where
        C: DerefMut<Target = ConnectionCommon<D>>,
        D: SideData,
    {
        let mut f = Vec::new();
        codec::encode(m, self.cfg.max_frame, &mut f).map_err(io_fail)?;
        stream::write_all(conn, sock, &f, deadline).map_err(io_fail)
    }

    /// The established connection: non-blocking reads and writes, control
    /// frames before data frames, keepalive and idle timeout.
    fn conn_loop<C, D>(
        &self,
        conn: &mut C,
        sock: &mut TcpStream,
        pid: MemberId,
        g: u64,
        mut rbuf: Vec<u8>,
    ) -> Result<(), Fail>
    where
        C: DerefMut<Target = ConnectionCommon<D>>,
        D: SideData,
    {
        let Some(slot) = self.slots.get(usize::from(pid)) else { return Ok(()) };
        sock.set_nonblocking(true).map_err(io_fail)?;
        let mut tmp = vec![0u8; 64 << 10];
        // Plaintext handed to TLS per turn (reused).
        let mut wbuf: Vec<u8> = Vec::with_capacity(WRITE_BUDGET + self.cfg.max_frame + HEADER_LEN);
        let (mut last_rx, mut last_tx) = (Instant::now(), Instant::now());
        let witness_link = self.cfg.i_am_witness || self.spec(pid).is_some_and(|s| s.witness);
        // Frames already received with the HelloAck.
        self.dispatch(pid, witness_link, &mut rbuf)?;
        loop {
            if !self.running() && !self.stop.load(Ordering::Relaxed) {
                return Err(Fail::Closed("killed".into()));
            }
            if self.stop.load(Ordering::Relaxed) || slot.gen_.load(Ordering::Acquire) != g {
                return Ok(());
            }
            let mut progressed = false;
            // Read what is there.
            let mut read = 0usize;
            loop {
                match conn.read_tls(sock) {
                    Ok(0) => return Err(Fail::Closed("eof".into())),
                    Ok(n) => {
                        read += n;
                        progressed = true;
                        last_rx = Instant::now();
                        if let Err(e) = conn.process_new_packets() {
                            return Err(Fail::Closed(format!("TLS: {e}")));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(io_fail(e)),
                }
                loop {
                    match conn.reader().read(&mut tmp) {
                        Ok(0) => return Err(Fail::Closed("close_notify".into())),
                        Ok(n) => rbuf.extend_from_slice(tmp.get(..n).unwrap_or_default()),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(io_fail(e)),
                    }
                }
                self.dispatch(pid, witness_link, &mut rbuf)?;
                if read >= WRITE_BUDGET {
                    break;
                }
            }
            // Write: refill TLS only when it has flushed everything; take
            // up to WRITE_BUDGET bytes of frames under one lock and hand
            // them to TLS in one write (what TLS does not take now, its
            // buffer being bounded, goes first next turn).
            if !conn.wants_write() {
                if wbuf.is_empty() {
                    let frames = slot.q.lock().drain_into(&mut wbuf, WRITE_BUDGET);
                    self.stats.frames_tx.fetch_add(frames as u64, Ordering::Relaxed);
                    if frames == 0 && last_tx.elapsed() >= self.cfg.keepalive {
                        let ka = Msg::Ack { slice: KEEPALIVE_SLICE, seq: 0 };
                        codec::encode(&ka, self.cfg.max_frame, &mut wbuf).map_err(io_fail)?;
                    }
                }
                if !wbuf.is_empty() {
                    let n = conn.writer().write(&wbuf).map_err(io_fail)?;
                    wbuf.drain(..n.min(wbuf.len()));
                }
            }
            while conn.wants_write() {
                match conn.write_tls(sock) {
                    Ok(_) => {
                        progressed = true;
                        last_tx = Instant::now();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(io_fail(e)),
                }
            }
            if last_rx.elapsed() >= self.cfg.idle_timeout {
                return Err(Fail::Closed("idle timeout".into()));
            }
            if !progressed {
                self.idle_wait(conn.wants_write(), !wbuf.is_empty(), sock, slot, last_rx, last_tx)?;
            }
        }
    }

    /// Blocks in poll(2) until the socket is readable (or writable while
    /// TLS holds unsent bytes), a frame is queued (waker), or the next
    /// keepalive or idle deadline. Returns at once when there is
    /// plaintext to hand to TLS and TLS is not blocked on the socket.
    fn idle_wait(
        &self,
        want_write: bool,
        pending: bool,
        sock: &TcpStream,
        slot: &Slot,
        last_rx: Instant,
        last_tx: Instant,
    ) -> Result<(), Fail> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        {
            let mut q = slot.q.lock();
            if !want_write && (pending || !q.is_empty()) {
                return Ok(());
            }
            q.sleeping = true;
        }
        let until = (last_tx + self.cfg.keepalive).min(last_rx + self.cfg.idle_timeout);
        let wait = until.saturating_duration_since(Instant::now()).clamp(Duration::from_millis(1), IDLE_WAIT);
        let ts = Timespec { tv_sec: wait.as_secs() as _, tv_nsec: i64::from(wait.subsec_nanos()) as _ };
        let sock_ev = if want_write { PollFlags::IN | PollFlags::OUT } else { PollFlags::IN };
        let mut fds = [PollFd::new(sock, sock_ev), PollFd::new(&slot.waker.rx, PollFlags::IN)];
        let r = poll(&mut fds, Some(&ts));
        slot.q.lock().sleeping = false;
        slot.waker.drain();
        match r {
            Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
            Err(e) => Err(io_fail(e)),
        }
    }

    /// Decodes and delivers every complete frame in `rbuf`. A decode error
    /// (unknown type, bad field) closes the connection and is audited.
    fn dispatch(&self, pid: MemberId, witness_link: bool, rbuf: &mut Vec<u8>) -> Result<(), Fail> {
        let mut off = 0;
        let res = loop {
            match codec::decode(rbuf.get(off..).unwrap_or_default(), self.cfg.max_frame) {
                Ok(Some((msg, used))) => {
                    off += used;
                    self.stats.frames_rx.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = self.deliver(pid, witness_link, msg) {
                        break Err(e);
                    }
                }
                Ok(None) => break Ok(()),
                Err(e) => {
                    let r = if matches!(e, codec::CodecError::UnknownType(_)) {
                        RejectReason::Version
                    } else {
                        RejectReason::Protocol
                    };
                    tracing::warn!(peer = pid, "cluster frame refused: {e}");
                    break Err(Fail::Reject(r, Some(pid), None));
                }
            }
        };
        rbuf.drain(..off.min(rbuf.len()));
        if rbuf.len() > self.cfg.max_frame + HEADER_LEN {
            return Err(Fail::Closed("oversize frame".into()));
        }
        res
    }

    fn deliver(&self, pid: MemberId, witness_link: bool, msg: Msg) -> Result<(), Fail> {
        let Some(h) = self.inbound.get() else { return Ok(()) };
        match msg {
            Msg::Hello(_) | Msg::HelloAck(_) => Err(Fail::Reject(RejectReason::Protocol, Some(pid), None)),
            Msg::Ack { slice: KEEPALIVE_SLICE, .. } => Ok(()),
            m if m.is_control() => {
                h.control(pid, m);
                Ok(())
            }
            // AC-3: the witness only votes; replication to or from it is
            // ignored.
            _ if witness_link => Ok(()),
            m => match h.data(pid, m) {
                Ok(()) => Ok(()),
                Err(r) if r.close => {
                    tracing::warn!(peer = pid, reason = r.reason.as_str(), "cluster replication refused: {}", r.detail);
                    Err(Fail::Reject(r.reason, Some(pid), None))
                }
                Err(r) => {
                    tracing::debug!(
                        peer = pid,
                        reason = r.reason.as_str(),
                        "cluster replication dropped: {}",
                        r.detail
                    );
                    self.reject_member(pid, r.reason);
                    Ok(())
                }
            },
        }
    }

    /// Audits a refusal of an authenticated member's input (configured
    /// address and identity; token bucket like every refusal).
    fn reject_member(&self, pid: MemberId, r: RejectReason) {
        let Some(spec) = self.spec(pid) else { return };
        self.reject(spec.addr, Some(&spec.identity), Some(pid), r);
    }
}

/// An inbound connection's pending-handshake claim, released once the
/// Hello exchange completed or the connection ended.
struct Pending<'a> {
    net: &'a Net,
    ip: Option<IpAddr>,
}

impl Pending<'_> {
    fn done(&mut self) {
        if let Some(ip) = self.ip.take() {
            self.net.release_pending(ip);
        }
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.done();
    }
}

/// Reads one message (blocking, before `deadline`), keeping extra bytes in
/// `rbuf`.
fn read_msg<C, D>(
    conn: &mut C,
    sock: &mut TcpStream,
    rbuf: &mut Vec<u8>,
    max_frame: usize,
    deadline: Instant,
) -> Result<Msg, Fail>
where
    C: DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
    let mut tmp = [0u8; 4096];
    loop {
        match codec::decode(rbuf, max_frame) {
            Ok(Some((m, used))) => {
                rbuf.drain(..used.min(rbuf.len()));
                return Ok(m);
            }
            Ok(None) => {}
            Err(e) => return Err(io_fail(e)),
        }
        let n = stream::read_until(conn, sock, &mut tmp, deadline, |_| true).map_err(io_fail)?;
        if n == 0 {
            return Err(Fail::Closed("eof during hello".into()));
        }
        rbuf.extend_from_slice(tmp.get(..n).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(tag: u8, len: usize) -> Vec<u8> {
        vec![tag; len]
    }

    /// PERF-003: one drain moves control frames first, then whole data
    /// batches, up to the budget, and recycles the emptied buffers.
    #[test]
    fn drain_takes_control_first_then_batches_up_to_budget() {
        let mut q = Queues::default();
        for (b, n) in [(frame(2, 100), 3usize), (frame(3, 100), 2), (frame(4, 100), 1)] {
            q.data_bytes += b.len();
            q.data_frames += n;
            q.data.push_back((b, n));
        }
        q.ctrl_bytes += 10;
        q.ctrl.push_back(frame(1, 10));
        let mut out = Vec::new();
        assert_eq!(q.drain_into(&mut out, 150), 1 + 3 + 2);
        assert_eq!(out.len(), 210);
        assert_eq!((out[0], out[10], out[110]), (1, 2, 3));
        assert_eq!((q.data_bytes, q.data_frames, q.ctrl_bytes), (100, 1, 0));
        assert_eq!(q.spare.len(), 3);
        assert!(q.spare.iter().all(Vec::is_empty));
        out.clear();
        assert_eq!(q.drain_into(&mut out, 1000), 1);
        assert!(q.is_empty());
    }
}
