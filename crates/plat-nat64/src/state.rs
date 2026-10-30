//! BIB, session and subscriber tables (RFC 6146 §3.1–3.5) and the expiry
//! sweeper.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ahash::RandomState;
use crossbeam_utils::CachePadded;
use parking_lot::MutexGuard;
use plat_audit::{
    AcquireReason, AuditSink, BlockAdopt, BlockReleaseReason, Event, LimitKind, SliceAcquire, SliceCidr, TryEmit,
};
use plat_cluster::{MemberId, SliceId, SliceMap, SnapRecord, WireBib, WireBlock};
use plat_common::config::{AuditMode, Config, Filtering, OverflowPolicy, SteeringMode};
use plat_common::{Clock, Counter, Counters, DropReason, Ipv6Cidr};
use plat_packet::proto;

use crate::pool::{AllocFail, BlockRef, Pool, SliceState};
use crate::repl::{AdoptInput, Directory, ReplProducer, ReplRecord};
use crate::shard::{Map, Sharded};
use crate::tcp::{self, Side, TcpState, Timer};

/// An empty port block is kept this long before returning to the pool, so
/// short-lived flows do not churn allocate/release records.
pub const BLOCK_LINGER_MS: u64 = 60_000;
/// An empty BIB is kept for at least this long (avoids racing a session insert).
pub const BIB_GRACE_MS: u64 = 2_000;

/// IPv6 transport address. `proto` uses IPv4 numbering (6, 17, 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key6 {
    pub proto: u8,
    pub addr: u128,
    pub port: u16,
}

/// IPv4 transport address in the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key4 {
    pub proto: u8,
    pub addr: u32,
    pub port: u16,
}

/// The IPv4 side of a BIB as `bib6` stores it. The pool index rides along
/// so the HA outbound ownership check is one `AtomicU8` load, without a
/// second pool lookup (PERF-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapped {
    pub k4: Key4,
    /// Pool index of `k4.addr`.
    pub idx: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Session {
    pub expires_ms: u64,
    pub tcp: Option<TcpState>,
}

#[derive(Debug)]
pub struct Bib {
    pub k6: Key6,
    pub sub: u128,
    pub created_wall_us: u64,
    /// Adopted on takeover: kept without sessions until then, and (TCP) a
    /// non-SYN outbound segment may create a session before then. 0 for
    /// every BIB created locally.
    pub adopt_until_ms: u64,
    empty_since: Option<u64>,
    sub_sessions: Arc<AtomicU32>,
    /// Keyed by remote IPv4 (address, port); port 0 for ICMP.
    pub sessions: Map<(u32, u16), Session>,
    /// Number of sessions per remote IPv4 address, so address-dependent
    /// filtering is one hash lookup instead of a scan of `sessions`.
    /// Present only under address-dependent filtering (PERF-102).
    remotes: Option<Box<Map<u32, u32>>>,
}

impl Bib {
    fn insert_session(&mut self, remote: (u32, u16), s: Session) {
        self.sessions.insert(remote, s);
        if let Some(r) = self.remotes.as_mut() {
            *r.entry(remote.0).or_insert(0) += 1;
        }
        self.empty_since = None;
    }

    /// Has this BIB a session with any port of `addr`? (ADF index; an
    /// expired session counts until the sweeper removes it.)
    fn has_remote(&self, addr: u32) -> bool {
        self.remotes.as_ref().is_some_and(|r| r.contains_key(&addr))
    }
}

/// Decrements the ADF index entry for `addr`.
fn forget_remote(remotes: &mut Option<Box<Map<u32, u32>>>, addr: u32) {
    if let Some(r) = remotes.as_mut()
        && let Some(n) = r.get_mut(&addr)
    {
        *n -= 1;
        if *n == 0 {
            r.remove(&addr);
        }
    }
}

#[derive(Debug)]
struct Block {
    r: BlockRef,
    wall_us: u64,
    /// One bitmap per protocol (TCP, UDP, ICMP).
    used: [Box<[u64]>; 3],
    in_use: u32,
    empty_since: Option<u64>,
    /// The release record was abandoned on a disconnected audit sink and
    /// already counted as lost; later retries do not count it again
    /// (NIST-401).
    loss_counted: bool,
}

#[inline]
fn proto_idx(p: u8) -> usize {
    match p {
        proto::TCP => 0,
        proto::UDP => 1,
        _ => 2,
    }
}

impl Block {
    fn new(r: BlockRef, size: u16, wall_us: u64, now: u64) -> Self {
        let words = usize::from(size).div_ceil(64);
        let mk = || vec![0u64; words].into_boxed_slice();
        Self { r, wall_us, used: [mk(), mk(), mk()], in_use: 0, empty_since: Some(now), loss_counted: false }
    }

    /// Marks port offset `off` used (an adopted BIB). False if out of range
    /// or already used.
    fn mark(&mut self, pi: usize, off: u16) -> bool {
        let (w, b) = (usize::from(off) / 64, usize::from(off) % 64);
        match self.used.get_mut(pi).and_then(|m| m.get_mut(w)) {
            Some(word) if *word & (1 << b) == 0 => {
                *word |= 1 << b;
                self.in_use += 1;
                self.empty_since = None;
                true
            }
            _ => false,
        }
    }

    /// Allocates a random free port offset (RFC 6056 style randomisation
    /// within the block): a random word, then a random free bit in it.
    fn alloc(&mut self, pi: usize, rng: &mut u64, size: u16) -> Option<u16> {
        let map = &mut self.used[pi];
        let words = map.len();
        *rng ^= *rng << 13;
        *rng ^= *rng >> 7;
        *rng ^= *rng << 17;
        let start = (*rng % words as u64) as usize;
        for i in 0..words {
            let w = (start + i) % words;
            let valid =
                if (w + 1) * 64 <= usize::from(size) { u64::MAX } else { (1u64 << (usize::from(size) % 64)) - 1 };
            let free = !map[w] & valid;
            if free != 0 {
                // Select the r-th free bit (r uniform over the free bits).
                let mut f = free;
                for _ in 0..((*rng >> 32) as u32 % free.count_ones()) {
                    f &= f - 1;
                }
                let bit = f.trailing_zeros() as usize;
                map[w] |= 1 << bit;
                self.in_use += 1;
                self.empty_since = None;
                return Some((w * 64 + bit) as u16);
            }
        }
        None
    }

    fn free(&mut self, pi: usize, off: u16, now: u64) {
        let (w, b) = (usize::from(off) / 64, usize::from(off) % 64);
        if let Some(word) = self.used[pi].get_mut(w)
            && *word & (1 << b) != 0
        {
            *word &= !(1 << b);
            self.in_use -= 1;
            if self.in_use == 0 {
                self.empty_since = Some(now);
            }
        }
    }
}

#[derive(Debug)]
struct Subscriber {
    blocks: Vec<Block>,
    sessions: Arc<AtomicU32>,
    rng: u64,
}

#[derive(Debug, Clone, Copy)]
struct TimeoutsMs {
    udp: u64,
    tcp_est: u64,
    tcp_trans: u64,
    icmp: u64,
}

/// Results of one sweeper pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    pub sessions_expired: u64,
    pub bibs_removed: u64,
    pub blocks_released: u64,
    /// Empty blocks kept for another pass because their release record
    /// could not be queued (not counted as lost audit records).
    pub releases_deferred: u64,
}

/// Cluster (sliced pool) settings of the engine.
#[derive(Debug, Clone)]
pub struct ClusterSetup {
    pub slices: SliceMap,
    /// This node's member id (`node.id`).
    pub self_id: MemberId,
    pub steering: SteeringMode,
    /// Shared with the replicator, which applies peers' `SubHome`/`SubGone`.
    pub directory: Arc<Directory>,
    /// `cluster.ha.tcp_adopt_secs` (0 disables the TCP pickup window).
    pub tcp_adopt_secs: u32,
    /// `cluster.ha.takeover_quarantine_secs`.
    pub quarantine_secs: u32,
    /// `cluster.ha.reserve_ahead_blocks`.
    pub reserve_ahead: u16,
}

impl ClusterSetup {
    /// Settings from a validated config with `cluster.partition = "slices"`.
    pub fn from_config(cfg: &Config) -> Result<Self, String> {
        if let Some(h) = cfg.cluster.ha_active() {
            let workers = match cfg.dataplane.workers {
                0 => std::thread::available_parallelism().map_or(1, usize::from),
                n => n,
            };
            check_ring_memory(workers, h.repl_ring_entries)?;
        }
        let slices = SliceMap::new(&cfg.nat64.pool, cfg.cluster.slice_prefix_len).map_err(|e| e.to_string())?;
        let ha = cfg.cluster.ha_active();
        Ok(Self {
            slices,
            self_id: cfg.node.id,
            steering: cfg.cluster.steering_mode(),
            directory: Arc::new(Directory::new(cfg.nat64.table_shards, cfg.nat64.max_subscribers)),
            tcp_adopt_secs: ha.map_or(0, |h| h.tcp_adopt_secs),
            quarantine_secs: ha.map_or(600, |h| h.takeover_quarantine_secs),
            reserve_ahead: ha.map_or(8, |h| h.reserve_ahead_blocks),
        })
    }
}

/// Upper bound on the replication rings' total memory.
pub const MAX_REPL_RING_BYTES: u64 = 512 << 20;

/// Replication ring memory is `(workers + 1) × entries × 64 B` (one ring
/// per worker plus the sweeper's), preallocated at start.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - the preallocated ring memory is capped
///   (PERF-004), so a large `repl_ring_entries` on a many-core host cannot
///   exhaust memory at start
pub fn check_ring_memory(workers: usize, entries: u32) -> Result<u64, String> {
    let bytes = (workers as u64 + 1)
        .saturating_mul(u64::from(entries).next_power_of_two())
        .saturating_mul(crate::repl::REPL_SLOT_BYTES);
    if bytes > MAX_REPL_RING_BYTES {
        return Err(format!(
            "cluster.ha.repl_ring_entries: ({workers} workers + 1) x {entries} entries x 64 B = {bytes} B \
             exceeds the {MAX_REPL_RING_BYTES} B ring memory cap"
        ));
    }
    Ok(bytes)
}

#[derive(Debug)]
struct ClusterCtx {
    self_id: MemberId,
    slices: SliceMap,
    steering: SteeringMode,
    directory: Arc<Directory>,
    tcp_adopt_ms: u64,
    quarantine_ms: u64,
    /// Audit records already queued by an adoption that was refused part
    /// way (`AuditUnavailable`), per slice: a retry with the same epoch
    /// skips them, so each record is queued exactly once (NIST-004).
    /// Control thread only; at most one entry per slice (SC-5).
    adopt_log: parking_lot::Mutex<Map<SliceId, AdoptLog>>,
}

/// Progress of one adoption's audit records (see `ClusterCtx::adopt_log`).
#[derive(Debug)]
struct AdoptLog {
    epoch: u64,
    acquire: bool,
    blocks: std::collections::HashSet<BlockRef, RandomState>,
}

#[derive(Debug)]
pub struct State {
    pub bib6: Sharded<Key6, Mapped>,
    pub bib4: Sharded<Key4, Bib>,
    subs: Sharded<u128, Subscriber>,
    pub pool: Pool,
    sessions: CachePadded<AtomicU64>,
    /// Subscriber-table entries. Padded (PERF-101): it is written when a
    /// subscriber is created or removed and must not share a line with the
    /// read-mostly fields every packet uses (`bib6`, `sub_mask`, ...).
    sub_count: CachePadded<AtomicU64>,
    max_subs: u64,
    max_sessions: u64,
    max_sessions_per_sub: u32,
    max_blocks: u16,
    sub_mask: u128,
    sub_len: u8,
    paired: bool,
    filtering: Filtering,
    to: TimeoutsMs,
    audit: AuditSink,
    audit_mode: AuditMode,
    refuse_on_overflow: bool,
    limit_last: [AtomicU64; LIMIT_SLOTS],
    clock: Clock,
    /// Per-subscriber RNG seed source; padded for the same reason as
    /// `sub_count` (PERF-101).
    seed: CachePadded<AtomicU64>,
    /// One randomly keyed hasher shared by every per-BIB map (cloning is a
    /// copy; `RandomState::new()` per BIB would be wasted work).
    hasher: RandomState,
    /// Cumulative `SweepStats::releases_deferred` (SEC-302), exported to
    /// `/metrics`. Written by the sweeper only.
    releases_deferred: AtomicU64,
    /// `nat64.block_cooldown_secs` in ms.
    cooldown_ms: u64,
    /// Sliced-pool (HA) settings; `None` in legacy mode.
    cluster: Option<Box<ClusterCtx>>,
}

/// Rate-limit slots for `Limit` records, indexed by `LimitKind as usize`.
const LIMIT_SLOTS: usize = 8;

impl State {
    /// Legacy engine state over this node's `owned` addresses.
    pub fn new(cfg: &Config, owned: Vec<u32>, audit: AuditSink, clock: Clock) -> Self {
        let n = &cfg.nat64;
        let pool = Pool::new(owned, n.port_min, n.port_max, n.port_block_size);
        Self::build(cfg, pool, None, audit, clock)
    }

    /// Engine state over the whole sliced cluster pool; every slice starts
    /// [`SliceState::Inactive`].
    pub fn new_cluster(cfg: &Config, setup: ClusterSetup, audit: AuditSink, clock: Clock) -> Result<Self, String> {
        let n = &cfg.nat64;
        let pool = Pool::new_sliced(&setup.slices, n.port_min, n.port_max, n.port_block_size, setup.reserve_ahead)?;
        let ctx = ClusterCtx {
            self_id: setup.self_id,
            slices: setup.slices,
            steering: setup.steering,
            directory: setup.directory,
            tcp_adopt_ms: u64::from(setup.tcp_adopt_secs) * 1000,
            quarantine_ms: u64::from(setup.quarantine_secs) * 1000,
            adopt_log: parking_lot::Mutex::new(Map::with_hasher(RandomState::new())),
        };
        Ok(Self::build(cfg, pool, Some(Box::new(ctx)), audit, clock))
    }

    fn build(cfg: &Config, pool: Pool, cluster: Option<Box<ClusterCtx>>, audit: AuditSink, clock: Clock) -> Self {
        let n = &cfg.nat64;
        let t = &cfg.timeouts;
        let shards = n.table_shards;
        let cooldown_ms = u64::from(n.block_cooldown_secs) * 1000;
        Self {
            bib6: Sharded::new(shards),
            bib4: Sharded::new(shards),
            subs: Sharded::new(shards),
            pool: pool.with_cooldown(cooldown_ms),
            sessions: CachePadded::new(AtomicU64::new(0)),
            sub_count: CachePadded::new(AtomicU64::new(0)),
            max_subs: u64::from(n.max_subscribers),
            max_sessions: n.max_sessions,
            max_sessions_per_sub: n.max_sessions_per_subscriber,
            max_blocks: n.max_blocks_per_subscriber,
            sub_mask: Ipv6Cidr::mask_of(n.subscriber_prefix_len),
            sub_len: n.subscriber_prefix_len,
            paired: n.paired_pooling,
            filtering: n.filtering,
            to: TimeoutsMs {
                udp: u64::from(t.udp_secs) * 1000,
                tcp_est: u64::from(t.tcp_established_secs) * 1000,
                tcp_trans: u64::from(t.tcp_transitory_secs) * 1000,
                icmp: u64::from(t.icmp_secs) * 1000,
            },
            audit,
            audit_mode: cfg.audit.mode,
            refuse_on_overflow: cfg.audit.on_overflow == OverflowPolicy::RefuseNewBindings,
            limit_last: Default::default(),
            clock,
            // SEC-010: seed from the OS RNG (ahash runtime-rng), not the clock.
            seed: CachePadded::new(AtomicU64::new(RandomState::new().hash_one(Clock::wall_us()) | 1)),
            hasher: RandomState::new(),
            releases_deferred: AtomicU64::new(0),
            cooldown_ms,
            cluster,
        }
    }

    /// Coarse monotonic milliseconds (the engine's clock).
    #[inline]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Number of subscriber-table entries.
    pub fn subscriber_count(&self) -> u64 {
        self.sub_count.load(Ordering::Relaxed)
    }

    pub fn session_count(&self) -> u64 {
        self.sessions.load(Ordering::Relaxed)
    }

    pub fn audit(&self) -> &AuditSink {
        &self.audit
    }

    /// Emits a resource-limit record at most once per second per kind.
    /// Cold and out of line so the session fast path stays compact
    /// (PERF-001).
    #[cold]
    #[inline(never)]
    fn limit(&self, kind: LimitKind, sub: u128) {
        // Slots hold `now + 1`; 0 means "never emitted".
        let stamp = self.clock.now_ms() + 1;
        let Some(slot) = self.limit_last.get(kind as usize) else { return };
        let last = slot.load(Ordering::Relaxed);
        if (last == 0 || stamp.saturating_sub(last) >= 1000)
            && slot.compare_exchange(last, stamp, Ordering::Relaxed, Ordering::Relaxed).is_ok()
        {
            self.audit.emit(Event::Limit { ts_us: Clock::wall_us(), kind, sub, sub_len: self.sub_len });
        }
    }

    /// Queues a `port_block_alloc` record (once per block: cold, out of
    /// line, PERF-001). `false` if the queue refused it.
    #[cold]
    #[inline(never)]
    fn emit_port_block_alloc(&self, wall: u64, sub: u128, r: BlockRef, lo: u16, size: u16) -> bool {
        self.audit.emit(Event::PortBlockAlloc {
            ts_us: wall,
            sub,
            sub_len: self.sub_len,
            v4: self.pool.addr(r.addr_idx),
            port_lo: lo,
            port_hi: lo + (size - 1),
        })
    }

    /// Queues a `bib_create` record (session mode; new bindings only, out
    /// of line so the existing-session path stays compact, PERF-001).
    #[inline(never)]
    fn emit_bib_create(&self, wall: u64, k6: Key6, k4: Key4) -> bool {
        self.audit.emit(Event::BibCreate {
            ts_us: wall,
            proto: k6.proto,
            v6: k6.addr,
            v6_port: k6.port,
            v4: k4.addr,
            v4_port: k4.port,
        })
    }

    /// Queues a replication record (HA only; never blocks). The ring's
    /// tail is the pushed count (`ReplHub::pushed_total`), so no counter is
    /// written here.
    #[inline]
    fn repl(&self, repl: Option<&ReplProducer>, rec: ReplRecord) {
        if self.cluster.is_some()
            && let Some(tx) = repl
        {
            tx.push(rec);
        }
    }

    #[inline]
    fn wire_block(&self, r: BlockRef) -> WireBlock {
        WireBlock { addr: self.pool.addr(r.addr_idx), block: r.block }
    }

    /// Slice of a pool address (0 when not sliced; only used for records,
    /// which exist only when sliced).
    #[inline]
    fn slice_of_addr(&self, a: u32) -> SliceId {
        self.pool.index(a).and_then(|i| self.pool.slice_of_idx(i)).unwrap_or(0)
    }

    fn alloc_port(
        &self,
        s: &mut Subscriber,
        sub: u128,
        p: u8,
        counters: &Counters,
        repl: Option<&ReplProducer>,
    ) -> Result<(Key4, u32), DropReason> {
        let pi = proto_idx(p);
        let size = self.pool.block_size();
        let Subscriber { blocks, rng, .. } = s;
        for b in blocks.iter_mut() {
            // A block in a slice this node no longer serves is not used.
            if !self.pool.idx_active(b.r.addr_idx) {
                continue;
            }
            if let Some(off) = b.alloc(pi, rng, size) {
                let k4 = Key4 { proto: p, addr: self.pool.addr(b.r.addr_idx), port: self.pool.port_lo(b.r) + off };
                return Ok((k4, b.r.addr_idx));
            }
        }
        if blocks.len() >= usize::from(self.max_blocks) {
            self.limit(LimitKind::SubscriberBlocks, sub);
            return Err(DropReason::SubscriberLimit);
        }
        let prefer = blocks.iter().find(|b| self.pool.idx_active(b.r.addr_idx)).map(|b| b.r.addr_idx);
        let r = match self.pool.alloc_block(prefer, self.paired) {
            Ok(r) => r,
            Err(f) => {
                // COMPLIANCE MAPPING:
                // - NIST 800-53: AU-10, CP-10 - with an in-sync backup a block
                //   is handed out only after the backup acknowledged its
                //   reservation; none left is counted, never waited for
                // - NIST 800-53: SC-5, SI-4 - every refusal with free blocks
                //   left is counted by cause (B-8): reserve starvation, or
                //   the paired address (RFC 4787 REQ-2) exhausted
                match f {
                    AllocFail::Starved => counters.inc(Counter::ClusterReserveStarved),
                    AllocFail::PairedExhausted => counters.inc(Counter::PoolPairedExhausted),
                    AllocFail::Exhausted => {}
                }
                self.limit(LimitKind::PoolExhausted, sub);
                return Err(DropReason::PortExhausted);
            }
        };
        let wall = Clock::wall_us();
        let lo = self.pool.port_lo(r);
        // COMPLIANCE MAPPING:
        // - NIST 800-53: AU-12, AU-5 - attribution record precedes use; under
        //   refuse_new_bindings an unloggable block is never handed out.
        // - RFC 6888 REQ-12 / RFC 7422 §2 - port-block logging.
        if !self.emit_port_block_alloc(wall, sub, r, lo, size) && self.refuse_on_overflow {
            self.pool.unalloc(r);
            return Err(DropReason::AuditUnavailable);
        }
        if let Some(sl) = self.pool.slice_of_idx(r.addr_idx) {
            self.repl(repl, ReplRecord::BlockAlloc { slice: sl, sub, block: self.wire_block(r), wall_us: wall });
        }
        let mut b = Block::new(r, size, wall, self.clock.now_ms());
        let off = b.alloc(pi, rng, size).ok_or(DropReason::PortExhausted)?;
        blocks.push(b);
        Ok((Key4 { proto: p, addr: self.pool.addr(r.addr_idx), port: lo + off }, r.addr_idx))
    }

    /// Returns a port to its subscriber's block.
    fn free_port(&self, sub: u128, k4: Key4) {
        let Some(ai) = self.pool.index(k4.addr) else { return };
        let Some(r) = self.pool.block_of(ai, k4.port) else { return };
        let now = self.clock.now_ms();
        let mut g = self.subs.lock(&sub);
        if let Some(s) = g.get_mut(&sub)
            && let Some(b) = s.blocks.iter_mut().find(|b| b.r == r)
        {
            b.free(proto_idx(k4.proto), k4.port - self.pool.port_lo(r), now);
        }
    }

    /// Finds or creates the BIB entry for an outbound flow (RFC 6146
    /// §3.5.1.1, endpoint-independent mapping). With `create == false` a
    /// missing entry is `Err(TcpNoState)` and nothing is allocated (RFC 6146
    /// §3.5.2.2: only a SYN may create TCP state). With HA, new blocks,
    /// BIBs and subscribers are pushed to `repl`, which is only read on
    /// the (cold) create path (PERF-001). Returns the mapping with its pool
    /// index (PERF-002).
    #[inline]
    pub fn bib_for(
        &self,
        k6: Key6,
        create: bool,
        counters: &Counters,
        repl: &Option<ReplProducer>,
    ) -> Result<Mapped, DropReason> {
        let g6 = self.bib6.lock(&k6);
        if let Some(m) = g6.get(&k6) {
            return Ok(*m);
        }
        self.bib_create(g6, k6, create, counters, repl)
    }

    /// The miss path of [`State::bib_for`], out of line so the per-packet
    /// hit path stays small (the bib6 shard stays locked across).
    #[inline(never)]
    fn bib_create(
        &self,
        mut g6: MutexGuard<'_, Map<Key6, Mapped>>,
        k6: Key6,
        create: bool,
        counters: &Counters,
        repl: &Option<ReplProducer>,
    ) -> Result<Mapped, DropReason> {
        let repl = repl.as_ref();
        if !create {
            return Err(DropReason::TcpNoState);
        }
        if self.refuse_on_overflow && !self.audit.has_room() {
            return Err(DropReason::AuditUnavailable);
        }
        let sub = k6.addr & self.sub_mask;
        let (k4, ai, sub_sessions) = {
            let mut gs = self.subs.lock(&sub);
            let is_new = !gs.contains_key(&sub);
            if is_new && let Some(c) = &self.cluster {
                self.check_home(c, sub, counters)?;
            }
            if is_new {
                // POAM: POAM-013 no aggregate-prefix limit: one short client
                // prefix can fill the subscriber table up to max_subscribers.
                // COMPLIANCE MAPPING:
                // - NIST 800-53: SC-5 - bounded subscriber table; both
                //   rejections are read-only (PERF-101), so a flood of new
                //   subscribers against an exhausted pool or a full table
                //   writes no shared cache line and creates no entry.
                if self.pool.free_blocks() == 0 {
                    // B-2: blocks held back by the cluster (quarantine,
                    // reservations) are reserve starvation, not a pool
                    // that is too small (SI-4: the operator sees why).
                    if self.pool.cluster_starved() {
                        counters.inc(Counter::ClusterReserveStarved);
                    }
                    self.limit(LimitKind::PoolExhausted, sub);
                    return Err(DropReason::PortExhausted);
                }
                if self.sub_count.load(Ordering::Relaxed) >= self.max_subs {
                    self.limit(LimitKind::SubscriberTable, sub);
                    return Err(DropReason::SubscriberTableFull);
                }
                if self.sub_count.fetch_add(1, Ordering::Relaxed) >= self.max_subs {
                    self.sub_count.fetch_sub(1, Ordering::Relaxed);
                    self.limit(LimitKind::SubscriberTable, sub);
                    return Err(DropReason::SubscriberTableFull);
                }
            }
            let s = gs.entry(sub).or_insert_with(|| Subscriber {
                blocks: Vec::new(),
                sessions: Arc::new(AtomicU32::new(0)),
                rng: self.seed.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed) | 1,
            });
            match self.alloc_port(s, sub, k6.proto, counters, repl) {
                Ok((k4, ai)) => {
                    if is_new && let Some(slice) = self.pool.slice_of_idx(ai) {
                        self.repl(repl, ReplRecord::SubHome { sub, slice });
                    }
                    (k4, ai, s.sessions.clone())
                }
                Err(e) => {
                    // Never leave an empty subscriber entry behind (SC-5).
                    if is_new {
                        gs.remove(&sub);
                        self.sub_count.fetch_sub(1, Ordering::Relaxed);
                    }
                    return Err(e);
                }
            }
        };
        let wall = Clock::wall_us();
        if self.audit_mode == AuditMode::Session && !self.emit_bib_create(wall, k6, k4) && self.refuse_on_overflow {
            self.free_port(sub, k4);
            return Err(DropReason::AuditUnavailable);
        }
        self.bib4.lock(&k4).insert(
            k4,
            Bib {
                k6,
                sub,
                created_wall_us: wall,
                adopt_until_ms: 0,
                empty_since: None,
                sub_sessions,
                sessions: Map::with_hasher(self.hasher.clone()),
                remotes: (self.filtering == Filtering::AddressDependent)
                    .then(|| Box::new(Map::with_hasher(self.hasher.clone()))),
            },
        );
        g6.insert(k6, Mapped { k4, idx: ai });
        counters.inc(Counter::BibCreated);
        if let Some(slice) = self.pool.slice_of_idx(ai) {
            let bib = WireBib {
                sub,
                proto: k6.proto,
                v6: k6.addr,
                port6: k6.port,
                v4: k4.addr,
                port4: k4.port,
                created_wall_us: wall,
            };
            self.repl(repl, ReplRecord::BibCreate { slice, bib });
        }
        Ok(Mapped { k4, idx: ai })
    }

    /// Mis-steering check for a new subscriber (subscriber-create path
    /// only; one directory shard lock).
    ///
    /// Home (README "Subscriber home"): a subscriber is homed on every
    /// node that holds one of its port blocks; the home a node announces
    /// (`SubHome`, [`State::local_homes`]) is the slice of its first block
    /// in an Active slice. After takeover/failback a subscriber can hold
    /// blocks on both nodes and is then homed on both: each node
    /// translates with its own, separately attributed blocks (no block is
    /// ever on two nodes). Mis-steering is therefore only possible on a
    /// node holding none of its blocks, which is exactly when this check
    /// runs (`is_new`).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-10, SI-4 - a subscriber homed on another member is
    ///   counted (`cluster_steer_missteered`) and, in `drop` mode, refused
    ///   (`missteered`) so it is never attributed on two nodes at once
    #[cold]
    #[inline(never)]
    fn check_home(&self, c: &ClusterCtx, sub: u128, counters: &Counters) -> Result<(), DropReason> {
        match c.directory.home_of(sub) {
            Some(h) if h.node != c.self_id => {
                counters.inc(Counter::ClusterSteerMissteered);
                match c.steering {
                    SteeringMode::Count => Ok(()),
                    // `forward` is rejected by config validation (phase 2).
                    SteeringMode::Drop | SteeringMode::Forward => Err(DropReason::Missteered),
                }
            }
            _ => Ok(()),
        }
    }

    #[inline]
    fn timeout(&self, p: u8, t: Option<TcpState>) -> u64 {
        match (p, t) {
            (proto::TCP, Some(TcpState::Established | TcpState::V6FinRcv | TcpState::V4FinRcv)) => self.to.tcp_est,
            (proto::TCP, _) => self.to.tcp_trans,
            (proto::UDP, _) => self.to.udp,
            _ => self.to.icmp,
        }
    }

    fn admit_session(&self, bib: &Bib) -> Result<(), DropReason> {
        if self.sessions.fetch_add(1, Ordering::Relaxed) >= self.max_sessions {
            self.sessions.fetch_sub(1, Ordering::Relaxed);
            self.limit(LimitKind::GlobalSessions, bib.sub);
            return Err(DropReason::SessionLimit);
        }
        if bib.sub_sessions.fetch_add(1, Ordering::Relaxed) >= self.max_sessions_per_sub {
            bib.sub_sessions.fetch_sub(1, Ordering::Relaxed);
            self.sessions.fetch_sub(1, Ordering::Relaxed);
            self.limit(LimitKind::SubscriberSessions, bib.sub);
            return Err(DropReason::SubscriberLimit);
        }
        Ok(())
    }

    /// Refreshes a session. Stores only when a value changes: the coarse
    /// clock moves every 10 ms, so most packets leave the session's cache
    /// line clean instead of dirtying it on every packet.
    #[inline]
    fn refresh(&self, p: u8, s: &mut Session, side: Side, flags: u8, now: u64) {
        let timer = match s.tcp {
            Some(st) => {
                let (n, t) = tcp::step(st, side, flags);
                if n != st {
                    s.tcp = Some(n);
                }
                t
            }
            None => Timer::Established,
        };
        let expires = match timer {
            Timer::Keep => return,
            Timer::Transitory => now + self.to.tcp_trans,
            Timer::Established => now + self.timeout(p, s.tcp),
        };
        if s.expires_ms != expires {
            s.expires_ms = expires;
        }
    }

    /// Removes an expired session that the sweeper has not reached yet
    /// (RFC 6146 §3.5.4: a session ends when its lifetime expires).
    fn drop_expired(&self, bib: &mut Bib, remote: (u32, u16)) {
        if bib.sessions.remove(&remote).is_some() {
            forget_remote(&mut bib.remotes, remote.0);
            self.sessions.fetch_sub(1, Ordering::Relaxed);
            bib.sub_sessions.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Outbound (v6→v4) session update/creation. `Err(NoBinding)` means the
    /// BIB vanished concurrently; the caller retries once.
    pub fn outbound(&self, k4: Key4, remote: (u32, u16), flags: u8, counters: &Counters) -> Result<(), DropReason> {
        let now = self.clock.now_ms();
        let mut g = self.bib4.lock(&k4);
        let bib = g.get_mut(&k4).ok_or(DropReason::NoBinding)?;
        match bib.sessions.get_mut(&remote) {
            Some(s) if s.expires_ms > now => {
                self.refresh(k4.proto, s, Side::V6, flags, now);
                return Ok(());
            }
            Some(_) => self.drop_expired(bib, remote),
            None => {}
        }
        let (tcp, life) = if k4.proto == proto::TCP {
            match tcp::initial(Side::V6, flags) {
                Some(t) => (Some(t), self.timeout(k4.proto, Some(t))),
                // A picked-up session starts on the transitory timer.
                None => (Some(Self::pickup(bib, flags, now)?), self.to.tcp_trans),
            }
        } else {
            (None, self.timeout(k4.proto, None))
        };
        self.admit_session(bib)?;
        bib.insert_session(remote, Session { expires_ms: now + life, tcp });
        counters.inc(Counter::SessionCreated);
        Ok(())
    }

    /// A non-SYN outbound TCP segment without a session: only an adopted
    /// BIB inside its pickup window may create one (transitory until the
    /// IPv4 side answers), so a
    /// long-lived connection survives a takeover.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 6146 §3.5.2.2 - documented deviation: only a SYN creates TCP
    ///   state, except on a BIB adopted from a failed slice owner during
    ///   `cluster.ha.tcp_adopt_secs` (outbound only; RST never creates)
    /// - NIST 800-53: CP-10 - flow continuity across failover
    // POAM: POAM-028 RFC 6146 §3.5.2.2 deviation: on an adopted BIB a
    // non-SYN outbound TCP segment creates a session during the takeover
    // pickup window (sessions are not replicated, decision Q2). It runs on
    // the transitory timer (state Pickup, or V6 FIN RCV for a FIN) and
    // becomes ESTABLISHED only on a packet from the IPv4 side (RFC-002).
    #[cold]
    #[inline(never)]
    fn pickup(bib: &Bib, flags: u8, now: u64) -> Result<TcpState, DropReason> {
        if bib.adopt_until_ms > now && flags & tcp::RST == 0 {
            Ok(tcp::pickup(flags))
        } else {
            Err(DropReason::TcpNoState)
        }
    }

    /// Inbound (v4→v6) lookup with filtering (RFC 6146 §3.5.1.2, RFC 4787 §5).
    /// Returns the IPv6 transport address.
    pub fn inbound(&self, k4: Key4, remote: (u32, u16), flags: u8, counters: &Counters) -> Result<Key6, DropReason> {
        let now = self.clock.now_ms();
        let mut g = self.bib4.lock(&k4);
        let bib = g.get_mut(&k4).ok_or(DropReason::NoBinding)?;
        match bib.sessions.get_mut(&remote) {
            Some(s) if s.expires_ms > now => {
                self.refresh(k4.proto, s, Side::V4, flags, now);
                return Ok(bib.k6);
            }
            // RFC-102: an expired, not yet swept session neither passes the
            // filter nor is revived.
            Some(_) => self.drop_expired(bib, remote),
            None => {}
        }
        // COMPLIANCE MAPPING:
        // - NIST 800-53: SC-7, SC-7(5) - deny unsolicited inbound by default
        // - RFC 4787 REQ-8 / RFC 6146 §3.5.1.2 - address-dependent filtering
        let allowed = match self.filtering {
            Filtering::EndpointIndependent => true,
            Filtering::AddressDependent => bib.has_remote(remote.0),
            Filtering::AddressPortDependent => false,
        };
        if !allowed {
            // POAM: POAM-008 an unsolicited inbound TCP SYN is dropped, not
            // held 6 s for simultaneous open (RFC 6146 §3.5.2.2).
            return Err(DropReason::Filtered);
        }
        let tcp = if k4.proto == proto::TCP {
            Some(tcp::initial(Side::V4, flags).ok_or(DropReason::TcpNoState)?)
        } else {
            None
        };
        self.admit_session(bib)?;
        bib.insert_session(remote, Session { expires_ms: now + self.timeout(k4.proto, tcp), tcp });
        counters.inc(Counter::SessionCreated);
        Ok(bib.k6)
    }

    /// Read-only BIB lookup by pool address (for quoted packets in ICMP errors).
    pub fn lookup4(&self, k4: Key4) -> Option<Key6> {
        self.bib4.lock(&k4).get(&k4).map(|b| b.k6)
    }

    pub fn lookup6(&self, k6: Key6) -> Option<Key4> {
        self.bib6.lock(&k6).get(&k6).map(|m| m.k4)
    }

    /// BIB lookup by pool address that also requires a live session with
    /// `remote` (one `bib4` shard lock). `remote = None` checks the BIB only.
    /// Used to validate packets quoted in ICMP errors (RFC 6146 §3.5.3):
    /// `Err(NoBinding)` without a BIB, `Err(Filtered)` without the session.
    pub fn lookup4_session(&self, k4: Key4, remote: Option<(u32, u16)>) -> Result<Key6, DropReason> {
        let now = self.clock.now_ms();
        let g = self.bib4.lock(&k4);
        let bib = g.get(&k4).ok_or(DropReason::NoBinding)?;
        match remote {
            None => Ok(bib.k6),
            Some(r) => match bib.sessions.get(&r) {
                Some(s) if s.expires_ms > now => Ok(bib.k6),
                _ => Err(DropReason::Filtered),
            },
        }
    }

    /// Does BIB `k4` hold a live session with `remote`?
    pub fn has_session(&self, k4: Key4, remote: (u32, u16)) -> bool {
        self.lookup4_session(k4, Some(remote)).is_ok()
    }

    /// One incremental pass: expire sessions shard by shard, then remove
    /// empty BIBs, then release lingering empty blocks.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-10 (Network Disconnect) - idle sessions removed
    /// - RFC 6146 §3.5.4 - session and BIB lifetime
    // POAM: POAM-012 the sweeper walks every BIB under each shard lock on
    // every pass; no per-shard expiry hint or per-pass time budget yet.
    pub fn sweep(&self) -> SweepStats {
        self.sweep_with(None)
    }

    /// [`State::sweep`] that also replicates BIB deletions, block releases
    /// and subscriber removals through `repl` (the sweeper's own ring).
    pub fn sweep_with(&self, repl: Option<&ReplProducer>) -> SweepStats {
        let now = self.clock.now_ms();
        let mut st = SweepStats::default();
        self.pool.promote(now);
        let mut dead: Vec<(Key4, Key6)> = Vec::new();
        for i in 0..self.bib4.shard_count() {
            let mut g = self.bib4.lock_index(i);
            for (k4, bib) in g.iter_mut() {
                let before = bib.sessions.len();
                let Bib { sessions, remotes, .. } = bib;
                sessions.retain(|(addr, _), s| {
                    let keep = s.expires_ms > now;
                    if !keep {
                        forget_remote(remotes, *addr);
                    }
                    keep
                });
                let gone = (before - bib.sessions.len()) as u64;
                if gone > 0 {
                    self.sessions.fetch_sub(gone, Ordering::Relaxed);
                    bib.sub_sessions.fetch_sub(gone as u32, Ordering::Relaxed);
                    st.sessions_expired += gone;
                }
                if bib.sessions.is_empty() {
                    match bib.empty_since {
                        None => bib.empty_since = Some(now),
                        Some(t) if now.saturating_sub(t) >= BIB_GRACE_MS && bib.adopt_until_ms <= now => {
                            dead.push((*k4, bib.k6))
                        }
                        Some(_) => {}
                    }
                }
            }
        }

        for (k4, k6) in dead {
            let removed = {
                let mut g6 = self.bib6.lock(&k6);
                let mut g4 = self.bib4.lock(&k4);
                let still_dead = g4.get(&k4).is_some_and(|b| b.sessions.is_empty() && b.empty_since.is_some());
                if still_dead {
                    g6.remove(&k6);
                    g4.remove(&k4)
                } else {
                    None
                }
            };
            if let Some(bib) = removed {
                if self.audit_mode == AuditMode::Session {
                    let wall = Clock::wall_us();
                    self.audit.emit(Event::BibDelete {
                        ts_us: wall,
                        proto: k6.proto,
                        v6: k6.addr,
                        v6_port: k6.port,
                        v4: k4.addr,
                        v4_port: k4.port,
                        held_secs: (wall.saturating_sub(bib.created_wall_us) / 1_000_000) as u32,
                    });
                }
                self.free_port(bib.sub, k4);
                self.repl(
                    repl,
                    ReplRecord::BibDelete {
                        slice: self.slice_of_addr(k4.addr),
                        proto: k4.proto,
                        v4: k4.addr,
                        port4: k4.port,
                    },
                );
                st.bibs_removed += 1;
            }
        }

        for i in 0..self.subs.shard_count() {
            let mut g = self.subs.lock_index(i);
            g.retain(|sub, s| {
                s.blocks.retain_mut(|b| {
                    let release =
                        b.in_use == 0 && b.empty_since.is_some_and(|t| now.saturating_sub(t) >= BLOCK_LINGER_MS);
                    if !release {
                        return true;
                    }
                    let wall = Clock::wall_us();
                    let lo = self.pool.port_lo(b.r);
                    // COMPLIANCE MAPPING:
                    // - NIST 800-53: AU-12, AU-10 - a block returns to the pool
                    //   only after its release record is queued; otherwise it
                    //   stays with this subscriber and is retried next pass,
                    //   so attribution windows never overlap in the queued
                    //   record stream. A record lost after queuing (file
                    //   down, crash in the flush window) shows as a sequence
                    //   gap and `audit_output_failure` (AU-5).
                    // - NIST 800-53: AU-5, SI-4 - `try_emit`: a deferred
                    //   release is retried; a full queue is never counted as
                    //   lost (NIST-201), and a disconnected sink (logger
                    //   stopped) counts the abandoned record exactly once
                    //   per quarantined block (NIST-401).
                    let outcome = self.audit.try_emit(Event::PortBlockRelease {
                        ts_us: wall,
                        sub: *sub,
                        sub_len: self.sub_len,
                        v4: self.pool.addr(b.r.addr_idx),
                        port_lo: lo,
                        port_hi: lo + (self.pool.block_size() - 1),
                        held_secs: (wall.saturating_sub(b.wall_us) / 1_000_000) as u32,
                        reason: None,
                    });
                    match outcome {
                        TryEmit::Queued => {}
                        TryEmit::Full => {
                            st.releases_deferred += 1;
                            return true;
                        }
                        TryEmit::Disconnected => {
                            if !b.loss_counted {
                                b.loss_counted = true;
                                self.audit.count_lost();
                            }
                            st.releases_deferred += 1;
                            return true;
                        }
                    }
                    self.pool.release(b.r, now);
                    if let Some(slice) = self.pool.slice_of_idx(b.r.addr_idx) {
                        let block = self.wire_block(b.r);
                        self.repl(repl, ReplRecord::BlockRelease { slice, sub: *sub, block });
                    }
                    st.blocks_released += 1;
                    false
                });
                let keep = !s.blocks.is_empty() || s.sessions.load(Ordering::Relaxed) > 0;
                if !keep {
                    self.sub_count.fetch_sub(1, Ordering::Relaxed);
                    self.repl(repl, ReplRecord::SubGone { sub: *sub });
                }
                keep
            });
        }
        // PERF-302: skip the shared-line RMW on the common no-deferral pass.
        if st.releases_deferred != 0 {
            self.releases_deferred.fetch_add(st.releases_deferred, Ordering::Relaxed);
        }
        st
    }

    /// Port-block releases deferred since start because the release record
    /// could not be queued (cumulative over sweeper passes).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SI-4, AU-5 - makes a quarantine that drains the pool
    ///   visible as such (SEC-302)
    pub fn releases_deferred_total(&self) -> u64 {
        self.releases_deferred.load(Ordering::Relaxed)
    }
}

/// Resume point of [`State::export_slice`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportCursor {
    /// 0: port blocks (`subs`), 1: BIBs (`bib4`).
    phase: u8,
    shard: usize,
}

/// Context of a takeover, for the audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdoptMeta {
    pub epoch: u64,
    pub prev_owner: Option<MemberId>,
    pub reason: AcquireReason,
}

/// Result of [`State::adopt_slice`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AdoptStats {
    pub blocks_adopted: u32,
    pub bibs_adopted: u64,
    /// Held back for `takeover_quarantine_secs` (reserved but unseen,
    /// unknown with an incomplete shadow, or over a subscriber limit).
    pub blocks_held: u32,
    /// Finishing the previous owner's cool-down.
    pub blocks_cooling: u32,
    /// Replicated records that did not fit the slice or conflicted.
    pub rejected: u32,
    /// Stale local state of the slice released first.
    pub stale: ReleaseStats,
}

/// Why [`State::adopt_slice`] did not activate the slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptError {
    /// Legacy (unsliced) engine.
    NotSliced,
    /// Slice id out of range.
    BadSlice,
    /// The slice is already Active.
    Active,
    /// `refuse_new_bindings` and the audit queue cannot take every acquire
    /// and adopt record: the slice stays Adopting; retry later.
    AuditUnavailable,
}

/// Result of [`State::release_slice`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseStats {
    pub bibs_removed: u64,
    pub sessions_removed: u64,
    pub blocks_released: u64,
    pub subscribers_removed: u64,
}

/// Cluster control API (HA). Called by platd's control and replicator
/// threads, never by workers. Every method is a no-op (or empty) on a
/// legacy engine.
impl State {
    pub fn is_cluster(&self) -> bool {
        self.cluster.is_some()
    }

    pub fn slice_map(&self) -> Option<&SliceMap> {
        self.cluster.as_ref().map(|c| &c.slices)
    }

    pub fn directory(&self) -> Option<&Arc<Directory>> {
        self.cluster.as_ref().map(|c| &c.directory)
    }

    pub fn slice_state(&self, s: SliceId) -> Option<SliceState> {
        self.pool.slice_state(s)
    }

    /// Sets a slice's ownership state directly (e.g. re-activating a slice
    /// regained with an unbroken view chain). Use [`State::adopt_slice`]
    /// for a takeover and [`State::fence_slice`] to stop serving.
    pub fn set_slice_state(&self, s: SliceId, st: SliceState) -> Option<SliceState> {
        self.pool.set_slice_state(s, st)
    }

    /// Stops translating and allocating for slice `s` at once; state is
    /// kept. Returns the previous state.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-24 - lease lost: fail in a known state
    pub fn fence_slice(&self, s: SliceId) -> Option<SliceState> {
        self.pool.set_slice_state(s, SliceState::Fenced)
    }

    fn block_ref(&self, s: SliceId, w: WireBlock) -> Option<BlockRef> {
        let idx = self.pool.index(w.addr)?;
        (self.pool.slice_of_idx(idx) == Some(s) && w.block < self.pool.blocks_per_addr())
            .then_some(BlockRef { addr_idx: idx, block: w.block })
    }

    fn in_slice(&self, s: SliceId, a: u32) -> bool {
        self.pool.index(a).and_then(|i| self.pool.slice_of_idx(i)) == Some(s)
    }

    /// Local subscribers with the slice of their first block in an Active
    /// slice, from subscriber shard `shard` on, until `out` holds at least
    /// `max` entries. Returns the next shard to walk (`None`: done). Off
    /// the packet path: the replicator re-announces homes in chunks after
    /// a peer link comes up or a slice is acquired (B-9).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-10, SC-7 - peers relearn every home after a
    ///   restart or takeover, so a mis-steered subscriber is refused
    ///   (`missteered`) instead of being given a second home
    pub fn local_homes(&self, shard: usize, max: usize, out: &mut Vec<(u128, SliceId)>) -> Option<usize> {
        let mut i = shard;
        while i < self.subs.shard_count() {
            {
                let g = self.subs.lock_index(i);
                for (sub, sx) in g.iter() {
                    let first = sx.blocks.iter().find(|b| self.pool.idx_active(b.r.addr_idx));
                    if let Some(slice) = first.and_then(|b| self.pool.slice_of_idx(b.r.addr_idx)) {
                        out.push((*sub, slice));
                    }
                }
            }
            i += 1;
            if out.len() >= max {
                break;
            }
        }
        (i < self.subs.shard_count()).then_some(i)
    }

    /// Blocks to reserve with the backup (top-up to `reserve_ahead_blocks`);
    /// the replicator sends them as `Reserve` and calls
    /// [`State::reserve_acked`] on the backup's `Ack`.
    pub fn reserve_topup(&self, s: SliceId) -> Vec<WireBlock> {
        self.pool.reserve_take(s).into_iter().map(|r| self.wire_block(r)).collect()
    }

    pub fn reserve_acked(&self, s: SliceId, blocks: &[WireBlock]) -> usize {
        let refs: Vec<BlockRef> = blocks.iter().filter_map(|w| self.block_ref(s, *w)).collect();
        self.pool.reserve_confirm(s, &refs)
    }

    /// Drops every reservation of `s` (backup changed or lost).
    pub fn reserve_reset(&self, s: SliceId) {
        self.pool.reserve_reset(s)
    }

    pub fn reserve_deficit(&self, s: SliceId) -> usize {
        self.pool.reserve_deficit(s)
    }

    /// While `on`, slice `s` hands out only reserved blocks (set while an
    /// in-sync backup exists; clear when none does).
    pub fn set_reserve_required(&self, s: SliceId, on: bool) {
        self.pool.set_reserve_required(s, on)
    }

    /// Snapshot of slice `s` for a backup: port blocks, then BIBs. Walks
    /// whole shards (one lock at a time) until at least `budget` records
    /// are collected; returns the cursor to resume from, or `None` when
    /// done. Concurrent changes reach the backup through the rings, which
    /// it applies idempotently after the snapshot.
    pub fn export_slice(
        &self,
        s: SliceId,
        cursor: ExportCursor,
        budget: usize,
    ) -> (Vec<SnapRecord>, Option<ExportCursor>) {
        let mut out = Vec::new();
        let mut cur = cursor;
        if self.cluster.is_none() {
            return (out, None);
        }
        loop {
            if out.len() >= budget.max(1) {
                return (out, Some(cur));
            }
            match cur.phase {
                0 if cur.shard >= self.subs.shard_count() => cur = ExportCursor { phase: 1, shard: 0 },
                0 => {
                    let g = self.subs.lock_index(cur.shard);
                    for (sub, sx) in g.iter() {
                        for b in sx.blocks.iter().filter(|b| self.pool.slice_of_idx(b.r.addr_idx) == Some(s)) {
                            let block = self.wire_block(b.r);
                            out.push(SnapRecord::Block { sub: *sub, block, alloc_wall_us: b.wall_us });
                        }
                    }
                    cur.shard += 1;
                }
                1 if cur.shard < self.bib4.shard_count() => {
                    let g = self.bib4.lock_index(cur.shard);
                    for (k4, b) in g.iter().filter(|(k4, _)| self.in_slice(s, k4.addr)) {
                        out.push(SnapRecord::Bib(WireBib {
                            sub: b.sub,
                            proto: k4.proto,
                            v6: b.k6.addr,
                            port6: b.k6.port,
                            v4: k4.addr,
                            port4: k4.port,
                            created_wall_us: b.created_wall_us,
                        }));
                    }
                    cur.shard += 1;
                }
                _ => return (out, None),
            }
        }
    }

    /// Gives up slice `s`: fences it, removes its BIBs and sessions, and
    /// releases its port blocks (each with a `nat_port_block_release`
    /// record, `plat.release_reason = reason`), then frees the slice's
    /// blocks for whichever node owns it next.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-12, AU-10 - a handover ends every block's
    ///   attribution interval on this node with a release record
    ///   (POAM-009 closed for handover)
    pub fn release_slice(&self, s: SliceId, reason: Option<BlockReleaseReason>) -> ReleaseStats {
        let mut st = ReleaseStats::default();
        if self.cluster.is_none() || self.pool.slice_state(s).is_none() {
            return st;
        }
        if self.pool.slice_state(s) == Some(SliceState::Active) {
            self.pool.set_slice_state(s, SliceState::Fenced);
        }
        let mut dead: Vec<(Key4, Key6)> = Vec::new();
        for i in 0..self.bib4.shard_count() {
            let g = self.bib4.lock_index(i);
            dead.extend(g.iter().filter(|(k4, _)| self.in_slice(s, k4.addr)).map(|(k4, b)| (*k4, b.k6)));
        }
        for (k4, k6) in dead {
            let removed = {
                let mut g6 = self.bib6.lock(&k6);
                let mut g4 = self.bib4.lock(&k4);
                if g6.get(&k6).is_some_and(|m| m.k4 == k4) {
                    g6.remove(&k6);
                }
                g4.remove(&k4)
            };
            let Some(bib) = removed else { continue };
            let n = bib.sessions.len() as u64;
            self.sessions.fetch_sub(n, Ordering::Relaxed);
            bib.sub_sessions.fetch_sub(n as u32, Ordering::Relaxed);
            st.sessions_removed += n;
            st.bibs_removed += 1;
            if self.audit_mode == AuditMode::Session {
                let wall = Clock::wall_us();
                self.audit.emit(Event::BibDelete {
                    ts_us: wall,
                    proto: k6.proto,
                    v6: k6.addr,
                    v6_port: k6.port,
                    v4: k4.addr,
                    v4_port: k4.port,
                    held_secs: (wall.saturating_sub(bib.created_wall_us) / 1_000_000) as u32,
                });
            }
        }
        for i in 0..self.subs.shard_count() {
            let mut g = self.subs.lock_index(i);
            g.retain(|sub, sx| {
                sx.blocks.retain(|b| {
                    if self.pool.slice_of_idx(b.r.addr_idx) != Some(s) {
                        return true;
                    }
                    let wall = Clock::wall_us();
                    let lo = self.pool.port_lo(b.r);
                    self.audit.emit(Event::PortBlockRelease {
                        ts_us: wall,
                        sub: *sub,
                        sub_len: self.sub_len,
                        v4: self.pool.addr(b.r.addr_idx),
                        port_lo: lo,
                        port_hi: lo + (self.pool.block_size() - 1),
                        held_secs: (wall.saturating_sub(b.wall_us) / 1_000_000) as u32,
                        reason,
                    });
                    st.blocks_released += 1;
                    false
                });
                let keep = !sx.blocks.is_empty() || sx.sessions.load(Ordering::Relaxed) > 0;
                if !keep {
                    self.sub_count.fetch_sub(1, Ordering::Relaxed);
                    st.subscribers_removed += 1;
                }
                keep
            });
        }
        self.pool.reset_slice(s, &[], &[], &[]);
        st
    }

    /// Takes over slice `s` from replicated state: queues
    /// `cluster_slice_acquire` and one `nat_port_block_adopt` per adopted
    /// block, imports the blocks and BIBs (no sessions), holds back blocks
    /// whose fate is unknown, and only then sets the slice Active.
    ///
    /// Blocks reserved with the backup but never seen allocated, blocks
    /// over a subscriber limit, and (with `hold_unknown`) every block not
    /// adopted are held for `takeover_quarantine_secs`; blocks the previous
    /// owner released recently finish their cool-down. Imported BIBs are
    /// kept without sessions until `adopt_until_ms` (TCP: the pickup
    /// window; UDP/ICMP: one idle timeout).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-12, AU-5 - takeover is logged before use: the slice
    ///   is not Active until every record is queued; under
    ///   `refuse_new_bindings` an audit queue without room for all of them
    ///   leaves the slice Adopting (`AdoptError::AuditUnavailable`, retry)
    /// - NIST 800-53: AU-10, CP-10 - attribution continuity: the same
    ///   subscriber keeps the same blocks and mappings
    /// - RFC 6146 §3.5.1.1 - endpoint-independent mapping kept across takeover
    /// - RFC 7422 §2, RFC 6888 REQ-12 - no block of unknown attribution is
    ///   reused before the hold-back ends
    pub fn adopt_slice(&self, s: SliceId, input: &AdoptInput, meta: AdoptMeta) -> Result<AdoptStats, AdoptError> {
        let Some(c) = &self.cluster else { return Err(AdoptError::NotSliced) };
        let state = self.pool.slice_state(s).ok_or(AdoptError::BadSlice)?;
        if state == SliceState::Active {
            return Err(AdoptError::Active);
        }
        let cidr = c.slices.cidr(s).ok_or(AdoptError::BadSlice)?;
        self.pool.set_slice_state(s, SliceState::Adopting);
        let mut st = AdoptStats { stale: self.release_slice(s, None), ..AdoptStats::default() };
        let now = self.clock.now_ms();

        // Plan: validate everything before any record is queued.
        let mut owner: Map<BlockRef, (u128, u64)> = Map::with_hasher(self.hasher.clone());
        for &(sub, w, wall) in &input.blocks {
            match self.block_ref(s, w) {
                Some(r) if sub & self.sub_mask == sub && !owner.contains_key(&r) => {
                    owner.insert(r, (sub, wall));
                }
                _ => st.rejected += 1,
            }
        }
        let mut held: Vec<(u64, BlockRef)> = Vec::new();
        let hold_until = now + c.quarantine_ms;
        // Per-subscriber block limit and subscriber-table bound (SC-5).
        let mut per_sub: Map<u128, Vec<BlockRef>> = Map::with_hasher(self.hasher.clone());
        let mut refs: Vec<BlockRef> = owner.keys().copied().collect();
        refs.sort_unstable_by_key(|r| (r.addr_idx, r.block));
        for r in refs {
            if let Some(&(sub, _)) = owner.get(&r) {
                per_sub.entry(sub).or_default().push(r);
            }
        }
        let mut new_subs = 0u64;
        for (sub, blocks) in per_sub.iter_mut() {
            let (have, exists) = {
                let g = self.subs.lock(sub);
                g.get(sub).map_or((0, false), |x| (x.blocks.len(), true))
            };
            let room = if exists || self.sub_count.load(Ordering::Relaxed) + new_subs < self.max_subs {
                usize::from(self.max_blocks).saturating_sub(have)
            } else {
                0
            };
            new_subs += u64::from(!exists && room > 0);
            for r in blocks.drain(room.min(blocks.len())..) {
                owner.remove(&r);
                held.push((hold_until, r));
            }
        }
        let mut bibs: Vec<(Key6, Key4, &WireBib)> = Vec::new();
        let mut seen6: Map<Key6, ()> = Map::with_hasher(self.hasher.clone());
        let mut seen4: Map<Key4, ()> = Map::with_hasher(self.hasher.clone());
        for b in &input.bibs {
            let k6 = Key6 { proto: b.proto, addr: b.v6, port: b.port6 };
            let k4 = Key4 { proto: b.proto, addr: b.v4, port: b.port4 };
            let ok = matches!(b.proto, proto::TCP | proto::UDP | proto::ICMP)
                && b.v6 & self.sub_mask == b.sub
                && self.pool.index(b.v4).and_then(|i| self.pool.block_of(i, b.port4)).is_some_and(|r| {
                    self.pool.slice_of_idx(r.addr_idx) == Some(s) && owner.get(&r).is_some_and(|o| o.0 == b.sub)
                })
                && seen6.insert(k6, ()).is_none()
                && seen4.insert(k4, ()).is_none();
            if ok {
                bibs.push((k6, k4, b));
            } else {
                st.rejected += 1;
            }
        }
        for w in &input.reserved_unseen {
            if let Some(r) = self.block_ref(s, *w)
                && !owner.contains_key(&r)
            {
                held.push((hold_until, r));
            }
        }
        let mut cooling: Vec<(u64, BlockRef)> = Vec::new();
        for &(w, age) in &input.released {
            if let Some(r) = self.block_ref(s, w)
                && !owner.contains_key(&r)
            {
                cooling.push((now + self.cooldown_ms.saturating_sub(age), r));
            }
        }
        if input.hold_unknown
            && let Some((lo, hi)) = self.pool.slice_range(s)
        {
            let mut known: std::collections::HashSet<BlockRef, RandomState> =
                std::collections::HashSet::with_hasher(self.hasher.clone());
            known.extend(owner.keys().copied());
            known.extend(held.iter().map(|h| h.1));
            known.extend(cooling.iter().map(|h| h.1));
            for idx in lo..hi {
                for block in 0..self.pool.blocks_per_addr() {
                    let r = BlockRef { addr_idx: idx, block };
                    if !known.contains(&r) {
                        held.push((hold_until, r));
                    }
                }
            }
        }
        st.blocks_adopted = owner.len() as u32;
        st.bibs_adopted = bibs.len() as u64;
        st.blocks_held = held.len() as u32;
        st.blocks_cooling = cooling.len() as u32;

        // Log before use. A retry of a partly logged adoption (same epoch)
        // skips the records already queued; another epoch starts afresh.
        let mut logs = c.adopt_log.lock();
        let log = logs.entry(s).or_insert_with(|| AdoptLog {
            epoch: meta.epoch,
            acquire: false,
            blocks: std::collections::HashSet::with_hasher(RandomState::new()),
        });
        if log.epoch != meta.epoch {
            *log = AdoptLog {
                epoch: meta.epoch,
                acquire: false,
                blocks: std::collections::HashSet::with_hasher(RandomState::new()),
            };
        }
        let todo = owner.keys().filter(|r| !log.blocks.contains(*r)).count() + usize::from(!log.acquire);
        if self.refuse_on_overflow
            && (!self.audit.has_room() || self.audit.capacity().saturating_sub(self.audit.queued()) < todo)
        {
            return Err(AdoptError::AuditUnavailable);
        }
        let wall = Clock::wall_us();
        let acquire = SliceAcquire {
            slice: SliceCidr { net: cidr.network(), len: cidr.prefix_len() },
            epoch: meta.epoch,
            prev_owner: meta.prev_owner,
            reason: meta.reason,
            blocks_adopted: st.blocks_adopted,
            bibs_adopted: st.bibs_adopted,
            blocks_quarantined: st.blocks_held,
            in_sync: input.in_sync,
        };
        if !log.acquire {
            if !self.adopt_emit(Event::ClusterSliceAcquire { ts_us: wall, acquire: Arc::new(acquire) }) {
                return Err(AdoptError::AuditUnavailable);
            }
            log.acquire = true;
        }
        let size = self.pool.block_size();
        let mut adopted: Vec<(BlockRef, u128, u64)> = owner.iter().map(|(r, &(sub, w))| (*r, sub, w)).collect();
        adopted.sort_unstable_by_key(|a| (a.0.addr_idx, a.0.block));
        for &(r, sub, alloc_wall) in &adopted {
            if log.blocks.contains(&r) {
                continue;
            }
            let lo = self.pool.port_lo(r);
            let rec = BlockAdopt {
                sub,
                sub_len: self.sub_len,
                v4: self.pool.addr(r.addr_idx),
                port_lo: lo,
                port_hi: lo + (size - 1),
                allocated_us: alloc_wall,
                prev_owner: meta.prev_owner,
                epoch: meta.epoch,
            };
            if !self.adopt_emit(Event::PortBlockAdopt { ts_us: wall, adopt: Arc::new(rec) }) {
                return Err(AdoptError::AuditUnavailable);
            }
            log.blocks.insert(r);
        }
        // Every record is queued: the next adoption of `s` logs afresh.
        logs.remove(&s);
        drop(logs);

        // Import (the slice is not Active: no worker allocates in it).
        let mut in_use: Vec<BlockRef> = Vec::with_capacity(adopted.len());
        let mut sessions_of: Map<u128, Arc<AtomicU32>> = Map::with_hasher(self.hasher.clone());
        for &(r, sub, alloc_wall) in &adopted {
            let mut g = self.subs.lock(&sub);
            let sx = match g.entry(sub) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    if self.sub_count.fetch_add(1, Ordering::Relaxed) >= self.max_subs {
                        // Raced with new subscribers: the record is queued
                        // but the block cannot be served here; hold it back.
                        self.sub_count.fetch_sub(1, Ordering::Relaxed);
                        held.push((hold_until, r));
                        continue;
                    }
                    e.insert(Subscriber {
                        blocks: Vec::new(),
                        sessions: Arc::new(AtomicU32::new(0)),
                        rng: self.seed.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed) | 1,
                    })
                }
            };
            sx.blocks.push(Block::new(r, size, alloc_wall, now));
            sessions_of.insert(sub, sx.sessions.clone());
            in_use.push(r);
        }
        for (k6, k4, b) in bibs {
            let Some(sub_sessions) = sessions_of.get(&b.sub).cloned() else { continue };
            let Some(idx) = self.pool.index(k4.addr) else { continue };
            let until = now + if k4.proto == proto::TCP { c.tcp_adopt_ms } else { self.timeout(k4.proto, None) };
            let inserted = {
                let mut g6 = self.bib6.lock(&k6);
                let mut g4 = self.bib4.lock(&k4);
                if g6.contains_key(&k6) || g4.contains_key(&k4) {
                    false
                } else {
                    g4.insert(
                        k4,
                        Bib {
                            k6,
                            sub: b.sub,
                            created_wall_us: b.created_wall_us,
                            adopt_until_ms: until,
                            empty_since: None,
                            sub_sessions,
                            sessions: Map::with_hasher(self.hasher.clone()),
                            remotes: (self.filtering == Filtering::AddressDependent)
                                .then(|| Box::new(Map::with_hasher(self.hasher.clone()))),
                        },
                    );
                    g6.insert(k6, Mapped { k4, idx });
                    true
                }
            };
            if !inserted {
                st.bibs_adopted -= 1;
                st.rejected += 1;
                continue;
            }
            let Some(ai) = self.pool.index(k4.addr) else { continue };
            let Some(r) = self.pool.block_of(ai, k4.port) else { continue };
            let mut g = self.subs.lock(&b.sub);
            if let Some(blk) = g.get_mut(&b.sub).and_then(|sx| sx.blocks.iter_mut().find(|x| x.r == r)) {
                blk.mark(proto_idx(k4.proto), k4.port - self.pool.port_lo(r));
            }
        }
        self.pool.reset_slice(s, &in_use, &held, &cooling);
        self.pool.set_slice_state(s, SliceState::Active);
        Ok(st)
    }

    /// Queues one adoption record. Under `refuse_new_bindings` a full
    /// queue is retryable (`try_emit`, not counted as lost) and refuses the
    /// adoption; otherwise the record is emitted (lost and counted when
    /// full) and adoption goes on.
    fn adopt_emit(&self, ev: Event) -> bool {
        if !self.refuse_on_overflow {
            self.audit.emit(ev);
            return true;
        }
        match self.audit.try_emit(ev) {
            TryEmit::Queued => true,
            TryEmit::Full => false,
            TryEmit::Disconnected => {
                self.audit.count_lost();
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster_state() -> (State, crossbeam_channel::Receiver<Event>) {
        let t = include_str!("../../../config/platd.example.toml")
            .replace("192.0.2.0/24", "192.0.2.0/30")
            .replace("allow_non_global_destinations = false", "allow_non_global_destinations = true");
        let cfg = Config::from_toml(&t).unwrap();
        let setup = ClusterSetup {
            slices: SliceMap::new(&cfg.nat64.pool, 32).unwrap(),
            self_id: 1,
            steering: SteeringMode::Drop,
            directory: Arc::new(Directory::new(16, 1000)),
            tcp_adopt_secs: 300,
            quarantine_secs: 600,
            reserve_ahead: 2,
        };
        let (sink, rx) = AuditSink::bounded(64);
        (State::new_cluster(&cfg, setup, sink, Clock::new()).unwrap(), rx)
    }

    fn input() -> AdoptInput {
        let sub = 0x2001_0db8_0000_0001_u128 << 64;
        AdoptInput {
            blocks: (0..3).map(|b| (sub, WireBlock { addr: 0xc000_0200, block: b }, 1)).collect(),
            in_sync: true,
            ..AdoptInput::default()
        }
    }

    fn seed(st: &State, epoch: u64, acquire: bool, blocks: &[u16]) {
        let c = st.cluster.as_ref().unwrap();
        let mut set = std::collections::HashSet::with_hasher(RandomState::new());
        set.extend(blocks.iter().map(|&b| BlockRef { addr_idx: 0, block: b }));
        c.adopt_log.lock().insert(0, AdoptLog { epoch, acquire, blocks: set });
    }

    fn meta(epoch: u64) -> AdoptMeta {
        AdoptMeta { epoch, prev_owner: Some(2), reason: AcquireReason::Takeover }
    }

    /// NIST-004: a retry after an adoption refused part way (the acquire
    /// and block 0 already queued) queues only the missing records.
    #[test]
    fn adopt_retry_queues_each_record_once() {
        let (st, rx) = cluster_state();
        seed(&st, 7, true, &[0]);
        let stats = st.adopt_slice(0, &input(), meta(7)).unwrap();
        assert_eq!(stats.blocks_adopted, 3);
        let evs: Vec<_> = rx.try_iter().collect();
        assert_eq!(evs.len(), 2, "{evs:?}");
        assert!(evs.iter().all(|e| matches!(e, Event::PortBlockAdopt { .. })));
        assert!(st.cluster.as_ref().unwrap().adopt_log.lock().is_empty(), "progress cleared on success");
        assert_eq!(st.slice_state(0), Some(SliceState::Active));
    }

    /// Progress of another epoch is discarded: a new adoption logs afresh.
    #[test]
    fn adopt_log_of_another_epoch_is_ignored() {
        let (st, rx) = cluster_state();
        seed(&st, 6, true, &[0, 1]);
        st.adopt_slice(0, &input(), meta(7)).unwrap();
        let evs: Vec<_> = rx.try_iter().collect();
        assert_eq!(evs.len(), 4);
        assert!(matches!(evs[0], Event::ClusterSliceAcquire { .. }));
    }

    /// A refused adoption records what it queued; the retry completes it
    /// with every record exactly once.
    #[test]
    fn refused_then_retried_adoption_logs_each_record_once() {
        let (st, rx) = cluster_state();
        // Fill the queue so only 2 slots are left: the room check refuses.
        for _ in 0..62 {
            assert!(st.audit.emit(Event::ClusterSliceAcquire {
                ts_us: 0,
                acquire: Arc::new(SliceAcquire {
                    slice: SliceCidr { net: 0, len: 32 },
                    epoch: 0,
                    prev_owner: None,
                    reason: AcquireReason::Startup,
                    blocks_adopted: 0,
                    bibs_adopted: 0,
                    blocks_quarantined: 0,
                    in_sync: true,
                }),
            }));
        }
        assert_eq!(st.adopt_slice(0, &input(), meta(7)), Err(AdoptError::AuditUnavailable));
        assert_eq!(rx.try_iter().count(), 62, "nothing of the adoption queued");
        // Simulate the race the room check cannot close: acquire and block
        // 1 were queued before the queue filled.
        seed(&st, 7, true, &[1]);
        st.adopt_slice(0, &input(), meta(7)).unwrap();
        let blocks: Vec<u16> = rx
            .try_iter()
            .filter_map(|e| match e {
                Event::PortBlockAdopt { adopt, .. } => Some((adopt.port_lo - 1024) / 512),
                Event::ClusterSliceAcquire { .. } => panic!("acquire queued twice"),
                _ => None,
            })
            .collect();
        assert_eq!(blocks, [0, 2]);
    }
}
