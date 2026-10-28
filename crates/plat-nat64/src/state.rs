//! BIB, session and subscriber tables (RFC 6146 §3.1–3.5) and the expiry
//! sweeper.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ahash::RandomState;
use crossbeam_utils::CachePadded;
use plat_audit::{AuditSink, Event, LimitKind};
use plat_common::config::{AuditMode, Config, Filtering, OverflowPolicy};
use plat_common::{Clock, Counter, Counters, DropReason, Ipv6Cidr};
use plat_packet::proto;

use crate::pool::{BlockRef, Pool};
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
        Self { r, wall_us, used: [mk(), mk(), mk()], in_use: 0, empty_since: Some(now) }
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

#[derive(Debug)]
pub struct State {
    pub bib6: Sharded<Key6, Key4>,
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
}

/// Rate-limit slots for `Limit` records, indexed by `LimitKind as usize`.
const LIMIT_SLOTS: usize = 8;

impl State {
    pub fn new(cfg: &Config, owned: Vec<u32>, audit: AuditSink, clock: Clock) -> Self {
        let n = &cfg.nat64;
        let t = &cfg.timeouts;
        let shards = n.table_shards;
        Self {
            bib6: Sharded::new(shards),
            bib4: Sharded::new(shards),
            subs: Sharded::new(shards),
            pool: Pool::new(owned, n.port_min, n.port_max, n.port_block_size),
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

    fn alloc_port(&self, s: &mut Subscriber, sub: u128, p: u8) -> Result<Key4, DropReason> {
        let pi = proto_idx(p);
        let size = self.pool.block_size();
        let Subscriber { blocks, rng, .. } = s;
        for b in blocks.iter_mut() {
            if let Some(off) = b.alloc(pi, rng, size) {
                return Ok(Key4 { proto: p, addr: self.pool.addr(b.r.addr_idx), port: self.pool.port_lo(b.r) + off });
            }
        }
        if blocks.len() >= usize::from(self.max_blocks) {
            self.limit(LimitKind::SubscriberBlocks, sub);
            return Err(DropReason::SubscriberLimit);
        }
        let prefer = blocks.first().map(|b| b.r.addr_idx);
        let Some(r) = self.pool.alloc(prefer, self.paired) else {
            self.limit(LimitKind::PoolExhausted, sub);
            return Err(DropReason::PortExhausted);
        };
        let wall = Clock::wall_us();
        let lo = self.pool.port_lo(r);
        // COMPLIANCE MAPPING:
        // - NIST 800-53: AU-12, AU-5 - attribution record precedes use; under
        //   refuse_new_bindings an unloggable block is never handed out.
        // - RFC 6888 REQ-12 / RFC 7422 §2 - port-block logging.
        let ev = Event::PortBlockAlloc {
            ts_us: wall,
            sub,
            sub_len: self.sub_len,
            v4: self.pool.addr(r.addr_idx),
            port_lo: lo,
            port_hi: lo + (size - 1),
        };
        if !self.audit.emit(ev) && self.refuse_on_overflow {
            self.pool.release(r);
            return Err(DropReason::AuditUnavailable);
        }
        let mut b = Block::new(r, size, wall, self.clock.now_ms());
        let off = b.alloc(pi, rng, size).ok_or(DropReason::PortExhausted)?;
        blocks.push(b);
        Ok(Key4 { proto: p, addr: self.pool.addr(r.addr_idx), port: lo + off })
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
    /// §3.5.2.2: only a SYN may create TCP state).
    pub fn bib_for(&self, k6: Key6, create: bool, counters: &Counters) -> Result<Key4, DropReason> {
        let mut g6 = self.bib6.lock(&k6);
        if let Some(k4) = g6.get(&k6) {
            return Ok(*k4);
        }
        if !create {
            return Err(DropReason::TcpNoState);
        }
        if self.refuse_on_overflow && !self.audit.has_room() {
            return Err(DropReason::AuditUnavailable);
        }
        let sub = k6.addr & self.sub_mask;
        let (k4, sub_sessions) = {
            let mut gs = self.subs.lock(&sub);
            let is_new = !gs.contains_key(&sub);
            if is_new {
                // COMPLIANCE MAPPING:
                // - NIST 800-53: SC-5 - bounded subscriber table; both
                //   rejections are read-only (PERF-101), so a flood of new
                //   subscribers against an exhausted pool or a full table
                //   writes no shared cache line and creates no entry.
                if self.pool.free_blocks() == 0 {
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
            match self.alloc_port(s, sub, k6.proto) {
                Ok(k4) => (k4, s.sessions.clone()),
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
        if self.audit_mode == AuditMode::Session {
            let ev = Event::BibCreate {
                ts_us: wall,
                proto: k6.proto,
                v6: k6.addr,
                v6_port: k6.port,
                v4: k4.addr,
                v4_port: k4.port,
            };
            if !self.audit.emit(ev) && self.refuse_on_overflow {
                self.free_port(sub, k4);
                return Err(DropReason::AuditUnavailable);
            }
        }
        self.bib4.lock(&k4).insert(
            k4,
            Bib {
                k6,
                sub,
                created_wall_us: wall,
                empty_since: None,
                sub_sessions,
                sessions: Map::with_hasher(self.hasher.clone()),
                remotes: (self.filtering == Filtering::AddressDependent)
                    .then(|| Box::new(Map::with_hasher(self.hasher.clone()))),
            },
        );
        g6.insert(k6, k4);
        counters.inc(Counter::BibCreated);
        Ok(k4)
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
        let tcp = if k4.proto == proto::TCP {
            Some(tcp::initial(Side::V6, flags).ok_or(DropReason::TcpNoState)?)
        } else {
            None
        };
        self.admit_session(bib)?;
        bib.insert_session(remote, Session { expires_ms: now + self.timeout(k4.proto, tcp), tcp });
        counters.inc(Counter::SessionCreated);
        Ok(())
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
        self.bib6.lock(&k6).get(&k6).copied()
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
    pub fn sweep(&self) -> SweepStats {
        let now = self.clock.now_ms();
        let mut st = SweepStats::default();
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
                        Some(t) if now.saturating_sub(t) >= BIB_GRACE_MS => dead.push((*k4, bib.k6)),
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
                st.bibs_removed += 1;
            }
        }

        for i in 0..self.subs.shard_count() {
            let mut g = self.subs.lock_index(i);
            g.retain(|sub, s| {
                s.blocks.retain(|b| {
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
                    //   release is retried, not counted as lost (NIST-201).
                    let queued = self.audit.try_emit(Event::PortBlockRelease {
                        ts_us: wall,
                        sub: *sub,
                        sub_len: self.sub_len,
                        v4: self.pool.addr(b.r.addr_idx),
                        port_lo: lo,
                        port_hi: lo + (self.pool.block_size() - 1),
                        held_secs: (wall.saturating_sub(b.wall_us) / 1_000_000) as u32,
                    });
                    if !queued {
                        st.releases_deferred += 1;
                        return true;
                    }
                    self.pool.release(b.r);
                    st.blocks_released += 1;
                    false
                });
                let keep = !s.blocks.is_empty() || s.sessions.load(Ordering::Relaxed) > 0;
                if !keep {
                    self.sub_count.fetch_sub(1, Ordering::Relaxed);
                }
                keep
            });
        }
        st
    }
}
