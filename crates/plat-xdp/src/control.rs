//! `CONTROL` (plan §4.1, §9): the fast path's enable bit, the TUN ifindex
//! and MTU it routes against, and the dead-man deadline `platd` keeps
//! pushing forward; plus the grace-period step and the `plat-xdp-ctl`
//! thread that drives both.
//!
//! Words of the 24-byte record (host order): word 0 = `enabled` |
//! `tun_ifindex`, word 1 = `deadline_ns`, word 2 = `tun_mtu` | pad. Enabling
//! is one store of word 0 after the MTU and a deadline are in place, so the
//! program never sees `enabled = 1` with a zero ifindex.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-24 (Fail in Known State) - dead-man deadline: if
//!   `platd` stops refreshing it (crash, hang, stalled sweeper or workers),
//!   the program passes every packet to the slow path once it is reached
//! - NIST 800-53: SC-10 (Network Disconnect) - supporting: a fast-path
//!   session cannot outlive `platd` by more than `deadline_ms`

#[cfg(target_os = "linux")]
use std::io;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering, fence};
#[cfg(target_os = "linux")]
use std::thread::JoinHandle;
use std::time::Duration;

use plat_xdp_core::abi::Control;

use crate::maps::Words;
use crate::mirror::XdpMirror;

/// Interval of the grace-period step (plan §4.3).
pub const GRACE_INTERVAL: Duration = Duration::from_millis(100);

const W_EN: usize = 0;
const W_DEADLINE: usize = 1;
const W_MTU: usize = 2;

fn w0(enabled: u32, ifindex: u32) -> u64 {
    let (e, i) = (enabled.to_ne_bytes(), ifindex.to_ne_bytes());
    u64::from_ne_bytes([e[0], e[1], e[2], e[3], i[0], i[1], i[2], i[3]])
}

fn w2(mtu: u32) -> u64 {
    let m = mtu.to_ne_bytes();
    u64::from_ne_bytes([m[0], m[1], m[2], m[3], 0, 0, 0, 0])
}

/// The `CONTROL` record writer.
#[derive(Debug, Clone)]
pub struct XdpControl {
    mem: Arc<dyn Words>,
}

impl XdpControl {
    /// Over `mem` (at least 3 words).
    pub fn with_mem(mem: Arc<dyn Words>) -> Self {
        Self { mem }
    }

    /// Over `platd`'s `CONTROL` pin.
    #[cfg(target_os = "linux")]
    pub fn new(maps: &crate::maps::XdpMaps) -> Self {
        let mem: Arc<dyn Words> = maps.control.clone();
        Self { mem }
    }

    fn w(&self, i: usize) -> Option<&AtomicU64> {
        self.mem.words().get(i)
    }

    /// The record as stored.
    pub fn read(&self) -> Control {
        let mut b = [0u8; 24];
        for (d, i) in b.as_chunks_mut::<8>().0.iter_mut().zip(0..) {
            d.copy_from_slice(&self.w(i).map_or(0, |w| w.load(Ordering::Acquire)).to_ne_bytes());
        }
        Control::from_bytes(&b)
    }

    /// Stores the dead-man deadline (`CLOCK_MONOTONIC_COARSE` ns, see
    /// [`coarse_now_ns`]).
    pub fn heartbeat(&self, deadline_ns: u64) {
        if let Some(w) = self.w(W_DEADLINE) {
            w.store(deadline_ns, Ordering::Release);
        }
    }

    /// Enables the fast path routing through the TUN `tun_ifindex` of MTU
    /// `tun_mtu`, with a first deadline. Refuses zero values (the program
    /// would pass `disabled` anyway).
    pub fn enable(&self, tun_ifindex: u32, tun_mtu: u32, deadline_ns: u64) -> bool {
        if tun_ifindex == 0 || tun_mtu == 0 {
            return false;
        }
        let (Some(en), Some(mtu)) = (self.w(W_EN), self.w(W_MTU)) else { return false };
        mtu.store(w2(tun_mtu), Ordering::Relaxed);
        self.heartbeat(deadline_ns);
        fence(Ordering::Release);
        en.store(w0(1, tun_ifindex), Ordering::Release);
        true
    }

    /// Disables the fast path (one store, then a full fence): every later
    /// program run passes `disabled`.
    pub fn disable(&self) {
        if let Some(en) = self.w(W_EN) {
            let ifindex = self.read().tun_ifindex;
            en.store(w0(0, ifindex), Ordering::Release);
            fence(Ordering::SeqCst);
        }
    }
}

/// Why pinned maps are not fresh (SEC-001, `stale_maps`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Stale {
    /// `CONTROL` was enabled or claimed before: another `platd` used these
    /// maps (the loader leaves it all zero).
    #[error("CONTROL was already enabled or claimed by another process")]
    ControlUsed,
    /// `SLOT[slot]` is not all-zero: sessions of an earlier process may
    /// still be reachable.
    #[error("SLOT {0} holds a record of an earlier process")]
    SlotUsed(u32),
}

/// SEC-001: claims freshly created maps for this process, or refuses.
/// Fresh means `CONTROL` all zero (never enabled, never claimed) and every
/// `SLOT` header zero (`FREE`, slice 0, generation 0), a bounded scan of
/// `slots` words through the mmap at start. An all-`FREE` `SLOT` also
/// proves `OUT6` / `IN4` empty: the loader inserts nothing and every
/// writer install stores a non-zero header before any entry is published.
///
/// SEC-007: the claim itself is one `compare_exchange(0, 1)` on
/// `CONTROL.deadline_ns`, taken *before* the `SLOT` scan, so of two
/// processes racing on the same pins exactly one wins and the other gets
/// [`Stale::ControlUsed`]. Deadline 1 is in the past: the program still
/// passes everything. A claim refused by the scan keeps the mark (the
/// maps are stale either way; clearing it would reopen the race).
pub fn claim_fresh(control: &XdpControl, slot_mem: &dyn Words, slots: u32) -> Result<(), Stale> {
    let c = control.read();
    if c.enabled != 0 || c.tun_ifindex != 0 || c.tun_mtu != 0 {
        return Err(Stale::ControlUsed);
    }
    let Some(deadline) = control.w(W_DEADLINE) else {
        return Err(Stale::ControlUsed);
    };
    // AcqRel: the winner's later stores are ordered after the claim, and a
    // loser observes every store the winner made before it.
    if deadline.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return Err(Stale::ControlUsed);
    }
    let w = slot_mem.words();
    for i in 0..slots {
        let at = (i as usize).saturating_mul(plat_xdp_core::abi::SLOT_WORDS);
        if w.get(at).map_or(0, |a| a.load(Ordering::Acquire)) != 0 {
            return Err(Stale::SlotUsed(i));
        }
    }
    fence(Ordering::SeqCst);
    Ok(())
}

/// `CLOCK_MONOTONIC_COARSE` in nanoseconds: the clock of
/// `bpf_ktime_get_coarse_ns` (deadline and `seen_ns`).
#[cfg(target_os = "linux")]
pub fn coarse_now_ns() -> u64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::MonotonicCoarse);
    u64::try_from(t.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(t.tv_nsec).unwrap_or(0))
}

/// One forced RCU grace period: `membarrier(MEMBARRIER_CMD_GLOBAL)`, which
/// runs `synchronize_rcu()`. `EINVAL` on `nohz_full` hosts, where `[xdp]`
/// is refused (decision Q5).
#[cfg(target_os = "linux")]
pub fn grace_period() -> io::Result<()> {
    rustix::thread::membarrier(rustix::thread::MembarrierCommand::Global).map_err(io::Error::from)
}

/// Probes [`grace_period`] once at start (decision Q5): an error means the
/// fast path must stay disabled (`unsupported_host`).
#[cfg(target_os = "linux")]
pub fn probe_grace_period() -> io::Result<()> {
    grace_period()
}

/// After a successful grace period: advance the epoch and return
/// quarantined slots whose grace period has passed.
pub fn after_grace_period(m: &XdpMirror) -> u64 {
    m.slot_allocator().advance_epoch();
    m.slot_allocator().recycle()
}

/// Progress of one source (sweeper passes, a worker's housekeeping, the
/// publisher's passes) for the heartbeat's health check: healthy while
/// its counter moved within `window_ns`.
#[derive(Debug, Clone, Copy)]
pub struct Watch {
    last: u64,
    at: u64,
}

impl Watch {
    /// A watch started at `now_ns` (the first value counts as progress).
    pub fn new(now_ns: u64) -> Self {
        Self { last: u64::MAX, at: now_ns }
    }

    /// Records `value` at `now_ns`; `true` while the source made progress
    /// within `window_ns`.
    pub fn ok(&mut self, value: u64, now_ns: u64, window_ns: u64) -> bool {
        if value != self.last {
            (self.last, self.at) = (value, now_ns);
        }
        now_ns.saturating_sub(self.at) <= window_ns
    }
}

/// Interval of the integrity check (plan §9).
pub const INTEGRITY_INTERVAL: Duration = Duration::from_secs(10);

/// Slots the stale-generation collector scans per grace-period tick
/// (bounded control-thread work: about 650 k slots per minute, a full
/// default `SLOT` table every two minutes).
pub const GC_SCAN_PER_TICK: u32 = 1024;

/// Timing of the control thread (from `[xdp]`).
#[derive(Debug, Clone, Copy)]
pub struct ControlTiming {
    pub heartbeat: Duration,
    pub deadline: Duration,
}

/// Counters of the control thread.
#[derive(Debug, Default)]
pub struct ControlCounters {
    /// Heartbeats withheld because `healthy` said no
    /// (`plat_xdp_heartbeat_stalls_total`).
    pub heartbeat_stalls: AtomicU64,
    /// Grace periods that failed (the epoch did not move).
    pub grace_failures: AtomicU64,
    /// Highest `plat_xdp_slots_quarantined` seen by the control thread
    /// (SEC-007: a stuck grace period shows as a growing high-water mark).
    pub quarantined_high: AtomicU64,
    /// Integrity checks run.
    pub integrity_checks: AtomicU64,
}

/// Why the fast path was turned off for the rest of the process (an
/// `xdp_fastpath_state` reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The frozen `CONFIG` no longer equals this configuration's.
    ConfigMismatch,
    /// The loaded object is not this binary's (state file).
    ObjectMismatch,
    /// The attached program changed since start (state file program id).
    LinkMismatch,
    /// A pin is gone or now names another map (loader re-run or detach).
    MapsUnavailable,
    /// Grace periods fail (`membarrier`): slots could no longer be reused
    /// safely (SEC-007).
    UnsupportedHost,
}

/// A state change the control thread reports (audited by `platd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Heartbeats withheld: the deadline runs out and the fast path stops.
    /// `lapsed_ns`: `Some(now - deadline)` when a stored deadline ran out
    /// before this thread beat again (it did not run in time); `None` when
    /// the health check failed.
    Stalled { lapsed_ns: Option<u64> },
    /// Health came back: heartbeats resumed.
    Resumed,
    /// Disabled for good (`CONTROL.enabled = 0`).
    Fault(Fault),
    /// Stopped with the process (`CONTROL.enabled = 0`).
    Shutdown,
}

/// The hooks the control thread calls (`platd` supplies them; every hook
/// runs on `plat-xdp-ctl` only).
pub struct ControlHooks {
    /// The sweeper and every worker made progress recently (plan §9).
    pub healthy: Box<dyn FnMut() -> bool + Send>,
    /// Upper bound of the deadline (`CLOCK_MONOTONIC_COARSE` ns), e.g. the
    /// HA lease self-fence instant; `None`: no bound.
    pub cap_ns: Box<dyn FnMut() -> Option<u64> + Send>,
    /// Integrity check, every [`INTEGRITY_INTERVAL`].
    pub integrity: Box<dyn FnMut() -> Result<(), Fault> + Send>,
    /// One stale-generation collection step (after each grace period).
    pub gc: Box<dyn FnMut() + Send>,
    /// Called on every [`Transition`].
    pub notify: Box<dyn FnMut(Transition) + Send>,
}

impl std::fmt::Debug for ControlHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlHooks").finish_non_exhaustive()
    }
}

/// Consecutive failed grace periods after which the fast path is turned
/// off (`unsupported_host`): quarantined slots no longer return, so
/// installs would soon fail anyway (SEC-007).
pub const GRACE_FAILURE_LIMIT: u32 = 10;

/// The control thread's decisions, separate from its timing and syscalls
/// (host-testable).
#[derive(Debug, Default)]
pub struct ControlState {
    stalled: bool,
    faulted: bool,
    grace_failed: u32,
    /// The deadline last stored in `CONTROL` (0: none yet).
    last_deadline: u64,
    /// `last_deadline` was shortened by the cap (lease fence): its lapse is
    /// the fence, audited by the cluster records, not a missed heartbeat.
    capped: bool,
}

impl ControlState {
    /// Starts from the deadline `enable` stored, so a lapse before the
    /// first beat is seen too. Values 0 and 1 (unset, claim mark) are
    /// ignored.
    pub fn with_deadline(deadline_ns: u64) -> Self {
        Self { last_deadline: if deadline_ns > 1 { deadline_ns } else { 0 }, ..Self::default() }
    }

    /// A heartbeat tick: `Some(deadline)` to store, or `None` (stalled or
    /// faulted). Reports the transitions.
    pub fn beat(
        &mut self,
        healthy: bool,
        now_ns: u64,
        t: &ControlTiming,
        cap: Option<u64>,
        c: &ControlCounters,
        notify: &mut dyn FnMut(Transition),
    ) -> Option<u64> {
        if self.faulted {
            return None;
        }
        // COMPLIANCE MAPPING:
        // - NIST 800-53: AU-12 (Audit Record Generation) - a deadline lapse
        //   this thread did not see as it happened (SIGSTOP, CPU
        //   starvation, a long hook) is still reported as Stalled+Resumed
        // - NIST 800-53: SC-24 (Fail in Known State) - the program stops
        //   forwarding at `now >= deadline_ns` (`decide`); the same test on
        //   the same clock (`CLOCK_MONOTONIC_COARSE`) is applied here
        // - NIST 800-53: AU-4/SC-5 - a cap-bound deadline (fenced or
        //   minority member) is never a heartbeat lapse, so a fenced node
        //   does not emit a Stalled+Resumed pair per beat (SEC-V01)
        if !self.stalled && !self.capped && self.last_deadline != 0 && now_ns >= self.last_deadline {
            c.heartbeat_stalls.fetch_add(1, Ordering::Relaxed);
            self.stalled = true;
            notify(Transition::Stalled { lapsed_ns: Some(now_ns - self.last_deadline) });
        }
        if !healthy {
            c.heartbeat_stalls.fetch_add(1, Ordering::Relaxed);
            if !self.stalled {
                self.stalled = true;
                notify(Transition::Stalled { lapsed_ns: None });
            }
            return None;
        }
        if self.stalled {
            self.stalled = false;
            notify(Transition::Resumed);
        }
        let d = now_ns.saturating_add(t.deadline.as_nanos() as u64);
        let capped = cap.is_some_and(|c| c < d);
        let d = if capped { cap.unwrap_or(d) } else { d };
        self.capped = capped;
        self.last_deadline = d;
        Some(d)
    }

    /// A fault: `true` the first time (the caller disables `CONTROL`).
    pub fn fault(&mut self, f: Fault, notify: &mut dyn FnMut(Transition)) -> bool {
        if self.faulted {
            return false;
        }
        self.faulted = true;
        notify(Transition::Fault(f));
        true
    }

    /// A grace-period result; `true` when the failures reached
    /// [`GRACE_FAILURE_LIMIT`] in a row.
    pub fn grace(&mut self, ok: bool) -> bool {
        self.grace_failed = if ok { 0 } else { self.grace_failed.saturating_add(1) };
        self.grace_failed >= GRACE_FAILURE_LIMIT
    }

    pub fn faulted(&self) -> bool {
        self.faulted
    }
}

/// Starts `plat-xdp-ctl` (plan §9): every `heartbeat` it stores
/// `now + deadline` (capped by `hooks.cap_ns`) if `hooks.healthy()` says
/// the sweeper and workers made progress, else counts a stall and lets the
/// deadline run out; every [`GRACE_INTERVAL`] it runs one grace period,
/// recycles slots and runs one GC step; every [`INTEGRITY_INTERVAL`] it
/// runs `hooks.integrity` and on a fault disables the fast path for good.
/// Stops (and disables the fast path) when `stop` is set.
#[cfg(target_os = "linux")]
pub fn spawn(
    control: XdpControl,
    mirror: Arc<XdpMirror>,
    timing: ControlTiming,
    counters: Arc<ControlCounters>,
    stop: Arc<AtomicBool>,
    mut hooks: ControlHooks,
) -> io::Result<JoinHandle<()>> {
    let tick = GRACE_INTERVAL.min(timing.heartbeat);
    std::thread::Builder::new().name("plat-xdp-ctl".into()).spawn(move || {
        let mut st = ControlState::with_deadline(control.read().deadline_ns);
        let mut since_beat = Duration::ZERO;
        let mut since_grace = Duration::ZERO;
        let mut since_check = Duration::ZERO;
        while !stop.load(Ordering::Acquire) {
            if since_beat >= timing.heartbeat {
                since_beat = Duration::ZERO;
                let healthy = (hooks.healthy)();
                let cap = (hooks.cap_ns)();
                if let Some(d) = st.beat(healthy, coarse_now_ns(), &timing, cap, &counters, &mut *hooks.notify) {
                    control.heartbeat(d);
                }
            }
            if since_grace >= GRACE_INTERVAL {
                since_grace = Duration::ZERO;
                let ok = grace_period().is_ok();
                if ok {
                    after_grace_period(&mirror);
                } else {
                    counters.grace_failures.fetch_add(1, Ordering::Relaxed);
                }
                if st.grace(ok) && st.fault(Fault::UnsupportedHost, &mut *hooks.notify) {
                    control.disable();
                }
                (hooks.gc)();
                counters.quarantined_high.fetch_max(mirror.slot_allocator().quarantined(), Ordering::Relaxed);
            }
            if since_check >= INTEGRITY_INTERVAL {
                since_check = Duration::ZERO;
                counters.integrity_checks.fetch_add(1, Ordering::Relaxed);
                if let Err(f) = (hooks.integrity)()
                    && st.fault(f, &mut *hooks.notify)
                {
                    control.disable();
                }
            }
            std::thread::sleep(tick);
            since_beat += tick;
            since_grace += tick;
            since_check += tick;
        }
        control.disable();
        (hooks.notify)(Transition::Shutdown);
    })
}

/// Idle sleep of the publisher thread between empty passes.
pub const PUBLISH_IDLE: Duration = Duration::from_millis(1);

/// Starts `plat-xdp-pub` (WU5 deferred publish, plan §4.3): runs
/// [`XdpMirror::flush`] back to back while it finds work and every
/// [`PUBLISH_IDLE`] otherwise, so new flows reach the fast path within
/// about a millisecond and retired entries leave the maps as quickly;
/// every map syscall of the writer runs here, never under a `bib4` lock.
/// A last pass runs after `stop`.
#[cfg(target_os = "linux")]
pub fn spawn_publisher(mirror: Arc<XdpMirror>, stop: Arc<AtomicBool>) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new().name("plat-xdp-pub".into()).spawn(move || {
        while !stop.load(Ordering::Acquire) {
            if mirror.flush() == 0 {
                std::thread::sleep(PUBLISH_IDLE);
            }
        }
        mirror.flush();
    })
}

/// `CLOCK_MONOTONIC_COARSE` (ns) of the engine clock's origin
/// (`Clock::now_ms() == 0`), for [`XdpMirror::with_clock`]. Rust's
/// `Instant` is `CLOCK_MONOTONIC` on Linux, the same base as the coarse
/// clock; the two differ by at most one tick, which `seen_ms` absorbs by
/// clamping to `now`.
#[cfg(target_os = "linux")]
pub fn engine_origin_ns(clock: &plat_common::Clock) -> u64 {
    coarse_now_ns().saturating_sub(u64::try_from(clock.origin().elapsed().as_nanos()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::HeapWords;

    /// SEC-001: fresh maps are claimed once; a second claim (another
    /// `platd`, or a restart on the same pins) and maps with any slot
    /// record are refused.
    #[test]
    fn maps_are_claimed_once_and_used_maps_are_refused() {
        use plat_xdp_core::abi::{SLOT_DEAD, SLOT_WORDS, SlotRec};
        let c = XdpControl::with_mem(Arc::new(HeapWords::new(3)));
        let slots = HeapWords::new(8 * SLOT_WORDS);
        assert_eq!(claim_fresh(&c, &slots, 8), Ok(()));
        assert_eq!(c.read().deadline_ns, 1, "consumed mark");
        assert_eq!(c.read().enabled, 0, "still disabled");
        assert_eq!(claim_fresh(&c, &slots, 8), Err(Stale::ControlUsed), "attach twice");
        let c2 = XdpControl::with_mem(Arc::new(HeapWords::new(3)));
        if let Some(w) = slots.words().get(5 * SLOT_WORDS) {
            w.store(SlotRec::hdr_word(SLOT_DEAD, 0, 1), Ordering::Relaxed);
        }
        assert_eq!(claim_fresh(&c2, &slots, 8), Err(Stale::SlotUsed(5)));
        assert_eq!(c2.read().deadline_ns, 1, "SEC-007: the claim is taken before the scan and kept");
        assert_eq!(claim_fresh(&c2, &HeapWords::new(8 * SLOT_WORDS), 8), Err(Stale::ControlUsed), "still consumed");
        let c3 = XdpControl::with_mem(Arc::new(HeapWords::new(3)));
        assert!(c3.enable(7, 1500, 9));
        c3.disable();
        assert_eq!(claim_fresh(&c3, &HeapWords::new(8), 1), Err(Stale::ControlUsed), "enabled once");
    }

    /// SEC-007: of many claims racing on the same fresh maps exactly one
    /// succeeds; every other one is refused `ControlUsed` (the claim is a
    /// compare-exchange, not check-then-set).
    #[test]
    fn racing_claims_have_one_winner() {
        use plat_xdp_core::abi::SLOT_WORDS;
        for _ in 0..200 {
            let c = XdpControl::with_mem(Arc::new(HeapWords::new(3)));
            let slots = Arc::new(HeapWords::new(64 * SLOT_WORDS));
            let go = Arc::new(std::sync::Barrier::new(8));
            let hs: Vec<_> = (0..8)
                .map(|_| {
                    let (c, slots, go) = (c.clone(), Arc::clone(&slots), Arc::clone(&go));
                    std::thread::spawn(move || {
                        go.wait();
                        claim_fresh(&c, &*slots, 64)
                    })
                })
                .collect();
            let rs: Vec<_> = hs.into_iter().map(|h| h.join().unwrap_or(Err(Stale::SlotUsed(u32::MAX)))).collect();
            assert_eq!(rs.iter().filter(|r| r.is_ok()).count(), 1, "{rs:?}");
            assert!(rs.iter().all(|r| matches!(r, Ok(()) | Err(Stale::ControlUsed))), "{rs:?}");
            assert_eq!(c.read().deadline_ns, 1);
        }
    }

    /// SEC-002: a source that stops (a stuck or dead publisher thread)
    /// turns the health check false after its window, and true again when
    /// it moves.
    #[test]
    fn a_stalled_source_fails_the_health_check() {
        let mut w = Watch::new(0);
        assert!(w.ok(0, 0, 100));
        assert!(w.ok(1, 50, 100));
        assert!(w.ok(1, 150, 100), "within the window of the last change");
        assert!(!w.ok(1, 151, 100), "stalled");
        assert!(w.ok(2, 200, 100), "progress again");
    }

    #[test]
    fn stall_resume_fault_transitions() {
        let t = ControlTiming { heartbeat: Duration::from_millis(250), deadline: Duration::from_millis(1000) };
        let c = ControlCounters::default();
        let mut st = ControlState::default();
        let mut seen = Vec::new();
        let mut n = |x| seen.push(x);
        assert_eq!(st.beat(true, 10, &t, None, &c, &mut n), Some(1_000_000_010));
        assert_eq!(st.beat(true, 10, &t, Some(500), &c, &mut n), Some(500), "capped by the lease");
        assert_eq!(st.beat(false, 20, &t, None, &c, &mut n), None);
        assert_eq!(st.beat(false, 30, &t, None, &c, &mut n), None);
        assert!(st.beat(true, 40, &t, None, &c, &mut n).is_some());
        assert!(st.fault(Fault::ConfigMismatch, &mut n));
        assert!(!st.fault(Fault::LinkMismatch, &mut n), "reported once");
        assert_eq!(st.beat(true, 50, &t, None, &c, &mut n), None, "faulted: no more heartbeats");
        assert_eq!(c.heartbeat_stalls.load(Ordering::Relaxed), 2);
        assert_eq!(
            seen,
            [Transition::Stalled { lapsed_ns: None }, Transition::Resumed, Transition::Fault(Fault::ConfigMismatch)],
            "one record per transition"
        );
        let mut g = ControlState::default();
        for _ in 1..GRACE_FAILURE_LIMIT {
            assert!(!g.grace(false));
        }
        assert!(!g.grace(true), "a success resets the run");
        for _ in 1..GRACE_FAILURE_LIMIT {
            assert!(!g.grace(false));
        }
        assert!(g.grace(false));
    }

    #[test]
    fn a_missed_deadline_is_reported_once() {
        let t = ControlTiming { heartbeat: Duration::from_millis(250), deadline: Duration::from_millis(1000) };
        let c = ControlCounters::default();
        let mut st = ControlState::with_deadline(1_000);
        let mut seen = Vec::new();
        let mut n = |x| seen.push(x);
        // Normal beats inside the deadline: nothing.
        assert_eq!(st.beat(true, 999, &t, None, &c, &mut n), Some(1_000_000_999));
        assert_eq!(st.beat(true, 250_000_999, &t, None, &c, &mut n), Some(1_250_000_999));
        assert_eq!(c.heartbeat_stalls.load(Ordering::Relaxed), 0);
        // Frozen past the deadline (SIGSTOP): Stalled then Resumed, once.
        assert!(st.beat(true, 5_000_000_000, &t, None, &c, &mut n).is_some());
        assert!(st.beat(true, 5_250_000_000, &t, None, &c, &mut n).is_some());
        assert_eq!(c.heartbeat_stalls.load(Ordering::Relaxed), 1);
        drop(n);
        assert_eq!(seen, [Transition::Stalled { lapsed_ns: Some(3_749_999_001) }, Transition::Resumed]);
    }

    #[test]
    fn a_beat_at_the_deadline_is_a_lapse() {
        let t = ControlTiming { heartbeat: Duration::from_millis(250), deadline: Duration::from_millis(1000) };
        let c = ControlCounters::default();
        let mut seen = Vec::new();
        let mut n = |x| seen.push(x);
        let mut st = ControlState::default();
        let d = st.beat(true, 0, &t, None, &c, &mut n).unwrap_or(0);
        assert!(st.beat(true, d - 1, &t, None, &c, &mut n).is_some(), "one ns early: fine");
        let d = d - 1 + 1_000_000_000;
        assert!(st.beat(true, d, &t, None, &c, &mut n).is_some(), "the program fails at now >= deadline");
        // Unhealthy after a lapse: one Stalled, no double count.
        let mut st2 = ControlState::with_deadline(100);
        assert_eq!(st2.beat(false, 200, &t, None, &c, &mut n), None);
        drop(n);
        assert_eq!(
            seen,
            [
                Transition::Stalled { lapsed_ns: Some(0) },
                Transition::Resumed,
                Transition::Stalled { lapsed_ns: Some(100) }
            ]
        );
        assert_eq!(c.heartbeat_stalls.load(Ordering::Relaxed), 3, "lapse + lapse + unhealthy tick");
        assert_eq!(ControlState::with_deadline(1).last_deadline, 0, "claim mark ignored");
    }

    /// QA (L29): a lapse during an unhealthy stall is not reported twice;
    /// a cap-bound deadline never counts as a heartbeat lapse; a faulted state
    /// ignores lapses; unset seeds (0) never report a lapse.
    #[test]
    fn lapse_edge_cases() {
        let t = ControlTiming { heartbeat: Duration::from_millis(250), deadline: Duration::from_millis(1000) };
        let c = ControlCounters::default();
        let mut seen = Vec::new();
        let mut n = |x| seen.push(x);
        // Unhealthy (stalled) across the deadline, then healthy: one pair.
        let mut st = ControlState::with_deadline(1_000);
        assert_eq!(st.beat(false, 500, &t, None, &c, &mut n), None);
        assert_eq!(st.beat(false, 2_000, &t, None, &c, &mut n), None);
        assert_eq!(st.beat(true, 3_000, &t, None, &c, &mut n), Some(1_000_003_000));
        assert_eq!(c.heartbeat_stalls.load(Ordering::Relaxed), 2, "two unhealthy ticks, lapse not added");
        // A cap-bound deadline that lapses is the fence, not a lapse
        // (SEC-V01); the next uncapped deadline is checked again.
        assert_eq!(st.beat(true, 4_000, &t, Some(5_000), &c, &mut n), Some(5_000));
        assert!(st.beat(true, 5_000, &t, None, &c, &mut n).is_some());
        assert_eq!(c.heartbeat_stalls.load(Ordering::Relaxed), 2);
        assert!(st.beat(true, 2_000_000_000, &t, None, &c, &mut n).is_some(), "uncapped lapse");
        assert_eq!(c.heartbeat_stalls.load(Ordering::Relaxed), 3);
        // Faulted: no lapse report.
        assert!(st.fault(Fault::MapsUnavailable, &mut n));
        assert_eq!(st.beat(true, u64::MAX, &t, None, &c, &mut n), None);
        // Seed 0: no lapse at any time; deadline saturates.
        let mut z = ControlState::with_deadline(0);
        assert_eq!(z.beat(true, u64::MAX, &t, None, &c, &mut n), Some(u64::MAX));
        drop(n);
        assert_eq!(
            seen,
            [
                Transition::Stalled { lapsed_ns: None },
                Transition::Resumed,
                Transition::Stalled { lapsed_ns: Some(999_995_000) },
                Transition::Resumed,
                Transition::Fault(Fault::MapsUnavailable)
            ]
        );
        assert_eq!(c.heartbeat_stalls.load(Ordering::Relaxed), 3);
    }

    /// SEC-V01: a fenced member (cap == now) beats with a deadline already
    /// past; no beat reports a lapse and the stall counter stays put.
    #[test]
    fn a_fenced_member_reports_no_lapse() {
        let t = ControlTiming { heartbeat: Duration::from_millis(250), deadline: Duration::from_millis(1000) };
        let c = ControlCounters::default();
        let mut seen = Vec::new();
        let mut n = |x| seen.push(x);
        let mut st = ControlState::with_deadline(1_000);
        for now in [500u64, 250_000_500, 500_000_500, 750_000_500, 1_000_000_500] {
            assert_eq!(st.beat(true, now, &t, Some(now), &c, &mut n), Some(now));
        }
        drop(n);
        assert!(seen.is_empty(), "{seen:?}");
        assert_eq!(c.heartbeat_stalls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn enable_heartbeat_disable() {
        let c = XdpControl::with_mem(Arc::new(HeapWords::new(3)));
        assert_eq!(c.read(), Control::default());
        assert!(!c.enable(0, 1500, 1));
        assert!(!c.enable(7, 0, 1));
        assert_eq!(c.read().enabled, 0);
        assert!(c.enable(7, 1500, 1000));
        let r = c.read();
        assert_eq!((r.enabled, r.tun_ifindex, r.tun_mtu, r.deadline_ns), (1, 7, 1500, 1000));
        c.heartbeat(2000);
        assert_eq!(c.read().deadline_ns, 2000);
        c.disable();
        let r = c.read();
        assert_eq!((r.enabled, r.tun_ifindex), (0, 7));
    }

    #[test]
    fn grace_step_recycles() {
        let (_t, m) = crate::mirror::tests::mirror(4, 4);
        let e = crate::mirror::tests::entry(1);
        let s = m.install(&e, 1, 0).unwrap_or(u32::MAX);
        assert!(m.retire(s, &e).is_ok());
        m.flush();
        assert_eq!(after_grace_period(&m), 0);
        assert_eq!(after_grace_period(&m), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn coarse_clock_moves_forward() {
        let a = coarse_now_ns();
        std::thread::sleep(Duration::from_millis(30));
        assert!(coarse_now_ns() > a);
    }
}
