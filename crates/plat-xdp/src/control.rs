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
}

/// Starts `plat-xdp-ctl`: every `heartbeat` it stores `now + deadline`
/// (capped by `cap_ns`, e.g. the HA self-fence instant) if `healthy()`
/// says the sweeper and workers made progress, else counts a stall and
/// lets the deadline run out; every [`GRACE_INTERVAL`] it runs one grace
/// period and recycles slots. Stops (and disables the fast path) when
/// `stop` is set. The integrity checks of plan §9 are the caller's (WU5).
#[cfg(target_os = "linux")]
pub fn spawn<H, C>(
    control: XdpControl,
    mirror: Arc<XdpMirror>,
    timing: ControlTiming,
    counters: Arc<ControlCounters>,
    stop: Arc<AtomicBool>,
    mut healthy: H,
    mut cap_ns: C,
) -> io::Result<JoinHandle<()>>
where
    H: FnMut() -> bool + Send + 'static,
    C: FnMut() -> Option<u64> + Send + 'static,
{
    let tick = GRACE_INTERVAL.min(timing.heartbeat);
    std::thread::Builder::new().name("plat-xdp-ctl".into()).spawn(move || {
        let mut since_beat = Duration::ZERO;
        let mut since_grace = Duration::ZERO;
        while !stop.load(Ordering::Acquire) {
            if since_beat >= timing.heartbeat {
                since_beat = Duration::ZERO;
                if healthy() {
                    let d = coarse_now_ns().saturating_add(timing.deadline.as_nanos() as u64);
                    control.heartbeat(cap_ns().map_or(d, |c| d.min(c)));
                } else {
                    counters.heartbeat_stalls.fetch_add(1, Ordering::Relaxed);
                }
            }
            if since_grace >= GRACE_INTERVAL {
                since_grace = Duration::ZERO;
                match grace_period() {
                    Ok(()) => {
                        after_grace_period(&mirror);
                    }
                    Err(_) => {
                        counters.grace_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            std::thread::sleep(tick);
            since_beat += tick;
            since_grace += tick;
        }
        control.disable();
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::HeapWords;

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
        let s = m.install(&e, 0).unwrap_or(u32::MAX);
        assert!(m.retire(s, &e).is_ok());
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
