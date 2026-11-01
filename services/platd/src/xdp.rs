//! `[xdp]` wiring (POAM-016 Phase 1, plan §4.4, §5, §9): the XDP fast path
//! for established UDP sessions, attached by the privileged one-shot
//! `plat-xdp-loader` and driven here without privileges.
//!
//! Start-up, in order (every refusal leaves the data plane TUN-only and is
//! audited as `xdp_fastpath_state` `disabled` with its reason):
//!
//! 1. [`preflight`] (before anything else): `[xdp]` enabled in a build
//!    without the `xdp` feature, or off Linux, refuses the start.
//! 2. [`attach`] (engine built, workers not started):
//!    `membarrier(MEMBARRIER_CMD_GLOBAL)` probe (`unsupported_host`), the
//!    loader's state file names this binary's object (`object_mismatch`),
//!    the pins open with their shapes and the frozen `CONFIG` equals this
//!    configuration's digest (`config_mismatch`, `maps_unavailable`); only
//!    then `Nat64::set_mirror`.
//! 3. [`Attached::enable`] (workers running): `CONTROL` gets the TUN's
//!    ifindex and MTU and a first deadline (`xdp_fastpath_state`
//!    `enabled` / `start`), then `plat-xdp-ctl` runs the heartbeat (only
//!    while the sweeper and every worker make progress), the grace periods,
//!    the stale-generation GC and the 10 s integrity check; at shutdown it
//!    disables the fast path (`shutdown`).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-6, CM-7 - off unless configured; a build or host that
//!   cannot run it refuses the configuration or keeps the fast path off
//! - NIST 800-53: SI-7 - the fast path is enabled only when the attached
//!   object and the frozen parameters match this binary and configuration,
//!   re-checked every 10 s
//! - NIST 800-53: SC-24 - dead-man deadline driven by real progress of the
//!   sweeper and workers, capped by the HA lease self-fence instant
//! - NIST 800-53: AU-2, AU-12 - every fast-path state transition is
//!   audited (`xdp_fastpath_state`, schema 8)
//! - NIST 800-53: AC-6 - `platd` only opens pins (`/run/plat/bpf`); it
//!   never loads or attaches programs

use plat_audit::XdpStart;
use plat_common::Config;

/// Refuses a start whose `[xdp]` this build or OS cannot run (plan §4.5).
pub fn preflight(cfg: &Config) -> Result<(), String> {
    if !cfg.xdp.enabled {
        return Ok(());
    }
    if !cfg!(feature = "xdp") {
        return Err("xdp.enabled = true, but platd was built without the `xdp` feature".into());
    }
    if !cfg!(target_os = "linux") {
        return Err("xdp.enabled = true needs Linux".into());
    }
    Ok(())
}

/// The `service_start` XDP fields (schema 8).
pub fn start_fields(cfg: &Config) -> XdpStart {
    XdpStart {
        mode: cfg.xdp.mode_str(),
        object_sha256: cfg.xdp.enabled.then(object_sha256).flatten(),
        interfaces: if cfg.xdp.enabled { cfg.xdp.interface_names() } else { String::new() },
    }
}

#[cfg(feature = "xdp")]
fn object_sha256() -> Option<[u8; 32]> {
    Some(plat_xdp::object_sha256())
}

#[cfg(not(feature = "xdp"))]
fn object_sha256() -> Option<[u8; 32]> {
    None
}

#[cfg(all(feature = "xdp", target_os = "linux"))]
pub use imp::*;

#[cfg(all(feature = "xdp", target_os = "linux"))]
mod imp {
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use plat_audit::{AuditSink, Event, XdpReason, XdpState};
    use plat_common::{Clock, Config, Counters};
    use plat_nat64::Nat64;
    use plat_xdp::control::{
        self, ControlCounters, ControlHooks, ControlTiming, Fault, GC_SCAN_PER_TICK, Transition, Watch, XdpControl,
    };
    use plat_xdp::load::{AttachedState, LoadParams, config_record, read_state};
    use plat_xdp::maps::{OpenError, XdpMaps};
    use plat_xdp::mirror::XdpMirror;
    use plat_xdp::slots::PARTITIONS;
    use plat_xdp_core::abi::ConfigRec;

    use crate::metrics::Section;

    fn emit(sink: &AuditSink, state: XdpState, reason: XdpReason) {
        sink.emit(Event::XdpFastpathState { ts_us: Clock::wall_us(), state, reason });
    }

    fn reason(f: Fault) -> XdpReason {
        match f {
            Fault::ConfigMismatch => XdpReason::ConfigMismatch,
            Fault::ObjectMismatch => XdpReason::ObjectMismatch,
            Fault::LinkMismatch => XdpReason::LinkMismatch,
            Fault::MapsUnavailable => XdpReason::MapsUnavailable,
            Fault::UnsupportedHost => XdpReason::UnsupportedHost,
        }
    }

    /// The fast path set up in the engine, not yet enabled.
    pub struct Attached {
        maps: Arc<XdpMaps>,
        mirror: Arc<XdpMirror>,
        expected: ConfigRec,
        state: AttachedState,
    }

    /// Step 2 of the module docs. `None`: TUN-only (the reason is
    /// audited and logged).
    pub fn attach(cfg: &Config, nat: &mut Nat64, clock: &Clock, sink: &AuditSink) -> Option<Attached> {
        attach_at(cfg, nat, clock, sink, Path::new(plat_xdp::PIN_DIR), Path::new(plat_xdp::STATE_FILE))
    }

    pub(crate) fn attach_at(
        cfg: &Config,
        nat: &mut Nat64,
        clock: &Clock,
        sink: &AuditSink,
        pins: &Path,
        state_file: &Path,
    ) -> Option<Attached> {
        if !cfg.xdp.enabled {
            return None;
        }
        let refuse = |r: XdpReason, what: String| {
            tracing::error!(reason = r.as_str(), "XDP fast path stays off: {what}");
            emit(sink, XdpState::Disabled, r);
            None
        };
        // Decision Q5 / SEC-007: no forced grace period, no safe slot reuse.
        if let Err(e) = control::probe_grace_period() {
            return refuse(XdpReason::UnsupportedHost, format!("membarrier(MEMBARRIER_CMD_GLOBAL): {e}"));
        }
        let state = match read_state(state_file) {
            Ok(s) => s,
            Err(e) => return refuse(XdpReason::MapsUnavailable, format!("{}: {e}", state_file.display())),
        };
        let mine = plat_xdp::object_sha256_hex();
        if state.object_sha256 != mine {
            return refuse(
                XdpReason::ObjectMismatch,
                format!("attached object {} is not this binary's {mine}", state.object_sha256),
            );
        }
        // The digest binds this attach's nonce (SEC-001): only the maps
        // the state file describes match.
        let mut lp = LoadParams::from_config(cfg);
        lp.nonce = state.nonce;
        let expected = config_record(&lp, &plat_xdp::object_sha256());
        let maps = match XdpMaps::open_pinned(pins, &expected) {
            Ok(m) => Arc::new(m),
            Err(e @ OpenError::ConfigMismatch) => return refuse(XdpReason::ConfigMismatch, e.to_string()),
            Err(e) => return refuse(XdpReason::MapsUnavailable, e.to_string()),
        };
        // SEC-001: only maps no earlier process used (a platd restart
        // without a new attach would otherwise revive its LIVE records).
        if let Err(s) = maps.claim_fresh() {
            return refuse(
                XdpReason::StaleMaps,
                format!("pinned maps already used ({s}); restart plat-xdp.service to attach fresh maps"),
            );
        }
        let mirror =
            Arc::new(XdpMirror::new(&maps, PARTITIONS).with_clock(clock.clone(), control::engine_origin_ns(clock)));
        nat.set_mirror(mirror.clone());
        tracing::info!(
            sessions = maps.sessions(),
            slots = maps.slots(),
            prog_id = state.prog_id,
            "XDP fast path attached"
        );
        Some(Attached { maps, mirror, expected, state })
    }

    /// Progress sources for the heartbeat (plan §9).
    pub struct Progress {
        /// Completed sweeper passes.
        pub sweeps: Arc<AtomicU64>,
        pub workers: Vec<Arc<Counters>>,
        /// `CLOCK_MONOTONIC_COARSE` ns of the HA lease self-fence instant.
        pub cap: Box<dyn FnMut() -> Option<u64> + Send>,
    }

    /// What `run` keeps of a running fast path: the publisher and control
    /// threads (joined before the audit queue closes) and the metrics
    /// section (`None` when enabling failed; the publisher still keeps the
    /// writer's queues drained).
    pub struct Running {
        pub threads: Vec<JoinHandle<()>>,
        pub metrics: Option<Section>,
    }

    /// Health over windows: the sweeper must finish a pass within
    /// `sweep_window` and every worker housekeep within `worker_window`.
    struct Health {
        sweeps: Arc<AtomicU64>,
        workers: Vec<Arc<Counters>>,
        mirror: Arc<XdpMirror>,
        sweep: Watch,
        alive: Vec<Watch>,
        publisher: Watch,
        sweep_window: u64,
        worker_window: u64,
    }

    impl Health {
        /// Every source moved within its window: the sweeper, each worker
        /// and (SEC-002) the publisher thread, whose stall would leave new
        /// sessions unpublished and retired entries undeleted.
        fn check(&mut self) -> bool {
            let now = control::coarse_now_ns();
            let mut ok = self.sweep.ok(self.sweeps.load(Ordering::Relaxed), now, self.sweep_window);
            for (w, watch) in self.workers.iter().zip(self.alive.iter_mut()) {
                ok &= watch.ok(w.alive(), now, self.worker_window);
            }
            ok & self.publisher.ok(self.mirror.publisher_passes(), now, self.worker_window)
        }
    }

    impl Attached {
        /// Step 3 of the module docs. `aborted` receives the program's
        /// `aborted` count for the periodic `dataplane_counter` record
        /// (`xdp_aborted`), refreshed with the integrity check.
        pub fn enable(
            self,
            cfg: &Config,
            nat: Arc<Nat64>,
            progress: Progress,
            sink: AuditSink,
            stop: Arc<AtomicBool>,
            aborted: Arc<AtomicU64>,
        ) -> Running {
            let Self { maps, mirror, expected, state } = self;
            // Every map syscall of the writer runs on this thread (WU5
            // gate: none under a `bib4` lock).
            let mut threads = Vec::new();
            match control::spawn_publisher(mirror.clone(), stop.clone()) {
                Ok(t) => threads.push(t),
                Err(e) => {
                    // SEC-002: audited below (maps_unavailable) with the
                    // fast path left off.
                    tracing::error!("plat-xdp-pub: {e}");
                }
            }
            let fail = |threads| Running { threads, metrics: None };
            let control = XdpControl::new(&maps);
            let tun = &cfg.dataplane.interface;
            let timing = ControlTiming {
                heartbeat: Duration::from_millis(u64::from(cfg.xdp.heartbeat_ms)),
                deadline: Duration::from_millis(u64::from(cfg.xdp.deadline_ms)),
            };
            let Progress { sweeps, workers, mut cap } = progress;
            // SEC-005: the first deadline is capped by the HA lease too
            // (a lease not yet held gives a deadline in the past: nothing
            // is forwarded until the first capped heartbeat).
            let first = control::coarse_now_ns().saturating_add(timing.deadline.as_nanos() as u64);
            let first = cap().map_or(first, |c| first.min(c));
            let ok = match (plat_io::netdev::index(tun), plat_io::netdev::mtu(tun)) {
                (Ok(i), Ok(m)) => control.enable(i, m, first),
                (Err(e), _) | (_, Err(e)) => {
                    tracing::error!("XDP fast path stays off: TUN {tun}: {e}");
                    false
                }
            };
            if !ok || threads.is_empty() {
                control.disable();
                emit(&sink, XdpState::Disabled, XdpReason::MapsUnavailable);
                return fail(threads);
            }
            emit(&sink, XdpState::Enabled, XdpReason::Start);

            let counters = Arc::new(ControlCounters::default());
            let n = workers.len();
            let beat = u64::from(cfg.xdp.heartbeat_ms) * 1_000_000;
            let start = control::coarse_now_ns();
            let mut health = Health {
                sweeps,
                workers,
                mirror: mirror.clone(),
                sweep: Watch::new(start),
                alive: vec![Watch::new(start); n],
                publisher: Watch::new(start),
                // The sweeper sleeps one interval, then sweeps for at most
                // half of one; workers housekeep at least every poll
                // (100 ms) or 64 packets.
                sweep_window: (3 * cfg.dataplane.sweep_interval_ms * 1_000_000).max(3 * beat),
                worker_window: (3 * beat).max(1_000_000_000),
            };
            let (gc_nat, gc_mirror) = (nat.clone(), mirror.clone());
            let mut cursor = 0u32;
            let mut buf = Vec::with_capacity(GC_SCAN_PER_TICK as usize);
            let (im, ia) = (maps.clone(), aborted);
            let pins = std::path::PathBuf::from(plat_xdp::PIN_DIR);
            let started = state;
            let ns = sink.clone();
            let hooks = ControlHooks {
                healthy: Box::new(move || health.check()),
                cap_ns: cap,
                integrity: Box::new(move || {
                    if let Ok(s) = plat_xdp::stats::XdpStats::new(&im).snapshot() {
                        ia.store(s.aborted, Ordering::Relaxed);
                    }
                    im.verify(&pins, &expected)?;
                    match read_state(Path::new(plat_xdp::STATE_FILE)) {
                        Ok(s) if s.object_sha256 != started.object_sha256 => Err(Fault::ObjectMismatch),
                        Ok(s) if s.prog_id != started.prog_id => Err(Fault::LinkMismatch),
                        Ok(_) => Ok(()),
                        Err(_) => Err(Fault::MapsUnavailable),
                    }
                }),
                gc: Box::new(move || {
                    let (next, _) =
                        plat_xdp::glue::gc_step(&gc_mirror, gc_nat.state(), cursor, GC_SCAN_PER_TICK, &mut buf);
                    cursor = next;
                }),
                notify: Box::new(move |t| match t {
                    Transition::Stalled => {
                        tracing::warn!("XDP heartbeat withheld: sweeper or a worker made no progress");
                        emit(&ns, XdpState::Disabled, XdpReason::HeartbeatStalled);
                    }
                    Transition::Resumed => emit(&ns, XdpState::Enabled, XdpReason::HeartbeatResumed),
                    Transition::Fault(f) => {
                        tracing::error!(reason = reason(f).as_str(), "XDP fast path disabled");
                        emit(&ns, XdpState::Disabled, reason(f));
                    }
                    Transition::Shutdown => emit(&ns, XdpState::Disabled, XdpReason::Shutdown),
                }),
            };
            match control::spawn(control.clone(), mirror.clone(), timing, counters.clone(), stop, hooks) {
                Ok(t) => threads.push(t),
                Err(e) => {
                    tracing::error!("plat-xdp-ctl: {e}");
                    control.disable();
                    emit(&sink, XdpState::Disabled, XdpReason::MapsUnavailable);
                    return fail(threads);
                }
            }
            let metrics: Section = Box::new(move |o: &mut String| {
                let snap = plat_xdp::stats::XdpStats::new(&maps).snapshot().unwrap_or_default();
                let c = control.read();
                let on = c.enabled == 1 && c.deadline_ns > control::coarse_now_ns();
                plat_xdp::stats::render(o, on, &snap, &mirror, &counters);
            });
            Running { threads, metrics: Some(metrics) }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn cfg(xdp: &str) -> Config {
        Config::from_toml(&format!("{}{xdp}", include_str!("../../../config/platd.example.toml"))).unwrap()
    }

    const ON: &str = "\n[xdp]\nenabled = true\n[[xdp.interfaces]]\nname = \"eth0\"\nrole = \"access\"\n";

    #[test]
    fn off_by_default_and_recorded_as_off() {
        let c = cfg("");
        assert!(preflight(&c).is_ok());
        assert_eq!(start_fields(&c), XdpStart { mode: "off", object_sha256: None, interfaces: String::new() });
    }

    /// Plan §4.5: `[xdp]` enabled needs the `xdp` feature (and Linux), or
    /// the start is refused naming it.
    #[test]
    fn enabled_needs_the_feature_and_linux() {
        let c = cfg(ON);
        let r = preflight(&c);
        if cfg!(all(feature = "xdp", target_os = "linux")) {
            assert!(r.is_ok());
        } else {
            let e = r.unwrap_err();
            assert!(e.contains("`xdp` feature") || e.contains("Linux"), "{e}");
        }
        let f = start_fields(&c);
        assert_eq!((f.mode, f.interfaces.as_str()), ("native", "eth0"));
        assert_eq!(f.object_sha256.is_some(), cfg!(feature = "xdp"));
    }
}
