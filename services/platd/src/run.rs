//! Daemon lifecycle: FIPS gate → TLS material → audit → state → workers →
//! sweeper → management → signals.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
#[cfg(not(feature = "tls"))]
use plat_audit::FipsMark;
use plat_audit::{AuditSink, Event, LifecycleKind, Logger, LoggerHandle, NodeIdent};
use plat_common::{Clock, Config, Counter, Counters, DropReason};
use plat_io::PacketQueue;
use plat_nat64::{AdoptInput, AdoptMeta, ClusterSetup, Nat64, ReplHub, ReplProducer, Verdict};
use plat_xlat::HEADROOM;

use crate::metrics;

/// Largest packet a TUN read can return.
const MAX_PKT: usize = 65_535;

/// Transmits one packet, counting it (TxPackets/TxBytes) or the failure.
/// Never blocks: a full device queue (`EAGAIN` / `WouldBlock`) drops the
/// packet and counts `TxQueueFull` (back-pressure); any other error counts
/// `IoErrors`.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-4 - back-pressure is visible separately from faults.
#[inline]
fn transmit<Q: PacketQueue>(q: &mut Q, pkt: &[u8], counters: &Counters) {
    match q.send(pkt) {
        Ok(()) => {
            counters.inc(Counter::TxPackets);
            counters.add(Counter::TxBytes, pkt.len() as u64);
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => counters.inc(Counter::TxQueueFull),
        Err(_) => counters.inc(Counter::IoErrors),
    }
}

/// Run-to-completion worker: read → translate in place → write.
pub fn worker<Q: PacketQueue>(
    mut q: Q,
    nat: Arc<Nat64>,
    counters: Arc<Counters>,
    id: u16,
    repl: Option<ReplProducer>,
    stop: Arc<AtomicBool>,
) {
    let mut buf = vec![0u8; HEADROOM + MAX_PKT].into_boxed_slice();
    let mut ctx = nat.new_worker(counters.clone(), id.wrapping_mul(0x9e37));
    let mut since_housekeep = 0u32;
    if let Some(r) = repl {
        ctx = ctx.with_repl(r);
    }
    while !stop.load(Ordering::Relaxed) {
        // Fragment expiry and the fragment gauge, every 64 packets and when
        // idle (no blocking, no allocation).
        since_housekeep += 1;
        if since_housekeep >= 64 {
            since_housekeep = 0;
            nat.housekeep(&mut ctx);
        }
        let n = match q.recv(&mut buf[HEADROOM..]) {
            Ok(Some(n)) => n,
            Ok(None) => {
                since_housekeep = 64;
                continue;
            }
            Err(e) => {
                counters.inc(Counter::IoErrors);
                tracing::warn!(worker = id, "recv: {e}");
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        counters.inc(Counter::RxPackets);
        counters.add(Counter::RxBytes, n as u64);
        match nat.process(&mut buf, HEADROOM, n, &mut ctx) {
            Verdict::Forward { start, len } => transmit(&mut q, &buf[start..start + len], &counters),
            // RFC 7915 §4: translator-generated IPv6 fragments, in order.
            Verdict::ForwardFragments { .. } => {
                for f in ctx.fragments() {
                    transmit(&mut q, f, &counters);
                }
            }
            Verdict::Consumed | Verdict::Drop(_) => {}
        }
    }
}

/// `dataplane.workers = 0`: one worker per CPU, leaving one CPU for the
/// logger, sweeper, clock and kernel TUN work (at least one worker).
fn worker_count(cfg: &Config) -> usize {
    match cfg.dataplane.workers {
        0 => std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1).max(1)),
        n => n,
    }
}

/// Emits the stop record and waits for the logger to drain (NIST 800-53
/// AU-12: every exit after start is recorded). Callers drop every other
/// `AuditSink` clone (including the engine's) first.
fn stop_audit(sink: AuditSink, hooks: &HookSink, logger: LoggerHandle) {
    sink.emit(Event::Lifecycle { ts_us: Clock::wall_us(), kind: LifecycleKind::Stop, fips: None, cluster: None });
    drop(sink);
    // The revocation checker (held by the syslog senders' TLS configs)
    // reaches the queue only through this slot; empty it so the logger
    // sees the queue disconnect and drains.
    hooks.detach();
    logger.join();
}

/// An `AuditSink` slot for hooks owned by long-lived TLS objects (the
/// revocation checker inside the syslog senders' and the management
/// listener's TLS configs). Those objects outlive the logger's input, so
/// they must not hold a sink directly: `detach` at shutdown releases it.
#[derive(Debug, Clone, Default)]
pub struct HookSink(Arc<RwLock<Option<AuditSink>>>);

impl HookSink {
    pub fn new(sink: AuditSink) -> Self {
        Self(Arc::new(RwLock::new(Some(sink))))
    }

    /// Queues `ev` without blocking (lost and counted if the queue is
    /// full; dropped after `detach`).
    #[cfg(feature = "tls")]
    pub fn emit(&self, ev: Event) {
        if let Some(s) = self.0.read().as_ref() {
            s.emit(ev);
        }
    }

    pub fn detach(&self) {
        self.0.write().take();
    }
}

/// SC-13 start gate for a build without the `tls` feature: there is no
/// FIPS module, so the default `tls.require_fips` refuses to start, and a
/// TLS configuration is refused outright.
#[cfg(not(feature = "tls"))]
fn fips_gate(cfg: &Config) -> Result<FipsMark, String> {
    if cfg.uses_tls() {
        return Err("TLS is configured but platd was built without TLS support (feature `tls`)".into());
    }
    if cfg.tls.require_fips {
        return Err("platd was built without the FIPS module (feature `tls`); refusing to start \
                    (tls.require_fips = true)"
            .into());
    }
    Ok(FipsMark { active: false, provider: "none" })
}

#[cfg(feature = "tls")]
use crate::tls::fips_gate;

#[cfg(target_os = "linux")]
fn open_queues(cfg: &Config, n: usize) -> std::io::Result<Vec<plat_io::tun::TunQueue>> {
    plat_io::tun::TunQueue::open_multi(&cfg.dataplane.interface, n)
}

#[cfg(not(target_os = "linux"))]
fn open_queues(_cfg: &Config, _n: usize) -> std::io::Result<Vec<plat_io::mem::MemQueue>> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "the TUN data plane requires Linux"))
}

/// The engine for the configured partition: legacy contiguous, static
/// slices (every node serves its rendezvous primaries of the full member
/// set), or HA (every slice Inactive until the cluster acquires it; the
/// replication rings are returned, one per worker plus the sweeper's).
pub(crate) type Engine = (Nat64, Option<(Arc<ReplHub>, Vec<ReplProducer>)>);

pub(crate) fn build_engine(cfg: &Config, workers: usize, sink: &AuditSink, clock: &Clock) -> Result<Engine, String> {
    if cfg.cluster.partition != plat_common::config::Partition::Slices {
        return Ok((Nat64::new(cfg, plat_cluster::owned(cfg), sink.clone(), clock.clone())?, None));
    }
    let setup = ClusterSetup::from_config(cfg)?;
    let slices = setup.slices.len();
    let nat = Nat64::new_cluster(cfg, setup, sink.clone(), clock.clone())?;
    if let Some(h) = cfg.cluster.ha_active() {
        let (hub, prods) = ReplHub::new(workers + 1, h.repl_ring_entries as usize, slices);
        return Ok((nat, Some((hub, prods))));
    }
    // Static slices: adopt this node's primaries at once (AU-12: each with
    // its acquire record before use).
    if let Some((_, primary, _)) = crate::cluster::home_slices(cfg) {
        for s in primary {
            let meta = AdoptMeta { epoch: 0, prev_owner: None, reason: plat_audit::AcquireReason::Startup };
            nat.state()
                .adopt_slice(s, &AdoptInput { in_sync: true, ..AdoptInput::default() }, meta)
                .map_err(|e| format!("slice {s}: {e:?}"))?;
        }
    }
    Ok((nat, None))
}

pub fn run(cfg: Config) -> ExitCode {
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        if let Err(e) = signal_hook::flag::register(sig, stop.clone()) {
            tracing::error!("signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    let owned = crate::cluster::owned_addrs(&cfg);
    let n = worker_count(&cfg);
    let counters: Vec<Arc<Counters>> = (0..n).map(|_| Arc::new(Counters::default())).collect();

    // SC-13: the FIPS module is installed and checked before anything else
    // (no `service_start` is written when the start is refused).
    let fips = match fips_gate(&cfg) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(fips = fips.active, provider = fips.provider, "FIPS status");

    // The queue exists before the TLS material is loaded, so revocation
    // records produced from here on wait in it until the logger is up.
    let (sink, rx) = AuditSink::bounded(cfg.audit.queue_capacity);
    let hooks = HookSink::new(sink.clone());
    #[cfg(feature = "tls")]
    let tls = match crate::tls::prepare(&cfg, &hooks) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };

    // Audit first: nothing may be translated before attribution logging is up (AU-12).
    let node = NodeIdent { name: cfg.node.name.clone(), id: cfg.node.id, pid: std::process::id() };
    let summary_src = counters.clone();
    let logger = Logger::new(cfg.audit.clone(), node, rx, sink.stats().clone()).with_counters(Box::new(move || {
        DropReason::ALL
            .iter()
            .map(|r| (r.as_str(), summary_src.iter().map(|c| c.drops(*r)).sum()))
            .filter(|(_, v)| *v > 0)
            .collect()
    }));
    #[cfg(feature = "tls")]
    let logger = logger.with_tls(tls.logger_options(&cfg));
    let logger = match logger.spawn() {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("audit destinations: {e}");
            return ExitCode::FAILURE;
        }
    };
    sink.emit(Event::Lifecycle {
        ts_us: Clock::wall_us(),
        kind: LifecycleKind::Start,
        fips: Some(fips),
        cluster: Some(crate::cluster::cluster_start(&cfg)),
    });

    let clock = Clock::new();
    let (nat, repl) = match build_engine(&cfg, n, &sink, &clock) {
        Ok((nat, repl)) => (Arc::new(nat), repl),
        Err(e) => {
            tracing::error!("{e}");
            stop_audit(sink, &hooks, logger);
            return ExitCode::FAILURE;
        }
    };

    let queues = match open_queues(&cfg, n) {
        Ok(q) => q,
        Err(e) => {
            tracing::error!("opening {} ({n} queues): {e}", cfg.dataplane.interface);
            stop.store(true, Ordering::Relaxed);
            drop(nat);
            stop_audit(sink, &hooks, logger);
            return ExitCode::FAILURE;
        }
    };
    // CP-10: the cluster runtime (peer channel, membership, replication,
    // hooks) starts before the workers; every slice stays Inactive until
    // it is acquired (and logged).
    let (hub, mut producers) = match repl {
        Some((h, p)) => (Some(h), p.into_iter().map(Some).collect::<Vec<_>>()),
        None => (None, Vec::new()),
    };
    let sweep_repl = if producers.len() > n { producers.pop().flatten() } else { None };
    #[cfg(feature = "tls")]
    let cluster = match (&hub, tls.peer.clone()) {
        (Some(h), Some(peer)) => match crate::cluster::start(&cfg, nat.clone(), h.clone(), sink.clone(), peer) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::error!("{e}");
                stop.store(true, Ordering::Relaxed);
                drop(queues);
                drop(producers);
                drop(nat);
                stop_audit(sink, &hooks, logger);
                return ExitCode::FAILURE;
            }
        },
        _ => None,
    };
    #[cfg(not(feature = "tls"))]
    let _ = &hub;
    let cores = if cfg.dataplane.pin_cpus { core_affinity::get_core_ids().unwrap_or_default() } else { Vec::new() };

    let mut threads = Vec::new();
    {
        let (clock, stop) = (clock.clone(), stop.clone());
        threads.push(std::thread::Builder::new().name("plat-clock".into()).spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                clock.tick();
                std::thread::sleep(Duration::from_millis(10));
            }
        }));
    }
    {
        let (nat, stop) = (nat.clone(), stop.clone());
        let every = Duration::from_millis(cfg.dataplane.sweep_interval_ms);
        threads.push(std::thread::Builder::new().name("plat-sweep".into()).spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(every);
                let s = nat.state().sweep_with(sweep_repl.as_ref());
                tracing::debug!(?s, "sweep");
            }
        }));
    }
    for (i, q) in queues.into_iter().enumerate() {
        let (nat, c, stop) = (nat.clone(), counters[i].clone(), stop.clone());
        let prod = producers.get_mut(i).and_then(Option::take);
        let core = cores.get(i % cores.len().max(1)).copied();
        threads.push(std::thread::Builder::new().name(format!("plat-w{i}")).spawn(move || {
            if let Some(core) = core {
                core_affinity::set_for_current(core);
            }
            worker(q, nat, c, i as u16, prod, stop);
        }));
    }
    // IA-5(2): background revocation refresher (joined before the logger
    // stops).
    #[cfg(feature = "tls")]
    if let Some(c) = tls.checker.as_ref().filter(|c| c.settings().mode != plat_common::config::RevocationMode::Off) {
        threads.push(plat_tls::spawn_refresher(c.clone(), stop.clone()));
    }
    #[cfg(feature = "tls")]
    let extra = tls.sections();
    #[cfg(not(feature = "tls"))]
    let extra = Vec::new();
    // L17: kernel-side TUN drops (back-pressure) are otherwise invisible.
    let mut extra = extra;
    extra.push(metrics::tun_section(cfg.dataplane.interface.clone()));
    #[cfg(feature = "tls")]
    let cluster_src = cluster.as_ref().map(|c| {
        let (m, j, h) = (c.shared.clone(), c.shared.clone(), c.shared.clone());
        extra.push(Box::new(move |o: &mut String| m.render_metrics(o)));
        metrics::ClusterSource { json: Box::new(move || j.view_json()), health: Box::new(move || h.health_problem()) }
    });
    #[cfg(not(feature = "tls"))]
    let cluster_src = None;
    let src = metrics::Sources {
        nat: nat.clone(),
        workers: counters.clone(),
        audit: sink.clone(),
        fips: fips.active,
        extra,
        cluster: cluster_src,
    };
    #[cfg(feature = "tls")]
    let mut tls = tls;
    let metrics = cfg.management.listen.map(|addr| {
        #[cfg(feature = "tls")]
        if let Some(m) = tls.mgmt.take() {
            return crate::mgmt::spawn(
                addr,
                m,
                src,
                sink.clone(),
                tls.mgmt_stats.clone(),
                tls.limiter.clone(),
                stop.clone(),
            );
        }
        metrics::spawn(addr, src, stop.clone())
    });

    // Any thread or listener that failed to start is a failed start: stop
    // cleanly (audit drained, `service_stop` recorded) and exit non-zero.
    let mut failed = false;
    if let Some(Err(e)) = &metrics {
        tracing::error!("management listener: {e}");
        failed = true;
    }
    if let Some(e) = threads.iter().find_map(|t| t.as_ref().err()) {
        tracing::error!("starting threads: {e}");
        failed = true;
    }
    if failed {
        stop.store(true, Ordering::Relaxed);
    }

    tracing::info!(
        node = %cfg.node.name,
        workers = n,
        pool_addrs = owned.len(),
        prefix = %cfg.translation.nat64_prefix,
        "platd running"
    );
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
    }
    tracing::info!("shutting down");
    // Hand owned slices over (bounded by cluster.ha.shutdown_handover_ms)
    // and join the cluster threads before the audit queue closes.
    #[cfg(feature = "tls")]
    if let Some(c) = cluster {
        c.shutdown();
    }

    for t in threads.into_iter().flatten() {
        let _ = t.join();
    }
    if let Some(Ok(m)) = metrics {
        let _ = m.join();
    }
    #[cfg(feature = "tls")]
    if let Some(c) = &tls.checker {
        c.notify();
    }
    // Drop every AuditSink clone so the logger drains and exits.
    // With HA, owned slices were released (or handed over) above.
    // POAM: POAM-009 - live port blocks are not released (no `nat_port_block_release`
    // records) at shutdown; the release needs a plat-nat64 drain API. SIEM
    // correlation closes them at `service_stop`.
    drop(nat);
    stop_audit(sink, &hooks, logger);
    if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use plat_io::mem;
    use plat_packet::{be16, be32, checksum as ck, proto, put16};
    use plat_xlat::siit::{write_v4_header, write_v6_header};

    const PREFIX: u128 = 0x0064_ff9b_0001_0000_0000_0000_0000_0000;
    const CLIENT: u128 = 0x2001_0db8_0100_0001_0000_0000_0000_0001;
    const SERVER: u32 = 0xcb00_7105; // 203.0.113.5

    fn udp6(payload: &[u8]) -> Vec<u8> {
        let l = 8 + payload.len();
        let mut p = vec![0u8; 40 + l];
        let dst = PREFIX | u128::from(SERVER);
        write_v6_header(&mut p, 0, l as u16, proto::UDP, 64, CLIENT, dst);
        put16(&mut p, 40, 40000);
        put16(&mut p, 42, 5353);
        put16(&mut p, 44, l as u16);
        p[48..].copy_from_slice(payload);
        let c = ck::finish(ck::pseudo_v6(CLIENT, dst, proto::UDP, l as u32) + ck::sum(&p[40..]));
        put16(&mut p, 46, ck::udp_nonzero(c));
        p
    }

    fn udp4_df0(dst: u32, dport: u16, payload: &[u8]) -> Vec<u8> {
        let l = 28 + payload.len();
        let mut p = vec![0u8; l];
        write_v4_header(&mut p, 0, l as u16, 0x4321, false, false, 0, 64, proto::UDP, SERVER, dst);
        put16(&mut p, 20, 5353);
        put16(&mut p, 22, dport);
        put16(&mut p, 24, (8 + payload.len()) as u16);
        p[28..].copy_from_slice(payload);
        let c = ck::finish(ck::pseudo_v4(SERVER, dst, proto::UDP, (l - 20) as u16) + ck::sum(&p[20..]));
        put16(&mut p, 26, c);
        p
    }

    /// H1 / RFC 7915 §4: the worker transmits every translator-generated
    /// fragment and counts each one.
    #[test]
    fn worker_transmits_every_fragment() {
        // The fixture's server is in documentation space (non-global), so it opts in explicitly.
        let text = include_str!("../../../config/platd.example.toml")
            .replace("allow_non_global_destinations = false", "allow_non_global_destinations = true");
        let cfg = Config::from_toml(&text).unwrap();
        let (sink, _rx) = AuditSink::bounded(4096);
        let nat = Arc::new(Nat64::new(&cfg, plat_cluster::owned(&cfg), sink, Clock::new()).unwrap());
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (dev, mut host) = mem::pair(64);
        let w = {
            let (nat, counters, stop) = (nat.clone(), counters.clone(), stop.clone());
            std::thread::spawn(move || worker(dev, nat, counters, 0, None, stop))
        };
        let mut buf = vec![0u8; 70_000];
        let t = std::time::Instant::now();
        let mut next = |host: &mut mem::MemQueue| loop {
            assert!(t.elapsed() < Duration::from_secs(5), "worker did not transmit the expected packet");
            if let Some(n) = host.recv(&mut buf).unwrap() {
                break buf[..n].to_vec();
            }
        };

        host.send(&udp6(b"hello")).unwrap();
        let v4 = next(&mut host);
        let (mapped, mport) = (be32(&v4, 12), be16(&v4, 20));
        let payload = vec![0x5a; 1400];
        host.send(&udp4_df0(mapped, mport, &payload)).unwrap();
        let f1 = next(&mut host);
        let f2 = next(&mut host);
        stop.store(true, Ordering::Relaxed);
        w.join().unwrap();

        for f in [&f1, &f2] {
            assert_eq!(f[0] >> 4, 6);
            assert_eq!(f[6], proto::FRAGMENT, "IPv6 Fragment Header");
            assert!(f.len() <= 1280);
        }
        assert_eq!(f1.len(), 1280);
        // Fragment payloads (after 40 + 8 bytes of headers) carry the 8-byte
        // UDP header plus the IPv4 payload.
        assert_eq!(f1.len() + f2.len() - 2 * 48, 8 + payload.len());
        assert_eq!(counters.get(Counter::TxPackets), 3, "one IPv4 packet + two fragments");
        assert_eq!(counters.get(Counter::TxBytes), (v4.len() + f1.len() + f2.len()) as u64);
        assert_eq!(counters.get(Counter::IoErrors), 0);
    }

    /// The example config with the audit file in `dir`, a small queue, and
    /// an interface name no kernel accepts (IFNAMSIZ), so `run` always
    /// stops after the audit start-up, even as root on Linux.
    #[cfg(feature = "tls")]
    fn start_cfg(dir: &std::path::Path, extra: &str) -> Config {
        let text = include_str!("../../../config/platd.example.toml")
            .replace("/var/log/plat/nat64-audit.jsonl", &dir.join("audit.jsonl").display().to_string())
            .replace("queue_capacity = 1048576", "queue_capacity = 4096")
            .replace("min_free_bytes = 2147483648", "min_free_bytes = 1048576")
            .replace("interface = \"plat0\"", "interface = \"plat0-name-longer-than-ifnamsiz\"")
            .replace("[[audit.syslog]]\naddress = \"198.51.100.10:514\"\ntransport = \"udp\"\nformat = \"json\"\napp_name = \"platd\"\n", "")
            .replace("# [management.tls]", extra);
        Config::from_toml(&text).unwrap()
    }

    /// SC-13 (Q1): with `tls.require_fips` (default) and the FIPS module
    /// inactive, `run` refuses to start before the logger exists: exit
    /// non-zero, no audit file, no `service_start`; with or without TLS
    /// configured. `require_fips = false` starts and records
    /// `plat.fips=false`. One test, because the hook is process-global.
    #[cfg(feature = "tls")]
    #[test]
    fn require_fips_refuses_start_when_module_inactive() {
        let mgmt_tls = "[management.tls]\ncert_file = \"/nonexistent/mgmt.pem\"\nkey_file = \"/nonexistent/mgmt.key\"\n\
                        client_ca_file = \"/nonexistent/ca.pem\"\nallowed_clients = [\"dns:prom.test\"]\n# [x]";
        let plain_dir = crate::test_pki::TempDir::new("fips-plain");
        let tls_dir = crate::test_pki::TempDir::new("fips-tls");
        let plain = start_cfg(plain_dir.path(), "# [management.tls]");
        let with_tls = start_cfg(tls_dir.path(), mgmt_tls);
        assert!(with_tls.uses_tls() && !plain.uses_tls());

        let _serial = crate::test_pki::FIPS_HOOK.lock();
        plat_tls::fips::force_inactive_for_tests(true);
        let refused_plain = run(plain.clone());
        let refused_tls = run(with_tls.clone());
        let gate = fips_gate(&with_tls);
        let mut lax = plain.clone();
        lax.tls.require_fips = false;
        let lax_mark = fips_gate(&lax);
        plat_tls::fips::force_inactive_for_tests(false);

        assert_eq!(refused_plain, ExitCode::FAILURE);
        assert_eq!(refused_tls, ExitCode::FAILURE);
        for d in [&plain_dir, &tls_dir] {
            assert!(!d.path().join("audit.jsonl").exists(), "refused before the logger: no service_start");
        }
        let e = gate.unwrap_err();
        assert!(e.contains("refusing to start") && e.contains("require_fips"), "{e}");
        assert_eq!(lax_mark.unwrap(), plat_audit::FipsMark { active: false, provider: "aws-lc-rs-fips" });
        assert_eq!(fips_gate(&plain).unwrap(), plat_audit::FipsMark { active: true, provider: "aws-lc-rs-fips" });
    }

    /// SC-13 / AU-3: a start records the FIPS state on `service_start`
    /// (the data plane then fails to open the bogus interface and the
    /// daemon stops cleanly with `service_stop`).
    #[cfg(feature = "tls")]
    #[test]
    fn service_start_records_fips_state() {
        let dir = crate::test_pki::TempDir::new("fips-start");
        let cfg = start_cfg(dir.path(), "# [management.tls]");
        let serial = crate::test_pki::FIPS_HOOK.lock();
        assert_eq!(run(cfg), ExitCode::FAILURE, "no TUN device in tests");
        drop(serial);
        let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let start = text.lines().find(|l| l.contains("\"event.action\":\"service_start\"")).expect("service_start");
        assert!(start.contains("\"plat.fips\":true,\"plat.fips_provider\":\"aws-lc-rs-fips\""), "{start}");
        assert!(text.contains("\"event.action\":\"service_stop\""));
    }

    /// PERF-107: a full device queue is counted as back-pressure, not as
    /// an I/O error.
    #[test]
    fn full_tx_queue_counts_back_pressure() {
        let c = Counters::default();
        let (mut dev, _host) = mem::pair(1);
        transmit(&mut dev, b"first", &c);
        transmit(&mut dev, b"second", &c);
        assert_eq!(c.get(Counter::TxPackets), 1);
        assert_eq!(c.get(Counter::TxQueueFull), 1);
        assert_eq!(c.get(Counter::IoErrors), 0);
    }
}
