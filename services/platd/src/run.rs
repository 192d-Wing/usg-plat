//! Daemon lifecycle: audit → state → workers → sweeper → metrics → signals.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use plat_audit::{AuditSink, Event, LifecycleKind, Logger, LoggerHandle, NodeIdent};
use plat_common::{Clock, Config, Counter, Counters, DropReason};
use plat_io::PacketQueue;
use plat_nat64::{Nat64, Verdict, WorkerCtx};
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
pub fn worker<Q: PacketQueue>(mut q: Q, nat: Arc<Nat64>, counters: Arc<Counters>, id: u16, stop: Arc<AtomicBool>) {
    let mut buf = vec![0u8; HEADROOM + MAX_PKT].into_boxed_slice();
    let mut ctx = WorkerCtx::new(counters.clone(), id.wrapping_mul(0x9e37));
    while !stop.load(Ordering::Relaxed) {
        let n = match q.recv(&mut buf[HEADROOM..]) {
            Ok(Some(n)) => n,
            Ok(None) => continue,
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
            Verdict::Drop(_) => {}
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
fn stop_audit(sink: AuditSink, logger: LoggerHandle) {
    sink.emit(Event::Lifecycle { ts_us: Clock::wall_us(), kind: LifecycleKind::Stop });
    drop(sink);
    logger.join();
}

#[cfg(target_os = "linux")]
fn open_queues(cfg: &Config, n: usize) -> std::io::Result<Vec<plat_io::tun::TunQueue>> {
    plat_io::tun::TunQueue::open_multi(&cfg.dataplane.interface, n)
}

#[cfg(not(target_os = "linux"))]
fn open_queues(_cfg: &Config, _n: usize) -> std::io::Result<Vec<plat_io::mem::MemQueue>> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "the TUN data plane requires Linux"))
}

pub fn run(cfg: Config) -> ExitCode {
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        if let Err(e) = signal_hook::flag::register(sig, stop.clone()) {
            tracing::error!("signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    let owned = plat_cluster::owned(&cfg);
    let n = worker_count(&cfg);
    let counters: Vec<Arc<Counters>> = (0..n).map(|_| Arc::new(Counters::default())).collect();

    // Audit first: nothing may be translated before attribution logging is up (AU-12).
    let (sink, rx) = AuditSink::bounded(cfg.audit.queue_capacity);
    let node = NodeIdent { name: cfg.node.name.clone(), id: cfg.node.id, pid: std::process::id() };
    let summary_src = counters.clone();
    let logger = Logger::new(cfg.audit.clone(), node, rx, sink.stats().clone()).with_counters(Box::new(move || {
        DropReason::ALL
            .iter()
            .map(|r| (r.as_str(), summary_src.iter().map(|c| c.drops(*r)).sum()))
            .filter(|(_, v)| *v > 0)
            .collect()
    }));
    let logger = match logger.spawn() {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("audit destinations: {e}");
            return ExitCode::FAILURE;
        }
    };
    sink.emit(Event::Lifecycle { ts_us: Clock::wall_us(), kind: LifecycleKind::Start });

    let clock = Clock::new();
    let nat = match Nat64::new(&cfg, owned.clone(), sink.clone(), clock.clone()) {
        Ok(n) => Arc::new(n),
        Err(e) => {
            tracing::error!("{e}");
            stop_audit(sink, logger);
            return ExitCode::FAILURE;
        }
    };

    let queues = match open_queues(&cfg, n) {
        Ok(q) => q,
        Err(e) => {
            tracing::error!("opening {} ({n} queues): {e}", cfg.dataplane.interface);
            stop.store(true, Ordering::Relaxed);
            drop(nat);
            stop_audit(sink, logger);
            return ExitCode::FAILURE;
        }
    };
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
                let s = nat.state().sweep();
                tracing::debug!(?s, "sweep");
            }
        }));
    }
    for (i, q) in queues.into_iter().enumerate() {
        let (nat, c, stop) = (nat.clone(), counters[i].clone(), stop.clone());
        let core = cores.get(i % cores.len().max(1)).copied();
        threads.push(std::thread::Builder::new().name(format!("plat-w{i}")).spawn(move || {
            if let Some(core) = core {
                core_affinity::set_for_current(core);
            }
            worker(q, nat, c, i as u16, stop);
        }));
    }
    let metrics = cfg.management.listen.map(|addr| {
        metrics::spawn(
            addr,
            metrics::Sources { nat: nat.clone(), workers: counters.clone(), audit: sink.clone() },
            stop.clone(),
        )
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

    for t in threads.into_iter().flatten() {
        let _ = t.join();
    }
    if let Some(Ok(m)) = metrics {
        let _ = m.join();
    }
    // Drop every AuditSink clone so the logger drains and exits.
    // POAM: POAM-009 - live port blocks are not released (no `nat_port_block_release`
    // records) at shutdown; the release needs a plat-nat64 drain API. SIEM
    // correlation closes them at `service_stop`.
    drop(nat);
    stop_audit(sink, logger);
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
            std::thread::spawn(move || worker(dev, nat, counters, 0, stop))
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
