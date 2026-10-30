//! Read-only Prometheus metrics and health endpoint: rendering, routing,
//! and the plaintext listener (loopback only). The mutual-TLS listener is
//! in `mgmt`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-4 (System Monitoring)
//! - NIST 800-53: CM-7, AC-17 - plaintext only on loopback (enforced at
//!   config load); no secrets or subscriber identities are exposed.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use plat_audit::{AuditSink, MgmtPath, RemoteLossReason};
use plat_common::{Counter, Counters, DropReason};
use plat_nat64::Nat64;

/// Extra metric section (TLS, management, revocation), appended to
/// `/metrics`.
pub type Section = Box<dyn Fn(&mut String) + Send + Sync>;

pub struct Sources {
    pub nat: Arc<Nat64>,
    pub workers: Vec<Arc<Counters>>,
    pub audit: AuditSink,
    /// FIPS module active (`plat_fips_mode`, SC-13).
    pub fips: bool,
    pub extra: Vec<Section>,
    /// `[cluster.ha]`: the `/cluster` view and the cluster health check.
    pub cluster: Option<ClusterSource>,
}

/// Read-only cluster status for `/cluster` and `/healthz`.
pub struct ClusterSource {
    /// JSON view (`/cluster`).
    pub json: Box<dyn Fn() -> String + Send + Sync>,
    /// A problem that makes `/healthz` 503 (duplicate member id).
    pub health: Box<dyn Fn() -> Option<&'static str> + Send + Sync>,
}

pub fn render(s: &Sources) -> String {
    let mut o = String::with_capacity(4096);
    o.push_str("# TYPE plat_drops_total counter\n");
    for r in DropReason::ALL {
        let v: u64 = s.workers.iter().map(|c| c.drops(*r)).sum();
        let _ = writeln!(o, "plat_drops_total{{reason=\"{}\"}} {v}", r.as_str());
    }
    for c in Counter::ALL {
        let v: u64 = s.workers.iter().map(|w| w.get(*c)).sum();
        let _ = writeln!(o, "# TYPE plat_{}_total counter\nplat_{}_total {v}", c.as_str(), c.as_str());
    }
    let frag_entries: u64 = s.workers.iter().map(|w| w.fragment_entries()).sum();
    let _ = writeln!(o, "# TYPE plat_fragment_entries gauge\nplat_fragment_entries {frag_entries}");
    for (i, w) in s.workers.iter().enumerate() {
        let _ = writeln!(o, "plat_worker_rx_packets_total{{worker=\"{i}\"}} {}", w.get(Counter::RxPackets));
    }
    let st = s.nat.state();
    let a = s.audit.stats();
    let _ = write!(
        o,
        "# TYPE plat_sessions gauge\nplat_sessions {}\n\
         # TYPE plat_bibs gauge\nplat_bibs {}\n\
         # TYPE plat_pool_blocks_free gauge\nplat_pool_blocks_free {}\n\
         # TYPE plat_pool_blocks_total gauge\nplat_pool_blocks_total {}\n\
         # TYPE plat_pool_releases_deferred_total counter\nplat_pool_releases_deferred_total {}\n\
         # TYPE plat_sweep_resumed_total counter\nplat_sweep_resumed_total {}\n\
         # TYPE plat_audit_queue_depth gauge\nplat_audit_queue_depth {}\n\
         # TYPE plat_audit_enqueued_total counter\nplat_audit_enqueued_total {}\n\
         # TYPE plat_audit_lost_total counter\nplat_audit_lost_total {}\n\
         # TYPE plat_audit_written_total counter\nplat_audit_written_total {}\n\
         # TYPE plat_audit_output_errors_total counter\nplat_audit_output_errors_total {}\n\
         # TYPE plat_audit_file_lost_total counter\nplat_audit_file_lost_total {}\n\
         # TYPE plat_audit_remote_lost_total counter\nplat_audit_remote_lost_total {}\n\
         # TYPE plat_audit_seq_lease_failures_total counter\nplat_audit_seq_lease_failures_total {}\n\
         # TYPE plat_audit_degraded gauge\nplat_audit_degraded {}\n\
         # TYPE plat_audit_storage_low gauge\nplat_audit_storage_low {}\n",
        st.session_count(),
        st.bib6.len(),
        st.pool.free_blocks(),
        st.pool.total_blocks(),
        st.releases_deferred_total(),
        st.sweep_resumed_total(),
        s.audit.queued(),
        a.enqueued.load(Ordering::Relaxed),
        a.lost.load(Ordering::Relaxed),
        a.written.load(Ordering::Relaxed),
        a.output_errors.load(Ordering::Relaxed),
        a.file_lost.load(Ordering::Relaxed),
        a.remote_lost.load(Ordering::Relaxed),
        a.seq_lease_failures.load(Ordering::Relaxed),
        u8::from(a.degraded()),
        u8::from(a.storage_low()),
    );
    let _ = writeln!(o, "# TYPE plat_fips_mode gauge\nplat_fips_mode {}", u8::from(s.fips));
    let tls: Vec<_> = a.remotes().iter().filter(|r| r.transport == "tls").collect();
    if !tls.is_empty() {
        o.push_str("# TYPE plat_audit_remote_tls_handshakes_total counter\n");
        for r in &tls {
            let _ = writeln!(
                o,
                "plat_audit_remote_tls_handshakes_total{{dest=\"{}\"}} {}",
                r.address,
                r.tls_handshakes.load(Ordering::Relaxed)
            );
        }
        o.push_str("# TYPE plat_audit_remote_tls_failures_total counter\n");
        for r in &tls {
            for reason in RemoteLossReason::ALL {
                let _ = writeln!(
                    o,
                    "plat_audit_remote_tls_failures_total{{dest=\"{}\",reason=\"{}\"}} {}",
                    r.address,
                    reason.as_str(),
                    r.failures(reason)
                );
            }
        }
    }
    for section in &s.extra {
        section(&mut o);
    }
    o
}

/// Kernel drop counters of the TUN interface, read at scrape time from
/// `/sys/class/net/<if>/statistics/{rx,tx}_dropped` (Linux only; elsewhere
/// the section is empty). Drops caused by TUN back-pressure (a full queue
/// toward the kernel) are counted only there, not in `plat_drops_total`;
/// `plat_tx_queue_full_total` stays the user-space view.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-4, SC-5 - kernel-side drops are monitored (L17)
pub fn tun_section(ifname: String) -> Section {
    Box::new(move |o: &mut String| render_tun(o, std::path::Path::new("/sys/class/net"), &ifname))
}

fn render_tun(o: &mut String, sysfs: &std::path::Path, ifname: &str) {
    if !cfg!(target_os = "linux") && sysfs == std::path::Path::new("/sys/class/net") {
        return;
    }
    // The name comes from validated config; still refuse anything that is
    // not a single path component.
    if ifname.is_empty() || ifname == "." || ifname == ".." || ifname.contains(['/', '\0']) {
        return;
    }
    let dir = sysfs.join(ifname).join("statistics");
    for (metric, file) in [("plat_tun_rx_dropped_total", "rx_dropped"), ("plat_tun_tx_dropped_total", "tx_dropped")] {
        let Some(v) = std::fs::read_to_string(dir.join(file)).ok().and_then(|t| t.trim().parse::<u64>().ok()) else {
            continue;
        };
        let _ = write!(o, "# TYPE {metric} counter\n{metric}{{interface=\"");
        push_label_value(o, ifname);
        let _ = writeln!(o, "\"}} {v}");
    }
}

/// Appends `v` as a Prometheus label value: `\\`, `"` and newline escaped
/// (exposition format), so no name can break out of the label (SEC-9).
fn push_label_value(o: &mut String, v: &str) {
    for c in v.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            c => o.push(c),
        }
    }
}

/// Routes the request line of one read-only request: the audited path
/// class, status line and body. Nothing from the request is echoed.
pub fn route(line: &str, src: &Sources) -> (MgmtPath, &'static str, String) {
    if line.starts_with("GET /metrics ") {
        (MgmtPath::Metrics, "200 OK", render(src))
    } else if line.starts_with("GET /healthz ") {
        let (code, body) = health(&src.audit);
        match src.cluster.as_ref().and_then(|c| (c.health)()) {
            Some(p) if code.starts_with("200") => {
                (MgmtPath::Healthz, "503 Service Unavailable", format!("unhealthy: {p}\n"))
            }
            Some(p) => (MgmtPath::Healthz, code, format!("{}, {p}\n", body.trim_end())),
            None => (MgmtPath::Healthz, code, body),
        }
    } else if line.starts_with("GET /cluster ")
        && let Some(c) = &src.cluster
    {
        // CM-7: read-only; same listener rules as /metrics (mTLS or
        // loopback plaintext).
        (MgmtPath::Cluster, "200 OK", (c.json)())
    } else {
        (MgmtPath::Other, "404 Not Found", String::new())
    }
}

/// The full HTTP/1.1 response (`Connection: close`, one request).
pub fn response(code: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {code}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// `/healthz`: 503 while audit processing has failed or is about to
/// (local file not writable, log volume below `min_free_bytes`, queue full
/// or at least 90 % full).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-5 (alert on audit processing failure), AU-5(1), SI-4
pub fn health(audit: &AuditSink) -> (&'static str, String) {
    let st = audit.stats();
    let (queued, cap) = (audit.queued(), audit.capacity());
    let mut problems = Vec::new();
    if st.file_down() {
        problems.push("audit file not writable");
    }
    if st.storage_low() {
        problems.push("audit volume below min_free_bytes");
    }
    if !audit.has_room() && !st.degraded() {
        problems.push("audit queue full");
    } else if queued.saturating_mul(10) >= cap.saturating_mul(9) {
        problems.push("audit queue above 90%");
    }
    if problems.is_empty() {
        ("200 OK", "ok\n".into())
    } else {
        ("503 Service Unavailable", format!("unhealthy: {}\n", problems.join(", ")))
    }
}

pub fn spawn(addr: SocketAddr, src: Sources, stop: Arc<AtomicBool>) -> std::io::Result<JoinHandle<()>> {
    let l = TcpListener::bind(addr)?;
    l.set_nonblocking(true)?;
    std::thread::Builder::new().name("plat-metrics".into()).spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let Ok((mut s, _)) = l.accept() else {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            };
            let _ = s.set_nonblocking(false);
            // Short timeouts: one slow client must not hold the (single)
            // management thread.
            let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
            let _ = s.set_write_timeout(Some(Duration::from_millis(500)));
            let mut req = [0u8; 1024];
            let n = s.read(&mut req).unwrap_or(0);
            let line = std::str::from_utf8(req.get(..n).unwrap_or_default()).unwrap_or("").lines().next().unwrap_or("");
            let (_, code, body) = route(line, &src);
            let _ = s.write_all(response(code, &body).as_bytes());
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use plat_audit::{Event, LifecycleKind};

    fn ev() -> Event {
        Event::Lifecycle { ts_us: 0, kind: LifecycleKind::Start, fips: None, cluster: None }
    }

    #[test]
    fn tun_kernel_drops_are_exported() {
        let base = std::env::temp_dir().join(format!("platd-sysfs-{}", std::process::id()));
        let stats = base.join("plat0").join("statistics");
        std::fs::create_dir_all(&stats).unwrap();
        std::fs::write(stats.join("rx_dropped"), "3\n").unwrap();
        std::fs::write(stats.join("tx_dropped"), "1745\n").unwrap();
        let mut o = String::new();
        render_tun(&mut o, &base, "plat0");
        assert!(
            o.contains("# TYPE plat_tun_rx_dropped_total counter\nplat_tun_rx_dropped_total{interface=\"plat0\"} 3\n"),
            "{o}"
        );
        assert!(o.contains("plat_tun_tx_dropped_total{interface=\"plat0\"} 1745\n"), "{o}");
        let mut o = String::new();
        render_tun(&mut o, &base, "../plat0");
        render_tun(&mut o, &base, "missing0");
        assert!(o.is_empty(), "{o}");
        // SEC-9: quote and backslash cannot break out of the label.
        let odd = base.join("a\"b\\c").join("statistics");
        std::fs::create_dir_all(&odd).unwrap();
        std::fs::write(odd.join("rx_dropped"), "7\n").unwrap();
        render_tun(&mut o, &base, "a\"b\\c");
        assert!(o.contains("plat_tun_rx_dropped_total{interface=\"a\\\"b\\\\c\"} 7\n"), "{o}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn healthz_reports_audit_queue_pressure() {
        let (sink, rx) = AuditSink::bounded(10);
        assert_eq!(health(&sink).0, "200 OK");
        for _ in 0..9 {
            sink.emit(ev());
        }
        let (code, body) = health(&sink);
        assert_eq!(code, "503 Service Unavailable");
        assert!(body.contains("above 90%"), "{body}");
        sink.emit(ev());
        assert!(health(&sink).1.contains("queue full"));
        while rx.try_recv().is_ok() {}
        assert_eq!(health(&sink).0, "200 OK");
    }
}
