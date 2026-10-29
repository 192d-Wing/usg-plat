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
         # TYPE plat_audit_queue_depth gauge\nplat_audit_queue_depth {}\n\
         # TYPE plat_audit_enqueued_total counter\nplat_audit_enqueued_total {}\n\
         # TYPE plat_audit_lost_total counter\nplat_audit_lost_total {}\n\
         # TYPE plat_audit_written_total counter\nplat_audit_written_total {}\n\
         # TYPE plat_audit_output_errors_total counter\nplat_audit_output_errors_total {}\n\
         # TYPE plat_audit_file_lost_total counter\nplat_audit_file_lost_total {}\n\
         # TYPE plat_audit_remote_lost_total counter\nplat_audit_remote_lost_total {}\n\
         # TYPE plat_audit_degraded gauge\nplat_audit_degraded {}\n\
         # TYPE plat_audit_storage_low gauge\nplat_audit_storage_low {}\n",
        st.session_count(),
        st.bib6.len(),
        st.pool.free_blocks(),
        st.pool.total_blocks(),
        st.releases_deferred_total(),
        s.audit.queued(),
        a.enqueued.load(Ordering::Relaxed),
        a.lost.load(Ordering::Relaxed),
        a.written.load(Ordering::Relaxed),
        a.output_errors.load(Ordering::Relaxed),
        a.file_lost.load(Ordering::Relaxed),
        a.remote_lost.load(Ordering::Relaxed),
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

/// Routes the request line of one read-only request: the audited path
/// class, status line and body. Nothing from the request is echoed.
pub fn route(line: &str, src: &Sources) -> (MgmtPath, &'static str, String) {
    if line.starts_with("GET /metrics ") {
        (MgmtPath::Metrics, "200 OK", render(src))
    } else if line.starts_with("GET /healthz ") {
        let (code, body) = health(&src.audit);
        (MgmtPath::Healthz, code, body)
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
        Event::Lifecycle { ts_us: 0, kind: LifecycleKind::Start, fips: None }
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
