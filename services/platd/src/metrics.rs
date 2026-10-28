//! Read-only Prometheus metrics and health endpoint on loopback.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-4 (System Monitoring)
//! - NIST 800-53: CM-7, AC-17 - loopback only (enforced at config load);
//!   no secrets or subscriber identities are exposed.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use plat_audit::AuditSink;
use plat_common::{Counter, Counters, DropReason};
use plat_nat64::Nat64;

pub struct Sources {
    pub nat: Arc<Nat64>,
    pub workers: Vec<Arc<Counters>>,
    pub audit: AuditSink,
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
    o
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
            let line = std::str::from_utf8(&req[..n]).unwrap_or("").lines().next().unwrap_or("");
            let (code, body) = if line.starts_with("GET /metrics ") {
                ("200 OK", render(&src))
            } else if line.starts_with("GET /healthz ") {
                health(&src.audit)
            } else {
                ("404 Not Found", String::new())
            };
            let _ = write!(
                s,
                "HTTP/1.1 {code}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use plat_audit::{Event, LifecycleKind};

    fn ev() -> Event {
        Event::Lifecycle { ts_us: 0, kind: LifecycleKind::Start }
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
