//! Mutual-TLS management listener (`[management.tls]`).
//!
//! ```text
//!  plat-mgmt (accept, non-blocking poll)
//!     │  over max_connections or max_connections_per_ip
//!     │                     ─▶ close at once, audit over_capacity
//!     └─▶ plat-mgmt-conn (≤ max_connections threads)
//!            ClientHello ≤ 2 s (capped at handshake_timeout_ms)
//!            handshake ≤ handshake_timeout_ms (client cert REQUIRED,
//!            webpki + full-chain revocation on this thread)
//!            allow-list (typed cn:/dns:/uri:/sha256:, exact) ─▶ else close, audit
//!            one read-only request (/metrics, /healthz), close_notify
//! ```
//!
//! Every connection produces one `management_connection` record. Accepted
//! connections are always recorded (bounded by the connection cap and the
//! timeouts); rejections pass a token bucket (10/s, burst 20) and the
//! suppressed count is recorded as `management_connection_suppressed` once
//! per minute. Metrics count every connection regardless. Revocation
//! records produced during a management handshake are held on the
//! connection thread until the allow-list decision: for an authorized
//! client they are all emitted, otherwise each passes the same bucket
//! (SEC-003), so certificates from the management CA that are not
//! allow-listed cannot flood the audit queue.
//!
//! Why one thread per connection (capped) rather than one thread: a TLS
//! handshake from a slow or hostile client, plus a revocation fetch, can take
//! up to the handshake timeout; on a single thread that would block every
//! other client (slowloris). The cap bounds threads and memory.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-17, AC-17(2) (Remote Access; protection by
//!   cryptography: TLS 1.3, FIPS suites)
//! - NIST 800-53: IA-3, IA-5(2)(b)(1) - client certificate required, chained to
//!   `client_ca_file`, revocation checked; AC-3 - allow-list authorization
//! - NIST 800-53: AU-2, AU-3, AU-12 - `management_connection` records with
//!   peer address, certificate subject and fingerprint, and reason
//! - NIST 800-53: SC-5 - connection cap (global and per source IP),
//!   ClientHello deadline, handshake timeout, one request per connection,
//!   no session resumption; SC-8, SC-23

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use plat_audit::{AuditSink, AuditText, Event, MgmtConnection, MgmtPath, MgmtReason};
use plat_common::Clock;
use plat_tls::stream::{self, FailureClass};
use plat_tls::{AllowList, PeerIdentity, peer_identity};
use rustls::ServerConfig;

use crate::metrics::{self, Sources};

/// Every `plat.mgmt.reason`, in metric order.
pub const REASONS: [MgmtReason; 9] = [
    MgmtReason::Accepted,
    MgmtReason::NoClientCert,
    MgmtReason::BadCert,
    MgmtReason::NotAllowlisted,
    MgmtReason::HandshakeTimeout,
    MgmtReason::HandshakeFailed,
    MgmtReason::OverCapacity,
    MgmtReason::Revoked,
    MgmtReason::RevocationCheckFailed,
];

/// Largest request read (request line and headers), as for plaintext.
const MAX_REQUEST: usize = 1024;
/// Bound on sending `close_notify`.
const CLOSE_LIMIT: Duration = Duration::from_millis(500);
/// Accept poll interval when idle.
const ACCEPT_POLL: Duration = Duration::from_millis(100);
/// Time from accept to a complete ClientHello (capped at the handshake
/// timeout).
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(2);
/// Most revocation records held per handshake (chain depth is bounded
/// well below this; overflow falls back to immediate, rate-limited emit).
const MAX_DEFERRED: usize = 16;

thread_local! {
    /// Revocation records of the handshake running on this connection
    /// thread, held until the allow-list decision (`Some` only inside
    /// [`serve`]).
    static DEFERRED: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
}

/// Called by the revocation hook for a management-client record: holds
/// `ev` when running inside a management connection thread, otherwise (or
/// when the buffer is full) hands it back for immediate emission.
pub fn defer_revocation_event(ev: Event) -> Option<Event> {
    DEFERRED.with(|d| match d.borrow_mut().as_mut() {
        Some(v) if v.len() < MAX_DEFERRED => {
            v.push(ev);
            None
        }
        _ => Some(ev),
    })
}

/// Collects the revocation records of one management handshake and, on
/// drop, emits them: all if the client was authorized, otherwise each
/// through the rejection bucket (SEC-003).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5, AU-5 - non-allow-listed certificates cannot flood
///   the audit queue through revocation records
struct Deferred<'a> {
    ctx: &'a Ctx,
    authorized: bool,
}

impl<'a> Deferred<'a> {
    fn begin(ctx: &'a Ctx) -> Self {
        DEFERRED.with(|d| *d.borrow_mut() = Some(Vec::new()));
        Self { ctx, authorized: false }
    }
}

impl Drop for Deferred<'_> {
    fn drop(&mut self) {
        let held = DEFERRED.with(|d| d.borrow_mut().take()).unwrap_or_default();
        for ev in held {
            if self.authorized || self.ctx.limiter.admit() {
                self.ctx.audit.emit(ev);
            }
        }
    }
}

/// Listener material, loaded before the logger starts.
pub struct MgmtTls {
    pub config: Arc<ServerConfig>,
    pub allow: AllowList,
    pub max_connections: usize,
    /// Concurrent connections from one source IP.
    pub max_per_ip: usize,
    pub handshake_timeout: Duration,
}

/// Connection counters (`plat_mgmt_*`).
#[derive(Debug, Default)]
pub struct MgmtStats {
    by_reason: [AtomicU64; REASONS.len()],
    /// Connection threads currently running.
    pub active: AtomicUsize,
}

impl MgmtStats {
    fn count(&self, r: MgmtReason) {
        if let Some(i) = REASONS.iter().position(|x| *x == r)
            && let Some(a) = self.by_reason.get(i)
        {
            a.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn get(&self, r: MgmtReason) -> u64 {
        REASONS
            .iter()
            .position(|x| *x == r)
            .and_then(|i| self.by_reason.get(i))
            .map_or(0, |a| a.load(Ordering::Relaxed))
    }

    /// Prometheus section.
    pub fn render(&self, o: &mut String) {
        use std::fmt::Write as _;
        let accepted = self.get(MgmtReason::Accepted);
        let rejected: u64 = REASONS.iter().filter(|r| **r != MgmtReason::Accepted).map(|r| self.get(*r)).sum();
        let _ = write!(
            o,
            "# TYPE plat_mgmt_connections_total counter\n\
             plat_mgmt_connections_total{{outcome=\"accepted\"}} {accepted}\n\
             plat_mgmt_connections_total{{outcome=\"rejected\"}} {rejected}\n\
             # TYPE plat_mgmt_rejections_total counter\n"
        );
        for r in REASONS.iter().filter(|r| **r != MgmtReason::Accepted) {
            let _ = writeln!(o, "plat_mgmt_rejections_total{{reason=\"{}\"}} {}", r.as_str(), self.get(*r));
        }
    }
}

/// Token bucket for rejection-class audit records (management connection
/// rejections and the revocation records of rejected management chains),
/// with a periodic summary of what it suppressed.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5, AU-5 - a rejection flood cannot flood the audit
///   queue; the suppressed count is itself recorded.
#[derive(Debug)]
pub struct RejectLimiter {
    rate_per_sec: f64,
    burst: f64,
    window: Duration,
    st: Mutex<Bucket>,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
    suppressed: u64,
    window_start: Instant,
}

impl RejectLimiter {
    /// 10 records/s, burst 20, summary every 60 s (plan §5).
    pub fn standard() -> Self {
        Self::new(10.0, 20.0, Duration::from_secs(60))
    }

    pub fn new(rate_per_sec: f64, burst: f64, window: Duration) -> Self {
        let now = Instant::now();
        Self {
            rate_per_sec,
            burst,
            window,
            st: Mutex::new(Bucket { tokens: burst, last: now, suppressed: 0, window_start: now }),
        }
    }

    /// Takes a token; `false` (and the record counted as suppressed) when
    /// the bucket is empty.
    pub fn admit(&self) -> bool {
        let mut b = self.st.lock();
        let now = Instant::now();
        let refill = now.saturating_duration_since(b.last).as_secs_f64() * self.rate_per_sec;
        b.tokens = (b.tokens + refill).min(self.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            b.suppressed += 1;
            false
        }
    }

    /// The `management_connection_suppressed` record when a window with
    /// suppressed records has ended (or at once with `flush`, at shutdown).
    pub fn summary(&self, flush: bool) -> Option<Event> {
        let mut b = self.st.lock();
        let now = Instant::now();
        if !flush && now.saturating_duration_since(b.window_start) < self.window {
            return None;
        }
        b.window_start = now;
        let n = std::mem::take(&mut b.suppressed);
        (n > 0).then(|| Event::ManagementSuppressed {
            ts_us: Clock::wall_us(),
            suppressed: n,
            window_secs: u32::try_from(self.window.as_secs()).unwrap_or(u32::MAX),
        })
    }
}

/// State shared by the accept thread and every connection thread.
struct Ctx {
    tls: MgmtTls,
    src: Sources,
    audit: AuditSink,
    stats: Arc<MgmtStats>,
    limiter: Arc<RejectLimiter>,
    /// Active connections per source key (see [`source_key`]; at most
    /// `max_connections` keys; std `RandomState` hasher, randomly keyed).
    per_ip: Mutex<HashMap<IpAddr, usize>>,
}

/// Key for the per-source limit: IPv4 (incl. v4-mapped IPv6, via
/// `to_canonical`) by address, IPv6 by /64, the normal end-site
/// allocation, so one client cannot rotate addresses inside its own /64.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 (Denial-of-Service Protection)
pub(crate) fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
        v4 => v4,
    }
}

/// Typed, sanitised SANs of `id` (`dns:` then `uri:`), capped.
fn sans_of(id: &PeerIdentity) -> Vec<AuditText> {
    id.dns_sans
        .iter()
        .map(|d| ("dns:", d))
        .chain(id.uri_sans.iter().map(|u| ("uri:", u)))
        .take(MgmtConnection::SANS_MAX)
        .map(|(k, v)| AuditText::new(&format!("{k}{v}"), AuditText::SUBJECT_MAX))
        .collect()
}

impl Ctx {
    fn record(
        &self,
        peer: SocketAddr,
        id: Option<&PeerIdentity>,
        reason: MgmtReason,
        path: Option<MgmtPath>,
        allow_entry: Option<&str>,
    ) {
        self.stats.count(reason);
        if reason != MgmtReason::Accepted && !self.limiter.admit() {
            return;
        }
        let conn = MgmtConnection {
            ip: peer.ip(),
            port: peer.port(),
            subject: id.and_then(|i| i.subject_cn.as_deref()).map(|s| AuditText::new(s, AuditText::SUBJECT_MAX)),
            cert_sha256: id.map(|i| i.sha256),
            reason,
            path,
            allow_entry: allow_entry.map(|a| AuditText::new(a, AuditText::SUBJECT_MAX)),
            sans: id.map(sans_of).unwrap_or_default(),
        };
        self.audit.emit(Event::ManagementConnection { ts_us: Clock::wall_us(), conn: Arc::new(conn) });
    }
}

/// Decrements the active-connection counts (global and per source key)
/// when a connection thread ends (or when its closure is dropped because
/// the thread failed to start).
struct Active(Arc<Ctx>, IpAddr);

impl Drop for Active {
    fn drop(&mut self) {
        {
            let mut m = self.0.per_ip.lock();
            if let Some(n) = m.get_mut(&self.1) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    m.remove(&self.1);
                }
            }
        }
        self.0.stats.active.fetch_sub(1, Ordering::Release);
    }
}

fn reason_for(c: FailureClass) -> MgmtReason {
    match c {
        FailureClass::Timeout => MgmtReason::HandshakeTimeout,
        FailureClass::NoCertificate => MgmtReason::NoClientCert,
        FailureClass::Revoked => MgmtReason::Revoked,
        FailureClass::RevocationUnknown => MgmtReason::RevocationCheckFailed,
        FailureClass::BadCertificate => MgmtReason::BadCert,
        FailureClass::Io | FailureClass::Handshake => MgmtReason::HandshakeFailed,
    }
}

/// One connection: ClientHello, handshake, authorization, one request.
fn serve(ctx: &Ctx, mut sock: TcpStream, peer: SocketAddr) {
    // Accepted sockets inherit O_NONBLOCK from the listener on BSD/macOS.
    let _ = sock.set_nonblocking(false);
    let _ = sock.set_nodelay(true);
    let start = Instant::now();
    let deadline = start + ctx.tls.handshake_timeout;
    let hello_deadline = start + CLIENT_HELLO_TIMEOUT.min(ctx.tls.handshake_timeout);
    let Ok(mut conn) = rustls::ServerConnection::new(ctx.tls.config.clone()) else {
        ctx.record(peer, None, MgmtReason::HandshakeFailed, None, None);
        return;
    };
    // SEC-001: a short first-flight deadline, separate from the handshake
    // timeout (which must cover the revocation budget).
    if let Err(e) = stream::await_client_hello(&mut conn, &mut sock, hello_deadline) {
        tracing::debug!("management {peer}: {e}");
        ctx.record(peer, None, reason_for(e.class()), None, None);
        return;
    }
    let mut held = Deferred::begin(ctx);
    if let Err(e) = stream::handshake(&mut conn, &mut sock, deadline) {
        tracing::debug!("management {peer}: {e}");
        let id = conn.peer_certificates().and_then(|c| c.first()).map(peer_identity);
        ctx.record(peer, id.as_ref(), reason_for(e.class()), None, None);
        return;
    }
    let Some(id) = conn.peer_certificates().and_then(|c| c.first()).map(peer_identity) else {
        ctx.record(peer, None, MgmtReason::NoClientCert, None, None);
        return;
    };
    // AC-3: authenticated is not authorized. Close without an HTTP
    // response (reveals nothing).
    let Some(entry) = ctx.tls.allow.matched(&id) else {
        ctx.record(peer, Some(&id), MgmtReason::NotAllowlisted, None, None);
        drop(held);
        stream::close(&mut conn, &mut sock, CLOSE_LIMIT);
        return;
    };
    held.authorized = true;
    drop(held);
    let mut req = [0u8; MAX_REQUEST];
    let req_deadline = Instant::now() + ctx.tls.handshake_timeout;
    let n =
        stream::read_until(&mut conn, &mut sock, &mut req, req_deadline, |b| b.windows(4).any(|w| w == b"\r\n\r\n"))
            .unwrap_or(0);
    let line = std::str::from_utf8(req.get(..n).unwrap_or_default()).unwrap_or("").lines().next().unwrap_or("");
    let (path, code, body) = metrics::route(line, &ctx.src);
    ctx.record(peer, Some(&id), MgmtReason::Accepted, Some(path), Some(entry));
    let resp = metrics::response(code, &body);
    if let Err(e) = stream::write_all(&mut conn, &mut sock, resp.as_bytes(), Instant::now() + ctx.tls.handshake_timeout)
    {
        tracing::debug!("management {peer}: {e}");
        return;
    }
    stream::close(&mut conn, &mut sock, CLOSE_LIMIT);
}

/// Starts the accept thread. At `stop` it stops accepting and waits for
/// running connection threads (each bounded by its timeouts) before
/// returning, so every audit record is queued before the logger stops.
pub fn spawn(
    addr: SocketAddr,
    tls: MgmtTls,
    src: Sources,
    audit: AuditSink,
    stats: Arc<MgmtStats>,
    limiter: Arc<RejectLimiter>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<JoinHandle<()>> {
    spawn_on(TcpListener::bind(addr)?, tls, src, audit, stats, limiter, stop)
}

/// [`spawn`] on an already bound listener.
pub fn spawn_on(
    l: TcpListener,
    tls: MgmtTls,
    src: Sources,
    audit: AuditSink,
    stats: Arc<MgmtStats>,
    limiter: Arc<RejectLimiter>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<JoinHandle<()>> {
    l.set_nonblocking(true)?;
    let max = tls.max_connections.max(1);
    let per_ip_max = tls.max_per_ip.clamp(1, max);
    let drain = tls.handshake_timeout * 3 + CLOSE_LIMIT;
    let ctx = Arc::new(Ctx { tls, src, audit, stats, limiter, per_ip: Mutex::new(HashMap::new()) });
    std::thread::Builder::new().name("plat-mgmt".into()).spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            if let Some(ev) = ctx.limiter.summary(false) {
                ctx.audit.emit(ev);
            }
            let Ok((sock, peer)) = l.accept() else {
                std::thread::sleep(ACCEPT_POLL);
                continue;
            };
            // SC-5: over the cap the connection is closed before any TLS work.
            if ctx.stats.active.load(Ordering::Acquire) >= max {
                drop(sock);
                ctx.record(peer, None, MgmtReason::OverCapacity, None, None);
                continue;
            }
            // SEC-001: one source cannot take every slot.
            let ip_full = {
                let mut m = ctx.per_ip.lock();
                let n = m.entry(source_key(peer.ip())).or_insert(0);
                if *n >= per_ip_max {
                    true
                } else {
                    *n += 1;
                    false
                }
            };
            if ip_full {
                drop(sock);
                ctx.record(peer, None, MgmtReason::OverCapacity, None, None);
                continue;
            }
            ctx.stats.active.fetch_add(1, Ordering::AcqRel);
            let guard = Active(ctx.clone(), source_key(peer.ip()));
            let c = ctx.clone();
            let spawned = std::thread::Builder::new().name("plat-mgmt-conn".into()).spawn(move || {
                let _guard = guard;
                serve(&c, sock, peer);
            });
            if let Err(e) = spawned {
                tracing::warn!("management {peer}: no connection thread: {e}");
                ctx.record(peer, None, MgmtReason::OverCapacity, None, None);
            }
        }
        let t = Instant::now();
        while ctx.stats.active.load(Ordering::Acquire) > 0 && t.elapsed() < drain {
            std::thread::sleep(Duration::from_millis(20));
        }
        if let Some(ev) = ctx.limiter.summary(true) {
            ctx.audit.emit(ev);
        }
    })
}

#[cfg(test)]
mod tests;
