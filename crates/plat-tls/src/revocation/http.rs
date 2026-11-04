//! Minimal HTTP/1.0 client for OCSP (RFC 6960 Appendix A) and CRL
//! (RFC 5280 §4.2.1.13) fetches over `std::net::TcpStream`.
//!
//! Responder bytes are hostile: the header block is capped, the body is
//! capped (checked against `Content-Length` before reading, enforced while
//! reading), chunked transfer encoding is refused, redirects are not
//! followed (any non-200 status is an error), and every connect/read/write
//! is bounded by the caller's deadline.
//!
//! Name resolution is bounded too ([`Resolver`]): IP-literal hosts skip it;
//! other hosts are looked up on a `plat-dns` helper thread that the caller
//! waits on only until its deadline. A lookup cannot be cancelled, so at
//! most [`MAX_RESOLVER_THREADS`] helpers exist at once; past the cap the
//! fetch fails at once instead of spawning.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 - size and time bounds on every fetch, including
//!   name resolution; bounded resolver threads
//! - NIST 800-53: IA-5(2)(b)(1) - a hung resolver cannot stall the status
//!   check past `revocation.budget_ms` (normal failure policy applies)
//! - NIST 800-53: SI-10 - strict parsing of the status line and headers

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use plat_common::HttpUrl;

/// Header block cap (status line + headers).
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Most resolver helper threads alive at once, process-wide. Fetches come
/// from the refresher (serial) and handshake threads (management, syslog,
/// cluster peers), each single-flighted per certificate, so a healthy
/// resolver rarely has more than a few lookups in flight; 8 leaves headroom
/// while capping what a hung resolver can pin (8 threads, small stacks).
pub const MAX_RESOLVER_THREADS: usize = 8;

/// Addresses tried per host.
const MAX_ADDRS: usize = 4;

/// Helper thread stack: enough for getaddrinfo and NSS modules.
const RESOLVER_STACK: usize = 256 * 1024;

/// Name lookup function (`getaddrinfo` in production, scripted in tests).
pub type LookupFn = fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>;

fn system_lookup(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.take(MAX_ADDRS).collect())
}

/// Process-wide resolver used by [`fetch`].
static SYSTEM_RESOLVER: Resolver = Resolver::new(system_lookup, MAX_RESOLVER_THREADS);

/// Resolver counters (`plat_revocation_resolve_failures_total{reason}`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolverStats {
    /// Lookups abandoned at the deadline.
    pub timeouts: u64,
    /// Lookups refused because [`MAX_RESOLVER_THREADS`] were in flight.
    pub saturated: u64,
    /// Helper threads currently alive (including abandoned lookups).
    pub in_flight: usize,
}

/// Counters of the process-wide resolver.
pub fn resolver_stats() -> ResolverStats {
    SYSTEM_RESOLVER.stats()
}

/// Deadline-bounded name resolution with a cap on helper threads.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - bounded wait and bounded thread count under a
///   slow or hostile resolver (closes POAM-025 (a))
#[derive(Debug)]
pub struct Resolver {
    lookup: LookupFn,
    cap: usize,
    in_flight: AtomicUsize,
    timeouts: AtomicU64,
    saturated: AtomicU64,
}

/// Releases a helper slot when the helper thread ends (or fails to start),
/// whether or not the caller still waits.
struct Slot(&'static Resolver);

impl Drop for Slot {
    fn drop(&mut self) {
        // Release pairs with the Acquire in `try_acquire`.
        self.0.in_flight.fetch_sub(1, Ordering::Release);
    }
}

impl Resolver {
    pub const fn new(lookup: LookupFn, cap: usize) -> Self {
        Self { lookup, cap, in_flight: AtomicUsize::new(0), timeouts: AtomicU64::new(0), saturated: AtomicU64::new(0) }
    }

    pub fn stats(&self) -> ResolverStats {
        ResolverStats {
            timeouts: self.timeouts.load(Ordering::Relaxed),
            saturated: self.saturated.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::Acquire),
        }
    }

    fn try_acquire(&'static self) -> Option<Slot> {
        let mut n = self.in_flight.load(Ordering::Acquire);
        while n < self.cap {
            match self.in_flight.compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Acquire) {
                Ok(_) => return Some(Slot(self)),
                Err(cur) => n = cur,
            }
        }
        None
    }

    /// Resolves `host:port` to at most four addresses before `deadline`.
    /// IP literals (bare or bracketed) are returned without a lookup.
    /// Deadline or a full helper cap: [`HttpError::Timeout`]; lookup
    /// failure: [`HttpError::Connect`].
    pub fn resolve(&'static self, host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>, HttpError> {
        let lit = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        if let Ok(ip) = lit.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let wait = remaining(deadline)?;
        let Some(slot) = self.try_acquire() else {
            self.saturated.fetch_add(1, Ordering::Relaxed);
            return Err(HttpError::Timeout);
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let owned = host.to_owned();
        let lookup = self.lookup;
        let spawned = std::thread::Builder::new().name("plat-dns".into()).stack_size(RESOLVER_STACK).spawn(move || {
            let _slot = slot;
            let r = lookup(&owned, port);
            // The caller may have given up; a closed channel is fine.
            let _ = tx.try_send(r);
        });
        // On spawn failure the closure (and its slot) is dropped.
        if spawned.is_err() {
            return Err(HttpError::Connect);
        }
        match rx.recv_timeout(wait) {
            Ok(Ok(mut v)) => {
                v.truncate(MAX_ADDRS);
                Ok(v)
            }
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => Err(HttpError::Connect),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.timeouts.fetch_add(1, Ordering::Relaxed);
                Err(HttpError::Timeout)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    /// Deadline reached (resolve, connect, read or write).
    Timeout,
    /// Name resolution or TCP connect failed.
    Connect,
    /// Status other than 200 (redirects included).
    Status(u16),
    /// `Content-Type` not one of the accepted types.
    ContentType,
    /// Body larger than the cap (declared or actual).
    TooLarge,
    /// Unparseable status line/headers, chunked encoding, short body.
    Malformed,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub body: Vec<u8>,
    /// Lowercased media type without parameters.
    pub content_type: Option<String>,
}

/// Request description.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// `None` = GET, `Some((content_type, body))` = POST.
    pub post: Option<(&'a str, &'a [u8])>,
    pub accept: &'a str,
    /// Accepted response media types (lowercase); empty accepts any.
    pub accept_types: &'a [&'a str],
    pub max_body: usize,
    pub deadline: Instant,
}

fn remaining(deadline: Instant) -> Result<Duration, HttpError> {
    let r = deadline.saturating_duration_since(Instant::now());
    if r.is_zero() { Err(HttpError::Timeout) } else { Ok(r) }
}

fn io_err(e: &std::io::Error) -> HttpError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => HttpError::Timeout,
        _ => HttpError::Connect,
    }
}

fn connect(url: &HttpUrl, deadline: Instant) -> Result<TcpStream, HttpError> {
    // SC-5: resolution is bounded by `deadline` (POAM-025 (a) closed).
    let addrs = SYSTEM_RESOLVER.resolve(&url.host, url.port, deadline)?;
    let mut last = HttpError::Connect;
    for a in addrs {
        let t = remaining(deadline)?;
        match TcpStream::connect_timeout(&a, t) {
            Ok(s) => return Ok(s),
            Err(e) => last = io_err(&e),
        }
    }
    Err(last)
}

/// Performs one request and returns the 200 response body.
pub fn fetch(url: &HttpUrl, req: &Request<'_>) -> Result<HttpResponse, HttpError> {
    let mut s = connect(url, req.deadline)?;
    let _ = s.set_nodelay(true);
    let mut head = String::with_capacity(256);
    let method = if req.post.is_some() { "POST" } else { "GET" };
    head.push_str(method);
    head.push(' ');
    head.push_str(&url.path);
    head.push_str(" HTTP/1.0\r\nHost: ");
    head.push_str(&url.authority());
    head.push_str("\r\nAccept: ");
    head.push_str(req.accept);
    head.push_str("\r\nUser-Agent: platd\r\nConnection: close\r\n");
    if let Some((ct, body)) = req.post {
        head.push_str("Content-Type: ");
        head.push_str(ct);
        head.push_str(&format!("\r\nContent-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    s.set_write_timeout(Some(remaining(req.deadline)?)).map_err(|e| io_err(&e))?;
    s.write_all(head.as_bytes()).map_err(|e| io_err(&e))?;
    if let Some((_, body)) = req.post {
        s.set_write_timeout(Some(remaining(req.deadline)?)).map_err(|e| io_err(&e))?;
        s.write_all(body).map_err(|e| io_err(&e))?;
    }
    read_response(&mut s, req)
}

fn read_some(
    s: &mut impl Read,
    buf: &mut [u8],
    deadline: Instant,
    set: &mut dyn FnMut(Duration),
) -> Result<usize, HttpError> {
    set(remaining(deadline)?);
    loop {
        match s.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_err(&e)),
        }
    }
}

fn read_response(s: &mut TcpStream, req: &Request<'_>) -> Result<HttpResponse, HttpError> {
    let sc = s.try_clone().map_err(|_| HttpError::Connect)?;
    let mut set = |d: Duration| {
        let _ = sc.set_read_timeout(Some(d));
    };
    read_from(s, req, &mut set)
}

/// Parses a response from any reader (separated for tests and fuzzing).
pub fn read_from(
    s: &mut impl Read,
    req: &Request<'_>,
    set: &mut dyn FnMut(Duration),
) -> Result<HttpResponse, HttpError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(HttpError::Malformed);
        }
        let n = read_some(s, &mut chunk, req.deadline, set)?;
        if n == 0 {
            return Err(HttpError::Malformed);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if end > MAX_HEADER_BYTES {
        return Err(HttpError::Malformed);
    }
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| HttpError::Malformed)?;
    let mut lines = head.split("\r\n");
    let status = parse_status(lines.next().unwrap_or(""))?;
    let mut content_len: Option<usize> = None;
    let mut content_type = None;
    for l in lines {
        let (k, v) = l.split_once(':').ok_or(HttpError::Malformed)?;
        // RFC 9112 §5.1 / RFC 9110 §5.1: field-name = 1*tchar, no
        // whitespace before the colon (smuggling shape) - reject.
        // DEVIATION (deliberate, RFC-105): a line starting with SP/HTAB
        // (obs-fold) fails `is_token` and the whole response is rejected
        // as Malformed. RFC 9112 §5.2 says a user agent MUST replace
        // obs-fold with SP; we refuse instead (anti-smuggling, and fails
        // closed for a revocation fetcher).
        if !is_token(k) {
            return Err(HttpError::Malformed);
        }
        let v = v.trim();
        if k.eq_ignore_ascii_case("content-length") {
            // Duplicate or non-numeric lengths are request-smuggling shapes.
            if content_len.is_some() || v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(HttpError::Malformed);
            }
            content_len = Some(v.parse::<usize>().map_err(|_| HttpError::TooLarge)?);
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpError::Malformed);
        } else if k.eq_ignore_ascii_case("content-type") {
            let t = v.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            content_type = Some(t);
        }
    }
    if status != 200 {
        return Err(HttpError::Status(status));
    }
    if !req.accept_types.is_empty() && !content_type.as_deref().is_some_and(|t| req.accept_types.contains(&t)) {
        return Err(HttpError::ContentType);
    }
    if content_len.is_some_and(|n| n > req.max_body) {
        return Err(HttpError::TooLarge);
    }
    let mut body = buf.split_off(end + 4);
    let limit = content_len.unwrap_or(req.max_body);
    if body.len() > limit {
        return Err(if content_len.is_some() { HttpError::Malformed } else { HttpError::TooLarge });
    }
    while body.len() < limit || content_len.is_none() {
        let want = (limit + 1 - body.len()).min(chunk.len());
        let n = read_some(s, &mut chunk[..want], req.deadline, set)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > limit {
            return Err(if content_len.is_some() { HttpError::Malformed } else { HttpError::TooLarge });
        }
    }
    if content_len.is_some_and(|n| body.len() != n) {
        return Err(HttpError::Malformed);
    }
    Ok(HttpResponse { body, content_type })
}

/// RFC 9110 §5.6.2 `token` (1*tchar).
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn parse_status(line: &str) -> Result<u16, HttpError> {
    let mut it = line.splitn(3, ' ');
    let ver = it.next().unwrap_or("");
    if ver != "HTTP/1.0" && ver != "HTTP/1.1" {
        return Err(HttpError::Malformed);
    }
    let code = it.next().unwrap_or("");
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpError::Malformed);
    }
    code.parse().map_err(|_| HttpError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(max_body: usize) -> Request<'static> {
        Request {
            post: None,
            accept: "application/pkix-crl",
            accept_types: &["application/pkix-crl", "application/octet-stream"],
            max_body,
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }

    fn parse(raw: &[u8], max_body: usize) -> Result<HttpResponse, HttpError> {
        read_from(&mut &raw[..], &req(max_body), &mut |_| {})
    }

    #[test]
    fn ok_with_and_without_length() {
        let r = parse(b"HTTP/1.0 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: 3\r\n\r\nabc", 10)
            .unwrap();
        assert_eq!(r.body, b"abc");
        let r = parse(b"HTTP/1.1 200 OK\r\ncontent-type: Application/Octet-Stream; x=y\r\n\r\nabcdef", 10).unwrap();
        assert_eq!((r.body.as_slice(), r.content_type.as_deref()), (&b"abcdef"[..], Some("application/octet-stream")));
    }

    #[test]
    fn rejects_hostile_shapes() {
        let ct = "Content-Type: application/pkix-crl\r\n";
        let cases: [(&str, HttpError); 13] = [
            ("HTTP/1.0 200 OK\r\nTransfer-Encoding : chunked\r\n\r\n", HttpError::Malformed),
            ("HTTP/1.0 200 OK\r\n Content-Length: 1\r\n\r\na", HttpError::Malformed),
            ("HTTP/1.0 200 OK\r\n: x\r\n\r\n", HttpError::Malformed),
            ("HTTP/1.0 200 OK\r\nX(y): x\r\n\r\n", HttpError::Malformed),
            ("HTTP/1.0 302 Found\r\nLocation: http://x/\r\n\r\n", HttpError::Status(302)),
            ("HTTP/1.0 500 X\r\n\r\n", HttpError::Status(500)),
            ("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\nx", HttpError::ContentType),
            ("HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc", HttpError::ContentType),
            ("ICY 200 OK\r\n\r\n", HttpError::Malformed),
            ("HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", HttpError::Malformed),
            ("HTTP/1.0 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na", HttpError::Malformed),
            ("HTTP/1.0 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n", HttpError::TooLarge),
            ("HTTP/1.0 200 OK\r\nbad header\r\n\r\n", HttpError::Malformed),
        ];
        for (raw, want) in cases {
            assert_eq!(parse(raw.as_bytes(), 10).unwrap_err(), want, "{raw}");
        }
        // Declared too large: refused before reading the body.
        assert_eq!(
            parse(format!("HTTP/1.0 200 OK\r\n{ct}Content-Length: 11\r\n\r\n").as_bytes(), 10).unwrap_err(),
            HttpError::TooLarge
        );
        // Undeclared and too large while reading.
        let big = format!("HTTP/1.0 200 OK\r\n{ct}\r\n{}", "a".repeat(11));
        assert_eq!(parse(big.as_bytes(), 10).unwrap_err(), HttpError::TooLarge);
        // Short body.
        assert_eq!(
            parse(format!("HTTP/1.0 200 OK\r\n{ct}Content-Length: 5\r\n\r\nab").as_bytes(), 10).unwrap_err(),
            HttpError::Malformed
        );
        // Oversized header block.
        let huge = format!("HTTP/1.0 200 OK\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEADER_BYTES));
        assert_eq!(parse(huge.as_bytes(), 10).unwrap_err(), HttpError::Malformed);
        // Truncated head.
        assert_eq!(parse(b"HTTP/1.0 200 OK\r\n", 10).unwrap_err(), HttpError::Malformed);
    }

    fn leak(lookup: LookupFn, cap: usize) -> &'static Resolver {
        Box::leak(Box::new(Resolver::new(lookup, cap)))
    }

    fn addr() -> Vec<SocketAddr> {
        vec![SocketAddr::from(([192, 0, 2, 1], 80))]
    }

    fn hang(_: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
        std::thread::sleep(Duration::from_secs(3600));
        Ok(addr())
    }

    fn late(_: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
        std::thread::sleep(Duration::from_millis(400));
        Ok(addr())
    }

    fn panics(_: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
        unreachable!("IP literals must not be resolved")
    }

    fn many(_: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok((1..=9).map(|i| SocketAddr::from(([192, 0, 2, i], 80))).collect())
    }

    fn wait_idle(r: &Resolver, within: Duration) -> bool {
        let end = Instant::now() + within;
        while Instant::now() < end {
            if r.stats().in_flight == 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn resolver_never_answers_times_out_within_deadline() {
        let r = leak(hang, 2);
        let t0 = Instant::now();
        assert_eq!(r.resolve("ocsp.example", 80, t0 + Duration::from_millis(100)), Err(HttpError::Timeout));
        assert!(t0.elapsed() < Duration::from_millis(600), "{:?}", t0.elapsed());
        assert_eq!(r.stats().timeouts, 1);
        assert_eq!(r.stats().in_flight, 1);
    }

    #[test]
    fn resolver_late_answer_is_timeout_and_slot_is_released() {
        let r = leak(late, 1);
        let t0 = Instant::now();
        assert_eq!(r.resolve("crl.example", 80, t0 + Duration::from_millis(50)), Err(HttpError::Timeout));
        assert!(t0.elapsed() < Duration::from_millis(350));
        // The hung lookup still holds the only slot: refused without spawning.
        let t1 = Instant::now();
        assert_eq!(r.resolve("crl.example", 80, t1 + Duration::from_secs(5)), Err(HttpError::Timeout));
        assert!(t1.elapsed() < Duration::from_millis(50));
        assert_eq!(r.stats().saturated, 1);
        // Once the abandoned lookup returns, its slot is free again.
        assert!(wait_idle(r, Duration::from_secs(5)));
        assert_eq!(r.resolve("crl.example", 80, Instant::now() + Duration::from_secs(5)), Ok(addr()));
        assert!(wait_idle(r, Duration::from_secs(5)));
    }

    #[test]
    fn resolver_cap_full_fails_immediately() {
        let r = leak(hang, 2);
        for _ in 0..2 {
            assert_eq!(r.resolve("x.example", 80, Instant::now() + Duration::from_millis(20)), Err(HttpError::Timeout));
        }
        let t0 = Instant::now();
        for _ in 0..10 {
            assert_eq!(r.resolve("x.example", 80, Instant::now() + Duration::from_secs(5)), Err(HttpError::Timeout));
        }
        assert!(t0.elapsed() < Duration::from_millis(100));
        assert_eq!(r.stats(), ResolverStats { timeouts: 2, saturated: 10, in_flight: 2 });
    }

    #[test]
    fn resolver_ip_literals_bypass_lookup() {
        let r = leak(panics, 0);
        let d = Instant::now() + Duration::from_secs(1);
        assert_eq!(r.resolve("192.0.2.7", 80, d), Ok(vec![SocketAddr::from(([192, 0, 2, 7], 80))]));
        let v6: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        assert_eq!(r.resolve("2001:db8::1", 8080, d), Ok(vec![v6]));
        assert_eq!(r.resolve("[2001:db8::1]", 8080, d), Ok(vec![v6]));
        assert_eq!(r.stats(), ResolverStats::default());
    }

    #[test]
    fn resolver_caps_addresses_and_expired_deadline() {
        let r = leak(many, 1);
        assert_eq!(r.resolve("x.example", 80, Instant::now() + Duration::from_secs(5)).map(|v| v.len()), Ok(4));
        assert!(wait_idle(r, Duration::from_secs(5)));
        assert_eq!(r.resolve("x.example", 80, Instant::now()), Err(HttpError::Timeout));
        assert_eq!(r.stats().in_flight, 0);
    }

    proptest::proptest! {
        #[test]
        fn never_panics(raw in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)) {
            let _ = parse(&raw, 1024);
        }
    }
}
