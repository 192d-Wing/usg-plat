//! Minimal HTTP/1.0 client for OCSP (RFC 6960 Appendix A) and CRL
//! (RFC 5280 §4.2.1.13) fetches over `std::net::TcpStream`.
//!
//! Responder bytes are hostile: the header block is capped, the body is
//! capped (checked against `Content-Length` before reading, enforced while
//! reading), chunked transfer encoding is refused, redirects are not
//! followed (any non-200 status is an error), and every connect/read/write
//! is bounded by the caller's deadline.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 - size and time bounds on every fetch
//! - NIST 800-53: SI-10 - strict parsing of the status line and headers

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use plat_common::HttpUrl;

/// Header block cap (status line + headers).
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

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
    // POAM: POAM-025 - `ToSocketAddrs` name resolution has no timeout; use
    // IP literals or a local resolver for responders/CDPs.
    let addrs: Vec<SocketAddr> =
        (url.host.as_str(), url.port).to_socket_addrs().map_err(|_| HttpError::Connect)?.take(4).collect();
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

    proptest::proptest! {
        #[test]
        fn never_panics(raw in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)) {
            let _ = parse(&raw, 1024);
        }
    }
}
