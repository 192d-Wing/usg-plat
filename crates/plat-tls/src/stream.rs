//! Blocking TLS I/O over a `TcpStream` with a hard deadline.
//!
//! `rustls::Stream::complete_io` applies the socket timeout per read, so a
//! peer that trickles one byte per timeout could hold a handshake open
//! indefinitely. These helpers drive `read_tls`/`write_tls` themselves and
//! re-arm the socket timeouts to the time left before one deadline, so a
//! handshake (including the revocation check run by the verifier) never
//! outlives it.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - handshake time is
//!   bounded per connection (management `handshake_timeout_ms`, syslog
//!   `max(2 s, revocation budget + 1 s)`)
//! - NIST 800-53: SC-10 - stalled peers are disconnected

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::ops::DerefMut;
use std::time::{Duration, Instant};

use rustls::{CertificateError, ConnectionCommon, SideData};

/// Why a handshake or TLS write failed.
#[derive(Debug)]
pub enum TlsIoError {
    /// The deadline passed (or a socket timeout fired).
    Timeout,
    /// The peer closed the connection or a socket error occurred.
    Io(io::Error),
    /// TLS protocol or certificate verification failure.
    Tls(rustls::Error),
}

/// Coarse class of a [`TlsIoError`], for audit reasons and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    Timeout,
    Io,
    /// The peer sent no certificate (server side, client auth required).
    NoCertificate,
    /// A certificate was revoked (full-chain revocation check).
    Revoked,
    /// Revocation status could not be established (hard_fail, stale data,
    /// attack-class OCSP/CRL failure, path rebuild failure).
    RevocationUnknown,
    /// Any other certificate verification failure (unknown CA, name,
    /// validity, usage, signature).
    BadCertificate,
    /// Any other TLS failure (alert, version or group mismatch, decode).
    Handshake,
}

impl TlsIoError {
    pub fn class(&self) -> FailureClass {
        match self {
            Self::Timeout => FailureClass::Timeout,
            Self::Io(_) => FailureClass::Io,
            Self::Tls(e) => match e {
                rustls::Error::NoCertificatesPresented => FailureClass::NoCertificate,
                rustls::Error::InvalidCertificate(CertificateError::Revoked) => FailureClass::Revoked,
                rustls::Error::InvalidCertificate(CertificateError::UnknownRevocationStatus) => {
                    FailureClass::RevocationUnknown
                }
                rustls::Error::InvalidCertificate(_) => FailureClass::BadCertificate,
                // The peer rejected our certificate (mutual TLS) or the
                // alert names a certificate problem.
                rustls::Error::AlertReceived(a) if is_cert_alert(*a) => FailureClass::BadCertificate,
                _ => FailureClass::Handshake,
            },
        }
    }
}

fn is_cert_alert(a: rustls::AlertDescription) -> bool {
    use rustls::AlertDescription as A;
    matches!(
        a,
        A::BadCertificate
            | A::UnsupportedCertificate
            | A::CertificateRevoked
            | A::CertificateExpired
            | A::CertificateUnknown
            | A::UnknownCA
            | A::CertificateRequired
    )
}

impl std::fmt::Display for TlsIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("TLS deadline exceeded"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Tls(e) => write!(f, "TLS: {e}"),
        }
    }
}

impl std::error::Error for TlsIoError {}

fn io_err(e: io::Error) -> TlsIoError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => TlsIoError::Timeout,
        _ => match e.get_ref().and_then(<dyn std::error::Error + Send + Sync>::downcast_ref::<rustls::Error>) {
            Some(t) => TlsIoError::Tls(t.clone()),
            None => TlsIoError::Io(e),
        },
    }
}

/// Sets both socket timeouts to the time left before `deadline`.
fn arm(sock: &TcpStream, deadline: Instant) -> Result<(), TlsIoError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(TlsIoError::Timeout);
    }
    // A zero duration is rejected by the OS API; `left` is non-zero here.
    sock.set_read_timeout(Some(left)).map_err(TlsIoError::Io)?;
    sock.set_write_timeout(Some(left)).map_err(TlsIoError::Io)
}

fn flush_tls<C, D>(conn: &mut C, sock: &mut TcpStream, deadline: Instant) -> Result<(), TlsIoError>
where
    C: DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
    while conn.wants_write() {
        arm(sock, deadline)?;
        match conn.write_tls(sock) {
            Ok(0) => return Err(TlsIoError::Io(io::ErrorKind::WriteZero.into())),
            Ok(_) => {}
            Err(e) => return Err(io_err(e)),
        }
    }
    Ok(())
}

/// Completes the handshake before `deadline`. On a TLS error the alert is
/// sent best-effort. The certificate verifier (and so the revocation check)
/// runs inside this call, on the calling thread.
pub fn handshake<C, D>(conn: &mut C, sock: &mut TcpStream, deadline: Instant) -> Result<(), TlsIoError>
where
    C: DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
    while conn.is_handshaking() {
        flush_tls(conn, sock, deadline)?;
        if !conn.is_handshaking() {
            break;
        }
        arm(sock, deadline)?;
        match conn.read_tls(sock) {
            Ok(0) => return Err(TlsIoError::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(_) => {}
            Err(e) => return Err(io_err(e)),
        }
        if let Err(e) = conn.process_new_packets() {
            // Send our alert, bounded by the same deadline.
            let _ = flush_tls(conn, sock, deadline);
            return Err(TlsIoError::Tls(e));
        }
    }
    flush_tls(conn, sock, deadline)
}

/// Server side: reads until the peer's ClientHello has been processed
/// (the server has its first flight to send) before `deadline`. Run with a
/// short deadline ahead of [`handshake`] so a client that connects and
/// then sends nothing, or trickles its ClientHello, releases its
/// connection slot quickly instead of holding it for the full handshake
/// timeout.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - first-flight deadline (slowloris)
pub fn await_client_hello<C, D>(conn: &mut C, sock: &mut TcpStream, deadline: Instant) -> Result<(), TlsIoError>
where
    C: DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
    while conn.is_handshaking() && !conn.wants_write() {
        arm(sock, deadline)?;
        match conn.read_tls(sock) {
            Ok(0) => return Err(TlsIoError::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(_) => {}
            Err(e) => return Err(io_err(e)),
        }
        if let Err(e) = conn.process_new_packets() {
            let _ = flush_tls(conn, sock, deadline);
            return Err(TlsIoError::Tls(e));
        }
    }
    Ok(())
}

/// Writes all of `data` as application data and flushes it to the socket
/// before `deadline`. Never reads from the socket.
pub fn write_all<C, D>(conn: &mut C, sock: &mut TcpStream, mut data: &[u8], deadline: Instant) -> Result<(), TlsIoError>
where
    C: DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
    while !data.is_empty() {
        // Plaintext is accepted up to the connection's buffer limit; the
        // rest goes in later rounds once the TLS records are on the wire.
        let n = conn.writer().write(data).map_err(io_err)?;
        data = data.get(n..).unwrap_or_default();
        if n == 0 && !conn.wants_write() {
            return Err(TlsIoError::Io(io::ErrorKind::WriteZero.into()));
        }
        flush_tls(conn, sock, deadline)?;
    }
    flush_tls(conn, sock, deadline)
}

/// Reads application data into `buf` until `stop(buf_so_far)` is true, the
/// buffer is full, the peer closes, or `deadline` passes. Returns the
/// number of bytes read.
pub fn read_until<C, D>(
    conn: &mut C,
    sock: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
    stop: impl Fn(&[u8]) -> bool,
) -> Result<usize, TlsIoError>
where
    C: DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
    let mut n = 0;
    while n < buf.len() {
        let Some(rest) = buf.get_mut(n..) else { break };
        match conn.reader().read(rest) {
            Ok(0) => break,
            Ok(k) => {
                n += k;
                if buf.get(..n).is_some_and(&stop) {
                    break;
                }
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(io_err(e)),
        }
        arm(sock, deadline)?;
        match conn.read_tls(sock) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => return Err(io_err(e)),
        }
        if let Err(e) = conn.process_new_packets() {
            let _ = flush_tls(conn, sock, deadline);
            return Err(TlsIoError::Tls(e));
        }
        flush_tls(conn, sock, deadline)?;
    }
    Ok(n)
}

/// Sends `close_notify` best-effort, bounded by `limit` (RFC 8446 §6.1,
/// RFC 5425 §4.4).
pub fn close<C, D>(conn: &mut C, sock: &mut TcpStream, limit: Duration)
where
    C: DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
    conn.send_close_notify();
    let _ = flush_tls(conn, sock, Instant::now() + limit);
}

/// TLS 1.3 client: the server verifies the client (its certificate, or
/// that one is required) only after our Finished, so a rejection arrives
/// as an alert after [`handshake`] returned. Waits up to `wait` for it;
/// silence is success. Without this a collector that rejects us would
/// silently swallow the first batch (counted as delivered).
pub fn await_rejection<C, D>(conn: &mut C, sock: &mut TcpStream, wait: Duration) -> Result<(), TlsIoError>
where
    C: DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
    if wait.is_zero() {
        return Ok(());
    }
    sock.set_read_timeout(Some(wait)).map_err(TlsIoError::Io)?;
    match conn.read_tls(sock) {
        Ok(0) => Err(TlsIoError::Io(io::ErrorKind::UnexpectedEof.into())),
        Ok(_) => conn.process_new_packets().map(|_| ()).map_err(TlsIoError::Tls),
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(()),
        Err(e) => Err(io_err(e)),
    }
}
