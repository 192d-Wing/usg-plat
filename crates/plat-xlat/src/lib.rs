//! Stateless IP/ICMP translation (SIIT, RFC 7915) and IPv4-embedded IPv6
//! address mapping (RFC 6052).
//!
//! The fast path rewrites packets **in place**: the caller reads each packet
//! into a buffer at offset [`HEADROOM`] so an IPv4→IPv6 translation (which
//! grows the header by 20–28 bytes) can be written in front of the payload
//! without copying it. ICMP errors take a slower copy-based path because
//! the quoted inner packet changes size too.

pub mod icmp;
pub mod rfc6052;
pub mod siit;

pub use rfc6052::Prefix6052;
pub use siit::{Frags, Map4, Map6, XlatError, v4_to_v6, v4_to_v6_fragments, v6_to_v4, v6_to_v4_fragments};

/// Bytes reserved in front of every received packet.
pub const HEADROOM: usize = 64;
