//! Packet I/O. One [`PacketQueue`] per worker thread, so workers never share
//! a descriptor or a lock on the I/O path.

use std::io;
use std::time::Duration;

#[cfg(target_os = "linux")]
pub mod tun;

/// BPF map pins and element operations (XDP fast path; plan §2.2).
#[cfg(target_os = "linux")]
pub mod bpf_obj;

/// Shared-memory views of mmapable BPF arrays (XDP fast path).
#[cfg(target_os = "linux")]
pub mod bpf_mmap;

/// Interface index and MAC by name (XDP loader).
#[cfg(target_os = "linux")]
pub mod netdev;

pub mod mem;

pub mod cred;

/// How long `recv` waits before returning `Ok(None)`, so workers can
/// observe shutdown.
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A bidirectional packet queue owned by one worker.
pub trait PacketQueue: Send {
    /// Reads one packet into `buf`. `Ok(None)` on timeout.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>>;
    /// Writes one packet. Must not block indefinitely.
    fn send(&mut self, pkt: &[u8]) -> io::Result<()>;
}
