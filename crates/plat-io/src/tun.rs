//! Linux multiqueue TUN (`IFF_MULTI_QUEUE`): one file descriptor per worker;
//! the kernel spreads flows across queues by hash.
//!
//! The interface itself (addresses, routes for the NAT64 prefix and the
//! IPv4 pool, MTU) is created and configured outside the daemon as a
//! persistent multiqueue TUN owned by the daemon's user and group (see
//! `deploy/systemd/plat-tun-setup.sh`). Attaching queues to a TUN device the
//! caller owns needs no capability (the kernel's `tun_not_capable` check
//! passes on owner/group match), so the daemon runs with **no**
//! capabilities. If the device is missing or owned by someone else,
//! `TUNSETIFF` fails with `EPERM` and the daemon exits.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)

#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::{POLL_INTERVAL, PacketQueue};

const TUNSETIFF: u64 = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

#[derive(Debug)]
pub struct TunQueue {
    fd: OwnedFd,
}

fn poll(fd: i32, events: libc::c_short, timeout_ms: i32) -> io::Result<bool> {
    let mut p = libc::pollfd { fd, events, revents: 0 };
    // SAFETY: `p` is a valid pollfd for the duration of the call; nfds = 1.
    let r = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    match r {
        -1 => {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted { Ok(false) } else { Err(e) }
        }
        0 => Ok(false),
        _ => Ok(true),
    }
}

impl TunQueue {
    /// Attaches `queues` queues to the existing persistent TUN interface
    /// `name` (see the module docs; creating it would need CAP_NET_ADMIN).
    pub fn open_multi(name: &str, queues: usize) -> io::Result<Vec<TunQueue>> {
        let cname = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        if cname.as_bytes().len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name too long"));
        }
        (0..queues).map(|_| Self::open_one(&cname)).collect()
    }

    fn open_one(name: &CString) -> io::Result<TunQueue> {
        let path = c"/dev/net/tun";
        // SAFETY: `path` is NUL-terminated; flags are valid open(2) flags.
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly opened descriptor we exclusively own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut ifr = IfReq { name: [0; libc::IFNAMSIZ], flags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE, _pad: [0; 22] };
        for (d, s) in ifr.name.iter_mut().zip(name.as_bytes()) {
            *d = *s as libc::c_char;
        }
        // SAFETY: TUNSETIFF reads/writes a `struct ifreq`; `IfReq` matches its
        // layout (name[IFNAMSIZ], short flags, padding to 40 bytes) and lives
        // for the duration of the call.
        let r = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut ifr as *mut IfReq) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(TunQueue { fd })
    }
}

impl PacketQueue for TunQueue {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        loop {
            // SAFETY: `buf` is valid for writes of `buf.len()` bytes.
            let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n >= 0 {
                return Ok(Some(n as usize));
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => {
                    if !poll(self.fd.as_raw_fd(), libc::POLLIN, POLL_INTERVAL.as_millis() as i32)? {
                        return Ok(None);
                    }
                }
                io::ErrorKind::Interrupted => {}
                _ => return Err(e),
            }
        }
    }

    /// Writes one packet. A full device queue (`EAGAIN`, returned as
    /// `ErrorKind::WouldBlock`) drops the packet immediately; the worker
    /// counts it as `tx_queue_full`, distinct from `io_errors`. Waiting would
    /// stall every flow on this worker for one congested packet.
    fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        loop {
            // SAFETY: `pkt` is valid for reads of `pkt.len()` bytes.
            let n = unsafe { libc::write(self.fd.as_raw_fd(), pkt.as_ptr().cast(), pkt.len()) };
            if n >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}
