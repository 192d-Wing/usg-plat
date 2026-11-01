//! Interface index and hardware address by name (Linux), resolved in the
//! caller's network namespace with `SIOCGIFINDEX` / `SIOCGIFHWADDR` on an
//! `AF_UNIX` datagram socket.
//!
//! `AF_UNIX` because the XDP loader runs with
//! `RestrictAddressFamilies=AF_NETLINK AF_UNIX` (plan §7); the kernel
//! answers these device ioctls for any socket family. Not `/sys/class/net`:
//! `nsenter --net` keeps the outer namespace's `/sys` (plan §11 level 2).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-6 (Least Privilege) - no `AF_INET` socket needed

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const SIOCGIFHWADDR: libc::Ioctl = 0x8927;
const SIOCGIFINDEX: libc::Ioctl = 0x8933;
/// `ARPHRD_ETHER`.
const ARPHRD_ETHER: u16 = 1;

/// `struct ifreq`: name, then a 24-byte union (`ifr_ifindex`,
/// `ifr_hwaddr`).
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    data: [u8; 24],
}

fn ifreq(name: &str) -> io::Result<IfReq> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() >= libc::IFNAMSIZ || b.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name"));
    }
    let mut r = IfReq { name: [0; libc::IFNAMSIZ], data: [0; 24] };
    for (d, s) in r.name.iter_mut().zip(b) {
        *d = *s as libc::c_char;
    }
    Ok(r)
}

fn socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); no pointers.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn ioctl(req: libc::Ioctl, r: &mut IfReq) -> io::Result<()> {
    let s = socket()?;
    // SAFETY: `r` is a valid, writable `struct ifreq` for the duration of
    // the call; both requests read the name and write the union only.
    let rc = unsafe { libc::ioctl(s.as_raw_fd(), req, std::ptr::from_mut(r)) };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// The ifindex of `name`.
pub fn index(name: &str) -> io::Result<u32> {
    let mut r = ifreq(name)?;
    ioctl(SIOCGIFINDEX, &mut r)?;
    let (i, _) = r.data.split_first_chunk::<4>().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    u32::try_from(i32::from_ne_bytes(*i)).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

/// The Ethernet address of `name`; an error for non-Ethernet devices.
pub fn hw_addr(name: &str) -> io::Result<[u8; 6]> {
    let mut r = ifreq(name)?;
    ioctl(SIOCGIFHWADDR, &mut r)?;
    // `struct sockaddr`: `sa_family` (u16), then the address bytes.
    let (fam, rest) = r.data.split_first_chunk::<2>().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    if u16::from_ne_bytes(*fam) != ARPHRD_ETHER {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "not an Ethernet interface"));
    }
    rest.first_chunk::<6>().copied().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback() {
        assert_eq!(index("lo").ok(), Some(1));
        // Loopback is ARPHRD_LOOPBACK, not Ethernet.
        assert!(hw_addr("lo").is_err());
    }

    #[test]
    fn bad_names() {
        assert!(index("").is_err());
        assert!(index("a-name-longer-than-15").is_err());
        assert!(index("plat-nonexist0").is_err());
    }
}
