//! Peer credentials of a connected Unix stream socket (the cluster
//! operator socket).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement), AU-3 - the kernel-reported uid
//!   (and pid on Linux) of the process on the other end, used to authorize
//!   and attribute operator commands

use std::io;
use std::os::fd::AsFd;

/// Credentials of the peer process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    /// Not available on macOS (`getpeereid` returns uid and gid only).
    pub pid: Option<i32>,
}

/// `SO_PEERCRED` (Linux).
#[cfg(target_os = "linux")]
pub fn peer_cred(fd: impl AsFd) -> io::Result<PeerCred> {
    let c = rustix::net::sockopt::socket_peercred(fd)?;
    Ok(PeerCred { uid: c.uid.as_raw(), pid: Some(c.pid.as_raw_nonzero().get()) })
}

/// `getpeereid` (macOS: development hosts).
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub fn peer_cred(fd: impl AsFd) -> io::Result<PeerCred> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: `raw` is a valid descriptor borrowed for this call; `uid` and
    // `gid` are valid, writable locals of the types getpeereid(3) expects.
    let r = unsafe { libc::getpeereid(raw, &mut uid, &mut gid) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCred { uid, pid: None })
}

/// Unsupported platforms: no credentials (the caller refuses).
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn peer_cred(_fd: impl AsFd) -> io::Result<PeerCred> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "peer credentials unavailable"))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn own_uid_over_a_socket_pair() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap_or_else(|e| panic!("{e}"));
        let c = peer_cred(&a).unwrap_or_else(|e| panic!("{e}"));
        // A file this process creates is owned by its effective uid.
        let f = std::env::temp_dir().join(format!("plat-io-cred-{}", std::process::id()));
        std::fs::write(&f, b"x").unwrap_or_else(|e| panic!("{e}"));
        let uid = std::fs::metadata(&f).map(|m| std::os::unix::fs::MetadataExt::uid(&m));
        let _ = std::fs::remove_file(&f);
        assert_eq!(Ok(c.uid), uid.map_err(|e| e.to_string()));
        #[cfg(target_os = "linux")]
        assert_eq!(c.pid, Some(std::process::id() as i32));
    }
}
