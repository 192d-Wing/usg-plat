//! Certificate and private-key loading.
//!
//! Files are opened once; permissions are checked on the open handle
//! (`fstat`), then read from it, so a file swapped between check and read
//! is not accepted. Key bytes are held in [`Zeroizing`] buffers that are
//! wiped on drop.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management),
//!   IA-5(2)(a)(1) (authorized access to the private key) - key files must be private to the
//!   service user (or root-owned and readable by the service group only),
//!   key bytes zeroized after use.
//! - NIST 800-53: SC-5 - every file read is size-capped.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use zeroize::Zeroizing;

use crate::TlsError;

/// Largest certificate bundle or key file read (bytes).
pub const MAX_PEM_BYTES: u64 = 1 << 20;
/// Most certificates accepted from one file.
pub const MAX_CERTS_PER_FILE: usize = 256;

/// Accept/reject decision for a key file (Q4), separate from the file
/// system so every case is testable without root.
///
/// Accepted:
/// - owned by `euid`, mode one of 0600/0400/0640/0440 (owner read, no
///   owner execute, no group write/execute, no other bits);
/// - owned by root, group `egid`, group-readable (0640/0440).
///
/// Everything else is rejected, including any other-bits, group write,
/// setuid/setgid/sticky bits, or any other owner.
pub fn key_perm_decision(uid: u32, gid: u32, mode: u32, euid: u32, egid: u32) -> Result<(), String> {
    if mode & 0o7000 != 0 {
        return Err(format!("mode {:04o} has setuid/setgid/sticky bits", mode & 0o7777));
    }
    let perm = mode & 0o777;
    if perm & 0o007 != 0 {
        return Err(format!("mode {perm:04o} grants access to others"));
    }
    if perm & 0o030 != 0 {
        return Err(format!("mode {perm:04o} grants group write/execute"));
    }
    if perm & 0o100 != 0 {
        return Err(format!("mode {perm:04o} is executable"));
    }
    if perm & 0o400 == 0 {
        return Err(format!("mode {perm:04o} is not owner-readable"));
    }
    if uid == euid {
        return Ok(());
    }
    // Root-owned with our group: we read it through the group bit.
    if uid == 0 && gid == egid && perm & 0o040 != 0 {
        return Ok(());
    }
    Err(format!("owned by uid {uid} gid {gid}; must be owned by uid {euid}, or by root with group {egid}"))
}

/// Opens `path` read-only without blocking on FIFOs or devices: the open
/// uses `O_NONBLOCK`, the type is checked on the handle (`fstat`), and
/// only a regular file has `O_NONBLOCK` cleared and is returned. Anything
/// else fails with `InvalidInput` ("not a regular file").
///
/// Used for every operator-supplied file (certificates, keys, CRL files,
/// the CRL disk cache), so a FIFO or device at a configured path cannot
/// hang start-up, `check-config` or the refresher.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5 - no unbounded block on a hostile path
#[cfg(unix)]
pub fn open_regular(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{FileType, Mode, OFlags};
    let fd =
        rustix::fs::open(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY, Mode::empty())?;
    let st = rustix::fs::fstat(&fd)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"));
    }
    let fl = rustix::fs::fcntl_getfl(&fd)?;
    rustix::fs::fcntl_setfl(&fd, fl - OFlags::NONBLOCK)?;
    Ok(File::from(fd))
}

/// Non-Unix: open, then reject non-regular files on the handle.
#[cfg(not(unix))]
pub fn open_regular(path: &Path) -> std::io::Result<File> {
    let f = File::open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(f)
}

/// [`open_regular`] mapped to [`TlsError`]; a non-regular file is a
/// permissions error.
fn open_checked(path: &Path) -> Result<File, TlsError> {
    open_regular(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::InvalidInput {
            TlsError::Permissions(path.into(), "not a regular file".into())
        } else {
            TlsError::Io(path.into(), e)
        }
    })
}

#[cfg(unix)]
fn check_open_key(path: &Path, f: &File) -> Result<(), TlsError> {
    use std::os::unix::fs::MetadataExt;
    let md = f.metadata().map_err(|e| TlsError::Io(path.into(), e))?;
    if !md.is_file() {
        return Err(TlsError::Permissions(path.into(), "not a regular file".into()));
    }
    let euid = rustix::process::geteuid().as_raw();
    let egid = rustix::process::getegid().as_raw();
    key_perm_decision(md.uid(), md.gid(), md.mode(), euid, egid).map_err(|m| TlsError::Permissions(path.into(), m))
}

// POAM: POAM-025 (narrowed) - non-Unix builds do not check key-file
// permissions; the daemon only targets Linux.
#[cfg(not(unix))]
fn check_open_key(_path: &Path, _f: &File) -> Result<(), TlsError> {
    Ok(())
}

/// Checks a private-key file's ownership and mode without reading it.
pub fn check_key_file(path: &Path) -> Result<(), TlsError> {
    let f = open_checked(path)?;
    check_open_key(path, &f)
}

/// Reads at most [`MAX_PEM_BYTES`] from `f` into a zeroizing buffer.
fn read_capped(path: &Path, f: File) -> Result<Zeroizing<Vec<u8>>, TlsError> {
    let mut buf = Zeroizing::new(Vec::new());
    f.take(MAX_PEM_BYTES + 1).read_to_end(&mut buf).map_err(|e| TlsError::Io(path.into(), e))?;
    if buf.len() as u64 > MAX_PEM_BYTES {
        return Err(TlsError::TooLarge(path.into(), MAX_PEM_BYTES));
    }
    Ok(buf)
}

/// Loads every PEM `CERTIFICATE` in `path` (at least one).
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let f = open_checked(path)?;
    let buf = read_capped(path, f)?;
    let mut out = Vec::new();
    for c in CertificateDer::pem_slice_iter(&buf) {
        let c = c.map_err(|e| TlsError::Pem(path.into(), e.to_string()))?;
        if out.len() == MAX_CERTS_PER_FILE {
            return Err(TlsError::Pem(path.into(), format!("more than {MAX_CERTS_PER_FILE} certificates")));
        }
        out.push(c);
    }
    if out.is_empty() {
        return Err(TlsError::NoCertificates(path.into()));
    }
    Ok(out)
}

/// Loads the first private key (PKCS#8, PKCS#1 or SEC1 PEM) in `path`
/// after checking the file's permissions. Encrypted keys are rejected.
///
/// The file buffer is zeroized on return. The returned `PrivateKeyDer`
/// should be dropped as soon as the rustls config is built (AWS-LC keeps
/// its own copy inside the module).
pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let f = open_checked(path)?;
    check_open_key(path, &f)?;
    let buf = read_capped(path, f)?;
    if buf.windows(31).any(|w| w == b"-----BEGIN ENCRYPTED PRIVATE KE") {
        return Err(TlsError::EncryptedKey(path.into()));
    }
    match PrivateKeyDer::from_pem_slice(&buf) {
        Ok(k) => Ok(k),
        Err(rustls_pki_types::pem::Error::NoItemsFound) => Err(TlsError::NoKey(path.into())),
        Err(e) => Err(TlsError::Pem(path.into(), e.to_string())),
    }
}

/// Checks the optional on-disk revocation cache directory: a directory
/// owned by the effective uid with no group/other access (0700).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: IA-5(2)(b)(2) - protection of the local revocation cache
/// - NIST 800-53: AC-6, SI-7 - cached CRLs are re-verified on load anyway;
///   the directory rule stops other users planting or reading files.
pub fn check_cache_dir(path: &Path) -> Result<(), TlsError> {
    let md = std::fs::metadata(path).map_err(|e| TlsError::Io(path.into(), e))?;
    if !md.is_dir() {
        return Err(TlsError::Permissions(path.into(), "not a directory".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let euid = rustix::process::geteuid().as_raw();
        if md.uid() != euid {
            return Err(TlsError::Permissions(path.into(), format!("owned by uid {}, not {euid}", md.uid())));
        }
        if md.mode() & 0o077 != 0 {
            return Err(TlsError::Permissions(path.into(), format!("mode {:04o}; must be 0700", md.mode() & 0o777)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: (u32, u32) = (1000, 1000);

    fn d(uid: u32, gid: u32, mode: u32) -> Result<(), String> {
        key_perm_decision(uid, gid, mode, ME.0, ME.1)
    }

    #[test]
    fn own_key_modes() {
        for ok in [0o600, 0o400, 0o640, 0o440, 0o100_600] {
            d(1000, 1000, ok).unwrap();
            d(1000, 42, ok).unwrap();
        }
        for bad in [0o644, 0o660, 0o606, 0o620, 0o666, 0o604, 0o700, 0o610, 0o200, 0o000, 0o4600, 0o2640, 0o1600] {
            assert!(d(1000, 1000, bad).is_err(), "{bad:o}");
        }
    }

    #[test]
    fn root_owned_needs_our_group_and_group_read() {
        d(0, 1000, 0o640).unwrap();
        d(0, 1000, 0o440).unwrap();
        assert!(d(0, 1000, 0o600).is_err());
        assert!(d(0, 1000, 0o400).is_err());
        assert!(d(0, 7, 0o640).is_err());
        assert!(d(0, 1000, 0o660).is_err());
        assert!(d(0, 1000, 0o644).is_err());
    }

    #[test]
    fn foreign_owner_rejected() {
        assert!(d(1001, 1000, 0o600).is_err());
        assert!(d(1001, 1000, 0o640).is_err());
    }
}
