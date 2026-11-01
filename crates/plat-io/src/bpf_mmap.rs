//! Shared-memory views of `BPF_F_MMAPABLE` array maps (Linux): `platd`
//! writes the `SLOT`, `SLICE` and `CONTROL` records of the XDP fast path
//! with plain atomic stores instead of a `bpf()` syscall per field (plan
//! §4.1, §4.3).
//!
//! The mapping is the kernel's array memory itself: the eBPF program reads
//! (and, for `SLOT.seen_ns`, writes) the same pages concurrently. The views
//! are therefore atomics only ([`MmapRegion::words`], [`MmapRegion::bytes`]);
//! there is no `&mut` or plain-reference access. Array element memory is
//! never freed while the mapping exists (the mapping holds a reference on
//! the map), so the views stay valid until [`MmapRegion`] is dropped.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-24 (Fail in Known State) - slice fencing and the
//!   dead-man deadline are single atomic stores visible to the program at
//!   once
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - fixed-size mapping
//!   of a fixed-size map; no allocation after creation

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU8, AtomicU64};

/// A read-write `MAP_SHARED` mapping of an mmapable BPF array, unmapped on
/// drop.
#[derive(Debug)]
pub struct MmapRegion {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: the region is only ever accessed through atomics (`words`,
// `bytes`), which are safe to share and send between threads; the pointer
// is owned exclusively by this value and unmapped once, in `drop`.
unsafe impl Send for MmapRegion {}
// SAFETY: as above: shared access is atomic only.
unsafe impl Sync for MmapRegion {}

impl MmapRegion {
    /// Maps the first `len` bytes of the map behind `fd` (opened
    /// read-write; the map created with `BPF_F_MMAPABLE` and not frozen).
    /// `len` must be a non-zero multiple of 8 and at most the array's
    /// `max_entries × round_up(value_size, 8)` rounded up to a page; the
    /// kernel refuses anything larger.
    pub fn from_fd(fd: BorrowedFd<'_>, len: usize) -> io::Result<Self> {
        if len == 0 || !len.is_multiple_of(8) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "mmap length must be a non-zero multiple of 8"));
        }
        // SAFETY: a fresh mapping (addr NULL) of `len` bytes; no existing
        // memory is affected. The kernel validates `fd`, the map type and
        // the length.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(p.cast::<u8>()).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(Self { ptr, len })
    }

    /// Length of the mapping in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The mapping as 64-bit words (host order).
    pub fn words(&self) -> &[AtomicU64] {
        // SAFETY: `ptr` is page-aligned (so aligned for `AtomicU64`), valid
        // for `len` bytes (a multiple of 8) until `drop`, and only accessed
        // atomically, so concurrent writers (the program, other threads)
        // cannot cause a data race in Rust's model.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast::<AtomicU64>(), self.len / 8) }
    }

    /// The mapping as bytes.
    pub fn bytes(&self) -> &[AtomicU8] {
        // SAFETY: as for `words`, with byte alignment.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast::<AtomicU8>(), self.len) }
    }
}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` are exactly the mapping created in `from_fd`;
        // no view can outlive `self` (they borrow it).
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn rejects_bad_lengths() {
        let f = std::fs::File::open("/dev/null").unwrap_or_else(|e| panic!("{e}"));
        assert!(MmapRegion::from_fd(f.as_fd(), 0).is_err());
        assert!(MmapRegion::from_fd(f.as_fd(), 12).is_err());
    }

    #[test]
    fn maps_a_shared_file() {
        // Any MAP_SHARED-capable descriptor exercises the view code; BPF
        // arrays are covered by the root level-2 suite (plat-xdp).
        let p = std::env::temp_dir().join(format!("plat-io-mmap-{}", std::process::id()));
        std::fs::write(&p, [0u8; 4096]).unwrap_or_else(|e| panic!("{e}"));
        let f = std::fs::OpenOptions::new().read(true).write(true).open(&p).unwrap_or_else(|e| panic!("{e}"));
        let r = MmapRegion::from_fd(f.as_fd(), 4096).unwrap_or_else(|e| panic!("{e}"));
        r.words()[1].store(0x0102_0304_0506_0708, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(r.words().len(), 512);
        assert_eq!(r.bytes()[8].load(std::sync::atomic::Ordering::Relaxed), 0x0102_0304_0506_0708u64.to_ne_bytes()[0]);
        drop(r);
        let back = std::fs::read(&p).unwrap_or_else(|e| panic!("{e}"));
        let _ = std::fs::remove_file(&p);
        assert_eq!(back.get(8..16), Some(&0x0102_0304_0506_0708u64.to_ne_bytes()[..]));
    }
}
