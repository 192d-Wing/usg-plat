//! Translation core of the XDP fast path for established UDP sessions
//! (POAM-016 Phase 1), shared by the eBPF program (`plat-xdp-ebpf`) and the
//! host differential tests.
//!
//! The crate is `no_std`, allocates nothing, has no dependencies and no
//! `unsafe`, so the same source builds for the host and for
//! `bpfel-unknown-none`. It knows one fixed frame layout: untagged Ethernet
//! II, then IPv6 (40 bytes, next header UDP) or IPv4 (IHL 5, unfragmented),
//! then UDP. Everything else is declined with a [`abi::PassReason`] and the
//! program hands the frame, unmodified, to the kernel and the `platd` slow
//! path (`XDP_PASS`).
//!
//! - [`abi`]: BPF map keys and values, the `bpf_fib_lookup` layout, counter
//!   and pass-reason indices. Every layout has compile-time size and offset
//!   asserts.
//! - [`classify`]: fixed-offset header checks (a strict subset of what
//!   `plat-packet` accepts, with identical field values).
//! - [`rewrite`]: the IPv6⇄IPv4 header rewrite of RFC 7915 for one UDP
//!   packet, with the RFC 1624 checksum update.
//! - [`csum`]: bit-exact ports of `plat_packet::checksum`.
//! - [`ident`]: the RFC 7739 §5.3 IPv4 Identification counter step.
//! - [`decide`]: the per-packet decision over an [`decide::Env`] (map
//!   lookups, FIB, clock) that the eBPF program and the tests implement.
//!
//! No RFC 6052 code lives here: `platd` stores the synthesized addresses in
//! the session record, and the fast path matches exact keys and copies
//! addresses.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-10 (Information Input Validation) - fixed-layout
//!   validation; malformed input is declined, never a panic
//! - NIST 800-53: SC-7 (Boundary Protection), SC-24 - exact session match,
//!   slice fencing, dead-man deadline, interface roles and the
//!   per-direction egress allow-list. Decision logic only; enforcement
//!   requires `plat-xdp-ebpf` (WU2) and the `platd` writer (WU4)
//! - RFC 7915 §4.1, §5.1 - header translation; RFC 1624 - checksum update

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod abi;
pub mod classify;
pub mod csum;
pub mod decide;
pub mod ident;
pub mod rewrite;

pub use abi::{PassReason, StatIdx};
pub use classify::{V4Meta, V6Meta, classify_v4, classify_v6};
pub use decide::{Action, Env, Verdict, decide_frame, decide_v4, decide_v6};
pub use rewrite::{rewrite_v4_to_v6, rewrite_v6_to_v4};

/// Ethernet header length.
pub const ETH: usize = 14;
/// IPv6 fixed header length.
pub const IP6: usize = 40;
/// IPv4 header length without options.
pub const IP4: usize = 20;
/// UDP header length.
pub const UDP: usize = 8;
/// Header block the IPv6 side reads and writes: Ethernet + IPv6 + UDP.
pub const HDR6: usize = ETH + IP6 + UDP;
/// Header block the IPv4 side reads and writes: Ethernet + IPv4 + UDP.
pub const HDR4: usize = ETH + IP4 + UDP;

/// Copies `M` bytes of `src` starting at `off` into a new array. Offsets are
/// constants at every call site; bytes past the end of `src` read as zero
/// instead of panicking.
///
/// The in-range case is one fixed-size copy (`first_chunk`), which LLVM
/// lowers to a few loads in the eBPF object; an iterator copy with `skip`
/// was lowered to `memcpy` calls of computed length, a loop in `.text`
/// (PERF-002, PERF-009). The byte loop below is reached only for an
/// out-of-range constant offset and folds away otherwise.
#[inline(always)]
pub(crate) fn take<const N: usize, const M: usize>(src: &[u8; N], off: usize) -> [u8; M] {
    if let Some(a) = src.get(off..).and_then(|s| s.first_chunk::<M>()) {
        return *a;
    }
    let mut a = [0u8; M];
    for (d, s) in a.iter_mut().zip(src.iter().skip(off)) {
        *d = *s;
    }
    a
}

/// Writes `src` into `dst` at `off`. Offsets are constants at every call
/// site; bytes that would land past the end of `dst` are dropped instead of
/// panicking. As in [`take`], the in-range case is one fixed-size copy.
#[inline(always)]
pub(crate) fn put<const N: usize, const M: usize>(dst: &mut [u8; N], off: usize, src: &[u8; M]) {
    if let Some(d) = dst.get_mut(off..).and_then(|d| d.first_chunk_mut::<M>()) {
        *d = *src;
        return;
    }
    for (d, s) in dst.iter_mut().skip(off).zip(src.iter()) {
        *d = *s;
    }
}

#[cfg(test)]
mod tests {
    use super::{put, take};

    /// The fixed-size fast path and the byte-loop fallback agree with the
    /// documented semantics (PERF-002 rewrite): in range, an exact copy;
    /// past the end, zeros read and writes dropped.
    #[test]
    fn take_and_put_in_and_out_of_range() {
        let src: [u8; 6] = [1, 2, 3, 4, 5, 6];
        assert_eq!(take::<6, 2>(&src, 0), [1, 2]);
        assert_eq!(take::<6, 2>(&src, 4), [5, 6]);
        assert_eq!(take::<6, 4>(&src, 4), [5, 6, 0, 0]);
        assert_eq!(take::<6, 2>(&src, 6), [0, 0]);
        assert_eq!(take::<6, 2>(&src, usize::MAX), [0, 0]);

        let mut dst = [0u8; 6];
        put(&mut dst, 1, &[9, 8]);
        assert_eq!(dst, [0, 9, 8, 0, 0, 0]);
        put(&mut dst, 4, &[7, 7, 7]);
        assert_eq!(dst, [0, 9, 8, 0, 7, 7]);
        put(&mut dst, 6, &[1]);
        put(&mut dst, usize::MAX, &[1]);
        assert_eq!(dst, [0, 9, 8, 0, 7, 7]);
    }

    #[test]
    fn sum_at_matches_a_byte_reference() {
        let b: [u8; 7] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde];
        let reference = |off: usize, len: usize| {
            let s: [u8; 7] = core::array::from_fn(|i| if i >= off && i < off.saturating_add(len) { b[i] } else { 0 });
            let mut acc = 0u64;
            let mut i = off;
            while i < off.saturating_add(len).min(7) {
                let hi = s[i];
                let lo = if i + 1 < off.saturating_add(len).min(7) { s[i + 1] } else { 0 };
                acc += u64::from(u16::from_be_bytes([hi, lo]));
                i += 2;
            }
            acc
        };
        for off in 0..9 {
            for len in 0..10 {
                assert_eq!(crate::csum::sum_at(&b, off, len), reference(off, len), "off {off} len {len}");
            }
        }
    }
}
