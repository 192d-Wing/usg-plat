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
#[inline(always)]
pub(crate) fn take<const N: usize, const M: usize>(src: &[u8; N], off: usize) -> [u8; M] {
    let mut a = [0u8; M];
    for (d, s) in a.iter_mut().zip(src.iter().skip(off)) {
        *d = *s;
    }
    a
}

/// Writes `src` into `dst` at `off`. Offsets are constants at every call
/// site; bytes that would land past the end of `dst` are dropped instead of
/// panicking.
#[inline(always)]
pub(crate) fn put<const N: usize, const M: usize>(dst: &mut [u8; N], off: usize, src: &[u8; M]) {
    for (d, s) in dst.iter_mut().skip(off).zip(src.iter()) {
        *d = *s;
    }
}
