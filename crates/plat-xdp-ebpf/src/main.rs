//! The XDP program of the usg-plat fast path for established UDP sessions
//! (POAM-016 Phase 1, plan §2.3): `plat_xdp`, built for
//! `bpfel-unknown-none` with `bpf-linker` (`make xdp`,
//! `deploy/tests/xdp/build-object.sh`).
//!
//! The program is a thin shell around `plat-xdp-core`: [`ctx`] implements
//! [`plat_xdp_core::Env`] over the Aya maps of [`maps`] and the kernel
//! helpers, calls the core's `decide_v6` / `decide_v4` on the fixed header
//! block, and only after the last decline point moves the packet start,
//! trims the tail, copies the output header block in and redirects through
//! the `TX` devmap. Every other frame is passed, unmodified, to the kernel
//! and the `platd` slow path (`XDP_PASS`).
//!
//! On the host the crate is a stub `main`, so `cargo --workspace` (and
//! `check-linux`) build without `bpf-linker`; its host tests check the
//! level-2 vectors against `plat-xdp-core` and the `Env` reference shape
//! (PERF-010).
//!
//! `unsafe` is confined to [`ctx`] (packet pointers, helper calls, the
//! program and licence symbols), each block with a `// SAFETY:` comment
//! (plan §2.2, rule 6 restatement). [`maps`] holds only the map statics.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-7 (Boundary Protection), SC-24 (Fail in Known State),
//!   SC-5 (Denial-of-Service Protection), SI-10 (Information Input
//!   Validation) - enforcement point of the `plat-xdp-core` decision (Phase
//!   1, not attached until WU3/WU4; POAM-016); see `ctx.rs` and `maps.rs`
//! - NIST 800-53: CM-10 (Software Usage Restrictions) - licence section
//!   "Dual MIT/GPL" (decision Q2, Option A)

#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(target_arch = "bpf")]
mod ctx;
#[cfg(target_arch = "bpf")]
mod maps;

/// Host stub: the program exists only in the `bpfel-unknown-none` build.
#[cfg(not(target_arch = "bpf"))]
fn main() {}
