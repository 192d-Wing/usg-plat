//! Userspace side of the XDP fast path for established UDP sessions
//! (POAM-016 Phase 1, plan §2.2, §4).
//!
//! - [`load`]: `[xdp]` settings, the frozen `CONFIG` record and its digest,
//!   and (Linux) [`load::Loader`]: create the maps with their configured
//!   sizes, seed `IDENT` / `IDENT_KEY`, freeze `CONFIG` / `IDENT_KEY`, pin
//!   maps and program under [`PIN_DIR`], attach to the configured
//!   interfaces. Used by the one-shot privileged `plat-xdp-loader`.
//! - [`maps`]: the map table (names, pin modes, access) and (Linux)
//!   [`maps::XdpMaps::open_pinned`], how `platd` opens the pins without
//!   privileges (read-only pins through `plat_io::bpf_obj`).
//! - [`slots`]: the `SLOT` allocator (partitioned free stacks, RCU
//!   quarantine by grace-period epoch).
//! - [`mirror`]: the session writer: install / retire / `seen` read with
//!   the plan §4.3 ordering, slice state and generation writes.
//! - [`glue`]: `impl plat_nat64::Mirror for XdpMirror` and the
//!   stale-generation collector.
//! - [`control`]: the `CONTROL` record (enable, TUN ifindex/MTU, dead-man deadline)
//!   and the grace-period / heartbeat step.
//! - [`stats`]: per-CPU `STATS` / `FWD` sums and the `plat_xdp_*` metric
//!   text.
//!
//! The crate has no `unsafe`: Aya's (a reviewed dependency) and the
//! `plat-io` helpers (`bpf_obj`, `bpf_mmap`, `netdev`) hold it.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-6 (Least Privilege) - privileged loading is a
//!   separate one-shot step, and `platd` only opens pins (read-only where
//!   it only reads; wired in WU5, `services/platd/src/xdp.rs`; the units
//!   are WU6). Backed by the pin-mode tests
//!   (`maps::tests::pin_access_is_least_privilege`, `tests/unprivileged.rs`,
//!   `tests/refusals.rs`)
//! - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//!   the object is embedded at build time and its SHA-256 bound into the
//!   frozen `CONFIG` digest (see [`load::config_record`])

#![forbid(unsafe_code)]

pub mod control;
pub mod glue;
pub mod load;
pub mod maps;
pub mod mirror;
pub mod slots;
pub mod stats;

/// The `plat-nat64` engine test fixtures (packet builders, `Fx`), shared
/// with the `glue` tests.
#[cfg(test)]
#[path = "../../plat-nat64/tests/common/mod.rs"]
mod nat64_fixtures;

// CBOM: crypto/algorithm/sha-256/rustcrypto-sha2
use sha2::{Digest, Sha256};

/// The pin directory: a dedicated bpffs instance (plan §7,
/// `run-plat-bpf.mount`). Fixed, not configurable (CM-7).
pub const PIN_DIR: &str = "/run/plat/bpf";

/// State file the loader writes for `plat-fwguard` and `status` (object
/// SHA-256, program id and tag, interfaces). Outside the bpffs mount, which
/// holds pins only.
pub const STATE_FILE: &str = "/run/plat/xdp.state";

/// Name of the XDP program in the object.
pub const PROGRAM: &str = "plat_xdp";

/// 8-byte aligned storage for the embedded object (the ELF parser reads it
/// in place).
#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

#[cfg(feature = "xdp")]
static OBJECT: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/plat-xdp-ebpf")));
#[cfg(not(feature = "xdp"))]
static OBJECT: &Aligned<[u8]> = &Aligned([]);

/// The embedded `plat-xdp-ebpf` object. Empty without the `xdp` feature or
/// when built with `AYA_BUILD_SKIP=1`; the loader then refuses.
pub fn object() -> &'static [u8] {
    &OBJECT.0
}

/// SHA-256 of [`object`] (recorded in `service_start` and the `CONFIG`
/// digest).
pub fn object_sha256() -> [u8; 32] {
    Sha256::digest(object()).into()
}

/// [`object_sha256`] as lower-case hex.
pub fn object_sha256_hex() -> String {
    hex::encode(object_sha256())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_is_aligned() {
        assert_eq!(object().as_ptr() as usize % 8, 0);
    }

    #[cfg(not(feature = "xdp"))]
    #[test]
    fn no_object_without_the_feature() {
        assert!(object().is_empty());
        // SHA-256 of the empty string.
        assert_eq!(object_sha256_hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}
