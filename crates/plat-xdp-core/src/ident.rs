//! IPv4 Identification for fast-path packets with DF = 0: the RFC 7739
//! §5.3 randomized counter table of `plat_nat64::ident`. The eBPF program
//! keeps the counters in the per-CPU `IDENT` array, one
//! [`IdentEnt`](crate::abi::IdentEnt) per index holding the counter and the
//! xorshift64 state of its random step (seeded non-zero by the loader, no
//! random-number helper), and the key in the frozen `IDENT_KEY` map; the
//! host tests keep both in memory.
//!
//! A keyed hash of `(src6, dst4, proto)` picks one of [`TABLE`] 16-bit
//! counters, which advances by a random step of 1 to [`MAX_STEP`] per
//! packet ([`next`]); the ID is the counter plus a keyed per-flow offset
//! from the same hash. The arithmetic is `plat_nat64::ident`'s, on byte
//! arrays instead of `u128` (no 128-bit arithmetic in the eBPF object).
//!
//! COMPLIANCE MAPPING:
//! - RFC 7739 §5.3 - counters indexed by a keyed hash of the flow
//!   identifiers, random increments (step seed source: the loader's
//!   `getrandom` into `IDENT`, WU2/WU3, open)
//! - RFC 7915 §5.1 - the ID is used only when DF = 0 (DF = 1 sends ID 0)
//! - NIST 800-53: SC-7 (supporting) - no idle-scan / traffic-rate side
//!   channel through the IPv4 ID; decision logic only, enforcement requires
//!   `plat-xdp-ebpf` (WU2) and the loader (WU3)
//!
// POAM: POAM-038 - RFC 6864 / RFC 7739 deviation: the fast path and the
// slow path draw IDs from independent counter tables, so a flow that
// switches paths has probabilistic, not counter-guaranteed, ID uniqueness
// across the switch (extends RFC_COMPLIANCE deviation 8).

use crate::abi::IdentEnt;

/// Counters per table (the `IDENT` map size).
pub const TABLE: u32 = 4096;
/// Largest random step per packet (steps are 1..=MAX_STEP).
pub const MAX_STEP: u16 = 8;

/// The 128-bit table key (`IDENT_KEY`, from the loader's `getrandom`).
/// Not a cryptographic control (no SC-13 claim): it only makes the counter
/// index and offset unpredictable. `Debug` is redacted (SEC-008).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentKey {
    k0: u64,
    /// Forced odd by every constructor.
    k1: u64,
}

const _: () = assert!(core::mem::size_of::<IdentKey>() == 16);

impl core::fmt::Debug for IdentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdentKey(<redacted>)")
    }
}

impl IdentKey {
    /// A key from 16 random bytes (`k1` forced odd).
    #[inline(always)]
    pub const fn new(k0: u64, k1: u64) -> Self {
        Self { k0, k1: k1 | 1 }
    }

    /// The key from its `IDENT_KEY` map image (`k0`, then `k1`, host
    /// order; `k1` forced odd).
    #[inline(always)]
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        let (h, _) = b.as_chunks::<8>();
        let mut it = h.iter().map(|c| u64::from_ne_bytes(*c));
        Self::new(it.next().unwrap_or(0), it.next().unwrap_or(0))
    }

    /// The `IDENT_KEY` map image the loader writes.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        crate::put(&mut b, 0, &self.k0.to_ne_bytes());
        crate::put(&mut b, 8, &self.k1.to_ne_bytes());
        b
    }

    /// Keyed 64-bit hash of `(src6, dst4, proto)`: `plat_nat64::ident`'s
    /// multiply-xorshift over the folded tuple, with `src6` split into its
    /// big-endian halves.
    #[inline(always)]
    pub fn mix(&self, src6: &[u8; 16], dst4: &[u8; 4], proto: u8) -> u64 {
        let (hi, lo) = halves(src6);
        let x = lo ^ hi.rotate_left(29) ^ ((u64::from(u32::from_be_bytes(*dst4)) << 8) | u64::from(proto));
        let m = (x ^ self.k0).wrapping_mul(self.k1);
        (m ^ (m >> 29)).wrapping_mul(self.k1)
    }
}

/// The high and low big-endian 64-bit halves of an IPv6 address.
#[inline(always)]
fn halves(a: &[u8; 16]) -> (u64, u64) {
    let (h, _) = a.as_chunks::<8>();
    let mut it = h.iter().map(|c| u64::from_be_bytes(*c));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

/// Counter index of the flow hash `m` (`m mod TABLE`).
#[inline(always)]
pub fn index(m: u64) -> u32 {
    (m as u32) & (TABLE - 1)
}

/// One xorshift64 step of the per-CPU step generator (state never zero).
#[inline(always)]
pub fn xorshift(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

/// The random step (1..=[`MAX_STEP`]) drawn from a generator state.
#[inline(always)]
pub fn step(rng: u64) -> u16 {
    1 + (rng >> 61) as u16
}

/// Advances the flow's counter by `step` and returns `(new counter, ID)`.
#[inline(always)]
pub fn advance(counter: u16, step: u16, m: u64) -> (u16, u16) {
    let c = counter.wrapping_add(step);
    (c, c.wrapping_add((m >> 48) as u16))
}

/// Draws the next ID for the flow hash `m` from its `IDENT` entry: one
/// [`xorshift`] step of the entry's generator, then [`advance`].
#[inline(always)]
pub fn next(e: &mut IdentEnt, m: u64) -> u16 {
    let r = xorshift(e.rng);
    e.rng = r;
    let (c, id) = advance(e.counter, step(r), m);
    e.counter = c;
    id
}
