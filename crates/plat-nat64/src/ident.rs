//! IPv4 Identification for translated and locally generated packets.
//!
//! RFC 7739 §5.3 (randomized counter table): each worker keeps a table of
//! [`TABLE`] 16-bit counters. A keyed hash of `(src, dst, proto)` picks the
//! counter, which advances by a random step of 1 to [`MAX_STEP`] per packet;
//! the ID is the counter plus a keyed per-flow offset from the same hash.
//! Flows that do not share a counter learn nothing about each other, so an
//! observer of some flows cannot read the worker's packet rate, and the
//! random step keeps even a shared counter from being an exact packet count.
//!
//! COMPLIANCE MAPPING:
//! - RFC 7739 §5.3 - table of counters indexed by a keyed hash of the flow
//!   identifiers, random increments (closes POAM-011)
//! - RFC 6864 - an ID repeats within one flow's counter only after at least
//!   65536 / [`MAX_STEP`] packets of the flows sharing that counter
//! - NIST 800-53: SC-7 - no idle-scan / traffic-rate side channel

use ahash::RandomState;

/// Counters per worker (8 KiB).
pub const TABLE: usize = 4096;
/// Largest random step per packet (steps are 1..=MAX_STEP).
pub const MAX_STEP: u16 = 8;

/// Boot-random hash key, built once per engine and read-only afterwards.
/// Not a cryptographic control (no SC-13 claim): it only makes the counter
/// index and offset unpredictable, as RFC 7739 asks.
/// SEC-008: `Debug` is redacted; the key must not reach logs or metrics.
#[derive(Clone)]
pub struct IdentKey {
    k0: u64,
    /// Odd multiplier.
    k1: u64,
}

impl std::fmt::Debug for IdentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentKey(<redacted>)")
    }
}

impl std::fmt::Debug for IdentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentState(<redacted>)")
    }
}

impl Default for IdentKey {
    fn default() -> Self {
        Self::new()
    }
}

/// One worker's counter table and step generator. Owned by one thread.
/// SEC-008: `Debug` is redacted; counters and RNG state are never logged.
pub struct IdentState {
    /// Fixed size, so the masked index needs no bounds check (PERF).
    table: Box<[u16; TABLE]>,
    /// xorshift64 state (never zero).
    rng: u64,
}

impl IdentState {
    /// A table with random initial counters. `seed` only diversifies
    /// workers; the randomness comes from `ahash`'s OS-seeded state.
    pub fn new(seed: u16) -> Self {
        let r = RandomState::new();
        let mut rng = r.hash_one(seed) | 1;
        let mut table = Box::new([0u16; TABLE]);
        for c in table.iter_mut() {
            rng = xorshift(rng);
            *c = (rng >> 48) as u16;
        }
        Self { table, rng }
    }
}

#[inline(always)]
fn xorshift(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

impl IdentKey {
    /// A fresh random key (OS RNG via `ahash`'s runtime seed).
    pub fn new() -> Self {
        // Two independent 64-bit keys from the OS-seeded hasher.
        let r = RandomState::new();
        Self { k0: r.hash_one(0x5eed_u64), k1: r.hash_one(0xface_u64) | 1 }
    }

    /// Keyed 64-bit hash of `(src, dst, proto)`. `src` is the IPv6 source
    /// for translated packets, or the IPv4 source widened.
    ///
    /// A keyed multiply-xorshift over the folded tuple (PERF: one multiply
    /// pair on the hot path instead of a full hash). Not a MAC: it only has
    /// to be unpredictable without the key, which never leaves the process.
    #[inline(always)]
    fn mix(&self, src: u128, dst: u32, proto: u8) -> u64 {
        let x = (src as u64) ^ ((src >> 64) as u64).rotate_left(29) ^ (u64::from(dst) << 8 | u64::from(proto));
        let m = (x ^ self.k0).wrapping_mul(self.k1);
        (m ^ (m >> 29)).wrapping_mul(self.k1)
    }

    /// Keyed 16-bit offset for the flow (the high bits of the hash; the
    /// counter index uses the low bits).
    #[inline]
    pub fn offset(&self, src: u128, dst: u32, proto: u8) -> u16 {
        (self.mix(src, dst, proto) >> 48) as u16
    }

    /// Next Identification for the flow, advancing its counter in `st` by a
    /// random step.
    #[inline(always)]
    pub fn next(&self, st: &mut IdentState, src: u128, dst: u32, proto: u8) -> u16 {
        let m = self.mix(src, dst, proto);
        st.rng = xorshift(st.rng);
        let step = 1 + (st.rng >> 61) as u16;
        let c = &mut st.table[(m as usize) & (TABLE - 1)];
        *c = c.wrapping_add(step);
        c.wrapping_add((m >> 48) as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_flow_ids_advance_by_a_bounded_random_step() {
        let k = IdentKey::new();
        let mut st = IdentState::new(7);
        let a: Vec<u16> = (0..256).map(|_| k.next(&mut st, 1, 2, 17)).collect();
        let steps: Vec<u16> = a.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
        // One flow alone on its counter: every step is 1..=MAX_STEP, so
        // the IDs never repeat within 65536 / MAX_STEP packets.
        assert!(steps.iter().all(|s| (1..=MAX_STEP).contains(s)), "{steps:?}");
        // The step is random, not a fixed increment.
        let mut d = steps.clone();
        d.sort_unstable();
        d.dedup();
        assert!(d.len() >= MAX_STEP as usize - 1, "{d:?}");
    }

    #[test]
    fn flows_on_other_counters_do_not_reveal_each_other() {
        // Traffic of other flows moves this flow's counter only when they
        // share its table slot: 10_000 packets on tuples in other slots
        // leave this flow's next step within 1..=MAX_STEP.
        let k = IdentKey::new();
        let mut st = IdentState::new(1);
        let (s, d, p) = (0u128, 9u32, 6u8);
        let slot = (k.mix(s, d, p) as usize) & (TABLE - 1);
        let a = k.next(&mut st, s, d, p);
        for i in 1..10_000u128 {
            if (k.mix(i, d, p) as usize) & (TABLE - 1) != slot {
                k.next(&mut st, i, d, p);
            }
        }
        let b = k.next(&mut st, s, d, p);
        assert!((1..=MAX_STEP).contains(&b.wrapping_sub(a)));
    }

    #[test]
    fn offsets_differ_and_key_differs_between_instances() {
        let k = IdentKey::new();
        let mut v: Vec<u16> = (0..64u32).map(|i| k.offset(u128::from(i), 9, 6)).collect();
        v.sort_unstable();
        v.dedup();
        assert!(v.len() >= 60, "{}", v.len());
        // Two engines: the offsets of 8 tuples agree only by chance (2^-128).
        let (a, b) = (IdentKey::new(), IdentKey::new());
        assert!((0..8u32).any(|i| a.offset(u128::from(i), 1, 17) != b.offset(u128::from(i), 1, 17)));
    }

    #[test]
    fn debug_is_redacted() {
        let k = IdentKey::new();
        let d = format!("{k:?} {:?}", IdentState::new(1));
        assert_eq!(d, "IdentKey(<redacted>) IdentState(<redacted>)");
        assert!(!d.contains(&k.k0.to_string()));
    }
}
