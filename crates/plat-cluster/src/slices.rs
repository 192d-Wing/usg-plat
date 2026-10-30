//! Fixed-size pool slices and weighted rendezvous (HRW) ownership.
//!
//! A slice is an aligned IPv4 chunk of `slice_prefix_len` inside the pool.
//! Slices are the unit of ownership, route announcement, replication and
//! failover. Slice ids are dense (`0..len()`) and ordered by address, so
//! every node derives the same table from the same pool.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5(2) (Capacity, Bandwidth, and Redundancy) - adding or
//!   removing a member moves only ~1/N of the slices; CP-10 (System Recovery
//!   and Reconstitution) - every slice has a deterministic backup
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - slice count capped
//!   at [`MAX_SLICES`]

use plat_common::Ipv4Cidr;
use std::net::Ipv4Addr;

use crate::mix;

/// Upper bound on the number of slices (validated; bounds every per-slice
/// table and bitmap).
pub const MAX_SLICES: usize = 4096;

/// Shortest accepted slice prefix (a /16 slice is 65 536 addresses).
pub const MIN_SLICE_PREFIX_LEN: u8 = 16;

/// Dense slice index, `0..SliceMap::len()`.
pub type SliceId = u16;

/// Cluster member id (`cluster.members[].id`).
pub type MemberId = u16;

/// Weight of a member that has no entry in the weight table.
pub const DEFAULT_WEIGHT: u32 = 1;

/// Largest accepted member weight.
pub const MAX_WEIGHT: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SliceError {
    #[error("slice prefix length {0} is outside {MIN_SLICE_PREFIX_LEN}..=32")]
    SliceLen(u8),
    #[error("pool prefix {0} is longer than the slice prefix length /{1}")]
    PoolTooSmall(Ipv4Cidr, u8),
    #[error("pool is empty")]
    Empty,
    #[error("pool splits into {0} slices, more than {MAX_SLICES}")]
    TooMany(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    net: u32,
    len: u8,
    first: SliceId,
}

/// The slice table of a pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceMap {
    runs: Vec<Run>,
    slice_len: u8,
    count: usize,
}

impl SliceMap {
    /// Split `pool` into aligned `/slice_len` slices. Nested pool prefixes
    /// are de-duplicated; every pool prefix must be at least as short as
    /// `slice_len`.
    pub fn new(pool: &[Ipv4Cidr], slice_len: u8) -> Result<SliceMap, SliceError> {
        if !(MIN_SLICE_PREFIX_LEN..=32).contains(&slice_len) {
            return Err(SliceError::SliceLen(slice_len));
        }
        let mut sorted: Vec<Ipv4Cidr> = pool.to_vec();
        sorted.sort_unstable_by_key(|c| (c.network(), c.prefix_len()));
        let mut runs: Vec<Run> = Vec::with_capacity(sorted.len());
        let mut total: u64 = 0;
        for c in sorted {
            if c.prefix_len() > slice_len {
                return Err(SliceError::PoolTooSmall(c, slice_len));
            }
            // CIDRs are nested or disjoint; sorted by (network, len), a
            // nested prefix follows its parent.
            if let Some(last) = runs.last()
                && Ipv4Cidr::new(Ipv4Addr::from(last.net), last.len).is_ok_and(|p| p.contains(c.network()))
            {
                continue;
            }
            let n = 1u64 << (slice_len - c.prefix_len());
            if total + n > MAX_SLICES as u64 {
                return Err(SliceError::TooMany(total + n));
            }
            runs.push(Run { net: c.network(), len: c.prefix_len(), first: total as SliceId });
            total += n;
        }
        if runs.is_empty() {
            return Err(SliceError::Empty);
        }
        Ok(SliceMap { runs, slice_len, count: total as usize })
    }

    /// Number of slices.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The slice prefix length.
    pub fn slice_len(&self) -> u8 {
        self.slice_len
    }

    /// Addresses per slice.
    pub fn slice_size(&self) -> u32 {
        1u32 << (32 - u32::from(self.slice_len))
    }

    /// The slice holding `addr`, or `None` outside the pool. Binary search
    /// over the (few) sorted pool runs, then a shift.
    #[inline]
    pub fn slice_of(&self, addr: u32) -> Option<SliceId> {
        let i = self.runs.partition_point(|r| r.net <= addr).checked_sub(1)?;
        let r = self.runs.get(i)?;
        let off = u64::from(addr - r.net);
        if off >> (32 - u32::from(r.len)) != 0 {
            return None;
        }
        let idx = off >> (32 - u32::from(self.slice_len));
        Some(r.first + idx as SliceId)
    }

    /// The CIDR of slice `id`, or `None` when out of range.
    pub fn cidr(&self, id: SliceId) -> Option<Ipv4Cidr> {
        if usize::from(id) >= self.count {
            return None;
        }
        let i = self.runs.partition_point(|r| r.first <= id).checked_sub(1)?;
        let r = self.runs.get(i)?;
        let off = u64::from(id - r.first) << (32 - u32::from(self.slice_len));
        Ipv4Cidr::new(Ipv4Addr::from((u64::from(r.net) + off) as u32), self.slice_len).ok()
    }

    /// Every slice CIDR in id order.
    pub fn iter(&self) -> impl Iterator<Item = (SliceId, Ipv4Cidr)> + '_ {
        (0..self.count as u32).filter_map(|i| self.cidr(i as SliceId).map(|c| (i as SliceId, c)))
    }
}

/// Q32 fixed-point log2 of `x` (`x >= 1`), integer-only so every node and
/// architecture computes the same ranking.
fn log2_q32(x: u64) -> u64 {
    let x = x.max(1);
    let n = 63 - u64::from(x.leading_zeros());
    // Mantissa in [2^63, 2^64) as Q63.
    let mut m = u128::from(x) << (63 - n);
    let mut frac = 0u64;
    for _ in 0..32 {
        m = (m * m) >> 63;
        frac <<= 1;
        if m >= 1u128 << 64 {
            m >>= 1;
            frac |= 1;
        }
    }
    (n << 32) | frac
}

/// HRW key of `member` for `slice`: `-log2(u) / weight` with `u` uniform in
/// (0, 1). The smallest key wins, which gives each member a win probability
/// proportional to its weight. Returned as (numerator, weight).
fn key(slice: SliceId, member: MemberId, weight: u32) -> (u128, u128) {
    let h = mix(mix(u64::from(slice) + 1) ^ mix((u64::from(member) + 1) << 20)).max(1);
    let neg_log = (64u128 << 32) - u128::from(log2_q32(h));
    (neg_log, u128::from(weight.clamp(1, MAX_WEIGHT)))
}

fn weight_of(weights: &[u32], m: MemberId) -> u32 {
    weights.get(usize::from(m)).copied().unwrap_or(DEFAULT_WEIGHT)
}

/// `a` ranks before `b` (smaller key, ties to the lower id).
fn before(slice: SliceId, a: MemberId, b: MemberId, weights: &[u32]) -> bool {
    let (na, wa) = key(slice, a, weight_of(weights, a));
    let (nb, wb) = key(slice, b, weight_of(weights, b));
    // na/wa < nb/wb  <=>  na*wb < nb*wa (no overflow: n < 2^39, w <= 100).
    (na * wb, a) < (nb * wa, b)
}

fn best(slice: SliceId, cands: impl Iterator<Item = MemberId>, weights: &[u32]) -> Option<MemberId> {
    cands.fold(None, |acc, m| match acc {
        Some(b) if !before(slice, m, b, weights) => Some(b),
        _ => Some(m),
    })
}

/// Rendezvous rank of `slice` among `live`: (primary, backup). `weights` is
/// indexed by member id (missing entries weigh [`DEFAULT_WEIGHT`]). `None`
/// when `live` is empty.
pub fn rank(slice: SliceId, live: &[MemberId], weights: &[u32]) -> Option<(MemberId, Option<MemberId>)> {
    rank_with_standby(slice, live, &[], weights)
}

/// Like [`rank`], but the backup may also come from `standby` (members that
/// rejoined and sync as backup before failback). The primary is always from
/// `live`.
pub fn rank_with_standby(
    slice: SliceId,
    live: &[MemberId],
    standby: &[MemberId],
    weights: &[u32],
) -> Option<(MemberId, Option<MemberId>)> {
    let primary = best(slice, live.iter().copied(), weights)?;
    let backup = best(slice, live.iter().chain(standby).copied().filter(|m| *m != primary), weights);
    Some((primary, backup))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn c(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
    }

    #[test]
    fn log2_matches_known_values() {
        assert_eq!(log2_q32(1), 0);
        assert_eq!(log2_q32(1 << 40), 40 << 32);
        let l3 = log2_q32(3) as f64 / (1u64 << 32) as f64;
        assert!((l3 - 3f64.log2()).abs() < 1e-8);
    }

    #[test]
    fn slices_cover_pool_in_order() {
        let m = SliceMap::new(&[c("198.51.100.0/24"), c("192.0.2.0/27"), c("192.0.2.0/28")], 28).unwrap();
        assert_eq!(m.len(), 18);
        assert_eq!(m.cidr(0), Some(c("192.0.2.0/28")));
        assert_eq!(m.cidr(1), Some(c("192.0.2.16/28")));
        assert_eq!(m.cidr(2), Some(c("198.51.100.0/28")));
        assert_eq!(m.cidr(17), Some(c("198.51.100.240/28")));
        assert_eq!(m.cidr(18), None);
        assert_eq!(m.slice_of(u32::from(Ipv4Addr::new(192, 0, 2, 31))), Some(1));
        assert_eq!(m.slice_of(u32::from(Ipv4Addr::new(192, 0, 2, 32))), None);
        assert_eq!(m.slice_of(u32::from(Ipv4Addr::new(198, 51, 100, 255))), Some(17));
        assert_eq!(m.slice_of(0), None);
        assert_eq!(m.slice_of(u32::MAX), None);
    }

    #[test]
    fn slice_map_validation() {
        assert_eq!(SliceMap::new(&[c("192.0.2.0/24")], 15), Err(SliceError::SliceLen(15)));
        assert_eq!(SliceMap::new(&[c("192.0.2.0/24")], 33), Err(SliceError::SliceLen(33)));
        assert!(matches!(SliceMap::new(&[c("192.0.2.0/29")], 28), Err(SliceError::PoolTooSmall(..))));
        assert_eq!(SliceMap::new(&[], 28), Err(SliceError::Empty));
        assert_eq!(SliceMap::new(&[c("10.0.0.0/16")], 28).map(|m| m.len()), Ok(4096));
        assert_eq!(
            SliceMap::new(&[c("10.0.0.0/16"), c("10.1.0.0/32")], 28),
            Err(SliceError::PoolTooSmall(c("10.1.0.0/32"), 28))
        );
        assert_eq!(SliceMap::new(&[c("10.0.0.0/15")], 28), Err(SliceError::TooMany(8192)));
        assert_eq!(SliceMap::new(&[c("0.0.0.0/16")], 32), Err(SliceError::TooMany(65_536)));
    }

    #[test]
    fn whole_space_edges() {
        let m = SliceMap::new(&[c("255.255.0.0/16")], 16).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m.slice_of(u32::MAX), Some(0));
        assert_eq!(m.cidr(0), Some(c("255.255.0.0/16")));
        assert_eq!(m.slice_size(), 65_536);
    }

    #[test]
    fn rank_basics() {
        assert_eq!(rank(0, &[], &[]), None);
        assert_eq!(rank(7, &[3], &[]), Some((3, None)));
        for s in 0..500 {
            let (p, b) = rank(s, &[0, 1, 2, 3], &[]).unwrap();
            assert_ne!(Some(p), b);
            // Order of `live` does not matter.
            assert_eq!(rank(s, &[3, 1, 2, 0], &[]), Some((p, b)));
            // Removing the primary promotes the backup.
            let rest: Vec<u16> = [0, 1, 2, 3].into_iter().filter(|m| *m != p).collect();
            assert_eq!(rank(s, &rest, &[]).map(|r| r.0), b);
        }
    }

    #[test]
    fn standby_is_backup_of_the_slices_it_will_take() {
        for s in 0..1000 {
            let (p_all, _) = rank(s, &[0, 1, 2], &[]).unwrap();
            if p_all == 2 {
                let (p, b) = rank_with_standby(s, &[0, 1], &[2], &[]).unwrap();
                assert_ne!(p, 2);
                assert_eq!(b, Some(2), "slice {s}");
            }
        }
    }

    #[test]
    fn weights_are_respected() {
        let w = [1, 3, 1, 1];
        let mut n = [0u32; 4];
        for s in 0..4096 {
            n[usize::from(rank(s, &[0, 1, 2, 3], &w).unwrap().0)] += 1;
        }
        // Expect 4096 * 3/6 = 2048 for member 1, 682 for the others.
        assert!((1850..2250).contains(&n[1]), "{n:?}");
        for i in [0, 2, 3] {
            assert!((560..810).contains(&n[i]), "{n:?}");
        }
    }

    #[test]
    fn hrw_moves_about_one_over_n() {
        for n in 2u16..8 {
            let live: Vec<u16> = (0..n).collect();
            let grown: Vec<u16> = (0..=n).collect();
            let moved =
                (0..4096).filter(|s| rank(*s, &live, &[]).unwrap().0 != rank(*s, &grown, &[]).unwrap().0).count();
            let expect = 4096.0 / f64::from(n + 1);
            assert!((moved as f64 - expect).abs() < expect * 0.3, "n={n} moved={moved} expect={expect}");
            // Every moved slice moved to the new member.
            assert!((0..4096).all(|s| {
                let a = rank(s, &live, &[]).unwrap().0;
                let b = rank(s, &grown, &[]).unwrap().0;
                a == b || b == n
            }));
        }
    }

    proptest! {
        #[test]
        fn every_pool_address_in_exactly_one_slice(
            nets in proptest::collection::vec((0u32..4096, 20u8..=26), 1..6),
            slice_len in 26u8..=32,
        ) {
            let pool: Vec<Ipv4Cidr> = nets
                .iter()
                .map(|(n, l)| Ipv4Cidr::new(Ipv4Addr::from((n << 20) & (u32::MAX << (32 - l))), *l).unwrap())
                .collect();
            let Ok(m) = SliceMap::new(&pool, slice_len) else { return Ok(()) };
            let mut seen = vec![0u32; m.len()];
            for p in &pool {
                for a in p.addrs().step_by(7) {
                    let s = m.slice_of(a).unwrap();
                    prop_assert!(m.cidr(s).unwrap().contains(a));
                    seen[usize::from(s)] += 1;
                }
            }
            for (s, c) in m.iter() {
                prop_assert_eq!(m.slice_of(c.network()), Some(s));
                prop_assert!(pool.iter().any(|p| p.contains(c.network())));
            }
            // Slices are disjoint: cidrs strictly increase.
            let nets: Vec<u32> = m.iter().map(|(_, c)| c.network()).collect();
            prop_assert!(nets.windows(2).all(|w| w[0] < w[1]));
        }
    }
}
