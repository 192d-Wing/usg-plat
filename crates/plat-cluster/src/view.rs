//! Cluster views.
//!
//! A view is the leader's only output: which data members serve slices
//! (`live`), which are syncing as backup only (`standby`), and who leads.
//! The `epoch` packs the leader's term (high 32 bits, the Raft term used for
//! votes) and a per-term view version (low 32 bits), so epochs are unique
//! per view and strictly increase across views and leaders.

use crate::slices::{MemberId, SliceId, rank_with_standby};

/// Upper bound on voters (members plus witness): bounds views on the wire.
pub const MAX_MEMBERS: usize = 64;

/// Term part of an epoch.
#[inline]
pub fn term_of(epoch: u64) -> u32 {
    (epoch >> 32) as u32
}

/// Per-term version part of an epoch.
#[inline]
pub fn version_of(epoch: u64) -> u32 {
    epoch as u32
}

/// Epoch of view `version` in `term`.
#[inline]
pub fn make_epoch(term: u32, version: u32) -> u64 {
    (u64::from(term) << 32) | u64::from(version)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct View {
    pub epoch: u64,
    /// Data members that may be primary (sorted, unique).
    pub live: Vec<MemberId>,
    /// Data members that only back up (rejoined, waiting for failback).
    pub standby: Vec<MemberId>,
    pub leader: MemberId,
}

impl View {
    /// Sort and de-duplicate the member lists (standby never repeats a live
    /// member).
    pub fn normalize(&mut self) {
        self.live.sort_unstable();
        self.live.dedup();
        self.standby.sort_unstable();
        self.standby.dedup();
        let live = &self.live;
        self.standby.retain(|m| live.binary_search(m).is_err());
    }

    /// (primary, backup) of `slice` in this view.
    pub fn owners(&self, slice: SliceId, weights: &[u32]) -> Option<(MemberId, Option<MemberId>)> {
        rank_with_standby(slice, &self.live, &self.standby, weights)
    }

    /// Primary of `slice`.
    pub fn primary(&self, slice: SliceId, weights: &[u32]) -> Option<MemberId> {
        self.owners(slice, weights).map(|o| o.0)
    }

    pub fn is_live(&self, m: MemberId) -> bool {
        self.live.binary_search(&m).is_ok()
    }

    pub fn is_standby(&self, m: MemberId) -> bool {
        self.standby.binary_search(&m).is_ok()
    }

    /// Slices whose primary is `m`.
    pub fn primary_slices(&self, m: MemberId, slice_count: usize, weights: &[u32]) -> Vec<SliceId> {
        (0..slice_count as u32).map(|s| s as SliceId).filter(|s| self.primary(*s, weights) == Some(m)).collect()
    }

    /// Slices whose backup is `m`.
    pub fn backup_slices(&self, m: MemberId, slice_count: usize, weights: &[u32]) -> Vec<SliceId> {
        (0..slice_count as u32)
            .map(|s| s as SliceId)
            .filter(|s| self.owners(*s, weights).and_then(|o| o.1) == Some(m))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epochs_order_by_term_then_version() {
        assert!(make_epoch(1, u32::MAX) < make_epoch(2, 0));
        assert_eq!(term_of(make_epoch(7, 3)), 7);
        assert_eq!(version_of(make_epoch(7, 3)), 3);
    }

    #[test]
    fn normalize_and_roles() {
        let mut v = View { epoch: 1, live: vec![2, 0, 2], standby: vec![1, 0], leader: 0 };
        v.normalize();
        assert_eq!(v.live, vec![0, 2]);
        assert_eq!(v.standby, vec![1]);
        let p = v.primary_slices(0, 64, &[]);
        let q = v.primary_slices(2, 64, &[]);
        assert_eq!(p.len() + q.len(), 64);
        assert!(v.primary_slices(1, 64, &[]).is_empty());
        assert!(!v.backup_slices(1, 64, &[]).is_empty());
    }
}
