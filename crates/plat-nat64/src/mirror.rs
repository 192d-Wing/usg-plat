//! Session mirror hook: an index of eligible UDP sessions for an external
//! fast path (the XDP program of POAM-016 Phase 1, plan §2.3, §4).
//!
//! `plat-nat64` stays authoritative. A [`Mirror`] is only a copy, written
//! inside the same `bib4` shard critical section that creates or removes
//! the session, so a mirrored entry never outlives its session:
//!
//! - **install** after the session is inserted, on session create or on a
//!   slow-path hit of an eligible session that is not mirrored yet
//!   ([`State::outbound_with`](crate::state::State::outbound_with),
//!   [`State::inbound_with`](crate::state::State::inbound_with));
//! - **retire** with the removal: `drop_expired`, the sweeper, and
//!   [`State::release_slice`](crate::state::State::release_slice) (handover,
//!   takeover via `adopt_slice`);
//! - **seen read-back**: when a mirrored session looks expired, the engine
//!   reads [`Mirror::seen_ms`] and extends the session instead of expiring
//!   it (plan §5), in the sweeper and in every lookup that checks expiry;
//! - **slice state**: [`crate::pool::Pool::set_slice_state`] forwards every
//!   ownership change with its generation, inside the slice mutex, ordered
//!   so the copy is never more permissive than the engine (plan §9).
//!
//! The trait is object-safe and small; every call is on a cold path (`dyn`
//! is fine). Without a mirror (`None`, the default) the engine pays one
//! predictable branch on a field already in cache. [`NoMirror`] is the
//! explicit "off" value; `ModelMirror` models the BPF maps for tests and
//! exists only with `cfg(test)` or the `model` feature (SEC-008: never in
//! a production build).
//!
//! Lock order: a mirror implementation may take only leaf locks of its own
//! (it is called with a `bib4` shard or a slice mutex held) and must never
//! call back into the engine.

use std::fmt::Debug;

use plat_cluster::SliceId;

use crate::pool::SliceState;
use crate::state::{Key4, Key6};

/// `Session::slot` of a session that is not mirrored.
pub const NO_SLOT: u32 = u32::MAX;

/// Slice id and generation of every entry in a legacy (unsliced) pool: the
/// whole pool is slice 0, Active from the moment the mirror is attached.
pub const LEGACY_GENERATION: u32 = 1;

/// The keys of one mirrored session (enough to delete both index entries).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MirrorKeys {
    /// Subscriber transport address (`proto` is always UDP).
    pub k6: Key6,
    /// Pool transport address.
    pub k4: Key4,
    /// Remote IPv4 address and port.
    pub remote: (u32, u16),
    /// Canonical RFC 6052 embedding of `remote.0` with the engine's prefix
    /// (the outbound destination and the inbound translated source).
    pub dst6: u128,
}

/// One session to mirror (plan §4.4 `MirrorEntry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorEntry {
    pub keys: MirrorKeys,
    /// Slice of `keys.k4.addr` (0 in a legacy pool).
    pub slice: SliceId,
    /// Generation of `slice` when the entry was built; the fast path uses
    /// the entry only while the slice is Active with this generation.
    pub generation: u32,
}

/// Why an install was refused. The session stays on the slow path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorFail {
    /// The index or slot table is full (an implementation reports "no
    /// free slot" as `Full` too).
    Full,
    /// A key already exists (a stale entry not yet collected).
    Exists,
    /// Any other error (rolled back by the implementation).
    Error,
}

/// Install back-off after any [`MirrorFail`] (plan §9 back-pressure;
/// PERF-002: a mirror that keeps failing costs one attempt per back-off,
/// not one per slow-path packet).
pub const INSTALL_BACKOFF_MS: u64 = 1_000;

/// An index of eligible sessions kept by an external fast path.
///
/// Implementations (WU5: `impl Mirror for plat_xdp::XdpMirror`) must:
/// - never block for long, never allocate per call on a steady state, and
///   take only leaf locks: every method is called with a `bib4` shard lock
///   (install, retire, seen) or a slice mutex (slice_state) held;
/// - make an installed entry usable only when `install` returns `Ok`, and
///   roll back completely on `Err`;
/// - never call back into the engine.
pub trait Mirror: Send + Sync + Debug {
    /// Mirrors `e`. `shard` is the `bib4` shard index (for partitioned slot
    /// allocation). Returns the slot, which is passed back to
    /// [`Mirror::retire`] and [`Mirror::seen_ms`]; [`NO_SLOT`] is never a
    /// valid slot.
    fn install(&self, e: &MirrorEntry, shard: usize) -> Result<u32, MirrorFail>;

    /// Removes the entry in `slot` (installed with `keys`). After it
    /// returns, the fast path no longer uses the entry.
    fn retire(&self, slot: u32, keys: &MirrorKeys);

    /// Last fast-path use of `slot` in the engine clock (`State::now_ms`
    /// base), 0 if never. Must be one atomic load.
    fn seen_ms(&self, slot: u32) -> u64;

    /// Slice `slice` is now `st` with `generation` (bumped on every
    /// transition to Active).
    fn slice_state(&self, slice: SliceId, st: SliceState, generation: u32);

    /// False for a mirror that keeps nothing ([`NoMirror`]): the engine
    /// then treats it as no mirror at all and never calls it.
    fn enabled(&self) -> bool {
        true
    }
}

/// The explicit "no fast path" mirror, equivalent to none: it is not
/// [`Mirror::enabled`], so [`State::set_mirror`](crate::state::State::set_mirror)
/// ignores it and the engine behaves exactly as without a mirror. Its
/// methods keep nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMirror;

impl Mirror for NoMirror {
    fn install(&self, _: &MirrorEntry, _: usize) -> Result<u32, MirrorFail> {
        Err(MirrorFail::Error)
    }

    fn retire(&self, _: u32, _: &MirrorKeys) {}

    fn seen_ms(&self, _: u32) -> u64 {
        0
    }

    fn slice_state(&self, _: SliceId, _: SliceState, _: u32) {}

    fn enabled(&self) -> bool {
        false
    }
}

#[cfg(any(test, feature = "model"))]
pub use model::{ModelMirror, ModelSlot};

/// The test model (see `ModelMirror`).
#[cfg(any(test, feature = "model"))]
mod model {
    use std::collections::HashMap;
    use std::fmt::Debug;

    use ahash::RandomState;
    use parking_lot::Mutex;
    use plat_cluster::SliceId;

    use super::{Mirror, MirrorEntry, MirrorFail, MirrorKeys};
    use crate::pool::SliceState;

    /// Outbound index key of the model (`OUT6`).
    type OutKey = (u128, u16, u128, u16);
    /// Inbound index key of the model (`IN4`).
    type InKey = (u32, u32, u16, u16);

    /// One model slot (`SLOT`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ModelSlot {
        pub entry: MirrorEntry,
        /// Fast-path last use (engine clock), set by [`ModelMirror::touch`].
        pub seen_ms: u64,
        /// Install sequence number (distinguishes a reuse of the slot).
        pub seq: u64,
    }

    type Check = Box<dyn Fn(&MirrorEntry) -> Result<(), String> + Send + Sync>;

    #[derive(Debug, Default)]
    struct Model {
        cap: usize,
        slots: Vec<Option<ModelSlot>>,
        free: Vec<u32>,
        out6: HashMap<OutKey, u32, RandomState>,
        in4: HashMap<InKey, u32, RandomState>,
        slices: HashMap<SliceId, (SliceState, u32), RandomState>,
        fail: Option<(MirrorFail, u32)>,
        seq: u64,
        installs: u64,
        retires: u64,
        violations: Vec<String>,
    }

    /// Test model of the BPF maps (`OUT6`, `IN4`, `SLOT`, `SLICE`, plan §4.1)
    /// with the same insert semantics (`BPF_NOEXIST`, bounded) and checks of
    /// the engine's side of the contract. Test support only: one mutex guards
    /// the whole model, so it must never be used in production.
    ///
    /// Recorded violations ([`ModelMirror::violations`]): an install of a
    /// non-UDP session, a retire of a slot that is not live or with other
    /// keys, a transition to Active without a generation bump, and every error
    /// returned by the check given to [`ModelMirror::with_check`] (called at
    /// every install, with the engine's shard lock held).
    pub struct ModelMirror {
        inner: Mutex<Model>,
        check: Option<Check>,
    }

    impl Debug for ModelMirror {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ModelMirror").field("inner", &self.inner).finish_non_exhaustive()
        }
    }

    impl ModelMirror {
        /// A model with room for `cap` entries.
        pub fn new(cap: usize) -> Self {
            Self { inner: Mutex::new(Model { cap, ..Model::default() }), check: None }
        }

        /// [`ModelMirror::new`] with `check` run at every install (for example
        /// "the attributing audit record is queued", I4).
        pub fn with_check(
            cap: usize,
            check: impl Fn(&MirrorEntry) -> Result<(), String> + Send + Sync + 'static,
        ) -> Self {
            Self { check: Some(Box::new(check)), ..Self::new(cap) }
        }

        /// The next `n` installs fail with `f` (rollback paths).
        pub fn fail_next(&self, f: MirrorFail, n: u32) {
            self.inner.lock().fail = Some((f, n));
        }

        /// Live entries with their slots.
        pub fn live(&self) -> Vec<(u32, ModelSlot)> {
            let m = self.inner.lock();
            m.slots.iter().enumerate().filter_map(|(i, s)| s.map(|s| (i as u32, s))).collect()
        }

        /// Number of live entries.
        pub fn len(&self) -> usize {
            let m = self.inner.lock();
            m.slots.len() - m.free.len()
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// The live record in `slot`.
        pub fn slot(&self, slot: u32) -> Option<ModelSlot> {
            self.inner.lock().slots.get(slot as usize).copied().flatten()
        }

        /// The fast path's whole decision on the record: live, and its slice
        /// Active with the record's generation.
        pub fn usable(&self, slot: u32) -> bool {
            let m = self.inner.lock();
            m.slots
                .get(slot as usize)
                .copied()
                .flatten()
                .is_some_and(|s| m.slices.get(&s.entry.slice) == Some(&(SliceState::Active, s.entry.generation)))
        }

        /// `OUT6` lookup.
        pub fn lookup_out(&self, src6: u128, sport: u16, dst6: u128, dport: u16) -> Option<u32> {
            self.inner.lock().out6.get(&(src6, sport, dst6, dport)).copied()
        }

        /// `IN4` lookup.
        pub fn lookup_in(&self, pool4: u32, remote4: u32, pool_port: u16, rport: u16) -> Option<u32> {
            self.inner.lock().in4.get(&(pool4, remote4, pool_port, rport)).copied()
        }

        /// `SLICE[slice]`.
        pub fn slice(&self, slice: SliceId) -> Option<(SliceState, u32)> {
            self.inner.lock().slices.get(&slice).copied()
        }

        /// A fast-path packet on `slot` at engine time `ms` (stores `seen`).
        pub fn touch(&self, slot: u32, ms: u64) {
            if let Some(Some(s)) = self.inner.lock().slots.get_mut(slot as usize) {
                s.seen_ms = ms;
            }
        }

        pub fn installs(&self) -> u64 {
            self.inner.lock().installs
        }

        pub fn retires(&self) -> u64 {
            self.inner.lock().retires
        }

        pub fn violations(&self) -> Vec<String> {
            self.inner.lock().violations.clone()
        }
    }

    fn out_key(k: &MirrorKeys) -> OutKey {
        (k.k6.addr, k.k6.port, k.dst6, k.remote.1)
    }

    fn in_key(k: &MirrorKeys) -> InKey {
        (k.k4.addr, k.remote.0, k.k4.port, k.remote.1)
    }

    impl Mirror for ModelMirror {
        fn install(&self, e: &MirrorEntry, _shard: usize) -> Result<u32, MirrorFail> {
            let checked = self.check.as_ref().map(|c| c(e));
            let mut m = self.inner.lock();
            if let Some(Err(v)) = checked {
                m.violations.push(format!("install check: {v} ({e:?})"));
            }
            if e.keys.k6.proto != plat_packet::proto::UDP || e.keys.k4.proto != plat_packet::proto::UDP {
                m.violations.push(format!("I3: non-UDP install {e:?}"));
            }
            if let Some((f, n)) = m.fail {
                m.fail = (n > 1).then_some((f, n - 1));
                return Err(f);
            }
            let (ok, ik) = (out_key(&e.keys), in_key(&e.keys));
            if m.out6.contains_key(&ok) || m.in4.contains_key(&ik) {
                return Err(MirrorFail::Exists);
            }
            let slot = match m.free.pop() {
                Some(s) => s,
                None if m.slots.len() < m.cap => {
                    m.slots.push(None);
                    (m.slots.len() - 1) as u32
                }
                None => return Err(MirrorFail::Full),
            };
            m.seq += 1;
            let seq = m.seq;
            if let Some(s) = m.slots.get_mut(slot as usize) {
                *s = Some(ModelSlot { entry: *e, seen_ms: 0, seq });
            }
            m.out6.insert(ok, slot);
            m.in4.insert(ik, slot);
            m.installs += 1;
            Ok(slot)
        }

        fn retire(&self, slot: u32, keys: &MirrorKeys) {
            let mut m = self.inner.lock();
            match m.slots.get(slot as usize).copied().flatten() {
                Some(s) if s.entry.keys == *keys => {}
                other => {
                    m.violations.push(format!("retire of slot {slot} with {keys:?}: holds {other:?}"));
                    return;
                }
            }
            if let Some(s) = m.slots.get_mut(slot as usize) {
                *s = None;
            }
            m.out6.remove(&out_key(keys));
            m.in4.remove(&in_key(keys));
            m.free.push(slot);
            m.retires += 1;
        }

        fn seen_ms(&self, slot: u32) -> u64 {
            self.inner.lock().slots.get(slot as usize).copied().flatten().map_or(0, |s| s.seen_ms)
        }

        fn slice_state(&self, slice: SliceId, st: SliceState, generation: u32) {
            let mut m = self.inner.lock();
            let old = m.slices.insert(slice, (st, generation));
            if st == SliceState::Active
                && let Some((ost, ogen)) = old
                && ost != SliceState::Active
                && generation <= ogen
            {
                m.violations.push(format!("slice {slice}: Active without a generation bump ({ogen} -> {generation})"));
            }
        }
    }
}
