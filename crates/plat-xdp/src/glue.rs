//! The engine side of the writer: `impl plat_nat64::Mirror for XdpMirror`
//! (WU5, plan §4.4) and the stale-generation collector the control thread
//! runs on top of [`XdpMirror::stale_scan`].
//!
//! The trait contract (`plat_nat64::mirror`): every call runs with a
//! `bib4` shard lock or a slice mutex held, so the writer takes only its
//! own leaf locks (the slot partitions) and never calls back into the
//! engine. Lock order `bib4 → xslot` (CLAUDE.md rule 5).
//!
//! - **install**: the engine's [`MirrorEntry`] becomes a [`SessionEntry`]
//!   (network-order addresses, host-order ports) and is installed under
//!   exactly `e.generation` ([`XdpMirror::install`] refuses unless the
//!   slice is Active with it; SEC-005, RFC-001). [`InstallError::is_full`]
//!   (maps full, or no free slot in the partition) is `MirrorFail::Full`,
//!   everything else `MirrorFail::Error` (PERF-002); the engine backs that
//!   shard's lane off either way.
//! - **retire**: the key echo is checked against the record (QA F1), so a
//!   stale retire of a recycled slot never touches another session.
//! - **seen**: [`XdpMirror::seen_ms`] (engine milliseconds, clamped).
//! - **slice state**: `SLICE[s] = {state, generation}` as the engine
//!   orders it (`Pool::set_slice_state`: never more permissive than the
//!   engine).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-12 / CLAUDE.md rule 4 - the engine installs only after
//!   the attributing record was handed to the sink (I4), except under
//!   `on_overflow = "drop_and_alert"` (`plat-nat64` test
//!   `drop_and_alert_installs_even_when_the_record_is_lost`)
//! - NIST 800-53: SC-24, SC-7 - an entry is usable only under the slice
//!   generation the engine built it for; stale entries are collected under
//!   their `bib4` shard ([`gc_step`])
//! - NIST 800-53: SC-10, RFC 6146 §3.5.1 - `seen` refreshes the session in
//!   engine time (test `glue::tests::expiry_is_one_timeout_after_the_last_fast_path_packet`)

use plat_cluster::SliceId;
use plat_nat64::SliceState;
use plat_nat64::mirror::{Mirror, MirrorEntry, MirrorFail, MirrorKeys};
use plat_nat64::state::{Key4, Key6, State};
use plat_packet::proto;
use plat_xdp_core::abi::{SLICE_ACTIVE, SLICE_ADOPTING, SLICE_FENCED, SLICE_INACTIVE, SLOT_FAILED, SLOT_LIVE};

use crate::mirror::{SessionEntry, XdpMirror};

/// The `SLICE` state byte of an engine slice state.
pub const fn slice_code(st: SliceState) -> u8 {
    match st {
        SliceState::Inactive => SLICE_INACTIVE,
        SliceState::Active => SLICE_ACTIVE,
        SliceState::Fenced => SLICE_FENCED,
        SliceState::Adopting => SLICE_ADOPTING,
    }
}

/// The fast path's view of engine keys (slice `slice`).
pub fn session_entry(k: &MirrorKeys, slice: SliceId) -> SessionEntry {
    SessionEntry {
        src6: k.k6.addr.to_be_bytes(),
        sport6: k.k6.port,
        dst6: k.dst6.to_be_bytes(),
        dst4: k.remote.0.to_be_bytes(),
        dport: k.remote.1,
        pool4: k.k4.addr.to_be_bytes(),
        pool_port4: k.k4.port,
        slice,
    }
}

/// The engine keys of a record (UDP only: nothing else is ever installed).
pub fn keys_of(e: &SessionEntry) -> MirrorKeys {
    MirrorKeys {
        k6: Key6 { proto: proto::UDP, addr: u128::from_be_bytes(e.src6), port: e.sport6 },
        k4: Key4 { proto: proto::UDP, addr: u32::from_be_bytes(e.pool4), port: e.pool_port4 },
        remote: (u32::from_be_bytes(e.dst4), e.dport),
        dst6: u128::from_be_bytes(e.dst6),
    }
}

impl Mirror for XdpMirror {
    fn install(&self, e: &MirrorEntry, shard: usize) -> Result<u32, MirrorFail> {
        XdpMirror::install(self, &session_entry(&e.keys, e.slice), e.generation, shard)
            .map_err(|err| if err.is_full() { MirrorFail::Full } else { MirrorFail::Error })
    }

    fn retire(&self, slot: u32, keys: &MirrorKeys) {
        // The slice is the record's (the engine's keys do not carry it);
        // every other field must echo, or nothing is touched.
        let slice = self.record(slot).map_or(0, |r| r.slice);
        if XdpMirror::retire(self, slot, &session_entry(keys, slice)).is_err() {
            self.counters().retire_error.add(slot as usize, 1);
        }
    }

    fn seen_ms(&self, slot: u32) -> u64 {
        // The engine asks only for a session its own refresh no longer
        // keeps alive: a non-zero answer is a revalidation by fast-path
        // use (`plat_xdp_revalidated_total`).
        let ms = XdpMirror::seen_ms(self, slot);
        if ms != 0 {
            self.counters().revalidated.add(slot as usize, 1);
        }
        ms
    }

    fn slice_state(&self, slice: SliceId, st: SliceState, generation: u32) {
        self.set_slice(slice, slice_code(st), generation);
    }
}

/// Whether `slot` still holds the record of `e`, and it is either `LIVE`
/// under a generation its slice no longer has or `FAILED` (a publish that
/// failed): the GC's re-check, under the entry's `bib4` shard.
pub fn still_stale(m: &XdpMirror, slot: u32, e: &SessionEntry) -> bool {
    m.record(slot).is_some_and(|r| {
        SessionEntry::from_record(&r) == *e
            && (r.state == SLOT_FAILED
                || (r.state == SLOT_LIVE && m.slice(r.slice).is_none_or(|(_, g)| g != r.generation)))
    })
}

/// One stale-entry collection step (plan §4.3, §9; control thread):
/// scans `budget` slots from `cursor` and retires every live entry whose
/// generation is stale and every failed publish, each under its `bib4` shard with the re-check of
/// [`still_stale`] ([`State::mirror_gc`]). `buf` is reused across steps.
/// Returns the next cursor and how many entries were retired (counted in
/// `plat_xdp_gc_deleted_total`).
pub fn gc_step(
    m: &XdpMirror,
    state: &State,
    cursor: u32,
    budget: u32,
    buf: &mut Vec<(u32, SessionEntry)>,
) -> (u32, u64) {
    buf.clear();
    // PERF-005: failed publishes first, then the round-robin scan.
    let mut failed = Vec::new();
    m.take_failed(&mut failed, budget as usize);
    for s in failed {
        if let Some(r) = m.record(s)
            && r.state == SLOT_FAILED
        {
            buf.push((s, SessionEntry::from_record(&r)));
        }
    }
    let next = m.stale_scan(cursor, budget, buf);
    let mut n = 0;
    for (slot, e) in buf.iter() {
        let k = keys_of(e);
        if state.mirror_gc(k.k4, k.k6, k.remote, *slot, || still_stale(m, *slot, e)) {
            m.counters().gc_deleted.add(*slot as usize, 1);
            n += 1;
        }
    }
    (next, n)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;
    use std::time::Duration;

    use crate::nat64_fixtures::*;
    use plat_nat64::mirror::NO_SLOT;
    use plat_packet::{be16, be32};

    use super::*;
    use crate::mirror::InstallError;

    const SERVER: u32 = 0xc633_6407; // 198.51.100.7
    const UDP_MS: u64 = 300_000;
    /// `CLOCK_MONOTONIC_COARSE` at the engine origin (arbitrary).
    const ORIGIN_NS: u64 = 7_000_000_123;

    fn ns_at(ms: u64) -> u64 {
        ORIGIN_NS + ms * 1_000_000
    }

    fn setup(slots: u32) -> (Fx, Arc<XdpMirror>) {
        let mut fx = fixture(&[]);
        let (_t, m) = crate::mirror::tests::mirror(64, slots);
        let m = Arc::new(m.with_clock(fx.clock.clone(), ORIGIN_NS));
        fx.nat.set_mirror(m.clone());
        fx.clock.advance(Duration::from_secs(1));
        (fx, m)
    }

    fn flow(fx: &mut Fx, sport: u16) -> (Key4, u32) {
        let out = run(fx, &udp6(sub(1, 1), sport, SERVER, 53, b"x")).unwrap();
        let k4 = Key4 { proto: proto::UDP, addr: be32(&out, 12), port: be16(&out, 20) };
        let slot = fx.nat.state().session_slot(k4, (SERVER, 53)).unwrap();
        (k4, slot)
    }

    /// RFC-002 / NIST-WU34-006: a session kept alive only by the fast path
    /// expires exactly one UDP timeout after its last fast-path packet
    /// (engine milliseconds, sub-millisecond `seen_ns` rounded down).
    #[test]
    fn expiry_is_one_timeout_after_the_last_fast_path_packet() {
        use crate::mirror::SEEN_SLACK_MS;
        let (mut fx, m) = setup(64);
        let (k4, slot) = flow(&mut fx, 1000);
        assert_ne!(slot, NO_SLOT);
        let st = fx.nat.state();
        // The fast path carries the flow from here on. The true packet
        // time is `last` ms plus 0.999999 ms.
        fx.clock.advance(Duration::from_millis(UDP_MS - 1_000));
        let last = st.now_ms();
        m.touch_ns(slot, ns_at(last) + 999_999);
        assert_eq!(m.seen_ms(slot), last, "never in the future");
        // RFC-002: never before one full timeout after the true time.
        fx.clock.advance(Duration::from_millis(UDP_MS));
        assert_eq!(st.now_ms(), last + UDP_MS);
        assert!(st.has_session(k4, (SERVER, 53)), "live one timeout after the (rounded-down) packet time");
        let s = st.sweep();
        assert_eq!((s.sessions_expired, s.mirror_retired), (0, 0));
        // Rounded up plus one coarse tick of slack: live through
        // last + 1 + slack + timeout - 1, expired right after.
        fx.clock.advance(Duration::from_millis(SEEN_SLACK_MS));
        assert!(st.has_session(k4, (SERVER, 53)), "within the slack");
        fx.clock.advance(Duration::from_millis(1));
        assert_eq!(st.now_ms(), last + 1 + SEEN_SLACK_MS + UDP_MS);
        assert!(!st.has_session(k4, (SERVER, 53)), "expired at the bound");
        let s = st.sweep();
        assert_eq!((s.sessions_expired, s.mirror_retired), (1, 1));
        assert_eq!(m.counters().sessions.get(), 0);
        assert_eq!(m.counters().retires.get(), 1);
    }

    #[test]
    fn failed_publish_is_collected_and_the_session_forgets_the_slot() {
        let mut fx = fixture(&[]);
        let (t, m) = crate::mirror::tests::mirror(1, 64);
        let m = Arc::new(m.with_clock(fx.clock.clone(), ORIGIN_NS));
        fx.nat.set_mirror(m.clone());
        fx.clock.advance(Duration::from_secs(1));
        let (k1, s1) = flow(&mut fx, 1000);
        let (k2, s2) = flow(&mut fx, 1001);
        assert!(s1 != NO_SLOT && s2 != NO_SLOT);
        m.flush();
        assert_eq!(t.in4.lock().len(), 1);
        // The partitions drain in order: whichever came second found the
        // map full.
        let failed = |s| m.record(s).map(|r| r.state) == Some(SLOT_FAILED);
        let (kf, kl) = if failed(s2) { (k2, k1) } else { (k1, k2) };
        assert!(failed(s1) ^ failed(s2));
        let mut buf = Vec::new();
        let (_, n) = gc_step(&m, fx.nat.state(), 0, 64, &mut buf);
        assert_eq!(n, 1);
        assert_eq!(fx.nat.state().session_slot(kf, (SERVER, 53)), Some(NO_SLOT));
        assert_ne!(fx.nat.state().session_slot(kl, (SERVER, 53)), Some(NO_SLOT));
        m.flush();
        assert_eq!(t.in4.lock().len(), 1, "the other session's entry is kept");
        // QA: the forgotten session is mirrored again on its next
        // slow-path hit once there is room and the back-offs passed.
        t.in4.lock().clear();
        t.out6.lock().clear();
        fx.clock.advance(Duration::from_secs(3));
        std::thread::sleep(crate::mirror::INSTALL_BACKOFF + Duration::from_millis(50));
        let sport = if kf == k1 { 1000 } else { 1001 };
        let (k_again, s_again) = flow(&mut fx, sport);
        assert_eq!(k_again, kf, "same session");
        assert_ne!(s_again, NO_SLOT, "re-mirrored");
        m.flush();
        assert_eq!(m.record(s_again).map(|r| r.state), Some(SLOT_LIVE));
    }

    #[test]
    fn seen_is_clamped_to_now_and_never_zero_for_a_use() {
        let (mut fx, m) = setup(64);
        let (_k4, slot) = flow(&mut fx, 1000);
        let now = fx.nat.state().now_ms();
        assert_eq!(m.seen_ms(slot), 0, "never used by the fast path");
        m.touch_ns(slot, ns_at(now + 5_000));
        assert_eq!(m.seen_ms(slot), now, "a use is never in the future");
        m.touch_ns(slot, ORIGIN_NS - 1);
        assert_eq!(m.seen_ms(slot), crate::mirror::SEEN_SLACK_MS, "before the engine origin: still a use (0 + slack)");
        // Without the clock: no conversion, no revival.
        let (_t, bare) = crate::mirror::tests::mirror(4, 4);
        assert_eq!(bare.seen_ms(0), 0);
    }

    #[test]
    fn slots_exhaustion_is_full_and_mismatch_is_error() {
        // One slot per partition for shard lanes 0..4: the second install
        // in a partition finds no slot (InstallError::Slots -> Full).
        let (_t, m) = crate::mirror::tests::mirror(64, 4);
        let k = |n: u16| MirrorKeys {
            k6: Key6 { proto: proto::UDP, addr: 0x2001_0db8 << 96 | u128::from(n), port: 1000 },
            k4: Key4 { proto: proto::UDP, addr: 0xc000_0201, port: 2000 + n },
            remote: (SERVER, 53),
            dst6: 0x0064_ff9b_0001 << 80 | u128::from(SERVER),
        };
        let e = |n| MirrorEntry { keys: k(n), slice: 0, generation: 1 };
        assert!(Mirror::install(&m, &e(1), 0).is_ok());
        assert_eq!(Mirror::install(&m, &e(2), 0), Err(MirrorFail::Full));
        assert_eq!(m.counters().install_slots.get(), 1);
        let stale = MirrorEntry { generation: 2, ..e(3) };
        assert_eq!(Mirror::install(&m, &stale, 1), Err(MirrorFail::Error));
        assert!(InstallError::Slots.is_full());
        // Retire with the engine's keys (no slice): echo checked, then done.
        Mirror::retire(&m, 0, &k(9));
        assert_eq!(m.counters().retire_not_live.get(), 1, "wrong keys: untouched");
        Mirror::retire(&m, 0, &k(1));
        assert_eq!(m.counters().retires.get(), 1);
        // Slice state follows the engine's generation as given.
        Mirror::slice_state(&m, 5, SliceState::Active, 9);
        assert_eq!(m.slice(5), Some((SLICE_ACTIVE, 9)));
        Mirror::slice_state(&m, 5, SliceState::Fenced, 9);
        assert_eq!(m.slice(5), Some((SLICE_FENCED, 9)));
    }

    /// Plan §4.3: entries of a bumped generation are collected under their
    /// `bib4` shard; the session forgets its slot and is mirrored again on
    /// its next slow-path hit, under the current generation.
    #[test]
    fn stale_generation_gc_retires_and_forgets_the_slot() {
        let (mut fx, m) = setup(64);
        let (k4, slot) = flow(&mut fx, 1000);
        // The publisher makes it LIVE.
        m.flush();
        let mut buf = Vec::new();
        assert_eq!(gc_step(&m, fx.nat.state(), 0, 64, &mut buf), (0, 0), "current generation: nothing");
        // A takeover and re-acquire bumps the generation (simulated on the
        // map; the engine's own generation is irrelevant to the check).
        assert!(m.set_slice(0, SLICE_ACTIVE, 2));
        let (_, n) = gc_step(&m, fx.nat.state(), 0, 64, &mut buf);
        assert_eq!(n, 1);
        assert_eq!(m.counters().gc_deleted.get(), 1);
        assert_eq!(fx.nat.state().session_slot(k4, (SERVER, 53)), Some(NO_SLOT));
        assert_eq!(m.counters().sessions.get(), 0);
        m.flush();
        assert_eq!(m.slot_allocator().quarantined(), 1, "deferred delete, then quarantine");
        // A re-check that says "no longer stale" collects nothing.
        assert!(!fx.nat.state().mirror_gc(k4, keys_of(&buf[0].1).k6, (SERVER, 53), slot, || false));
    }
}
