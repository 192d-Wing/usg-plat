//! Held inbound TCP SYNs for simultaneous open (RFC 6146 §3.5.2.2).
//!
//! An unsolicited IPv4 SYN to a bound pool port that address(-port)-
//! dependent filtering refuses is not forwarded: it is recorded in a small
//! slot array attached to its BIB (inside the `bib4` shard, so the inbound
//! hold and the outbound match take the shard lock they already take). If
//! the subscriber sends a SYN to the same remote before the slot expires,
//! the new session starts ESTABLISHED (V4 INIT + V6 SYN); otherwise the
//! sweeper clears the slot and, with `nat64.held_syn_unreachable`, queues
//! an ICMPv4 Port Unreachable that a worker sends.
//!
//! A slot stores only the header fields the ICMP quote needs (IPv4 header
//! plus the first 8 bytes of TCP, RFC 792), never packet bytes.
//!
//! COMPLIANCE MAPPING:
//! - RFC 6146 §3.5.2.2 - CLOSED + V4 SYN with a BIB under ADF/APDF: the
//!   packet is stored, no BIB is created, the filter is not opened
//! - RFC 6146 §4, RFC 5382 - TCP_INCOMING_SYN (6 s minimum)
//! - NIST 800-53: SC-5 - node-wide cap (`nat64.max_held_syns`), per-BIB cap
//!   (`nat64.max_held_syns_per_bib`), bounded expiry ring
//! - NIST 800-53: SC-7, SC-7(5) - a held SYN is never forwarded and is
//!   invisible to filtering, session lookups and session quotas

use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_channel::{Receiver, Sender, TrySendError};
use crossbeam_utils::CachePadded;
use plat_common::config::{HELD_SYN_EXPIRY_BYTES, HELD_SYN_SLOT_BYTES, MAX_HELD_SYNS_PER_BIB, Nat64Config};

/// The fields of a held SYN (from `plat-packet` views; the engine fills it
/// only for an unfragmented SYN without ACK or RST).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynMeta {
    pub seq: u32,
    pub ttl: u8,
    pub tos: u8,
    pub ident: u16,
    /// IPv4 total length of the SYN (the quote keeps it, RFC 792).
    pub len: u16,
    /// The SYN's DF bit (restored in the quote, RFC-004).
    pub df: bool,
}

/// One held SYN (32 bytes). `expires_ms == 0` marks a free slot.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeldSlot {
    pub remote: u32,
    pub rport: u16,
    pub ttl: u8,
    pub tos: u8,
    pub seq: u32,
    pub ident: u16,
    pub len: u16,
    pub df: bool,
    pub expires_ms: u64,
}

/// Slots in one BIB's array (`nat64.max_held_syns_per_bib` caps the use).
pub const SLOTS: usize = MAX_HELD_SYNS_PER_BIB as usize;

// Memory accounting in `Nat64Config::held_syn_memory` uses these sizes.
const _: () = assert!(size_of::<HeldSlot>() as u64 == HELD_SYN_SLOT_BYTES);
const _: () = assert!(size_of::<HeldSynExpiry>() as u64 <= HELD_SYN_EXPIRY_BYTES);

impl HeldSlot {
    #[inline]
    pub fn used(&self) -> bool {
        self.expires_ms != 0
    }
}

/// An expired held SYN to answer with ICMPv4 Port Unreachable: the stored
/// SYN was sent from (`src4`, `sport`) to the pool address (`dst4`,
/// `dport`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldSynExpiry {
    pub src4: u32,
    pub dst4: u32,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ttl: u8,
    pub tos: u8,
    pub ident: u16,
    pub len: u16,
    pub df: bool,
}

/// Node-wide held-SYN settings, counters and the expiry ring. Present
/// only while holding is in effect ([`Nat64Config::holds_syns`]).
#[derive(Debug)]
pub struct HeldCtx {
    pub max: u64,
    pub per_bib: usize,
    pub life_ms: u64,
    /// Live slots (gauge `plat_held_syns`). Relaxed: a bound, like the
    /// session count; each slot is added once and removed once.
    pub count: CachePadded<AtomicU64>,
    /// Slots cleared unmatched (expiry, BIB removal, slice release).
    /// Written by the sweeper / control thread only.
    pub expired: AtomicU64,
    /// Slot arrays attached to BIBs; each holds at least one live slot,
    /// so this never exceeds `max` (PERF-006).
    pub arrays: AtomicU64,
    /// Expiry ICMPs dropped because the ring was full.
    pub icmp_lost: AtomicU64,
    /// Sweeper → workers; `None` unless `nat64.held_syn_unreachable`.
    ring: Option<(Sender<HeldSynExpiry>, Receiver<HeldSynExpiry>)>,
}

impl HeldCtx {
    /// `None` when holding is off (disabled, zero cap, or EIF).
    pub fn from_config(n: &Nat64Config) -> Option<Box<Self>> {
        if !n.holds_syns() {
            return None;
        }
        let ring = n.held_syn_ring();
        Some(Box::new(Self {
            max: u64::from(n.max_held_syns),
            per_bib: usize::from(n.max_held_syns_per_bib).clamp(1, SLOTS),
            life_ms: u64::from(n.held_syn_secs) * 1000,
            count: CachePadded::new(AtomicU64::new(0)),
            expired: AtomicU64::new(0),
            arrays: AtomicU64::new(0),
            icmp_lost: AtomicU64::new(0),
            // A bounded channel preallocates its array (SC-5).
            ring: (ring > 0).then(|| crossbeam_channel::bounded(ring as usize)),
        }))
    }

    /// Reserves one slot against the node-wide cap.
    #[inline]
    pub fn acquire(&self) -> bool {
        // PERF-004: at the cap, refuse without dirtying the shared line.
        if self.count.load(Ordering::Relaxed) >= self.max {
            return false;
        }
        if self.count.fetch_add(1, Ordering::Relaxed) >= self.max {
            self.count.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Returns `n` slots.
    #[inline]
    pub fn release(&self, n: u64) {
        if n > 0 {
            let before = self.count.fetch_sub(n, Ordering::Relaxed);
            debug_assert!(before >= n, "held SYN count underflow");
        }
    }

    /// Detaches an emptied slot array from its BIB; the caller drops it
    /// after releasing the shard guard.
    #[inline]
    pub fn take_array(&self, held: &mut HeldSlots) -> HeldSlots {
        let a = held.take();
        if a.is_some() {
            self.arrays.fetch_sub(1, Ordering::Relaxed);
        }
        a
    }

    pub fn icmp_enabled(&self) -> bool {
        self.ring.is_some()
    }

    /// Queues an expiry ICMP; never blocks (full: counted lost).
    pub fn push_expiry(&self, e: HeldSynExpiry) {
        if let Some((tx, _)) = &self.ring
            && let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = tx.try_send(e)
        {
            self.icmp_lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Takes up to `out.len()` queued expiries; never blocks.
    pub fn drain(&self, out: &mut [HeldSynExpiry]) -> usize {
        let Some((_, rx)) = &self.ring else { return 0 };
        let mut n = 0;
        for slot in out.iter_mut() {
            match rx.try_recv() {
                Ok(e) => {
                    *slot = e;
                    n += 1;
                }
                Err(_) => break,
            }
        }
        n
    }
}

/// The slot array of one BIB (thin pointer).
pub type HeldBox = Box<[HeldSlot; SLOTS]>;

/// A BIB's slot array: allocated (under the `bib4` guard, cold path) when
/// the BIB holds its first SYN, detached when its last slot is cleared
/// (match, expiry, BIB removal) and freed after the guard is released.
/// An array exists only while it holds a live slot, so at most
/// `nat64.max_held_syns` arrays exist (SC-5, PERF-006).
pub type HeldSlots = Option<HeldBox>;

/// The expiry ICMP intent for slot `s` of BIB `k4`.
pub fn expiry_of(k4: crate::state::Key4, s: &HeldSlot) -> HeldSynExpiry {
    HeldSynExpiry {
        src4: s.remote,
        dst4: k4.addr,
        sport: s.rport,
        dport: k4.port,
        seq: s.seq,
        ttl: s.ttl,
        tos: s.tos,
        ident: s.ident,
        len: s.len,
        df: s.df,
    }
}
