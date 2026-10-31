//! Packet and helper access: the one module of the program with `unsafe`
//! (plan §2.2), each block with a `// SAFETY:` comment.
//!
//! - [`MapEnv`] implements [`Env`] over the maps of [`crate::maps`] and the
//!   helpers. Every lookup returns a reference into map memory (no map
//!   value is copied to the stack, PERF-001 / PERF-010); `fib` passes the
//!   caller's 64-byte [`FibParams`] by pointer to `bpf_fib_lookup`. The
//!   output header block is this CPU's `SCRATCH` entry, not a stack buffer.
//! - [`run`] is the program body: one bounds check for the fixed header
//!   block of the frame's direction, the core's decision on a reference to
//!   that block, then (redirect only) `bpf_xdp_adjust_head` /
//!   `bpf_xdp_adjust_tail`, exactly one bounds re-check, the header copy,
//!   the `seen_ns` touch and `bpf_redirect_map` (plan §2.5 rules 1 and 3).
//!
//! Lengths are compared as scalars and packet pointers are offset only by
//! constants (plan §2.5 rule 1). There are no loops and no bpf-to-bpf calls:
//! everything is `#[inline(always)]` into `plat_xdp` (plan §2.5 rule 5;
//! `deploy/tests/xdp/obj-gate.py` checks the stack depth and instruction
//! count, `check-object.py` the absence of back-edges).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-10 (Information Input Validation) - the frame is read
//!   only inside the bounds-checked fixed header block; anything shorter or
//!   other than untagged IPv4/IPv6 is passed (`not_ip` / `bad_l3`)
//! - NIST 800-53: SC-7 (Boundary Protection), SC-24 (Fail in Known State) -
//!   nothing is written to the packet before the last decline point; a
//!   failed re-check after a successful adjust drops the frame
//!   (`XDP_ABORTED`, counted `aborted`) instead of passing a half-rewritten
//!   one; a `TX` miss after the rewrite is aborted the same way
//! - NIST 800-53: SI-4 (System Monitoring) - per-CPU counters for every
//!   pass reason and aborts (`STATS`), forwarded packets and bytes per
//!   direction (`FWD`)
//! - RFC 6146 §3.5.1 - UDP session lifetime refresh (`SLOT.seen_ns`)

#![allow(unsafe_code)]

use core::cell::Cell;
use core::mem::{offset_of, size_of};
use core::ptr::NonNull;

use aya_ebpf::bindings::{bpf_fib_lookup as KernelFib, xdp_action, xdp_md};
use aya_ebpf::helpers::generated::{bpf_fib_lookup, bpf_ktime_get_coarse_ns, bpf_xdp_adjust_head, bpf_xdp_adjust_tail};
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use plat_xdp_core::abi::{
    Control, EgressEnt, FibParams, FwdDir, IdentEnt, IfaceEnt, Key4, Key6, PassReason, SliceEnt, SlotRec, StatIdx,
    XlatConfig, iface_slot,
};
use plat_xdp_core::classify::{ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use plat_xdp_core::ident::IdentKey;
use plat_xdp_core::{ETH, Env, HDR4, HDR6, Verdict, decide_v4, decide_v6};

use crate::maps::{CONFIG, CONTROL, EGRESS, FWD, IDENT, IDENT_KEY, IFACES, IN4, OUT6, SCRATCH, SLICE, SLOT, STATS, TX};

// plan §2.5 rule 2: the core's `FibParams` is the kernel's 64-byte
// `struct bpf_fib_lookup` (the host asserts the full layout in
// `plat-xdp-core::abi`; this checks it against the kernel bindings too).
const _: () = {
    assert!(size_of::<FibParams>() == 64);
    assert!(size_of::<KernelFib>() == size_of::<FibParams>());
    assert!(offset_of!(KernelFib, family) == offset_of!(FibParams, family));
    assert!(offset_of!(KernelFib, l4_protocol) == offset_of!(FibParams, l4_protocol));
    assert!(offset_of!(KernelFib, sport) == offset_of!(FibParams, sport));
    assert!(offset_of!(KernelFib, dport) == offset_of!(FibParams, dport));
    assert!(offset_of!(KernelFib, ifindex) == offset_of!(FibParams, ifindex));
    assert!(offset_of!(KernelFib, smac) == offset_of!(FibParams, smac));
    assert!(offset_of!(KernelFib, dmac) == offset_of!(FibParams, dmac));
};

/// [`Env`] over the program's maps and helpers for one packet.
pub(crate) struct MapEnv {
    ctx: *mut xdp_md,
    /// The `SLOT` element of the matched session, kept from [`Env::slot`]
    /// so the `seen_ns` touch needs no second lookup.
    slot: Cell<Option<NonNull<SlotRec>>>,
}

impl MapEnv {
    #[inline(always)]
    fn new(ctx: *mut xdp_md) -> Self {
        Self { ctx, slot: Cell::new(None) }
    }

    /// Stores `now` in the matched record's `seen_ns`.
    ///
    // PERF-011: `seen_ns` shares the record's cache line, which both
    // directions of the session read on every packet. The core asks for a
    // store only when the stored value is at least `SEEN_GRANULARITY_NS`
    // (1 s) old, so the line stays read-mostly; do not shorten that
    // granularity without revisiting this (and the sweeper's idle timers).
    #[inline(always)]
    fn touch(&self, now: u64) {
        if let Some(rec) = self.slot.get() {
            // SAFETY: `rec` came from a successful `SLOT` lookup for this
            // packet; array elements are never freed, so the pointer stays
            // valid for the program's run. No reference to the record is
            // alive (the decision has returned). `platd` reads `seen_ns`
            // with an atomic load and never writes it while the slot is
            // reachable; an aligned 8-byte store cannot tear.
            unsafe { core::ptr::write_volatile(&raw mut (*rec.as_ptr()).seen_ns, now) };
        }
    }
}

impl Env for MapEnv {
    #[inline(always)]
    fn iface(&self, ifindex: u32) -> Option<&IfaceEnt> {
        IFACES.get(iface_slot(ifindex))
    }

    #[inline(always)]
    fn control(&self) -> Option<&Control> {
        CONTROL.get(0)
    }

    // PERF-004: CONFIG stays a separate map (not folded into CONTROL): it
    // is `BPF_F_RDONLY_PROG` and frozen after the loader writes it, while
    // CONTROL is `platd`'s writable mmap page, so folding would make the
    // translation parameters writable by `platd` (CM-6). Both are
    // single-entry arrays looked up with a constant key, which the verifier
    // inlines (no helper call); CONFIG is read only once a session matched.
    #[inline(always)]
    fn config(&self) -> Option<XlatConfig> {
        CONFIG.get(0).map(|c| c.xlat())
    }

    #[inline(always)]
    fn now_ns(&self) -> u64 {
        // SAFETY: helper without arguments.
        unsafe { bpf_ktime_get_coarse_ns() }
    }

    #[inline(always)]
    fn out6(&self, key: &Key6) -> Option<u32> {
        // SAFETY: the value is a plain `u32` copied out at once; `platd`
        // replaces elements only after the slot's quarantine (plan §4.3)
        // and the key echo in `SLOT` catches a reused element.
        unsafe { OUT6.get(key) }.copied()
    }

    #[inline(always)]
    fn in4(&self, key: &Key4) -> Option<u32> {
        // SAFETY: as for `out6`.
        unsafe { IN4.get(key) }.copied()
    }

    #[inline(always)]
    fn slot(&self, idx: u32) -> Option<&SlotRec> {
        let p = NonNull::new(SLOT.get_ptr_mut(idx)?)?;
        self.slot.set(Some(p));
        // SAFETY: a non-null pointer to an array element, valid for the
        // program's run. The program writes the element only in `touch`,
        // after the decision (and so this reference) is gone; `platd`
        // rewrites every field but `seen_ns` only while the slot is
        // unreachable (plan §4.3).
        Some(unsafe { p.as_ref() })
    }

    #[inline(always)]
    fn slice(&self, idx: u16) -> Option<&SliceEnt> {
        SLICE.get(u32::from(idx))
    }

    #[inline(always)]
    fn fib(&self, p: &mut FibParams) -> i64 {
        // SAFETY: `ctx` is the program's context; `p` is an exclusive
        // 64-byte `struct bpf_fib_lookup` (layout asserted above) on the
        // stack, which the helper reads and fills.
        unsafe { bpf_fib_lookup(self.ctx.cast(), core::ptr::from_mut(p).cast(), size_of::<FibParams>() as i32, 0) }
    }

    #[inline(always)]
    fn egress(&self, ifindex: u32) -> Option<&EgressEnt> {
        EGRESS.get(iface_slot(ifindex))
    }

    #[inline(always)]
    fn ident_key(&self) -> Option<&IdentKey> {
        IDENT_KEY.get(0)
    }

    #[inline(always)]
    fn with_ident<F: FnOnce(&mut IdentEnt) -> u16>(&self, idx: u32, f: F) -> Option<u16> {
        let p = IDENT.get_ptr_mut(idx)?;
        // SAFETY: this CPU's element of a per-CPU array. XDP runs in
        // softirq (NAPI) context, serialised per CPU against other bottom
        // halves, with migration disabled, and XDP programs do not nest on
        // a CPU, so nothing else touches the element during `f`.
        Some(f(unsafe { &mut *p }))
    }
}

/// Adds `n` to this CPU's `STATS` counter `idx`.
#[inline(always)]
fn count(idx: u32, n: u64) {
    if let Some(p) = STATS.get_ptr_mut(idx) {
        // SAFETY: this CPU's element of a per-CPU array (see `with_ident`).
        unsafe { *p += n };
    }
}

#[inline(always)]
fn pass(r: PassReason) -> u32 {
    count(r.stat_idx(), 1);
    xdp_action::XDP_PASS
}

#[inline(always)]
fn aborted() -> u32 {
    count(StatIdx::Aborted as u32, 1);
    xdp_action::XDP_ABORTED
}

/// Reads byte `off` of the frame at `data`.
///
/// # Safety
///
/// The caller has checked `data + off < data_end` against the context's
/// `data_end`.
#[inline(always)]
unsafe fn byte(data: usize, off: usize) -> u8 {
    // SAFETY: in bounds per the caller's contract.
    unsafe { *((data + off) as *const u8) }
}

/// The program (section `xdp`): see the module documentation.
#[xdp]
pub fn plat_xdp(ctx: XdpContext) -> u32 {
    run(&ctx)
}

/// Dispatch on the Ethertype, in `plat_xdp_core::decide_frame`'s order: a
/// frame without an Ethernet header, or with any Ethertype other than
/// IPv6 / IPv4, is `not_ip`; one shorter than its direction's header block
/// is `bad_l3`.
#[inline(always)]
fn run(ctx: &XdpContext) -> u32 {
    let data = ctx.data();
    let end = ctx.data_end();
    if data + ETH > end {
        return pass(PassReason::NotIp);
    }
    // SAFETY: bytes 12 and 13 are below ETH, checked just above.
    match u16::from_be_bytes(unsafe { [byte(data, 12), byte(data, 13)] }) {
        ETHERTYPE_IPV6 => v6_to_v4(ctx),
        ETHERTYPE_IPV4 => v4_to_v6(ctx),
        _ => pass(PassReason::NotIp),
    }
}

/// This CPU's output header block (`SCRATCH`).
///
/// PERF-002: fetched for every IPv4/IPv6 frame, also ones declined later,
/// because the core's `decide_v6` / `decide_v4` take the output block as an
/// argument and write it during the decision. Fetching it only after the
/// session match would need an `Env` hook in `plat-xdp-core` (a WU1 API
/// change); a one-entry per-CPU array lookup is cheap next to the session
/// hash lookup, and declined frames stop at the first failed check anyway.
#[inline(always)]
fn scratch() -> Option<&'static mut [u8; HDR6]> {
    let p = SCRATCH.get_ptr_mut(0)?;
    // SAFETY: this CPU's element of a per-CPU array (see `with_ident`);
    // only this run uses it, and every byte a redirect copies out is
    // written by the core's rewrite first.
    Some(unsafe { &mut *p })
}

/// IPv6 → IPv4. Inlined like everything else: one frame, no subprograms.
/// (As separate bpf-to-bpf subprograms the two directions measured 8 + 336
/// and 8 + 200 B on 6.8: the IPv6 → IPv4 frame alone is the whole stack,
/// so splitting gains nothing and costs a call.)
#[inline(always)]
fn v6_to_v4(ctx: &XdpContext) -> u32 {
    let data = ctx.data();
    let end = ctx.data_end();
    if data + HDR6 > end {
        return pass(PassReason::BadL3);
    }
    // SAFETY: the HDR6 bytes at `data` are in the packet (checked above)
    // and nothing writes the packet while `h` lives (the decision only
    // reads it).
    let h = unsafe { &*(data as *const [u8; HDR6]) };
    // A scalar, never added to a packet pointer (plan §2.5 rule 1).
    let frame_len = (end - data) as u32;
    let Some(o) = scratch().and_then(|s| s.first_chunk_mut::<HDR4>()) else {
        return pass(PassReason::Disabled);
    };
    let env = MapEnv::new(ctx.ctx);
    match decide_v6(&env, ctx.ingress_ifindex() as u32, h, frame_len, o) {
        Verdict::Pass(r) => pass(r),
        Verdict::Redirect { ifindex, new_len, trim, touch, .. } => {
            let v = Out { ifindex, new_len, trim, touch, dir: FwdDir::V6ToV4 };
            // The header shrinks by 20 bytes.
            transmit(ctx, &env, o, (HDR6 - HDR4) as i32, &v)
        }
    }
}

/// IPv4 → IPv6 (see [`v6_to_v4`]).
#[inline(always)]
fn v4_to_v6(ctx: &XdpContext) -> u32 {
    let data = ctx.data();
    let end = ctx.data_end();
    if data + HDR4 > end {
        return pass(PassReason::BadL3);
    }
    // SAFETY: as in `v6_to_v4`, for the HDR4 bytes at `data`.
    let h = unsafe { &*(data as *const [u8; HDR4]) };
    let frame_len = (end - data) as u32;
    let Some(o) = scratch() else {
        return pass(PassReason::Disabled);
    };
    let env = MapEnv::new(ctx.ctx);
    match decide_v4(&env, ctx.ingress_ifindex() as u32, h, frame_len, o) {
        Verdict::Pass(r) => pass(r),
        Verdict::Redirect { ifindex, new_len, trim, touch, .. } => {
            let v = Out { ifindex, new_len, trim, touch, dir: FwdDir::V4ToV6 };
            // The header grows by 20 bytes.
            transmit(ctx, &env, o, -((HDR6 - HDR4) as i32), &v)
        }
    }
}

/// A redirect verdict's fields and its direction (the `FWD` entry).
struct Out {
    ifindex: u32,
    new_len: u32,
    trim: u32,
    touch: Option<u64>,
    dir: FwdDir,
}

/// Counts one forwarded packet of `new_len` bytes: one `FWD` lookup for
/// both counters (PERF-001).
#[inline(always)]
fn count_fwd(dir: FwdDir, new_len: u32) {
    if let Some(p) = FWD.get_ptr_mut(dir as u32) {
        // SAFETY: this CPU's element of a per-CPU array (see `with_ident`).
        let c = unsafe { &mut *p };
        c.packets += 1;
        c.bytes += u64::from(new_len);
    }
}

/// Applies a redirect: every check has passed and `hdr` holds the output
/// header block. Moves the packet start by `head` bytes, trims the tail to
/// `new_len`, re-checks the bounds once, writes `hdr`, touches `seen_ns`
/// and redirects.
#[inline(always)]
fn transmit<const N: usize>(ctx: &XdpContext, env: &MapEnv, hdr: &[u8; N], head: i32, v: &Out) -> u32 {
    // SAFETY: helper on the program's context. On failure the frame is
    // unchanged, so it can still be passed.
    //
    // SEC-003 / RFC-004: for a DF = 0 IPv6 → IPv4 packet the decision has
    // already advanced this CPU's IDENT counter, so a `headroom` decline
    // here consumes one Identification value the packet never uses. That
    // only skips a value of a randomized counter (RFC 7739 §5.3); it leaks
    // nothing and needs no rollback.
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, head) } != 0 {
        return pass(PassReason::Headroom);
    }
    // From here on the frame is modified: any failure aborts (plan §2.5
    // rule 3).
    // SAFETY: helper on the program's context; shrinking by the frame's
    // trailing bytes leaves `new_len` ≥ HDR4 bytes.
    if v.trim != 0 && unsafe { bpf_xdp_adjust_tail(ctx.ctx, -(v.trim as i32)) } != 0 {
        return aborted();
    }
    let data = ctx.data();
    let end = ctx.data_end();
    if data + N > end || (end - data) as u32 != v.new_len {
        return aborted();
    }
    // SAFETY: the N bytes at `data` are in the packet (re-checked above);
    // `hdr` is this CPU's `SCRATCH` map value, not packet memory, so the
    // ranges do not overlap.
    unsafe { core::ptr::copy_nonoverlapping(hdr.as_ptr(), data as *mut u8, N) };
    match TX.redirect(v.ifindex, 0) {
        Ok(action) => {
            if let Some(now) = v.touch {
                env.touch(now);
            }
            count_fwd(v.dir, v.new_len);
            action
        }
        // EGRESS allowed the interface but TX has no entry (a loader
        // inconsistency): the frame is already rewritten, so drop it.
        Err(_) => aborted(),
    }
}

/// The object's licence (decision Q2, Option A): `bpf_fib_lookup` is
/// `gpl_only`, so the kernel needs a GPL-compatible string.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

/// No panic path is reachable (the crates deny `unwrap`/`expect`/indexing
/// /`panic`, release has no overflow checks); a remaining one would show up
/// as a loop back-edge, which `check-object.py` and the verifier reject.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
