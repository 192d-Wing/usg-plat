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
//! constants (plan §2.5 rule 1). Packet pointers are
//! never subtracted: `pointer -= pointer` needs `allow_ptr_leaks`
//! (CAP_PERFMON), which also turns off the verifier's Spectre v1/v4
//! hardening for the program (SEC-001). The frame length comes from
//! `bpf_xdp_get_buff_len` instead ([`frame_len`]). There are no loops and no bpf-to-bpf calls:
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
use aya_ebpf::helpers::generated::{
    bpf_csum_diff, bpf_fib_lookup, bpf_ktime_get_coarse_ns, bpf_xdp_adjust_head, bpf_xdp_adjust_tail,
    bpf_xdp_get_buff_len, bpf_xdp_load_bytes,
};
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use plat_xdp_core::abi::{
    CSUM_MAX_L4, Control, EgressEnt, FibParams, FwdDir, IdentEnt, IfaceEnt, Key4, Key6, PassReason, SliceEnt, SlotRec,
    StatIdx, XlatConfig, iface_slot,
};
use plat_xdp_core::classify::{ETHERTYPE_IPV4, ETHERTYPE_IPV6, PROTO_UDP};
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

    /// RFC-001: verifies the UDP checksum of the frame's datagram before
    /// the decision runs ([`udp_csum_verify`], while few values are live);
    /// [`Env::udp_csum_ok`] answers from this result.
    #[inline(always)]
    fn precompute_csum(&self, v6: bool, len: u32) {
        let ok = udp_csum_verify(self.ctx, u32::from(v6), len) == 1;
        set_csum_ok(if ok { CSUM_VERIFIED | len << 1 | u32::from(v6) } else { 0 });
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

    /// The result `precompute_csum` stored for exactly this datagram.
    #[inline(always)]
    fn udp_csum_ok(&self, v6: bool, len: u32) -> bool {
        csum_ok() == CSUM_VERIFIED | len << 1 | u32::from(v6)
    }
}

/// RFC-001: whether the UDP checksum of the frame's IPv6 (`v6`) or IPv4
/// datagram of `len` bytes verifies (1) or not (0), as
/// `plat_xdp_core::udp_csum_ok_in` computes it. Everything is read with
/// `bpf_xdp_load_bytes` into this CPU's `SCRATCH` (no packet pointer
/// arithmetic with a variable length, which the verifier refuses without
/// CAP_PERFMON): the pseudo-header addresses (one constant-size load) and
/// the datagram's whole 4-byte words, summed with `bpf_csum_diff` in four
/// constant 512-byte windows (sizes bounded, multiples of 4); the 0-3 tail
/// bytes come from the datagram's last 4 bytes (one constant-size load)
/// and are added in network order with the length and protocol. The
/// kernel's sum is in host byte order: folded and byte-swapped on a
/// little-endian target it is the network-order sum (RFC 1071 §2(B)).
///
/// Stack (measured on 6.8): it reads only through the helpers (reading the
/// addresses through the caller's packet pointers kept those loads live
/// across the helper calls), runs before the decision, and `SCRATCH.hdr`
/// stays at offset 0 (at offset 2048 the frame grew from 336 to 496 B);
/// inlined, the program's one frame is 344 B (budget 384). As a separate
/// bpf-to-bpf subprogram the chain was 344 + 48 B.
#[inline(always)]
fn udp_csum_verify(ctx: *mut xdp_md, v6: u32, len: u32) -> u32 {
    u32::from(udp_csum_verify_inner(ctx, v6 != 0, len).unwrap_or(false))
}

#[inline(always)]
fn csum_add(buf: *mut u8, n: u32, acc: u32) -> Option<u32> {
    // The data goes in as `to`: the helper complements every `from` word
    // (it computes a checksum difference), and sums `to` as is.
    // SAFETY: callers pass a pointer into this CPU's SCRATCH value with
    // `n` (a multiple of 4, ≤ 512) bytes inside it.
    let r = unsafe { bpf_csum_diff(core::ptr::null_mut(), 0, buf.cast(), n, acc) };
    if r < 0 { None } else { Some(r as u32) }
}

#[inline(always)]
fn udp_csum_verify_inner(ctx: *mut xdp_md, v6: bool, len: u32) -> Option<bool> {
    // A UDP datagram has at least its 8-byte header (classify checked
    // it).
    if !(8..=CSUM_MAX_L4).contains(&len) {
        return None;
    }
    let s = SCRATCH.get_ptr_mut(0)?;
    // SAFETY: this CPU's element (see `scratch`); only the helpers below
    // write `l4` and `addrs`, through these pointers.
    let (buf, addrs): (*mut u8, *mut u8) = unsafe { ((&raw mut (*s).l4).cast(), (&raw mut (*s).addrs).cast()) };
    // Pseudo-header addresses: IPv6 src + dst (32 bytes at ETH + 8),
    // IPv4 src + dst (8 bytes at ETH + 12).
    let mut acc: u32 = 0;
    if v6 {
        // SAFETY: helper on the program's context, 32 bytes into `addrs`.
        if unsafe { bpf_xdp_load_bytes(ctx, (ETH + 8) as u32, addrs.cast(), 32) } != 0 {
            return None;
        }
        acc = csum_add(addrs, 32, acc)?;
    } else {
        // SAFETY: as above, 8 bytes.
        if unsafe { bpf_xdp_load_bytes(ctx, (ETH + 12) as u32, addrs.cast(), 8) } != 0 {
            return None;
        }
        acc = csum_add(addrs, 8, acc)?;
    }
    let off = (ETH + if v6 { 40 } else { 20 }) as u32;
    // The whole words, a multiple of 4: 8 ≤ main ≤ CSUM_MAX_L4 at run
    // time. Written as mask-then-add so the verifier sees a non-zero
    // minimum (`len & !3` loses it; `bpf_xdp_load_bytes` needs one) and a
    // maximum of 2052 (`0x7fc + 8`), inside the SCRATCH value; LLVM cannot
    // fold it back into a mask. (len ≤ 1536 here, so the mask never cuts.)
    const _: () = assert!(
        CSUM_MAX_L4 <= 1536
            && core::mem::offset_of!(crate::maps::Scratch, l4) + 2052 <= core::mem::size_of::<crate::maps::Scratch>()
    );
    let main = ((len - 8) & 0x7fc) + 8;
    // SAFETY: helper on the program's context; it writes `main` bytes into
    // `buf` and fails if they are not all in the packet (gpl_only = false).
    if unsafe { bpf_xdp_load_bytes(ctx, off, buf.cast(), main) } != 0 {
        return None;
    }
    // Three windows, explicitly: each stops the chain once the words are
    // summed, so the verifier walks 3 paths, not 2^3 (least-privilege
    // instruction budget).
    const _: () = assert!(CSUM_MAX_L4 == 3 * CSUM_CHUNK);
    if main <= CSUM_CHUNK {
        acc = csum_add(buf, main, acc)?;
    } else {
        acc = csum_add(buf, CSUM_CHUNK, acc)?;
        // SAFETY: offsets inside `l4` (main > 512).
        let b1 = unsafe { buf.add(CSUM_CHUNK as usize) };
        if main <= 2 * CSUM_CHUNK {
            acc = csum_add(b1, main - CSUM_CHUNK, acc)?;
        } else {
            acc = csum_add(b1, CSUM_CHUNK, acc)?;
            // SAFETY: as above (main > 1024).
            let b2 = unsafe { buf.add(2 * CSUM_CHUNK as usize) };
            acc = csum_add(b2, main - 2 * CSUM_CHUNK, acc)?;
        }
    }
    let f = plat_xdp_core::csum::fold(u64::from(acc));
    let mut sum = u64::from(if cfg!(target_endian = "little") { f.swap_bytes() } else { f });
    sum += u64::from(len) + u64::from(PROTO_UDP);
    let tail = len & 3;
    if tail != 0 {
        let mut w = [0u8; 4];
        // SAFETY: helper on the program's context; 4 bytes into the stack
        // word (len ≥ 8, so the last 4 bytes are in the datagram).
        if unsafe { bpf_xdp_load_bytes(ctx, off + len - 4, w.as_mut_ptr().cast(), 4) } != 0 {
            return None;
        }
        let [_, b1, b2, b3] = w;
        sum += match tail {
            1 => u64::from(b3) << 8,
            2 => u64::from(u16::from_be_bytes([b2, b3])),
            _ => u64::from(u16::from_be_bytes([b1, b2])) + (u64::from(b3) << 8),
        };
    }
    Some(plat_xdp_core::csum::fold(sum) == 0xffff)
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

/// Largest frame length the program trusts (a 16-bit IP total length plus
/// the Ethernet header); `bpf_xdp_get_buff_len` returns an unbounded
/// scalar to the verifier.
const MAX_FRAME: usize = 0xffff + ETH;

/// The frame's length in bytes, from `bpf_xdp_get_buff_len` (SEC-001: no
/// packet pointer subtraction, so no CAP_PERFMON).
///
/// The program is never loaded with `BPF_F_XDP_HAS_FRAGS` (section `xdp`,
/// not `xdp.frags`; `check-object.py` and the loader assert it), so the
/// buffer is linear and the helper's result is exactly `data_end - data`.
/// A value above [`MAX_FRAME`] (impossible for a linear buffer) becomes 0,
/// which fails every decision's `end > frame_len` check, so the frame is
/// passed (`bad_l3`).
#[inline(always)]
fn frame_len(ctx: &XdpContext) -> u32 {
    // SAFETY: helper on the program's context; it only reads the buffer
    // lengths (`gpl_only = false`, kernel 5.18+; see check-object.py).
    let n = unsafe { bpf_xdp_get_buff_len(ctx.ctx) };
    if n > MAX_FRAME as u64 { 0 } else { n as u32 }
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
    // written by the core's rewrite first. The `l4` part is touched only
    // through raw pointers by the helpers in `l4_sum`, never while this
    // reference is used to read.
    Some(unsafe { &mut (*p).hdr })
}

/// Flag of a verified `SCRATCH.csum_ok` (lengths are ≤ CSUM_MAX_L4).
const CSUM_VERIFIED: u32 = 1 << 31;

/// Stores this frame's checksum result, `CSUM_VERIFIED | len << 1 | v6`
/// or 0, in this CPU's `SCRATCH` (map memory, not the stack: the verifier
/// does not track it, so the decision's paths are verified once, not once
/// per checksum outcome, which kept least-privilege verification inside
/// the instruction budget).
#[inline(always)]
fn set_csum_ok(v: u32) {
    if let Some(p) = SCRATCH.get_ptr_mut(0) {
        // SAFETY: this CPU's element (see `scratch`).
        unsafe { core::ptr::write_volatile(&raw mut (*p).csum_ok, v) };
    }
}

#[inline(always)]
fn csum_ok() -> u32 {
    // SAFETY: this CPU's element (see `scratch`).
    SCRATCH.get_ptr_mut(0).map_or(0, |p| unsafe { core::ptr::read_volatile(&raw const (*p).csum_ok) })
}

/// `bpf_csum_diff`'s per-call limit (`sizeof(sp->diff)`, 128 words).
const CSUM_CHUNK: u32 = 512;

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
    let frame_len = frame_len(ctx);
    let Some(o) = scratch().and_then(|s| s.first_chunk_mut::<HDR4>()) else {
        return pass(PassReason::Disabled);
    };
    let env = MapEnv::new(ctx.ctx);
    // RFC-001: UDP only (anything else passes anyway); `payload_len` is
    // the UDP length the decision checks.
    if h[ETH + 6] == PROTO_UDP {
        env.precompute_csum(true, u32::from(u16::from_be_bytes([h[ETH + 4], h[ETH + 5]])));
    } else {
        set_csum_ok(0);
    }
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
    let frame_len = frame_len(ctx);
    let Some(o) = scratch() else {
        return pass(PassReason::Disabled);
    };
    let env = MapEnv::new(ctx.ctx);
    // RFC-001: UDP without options only (anything else passes anyway).
    let total = u32::from(u16::from_be_bytes([h[ETH + 2], h[ETH + 3]]));
    if h[ETH] == 0x45 && h[ETH + 9] == PROTO_UDP && total >= 28 {
        env.precompute_csum(false, total - 20);
    } else {
        set_csum_ok(0);
    }
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
    // SEC-001: the length re-check compares scalars: the helper's frame
    // length (after the adjusts) with the verdict's `new_len`. Neither a
    // pointer difference (`end - data` needs `allow_ptr_leaks`) nor a
    // bounded `data + new_len != end` works without CAP_PERFMON: for a
    // caller without `bypass_spec_v1` the verifier refuses packet pointer +
    // variable scalar outright ("pointer arithmetic with it prohibited for
    // !root", `retrieve_ptr_limit` handles only stack and map values;
    // measured on 6.8). The constant `data + N > end` check remains for the
    // header copy.
    if data + N > end || frame_len(ctx) != v.new_len {
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
