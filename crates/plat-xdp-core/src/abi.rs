//! BPF map ABI shared by the eBPF program, `platd` (`plat-xdp`) and the host
//! tests: map keys and values, the kernel `struct bpf_fib_lookup` layout,
//! state constants, and the counter and pass-reason indices.
//!
//! Every type is `#[repr(C)]` with compile-time size and offset asserts, so
//! a layout change fails the build on the host and for `bpfel-unknown-none`
//! alike. Multi-byte addresses and ports are byte arrays in network order
//! (exactly as they sit in the packet); other integers are in host order
//! (the kernel and `platd` share the CPU). `to_bytes` / `from_bytes` give
//! the byte image userspace passes to Aya (`[u8; N]` is `aya::Pod`), so no
//! crate needs an `unsafe impl Pod`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - every map has a
//!   fixed size; the constants below bound the ones not sized from config
//! - NIST 800-53: CM-6 - the `CONFIG` record is written once by the loader
//!   and frozen; `platd` verifies its digest

use core::mem::{offset_of, size_of};

use crate::put;
use crate::take;

/// `AF_INET` for [`FibParams::family`] (Linux).
pub const AF_INET: u8 = 2;
/// `AF_INET6` for [`FibParams::family`] (Linux).
pub const AF_INET6: u8 = 10;

/// `bpf_fib_lookup` return codes (`enum bpf_fib_lookup_ret`, linux/bpf.h).
pub const FIB_RET_SUCCESS: i64 = 0;
/// Forwarding is disabled on the lookup's ingress device (the TUN):
/// `plat-fwguard`'s fail-closed action.
pub const FIB_RET_FWD_DISABLED: i64 = 5;
/// The next hop has no resolved neighbour entry.
pub const FIB_RET_NO_NEIGH: i64 = 7;
/// `tot_len` exceeds the egress MTU.
pub const FIB_RET_FRAG_NEEDED: i64 = 8;

/// `SLOT` record states.
pub const SLOT_FREE: u8 = 0;
/// Installed and reachable from `OUT6` / `IN4`.
pub const SLOT_LIVE: u8 = 1;
/// Retired; waiting in quarantine for an RCU grace period.
pub const SLOT_DEAD: u8 = 2;

/// `SLICE` states. The values equal `plat_nat64::SliceState` (asserted by
/// the host tests).
pub const SLICE_INACTIVE: u8 = 0;
/// The only state in which the fast path forwards.
pub const SLICE_ACTIVE: u8 = 1;
pub const SLICE_FENCED: u8 = 2;
pub const SLICE_ADOPTING: u8 = 3;

/// Interface roles (decision Q3): IPv6→IPv4 only on `access`, IPv4→IPv6
/// only on `upstream`, both on `both`. Bit 0: access, bit 1: upstream.
pub const ROLE_ACCESS: u8 = 1;
pub const ROLE_UPSTREAM: u8 = 2;
pub const ROLE_BOTH: u8 = ROLE_ACCESS | ROLE_UPSTREAM;

/// `SLICE` entries (slices of a cluster pool; entry 0 without HA).
pub const MAX_SLICES: u32 = 4096;
/// `IFACES`, `EGRESS` and `TX` entries; indexed by `ifindex % IFACE_SLOTS`
/// and checked against the stored ifindex.
pub const IFACE_SLOTS: u32 = 64;
/// `STATS` entries (per-CPU `u64` counters).
pub const STATS_LEN: u32 = 40;
/// First `STATS` index of the pass reasons ([`PassReason::stat_idx`]).
pub const STAT_PASS_BASE: u32 = 8;
/// `SLOT.seen_ns` is stored only when it moved by at least this much, so a
/// session's line stays read-mostly (one store per second per session).
pub const SEEN_GRANULARITY_NS: u64 = 1_000_000_000;

/// `IFACES` / `EGRESS` index of an interface.
#[inline(always)]
pub const fn iface_slot(ifindex: u32) -> u32 {
    ifindex % IFACE_SLOTS
}

/// `OUT6` key: the IPv6 side of a UDP session as the subscriber sends it.
/// `dst6` is the canonical RFC 6052 embedding of the remote IPv4 address,
/// so a packet with a non-canonical suffix misses (slow path).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Key6 {
    pub src6: [u8; 16],
    pub dst6: [u8; 16],
    pub sport: [u8; 2],
    pub dport: [u8; 2],
    /// Always zero (the kernel hashes and compares every key byte).
    pub pad: [u8; 4],
}

/// `IN4` key: the IPv4 side as the remote sends it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Key4 {
    pub pool4: [u8; 4],
    pub remote4: [u8; 4],
    pub pool_port: [u8; 2],
    pub rport: [u8; 2],
}

/// `SLOT` record (64 bytes, one cache line). `platd` writes every field
/// except `seen_ns` only while the slot is unreachable, then stores
/// `state = LIVE`; the program writes `seen_ns` only. The key echo
/// (`src6`, `sport6`, `dst6`, `dport` outbound; `pool4`, `dst4`,
/// `pool_port4`, `dport` inbound) is compared with the packet, so a reused
/// hash element can never select another session's mapping (plan §4.3).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SlotRec {
    pub state: u8,
    pub pad0: u8,
    pub slice: u16,
    /// Slice generation at install; must equal `SLICE[slice].gen`.
    pub generation: u32,
    /// `bpf_ktime_get_coarse_ns` of the last fast-path packet (≥ 1 s steps).
    pub seen_ns: u64,
    /// Subscriber IPv6 address.
    pub src6: [u8; 16],
    /// Canonical RFC 6052 embedding of `dst4` (outbound key, inbound source).
    pub dst6: [u8; 16],
    /// Subscriber port.
    pub sport6: [u8; 2],
    /// Remote port.
    pub dport: [u8; 2],
    /// Pool port.
    pub pool_port4: [u8; 2],
    pub pad1: [u8; 2],
    /// Pool address.
    pub pool4: [u8; 4],
    /// Remote IPv4 address.
    pub dst4: [u8; 4],
}

/// `CONTROL` record, written by `platd` through `mmap`: the heartbeat
/// stores `deadline_ns`; `tun_ifindex` and `tun_mtu` are stored once,
/// before `enabled`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Control {
    /// 1: the fast path may forward. Anything else: pass `disabled`.
    pub enabled: u32,
    /// Ingress device of the FIB lookup, so the fast path gets the slow
    /// path's routing decision, policy rules and `forwarding` sysctl.
    pub tun_ifindex: u32,
    /// Dead-man deadline (`bpf_ktime_get_coarse_ns` clock): at or after it,
    /// pass `deadline`.
    pub deadline_ns: u64,
    /// MTU of the TUN. A packet longer than this never reaches `platd`
    /// whole (the kernel answers Packet Too Big or fragments it), so the
    /// fast path declines it too (`too_big`).
    pub tun_mtu: u32,
    pub pad: u32,
}

/// `SLICE` entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SliceEnt {
    pub state: u8,
    pub pad: [u8; 3],
    /// Bumped on every transition to Active, so a slice handover
    /// invalidates every record of the slice at once.
    pub generation: u32,
}

/// `CONFIG` record: written by the loader, then frozen.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConfigRec {
    /// `translation.ipv4_mtu`.
    pub mtu4: u16,
    /// `translation.ipv6_mtu`.
    pub mtu6: u16,
    /// `min(translation.lowest_ipv6_mtu, ipv6_mtu)` (RFC 7915 §4).
    pub frag6: u16,
    /// `translation.copy_tos` (0 or 1).
    pub copy_tos: u8,
    /// 1 with a sliced cluster pool.
    pub sliced: u8,
    /// SHA-256 of the translation parameters, checked by `platd`.
    pub digest: [u8; 32],
}

/// The translation parameters the decision needs (the [`ConfigRec`] fields
/// read per packet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XlatConfig {
    pub mtu4: u16,
    pub mtu6: u16,
    pub frag6: u16,
    pub copy_tos: bool,
}

/// `IFACES` entry (written by the loader).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IfaceEnt {
    pub ifindex: u32,
    /// Interface MAC: frames to any other destination are passed
    /// (`not_for_us`, the kernel's `PACKET_OTHERHOST`).
    pub mac: [u8; 6],
    /// `ROLE_*`.
    pub role: u8,
    pub pad: u8,
}

/// `EGRESS` entry (written by the loader): the configured interfaces a
/// translated packet may leave by.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EgressEnt {
    pub ifindex: u32,
    pub allowed: u8,
    pub pad: [u8; 3],
}

/// Kernel `struct bpf_fib_lookup` (64 bytes). Unions are flattened to their
/// widest member: `tot_len` / `mtu_result`; `tos` (byte 0) / `flowinfo`
/// (`__be32`) / `rt_metric`; `ipv4_src` (first 4 bytes) / `ipv6_src`;
/// `ipv4_dst` / `ipv6_dst`; `h_vlan_proto` + `h_vlan_TCI` / `tbid`; and,
/// since Linux 6.10, the input `mark` shares its bytes with `smac`. A
/// hand-rolled 68-byte variant was accepted by the helper and returned the
/// MACs 4 bytes off (spike Q3), hence the asserts below.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FibParams {
    pub family: u8,
    pub l4_protocol: u8,
    /// `__be16`.
    pub sport: [u8; 2],
    /// `__be16`.
    pub dport: [u8; 2],
    /// In: `tot_len` (host order). Out: `mtu_result` on `FRAG_NEEDED`.
    pub tot_len: u16,
    /// In: the lookup's ingress ifindex. Out: the egress ifindex.
    pub ifindex: u32,
    /// IPv4: `tos` in byte 0. IPv6: `flowinfo` (`__be32`).
    pub tos: [u8; 4],
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub vlan: [u8; 4],
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
}

const _: () = {
    assert!(size_of::<Key6>() == 40);
    assert!(offset_of!(Key6, src6) == 0);
    assert!(offset_of!(Key6, dst6) == 16);
    assert!(offset_of!(Key6, sport) == 32);
    assert!(offset_of!(Key6, dport) == 34);
    assert!(offset_of!(Key6, pad) == 36);

    assert!(size_of::<Key4>() == 12);
    assert!(offset_of!(Key4, pool4) == 0);
    assert!(offset_of!(Key4, remote4) == 4);
    assert!(offset_of!(Key4, pool_port) == 8);
    assert!(offset_of!(Key4, rport) == 10);

    assert!(size_of::<SlotRec>() == 64);
    assert!(offset_of!(SlotRec, state) == 0);
    assert!(offset_of!(SlotRec, slice) == 2);
    assert!(offset_of!(SlotRec, generation) == 4);
    assert!(offset_of!(SlotRec, seen_ns) == 8);
    assert!(offset_of!(SlotRec, src6) == 16);
    assert!(offset_of!(SlotRec, dst6) == 32);
    assert!(offset_of!(SlotRec, sport6) == 48);
    assert!(offset_of!(SlotRec, dport) == 50);
    assert!(offset_of!(SlotRec, pool_port4) == 52);
    assert!(offset_of!(SlotRec, pool4) == 56);
    assert!(offset_of!(SlotRec, dst4) == 60);

    assert!(size_of::<Control>() == 24);
    assert!(offset_of!(Control, enabled) == 0);
    assert!(offset_of!(Control, tun_ifindex) == 4);
    assert!(offset_of!(Control, deadline_ns) == 8);
    assert!(offset_of!(Control, tun_mtu) == 16);

    assert!(size_of::<SliceEnt>() == 8);
    assert!(offset_of!(SliceEnt, state) == 0);
    assert!(offset_of!(SliceEnt, generation) == 4);

    assert!(size_of::<ConfigRec>() == 40);
    assert!(offset_of!(ConfigRec, mtu4) == 0);
    assert!(offset_of!(ConfigRec, mtu6) == 2);
    assert!(offset_of!(ConfigRec, frag6) == 4);
    assert!(offset_of!(ConfigRec, copy_tos) == 6);
    assert!(offset_of!(ConfigRec, sliced) == 7);
    assert!(offset_of!(ConfigRec, digest) == 8);

    assert!(size_of::<IfaceEnt>() == 12);
    assert!(offset_of!(IfaceEnt, ifindex) == 0);
    assert!(offset_of!(IfaceEnt, mac) == 4);
    assert!(offset_of!(IfaceEnt, role) == 10);

    assert!(size_of::<EgressEnt>() == 8);
    assert!(offset_of!(EgressEnt, ifindex) == 0);
    assert!(offset_of!(EgressEnt, allowed) == 4);

    // linux/bpf.h `struct bpf_fib_lookup`.
    assert!(size_of::<FibParams>() == 64);
    assert!(offset_of!(FibParams, family) == 0);
    assert!(offset_of!(FibParams, l4_protocol) == 1);
    assert!(offset_of!(FibParams, sport) == 2);
    assert!(offset_of!(FibParams, dport) == 4);
    assert!(offset_of!(FibParams, tot_len) == 6);
    assert!(offset_of!(FibParams, ifindex) == 8);
    assert!(offset_of!(FibParams, tos) == 12);
    assert!(offset_of!(FibParams, src) == 16);
    assert!(offset_of!(FibParams, dst) == 32);
    assert!(offset_of!(FibParams, vlan) == 48);
    assert!(offset_of!(FibParams, smac) == 52);
    assert!(offset_of!(FibParams, dmac) == 58);

    assert!(STAT_PASS_BASE > StatIdx::Aborted as u32);
    assert!(STAT_PASS_BASE + PassReason::COUNT <= STATS_LEN);
};

impl Key6 {
    #[inline(always)]
    pub const fn new(src6: [u8; 16], dst6: [u8; 16], sport: [u8; 2], dport: [u8; 2]) -> Self {
        Self { src6, dst6, sport, dport, pad: [0; 4] }
    }

    pub fn to_bytes(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        put(&mut b, offset_of!(Key6, src6), &self.src6);
        put(&mut b, offset_of!(Key6, dst6), &self.dst6);
        put(&mut b, offset_of!(Key6, sport), &self.sport);
        put(&mut b, offset_of!(Key6, dport), &self.dport);
        put(&mut b, offset_of!(Key6, pad), &self.pad);
        b
    }

    pub fn from_bytes(b: &[u8; 40]) -> Self {
        Self {
            src6: take(b, offset_of!(Key6, src6)),
            dst6: take(b, offset_of!(Key6, dst6)),
            sport: take(b, offset_of!(Key6, sport)),
            dport: take(b, offset_of!(Key6, dport)),
            pad: take(b, offset_of!(Key6, pad)),
        }
    }
}

impl Key4 {
    #[inline(always)]
    pub const fn new(pool4: [u8; 4], remote4: [u8; 4], pool_port: [u8; 2], rport: [u8; 2]) -> Self {
        Self { pool4, remote4, pool_port, rport }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        put(&mut b, offset_of!(Key4, pool4), &self.pool4);
        put(&mut b, offset_of!(Key4, remote4), &self.remote4);
        put(&mut b, offset_of!(Key4, pool_port), &self.pool_port);
        put(&mut b, offset_of!(Key4, rport), &self.rport);
        b
    }

    pub fn from_bytes(b: &[u8; 12]) -> Self {
        Self {
            pool4: take(b, offset_of!(Key4, pool4)),
            remote4: take(b, offset_of!(Key4, remote4)),
            pool_port: take(b, offset_of!(Key4, pool_port)),
            rport: take(b, offset_of!(Key4, rport)),
        }
    }
}

/// 64-bit words of a [`SlotRec`] as `platd` sees them through `mmap`
/// (`&[AtomicU64]`).
pub const SLOT_WORDS: usize = 8;
/// Word holding `state`, `slice` and `generation` (one atomic store).
pub const SLOT_WORD_HDR: usize = 0;
/// Word holding `seen_ns`.
pub const SLOT_WORD_SEEN: usize = 1;

impl SlotRec {
    /// The header word (`state`, `slice`, `generation`) in host order, as
    /// one atomic store publishes it.
    #[inline(always)]
    pub const fn hdr_word(state: u8, slice: u16, generation: u32) -> u64 {
        let s = slice.to_ne_bytes();
        let g = generation.to_ne_bytes();
        u64::from_ne_bytes([state, 0, s[0], s[1], g[0], g[1], g[2], g[3]])
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        put(&mut b, offset_of!(SlotRec, state), &[self.state]);
        put(&mut b, offset_of!(SlotRec, pad0), &[self.pad0]);
        put(&mut b, offset_of!(SlotRec, slice), &self.slice.to_ne_bytes());
        put(&mut b, offset_of!(SlotRec, generation), &self.generation.to_ne_bytes());
        put(&mut b, offset_of!(SlotRec, seen_ns), &self.seen_ns.to_ne_bytes());
        put(&mut b, offset_of!(SlotRec, src6), &self.src6);
        put(&mut b, offset_of!(SlotRec, dst6), &self.dst6);
        put(&mut b, offset_of!(SlotRec, sport6), &self.sport6);
        put(&mut b, offset_of!(SlotRec, dport), &self.dport);
        put(&mut b, offset_of!(SlotRec, pool_port4), &self.pool_port4);
        put(&mut b, offset_of!(SlotRec, pad1), &self.pad1);
        put(&mut b, offset_of!(SlotRec, pool4), &self.pool4);
        put(&mut b, offset_of!(SlotRec, dst4), &self.dst4);
        b
    }

    pub fn from_bytes(b: &[u8; 64]) -> Self {
        let [state] = take(b, offset_of!(SlotRec, state));
        let [pad0] = take(b, offset_of!(SlotRec, pad0));
        Self {
            state,
            pad0,
            slice: u16::from_ne_bytes(take(b, offset_of!(SlotRec, slice))),
            generation: u32::from_ne_bytes(take(b, offset_of!(SlotRec, generation))),
            seen_ns: u64::from_ne_bytes(take(b, offset_of!(SlotRec, seen_ns))),
            src6: take(b, offset_of!(SlotRec, src6)),
            dst6: take(b, offset_of!(SlotRec, dst6)),
            sport6: take(b, offset_of!(SlotRec, sport6)),
            dport: take(b, offset_of!(SlotRec, dport)),
            pool_port4: take(b, offset_of!(SlotRec, pool_port4)),
            pad1: take(b, offset_of!(SlotRec, pad1)),
            pool4: take(b, offset_of!(SlotRec, pool4)),
            dst4: take(b, offset_of!(SlotRec, dst4)),
        }
    }

    /// The record as host-order 64-bit words (the `mmap` view).
    pub fn to_words(&self) -> [u64; SLOT_WORDS] {
        let b = self.to_bytes();
        let mut w = [0u64; SLOT_WORDS];
        let (chunks, _) = b.as_chunks::<8>();
        for (d, c) in w.iter_mut().zip(chunks) {
            *d = u64::from_ne_bytes(*c);
        }
        w
    }
}

impl Control {
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        put(&mut b, offset_of!(Control, enabled), &self.enabled.to_ne_bytes());
        put(&mut b, offset_of!(Control, tun_ifindex), &self.tun_ifindex.to_ne_bytes());
        put(&mut b, offset_of!(Control, deadline_ns), &self.deadline_ns.to_ne_bytes());
        put(&mut b, offset_of!(Control, tun_mtu), &self.tun_mtu.to_ne_bytes());
        put(&mut b, offset_of!(Control, pad), &self.pad.to_ne_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; 24]) -> Self {
        Self {
            enabled: u32::from_ne_bytes(take(b, offset_of!(Control, enabled))),
            tun_ifindex: u32::from_ne_bytes(take(b, offset_of!(Control, tun_ifindex))),
            deadline_ns: u64::from_ne_bytes(take(b, offset_of!(Control, deadline_ns))),
            tun_mtu: u32::from_ne_bytes(take(b, offset_of!(Control, tun_mtu))),
            pad: u32::from_ne_bytes(take(b, offset_of!(Control, pad))),
        }
    }
}

impl SliceEnt {
    /// The entry as one host-order word (one atomic store).
    #[inline(always)]
    pub const fn word(state: u8, generation: u32) -> u64 {
        let g = generation.to_ne_bytes();
        u64::from_ne_bytes([state, 0, 0, 0, g[0], g[1], g[2], g[3]])
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        put(&mut b, offset_of!(SliceEnt, state), &[self.state]);
        put(&mut b, offset_of!(SliceEnt, pad), &self.pad);
        put(&mut b, offset_of!(SliceEnt, generation), &self.generation.to_ne_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; 8]) -> Self {
        let [state] = take(b, offset_of!(SliceEnt, state));
        Self {
            state,
            pad: take(b, offset_of!(SliceEnt, pad)),
            generation: u32::from_ne_bytes(take(b, offset_of!(SliceEnt, generation))),
        }
    }
}

impl ConfigRec {
    /// The fields the per-packet decision reads.
    #[inline(always)]
    pub const fn xlat(&self) -> XlatConfig {
        XlatConfig { mtu4: self.mtu4, mtu6: self.mtu6, frag6: self.frag6, copy_tos: self.copy_tos == 1 }
    }

    pub fn to_bytes(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        put(&mut b, offset_of!(ConfigRec, mtu4), &self.mtu4.to_ne_bytes());
        put(&mut b, offset_of!(ConfigRec, mtu6), &self.mtu6.to_ne_bytes());
        put(&mut b, offset_of!(ConfigRec, frag6), &self.frag6.to_ne_bytes());
        put(&mut b, offset_of!(ConfigRec, copy_tos), &[self.copy_tos]);
        put(&mut b, offset_of!(ConfigRec, sliced), &[self.sliced]);
        put(&mut b, offset_of!(ConfigRec, digest), &self.digest);
        b
    }

    pub fn from_bytes(b: &[u8; 40]) -> Self {
        let [copy_tos] = take(b, offset_of!(ConfigRec, copy_tos));
        let [sliced] = take(b, offset_of!(ConfigRec, sliced));
        Self {
            mtu4: u16::from_ne_bytes(take(b, offset_of!(ConfigRec, mtu4))),
            mtu6: u16::from_ne_bytes(take(b, offset_of!(ConfigRec, mtu6))),
            frag6: u16::from_ne_bytes(take(b, offset_of!(ConfigRec, frag6))),
            copy_tos,
            sliced,
            digest: take(b, offset_of!(ConfigRec, digest)),
        }
    }
}

impl IfaceEnt {
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        put(&mut b, offset_of!(IfaceEnt, ifindex), &self.ifindex.to_ne_bytes());
        put(&mut b, offset_of!(IfaceEnt, mac), &self.mac);
        put(&mut b, offset_of!(IfaceEnt, role), &[self.role]);
        put(&mut b, offset_of!(IfaceEnt, pad), &[self.pad]);
        b
    }

    pub fn from_bytes(b: &[u8; 12]) -> Self {
        let [role] = take(b, offset_of!(IfaceEnt, role));
        let [pad] = take(b, offset_of!(IfaceEnt, pad));
        Self {
            ifindex: u32::from_ne_bytes(take(b, offset_of!(IfaceEnt, ifindex))),
            mac: take(b, offset_of!(IfaceEnt, mac)),
            role,
            pad,
        }
    }
}

impl EgressEnt {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        put(&mut b, offset_of!(EgressEnt, ifindex), &self.ifindex.to_ne_bytes());
        put(&mut b, offset_of!(EgressEnt, allowed), &[self.allowed]);
        put(&mut b, offset_of!(EgressEnt, pad), &self.pad);
        b
    }

    pub fn from_bytes(b: &[u8; 8]) -> Self {
        let [allowed] = take(b, offset_of!(EgressEnt, allowed));
        Self {
            ifindex: u32::from_ne_bytes(take(b, offset_of!(EgressEnt, ifindex))),
            allowed,
            pad: take(b, offset_of!(EgressEnt, pad)),
        }
    }
}

/// Why a frame was passed to the slow path. Indices are stable (they are
/// `STATS` indices via [`PassReason::stat_idx`] and the `reason` label of
/// `plat_xdp_pass_total`); append new reasons at the end only.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PassReason {
    /// Not untagged IPv4/IPv6 (VLAN, ARP, anything else).
    NotIp = 0,
    /// Destination MAC is not the ingress interface's (multicast, broadcast,
    /// another host).
    NotForUs = 1,
    /// The ingress interface's role does not allow this direction, or it is
    /// not a configured interface.
    Role = 2,
    /// Version, length or IPv4 header checksum wrong, or the frame is
    /// shorter than the fixed header block.
    BadL3 = 3,
    /// IPv4 IHL > 5.
    Ipv4Options = 4,
    /// IPv4 MF set or fragment offset non-zero.
    Fragment = 5,
    /// IPv6 next header is an extension header.
    ExtHeader = 6,
    /// Not UDP (TCP, ICMP, anything else).
    NotUdp = 7,
    /// UDP length differs from the IP payload length.
    UdpLen = 8,
    /// UDP checksum 0 (IPv6: invalid; IPv4: needs a full checksum).
    UdpZeroCsum = 9,
    /// TTL / hop limit ≤ 2 (two-hop model, RFC-007): the kernel or `platd`
    /// answers with Time Exceeded.
    HopLimit = 10,
    /// `CONTROL.enabled` is not 1.
    Disabled = 11,
    /// The dead-man deadline passed.
    Deadline = 12,
    /// No `OUT6` / `IN4` entry for the exact key.
    NoSession = 13,
    /// The slot is not LIVE or its key echo differs.
    SlotDead = 14,
    /// The record's slice is not Active or its generation is stale.
    SliceInactive = 15,
    /// Above `tun_mtu`, `ipv4_mtu`, `ipv6_mtu` or (DF = 0) the lowest IPv6
    /// MTU: the slow path fragments or sends Packet Too Big / Frag Needed.
    TooBig = 16,
    /// `bpf_fib_lookup`: forwarding disabled on the TUN.
    FibFwdDisabled = 17,
    /// `bpf_fib_lookup`: next hop unresolved.
    FibNoNeigh = 18,
    /// `bpf_fib_lookup`: egress MTU below the packet.
    FibFragNeeded = 19,
    /// `bpf_fib_lookup`: any other result.
    FibOther = 20,
    /// The FIB egress interface is not in `EGRESS`.
    EgressNotAllowed = 21,
    /// `bpf_xdp_adjust_head` failed (no headroom; eBPF program only).
    Headroom = 22,
}

impl PassReason {
    /// Number of reasons.
    pub const COUNT: u32 = 23;

    /// Every reason in index order.
    pub const ALL: [PassReason; Self::COUNT as usize] = [
        Self::NotIp,
        Self::NotForUs,
        Self::Role,
        Self::BadL3,
        Self::Ipv4Options,
        Self::Fragment,
        Self::ExtHeader,
        Self::NotUdp,
        Self::UdpLen,
        Self::UdpZeroCsum,
        Self::HopLimit,
        Self::Disabled,
        Self::Deadline,
        Self::NoSession,
        Self::SlotDead,
        Self::SliceInactive,
        Self::TooBig,
        Self::FibFwdDisabled,
        Self::FibNoNeigh,
        Self::FibFragNeeded,
        Self::FibOther,
        Self::EgressNotAllowed,
        Self::Headroom,
    ];

    /// The `reason` label of `plat_xdp_pass_total` (plan §4.7).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotIp => "not_ip",
            Self::NotForUs => "not_for_us",
            Self::Role => "role",
            Self::BadL3 => "bad_l3",
            Self::Ipv4Options => "ipv4_options",
            Self::Fragment => "fragment",
            Self::ExtHeader => "ext_header",
            Self::NotUdp => "not_udp",
            Self::UdpLen => "udp_len",
            Self::UdpZeroCsum => "udp_zero_csum",
            Self::HopLimit => "hop_limit",
            Self::Disabled => "disabled",
            Self::Deadline => "deadline",
            Self::NoSession => "no_session",
            Self::SlotDead => "slot_dead",
            Self::SliceInactive => "slice_inactive",
            Self::TooBig => "too_big",
            Self::FibFwdDisabled => "fib_fwd_disabled",
            Self::FibNoNeigh => "fib_no_neigh",
            Self::FibFragNeeded => "fib_frag_needed",
            Self::FibOther => "fib_other",
            Self::EgressNotAllowed => "egress_not_allowed",
            Self::Headroom => "headroom",
        }
    }

    /// `STATS` index of this reason.
    #[inline(always)]
    pub const fn stat_idx(self) -> u32 {
        STAT_PASS_BASE + self as u32
    }
}

/// `STATS` indices of the non-pass counters. Stable; append only.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatIdx {
    /// `plat_xdp_packets_total{dir="v6_to_v4"}`.
    PacketsV6ToV4 = 0,
    /// `plat_xdp_packets_total{dir="v4_to_v6"}`.
    PacketsV4ToV6 = 1,
    /// `plat_xdp_bytes_total{dir="v6_to_v4"}` (output frame bytes).
    BytesV6ToV4 = 2,
    /// `plat_xdp_bytes_total{dir="v4_to_v6"}`.
    BytesV4ToV6 = 3,
    /// `plat_xdp_aborted_total`: a bounds re-check failed after an adjust.
    Aborted = 4,
}

impl StatIdx {
    pub const ALL: [StatIdx; 5] =
        [Self::PacketsV6ToV4, Self::PacketsV4ToV6, Self::BytesV6ToV4, Self::BytesV4ToV6, Self::Aborted];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PacketsV6ToV4 => "packets_v6_to_v4",
            Self::PacketsV4ToV6 => "packets_v4_to_v6",
            Self::BytesV6ToV4 => "bytes_v6_to_v4",
            Self::BytesV4ToV6 => "bytes_v4_to_v6",
            Self::Aborted => "aborted",
        }
    }
}
