//! The program's BPF maps (plan §4.1): legacy `bpf_map_def` definitions as
//! emitted by aya-ebpf 0.2.1 (plan §2.5 rule 6). Keys and values are the
//! `plat-xdp-core::abi` types, whose sizes and offsets are asserted at
//! compile time, so the program, the loader and `platd` share one layout.
//!
//! The loader (WU3) creates and pins every map and sets `max_entries` of
//! `OUT6`, `IN4` and `SLOT` from `xdp.max_sessions`; the sizes below are
//! fail-safe placeholders (a table that is too small sends more traffic to
//! the slow path, never less checking). The program only looks maps up: it
//! never inserts or deletes elements (no `bpf_map_update_elem` /
//! `bpf_map_delete_elem`; `check-object.py` rejects them). It writes only
//! through lookup pointers: `SLOT.seen_ns`, this CPU's `IDENT` entry,
//! this CPU's `SCRATCH` block and this CPU's `STATS` counters.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 (Denial-of-Service Protection) - every map has a
//!   fixed `max_entries`; no per-packet state is created
//! - NIST 800-53: SC-24 (Fail in Known State) - `CONTROL`, `SLICE` gate
//!   forwarding; `CONFIG` and `IDENT_KEY` are read-only to the program
//!   (`BPF_F_RDONLY_PROG`)
//! - CLAUDE.md rule 3 - the kernel keys every BPF hash map with a random
//!   seed (`htab->hashrnd`; the loader never sets `BPF_F_ZERO_SEED`)

use aya_ebpf::bindings::{BPF_F_MMAPABLE, BPF_F_RDONLY_PROG};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, DevMapHash, HashMap, PerCpuArray};
use plat_xdp_core::HDR6;
use plat_xdp_core::abi::{
    ConfigRec, Control, EgressEnt, IFACE_SLOTS, IdentEnt, IfaceEnt, Key4, Key6, MAX_SLICES, STATS_LEN, SliceEnt,
    SlotRec,
};
use plat_xdp_core::ident::{IdentKey, TABLE};

/// Placeholder `OUT6` / `IN4` size (the loader sets `xdp.max_sessions`).
const SESSIONS: u32 = 1024;
/// Placeholder `SLOT` size: ⌈1.25 × sessions⌉ (plan §4.1).
const SLOTS: u32 = SESSIONS + SESSIONS / 4;

/// `{src6, dst6, sport, dport}` → slot (preallocated hash).
#[map(name = "OUT6")]
pub(crate) static OUT6: HashMap<Key6, u32> = HashMap::with_max_entries(SESSIONS, 0);

/// `{pool4, remote4, pool_port, rport}` → slot (preallocated hash).
#[map(name = "IN4")]
pub(crate) static IN4: HashMap<Key4, u32> = HashMap::with_max_entries(SESSIONS, 0);

/// Session records; `platd` writes them through `mmap`.
#[map(name = "SLOT")]
pub(crate) static SLOT: Array<SlotRec> = Array::with_max_entries(SLOTS, BPF_F_MMAPABLE);

/// Slice state and generation (entry 0 without HA).
#[map(name = "SLICE")]
pub(crate) static SLICE: Array<SliceEnt> = Array::with_max_entries(MAX_SLICES, BPF_F_MMAPABLE);

/// `enabled`, `tun_ifindex`, `deadline_ns`, `tun_mtu` (the `platd` heartbeat).
#[map(name = "CONTROL")]
pub(crate) static CONTROL: Array<Control> = Array::with_max_entries(1, BPF_F_MMAPABLE);

/// Translation parameters, written once by the loader and frozen.
#[map(name = "CONFIG")]
pub(crate) static CONFIG: Array<ConfigRec> = Array::with_max_entries(1, BPF_F_RDONLY_PROG);

/// Per-CPU RFC 7739 §5.3 counters and their step generators.
#[map(name = "IDENT")]
pub(crate) static IDENT: PerCpuArray<IdentEnt> = PerCpuArray::with_max_entries(TABLE, 0);

/// The counter-table key, written once by the loader and frozen.
#[map(name = "IDENT_KEY")]
pub(crate) static IDENT_KEY: Array<IdentKey> = Array::with_max_entries(1, BPF_F_RDONLY_PROG);

/// Interface roles and MACs, indexed by `ifindex % IFACE_SLOTS`.
#[map(name = "IFACES")]
pub(crate) static IFACES: Array<IfaceEnt> = Array::with_max_entries(IFACE_SLOTS, 0);

/// Egress allow-list, indexed by `ifindex % IFACE_SLOTS`.
#[map(name = "EGRESS")]
pub(crate) static EGRESS: Array<EgressEnt> = Array::with_max_entries(IFACE_SLOTS, 0);

/// Redirect targets (egress ifindex → device).
#[map(name = "TX")]
pub(crate) static TX: DevMapHash = DevMapHash::with_max_entries(IFACE_SLOTS, 0);

/// Per-CPU counters (`StatIdx`, then `PassReason::stat_idx`).
#[map(name = "STATS")]
pub(crate) static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STATS_LEN, 0);

/// This CPU's output header block (Ethernet + IPv6 + UDP, the larger
/// direction). It lives in a map rather than on the stack to keep 64 B of
/// stack headroom under the 384 B budget (plan §2.5 rule 5; the brief's
/// PERF-001 fallback). Created by the loader, never pinned; nothing reads it
/// outside one program run.
#[map(name = "SCRATCH")]
pub(crate) static SCRATCH: PerCpuArray<[u8; HDR6]> = PerCpuArray::with_max_entries(1, 0);
