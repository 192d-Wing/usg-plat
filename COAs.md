# Courses of action: data-plane throughput (POAM-016)

Problem: one TUN syscall per packet caps a worker at about 0.45–0.62 Mpps,
with about 86% of its CPU in the kernel (Lima VM, indicative only; see
`docs/compliance/POAM.md` POAM-016). The translation engine is about 10%
of the cost, so speeding it up does not help; kernel crossings must go.

Every gain figure below is an estimate. None is measured. A Linux baseline
benchmark is a prerequisite for every COA.

## Decision

**Selected: COA 1, XDP hybrid** (2026-10-30). The COA's own
recommendation (pursue only if AF_XDP cannot meet a target) is
superseded by this selection. Proceed by its phasing: Phase 0 baseline,
then Phase 1 (established UDP fast path with a differential test harness),
each phase gated on fast-path/slow-path equivalence. COA 2 (FPGA) is not
pursued.

**Licensing** (2026-10-30): the eBPF crate is `MIT OR GPL-2.0-only` and
its object declares `"Dual MIT/GPL"`, because the fast path calls
`bpf_fib_lookup`, a GPL-only kernel helper. Every other crate keeps the
workspace licence (`Apache-2.0`); `deny.toml` gets an exception scoped to
the eBPF crate. Keeping `bpf_fib_lookup` preserves routing parity with the slow
path and fail-closed behaviour when forwarding is disabled.

## COA 1: XDP hybrid (fast path in eBPF, slow path in platd)

### Concept

Split the data plane in two:

| Path | Runs in | Handles |
|---|---|---|
| Fast path | eBPF program at the XDP hook, in the NIC driver before the kernel stack | Packets of an existing session: map lookup, in-place IPv6↔IPv4 header rewrite, incremental checksums, session timer refresh, transmit |
| Slow path | `platd` (today's Rust engine) | New flows (port allocation, audit record first), ICMP errors, fragments, held SYNs, IPv4 options, IPv6 extension headers, anything malformed or unknown |

`platd` remains the only component that creates mappings. It writes each
new mapping into shared BPF maps after its audit record is queued, so the
fast path only ever uses mappings that are already attributed.

### Kernel building blocks

- `bpf_xdp_adjust_head`: grow or shrink the packet by 20 bytes (IPv4↔IPv6 header).
- `bpf_csum_diff` and friends: RFC 1624 incremental checksum updates.
- `bpf_fib_lookup`: routing and neighbour lookup (next hop, MAC). `platd`
  does not need its own ARP/ND, unlike AF_XDP.
- `bpf_redirect` / `XDP_TX`: transmit.
- BPF maps (fixed-size hash/LRU, per-CPU variants): BIB, sessions, slice
  ownership.
- `bpf_spin_lock` / `bpf_timer`: per-entry state updates and expiry.
- `BPF_PROG_TEST_RUN`: run the program on crafted packets in tests.
- Toolchain: [Aya](https://aya-rs.dev) compiles Rust to eBPF, so the fast
  path, loader and map handling can stay in Rust.

### Expected benefit

The highest ceiling of the software COAs: XDP forwarding typically reaches
several to tens of Mpps per core, against about 0.5 Mpps per worker today.
Established-session traffic, which is almost all traffic, never leaves the
driver.

### Fit with project rules

| Rule / control | Effect |
|---|---|
| Bounded everything (SC-5) | Good fit: map sizes are fixed at creation. |
| Attribution first (AU-12, AU-5) | Preserved: only `platd` creates mappings, after the audit record is queued. |
| Pure-Rust data plane | Preserved via Aya; no C in the fast path. |
| Packets are hostile; parse only through `plat-packet` | Must be restated: the fast path parses in eBPF, outside `plat-packet`. The verifier proves memory safety, not RFC correctness. |
| `unsafe` only in `plat-io` | Must be restated for eBPF code and the map-sharing layer. |
| Lock order, one shard lock per table | Now also applies to kernel code (`bpf_spin_lock` on session entries). |
| AC-6 / SC-39 (no capabilities) | Breaks for loading: `CAP_BPF` + `CAP_NET_ADMIN` are needed. Mitigation: a small privileged loader that loads and pins the program, leaving `platd` with reduced rights. Needs NIST review. |
| SC-7 boundary protection | XDP runs before netfilter: the `nftables` forward policy and `plat-fwguard` no longer cover fast-path traffic. Enforcement rests entirely on the program and `platd`. |
| SC-24 / HA fencing | The fast path must enforce slice ownership itself, so a fenced slice stops forwarding at once. |

### Hard parts

1. **Two translators.** The fast path re-implements header translation,
   RFC 6052 mapping and checksums. It must stay byte-for-byte identical to
   `plat-xlat`. Needs differential testing (same packets through both,
   outputs compared) and doubles the RFC conformance surface.
2. **Verifier limits.** Bounded loops, 512-byte stack, no heap, limited
   program size. Extension-header walking and ICMP-error translation stay
   in the slow path for this reason.
3. **Concurrent state.** TCP FSM and timer refresh update shared session
   entries from many CPUs.
4. **Expiry.** Today's incremental sweeper does not carry over; it must
   walk BPF maps from userspace or use `bpf_timer`.
5. **Fragments.** XDP cannot reassemble; all fragments go to the slow path,
   which still needs a packet channel (TUN or AF_XDP) alongside.
6. **Platform dependence.** Native XDP needs driver support (generic XDP
   is slow); helpers and verifier limits vary by kernel version, so a
   minimum kernel must be set and tested.
7. **Compliance evidence.** Assessors will ask how in-kernel parsing is
   verified and how the two paths are kept equivalent.

### Phasing

1. **Phase 0:** Linux baseline benchmark on bare metal with a real NIC and
   an external traffic generator.
2. **Phase 1:** fast path for established **UDP** only; everything else to
   `platd`. Differential test harness (fast path vs `plat-xlat`) from day
   one. Privileged loader design and NIST review of AC-6 / SC-7.
3. **Phase 2:** established **TCP** (FSM updates under `bpf_spin_lock`),
   slice-ownership enforcement, map-based expiry.
4. **Phase 3:** ICMP echo; decide whether ICMP errors ever move to the fast
   path (probably not).

### Effort and risk

Largest of the software COAs: effectively a second data plane. Ongoing
cost is the equivalence of two translators, inside an environment that is
hard to verify, for a project whose selling point is assurance.

### Recommendation

Pursue only if AF_XDP (single translator, ~4–8× estimated) cannot meet a
concrete throughput target. If pursued, start with Phase 1 and gate each
phase on differential-test equivalence.

### Comparison with other software COAs

| | io_uring on TUN | AF_XDP | XDP hybrid |
|---|---|---|---|
| Expected gain | ~1.3–1.6× | ~4–8× | Highest |
| Translator implementations | 1 | 1 | 2 |
| ARP/ND in `platd` | No | Yes | No (kernel lookup) |
| Privileged loader | No | Yes | Yes |
| `nftables` in path | Yes | No | No |
| Effort | One workflow run | Several PRs | A second data plane |

## COA 2: FPGA SmartNIC offload (exploratory)

### Concept

The same fast/slow split as COA 1, with the fast path in NIC hardware
instead of eBPF:

| Path | Runs in | Handles |
|---|---|---|
| Fast path | FPGA on the NIC (P4 compiled to FPGA, or HLS/HDL) | Established-session lookup in on-card tables, header rewrite, checksums, timer refresh, at line rate |
| Slow path | `platd` on the host | Everything COA 1 sends to the slow path, plus pushing new mappings into the card's tables over PCIe after their audit record is queued |

Candidate hardware classes (vendor and model availability to be confirmed
before any decision):

- **FPGA SmartNICs** with a P4 flow (for example AMD's Vitis Networking P4
  on Alveo cards) or a vendor shell for HLS/HDL.
- **DPUs** (ARM cores plus fixed-function flow offload, not FPGA): an
  alternative in the same class, where `platd` might run on the card's ARM
  cores and program the hardware flow tables.
- **P4 switch ASICs**: the best-known line (Intel Tofino) is no longer
  developed, so not a basis for new work.

### Expected benefit

Line rate per card (100–400 Gb/s class NICs), with the host CPU handling
only new flows and exceptions. This is the only COA that could move
established traffic at full NIC speed independent of core count.

### What is hard

1. **Stateful tables in hardware.** P4's model is largely stateless; the
   project's 4 M sessions need on-card HBM or DDR and custom table
   logic. Research exists on stateful P4 on FPGA SmartNICs with HBM (see
   sources), but no off-the-shelf stateful NAT64 design was found.
2. **Three implementations.** Rust slow path, the FPGA fast path, and its
   simulation model must agree; HDL/P4 verification (simulation, ideally
   formal) replaces Rust's type system as the assurance basis.
3. **New-flow rate.** Every new mapping crosses PCIe to the card; CGN-scale
   connection rates and TCP FSM updates in hardware must be sized.
4. **Expiry, HA and fencing in hardware.** Timers, slice ownership and
   immediate fencing must be enforced by the card.
5. **Toolchains and skills.** Vendor FPGA toolchains are closed and
   specialised; long build cycles; a different engineering skill set from
   this Rust project.
6. **Hardware assurance.** Supply-chain controls (SR-3, SR-11 component
   authenticity), bitstream and NIC-firmware integrity (SI-7: signed
   bitstreams, secure boot of the card), and a new firmware attack surface.
   No crypto moves to the card, so FIPS scope is unchanged.
7. **SC-7 and AC-6.** As in COA 1, traffic bypasses the kernel's
   `nftables` policy; programming the card needs privileged drivers.
8. **Cost and lock-in.** Specialised cards per node, tied to one vendor's
   shell and tools; testing needs the physical cards.

### Comparison with scaling out

usg-plat already scales horizontally (`plat-cluster` slices, HA). Adding
commodity nodes running COA 1 or AF_XDP is likely cheaper than FPGA
offload until a single node must exceed what its CPU cores can do, roughly
the 100 Gb/s-per-box class.

### Recommendation

Do not pursue now. Revisit only with a concrete requirement for per-node
throughput beyond CPU-based options (AF_XDP or COA 1 across all cores),
after the Linux baseline, and with a hardware-assurance plan for the card.

### Sources

- [Enabling Flexible and High-Performance Networking with FPGA-Based SmartNICs (Northeastern dissertation)](https://repository.library.northeastern.edu/files/neu:ms40c4213/fulltext.pdf): stateful P4 processing on FPGA SmartNICs with HBM.
- [Reconfigurable SmartNICs: A Comprehensive Review of FPGA Shells and Heterogeneous Offloading Architectures (2026)](https://www.mdpi.com/2076-3417/16/3/1476): P4 model and resource limits, toolchain cost.
- [Gryphon: DPU-augmented hierarchical co-offloading for multi-tenant gateways](https://arxiv.org/pdf/2510.11043)
- [Accelerating Stateful Network Applications with Performance Prediction on SoC SmartNICs](https://arxiv.org/pdf/2410.22229)
