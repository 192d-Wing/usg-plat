# usg-plat vs Jool

Feature comparison of usg-plat with [Jool](https://nicmx.github.io/Jool/)
4.1.15 (latest stable, 2026-01-26). The usg-plat column comes from this
repository's README, example config, `docs/compliance/RFC_COMPLIANCE.md` and
`docs/compliance/POAM.md`. Only Jool's version and MAP-T status were checked
against its download page; the other Jool rows come from its documentation
from memory and should be confirmed before relying on them.

They solve different problems. Jool is a general-purpose kernel translator:
SIIT, NAT64 and (in an unreleased version) MAP-T, with a lot of
address-mapping flexibility. usg-plat does one job, a stateful NAT64 PLAT, and
builds around it things Jool lacks: subscriber attribution logging, a
hardened audit trail, FIPS TLS and clustered high availability.

## Platform and architecture

| | usg-plat | Jool |
|---|---|---|
| Where it runs | Userspace daemon (`platd`), Rust, multiqueue TUN, one worker per CPU | Linux kernel module (netfilter hook or iptables target), C |
| Packet I/O cost | One TUN syscall per packet. About 86% of a worker's CPU is kernel time (POAM-016); about 0.5 Mpps per worker in an indicative VM test | Translates inside the kernel forwarding path: no copy to userspace, no syscalls |
| Memory safety | Safe Rust; `unsafe` only in `plat-io`; property tests check parsers never panic | C in the kernel; a parser bug can crash the host |
| Privilege | Runs with no capabilities as the unprivileged `plat` user under a systemd sandbox | Kernel code; configured as root |
| Multiple instances / network namespaces | One instance per daemon | Several instances per network namespace |
| Licence / maturity | New. Several features are on unreleased branches; Linux checks were run on one host | GPL; mature, about ten years of production use |

## Translation modes

| Feature | usg-plat | Jool |
|---|---|---|
| Stateful NAT64 (RFC 6146) | Yes | Yes |
| Stateless SIIT (RFC 7915) as its own mode | No (SIIT is used only inside NAT64) | Yes (`jool_siit`) |
| Explicit address mappings, EAMT (RFC 7757) | No | Yes |
| CLAT side of 464XLAT | No (PLAT only) | Yes (SIIT plus EAMT) |
| MAP-T (RFC 7599) | No | Only in the 4.2 release candidates (2020–21), never released as stable |
| RFC 6052 prefixes (/32 to /96) | Yes, one prefix per daemon | Yes |
| RFC 6791 source for ICMP errors | Yes (pool address of the affected flow) | Yes (`pool6791`) |
| Non-global IPv4 destinations | Denied by default for the whole RFC 6890 table, enforced under the Well-Known Prefix | Configurable deny-list (`denylist4`) |

## NAT64 behaviour

| Feature | usg-plat | Jool |
|---|---|---|
| Port allocation | Per-subscriber port blocks, paired pooling, random port inside the block, 120 s cool-down before a block is reused | Per-flow ports (RFC 6056), `pool4` with marks and port ranges |
| Static BIB entries (port forwarding) | No | Yes |
| Filtering | Address-dependent (default), endpoint-independent or address-and-port-dependent | Address-dependent toggle, option to drop externally initiated TCP |
| TCP simultaneous open | Yes: a refused SYN on a port with a BIB is held `held_syn_secs` (default 6 s), bounded by per-BIB and node caps; SYNs to unbound ports dropped by policy; expiry ICMP opt-in | Yes: holds the SYN for 6 s |
| Hairpinning | Yes, including across cluster nodes | Yes |
| Protocols | TCP, UDP, ICMP | TCP, UDP, ICMP |
| Per-subscriber limits | Sessions, blocks and `max_subscribers` | Limited (BIB size limit) |
| Fragments | Own bounded per-worker fragment table and reassembly; overlap and tiny-fragment checks | Relies on the kernel's defragmentation |
| Generated ICMP errors | Time Exceeded, Unreachable, Parameter Problem, Packet Too Big, with a per-worker rate limit | Translation-related errors; rate limiting is left to the kernel |
| MTU plateau table, lowest IPv6 MTU, ToS copy | Yes | Yes (configurable plateaus) |

## Logging, operations and security

| Feature | usg-plat | Jool |
|---|---|---|
| Subscriber attribution logs | Port-block or per-session records; the record is queued before the binding is used; new bindings are refused if logging overflows | BIB/session logging to the kernel log only |
| Log transport | JSON or CEF; syslog over UDP, TCP or TLS 1.3 (RFC 5425); hash-chained local file plus `verify-log` | dmesg/journal |
| Tamper evidence | SHA-256 chain across rotated files (unkeyed, so root can rewrite it: POAM-003) | None |
| Cryptography | AWS-LC FIPS module; refuses to start without it; TLS 1.3 only with post-quantum hybrid key exchange; OCSP/CRL revocation | None (no network management interface) |
| Management | `/metrics` (Prometheus) and `/healthz`, loopback or mutual TLS with a typed client allow-list | `jool` command over Netlink; `jool stats` counters |
| Configuration | Validated TOML, unknown fields rejected, `check-config`; no hot reload | Atomic JSON config, changeable at run time |
| Host firewall | Ships an nftables forward policy plus a guard that turns forwarding off if the policy changes | Up to the operator |
| Compliance evidence | NIST 800-53 mapping, per-requirement RFC conformance table, POA&M | None |

## Scale-out and high availability

| | usg-plat | Jool |
|---|---|---|
| Scale-out | Fixed IPv4 pool slices per node, BGP announce/withdraw hooks (FRR examples) | Run several separate instances |
| State sync | Primary and backup per slice; port blocks and BIB replicated over mutual TLS; leases, a witness node, self-fencing | `joold`: active/active session sync over Netlink and TCP, documented as best-effort |
| Gaps | Sessions are not replicated, so TCP is picked up after takeover (POAM-028); takeover takes about 6.2 s against a 5 s target; not yet tested against a real BGP/BFD peer | No fencing or split-brain protection |

## Summary

- **Choose Jool** for stateless SIIT or CLAT, EAMT, static port forwarding,
  kernel-path throughput, or a mature deployment base.
- **Choose usg-plat** for a carrier or government PLAT that needs
  subscriber-level attribution with guaranteed logging, FIPS TLS and an
  accreditation-ready evidence trail, or for active/standby clustering with
  fencing.
- **usg-plat gaps worth considering against Jool:**
  - Per-packet TUN syscall cost (POAM-016). AF_XDP or batched I/O would be
    the fix.
  - No static BIB entries.
  - No configuration reload at run time.
  - One NAT64 prefix per daemon.
