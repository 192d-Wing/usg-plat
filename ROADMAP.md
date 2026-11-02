# Roadmap

Status as of 2026-11-02 (`main` @ `4facf34`). Everything below is
unreleased: the workspace is version 0.1.0 and `CHANGELOG.md` has only an
`[Unreleased]` section. Gaps are tracked as POA&M items in
[`docs/compliance/POAM.md`](docs/compliance/POAM.md); this file groups them
into work and does not replace that register.

## Where things stand

| Area | State |
|------|-------|
| Stateful NAT64 / 464XLAT PLAT (RFC 6146, 7915, 6052) | Implemented: TUN data path, run-to-completion workers, fragments and reassembly (POAM-001), ICMP error generation (POAM-002), TCP simultaneous open (POAM-008), port blocks with cool-down and per-subscriber / per-aggregate limits |
| Attribution logging (AU-*) | Implemented: schema 8, JSON/CEF, syslog UDP/TCP/TLS 1.3, SHA-256 chained files with `verify-log`; chain is unkeyed (POAM-003) |
| FIPS / TLS (SC-8, SC-13, IA-*) | Implemented: aws-lc-rs FIPS, TLS 1.3 only, mTLS management, OCSP/CRL revocation; CMVP certificate for AWS-LC-FIPS 4.x pending (POAM-026) |
| Cluster scale-out and HA (CP-10) | Partial (POAM-007): slices, replication, leases, witness, takeover tested in-process; the three-VM BGP/BFD runs (LINUX_VERIFICATION L19–L23) not done; leader-crash takeover ~6.2 s vs a 5 s target |
| Host hardening (AC-6, SC-7, SC-39) | Implemented: capability-free `platd`, nftables forward policy with `plat-fwguard`; verified on one Ubuntu 24.04 VM |
| XDP fast path (POAM-016) | Phase 1 code-complete (PRs #23–#28): established UDP in eBPF, `platd` as slow path, loader and systemd units, schema 8 records, `[xdp]` off by default, kernel ≥ 6.6. CI checks are required on `main` on x86_64 and aarch64 (#29). Speed-up not measured |
| Developer workflow | `/plat-workflow` multi-agent team for Claude Code and Codex (#30); CI: fmt/clippy (host + aarch64), Linux tests, cargo-audit/deny, XDP build/VM/proptest, SonarQube, CodeQL, docs site |

See also [`COAs.md`](COAs.md) (data-plane throughput options; XDP hybrid
selected) and [`docs/jool-comparison.md`](docs/jool-comparison.md).

## Next

Ordered by value for the effort, with what each needs.

1. **XDP verification the VM can do (no new hardware).** Run
   LINUX_VERIFICATION L29 (`kill -STOP` dead-man deadline), L30 (HA fence
   and takeover, on the two existing Lima nodes) and L32 (map-full
   fallback); write the two missing e2e cases (TUN-only capture comparison,
   `frag_needed_revalidate`). Turns SC-24 for the fast path from
   in-process to Linux-verified.
2. **XDP Phase 0: bare-metal measurement (needs hardware).** x86 host with
   a real NIC (zero-copy XDP driver) and an external traffic generator.
   Measures the actual speed-up over TUN, the `bib4` maximum hold ≤ 20 µs
   criterion, and L27 on a real NIC. This is the evidence POAM-016 exists
   for.
3. **First release.** Decide the version, cut `CHANGELOG.md`, tag, and
   publish signed packages (packages are unsigned today, SI-7).
4. **HA verification (POAM-007).** Three-VM runs with a real BGP/BFD peer
   (L19–L23) and the takeover-time target.

## Backlog

### XDP fast path (POAM-016 and residuals)

- **Phase 2: TCP on the fast path.** Needs the slow-to-fast reordering
  window bounded (RFC-003), the TCP state machine in eBPF under per-session
  locks, and instruction headroom: the 6.6 verifier processes 10 167 of the
  12 000 budget under least privilege today. Plan only after Phase 0
  confirms the speed-up.
- **Phase 3: ICMP echo** on the fast path.
- POAM-037: host filters (nftables beyond `inet plat`, `rp_filter`, tc)
  do not see fast-path packets; fwguard cannot detach a foreign program held
  by its own `bpf_link`.
- POAM-038: fast and slow paths draw IPv4 IDs from independent tables.
- POAM-039: drops after `XDP_REDIRECT` are invisible to `platd`.
- Smaller items: preallocated pool for the per-BIB slot arrays (rule 2);
  sharded publisher threads above ~1 M flow lifecycles/s per node; the three
  test-string constants SonarQube flags in `deploy-scripts-test.sh`.

### Performance

- POAM-015: per-packet shard locks (accepted pending the I/O backend work).
- POAM-035: fragment state is per worker; re-check with any new I/O backend
  or queue steering.

### Cluster and HA

- POAM-017: leader-side batching of slice moves; handover bursts on
  membership change; legacy `contiguous` mode.
- POAM-028: sessions are not replicated (TCP pickup window after takeover).
- POAM-029 to POAM-033: subscriber-home directory, leader-coordinated
  graceful shutdown, one-sided peer-address pinning, single trust domain,
  operator socket serves one client at a time.
- POAM-009: port blocks live at a crash get no release record.

### Audit integrity

- POAM-003: keyed (HMAC or signed) audit chain; needs a key-management
  decision.
- POAM-027: `verify-log` cannot tell a power cut from deliberate truncation
  of the newest file (tied to POAM-003).

### TLS, PKI and FIPS

- POAM-025: OCSP/CRL fetcher resolves names without a timeout (use IP
  literals or a local resolver meanwhile), plus two bounded residuals.
- POAM-026: CMVP validation of AWS-LC-FIPS 4.x pending; re-pin to a
  validated module when a certificate covers it.

### Boundary and protocol

- POAM-014: source authenticity depends on the access network.
- POAM-019: residuals of the nftables guard (direct `nft` changes between
  guard runs).
- POAM-022: WKP non-global ICMP errors (risk acceptance, only if enabled).
- POAM-024: spoofed pool sources (narrowed).
- POAM-034: fragment-table entries carry no BIB generation.
- POAM-036: RFC 6888 REQ-8, configurable count of ports held after
  deallocation.
- RFC 4787 REQ-3a/REQ-4 (port range and parity preservation) are
  documented deviations (RFC-015), not planned.

## How this file is kept

Update it when a milestone lands or a POA&M item opens or closes; the POA&M
register stays the source of truth for status and evidence.
