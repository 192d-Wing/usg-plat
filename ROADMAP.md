# Roadmap

Status as of 2026-11-10. The latest release is
[v0.4.2](https://github.com/192d-Wing/usg-plat/releases/tag/v0.4.2)
(signed, see `CHANGELOG.md`). Gaps are tracked as POA&M items in
[`docs/compliance/POAM.md`](docs/compliance/POAM.md); this file groups them
into work and does not replace that register.

## Where things stand

| Area | State |
|------|-------|
| Stateful NAT64 / 464XLAT PLAT (RFC 6146, 7915, 6052) | Implemented: TUN data path, run-to-completion workers, fragments and reassembly (POAM-001), ICMP error generation (POAM-002), TCP simultaneous open (POAM-008), port blocks with cool-down and per-subscriber / per-aggregate limits |
| Attribution logging (AU-*) | Implemented: schema 8, JSON/CEF, syslog UDP/TCP/TLS 1.3, SHA-256 chained files with `verify-log`; chain is unkeyed (POAM-003) |
| FIPS / TLS (SC-8, SC-13, IA-*) | Implemented: aws-lc-rs FIPS, TLS 1.3 only, mTLS management, OCSP/CRL revocation; CMVP certificate for AWS-LC-FIPS 4.x pending (POAM-026) |
| Cluster scale-out and HA (CP-10) | Partial (POAM-007): slices, replication, leases, witness, takeover; three-VM runs with an FRR BGP/BFD edge (LINUX_VERIFICATION L19–L23) PASS (round 6, 2026-10-29): `kill -9` takeover 3.8 s and VM loss 3.4 s with 200/200 TCP flows, leader crash max 4.5 s over 27 trials (≤ 5 s target; old election; the new election's simulated bound excludes adoption time and has no VM trials yet); sessions not replicated (POAM-028) |
| Host hardening (AC-6, SC-7, SC-39) | Implemented: capability-free `platd`, nftables forward policy with `plat-fwguard`; verified on one Ubuntu 24.04 VM |
| XDP fast path (POAM-016) | Phase 1 code-complete (PRs #23–#28): established UDP in eBPF, `platd` as slow path, loader and systemd units, schema 8 records, `[xdp]` off by default, kernel ≥ 6.6. CI checks are required on `main` on x86_64 and aarch64 (#29). Speed-up not measured |
| Releases and install-time verification (SI-7, SR-4, SR-11, CM-14) | Implemented, Partial (POAM-044): `v*` tags signed with cosign keyless and build provenance (v0.2.1 onwards, `scripts/verify-release.sh`); apt/dnf repository at https://192d-wing.github.io/usg-plat-packages/ and an offline tarball per tag; install-time gate `usg-plat-verify` (v0.4.0 onwards; apt hook + dnf4 plugin, `platd` depends on it). Packages install on EL9, Debian 12 and Ubuntu 22.04/24.04 (glibc floor 2.34). Live installs through the gate: L35 (v0.4.0, fixed in v0.4.1), L36 (v0.4.1) PASS; L37 offline mirror PARTIAL (apt fixed in v0.4.2, live re-run open). arm64 containers only |
| Developer workflow | `/plat-workflow` multi-agent team for Claude Code and Codex (#30); CI: fmt/clippy (host + aarch64), Linux tests, cargo-audit/deny, XDP build/VM/proptest, SonarQube, CodeQL, docs site |

See also [`COAs.md`](COAs.md) (data-plane throughput options; XDP hybrid
selected) and [`docs/jool-comparison.md`](docs/jool-comparison.md).

## Next

Ordered by value for the effort, with what each needs.

1. **Close out L37 (no new hardware).** Re-run the live apt offline-mirror
   install (`file:` mirror, `--network none`) against v0.4.2, which carries
   the apt-hook fix (E23). Then x86_64 runs of L34–L37 and an install on a
   systemd host rather than a container.
2. **XDP Phase 0: bare-metal measurement (needs hardware).** x86 host with
   a real NIC (zero-copy XDP driver) and an external traffic generator.
   Measures the actual speed-up over TUN, the `bib4` maximum hold ≤ 20 µs
   criterion, and L27 on a real NIC. This is the evidence POAM-016 exists
   for.
3. **HA verification (POAM-007).** L19–L23 PASS on three VMs with FRR
   (2026-10-29, round 6). Leader-crash election changes C1–C7 have a simulated
   bound (`leader_crash_bound_holds_across_topologies`, adoption time
   excluded). Left: chunked slice adoption (POAM-047, separate PR first),
   VM trials of the new election on a three-data-member bed (WU-A5), and
   session pickup (POAM-028).

Done since the last update:

- **XDP verification the VM can do** (2026-11-03): L29, L30 and L32 PASS;
  the TUN-only capture comparison and `frag_needed_revalidate` e2e cases
  pass. The intermittent `frag_needed_revalidate` failure was a tcpdump
  capture race in the test, fixed with `--immediate-mode` and a wait for
  the Packet Too Big (20 of 20 runs pass, native and generic).
- **Signed releases** v0.2.1 (2026-11-03) through v0.4.2 (2026-11-10),
  verified end to end with `scripts/verify-release.sh`.
- **Install-time enforcement (POAM-044 (c))** in v0.4.0 (2026-11-07):
  `usg-plat-verify`, the apt/dnf repository and the offline tarball; fixes
  from the live installs in v0.4.1 (curl/ca-certificates dependency) and
  v0.4.2 (`file:` mirror in the apt hook).

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
- Level-4 e2e (`deploy/tests/xdp/e2e.sh`) runs by hand only, not in CI;
  `capture_compare` does not run under `E2E_UNITS=1`.

### Release and install-time verification (POAM-044 residuals)

- (c) partial: `dpkg -i` / `rpm -U` and dnf5 bypass the gate.
- (f): after a Sigstore key rotation, a stale pinned `trusted_root.json`
  makes hosts refuse new releases (fail closed); needs a trust-root update
  path.
- (g), accepted: a refusal aborts the whole apt/dnf transaction, holding
  back distro security updates in that run (unattended-upgrades,
  dnf-automatic).
- (h): downgrade refusal is in-transaction only (POAM044-SEC-006).
- Repository metadata is unsigned by design; the gate verifies package
  digests against the signed `SHA256SUMS` instead.

### Performance

- POAM-015: per-packet shard locks (accepted pending the I/O backend work).
- POAM-035: fragment state is per worker; re-check with any new I/O backend
  or queue steering.

### Cluster and HA

- **RustyBGP as an alternative routing daemon (optional).**
  [RustyBGP](https://github.com/osrg/rustybgp) (Rust, GoBGP gRPC API and
  config format) supports single-hop BFD (RFC 5880/5881, since 2026-06,
  release v0.2.0) and installs routes in the kernel without Zebra, so it
  could replace FRR on the edge and on the translator nodes for an
  all-Rust stack. Work: a second hook set beside
  `deploy/hooks/frr-{announce,withdraw}.sh` and `plat-v6-announce.sh` (which
  drive FRR through `vtysh`), probably on the `gobgp` CLI, with its own
  `platd.service` sandbox paths and `make test-deploy` coverage; Lima
  profiles for it; a re-run of L19 (takeover timing with RustyBGP's BFD
  300 ms × 3) before it is offered. FRR stays the default; RustyBGP's BFD is
  young (one release), which matters for ATO evidence.

- POAM-017: leader-side batching of slice moves; handover bursts on
  membership change; legacy `contiguous` mode.
- POAM-047: chunked slice adoption (about 64k BIBs per chunk, heartbeats
  between, slice Pending until done); before session hints.
- POAM-007 (2): VM trials of the new election (WU-A5).
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
- POAM-043 (a): keyed chain v3 with an explicit algorithm field (with
  POAM-003).

### TLS, PKI and FIPS

- POAM-025: (a) bounded name resolution closed (deadline-bounded `plat-dns`
  helper, 8-thread cap); (b) non-Unix key checks and (c) responder status /
  delta and indirect CRLs remain.
- POAM-026: CMVP validation of AWS-LC-FIPS 4.x pending; re-pin to a
  validated module when a certificate covers it.
- POAM-042: CNSA 2.0 applicability decision (AO / system owner). If it
  applies: a `tls` profile option (AES-256 only, SHA-384, ML-KEM-1024 or a
  P-384 + ML-KEM-1024 hybrid once FIPS-approved, ML-DSA-87 per POAM-041) and
  a matching CBOM variant, on the AO's transition dates. POAM-043 (b)–(e)
  follow this decision.
- POAM-041: ML-DSA (and Ed25519 / P-521) certificates are refused today; add
  them only with `sig.rs` OCSP/CRL rows, confirmed FIPS approval and an
  operator PKI.
- POAM-045: OCSP/CRL host names resolve through hickory and bypass
  nsswitch, with no fallback: names known only to NSS modules (`sss`,
  `mdns4_minimal`, `myhostname`, LDAP/NIS) do not resolve.
- POAM-046: addresses resolved for responder/CDP names are not filtered
  (loopback, link-local, RFC 1918 and metadata addresses are reachable).

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
