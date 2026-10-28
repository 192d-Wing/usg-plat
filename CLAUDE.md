# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project Overview

usg-plat is a pure-Rust **464XLAT PLAT** (RFC 6877): a multithreaded,
stateful NAT64 translator (RFC 6146) built on SIIT header translation
(RFC 7915) and RFC 6052 address mapping, designed for NIST SP 800-53 Rev 5
ATO readiness and horizontal scale-out in a cluster. It runs on Linux using
multiqueue TUN, with one run-to-completion worker per CPU.

See `ARCHITECTURE.md` for the data path, concurrency model and cluster design.

## Multi-Agent Workflow

For features, bug fixes, and reviews that need the full team, use the
`/plat-workflow` skill (`.claude/skills/plat-workflow/SKILL.md`). The main
conversation acts as orchestrator and delegates to the subagents in
`.claude/agents/`: `plat-architect`, `plat-coder`, `qa-engineer`,
`security-reviewer`, `nist-800-53-reviewer`, `rfc-conformance-reviewer`,
`performance-reviewer`, `compliance-scribe`, `release-engineer`.

- `/plat-workflow <task>`: plan → build → test → parallel review → fix loop → docs → release gate
- `/plat-workflow review [base-ref]`: review the current diff only
- `/plat-workflow plan <task>`: plan only

<!-- --8<-- [start:dev] -->
## Workspace

| Crate | Role |
|-------|------|
| `crates/plat-common` | Config (TOML, validated), CIDR types, coarse clock, per-worker counters |
| `crates/plat-packet` | Bounds-checked IPv4/IPv6/L4 parsing, RFC 1071/1624 checksums |
| `crates/plat-xlat` | RFC 6052 mapping, RFC 7915 in-place header translation, ICMP error translation |
| `crates/plat-nat64` | Sharded BIB/session/subscriber tables, port blocks, TCP FSM, sweeper, engine |
| `crates/plat-audit` | Non-blocking SIEM logging: JSON/CEF, RFC 5424 syslog, SHA-256 chained file |
| `crates/plat-io` | `PacketQueue` trait, Linux multiqueue TUN, in-memory queue |
| `crates/plat-cluster` | Deterministic pool partitioning, CIDR cover, rendezvous hashing |
| `services/platd` | Daemon: workers, sweeper, clock, metrics, `check-config`, `verify-log` |

## Development Commands

```bash
make check        # fmt --check + clippy (host) + clippy (Linux target)
make test         # cargo test --workspace
make bench        # criterion benches (xlat, nat64, audit)
make check-linux  # clippy for aarch64-unknown-linux-gnu (TUN backend)
make security     # cargo audit + cargo deny
cargo run -p platd -- check-config -c config/platd.example.toml
cargo run -p platd -- check-config -c config/platd.example.toml --format env
cargo run -p platd -- verify-log /var/log/plat/nat64-audit.jsonl /var/log/plat/nat64-audit.jsonl.*
```

`verify-log` exits 0 when every file verifies and the files link into one
chain, 1 on a verification failure, an unverified tail (unless
`--allow-tail`) or a gap (unless `--allow-gap`), and 2 on an I/O error.

## Non-negotiable rules

1. **Packets are hostile.** Parse only through `plat-packet`. No `unwrap`,
   `expect`, or unchecked indexing on packet bytes; malformed input becomes a
   counted `DropReason`, never a panic.
2. **Hot path budget.** No heap allocation, no blocking I/O, no global lock on
   the steady-state path. At most one shard lock per table. Audit hand-off is
   `AuditSink::emit` (non-blocking `try_send`).
3. **Bounded everything (SC-5).** Every table, queue and per-subscriber resource
   has a configured limit (including `nat64.max_subscribers`); locally
   generated ICMP errors use a per-worker token bucket
   (`translation.icmp_errors_per_sec`); hash maps use randomly keyed `ahash`.
4. **Attribution first (AU-12, AU-5).** A port block or binding is never used
   before its audit record is queued, unless `on_overflow = "drop_and_alert"`.
   A block returns to the pool only after its release record is queued.
   Records the caller retries use `AuditSink::try_emit` (not counted as lost).
5. **Lock order.** `bib6 → subs (released) → bib4`; sweeper `bib6 → bib4`, then
   `subs`. Never take `bib6` or `subs` while holding `bib4`.
6. **`unsafe` only in `plat-io`**, each block with a `// SAFETY:` comment.
7. **Annotate controls and RFC sections** with `// COMPLIANCE MAPPING:`; mark
   known gaps `// POAM:` and list them in `docs/compliance/POAM.md`.
8. **Log schema is an interface.** Any change to SIEM field names bumps
   `plat_audit::LOG_SCHEMA_VERSION` and `docs/compliance/SIEM_LOGGING.md`.

<!-- --8<-- [end:dev] -->

## NIST 800-53 Rev 5 focus for a boundary translator

| Family | Where |
|--------|-------|
| SC-5 DoS protection | limits in `Nat64Config` (incl. `max_subscribers`), `State::admit_session`, `State::bib_for`, per-worker ICMP error token bucket, keyed hashing in `shard.rs` |
| SC-7 boundary protection | client prefix allow-list, RFC 6052 §3.1 checks, non-global IPv4 denied by default (`allow_non_global_destinations`), ICMP error validation, ADF filtering, host nftables forward policy (`deploy/systemd/plat-tun-setup.sh`) |
| SC-10 network disconnect | idle timers (RFC 6146 minimums enforced in config) + `State::sweep` |
| AU-2/3/8/12 | `plat-audit` events, UTC µs timestamps, sequence numbers, node identity |
| AU-4/AU-5/AU-5(1) | bounded queue, `on_overflow` policy, degraded state on file failure or low free space (`min_free_bytes`), `/healthz`, `audit_queue_overflow` / `audit_output_failure` / `audit_storage_threshold` records |
| AU-6(3)/(4) | ECS/CEF correlation fields, RFC 5424 syslog export |
| AU-9/AU-11 | SHA-256 chain v2 across files (unkeyed, POAM-003), `platd verify-log`, 0640 file mode, `max_files` retention with `audit_retention_prune` records |
| SI-4 | per-worker counters, Prometheus `/metrics`, periodic counter records |
| SI-10 | `plat-packet` validation, property tests that parsers never panic |
| CM-6/CM-7 | `deny_unknown_fields`, validated ranges, loopback-only management |
| AC-6/SC-39 | systemd unit grants no capabilities and sandboxes the unprivileged `plat` user (not yet verified on Linux, `docs/compliance/LINUX_VERIFICATION.md`) |

## Compliance Documentation

Any code change updates the matching `docs/compliance/*.md` file in the same
change. Never claim a control is implemented without a code location and test.
