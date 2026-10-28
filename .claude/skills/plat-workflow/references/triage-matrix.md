# Triage Matrix — which roles run

When in doubt, include the reviewer: a skipped reviewer is a silent gap in ATO
evidence, an extra one costs only tokens.

## Always-on for any code change

- `qa-engineer`
- `security-reviewer`
- `nist-800-53-reviewer`
- `compliance-scribe`

## Path-triggered roles

| Touched path / topic | Add |
|----------------------|-----|
| `crates/plat-packet/**` (header parse/build, checksums) | `rfc-conformance-reviewer`, `performance-reviewer` |
| `crates/plat-xlat/**` (RFC 6052 mapping, RFC 7915 SIIT, ICMP translation) | `rfc-conformance-reviewer`, `performance-reviewer` |
| `crates/plat-nat64/**` (BIB/session tables, port blocks, timers, filtering, TCP state) | `rfc-conformance-reviewer`, `performance-reviewer` |
| `crates/plat-audit/**` (SIEM logging, hash chain, syslog) | `performance-reviewer` (back-pressure), flag AU-4/AU-5/AU-9 focus |
| `crates/plat-io/**` (TUN, multiqueue, `unsafe`/libc) | `performance-reviewer`, flag `unsafe` + privilege focus |
| `crates/plat-cluster/**` (pool partitioning, membership) | `performance-reviewer`, `rfc-conformance-reviewer` (RFC 7422/6888 port allocation) |
| `services/platd/**` worker loop, threading, affinity | `performance-reviewer` |
| `services/platd/**` management/metrics endpoint | (always-on set; flag AC-3/IA-3/SC-8 focus) |
| `crates/plat-common/src/config.rs` | `release-engineer` (config schema), flag CM-6/CM-7 |
| `Cargo.toml`, `Cargo.lock`, `deny.toml` | `release-engineer` |
| `Dockerfile`, `deploy/**` (systemd, Helm, sysctl) | `release-engineer` |
| CI files, `Makefile` | `release-engineer` |
| `fuzz/**`, `tests/**`, `benches/**` only | `qa-engineer` only (+ `performance-reviewer` for benches) |

## Phase skips

| Situation | Skip |
|-----------|------|
| Docs / comments only | Phases 1–4; run scribe + `markdownlint` only |
| Bug fix with an obvious one-file cause | Phase 1 may be a short inline plan by the orchestrator |
| Internal refactor, no behaviour/API change | Phase 6 (but still run benches if hot path touched) |
| `review` mode | Phases 1–2 |

Record every skipped role or phase, with the reason, in `brief.md`.
