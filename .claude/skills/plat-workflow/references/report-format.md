# Report Formats

## Findings file (`findings-<role>.md`)

```markdown
# Findings — <role>

Scope: <base>...<head> (<n> files), plan: <run>/plan.md
Verdict: APPROVE | APPROVE WITH COMMENTS | CHANGES REQUESTED

## <ROLE-PREFIX>-001 [BLOCKER] <one-line title>

- **Location**: `crates/plat-x/src/file.rs:123`
- **Reference**: NIST 800-53 SC-5 | RFC 7915 §4.2 | CWE-...
- **Problem**: what is wrong, in one or two sentences.
- **Failure scenario**: concrete packet/state → concrete bad outcome.
- **Fix**: the smallest change that resolves it.
- **Confidence**: high | medium | low
```

Role prefixes: `SEC` (security), `NIST` (800-53), `RFC` (protocol),
`PERF` (performance), `QA` (testing), `REL` (release).

### Severity

| Severity | Meaning | Gate effect |
|----------|---------|-------------|
| BLOCKER | Remote crash/panic from a packet, memory unsafety, filtering bypass, mapping that leaks/misroutes traffic, audit bypass or lost attribution, broken RFC MUST | Must fix |
| MAJOR | Missing required control/test, DoS amplification or unbounded state, RFC SHOULD violated without reason, fail-open path, >10% hot-path regression, blocking call on data plane | Must fix |
| MINOR | Hardening, missing annotation, weak test, unclear error type, small perf win | Advisory |
| NIT | Style, naming, comments | Advisory |

A finding without a location and a failure scenario is MINOR at most.

## Fix response (`fixes-round-<n>.md`)

```markdown
| Finding | Action | Change |
|---------|--------|--------|
| SEC-001 | Fixed | `parse.rs:120-131` check IHL ≥ 5 before slicing options |
| RFC-002 | Rebutted | RFC 7915 §4.1 permits dropping IPv4 options |
```

## Gate summary (`gate.md`)

```markdown
# Gate — <task>

Verdict: PASS | PASS WITH POA&M | FAIL

| Gate | Result | Evidence |
|------|--------|----------|
| fmt | PASS | `cargo fmt --all --check` |
| clippy | PASS | `make clippy` |
| linux check | PASS | `make check-linux` |
| tests | PASS (212) | `make test` |
| benches | PASS (xlat/v6_to_v4 −2%) | `make bench` |
| security review | APPROVE | findings-security.md |
| NIST 800-53 review | APPROVE WITH COMMENTS | findings-nist.md (2 MINOR) |
| RFC review | APPROVE | findings-rfc.md |
| performance review | APPROVE | findings-perf.md |
| compliance docs | UPDATED | docs-update.md |
| release | CHANGELOG + minor bump | release-notes.md |

## Open items
## POA&M
## Dropped findings
```
