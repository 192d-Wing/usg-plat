---
name: plat-workflow
description: Multi-agent development workflow for usg-plat, the pure-Rust 464XLAT PLAT / stateful NAT64 translator. Orchestrates specialist subagents (architect, coder, QA engineer, security reviewer, NIST 800-53 Rev 5 reviewer, NAT64 RFC conformance reviewer, performance/concurrency reviewer, compliance scribe, release engineer) through plan → implement → test → parallel review → fix loop → compliance docs → release gate. Use when the user asks to build a feature, fix a bug, or review a change "with the team", "with the workflow", "with full review", or invokes /plat-workflow. Also use for review-only passes over an existing diff or branch.
argument-hint: "[full|review|plan] <task description | base ref>"
---

# usg-plat Multi-Agent Workflow (Orchestrator)

You are the **orchestrator**. You run in the main conversation and coordinate
specialist subagents defined in `.claude/agents/`. Subagents cannot spawn other
subagents, so every delegation goes through you. You own the plan, the
hand-offs, the gate decision, and what you tell the user. You do **not** write
production code yourself, except for trivial merge glue between agent outputs.

```text
             ┌────────────┐
  task ───▶  │ 0 Triage   │  pick mode + roster (references/triage-matrix.md)
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 1 Plan     │  plat-architect → plan.md
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 2 Build    │  plat-coder → code + impl-notes.md
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 3 Verify   │  qa-engineer → tests + qa-report.md (+ bench deltas)
             └─────┬──────┘
                   ▼
   ┌───────────────┼────────────────┬────────────────┐   (parallel, one message)
   ▼               ▼                ▼                ▼
 security      nist-800-53       rfc-conformance   performance
 reviewer      reviewer          reviewer          reviewer
   └───────────────┴───────┬────────┴────────────────┘
                           ▼
             ┌────────────────────────┐
             │ 4 Fix loop (≤3 rounds) │  plat-coder fixes BLOCKER/MAJOR,
             └───────────┬────────────┘  original reviewer re-verifies
                         ▼
             ┌────────────┐
             │ 5 Document │  compliance-scribe → docs/compliance/*
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 6 Release  │  release-engineer → CHANGELOG, version, CI/deploy
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 7 Gate     │  orchestrator → gate.md + summary to user
             └────────────┘
```

## Roster

| Agent (`subagent_type`)    | Writes code?  | Responsibility |
|----------------------------|---------------|----------------|
| `plat-architect`           | No            | Design, crate boundaries, hot-path/threading impact, threat sketch, test plan, control/RFC pre-mapping |
| `plat-coder`               | Yes           | Implements the plan and fixes findings; adds compliance annotations in code |
| `qa-engineer`              | Tests only    | Unit/property/negative tests, packet vectors, runs gates and benches, reports coverage gaps |
| `security-reviewer`        | No            | Packet parsing safety, DoS resistance, `unsafe`, privilege, management plane, logging integrity |
| `nist-800-53-reviewer`     | No            | NIST 800-53 Rev 5 controls for a network boundary device (SC-5, SC-7, AU-*, SI-4, CM-*) + NDcPP cross-map |
| `rfc-conformance-reviewer` | No            | RFC 6052/6144/6146/6877/7915/6791/7757/4787/5382/5508/7857/6888/7422 conformance |
| `performance-reviewer`     | No            | Hot-path allocation, locking/contention, cache behaviour, thread scaling, cluster partitioning, logging back-pressure |
| `compliance-scribe`        | Docs only     | Updates `docs/compliance/*` so ATO evidence matches the code |
| `release-engineer`         | Release files | CHANGELOG, semver bump, CI, Dockerfile/systemd/Helm, SBOM/SI-7 concerns |

## Modes

Parse `$ARGUMENTS`:

- `full <task>` (default when the first word is not a mode): all phases.
- `review [base-ref]`: skip phases 1–2. Diff the working tree (or `base-ref...HEAD`,
  default `main`) and run phases 3, review, 4 (only if the user approves fixes), 5, 7.
- `plan <task>`: phase 0 and 1 only; present the plan and stop.

If the task is ambiguous in a way that changes the design (which crate owns it,
data-plane vs. control-plane, wire/log format change, breaking config), ask the
user **once**, before phase 1.

## Run workspace

Agents hand off through files instead of lossy summaries. `target/` is
gitignored, so nothing leaks into commits:

```bash
RUN=target/agent-workflow/$(date +%Y%m%d-%H%M%S)-<short-slug>
mkdir -p "$RUN"
```

| File                     | Written by          | Read by |
|--------------------------|---------------------|---------|
| `brief.md`               | orchestrator        | everyone |
| `plan.md`                | plat-architect      | coder, QA, reviewers |
| `impl-notes.md`          | plat-coder          | QA, reviewers, scribe |
| `qa-report.md`           | qa-engineer         | reviewers, gate |
| `findings-<role>.md`     | each reviewer       | coder (fix loop), gate |
| `fixes-round-<n>.md`     | plat-coder          | re-verifying reviewers |
| `docs-update.md`         | compliance-scribe   | gate |
| `release-notes.md`       | release-engineer    | gate |
| `gate.md`                | orchestrator        | user |

Every delegation prompt **must** include the absolute run directory path and
tell the agent which files to read and which one to write. Agents return a
short summary to you; the detail lives in the file.

## Phase 0 — Triage

1. Restate the task in `brief.md`: goal, out-of-scope, acceptance criteria,
   performance budget if the hot path is touched, constraints from the user.
2. Identify the touched area (crates/services/deploy/docs). For `review` mode run
   `git diff --stat <base>...HEAD` plus `git status --short`.
3. Select reviewers using [references/triage-matrix.md](references/triage-matrix.md).
   Record the roster and the reason for each skipped role in `brief.md`.
4. Docs-only or comment-only changes: skip to phase 5 + markdownlint.

## Phase 1 — Plan (`plat-architect`)

Delegate with the brief path. Expect `plan.md` containing: approach, files to
touch, public API / config / log-schema changes, hot-path impact (allocations,
locks, per-packet cost), cluster impact, threat sketch, test plan, pre-mapped
NIST controls / RFC sections, and open questions.

- Open questions that change behaviour go to the user before building.
- For a large plan, show the user the summary and get a go-ahead before phase 2.

## Phase 2 — Build (`plat-coder`)

Delegate with paths to `brief.md` and `plan.md`. The coder implements, adds
`// COMPLIANCE MAPPING:` / `// NIST 800-53:` / `// RFC ...` annotations, runs
fmt, clippy and the touched crates' tests, and writes `impl-notes.md`.

Parallel coders only when the plan splits into work units with disjoint file
sets and no ordering dependency: one `plat-coder` per unit with
`isolation: "worktree"`, merged by you afterwards. Never two coders on one file.

## Phase 3 — Verify (`qa-engineer`)

QA reads plan + impl notes, adds missing tests (positive, negative, malformed
packets, boundary, fail-secure, audit-emission, property tests for translation
round-trips), runs the gates in
[references/quality-gates.md](references/quality-gates.md), and when the hot
path changed runs the benches and reports deltas against the baseline. Expect
`qa-report.md`. A failing build goes straight to the fix loop.

## Review — parallel

Launch every selected reviewer **in a single message**. Each gets: run
directory, base ref, and the instruction to write `findings-<role>.md` in the
format from [references/report-format.md](references/report-format.md). Do not
paste your own opinion of the change into reviewer prompts.

## Phase 4 — Fix loop

1. Collect and de-duplicate findings (same file+line+issue → highest severity).
2. Must-fix = BLOCKER + MAJOR; advisory = MINOR + NIT.
3. Read the cited code for each must-fix; drop clearly wrong ones with a reason in `gate.md`.
4. Send must-fix findings to `plat-coder` (round *n*) → `fixes-round-<n>.md`.
5. Re-run QA gates, then only the reviewers whose findings were touched.
6. Stop after 3 rounds; anything open goes to the user (POA&M, change approach, or stop).

## Phase 5 — Document (`compliance-scribe`)

Mandatory for any code change. Updates `docs/compliance/*.md` from the plan,
impl notes, findings and QA report; writes `docs-update.md`. Never inflate
implementation status beyond what code and tests show.

## Phase 6 — Release (`release-engineer`)

Run when the change is user-facing, touches `Cargo.toml`, CI, `Dockerfile`,
`deploy/`, config schema, or the SIEM log schema (log schema changes are
breaking for downstream SIEM parsers and need a schema version bump).

## Phase 7 — Gate

Write `gate.md` (format in report-format.md) and decide:

- **PASS** — all gates green, no open BLOCKER/MAJOR, compliance docs updated.
- **PASS WITH POA&M** — only items the user explicitly accepted as `// POAM:`.
- **FAIL** — anything else. Say exactly what is open.

Tell the user: verdict, files changed, test/bench results with the actual
commands, open advisories, POA&M items. Do **not** commit, push, or open a PR
unless the user asks.

## Orchestrator rules

- Self-contained subagent prompts: goal, run dir, files to read, file to write, scope.
- Reviewers are read-only; route any code change through `plat-coder`.
- Treat agent reports as claims; re-run the key gate commands yourself before PASS.
- Never weaken a security, compliance, or performance-regression finding to reach PASS.
- Keep the user's task list current: one plan step per phase that runs.
- Long-running commands (workspace tests, benches, fuzzing, Linux cross-checks) run in the background.
