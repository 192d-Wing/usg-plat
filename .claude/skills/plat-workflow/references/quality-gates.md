# Quality Gates

Commands come from the repo `Makefile`. Scope to touched crates (`-p <crate>`)
while iterating; run the workspace-wide form once before the final gate.

| Gate | Iterating | Final | Required |
|------|-----------|-------|----------|
| Format | `cargo fmt --all` | `cargo fmt --all --check` | Yes |
| Lint | `cargo clippy -p <crate> --all-targets -- -D warnings` | `make clippy` | Yes |
| Linux check | — | `make check-linux` (`cargo clippy --target aarch64-unknown-linux-gnu`) | Yes (TUN backend is Linux-only) |
| Unit tests | `cargo test -p <crate>` | `make test` | Yes |
| Benches | `cargo bench -p <crate> -- --save-baseline new` | `make bench` | When hot path changed (packet, xlat, nat64, audit, io, worker loop) |
| Supply chain | — | `make security` (`cargo audit` + `cargo deny check`) | When `Cargo.toml`/`Cargo.lock` changed |
| Fuzz smoke | `cargo fuzz run <target> -- -max_total_time=60` | `make fuzz-smoke` | When a packet parser changed |
| Annotations | — | `make compliance-annotations` (count should not drop) | Yes for code changes |
| Markdown | — | `npx markdownlint-cli "docs/**/*.md"` | When docs changed |

## Performance budget

Per-packet hot path (translate + table lookup, existing session), measured by
`cargo bench -p plat-nat64`:

- No heap allocation on the steady-state path (new session creation may allocate).
- No global lock; at most one shard lock per table touched.
- No blocking I/O; audit events are handed off with a non-blocking `try_send`.
- A regression > 10% on any `xlat/*` or `nat64/*` bench is a MAJOR finding unless justified.

## Rules

- Record every command with exit status and the last relevant output lines in
  `qa-report.md`. "Tests pass" without the command is not evidence.
- Missing environment (no Linux host, no root for TUN, no cargo-fuzz) → gate is
  **NOT RUN**, never PASS.
- No new `#[allow(clippy::...)]`, `#[ignore]`, or `unwrap()` on packet data
  without a justification comment and a finding entry.
