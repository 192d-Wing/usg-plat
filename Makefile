# usg-plat quality gates (see .claude/skills/plat-workflow/references/quality-gates.md)
LINUX_TARGET ?= aarch64-unknown-linux-gnu
ZENSICAL ?= uvx zensical@0.0.73

.PHONY: all check fmt clippy check-linux test bench security compliance-annotations release docs docs-serve

all: check test

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

check-linux:
	cargo clippy --workspace --all-targets --target $(LINUX_TARGET) -- -D warnings

check: fmt clippy check-linux

test:
	cargo test --workspace

bench:
	cargo bench -p plat-xlat -p plat-nat64 -p plat-audit --bench xlat --bench nat64 --bench audit

security:
	cargo audit
	cargo deny check

compliance-annotations:
	@grep -rEc "COMPLIANCE MAPPING|NIST 800-53:|RFC [0-9]+" crates services --include=*.rs | awk -F: '{s+=$$2} END {print "compliance annotations:", s}'
	@grep -rn "POAM:" crates services --include=*.rs || true

release:
	cargo build --release -p platd

docs:
	$(ZENSICAL) build --clean

docs-serve:
	$(ZENSICAL) serve
