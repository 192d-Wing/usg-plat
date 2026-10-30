# usg-plat quality gates (see .claude/skills/plat-workflow/references/quality-gates.md)
LINUX_TARGET ?= aarch64-unknown-linux-gnu
ZENSICAL ?= uvx zensical@0.0.73

.PHONY: all check fmt clippy check-linux check-notls test test-deploy bench ir security compliance-annotations release dist deb rpm packages docs docs-serve

all: check test

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# TLS (aws-lc-fips-sys) needs a C cross compiler for $(LINUX_TARGET). Without one
# (e.g. local macOS) fall back to the TLS-off feature set and warn; CI installs it.
# The fallback lints lib/bin targets only: the TLS test dev-dependencies
# (plat-tls, rcgen) build aws-lc too, and cargo has no optional dev-deps.
NOTLS_PKGS := -p plat-audit -p platd
LINUX_CC := $(or $(CC_aarch64_unknown_linux_gnu),$(shell command -v aarch64-linux-gnu-gcc 2>/dev/null))

check-linux:
ifneq ($(LINUX_CC),)
	cargo clippy --workspace --all-targets --target $(LINUX_TARGET) -- -D warnings
else
	@echo "WARNING: no aarch64-linux-gnu-gcc / CC_aarch64_unknown_linux_gnu; check-linux runs WITHOUT TLS (lib/bin targets only)" >&2
	cargo clippy $(NOTLS_PKGS) --no-default-features --target $(LINUX_TARGET) -- -D warnings
endif

check-notls:
	cargo clippy $(NOTLS_PKGS) --no-default-features --all-targets -- -D warnings

check: fmt clippy check-linux check-notls

test:
	cargo test --workspace

# Deploy scripts: POSIX syntax, shellcheck (required when CI=true) and a stubbed run
# against the real `platd check-config --format env` output.
DEPLOY_SH := deploy/systemd/plat-tun-setup.sh deploy/systemd/plat-fwguard.sh deploy/tests/deploy-scripts-test.sh \
	deploy/hooks/frr-announce.sh deploy/hooks/frr-withdraw.sh deploy/systemd/plat-v6-announce.sh $(wildcard deploy/tests/cluster/*.sh)
test-deploy:
	for f in $(DEPLOY_SH); do sh -n $$f || exit 1; done
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck -x $(DEPLOY_SH); \
	elif [ "$$CI" = true ]; then echo "ERROR: shellcheck is required in CI" >&2; exit 1; \
	else echo "WARNING: shellcheck not installed; skipped" >&2; fi
	sh deploy/tests/deploy-scripts-test.sh

bench:
	cargo bench -p plat-xlat -p plat-nat64 -p plat-audit --bench xlat --bench nat64 --bench audit

# Hot-path instructions per packet (cachegrind, Linux): the difference of a
# 200k and a 100k packet run, so setup cost cancels (PERF-002).
ir:
	cargo build --release -p plat-nat64 --example ir
	@for d in v6 v4; do \
	  a=$$(valgrind --tool=cachegrind --cache-sim=no --cachegrind-out-file=/dev/null target/release/examples/ir 100000 $$d 2>&1 | awk '/I *refs/ {gsub(",","",$$4); print $$4}'); \
	  b=$$(valgrind --tool=cachegrind --cache-sim=no --cachegrind-out-file=/dev/null target/release/examples/ir 200000 $$d 2>&1 | awk '/I *refs/ {gsub(",","",$$4); print $$4}'); \
	  echo "$$d: $$(( (b - a) / 100000 )) instructions/packet"; \
	done

security:
	cargo audit
	cargo deny check

compliance-annotations:
	@grep -rEc "COMPLIANCE MAPPING|NIST 800-53:|RFC [0-9]+" crates services --include=*.rs | awk -F: '{s+=$$2} END {print "compliance annotations:", s}'
	@grep -rn "POAM:" crates services --include=*.rs || true

release:
	cargo build --release -p platd

# Linux packages for the host architecture. Native build only: the AWS-LC
# FIPS module is built with the host toolchain, never cross-linked (SC-13).
# CI builds x86_64 and aarch64 on native runners (.github/workflows/packages.yml).
dist:
	cargo build --profile dist -p platd

deb: dist
	cargo deb -p platd --no-build --no-strip --profile dist

rpm: dist
	cargo generate-rpm -p services/platd --profile dist

packages: deb rpm

docs:
	$(ZENSICAL) build --clean

docs-serve:
	$(ZENSICAL) serve
