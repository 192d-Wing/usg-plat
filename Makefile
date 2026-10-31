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

# XDP fast path (POAM-016 Phase 1, plan §15). Not part of check/test: those need
# no bpf-linker and no Linux VM. The crates arrive in later work units, so each
# target runs only what is in the tree and says what it skipped.
# RUSTC_BOOTSTRAP=1 is set on the one bpfel-unknown-none command it is needed for
# (-Z build-std=core on stable 1.99.1), never exported or set for the workspace.
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-15 (Development Tools), CM-2 (Baseline Configuration), SA-11
#   (Developer Testing)
XDP_CORE := $(wildcard crates/plat-xdp-core/Cargo.toml)
XDP_EBPF := $(wildcard crates/plat-xdp-ebpf/Cargo.toml)
XDP_USER := $(wildcard crates/plat-xdp/Cargo.toml)
XDP_LOADER := $(wildcard services/plat-xdp-loader/Cargo.toml)
XDP_BPF_PKGS := $(if $(XDP_CORE),-p plat-xdp-core) $(if $(XDP_EBPF),-p plat-xdp-ebpf)
XDP_SH := $(wildcard deploy/tests/xdp/*.sh)
XDP_PY := $(wildcard deploy/tests/xdp/*.py)
BPF_TARGET := bpfel-unknown-none
BPF_STD := --target $(BPF_TARGET) -Z build-std=core
# Kernel matrix for test-xdp (deploy/tests/xdp/kernels.conf); XDP_VNG_FLAGS=-m on
# CI runners installs the kernel modules into /lib/modules.
XDP_KERNELS ?= 6.1 6.6 6.12 latest
XDP_VNG_FLAGS ?=

.PHONY: xdp check-xdp test-xdp bench-xdp xdp-env

xdp-env:
ifneq ($(origin RUSTC_BOOTSTRAP),undefined)
	$(error RUSTC_BOOTSTRAP is set ($(origin RUSTC_BOOTSTRAP)); the workspace build must stay plain stable (plan §15))
endif
	@true

# Build: plat-xdp-core for bpfel (a library: proves it is no_std/BPF-clean, no
# linker needed); plat-xdp with the xdp feature, whose build script builds and
# links the plat-xdp-ebpf object (bpf-linker), then the object checks.
xdp: xdp-env
ifneq ($(XDP_CORE),)
	RUSTC_BOOTSTRAP=1 cargo build -p plat-xdp-core $(BPF_STD) --release
else
	@echo "xdp: skipped bpfel build (no crates/plat-xdp-core yet; WU1)"
endif
ifneq ($(XDP_USER),)
	cargo build -p plat-xdp --features xdp --release
	@objs=$$(find target/release/build -path '*/out/plat-xdp-ebpf' -type f 2>/dev/null); \
	[ -n "$$objs" ] || { echo "ERROR: plat-xdp built but no plat-xdp-ebpf object under target/release/build" >&2; exit 1; }; \
	for o in $$objs; do python3 -I deploy/tests/xdp/check-object.py "$$o" || exit 1; done
else
	@echo "xdp: skipped plat-xdp object build (no crates/plat-xdp yet; WU3)"
endif

# Lint: the deploy/tests/xdp scripts (shellcheck required when CI=true), the
# object checker's self-test, clippy for bpfel, clippy with the xdp feature.
check-xdp: xdp-env
	for f in $(XDP_SH); do sh -n $$f || exit 1; done
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck -x $(XDP_SH); \
	elif [ "$$CI" = true ]; then echo "ERROR: shellcheck is required in CI" >&2; exit 1; \
	else echo "WARNING: shellcheck not installed; skipped" >&2; fi
	for f in $(XDP_PY); do python3 -I -c 'import ast, sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' $$f || exit 1; done
	python3 -I deploy/tests/xdp/check-object.py --self-test
ifneq ($(strip $(XDP_BPF_PKGS)),)
	RUSTC_BOOTSTRAP=1 cargo clippy $(XDP_BPF_PKGS) $(BPF_STD) -- -D warnings
else
	@echo "check-xdp: skipped bpfel clippy (no plat-xdp-core / plat-xdp-ebpf yet; WU1/WU2)"
endif
ifneq ($(XDP_USER),)
	cargo clippy -p plat-xdp --features xdp --all-targets -- -D warnings
endif
ifneq ($(XDP_LOADER),)
	cargo clippy -p plat-xdp-loader --features xdp --all-targets -- -D warnings
endif

# Levels 2-4 in virtme-ng VMs (Linux only; plan §11): fetch each matrix kernel
# through the signed Debian chain, boot it, run deploy/tests/xdp/guest.sh.
# WU3 adds the level-2 test_run binary as the guest's second argument.
test-xdp: xdp-env
	@[ "$$(uname -s)" = Linux ] || { echo "ERROR: test-xdp needs Linux with virtme-ng and QEMU (plan §11)" >&2; exit 1; }
	@for k in $(XDP_KERNELS); do \
	  kimg=$$(deploy/tests/xdp/fetch-kernel.sh $$k) || exit 1; \
	  deploy/tests/xdp/vng-run.sh $(XDP_VNG_FLAGS) "$$kimg" || exit 1; \
	done

bench-xdp: xdp-env
ifneq ($(XDP_CORE),)
	cargo bench -p plat-xdp-core
else
	@echo "bench-xdp: skipped (no plat-xdp-core yet; WU1)"
endif

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
