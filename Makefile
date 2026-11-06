# usg-plat quality gates (see .claude/skills/plat-workflow/references/quality-gates.md)
LINUX_TARGET ?= aarch64-unknown-linux-gnu
ZENSICAL ?= uvx zensical@0.0.73

.PHONY: all check fmt clippy check-linux check-notls test test-deploy bench ir security compliance-annotations release dist deb rpm packages docs docs-serve sbom cbom-check verify-release

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

# xdp-env (defined below) refuses a pre-set RUSTC_BOOTSTRAP, so the required
# CI jobs (which run these targets) assert it too (SEC-004 / NIST-007).
check: xdp-env fmt clippy check-linux check-notls codex-agents-check cbom-check

# Codex agent definitions (.codex/agents/*.toml) are generated from the Claude
# Code ones (.claude/agents/*.md); check fails when they have drifted.
.PHONY: codex-agents codex-agents-check
codex-agents:
	python3 -I .codex/sync-agents.py

codex-agents-check:
	python3 -I .codex/sync-agents.py --check

test: xdp-env
	cargo test --workspace

# shellcheck is pinned (deploy/tests/install-shellcheck.sh installs it in CI).
# CI=true: missing or another version fails; locally: a warning, then lint.
SHELLCHECK_VERSION := 0.11.0
SHELLCHECK = sh -c 'if ! command -v shellcheck >/dev/null 2>&1; then \
	  if [ "$$CI" = true ]; then echo "ERROR: shellcheck is required in CI" >&2; exit 1; fi; \
	  echo "WARNING: shellcheck not installed; skipped" >&2; exit 0; fi; \
	v=$$(shellcheck --version | sed -n "s/^version: //p"); \
	if [ "$$v" != "$(SHELLCHECK_VERSION)" ]; then \
	  if [ "$$CI" = true ]; then echo "ERROR: shellcheck $$v, want $(SHELLCHECK_VERSION)" >&2; exit 1; fi; \
	  echo "WARNING: shellcheck $$v, CI uses $(SHELLCHECK_VERSION)" >&2; fi; \
	exec shellcheck -x "$$@"' shellcheck

# Install-time gate scripts (see verify-pkg below); defined here because
# DEPLOY_SH includes them.
VERIFY_SH := deploy/verify/build.sh deploy/verify/trusted-root.sh deploy/verify/debian/postinst deploy/verify/debian/prerm \
	$(wildcard deploy/verify/libexec/*) $(wildcard deploy/verify/bin/usg-plat-verify) $(wildcard deploy/tests/verify/*.sh) $(wildcard deploy/tests/verify/install/*.sh)
VERIFY_PY := $(wildcard deploy/tests/verify/test_dnf_plugin.py)

# Deploy scripts: POSIX syntax, shellcheck (required when CI=true) and a stubbed run
# against the real `platd check-config --format env` output.
DEPLOY_SH := deploy/systemd/plat-tun-setup.sh deploy/systemd/plat-fwguard.sh deploy/tests/deploy-scripts-test.sh \
	deploy/hooks/frr-announce.sh deploy/hooks/frr-withdraw.sh deploy/systemd/plat-v6-announce.sh deploy/tests/xdp/e2e.sh deploy/tests/resolver/l33-resolver.sh scripts/verify-release.sh deploy/tests/install-shellcheck.sh $(wildcard deploy/tests/cluster/*.sh) \
	$(VERIFY_SH)
test-deploy:
	for f in $(DEPLOY_SH); do sh -n $$f || exit 1; done
	@$(SHELLCHECK) $(DEPLOY_SH)
	sh deploy/tests/deploy-scripts-test.sh

# Install-time signature gate (POAM-044 (c)): the usg-plat-verify .deb/.rpm.
# The package is shell, python and data only (no binary, no crypto): it stays
# out of the cargo graph, the SBOM's Rust components and the CBOM. The bundled
# Sigstore trusted root is fetched with cosign and refused unless it matches
# deploy/verify/trusted_root.sha256; a new root lands only through a reviewed
# PR (make trusted-root-update). The sources of units not yet in the tree are
# picked up by wildcard; build.sh refuses to build without them.
# COMPLIANCE MAPPING:
# - NIST 800-53: SI-7(15) (Code Authentication), CM-14 (Signed Components),
#   SR-11 (Component Authenticity), CM-3 (Configuration Change Control)

.PHONY: verify-pkg trusted-root-update test-verify
verify-pkg:
	sh deploy/verify/trusted-root.sh --out target/verify/trusted_root.json
	sh deploy/verify/build.sh --trusted-root target/verify/trusted_root.json

trusted-root-update:
	sh deploy/verify/trusted-root.sh --update --out target/verify/trusted_root.json

test-verify:
	for f in $(VERIFY_SH); do sh -n $$f || exit 1; done
	@$(SHELLCHECK) $(VERIFY_SH)
	@if grep -rn -e '--certificate-identity-regexp' deploy/verify; then \
	  echo "ERROR: the verifier must pass an exact --certificate-identity" >&2; exit 1; fi
	sh deploy/verify/trusted-root.sh --self-test
	sh deploy/verify/build.sh --self-test
	$(if $(wildcard deploy/tests/verify/unit.sh),sh deploy/tests/verify/unit.sh,@if [ "$$CI" = true ]; then echo "ERROR: deploy/tests/verify/unit.sh is required in CI" >&2; exit 1; fi; echo "WARNING: deploy/tests/verify/unit.sh not in the tree; skipped" >&2)
	$(if $(VERIFY_PY),python3 -I -m unittest discover -s deploy/tests/verify -p 'test_dnf_plugin.py',@if [ "$$CI" = true ]; then echo "ERROR: deploy/tests/verify/test_dnf_plugin.py is required in CI" >&2; exit 1; fi; echo "WARNING: deploy/tests/verify/test_dnf_plugin.py not in the tree; skipped" >&2)

bench:
	cargo bench -p plat-xlat -p plat-nat64 -p plat-audit -p plat-xdp-core -p plat-tls --bench xlat --bench nat64 --bench audit --bench decide --bench handshake

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
XDP_KERNELS ?= 6.6 6.12 latest
XDP_VNG_FLAGS ?=

.PHONY: xdp check-xdp test-xdp bench-xdp xdp-env

xdp-env:
ifneq ($(origin RUSTC_BOOTSTRAP),undefined)
	$(error RUSTC_BOOTSTRAP is set ($(origin RUSTC_BOOTSTRAP)); the workspace build must stay plain stable (plan §15))
endif
	@true

# Build: plat-xdp-core for bpfel (a library: proves it is no_std/BPF-clean, no
# linker needed); the plat-xdp-ebpf object (build-object.sh: bpf-linker, the
# aya-build flags, path-independent) into $(XDP_OBJ), then the object checks
# (licence, helper allow-list, no loops); plat-xdp with the xdp feature, whose
# build script builds and links the object again, then the same checks.
XDP_OBJ := target/xdp/plat-xdp-ebpf
xdp: xdp-env
ifneq ($(XDP_CORE),)
	RUSTC_BOOTSTRAP=1 cargo build -p plat-xdp-core $(BPF_STD) --release
else
	@echo "xdp: skipped bpfel build (no crates/plat-xdp-core yet; WU1)"
endif
ifneq ($(XDP_EBPF),)
	deploy/tests/xdp/build-object.sh target/xdp
	python3 -I deploy/tests/xdp/check-object.py $(XDP_OBJ)
else
	@echo "xdp: skipped eBPF object build (no crates/plat-xdp-ebpf yet; WU2)"
endif
ifneq ($(XDP_USER),)
	cargo build -p plat-xdp --features xdp --release
	@objs=$$(find target/release/build -path '*/out/plat-xdp-ebpf' -type f 2>/dev/null); \
	[ -n "$$objs" ] || { echo "ERROR: plat-xdp built but no plat-xdp-ebpf object under target/release/build" >&2; exit 1; }; \
	for o in $$objs; do python3 -I deploy/tests/xdp/check-object.py "$$o" || exit 1; done
	@# SI-7: the embedded object (newest build-script output) must be the gated one.
	@o=$$(ls -t $$(find target/release/build -path '*/out/plat-xdp-ebpf' -type f) | head -n 1); \
	want=$$(cut -d' ' -f1 $(XDP_OBJ).sha256); got=$$(sha256sum "$$o" | cut -d' ' -f1); \
	[ "$$want" = "$$got" ] || { echo "ERROR: embedded object $$o ($$got) differs from $(XDP_OBJ) ($$want)" >&2; exit 1; }; \
	echo "xdp: embedded object = gated object ($$got)"
	cargo build -p plat-xdp-loader --features xdp --release
	cargo build -p platd --features xdp --release
else
	@echo "xdp: skipped plat-xdp object build (no crates/plat-xdp yet; WU3)"
endif

# Lint: the deploy/tests/xdp scripts (shellcheck required when CI=true), the
# self-tests of the object checker and of the stack/instruction gate's
# evaluation, clippy for bpfel, clippy with the xdp feature.
check-xdp: xdp-env
	for f in $(XDP_SH); do sh -n $$f || exit 1; done
	@$(SHELLCHECK) $(XDP_SH)
	for f in $(XDP_PY); do python3 -I -c 'import ast, sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' $$f || exit 1; done
	python3 -I deploy/tests/xdp/check-object.py --self-test
	python3 -I deploy/tests/xdp/obj-gate.py --self-test
	@# SEC-002: RUSTC_BOOTSTRAP only on the bpfel command lines, never exported
	@# or assigned for make, and never in a cargo config.
	@if grep -nE '^(export[[:space:]]+)?RUSTC_BOOTSTRAP[[:space:]]*[:?+!]?=|^[[:space:]]*export[[:space:]]+RUSTC_BOOTSTRAP' Makefile; then \
	  echo "ERROR: RUSTC_BOOTSTRAP exported or assigned in the Makefile (plan §15)" >&2; exit 1; fi
	@if grep -nE '^	RUSTC_BOOTSTRAP=' Makefile | grep -vF '$$(BPF_STD)'; then \
	  echo "ERROR: RUSTC_BOOTSTRAP on a recipe line without the bpfel target (plan §15)" >&2; exit 1; fi
	@if ls .cargo/config* >/dev/null 2>&1 && grep -n RUSTC_BOOTSTRAP .cargo/config*; then \
	  echo "ERROR: RUSTC_BOOTSTRAP in .cargo/config (plan §15)" >&2; exit 1; fi
	@# NIST-003: ctx.rs is the only module of the eBPF crate allowed unsafe code.
	@if grep -rn 'allow(unsafe_code)' crates/plat-xdp-ebpf | grep -v '^crates/plat-xdp-ebpf/src/ctx.rs:'; then \
	  echo "ERROR: allow(unsafe_code) outside crates/plat-xdp-ebpf/src/ctx.rs (rule 6)" >&2; exit 1; fi
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
	cargo clippy -p platd --features xdp --all-targets -- -D warnings
endif

# Levels 2-4 in virtme-ng VMs (Linux only; plan §11): fetch each matrix kernel
# through the signed Debian chain, boot it, run deploy/tests/xdp/guest.sh.
# With plat-xdp-ebpf, builds the object first (make xdp) and the guest runs
# the stack/instruction gate and the level-2 smoke vectors on it
# (obj-gate.py). With plat-xdp, the level-2 test_run binary (built here with
# the xdp feature) runs in the guest's netns as root (vng-run.sh -l).
# Prerequisites: virtme-ng, QEMU, gpgv and the Debian archive keyring
# (`apt-get install debian-archive-keyring`, as the xdp-vm CI job does), or
# XDP_DEBIAN_KEYRING=/path/to/debian-archive-keyring.gpg; without it
# fetch-kernel.sh fails closed ("keyring not found").
XDP_L2_JSON := python3 -I -c 'import json, sys; [print(m["executable"]) for m in map(json.loads, sys.stdin) if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "test_run"]'
test-xdp: xdp-env $(if $(XDP_EBPF),xdp)
	@[ "$$(uname -s)" = Linux ] || { echo "ERROR: test-xdp needs Linux with virtme-ng and QEMU (plan §11)" >&2; exit 1; }
	@l2=; if [ -n "$(XDP_USER)" ]; then \
	  l2=$$(cargo test -p plat-xdp --features xdp --release --test test_run --no-run --message-format=json | $(XDP_L2_JSON) | tail -n 1); \
	  [ -n "$$l2" ] || { echo "ERROR: no plat-xdp test_run binary" >&2; exit 1; }; fi; \
	for k in $(XDP_KERNELS); do \
	  kimg=$$(deploy/tests/xdp/fetch-kernel.sh $$k) || exit 1; \
	  deploy/tests/xdp/vng-run.sh $(XDP_VNG_FLAGS) $(if $(XDP_EBPF),-o $(CURDIR)/$(XDP_OBJ)) $${l2:+-l $$l2} "$$kimg" || exit 1; \
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
# The packages also carry plat-xdp-loader and the XDP units (off by default).
# Without XDP=1 the loader has no embedded object and refuses to attach;
# XDP=1 builds platd and the loader with the `xdp` feature (bpf-linker
# required, see `make xdp`).
DIST_FEATURES := $(if $(XDP),--features platd/xdp --features plat-xdp-loader/xdp)
#
# Shipped binaries are built with `cargo auditable` (pinned below), which
# embeds the dependency list in a .dep-v0 section (`cargo audit bin`, T7).
# AUDITABLE=0 falls back to a plain build for local development only and is
# refused when CI=true.
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-8 (System Component Inventory), SR-4 (Provenance), RA-5
#   (Vulnerability Monitoring and Scanning), CM-2 (pinned tools)
CARGO_AUDITABLE_VERSION ?= 0.7.7
CARGO_CYCLONEDX_VERSION ?= 0.5.9
CHECK_JSONSCHEMA_VERSION ?= 0.39.0
# Schema validation: CI installs the hash-locked check-jsonschema and sets
# CHECK_JSONSCHEMA=check-jsonschema; locally uvx is used when present (the
# scripts skip with a warning without it, and fail without it when CI=true).
CHECK_JSONSCHEMA ?= $(if $(shell command -v uvx 2>/dev/null),uvx --from check-jsonschema==$(CHECK_JSONSCHEMA_VERSION) check-jsonschema)
export CHECK_JSONSCHEMA
# Fails unless `cargo install --list` shows tool $(1) at version $(2).
tool-pin = cargo install --list | grep -qE '^$(1) v$(2)( \(.*\))?:$$' || { echo "ERROR: $(1) $(2) required: deploy/tests/supply-chain/install-cargo-tools.sh $(1)" >&2; exit 1; }

dist:
ifeq ($(AUDITABLE),0)
	@if [ "$$CI" = true ]; then echo "ERROR: AUDITABLE=0 is refused in CI (shipped binaries must be auditable)" >&2; exit 1; fi
	@echo "WARNING: AUDITABLE=0: plain cargo build, the binaries carry no .dep-v0 dependency data" >&2
	cargo build --profile dist -p platd -p plat-xdp-loader $(DIST_FEATURES)
else
	@$(call tool-pin,cargo-auditable,$(CARGO_AUDITABLE_VERSION))
	cargo auditable build --profile dist -p platd -p plat-xdp-loader $(DIST_FEATURES)
endif

# CycloneDX SBOM (1.5 JSON; cargo-cyclonedx emits <= 1.5) of the shipped
# binaries for the host triple, finished and cross-checked by sbom-finish.py
# (T6 against cargo metadata, T7 against the .dep-v0 data on Linux, and with
# XDP=1 T8: the eBPF object from `make xdp` with its hash and build
# formulation). Writes target/sbom/platd[-xdp]-<version>-<arch>.cdx.json and
# the fixed-name copy target/sbom/platd-sbom.cdx.json the packages install.
HOST_TRIPLE := $(shell rustc -vV 2>/dev/null | sed -n 's/^host: //p')
WS_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
SBOM_NAME := platd$(if $(XDP),-xdp)-$(WS_VERSION)-$(firstword $(subst -, ,$(HOST_TRIPLE))).cdx.json
comma := ,
SBOM_RAW := services/platd/platd_bin.cdx.json services/plat-xdp-loader/plat-xdp-loader_bin.cdx.json
sbom: dist
	@$(call tool-pin,cargo-cyclonedx,$(CARGO_CYCLONEDX_VERSION))
	@if [ -n "$(XDP)" ] && [ ! -f $(XDP_OBJ).sha256 ]; then echo "ERROR: sbom XDP=1 needs the gated object: run make xdp first" >&2; exit 1; fi
	rm -f $(SBOM_RAW) && mkdir -p target/sbom/raw
	cargo cyclonedx --manifest-path services/platd/Cargo.toml -f json --spec-version 1.5 --describe binaries -q \
	  --target $(HOST_TRIPLE) $(if $(XDP),-F platd/xdp$(comma)plat-xdp-loader/xdp)
	mv $(SBOM_RAW) target/sbom/raw/
	find crates services -maxdepth 2 -name '*_bin.cdx.json' -delete
	python3 -I deploy/tests/supply-chain/sbom-finish.py --target $(HOST_TRIPLE) --out target/sbom/$(SBOM_NAME) \
	  --raw target/sbom/raw/platd_bin.cdx.json --raw target/sbom/raw/plat-xdp-loader_bin.cdx.json \
	  --auditable target/dist/platd --auditable target/dist/plat-xdp-loader \
	  --tool "cargo-cyclonedx $(CARGO_CYCLONEDX_VERSION)" $(if $(XDP),--features xdp --xdp-object $(XDP_OBJ))
	cp target/sbom/$(SBOM_NAME) target/sbom/platd-sbom.cdx.json

# CBOM drift checks T3-T5 (dependency graph, // CBOM: markers, structure and
# schema), the self-tests of both supply-chain scripts and the T3 negative
# cases (test_drift_negative.py). T1 runs in `make test`. `cargo fetch`
# fills the registry cache first so the scripts can stay `--offline`.
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-8, SR-3 (Supply Chain Controls), SA-11 (Developer Testing)
cbom-check:
	cargo fetch --locked
	python3 -I deploy/tests/supply-chain/check-cbom.py --self-test --all
	python3 -I deploy/tests/supply-chain/sbom-finish.py --self-test
	python3 -I deploy/tests/supply-chain/test_drift_negative.py

deb: sbom
	cargo deb -p platd --no-build --no-strip --profile dist

rpm: sbom
	cargo generate-rpm -p services/platd --profile dist

packages: deb rpm

# Verify a downloaded GitHub Release: make verify-release DIR=./dl TAG=v0.3.0
# (cosign keyless bundles, identity = packages.yml at refs/tags/v*; SI-7, SR-11).
verify-release:
	@test -n "$(DIR)" && test -n "$(TAG)" || { echo "usage: make verify-release DIR=<dir> TAG=v<x.y.z>" >&2; exit 2; }
	sh scripts/verify-release.sh $(DIR) $(TAG)

docs:
	$(ZENSICAL) build --clean

docs-serve:
	$(ZENSICAL) serve
