#!/bin/sh
# Prepare the EL9 package build container (Rocky Linux 9, glibc 2.34): the
# AWS-LC FIPS build deps (CMake, Go, clang/gcc, perl), dpkg-dev for cargo-deb,
# rpm tools, Python 3.12 for the supply-chain scripts, and rustup. The
# toolchain itself comes from rust-toolchain.toml on the first cargo call.
#
# Release packages are built here, not on the ubuntu-24.04 runner, so the
# shipped ELF files need no GLIBC_ symbol newer than 2.34 and install on EL9,
# Debian 12 and Ubuntu 22.04/24.04 (check-glibc-floor.sh enforces this).
#
# Run as root inside the image pinned in packages.yml (`EL9_IMAGE`), e.g.
#   podman run --rm -v "$PWD":/src -w /src "$EL9_IMAGE" sh deploy/build/el9-build-deps.sh
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-2 (Baseline Configuration), SA-15 (Development Process,
#   Standards, and Tools), SR-3 (Supply Chain Controls) - base image pinned
#   by digest; distro packages verified by dnf GPG signatures (Rocky, EPEL);
#   rustup-init pinned by version and sha256 before it is executed
set -eu

RUSTUP_VERSION=1.29.3
SHA256_AARCH64=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282
SHA256_X86_64=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55

die() { echo "el9-build-deps: $1" >&2; exit "${2:-1}"; }

[ "$(id -u)" = 0 ] || die "run as root inside the build container" 2
grep -q '^VERSION_ID="9' /etc/os-release || die "not an EL9 image" 2

case "$(uname -m)" in
    aarch64) want=$SHA256_AARCH64 ;;
    x86_64) want=$SHA256_X86_64 ;;
    *) die "unsupported arch $(uname -m)" 2 ;;
esac

dnf_opts="-y --setopt=install_weak_deps=False --setopt=retries=5 --setopt=timeout=30"
# epel-release comes from Rocky "extras" (signed); dpkg-dev is EPEL only.
# shellcheck disable=SC2086
dnf $dnf_opts install epel-release
# shellcheck disable=SC2086
dnf $dnf_opts install \
    cmake golang clang gcc gcc-c++ make perl perl-FindBin perl-IPC-Cmd \
    git tar gzip xz zstd findutils diffutils which binutils \
    dpkg dpkg-dev rpm-build cpio python3.12 python3.12-pip
dnf -y clean all

# python3 for the Makefile (`python3 -I ...`): the scripts need 3.11+ (tomllib).
ln -sf /usr/bin/python3.12 /usr/local/bin/python3

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
url=https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/$(uname -m)-unknown-linux-gnu/rustup-init
curl --proto '=https' --tlsv1.2 -sSfL --retry 5 -o "$work/rustup-init" "$url"
echo "$want  $work/rustup-init" | sha256sum -c - >/dev/null || die "rustup-init sha256 mismatch"
chmod 0755 "$work/rustup-init"
"$work/rustup-init" -y --no-modify-path --profile minimal --default-toolchain none

echo "el9-build-deps: glibc $(rpm -q --qf '%{VERSION}' glibc), $(cmake --version | head -n1), $(go version)"
