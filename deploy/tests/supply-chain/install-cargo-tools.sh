#!/usr/bin/env bash
# Installs the packaging, SBOM and audit tools from crates.io, pinned by
# version AND by the SHA-256 of the published .crate (the crates.io index
# checksum, recorded here when the pin was chosen). Each crate is downloaded,
# verified, unpacked and built with `cargo install --locked --path`, so the
# tool's own Cargo.lock (whose dependency checksums cargo verifies) is used.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SR-3, SR-4 (supply chain provenance), CM-14 (signed or
#   verified components) - tools that produce the SBOM are integrity-pinned.
#
# Usage: install-cargo-tools.sh [name ...]   (default: all listed tools)
# Updating a pin: change the version and the checksum together; the checksum
# is the `cksum` of that version in https://index.crates.io/<prefix>/<name>.
set -euo pipefail

PINS="
cargo-deb 3.8.0 201780f7056812fe4d8078b2772c1a222c56fa924cd2aafa1aaf74ff2777e188
cargo-generate-rpm 0.21.1 94d79151322105715a0daaf2440a42eb5fd8a7793f04e92571ed910c4bd3f632
cargo-cyclonedx 0.5.9 5d162f67705f0f5038759d73bf546a083bf30e8677c2e944b416bca48d9d69a8
cargo-auditable 0.7.7 ccdd489bc94d1338cd04389a842e00661300331ec915fb376b4810ef7d480b5d
cargo-audit 0.22.2 700c2b240f7fd330c24b675fe429f73a5b676531fcc6300400b2b67f155ba12a
"

sha256() {
	local file="$1"
	if command -v sha256sum >/dev/null; then sha256sum "$file" | cut -d" " -f1; else shasum -a 256 "$file" | cut -d" " -f1; fi
}

want=("$@")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

while read -r name version sum; do
	[[ -n "$name" ]] || continue
	if [[ ${#want[@]} -gt 0 ]] && ! printf '%s\n' "${want[@]}" | grep -qx "$name"; then continue; fi
	if cargo install --list | grep -qx "$name v$version:"; then
		echo "$name $version already installed"
		continue
	fi
	crate="$work/$name-$version.crate"
	curl --proto '=https' --tlsv1.2 -sSfL -o "$crate" "https://static.crates.io/crates/$name/$name-$version.crate"
	got=$(sha256 "$crate")
	if [[ "$got" != "$sum" ]]; then
		echo "ERROR: $name $version checksum mismatch: got $got, pinned $sum" >&2
		exit 1
	fi
	tar -xzf "$crate" -C "$work"
	cargo install --locked --path "$work/$name-$version"
done <<<"$PINS"
