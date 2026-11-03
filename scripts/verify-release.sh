#!/bin/sh
# Verify a downloaded usg-plat GitHub Release (cosign keyless bundles).
# Usage: scripts/verify-release.sh <dir> <tag>   e.g. scripts/verify-release.sh ./dl v0.2.0
# Needs cosign v3.0.3 or later (the release is signed with cosign v3.1.4 in
# the protobuf bundle format; v3.0.3 fixed the bundle verify path,
# GHSA-whqx-f9j3-ch6m) and network access to the public Sigstore trust root.
# If `gh` is installed, also checks the GitHub build provenance attestations.
# COMPLIANCE MAPPING:
# - NIST 800-53: SI-7 (Software Integrity), SR-4 (Provenance),
#   SR-11 (Component Authenticity), CM-14 (Signed Components)
# POAM: POAM-044 (verification is manual; nothing enforces it at install)
set -eu
usage="usage: verify-release.sh <dir> <tag>"
dir=${1:?$usage}
tag=${2:?$usage}
case $tag in v[0-9]*) ;; *) echo "tag must look like v<x.y.z>" >&2; exit 2 ;; esac
case $tag in *[!A-Za-z0-9._-]*) echo "tag contains unexpected characters" >&2; exit 2 ;; esac
repo=${PLAT_REPO:-192d-Wing/usg-plat}
case $repo in */*/*|*[!A-Za-z0-9._/-]*) echo "bad PLAT_REPO" >&2; exit 2 ;; esac
workflow=.github/workflows/packages.yml
# Exact identity: this repository's packages.yml at this tag (no regexp).
identity="https://github.com/$repo/$workflow@refs/tags/$tag"
issuer=https://token.actions.githubusercontent.com

command -v cosign >/dev/null 2>&1 || { echo "cosign not found" >&2; exit 2; }
ver=$(cosign version 2>/dev/null | sed -n 's/^GitVersion:[[:space:]]*v\{0,1\}\([0-9][0-9.]*\).*/\1/p' | head -n1)
major=${ver%%.*}; rest=${ver#*.}; minor=${rest%%.*}; patch=${rest#*.}; patch=${patch%%[!0-9]*}
if [ -z "$ver" ] || [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -eq 0 ] && [ "${patch:-0}" -lt 3 ]; }; then
  echo "cosign v3.0.3 or later required (found: ${ver:-unknown})" >&2; exit 2
fi

cd "$dir"
[ -f SHA256SUMS ] || { echo "SHA256SUMS missing in $dir" >&2; exit 1; }
verify() {
  cosign verify-blob --bundle "$1.sigstore.json" \
    --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$1"
}
verify SHA256SUMS
sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS
n=0
while read -r _ f; do verify "$f"; n=$((n + 1)); done < SHA256SUMS
if command -v gh >/dev/null 2>&1; then
  while read -r _ f; do
    gh attestation verify "$f" --repo "$repo" \
      --signer-workflow "$repo/$workflow" --source-ref "refs/tags/$tag"
  done < SHA256SUMS
  att="; provenance attestations verified"
else
  att="; gh not found, provenance attestations not checked"
fi
echo "OK: SHA256SUMS and $n artifacts verified for $repo $tag$att"
