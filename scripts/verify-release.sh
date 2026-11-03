#!/bin/sh
# Verify a downloaded usg-plat GitHub Release (cosign keyless bundles).
# Usage: scripts/verify-release.sh <dir> <tag>   e.g. scripts/verify-release.sh ./dl v0.2.0
# Needs cosign >= 2.0 and network access to the public Sigstore trust root.
# COMPLIANCE MAPPING:
# - NIST 800-53: SI-7 (Software Integrity), SR-4 (Provenance),
#   SR-11 (Component Authenticity), CM-14 (Signed Components)
set -eu
dir=${1:?usage: verify-release.sh <dir> <tag>}
tag=${2:?usage: verify-release.sh <dir> <tag>}
case $tag in v*) ;; *) echo "tag must start with v" >&2; exit 2 ;; esac
repo=${PLAT_REPO:-192d-Wing/usg-plat}
id_re="^https://github\.com/$(printf '%s' "$repo" | sed 's/[.]/\\./g')/\.github/workflows/packages\.yml@refs/tags/v.*\$"
issuer=https://token.actions.githubusercontent.com
cd "$dir"
[ -f SHA256SUMS ] || { echo "SHA256SUMS missing in $dir" >&2; exit 1; }
verify() {
  cosign verify-blob --bundle "$1.sigstore.json" \
    --certificate-identity-regexp "$id_re" --certificate-oidc-issuer "$issuer" "$1"
}
verify SHA256SUMS
# Bind the signing identity to this exact tag, not just any v* tag.
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/$repo/.github/workflows/packages.yml@refs/tags/$tag" \
  --certificate-oidc-issuer "$issuer" SHA256SUMS
sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS
n=0
while read -r _ f; do verify "$f"; n=$((n + 1)); done < SHA256SUMS
echo "OK: SHA256SUMS and $n artifacts verified for $repo $tag"
