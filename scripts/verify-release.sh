#!/bin/sh
# Verify a downloaded usg-plat GitHub Release (cosign keyless bundles).
# Usage: scripts/verify-release.sh [--trusted-root FILE] <dir> <tag>
#   e.g. scripts/verify-release.sh ./dl v0.2.0
# Needs cosign v3.0.3 or later (the release is signed with cosign v3.1.4 in
# the protobuf bundle format; v3.0.3 fixed the bundle verify path,
# GHSA-whqx-f9j3-ch6m). Without --trusted-root, cosign fetches the public
# Sigstore trust root over the network (TUF). With --trusted-root FILE (a
# pinned trusted_root.json), every cosign verify-blob uses that file and needs
# no network; --offline is never passed (deprecated in cosign v3, and
# --trusted-root alone keeps cosign off the network).
# If `gh` is installed, also checks the GitHub build provenance attestations.
# COMPLIANCE MAPPING:
# - NIST 800-53: SI-7 (Software Integrity), SR-4 (Provenance),
#   SR-11 (Component Authenticity), CM-14 (Signed Components)
# POAM: POAM-044 (verification is manual; nothing enforces it at install)
set -eu
usage="usage: verify-release.sh [--trusted-root FILE] <dir> <tag>"
trusted_root=
while [ $# -gt 0 ]; do
  opt=$1
  case $opt in
    --trusted-root)
      [ $# -ge 2 ] || { echo "$usage" >&2; exit 2; }
      trusted_root=$2; shift 2 ;;
    --trusted-root=*) trusted_root=${opt#--trusted-root=}; shift ;;
    -h|--help) echo "$usage"; exit 0 ;;
    --) shift; break ;;
    -*) echo "unknown option: $opt" >&2; echo "$usage" >&2; exit 2 ;;
    *) break ;;
  esac
done
[ $# -eq 2 ] || { echo "$usage" >&2; exit 2; }
dir=$1
tag=$2
if [ -n "$trusted_root" ]; then
  [ -f "$trusted_root" ] && [ -r "$trusted_root" ] || { echo "trusted root not a readable file: $trusted_root" >&2; exit 2; }
  # Absolute path: the script changes into <dir> before verifying.
  case $trusted_root in /*) ;; *) trusted_root=$(pwd)/$trusted_root ;; esac
fi
case $tag in v[0-9]*) ;; *) echo "tag must look like v<x.y.z>" >&2; exit 2 ;; esac
case $tag in *[!A-Za-z0-9._-]*) echo "tag contains unexpected characters" >&2; exit 2 ;; *) ;; esac
repo=${PLAT_REPO:-192d-Wing/usg-plat}
case $repo in */*/*|*[!A-Za-z0-9._/-]*) echo "bad PLAT_REPO" >&2; exit 2 ;; *) ;; esac
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
  vf=$1
  if [ -n "$trusted_root" ]; then
    cosign verify-blob --bundle "$vf.sigstore.json" --trusted-root "$trusted_root" \
      --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$vf"
  else
    cosign verify-blob --bundle "$vf.sigstore.json" \
      --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$vf"
  fi
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
