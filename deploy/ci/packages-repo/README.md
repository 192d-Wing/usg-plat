# usg-plat-packages

apt and dnf repositories for [usg-plat](https://github.com/192d-Wing/usg-plat),
served by GitHub Pages at <https://192d-wing.github.io/usg-plat-packages/>.

**Do not edit this repository by hand.** Every commit is written by the
`publish` job of `usg-plat/.github/workflows/packages.yml` on a `v*` tag
(`deploy/ci/publish-packages.sh`), using a write deploy key held only in the
usg-plat `release` environment. This README is copied from
`usg-plat/deploy/ci/packages-repo/` on each publish.

## Security model: metadata is unsigned by design

The repository metadata (apt `Release`, dnf `repomd.xml`) is **not signed**:
the apt source uses `Trusted: yes` and the dnf repo uses `gpgcheck=0`.
Packages are authenticated at install time instead, by the
`usg-plat-verify` gate: apt (`DPkg::Pre-Install-Pkgs`) and dnf4 (plugin)
refuse `platd` and `usg-plat-verify` unless the package's SHA-256 is in the
release `SHA256SUMS` and that file's Sigstore keyless signature verifies
offline against the pinned trust root and the exact release workflow
identity. An attacker who controls this repository or its transport can
withhold or roll back updates (freeze), but cannot get an unsigned usg-plat
package installed. Only `platd`, `usg-plat-verify` and `usg-plat-pin-canary`
are ever published; the publish step refuses any other name.

## Layout

| Path | Contents |
|------|----------|
| `apt/dists/stable/` | `Release`, `main/binary-{amd64,arm64}/Packages{,.gz}` |
| `apt/pool/main/` | `.deb` files |
| `rpm/x86_64/`, `rpm/aarch64/` | `.rpm` files and `repodata/` (noarch packages are in both) |
| `releases/vX.Y.Z/` | `SHA256SUMS`, `SHA256SUMS.sigstore.json` and per-file bundles |

The newest 10 releases are kept. `usg-plat-pin-canary` is an empty package
that must never be installable: `usg-plat-verify selftest --apt` (run after
every `apt-get update`) checks that apt reports no candidate for it, which
proves the `-1` pin for foreign names matches this origin.

## Bootstrap

1. Install cosign >= 3.0.3 from the upstream release (checksum-verified) as
   `/usr/local/bin/cosign`.
2. Download `usg-plat-verify` and the release files from the usg-plat GitHub
   Release, verify them with `scripts/verify-release.sh`, then install it with
   `dpkg -i` or `rpm -i` (this one install is not gated).
3. The package installs the apt source and pin, or the dnf repo file; from
   then on `apt-get install platd` / `dnf install platd` is gated.

See the usg-plat install guide for details, offline mirrors (`file:` sources
with `Pin: origin ""`) and alerting on refusals.
