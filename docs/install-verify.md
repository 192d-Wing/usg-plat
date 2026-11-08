# Install-time signature verification (`usg-plat-verify`)

`usg-plat-verify` is a host package. It makes apt and dnf4 refuse to install
`platd` or `usg-plat-verify` unless the package's SHA-256 is listed in that
release's `SHA256SUMS`, and that file's Sigstore keyless signature verifies
offline. The check uses the pinned trust root and the exact release identity
`https://github.com/192d-Wing/usg-plat/.github/workflows/packages.yml@refs/tags/v<version>`
(issuer `https://token.actions.githubusercontent.com`). The gate checks no
other packages. `platd` depends on `usg-plat-verify`.

The gate runs on the host, not in `platd`. It closes POAM-044 (c) only in
part. The gaps are listed under [What the gate does not cover](#what-the-gate-does-not-cover)
and in `docs/compliance/POAM.md`.

!!! warning "Availability"
    The apt/dnf repository at <https://192d-wing.github.io/usg-plat-packages/>
    is filled by the `publish` job of `packages.yml` on a `v*` tag. That job
    has not run yet. v0.3.0 and earlier have no `usg-plat-verify` package.
    The steps below apply from the first release that ships one.

Supported: Debian 12 and Ubuntu 24.04 (apt 2.6 or later) and EL9 and EL10
(dnf4: dnf 4.14 on EL9, 4.20 on Rocky 10). dnf5 is not supported.

## 1. Install cosign (operator-provided)

The gate calls `/usr/local/bin/cosign` (`COSIGN` in
`/etc/usg-plat-verify/verify.conf`) and needs version 3.0.3 or later. No
distribution package is usable: Debian 13 ships 2.5.0, and Debian 12,
Ubuntu 24.04 and EPEL 9/10 have none. cosign is never bundled with
usg-plat. Install the upstream binary at the version CI pins (v3.1.4):

```sh
V=v3.1.4
A=amd64        # or arm64
curl --proto =https -fsSLO "https://github.com/sigstore/cosign/releases/download/$V/cosign-linux-$A"
curl --proto =https -fsSLO "https://github.com/sigstore/cosign/releases/download/$V/cosign_checksums.txt"
sha256sum --ignore-missing -c cosign_checksums.txt
# The pinned digests, the same as in packages.yml / real-release.sh:
#   amd64 424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
#   arm64 ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2
echo "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  cosign-linux-$A" | sha256sum -c -
install -m 0755 -o root -g root "cosign-linux-$A" /usr/local/bin/cosign
cosign version
```

`cosign_checksums.txt` comes from the same place as the binary, so it only
detects a damaged download. The check against the pinned digest is what
authenticates the binary. Record the cosign version and SHA-256 in the
host's CM-2 / CM-8 baseline. `usg-plat-verify status` prints both.

If cosign is missing, older than `COSIGN_MIN` (3.0.3), or fails, every
`platd` and `usg-plat-verify` install is refused (fail closed). Other
packages are unaffected. Evidence: install cases E05 and E07, unit tests
`cosign missing`, `cosign 3.0.2 below 3.0.3`, `cosign timeout`, and real
cosign case R14 (`docs/compliance/LINUX_VERIFICATION.md` L34).

The gate runs cosign with `GODEBUG=fips140=only` (`COSIGN_GODEBUG`). That
setting keeps cosign inside Go's native FIPS 140-3 module, but the CMVP
status of that module version is a host-side, organisational determination
(see `docs/compliance/CRYPTO_INVENTORY.md`). Case R03 checks the default,
and R04–R08 verify under it.

## 2. Bootstrap `usg-plat-verify` (one ungated install)

The first `usg-plat-verify` install cannot be gated by itself. Verify it
by hand on a workstation, then install it with `apt-get install ./…` or
`dnf install ./…`:

```sh
gh release download vX.Y.Z -R 192d-Wing/usg-plat -D dl
# Pinned Sigstore trust root (cosign initialize; refused unless its SHA-256
# equals deploy/verify/trusted_root.sha256):
deploy/verify/trusted-root.sh --out "$PWD/trusted_root.json"
scripts/verify-release.sh --trusted-root "$PWD/trusted_root.json" dl vX.Y.Z
```

`verify-release.sh` checks every file against `SHA256SUMS` and every bundle
against the exact tag. Without `--trusted-root` it fetches the public
Sigstore root over the network (TUF). Copy the verified package to the host:

```sh
sudo apt-get install ./usg-plat-verify_X.Y.Z-1_all.deb  # Debian / Ubuntu
sudo dnf install ./usg-plat-verify-X.Y.Z-1.noarch.rpm   # EL9 / EL10
```

Use `apt-get install ./…` and `dnf install ./…`, not `dpkg -i` or
`rpm -i`: from v0.4.1 the package depends on `curl | wget` and
`ca-certificates`, which `dpkg -i` and `rpm -i` do not install. Stock
Debian 12 and Ubuntu 24.04 images have neither curl nor wget (L35, L36).

The install prints a warning when cosign is missing (E01) and still
installs. On EL, `%pre` refuses a host whose dnf `PLUGINPATH` is neither
the EL9 (`python3.9`) nor the EL10 (`python3.12`) directory, because dnf
would never load the plugin there (E00).

After this install, `usg-plat-verify` upgrades go through the gate as
well.

## 3. Repository configuration

The package installs these files as conffiles:

| Host | File | Content |
|------|------|---------|
| apt | `/etc/apt/sources.list.d/usg-plat.sources` | `URIs: https://192d-wing.github.io/usg-plat-packages/apt`, `Suites: stable`, `Components: main`, `Trusted: yes` |
| apt | `/etc/apt/preferences.d/usg-plat` | `Package: *` at `-1` and `Package: platd usg-plat-verify` at `500`, both `Pin: origin "192d-wing.github.io"` |
| apt | `/etc/apt/apt.conf.d/50usg-plat-verify` | `DPkg::Pre-Install-Pkgs` hook (protocol v3); after `apt-get update`, `fetch-sums` (best effort) and `selftest --apt` (not masked) |
| dnf | `/etc/yum.repos.d/usg-plat.repo` | `baseurl=https://192d-wing.github.io/usg-plat-packages/rpm/$basearch`, `gpgcheck=0`, `repo_gpgcheck=0`, `includepkgs=platd usg-plat-verify` |
| dnf | `/etc/dnf/plugins/usg_plat_verify.conf` | `enabled=1` |
| both | `/etc/usg-plat-verify/verify.conf` | `NAMES`, `REPO_HOST`, `REPO_BASE`, `COSIGN`, `COSIGN_MIN`, `COSIGN_GODEBUG`, `ALLOW_DOWNGRADE` |

The repository metadata is unsigned by design: signing is keyless only,
with no OpenPGP key. Integrity comes from the gate. The pin (apt) and
`includepkgs` (dnf) stop the repository from supplying any other package
name (E03, E04). The `Pin: origin` value must be the bare lowercase host,
with no scheme and no port: a pin that does not match fails open. To catch
that, `selftest --apt` runs after every `apt-get update` and makes the
update exit 100 when it fails (E18). It checks that the source host
and the pin origins equal `REPO_HOST`, and that the empty package
`usg-plat-pin-canary` has `Candidate: (none)` (E03). A repository that
does not publish the canary therefore fails every `apt-get update`, by
design.

Then:

```sh
sudo apt-get update && sudo apt-get install platd   # E02, E08; upgrades E10
sudo dnf install platd                              # E02, E08; upgrades E10
sudo usg-plat-verify selftest                       # cosign, trust root, pin / repo
```

`usg-plat-verify selftest` runs `selftest --full`. On dnf hosts it also
checks that dnf actually loaded the plugin. dnf skips a plugin that fails
to import with only a warning, which would leave the host ungated, so this
check is the only way to detect that case (E02; unit tests
`selftest --dnf passes with the plugin loaded`,
`selftest --dnf fails when dnf did not load the plugin`). Run it after
every dnf or Python update, and from monitoring.

Local files are gated too. `apt install ./platd_X.Y.Z-1_amd64.deb` and
`dnf install ./platd-X.Y.Z-1.x86_64.rpm` are accepted only when the
signed `SHA256SUMS` and `SHA256SUMS.sigstore.json` of that release sit
next to the package (E13). A flipped byte is refused (E14), and so is an
altered `SHA256SUMS` (E15). `usg-plat-verify verify FILE` runs the same
check without installing.

Stage local packages and their `SHA256SUMS` files in a root-owned
directory that group and other cannot write (for example
`install -d -m 0755 -o root -g root /root/usg-plat-stage`). Otherwise
another user could swap a file between the check and the install.
The gate enforces this (POAM044-SEC-001): every package path it checks
(apt archives, the dnf cache and local paths alike), and each of its
ancestors, must exist, must not be a symlink, must be owned by uid 0 and
must not be group- or other-writable. Paths containing `.`, `..` or `//`
are refused, and so is a sticky world-writable directory such as `/tmp`.
Unit tests `local .deb in a world-writable directory refused`,
`local .deb in a sticky world-writable directory refused`,
`group-writable local .deb refused`,
`local .deb below a world-writable ancestor refused`,
`dot-dot path refused`, `archives directory that is world-writable refused`,
`root-only refusals never call cosign`; plugin tests
`test_world_writable_directory_refused`,
`test_world_writable_ancestor_refused`, `test_group_writable_file_refused`,
`test_root_only_dir_accepted`, `test_root_only_untrusted_owner`,
`test_root_only_rejects_unnormalised`, `test_symlink_refused_with_o_nofollow`;
install case E21 (apt and dnf: a package in a sticky world-writable
directory is refused). The check reads mode bits and owner only. It does
not inspect POSIX ACLs, and it trusts the owner the filesystem reports.
A filesystem a non-root user controls can report uid 0: a loop-mounted
image from `udisksctl` under `/media/$USER`, FUSE with `allow_other`, or
NFS with `no_root_squash` (POAM044-SEC-009, POAM-044 (c)). Install local
packages only from a local root filesystem without ACLs, staged in a
root-only directory such as `/root/pkgs`.

Install cosign as root into a root-only directory. POAM044-SEC-010: the
cosign binary and every directory above it (both the directory of the
link and of the resolved target) must be root-owned and not group- or
other-writable, else the gate exits 2 before cosign runs, `selftest
--full` fails, and postinst/%post warn. Residual: in a chain of two or
more symlinks only the first link's directories and the final target
are checked, not the directories of intermediate links. Unit tests
`cosign in a group-writable directory refused`, `untrusted cosign never
ran`, `symlink to a root-only cosign accepted`, `symlink to a cosign in
a group-writable directory refused`, `symlink in a group-writable
directory refused`, `group-writable cosign file refused`, `cosign owned
by another uid refused` (root only), `selftest --full flags an
untrusted cosign`. On Debian, `/usr/local/bin` may be `root:staff`
mode 2775: check with `stat -c '%U:%G %a' /usr/local/bin` and use a root-only
directory if it is group-writable.

## 4. Offline mirror

Each `publish` run uploads `usg-plat-repo-<tag>.tar` as a workflow
artifact of that run. The tarball is the whole repository tree: `apt/`,
`rpm/` and `releases/` with the newest 10 releases. It is **not** listed in
`SHA256SUMS` and has no signature of its own. It contains `SHA256SUMS`
and its bundle, so it cannot be listed in that file, and it is built after
signing. Treat the tarball as untrusted transport: the gate checks every
`platd` and `usg-plat-verify` package installed from it against the
signed `SHA256SUMS` inside it.

apt, with the tree unpacked at `/srv/usg-plat`:

```text
# /etc/apt/sources.list.d/usg-plat.sources
Types: deb
URIs: file:/srv/usg-plat/apt
Suites: stable
Components: main
Trusted: yes

# /etc/apt/preferences.d/usg-plat: both stanzas use the empty origin
Package: *
Pin: origin ""
Pin-Priority: -1

Package: platd usg-plat-verify
Pin: origin ""
Pin-Priority: 500
```

Then set `REPO_BASE=file:///srv/usg-plat` in `verify.conf`, so
`fetch-sums` reads `releases/<tag>/` from the mirror. `selftest --apt`
accepts a `file:` source only with `Pin: origin ""`, and it refuses
`http:` sources and a mix of https and `file:` sources (unit tests
`file: source with origin "" passes`, `file: source with origin REPO_HOST fails`,
`mixed https and file: sources fail`, `http: source with origin "" fails`,
`fetch-sums from a file:// base`). Both apt and dnf offline mirrors
pass `selftest`. No install case (E-series) covers an
install from a `file:` mirror yet. The release gate requires one install
from the offline tarball (`LINUX_VERIFICATION.md` L34, not run).

dnf: point `baseurl=file:///srv/usg-plat/rpm/$basearch` at the unpacked
tree and set `REPO_BASE=file:///srv/usg-plat` as above. `selftest --dnf`
accepts a `file:///path` `baseurl` and refuses `file://host`, `http:` and
https on another host (unit tests `selftest --dnf accepts a file:/// mirror`,
`selftest --dnf refuses file://host`, `selftest --dnf refuses http:`,
`selftest --dnf refuses https on another host`). Installing from the
unpacked tree with `dnf install ./platd-*.rpm` and the release's
`SHA256SUMS` beside it (E13) also works.

## 5. Downgrades

Downgrades of `platd` and `usg-plat-verify` are refused (E11). To allow
one run:

```sh
sudo USG_PLAT_ALLOW_DOWNGRADE=1 apt-get install --allow-downgrades platd=X.Y.Z-1
sudo USG_PLAT_ALLOW_DOWNGRADE=1 dnf downgrade platd
```

(E12.) `ALLOW_DOWNGRADE=1` in `verify.conf` allows downgrades permanently
(unit test `downgrade allowed with ALLOW_DOWNGRADE=1`;
`test_downgrade_allowed_by_conf`). Record either change in the host CM
baseline. A downgrade still has to pass the signature check. Setting
`USG_PLAT_ALLOW_DOWNGRADE=1` is logged at `authpriv.warning` by the apt
hook, and every downgrade it allows is logged at `authpriv.warning` by
the apt hook and the dnf plugin (POAM044-SEC-003; unit tests
`USG_PLAT_ALLOW_DOWNGRADE=1 is logged`, `override logged at authpriv.warning`,
`allowed downgrade logged`; plugin test `test_env_downgrade_override_logged`).
An unsafe or non-literal `verify.conf` never enables `ALLOW_DOWNGRADE`
(`test_writable_conf_does_not_enable_downgrade`).

Downgrade protection works only inside a single transaction: it compares
the installed version with the new one. If you remove the package and
then install an older one, or install an older version on a fresh host,
any older signed release is accepted, including an older
`usg-plat-verify` (POAM-044 (h), POAM044-SEC-006). Pin the version you approve
in your CM process.

The `USG_PLAT_VERIFY_*` path variables (`_CONF`, `_STATE`,
`_TRUSTED_ROOT`, `_PATH` and so on) and `TMPDIR` are test hooks. They are
honoured only with `USG_PLAT_VERIFY_TEST=1`. Otherwise they are unset
before anything runs, `PATH` is reset, and their presence is logged once
to stderr and `authpriv.warning` (POAM044-SEC-003). `_SUMS_DIR` is set by
the front ends for local files and is itself verified. The dnf plugin
passes `verify-pkg` an environment without these variables and sets only
`_SUMS_DIR` for `@commandline` packages. Unit tests
`overrides ignored without USG_PLAT_VERIFY_TEST=1`,
`overrides ignored: stand-in cosign never ran`,
`USG_PLAT_VERIFY_TEST=0 is not test mode`; plugin tests
`test_test_hooks_and_tmpdir_stripped`, `test_commandline_sets_only_sums_dir`.
Residual (POAM044-SEC-012): `USG_PLAT_VERIFY_TEST=1` in root's
environment re-enables the overrides on the apt path (the dnf plugin
ignores it). Keep `env_reset` for apt in sudoers and do not grant
`SETENV` or `env_keep` for `USG_PLAT_VERIFY_*`. When honoured, test
mode is announced on stderr and logged at `authpriv.warning` on every
run (unit tests `test mode is announced`,
`test mode logged at authpriv.warning`). postinst and %post use the
shared `root_only` check (POAM044-SEC-013; unit tests
`common block identical in postinst and %post`,
`common-exec block identical where cosign is checked`).

`verify.conf` and the pinned trusted root must pass the same root-only
check (POAM044-SEC-008). Otherwise `verify-pkg`, `fetch-sums` and
`selftest` exit 2 and the apt hook refuses. `status` warns and does not
read the file, and the package scripts read only a uid-0 file that group
and other cannot write. The dnf plugin refuses our packages when the file
is unsafe or holds a line that is not a literal assignment. Unit tests
`group-writable verify.conf: verify-pkg exit 2`,
`group-writable verify.conf: apt-hook refuses`,
`group-writable verify.conf: fetch-sums exit 2`,
`group-writable verify.conf: selftest exit 2`,
`conf refusals never call cosign`,
`verify.conf in a world-writable directory: exit 2`,
`other-writable trusted root: exit 2`,
`verify.conf owned by another uid: exit 2` (root only); plugin tests
`test_writable_conf_refuses`, `test_non_literal_conf_refuses`,
`test_conf_parser_matches_shell`.

cosign output is accepted only on exit 0 plus a line that is exactly
`Verified OK` (POAM044-SEC-007; unit tests
`cosign exit 0, exact Verified OK line, other noise accepted`,
`cosign exit 0 with only near-miss Verified OK lines refused`,
`cosign exit 0 without Verified OK`).

## 6. Alerting

Every decision goes to syslog with tag `usg-plat-verify`: refusals and
failed self-tests at `authpriv.err`, accepts at `authpriv.info`. Each
message is also printed to stderr (E09, E19; unit tests
`refusal logged at authpriv.err with tag`, `accept logged at authpriv.info`).
These are host records written by shell scripts. They are not `platd`
audit records and follow no `platd` log schema
(`docs/compliance/SIEM_LOGGING.md`).

| Signal | Where | Alert when |
|--------|-------|------------|
| journal | `SYSLOG_IDENTIFIER=usg-plat-verify`, `PRIORITY<=3` (`journalctl -t usg-plat-verify -p err`) | any record |
| `last-refusal` | `/var/lib/usg-plat-verify/last-refusal`: one line, `<UTC time> <name> <version> <reason>` | the file changes |
| counter | `/var/lib/usg-plat-verify/refusals_total` (apt and dnf; dnf plugin test `test_plugin_refusal_counted_and_exported`) | it increases |
| textfile metrics | `/var/lib/node_exporter/textfile_collector/usg-plat-verify.prom`, written only when that directory exists: `usg_plat_verify_refusals_total`, `usg_plat_verify_last_refusal_timestamp_seconds` | rate > 0 |
| automatic updates | `unattended-upgrades` / `dnf-automatic` exit status and logs | any failure |

These metrics come from the host. `platd`'s `/metrics` does not include
them. Record lines look like this:

```text
usg-plat-verify: refusing platd 0.3.1-1 amd64: cosign not found at /usr/local/bin/cosign (install it, see the install guide)
usg-plat-verify: accepted platd_0.3.1-1_amd64.deb (v0.3.1, sha256 <hex>)
usg-plat-verify: selftest: FAIL: /etc/apt/preferences.d/usg-plat has 'Pin: origin "https://192d-wing.github.io"'; ...
```

## 7. Runbook: a refusal blocks automatic updates

A refusal aborts the **whole** apt or dnf transaction. That includes
`unattended-upgrades` and `dnf-automatic` runs, so any distribution
security updates in the same run are not applied either (E06, E09;
POAM-044 (g)). The node keeps running its current `platd`.

1. Run `sudo usg-plat-verify status` and `sudo usg-plat-verify selftest`,
   then read the reason in `last-refusal` or in the journal.
2. Fix the cause. Common ones: cosign missing or too old; no
   `SHA256SUMS` cached for the tag (run `apt-get update`, or
   `/usr/libexec/usg-plat-verify/fetch-sums vX.Y.Z`); a stale trust root
   after a Sigstore key rotation (section 8); a tampered or unlisted
   package (treat it as an incident and do not override).
3. If distribution updates must go ahead first, hold usg-plat back and
   log it:

    ```sh
    sudo apt-mark hold platd usg-plat-verify      # later: apt-mark unhold ...
    # dnf: add to /etc/yum.repos.d/usg-plat.repo, remove when fixed
    excludepkgs=platd usg-plat-verify
    ```

4. Rerun the automatic update and check that it succeeds. Remove the hold
   once the gate accepts the package.

## 8. Trust root rotation

The trust root (`/usr/share/usg-plat-verify/trusted_root.json`, SHA-256
pinned in `deploy/verify/trusted_root.sha256`) is used offline only.
After Sigstore rotates its Fulcio, Rekor or CT keys, releases signed under
the new keys are refused by hosts with the old root (fail closed; R13
refuses a wrong root). Maintainers refresh the pin with
`make trusted-root-update`, reviewed in a PR. The `release` job fails
unless the root it fetches matches the pin. Hosts get the new root from
the next `usg-plat-verify` package. If the old root refuses that package,
bootstrap it again out of band (section 2). This is POAM-044 (f).

## What the gate does not cover

| Gap | Evidence | POAM |
|-----|----------|------|
| `dpkg -i` and `rpm -i` / `rpm -U` bypass the gate | E16 (GAP) | POAM-044 (c) |
| apt: an explicit `apt-get install foo=<ver>` installs a foreign name from the `Trusted: yes` source. The publish step refuses any name other than `platd`, `usg-plat-verify` and `usg-plat-pin-canary`. dnf `includepkgs` blocks this | E17 (GAP on apt, PASS on dnf) | POAM-044 (c) |
| Unsigned metadata: a frozen or rolled-back repository hides updates | design | POAM-044 (c) |
| dnf skips a plugin that fails to load and continues ungated; `selftest --dnf` detects it | unit tests above | POAM-044 (c) |
| dnf5 | not tested | POAM-044 (c) |
| root can remove or disable the gate | design | POAM-044 (c) |
| cosign must be installed and kept current by the operator | E05 | POAM-044 (c) |
| A stale trust root after a Sigstore rotation refuses new releases | R13 | POAM-044 (f) |
| One refusal aborts the whole transaction | E06 (GAP) | POAM-044 (g) |
| Downgrade check works only inside one transaction: remove then install an older version, or a fresh host, accepts any older signed release | design (POAM044-SEC-006) | POAM-044 (h) |
| Trust in GitHub OIDC and public Sigstore | design | POAM-044 (b) |

## Maintainers: publishing

- The `publish` job (tag only, `environment: release`,
  `concurrency: usg-plat-packages`) downloads the GitHub Release again and
  runs `scripts/verify-release.sh` on it. It then builds the tree with
  `deploy/ci/publish-packages.sh` and pushes to `192d-Wing/usg-plat-packages`
  `main`, which Pages serves. Untested until the first tag.
- Layout: `apt/dists/stable/` (unsigned `Release`, no `InRelease`),
  `apt/pool/main/`, `rpm/{x86_64,aarch64}/` (noarch packages are copied
  into both), `releases/vX.Y.Z/`. The newest 10 releases are kept; the
  canary is never pruned. A tag that is published again with a different
  `SHA256SUMS` is refused (`publish-packages.sh --self-test`).
- Immutability: a `platd` or `usg-plat-verify` package already in the tree
  under the same file name must be byte-identical (no-op), or the publish
  refuses before copying anything. `usg-plat-pin-canary` is matched by
  name, version and architecture (`0.0.0` `all`, `0.0.0-1.noarch`): the
  tree's copy is kept whatever its bytes, and any other canary version in
  the tree is refused (self-test cases in `publish-packages.sh --self-test`).
- The push retries up to 3 times on a non-fast-forward rejection, each
  time re-cloning and re-running `publish-packages.sh`. Other push errors
  fail at once. Untested until the first tag.
- `make ci-pins-check` (`deploy/ci/check-container-pins.sh`, part of
  `make check`) requires every container image to be pinned by digest with
  one digest per image, so the two Rocky 9 pins in `packages.yml` stay
  identical.
- `usg-plat-pin-canary` must be in the first publish. Without it,
  `apt-get update` fails on every gated host (section 3).
- Deploy key: an SSH key with write access on usg-plat-packages. Its
  private half is `PACKAGES_REPO_TOKEN`, a secret of the `release`
  environment only; no repository-level copy exists (POAM044-SEC-002).
  That environment admits `v*` tags only, and admins cannot bypass it.
  Ruleset 26701581 on usg-plat-packages blocks force-push and deletion
  of `main`. The job pins the github.com ed25519 host key and
  deletes the key file in an `always()` step. Rotation: create a new
  ed25519 key, add it as a write deploy key, replace the secret, delete
  the old deploy key, and record the change. Custody and rotation are
  organisational (no test).
