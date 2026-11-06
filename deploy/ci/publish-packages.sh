#!/bin/sh
# Add one signed usg-plat release to a checkout of 192d-Wing/usg-plat-packages
# (served by GitHub Pages at https://192d-wing.github.io/usg-plat-packages/).
#
#   publish-packages.sh --dist DIR --tag vX.Y.Z --repo DIR
#                       [--seed DIR] [--keep N] [--tar FILE] [--dry-run]
#   publish-packages.sh --self-test
#
# --dist holds the release files (the `release` job's dist/: packages,
# SHA256SUMS, SHA256SUMS.sigstore.json and per-file bundles). --repo is the
# working tree to update in place; the caller commits and pushes it (only on
# a v* tag). --seed (default deploy/ci/packages-repo) is copied to the
# repository root (README.md, .nojekyll). --dry-run accepts an unsigned dist
# and writes SHA256SUMS itself when it is missing (non-tag CI runs; nothing
# is signed or pushed). --tar writes the offline mirror tarball
# usg-plat-repo-<tag>.tar (the whole tree without .git).
#
# Layout written:
#   apt/pool/main/*.deb
#   apt/dists/stable/{Release,main/binary-{amd64,arm64}/Packages{,.gz}}
#                     (unsigned, no InRelease: sources use `Trusted: yes`,
#                     packages are verified at install by usg-plat-verify)
#   rpm/{x86_64,aarch64}/*.rpm + repodata/   (createrepo_c; the noarch
#                     usg-plat-verify and canary rpms are copied into each
#                     arch dir, so baseurl .../rpm/$basearch reaches them)
#   releases/<tag>/{SHA256SUMS,*.sigstore.json}   (read by fetch-sums)
#
# Refuses (exit 1, the tree may be partly written; the caller does not push):
#   - any package name other than platd, usg-plat-verify, usg-plat-pin-canary
#     (in the dist or anywhere in the tree: the apt source is `Trusted: yes`,
#     so a foreign name would be one `apt-get install foo=ver` away);
#   - a file name that is not the frozen grammar for its metadata;
#   - a platd / usg-plat-verify version that is not the tag;
#   - a package not listed in SHA256SUMS with its digest;
#   - a dist or tree without the canary (apt-get update on hosts fails
#     without it, by design);
#   - an existing releases/<tag>/ whose SHA256SUMS differs (releases are
#     immutable).
# Keeps the newest --keep (default 10) releases; older release dirs and the
# platd / usg-plat-verify packages of those versions are removed.
#
# Needs dpkg-deb, apt-ftparchive (apt-utils), rpm, createrepo_c, gzip, GNU tar.
# Exit: 0 ok, 1 refused or tool failure, 2 usage.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-14 (Signed Components), SI-7(15) (Code Authentication) -
#   publishes the signed SHA256SUMS the install-time gate verifies
# - NIST 800-53: CM-7 (Least Functionality) - only our package names, and the
#   pin canary, are ever published
# - NIST 800-53: AU-11 / SC-5 - bounded retention (newest 10 releases)
# POAM: POAM-044 (c) - repository metadata is unsigned by design; a frozen or
#   rolled-back mirror hides updates (it cannot install unsigned packages)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
NAMES_OK='platd usg-plat-verify usg-plat-pin-canary'
CANARY_DEB=usg-plat-pin-canary_0.0.0_all.deb
CANARY_RPM=usg-plat-pin-canary-0.0.0-1.noarch.rpm
DEB_ARCHES='amd64 arm64'
RPM_ARCHES='x86_64 aarch64'

die() { echo "publish-packages: $*" >&2; exit 2; }
refuse() { echo "publish-packages: REFUSED: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || refuse "$1 not found"; }

abs_dir() { (cd "$1" && pwd); }

# deb_meta FILE -> "name version arch"; rpm_meta FILE -> "name version release arch"
deb_meta() {
    printf '%s %s %s\n' "$(dpkg-deb -f "$1" Package)" "$(dpkg-deb -f "$1" Version)" "$(dpkg-deb -f "$1" Architecture)"
}
rpm_meta() { rpm -qp --nosignature --qf '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n' "$1" 2>/dev/null; }

name_ok() {
    # Own loop variable: sh has no locals and check_pkg uses $n.
    for ok_name in $NAMES_OK; do [ "$1" = "$ok_name" ] && return 0; done
    return 1
}

# check_pkg FILE TAG-or-empty: name allow-list and frozen file-name grammar.
# Prints the upstream version of a platd / usg-plat-verify package (empty
# for the canary).
check_pkg() {
    f=$1 b=$(basename "$1")
    case $b in
        *.deb)
            meta=$(deb_meta "$f") || refuse "$b: unreadable deb"
            read -r n v a x <<EOF
$meta
EOF
            [ -n "$a" ] && [ -z "$x" ] || refuse "$b: unreadable deb control"
            name_ok "$n" || refuse "$b: package name '$n' is not one of: $NAMES_OK"
            case $n in
                platd)
                    case $a in amd64 | arm64) ;; *) refuse "$b: platd arch '$a'" ;; esac
                    printf '%s\n' "$v" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+-[0-9]+' || refuse "$b: version '$v'"
                    want="platd_${v}_$a.deb" ;;
                usg-plat-verify)
                    [ "$a" = all ] || refuse "$b: usg-plat-verify arch '$a'"
                    printf '%s\n' "$v" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+-1' || refuse "$b: version '$v'"
                    want="usg-plat-verify_${v}_all.deb" ;;
                *) [ "$v" = 0.0.0 ] && [ "$a" = all ] || refuse "$b: canary $v $a"
                    want=$CANARY_DEB ;;
            esac
            [ "$b" = "$want" ] || refuse "$b: file name does not match its control fields (want $want)"
            ;;
        *.rpm)
            meta=$(rpm_meta "$f") || refuse "$b: unreadable rpm"
            read -r n v r a x <<EOF
$meta
EOF
            [ -n "$a" ] && [ -z "$x" ] || refuse "$b: unreadable rpm header"
            name_ok "$n" || refuse "$b: package name '$n' is not one of: $NAMES_OK"
            printf '%s\n' "$v" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || refuse "$b: version '$v'"
            printf '%s\n' "$r" | grep -Eqx '[0-9]+' || refuse "$b: release '$r'"
            case $n in
                platd) case $a in x86_64 | aarch64) ;; *) refuse "$b: platd arch '$a'" ;; esac ;;
                usg-plat-verify) [ "$a" = noarch ] && [ "$r" = 1 ] || refuse "$b: usg-plat-verify $r.$a" ;;
                *) [ "$v-$r.$a" = 0.0.0-1.noarch ] || refuse "$b: canary $v-$r.$a" ;;
            esac
            want="$n-$v-$r.$a.rpm"
            [ "$b" = "$want" ] || refuse "$b: file name does not match its header (want $want)"
            ;;
        *) refuse "$b: not a package" ;;
    esac
    [ "$n" = usg-plat-pin-canary ] || printf '%s\n' "${v%%-*}"
}

sort_tags() { sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | sed 's/^/v/'; }

# Upstream version from a platd / usg-plat-verify file name; empty otherwise.
file_version() {
    case $1 in
        "$CANARY_DEB" | "$CANARY_RPM") ;;
        platd_*.deb | usg-plat-verify_*.deb) v=${1#*_}; printf '%s\n' "${v%%-*}" ;;
        platd-*.rpm) v=${1#platd-}; printf '%s\n' "${v%%-*}" ;;
        usg-plat-verify-*.rpm) v=${1#usg-plat-verify-}; printf '%s\n' "${v%%-*}" ;;
        *) ;;
    esac
}

publish() {
    [ -n "$DIST" ] && [ -n "$TAG" ] && [ -n "$REPO" ] || die "--dist, --tag and --repo are required"
    printf '%s\n' "$TAG" | grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+' || die "tag '$TAG' is not vX.Y.Z"
    printf '%s\n' "$KEEP" | grep -Eqx '[1-9][0-9]*' || die "--keep must be a positive integer"
    [ -d "$DIST" ] || die "no dist directory $DIST"
    [ -d "$REPO" ] || die "no repository directory $REPO"
    DIST=$(abs_dir "$DIST")
    REPO=$(abs_dir "$REPO")
    [ "$REPO" != / ] || die "refusing / as the repository"
    for t in dpkg-deb apt-ftparchive rpm createrepo_c gzip sha256sum; do need "$t"; done
    ver=${TAG#v}

    # 1. Validate the whole dist before touching the tree.
    if [ ! -f "$DIST/SHA256SUMS" ]; then
        [ "$DRY_RUN" = 1 ] || refuse "SHA256SUMS missing in $DIST"
        (cd "$DIST" && find . -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) | sed 's|^\./||' |
            LC_ALL=C sort | xargs sha256sum --) >"$DIST/SHA256SUMS"
        echo "publish-packages: dry run: wrote an unsigned $DIST/SHA256SUMS"
    fi
    [ "$DRY_RUN" = 1 ] || [ -f "$DIST/SHA256SUMS.sigstore.json" ] || refuse "SHA256SUMS.sigstore.json missing in $DIST"
    pkgs=$(cd "$DIST" && find . -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) | sed 's|^\./||' | LC_ALL=C sort)
    [ -n "$pkgs" ] || refuse "no packages in $DIST"
    for b in $pkgs; do
        v=$(check_pkg "$DIST/$b") || exit 1
        [ -z "$v" ] || [ "$v" = "$ver" ] || refuse "$b: version $v is not tag $TAG"
        d=$(sha256sum -- "$DIST/$b" | cut -d' ' -f1)
        grep -qxF "$d  $b" "$DIST/SHA256SUMS" || refuse "$b: not in SHA256SUMS with digest $d"
    done
    for c in $CANARY_DEB $CANARY_RPM; do
        [ -f "$DIST/$c" ] || refuse "$c missing from the dist (hosts fail apt-get update without the canary)"
    done
    for a in $DEB_ARCHES; do
        ls "$DIST"/platd_"$ver"-*_"$a".deb >/dev/null 2>&1 ||
            refuse "no platd $a deb for $TAG"
    done
    for a in $RPM_ARCHES; do
        ls "$DIST"/platd-"$ver"-*."$a".rpm >/dev/null 2>&1 || refuse "no platd $a rpm for $TAG"
    done
    rel=$REPO/releases/$TAG
    if [ -d "$rel" ]; then
        cmp -s "$rel/SHA256SUMS" "$DIST/SHA256SUMS" || refuse "releases/$TAG exists with a different SHA256SUMS (releases are immutable)"
        echo "publish-packages: releases/$TAG already published with the same SHA256SUMS; re-indexing"
    fi

    # 2. Copy.
    mkdir -p "$REPO/apt/pool/main" "$rel"
    for a in $RPM_ARCHES; do mkdir -p "$REPO/rpm/$a"; done
    for b in $pkgs; do
        case $b in
            *.deb) cp -- "$DIST/$b" "$REPO/apt/pool/main/$b" ;;
            *.noarch.rpm) for a in $RPM_ARCHES; do cp -- "$DIST/$b" "$REPO/rpm/$a/$b"; done ;;
            *.rpm) a=${b%.rpm}; a=${a##*.}; cp -- "$DIST/$b" "$REPO/rpm/$a/$b" ;;
        esac
    done
    cp -- "$DIST/SHA256SUMS" "$rel/SHA256SUMS"
    for s in "$DIST"/*.sigstore.json; do
        [ -f "$s" ] && cp -- "$s" "$rel/"
    done
    if [ -d "$SEED" ]; then
        (cd "$SEED" && find . -type f) | while read -r f; do
            mkdir -p "$REPO/$(dirname "$f")"
            cp -- "$SEED/$f" "$REPO/$f"
        done
    fi

    # 3. Retention: newest KEEP release dirs, and their packages.
    tags=$(cd "$REPO/releases" && find . -mindepth 1 -maxdepth 1 -type d -name 'v*' | sed 's|^\./||' |
        grep -Ex 'v[0-9]+\.[0-9]+\.[0-9]+' | sort_tags)
    n=$(printf '%s\n' "$tags" | grep -c . || true)
    keep_tags=$(printf '%s\n' "$tags" | tail -n "$KEEP")
    if [ "$n" -gt "$KEEP" ]; then
        printf '%s\n' "$tags" | head -n "$((n - KEEP))" | while read -r t; do
            # $t matched vX.Y.Z above; REPO is absolute and not /.
            echo "publish-packages: pruning releases/$t"
            rm -r -- "${REPO:?}/releases/$t"
        done
    fi
    for d in "$REPO/apt/pool/main" "$REPO"/rpm/x86_64 "$REPO"/rpm/aarch64; do
        (cd "$d" && find . -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) | sed 's|^\./||') |
            while read -r b; do
                v=$(file_version "$b")
                [ -n "$v" ] || continue
                printf '%s\n' "$keep_tags" | grep -qxF "v$v" && continue
                echo "publish-packages: pruning $b"
                rm -f -- "$d/$b"
            done
    done

    # 4. The whole tree: our names only, canary present.
    found=$(find "$REPO" -path "$REPO/.git" -prune -o -type f \( -name '*.deb' -o -name '*.rpm' \) -print |
        grep -v -e "^$REPO/apt/pool/main/[^/]*$" -e "^$REPO/rpm/x86_64/[^/]*$" -e "^$REPO/rpm/aarch64/[^/]*$" || true)
    [ -z "$found" ] || refuse "packages outside apt/pool/main and rpm/<arch>: $found"
    for d in "$REPO/apt/pool/main" "$REPO/rpm/x86_64" "$REPO/rpm/aarch64"; do
        for f in "$d"/*.deb "$d"/*.rpm; do
            [ -f "$f" ] || continue
            check_pkg "$f" >/dev/null || exit 1
        done
    done
    [ -f "$REPO/apt/pool/main/$CANARY_DEB" ] || refuse "tree has no $CANARY_DEB"
    for a in $RPM_ARCHES; do
        [ -f "$REPO/rpm/$a/$CANARY_RPM" ] || refuse "rpm/$a has no $CANARY_RPM"
        ls "$REPO/rpm/$a"/usg-plat-verify-*.noarch.rpm >/dev/null 2>&1 || refuse "rpm/$a has no usg-plat-verify rpm"
    done

    # 5. Indexes (regenerated from the pool every time).
    (
        cd "$REPO/apt"
        for a in $DEB_ARCHES; do
            mkdir -p "dists/stable/main/binary-$a"
            apt-ftparchive --arch "$a" packages pool/main >"dists/stable/main/binary-$a/Packages"
            gzip -9n -c "dists/stable/main/binary-$a/Packages" >"dists/stable/main/binary-$a/Packages.gz"
            grep -qx 'Package: usg-plat-pin-canary' "dists/stable/main/binary-$a/Packages" ||
                refuse "binary-$a/Packages has no canary"
        done
        rm -f dists/stable/Release dists/stable/InRelease dists/stable/Release.gpg
        apt-ftparchive \
            -o APT::FTPArchive::Release::Origin=usg-plat \
            -o APT::FTPArchive::Release::Label=usg-plat \
            -o APT::FTPArchive::Release::Suite=stable \
            -o APT::FTPArchive::Release::Codename=stable \
            -o "APT::FTPArchive::Release::Architectures=$DEB_ARCHES" \
            -o APT::FTPArchive::Release::Components=main \
            -o "APT::FTPArchive::Release::Description=usg-plat (unsigned; packages verified at install by usg-plat-verify)" \
            release dists/stable >"$REPO/apt/Release.tmp"
        mv -f -- "$REPO/apt/Release.tmp" dists/stable/Release
    )
    for a in $RPM_ARCHES; do
        createrepo_c --quiet --general-compress-type=gz "$REPO/rpm/$a" >/dev/null
        [ -f "$REPO/rpm/$a/repodata/repomd.xml" ] || refuse "createrepo_c wrote no rpm/$a/repodata"
    done

    if [ -n "$TAR" ]; then
        case $TAR in /*) ;; *) TAR=$(pwd)/$TAR ;; esac
        : "${SOURCE_DATE_EPOCH:=$(date +%s)}"
        tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
            --exclude=./.git -cf "$TAR" -C "$REPO" .
        tar -tf "$TAR" | grep -qx "./releases/$TAG/SHA256SUMS" || refuse "tarball lacks releases/$TAG"
        echo "publish-packages: $TAR"
    fi
    echo "publish-packages: $TAG published into $REPO (releases kept: $(printf '%s\n' "$keep_tags" | tr '\n' ' '))"
}

# ---- self-test ----------------------------------------------------------

fx_deb() { # fx_deb OUT NAME VERSION ARCH
    r=$st/debroot
    mkdir -p "$r/DEBIAN"
    printf 'Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: test\nDescription: fixture\n' \
        "$2" "$3" "$4" >"$r/DEBIAN/control"
    dpkg-deb --root-owner-group -b "$r" "$1/${2}_${3}_$4.deb" >/dev/null
}
fx_rpm() { # fx_rpm OUT NAME VERSION ARCH
    # BuildArch only for noarch: an arch rpm is built with --target, which
    # also works on a host of the other architecture.
    ba=
    [ "$4" = noarch ] && ba='BuildArch: noarch'
    cat >"$st/fx.spec" <<EOF
Name: $2
Version: $3
Release: 1
Summary: fixture
License: Apache-2.0
$ba
%description
fixture
%files
EOF
    rpmbuild -bb --quiet --target "$4" --define "_topdir $st/rpmtop" --define "_rpmdir $1" \
        --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" "$st/fx.spec" \
        >"$st/rpmbuild.log" 2>&1 || { cat "$st/rpmbuild.log" >&2; return 1; }
}
fx_dist() { # fx_dist DIR VERSION -> a full release dist
    mkdir -p "$1"
    fx_deb "$1" platd "$2-1" amd64
    fx_deb "$1" platd "$2-1" arm64
    fx_deb "$1" usg-plat-verify "$2-1" all
    fx_deb "$1" usg-plat-pin-canary 0.0.0 all
    fx_rpm "$1" platd "$2" x86_64
    fx_rpm "$1" platd "$2" aarch64
    fx_rpm "$1" usg-plat-verify "$2" noarch
    fx_rpm "$1" usg-plat-pin-canary 0.0.0 noarch
    fx_sums "$1"
}
fx_sums() {
    (cd "$1" && rm -f SHA256SUMS && sha256sum -- *.deb *.rpm >SHA256SUMS.new && mv SHA256SUMS.new SHA256SUMS)
    printf '{"fixture": "bundle"}\n' >"$1/SHA256SUMS.sigstore.json"
}

self_test() {
    for t in dpkg-deb apt-ftparchive rpm rpmbuild createrepo_c tar; do
        command -v "$t" >/dev/null 2>&1 || {
            echo "FAIL self-test needs $t (apt-get install dpkg-dev apt-utils rpm createrepo-c)"
            return 1
        }
    done
    st=$(mktemp -d)
    trap 'rm -rf -- "$st"' EXIT INT TERM
    rc=0
    ok() { echo "ok   $1"; }
    bad() { echo "FAIL $1"; rc=1; }
    run() { # run EXPECTED_RC LOG ARGS... ; checks rc and returns the log name
        e=$1 log=$2; shift 2
        r=0
        sh "$here/publish-packages.sh" "$@" >"$log" 2>&1 || r=$?
        [ "$r" = "$e" ] || { echo "     (rc $r, want $e)"; sed 's/^/     | /' "$log"; return 1; }
    }
    repo=$st/repo
    mkdir -p "$repo" "$st/seed"
    printf 'seed\n' >"$st/seed/README.md"
    : >"$st/seed/.nojekyll"

    # Eleven releases into one tree: the newest ten survive.
    i=1
    while [ $i -le 11 ]; do
        fx_dist "$st/d$i" "0.$i.0"
        run 0 "$st/log$i" --dist "$st/d$i" --tag "v0.$i.0" --repo "$repo" --seed "$st/seed" ||
            { bad "publish v0.$i.0"; break; }
        i=$((i + 1))
    done
    n=$(find "$repo/releases" -mindepth 1 -maxdepth 1 -type d | wc -l)
    if [ "$n" -eq 10 ] && [ ! -d "$repo/releases/v0.1.0" ] && [ -d "$repo/releases/v0.11.0" ] &&
        [ ! -f "$repo/apt/pool/main/platd_0.1.0-1_amd64.deb" ] && [ ! -f "$repo/rpm/x86_64/platd-0.1.0-1.x86_64.rpm" ] &&
        [ -f "$repo/apt/pool/main/platd_0.2.0-1_amd64.deb" ]; then
        ok "retention keeps the newest 10 releases and their packages"
    else
        bad "retention ($n release dirs)"
    fi
    p=$repo/apt/dists/stable/main/binary-arm64/Packages
    if grep -qx 'Version: 0.11.0-1' "$p" && grep -qx 'Package: usg-plat-pin-canary' "$p" &&
        grep -qx 'Package: usg-plat-verify' "$p" && ! grep -q 'Architecture: amd64' "$p" &&
        ! grep -q '0\.1\.0-1' "$p" && [ -f "$p.gz" ] &&
        grep -qx 'Suite: stable' "$repo/apt/dists/stable/Release" &&
        grep -q 'main/binary-arm64/Packages' "$repo/apt/dists/stable/Release" &&
        [ ! -e "$repo/apt/dists/stable/InRelease" ]; then
        ok "apt indexes regenerated (arm64 + all, canary, unsigned Release)"
    else
        bad "apt indexes"
    fi
    good=1
    for a in x86_64 aarch64; do
        prim=$(find "$repo/rpm/$a/repodata" -name '*primary.xml.gz')
        if [ -z "$prim" ] || ! gzip -dc "$prim" >"$st/primary-$a.xml"; then good=0; continue; fi
        for want in "<name>platd</name>" "<name>usg-plat-verify</name>" "<name>usg-plat-pin-canary</name>"; do
            grep -qF "$want" "$st/primary-$a.xml" || good=0
        done
        grep -q 'ver="0.1.0"' "$st/primary-$a.xml" && good=0
        [ -f "$repo/rpm/$a/usg-plat-verify-0.11.0-1.noarch.rpm" ] || good=0
    done
    if [ "$good" = 1 ]; then ok "rpm repodata per arch, noarch rpms in each arch dir"; else bad "rpm repodata"; fi
    if [ -f "$repo/README.md" ] && [ -f "$repo/.nojekyll" ]; then ok "seed files copied"; else bad "seed files"; fi

    # Re-publishing the same release is idempotent; a changed one is refused.
    if run 0 "$st/re" --dist "$st/d11" --tag v0.11.0 --repo "$repo" --seed "$st/seed"; then
        ok "re-publish with identical SHA256SUMS"
    else bad "re-publish identical"; fi
    cp -R "$st/d11" "$st/d11b"
    printf '%s  extra\n' 0000000000000000000000000000000000000000000000000000000000000000 >>"$st/d11b/SHA256SUMS"
    if run 1 "$st/imm" --dist "$st/d11b" --tag v0.11.0 --repo "$repo" && grep -q immutable "$st/imm"; then
        ok "changed SHA256SUMS for a published tag refused"
    else bad "immutability"; fi

    # Tarball holds releases/<tag>/.
    fx_dist "$st/d12" 0.12.0
    if run 0 "$st/tar" --dist "$st/d12" --tag v0.12.0 --repo "$repo" --tar "$st/usg-plat-repo-v0.12.0.tar" &&
        tar -tf "$st/usg-plat-repo-v0.12.0.tar" | grep -qx './releases/v0.12.0/SHA256SUMS.sigstore.json' &&
        ! tar -tf "$st/usg-plat-repo-v0.12.0.tar" | grep -q '^\./\.git'; then
        ok "tarball contains releases/<tag>/"
    else bad "tarball"; fi

    # Refusals (each against a fresh copy of a good dist and an empty tree).
    refusal() { # refusal LABEL GREP MUTATE-COMMANDS
        label=$1 pat=$2 mut=$3
        rm -rf -- "$st/x" "$st/xr"
        cp -R "$st/d12" "$st/x"
        mkdir -p "$st/xr"
        (cd "$st/x" && eval "$mut")
        if run 1 "$st/xlog" --dist "$st/x" --tag v0.12.0 --repo "$st/xr" && grep -q "$pat" "$st/xlog"; then
            ok "$label refused"
        else
            bad "$label"
            sed 's/^/     | /' "$st/xlog"
        fi
    }
    fx_deb "$st" openssl 99.0 amd64
    fx_rpm "$st" openssl 99.0 x86_64
    refusal "foreign deb name" "package name 'openssl'" "cp -- '$st/openssl_99.0_amd64.deb' . && fx_sums ."
    refusal "foreign rpm name" "package name 'openssl'" "cp -- '$st/openssl-99.0-1.x86_64.rpm' . && fx_sums ."
    refusal "foreign deb renamed to an allowed file name" "package name 'openssl'" \
        "cp -- '$st/openssl_99.0_amd64.deb' platd_0.12.0-1_amd64.deb && fx_sums ."
    refusal "dist without the deb canary" "$CANARY_DEB missing" "rm -f -- $CANARY_DEB && fx_sums ."
    refusal "dist without the rpm canary" "$CANARY_RPM missing" "rm -f -- $CANARY_RPM && fx_sums ."
    refusal "digest not in SHA256SUMS" "not in SHA256SUMS" "printf x >>platd_0.12.0-1_arm64.deb"
    refusal "missing bundle" "sigstore.json missing" "rm -f -- SHA256SUMS.sigstore.json"
    refusal "version other than the tag" "is not tag" \
        "rm -f -- usg-plat-verify_0.12.0-1_all.deb && fx_deb . usg-plat-verify 0.11.0-1 all && fx_sums ."
    refusal "file name not matching its header" "does not match" \
        "mv -- platd-0.12.0-1.x86_64.rpm platd-0.12.0-2.x86_64.rpm && fx_sums ."

    # A foreign package already in the tree is refused.
    rm -rf -- "$st/xr"
    mkdir -p "$st/xr/apt/pool/main"
    cp -- "$st/openssl_99.0_amd64.deb" "$st/xr/apt/pool/main/"
    if run 1 "$st/xlog" --dist "$st/d12" --tag v0.12.0 --repo "$st/xr" && grep -q "package name 'openssl'" "$st/xlog"; then
        ok "foreign package already in the tree refused"
    else bad "foreign package in tree"; fi

    # Dry run: unsigned dist, SHA256SUMS written, no bundle needed.
    rm -rf -- "$st/x" "$st/xr"
    cp -R "$st/d12" "$st/x"
    rm -f -- "$st/x/SHA256SUMS" "$st/x/SHA256SUMS.sigstore.json"
    mkdir -p "$st/xr"
    if run 0 "$st/dry" --dry-run --dist "$st/x" --tag v0.12.0 --repo "$st/xr" &&
        [ -f "$st/xr/releases/v0.12.0/SHA256SUMS" ] && [ -f "$st/xr/apt/dists/stable/Release" ]; then
        ok "dry run on an unsigned dist"
    else bad "dry run"; fi
    if run 2 "$st/use" --dist "$st/x" --tag 0.12.0 --repo "$st/xr"; then ok "bad tag is a usage error"; else bad "bad tag"; fi

    rm -rf -- "$st"
    trap - EXIT INT TERM
    [ "$rc" = 0 ] && echo "publish-packages: self-test passed" || echo "publish-packages: self-test FAILED"
    return "$rc"
}

DIST='' TAG='' REPO='' TAR='' KEEP=10 DRY_RUN=0
SEED=$here/packages-repo
while [ $# -gt 0 ]; do
    case $1 in
        --dist | --tag | --repo | --seed | --keep | --tar)
            [ $# -ge 2 ] || die "$1 needs a value"
            case $1 in
                --dist) DIST=$2 ;; --tag) TAG=$2 ;; --repo) REPO=$2 ;;
                --seed) SEED=$2 ;; --keep) KEEP=$2 ;; --tar) TAR=$2 ;;
            esac
            shift ;;
        --dry-run) DRY_RUN=1 ;;
        --self-test) self_test; exit $? ;;
        -h | --help) sed -n '2,45p' "$0"; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done
publish
