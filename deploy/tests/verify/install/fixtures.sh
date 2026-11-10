#!/bin/sh
# Build the throwaway fixtures for the install-time gate tests (run.sh).
#
#   fixtures.sh [--deps] --out DIR --verify-dir DIR
#
# --verify-dir holds the usg-plat-verify .deb and .rpm built by
# `make verify-pkg` (target/verify). --deps first installs the build tools
# (Debian 12: dpkg-dev apt-utils rpm createrepo-c openssl); run.sh runs this
# script in a Debian 12 builder container. DIR must not exist yet.
#
# Output under DIR (layouts as plan-v3 §2 and deploy/ci/publish-packages.sh):
#   versions.env          P1 P2 (in the repo), P3 (unlisted), P4 (local only) and VV (gate version)
#   stub/cosign           stand-in cosign (see below)
#   tls/                  test CA and the usg-plat.test server cert and key
#   verify/               copies of the usg-plat-verify .deb and .rpm
#   www/usg-plat-packages/
#     apt/pool/main/*.deb, apt/dists/stable/{Release,main/binary-{amd64,arm64}/Packages{,.gz}}
#     rpm/{x86_64,aarch64}/*.rpm + repodata (createrepo_c; noarch copied per arch)
#     releases/v<P1>/, releases/v<P2>/   SHA256SUMS + SHA256SUMS.sigstore.json
#   distro/apt (flat), distro/rpm        an unrelated "distro" repository:
#                                        usg-test-hello, usg-test-extra
#   local/     platd <P4> (release not in the repo) (all arches) with sibling SHA256SUMS + bundle (./x installs)
#   tamper/    the same names, one payload byte changed (.rpm rebuilt, see below)
#   badsums/   good packages, SHA256SUMS with one extra line (signature no longer matches)
#   unlisted/  platd <P3>, in no SHA256SUMS (dpkg -i / rpm -U bypass)
#   submirror/usg-plat-packages/  www copy with substitute platd <P2> packages and
#              regenerated indexes (file: mirror substitution, E23)
#
# The usg-plat repository also carries usg-plat-pin-canary 0.0.0 and, to
# simulate a compromised Pages site, usg-test-foreign 99.0 (a foreign name
# the pin and includepkgs must hide; `pkg=ver` on apt is a recorded residual).
#
# Real keyless signing cannot run here, so SHA256SUMS.sigstore.json is a stub
# "bundle" that records the SHA-256 of SHA256SUMS and the signer identity; the
# stub cosign accepts verify-blob only when both match and refuses the regexp
# identity form and the offline flag. Real cosign runs in real-release.sh.
#
# Exit: 0 ok; 1 build failure; 2 usage.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-7(15), CM-14 -
#   fixtures for the install-time gate tests (POAM-044 (c))
set -eu

IDP=https://github.com/192d-Wing/usg-plat/.github/workflows/packages.yml@refs/tags/
MARKER=USGPLAT-FIXTURE-PAYLOAD-A

die() { echo "fixtures: $*" >&2; exit 2; }

out='' vdir='' deps=0
while [ $# -gt 0 ]; do
    case $1 in
        --deps) deps=1 ;;
        --out) [ $# -ge 2 ] || die "--out needs a directory"; out=$2; shift ;;
        --verify-dir) [ $# -ge 2 ] || die "--verify-dir needs a directory"; vdir=$2; shift ;;
        *) die "usage: fixtures.sh [--deps] --out DIR --verify-dir DIR" ;;
    esac
    shift
done
[ -n "$out" ] && [ -n "$vdir" ] || die "usage: fixtures.sh [--deps] --out DIR --verify-dir DIR"
[ ! -e "$out" ] || die "$out already exists"

if [ $deps -eq 1 ]; then
    export DEBIAN_FRONTEND=noninteractive
    # shellcheck disable=SC2086 # APT_OPTS is a list of options
    apt-get ${APT_OPTS:-} update >/dev/null
    # shellcheck disable=SC2086
    apt-get ${APT_OPTS:-} install -y --no-install-recommends \
        dpkg-dev apt-utils rpm createrepo-c openssl >/dev/null
fi
for t in dpkg-deb apt-ftparchive rpmbuild createrepo_c openssl sha256sum gzip; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done

# --- gate packages (make verify-pkg) ---------------------------------------------
vdeb='' vrpm=''
for f in "$vdir"/usg-plat-verify_*-1_all.deb; do [ -f "$f" ] && vdeb=$f; done
for f in "$vdir"/usg-plat-verify-*-1.noarch.rpm; do [ -f "$f" ] && vrpm=$f; done
[ -n "$vdeb" ] && [ -n "$vrpm" ] || die "no usg-plat-verify .deb/.rpm in $vdir (run make verify-pkg)"
VV=${vdeb##*/usg-plat-verify_}
VV=${VV%-1_all.deb}
printf '%s\n' "$VV" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || die "cannot read the gate version from $vdeb"
[ -f "$vdir/usg-plat-verify-$VV-1.noarch.rpm" ] || die "deb and rpm versions differ in $vdir"
P1=$VV
P2=${VV%.*}.$((${VV##*.} + 1))
P3=${VV%.*}.$((${VV##*.} + 2))
P4=${VV%.*}.$((${VV##*.} + 3))

mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$out/.build
mkdir -p "$work" "$out/stub" "$out/tls" "$out/verify" "$out/local" "$out/tamper" \
    "$out/badsums" "$out/unlisted" "$out/distro/apt" "$out/distro/rpm"
www=$out/www/usg-plat-packages
mkdir -p "$www/apt/pool/main" "$www/rpm/x86_64" "$www/rpm/aarch64" "$www/releases"
cp -- "$vdeb" "$vrpm" "$out/verify/"
printf 'P1=%s\nP2=%s\nP3=%s\nP4=%s\nVV=%s\n' "$P1" "$P2" "$P3" "$P4" "$VV" >"$out/versions.env"

# --- dummy packages ----------------------------------------------------------------
# mkdeb NAME VERSION ARCH OUTDIR [DEPENDS]: no compression, so a one-byte
# payload change keeps the archive well formed.
mkdeb() {
    r=$work/deb-$1-$2-$3
    mkdir -p "$r/DEBIAN" "$r/usr/share/doc/$1"
    {
        echo "Package: $1"
        echo "Version: $2"
        echo "Architecture: $3"
        echo "Maintainer: usg-plat test fixtures <noreply@example.invalid>"
        if [ -n "${5:-}" ]; then echo "Depends: $5"; fi
        echo "Description: usg-plat install-test fixture (no payload)"
    } >"$r/DEBIAN/control"
    printf '%s %s %s\n' "$MARKER" "$1" "$2" >"$r/usr/share/doc/$1/FIXTURE"
    dpkg-deb --root-owner-group -Znone -b "$r" "$4/${1}_${2}_${3}.deb" >/dev/null
}

# mkrpm NAME VERSION ARCH OUTDIR [REQUIRES]: uncompressed payload, release 1.
mkrpm() {
    top=$work/rpm-$1-$2-$3
    mkdir -p "$top/SPECS" "$top/RPMS"
    {
        echo '%global debug_package %{nil}'
        echo '%global __os_install_post %{nil}'
        echo '%define _binary_payload w0.ufdio'
        echo "Name: $1"
        echo "Version: $2"
        echo 'Release: 1'
        echo 'Summary: usg-plat install-test fixture (no payload)'
        echo 'License: Apache-2.0'
        if [ "$3" = noarch ]; then echo 'BuildArch: noarch'; fi
        if [ -n "${5:-}" ]; then echo "Requires: $5"; fi
        echo '%description'
        echo 'usg-plat install-test fixture.'
        echo '%install'
        echo "mkdir -p %{buildroot}/usr/share/doc/$1"
        echo "echo '$MARKER $1 $2' > %{buildroot}/usr/share/doc/$1/FIXTURE"
        echo '%files'
        echo "/usr/share/doc/$1/FIXTURE"
    } >"$top/SPECS/$1.spec"
    if [ "$3" = noarch ]; then tgt=''; else tgt="--target $3"; fi
    # shellcheck disable=SC2086 # tgt is empty or two words
    rpmbuild -bb --quiet $tgt \
        --define "_topdir $top" \
        --define "_rpmdir $top/RPMS" \
        --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
        "$top/SPECS/$1.spec" >"$top/build.log" 2>&1 || {
        cat "$top/build.log" >&2
        echo "fixtures: rpmbuild failed for $1 $2 $3" >&2
        exit 1
    }
    cp -- "$top/RPMS/$1-$2-1.$3.rpm" "$4/"
}

pool=$www/apt/pool/main
for v in "$P1" "$P2"; do
    for a in amd64 arm64; do mkdeb platd "$v-1" "$a" "$pool" usg-plat-verify; done
    for a in x86_64 aarch64; do mkrpm platd "$v" "$a" "$www/rpm/$a" usg-plat-verify; done
done
cp -- "$vdeb" "$pool/"
mkdeb usg-plat-pin-canary 0.0.0 all "$pool"
mkdeb usg-test-foreign 99.0 all "$pool"
mkrpm usg-plat-pin-canary 0.0.0 noarch "$work"
mkrpm usg-test-foreign 99.0 noarch "$work"
for a in x86_64 aarch64; do
    cp -- "$vrpm" "$work/usg-plat-pin-canary-0.0.0-1.noarch.rpm" \
        "$work/usg-test-foreign-99.0-1.noarch.rpm" "$www/rpm/$a/"
done
for a in amd64 arm64; do mkdeb platd "$P3-1" "$a" "$out/unlisted" usg-plat-verify; done
for a in x86_64 aarch64; do mkrpm platd "$P3" "$a" "$out/unlisted" usg-plat-verify; done
for n in usg-test-hello usg-test-extra; do
    mkdeb "$n" 1.0 all "$out/distro/apt"
    mkrpm "$n" 1.0 noarch "$out/distro/rpm"
done

# --- SHA256SUMS and stub bundles ------------------------------------------------------
sign() { # DIR TAG
    h=$(sha256sum -- "$1/SHA256SUMS" | cut -d' ' -f1)
    printf '{"mediaType":"application/x.usg-plat-test.stub-bundle","sha256":"%s","identity":"%s%s"}\n' \
        "$h" "$IDP" "$2" >"$1/SHA256SUMS.sigstore.json"
}
mksums() { # DIR FILE...
    d=$1
    shift
    mkdir -p "$d"
    for f in "$@"; do
        h=$(sha256sum -- "$f" | cut -d' ' -f1)
        printf '%s  %s\n' "$h" "${f##*/}"
    done >"$d/SHA256SUMS"
}
mksums "$www/releases/v$P1" "$pool/platd_$P1-1_amd64.deb" "$pool/platd_$P1-1_arm64.deb" \
    "$www/rpm/x86_64/platd-$P1-1.x86_64.rpm" "$www/rpm/aarch64/platd-$P1-1.aarch64.rpm" "$vdeb" "$vrpm"
sign "$www/releases/v$P1" "v$P1"
mksums "$www/releases/v$P2" "$pool/platd_$P2-1_amd64.deb" "$pool/platd_$P2-1_arm64.deb" \
    "$www/rpm/x86_64/platd-$P2-1.x86_64.rpm" "$www/rpm/aarch64/platd-$P2-1.aarch64.rpm"
sign "$www/releases/v$P2" "v$P2"

# Local installs use P4, a release that is not in the repository: with the
# same version in the repository, apt fetches the repository copy instead of
# the ./x file.
p4=$work/p4
mkdir -p "$p4"
for a in amd64 arm64; do mkdeb platd "$P4-1" "$a" "$p4" usg-plat-verify; done
for a in x86_64 aarch64; do mkrpm platd "$P4" "$a" "$p4" usg-plat-verify; done
mksums "$p4" "$p4"/*.deb "$p4"/*.rpm
sign "$p4" "v$P4"
for d in local tamper badsums; do
    cp -- "$p4"/*.deb "$p4"/*.rpm "$p4/SHA256SUMS" "$p4/SHA256SUMS.sigstore.json" "$out/$d/"
done
# tamper/ .deb: flip the last byte of the payload marker (A -> B); dpkg has no
# payload digest, so the archive still installs without the gate. tamper/
# .rpm: rpm checks its own payload digest before the gate runs, so the rpm is
# rebuilt with that one byte changed (same NEVRA, consistent rpm digests,
# different SHA-256).
for f in "$out"/tamper/*.deb; do
    off=$(grep -abo "$MARKER" "$f" | head -n 1 | cut -d: -f1)
    [ -n "$off" ] || { echo "fixtures: no payload marker in $f" >&2; exit 1; }
    off=$((off + ${#MARKER} - 1))
    printf 'B' | dd of="$f" bs=1 seek="$off" conv=notrunc 2>/dev/null
done
MARKER=USGPLAT-FIXTURE-PAYLOAD-B
for a in x86_64 aarch64; do mkrpm platd "$P4" "$a" "$out/tamper" usg-plat-verify; done
for f in "$out"/tamper/*.deb "$out"/tamper/*.rpm; do
    if cmp -s "$f" "$out/local/${f##*/}"; then
        echo "fixtures: tampering $f changed nothing" >&2
        exit 1
    fi
done
# badsums/: SHA256SUMS gains a line after signing.
printf '%064d  evil_%s-1_amd64.deb\n' 0 "$P4" >>"$out/badsums/SHA256SUMS"

# --- repository indexes -----------------------------------------------------------------
(
    cd "$www/apt"
    for a in amd64 arm64; do
        mkdir -p "dists/stable/main/binary-$a"
        apt-ftparchive --arch "$a" packages pool/main >"dists/stable/main/binary-$a/Packages"
        gzip -9nk "dists/stable/main/binary-$a/Packages"
    done
    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin=usg-plat \
        -o APT::FTPArchive::Release::Label=usg-plat \
        -o APT::FTPArchive::Release::Suite=stable \
        -o APT::FTPArchive::Release::Codename=stable \
        -o "APT::FTPArchive::Release::Architectures=amd64 arm64" \
        -o APT::FTPArchive::Release::Components=main \
        release dists/stable >"$work/Release"
    mv -- "$work/Release" dists/stable/Release
)
for a in x86_64 aarch64; do createrepo_c -q "$www/rpm/$a"; done
(
    cd "$out/distro/apt"
    apt-ftparchive packages . >Packages
    apt-ftparchive -o APT::FTPArchive::Release::Origin=usgtest-distro release . >"$work/Release"
    mv -- "$work/Release" Release
)
createrepo_c -q "$out/distro/rpm"

# --- submirror/: a substituted offline mirror (E23) ----------------------------------
# A copy of www/usg-plat-packages in which every platd <P2> package is rebuilt
# (same Package/Version/Arch and NEVRA, different payload) and the indexes are
# regenerated with the same Origin/Label/Codename, as an attacker who can write
# the mirror tree would. releases/ is unchanged, so the substitutes are in no
# SHA256SUMS.
sub=$out/submirror/usg-plat-packages
mkdir -p "$out/submirror"
cp -R -- "$www" "$sub"
MARKER=USGPLAT-FIXTURE-PAYLOAD-C
for a in amd64 arm64; do mkdeb platd "$P2-1" "$a" "$sub/apt/pool/main" usg-plat-verify; done
# mkdeb / mkrpm reuse their <P2> build trees: control, spec and payload are rewritten.
for a in x86_64 aarch64; do
    mkrpm platd "$P2" "$a" "$sub/rpm/$a" usg-plat-verify
    rm -rf -- "$sub/rpm/$a/repodata"
    createrepo_c -q "$sub/rpm/$a"
done
for f in "$sub"/apt/pool/main/platd_"$P2"-1_*.deb "$sub"/rpm/*/platd-"$P2"-1.*.rpm; do
    rel=${f#"$sub"/}
    if cmp -s "$f" "$www/$rel"; then
        echo "fixtures: substitute $rel equals the original" >&2
        exit 1
    fi
done
(
    cd "$sub/apt"
    rm -rf dists
    for a in amd64 arm64; do
        mkdir -p "dists/stable/main/binary-$a"
        apt-ftparchive --arch "$a" packages pool/main >"dists/stable/main/binary-$a/Packages"
        gzip -9nk "dists/stable/main/binary-$a/Packages"
    done
    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin=usg-plat \
        -o APT::FTPArchive::Release::Label=usg-plat \
        -o APT::FTPArchive::Release::Suite=stable \
        -o APT::FTPArchive::Release::Codename=stable \
        -o "APT::FTPArchive::Release::Architectures=amd64 arm64" \
        -o APT::FTPArchive::Release::Components=main \
        release dists/stable >"$work/Release.sub"
    mv -- "$work/Release.sub" dists/stable/Release
)

# --- TLS for https://usg-plat.test ----------------------------------------------------
(
    cd "$out/tls"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
        -subj '/CN=usg-plat install-test CA' -addext basicConstraints=critical,CA:TRUE \
        -addext keyUsage=critical,keyCertSign,cRLSign -keyout ca.key -out ca.pem 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=usg-plat.test \
        -keyout server.key -out "$work/server.csr" 2>/dev/null
    printf 'subjectAltName=DNS:usg-plat.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' >"$work/ext"
    openssl x509 -req -in "$work/server.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 \
        -extfile "$work/ext" -out server.pem 2>/dev/null
    rm -f ca.key ca.srl
)

# --- stub cosign --------------------------------------------------------------------------
cat >"$out/stub/cosign" <<'STUB'
#!/bin/sh
# Stand-in cosign for the install tests. NOT a signature check: it accepts
# verify-blob only when the stub bundle records the blob's SHA-256 and the
# exact identity asked for. It refuses the regexp identity and the offline
# flag (the gate must never pass them) and logs argv for the tests.
printf '%s\n' "$*" >>/var/log/usgtest-cosign.argv 2>/dev/null
case ${1:-} in
    version) echo 'GitVersion:    v3.1.4-usgtest-stub'; exit 0 ;;
    verify-blob) shift ;;
    *) echo "Error: stub cosign: unsupported command ${1:-}" >&2; exit 2 ;;
esac
blob=${1:-}
shift
bundle='' ident='' issuer='' root=''
while [ $# -ge 2 ]; do
    case $1 in
        --bundle) bundle=$2 ;;
        --certificate-identity) ident=$2 ;;
        --certificate-oidc-issuer) issuer=$2 ;;
        --trusted-root) root=$2 ;;
        *) echo "Error: stub cosign: unexpected argument $1" >&2; exit 2 ;;
    esac
    shift 2
done
[ $# -eq 0 ] || { echo "Error: stub cosign: unexpected argument $1" >&2; exit 2; }
[ -f "$blob" ] && [ -f "$bundle" ] || { echo "Error: stub cosign: missing blob or bundle" >&2; exit 1; }
[ -f "$root" ] || { echo "Error: stub cosign: --trusted-root missing" >&2; exit 1; }
[ "$issuer" = https://token.actions.githubusercontent.com ] || { echo "Error: stub cosign: issuer" >&2; exit 1; }
h=$(sha256sum -- "$blob" | cut -d' ' -f1)
grep -qF "\"sha256\":\"$h\"" "$bundle" || { echo "Error: stub cosign: invalid signature when validating ASN.1 encoded signature" >&2; exit 1; }
grep -qF "\"identity\":\"$ident\"" "$bundle" || { echo "Error: stub cosign: none of the expected identities matched" >&2; exit 1; }
echo 'Verified OK' >&2
exit 0
STUB
chmod 0755 "$out/stub/cosign"

echo "fixtures: built in $out (gate $VV, platd $P1 $P2, unlisted $P3)"
