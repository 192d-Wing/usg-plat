# usg-plat-verify: install-time signature gate (dnf4 front end).
# Built by deploy/verify/build.sh with rpmbuild -bb; the source dir is the
# staged tree; pkgversion comes from the workspace version.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SI-7(15) (Code Authentication), CM-14 (Signed Components),
#   SR-11 (Component Authenticity) - dnf refuses platd / usg-plat-verify
#   unless the release signature verifies (verify-pkg)
# - NDcPP FPT_TUD_EXT.1 - the platform package manager performs the check
#
# The package is noarch and built on the Ubuntu CI runner: no debuginfo, no
# brp scripts (they would byte-compile with the build host's python).
%global debug_package %{nil}
%global __os_install_post %{nil}
%global __brp_python_bytecompile %{nil}

# dnf loads plugins from dnf.const.PLUGINPATH = <platform python sitelib>/dnf-plugins.
# A noarch package cannot use the build host's %%{python3_sitelib}, so the
# plugin is installed for each supported platform python (EL9 3.9, EL10 3.12)
# and %%pre refuses a host whose dnf uses another one (fails closed rather
# than installing a gate dnf never loads).
%global plugin_pys python3.9 python3.12
# The plugin is installed for both EL9 (python3.9) and EL10 (python3.12); %%pre
# refuses a host whose dnf uses neither. rpmbuild would otherwise add
# Requires: python(abi) = 3.9 AND = 3.12, which no host satisfies.
%global __requires_exclude ^python\\(abi\\)

Name:           usg-plat-verify
Version:        %{pkgversion}
Release:        1
Summary:        Install-time signature gate for usg-plat packages
License:        Apache-2.0
BuildArch:      noarch
Requires:       dnf >= 4.14
Requires:       python3-dnf
Requires:       rpm
Requires:       coreutils
Requires:       util-linux
# fetch-sums downloads SHA256SUMS over https (curl or curl-minimal provides curl).
Requires:       curl
Requires:       ca-certificates
Requires(pre):  python3-dnf

%description
Refuses dnf installs and upgrades of platd and usg-plat-verify unless the
package's SHA-256 is listed in the release SHA256SUMS and that file's cosign
keyless signature verifies offline against the pinned Sigstore trusted root
and the exact release workflow identity. Requires an operator-installed
cosign >= 3.0.3 (/usr/local/bin/cosign by default); without it every
usg-plat install is refused. rpm -i / rpm -U bypass the gate; dnf5 is not
covered.

%prep

%build

%install
install -D -m 0755 %{_sourcedir}/libexec/verify-pkg %{buildroot}/usr/libexec/usg-plat-verify/verify-pkg
install -D -m 0755 %{_sourcedir}/libexec/fetch-sums %{buildroot}/usr/libexec/usg-plat-verify/fetch-sums
install -D -m 0755 %{_sourcedir}/libexec/selftest %{buildroot}/usr/libexec/usg-plat-verify/selftest
install -D -m 0755 %{_sourcedir}/bin/usg-plat-verify %{buildroot}/usr/sbin/usg-plat-verify
install -D -m 0644 %{_sourcedir}/etc/verify.conf %{buildroot}/etc/usg-plat-verify/verify.conf
install -D -m 0644 %{_sourcedir}/trusted_root.json %{buildroot}/usr/share/usg-plat-verify/trusted_root.json
for py in %{plugin_pys}; do
    install -D -m 0644 %{_sourcedir}/dnf/usg_plat_verify.py %{buildroot}/usr/lib/$py/site-packages/dnf-plugins/usg_plat_verify.py
done
install -D -m 0644 %{_sourcedir}/dnf/usg_plat_verify.conf %{buildroot}/etc/dnf/plugins/usg_plat_verify.conf
install -D -m 0644 %{_sourcedir}/dnf/usg-plat.repo %{buildroot}/etc/yum.repos.d/usg-plat.repo

%pre
pp=$(python3 -I -c 'import dnf.const; print(dnf.const.PLUGINPATH)' 2>/dev/null) || pp=
case "$pp" in
    /usr/lib/python3.9/site-packages/dnf-plugins | /usr/lib/python3.12/site-packages/dnf-plugins) ;;
    *)
        echo "usg-plat-verify: refusing: dnf plugin path '$pp' is not supported (EL9/EL10 dnf4 only)" >&2
        exit 1
        ;;
esac

%post
# >>> common: test hooks and root_only (identical in every script; unit.sh checks)
# Test hooks (the USG_PLAT_VERIFY_* overrides named in the header, and TMPDIR)
# are honoured only when USG_PLAT_VERIFY_TEST=1, which only the test suites
# set. Otherwise they are unset, so children inherit a clean environment, and
# logged once to authpriv. When it is honoured, every invocation logs
# "test mode enabled" at authpriv.warning and on stderr, so a production host
# left in test mode is visible. USG_PLAT_VERIFY_SUMS_DIR is not a hook: the front
# ends set it for local installs and verify-pkg still verifies what it names.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-6 (Configuration Settings), SI-7(15) (Code Authentication)
#   - the decision depends only on root-owned, root-only-writable files
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
uv_test=0
if [ "${USG_PLAT_VERIFY_TEST:-}" = 1 ]; then
    uv_test=1
    uv_msg="test mode enabled: overrides honoured (USG_PLAT_VERIFY_TEST=1)"
    printf 'usg-plat-verify: %%s\n' "$uv_msg" >&2
    PATH=${USG_PLAT_VERIFY_PATH:-$PATH} logger -t usg-plat-verify -p authpriv.warning -- "$uv_msg" 2>/dev/null || :
else
    uv_ign=$(env | sed -n 's/^\(USG_PLAT_VERIFY_[A-Z_]*\)=.*/\1/p' |
        grep -v -x -e USG_PLAT_VERIFY_SUMS_DIR -e USG_PLAT_VERIFY_TEST | sort -u | tr '\n' ' ')
    [ -n "${TMPDIR+x}" ] && uv_ign="${uv_ign}TMPDIR "
    for uv_v in $uv_ign; do
        unset "$uv_v"
    done
    unset USG_PLAT_VERIFY_TEST
    if [ -n "$uv_ign" ]; then
        uv_msg="ignoring test-only environment (USG_PLAT_VERIFY_TEST is not 1): $uv_ign"
        printf 'usg-plat-verify: %%s\n' "$uv_msg" >&2
        logger -t usg-plat-verify -p authpriv.warning -- "$uv_msg" 2>/dev/null || :
    fi
fi

# root_only PATH: PATH and every ancestor directory exist, are not symlinks,
# are owned by uid 0 and are neither group- nor other-writable (POSIX ACLs
# are not inspected). A sticky world-writable directory such as /tmp fails: its other users
# can still rename or replace entries they own. In test mode the invoking uid
# also counts as an owner and the walk stops at USG_PLAT_VERIFY_TEST_TOP.
root_only() {
    case $1 in /*) ;; *) return 1 ;; esac
    case $1 in */./* | */../* | */. | */.. | *//*) return 1 ;; *) ;; esac
    ro_p=$1
    while :; do
        if [ $uv_test -eq 1 ] && [ -n "${USG_PLAT_VERIFY_TEST_TOP:-}" ] &&
            [ "$ro_p" = "$USG_PLAT_VERIFY_TEST_TOP" ]; then
            return 0
        fi
        [ -e "$ro_p" ] && [ ! -L "$ro_p" ] || return 1
        ro_l=$(LC_ALL=C stat -c '%%A %%u' -- "$ro_p" 2>/dev/null) || return 1
        ro_m=${ro_l%%%% *} ro_u=${ro_l#* }
        case $ro_m in
            ?????w* | ????????w*) return 1 ;;
            ??????????*) ;;
            *) return 1 ;;
        esac
        if [ "$ro_u" != 0 ]; then
            [ $uv_test -eq 1 ] && [ "$ro_u" = "$(id -u)" ] || return 1
        fi
        [ "$ro_p" = / ] && return 0
        ro_p=${ro_p%%/*}
        [ -n "$ro_p" ] || ro_p=/
    done
}
# <<< common

# >>> common-exec (identical where cosign is checked; unit.sh checks)
# root_only_exec PATH: an executable that may be a symlink (cosign in
# /usr/local/bin often is). Every ancestor of PATH must pass root_only, and
# so must the fully resolved target (readlink -f), which must be a regular
# executable file.
root_only_exec() {
    case $1 in /*) ;; *) return 1 ;; esac
    rx_d=${1%%/*}
    [ -n "$rx_d" ] || rx_d=/
    root_only "$rx_d" || return 1
    rx_t=$(readlink -f -- "$1" 2>/dev/null) || return 1
    [ -n "$rx_t" ] && [ -f "$rx_t" ] && [ -x "$rx_t" ] || return 1
    root_only "$rx_t"
}
# <<< common-exec
install -d -m 0755 -o root -g root /var/lib/usg-plat-verify /var/lib/usg-plat-verify/releases
COSIGN=/usr/local/bin/cosign
c=/etc/usg-plat-verify/verify.conf
# Sourced only when root-owned and not group/other-writable.
if [ -r "$c" ] && root_only "$c"; then
    . "$c"
elif [ -e "$c" ]; then
    msg="$c is not root-owned or is group/other-writable: every platd / usg-plat-verify install will be REFUSED until it is fixed"
    echo "usg-plat-verify: WARNING: $msg" >&2
    logger -t usg-plat-verify -p authpriv.warning "$msg" 2>/dev/null || :
fi
if [ ! -x "$COSIGN" ]; then
    msg="cosign not found at $COSIGN: every platd / usg-plat-verify install and upgrade will be REFUSED until cosign >= 3.0.3 is installed (see the install guide)"
    echo "usg-plat-verify: WARNING: $msg" >&2
    logger -t usg-plat-verify -p authpriv.warning "$msg" 2>/dev/null || :
fi
if [ -x "$COSIGN" ] && ! root_only_exec "$COSIGN"; then
    msg="cosign $COSIGN (its target or a parent directory) is not root-owned, is group/other-writable or is not a regular file: every platd / usg-plat-verify install and upgrade will be REFUSED until it is fixed"
    echo "usg-plat-verify: WARNING: $msg" >&2
    logger -t usg-plat-verify -p authpriv.warning "$msg" 2>/dev/null || :
fi
exit 0

%preun
if [ "$1" -eq 0 ]; then
    msg="usg-plat-verify remove: the install-time signature gate is being removed"
    echo "usg-plat-verify: $msg" >&2
    logger -t usg-plat-verify -p authpriv.warning "$msg" 2>/dev/null || :
fi
exit 0

%files
%dir /usr/libexec/usg-plat-verify
/usr/libexec/usg-plat-verify/verify-pkg
/usr/libexec/usg-plat-verify/fetch-sums
/usr/libexec/usg-plat-verify/selftest
/usr/sbin/usg-plat-verify
%dir /etc/usg-plat-verify
%config(noreplace) /etc/usg-plat-verify/verify.conf
%dir /usr/share/usg-plat-verify
/usr/share/usg-plat-verify/trusted_root.json
/usr/lib/python3.9/site-packages/dnf-plugins/usg_plat_verify.py
/usr/lib/python3.12/site-packages/dnf-plugins/usg_plat_verify.py
%config(noreplace) /etc/dnf/plugins/usg_plat_verify.conf
%config(noreplace) /etc/yum.repos.d/usg-plat.repo
