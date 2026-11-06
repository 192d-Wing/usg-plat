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
install -d -m 0755 -o root -g root /var/lib/usg-plat-verify /var/lib/usg-plat-verify/releases
COSIGN=/usr/local/bin/cosign
[ -r /etc/usg-plat-verify/verify.conf ] && . /etc/usg-plat-verify/verify.conf
if [ ! -x "$COSIGN" ]; then
    msg="cosign not found at $COSIGN: every platd / usg-plat-verify install and upgrade will be REFUSED until cosign >= 3.0.3 is installed (see the install guide)"
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
