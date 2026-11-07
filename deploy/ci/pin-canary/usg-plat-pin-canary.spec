# usg-plat-pin-canary: empty package published in every usg-plat repository
# arch dir. dnf hides it (includepkgs=platd usg-plat-verify); apt must report
# `Candidate: (none)` for it (usg-plat-verify selftest --apt). Built by
# deploy/ci/pin-canary/build.sh.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-7 (Least Functionality) - proves the repository pin
%global debug_package %{nil}
%global __os_install_post %{nil}

Name:           usg-plat-pin-canary
Version:        0.0.0
Release:        1
Summary:        Pin canary for the usg-plat repository (never installable)
License:        Apache-2.0
BuildArch:      noarch

%description
Empty package. The usg-plat repository publishes it so that the host gate can
show that only platd and usg-plat-verify are installable from it.

%prep

%build

%install

%files
