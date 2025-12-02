Name:           certinfo
Version:        1.2.0
Release:        1%{?dist}
Summary:        Certificate Information Tool
License:        MIT
URL:            https://github.com/daniejstriata/certinfo
Source0:        https://github.com/daniejstriata/certinfo/archive/refs/tags/%{version}.tar.gz

# We use CMake now
BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  openssl-devel
BuildRequires:  make

# No debug package (your previous choice)
%define debug_package %{nil}

%description
Certinfo extracts and displays information from X.509 certificates,
including CN, validity period, and Subject Alternative Names (SAN).

%prep
%autosetup -n certinfo-%{version}

%build
# Standard CMake out-of-tree build
%cmake -DBUILD_C=ON -DBUILD_CPP=ON
%cmake_build

%install
# Install both into buildroot
%cmake_install

# Now remove the C version so only C++ ships:
rm -f %{buildroot}%{_bindir}/certinfo_c

# Rename cpp version to main binary name
mv %{buildroot}%{_bindir}/certinfo_cpp %{buildroot}%{_bindir}/certinfo

%files
%{_bindir}/certinfo

%changelog
* Tue Dec 3 2025 Danie de Jager <danie.dejager@gmail.com> - 1.2.0-1
- First release using CMake.
- Build both C and C++ implementations, ship the C++ binary.
* Fri Oct 4 2024 Danie de Jager <danie.dejager@gmail.com> - 1.1.3-1
- Fix for cert counter limit.
* Wed Oct 2 2024 Danie de Jager <danie.dejager@gmail.com> - 1.1.2-1
* Mon Feb 12 2024 Danie de Jager <danie.dejager@gmail.com> - 1.1-1
- Process SAN entries.
* Mon Feb 12 2024 Danie de Jager <danie.dejager@gmail.com> - 1.0-2
- remove debug info.
* Mon Feb 12 2024 Danie de Jager <danie.dejager@gmail.com> - 1.0-1
- Initial release.
