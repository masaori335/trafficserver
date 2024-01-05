%define compiler_CC /opt/bazinga/bin/clang
%define compiler_CXX /opt/bazinga/bin/clang++

# Don't strip binaries for ASAN builds
%if %{?_with_asan:1}%{!?_with_asan:0} || %{?_with_lsan:1}%{!?_with_lsan:0}
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
%endif

%define cxx_version 17

%define make_verbose -v
%define _cpp_flags %{nil}

%define base_package_name bazinga-trafficserver

%if %{?_with_pr:1}%{!?_with_pr:0}
%define pr_release_prefix intpr.%{_pr_id}.
%endif

%define package_name %{base_package_name}

%define srcdir %{base_package_name}-%{version}

# This package is not relocatable. It always installs into /opt/bazinga.
%define _prefix /opt/bazinga

# default values
%{!?_version: %define _version 0.0.0}
%{!?_release: %define _release 0}
%{!?_archive: %define _archive %{srcdir}.tar.gz}
%{!?_commit: %define _commit UNKNOWN}
%{!?_gittag: %define _gittag UNKNOWN}
%if "%{dist}" == ".el7"
%{!?_boringssl_version %define _boringssl_version 25.20230726-39.el7}
%else
%{!?_boringssl_version %define _boringssl_version 25.20230727-4.el9}
%endif
%{!?_liburing_version %define _liburing_version 2.4}


%define release %{?boring_release_prefix}%{?asan_release_prefix}%{?lsan_release_prefix}%{?debug_release_prefix}%{?pr_release_prefix}%{_release}

Summary:	Apache Traffic Server, a reverse, forward and transparent HTTP proxy cache
Vendor:		GNS Edge Services, Apple Inc.
Name:		%{package_name}
Version:	%{_version}
Epoch:		1
Release:	%{release}%{?dist}
License:	ASL 2.0
Group:		System Environment/Daemons
Source:		%{_archive}
URL:		http://trafficserver.apache.org/index.html
BuildRoot:	%{_tmppath}/%{name}-%{version}-root

# NOTE: If adding/removing bazinga BuildRequires, increment/decrement the grep/count in install section
BuildRequires: autoconf, automake, libtool
BuildRequires: bazinga-llvm
BuildRequires:	bazinga-jemalloc-devel >= 4.3.1, bazinga-brotli-devel
BuildRequires:	expat-devel, pcre-devel, zlib-devel, xz-devel, hwloc-devel
BuildRequires:	libcurl-devel, ncurses-devel, libcap-devel
%if "%{dist}" == ".el7"
BuildRequires:	bazinga-luajit-devel
%else
BuildRequires:	luajit-devel
%endif

%{?_with_boringssl:BuildRequires: bazinga-boringssl = %{_boringssl_version}}
%{!?_with_boringssl:BuildRequires: bazinga-openssl-devel}
BuildRequires: bazinga-llvm-lld
%{?_with_io_uring:BuildRequires: bazinga-liburing-devel = %{_liburing_version}}

# trafficserver fails to build on ppc and others, TS-1131, see lib/ts/ink_queue.h
ExclusiveArch:	%{ix86} x86_64 ia64 %{arm}

%if %{?_with_debug:1}%{!?_with_debug:0}
Conflicts: %{base_package_name}, %{base_package_name}-devel
Provides: %{base_package_name}-debuginfo
%endif

# something in perl-devel(or it's dependencies) generates extra unpackaged files
BuildConflicts: perl-devel

Requires:	initscripts, zlib, pcre, expat, xz
Requires:	libcurl, ncurses-libs, libcap, hwloc, libmaxminddb
Requires:	bazinga-jemalloc >= 4.3.1
Requires:	bazinga-brotli >= 1.0.6
%{?_with_io_uring:Requires: bazinga-liburing = %{_liburing_version}}
%{?_with_boringssl:Requires: bazinga-boringssl  = %{_boringssl_version}}
%{!?_with_boringssl:Requires: bazinga-openssl-libs >= 1.1.1a}
Requires(post):	chkconfig
Requires(preun): chkconfig initscripts
Requires(postun): initscripts

%description
Apache Traffic Server is an OpenSource HTTP / HTTPS / HTTP/2 reverse,
forward and transparent proxy and cache.

Version: %{_commit}
Tag: %{_gittag}

%if %{?_with_pr:1}%{!?_with_pr:0}
NOTE: Pull-Request applied: %{_pr_id}
%endif

%package devel
Summary: Apache Traffic Server devel package
Group: Development/Libraries
Requires: %{package_name}
Requires: initscripts
Requires(post): chkconfig
Requires(preun): chkconfig initscripts
Requires(postun): initscripts
%description devel
Include files and various tools for ATS developers.

%package internal
Summary: Apache Traffic Server internal devel package
Group: Development/Libraries
Requires: %{package_name}
%description internal
Internal include files from ATS

%prep
# The release script only knows the release number when it creates the tarball,
# so we have to override the default name, which would use the version.
%setup -q -n %{base_package_name}-%{version}

%build
%if %{?_with_pr:1}%{!?_with_pr:0}
echo PR: %{_pr_id}
%endif

cmake -B build -S . --preset bazinga -DCMAKE_INSTALL_PREFIX=%{_prefix}
cmake --build build -j$(nproc)

%check

cmake --build build -t test

%install
rm -rf $RPM_BUILD_ROOT
DESTDIR=$RPM_BUILD_ROOT cmake --install build

## Currently we have 5 or 4 "bazinga" libraries we link against.
## If the next line fails check the output of ldd and see if we're missing something (did compiler image change?)
#ldd $RPM_BUILD_ROOT/opt/bazinga/bin/traffic_server
#%if %{?_with_asan:1}%{!?_with_asan:0}
## jemalloc and asan is orthogonal
#[ $(ldd $RPM_BUILD_ROOT/opt/bazinga/bin/traffic_server | grep bazinga | egrep -E 'crypto.so|libc\+\+.so|libc\+\+abi.so|ssl.so' | wc -l) -eq 4 ]
#%else
#[ $(ldd $RPM_BUILD_ROOT/opt/bazinga/bin/traffic_server | grep bazinga | egrep -E 'crypto.so|libc\+\+.so|libc\+\+abi.so|ssl.so|jemalloc.so' | wc -l) -eq 5 ]
#%endif
#
## ensure compress.so links against brotli (2 libraries)
#ldd $RPM_BUILD_ROOT/opt/bazinga/lib/trafficserver/plugins/compress.so
#[ $(ldd $RPM_BUILD_ROOT/opt/bazinga/lib/trafficserver/plugins/compress.so | grep bazinga | egrep -E 'brotli' | wc -l) -eq 2 ]
#
mkdir -p $RPM_BUILD_ROOT/usr/lib/systemd/system
mv %{_builddir}/%{srcdir}/build/rc/trafficserver.service $RPM_BUILD_ROOT/usr/lib/systemd/system/trafficserver.service

mkdir -p $RPM_BUILD_ROOT%{_prefix}/include/internal

cp -r %{_builddir}/%{srcdir}/include/shared $RPM_BUILD_ROOT%{_prefix}/include/internal
cp -r %{_builddir}/%{srcdir}/include/ts $RPM_BUILD_ROOT%{_prefix}/include/internal
cp -r %{_builddir}/%{srcdir}/include/tscore $RPM_BUILD_ROOT%{_prefix}/include/internal
cp -r %{_builddir}/%{srcdir}/include/tscpp $RPM_BUILD_ROOT%{_prefix}/include/internal
cp -r %{_builddir}/%{srcdir}/include/proxy $RPM_BUILD_ROOT%{_prefix}/include/internal
cp -r %{_builddir}/%{srcdir}/include/iocore $RPM_BUILD_ROOT%{_prefix}/include/internal

# We don't want
#	libtool archives
#	share
rm -f $RPM_BUILD_ROOT%{_prefix}/lib/trafficserver/plugin_*
rm -rf $RPM_BUILD_ROOT%{_prefix}/share
rm -rf $RPM_BUILD_ROOT%{_prefix}/lib64
#rmdir $RPM_BUILD_ROOT/var/trafficserver


# The clean section is only needed for EPEL and Fedora < 13
# http://fedoraproject.org/wiki/PackagingGuidelines#.25clean
%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, bazinga, bazinga, -)
# Leif removed CHANGES or something see c31e12b49 in Apple's trafficserver
%doc README.md NOTICE LICENSE
%attr(0755,root,root) %dir %{_prefix}/bin
%attr(0755,root,root) %{_prefix}/bin/*
%attr(0755,root,root) %dir %{_prefix}/lib/trafficserver
%attr(0755,root,root) %dir %{_prefix}/lib/trafficserver/plugins
%attr(0755,root,root) %{_prefix}/lib/trafficserver/*.so*
%attr(0755,root,root) %{_prefix}/lib/trafficserver/*.a
%attr(0755,root,root) %{_prefix}/lib/trafficserver/plugins/*.so
%exclude %{_prefix}/include

%config(noreplace) %{_prefix}/etc/trafficserver/*

%attr(0755, root, root) %config(noreplace) /usr/lib/systemd/system/trafficserver.service

%attr(0755, bazinga, bazinga) %dir %{_prefix}/etc/trafficserver

%dir /var/log/trafficserver
%dir /var/run/trafficserver
%dir /var/cache/trafficserver

%files devel
%exclude %{_prefix}/include/internal
%{_prefix}/include
%attr(0755,root,root) %dir %{_prefix}/lib
%attr(0644,root,root) %{_prefix}/lib/trafficserver/cmake
%attr(0644,root,root) %{_prefix}/lib/trafficserver/pkgconfig

%files internal
%{_prefix}/include/internal

%post
/sbin/ldconfig
/usr/bin/systemctl enable trafficserver >/dev/null 2>&1

%preun
if [ $1 -eq 0 ] ; then
  /sbin/service %{name} stop > /dev/null 2>&1
  /usr/bin/systemctl --no-reload disable trafficserver.service
fi

%postun
/sbin/ldconfig

/bin/rm -f /run/trafficserver/records.snap

if [ $1 -eq 1 ] ; then
	/sbin/service trafficserver condrestart &>/dev/null || :
fi
