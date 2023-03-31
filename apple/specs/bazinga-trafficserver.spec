%define compiler_CC /opt/bazinga/bin/clang
%define compiler_CXX /opt/bazinga/bin/clang++

# Don't strip binaries for ASAN builds
%if %{?_with_asan:1}%{!?_with_asan:0}
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
%endif

%if "%{_version}" >= "8.0.0"
%define cxx_version 17
%else
%define cxx_version 11
%endif

%define make_verbose V=1
%define _cpp_flags %{nil}

%if %{?_with_debug:0}%{!?_with_debug:1}
%define _release_cflags -O3 -DNDEBUG
%else
%define _release_cflags %{nil}
%endif

%define _with_llvm_cppflags -std=c++%{cxx_version} -stdlib=libc++ -I/opt/bazinga/include/c++/v1
%if "%{_version}" >= "9.0.0"
%define _with_llvm_cflags %{_release_cflags} -fPIE -fstack-protector -fno-omit-frame-pointer -flto=thin -gdwarf-4
%define _with_llvm_cxxflags %{_with_llvm_cflags}
%define _with_llvm_ldflags -stdlib=libc++ -Wl,--build-id=sha1
%define compiler_CC /opt/bazinga/bin/clang -fuse-ld=lld --ld-path=/opt/bazinga/bin/ld.lld
%define compiler_CXX /opt/bazinga/bin/clang++ -fuse-ld=lld --ld-path=/opt/bazinga/bin/ld.lld
%else
%define _with_llvm_cflags -fPIE -fstack-protector -fno-omit-frame-pointer
%define _with_llvm_cxxflags %{_with_llvm_cflags}
%define _with_llvm_ldflags -stdlib=libc++ -Wl,--build-id
%endif

%define base_package_name bazinga-trafficserver

%if %{?_with_asan:1}%{!?_with_asan:0}
%define asan_release_prefix asan.
%define _enable_asan --enable-asan
%else
%define _enable_asan %{nil}
%endif

%if %{?_with_io_uring:1}%{!?_with_io_uring:0}
%define _enable_io_uring --enable-experimental-linux-io-uring
%else
%define _enable_io_uring %{nil}
%endif

%if %{?_with_tests:1}%{!?_with_tests:0}
%define _enable_tests --enable-example-plugins
# Use default layout for test run builds (allows for compiling upstream trees)
%define _enable_layout %{nil}
%define make_verbose %{nil}
%else
%define _enable_tests %{nil}
%define _enable_layout --enable-layout=AppleBazinga
%endif

%if %{?_with_debug:1}%{!?_with_debug:0}
%define debug_release_prefix debug.
%define _enable_debug --enable-debug
%else
%define _enable_debug %{nil}
%endif

%if %{?_with_boringssl:1}%{!?_with_boringssl:0}
%define boring_release_prefix boringssl.
%define ssl_library /opt/bazinga/boringssl
%else
%define ssl_library /opt/bazinga
%endif

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

%define release %{?boring_release_prefix}%{?asan_release_prefix}%{?debug_release_prefix}%{?pr_release_prefix}%{_release}

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
BuildRequires:	bazinga-jemalloc-devel >= 4.3.1, bazinga-brotli-devel, perl-URI
%if "%{_version}" < "9.0.0"
BuildRequires:	tcl-devel
%endif
BuildRequires:	expat-devel, pcre-devel, zlib-devel, xz-devel, hwloc-devel
BuildRequires:	libcurl-devel, ncurses-devel, libcap-devel
BuildRequires:	bazinga-luajit-devel
%if "%{_version}" < "8.1.0"
BuildRequires:	bazinga-yaml-cpp-devel
%endif
%{?_with_boringssl:BuildRequires: bazinga-boringssl < 19}
%{!?_with_boringssl:BuildRequires: bazinga-openssl-devel}
BuildRequires: bazinga-llvm-lld

# trafficserver fails to build on ppc and others, TS-1131, see lib/ts/ink_queue.h
ExclusiveArch:	%{ix86} x86_64 ia64 %{arm}

%if %{?_with_debug:1}%{!?_with_debug:0}
Conflicts: %{base_package_name}, %{base_package_name}-devel
Provides: %{base_package_name}-debuginfo
%endif

# something in perl-devel(or it's dependencies) generates extra unpackaged files
BuildConflicts: perl-devel

%if "%{_version}" < "9.0.0"
Requires:  tcl
%endif
Requires:	initscripts, zlib, pcre, expat, xz
Requires:	libcurl, ncurses-libs, libcap, hwloc, libmaxminddb
Requires:	bazinga-jemalloc >= 4.3.1
Requires:	bazinga-brotli >= 1.0.6
%{?_with_boringssl:Requires: bazinga-boringssl < 19}
%{!?_with_boringssl:Requires: bazinga-openssl-libs >= 1.1.1a}
Requires(post):	chkconfig
Requires(preun): chkconfig initscripts
Requires(postun): initscripts
Obsoletes: bazinga-trafficserver-tslua

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
%if "%{_version}" < "9.0.0"
Requires: tcl
%endif
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

# hackity hack for lld
sed -i -e 's/-Wl,--add-needed //g' build/jemalloc.m4
sed -i -e 's/ -Wl,--no-as-needed//g' build/jemalloc.m4

autoreconf -if
export LD_LIBRARY_PATH=/opt/bazinga/lib64
export LIBRARY_PATH=/opt/bazinga/lib64
./configure \
     --with-build-number=%{release} \
     %{?_enable_layout} \
     --prefix=%{_prefix} \
%if %{?_with_asan:1}%{!?_with_asan:0}
%else
     --with-jemalloc=/opt/bazinga/include:/opt/bazinga/lib64 \
%endif
     --enable-experimental-plugins \
     --disable-dependency-tracking \
     --with-user=nobody \
     --with-group=bazinga \
%if "%{_version}" < "9.0.0"
     --with-max-api-stats=8192 \
%endif
%if %{?_with_quiche:1}%{!?_with_quiche:0}
    --with-quiche=/workspace/quiche \
%endif
     --with-brotli=/opt/bazinga/include:/opt/bazinga/lib64 \
     --with-openssl=%{ssl_library} \
%if "%{_version}" < "8.1.0"
     --with-yaml-cpp=/opt/bazinga \
%endif
     %{?_enable_debug} \
     %{?_enable_asan} \
     %{?_enable_io_uring} \
     %{?_enable_tests} \
     CPPFLAGS="%{_cpp_flags} -DTCP_FASTOPEN=23 -DSO_REUSEPORT=15 -DTCP_NOTSENT_LOWAT=25 -I/opt/bazinga/include" \
     CFLAGS="%{_with_llvm_cflags}" \
     CXXFLAGS="%{_with_llvm_cxxflags} %{?_with_llvm_cppflags}" \
     LDFLAGS="-pie -Wl,-z,relro -Wl,-z,now -L/opt/bazinga/lib64 -Wl,-rpath,%{ssl_library}/lib64 -Wl,-rpath,/opt/bazinga/lib64 %{?_with_llvm_ldflags}" \
%if "%{_version}" >= "9.0.0"
     AR=/opt/bazinga/bin/llvm-ar \
     NM=/opt/bazinga/bin/llvm-nm \
     RANLIB=/opt/bazinga/bin/llvm-ranlib \
%endif
     CC="%{compiler_CC}" \
     CXX="%{compiler_CXX}"

# Hackup libtool to work with newer clangs
sed -i -e 's/-lstdc++ //g' libtool
%if "%{_version}" > "9.0.0"
sed -i -e 's/-fuse-linker-plugin/-fuse-ld=*/g' libtool
%endif

make %{?_smp_mflags} %{make_verbose}

%check
make check %{?_smp_mflags} %{make_verbose}

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install

# Currently we have 5 or 4 "bazinga" libraries we link against.
# If the next line fails check the output of ldd and see if we're missing something (did compiler image change?)
ldd $RPM_BUILD_ROOT/opt/bazinga/bin/traffic_server
%if %{?_with_asan:1}%{!?_with_asan:0}
# jemalloc and asan is orthogonal
[ $(ldd $RPM_BUILD_ROOT/opt/bazinga/bin/traffic_server | grep bazinga | egrep -E 'crypto.so|libc\+\+.so|libc\+\+abi.so|ssl.so' | wc -l) -eq 4 ]
%else
[ $(ldd $RPM_BUILD_ROOT/opt/bazinga/bin/traffic_server | grep bazinga | egrep -E 'crypto.so|libc\+\+.so|libc\+\+abi.so|ssl.so|jemalloc.so' | wc -l) -eq 5 ]
%endif

# ensure compress.so links against brotli (2 libraries)
ldd $RPM_BUILD_ROOT/opt/bazinga/lib/trafficserver/plugins/compress.so
[ $(ldd $RPM_BUILD_ROOT/opt/bazinga/lib/trafficserver/plugins/compress.so | grep bazinga | egrep -E 'brotli' | wc -l) -eq 2 ]

mkdir -p $RPM_BUILD_ROOT/usr/lib/systemd/system
mv %{_builddir}/%{srcdir}/rc/trafficserver.service $RPM_BUILD_ROOT/usr/lib/systemd/system/trafficserver.service

mkdir -p $RPM_BUILD_ROOT%{_prefix}/include/internal

cp    %{_builddir}/%{srcdir}/include/ink_autoconf.h $RPM_BUILD_ROOT%{_prefix}/include/internal
%if "%{_version}" >= "9.0.0"
cp -r %{_builddir}/%{srcdir}/include/shared $RPM_BUILD_ROOT%{_prefix}/include/internal
%endif
cp -r %{_builddir}/%{srcdir}/include/ts $RPM_BUILD_ROOT%{_prefix}/include/internal
cp -r %{_builddir}/%{srcdir}/include/tscore $RPM_BUILD_ROOT%{_prefix}/include/internal
cp -r %{_builddir}/%{srcdir}/include/tscpp $RPM_BUILD_ROOT%{_prefix}/include/internal
mkdir -p $RPM_BUILD_ROOT%{_prefix}/include/internal/records
cp -r %{_builddir}/%{srcdir}/lib/records/*h $RPM_BUILD_ROOT%{_prefix}/include/internal/records

# Selectively take proxy and iocore headers and flatten for easier inclusion
pushd %{_builddir}/%{srcdir}
find proxy -name \*.h -type f | cpio -pdmv $RPM_BUILD_ROOT%{_prefix}/include/internal
find iocore -name \*.h -type f | cpio -pdmv $RPM_BUILD_ROOT%{_prefix}/include/internal
popd

find $RPM_BUILD_ROOT%{_prefix}/include/internal -name Makefile\* | xargs rm

# We don't want
#	libtool archives
#	share
rm -f $RPM_BUILD_ROOT%{_prefix}/lib/trafficserver/*.la
rm -f $RPM_BUILD_ROOT%{_prefix}/lib/trafficserver/plugins/*.la
rm -f $RPM_BUILD_ROOT%{_prefix}/lib/trafficserver/plugin_*
rm -rf $RPM_BUILD_ROOT%{_prefix}/share
rm -rf $RPM_BUILD_ROOT%{_prefix}/lib64
rmdir $RPM_BUILD_ROOT/var/trafficserver

# Needed for devel package
mkdir $RPM_BUILD_ROOT%{_prefix}/lib/perl
cp -r lib/perl/lib/* $RPM_BUILD_ROOT%{_prefix}/lib/perl/

# The clean section is only needed for EPEL and Fedora < 13
# http://fedoraproject.org/wiki/PackagingGuidelines#.25clean
%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, bazinga, bazinga, -)
# Leif removed CHANGES or something see c31e12b49 in Apple's trafficserver
%if "%{_version}" >= "9.2.0"
%doc README.md NOTICE LICENSE
%else
%doc README NOTICE LICENSE
%endif
%attr(0755,root,root) %dir %{_prefix}/bin
%attr(0755,root,root) %{_prefix}/bin/*
%attr(0755,root,root) %dir %{_prefix}/lib/trafficserver
%attr(0755,root,root) %dir %{_prefix}/lib/trafficserver/plugins
%attr(0755,root,root) %{_prefix}/lib/trafficserver/*.so*
%attr(0755,root,root) %{_prefix}/lib/trafficserver/pkgconfig/*.pc
%attr(0755,root,root) %{_prefix}/lib/trafficserver/plugins/*.so
%exclude %{_prefix}/bin/tsxs
%exclude %{_prefix}/include

%config(noreplace) %{_prefix}/etc/trafficserver/*

%attr(0755, root, root) %config(noreplace) /usr/lib/systemd/system/trafficserver.service

%attr(0755, bazinga, bazinga) %dir %{_prefix}/etc/trafficserver
%attr(0444, bazinga, bazinga) %{_prefix}/etc/trafficserver/body_factory/default/*

%dir /var/log/trafficserver
%dir /var/run/trafficserver
%dir /var/cache/trafficserver

%files devel
%exclude %{_prefix}/include/internal
%{_prefix}/include
%attr(0755,root,root) %{_prefix}/bin/tsxs
%attr(0755,root,root) %dir %{_prefix}/lib
%attr(0755,root,root) %dir %{_prefix}/lib/perl
%attr(0755,root,root) %{_prefix}/lib/perl/*

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
