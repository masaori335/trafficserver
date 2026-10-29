#!/bin/bash

# Installs the build dependencies for an aarch64 toolchain image. The bazinga
# boringssl, liburing and fmt packages that apple/rio.sh installs on x86_64
# have no aarch64 builds, so this uses the system packages where their ABI
# allows it.

set -x
set -e

FMT_VERSION=${FMT_VERSION:-8.1.1}

# The tests' nc invocations use nmap-ncat options, as on the x86_64 image.
yum remove -y netcat
LD_LIBRARY_PATH=/lib64 yum install -d1 -y nmap-ncat libunwind-devel brotli-devel zlib-devel openssl-devel pcre2-devel libcap-devel jemalloc-devel

# The system fmt is built against libstdc++, so a libc++ libcripts.so linked
# to it fails to resolve fmt::vformat at plugin load. Build fmt with the
# bazinga toolchain into /opt/bazinga, which the presets and RUNPATH search.
if [ ! -f /opt/bazinga/lib64/cmake/fmt/fmt-config.cmake ]; then
    yum remove -y fmt fmt-devel
    FMT_SRC=$(mktemp -d)
    curl -sSfL https://github.com/fmtlib/fmt/archive/refs/tags/${FMT_VERSION}.tar.gz | tar -xz -C $FMT_SRC --strip-components=1
    CXXFLAGS="-stdlib=libc++" cmake -S $FMT_SRC -B $FMT_SRC/build -G Ninja \
        -DCMAKE_C_COMPILER=/opt/bazinga/bin/clang -DCMAKE_CXX_COMPILER=/opt/bazinga/bin/clang++ \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=ON \
        -DFMT_DOC=OFF -DFMT_TEST=OFF -DCMAKE_INSTALL_PREFIX=/opt/bazinga -DCMAKE_INSTALL_LIBDIR=lib64
    cmake --build $FMT_SRC/build
    cmake --install $FMT_SRC/build
    rm -rf $FMT_SRC
fi
