#!/bin/bash

# Installs the build dependencies for an x86_64 build or test image from the
# artifactory-ci bazinga packages. BORINGSSL_VERSION and LIBURING_VERSION come
# from apple/rio.sh.

set -x
set -e

: "${BORINGSSL_VERSION:?}" "${LIBURING_VERSION:?}"

LD_LIBRARY_PATH=/lib64 yum install -d1 -y --disablerepo=\* --enablerepo=artifactory-ci bazinga-boringssl-devel-${BORINGSSL_VERSION}
LD_LIBRARY_PATH=/lib64 yum erase -d1 -y bazinga-openssl-devel

# The images' fmt is built against libstdc++, which libc++ libcripts.so
# cannot link against.
yum remove -y fmt fmt-devel
LD_LIBRARY_PATH=/lib64 yum install -d1 -y --disablerepo=\* --enablerepo=artifactory-ci bazinga-liburing-devel-${LIBURING_VERSION} bazinga-fmt-devel
