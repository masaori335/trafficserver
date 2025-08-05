#!/bin/bash
set -e
set -x

function parse_version() {
    awk -F ' |)' '/^project/ { print $3 }' CMakeLists.txt
}

BUILD_VERSION=$1
if [ -z ${BUILD_VERSION} ]
then
    echo "BUILD_VERSION not set!"
fi

INTERNAL_GITHUB_PR=$2

# VARIATION (eg -boringssl)
TS_BUILD_REPO=${TS_BUILD_REPO:-.}  # https://code.edge.apple.com/trafficserver-build
SRC_REPO=${SRC_REPO:-.}  # https://gitlab.sd.apple.com/trafficserver/trafficserver

GIT_VERSION=notgit
if [ -d ${SRC_REPO}/.git ]; then
    GIT_VERSION=$(git --git-dir=${SRC_REPO}/.git rev-parse HEAD)
fi

# TS_VERSION (eg -6.1.2-6.2)
VERSION=$(parse_version)
VERSION_MAJOR=$(echo $VERSION | cut -d . -f 1)

buildroot=build  # directory where the build is done, artifacts stored.

# it is important that the tarball, when unpacked, produce a $srcdir top-directory
srcdir=bazinga-trafficserver-${VERSION}

mkdir -p $buildroot

archive=bazinga-trafficserver-${VERSION}.tar.gz
archive_path=rpmbuild/SOURCES/$archive

specfilename=bazinga-trafficserver.spec

# Copy spec file to the buildroot
cp $TS_BUILD_REPO/apple/specs/bazinga-trafficserver.spec $buildroot/$specfilename


mkdir -p $(dirname $buildroot/$archive_path)

# Make the archive used by rpmbuild:
if [ $(uname) == "Darwin" ]; then
    tar -c -z -f $buildroot/$archive_path --exclude .git -s ",^$SRC_REPO,$srcdir," $SRC_REPO
else
    tar -c -z -f $buildroot/$archive_path --exclude .git --exclude $buildroot --transform "s,^$SRC_REPO,$srcdir," $SRC_REPO
fi

RPMBUILD_FLAGS=()

if [ "$VARIATION" != "" ]; then
    RPMBUILD_FLAGS+=" --with variant"
fi

if [ "$INTERNAL_GITHUB_PR" != "" ]; then
    RPMBUILD_FLAGS+=" --with pr"
fi

RPMBUILD_MODE=-ba

if [ "$RUN_AUTEST" != "" ]; then
    RPMBUILD_MODE=-bc
    RPMBUILD_FLAGS+=" --with tests"
fi

RPMBUILD_FLAGS+=" --with boringssl --with io_uring"

rpmbuild $RPMBUILD_MODE $buildroot/$specfilename \
         --define "_version ${VERSION}" \
         --define "_version_major ${VERSION_MAJOR}" \
         --define "_release ${BUILD_VERSION}" \
         --define "_archive ${archive}" \
         --define "_commit ${GIT_VERSION}" \
         --define "_gittag ${GIT_TAG}" \
         --define "_topdir `pwd`/$buildroot/rpmbuild" \
         --define "_pr_id ${INTERNAL_GITHUB_PR:-'%{nil}'}" \
         --define "_libquiche_version ${QUICHE_VERSION:-0.20.0-5.el7}" \
         --define "_boringssl_version ${BORINGSSL_VERSION:-29}" \
         --define "_liburing_version ${LIBURING_VERSION:-2.4}" \
         --define "_preset bazinga${VARIATION}" \
         --define "_variant ${VARIATION:-default}" \
         ${RPMBUILD_FLAGS}
