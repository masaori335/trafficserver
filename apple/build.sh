#!/bin/bash
set -e
set -x

BUILD_VERSION=$1
if [ -z ${BUILD_VERSION} ]
then
    echo "BUILD_VERSION not set!"
fi

INTERNAL_GITHUB_PR=$2

# VARIATION (eg -boringssl)
# SUBPROJECT (eg -plugins )
TS_BUILD_REPO=${TS_BUILD_REPO:-.}  # https://code.edge.apple.com/trafficserver-build
SRC_REPO=${SRC_REPO:-trafficserver}  # https://gitlab.sd.apple.com/trafficserver/trafficserver

GIT_VERSION=notgit
if [ -d ${SRC_REPO}/.git ]; then
    GIT_VERSION=$(git --git-dir=${SRC_REPO}/.git rev-parse HEAD)
fi

if [ "$SUBPROJECT" == "-plugins" ];then
    VERSION=${TS_PLUGIN_VERSION}
    VERSION_SEPARATOR="-"
else
    # TS_VERSION (eg -6.1.2-6.2)
    VERSION=$(grep '\[TS_VERSION_S\]' $SRC_REPO/configure.ac | head -n 1 | perl -pe 's{^.*\],\[(\d+.\d+.\d+).*$}{$1}')
    VERSION_SEPARATOR="/"
fi

DOCKER_IMAGE=trafficserver-builder${SUBPROJECT}${TS_PLUGIN_VERSION}${VARIATION}

buildroot=build  # directory where the build is done, artifacts stored.

# it is important that the tarball, when unpacked, produce a $srcdir top-directory
srcdir=bazinga-trafficserver$SUBPROJECT-${VERSION}

mkdir -p $buildroot

if [ "$SUBPROJECT" == "-plugins" ];then
    BZ_DEVEL_PKG=bazinga-trafficserver-devel$TS_VERSION
    if [ "$VARIATION" == "-asan" ];then
        BZ_DEVEL_PKG=bazinga-trafficserver$VARIATION-devel$TS_VERSION
    fi

    sudo yum -y install $BZ_DEVEL_PKG --enablerepo=bazinga-testing
fi

archive=bazinga-trafficserver${SUBPROJECT}-${VERSION}.tar.gz
archive_path=rpmbuild/SOURCES/$archive

specfilename=bazinga-trafficserver${SUBPROJECT}.spec

# Copy spec file to the buildroot
cp $TS_BUILD_REPO/apple/specs/bazinga-trafficserver${SUBPROJECT}.spec $buildroot/$specfilename

mkdir -p $(dirname $buildroot/$archive_path)

# Make the archive used by rpmbuild:
if [ -d ${SRC_REPO}/.git ]; then
    WORKDIR=$PWD
    pushd $SRC_REPO
    git archive -o $WORKDIR/$buildroot/$archive_path --format=tar.gz --prefix "$srcdir/" HEAD
    popd
else
    if [ $(uname) == "Darwin" ]; then
        tar -c -z -f $buildroot/$archive_path --exclude .git -s ",^$SRC_REPO,$srcdir," $SRC_REPO
    else
        tar -c -z -f $buildroot/$archive_path --exclude .git  --transform "s,^$SRC_REPO,$srcdir," $SRC_REPO
    fi
fi

RPMBUILD_FLAGS=()
if [ "$VARIATION" != "" ]; then
    X=$(echo $VARIATION | sed -e 's/^-//g')
    RPMBUILD_FLAGS+="--with $X"
fi

# -asan requires llvm
if [ "$VARIATION" == "-asan" ];then
    RPMBUILD_FLAGS+=" --with llvm"
fi

# skip check for io_uring as it doesn't currently work in rio
if [ "$VARIATION" == "-io_uring" ];then
    RPMBUILD_FLAGS+=" --nocheck"
fi

# -quiche requires boringssl
if [ "$VARIATION" == "-quiche" ];then
    RPMBUILD_FLAGS+=" --with boringssl"
fi

if [ "$INTERNAL_GITHUB_PR" != "" ]; then
    RPMBUILD_FLAGS+=" --with pr"
fi

RPMBUILD_MODE=-ba

if [ "$RUN_AUTEST" != "" ]; then
    RPMBUILD_MODE=-bc
    RPMBUILD_FLAGS+=" --with tests"
fi

rpmbuild $RPMBUILD_MODE $buildroot/$specfilename \
         --define "_version ${VERSION}" \
         --define "_release ${BUILD_VERSION}" \
         --define "_archive ${archive}" \
         --define "_commit ${GIT_VERSION}" \
         --define "_gittag ${GIT_TAG}" \
         --define "_topdir `pwd`/$buildroot/rpmbuild" \
         --define "_pr_id ${INTERNAL_GITHUB_PR}" \
         ${RPMBUILD_FLAGS}
