#!/bin/bash

set -x
set -e

FILTER_TESTS=$1
BUILD_VERSION=${BUILD_VERSION:-1}
TMP=${TMP:-/tmp}

export PIPENV_COLORBLIND=1
export VARIATION=${VARIATION:--llvm}
export RUN_AUTEST=1

if [ ! -f trafficserver/configure.ac ]; then
    echo "Requires trafficserver source tree located at ./trafficserver"
    exit 1
fi

ATS_VERSION=$(grep '\[TS_VERSION_S\]' trafficserver/configure.ac | head -n 1 | perl -pe 's{^.*\],\[(\d+.\d+.\d+).*$}{$1}')

SOURCE_DIR=build/rpmbuild/BUILD/bazinga-trafficserver-$ATS_VERSION

if [ ! -f $SOURCE_DIR/.built ]; then
    . apple/build.sh $BUILD_VERSION
    touch $SOURCE_DIR/.built
fi

mkdir -p build/.out

cd $SOURCE_DIR

if [ ! -f $TMP/.installed ]; then
    make -j`nproc` install >& install.log || cat install.log
    touch $TMP/.installed

    # Purge potentially conflicting proxy-verifier
    rm -rf tests/proxy-verifier
fi

# prepare_proxy_verifier.sh needs $ROOT pointed at top of tree
ROOT=$PWD
export ROOT

cd tests

sh -x prepare_proxy_verifier.sh >& pv.log || cat pv.log

export PYTHONPATH=$(pwd):$PYTHONPATH

if [ ! -f $TMP/pip.log ]; then
    rm -f Pipfile.lock
    pipenv install -i https://pypi.apple.com/simple/ >& $TMP/pipenv.log || cat $TMP/pipenv.log
    ./test-env-check.sh >& $TMP/pip.log || cat $TMP/pip.log
fi

export PATH=/opt/bazinga/bin:$PATH

# hint for tls_engine test
export CC='/opt/bazinga/bin/clang -fuse-ld=lld --ld-path=/opt/bazinga/bin/ld.lld'

# Disabled tests
rm -f ./gold_tests/tls/prewarm.test.py

AUTEST_FLAGS=()
if [ "$RIO_BUILD_NUMBER" != "" ]; then
    AUTEST_FLAGS+=" --sandbox=/tmp/_sandbox --disable-color"

    # Broken under rio
    rm -r ./gold_tests/thread_config
    rm -f ./gold_tests/tls/tls_forward_nonhttp.test.py
else
    AUTEST_FLAGS+=" --sandbox=/workspace/_sandbox"
    # plugin hot reload gets in the way, again.
    export TMP=/workspace/tmp
    mkdir -p $TMP
fi

if [ "$FILTER_TESTS" != "" ]; then
    AUTEST_FLAGS+=" --filter=$FILTER_TESTS"
fi

export LD_LIBRARY_PATH="/lib64:$LD_LIBRARY_PATH"
pipenv run autest -D gold_tests --ats-bin=/opt/bazinga/bin ${AUTEST_FLAGS} | /usr/bin/au2junit-report --output-filename /workspace/build/.out/autest.xml

if [ "$RIO_BUILD_NUMBER" != "" ]; then
    cp -r /tmp/_sandbox /workspace
fi
