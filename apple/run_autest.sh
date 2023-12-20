#!/bin/bash

set -x
set -e

FILTER_TESTS=$1
BUILD_VERSION=${BUILD_VERSION:-1}
TMP=${TMP:-/tmp}

export PIPENV_COLORBLIND=1

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

cmake --preset bazinga-autest
export LD_LIBRARY_PATH=/opt/bazinga/lib/trafficserver
cmake --build build-autest -t autest

