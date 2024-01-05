#!/bin/bash

set -x
set -e

FILTER_TESTS=$1
BUILD_VERSION=${BUILD_VERSION:-1}
TMP=${TMP:-/tmp}

export NO_COLOR=1

# Disabled tests
rm -f ./tests/gold_tests/tls/prewarm.test.py

AUTEST_SANDBOX="/work/_sandbox"
AUTEST_FLAGS=()
if [ "$RIO_BUILD_NUMBER" != "" ]; then
    AUTEST_FLAGS+=" --disable-color"

    # Broken under rio
    rm -r ./tests/gold_tests/thread_config
    rm -f ./tests/gold_tests/tls/tls_forward_nonhttp.test.py
else
    AUTEST_SANDBOX="/work/_sandbox"
    # plugin hot reload gets in the way, again.
    export TMP=/workspace/tmp
    mkdir -p $TMP
fi

if [ "$FILTER_TESTS" != "" ]; then
    AUTEST_FLAGS+=" --filter=$FILTER_TESTS"
fi

cmake --preset bazinga-autest -DAUTEST_SANDBOX=$AUTEST_SANDBOX
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/opt/bazinga/lib/trafficserver
cmake --build build-autest -t autest

if [ "$RIO_BUILD_NUMBER" != "" ]; then
    cp -r $AUTEST_SANDBOX /workspace
fi

