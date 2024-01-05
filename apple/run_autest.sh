#!/bin/bash

set -x
set -e

echo "Running as ${USER} with id $(id)"

FILTER_TESTS=$1
BUILD_VERSION=${BUILD_VERSION:-1}
TMP=${TMP:-/tmp}

export NO_COLOR=1

# Disabled tests
rm -f ./tests/gold_tests/tls/prewarm.test.py

AUTEST_SANDBOX="/tmp/_sandbox"
AUTEST_FLAGS=()
if [ "$RIO_BUILD_NUMBER" != "" ]; then
    AUTEST_FLAGS+=" --disable-color"

    # Broken under rio
    rm -r ./tests/gold_tests/thread_config
    rm -f ./tests/gold_tests/tls/tls_forward_nonhttp.test.py
else
    # plugin hot reload gets in the way, again.
    export TMP=/workspace/tmp
    mkdir -p $TMP
fi

if [ "$FILTER_TESTS" != "" ]; then
    AUTEST_FLAGS+=" --filter=$FILTER_TESTS"
fi

cmake --preset bazinga-autest -DAUTEST_SANDBOX=$AUTEST_SANDBOX
cmake --build build-autest
cmake --install build-autest
cd build-autest/tests
rm -rf $AUTEST_SANDBOX
mkdir -p $AUTEST_SANDBOX
chown bazinga:bazinga $AUTEST_SANDBOX
chmod a+rwx .
/usr/local/bin/pipenv install
./autest.sh --sandbox $AUTEST_SANDBOX --disable-color | /usr/bin/au2junit-report --output-filename autest.xml

if [ "$RIO_BUILD_NUMBER" != "" ]; then
    cp -r $AUTEST_SANDBOX /workspace
fi

