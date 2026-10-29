#!/bin/bash

set -x
set -e

echo "Running as ${USER} with id $(id)"

# A pytest -k expression; empty or "*" runs everything.
FILTER_TESTS=$1
BUILD_VERSION=${BUILD_VERSION:-1}
TMP=${TMP:-/tmp}
SRC=$(pwd)

export NO_COLOR=1

URTEST_SANDBOX="/tmp/_sandbox"
URTEST_FLAGS=(-n "${URTEST_JOBS:-auto}" --junitxml="${SRC}/build-urtest/tests/urtest.xml")
if [ "$RIO_BUILD_NUMBER" != "" ]; then
    URTEST_FLAGS+=(--color=no)

    # Broken under rio
    URTEST_FLAGS+=(--ignore="${SRC}/tests/uranium_tests/thread_config")
    URTEST_FLAGS+=(--ignore="${SRC}/tests/uranium_tests/tls/test_tls_forward_nonhttp.py")
else
    # plugin hot reload gets in the way, again.
    export TMP=/workspace/tmp
    mkdir -p $TMP
fi

if [ "$FILTER_TESTS" != "" ] && [ "$FILTER_TESTS" != "*" ]; then
    URTEST_FLAGS+=(-k "$FILTER_TESTS")
fi

export LD_LIBRARY_PATH=/opt/bazinga/lib64
export UV_CACHE_DIR=/tmp/uv-cache

cmake --preset bazinga-urtest -DURTEST_SANDBOX=$URTEST_SANDBOX
cmake --build build-urtest
cmake --install build-urtest
cd build-urtest/tests
rm -rf $URTEST_SANDBOX
mkdir -p $URTEST_SANDBOX $UV_CACHE_DIR
chown bazinga:bazinga $URTEST_SANDBOX $UV_CACHE_DIR
# bazinga must be able to traverse the workspace to reach the build tree. A
# bind-mounted local workspace cannot be chmod'ed.
if [ "$RIO_BUILD_NUMBER" != "" ]; then
    chmod a+rx /workspace
fi
chmod a+rx /workspace/build-urtest
chmod a+rwx .
# The relock below rewrites the root-owned copy of uv.lock as bazinga.
chmod a+rw uv.lock

# Some tests write generated data into the test directory
chmod -R a+rwx /workspace/tests/uranium_tests

# uv.lock pins pypi.org, but the image points uv at pypi.apple.com, so relock
# this build-tree copy against it; uv keeps the locked versions. Then fetch the
# environment now, since urtest.sh clears the proxy variables before "uv run".
su --command "uv lock --project $(pwd)" bazinga
su --command "uv sync --locked --project $(pwd)" bazinga

set +e
su --command "./urtest.sh --no-run-in-container $(printf '%q ' "${URTEST_FLAGS[@]}")" bazinga
urtest_rc=$?
set -e

if [ "$RIO_BUILD_NUMBER" != "" ]; then
    cp -r $URTEST_SANDBOX /workspace
fi

if [ "$urtest_rc" -ne 0 ]; then
    echo >&2 "urtest exited with status ${urtest_rc}"
fi
exit $urtest_rc
