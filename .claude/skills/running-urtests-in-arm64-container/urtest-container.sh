#!/bin/bash
#
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# Runs the internal urtest pipeline (apple/run_urtest.sh) inside the arm64
# toolchain image with Apple's `container` CLI, against the checkout or
# worktree given by URTEST_SRC (default: the current git top level).
#
#   urtest-container.sh start            create the long-lived container
#   urtest-container.sh prepare          one-time package and crypto setup
#   urtest-container.sh run [-k EXPR]    build, install and run urtest
#   urtest-container.sh test [ARGS...]   rerun urtest.sh without rebuilding
#   urtest-container.sh summary          list failures from urtest.xml
#   urtest-container.sh shell            interactive shell in /workspace
#   urtest-container.sh stop             delete the container

set -euo pipefail

IMAGE=${URTEST_IMAGE:-docker.apple.com/edge/trafficserver_toolchain:f2efdfceda58-1-el9}
SRC=${URTEST_SRC:-$(git rev-parse --show-toplevel)}
SRC=$(cd "$SRC" && pwd -P)
# One container per source tree, so a worktree never shares /opt/bazinga or
# /tmp/_sandbox with another tree's run.
NAME=${URTEST_CONTAINER:-urtest-$(basename "$SRC")}

# A worktree's .git file points at the main clone by host path; mounting the
# common git dir at that same path keeps git, and the proxy-verifier download
# cached under it, working inside the container.
common_dir=$(git -C "$SRC" rev-parse --path-format=absolute --git-common-dir)
mounts=(-v "$SRC:/workspace")
if [ "$common_dir" != "$SRC/.git" ]; then
  mounts+=(-v "$common_dir:$common_dir")
fi

in_container() {
  container exec "$NAME" bash -c "cd /workspace && $1"
}

cmd=${1:-}
shift || true

case "$cmd" in
start)
  container run -d --name "$NAME" ${URTEST_PLATFORM:+--platform "$URTEST_PLATFORM"} -c "${URTEST_CPUS:-8}" -m "${URTEST_MEMORY:-16g}" "${mounts[@]}" "$IMAGE" sleep infinity
  ;;
prepare)
  # What apple/rio.sh does before building, minus its `git checkout`.
  in_container 'if [ "$(uname -m)" = x86_64 ]; then
      eval "$(grep -E "^(BORINGSSL|LIBURING)_VERSION=" apple/rio.sh)" &&
      BORINGSSL_VERSION=$BORINGSSL_VERSION LIBURING_VERSION=$LIBURING_VERSION ./apple/install_x86_deps.sh
    else
      ./apple/install_arm64_deps.sh
    fi &&
    update-crypto-policies --set DEFAULT:SHA1 &&
    cp apple/CMakeUserPresets.json .'
  ;;
run)
  filter=""
  if [ "${1:-}" = "-k" ]; then
    filter=$2
  fi
  rc=0
  in_container "rm -f build-urtest/tests/urtest.xml; ./apple/run_urtest.sh $(printf '%q' "$filter")" || rc=$?
  # run_urtest.sh makes tests/uranium_tests world-writable for user bazinga;
  # drop the exec bits it added so git sees no mode changes.
  git -C "$SRC" diff --summary -- tests/uranium_tests | sed -n 's/^ mode change 100644 => 100755 //p' |
    while IFS= read -r file; do chmod a-x "$SRC/$file"; done
  exit $rc
  ;;
test)
  # Pytest arguments pass straight through after the default -n auto, e.g.
  # `test -k tunnel -n 0`; results replace urtest.xml so `summary` reads this
  # run. TMP matches what run_urtest.sh uses outside Rio.
  container exec "$NAME" su --command "cd /workspace/build-urtest/tests && mkdir -p /workspace/tmp && TMP=/workspace/tmp NO_COLOR=1 ./urtest.sh --no-run-in-container --junitxml=/workspace/build-urtest/tests/urtest.xml -n auto ${*:+$(printf '%q ' "$@")}" bazinga
  ;;
summary)
  python3 - "$SRC/build-urtest/tests/urtest.xml" <<'EOF'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
suites = [root] if root.tag == "testsuite" else list(root)
totals = {k: sum(int(s.get(k, 0)) for s in suites) for k in ("tests", "failures", "errors", "skipped")}
print(" ".join(f"{k}={v}" for k, v in totals.items()))
for case in root.iter("testcase"):
    for kind in ("failure", "error"):
        node = case.find(kind)
        if node is not None:
            message = (node.get("message") or "").splitlines()[0][:160] if node.get("message") else ""
            print(f"{kind.upper():7} {case.get('classname')}::{case.get('name')}  {message}")
EOF
  ;;
shell)
  container exec -it "$NAME" bash -c 'cd /workspace && exec bash'
  ;;
stop)
  container stop "$NAME" || true
  container rm "$NAME"
  ;;
*)
  sed -n '19,29p' "$0"
  exit 2
  ;;
esac
