---
name: running-urtests-in-arm64-container
description: Use when running, reproducing or debugging the internal Uranium (urtest, pytest) suite for an internal ATS branch on an Apple Silicon Mac, when apple/rio.sh --test or apple/run_urtest.sh needs to run outside Rio, or when a urtest fails only in the internal Rio pipeline (x86_64, BoringSSL).
---

<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
-->

# Running urtests in the arm64 toolchain container

## Overview

The internal pipeline runs `apple/rio.sh --test`, which installs dependencies,
builds the `bazinga-urtest` preset, installs it to `/opt/bazinga` and runs
`build-urtest/tests/urtest.sh` as user `bazinga`. Locally, run the same script
in the native arm64 toolchain image
(`docker.apple.com/edge/trafficserver_toolchain:*-el9`) with Apple's
`container` CLI. `urtest-container.sh` in this directory wraps it.

Rio's test machine is x86_64 (`trafficserver_autest` in `rio.yml`) with ATS
built against bazinga BoringSSL (`apple/install_x86_deps.sh`). The arm64
dependencies (`apple/install_arm64_deps.sh`) use system OpenSSL instead, so
TLS results differ. To reproduce a Rio-only failure, run the Rio image under
emulation from a separate worktree (the build directory is per architecture):

```bash
git worktree add --detach .claude/worktrees/urtest-x86 <branch>
cd .claude/worktrees/urtest-x86
export URTEST_PLATFORM=linux/amd64 URTEST_IMAGE=docker.apple.com/edge/trafficserver_autest:<tag from rio.yml>
$SKILL/urtest-container.sh start && $SKILL/urtest-container.sh prepare && $SKILL/urtest-container.sh run -k tls
```

Emulation makes the build about 20 minutes and tests several times slower,
so narrow with `-k`. On both architectures the test clients (`openssl`,
`curl`, Python's `ssl`) are the system OpenSSL; only ATS uses BoringSSL on
x86, so tests must ask ATS for its library (`ats.tls_library()`) rather than
the client.

## Quick reference

Run from the checkout or worktree to test (or set `URTEST_SRC`):

| Step | Command |
|---|---|
| Create container (once) | `$SKILL/urtest-container.sh start` |
| Install deps (once per container) | `$SKILL/urtest-container.sh prepare` |
| Build, install, run everything | `$SKILL/urtest-container.sh run` |
| Rebuild, then run a subset (`pytest -k`) | `$SKILL/urtest-container.sh run -k 'cripts or header_rewrite'` |
| Rerun without rebuilding (Python/test edits) | `$SKILL/urtest-container.sh test -k tunnel -n 0` |
| List failures | `$SKILL/urtest-container.sh summary` |
| Failed-test sandboxes | `container exec urtest-<dir> ls /tmp/_sandbox` |
| Delete container | `$SKILL/urtest-container.sh stop` |

`$SKILL` is `.claude/skills/running-urtests-in-arm64-container`. The
container is named `urtest-<basename of source dir>`, so each worktree gets
its own `/opt/bazinga` and `/tmp/_sandbox`. Override the image, CPUs and
memory with `URTEST_IMAGE`, `URTEST_CPUS`, `URTEST_MEMORY`.

A clean build is about 10 minutes and the full suite about 10 more at 8
CPUs; run it in the background and read `summary` afterwards. Test files are
read from the source tree, and `tools/cripts/compiler.sh` is copied from it
per test, so edits to them only need `test`; C++ and CMake edits need `run`.

## Reading failures

- Results: `build-urtest/tests/urtest.xml` (JUnit) in the source tree.
- Sandboxes of **failed** tests stay in the container at
  `/tmp/_sandbox/<test name>/<process>/log/{traffic.out,diags.log}`; passing
  ones are deleted unless `--keep-sandboxes` is passed to `urtest.sh`.
- "exited with status 33/70 while waiting for the fully initialized log
  message" is ATS dying at startup; the cause is the `ERROR`/`Fatal` line
  in that process's `diags.log`. Many tests failing this way at once is
  almost always one shared library or plugin failing to load.

## Common mistakes

| Mistake | Fix |
|---|---|
| Two concurrent runs in one container | The harness locks the sandbox ("Uranium sandbox is already in use"); give each `test` its own `--sandbox=/tmp/_sandbox_<name>` and `--junitxml`. Never `run` (reinstall `/opt/bazinga`) while another run is active. |
| Passing a test path to narrow a run | The runner always collects both test roots; select with `-k`. |
| Editing a Find module or swapping a package | Cached `find_library`/`find_path` results stick while the old file still exists; `cmake -U 'pkg_*' build-urtest` or delete `build-urtest/CMakeCache.txt`. |
| Running `rio.sh` against a worktree mounted alone | Its `git` calls fail; the script also mounts the common git dir at its host path. |
| Running servers or ATS on the Mac host | The host blocks sockets for agent-spawned processes; everything runs inside the container. |
| Committing after a run outside the script | `run_urtest.sh` does `chmod -R a+rwx tests/uranium_tests`, and `git add` then commits 100755 modes. `run` resets them; otherwise check `git diff --summary` before committing. |
| `rio.sh` in the user's checkout | It does `git checkout --branch` and overwrites `CMakeUserPresets.json`; prefer `prepare` + `run`. |
