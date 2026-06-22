#!/usr/bin/env bash
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
#
# apple/publish-hrw4u.sh -- Build an apple-hrw4u wheel and stage it for Rio.
#
# Invoked from apple/rio.sh's TAGBUILD block when a release-branch publish
# pipeline runs with --tagbuild. Caller is responsible for gating: this
# script unconditionally builds and stages a wheel for whatever version it
# is given.
#
# Usage:
#   apple/publish-hrw4u.sh --version <ATS_VERSION> --build-number <N>
#
# The built wheel is a PEP 440 release candidate: <VERSION>.<BUILD_NUMBER>rc0.
# pip treats these as pre-releases and excludes them from default resolution
# unless the consumer explicitly opts in (e.g. pip install --pre, or pinning
# the exact version). The final release of the same build_number drops the
# 'rc0' suffix (e.g. 10.2.0.22rc0 -> 10.2.0.22) and is published manually
#
# This script does NOT upload to PyPI directly. It stages the wheel for
# Rio's package.freeform.publish mechanism, which uploads to
# apple-pypi-release-local using the project's APS group / allowRio
# default credentials. No Rio secret is required.

set -euo pipefail
shopt -s nullglob

VERSION=""
BUILD_NUMBER=""
while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --build-number)
            BUILD_NUMBER="$2"
            shift 2
            ;;
        *)
            echo >&2 "ERROR: unknown argument: $1"
            echo >&2 "usage: $0 --version <ATS_VERSION> --build-number <N>"
            exit 2
            ;;
    esac
done

if [ -z "$VERSION" ] || [ -z "$BUILD_NUMBER" ]; then
    echo >&2 "ERROR: --version and --build-number are required"
    echo >&2 "usage: $0 --version <ATS_VERSION> --build-number <N>"
    exit 2
fi

# Validate inputs are canonical PEP 440 segments. python -m build normalizes
# versions in the produced wheel filename (e.g. '01' -> '1', '10.02.0' ->
# '10.2.0'), which would mismatch our composed PKG_VERSION used for the
# stage path and wheel-glob. Reject leading-zero or otherwise non-canonical
# values up front so the operator gets a clear error instead of an opaque
# wheel-not-found later.
if ! [[ "$VERSION" =~ ^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}$ ]]; then
    echo >&2 "ERROR: --version must be canonical X.Y.Z with no leading zeros (got: '$VERSION')"
    exit 2
fi
if ! [[ "$BUILD_NUMBER" =~ ^[1-9][0-9]*$ ]]; then
    echo >&2 "ERROR: --build-number must be a positive integer with no leading zeros (got: '$BUILD_NUMBER')"
    exit 2
fi

PKG_VERSION="${VERSION}.${BUILD_NUMBER}rc0"
echo "==> publish-hrw4u: PKG_VERSION=${PKG_VERSION}"

# Skip if this version is already published. Artifactory's
# apple-pypi-release-local rejects overwriting an existing version, so a
# re-trigger of the same BUILD_NUMBER would otherwise fail the pipeline.
# We probe the wheel file itself (not the version folder), since Artifactory
# returns 200 for any folder that exists, including an empty one left behind
# by an aborted previous publish.
wheel_filename="apple_hrw4u-${PKG_VERSION}-py3-none-any.whl"
existing_url="https://artifacts.apple.com/api/storage/apple-pypi-release-local/apple-hrw4u/${PKG_VERSION}/${wheel_filename}"
http_code=$(curl -s -o /dev/null -w '%{http_code}' --netrc -I "$existing_url" 2>/dev/null || echo "000")
case "$http_code" in
    200)
        echo "==> publish-hrw4u: skipping; apple-hrw4u==${PKG_VERSION} already exists on apple-pypi-release-local"
        exit 0
        ;;
    404)
        echo "==> publish-hrw4u: version not yet published, proceeding"
        ;;
    *)
        echo "==> publish-hrw4u: WARN: existence check returned http=${http_code}, proceeding optimistically"
        ;;
esac

# Restore pyproject.toml on exit so a reused Rio workspace stays clean.
# git checkout is a no-op if the file was never mutated.
trap 'git checkout -- tools/hrw4u/pyproject.toml 2>/dev/null || true' EXIT

python3 tools/hrw4u/scripts/sync_version.py \
    --version "${PKG_VERSION}" \
    --pyproject tools/hrw4u/pyproject.toml

(cd tools/hrw4u && make package)

wheels=( tools/hrw4u/dist/apple_hrw4u-${PKG_VERSION}-*.whl )
case "${#wheels[@]}" in
    0)
        echo >&2 "ERROR: no wheel found at tools/hrw4u/dist/apple_hrw4u-${PKG_VERSION}-*.whl"
        ls -la tools/hrw4u/dist/ >&2 || true
        exit 1
        ;;
    1)
        ;;
    *)
        echo >&2 "ERROR: expected exactly one wheel, got ${#wheels[@]}: ${wheels[*]}"
        exit 1
        ;;
esac
wheel_path="${wheels[0]}"
echo "==> publish-hrw4u: built ${wheel_path}"

ci stage-lib --label wheel "${wheel_path},apple-hrw4u/${PKG_VERSION}/"

echo "==> publish-hrw4u: staged ${wheel_path} for apple-pypi-release-local/apple-hrw4u/${PKG_VERSION}/"
