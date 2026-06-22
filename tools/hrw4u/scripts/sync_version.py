#!/usr/bin/env python3
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
"""Rewrite the version field in pyproject.toml.

Composition (CMakeLists ATS version + bazinga build segments + HRW4U patch)
happens in apple/rio-hrw4u.sh; this script just writes the final string.
"""

import argparse
import re
import sys
from pathlib import Path

VERSION_LINE = re.compile(r'^(version\s*=\s*)"[^"]*"', re.MULTILINE)


def update(content: str, version: str) -> str:
    new_content, n = VERSION_LINE.subn(rf'\1"{version}"', content, count=1)
    if n == 0:
        raise ValueError("no top-level 'version = \"...\"' line found in pyproject.toml")
    return new_content


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="PEP 440 version to write")
    parser.add_argument("--pyproject", default="pyproject.toml", help="pyproject.toml path")
    args = parser.parse_args()

    path = Path(args.pyproject)
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr)
        return 1

    content = path.read_text()
    try:
        new_content = update(content, args.version)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if new_content != content:
        path.write_text(new_content)
        print(f"wrote {path} version = \"{args.version}\"")
    else:
        print(f"{path} version already \"{args.version}\"; no change")
    return 0


if __name__ == "__main__":
    sys.exit(main())
