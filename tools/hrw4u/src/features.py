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
"""The language features that need more than IR 1.0, or that a .conf cannot spell, and the IR versions hrw4u writes."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

# The versions plugins/experimental/hrw4u/src/ir_reader.h reads: the two rise together.
IR_VERSIONS = ((1, 0), (1, 1))


@dataclass(frozen=True)
class Feature:
    name: str
    ir_version: tuple[int, int]
    conf: bool  # whether header_rewrite has a spelling for it


CALL_VALUE = Feature("a call to a library function", (1, 1), False)
INSTANCE_VARS = Feature("INSTANCE_VARS", (1, 1), False)


def version_text(version: tuple[int, int]) -> str:
    return f"{version[0]}.{version[1]}"


def parse_ir_version(text: str) -> tuple[int, int]:
    for version in IR_VERSIONS:
        if version_text(version) == text:
            return version
    raise ValueError(f"unknown IR version '{text}' ({', '.join(map(version_text, IR_VERSIONS))})")


def version_line(version: tuple[int, int]) -> str:
    return f"hrw4u-ir {version_text(version)}"


def ir_version_for(features: Iterable[Feature]) -> tuple[int, int]:
    """The lowest version that has every feature a program uses, so a reader of an older one still takes the program."""
    return max((feature.ir_version for feature in features), default=IR_VERSIONS[0])


def check_target(feature: Feature, target: tuple[int, int] | None) -> None:
    """Refuse a feature the output cannot hold: `target` is the IR version written, or None for a .conf."""
    if target is None:
        if not feature.conf:
            raise ValueError(f"'{feature.name}' has no .conf spelling; compile with --output ir")
        return
    if feature.ir_version > target:
        raise ValueError(
            f"'{feature.name}' needs IR {version_text(feature.ir_version)}; the target is {version_text(target)} (--ir-version)")
