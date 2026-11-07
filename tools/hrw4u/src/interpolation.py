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
"""The "{...}" holes of a string literal: a scanner finds them, and the grammar's `interpolation` rule parses one that
holds a call.

The STRING token keeps a hole as text, so a call is parsed on its own once the hole's bounds are known. A hole without
one stays a name for the symbol lookup, as it was before holes were parsed: a header name may hold characters, such
as `~` or `+`, that IDENT does not, and a 1.0 spelling must keep its meaning. A hole-only token for a name needs lexer
modes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from hrw4u.ast_visitor import make_parser
from hrw4u.common import parse_mods
from hrw4u.errors import Hrw4uSyntaxError
from hrw4u.hrw4uParser import hrw4uParser

# What opened a call in 1.0: a name or a qualified one, then `(`. IDENT also takes a dot, but "{a.b()}" was text.
_CALL = re.compile(r"\s*[a-zA-Z_][a-zA-Z0-9_-]*(?:::[a-zA-Z_][a-zA-Z0-9_-]*)*\s*\(")


@dataclass(frozen=True, slots=True)
class Escaped:
    text: str  # "{{...}}" as written


@dataclass(frozen=True, slots=True)
class Hole:
    text: str  # between the braces, as written

    @property
    def holds_call(self) -> bool:
        return _CALL.match(self.text) is not None


@dataclass(frozen=True, slots=True)
class HoleCall:
    call: hrw4uParser.FunctionCallContext
    args: tuple[str, ...]  # as written
    mods: list[str]


def scan(inner: str) -> list[str | Escaped | Hole]:
    """Split the inner text of a string literal into literal text, `{{...}}` escapes and holes. A `{` that opens
    neither, `%{`, `{}` and a parenthesis that opens no call among them, is literal text."""
    parts: list[str | Escaped | Hole] = []
    literal = 0
    i = 0
    while i < len(inner):
        found = _part_at(inner, i)
        if found is None:
            i += 1
            continue
        if i > literal:
            parts.append(inner[literal:i])
        part, literal = found
        parts.append(part)
        i = literal
    if literal < len(inner):
        parts.append(inner[literal:])
    return parts


def _part_at(inner: str, start: int) -> tuple[Escaped | Hole, int] | None:
    """The escape or hole at `start`, and where it ends."""
    if inner.startswith("{{", start) and (close := inner.find("}}", start + 2)) >= 0:
        return Escaped(inner[start:close + 2]), close + 2
    if inner[start] != "{" or inner[start - 1:start] == "%":
        return None
    depth = 0
    quoted = False
    escape = False
    i = start + 1
    # Inside a call's parentheses, a quoted string, read as the STRING token's escapes are undone, may hold a brace.
    while i < len(inner):
        char, width = _unescaped(inner, i)
        if quoted:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                quoted = False
        elif char == '"' and depth > 0:
            quoted = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0 and char == "}":
            if i == start + 1:
                return None
            hole = Hole(inner[start + 1:i])
            # Neither a name nor a call: text, as in 1.0, such as "see {(x)}".
            if "(" in hole.text and not hole.holds_call:
                return None
            return hole, i + 1
        elif depth == 0 and char == "{":
            return None
        i += width
    return None


def _unescaped(text: str, i: int) -> tuple[str, int]:
    """The character at `i` once the STRING token's `\\"` and `\\\\` escapes are undone, and how many it spans."""
    if text[i] == "\\" and i + 1 < len(text) and text[i + 1] in '"\\':
        return text[i + 1], 2
    return text[i], 1


def unescape(text: str) -> tuple[str, list[int]]:
    """`text` with the STRING token's escapes undone, and where each of its characters, and its end, is in `text`."""
    out: list[str] = []
    offsets: list[int] = []
    i = 0
    while i < len(text):
        char, width = _unescaped(text, i)
        out.append(char)
        offsets.append(i)
        i += width
    offsets.append(len(text))
    return "".join(out), offsets


def parse_call(hole: Hole) -> HoleCall:
    text, offsets = unescape(hole.text)
    try:
        tree = make_parser(text, "<interpolation>").interpolation()
    except Hrw4uSyntaxError as exc:
        raise ValueError(f"'{{{hole.text}}}' does not parse: {exc.message}") from None

    mods: list[str] = []
    if tree.modifier():
        mods = parse_mods(",".join(tok.text for tok in tree.modifier().modifierList().mods))
    call = tree.functionCall()
    args: tuple[str, ...] = ()
    if call.argumentList():
        args = tuple(
            hole.text[offsets[arg.start.start]:offsets[arg.stop.stop + 1]]
            for arg in call.argumentList().getChildren()
            if isinstance(arg, (hrw4uParser.ValueContext, hrw4uParser.FunctionCallContext)))
    return HoleCall(call=call, args=args, mods=mods)
