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
"""What header_rewrite makes of a config, so two configs can be compared by meaning.

u4wrh and hrw4u respell a config freely -- quoting, [AND], indentation, an explicit
hook where the original relied on the default -- so comparing config text would flag
almost every round trip. Comparing what the plugin builds from the text does not.

The tokenizer and the rule grouping are ports of plugins/header_rewrite/parser.cc
(Parser::parse_line, Parser::preprocess) and header_rewrite.cc (RulesConfig::parse_config),
so they agree with the plugin on what a line means without anyone having to list it.
Equivalences the plugin applies later, while building conditions and operators, are
the only hand-written part; each cites the code that makes it hold.

Deriving any of this from hrw4u's own tables would make the oracle agree with the code
it is meant to check.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

# Parser::cond_is_hook
HOOKS = frozenset(
    {
        "READ_RESPONSE_HDR_HOOK",
        "READ_REQUEST_HDR_HOOK",
        "READ_REQUEST_PRE_REMAP_HOOK",
        "SEND_REQUEST_HDR_HOOK",
        "SEND_RESPONSE_HDR_HOOK",
        "REMAP_PSEUDO_HOOK",
        "POST_REMAP_HOOK",
        "TXN_START_HOOK",
        "TXN_CLOSE_HOOK",
    })

REMAP_DEFAULT_HOOK = "REMAP_PSEUDO_HOOK"
GLOBAL_DEFAULT_HOOK = "READ_RESPONSE_HDR_HOOK"

# Resources::gather points the hook-relative header at the same buffer as these.
_HEADER_AT_HOOK = {
    "SEND_REQUEST_HDR_HOOK": "SERVER-HEADER",
    "READ_REQUEST_HDR_HOOK": "CLIENT-HEADER",
    "READ_REQUEST_PRE_REMAP_HOOK": "CLIENT-HEADER",
    "POST_REMAP_HOOK": "CLIENT-HEADER",
}

# Condition::initialize: no AND/OR means AND, and CASE is the default.
_NO_OP_COND_MODS = frozenset({"AND", "CASE"})

_CIDR_DEFAULT_V4 = "24"
_CIDR_DEFAULT_V6 = "48"


@dataclass(frozen=True)
class Cond:
    name: str
    match: str
    arg: str | frozenset[str]
    mods: frozenset[str]


@dataclass(frozen=True)
class Op:
    name: str
    arg: str
    value: str
    mods: frozenset[str]


@dataclass(frozen=True)
class Keyword:
    word: str


Item = Cond | Op | Keyword


@dataclass(frozen=True)
class Rule:
    hook: str
    items: tuple[Item, ...]


def tokenize(line: str) -> list[str]:
    """Parser::parse_line, minus the error reporting; an empty list is a comment or blank line."""
    chars = list(line)
    tokens: list[str] = []
    state = "default"
    extracting = False
    start = 0
    i = 0

    while i < len(chars):
        c = chars[i]
        if state == "default" and (c.isspace() or c == "="):
            if extracting:
                if i > start:
                    tokens.append("".join(chars[start:i]))
                extracting = False
            elif not c.isspace():
                tokens.append(c)
        elif state != "quote" and c == "/":
            if state != "regex" and not extracting:
                state, extracting, start = "regex", True, i
            elif state == "regex" and extracting and chars[i - 1] != "\\":
                tokens.append("".join(chars[start:i + 1]))
                state, extracting = "default", False
        elif state != "regex" and c == "\\":
            if not extracting:
                extracting, start = True, i
            # Either way the character after the backslash is stepped over, so an escaped quote stays literal.
            if i + 1 < len(chars) and (ctrl := "trn".find(chars[i + 1])) >= 0:
                chars[i] = "\t\r\n"[ctrl]
                del chars[i + 1]
            else:
                del chars[i]
        elif state not in ("regex", "paren") and c == '"':
            if state != "quote" and not extracting:
                state, extracting, start = "quote", True, i + 1
            elif state == "quote" and extracting:
                tokens.append("".join(chars[start:i]))
                state, extracting = "default", False
            else:
                raise ValueError(f"malformed line: {line}")
        elif state == "default" and (i == 0 or chars[i - 1] != "%") and c == "{":
            state, extracting, start = "brace", True, i
        elif state == "brace" and c == "}":
            tokens.append("".join(chars[start:i + 1]))
            state, extracting = "default", False
        elif state == "default" and c == "(":
            state, extracting, start = "paren", True, i
        elif state == "paren" and c == ")":
            tokens.append("".join(chars[start:i + 1]))
            state, extracting = "default", False
        elif not extracting:
            if not tokens and c == "#":
                return []
            if c in "=+":
                tokens.append(c)
                i += 1
                continue
            extracting, start = True, i
        i += 1

    if extracting:
        if state == "quote":
            raise ValueError(f"unterminated quotation: {line}")
        tokens.append("".join(chars[start:]))
    return tokens


def _set_members(text: str) -> frozenset[str]:
    """Matchers<T>::set for MATCH_SET: commas split outside quotes, each member trimmed."""
    members: set[str] = set()
    in_quotes = False
    start = cur = skip = 0

    while cur < len(text):
        if text[cur] == '"':
            skip = 1
            in_quotes = not in_quotes
        elif text[cur] == "," and not in_quotes:
            members.add(text[start + skip:cur - skip].strip())
            start = cur + 1
            skip = 0
        cur += 1

    if in_quotes:
        raise ValueError(f"unmatched quotes in set: {text}")
    if start < len(text):
        members.add(text[start + skip:len(text) - skip].strip())
    return frozenset(members)


def _match(arg: str) -> tuple[str, str | frozenset[str]]:
    """parse_matcher_op: a bare argument is an equality match."""
    if not arg:
        return "", ""
    if arg[0] in "=<>":
        return arg[0], arg[1:]
    if arg[0] == "(" and arg.endswith(")"):
        return "(", _set_members(arg[1:-1])
    if arg[0] in "/{":
        return arg[0], arg
    return "=", arg


def _header_at(hook: str, text: str) -> str:
    if replacement := _HEADER_AT_HOOK.get(hook):
        return re.sub(r"(?<![-\w])HEADER:", f"{replacement}:", text)
    return text


def _cond(name: str, arg: str, mods: list[str], hook: str) -> Cond:
    name = _header_at(hook, name)
    if name == "CIDR" or name.startswith("CIDR:"):
        v4, _, v6 = name.removeprefix("CIDR").removeprefix(":").partition(",")
        name = f"CIDR:{v4 or _CIDR_DEFAULT_V4},{v6 or _CIDR_DEFAULT_V6}"
    match, value = _match(arg)
    return Cond(name, match, value, frozenset(mods) - _NO_OP_COND_MODS)


def _op(name: str, arg: str, value: str, mods: list[str], hook: str) -> Op:
    # OperatorSetConfig hands an INT record's value to strtol, which reads either spelling as 0.
    if name == "set-config" and value.lower() in ("true", "false"):
        value = value.lower()
    return Op(name, _header_at(hook, arg), _header_at(hook, value), frozenset(mods))


def _clause(tokens: list[str]) -> tuple[str, list[str], list[str]]:
    """Parser::preprocess: split off the [mods] token and classify the line."""
    mods: list[str] = []
    if tokens[-1].startswith("["):
        if not tokens[-1].endswith("]"):
            raise ValueError(f"mods have to be enclosed in []: {tokens[-1]}")
        mods = tokens.pop()[1:-1].split(",")
    head = tokens[0]
    if head in ("if", "elif", "else", "endif"):
        return head, [], mods
    if head == "cond":
        return "cond", tokens[1:], mods
    if head.startswith("%{"):
        return "cond", tokens, mods
    return "op", tokens, mods


def _cond_parts(tokens: list[str]) -> tuple[str, str]:
    if not (tokens[0].startswith("%{") and tokens[0].endswith("}")):
        raise ValueError(f"conditions must be embraced in %{{}}: {tokens[0]}")
    name = tokens[0][2:-1]
    if len(tokens) > 2 and tokens[1][0] in "=<>":
        return name, tokens[1] + tokens[2]
    return name, tokens[1] if len(tokens) > 1 else ""


def _hoist_sole_if(items: tuple[Item, ...]) -> tuple[Item, ...]:
    """A rule that is nothing but `if ... endif` runs its body exactly when the rule's own conditions would."""
    while len(items) >= 2 and items[0] == Keyword("if") and items[-1] == Keyword("endif"):
        depth = 0
        for pos, item in enumerate(items):
            if item in (Keyword("if"), Keyword("endif")):
                depth += 1 if item == Keyword("if") else -1
            if depth == 0 and pos < len(items) - 1:
                return items
            if depth == 1 and item in (Keyword("elif"), Keyword("else")):
                return items
        items = items[1:-1]
    return items


def rules(text: str, default_hook: str = REMAP_DEFAULT_HOOK) -> list[Rule]:
    """RulesConfig::parse_config: where one rule ends and the next begins, and on which hook."""
    out: list[Rule] = []
    hook = ""
    items: list[Item] = []
    in_rule = False
    section_has_operator = False
    if_depth = 0

    def close() -> None:
        out.append(Rule(hook, _hoist_sole_if(tuple(items))))

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = tokenize(line)
        if not tokens:
            continue
        kind, tokens, mods = _clause(tokens)

        if kind in ("elif", "else"):
            if not in_rule:
                raise ValueError(f"{kind} without preceding conditions")
            if if_depth == 0:
                section_has_operator = False
            items.append(Keyword(kind))
            continue

        name, arg = _cond_parts(tokens) if kind == "cond" else ("", "")
        is_hook = kind == "cond" and name in HOOKS

        if kind == "cond" and in_rule and if_depth == 0 and (is_hook or section_has_operator):
            close()
            in_rule = False

        if not in_rule:
            hook = name if is_hook else default_hook
            items = []
            in_rule = True
            section_has_operator = False
            if is_hook:
                continue
        elif is_hook:
            raise ValueError(f"%{{{name}}} must be the first condition of its rule")

        if kind == "cond":
            items.append(_cond(name, arg, mods, hook))
        elif kind == "op":
            value = " ".join(tokens[2:])
            items.append(_op(tokens[0], tokens[1] if len(tokens) > 1 else "", value, mods, hook))
            section_has_operator = section_has_operator or if_depth == 0
        else:
            items.append(Keyword(kind))
            if_depth += 1 if kind == "if" else -1
            if kind == "endif" and if_depth == 0:
                section_has_operator = True

    if in_rule:
        close()
    return out
