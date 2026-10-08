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
"""A header_rewrite config must survive u4wrh and hrw4u with its meaning intact.

        conf0 --u4wrh--> hrw4u1 --hrw4u--> conf1 --u4wrh--> hrw4u2 --hrw4u--> conf2

    equivalent   conf0 and conf1 build the same rules (hrw_semantics)
    stable       hrw4u1 == hrw4u2 and conf1 == conf2
    raw-percent  hrw4u1 carries no %{...} that u4wrh failed to translate
    u4wrh/hrw4u  every step succeeds

conf0 and conf1 are compared as the plugin reads them, never as text: the tools respell
quoting, [AND] and hooks, so a textual diff fails for reasons that change nothing. Nor is
stability enough on its own -- a dropped [L] is lost on the first pass and then reproduces
faithfully forever.

The corpus is every fixture config plus the hand-written autest rules, which hrw4u did not
emit and so exercise spellings the fixtures never do. Starting from a fixture's config also
covers the trip that starts from its .hrw4u input, which compiles to that config. Inputs
with no config of their own -- the sandbox denials -- are compiled without the sandbox to
get one, since what the sandbox forbids is no less likely to break a round trip.

Known gaps are pinned in roundtrip_known_failures.txt, check by check: a case must fail
exactly as recorded, so a fix that clears a check, or a change that makes it fail for a
new reason, has to update the entry.
"""

from __future__ import annotations

from dataclasses import dataclass
import difflib
from pathlib import Path
import re

import pytest
from antlr4 import CommonTokenStream, InputStream

import hrw_semantics
from hrw4u.errors import ThrowingErrorListener
from hrw4u.hrw4uLexer import hrw4uLexer
from hrw4u.hrw4uParser import hrw4uParser
from hrw4u.states import SectionType
from hrw4u.visitor import HRW4UVisitor
from u4wrh.hrw_visitor import HRWInverseVisitor
from u4wrh.u4wrhLexer import u4wrhLexer
from u4wrh.u4wrhParser import u4wrhParser

FIXTURES = Path("tests/data")
AUTEST = Path("../../tests/gold_tests/pluginTest/header_rewrite")
KNOWN_FAILURES = FIXTURES / "roundtrip_known_failures.txt"

STAGE_CHECKS = ("u4wrh", "hrw4u")
CHECKS = STAGE_CHECKS + ("equivalent", "stable", "raw-percent")


@dataclass(frozen=True)
class Case:
    id: str
    path: Path
    global_plugin: bool
    compile_first: bool = False


def _global_rule_files() -> set[str]:
    """Rule files an autest loads from plugin.config, where a rule without a hook runs on READ_RESPONSE."""
    loaded = re.compile(r"plugin_config\.AddLine\(.*header_rewrite\.so\s[^)]*?([\w.-]+\.conf)")
    return {m.group(1) for test in AUTEST.glob("*.test.py") for m in loaded.finditer(test.read_text())}


def _cases() -> list[Case]:
    global_files = _global_rule_files()
    fixtures = [
        Case(f"{f.parent.name}/{f.name.removesuffix('.output.txt')}", f, False) for f in sorted(FIXTURES.glob("*/*.output.txt"))
    ]
    inputs_without_config = [
        Case(f"{f.parent.name}/{f.name.removesuffix('.input.txt')}", f, False, compile_first=True)
        for f in sorted(FIXTURES.glob("*/*.input.txt"))
        if ".fail." not in f.name and not f.with_name(f.name.replace(".input.txt", ".output.txt")).exists()
    ]
    autest = [Case(f"rules/{f.stem}", f, f.name in global_files) for f in sorted((AUTEST / "rules").glob("*.conf"))]
    return fixtures + inputs_without_config + autest


def _known_failures() -> dict[str, dict[str, str]]:
    """`case: check ["substring"], ...` -- a stage check must name part of its error, the rest stand alone."""
    entry = re.compile(r'\s*([a-z0-9-]+)(?:\s+"([^"]*)")?\s*(?:,|$)')
    known: dict[str, dict[str, str]] = {}

    for lineno, line in enumerate(KNOWN_FAILURES.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        case_id, sep, rest = line.partition(":")
        assert sep, f"{KNOWN_FAILURES}:{lineno}: expected `case: check, ...`"
        checks: dict[str, str] = {}
        pos = 0
        while pos < len(rest):
            m = entry.match(rest, pos)
            assert m and m.end() > pos, f"{KNOWN_FAILURES}:{lineno}: cannot parse {rest[pos:]!r}"
            check, substring = m.group(1), m.group(2) or ""
            assert check in CHECKS, f"{KNOWN_FAILURES}:{lineno}: unknown check {check!r}"
            assert bool(substring) == (check in STAGE_CHECKS), (
                f"{KNOWN_FAILURES}:{lineno}: {check} {'needs' if check in STAGE_CHECKS else 'takes no'} error substring")
            checks[check] = substring
            pos = m.end()
        assert case_id not in known, f"{KNOWN_FAILURES}:{lineno}: {case_id} listed twice"
        known[case_id] = checks
    return known


def _parse(text: str, filename: str, lexer_class: type, parser_class: type):
    listener = ThrowingErrorListener(filename=filename)
    lexer = lexer_class(InputStream(text))
    lexer.removeErrorListeners()
    lexer.addErrorListener(listener)
    parser = parser_class(CommonTokenStream(lexer))
    parser.removeErrorListeners()
    parser.addErrorListener(listener)
    return parser.program()


def _to_hrw4u(conf: str, case: Case) -> str:
    # The u4wrh grammar ends every line with EOL, and hrw4u does not end its output with one.
    tree = _parse(conf if conf.endswith("\n") else conf + "\n", case.id, u4wrhLexer, u4wrhParser)
    section = SectionType.READ_RESPONSE if case.global_plugin else SectionType.REMAP
    return "\n".join(HRWInverseVisitor(filename=case.id, section_label=section).visit(tree))


def _to_conf(hrw4u: str, case: Case) -> str:
    tree = _parse(hrw4u, case.id, hrw4uLexer, hrw4uParser)
    return "\n".join(HRW4UVisitor(filename=case.id).visit(tree))


def _error(e: Exception) -> str:
    text = str(e).strip()
    return text.splitlines()[0] if text else type(e).__name__


def _rule_diff(before: list[hrw_semantics.Rule], after: list[hrw_semantics.Rule]) -> str:

    def lines(rules: list[hrw_semantics.Rule]) -> list[str]:
        return [line for r in rules for line in [f"rule on {r.hook}"] + [f"    {item}" for item in r.items]]

    return "\n".join(difflib.unified_diff(lines(before), lines(after), "conf0", "conf1", lineterm="", n=1))


def _round_trip(case: Case) -> dict[str, str]:
    """The checks this case fails, each with what went wrong."""
    conf0 = case.path.read_text()
    if case.compile_first:
        conf0 = _to_conf(conf0, case)
    try:
        hrw4u1 = _to_hrw4u(conf0, case)
    except Exception as e:
        return {"u4wrh": _error(e)}
    try:
        conf1 = _to_conf(hrw4u1, case)
    except Exception as e:
        return {"hrw4u": f"{_error(e)}\n--- hrw4u1 ---\n{hrw4u1}"}

    failures: dict[str, str] = {}
    default_hook = hrw_semantics.GLOBAL_DEFAULT_HOOK if case.global_plugin else hrw_semantics.REMAP_DEFAULT_HOOK
    before, after = hrw_semantics.rules(conf0, default_hook), hrw_semantics.rules(conf1, default_hook)
    if before != after:
        failures["equivalent"] = f"{_rule_diff(before, after)}\n--- hrw4u1 ---\n{hrw4u1}"

    untranslated = [line.strip() for line in hrw4u1.splitlines() if "%{" in line and not line.lstrip().startswith("#")]
    if untranslated:
        failures["raw-percent"] = "\n".join(untranslated)

    try:
        hrw4u2 = _to_hrw4u(conf1, case)
    except Exception as e:
        failures["u4wrh"] = f"second pass: {_error(e)}"
        return failures
    try:
        conf2 = _to_conf(hrw4u2, case)
    except Exception as e:
        failures["hrw4u"] = f"second pass: {_error(e)}"
        return failures

    if (hrw4u1, conf1) != (hrw4u2, conf2):
        diff = difflib.unified_diff(
            (hrw4u1 + "\n" + conf1).splitlines(), (hrw4u2 + "\n" + conf2).splitlines(),
            "first pass",
            "second pass",
            lineterm="",
            n=1)
        failures["stable"] = "\n".join(diff)
    return failures


CASES = _cases()
KNOWN = _known_failures()


@pytest.mark.reverse
@pytest.mark.parametrize("case", [pytest.param(c, id=c.id) for c in CASES])
def test_config_survives_a_round_trip(case: Case) -> None:
    actual = _round_trip(case)
    expected = KNOWN.get(case.id, {})

    matches = actual.keys() == expected.keys() and all(expected[check] in actual[check] for check in expected)
    report = "\n\n".join(f"[{check}] {message}" for check, message in actual.items())
    assert matches, (
        f"{case.id}: {KNOWN_FAILURES} expects {expected or 'no failures'}, got {sorted(actual) or 'no failures'}\n\n{report}")


def test_every_known_failure_names_a_case() -> None:
    assert not KNOWN.keys() - {c.id for c in CASES}


def test_global_rule_files_are_found() -> None:
    # If this pattern stops matching, every autest rule silently becomes a remap rule.
    assert any(c.global_plugin for c in CASES)
