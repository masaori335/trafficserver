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
"""How a string literal splits into text, `{{...}}` escapes and holes, and what a hole holding a call parses to."""

from __future__ import annotations

import pytest

from hrw4u.interpolation import Escaped, Hole, parse_call, scan


@pytest.mark.parametrize(
    "inner, parts", [
        ("plain", ["plain"]),
        ("a {inbound.url.path} b", ["a ", Hole("inbound.url.path"), " b"]),
        ("{{x}}{y}", [Escaped("{{x}}"), Hole("y")]),
        ("%{METHOD}", ["%{METHOD}"]),
        ("{}", ["{}"]),
        ("a{b", ["a{b"]),
        ("a{b{c}", ["a{b", Hole("c")]),
        ("{{a}", ["{", Hole("a")]),
        ("{a)b}", ["{a)b}"]),
        ("{inbound.req.X~Foo}", [Hole("inbound.req.X~Foo")]),
        ('{T::F(\\"}\\")}!', [Hole('T::F(\\"}\\")'), "!"]),
        ('{T::F(\\"a\\\\\\"}\\")}', [Hole('T::F(\\"a\\\\\\"}\\")')]),
        ("{f(a}", ["{f(a}"]),
        ("see {(x)}", ["see {(x)}"]),
        ("{a b(c)}", ["{a b(c)}"]),
        ("{a.b()}", ["{a.b()}"]),
    ],
    ids=[
        "text", "hole", "escape", "percent", "empty", "unterminated", "unterminated-then-hole", "unclosed-escape", "stray-paren",
        "header-name", "brace-in-quoted-argument", "escaped-quote-in-argument", "unclosed-call", "parenthesis", "words-then-call",
        "dotted-call"
    ])
def test_a_literal_splits_into_parts(inner, parts):
    assert scan(inner) == parts


@pytest.mark.parametrize("text, holds_call", [("inbound.url.path with NORM", False), ("random(1)", True)], ids=["name", "call"])
def test_only_a_hole_with_a_parenthesis_holds_a_call(text, holds_call):
    assert Hole(text).holds_call is holds_call


@pytest.mark.parametrize(
    "text, name, args", [
        ("cache()", "cache", ()),
        ("cidr(24,48)", "cidr", ("24", "48")),
        (" cidr( 24 , 48 ) ", "cidr", ("24", "48")),
        ('f(\\"a, b\\", c)', "f", ('\\"a, b\\"', "c")),
        ('f(\\"a\\\\\\"b\\")', "f", ('\\"a\\\\\\"b\\"',)),
        ("f(g(a, b), c)", "f", ("g(a, b)", "c")),
        ("T::F(1, true)", "T::F", ("1", "true")),
    ],
    ids=["no-args", "args", "whitespace", "quoted-comma", "escaped-quote", "nested-call", "qualified"])
def test_a_call_keeps_its_arguments_as_written(text, name, args):
    hole = parse_call(Hole(text))
    assert (hole.call.funcName.text, hole.args, hole.mods) == (name, args, [])


@pytest.mark.parametrize(
    "text, mods", [("random(1) with NORM", ["NORM"]), ("random(1) with norm, NORM,", ["NORM"])], ids=["mods", "trailing-comma"])
def test_a_call_takes_modifiers(text, mods):
    assert parse_call(Hole(text)).mods == mods


def test_a_call_that_does_not_parse_names_the_hole():
    with pytest.raises(ValueError, match=r"^'\{f\(a b\)\}' does not parse: "):
        parse_call(Hole("f(a b)"))
