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
"""hrw_semantics is the round-trip test's oracle: these pin both what it forgives and what it must not."""

from __future__ import annotations

import pytest

import hrw_semantics
from hrw_semantics import GLOBAL_DEFAULT_HOOK, Cond, Op, Rule, rules

EQUIVALENT = [
    pytest.param(
        'cond %{SEND_RESPONSE_HDR_HOOK}\n  set-header X-A "a b"\n',
        '# comment\n\ncond %{SEND_RESPONSE_HDR_HOOK} [AND]\n        set-header X-A "a b"\n',
        id="layout-comments-and-default-AND"),
    pytest.param('set-header X-A hello\n', 'set-header X-A "hello"\n', id="op-quoting"),
    pytest.param(
        'cond %{CLIENT-HEADER:X} "v"\nset-status 403\n', 'cond %{CLIENT-HEADER:X} =v\nset-status 403\n', id="implicit-equality"),
    pytest.param(
        'cond %{CLIENT-HEADER:X} =v [NOCASE,PRE]\nset-status 403\n',
        'cond %{CLIENT-HEADER:X} =v [PRE,NOCASE,CASE]\nset-status 403\n',
        id="mod-order-and-CASE"),
    pytest.param('set-status 403\n', 'cond %{REMAP_PSEUDO_HOOK}\nset-status 403\n', id="implicit-remap-hook"),
    pytest.param('cond %{METHOD} (GET,"PUT")\nset-status 403\n', 'cond %{METHOD} (PUT, GET)\nset-status 403\n', id="set-members"),
    pytest.param(
        'cond %{CIDR} =10.0.0.0\nset-status 403\ncond %{CIDR:16} =10.0.0.0\nset-status 403\n'
        'cond %{CIDR:,8} =10.0.0.0\nset-status 403\n',
        'cond %{CIDR:24,48} =10.0.0.0\nset-status 403\ncond %{CIDR:16,48} =10.0.0.0\nset-status 403\n'
        'cond %{CIDR:24,8} =10.0.0.0\nset-status 403\n',
        id="cidr-defaults"),
    pytest.param(
        'cond %{SEND_REQUEST_HDR_HOOK}\ncond %{HEADER:X} =v\nset-header X-A "v=%{HEADER:Y}"\n',
        'cond %{SEND_REQUEST_HDR_HOOK}\ncond %{SERVER-HEADER:X} =v\nset-header X-A "v=%{SERVER-HEADER:Y}"\n',
        id="hook-relative-header"),
    pytest.param(
        'cond %{REMAP_PSEUDO_HOOK}\nif\n  cond %{CLIENT-URL:PATH} /x/\n    set-status 403\nendif\n',
        'cond %{REMAP_PSEUDO_HOOK}\ncond %{CLIENT-URL:PATH} /x/\n  set-status 403\n',
        id="sole-if-block"),
    pytest.param(
        'set-config proxy.config.http.cache.http FALSE\n',
        'set-config "proxy.config.http.cache.http" false\n',
        id="set-config-bool-spelling"),
]

DIFFERENT = [
    pytest.param(
        'cond %{SEND_RESPONSE_HDR_HOOK}\nset-header X-A a [L]\n', 'cond %{SEND_RESPONSE_HDR_HOOK}\nset-header X-A a\n', id="L"),
    pytest.param(
        'cond %{GROUP}\ncond %{CLIENT-HEADER:X} =v [NOT]\ncond %{GROUP:END} [NOT]\nset-status 403\n',
        'cond %{GROUP}\ncond %{CLIENT-HEADER:X} =v [NOT]\ncond %{GROUP:END}\nset-status 403\n',
        id="group-NOT"),
    pytest.param(
        'cond %{METHOD} ("a,b")\nset-status 403\n', 'cond %{METHOD} ("a, b")\nset-status 403\n', id="space-inside-set-member"),
    pytest.param(
        'cond %{SEND_RESPONSE_HDR_HOOK}\ncond %{CLIENT-HEADER:X} =v\n  set-status 403\nelse\n  set-status 404\n'
        'cond %{CLIENT-HEADER:Y} =v\n  set-status 405\n',
        'cond %{SEND_RESPONSE_HDR_HOOK}\ncond %{CLIENT-HEADER:X} =v\n  set-status 403\nelse\n  set-status 404\n'
        '  if\n    cond %{CLIENT-HEADER:Y} =v\n      set-status 405\n  endif\n',
        id="cond-after-else-starts-a-default-hook-rule"),
    pytest.param(
        'cond %{SEND_RESPONSE_HDR_HOOK}\ncond %{HEADER:X} =v\nset-status 403\n',
        'cond %{SEND_RESPONSE_HDR_HOOK}\ncond %{SERVER-HEADER:X} =v\nset-status 403\n',
        id="header-equivalence-is-per-hook"),
    pytest.param('cond %{STATE-FLAG:7}\nset-status 403\n', 'cond %{STATE-FLAG:0}\nset-status 403\n', id="state-slot"),
    pytest.param(
        'cond %{REMAP_PSEUDO_HOOK}\nif\n  cond %{CLIENT-URL:PATH} /x/\n    set-status 403\nelse\n    set-status 404\nendif\n',
        'cond %{REMAP_PSEUDO_HOOK}\ncond %{CLIENT-URL:PATH} /x/\n  set-status 403\nelse\n  set-status 404\n',
        id="if-with-else-is-not-hoisted"),
]


@pytest.mark.parametrize("left,right", EQUIVALENT)
def test_equivalent_spellings_compare_equal(left: str, right: str) -> None:
    assert rules(left) == rules(right)


@pytest.mark.parametrize("left,right", DIFFERENT)
def test_different_meanings_compare_unequal(left: str, right: str) -> None:
    assert rules(left) != rules(right)


def test_default_hook_depends_on_where_the_config_is_loaded() -> None:
    config = 'set-header X-A a\n'

    assert rules(config, GLOBAL_DEFAULT_HOOK) == [Rule(GLOBAL_DEFAULT_HOOK, (Op("set-header", "X-A", "a", frozenset()),))]
    assert rules(config, GLOBAL_DEFAULT_HOOK) != rules(config)


def test_a_cond_after_an_operator_starts_a_new_rule() -> None:
    parsed = rules('cond %{SEND_RESPONSE_HDR_HOOK}\nset-status 403\ncond %{CLIENT-HEADER:X} =v\nset-status 404\n')

    assert [r.hook for r in parsed] == ["SEND_RESPONSE_HDR_HOOK", hrw_semantics.REMAP_DEFAULT_HOOK]
    assert parsed[1].items[0] == Cond("CLIENT-HEADER:X", "=", "v", frozenset())


@pytest.mark.parametrize(
    "line,tokens", [
        pytest.param('set-header X "a b"', ["set-header", "X", "a b"], id="quotes-are-stripped"),
        pytest.param(r'set-header X "a\"b"', ["set-header", "X", 'a"b'], id="escaped-quote-stays-literal"),
        pytest.param(r'set-header X a\tb', ["set-header", "X", "a\tb"], id="control-escape"),
        pytest.param(
            'cond %{CLIENT-URL:PATH} /^a\\/b$/ [NOCASE]', ["cond", "%{CLIENT-URL:PATH}", "/^a\\/b$/", "[NOCASE]"],
            id="regex-keeps-backslashes"),
        pytest.param('cond %{METHOD} (GET, "P,Q")', ["cond", "%{METHOD}", '(GET, "P,Q")'], id="paren-keeps-quotes"),
        pytest.param('  # just a comment', [], id="comment"),
    ])
def test_tokenize_matches_the_plugin(line: str, tokens: list[str]) -> None:
    assert hrw_semantics.tokenize(line.strip()) == tokens
