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

from pathlib import Path

import pytest

from hrw4u.common import compile_to_ir, create_parse_tree
from hrw4u.errors import ErrorCollector, Hrw4uSyntaxError
from hrw4u.externs import load_manifests
from hrw4u.hrw4uLexer import hrw4uLexer
from hrw4u.hrw4uParser import hrw4uParser
from utils import extern_files_for, parse_input_text

_REFUSED = 'READ_RESPONSE {\n    set-body-from("http://x/", "plain");\n}\n'


def _golden(input_file: Path) -> str:
    return input_file.with_name(input_file.name.replace(".input.txt", ".ir.txt")).read_text()


@pytest.mark.parametrize("input_file", sorted(Path("tests/data/ir").glob("*.input.txt")), ids=lambda p: p.name.split(".")[0])
def test_matches_the_parity_ir(input_file):
    source = input_file.read_text()
    _, tree = parse_input_text(source)
    # The highest target: a program still writes the lowest version that has what it uses.
    externs = load_manifests(extern_files_for(input_file))
    lines = compile_to_ir(tree, str(input_file), source, error_collector=ErrorCollector(), externs=externs, ir_version=(1, 1))
    assert "\n".join(lines) + "\n" == _golden(input_file)


def test_refusal_is_collected_and_writes_nothing():
    _, tree = parse_input_text(_REFUSED)
    collector = ErrorCollector()
    assert compile_to_ir(tree, "<test>", _REFUSED, error_collector=collector) == []
    assert [(e.line, e.column) for e in collector.errors] == [(2, 4)]
    assert "IR emitter" in collector.errors[0].message


def test_refusal_raises_without_a_collector():
    _, tree = parse_input_text(_REFUSED)
    with pytest.raises(Hrw4uSyntaxError) as err:
        compile_to_ir(tree, "<test>", _REFUSED)
    assert (err.value.line, err.value.column) == (2, 4)


def test_syntax_error_writes_nothing():
    source = "SEND_RESPONSE {\n"
    tree, _, collector = create_parse_tree(source, "<test>", hrw4uLexer, hrw4uParser, "hrw4u", collect_errors=True)
    assert collector.has_errors()
    assert compile_to_ir(tree, "<test>", source, error_collector=collector) == []


def test_sema_error_stops_before_lowering():
    source = 'REMAP {\n    inbound.resp.X-A = "1";\n}\n'
    _, tree = parse_input_text(source)
    collector = ErrorCollector()
    assert compile_to_ir(tree, "<test>", source, error_collector=collector) == []
    assert collector.errors
    assert not any("IR emitter" in e.message for e in collector.errors)
