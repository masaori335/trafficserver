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
import utils

from hrw4u.common import compile_to_conf, compile_to_ir
from hrw4u.errors import ErrorCollector, Hrw4uSyntaxError
from hrw4u.externs import ExternDecl, load_manifests
from hrw4u.visitor import HRW4UVisitor

_CRIPTS = Path("tests/data/extern/cripts.ext.hrw4u")

_EXTERN_CALL = Path("tests/data/ir/extern_call.input.txt")
_TEST_FUNCTIONS = ("extern T::Log(string) -> string;\nextern T::Str(int64, bool) -> string pure;\nextern T::Flag() -> bool pure;\n")


def _manifest(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


def _load_error(*paths: Path) -> Hrw4uSyntaxError:
    with pytest.raises(Hrw4uSyntaxError) as err:
        load_manifests(list(paths))
    return err.value


def test_the_cripts_manifest_loads():
    externs = load_manifests([_CRIPTS])
    assert list(externs) == [
        "prism::Crypto::Base64::Encode",
        "prism::Crypto::Base64::Decode",
        "prism::File::FirstLine",
        "prism::Crypto::Hex::Decode",
        "prism::Crypto::HMAC::SHA256::Sign",
        "cripts::Geo::Country",
        "cripts::Geo::ASN",
        "cripts::Geo::ASNName",
    ]
    assert externs["prism::Crypto::Base64::Encode"] == ExternDecl(
        "prism::Crypto::Base64::Encode", ("string",), "string", "pure", f"{_CRIPTS}:4")
    assert externs["prism::File::FirstLine"].effect == "load"
    assert externs["prism::Crypto::HMAC::SHA256::Sign"] == ExternDecl(
        "prism::Crypto::HMAC::SHA256::Sign", ("string", "string"), "string", "pure", f"{_CRIPTS}:8")
    assert externs["cripts::Geo::ASN"] == ExternDecl("cripts::Geo::ASN", (), "int64", "pure", f"{_CRIPTS}:12")


def test_no_effect_word_declares_an_effect(tmp_path):
    path = _manifest(tmp_path, "e.ext.hrw4u", "extern T::Log(string) -> bool;\n")
    assert load_manifests([path])["T::Log"] == ExternDecl("T::Log", ("string",), "bool", "effect", f"{path}:1")


def test_extern_in_a_script_errors_on_both_front_ends():
    source = "extern T::F() -> string pure;\nREMAP {\n    no-op();\n}\n"
    _, tree = utils.parse_input_text(source)
    expected = [(1, 0, "extern is allowed only in a manifest (--extern FILE)")]

    sema = ErrorCollector()
    assert compile_to_ir(tree, "<test>", source, error_collector=sema) == []
    assert [(e.line, e.column, e.message) for e in sema.errors] == expected

    cst = ErrorCollector()
    HRW4UVisitor(filename="<test>", error_collector=cst).visit(tree)
    assert [(e.line, e.column, e.message) for e in cst.errors] == expected


def test_extern_is_still_a_name_in_a_script():
    """`extern` is not reserved: a 1.0 script naming a variable or a parameter with it compiles as one naming it otherwise."""
    source = (
        "procedure syn::p($extern) {\n    inbound.req.X-A = \"$extern\";\n}\nVARS {\n    extern: bool;\n}\n"
        "REMAP {\n    if extern {\n        no-op();\n    }\n    syn::p(extern);\n}\n")
    renamed = source.replace("extern", "flag")
    outputs = []
    for text in (source, renamed):
        _, tree = utils.parse_input_text(text)
        cst, sema = ErrorCollector(), ErrorCollector()
        outputs.append(HRW4UVisitor(filename="<test>", error_collector=cst).visit(tree))
        assert compile_to_conf(tree, "<test>", text, error_collector=sema) == outputs[-1]
        assert not cst.has_errors() and not sema.has_errors()
    # The procedure writes its argument's text, which is the name.
    assert [line.replace("extern", "flag") for line in outputs[0]] == outputs[1]
    assert "cond %{STATE-FLAG:0}" in "\n".join(outputs[0])


def test_a_declaration_spelled_with_another_word_is_a_syntax_error(tmp_path):
    expected = [(1, 0, "mismatched input 'foo' expecting 'extern'")]
    source = "foo T::F() -> string pure;\nREMAP {\n    no-op();\n}\n"
    _, tree = utils.parse_input_text(source)

    sema = ErrorCollector()
    assert compile_to_ir(tree, "<test>", source, error_collector=sema) == []
    assert [(e.line, e.column, e.message) for e in sema.errors] == expected

    cst = ErrorCollector()
    HRW4UVisitor(filename="<test>", error_collector=cst).visit(tree)
    assert [(e.line, e.column, e.message) for e in cst.errors] == expected

    err = _load_error(_manifest(tmp_path, "m.ext.hrw4u", "foo T::F() -> string pure;\n"))
    assert (err.line, err.column, err.message) == expected[0]


def test_a_section_in_a_manifest_errors(tmp_path):
    path = _manifest(tmp_path, "m.ext.hrw4u", "extern T::F() -> string pure;\nREMAP {\n    no-op();\n}\n")
    err = _load_error(path)
    assert (err.filename, err.line, err.message) == (str(path), 2, "a manifest holds extern declarations only")


def test_a_duplicate_across_two_manifests_names_both_places(tmp_path):
    first = _manifest(tmp_path, "a.ext.hrw4u", "# a\nextern T::F() -> string pure;\n")
    second = _manifest(tmp_path, "b.ext.hrw4u", "extern T::F(string) -> string pure;\n")
    err = _load_error(first, second)
    assert (err.filename, err.line) == (str(second), 1)
    assert err.message == f"'T::F' is declared twice: {first}:2 and {second}:1"


@pytest.mark.parametrize(
    "decl", ["extern T::F(string, float) -> string pure;", "extern T::F() -> float pure;"], ids=["param", "result"])
def test_float_is_an_unknown_type(tmp_path, decl):
    err = _load_error(_manifest(tmp_path, "t.ext.hrw4u", decl + "\n"))
    assert (err.line, err.message) == (1, "unknown type 'float' (string, int64, bool)")


def test_impure_is_an_unknown_effect(tmp_path):
    err = _load_error(_manifest(tmp_path, "t.ext.hrw4u", "extern T::F() -> string impure;\n"))
    assert (err.line, err.message) == (1, "unknown effect 'impure' (pure, load, or none)")


def test_a_syntax_error_names_the_manifest(tmp_path):
    path = _manifest(tmp_path, "t.ext.hrw4u", "extern T::F( -> string;\n")
    assert _load_error(path).filename == str(path)


@pytest.fixture
def externs(tmp_path: Path):
    return load_manifests([_CRIPTS, _manifest(tmp_path, "t.ext.hrw4u", _TEST_FUNCTIONS)])


def _ir(source: str, externs, ir_version=(1, 1)) -> tuple[list[str], list[tuple[int, int, str]]]:
    _, tree = utils.parse_input_text(source)
    collector = ErrorCollector()
    lines = compile_to_ir(tree, "<test>", source, error_collector=collector, externs=externs, ir_version=ir_version)
    return lines, [(e.line, e.column, e.message) for e in collector.errors]


def _cst_errors(source: str, externs) -> list[tuple[int, int, str]]:
    _, tree = utils.parse_input_text(source)
    collector = ErrorCollector()
    HRW4UVisitor(filename="<test>", error_collector=collector, externs=externs).visit(tree)
    return [(e.line, e.column, e.message) for e in collector.errors]


def _assignment(value: str, operator: str = "=") -> str:
    return f"SEND_RESPONSE {{\n    inbound.resp.X {operator} {value};\n}}\n"


def test_nested_calls_lower_the_inner_call_first(externs):
    lines, errors = _ir(_assignment('prism::Crypto::Hex::Decode(prism::Crypto::Base64::Decode("aGk="))'), externs)
    assert errors == []
    assert lines[0] == "hrw4u-ir 1.1"
    assert lines[5:] == [
        "    %1:sview = const.s K0 @2:4",
        "    %2:sview = const.s K1 @2:4",
        '    %3:sview = call.pure EXT"prism::Crypto::Base64::Decode", %2 @2:4',
        '    %4:sview = call.pure EXT"prism::Crypto::Hex::Decode", %3 @2:4',
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %4 @2:4",
        "    ret @2:4",
    ]


def test_arguments_take_the_types_the_declaration_names(externs):
    lines, errors = _ir(_assignment("T::Str(5, true)"), externs)
    assert errors == []
    assert lines[3:5] == ['  consts = [K0:"X"]', "  ints   = [I0:5, I1:1]"]
    assert lines[6:10] == [
        "    %1:sview = const.s K0 @2:4",
        "    %2:i64 = const.i I0 @2:4",
        "    %3:bool = const.i I1 @2:4",
        '    %4:sview = call.pure EXT"T::Str", %2, %3 @2:4',
    ]


def test_a_call_appends_with_plus_equal(externs):
    lines, errors = _ir(_assignment('prism::Crypto::Base64::Encode("a")', "+="), externs)
    assert errors == []
    assert "    call.eff BI_ADD_CLIENT_RESP_HEADER, %1, %3 @2:4" in lines


@pytest.mark.parametrize("target", ["inbound.resp.body", "inbound.status.reason"])
def test_a_call_sets_a_target_whose_value_is_validated(externs, target):
    source = f'SEND_RESPONSE {{\n    {target} = prism::Crypto::Base64::Encode("a");\n}}\n'
    lines, errors = _ir(source, externs)
    assert errors == []
    assert '    %2:sview = call.pure EXT"prism::Crypto::Base64::Encode", %1 @2:4' in lines


def test_a_call_in_a_procedure_takes_its_arguments(externs):
    source = (
        'procedure syn::p($v) {\n    inbound.resp.X = prism::Crypto::Base64::Encode("$v");\n}\n'
        'SEND_RESPONSE {\n    syn::p("a");\n}\n')
    lines, errors = _ir(source, externs)
    assert errors == []
    assert lines[3] == '  consts = [K0:"X", K1:"a"]'
    assert '    %3:sview = call.pure EXT"prism::Crypto::Base64::Encode", %2 @5:4' in lines


@pytest.mark.parametrize(
    "value, message", [
        ('T::Nope("a")', "unknown function 'T::Nope': no --extern manifest declares it"),
        ("prism::Crypto::Base64::Encode()", "'prism::Crypto::Base64::Encode' takes 1 arguments, 0 given"),
        ('prism::Crypto::Base64::Encode("a", "b")', "'prism::Crypto::Base64::Encode' takes 1 arguments, 2 given"),
        ("prism::Crypto::Base64::Encode(5)", "argument 1 of 'prism::Crypto::Base64::Encode' is int64, not string"),
        ("prism::Crypto::Base64::Encode(cripts::Geo::ASN())", "argument 1 of 'prism::Crypto::Base64::Encode' is int64, not string"),
        ('T::Str(5, "true")', "argument 2 of 'T::Str' is string, not bool"),
        ("cripts::Geo::ASN()", "'cripts::Geo::ASN' returns int64; inbound.resp.X takes a string"),
        ('T::Log("a")', "'T::Log' has an effect; calling it is not supported yet"),
        ('prism::File::FirstLine("k")', "'prism::File::FirstLine' runs at load only; call it in an INSTANCE_VARS initializer"),
    ],
    ids=["unknown", "too-few", "too-many", "int-for-string", "call-for-string", "string-for-bool", "result", "effect", "load"])
def test_a_call_that_cannot_be_compiled_errors(externs, value, message):
    lines, errors = _ir(_assignment(value), externs)
    assert lines == []
    assert errors == [(2, 4, message)]


_EXTERN_CALL_IN_HOLE = Path("tests/data/ir/extern_call_in_hole.input.txt")


def _hole(call: str) -> str:
    return _assignment(f'"<{{{call}}}>"')


def _hole_ir(lines: list[str]) -> list[str]:
    """The hook's instructions between the header value's name and the write."""
    body = lines[lines.index("    %1:sview = const.s K0 @2:4") + 1:]
    return body[:-2]


@pytest.mark.parametrize(
    "call, lowered", [
        ("cripts::Geo::ASN()", ['    %2:i64 = call.pure EXT"cripts::Geo::ASN" @2:4', "    %3:sview = fmt F0, %2 @2:4"]),
        ("T::Flag()", ['    %2:bool = call.pure EXT"T::Flag" @2:4', "    %3:sview = fmt F0, %2 @2:4"]),
        (
            "T::Str(5, true)", [
                "    %2:i64 = const.i I0 @2:4",
                "    %3:bool = const.i I1 @2:4",
                '    %4:sview = call.pure EXT"T::Str", %2, %3 @2:4',
                "    %5:sview = fmt F0, %4 @2:4",
            ]),
        (
            'prism::Crypto::Hex::Decode(prism::Crypto::Base64::Decode(\\"aGk=\\"))', [
                "    %2:sview = const.s K1 @2:4",
                '    %3:sview = call.pure EXT"prism::Crypto::Base64::Decode", %2 @2:4',
                '    %4:sview = call.pure EXT"prism::Crypto::Hex::Decode", %3 @2:4',
                "    %5:sview = fmt F0, %4 @2:4",
            ]),
        (
            'prism::Crypto::Base64::Encode(\\"a\\") with NORM', [
                "    %2:sview = const.s K1 @2:4",
                '    %3:sview = call.pure EXT"prism::Crypto::Base64::Encode", %2 @2:4',
                "    %4:sview = call.pure BI_NORM, %3 @2:4",
                "    %5:sview = fmt F0, %4 @2:4",
            ]),
    ],
    ids=["int64-result", "bool-result", "number-and-bool-arguments", "nested-call", "value-modifier"])
def test_a_call_in_a_hole_is_a_hole_of_the_format(externs, call, lowered):
    lines, errors = _ir(_hole(call), externs)
    assert errors == []
    assert lines[0] == "hrw4u-ir 1.1"
    assert _hole_ir(lines) == lowered


def test_a_call_in_a_hole_reads_an_instance_variable(externs):
    source = 'INSTANCE_VARS {\n    k: string = "x";\n}\n' + _hole("prism::Crypto::Base64::Encode(k)")
    lines, errors = _ir(source, externs)
    assert errors == []
    assert lines[-5:-2] == [
        "    %2:sview = load.i i0 @5:4",
        '    %3:sview = call.pure EXT"prism::Crypto::Base64::Encode", %2 @5:4',
        "    %4:sview = fmt F0, %3 @5:4",
    ]


@pytest.mark.parametrize(
    "call, message", [
        ('T::Nope(\\"a\\")', "unknown function 'T::Nope': no --extern manifest declares it"),
        ("prism::Crypto::Base64::Encode()", "'prism::Crypto::Base64::Encode' takes 1 arguments, 0 given"),
        ("prism::Crypto::Base64::Encode(5)", "argument 1 of 'prism::Crypto::Base64::Encode' is int64, not string"),
        (
            "prism::Crypto::Base64::Encode(inbound.method)",
            "argument 1 of 'prism::Crypto::Base64::Encode' is a bare reference; write it as \"{inbound.method}\""),
        ('T::Log(\\"a\\")', "'T::Log' has an effect; calling it is not supported yet"),
        ('prism::File::FirstLine(\\"k\\")', "'prism::File::FirstLine' runs at load only; call it in an INSTANCE_VARS initializer"),
        (
            "prism::Crypto::Base64::Encode(a b)",
            "'{prism::Crypto::Base64::Encode(a b)}' does not parse: extraneous input 'b' expecting ')'"),
    ],
    ids=["unknown", "arity", "argument-type", "bare-reference", "effect", "load", "syntax"])
def test_a_call_in_a_hole_that_cannot_be_compiled_errors(externs, call, message):
    lines, errors = _ir(_hole(call), externs)
    assert lines == []
    assert errors == [(2, 4, f"symbol error in {{}}: {message}")]


def test_a_call_in_a_hole_needs_the_target_to_be_ir_1_1(externs):
    lines, errors = _ir(_EXTERN_CALL_IN_HOLE.read_text(), externs, ir_version=(1, 0))
    assert lines == []
    assert errors == [(1, 16, "symbol error in {}: 'a call to a library function' needs IR 1.1; the target is 1.0 (--ir-version)")]


def test_a_call_in_a_hole_has_no_conf_spelling_on_either_front_end(externs):
    source = _EXTERN_CALL_IN_HOLE.read_text()
    expected = [(1, 16, "symbol error in {}: 'a call to a library function' has no .conf spelling; compile with --output ir")]
    assert _cst_errors(source, externs) == expected

    _, tree = utils.parse_input_text(source)
    collector = ErrorCollector()
    assert compile_to_conf(tree, "<test>", source, error_collector=collector, externs=externs) == []
    assert [(e.line, e.column, e.message) for e in collector.errors] == expected


def test_a_call_in_a_condition_function_argument_stays_text(externs):
    source = 'REMAP {\n    if access("{cripts::Geo::Country()}") {\n        no-op();\n    }\n}\n'
    lines, errors = _ir(source, externs)
    assert errors == []
    assert lines[:4] == ["hrw4u-ir 1.0", "", "Section[REMAP]:", '  consts = [K0:"{cripts::Geo::Country()}"]']

    _, tree = utils.parse_input_text(source)
    output = HRW4UVisitor(filename="<test>", error_collector=ErrorCollector(), externs=externs).visit(tree)
    assert "cond %{ACCESS:{cripts::Geo::Country()}}" in output


def test_a_call_needs_the_target_to_be_ir_1_1(externs):
    source = _EXTERN_CALL.read_text()
    lines, errors = _ir(source, externs, ir_version=(1, 0))
    assert lines == []
    assert errors == [(1, 16, "'a call to a library function' needs IR 1.1; the target is 1.0 (--ir-version)")]


def test_a_call_has_no_conf_spelling_on_either_front_end(externs):
    source = _EXTERN_CALL.read_text()
    expected = [(1, 16, "'a call to a library function' has no .conf spelling; compile with --output ir")]
    assert _cst_errors(source, externs) == expected

    _, tree = utils.parse_input_text(source)
    collector = ErrorCollector()
    assert compile_to_conf(tree, "<test>", source, error_collector=collector, externs=externs) == []
    assert [(e.line, e.column, e.message) for e in collector.errors] == expected


@pytest.mark.parametrize(
    "condition, name", [
        ("cripts::Geo::ASN() == 1", "cripts::Geo::ASN"),
        ("cripts::Geo::Country()", "cripts::Geo::Country"),
        ("access(cripts::Geo::Country())", "cripts::Geo::Country"),
    ],
    ids=["comparison", "bare", "argument"])
def test_a_declared_function_cannot_be_called_in_a_condition(externs, condition, name):
    source = f'SEND_RESPONSE {{\n    if {condition} {{\n        inbound.resp.X = "y";\n    }}\n}}\n'
    expected = [(2, 7, f"'{name}' cannot be called in a condition yet")]
    assert _ir(source, externs)[1] == expected
    assert _cst_errors(source, externs) == expected


@pytest.mark.parametrize(
    "source, message", [
        (
            "SEND_RESPONSE {\n    counter(cripts::Geo::Country());\n}\n",
            "a call to 'cripts::Geo::Country' cannot be an argument of 'counter' yet"),
        (
            "procedure syn::p($v) {\n    inbound.resp.X = $v;\n}\nSEND_RESPONSE {\n    if true {\n"
            "        syn::p(cripts::Geo::Country());\n    }\n}\n",
            "a call to 'cripts::Geo::Country' cannot be an argument of 'syn::p' yet"),
    ],
    ids=["statement-function", "procedure"])
def test_a_call_is_an_argument_of_a_declared_function_only(externs, source, message):
    _, errors = _ir(source, externs)
    assert [m for _, _, m in errors] == [message]
    assert _cst_errors(source, externs) == errors


def test_a_procedure_called_for_a_value_is_not_inlined(externs):
    source = "procedure syn::p() {\n    no-op();\n}\nSEND_RESPONSE {\n    inbound.resp.X = syn::p();\n}\n"
    expected = [(5, 4, "unknown function 'syn::p': no --extern manifest declares it")]
    assert _ir(source, externs)[1] == expected
    assert _cst_errors(source, externs) == expected


def test_a_declared_function_called_as_a_statement_is_called_for_its_value(externs):
    source = 'SEND_RESPONSE {\n    prism::Crypto::Base64::Encode("a");\n}\n'
    expected = [(2, 4, "'prism::Crypto::Base64::Encode' is called for its value; assign it")]
    assert _ir(source, externs)[1] == expected
    assert _cst_errors(source, externs) == expected


@pytest.mark.parametrize(
    "value, message", [
        (
            "prism::Crypto::Base64::Encode(inbound.req.X-Foo)",
            "argument 1 of 'prism::Crypto::Base64::Encode' is a bare reference; write it as \"{inbound.req.X-Foo}\""),
        (
            'prism::Crypto::HMAC::SHA256::Sign("a", outbound.req.X-Foo)',
            "argument 2 of 'prism::Crypto::HMAC::SHA256::Sign' is a bare reference; write it as \"{outbound.req.X-Foo}\""),
    ],
    ids=["first", "second"])
def test_a_bare_reference_is_not_a_string_argument(externs, value, message):
    source = _assignment(value)
    expected = [(2, 4, message)]
    assert _ir(source, externs)[1] == expected
    assert _cst_errors(source, externs) == expected
