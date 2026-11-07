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

import pytest

from hrw4u.ast_visitor import ASTVisitor
from hrw4u.emit_ir import write_ir
from hrw4u.errors import ErrorCollector, Hrw4uSyntaxError
from hrw4u.features import ir_version_for
from hrw4u.lower import decode_conf_escapes, lower
from hrw4u.sema import Sema
from utils import parse_input_text


def _ir(source: str, **sema_kwargs) -> list[str]:
    _, tree = parse_input_text(source)
    ast = ASTVisitor(filename="<test>").visit(tree)
    sema = Sema(**sema_kwargs)
    sema.source_map.add("<test>", source)
    program = sema.analyze(ast)
    return write_ir(lower(program, sema.source_map, "<test>"), ir_version_for(sema.features))


def test_set_twice_reuses_the_name_const():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-Foo = "one";\n    inbound.resp.X-Foo = "two";\n}\n')
    assert out[3] == '  consts = [K0:"X-Foo", K1:"one", K2:"two"]'
    assert out[8] == "    %3:sview = const.s K0 @3:4"


def test_break_is_written_and_later_statements_still_lowered():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "1";\n    break;\n    inbound.resp.X-B = "2";\n}\n')
    assert out[5:] == [
        "    %1:sview = const.s K0 @2:4",
        "    %2:sview = const.s K1 @2:4",
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %2 @2:4",
        "    break @3:4",
        "    %3:sview = const.s K2 @4:4",
        "    %4:sview = const.s K3 @4:4",
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %3, %4 @4:4",
        "    ret @4:4",
    ]


def test_special_value_is_decoded():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-Foo = "a b \\"q\\" ü {{x}}";\n}\n')
    assert out[3] == '  consts = [K0:"X-Foo", K1:"a b \\"q\\" ü {x}"]'


def test_tab_and_backslash_survive_the_round_trip():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "a\\tb\\\\c";\n}\n')
    assert out[3] == '  consts = [K0:"X-A", K1:"a\\tb\\\\c"]'


def test_name_and_value_share_a_const():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X = "X";\n}\n')
    assert out[3] == '  consts = [K0:"X"]'
    assert out[5:7] == ["    %1:sview = const.s K0 @2:4", "    %2:sview = const.s K0 @2:4"]


def test_comment_does_not_move_ret():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "1";\n    # trailing\n}\n')
    assert out[-1] == "    ret @2:4"


def test_empty_section_rets_at_the_section():
    assert _ir('SEND_RESPONSE {\n}\n')[-1] == "    ret @1:0"


def _body_ir(cond: str) -> list[str]:
    """The IR lines of `if <cond> { set X-A }` in SEND_RESPONSE."""
    out = _ir(f'SEND_RESPONSE {{\n    if {cond} {{\n        inbound.resp.X-A = "1";\n    }}\n}}\n')
    return out[out.index("  IR:") + 1:]


def test_or_jumps_into_the_body_when_its_left_side_holds():
    assert _body_ir('inbound.req.A == "a" || inbound.req.B != "b"') == [
        "    %1:sview = const.s K0 @2:7",
        "    %2:sview = call.pure BI_CLIENT_HEADER, %1 @2:7",
        "    %3:sview = const.s K1 @2:7",
        "    %4:bool = cmp.s.eq %2, %3 @2:7",
        "    br.t %4, .L10 @2:7",
        "    %5:sview = const.s K2 @2:31",
        "    %6:sview = call.pure BI_CLIENT_HEADER, %5 @2:31",
        "    %7:sview = const.s K3 @2:31",
        "    %8:bool = cmp.s.ne %6, %7 @2:31",
        "    br.f %8, .L13 @2:31",
        "    .L10: %9:sview = const.s K4 @3:8",
        "    %10:sview = const.s K5 @3:8",
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %9, %10 @3:8",
        "    .L13: ret @3:8",
    ]


def test_negated_and_skips_its_right_side_when_its_left_side_fails():
    out = _body_ir('!(inbound.req.A && inbound.req.B)')
    assert [line.split(" @")[0] for line in out if "br" in line or ".L" in line] == [
        "    br.f %4, .L10",
        "    br.t %8, .L13",
        "    .L10: %9:sview = const.s K3",
        "    .L13: ret",
    ]


def test_existence_compares_with_the_empty_string():
    assert _body_ir("inbound.req.A")[:5] == [
        "    %1:sview = const.s K0 @2:7",
        "    %2:sview = call.pure BI_CLIENT_HEADER, %1 @2:7",
        "    %3:sview = const.s K1 @2:7",
        "    %4:bool = cmp.s.ne %2, %3 @2:7",
        "    br.f %4, .L8 @2:7",
    ]


def test_unquoted_operand_is_a_string():
    out = _ir('SEND_RESPONSE {\n    if inbound.method == GET {\n        inbound.resp.X-A = "1";\n    }\n}\n')
    assert out[3] == '  consts = [K0:"GET", K1:"X-A", K2:"1"]'


def test_elif_without_else_does_not_branch_after_its_last_arm():
    out = _ir('SEND_RESPONSE {\n    if inbound.req.A {\n        break;\n    } elif inbound.req.B {\n        break;\n    }\n}\n')
    assert out[9:] == [
        "    br.f %4, .L7 @2:7",
        "    break @3:8",
        "    br .L13 @2:4",
        "    .L7: %5:sview = const.s K2 @4:11",
        "    %6:sview = call.pure BI_CLIENT_HEADER, %5 @4:11",
        "    %7:sview = const.s K1 @4:11",
        "    %8:bool = cmp.s.ne %6, %7 @4:11",
        "    br.f %8, .L13 @4:11",
        "    break @5:8",
        "    .L13: ret @5:8",
    ]


def test_empty_if_rets_at_the_if():
    out = _ir('SEND_RESPONSE {\n    if inbound.req.A {\n    }\n}\n')
    assert out[-1] == "    .L5: ret @2:4"


def test_status_compares_as_an_integer():
    assert _body_ir("inbound.status != 200")[:4] == [
        "    %1:i64 = call.pure BI_CLIENT_RESP_STATUS @2:7",
        "    %2:i64 = const.i I0 @2:7",
        "    %3:bool = cmp.i64.ne %1, %2 @2:7",
        "    br.f %3, .L7 @2:7",
    ]


@pytest.mark.parametrize(
    "hook, statement, builtin, scope", [
        ("REMAP", "http.status = 403;", "BI_SET_CLIENT_RESP_STATUS", "inbound.status"),
        ("READ_RESPONSE", "http.status = 503;", "BI_SET_SERVER_RESP_STATUS", "outbound.status"),
        ("SEND_RESPONSE", "http.status = 503;", "BI_SET_CLIENT_RESP_STATUS", "inbound.status"),
        ("READ_RESPONSE", 'http.status.reason = "R";', "BI_SET_SERVER_RESP_STATUS_REASON", "outbound.status.reason"),
        ("SEND_RESPONSE", 'http.status.reason = "R";', "BI_SET_CLIENT_RESP_STATUS_REASON", "inbound.status.reason"),
    ])
def test_http_status_sets_the_hooks_response_and_warns(hook, statement, builtin, scope):
    collector, err = _warnings(f"{hook} {{\n    {statement}\n}}\n")
    assert err is None
    assert [(w.line, w.column) for w in collector.warnings] == [(2, 4)]
    assert f"write '{scope}' instead" in collector.warnings[0].message
    assert any(f"call.eff {builtin}," in line for line in _ir(f"{hook} {{\n    {statement}\n}}\n"))


@pytest.mark.parametrize(
    "hook, statement, builtin", [
        ("REMAP", "inbound.status = 404;", "call.eff BI_SET_CLIENT_RESP_STATUS,"),
        ("READ_RESPONSE", "outbound.status = 404;", "call.eff BI_SET_SERVER_RESP_STATUS,"),
        ("SEND_RESPONSE", "inbound.status = 404;", "call.eff BI_SET_CLIENT_RESP_STATUS,"),
        ("READ_RESPONSE", 'outbound.status.reason = "R";', "call.eff BI_SET_SERVER_RESP_STATUS_REASON,"),
        ("SEND_RESPONSE", 'inbound.status.reason = "R";', "call.eff BI_SET_CLIENT_RESP_STATUS_REASON,"),
        ("READ_RESPONSE", 'if outbound.status > 1 {\n    }', "call.pure BI_SERVER_RESP_STATUS"),
        ("SEND_RESPONSE", 'if inbound.status > 1 {\n    }', "call.pure BI_CLIENT_RESP_STATUS"),
    ])
def test_status_names_its_response(hook, statement, builtin):
    assert any(builtin in line for line in _ir(f"{hook} {{\n    {statement}\n}}\n"))


@pytest.mark.parametrize(
    "hook, statement, scope", [
        ("REMAP", "outbound.status = 404;", "inbound.status"),
        ("READ_RESPONSE", 'inbound.status.reason = "R";', "outbound.status"),
        ("SEND_RESPONSE", 'outbound.status.reason = "R";', "inbound.status"),
        ("READ_RESPONSE", "inbound.status = 404;", "outbound.status"),
        ("SEND_RESPONSE", "outbound.status = 404;", "inbound.status"),
        ("READ_RESPONSE", 'if inbound.status > 1 {\n    }', "outbound.status"),
        ("SEND_RESPONSE", 'if outbound.status > 1 {\n    }', "inbound.status"),
    ])
def test_status_scope_naming_another_response_than_the_hooks_is_refused(hook, statement, scope):
    # header_rewrite works on the hook's response whatever the scope says.
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"{hook} {{\n    {statement}\n}}\n")
    assert f"in {hook}: this hook's status is {scope}, which header_rewrite would work on instead" in err.value.message


@pytest.mark.parametrize(
    "hook, statement, message", [
        ("REMAP", 'if inbound.status > 1 {\n    }', "runs BI_CLIENT_RESP_STATUS only in SEND_RESPONSE"),
        ("SEND_REQUEST", "http.status = 404;", "this hook has no status"),
        ("SEND_REQUEST", 'if outbound.status > 1 {\n    }', "this hook has no status"),
    ])
def test_status_in_a_hook_without_it_is_refused(hook, statement, message):
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"{hook} {{\n    {statement}\n}}\n")
    assert message in err.value.message


def test_order_on_a_string_is_refused():
    err = _refused('SEND_RESPONSE {\n    if inbound.req.A > "a" {\n        break;\n    }\n}\n')
    assert "'>' on a sview value" in err.message


@pytest.mark.parametrize("cond", ['inbound.status == "OK"', 'inbound.status > "200"', 'inbound.status < "500"'])
def test_operand_header_rewrite_cannot_read_as_a_number_is_refused(cond):
    _refused(f'SEND_RESPONSE {{\n    if {cond} {{\n        break;\n    }}\n}}\n')


@pytest.mark.parametrize(
    "cond, entry, branch", [
        ('inbound.req.A == "Content/" with NOCASE,PRE', 'S0:s("Content/") pre nocase', "br.f"),
        ('inbound.req.A != "/index.m3u8" with MID', 'S0:s("/index.m3u8") mid', "br.t"),
        ('inbound.req.A == "a" with NOCASE', 'S0:s("a") nocase', "br.f"),
    ])
def test_modifier_on_a_comparison_matches_one_item(cond, entry, branch):
    out = _ir(f'SEND_RESPONSE {{\n    if {cond} {{\n        break;\n    }}\n}}\n')
    assert out[4] == f"  sets   = [{entry}]"
    assert out[8:10] == ["    %3:bool = in.set %2, S0 @2:7", f"    {branch} %3, .L5 @2:7"]


def test_match_mode_on_a_set():
    out = _ir('SEND_RESPONSE {\n    if inbound.req.A in ["m3u8", ts] with NOCASE,EXT {\n        break;\n    }\n}\n')
    assert out[4] == '  sets   = [S0:s("m3u8", "ts") ext nocase]'


def test_modifier_on_an_integer_comparison_is_refused():
    err = _refused('SEND_RESPONSE {\n    if inbound.status == 200 with NOCASE {\n        break;\n    }\n}\n')
    assert (err.line, err.column) == (2, 7)


def test_interpolated_operand_is_refused():
    err = _refused('SEND_RESPONSE {\n    if inbound.req.A == "{inbound.req.B}" {\n        break;\n    }\n}\n')
    assert (err.line, err.column) == (2, 7)


def test_unsupported_condition_is_refused_at_its_position():
    err = _refused('SEND_RESPONSE {\n    if cache() {\n        break;\n    }\n}\n')
    assert (err.line, err.column) == (2, 7)
    assert "the condition 'cache()'" in err.message


def test_negated_match_with_nocase():
    out = _ir('SEND_RESPONSE {\n    if inbound.req.A !~ /a\\/b/ with NOCASE {\n        break;\n    }\n}\n')
    assert out[4] == "  regex  = [R0:/a\\\\\\/b/i]"
    assert out[8:10] == ["    %3:bool = re.match %2, R0 @2:7", "    br.t %3, .L5 @2:7"]


def test_string_set_is_split_as_header_rewrite_does():
    out = _ir('SEND_RESPONSE {\n    if inbound.req.A !in [foo, "b,ar", 12] with NOCASE {\n        break;\n    }\n}\n')
    assert out[4] == '  sets   = [S0:s("foo", "b,ar", "12") nocase]'
    assert out[8:10] == ["    %3:bool = in.set %2, S0 @2:7", "    br.t %3, .L5 @2:7"]


def test_integer_set_tests_an_integer():
    out = _ir('SEND_RESPONSE {\n    if inbound.status !in [200, 0404] {\n        break;\n    }\n}\n')
    assert out[3] == "  sets   = [S0:i(200, 404)]"
    assert out[5:8] == [
        "    %1:i64 = call.pure BI_CLIENT_RESP_STATUS @2:7",
        "    %2:bool = in.set %1, S0 @2:7",
        "    br.t %2, .L4 @2:7",
    ]


def test_ip_range_tests_the_address():
    out = _ir('SEND_RESPONSE {\n    if inbound.ip in {10.0.0.0/8, ::1} {\n        break;\n    }\n}\n')
    assert out[3] == '  sets   = [S0:ip("10.0.0.0/8", "::1")]'
    assert out[5:7] == ["    %1:addr = call.pure BI_IP_CLIENT @2:7", "    %2:bool = in.set %1, S0 @2:7"]


@pytest.mark.parametrize(
    "cond", ['inbound.req.A ~ /a/ with PRE', 'inbound.ip ~ /a/', 'inbound.req.A in {10.0.0.0/8}', 'inbound.status in [20x]'])
def test_unsupported_match_is_refused(cond):
    err = _refused(f'SEND_RESPONSE {{\n    if {cond} {{\n        break;\n    }}\n}}\n')
    assert (err.line, err.column) == (2, 7)


@pytest.mark.parametrize(
    "raw, value", [("a\\tb", "a\tb"), ("\\r\\n", "\r\n"), ('\\"', '"'), ("\\\\", "\\"), ("\\z", "z"), ("a\\", "a")])
def test_decode_conf_escapes(raw, value):
    assert decode_conf_escapes(raw) == value


def _refused(source: str, **sema_kwargs) -> Hrw4uSyntaxError:
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(source, **sema_kwargs)
    assert "not supported by the IR emitter yet" in err.value.message
    return err.value


def _refused_statement(statement: str) -> Hrw4uSyntaxError:
    err = _refused(f'SEND_RESPONSE {{\n    {statement}\n}}\n')
    assert (err.line, err.column) == (2, 4)
    return err


@pytest.mark.parametrize("hook", ["TXN_START", "READ_REQUEST", "PRE_REMAP"])
def test_hooks_before_remap_are_sections(hook):
    assert _ir(f'{hook} {{\n    break;\n}}\n')[2:] == [f"Section[{hook}]:", "  IR:", "    break @2:4", "    ret @2:4"]


@pytest.mark.parametrize("hook", ["READ_REQUEST", "PRE_REMAP"])
def test_hooks_before_remap_write_the_client_request(hook):
    out = _ir(f'{hook} {{\n    inbound.req.X-A = "1";\n}}\n')
    assert out[7] == "    call.eff BI_SET_CLIENT_HEADER, %1, %2 @2:4"


@pytest.mark.parametrize(
    "hook, statement, builtin", [
        ("READ_REQUEST", "inbound.conn.dscp = 8;", "BI_SET_CONN_DSCP"),
        ("READ_REQUEST", "http.cntl.LOGGING = off;", "BI_SET_HTTP_CNTL"),
        ("READ_REQUEST", "set-debug();", "BI_SET_HTTP_CNTL"),
        ("PRE_REMAP", "inbound.status = 403;", "BI_SET_CLIENT_RESP_STATUS"),
        ("PRE_REMAP", 'inbound.cookie.c = "v";', "BI_SET_CLIENT_COOKIE"),
    ])
def test_effects_header_rewrite_runs_before_remap(hook, statement, builtin):
    assert any(f"call.eff {builtin}," in line for line in _ir(f"{hook} {{\n    {statement}\n}}\n"))


def test_sections_of_a_hook_run_in_order_as_one():
    out = _ir(
        'SEND_RESPONSE {\n    break;\n}\nREMAP {\n    inbound.req.X-R = "r";\n}\n'
        'SEND_RESPONSE {\n    inbound.resp.X-B = "2";\n}\n')
    assert [line for line in out if line.startswith("Section[")] == ["Section[SEND_RESPONSE]:", "Section[REMAP]:"]
    send_response = out[:out.index("Section[REMAP]:")]
    assert send_response[-6:-1] == [
        "    break @2:4",
        "    %1:sview = const.s K0 @8:4",
        "    %2:sview = const.s K1 @8:4",
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %2 @8:4",
        "    ret @8:4",
    ]


def test_remap_writes_the_client_request():
    out = _ir('REMAP {\n    inbound.req.X-A = "1";\n}\n')
    assert out[2] == "Section[REMAP]:"
    assert out[7] == "    call.eff BI_SET_CLIENT_HEADER, %1, %2 @2:4"


def test_txn_close_is_a_section():
    assert _ir('TXN_CLOSE {\n    break;\n}\n')[2:] == ["Section[TXN_CLOSE]:", "  IR:", "    break @2:4", "    ret @2:4"]


def test_registers_restart_in_each_section():
    out = _ir('SEND_REQUEST {\n    outbound.req.X-A = "1";\n}\nSEND_RESPONSE {\n    inbound.resp.X-B = "2";\n}\n')
    assert out[12:] == [
        "    %1:sview = const.s K2 @5:4",
        "    %2:sview = const.s K3 @5:4",
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %2 @5:4",
        "    ret @5:4",
    ]


@pytest.mark.parametrize(
    "hook, statement, builtin", [
        ("READ_REQUEST", 'inbound.req.X-A = "1";', "BI_SET_CLIENT_HEADER"),
        ("PRE_REMAP", 'inbound.req.X-A += "1";', "BI_ADD_CLIENT_HEADER"),
        ("REMAP", 'inbound.req.X-A = "";', "BI_RM_CLIENT_HEADER"),
        ("SEND_REQUEST", 'outbound.req.X-A = "1";', "BI_SET_SERVER_HEADER"),
        ("SEND_REQUEST", 'outbound.req.X-A += "1";', "BI_ADD_SERVER_HEADER"),
        ("SEND_REQUEST", 'outbound.req.X-A = "";', "BI_RM_SERVER_HEADER"),
        ("READ_RESPONSE", 'outbound.resp.X-A = "1";', "BI_SET_SERVER_RESP_HEADER"),
        ("READ_RESPONSE", 'outbound.resp.X-A += "1";', "BI_ADD_SERVER_RESP_HEADER"),
        ("READ_RESPONSE", 'outbound.resp.X-A = "";', "BI_RM_SERVER_RESP_HEADER"),
        ("SEND_RESPONSE", 'inbound.resp.X-A = "1";', "BI_SET_CLIENT_RESP_HEADER"),
        ("SEND_RESPONSE", 'inbound.resp.X-A += "1";', "BI_ADD_CLIENT_RESP_HEADER"),
        ("SEND_RESPONSE", 'inbound.resp.X-A = "";', "BI_RM_CLIENT_RESP_HEADER"),
    ])
def test_header_write_names_its_message(hook, statement, builtin):
    assert any(f"call.eff {builtin}," in line for line in _ir(f"{hook} {{\n    {statement}\n}}\n"))


@pytest.mark.parametrize(
    "hook, statement, message", [
        ("SEND_REQUEST", 'inbound.req.X-A = "1";', "outbound.req."),
        ("READ_RESPONSE", 'inbound.resp.X-A = "1";', "outbound.resp."),
        ("SEND_RESPONSE", 'outbound.resp.X-A = "1";', "inbound.resp."),
        ("SEND_RESPONSE", 'inbound.req.X-A = "";', "inbound.resp."),
        ("READ_RESPONSE", 'outbound.req.X-A += "1";', "outbound.resp."),
        ("READ_RESPONSE", 'outbound.resp.X-A = "{inbound.resp.X-B}";', "outbound.resp."),
        ("SEND_RESPONSE", 'inbound.resp.X-A = "{outbound.resp.X-B}";', "inbound.resp."),
    ])
def test_header_scope_naming_another_message_than_the_hooks_is_refused(hook, statement, message):
    # header_rewrite works on the hook's message whatever the scope says.
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"{hook} {{\n    {statement}\n}}\n")
    assert f"in {hook}: this hook's message is {message}, which header_rewrite would work on instead" in err.value.message


def test_empty_value_removes_the_header():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "";\n}\n')
    assert out[3:] == [
        '  consts = [K0:"X-A"]',
        "  IR:",
        "    %1:sview = const.s K0 @2:4",
        "    call.eff BI_RM_CLIENT_RESP_HEADER, %1 @2:4",
        "    ret @2:4",
    ]


def test_plus_equals_adds_the_header():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A += "1";\n}\n')
    assert out[3:8] == [
        '  consts = [K0:"X-A", K1:"1"]',
        "  IR:",
        "    %1:sview = const.s K0 @2:4",
        "    %2:sview = const.s K1 @2:4",
        "    call.eff BI_ADD_CLIENT_RESP_HEADER, %1, %2 @2:4",
    ]


def test_connection_mark_marks_the_clients_packets():
    out = _ir("REMAP {\n    inbound.conn.mark = 17;\n}\n")
    assert out[5:7] == ["    %1:i64 = const.i I0 @2:4", "    call.eff BI_SET_CONN_MARK, %1 @2:4"]


def test_status_reason_is_set_on_the_hooks_response():
    out = _ir('READ_RESPONSE {\n    outbound.status.reason = "Up {inbound.req.X}";\n}\n')
    assert out[-3:-1] == [
        "    %3:sview = fmt F0, %2 @2:4",
        "    call.eff BI_SET_SERVER_RESP_STATUS_REASON, %3 @2:4",
    ]


@pytest.mark.parametrize(
    "hook, statement, message", [
        ("REMAP", 'inbound.status.reason = "R";', "hrw4u.so runs BI_SET_CLIENT_RESP_STATUS_REASON only in"),
    ])
def test_status_reason_follows_the_status_hooks(hook, statement, message):
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"{hook} {{\n    {statement}\n}}\n")
    assert message in err.value.message


def test_cookie_writes_change_the_request_cookie():
    out = _ir('REMAP {\n    inbound.cookie.a = "{inbound.req.X}";\n    inbound.cookie.b = "";\n}\n')
    assert out[-3:-1] == ["    %5:sview = const.s K2 @3:4", "    call.eff BI_RM_CLIENT_COOKIE, %5 @3:4"]
    assert "    call.eff BI_SET_CLIENT_COOKIE, %1, %4 @2:4" in out


@pytest.mark.parametrize(
    "statement, builtin",
    [('outbound.cookie.a = "1";', "BI_SET_SERVER_COOKIE, %1, %2"), ('outbound.cookie.a = "";', "BI_RM_SERVER_COOKIE, %1")])
def test_outbound_cookie_write_changes_the_origin_request(statement, builtin):
    out = _ir(f"SEND_REQUEST {{\n    {statement}\n}}\n")
    assert out[-2] == f"    call.eff {builtin} @2:4"


def test_inbound_cookie_write_at_send_request_is_refused():
    # header_rewrite's set-cookie changes the hook's request, there the origin's, whatever the scope says.
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir('SEND_REQUEST {\n    inbound.cookie.a = "1";\n}\n')
    assert "in SEND_REQUEST: this hook's request is outbound.cookie., which header_rewrite would work on instead" in err.value.message


def test_cookie_write_in_a_response_hook_is_refused():
    # header_rewrite's set-cookie writes there onto the response, or does nothing, by the hook's other rules.
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir('SEND_RESPONSE {\n    outbound.cookie.a = "1";\n}\n')
    assert "in SEND_RESPONSE: this hook has no request" in err.value.message


def test_empty_body_is_set_as_the_conf_does():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.body = "";\n}\n')
    assert out[5:8] == ["    %1:sview = const.s K0 @2:4", "    %2:sview = const.s K0 @2:4", "    call.eff BI_SET_BODY, %1, %2 @2:4"]


@pytest.mark.parametrize("value, on", [("on", 1), ("TRUE", 1), ("1", 1), ("yes", 0), ("off", 0)])
def test_http_cntl_reads_on_as_set_http_cntl_does(value, on):
    out = _ir(f"REMAP {{\n    http.cntl.TXN_DEBUG = {value};\n}}\n")
    assert out[3] == f"  ints   = [I0:5, I1:{on}]"
    assert out[7] == "    call.eff BI_SET_HTTP_CNTL, %1, %2 @2:4"


def test_destination_set_takes_a_template():
    out = _ir('REMAP {\n    inbound.url.path = "p/{inbound.req.X}";\n}\n')
    assert out[-2] == "    call.eff BI_SET_CLIENT_URL, %1, %4 @2:4"


@pytest.mark.parametrize(
    "hook, statement, builtin", [
        ("SEND_REQUEST", "inbound.conn.dscp = 8;", "BI_SET_CONN_DSCP"),
        ("PRE_REMAP", "inbound.conn.dscp = 8;", "BI_SET_CONN_DSCP"),
        ("READ_RESPONSE", 'inbound.resp.body = "x";', "BI_SET_BODY"),
    ])
def test_effect_in_a_hook_hrw4u_so_does_not_run_it_in_is_refused(hook, statement, builtin):
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"{hook} {{\n    {statement}\n}}\n")
    assert f"hrw4u.so runs {builtin} only in" in err.value.message


@pytest.mark.parametrize("hook", ["SEND_REQUEST", "PRE_REMAP"])
def test_set_http_cntl_runs_where_header_rewrite_runs_it(hook):
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"{hook} {{\n    http.cntl.LOGGING = off;\n}}\n")
    assert "header_rewrite refuses set-http-cntl in this hook" in err.value.message


def test_skip_remap_runs_before_remap_as_header_rewrite_runs_it():
    out = _ir("PRE_REMAP {\n    skip-remap(true);\n}\n")
    assert out[-2] == "    call.eff BI_SET_HTTP_CNTL, %1, %2 @2:4"


def test_interpolation_goes_through_fmt():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "a\\t{inbound.req.Host}-{inbound.resp.Via}";\n}\n')
    assert out[3:] == [
        '  consts = [K0:"X-A", K1:"Host", K2:"Via"]',
        '  fmt    = [F0:"a\\\\t{inbound.req.Host}-{inbound.resp.Via}" arity=2 lits=["a\\t", "-", ""]]',
        "  IR:",
        "    %1:sview = const.s K0 @2:4",
        "    %2:sview = const.s K1 @2:4",
        "    %3:sview = call.pure BI_CLIENT_HEADER, %2 @2:4",
        "    %4:sview = const.s K2 @2:4",
        "    %5:sview = call.pure BI_CLIENT_RESP_HEADER, %4 @2:4",
        "    %6:sview = fmt F0, %3, %5 @2:4",
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %6 @2:4",
        "    ret @2:4",
    ]


def test_lone_hole_still_goes_through_fmt():
    out = _ir('REMAP {\n    inbound.req.X-A = "{inbound.req.X-B}";\n}\n')
    assert out[4] == '  fmt    = [F0:"{inbound.req.X-B}" arity=1 lits=["", ""]]'
    assert out[9] == "    %4:sview = fmt F0, %3 @2:4"


def test_same_template_shares_a_fmt():
    out = _ir(
        'SEND_REQUEST {\n    outbound.req.X-A = "{inbound.req.X}";\n}\n'
        'SEND_RESPONSE {\n    inbound.resp.X-A = "{inbound.req.X}";\n}\n')
    assert out[4] == '  fmt    = [F0:"{inbound.req.X}" arity=1 lits=["", ""]]'
    assert out[-2] == "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %4 @5:4"


@pytest.mark.parametrize(
    "hook, target",
    [("SEND_REQUEST", "outbound.req.X-A"), ("READ_RESPONSE", "outbound.resp.X-A"), ("SEND_RESPONSE", "inbound.resp.X-A")])
def test_server_request_is_read_in_every_hook_that_names_it(hook, target):
    out = _ir(f'{hook} {{\n    {target} = "{{outbound.req.X-B}}";\n}}\n')
    assert out[8] == "    %3:sview = call.pure BI_SERVER_HEADER, %2 @2:4"


def test_client_response_is_read_in_send_response():
    out = _ir('SEND_RESPONSE {\n    if inbound.resp.X-B == "b" {\n        break;\n    }\n}\n')
    assert "    %2:sview = call.pure BI_CLIENT_RESP_HEADER, %1 @2:7" in out


def test_numbered_reads_load_their_number_from_ints():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{capture.2}/{random(10)}/{inbound.url.path}";\n}\n')
    assert out[4] == "  ints   = [I0:2, I1:10, I2:3]"
    assert out[8:15] == [
        "    %2:i64 = const.i I0 @2:4",
        "    %3:sview = call.pure BI_LAST_CAPTURE, %2 @2:4",
        "    %4:i64 = const.i I1 @2:4",
        "    %5:i64 = call.pure BI_RANDOM, %4 @2:4",
        "    %6:i64 = const.i I2 @2:4",
        "    %7:sview = call.pure BI_CLIENT_URL, %6 @2:4",
        "    %8:sview = fmt F0, %3, %5, %7 @2:4",
    ]


def test_named_and_plain_reads():
    out = _ir('REMAP {\n    inbound.req.X-A = "{inbound.cookie.c}{inbound.url.query.q}{inbound.method}{inbound.ip}";\n}\n')
    assert out[7:14] == [
        "    %2:sview = const.s K1 @2:4",
        "    %3:sview = call.pure BI_COOKIE, %2 @2:4",
        "    %4:sview = const.s K2 @2:4",
        "    %5:sview = call.pure BI_CLIENT_URL_PARAM, %4 @2:4",
        "    %6:sview = call.pure BI_METHOD @2:4",
        "    %7:addr = call.pure BI_IP_CLIENT @2:4",
        "    %8:sview = fmt F0, %3, %5, %6, %7 @2:4",
    ]


def test_cidr_loads_both_prefix_lengths():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{cidr(24, 64)}";\n}\n')
    assert out[4] == "  ints   = [I0:24, I1:64]"
    assert out[8:11] == [
        "    %2:i64 = const.i I0 @2:4",
        "    %3:i64 = const.i I1 @2:4",
        "    %4:sview = call.pure BI_CIDR, %2, %3 @2:4",
    ]


def test_txn_count_is_an_integer():
    out = _ir('SEND_RESPONSE {\n    if txn-count() > 8192 {\n        break;\n    }\n}\n')
    assert out[5:8] == [
        "    %1:i64 = call.pure BI_TXN_COUNT @2:7",
        "    %2:i64 = const.i I0 @2:7",
        "    %3:bool = cmp.i64.gt %1, %2 @2:7",
    ]


def test_remote_addr_is_read_whatever_its_case():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{inbound.conn.remote-addr}";\n}\n')
    assert out[7] == "    %2:addr = call.pure BI_IP_CLIENT @2:4"


@pytest.mark.parametrize(
    "hook, statement, what, does, inbound", [
        (
            "SEND_REQUEST", 'outbound.req.X-A = "{outbound.method}";', "outbound.method", "reads the client's request",
            "inbound.method"),
        (
            "SEND_REQUEST", 'outbound.req.X-A = "{outbound.cookie.c}";', "outbound.cookie.c", "reads the client's request",
            "inbound.cookie.c"),
        (
            "SEND_RESPONSE", "outbound.conn.dscp = 8;", "outbound.conn.dscp", "marks the client connection's packets",
            "inbound.conn.dscp"),
        (
            "SEND_RESPONSE", "outbound.conn.mark = 8;", "outbound.conn.mark", "marks the client connection's packets",
            "inbound.conn.mark"),
    ])
def test_outbound_name_header_rewrite_takes_for_the_client_is_refused(hook, statement, what, does, inbound):
    # header_rewrite works on the client's side for these whatever the hook, which their name does not say.
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"{hook} {{\n    {statement}\n}}\n")
    assert f"'{what}': header_rewrite {does} here whatever the scope; write '{inbound}' instead" in err.value.message


def test_outbound_cookie_write_is_not_refused():
    assert _ir('SEND_REQUEST {\n    outbound.cookie.c = "1";\n}\n')[-2] == "    call.eff BI_SET_SERVER_COOKIE, %1, %2 @2:4"


def test_stack_reads_every_tag():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{inbound.conn.STACK}";\n}\n')
    assert out[7] == "    %2:sview = call.pure BI_CLIENT_STACK @2:4"


def test_outbound_connection_field_is_refused():
    assert "reading 'outbound.conn.STACK'" in _refused_statement('inbound.resp.X-A = "{outbound.conn.STACK}";').message


def test_local_address_is_read_as_inbound_server_reads_it():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{inbound.server}{inbound.conn.local-addr}";\n}\n')
    assert out[7:9] == ["    %2:addr = call.pure BI_IP_INBOUND @2:4", "    %3:addr = call.pure BI_IP_INBOUND @2:4"]


def test_equal_numbers_share_an_int():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{inbound.url.host}{id.PROCESS}";\n}\n')
    assert out[4] == "  ints   = [I0:1]"


def test_to_url_is_read_in_remap_only():
    out = _ir('REMAP {\n    inbound.req.X-A = "{to.url.host}";\n}\n')
    assert out[9] == "    %3:sview = call.pure BI_TO_URL, %2 @2:4"
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{to.url.host}";\n}\n')
    assert "hrw4u.so runs BI_TO_URL only in REMAP" in err.value.message


def test_from_url_is_read_in_remap_only():
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{from.url.host}";\n}\n')
    assert "'from.url.HOST' in SEND_RESPONSE: hrw4u.so runs BI_FROM_URL only in REMAP" in err.value.message


def test_refused_function_read_is_named_as_a_call():
    assert "reading 'access(x)'" in _refused_statement('inbound.resp.X-A = "{access(x)}";').message


def test_cache_reads_the_lookup_status():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{cache()}";\n}\n')
    assert out[7] == "    %2:sview = call.pure BI_CACHE @2:4"


def test_server_url_reads_the_request_to_the_origin():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{outbound.url.path}{outbound.url.query.q}";\n}\n')
    assert "    %3:sview = call.pure BI_SERVER_URL, %2 @2:4" in out
    assert "    %5:sview = call.pure BI_SERVER_URL_PARAM, %4 @2:4" in out


@pytest.mark.parametrize("scope, builtin", [("from", "BI_FROM_URL_PARAM"), ("to", "BI_TO_URL_PARAM")])
def test_remap_url_query_parameter_is_read_at_remap(scope, builtin):
    out = _ir(f'REMAP {{\n    inbound.req.X-A = "{{{scope}.url.query.q}}";\n}}\n')
    assert out[8] == f"    %3:sview = call.pure {builtin}, %2 @2:4"
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f'SEND_RESPONSE {{\n    inbound.resp.X-A = "{{{scope}.url.query.q}}";\n}}\n')
    assert f"hrw4u.so runs {builtin} only in REMAP" in err.value.message


def test_ssn_txn_count_is_an_integer():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{ssn-txn-count()}";\n}\n')
    assert out[7] == "    %2:i64 = call.pure BI_SSN_TXN_COUNT @2:4"


@pytest.mark.parametrize(
    "line, column", [("if geo.COUNTRY-ISO == 840 {\n        break;\n    }", 7), ('inbound.resp.X-A = "{geo.country-iso}";', 4)])
def test_geo_country_iso_is_refused(line, column):
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"SEND_RESPONSE {{\n    {line}\n}}\n")
    assert (err.value.line, err.value.column) == (2, column)
    assert "'geo.COUNTRY-ISO': header_rewrite with MaxMind reads -1 for it whatever the address; read 'geo.COUNTRY' instead" in (
        err.value.message)


@pytest.mark.parametrize(
    "field, binding, ty", [
        ("COUNTRY", "cripts::Geo::Country", "sview"), ("ASN", "cripts::Geo::ASN", "i64"),
        ("ASN-NAME", "cripts::Geo::ASNName", "sview")
    ])
def test_geo_calls_the_cripts_binding(field, binding, ty):
    out = _ir(f'SEND_RESPONSE {{\n    inbound.resp.X-A = "{{geo.{field}}}";\n}}\n')
    assert out[7] == f'    %2:{ty} = call.pure EXT"{binding}" @2:4'


@pytest.mark.parametrize("cond", ["geo.ASN", "!geo.ASN"])
def test_bare_geo_asn_is_refused_as_a_condition(cond):
    err = _refused(f'SEND_RESPONSE {{\n    if {cond} {{\n        break;\n    }}\n}}\n')
    assert "a i64 value as a condition" in err.message


def test_geo_asn_compares_as_an_integer():
    out = _ir('SEND_RESPONSE {\n    if geo.ASN == 15169 {\n        break;\n    }\n}\n')
    assert out[3] == "  ints   = [I0:15169]"
    assert out[5:8] == [
        '    %1:i64 = call.pure EXT"cripts::Geo::ASN" @2:7',
        "    %2:i64 = const.i I0 @2:7",
        "    %3:bool = cmp.i64.eq %1, %2 @2:7",
    ]


def test_now_reads_the_part_it_names():
    out = _ir('SEND_RESPONSE {\n    if now.WEEKDAY > 5 {\n        break;\n    }\n}\n')
    assert out[5:7] == ["    %1:i64 = const.i I0 @2:7", "    %2:i64 = call.pure BI_NOW, %1 @2:7"]
    assert out[3] == "  ints   = [I0:5]"


@pytest.mark.parametrize(
    "op, cmp, operand",
    [(">", "gt", "5"), ("<", "lt", "5"), ("==", "eq", "5"), ("!=", "ne", "5"), ("==", "eq", '"5"'), ("!=", "ne", '"5"')])
def test_request_id_compares_as_an_integer(op, cmp, operand):
    out = _ir(f'SEND_RESPONSE {{\n    if id.REQUEST {op} {operand} {{\n        break;\n    }}\n}}\n')
    assert out[3] == "  ints   = [I0:5]"
    assert out[5:8] == [
        "    %1:i64 = call.pure BI_REQUEST_ID @2:7",
        "    %2:i64 = const.i I0 @2:7",
        f"    %3:bool = cmp.i64.{cmp} %1, %2 @2:7",
    ]


def test_bare_now_reads_the_epoch():
    out = _ir('SEND_RESPONSE {\n    if now > 1700000000 {\n        break;\n    }\n}\n')
    assert out[5:7] == ["    %1:i64 = const.i I0 @2:7", "    %2:i64 = call.pure BI_NOW, %1 @2:7"]
    assert out[3] == "  ints   = [I0:7, I1:1700000000]"


def test_norm_normalizes_a_hole():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{inbound.req.Host with NORM}";\n}\n')
    assert out[8:10] == ["    %3:sview = call.pure BI_CLIENT_HEADER, %2 @2:4", "    %4:sview = call.pure BI_NORM, %3 @2:4"]


@pytest.mark.parametrize("cond", ['inbound.url.path == "a b" with NORM', 'inbound.url.path ~ /a b/ with NORM'])
def test_norm_normalizes_the_value_a_condition_tests(cond):
    out = _ir(f'REMAP {{\n    if {cond} {{\n        break;\n    }}\n}}\n')
    assert any("call.pure BI_NORM" in line for line in out)


def test_norm_on_a_number_is_refused():
    assert "NORM on a i64 value" in _refused_statement('inbound.resp.X-A = "{now.HOUR with NORM}";').message


def test_percent_brace_in_a_literal_part_is_refused():
    _refused_statement('inbound.resp.X-A = "{inbound.req.Host}%{X}";')


def test_percent_brace_is_refused():
    assert "%{" in _refused_statement('inbound.resp.X-A = "%{CLIENT-HEADER:Host}";').message


def test_escaped_percent_brace_is_refused():
    _refused_statement('inbound.resp.X-A = "\\%{X}";')


@pytest.mark.parametrize("source", ["", "# only a comment\n"], ids=["empty", "comment-only"])
def test_empty_program_is_refused(source):
    err = _refused(source)
    assert (err.filename, err.line, err.column) == ("<test>", 1, 0)


def test_variable_brings_in_every_slot_below_it():
    out = _ir('VARS {\n    a: bool @2;\n}\nSEND_RESPONSE {\n    inbound.resp.X-A = "{a}";\n}\n')
    assert out[3] == "  vars   = [v0:bool, v1:bool, v2:bool]"
    assert out[8] == "    %2:bool = load.v v2:bool @5:4"


def test_variable_assignment_stores_a_constant_or_another_variable():
    out = _ir('VARS {\n    a: bool;\n    b: bool;\n}\nSEND_RESPONSE {\n    a = true;\n    b = false;\n    a = b;\n}\n')
    assert out[3:5] == ["  vars   = [v0:bool, v1:bool]", "  ints   = [I0:1, I1:0]"]
    assert out[6:12] == [
        "    %1:bool = const.i I0 @6:4",
        "    store.v v0:bool, %1 @6:4",
        "    %2:bool = const.i I1 @7:4",
        "    store.v v1:bool, %2 @7:4",
        "    %3:bool = load.v v1:bool @8:4",
        "    store.v v0:bool, %3 @8:4",
    ]


@pytest.mark.parametrize("word, on", [("true", 1), ("ON", 1), ("1", 1), ("yes", 0), ("false", 0)])
def test_variable_assignment_takes_set_state_flags_on_words(word, on):
    out = _ir(f"VARS {{\n    a: bool;\n}}\nSEND_RESPONSE {{\n    a = {word};\n}}\n")
    assert out[4] == f"  ints   = [I0:{on}]"


def test_integer_variables_are_numbered_by_kind_and_read_as_i64():
    out = _ir(
        'VARS {\n    f: bool;\n    a: int8;\n    b: int8 @2;\n    c: int16;\n}\n'
        'SEND_RESPONSE {\n    a = 7;\n    b = a;\n    c = 1000;\n    if b > 5 {\n        inbound.resp.X-C = "{c}";\n    }\n}\n')
    assert out[3] == "  vars   = [v0:u8, v1:u8, v2:u8, v0:u16]"
    assert out[8:16] == [
        "    %1:i64 = const.i I0 @8:4",
        "    store.v v0:u8, %1 @8:4",
        "    %2:i64 = load.v v0:u8 @9:4",
        "    store.v v2:u8, %2 @9:4",
        "    %3:i64 = const.i I1 @10:4",
        "    store.v v0:u16, %3 @10:4",
        "    %4:i64 = load.v v2:u8 @11:7",
        "    %5:i64 = const.i I2 @11:7",
    ]


@pytest.mark.parametrize(
    "decl, statement, kind", [
        ("a: bool;", "if a {\n        break;\n    }", "session bool"),
        ("a: int8;", "a = 1;", "session int8"),
        ("a: int16;", "inbound.resp.X-A = \"{a}\";", "session int16"),
    ])
def test_session_variable_is_refused(decl, statement, kind):
    err = _refused(f"SESSION_VARS {{\n    {decl}\n}}\nSEND_RESPONSE {{\n    {statement}\n}}\n")
    assert f"a {kind} variable" in err.message


def test_internal_and_bool_literals_are_bool_conditions():
    assert _body_ir("internal() || false")[:3] == [
        "    %1:bool = call.pure BI_INTERNAL @2:7",
        "    br.t %1, .L4 @2:7",
        "    %2:bool = const.i I0 @2:21",
    ]


def test_bare_string_read_is_refused_as_a_condition():
    err = _refused('SEND_RESPONSE {\n    if inbound.method {\n        break;\n    }\n}\n')
    assert "a sview value as a condition" in err.message


def test_non_string_value_is_named_as_such():
    err = _refused_statement("inbound.resp.X-A = inbound.req.Host;")
    assert "non-string value" in err.message


@pytest.mark.parametrize("call, args", [('run-plugin("x.so")', '""'), ('run-plugin("x.so", "a", "b c")', '"a b c"')])
def test_run_plugin_joins_its_arguments_as_the_conf_parser_does(call, args):
    out = _ir(f"REMAP {{\n    {call};\n}}\n")
    assert out[3].endswith(f"K1:{args}]")
    assert out[-2] == "    call.eff BI_RUN_PLUGIN, %1, %2 @2:4"


def _warnings(source: str, **sema_kwargs) -> tuple[ErrorCollector, Hrw4uSyntaxError | None]:
    _, tree = parse_input_text(source)
    sema = Sema(**sema_kwargs)
    sema.source_map.add("<test>", source)
    collector = ErrorCollector()
    try:
        lower(sema.analyze(ASTVisitor(filename="<test>").visit(tree)), sema.source_map, "<test>", collector)
    except Hrw4uSyntaxError as err:
        return collector, err
    return collector, None


def test_run_plugin_warns_that_the_plugin_belongs_in_cripts_or_an_extension():
    collector, err = _warnings('REMAP {\n    run-plugin("rate_limit.so", "--limit=300");\n}\n')
    assert err is None
    assert [(w.line, w.column) for w in collector.warnings] == [(2, 4)]
    assert "'rate_limit.so'" in collector.warnings[0].message
    assert "Cripts module or a Prism VM extension" in collector.warnings[0].message


def test_refused_run_plugin_does_not_warn():
    collector, err = _warnings('SEND_RESPONSE {\n    run-plugin("x.so");\n}\n')
    assert err is not None
    assert collector.warnings == []


def test_run_plugin_in_a_procedure_called_twice_warns_once(tmp_path):
    procs = _procs(tmp_path, '    run-plugin("rate_limit.so");\n')
    collector, err = _warnings('use Base::P\nREMAP {\n    Base::P();\n    Base::P();\n}\n', proc_search_paths=procs)
    assert err is None
    assert len(collector.warnings) == 1


def test_run_plugin_outside_remap_is_refused():
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir('SEND_RESPONSE {\n    run-plugin("x.so");\n}\n')
    assert "runs BI_RUN_PLUGIN only in REMAP" in err.value.message


@pytest.mark.parametrize(
    "hook, builtin, scope", [
        ("REMAP", "BI_SET_CLIENT_RESP_REDIRECT", "inbound.resp."),
        ("READ_RESPONSE", "BI_SET_SERVER_RESP_REDIRECT", "outbound.resp."),
        ("SEND_RESPONSE", "BI_SET_CLIENT_RESP_REDIRECT", "inbound.resp."),
    ])
def test_set_redirect_takes_a_status_and_a_string_for_the_hooks_response_and_warns(hook, builtin, scope):
    source = f'{hook} {{\n    set-redirect(301, "https://example.com/{{inbound.url.path}}");\n}}\n'
    collector, err = _warnings(source)
    assert err is None
    assert [(w.line, w.column) for w in collector.warnings] == [(2, 4)]
    assert f"here {scope}; write '{scope}set-redirect(...)' instead" in collector.warnings[0].message
    assert _ir(source)[-2].startswith(f"    call.eff {builtin}, %1, %")


@pytest.mark.parametrize(
    "hook, call, builtin", [
        ("REMAP", "inbound.resp.set-redirect", "BI_SET_CLIENT_RESP_REDIRECT"),
        ("SEND_RESPONSE", "inbound.resp.set-redirect", "BI_SET_CLIENT_RESP_REDIRECT"),
        ("READ_RESPONSE", "outbound.resp.set-redirect", "BI_SET_SERVER_RESP_REDIRECT"),
    ])
def test_scoped_set_redirect_names_its_response(hook, call, builtin):
    source = f'{hook} {{\n    {call}(301, "https://example.com/");\n}}\n'
    collector, err = _warnings(source)
    assert err is None
    assert collector.warnings == []
    assert _ir(source)[-2].startswith(f"    call.eff {builtin}, %1, %")


@pytest.mark.parametrize("hook, call", [("READ_RESPONSE", "inbound.resp.set-redirect"), ("REMAP", "outbound.resp.set-redirect")])
def test_scoped_set_redirect_outside_the_hooks_of_its_response_is_refused(hook, call):
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f'{hook} {{\n    {call}(301, "https://example.com/");\n}}\n')
    assert f"is not available in the {hook} section" in err.value.message


def test_set_redirect_is_refused_where_header_rewrite_refuses_it():
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir('SEND_REQUEST {\n    set-redirect(301, "https://example.com/");\n}\n')
    assert "in SEND_REQUEST: this hook has no response" in err.value.message


def test_counter_takes_a_constant_name():
    out = _ir('SEND_RESPONSE {\n    counter("hits");\n}\n')
    assert out[5:7] == ["    %1:sview = const.s K0 @2:4", "    call.eff BI_COUNTER, %1 @2:4"]


def test_access_takes_a_constant_path():
    assert _body_ir('access("/etc/hosts")')[:2] == [
        "    %1:sview = const.s K0 @2:7",
        "    %2:bool = call.pure BI_ACCESS, %1 @2:7",
    ]


def test_no_op_lowers_to_nothing():
    out = _ir('SEND_RESPONSE {\n    no-op();\n    inbound.resp.X-A = "1";\n}\n')
    assert out[5:8] == [
        "    %1:sview = const.s K0 @3:4", "    %2:sview = const.s K1 @3:4", "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %2 @3:4"
    ]


def test_set_debug_and_skip_remap_set_their_controls():
    out = _ir('REMAP {\n    set-debug();\n    skip-remap(true);\n    skip-remap(yes);\n}\n')
    assert out[3] == "  ints   = [I0:5, I1:1, I2:6, I3:0]"
    assert out[5:14] == [
        "    %1:i64 = const.i I0 @2:4",
        "    %2:bool = const.i I1 @2:4",
        "    call.eff BI_SET_HTTP_CNTL, %1, %2 @2:4",
        "    %3:i64 = const.i I2 @3:4",
        "    %4:bool = const.i I1 @3:4",
        "    call.eff BI_SET_HTTP_CNTL, %3, %4 @3:4",
        "    %5:i64 = const.i I2 @4:4",
        "    %6:bool = const.i I3 @4:4",
        "    call.eff BI_SET_HTTP_CNTL, %5, %6 @4:4",
    ]


def test_set_debug_where_header_rewrite_refuses_it_is_refused():
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir("SEND_RESPONSE {\n    set-debug();\n}\n")
    assert "header_rewrite refuses set-debug in this hook" in err.value.message


def test_http_cntl_is_read_as_a_bool():
    out = _ir('SEND_RESPONSE {\n    if http.cntl.TXN_DEBUG {\n        break;\n    }\n}\n')
    assert out[5:8] == [
        "    %1:i64 = const.i I0 @2:7",
        "    %2:bool = call.pure BI_HTTP_CNTL, %1 @2:7",
        "    br.f %2, .L4 @2:7",
    ]


def test_set_config_takes_constants_only():
    err = _refused_statement('set-config("proxy.config.http.response_server_str", "{inbound.req.X}");')
    assert 'the operand "{inbound.req.X}"' in err.message


def test_query_key_lists_are_constants():
    out = _ir('REMAP {\n    inbound.url.remove_query("b,d");\n    inbound.url.keep_query(a);\n}\n')
    assert out[3:5] == ['  consts = [K0:"b,d", K1:"a"]', "  ints   = [I0:4]"]
    assert out[6:11] == [
        "    %1:i64 = const.i I0 @2:4",
        "    %2:sview = const.s K0 @2:4",
        "    call.eff BI_RM_CLIENT_URL, %1, %2 @2:4",
        "    %3:sview = const.s K1 @3:4",
        "    call.eff BI_KEEP_CLIENT_QUERY, %3 @3:4",
    ]


@pytest.mark.parametrize("call", ['keep_query("a")', 'remove_query("a")'])
def test_query_key_lists_run_only_in_hooks_with_a_request(call):
    _ir(f"SEND_REQUEST {{\n    {call};\n}}\n")
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"SEND_RESPONSE {{\n    {call};\n}}\n")
    assert "in SEND_RESPONSE: this hook has no URL" in err.value.message


@pytest.mark.parametrize(
    "hook, call, builtin", [
        ("REMAP", 'inbound.url.remove_query("a")', "BI_RM_CLIENT_URL"),
        ("REMAP", 'inbound.url.keep_query("a")', "BI_KEEP_CLIENT_QUERY"),
        ("SEND_REQUEST", 'outbound.url.remove_query("a")', "BI_RM_SERVER_URL"),
        ("SEND_REQUEST", 'outbound.url.keep_query("a")', "BI_KEEP_SERVER_QUERY"),
    ])
def test_scoped_query_key_lists_name_their_request(hook, call, builtin):
    collector, err = _warnings(f"{hook} {{\n    {call};\n}}\n")
    assert err is None
    assert collector.warnings == []
    assert any(f"call.eff {builtin}," in line for line in _ir(f"{hook} {{\n    {call};\n}}\n"))


@pytest.mark.parametrize(
    "hook, call, builtin, scope", [
        ("REMAP", 'remove_query("a")', "BI_RM_CLIENT_URL", "inbound.url."),
        ("REMAP", 'keep_query("a")', "BI_KEEP_CLIENT_QUERY", "inbound.url."),
        ("SEND_REQUEST", 'remove_query("a")', "BI_RM_SERVER_URL", "outbound.url."),
        ("SEND_REQUEST", 'keep_query("a")', "BI_KEEP_SERVER_QUERY", "outbound.url."),
    ])
def test_unscoped_query_key_lists_work_on_the_hooks_request_and_warn(hook, call, builtin, scope):
    collector, err = _warnings(f"{hook} {{\n    {call};\n}}\n")
    assert err is None
    assert [(w.line, w.column) for w in collector.warnings] == [(2, 4)]
    func = call.split("(")[0]
    assert f"here {scope}; write '{scope}{func}(...)' instead" in collector.warnings[0].message
    assert any(f"call.eff {builtin}," in line for line in _ir(f"{hook} {{\n    {call};\n}}\n"))


@pytest.mark.parametrize(
    "hook, call", [("REMAP", 'outbound.url.keep_query("a")'), ("SEND_REQUEST", 'inbound.url.remove_query("a")')])
def test_scoped_query_key_list_outside_the_hooks_of_its_url_is_refused(hook, call):
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"{hook} {{\n    {call};\n}}\n")
    assert f"is not available in the {hook} section" in err.value.message


@pytest.mark.parametrize("func", ["keep_query", "remove_query", "inbound.url.keep_query", "inbound.url.remove_query"])
def test_query_key_list_with_a_hole_is_refused(func):
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f'REMAP {{\n    {func}("{{inbound.req.X}}");\n}}\n')
    assert "cannot interpolate" in err.value.message


@pytest.mark.parametrize(
    "hook, builtin, scope", [
        ("REMAP", "BI_ADD_CLIENT_HEADER", "inbound.req."),
        ("SEND_REQUEST", "BI_ADD_SERVER_HEADER", "outbound.req."),
        ("READ_RESPONSE", "BI_ADD_SERVER_RESP_HEADER", "outbound.resp."),
        ("SEND_RESPONSE", "BI_ADD_CLIENT_RESP_HEADER", "inbound.resp."),
    ])
def test_add_header_adds_to_the_hooks_message_and_warns(hook, builtin, scope):
    collector, err = _warnings(f'{hook} {{\n    add-header(X-A, "v{{inbound.req.B}}");\n}}\n')
    assert err is None
    assert [(w.line, w.column) for w in collector.warnings] == [(2, 4)]
    assert f"here {scope}; write '{scope}X-A += ...' instead" in collector.warnings[0].message
    out = _ir(f'{hook} {{\n    add-header(X-A, "v{{inbound.req.B}}");\n}}\n')
    assert out[6] == "    %1:sview = const.s K0 @2:4"
    assert out[-2] == f"    call.eff {builtin}, %1, %4 @2:4"


def test_procedure_body_takes_the_call_position(tmp_path):
    procs = tmp_path / "procs"
    (procs / "Base").mkdir(parents=True)
    (procs / "Base" / "Hdr.hrw4u").write_text('procedure Base::Hdr() {\n    inbound.resp.X-P = "1";\n    break;\n}\n')
    out = _ir('use Base::Hdr\nSEND_RESPONSE {\n    Base::Hdr();\n}\n', proc_search_paths=[procs])
    assert out[5:] == [
        "    %1:sview = const.s K0 @3:4",
        "    %2:sview = const.s K1 @3:4",
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %2 @3:4",
        "    break @3:4",
        "    ret @3:4",
    ]


def test_nested_procedure_takes_the_outermost_call_position(tmp_path):
    procs = tmp_path / "procs"
    (procs / "Base").mkdir(parents=True)
    (procs / "Base" / "Inner.hrw4u").write_text('procedure Base::Inner() {\n    break;\n}\n')
    (procs / "Base" / "Outer.hrw4u").write_text('use Base::Inner\nprocedure Base::Outer() {\n    Base::Inner();\n}\n')
    out = _ir('use Base::Outer\nSEND_RESPONSE {\n    inbound.resp.X-A = "1";\n    Base::Outer();\n}\n', proc_search_paths=[procs])
    assert out[-2:] == ["    break @4:4", "    ret @4:4"]


def test_server_response_is_read_in_read_response():
    out = _ir('READ_RESPONSE {\n    outbound.resp.X-A = "{outbound.resp.X-B}";\n}\n')
    assert out[8] == "    %3:sview = call.pure BI_SERVER_RESP_HEADER, %2 @2:4"


def test_escaped_braces_join_the_literal_around_them():
    out = _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "a{{x}}b{inbound.req.B}";\n}\n')
    assert out[4] == '  fmt    = [F0:"a{{x}}b{inbound.req.B}" arity=1 lits=["a{x}b", ""]]'


def test_percent_brace_made_of_escaped_braces_is_refused():
    _refused_statement('inbound.resp.X-A = "%{{X}}{inbound.req.B}";')


def test_or_under_and_skips_its_right_side_when_its_left_side_holds():
    out = _body_ir('(inbound.req.A || inbound.req.B) && inbound.req.C')
    assert [line.split(" @")[0] for line in out if line.split()[0] in ("br", "br.t", "br.f") or ".L" in line] == [
        "    br.t %4, .L10",
        "    br.f %8, .L18",
        "    .L10: %9:sview = const.s K3",
        "    br.f %12, .L18",
        "    .L18: ret",
    ]


def test_nested_if_branches_inside_its_arm():
    out = _ir(
        'SEND_RESPONSE {\n    if inbound.req.A {\n        if inbound.req.B {\n            break;\n        }\n'
        '    } else {\n        break;\n    }\n}\n')
    body = out[out.index("  IR:") + 1:]
    assert [line.split(" @")[0] for line in body if line.split()[0] in ("br", "br.t", "br.f", "break") or ".L" in line] == [
        "    br.f %4, .L12",
        "    br.f %8, .L11",
        "    break",
        "    .L11: br .L13",
        "    .L12: break",
        "    .L13: ret",
    ]
    assert out[-1] == "    .L13: ret @7:8"


def test_string_comparison_on_an_address_is_refused():
    err = _refused('SEND_RESPONSE {\n    if inbound.ip == "10.0.0.1" {\n        break;\n    }\n}\n')
    assert (err.line, err.column) == (2, 7)


@pytest.mark.parametrize("operand", ["foo", "9223372036854775808"])
def test_operand_that_is_not_an_i64_is_refused(operand):
    _refused(f"SEND_RESPONSE {{\n    if inbound.status == {operand} {{\n        break;\n    }}\n}}\n")


def test_largest_i64_operand_is_kept():
    out = _ir("SEND_RESPONSE {\n    if inbound.status < 9223372036854775807 {\n        break;\n    }\n}\n")
    assert out[3] == "  ints   = [I0:9223372036854775807]"


def test_less_than_on_a_string_is_refused():
    _refused('SEND_RESPONSE {\n    if inbound.req.A < "a" {\n        break;\n    }\n}\n')


def test_unread_variables_write_no_vars_pool():
    out = _ir('VARS {\n    a: bool;\n}\nSEND_RESPONSE {\n    inbound.resp.X-A = "1";\n}\n')
    assert out[3] == '  consts = [K0:"X-A", K1:"1"]'


def test_bool_literals_share_the_ints_of_zero_and_one():
    out = _ir('SEND_RESPONSE {\n    if random(1) == 0 || true {\n        break;\n    }\n}\n')
    assert out[3] == "  ints   = [I0:1, I1:0]"
    assert "    %5:bool = const.i I0 @2:25" in out


@pytest.mark.parametrize("items", ['"\\""', 'a, "\\""', '"a\\b"'])
def test_set_with_a_backslash_or_an_odd_quote_is_refused(items):
    _refused(f'SEND_RESPONSE {{\n    if inbound.req.A in [{items}] {{\n        break;\n    }}\n}}\n')


def test_set_item_is_trimmed_inside_its_quotes():
    out = _ir('SEND_RESPONSE {\n    if inbound.req.A in [" foo "] {\n        break;\n    }\n}\n')
    assert out[4] == '  sets   = [S0:s("foo")]'


def test_regex_and_set_pools_share_equal_entries():
    out = _ir(
        'SEND_RESPONSE {\n    if inbound.req.A ~ /a/ || inbound.req.B ~ /a/ || inbound.req.C ~ /a/ with NOCASE {\n'
        '        break;\n    }\n}\n')
    assert out[4] == "  regex  = [R0:/a/, R1:/a/i]"


def test_removing_the_port_clears_it():
    out = _ir('REMAP {\n    inbound.url.port = "";\n}\n')
    assert out[3:5] == ['  consts = [K0:""]', "  ints   = [I0:2]"]
    assert out[-2] == "    call.eff BI_RM_CLIENT_URL, %1, %2 @2:4"


@pytest.mark.parametrize("port", ["8080", '"8080"'])
def test_setting_the_port_takes_a_constant(port):
    out = _ir(f'REMAP {{\n    inbound.url.port = {port};\n}}\n')
    assert out[3] == "  ints   = [I0:8080]"
    assert out[-2] == "    call.eff BI_SET_CLIENT_URL_PORT, %1 @2:4"


def test_setting_the_whole_url_is_a_destination_field():
    out = _ir('REMAP {\n    inbound.url.url = "http://other.test/x";\n}\n')
    assert out[4] == "  ints   = [I0:5]"
    assert out[-2] == "    call.eff BI_SET_CLIENT_URL, %1, %2 @2:4"


@pytest.mark.parametrize("port", ['"x"', '"0"', '"65536"', '"{inbound.req.X-Port}"'])
def test_a_port_set_destination_would_skip_is_refused(port):
    _refused(f'REMAP {{\n    inbound.url.port = {port};\n}}\n')


@pytest.mark.parametrize("statement", ['inbound.url.path = "";', 'inbound.url.path = "x";'])
def test_url_write_in_a_response_hook_is_refused(statement):
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"SEND_RESPONSE {{\n    {statement}\n}}\n")
    assert "in SEND_RESPONSE: this hook has no URL" in err.value.message


def test_outbound_url_write_at_send_request_sets_the_origin_request_url():
    out = _ir('SEND_REQUEST {\n    outbound.url.path = "x";\n}\n')
    assert out[-2] == "    call.eff BI_SET_SERVER_URL, %1, %2 @2:4"


@pytest.mark.parametrize(
    "hook, statement, scope", [
        ("SEND_REQUEST", 'inbound.url.path = "x";', "outbound.url."),
        ("REMAP", 'outbound.url.path = "x";', "inbound.url."),
        ("PRE_REMAP", "outbound.url.port = 8080;", "inbound.url."),
    ])
def test_url_scope_naming_another_request_than_the_hooks_is_refused(hook, statement, scope):
    # header_rewrite's set-destination changes the hook's request whatever the scope says.
    with pytest.raises(Hrw4uSyntaxError) as err:
        _ir(f"{hook} {{\n    {statement}\n}}\n")
    assert f"in {hook}: this hook's URL is {scope}, which header_rewrite would work on instead" in err.value.message


def test_set_body_from_fetches_an_interpolated_url():
    out = _ir('READ_RESPONSE {\n    set-body-from("http://errors.example.com/{inbound.req.Host}");\n}\n')
    assert out[-3:-1] == ["    %4:sview = const.s K1 @2:4", "    call.eff BI_SET_BODY_FROM, %3, %4 @2:4"]


@pytest.mark.parametrize("control, value, ints", [
    ("TIMEZONE", "GMT", "[I0:0, I1:1]"),
    ("INBOUND_IP_SOURCE", "PROXY", "[I0:1]"),
])
def test_set_plugin_cntl_numbers_the_control_and_its_value(control, value, ints):
    out = _ir(f'SEND_RESPONSE {{\n    set-plugin-cntl({control}, {value});\n}}\n')
    assert out[3] == f"  ints   = {ints}"
    assert out[-2].startswith("    call.eff BI_SET_PLUGIN_CNTL, %1, %2 ")


@pytest.mark.parametrize(
    "field, prefix", [
        ("TLS", "tls/"),
        ("H2", "h2"),
        ("IPV4", "ipv4"),
        ("IPV6", "ipv6"),
        ("IP-FAMILY", "ip"),
    ])
def test_client_protocol_field_asks_for_its_tag_prefix(field, prefix):
    out = _ir(f'SEND_RESPONSE {{\n    inbound.resp.X-A = "{{inbound.conn.{field}}}";\n}}\n')
    assert out[3] == f'  consts = [K0:"X-A", K1:"{prefix}"]'
    assert "    %3:sview = call.pure BI_CLIENT_PROTOCOL, %2 @2:4" in out


@pytest.mark.parametrize("field, number", [("HOST", 0), ("PORT", 1), ("STRATEGY", 2)])
def test_next_hop_numbers_its_field(field, number):
    out = _ir(f'READ_RESPONSE {{\n    outbound.resp.X-A = "{{nexthop.{field}}}";\n}}\n')
    assert out[4] == f"  ints   = [I0:{number}]"
    assert "    %3:sview = call.pure BI_NEXT_HOP, %2 @2:4" in out


@pytest.mark.parametrize(
    "field, number", [
        ("PEM", 0), ("sig", 1), ("SUBJECT", 2), ("ISSUER", 3), ("serial", 4), ("NOT_BEFORE", 5), ("not_after", 6), ("VERSION", 7),
        ("SAN.DNS", 8), ("san.ip", 9), ("SAN.EMAIL", 10), ("san.uri", 11)
    ])
@pytest.mark.parametrize("role, builtin", [("client", "BI_INBOUND_CLIENT_CERT"), ("server", "BI_INBOUND_SERVER_CERT")])
def test_inbound_cert_numbers_its_field(role, builtin, field, number):
    out = _ir(f'SEND_RESPONSE {{\n    inbound.resp.X-A = "{{inbound.conn.{role}-cert.{field}}}";\n}}\n')
    assert out[4] == f"  ints   = [I0:{number}]"
    assert f"    %3:sview = call.pure {builtin}, %2 @2:4" in out


def test_ports_are_strings():
    out = _ir('SEND_RESPONSE {\n    if inbound.conn.LOCAL-PORT == "0" {\n        break;\n    }\n}\n')
    assert out[5:8] == [
        "    %1:sview = call.pure BI_LOCAL_PORT @2:7",
        "    %2:sview = const.s K0 @2:7",
        "    %3:bool = cmp.s.eq %1, %2 @2:7",
    ]
    assert "call.pure BI_CLIENT_PORT" in "\n".join(
        _ir('SEND_RESPONSE {\n    inbound.resp.X-A = "{inbound.conn.REMOTE-PORT}";\n}\n'))


def _procs(tmp_path, body: str, params: str = ""):
    procs = tmp_path / "procs"
    (procs / "Base").mkdir(parents=True)
    (procs / "Base" / "P.hrw4u").write_text(f"procedure Base::P({params}) {{\n{body}}}\n")
    return [procs]


def test_statement_after_a_procedure_call_keeps_its_own_position(tmp_path):
    out = _ir(
        'use Base::P\nSEND_RESPONSE {\n    Base::P();\n    inbound.resp.X-A = "1";\n}\n',
        proc_search_paths=_procs(tmp_path, "    break;\n"))
    assert out[-5:] == [
        "    break @3:4",
        "    %1:sview = const.s K0 @4:4",
        "    %2:sview = const.s K1 @4:4",
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %2 @4:4",
        "    ret @4:4",
    ]


def test_procedure_that_lowers_nothing_does_not_move_ret(tmp_path):
    out = _ir(
        'use Base::P\nSEND_RESPONSE {\n    inbound.resp.X-A = "1";\n    Base::P();\n}\n',
        proc_search_paths=_procs(tmp_path, "    # nothing\n"))
    assert out[-1] == "    ret @3:4"


@pytest.mark.parametrize("argument", ['"{inbound.req.Host}"', '"a\\tb"'])
def test_bare_parameter_carrying_conf_text_is_refused_as_an_operand(tmp_path, argument):
    procs = _procs(tmp_path, "    if inbound.req.X-Foo == $v {\n        break;\n    }\n", "$v")
    assert "the operand" in _refused(
        f"use Base::P\nSEND_RESPONSE {{\n    Base::P({argument});\n}}\n", proc_search_paths=procs).message


def test_parameter_in_a_call_is_substituted(tmp_path):
    procs = _procs(tmp_path, '    add-header($n, "x");\n', "$n")
    out = _ir('use Base::P\nSEND_RESPONSE {\n    Base::P(X-A);\n}\n', proc_search_paths=procs)
    assert out[3] == '  consts = [K0:"X-A", K1:"x"]'


def _instance_ir(decls: str, hook: str) -> list[str]:
    source = f"INSTANCE_VARS {{\n    {decls}\n}}\nSEND_RESPONSE {{\n    {hook}\n}}\n"
    return _ir(source, ir_version=(1, 1))


def test_each_instance_variable_is_stored_once_in_declaration_order():
    out = _instance_ir('a: string = "x";\n    # c\n    b: string = "y";', "inbound.resp.X = b;")
    assert out[:12] == [
        "hrw4u-ir 1.1",
        "",
        "Instance:",
        "  ivars  = [i0:sview, i1:sview]",
        '  consts = [K0:"x", K1:"y", K2:"X"]',
        "  IR:",
        "    %1:sview = const.s K0 @2:4",
        "    store.i i0, %1 @2:4",
        "    %2:sview = const.s K1 @4:4",
        "    store.i i1, %2 @4:4",
        "    ret @4:4",
        "",
    ]
    assert out[12:15] == ["Section[SEND_RESPONSE]:", "  IR:", "    %1:sview = const.s K2 @7:4"]
    assert out[15] == "    %2:sview = load.i i1 @7:4"


def test_an_instance_variable_fills_a_hole():
    out = _instance_ir('a: string = "x";', 'inbound.resp.X = "<{a}>";')
    assert '  fmt    = [F0:"<{a}>" arity=1 lits=["<", ">"]]' in out
    assert out[-4:-2] == ["    %2:sview = load.i i0 @5:4", "    %3:sview = fmt F0, %2 @5:4"]


def test_an_instance_variable_where_a_constant_must_go_is_refused():
    with pytest.raises(Hrw4uSyntaxError) as err:
        _instance_ir('a: string = "x";', "counter(a);")
    assert err.value.message == "the operand a is not supported by the IR emitter yet"
