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

from hrw4u.emit_ir import qstr, write_ir
from hrw4u.ir_nodes import (
    Builtin, Const, Extern, Format, Instruction, IRProgram, IRSection, IVar, Label, Op, Pattern, Pools, Reg, Ty, Var, VarKind)
from hrw4u.states import SectionType


def _program(pools: Pools, instructions: list[Instruction]) -> IRProgram:
    return IRProgram(pools, [IRSection(SectionType.SEND_RESPONSE, instructions)])


def test_writes_set_foo():
    pools = Pools()
    k0, k1 = pools.intern_const("X-Foo"), pools.intern_const("bar")
    instructions = [
        Instruction(Op.CONST_S, (Const(k0),), Reg(1, Ty.SVIEW), 2, 4),
        Instruction(Op.CONST_S, (Const(k1),), Reg(2, Ty.SVIEW), 2, 4),
        Instruction(Op.CALL_EFF, (Builtin("BI_SET_CLIENT_RESP_HEADER"), Reg(1, Ty.SVIEW), Reg(2, Ty.SVIEW)), None, 2, 4),
        Instruction(Op.RET, (), None, 2, 4),
    ]
    assert write_ir(_program(pools, instructions), (1, 0)) == [
        "hrw4u-ir 1.0",
        "",
        "Section[SEND_RESPONSE]:",
        '  consts = [K0:"X-Foo", K1:"bar"]',
        "  IR:",
        "    %1:sview = const.s K0 @2:4",
        "    %2:sview = const.s K1 @2:4",
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %2 @2:4",
        "    ret @2:4",
    ]


def test_empty_pool_writes_no_consts_line():
    program = _program(Pools(), [Instruction(Op.RET, (), None, 1, 0)])
    assert write_ir(program, (1, 0)) == ["hrw4u-ir 1.0", "", "Section[SEND_RESPONSE]:", "  IR:", "    ret @1:0"]


def test_writes_the_version_it_is_given():
    program = _program(Pools(), [Instruction(Op.RET, (), None, 1, 0)])
    assert write_ir(program, (1, 1))[0] == "hrw4u-ir 1.1"


def test_break_has_no_operands():
    program = _program(Pools(), [Instruction(Op.BREAK, (), None, 3, 4), Instruction(Op.RET, (), None, 3, 4)])
    assert write_ir(program, (1, 0))[-2] == "    break @3:4"


def test_pools_are_written_under_the_first_section_only():
    pools = Pools()
    pools.intern_const("X")
    program = IRProgram(
        pools, [
            IRSection(SectionType.SEND_REQUEST, [Instruction(Op.RET, (), None, 2, 4)]),
            IRSection(SectionType.SEND_RESPONSE, [Instruction(Op.RET, (), None, 6, 4)]),
        ])
    assert write_ir(program, (1, 0)) == [
        "hrw4u-ir 1.0",
        "",
        "Section[SEND_REQUEST]:",
        '  consts = [K0:"X"]',
        "  IR:",
        "    ret @2:4",
        "",
        "Section[SEND_RESPONSE]:",
        "  IR:",
        "    ret @6:4",
    ]


def test_the_instance_section_comes_first_and_takes_the_pools():
    pools = Pools()
    pools.ivars.append(IVar(0))
    k0, k1 = pools.intern_const("key.hex"), pools.intern_const("X")
    instance = [
        Instruction(Op.CONST_S, (Const(k0),), Reg(1, Ty.SVIEW), 2, 4),
        Instruction(Op.CALL_LOAD, (Extern("cripts::File::Line::Read"), Reg(1, Ty.SVIEW)), Reg(2, Ty.SVIEW), 2, 4),
        Instruction(Op.STORE_I, (IVar(0), Reg(2, Ty.SVIEW)), None, 2, 4),
        Instruction(Op.RET, (), None, 2, 4),
    ]
    hook = [
        Instruction(Op.CONST_S, (Const(k1),), Reg(1, Ty.SVIEW), 5, 4),
        Instruction(Op.LOAD_I, (IVar(0),), Reg(2, Ty.SVIEW), 5, 4),
        Instruction(Op.CALL_EFF, (Builtin("BI_SET_CLIENT_RESP_HEADER"), Reg(1, Ty.SVIEW), Reg(2, Ty.SVIEW)), None, 5, 4),
        Instruction(Op.RET, (), None, 5, 4),
    ]
    program = IRProgram(pools, [IRSection(SectionType.SEND_RESPONSE, hook)], instance)
    assert write_ir(program, (1, 1)) == [
        "hrw4u-ir 1.1",
        "",
        "Instance:",
        "  ivars  = [i0:sview]",
        '  consts = [K0:"key.hex", K1:"X"]',
        "  IR:",
        "    %1:sview = const.s K0 @2:4",
        '    %2:sview = call.load EXT"cripts::File::Line::Read", %1 @2:4',
        "    store.i i0, %2 @2:4",
        "    ret @2:4",
        "",
        "Section[SEND_RESPONSE]:",
        "  IR:",
        "    %1:sview = const.s K1 @5:4",
        "    %2:sview = load.i i0 @5:4",
        "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %2 @5:4",
        "    ret @5:4",
    ]


def test_ivars_are_written_before_vars():
    pools = Pools()
    pools.ivars += [IVar(0), IVar(1)]
    pools.use_var(Var(0, VarKind.BOOL))
    program = IRProgram(pools, [IRSection(SectionType.SEND_RESPONSE, [Instruction(Op.RET, (), None, 1, 0)])], [])
    assert write_ir(program, (1, 1))[2:5] == ["Instance:", "  ivars  = [i0:sview, i1:sview]", "  vars   = [v0:bool]"]


def test_ints_are_written_between_consts_and_fmt():
    pools = Pools()
    pools.intern_const("X")
    pools.intern_int(3)
    pools.intern_fmt(Format("{x}", ("", "")))
    assert write_ir(_program(pools, [Instruction(Op.RET, (), None, 1, 0)]), (1, 0))[3:6] == [
        '  consts = [K0:"X"]',
        "  ints   = [I0:3]",
        '  fmt    = [F0:"{x}" arity=1 lits=["", ""]]',
    ]


def test_label_is_written_on_a_branch_target_only():
    target = Label(2)
    instructions = [
        Instruction(Op.BR, (target,), None, 2, 4),
        Instruction(Op.BREAK, (), None, 3, 4),
        Instruction(Op.RET, (), None, 3, 4),
    ]
    assert write_ir(_program(Pools(), instructions), (1, 0))[-3:] == ["    br .L2 @2:4", "    break @3:4", "    .L2: ret @3:4"]


def test_intern_const_reuses_the_index():
    pools = Pools()
    assert [pools.intern_const(v) for v in ("a", "b", "a")] == [0, 1, 0]
    assert pools.consts == ["a", "b"]


def test_qstr_escapes_quote_and_backslash():
    assert qstr('a"b\\c') == '"a\\"b\\\\c"'


def test_qstr_escapes_control_characters():
    assert qstr("\n\r\t") == '"\\n\\r\\t"'
    assert qstr("\x01\x7f") == '"\\x01\\x7F"'


def test_qstr_keeps_utf8_and_braces_raw():
    assert qstr("ü {x}") == '"ü {x}"'


def test_extern_name_is_quoted_as_a_string():
    assert Extern("cripts::Geo::Country").text == 'EXT"cripts::Geo::Country"'
    assert Extern('a"b\\c').text == 'EXT"a\\"b\\\\c"'


def test_regex_escapes_slash_backslash_and_controls():
    pools = Pools()
    pools.intern_regex(Pattern("a/\\\x01", True))
    assert write_ir(_program(pools, [Instruction(Op.RET, (), None, 1, 0)]), (1, 0))[3] == "  regex  = [R0:/a\\/\\\\\\x01/i]"
