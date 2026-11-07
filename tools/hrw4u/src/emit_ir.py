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

from __future__ import annotations

from hrw4u.features import version_line
from hrw4u.ir_nodes import Format, Instruction, IRProgram, Label, Pattern, Pools, SetEntry, SetKind, qstr

_REGEX_ESCAPES = {"\\": "\\\\", "/": "\\/", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _instruction_line(index: int, instruction: Instruction, targets: set[int]) -> str:
    text = "    "
    if index in targets:
        text += f".L{index}: "
    if instruction.dest is not None:
        text += f"{instruction.dest.text}:{instruction.dest.ty} = "
    text += instruction.op
    if instruction.operands:
        text += " " + ", ".join(op.text for op in instruction.operands)
    return f"{text} @{instruction.line}:{instruction.column}"


def _pool_lines(pools: Pools) -> list[str]:
    out = []
    if pools.ivars:
        entries = ", ".join(f"{var.text}:sview" for var in pools.ivars)
        out.append(f"  {'ivars':<6} = [{entries}]")
    if pools.vars:
        entries = ", ".join(var.text for var in pools.vars)
        out.append(f"  {'vars':<6} = [{entries}]")
    if pools.consts:
        entries = ", ".join(f"K{i}:{qstr(v)}" for i, v in enumerate(pools.consts))
        out.append(f"  {'consts':<6} = [{entries}]")
    if pools.ints:
        entries = ", ".join(f"I{i}:{v}" for i, v in enumerate(pools.ints))
        out.append(f"  {'ints':<6} = [{entries}]")
    if pools.regexes:
        entries = ", ".join(_regex_entry(i, r) for i, r in enumerate(pools.regexes))
        out.append(f"  {'regex':<6} = [{entries}]")
    if pools.fmts:
        entries = ", ".join(_format_entry(i, f) for i, f in enumerate(pools.fmts))
        out.append(f"  {'fmt':<6} = [{entries}]")
    if pools.sets:
        entries = ", ".join(_set_entry(i, s) for i, s in enumerate(pools.sets))
        out.append(f"  {'sets':<6} = [{entries}]")
    return out


def _regex_char(ch: str) -> str:
    if ch in _REGEX_ESCAPES:
        return _REGEX_ESCAPES[ch]
    if ord(ch) < 0x20 or ord(ch) == 0x7F:
        return f"\\x{ord(ch):02X}"
    return ch


def _regex_entry(index: int, regex: Pattern) -> str:
    body = "".join(_regex_char(ch) for ch in regex.body)
    flags = ""
    if regex.nocase:
        flags = "i"
    return f"R{index}:/{body}/{flags}"


def _set_entry(index: int, entry: SetEntry) -> str:
    items = ", ".join(qstr(item) for item in entry.items)
    if entry.kind is SetKind.INT:
        items = ", ".join(entry.items)
    match = ""
    if entry.match:
        match = f" {entry.match}"
    nocase = ""
    if entry.nocase:
        nocase = " nocase"
    return f"S{index}:{entry.kind}({items}){match}{nocase}"


def _format_entry(index: int, fmt: Format) -> str:
    lits = ", ".join(qstr(lit) for lit in fmt.lits)
    return f"F{index}:{qstr(fmt.source)} arity={len(fmt.lits) - 1} lits=[{lits}]"


def _section_lines(header: str, instructions: list[Instruction], pools: list[str]) -> list[str]:
    out = ["", header, *pools, "  IR:"]
    # The reader takes a label on a branch target only.
    targets = {op.index for i in instructions for op in i.operands if isinstance(op, Label)}
    assert None not in targets, "a branch to a label the lowerer never placed"
    out.extend(_instruction_line(n, instruction, targets) for n, instruction in enumerate(instructions))
    return out


def write_ir(program: IRProgram, version: tuple[int, int]) -> list[str]:
    out = [version_line(version)]
    # The reader takes the pools under the first section only, the Instance section when there is one: they serve the
    # whole program.
    pools = _pool_lines(program.pools)
    if program.instance is not None:
        out += _section_lines("Instance:", program.instance, pools)
        pools = []
    for section in program.sections:
        out += _section_lines(f"Section[{section.hook.value}]:", section.instructions, pools)
        pools = []
    return out
