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
"""The Typed IR program that hrw4u.so reads, as data the text writer renders."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Union

from hrw4u.states import SectionType

_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def qstr(value: str) -> str:
    """The IR's quoted string. Code points from 0x80 stay raw, so a UTF-8 header value stays readable."""
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\x{code:02X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


class Ty(StrEnum):
    BOOL = "bool"
    SVIEW = "sview"
    I64 = "i64"
    ADDR = "addr"


class Op(StrEnum):
    CONST_S = "const.s"
    CONST_I = "const.i"
    FMT = "fmt"
    CMP_S_EQ = "cmp.s.eq"
    CMP_S_NE = "cmp.s.ne"
    CMP_I64_EQ = "cmp.i64.eq"
    CMP_I64_NE = "cmp.i64.ne"
    CMP_I64_LT = "cmp.i64.lt"
    CMP_I64_GT = "cmp.i64.gt"
    RE_MATCH = "re.match"
    IN_SET = "in.set"
    LOAD_V = "load.v"
    STORE_V = "store.v"
    LOAD_I = "load.i"  # IR 1.1
    STORE_I = "store.i"  # IR 1.1
    CALL_PURE = "call.pure"
    CALL_LOAD = "call.load"  # IR 1.1
    CALL_EFF = "call.eff"
    BR_T = "br.t"
    BR_F = "br.f"
    BR = "br"
    BREAK = "break"
    RET = "ret"


@dataclass(frozen=True, slots=True)
class Reg:
    n: int
    ty: Ty

    @property
    def text(self) -> str:
        return f"%{self.n}"


@dataclass(frozen=True, slots=True)
class Const:
    index: int

    @property
    def text(self) -> str:
        return f"K{self.index}"


@dataclass(frozen=True, slots=True)
class IntConst:
    index: int

    @property
    def text(self) -> str:
        return f"I{self.index}"


class VarKind(StrEnum):
    """What a transaction variable keeps: a bool, or an integer in hrw4u's int8 (0-255) or int16 (0-65535) range."""
    BOOL = "bool"
    U8 = "u8"
    U16 = "u16"


@dataclass(frozen=True, slots=True)
class Var:
    slot: int  # numbered within its kind, as hrw4u numbers its slots
    kind: VarKind

    @property
    def text(self) -> str:
        return f"v{self.slot}:{self.kind}"


@dataclass(frozen=True, slots=True)
class IVar:
    """IR 1.1: an instance variable, a string the Instance section stores once, at load, and every hook reads."""
    index: int

    @property
    def text(self) -> str:
        return f"i{self.index}"


@dataclass(frozen=True, slots=True)
class Regex:
    index: int

    @property
    def text(self) -> str:
        return f"R{self.index}"


@dataclass(frozen=True, slots=True)
class Set:
    index: int

    @property
    def text(self) -> str:
        return f"S{self.index}"


@dataclass(frozen=True, slots=True)
class Fmt:
    index: int

    @property
    def text(self) -> str:
        return f"F{self.index}"


@dataclass(frozen=True, slots=True)
class Builtin:
    name: str

    @property
    def text(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class Extern:
    """A function hrw4u.so binds by the name it registers: an extension's, or a Cripts binding such as
    cripts::Geo::Country."""
    name: str

    @property
    def text(self) -> str:
        return "EXT" + qstr(self.name)


@dataclass(eq=False, slots=True)
class Label:
    """A branch target, placed at an instruction index once the lowerer reaches it."""
    index: int | None = None

    @property
    def text(self) -> str:
        return f".L{self.index}"


Operand = Union[Reg, Const, IntConst, Var, IVar, Regex, Fmt, Set, Builtin, Extern, Label]


@dataclass(frozen=True, slots=True)
class Instruction:
    op: Op
    operands: tuple[Operand, ...]
    dest: Reg | None
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class Format:
    """A string with holes: lits[0], hole 0, lits[1], ..., lits[n]. `source` is the template as written."""
    source: str
    lits: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Pattern:
    """A regular expression as written between its slashes."""
    body: str
    nocase: bool


class SetKind(StrEnum):
    STRING = "s"
    INT = "i"
    IP = "ip"


class SetMatch(StrEnum):
    WHOLE = ""
    PREFIX = "pre"
    SUFFIX = "suf"
    SUBSTRING = "mid"
    EXTENSION = "ext"


@dataclass(frozen=True, slots=True)
class SetEntry:
    kind: SetKind
    items: tuple[str, ...]
    nocase: bool
    match: SetMatch = SetMatch.WHOLE


@dataclass
class Pools:
    ivars: list[IVar] = field(default_factory=list)  # IR 1.1
    vars: list[Var] = field(default_factory=list)
    consts: list[str] = field(default_factory=list)
    ints: list[int] = field(default_factory=list)
    regexes: list[Pattern] = field(default_factory=list)
    fmts: list[Format] = field(default_factory=list)
    sets: list[SetEntry] = field(default_factory=list)
    _index: dict[tuple[str, object], int] = field(default_factory=dict, repr=False)

    def use_var(self, var: Var) -> None:
        """The reader numbers the variables of each kind densely from v0, so a variable brings in every one below it."""
        for slot in range(var.slot + 1):
            if Var(slot, var.kind) not in self.vars:
                self.vars.append(Var(slot, var.kind))

    def intern_const(self, value: str) -> int:
        return self._intern("consts", self.consts, value)

    def intern_int(self, value: int) -> int:
        return self._intern("ints", self.ints, value)

    def intern_regex(self, value: Pattern) -> int:
        return self._intern("regexes", self.regexes, value)

    def intern_set(self, value: SetEntry) -> int:
        return self._intern("sets", self.sets, value)

    def intern_fmt(self, value: Format) -> int:
        return self._intern("fmts", self.fmts, value)

    def _intern(self, name: str, pool: list, value: object) -> int:
        key = (name, value)
        if key not in self._index:
            self._index[key] = len(pool)
            pool.append(value)
        return self._index[key]


@dataclass
class IRSection:
    hook: SectionType
    instructions: list[Instruction]


@dataclass
class IRProgram:
    pools: Pools
    sections: list[IRSection]
    instance: list[Instruction] | None = None  # IR 1.1: the Instance section's, run once at load
