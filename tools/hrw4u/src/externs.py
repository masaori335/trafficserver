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
"""The functions hrw4u.so binds, as the manifests hrw4u-extern prints declare them."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import hrw4u.ast_nodes as ast
from hrw4u.ast_visitor import parse_file
from hrw4u.errors import SourceMap

SCRIPT_DECL_ERROR = "extern is allowed only in a manifest (--extern FILE)"

_TYPES = ("string", "int64", "bool")
_EFFECTS = ("pure", "load")


@dataclass(frozen=True)
class ExternDecl:
    name: str
    params: tuple[str, ...]
    result: str
    effect: str  # "pure", "load" or "effect"
    where: str  # "file:line"


def load_manifests(paths: list[Path]) -> dict[str, ExternDecl]:
    """The declarations of the manifests, by name, read in order."""
    declared: dict[str, ExternDecl] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8")
        source_map = SourceMap()
        source_map.add(str(path), text)
        for node in parse_file(text, str(path)).body:
            match node:
                case ast.Comment():
                    continue
                case ast.ExternDecl():
                    decl = _declaration(node, source_map)
                    if first := declared.get(decl.name):
                        raise source_map.error_at(node.span, f"'{decl.name}' is declared twice: {first.where} and {decl.where}")
                    declared[decl.name] = decl
                case _:
                    raise source_map.error_at(node.span, "a manifest holds extern declarations only")
    return declared


def _declaration(node: ast.ExternDecl, source_map: SourceMap) -> ExternDecl:
    for name in (*node.params, node.result):
        if name not in _TYPES:
            raise source_map.error_at(node.span, f"unknown type '{name}' ({', '.join(_TYPES)})")
    effect = "effect"
    if node.effect is not None:
        if node.effect not in _EFFECTS:
            raise source_map.error_at(node.span, f"unknown effect '{node.effect}' ({', '.join(_EFFECTS)}, or none)")
        effect = node.effect
    return ExternDecl(node.name, node.params, node.result, effect, f"{node.span.file}:{node.span.line}")


def lookup(externs: dict[str, ExternDecl], name: str) -> ExternDecl:
    if decl := externs.get(name):
        return decl
    raise ValueError(f"unknown function '{name}': no --extern manifest declares it")


def check_call(decl: ExternDecl, arg_types: list[str | None], *, at_load: bool = False) -> None:
    """Refuse a call for its value the IR cannot make, in a hook or, `at_load`, in an INSTANCE_VARS initializer. An
    argument's type is None when only lowering knows it."""
    if decl.effect == "effect":
        raise ValueError(f"'{decl.name}' has an effect; calling it is not supported yet")
    if decl.effect == "load" and not at_load:
        raise ValueError(f"'{decl.name}' runs at load only; call it in an INSTANCE_VARS initializer")
    if len(arg_types) != len(decl.params):
        raise ValueError(f"'{decl.name}' takes {len(decl.params)} arguments, {len(arg_types)} given")
    for n, (given, param) in enumerate(zip(arg_types, decl.params), 1):
        if given is not None and given != param:
            raise ValueError(f"argument {n} of '{decl.name}' is {given}, not {param}")


def refuse_bare_refs(decl: ExternDecl, refs: list[str | None]) -> None:
    """Refuse a string argument written as a bare reference, `refs[i]` being its text or None, which the IR passes no
    value for."""
    for n, (ref, param) in enumerate(zip(refs, decl.params), 1):
        if ref is not None and param == "string":
            raise ValueError(f"argument {n} of '{decl.name}' is a bare reference; write it as \"{{{ref}}}\"")


def value_call_statement(name: str) -> ValueError:
    return ValueError(f"'{name}' is called for its value; assign it")


def refuse_call_args(externs: dict[str, ExternDecl], name: str, calls: list[str], *, in_condition: bool) -> None:
    """Refuse a call among the arguments of `name`, which takes values only, and in a condition, a call to a declared
    function before anything else."""
    for callee in [name, *calls]:
        if in_condition and callee in externs:
            raise ValueError(f"'{callee}' cannot be called in a condition yet")
    for callee in calls:
        raise ValueError(f"a call to '{callee}' cannot be an argument of '{name}' yet")
