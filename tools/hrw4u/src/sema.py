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

import re
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Callable

import hrw4u.ast_nodes as ast
import hrw4u.sema_nodes as ir
import hrw4u.types as types
from hrw4u.ast_visitor import call_ast
from hrw4u.common import SystemDefaults, split_interpolation_mods
from hrw4u.debugging import Dbg
from hrw4u.errors import ErrorCollector, Hrw4uSyntaxError, SourceMap, SymbolResolutionError, Warning, hrw4u_error_at
from hrw4u.externs import (
    SCRIPT_DECL_ERROR, ExternDecl, check_call, lookup, refuse_bare_refs, refuse_call_args, value_call_statement)
from hrw4u.features import CALL_VALUE, INSTANCE_VARS, Feature, check_target
from hrw4u.interpolation import Escaped, Hole, parse_call, scan
from hrw4u.procedures import ProcEntry, ProcRegistry
from hrw4u.sandbox import SandboxConfig, SandboxDenialError
from hrw4u.states import CondState, SectionType, VALUE_MODIFIERS
from hrw4u.symbols import SymbolResolver
from hrw4u.validation import Validator

_VAR_SECTIONS = {
    "txn": ("Variable", "VARS", types.VarScope.TXN),
    "session": ("Session variable", "SESSION_VARS", types.VarScope.SESSION),
    "instance": ("Instance variable", "INSTANCE_VARS", None),
}

_LOAD_READS_TXN = "an INSTANCE_VARS initializer cannot read the transaction"

_PARAM_REF = re.compile(r'\$([a-zA-Z_][a-zA-Z0-9_-]*)')


def _quoted_params(sig: ProcEntry, call: ast.FunctionCall) -> frozenset[str]:
    """The parameters a call binds to a string: a quoted argument, or a string default it leaves in place."""
    quoted = {p.name for p, a in zip(sig.params, call.args) if isinstance(a, ast.LiteralStringValue)}
    quoted |= {p.name for p in sig.params[len(call.args):] if isinstance(p.default, ast.LiteralStringValue)}
    return frozenset(quoted)


def _calls(args: tuple[ast.ValueExpr | ast.FunctionCall, ...]) -> list[str]:
    return [a.name for a in args if isinstance(a, ast.FunctionCall)]


def _strip_quotes(text: str) -> str:
    if text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return text


# _unescape_double_braces is copied from HRW4UVisitor rather than shared: its copy goes with the CST emitter.
def _unescape_double_braces(escaped: str) -> str:
    """`{{...}}` in a string literal: the payload as literal `{...}`, unescaped quotes escaped."""
    out: list[str] = []
    backslashes = 0
    for char in escaped[2:-2]:
        if char == '"' and backslashes % 2 == 0:
            out.append('\\')
        out.append(char)
        if char == '\\':
            backslashes += 1
        else:
            backslashes = 0
    return "{" + "".join(out) + "}"


class Sema:
    """Resolves an HRW4U AST into a backend-neutral tree.

    Sandbox checks run during resolution, here and in SymbolResolver.lookup_*, rather than as one
    pass over the finished tree: the CST emitter checks as it goes and drops what it denies, and
    parity holds sema to the same diagnostics in the same order. Once the CLI routes through sema
    and the CST emitter is gone, they can move to a single pass after resolution.
    """

    def __init__(
            self,
            *,
            debug: bool = SystemDefaults.DEFAULT_DEBUG,
            error_collector: ErrorCollector | None = None,
            preserve_comments: bool = True,
            proc_search_paths: list[Path] | None = None,
            sandbox: SandboxConfig | None = None,
            externs: dict[str, ExternDecl] | None = None,
            ir_version: tuple[int, int] | None = None) -> None:
        """`ir_version` is the IR version the output may use, or None when the output is a .conf."""
        self.error_collector = error_collector
        self.preserve_comments = preserve_comments
        self.source_map = SourceMap()
        self._sandbox = sandbox or SandboxConfig.empty()
        self._dbg = Dbg(debug)
        self.symbol_resolver = SymbolResolver(debug, sandbox=self._sandbox, dbg=self._dbg)
        self._proc_search_paths: list[Path] = list(proc_search_paths or [])
        self._section: SectionType | None = None
        self.procs = ProcRegistry(source_map=self.source_map)
        self._proc_stack: list[str] = []
        self._externs = externs or {}
        self._ir_version = ir_version
        self.features: set[Feature] = set()

    def _report(self, span: ast.Span, exc: Exception, *, note: str | None = None) -> None:
        error = hrw4u_error_at(span, exc, self.source_map.line_at(span))
        if note:
            error.add_note(note)
        if self.error_collector is None:
            raise error
        self.error_collector.add_error(error)
        if isinstance(exc, SandboxDenialError) and exc.sandbox_message:
            self.error_collector.set_sandbox_message(exc.sandbox_message)

    @contextmanager
    def trap(self, span: ast.Span, *, note: str | None = None):
        try:
            yield
        except Exception as exc:
            self._report(span, exc, note=note)

    def _warn(self, span: ast.Span, message: str) -> None:
        if self.error_collector is not None:
            self.error_collector.add_warning(Warning.from_span(span, message, self.source_map.line_at(span)))
            if self._sandbox.message:
                self.error_collector.set_sandbox_message(self._sandbox.message)

    def _drain_resolver_warnings(self, span: ast.Span) -> None:
        for warning in self.symbol_resolver.drain_warnings():
            self._warn(span, warning)

    def _unbound_param(self, name: str, span: ast.Span) -> Hrw4uSyntaxError:
        return self.source_map.error_at(span, f"'${name}' used outside procedure context")

    def _sandbox_check(self, span: ast.Span, check_fn: Callable[[], str | None]) -> bool:
        try:
            if warning := check_fn():
                self._warn(span, warning)
            return True
        except SandboxDenialError as exc:
            self._report(span, exc)
            return False

    def analyze(self, tree: ast.HRW4UAST) -> ir.Program:
        items: list[ir.ResolvedSection | ir.VarsBlock | ir.InstanceVarsBlock | ir.CommentStmt] = []
        seen_sections = False

        for node in tree.body:
            match node:
                case ast.Comment():
                    if self.preserve_comments:
                        items.append(ir.CommentStmt(text=node.text, span=node.span))
                case ast.VarSection():
                    seen_sections = True
                    items.append(self._declare_vars(node))
                case ast.UseDirective():
                    if seen_sections:
                        self._report(node.span, ValueError("'use' directives must appear before any section blocks"))
                        continue
                    with self.trap(node.span):
                        self.procs.load(node.spec, node.span, self._proc_search_paths)
                case ast.ProcedureDecl():
                    if seen_sections:
                        self._report(node.span, ValueError("'procedure' declarations must appear before any section blocks"))
                        continue
                    with self.trap(node.span):
                        self.procs.register(node)
                case ast.ExternDecl():
                    self._report(node.span, ValueError(SCRIPT_DECL_ERROR))
                case ast.Section():
                    seen_sections = True
                    if section := self._section_of(node):
                        items.append(section)

        return ir.Program(items=tuple(items))

    def _section_of(self, node: ast.Section) -> ir.ResolvedSection | None:
        with self.trap(node.span):
            if warning := self._sandbox.check_section(node.type):
                self._warn(node.span, warning)
            try:
                self._section = SectionType(node.type)
            except ValueError:
                valid = ', '.join(s.value for s in SectionType)
                raise ValueError(f"Invalid section name: '{node.type}'. Valid sections: {valid}") from None

            hook = self._section.hook_name
            self._dbg(f"`{node.type}' -> `{hook}'")
            return ir.ResolvedSection(section=self._section, body=self._body(node.body), span=node.span)
        return None

    def _body(self, nodes: tuple[ast.BodyNode, ...]) -> tuple[ir.Stmt, ...]:
        out: list[ir.Stmt] = []
        for node in nodes:
            # Per statement, not per section: a denial or a resolution failure costs that
            # statement and not everything around it.
            with self.trap(node.span):
                self._body_item(node, out)
        return tuple(out)

    def _body_item(self, node: ast.BodyNode, out: list[ir.Stmt]) -> None:
        match node:
            case ast.Comment():
                if self.preserve_comments:
                    out.append(ir.CommentStmt(text=node.text, span=node.span))
            case ast.Break():
                if warning := self._sandbox.check_language("break"):
                    self._warn(node.span, warning)
                out.append(ir.BreakStmt(span=node.span))
            case ast.Assignment():
                if stmt := self._assignment(node):
                    out.append(stmt)
            case ast.FunctionCall() if self.procs.get(node.name) is not None:
                with self._inlining(node) as inlined:
                    if inlined is None:
                        return
                    # The first source item is resolved alone so that Inlined can say whether body[0] is it.
                    head, rest = self._body(inlined[:1]), self._body(inlined[1:])
                    opens_with_statement = bool(head) and not isinstance(head[0], (ir.CommentStmt, ir.Inlined))
                out.append(ir.Inlined(body=head + rest, opens_with_statement=opens_with_statement, span=node.span))
            case ast.FunctionCall():
                if stmt := self._statement_call(node):
                    out.append(stmt)
            case ast.IfBlock():
                out.append(self._if_block(node))

    def _if_block(self, node: ast.IfBlock) -> ir.If:
        # Source order, so that without a collector the error raised is the first one in the file.
        cond = self._condition(node.condition)
        body = self._body(node.body)

        elifs = []
        for arm in node.elif_branches:
            if self._sandbox_check(arm.span, lambda: self._sandbox.check_language("elif")):
                elifs.append(ir.ElifArm(cond=self._condition(arm.condition), body=self._body(arm.body), span=arm.span))

        else_body: tuple[ir.Stmt, ...] = ()
        else_span = node.else_span or node.span
        has_else = node.has_else and self._sandbox_check(else_span, lambda: self._sandbox.check_language("else"))
        if has_else:
            else_body = self._body(node.else_body)

        return ir.If(cond=cond, body=body, elifs=tuple(elifs), else_body=else_body, span=node.span, has_else=has_else)

    def _condition(self, node: ast.ConditionExpr) -> ir.Cond:
        match node:
            case ast.LogicalOp():
                if node.operator == "||":
                    modifier, combine = "OR", ir.Or
                else:
                    modifier, combine = "AND", ir.And
                if not self._sandbox_check(node.span, lambda: self._sandbox.check_modifier(modifier)):
                    return ir.Unresolved(span=node.span)
                left, right = self._condition(node.left), self._condition(node.right)
                return combine(left=left, right=right, span=node.span)
            case ast.NotOp():
                if not self._sandbox_check(node.span, lambda: self._sandbox.check_modifier("NOT")):
                    return ir.Unresolved(span=node.span)
                return ir.Not(inner=self._condition(node.operand), span=node.span)
            case ast.Group():
                return ir.Group(inner=self._condition(node.inner), span=node.span)
            case ast.BoolLiteral():
                return ir.BoolCond(value=node.value, span=node.span)
            case ast.FunctionCall():
                return self._func_cond(node)
            case ast.IdentCondition():
                return self._truth(node)
            case ast.Comparison():
                return self._test(node)
        raise SymbolResolutionError("condition", f"Unsupported condition {node!r}")

    def _func_cond(self, node: ast.FunctionCall) -> ir.Cond:
        with self.trap(node.span):
            refuse_call_args(self._externs, node.name, _calls(node.args), in_condition=True)
            for arg in node.args:
                if isinstance(arg, ast.IdentValue):
                    self._refuse_instance_var_in_condition(arg.raw)
            # Source text, not resolved values: a `{...}` in a condition function's string argument
            # is not interpolated.
            args = [self._source_text(a, node.span) for a in node.args]
            # Validate before stripping quotes: quoted_or_simple() needs to see the quotes on values
            # such as file paths.
            key, entry = self.symbol_resolver.lookup_function(node.name, args)
            self._drain_resolver_warnings(node.span)
            return ir.FuncCond(key=key, entry=entry, args=tuple(ir.RawArg(text=_strip_quotes(a)) for a in args), span=node.span)
        return ir.Unresolved(span=node.span)

    def _truth(self, node: ast.IdentCondition) -> ir.Cond:
        with self.trap(node.span):
            ref, existence = self._reference(node.name, node.span)
            return ir.Truth(ref=ref, existence=existence, span=node.span)
        return ir.Unresolved(span=node.span)

    def _test(self, node: ast.Comparison) -> ir.Cond:
        with self.trap(node.span):
            if isinstance(node.left, ast.FunctionCall):
                func = self._func_cond(node.left)
                if not isinstance(func, ir.FuncCond):
                    return ir.Unresolved(span=node.span)  # _func_cond already reported
                ref = ir.BuiltinRef.from_function(func.key, func.entry, [a.text for a in func.args])
            else:
                ref, _ = self._reference(node.left.raw, node.span)

            op = ir.CmpOp(node.operator)

            if op in ir.NEGATED_OPS and not self._sandbox_check(node.span, lambda: self._sandbox.check_modifier("NOT")):
                return ir.Unresolved(span=node.span)

            if op in (ir.CmpOp.IN, ir.CmpOp.NOT_IN):
                rhs = self._operand(node.right, node.span)
                if not self._sandbox_check(node.span, lambda: self._sandbox.check_language("in")):
                    return ir.Unresolved(span=node.span)
            elif op in (ir.CmpOp.MATCH, ir.CmpOp.NOT_MATCH):
                # Trapped here rather than by the enclosing trap: a bad pattern must not cost the
                # modifier diagnostics below.
                with self.trap(node.right.span or node.span):
                    Validator.regex_pattern()(node.right.raw)
                rhs = ir.RegexLit(text=node.right.raw)
            else:
                rhs = self._operand(node.right, node.span)

            # A denied, unknown or conflicting modifier drops itself and every modifier after it,
            # but the comparison survives. Validated here, not left to the emitter, so that it is
            # a collected error rather than a raise out of the compile.
            mods: list[str] = []
            mod_span = node.modifier_span or node.span
            state = CondState()
            for mod in node.modifiers:
                if not self._sandbox_check(mod_span, lambda m=mod: self._sandbox.check_modifier(m.upper())):
                    break
                try:
                    state.add_modifier(mod)
                except SymbolResolutionError as exc:
                    self._report(mod_span, exc)
                    break
                mods.append(mod.upper())

            return ir.Test(ref=ref, op=op, rhs=rhs, modifiers=tuple(mods), span=node.span)
        return ir.Unresolved(span=node.span)

    def _reference(self, name: str, span: ast.Span) -> tuple[ir.Ref, bool]:
        if not name:
            raise SymbolResolutionError("identifier", "Missing or empty identifier text")
        self._refuse_instance_var_in_condition(name)

        try:
            found = self.symbol_resolver.lookup_condition(name, self._section)
        except SandboxDenialError:
            raise
        except SymbolResolutionError:
            # Only an unqualified name can be a variable; a dotted or qualified one keeps the resolver's error.
            if '.' not in name and ':' not in name:
                error = SymbolResolutionError(
                    "identifier", f"Undefined variable: '{name}'. Variables must be declared in a VARS section.")
                if suggestions := self.symbol_resolver.get_variable_suggestions(name, self._section):
                    error.add_symbol_suggestion(suggestions)
                raise error from None
            raise

        self._drain_resolver_warnings(span)

        if found.symbol is not None:
            return ir.VarRef(symbol=found.symbol), False
        return ir.BuiltinRef(key=found.key, entry=found.entry, arg=found.arg), found.existence

    def _refuse_instance_var_in_condition(self, name: str) -> None:
        if self.symbol_resolver.instance_var(name) is not None:
            raise ValueError(f"'{name}' is an instance variable, which cannot be read in a condition yet")

    def _assignment(self, node: ast.Assignment) -> ir.Stmt | None:
        with self.trap(node.span):
            if self.symbol_resolver.instance_var(node.name) is not None:
                raise ValueError(f"'{node.name}' is an instance variable; it is set once, at load")
            if isinstance(node.value, ast.FunctionCall):
                value = self._extern_call(node.value, node.span)
            else:
                value = self._operand(node.value, node.span)
            value_text = ir.value_text(value)
            if isinstance(value, ir.InstanceRef) or (isinstance(value, ir.ExternCall) and value.decl.result == "string"):
                # A validator checks a value as written, and a string only lowering has is checked as a quoted one.
                value_text = f'"{value_text}"'
            add = node.operator == "+="
            found = self.symbol_resolver.lookup_operator(node.name, value_text, self._section, add=add)
            self._drain_resolver_warnings(node.span)

            if found.symbol is not None:
                if isinstance(node.value, ast.IdentValue) and (rhs_symbol := self.symbol_resolver.symbol_for(node.value.raw)):
                    value = ir.VarRef(symbol=rhs_symbol)
                return ir.SetVar(symbol=found.symbol, value=value, span=node.span)

            if isinstance(value, ir.ExternCall) and value.decl.result != "string":
                raise ValueError(f"'{value.decl.name}' returns {value.decl.result}; {node.name} takes a string")

            if add:
                variant = ir.OpVariant.ADD
            elif value_text == '""':
                variant = ir.OpVariant.REMOVE
            else:
                variant = ir.OpVariant.SET

            return ir.SetOp(
                key=found.key, entry=found.entry, qualifier=found.qualifier, value=value, variant=variant, span=node.span)
        return None

    def _statement_call(self, node: ast.FunctionCall) -> ir.Stmt | None:
        with self.trap(node.span):
            if node.name in self._externs:
                raise value_call_statement(node.name)
            if '::' in node.name:
                raise self.source_map.error_at(node.span, f"unknown procedure '{node.name}': not loaded via 'use'")
            refuse_call_args(self._externs, node.name, _calls(node.args), in_condition=False)
            # _operand: a `$param` still here is unbound, and validators such as a header name's would take its text.
            args = [self._operand(a, node.span) for a in node.args]
            arg_texts = [ir.value_text(a) for a in args]
            key, entry = self.symbol_resolver.lookup_statement_function(node.name, arg_texts, self._section)
            self._drain_resolver_warnings(node.span)
            return ir.CallOp(key=key, entry=entry, args=tuple(map(self._normalized_arg, args, arg_texts)), span=node.span)
        return None

    def _extern_call(self, call: ast.FunctionCall, span: ast.Span, *, at_load: bool = False) -> ir.ExternCall:
        """A call for its value, in a hook or, `at_load`, in an INSTANCE_VARS initializer."""
        decl = lookup(self._externs, call.name)
        if warning := self._sandbox.check_function(call.name):
            self._warn(span, warning)
        args = []
        for arg in call.args:
            if isinstance(arg, ast.FunctionCall):
                args.append(self._extern_call(arg, span, at_load=at_load))
            elif at_load:
                args.append(self._load_arg(arg, span))
            else:
                args.append(self._operand(arg, span))
        check_call(decl, [self._arg_type(node, arg) for node, arg in zip(call.args, args)], at_load=at_load)
        refuse_bare_refs(decl, [self._bare_ref(node, arg) for node, arg in zip(call.args, args)])
        self._use(CALL_VALUE)
        return ir.ExternCall(decl=decl, args=tuple(args), span=call.span)

    @staticmethod
    def _arg_type(node: ast.ValueExpr | ast.FunctionCall, arg: ir.RValue) -> str | None:
        if isinstance(arg, ir.InstanceRef):
            return "string"
        match node:
            case ast.FunctionCall():
                return arg.decl.result
            case ast.LiteralStringValue():
                return "string"
            case ast.NumberValue():
                return "int64"
            case ast.BoolValue():
                return "bool"
        return None

    @staticmethod
    def _bare_ref(node: ast.ValueExpr | ast.FunctionCall, arg: ir.RValue) -> str | None:
        if isinstance(node, ast.IdentValue) and not isinstance(arg, ir.InstanceRef):
            return node.raw
        return None

    def _use(self, feature: Feature) -> None:
        check_target(feature, self._ir_version)
        self.features.add(feature)

    @staticmethod
    def _normalized_arg(arg: ir.RValue, text: str) -> ir.RValue:
        """Validators normalize argument text in place; an argument they left alone keeps its resolved form."""
        if text == ir.value_text(arg):
            return arg
        return ir.RawArg(text=text)

    @contextmanager
    def _inlining(self, call: ast.FunctionCall):
        sig = self.procs.get(call.name)
        if call.name in self._proc_stack:
            self._report(call.span, ValueError(f"circular procedure call: {' -> '.join([*self._proc_stack, call.name])}"))
            yield None
            return

        bindings = self._bind(sig, call)
        if bindings is None:
            yield None
            return

        body = tuple(self._substitute(node, bindings, _quoted_params(sig, call)) for node in sig.body)
        self._proc_stack.append(call.name)
        try:
            yield body
        finally:
            self._proc_stack.pop()

    def _bind(self, sig: ProcEntry, call: ast.FunctionCall) -> dict[str, str] | None:
        with self.trap(call.span):
            refuse_call_args(self._externs, call.name, _calls(call.args), in_condition=False)
            args = [self._binding_text(a, call.span) for a in call.args]
            required = sum(1 for p in sig.params if p.default is None)
            if not (required <= len(args) <= len(sig.params)):
                expected = str(len(sig.params))
                if required < len(sig.params):
                    expected = f"{required}-{len(sig.params)}"
                raise ValueError(f"procedure '{sig.name}': expected {expected} arg(s), got {len(args)}")

            bindings = dict(zip((p.name for p in sig.params), args))
            for param in sig.params[len(args):]:
                bindings[param.name] = self._default_text(param.default, call.span)
            return bindings
        return None

    def _default_text(self, value: ast.ValueExpr, span: ast.Span) -> str:
        """A string default loses its quotes but, unlike a call argument, is not interpolated."""
        if isinstance(value, ast.LiteralStringValue):
            return value.raw
        return self._binding_text(value, span)

    def _binding_text(self, value, span: ast.Span) -> str:
        """A binding is plain text: a string literal contributes its inner text."""
        if isinstance(value, ast.LiteralStringValue):
            return ir.value_text(self._template(value, span))[1:-1]
        if isinstance(value, ast.ParamRef):
            # _substitute replaced every bound `$param`, so one left here is unbound.
            raise self._unbound_param(value.raw, value.span or span)
        return ir.value_text(self._value(value, span))

    def _substitute(self, node: ast.BodyNode, bindings: dict[str, str], quoted: frozenset[str]) -> ast.BodyNode:

        def sub_text(text: str) -> str:
            return _PARAM_REF.sub(lambda m: bindings.get(m.group(1), m.group(0)), text)

        def sub_string(value):
            if isinstance(value, ast.LiteralStringValue):
                return ast.LiteralStringValue(raw=sub_text(value.raw), written=value.written or value.raw)
            return value

        def sub_call(call: ast.FunctionCall) -> ast.FunctionCall:
            return replace(call, args=tuple(map(sub_arg, call.args)))

        def sub_value(value):
            if isinstance(value, ast.FunctionCall):
                return sub_call(value)
            if isinstance(value, ast.ParamRef) and value.raw in bindings:
                # A bare `$param` takes its binding verbatim, so a string argument reaches the operator unquoted.
                return ast.IdentValue(raw=bindings[value.raw])
            # An unbound `$param` stays a ParamRef so the statement using it reports the error, in source order.
            return sub_string(value)

        def sub_arg(value):
            # A bare `$param` in a function argument stands for the argument as the caller wrote it: a string, as
            # `"$param"` makes it, when the caller quoted it, and as it is otherwise.
            if isinstance(value, ast.FunctionCall):
                return sub_call(value)
            if isinstance(value, ast.ParamRef) and value.raw in bindings:
                if value.raw in quoted:
                    return ast.LiteralStringValue(raw=bindings[value.raw], written=f"${value.raw}")
                return ast.IdentValue(raw=bindings[value.raw])
            return sub_string(value)

        # replace(), not a rebuild: a rebuilt node silently drops any field it does not name,
        # such as `else_span` or `modifier_span`, and the inlined copy then diagnoses differently.
        match node:
            case ast.Assignment():
                return replace(node, value=sub_value(node.value))
            case ast.FunctionCall():
                return sub_call(node)
            case ast.IfBlock():
                return replace(
                    node,
                    condition=self._substitute_cond(node.condition, sub_value, sub_arg),
                    body=tuple(self._substitute(b, bindings, quoted) for b in node.body),
                    elif_branches=tuple(
                        replace(
                            arm,
                            condition=self._substitute_cond(arm.condition, sub_value, sub_arg),
                            body=tuple(self._substitute(b, bindings, quoted) for b in arm.body)) for arm in node.elif_branches),
                    else_body=tuple(self._substitute(b, bindings, quoted) for b in node.else_body))
        return node

    def _substitute_cond(self, node: ast.ConditionExpr, sub_value: Callable, sub_arg: Callable) -> ast.ConditionExpr:
        match node:
            case ast.Comparison():
                left = node.left
                if isinstance(left, ast.FunctionCall):
                    left = replace(left, args=tuple(map(sub_arg, left.args)))
                return replace(node, left=left, right=sub_value(node.right))
            case ast.FunctionCall():
                return replace(node, args=tuple(map(sub_arg, node.args)))
            case ast.LogicalOp():
                return replace(
                    node,
                    left=self._substitute_cond(node.left, sub_value, sub_arg),
                    right=self._substitute_cond(node.right, sub_value, sub_arg))
            case ast.NotOp():
                return replace(node, operand=self._substitute_cond(node.operand, sub_value, sub_arg))
            case ast.Group():
                return replace(node, inner=self._substitute_cond(node.inner, sub_value, sub_arg))
        return node

    def _value(self, node, span: ast.Span) -> ir.RValue:
        match node:
            case ast.IdentValue() if (index := self.symbol_resolver.instance_var(node.raw)) is not None:
                return ir.InstanceRef(index=index, name=node.raw)
            case ast.NumberValue() | ast.IdentValue() | ast.BoolValue() | ast.IPValue():
                return ir.RawArg(text=node.raw)
            case ast.LiteralStringValue():
                return self._template(node, span)
            case ast.ParamRef():
                # Unsubstituted: the entry's validator produces the diagnostic.
                return ir.RawArg(text=f"${node.raw}")
            case ast.RegexValue():
                return ir.RegexLit(text=node.raw)
            case ast.SetValue():
                return ir.SetLit(text=node.raw)
            case ast.IpRangeValue():
                return ir.IpRangeLit(text=node.raw)
        raise SymbolResolutionError("value", f"Unsupported value {node!r}")

    def _operand(self, node, span: ast.Span) -> ir.RValue:
        """An assignment or comparison right-hand side, where an unbound `$name` is an error."""
        if isinstance(node, ast.ParamRef):
            raise self._unbound_param(node.raw, node.span or span)
        return self._value(node, span)

    def _source_text(self, node, span: ast.Span) -> str:
        if isinstance(node, ast.LiteralStringValue):
            return f'"{node.raw}"'
        return ir.value_text(self._operand(node, span))

    def _template(self, literal: ast.LiteralStringValue, span: ast.Span) -> ir.StrTemplate:
        inner = literal.raw
        parts: list[str | ir.Ref | ir.InstanceRef | ir.ExternCall | ir.ModifiedRef] = []
        for part in scan(inner):
            if isinstance(part, str):
                parts.append(part)
            else:
                parts.append(self._template_part(part, span, literal.written or inner))
        return ir.StrTemplate(parts=tuple(parts), source=inner)

    def _template_part(
            self, part: Escaped | Hole, span: ast.Span,
            inner: str) -> str | ir.Ref | ir.InstanceRef | ir.ExternCall | ir.ModifiedRef:
        try:
            return self._template_part_inner(part, span)
        except SandboxDenialError as exc:
            # Unwrapped, so the sandbox message is still set.
            exc.add_note(self._interpolation_note(inner))
            self._report(span, exc)
            failure = exc
        except Exception as exc:
            # Both notes: neither the literal the hole came from nor the section it was read in
            # is recoverable from the span.
            wrapped = RuntimeError(f"symbol error in {{}}: {exc}")
            wrapped.add_note(self._interpolation_note(inner))
            if self._section:
                wrapped.add_note(f"Current section: {self._section.value}")
            self._report(span, wrapped)
            failure = exc
        # A bad hole must not cost the assignment around it.
        return f"{{ERROR: {failure}}}"

    @staticmethod
    def _interpolation_note(inner: str) -> str:
        literal = f'"{inner}"'
        return f"String interpolation context: {literal[:50]}..."

    def _template_part_inner(self, part: Escaped | Hole, span: ast.Span):
        if isinstance(part, Escaped):
            return _unescape_double_braces(part.text)
        if not part.holds_call:
            name, mods = split_interpolation_mods(part.text)
            self._check_value_mods(mods, span)
            if (index := self.symbol_resolver.instance_var(name)) is not None:
                return self._with_mods(ir.InstanceRef(index=index, name=name), mods)
            found = self.symbol_resolver.lookup_condition(name, self._section)
            self._drain_resolver_warnings(span)
            if found.symbol is not None:
                return self._with_mods(ir.VarRef(symbol=found.symbol), mods)
            return self._with_mods(ir.BuiltinRef(key=found.key, entry=found.entry, arg=found.arg), mods)
        hole = parse_call(part)
        name = hole.call.funcName.text
        self._check_value_mods(hole.mods, span)
        if "::" in name:
            return self._with_mods(self._extern_call(call_ast(hole.call, span.file), span), hole.mods)
        args = list(hole.args)
        key, entry = self.symbol_resolver.lookup_function(name, args)
        self._drain_resolver_warnings(span)
        return self._with_mods(ir.BuiltinRef.from_function(key, entry, args), hole.mods)

    def _check_value_mods(self, mods: list[str], span: ast.Span) -> None:
        for mod in mods:
            if mod not in VALUE_MODIFIERS:
                raise SymbolResolutionError(mod, f"Not a value modifier, expected one of {', '.join(sorted(VALUE_MODIFIERS))}")
            if warning := self._sandbox.check_modifier(mod):
                self._warn(span, warning)

    @staticmethod
    def _with_mods(
            ref: ir.Ref | ir.InstanceRef | ir.ExternCall,
            mods: list[str]) -> ir.Ref | ir.InstanceRef | ir.ExternCall | ir.ModifiedRef:
        if mods:
            return ir.ModifiedRef(ref=ref, mods=tuple(mods))
        return ref

    def _declare_vars(self, node: ast.VarSection) -> ir.VarsBlock | ir.InstanceVarsBlock:
        noun, label, scope = _VAR_SECTIONS[node.scope]
        if self._section is not None:
            self._report(node.span, ValueError(f"{noun} section must be first in a section"))
            return ir.VarsBlock(comments=(), span=node.span)

        if not self._sandbox_check(node.span, lambda: self._sandbox.check_section(label)):
            return ir.VarsBlock(comments=(), span=node.span)
        if not self._sandbox_check(node.span, lambda: self._sandbox.check_language("variables")):
            return ir.VarsBlock(comments=(), span=node.span)
        if node.scope == "instance":
            return self._declare_instance_vars(node)

        comments: list[ir.CommentStmt] = []
        for decl in node.items:
            if isinstance(decl, ast.Comment):
                if self.preserve_comments:
                    comments.append(ir.CommentStmt(text=decl.text, span=decl.span))
                continue
            with self.trap(decl.span, note=self._decl_note(decl)):
                if '.' in decl.name or ':' in decl.name:
                    raise SymbolResolutionError("variable", f"Variable name '{decl.name}' cannot contain '.' or ':' characters")
                self.symbol_resolver.declare_variable(decl.name, decl.type_name, decl.slot, scope)
        return ir.VarsBlock(comments=tuple(comments), span=node.span)

    def _declare_instance_vars(self, node: ast.VarSection) -> ir.VarsBlock | ir.InstanceVarsBlock:
        with self.trap(node.span):
            self._use(INSTANCE_VARS)
            declared = []
            for decl in node.items:
                if isinstance(decl, ast.InstanceVarDecl):
                    with self.trap(decl.span):
                        declared.append(self._instance_var(decl))
            return ir.InstanceVarsBlock(vars=tuple(declared), span=node.span)
        return ir.VarsBlock(comments=(), span=node.span)

    def _instance_var(self, decl: ast.InstanceVarDecl) -> ir.InstanceVar:
        if '.' in decl.name or ':' in decl.name:
            raise SymbolResolutionError("variable", f"Variable name '{decl.name}' cannot contain '.' or ':' characters")
        # Declared before its initializer is resolved, so a failed one leaves no hook reading an unknown name.
        index = self.symbol_resolver.declare_instance_variable(decl.name, decl.type_name)
        if isinstance(decl.value, ast.FunctionCall):
            value = self._extern_call(decl.value, decl.span, at_load=True)
            if value.decl.result != "string":
                raise ValueError(f"'{value.decl.name}' returns {value.decl.result}; {decl.name} takes a string")
        else:
            value = self._load_string(decl.value, decl.span)
        return ir.InstanceVar(index=index, value=value, span=decl.span)

    def _load_arg(self, arg: ast.ValueExpr, span: ast.Span) -> ir.RValue:
        """An argument of a call in an INSTANCE_VARS initializer, which runs at load, with no transaction."""
        match arg:
            case ast.LiteralStringValue():
                return self._load_string(arg, span)
            case ast.IdentValue():
                raise self._load_read(arg.raw)
        return self._operand(arg, span)

    def _load_string(self, literal: ast.LiteralStringValue, span: ast.Span) -> ir.StrTemplate:
        for part in scan(literal.raw):
            if not isinstance(part, Hole):
                continue
            if part.holds_call:
                raise ValueError(_LOAD_READS_TXN)
            raise self._load_read(split_interpolation_mods(part.text)[0])
        return self._template(literal, span)

    def _load_read(self, name: str) -> ValueError:
        if self.symbol_resolver.instance_var(name) is not None:
            return ValueError(f"'{name}' is an instance variable, which an INSTANCE_VARS initializer cannot read yet")
        return ValueError(_LOAD_READS_TXN)

    @staticmethod
    def _decl_note(decl: ast.VarDecl) -> str:
        note = f"Variable declaration: {decl.name}:{decl.type_name}"
        if decl.slot is not None:
            note += f" @{decl.slot}"
        return note
