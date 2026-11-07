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
"""Lowers the resolved tree to the Typed IR. Refuses, at its position, whatever it cannot lower yet."""

from __future__ import annotations

import dataclasses
import re

import hrw4u.sema_nodes as resolved
from hrw4u.ast_nodes import Span
from hrw4u.errors import ErrorCollector, Hrw4uSyntaxError, SourceMap, Warning
from hrw4u.ir_nodes import (
    Builtin, Const, Extern, Fmt, Format, Instruction, IntConst, IRProgram, IRSection, IVar, Label, Op, Operand, Pattern, Pools, Reg,
    Regex, Set, SetEntry, SetKind, SetMatch, Ty, Var, VarKind)
from hrw4u.states import SectionType
from hrw4u.types import Symbol, VarScope, VarType

_CONTROLS = {"t": "\t", "r": "\r", "n": "\n"}


def decode_conf_escapes(text: str) -> str:
    # The value means at run time what header_rewrite makes of it in the .conf (parser.cc), so decode as it does.
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 < len(text):
            escaped = text[i + 1]
            out.append(_CONTROLS.get(escaped, escaped))
        i += 2
    return "".join(out)


# The hooks with a message: the client's request is read after TXN_START.
_MESSAGE_HOOKS = frozenset(
    {
        SectionType.READ_REQUEST, SectionType.PRE_REMAP, SectionType.REMAP, SectionType.SEND_REQUEST, SectionType.READ_RESPONSE,
        SectionType.SEND_RESPONSE, SectionType.TXN_CLOSE
    })

# The message header_rewrite's header operators work on in each hook, by the scope that names it. hrw4u.so's header
# builtins name their message, and run only in the hooks where it is this one, so a scope naming another is refused.
_HOOK_MESSAGES = {
    SectionType.READ_REQUEST: "inbound.req.",
    SectionType.PRE_REMAP: "inbound.req.",
    SectionType.REMAP: "inbound.req.",
    SectionType.SEND_REQUEST: "outbound.req.",
    SectionType.READ_RESPONSE: "outbound.resp.",
    SectionType.SEND_RESPONSE: "inbound.resp.",
    SectionType.TXN_CLOSE: "inbound.resp.",
}

# The response header_rewrite's set-status, set-status-reason and %{STATUS} work on in each hook, by the scope that names
# it: before remap, the one the transaction makes itself.
_HOOK_STATUSES = {
    SectionType.READ_REQUEST: "inbound.status",
    SectionType.PRE_REMAP: "inbound.status",
    SectionType.REMAP: "inbound.status",
    SectionType.READ_RESPONSE: "outbound.status",
    SectionType.SEND_RESPONSE: "inbound.status",
}

# The response each status scope names, as the status builtins spell it.
_STATUS_MESSAGES = {"inbound.status": "CLIENT_RESP", "outbound.status": "SERVER_RESP"}

# The message each header scope names, as the header builtins spell it.
_HEADER_MESSAGES = {
    "inbound.req.": "CLIENT",
    "outbound.req.": "SERVER",
    "outbound.resp.": "SERVER_RESP",
    "inbound.resp.": "CLIENT_RESP"
}

# The hooks hrw4u.so runs: TXN_START too, which comes before the client's request is read and so has no header.
_IR_HOOKS = _MESSAGE_HOOKS | {SectionType.TXN_START}

# The request whose Cookie header header_rewrite's set-cookie and rm-cookie change in each hook, by the scope that names
# it. Elsewhere they write a Cookie header onto the response when another rule of the hook needs the response's headers,
# or do nothing: neither changes a request.
_HOOK_COOKIES = {
    SectionType.READ_REQUEST: "inbound.cookie.",
    SectionType.PRE_REMAP: "inbound.cookie.",
    SectionType.REMAP: "inbound.cookie.",
    SectionType.SEND_REQUEST: "outbound.cookie.",
}

# The request each cookie scope names, as the cookie builtins spell it.
_COOKIE_MESSAGES = {"inbound.cookie.": "CLIENT", "outbound.cookie.": "SERVER"}

# The request whose URL header_rewrite's set-destination and rm-destination change in each hook, by the scope that names
# it. Elsewhere they find no URL to change.
_HOOK_URLS = {
    SectionType.READ_REQUEST: "inbound.url.",
    SectionType.PRE_REMAP: "inbound.url.",
    SectionType.REMAP: "inbound.url.",
    SectionType.SEND_REQUEST: "outbound.url.",
}

# The response header_rewrite's set-redirect works on in each hook, by the scope that names it: at REMAP, the one the
# core makes itself.
_HOOK_REDIRECTS = {
    SectionType.REMAP: "inbound.resp.",
    SectionType.READ_RESPONSE: "outbound.resp.",
    SectionType.SEND_RESPONSE: "inbound.resp.",
}

# The request each URL scope names, as the URL builtins spell it.
_URL_MESSAGES = {"inbound.url.": "CLIENT", "outbound.url.": "SERVER"}

# The builtins hrw4u.so runs in some hooks only; the reader refuses them elsewhere. Those that read the client's request,
# its URL or its method run in every hook with a message.
_BUILTIN_HOOKS = {
    **{
        f"BI_{verb}{message}_HEADER": frozenset(hook for hook, scope in _HOOK_MESSAGES.items() if scope == key)
        for key, message in _HEADER_MESSAGES.items() for verb in ("SET_", "ADD_", "RM_")
    },
    "BI_SERVER_RESP_HEADER": frozenset({SectionType.READ_RESPONSE}),
    "BI_CLIENT_RESP_HEADER": frozenset({SectionType.SEND_RESPONSE, SectionType.TXN_CLOSE}),
    "BI_CLIENT_HEADER": _MESSAGE_HOOKS,
    "BI_CLIENT_URL": _MESSAGE_HOOKS,
    "BI_CLIENT_URL_PARAM": _MESSAGE_HOOKS,
    "BI_COOKIE": _MESSAGE_HOOKS,
    "BI_METHOD": _MESSAGE_HOOKS,
    "BI_FROM_URL": frozenset({SectionType.REMAP}),
    "BI_FROM_URL_PARAM": frozenset({SectionType.REMAP}),
    "BI_TO_URL": frozenset({SectionType.REMAP}),
    "BI_TO_URL_PARAM": frozenset({SectionType.REMAP}),
    "BI_SERVER_RESP_STATUS": frozenset({SectionType.READ_RESPONSE}),
    "BI_CLIENT_RESP_STATUS": frozenset({SectionType.SEND_RESPONSE}),
    "BI_SET_SERVER_RESP_STATUS": frozenset({SectionType.READ_RESPONSE}),
    "BI_SET_CLIENT_RESP_STATUS": frozenset(hook for hook, scope in _HOOK_STATUSES.items() if scope == "inbound.status"),
    "BI_SET_SERVER_RESP_STATUS_REASON": frozenset({SectionType.READ_RESPONSE}),
    "BI_SET_CLIENT_RESP_STATUS_REASON": frozenset({SectionType.SEND_RESPONSE}),
    **{
        builtin.format(message): frozenset(hook for hook, scope in _HOOK_URLS.items() if scope == key)
        for key, message in _URL_MESSAGES.items()
        for builtin in ("BI_SET_{}_URL", "BI_SET_{}_URL_PORT", "BI_RM_{}_URL", "BI_KEEP_{}_QUERY")
    },
    **{
        f"BI_{verb}{message}_COOKIE": frozenset(hook for hook, scope in _HOOK_COOKIES.items() if scope == key)
        for key, message in _COOKIE_MESSAGES.items() for verb in ("SET_", "RM_")
    },
    "BI_SET_CONN_DSCP": frozenset({SectionType.READ_REQUEST, SectionType.REMAP, SectionType.SEND_RESPONSE}),
    "BI_SET_CONN_MARK": frozenset({SectionType.READ_REQUEST, SectionType.REMAP, SectionType.SEND_RESPONSE}),
    "BI_SET_BODY": frozenset({SectionType.REMAP, SectionType.SEND_RESPONSE}),
    "BI_SET_BODY_FROM": frozenset({SectionType.READ_RESPONSE}),
    "BI_SET_BODY_FROM_FILE": frozenset({SectionType.REMAP, SectionType.SEND_RESPONSE}),
    **{
        f"BI_SET_{_HEADER_MESSAGES[key]}_REDIRECT": frozenset(hook for hook, scope in _HOOK_REDIRECTS.items() if scope == key)
        for key in set(_HOOK_REDIRECTS.values())
    },
    "BI_RUN_PLUGIN": frozenset({SectionType.REMAP}),
}

_I64_MAX = 2**63 - 1

_STATUS_WRITES = frozenset({"inbound.status", "outbound.status", "http.status"})
_REASON_WRITES = frozenset(f"{key}.reason" for key in _STATUS_WRITES)

_INT_COMPARES = {
    resolved.CmpOp.EQ: Op.CMP_I64_EQ,
    resolved.CmpOp.NE: Op.CMP_I64_NE,
    resolved.CmpOp.GT: Op.CMP_I64_GT,
    resolved.CmpOp.LT: Op.CMP_I64_LT,
}

# The outbound names header_rewrite works on the client's side for whatever the hook, and what it does there. They are
# refused rather than lowered to what their name does not say; the inbound name says it.
_CLIENT_SIDE_OUTBOUND = {
    "outbound.method": "reads the client's request",
    "outbound.cookie.": "reads the client's request",
    "outbound.conn.dscp": "marks the client connection's packets",
    "outbound.conn.mark": "marks the client connection's packets",
}

# The reads that take a name: a cookie, a query parameter of a URL.
_NAMED_READS = {
    "inbound.cookie.": "BI_COOKIE",
    "inbound.url.query.": "BI_CLIENT_URL_PARAM",
    "outbound.url.query.": "BI_SERVER_URL_PARAM",
    "from.url.query.": "BI_FROM_URL_PARAM",
    "to.url.query.": "BI_TO_URL_PARAM",
}

# The reads that take no argument. inbound.conn.REMOTE-ADDR is the address inbound.ip reads, and inbound.conn.LOCAL-ADDR
# the one inbound.server reads, as in header_rewrite. id.REQUEST is a number, as header_rewrite compares %{ID:REQUEST}.
_PLAIN_READS = {
    "tcp.info": ("BI_TCP_INFO", Ty.SVIEW),
    "cache()": ("BI_CACHE", Ty.SVIEW),
    "inbound.method": ("BI_METHOD", Ty.SVIEW),
    "inbound.ip": ("BI_IP_CLIENT", Ty.ADDR),
    "inbound.conn.REMOTE-ADDR": ("BI_IP_CLIENT", Ty.ADDR),
    "inbound.server": ("BI_IP_INBOUND", Ty.ADDR),
    "inbound.conn.LOCAL-ADDR": ("BI_IP_INBOUND", Ty.ADDR),
    "inbound.conn.LOCAL-PORT": ("BI_LOCAL_PORT", Ty.SVIEW),
    "inbound.conn.REMOTE-PORT": ("BI_CLIENT_PORT", Ty.SVIEW),
    "inbound.conn.STACK": ("BI_CLIENT_STACK", Ty.SVIEW),
    "outbound.ip": ("BI_IP_SERVER", Ty.ADDR),
    "outbound.server": ("BI_IP_OUTBOUND", Ty.ADDR),
    "txn-count()": ("BI_TXN_COUNT", Ty.I64),
    "id.REQUEST": ("BI_REQUEST_ID", Ty.I64),
    "ssn-txn-count()": ("BI_SSN_TXN_COUNT", Ty.I64),
}

# The numbers the reader gives the fields of a URL and of an identifier.
_URL_FIELDS = {"SCHEME": 0, "HOST": 1, "PORT": 2, "PATH": 3, "QUERY": 4, "URL": 5}
_ID_FIELDS = {"PROCESS": 1, "UNIQUE": 2}
_NOW_FIELDS = {"YEAR": 0, "MONTH": 1, "DAY": 2, "HOUR": 3, "MINUTE": 4, "WEEKDAY": 5, "YEARDAY": 6}
_NOW_EPOCH = 7
_HTTP_CNTLS = {
    "LOGGING": 0,
    "INTERCEPT_RETRY": 1,
    "RESP_CACHEABLE": 2,
    "REQ_CACHEABLE": 3,
    "SERVER_NO_STORE": 4,
    "TXN_DEBUG": 5,
    "SKIP_REMAP": 6,
}

# The inbound.conn. fields that read the client's protocol stack, and the tag prefix header_rewrite asks it for.
_CLIENT_PROTOCOLS = {"TLS": "tls/", "H2": "h2", "IPV4": "ipv4", "IPV6": "ipv6", "IP-FAMILY": "ip"}

# The nexthop. fields hrw4u.so reads, as the IR numbers them (NextHopField).
_NEXT_HOP_FIELDS = {"HOST": 0, "PORT": 1, "STRATEGY": 2}

# The certificate fields hrw4u.so reads, as the IR numbers them (CertField), and the SAN. ones after them.
_CERT_FIELDS = {"PEM": 0, "SIG": 1, "SUBJECT": 2, "ISSUER": 3, "SERIAL": 4, "NOT_BEFORE": 5, "NOT_AFTER": 6, "VERSION": 7}
_SAN_FIELDS = {"DNS": 8, "IP": 9, "EMAIL": 10, "URI": 11}

# geo.<field> is header_rewrite's %{GEO}, which hrw4u spells as a read of the language's own, so it is mapped here by
# name to the Cripts bindings that answer the same. It is the one exception: a binding or an extension added later is
# to be called through an extern declaration checked against its manifest, not by adding its name to a table here.
_GEO_BINDINGS = {
    "COUNTRY": ("cripts::Geo::Country", Ty.SVIEW),
    "ASN": ("cripts::Geo::ASN", Ty.I64),
    "ASN-NAME": ("cripts::Geo::ASNName", Ty.SVIEW),
}

# set-plugin-cntl's controls and the values each takes, as the IR numbers them (PluginCntl, Timezone, IpSource).
_PLUGIN_CNTLS = {
    "TIMEZONE": (0, {
        "LOCAL": 0,
        "GMT": 1
    }),
    "INBOUND_IP_SOURCE": (1, {
        "PEER": 0,
        "PROXY": 1
    }),
}

# What set-http-cntl and set-state-flag take as on (operators.cc); anything else is off, "yes" included.
_ON_WORDS = frozenset({"1", "true", "on", "enable"})

# What skip-remap takes as on (operators.cc), case and all: "YES" and "ON" are off.
_SKIP_REMAP_ON = frozenset({"1", "true", "TRUE"})

# The hooks header_rewrite allows set-debug and set-http-cntl in that hrw4u.so runs; it refuses the rule elsewhere.
# skip-remap compiles to BI_SET_HTTP_CNTL as well, and header_rewrite runs that in every hook.
_SET_DEBUG_HOOKS = frozenset({SectionType.READ_REQUEST, SectionType.REMAP, SectionType.READ_RESPONSE})
_SET_HTTP_CNTL_HOOKS = frozenset(
    {SectionType.READ_REQUEST, SectionType.REMAP, SectionType.READ_RESPONSE, SectionType.SEND_RESPONSE})

# The reads that take a field number, an index or a bound: (builtin, result, the number from the reference's arg).
_NUMBERED_READS = {
    "inbound.url.": ("BI_CLIENT_URL", Ty.SVIEW, _URL_FIELDS.__getitem__),
    "outbound.url.": ("BI_SERVER_URL", Ty.SVIEW, _URL_FIELDS.__getitem__),
    "from.url.": ("BI_FROM_URL", Ty.SVIEW, _URL_FIELDS.__getitem__),
    "to.url.": ("BI_TO_URL", Ty.SVIEW, _URL_FIELDS.__getitem__),
    "id.": ("BI_ID", Ty.SVIEW, _ID_FIELDS.__getitem__),
    "capture.": ("BI_LAST_CAPTURE", Ty.SVIEW, int),
    "random": ("BI_RANDOM", Ty.I64, int),
    "now.": ("BI_NOW", Ty.I64, _NOW_FIELDS.__getitem__),
    **{
        f"inbound.conn.{role}-cert.{san}": (f"BI_INBOUND_{role.upper()}_CERT", Ty.SVIEW, fields.__getitem__)
        for role in ("client", "server") for san, fields in (("", _CERT_FIELDS), ("SAN.", _SAN_FIELDS), ("san.", _SAN_FIELDS))
    },
}

# header_rewrite's substring modifiers (matcher.cc), which a string set takes as its match mode.
_SET_MATCHES = {"PRE": SetMatch.PREFIX, "SUF": SetMatch.SUFFIX, "MID": SetMatch.SUBSTRING, "EXT": SetMatch.EXTENSION}

_CONN_PACKET_WRITES = {"inbound.conn.dscp": "BI_SET_CONN_DSCP", "inbound.conn.mark": "BI_SET_CONN_MARK"}

_VAR_KINDS = {VarType.BOOL: VarKind.BOOL, VarType.INT8: VarKind.U8, VarType.INT16: VarKind.U16}

_HEADER_VERBS = {resolved.OpVariant.SET: "SET", resolved.OpVariant.ADD: "ADD", resolved.OpVariant.REMOVE: "RM"}

# A manifest's types, as the IR names them.
_EXTERN_TYPES = {"string": Ty.SVIEW, "int64": Ty.I64, "bool": Ty.BOOL}


def _ref_text(ref: resolved.BuiltinRef) -> str:
    if ref.wrap:
        return f"{ref.key}({ref.arg or ''})"
    return ref.key + (ref.arg or "")


def _cond_text(cond: resolved.Cond) -> str:
    match cond:
        case resolved.Test():
            return f"{_any_ref_text(cond.ref)} {cond.op.value} {resolved.value_text(cond.rhs)}"
        case resolved.Truth():
            return _any_ref_text(cond.ref)
        case resolved.FuncCond():
            return f"{cond.key}({', '.join(a.text for a in cond.args)})"
        case resolved.BoolCond():
            return str(cond.value).lower()
    return type(cond).__name__


def _any_ref_text(ref: resolved.Ref) -> str:
    if isinstance(ref, resolved.BuiltinRef):
        return _ref_text(ref)
    return ref.as_value_text()


class _Lowerer:

    def __init__(self, source_map: SourceMap, filename: str, error_collector: ErrorCollector | None) -> None:
        self._source_map = source_map
        self._filename = filename
        self._error_collector = error_collector
        # A procedure inlined at several calls lowers its statements once per call; warn at each statement once.
        self._warned: set[Span] = set()
        self._pools = Pools()
        self._hook: SectionType | None = None
        self._instructions: list[Instruction] = []
        self._next_reg = 1
        self._call_site: Span | None = None

    def lower(self, program: resolved.Program) -> IRProgram:
        by_hook: dict[SectionType, list[resolved.ResolvedSection]] = {}
        instance_vars: list[resolved.InstanceVar] = []
        for item in program.items:
            match item:
                case resolved.CommentStmt() | resolved.VarsBlock():
                    # Sema has taken the declarations; a variable reaches the IR where it is read.
                    continue
                case resolved.InstanceVarsBlock():
                    instance_vars += item.vars
                case resolved.ResolvedSection():
                    by_hook.setdefault(item.section, []).append(item)
                case _:
                    raise self._refuse(item)
        if not by_hook:
            raise self._error(Span(self._filename, 1, 0), "a program with no section")
        instance = None
        if instance_vars:
            instance = self._instance(instance_vars)
        return IRProgram(self._pools, [self._section(nodes) for nodes in by_hook.values()], instance)

    def _instance(self, instance_vars: list[resolved.InstanceVar]) -> list[Instruction]:
        """The Instance section, which stores each instance variable once, at load, before any hook runs."""
        self._hook = None
        self._instructions = []
        self._next_reg = 1
        for var in instance_vars:
            self._pools.ivars.append(IVar(var.index))
            self._emit(Op.STORE_I, (IVar(var.index), self._string(var.value, var.span)), var.span)
        self._emit(Op.RET, (), instance_vars[-1].span)
        return self._instructions

    def _section(self, nodes: list[resolved.ResolvedSection]) -> IRSection:
        hook = nodes[0].section
        if hook not in _IR_HOOKS:
            raise self._error(nodes[0].span, f"section {hook.value}")
        self._hook = hook
        self._instructions = []
        self._next_reg = 1
        # The sections of a hook run one after another, as header_rewrite runs a hook's rules in order of the file, so a
        # break, header_rewrite's [L], stops the later ones too.
        last = nodes[0].span
        for node in nodes:
            last = self._body(node.body) or node.span
        self._emit(Op.RET, (), last)
        return IRSection(hook, self._instructions)

    def _body(self, body: tuple[resolved.Stmt, ...]) -> Span | None:
        """Lowers the statements, and returns the position of the last one lowered, which `ret` takes."""
        last = None
        for stmt in body:
            last = self._stmt(stmt) or last
        return last

    def _stmt(self, stmt: resolved.Stmt) -> Span | None:
        match stmt:
            case resolved.CommentStmt():
                return None
            case resolved.BreakStmt():
                self._emit(Op.BREAK, (), stmt.span)
            case resolved.SetOp():
                self._set_op(stmt)
            case resolved.SetVar():
                self._set_var(stmt)
            case resolved.CallOp():
                self._call_op(stmt)
            case resolved.If():
                return self._if(stmt)
            case resolved.Inlined():
                return self._inlined(stmt)
            case _:
                raise self._refuse(stmt)
        return stmt.span

    def _inlined(self, stmt: resolved.Inlined) -> Span | None:
        # An instruction's @line:col has no file, so a procedure body takes the position of the outermost call in
        # the file being compiled rather than positions in the procedure's own file.
        outer = self._call_site
        self._call_site = outer or stmt.span
        try:
            if self._body(stmt.body) is None:
                return None
            return self._call_site
        finally:
            self._call_site = outer

    def _if(self, stmt: resolved.If) -> Span:
        arms = [(stmt.cond, stmt.body)] + [(arm.cond, arm.body) for arm in stmt.elifs]
        end = Label()
        last = None
        for n, (cond, body) in enumerate(arms):
            next_arm = Label()
            self._branch(cond, next_arm, jump_if=False)
            last = self._body(body) or last
            if stmt.has_else or n < len(arms) - 1:
                self._emit(Op.BR, (end,), stmt.span)
            self._place(next_arm)
        if stmt.has_else:
            last = self._body(stmt.else_body) or last
        self._place(end)
        return last or stmt.span

    def _branch(self, cond: resolved.Cond, target: Label, *, jump_if: bool) -> None:
        """Jumps to `target` when `cond` is `jump_if`, and falls through otherwise, evaluating as little as
        header_rewrite does: an operand of AND or OR runs only when it can still change the result."""
        match cond:
            case resolved.Group():
                self._branch(cond.inner, target, jump_if=jump_if)
            case resolved.Not():
                self._branch(cond.inner, target, jump_if=not jump_if)
            case resolved.And() | resolved.Or():
                if isinstance(cond, resolved.And) != jump_if:
                    self._branch(cond.left, target, jump_if=jump_if)
                    self._branch(cond.right, target, jump_if=jump_if)
                else:
                    skip = Label()
                    self._branch(cond.left, skip, jump_if=not jump_if)
                    self._branch(cond.right, target, jump_if=jump_if)
                    self._place(skip)
            case _:
                reg, negated = self._test(cond)
                op = Op.BR_F
                if jump_if != negated:
                    op = Op.BR_T
                self._emit(op, (reg, target), cond.span)

    def _test(self, cond: resolved.Cond) -> tuple[Reg, bool]:
        """A condition as a bool register, and whether the register holds its negation."""
        if isinstance(cond, resolved.Test) and "NORM" in cond.modifiers:
            # header_rewrite normalizes the value before any matcher sees it, as it does a {... with NORM} hole.
            mods = tuple(m for m in cond.modifiers if m != "NORM")
            cond = dataclasses.replace(cond, ref=resolved.ModifiedRef(cond.ref, ("NORM",)), modifiers=mods)
        match cond:
            case resolved.Truth(existence=True):
                value = self._read(cond.ref, cond.span)
                if value.ty is not Ty.SVIEW:
                    raise self._error(cond.span, f"a {value.ty} value as a condition")
                return self._value(Op.CMP_S_NE, (value, self._const_s("", cond.span)), Ty.BOOL, cond.span), False
            case resolved.Truth():
                value = self._read(cond.ref, cond.span)
                if value.ty is not Ty.BOOL:
                    raise self._error(cond.span, f"a {value.ty} value as a condition")
                return value, False
            case resolved.FuncCond(key="internal"):
                return self._pure("BI_INTERNAL", (), Ty.BOOL, cond.span, "internal()"), False
            case resolved.FuncCond(key="access"):
                # hrw4u.so checks the file when the rule loads, so the path must be a constant.
                path = self._literal(cond.args[0], cond.span)
                return self._pure("BI_ACCESS", (path,), Ty.BOOL, cond.span, "access()"), False
            case resolved.BoolCond():
                return self._const_bool(cond.value, cond.span), False
            case resolved.Test(op=resolved.CmpOp.MATCH | resolved.CmpOp.NOT_MATCH):
                return self._match(cond), cond.op is resolved.CmpOp.NOT_MATCH
            case resolved.Test(op=resolved.CmpOp.IN | resolved.CmpOp.NOT_IN):
                return self._in_set(cond), cond.op is resolved.CmpOp.NOT_IN
            case resolved.Test(op=resolved.CmpOp.EQ | resolved.CmpOp.NE) if cond.modifiers:
                # A modifier makes `=` a match of one item, as header_rewrite's matcher tests one value the way it
                # tests a set's items.
                lhs = self._operand_of(cond, Ty.SVIEW)
                match, nocase = self._string_match(cond)
                entry = SetEntry(SetKind.STRING, (self._literal_text(cond.rhs, cond.span),), nocase, match)
                reg = self._value(Op.IN_SET, (lhs, Set(self._pools.intern_set(entry))), Ty.BOOL, cond.span)
                return reg, cond.op is resolved.CmpOp.NE
            case resolved.Test(op=resolved.CmpOp.EQ | resolved.CmpOp.NE | resolved.CmpOp.GT | resolved.CmpOp.LT):
                return self._compare(cond), False
        raise self._error(cond.span, f"the condition '{_cond_text(cond)}'")

    def _compare(self, cond: resolved.Test) -> Reg:
        if cond.modifiers:
            raise self._error(cond.span, f"the modifier {', '.join(cond.modifiers)} on a comparison")
        lhs = self._read(cond.ref, cond.span)
        if lhs.ty is Ty.I64:
            # header_rewrite's parser splits a quoted operand from "=" only, and refuses the line for "<" or ">".
            quoted = cond.op in (resolved.CmpOp.EQ, resolved.CmpOp.NE)
            rhs = self._const_i(self._int_literal(cond.rhs, cond.span, quoted), cond.span)
            return self._value(_INT_COMPARES[cond.op], (lhs, rhs), Ty.BOOL, cond.span)
        if lhs.ty is not Ty.SVIEW or cond.op not in (resolved.CmpOp.EQ, resolved.CmpOp.NE):
            raise self._error(cond.span, f"'{cond.op.value}' on a {lhs.ty} value")
        rhs = self._literal(cond.rhs, cond.span)
        op = Op.CMP_S_EQ
        if cond.op is resolved.CmpOp.NE:
            op = Op.CMP_S_NE
        return self._value(op, (lhs, rhs), Ty.BOOL, cond.span)

    def _match(self, cond: resolved.Test) -> Reg:
        nocase = self._nocase(cond)
        lhs = self._operand_of(cond, Ty.SVIEW)
        regex = self._pools.intern_regex(Pattern(cond.rhs.text[1:-1], nocase))
        return self._value(Op.RE_MATCH, (lhs, Regex(regex)), Ty.BOOL, cond.span)

    def _in_set(self, cond: resolved.Test) -> Reg:
        match cond.rhs:
            case resolved.IpRangeLit():
                if cond.modifiers:
                    raise self._error(cond.span, f"the modifier {', '.join(cond.modifiers)} on an IP range")
                entry = SetEntry(SetKind.IP, tuple(r.strip() for r in cond.rhs.text[1:-1].split(",")), False)
                lhs = self._operand_of(cond, Ty.ADDR)
            case resolved.SetLit():
                lhs = self._read(cond.ref, cond.span)
                if lhs.ty is Ty.I64:
                    if cond.modifiers:
                        raise self._error(cond.span, f"the modifier {', '.join(cond.modifiers)} on an integer set")
                    entry = SetEntry(SetKind.INT, self._int_items(cond.rhs.text, cond.span), False)
                else:
                    match, nocase = self._string_match(cond)
                    entry = SetEntry(SetKind.STRING, self._set_items(cond.rhs.text, cond.span), nocase, match)
                    if lhs.ty is not Ty.SVIEW:
                        raise self._error(cond.span, f"'{cond.op.value}' on a {lhs.ty} value")
            case _:
                raise self._error(cond.span, f"the operand {resolved.value_text(cond.rhs)}")
        return self._value(Op.IN_SET, (lhs, Set(self._pools.intern_set(entry))), Ty.BOOL, cond.span)

    def _set_items(self, text: str, span: Span) -> tuple[str, ...]:
        """Splits a set as header_rewrite does (matcher.h): at commas outside quotes, each item unquoted and
        trimmed. A backslash or an unmatched quote is refused: the .conf parser drops backslashes before the
        matcher sees the set, and the matcher refuses unmatched quotes."""
        if "\\" in text or text.count('"') % 2:
            raise self._error(span, f"the set [{text}]")
        items = []
        start = 0
        in_quotes = False
        for i, ch in enumerate(text + ","):
            if ch == '"':
                in_quotes = not in_quotes
            elif ch == "," and not in_quotes:
                item = text[start:i].strip()
                if len(item) >= 2 and item[0] == item[-1] == '"':
                    item = item[1:-1].strip()
                items.append(item)
                start = i + 1
        return tuple(items)

    def _string_match(self, cond: resolved.Test) -> tuple[SetMatch, bool]:
        """A string test's match mode and case: Sema has refused more than one mode."""
        match = SetMatch.WHOLE
        for mod in cond.modifiers:
            if mod in _SET_MATCHES:
                match = _SET_MATCHES[mod]
            elif mod != "NOCASE":
                raise self._error(cond.span, f"the modifier {mod}")
        return match, "NOCASE" in cond.modifiers

    def _int_items(self, text: str, span: Span) -> tuple[str, ...]:
        """A set on an integer condition, as header_rewrite reads it: each item, split as a string set's, a number."""
        items = []
        for item in self._set_items(text, span):
            if not re.fullmatch(r"[+-]?[0-9]+", item) or abs(int(item)) > _I64_MAX:
                raise self._error(span, f"the integer set item '{item}'")
            items.append(str(int(item)))
        return tuple(items)

    def _nocase(self, cond: resolved.Test) -> bool:
        if cond.modifiers not in ((), ("NOCASE",)):
            raise self._error(cond.span, f"the modifier {', '.join(cond.modifiers)}")
        return bool(cond.modifiers)

    def _operand_of(self, cond: resolved.Test, ty: Ty) -> Reg:
        lhs = self._read(cond.ref, cond.span)
        if lhs.ty is not ty:
            raise self._error(cond.span, f"'{cond.op.value}' on a {lhs.ty} value")
        return lhs

    def _int_literal(self, value: resolved.RValue, span: Span, quoted: bool = True) -> int:
        # The grammar's NUMBER has no sign; the reader keeps an integer in an i64. header_rewrite's parser drops the
        # quotes of a token before it reads the number, so "42" is 42 too where @a quoted allows it.
        text = None
        if isinstance(value, resolved.RawArg):
            text = value.text
        elif quoted and isinstance(value, resolved.StrTemplate) and len(value.parts) == 1 and \
                isinstance(value.parts[0], str):
            text = value.parts[0]
        if text is not None and text.isascii() and text.isdigit() and int(text) <= _I64_MAX:
            return int(text)
        raise self._error(span, f"the integer operand {resolved.value_text(value)}")

    def _literal(self, value: resolved.RValue, span: Span) -> Reg:
        """A value header_rewrite takes as written, without expanding it: a comparison's right-hand side, a name."""
        return self._const_s(self._literal_text(value, span), span)

    def _literal_text(self, value: resolved.RValue, span: Span) -> str:
        # A procedure's bare $param can carry a string argument here as text Sema already rendered for the .conf,
        # holes as %{...} and escapes as written, which no literal of the program itself can spell; and a $param
        # nothing binds arrives as its own text.
        if isinstance(value, resolved.RawArg) and not value.text.startswith("$") and "%{" not in value.text and \
                "\\" not in value.text:
            return value.text
        if isinstance(value, resolved.StrTemplate):
            if all(isinstance(p, str) for p in value.parts):
                text = decode_conf_escapes("".join(value.parts))
                # header_rewrite expands %{...} in a value at run time (value.cc), so a constant would mean something
                # else.
                if "%{" in text:
                    raise self._error(span, "'%{' in a string")
                return text
            raise self._error(span, f'the operand "{value.source}"')
        raise self._error(span, f"the operand {resolved.value_text(value)}")

    def _set_op(self, stmt: resolved.SetOp) -> None:
        target = stmt.key + (stmt.qualifier or "")
        if stmt.key in _HEADER_MESSAGES:
            self._header_write(stmt, target)
        elif stmt.key in _COOKIE_MESSAGES:
            self._check_message(stmt.key, stmt.span, target, _HOOK_COOKIES, "request")
            message = _COOKIE_MESSAGES[stmt.key]
            name = self._const_s(stmt.qualifier, stmt.span)
            if stmt.variant is resolved.OpVariant.REMOVE:
                self._effect(f"BI_RM_{message}_COOKIE", (name,), stmt.span, target)
            else:
                self._effect(f"BI_SET_{message}_COOKIE", (name, self._string(stmt.value, stmt.span)), stmt.span, target)
        elif stmt.key in _STATUS_WRITES:
            scope = self._status_scope(stmt.key, stmt.span, target)
            builtin = f"BI_SET_{_STATUS_MESSAGES[scope]}_STATUS"
            status = self._const_i(self._int_literal(stmt.value, stmt.span), stmt.span)
            self._effect(builtin, (status,), stmt.span, target)
            self._warn_unscoped_status(stmt.key, scope, "", stmt.span)
        elif stmt.key in _REASON_WRITES:
            key = stmt.key.removesuffix(".reason")
            scope = self._status_scope(key, stmt.span, target)
            # `= ""` is a remove to Sema; set-status-reason "" changes nothing, and so does the builtin.
            builtin = f"BI_SET_{_STATUS_MESSAGES[scope]}_STATUS_REASON"
            self._effect(builtin, (self._string(stmt.value, stmt.span),), stmt.span, target)
            self._warn_unscoped_status(key, scope, ".reason", stmt.span)
        elif stmt.key in _URL_MESSAGES:
            self._check_message(stmt.key, stmt.span, target, _HOOK_URLS, "URL")
            self._set_destination(stmt, _URL_MESSAGES[stmt.key], target)
        elif stmt.key in _CLIENT_SIDE_OUTBOUND:
            raise self._client_side_outbound(stmt.key, target, stmt.span)
        elif stmt.key in _CONN_PACKET_WRITES:
            value = self._const_i(self._int_literal(stmt.value, stmt.span), stmt.span)
            self._effect(_CONN_PACKET_WRITES[stmt.key], (value,), stmt.span, target)
        elif stmt.key == "http.cntl.":
            if self._hook not in _SET_HTTP_CNTL_HOOKS:
                raise self._source_map.error_at(
                    stmt.span, f"'{target}' in {self._hook.value}: header_rewrite refuses set-http-cntl in this hook")
            cntl = self._const_i(_HTTP_CNTLS[stmt.qualifier], stmt.span)
            on = self._const_bool(resolved.value_text(stmt.value).lower() in _ON_WORDS, stmt.span)
            self._effect("BI_SET_HTTP_CNTL", (cntl, on), stmt.span, target)
        elif stmt.key == "inbound.resp.body":
            # `= ""` is a remove to Sema, but the .conf sets an empty body, so the IR does too.
            body = self._string(stmt.value, stmt.span)
            self._effect("BI_SET_BODY", (body, self._content_type((), stmt.span)), stmt.span, target)
        else:
            raise self._error(stmt.span, f"assignment to '{target}'")

    def _call_op(self, stmt: resolved.CallOp) -> None:
        what = f"{stmt.key}()"
        match stmt.key, len(stmt.args):
            case "set-config", 2:
                # hrw4u.so resolves the record and its value when the rule loads, so both must be constants.
                name = self._literal(stmt.args[0], stmt.span)
                value = self._literal(stmt.args[1], stmt.span)
                self._effect("BI_SET_CONFIG", (name, value), stmt.span, what)
            case "set-plugin-cntl", 2:
                # Sema has checked the control and its value.
                field, values = _PLUGIN_CNTLS[self._literal_text(stmt.args[0], stmt.span)]
                value = values[self._literal_text(stmt.args[1], stmt.span)]
                args = (self._const_i(field, stmt.span), self._const_i(value, stmt.span))
                self._effect("BI_SET_PLUGIN_CNTL", args, stmt.span, what)
            case "set-redirect" | "inbound.resp.set-redirect" | "outbound.resp.set-redirect", 2:
                scope = stmt.key.removesuffix("set-redirect")
                if not scope:
                    scope = _HOOK_REDIRECTS.get(self._hook, "")
                self._check_message(scope, stmt.span, what, _HOOK_REDIRECTS, "response")
                # Sema has checked the status is 300-399.
                status = self._const_i(self._int_literal(stmt.args[0], stmt.span), stmt.span)
                builtin = f"BI_SET_{_HEADER_MESSAGES[scope]}_REDIRECT"
                self._effect(builtin, (status, self._string(stmt.args[1], stmt.span)), stmt.span, what)
                if stmt.key == "set-redirect":
                    self._warn(
                        stmt.span, f"set-redirect() names no response and works on the hook's, here {scope}; write "
                        f"'{scope}set-redirect(...)' instead")
            case "run-plugin", n if n >= 1:
                # hrw4u.so loads the plugin when the rule loads, so it and its arguments must be constants. They join
                # with spaces, as header_rewrite's parser joins the .conf line's tokens for run-plugin to split.
                name = self._literal_text(stmt.args[0], stmt.span)
                args = " ".join(self._literal_text(arg, stmt.span) for arg in stmt.args[1:])
                plugin = self._const_s(name, stmt.span)
                self._effect("BI_RUN_PLUGIN", (plugin, self._const_s(args, stmt.span)), stmt.span, what)
                self._warn(
                    stmt.span, f"run-plugin runs '{name}' as a remap plugin inside the Prism VM; implement it as a Cripts "
                    "module or a Prism VM extension instead")
            case "set-body", 1 | 2:
                body = self._string(stmt.args[0], stmt.span)
                self._effect("BI_SET_BODY", (body, self._content_type(stmt.args[1:], stmt.span)), stmt.span, what)
            case "set-body-from", 1 | 2:
                url = self._string(stmt.args[0], stmt.span)
                self._effect("BI_SET_BODY_FROM", (url, self._content_type(stmt.args[1:], stmt.span)), stmt.span, what)
            case "set-body-from-file", 1 | 2:
                # hrw4u.so reads the file when the rule loads, so the path must be a constant.
                path = self._literal(stmt.args[0], stmt.span)
                content_type = self._content_type(stmt.args[1:], stmt.span)
                self._effect("BI_SET_BODY_FROM_FILE", (path, content_type), stmt.span, what)
            case "add-header", 2:
                # Sema allows add-header() only in hooks with a message.
                scope = _HOOK_MESSAGES[self._hook]
                name = self._literal_text(stmt.args[0], stmt.span)
                args = (self._const_s(name, stmt.span), self._string(stmt.args[1], stmt.span))
                self._effect(f"BI_ADD_{_HEADER_MESSAGES[scope]}_HEADER", args, stmt.span, what)
                self._warn(
                    stmt.span, f"add-header() names no message and adds to the one the hook has, here {scope}; write "
                    f"'{scope}{name} += ...' instead")
            case "counter", 1:
                # hrw4u.so makes or finds the metric when the rule loads, so the name must be a constant.
                self._effect("BI_COUNTER", (self._literal(stmt.args[0], stmt.span),), stmt.span, what)
            case "no-op", 0:
                # header_rewrite's no-op does nothing without [L], which hrw4u writes only for break.
                pass
            case "set-debug", 0:
                if self._hook not in _SET_DEBUG_HOOKS:
                    raise self._source_map.error_at(
                        stmt.span, f"'{what}' in {self._hook.value}: header_rewrite refuses set-debug in this hook")
                cntl = self._const_i(_HTTP_CNTLS["TXN_DEBUG"], stmt.span)
                self._effect("BI_SET_HTTP_CNTL", (cntl, self._const_bool(True, stmt.span)), stmt.span, what)
            case "skip-remap", 1:
                cntl = self._const_i(_HTTP_CNTLS["SKIP_REMAP"], stmt.span)
                on = self._const_bool(resolved.value_text(stmt.args[0]) in _SKIP_REMAP_ON, stmt.span)
                self._effect("BI_SET_HTTP_CNTL", (cntl, on), stmt.span, what)
            case "remove_query" | "inbound.url.remove_query" | "outbound.url.remove_query", 1:
                message = self._query_url(stmt.key, stmt.span, what)
                # rm-destination QUERY takes its key list as written, without expanding it.
                field = self._const_i(_URL_FIELDS["QUERY"], stmt.span)
                self._effect(f"BI_RM_{message}_URL", (field, self._literal(stmt.args[0], stmt.span)), stmt.span, what)
                self._warn_unscoped_query(stmt.key, stmt.span)
            case "keep_query" | "inbound.url.keep_query" | "outbound.url.keep_query", 1:
                message = self._query_url(stmt.key, stmt.span, what)
                self._effect(f"BI_KEEP_{message}_QUERY", (self._literal(stmt.args[0], stmt.span),), stmt.span, what)
                self._warn_unscoped_query(stmt.key, stmt.span)
            case _:
                raise self._error(stmt.span, f"'{what}' with {len(stmt.args)} argument(s)")

    def _query_url(self, key: str, span: Span, what: str) -> str:
        """The request a key-list call works on, as the URL builtins spell it: the unscoped ones name none, so the hook's."""
        scope = key.removesuffix("remove_query").removesuffix("keep_query")
        if not scope:
            scope = _HOOK_URLS.get(self._hook, "")
        self._check_message(scope, span, what, _HOOK_URLS, "URL")
        return _URL_MESSAGES[scope]

    def _warn_unscoped_query(self, key: str, span: Span) -> None:
        if "." not in key:
            scope = _HOOK_URLS[self._hook]
            self._warn(
                span, f"{key}() names no URL and works on the hook's request's, here {scope}; write "
                f"'{scope}{key}(...)' instead")

    def _set_destination(self, stmt: resolved.SetOp, message: str, target: str) -> None:
        if stmt.variant is resolved.OpVariant.REMOVE:
            # rm-destination with no key list: it clears the path, the query or the port, and ignores the other fields
            # in both plugins.
            field = self._const_i(_URL_FIELDS[stmt.qualifier], stmt.span)
            self._effect(f"BI_RM_{message}_URL", (field, self._const_s("", stmt.span)), stmt.span, target)
            return
        if stmt.qualifier == "PORT":
            # header_rewrite reads the port once, from a constant, and skips one out of range at run time; this
            # refuses it instead.
            port = self._int_literal(stmt.value, stmt.span)
            if not 0 < port <= 0xFFFF:
                raise self._error(stmt.span, f"the port {port}")
            self._effect(f"BI_SET_{message}_URL_PORT", (self._const_i(port, stmt.span),), stmt.span, target)
            return
        field = self._const_i(_URL_FIELDS[stmt.qualifier], stmt.span)
        self._effect(f"BI_SET_{message}_URL", (field, self._string(stmt.value, stmt.span)), stmt.span, target)

    def _content_type(self, args: tuple[resolved.RValue, ...], span: Span) -> Reg:
        """The optional content type of set-body and the calls like it, empty for none. header_rewrite refuses a constant one without a '/' at load
        (initialize_content_type()), one with no %{...} in it, so this refuses it too."""
        if not args:
            return self._const_s("", span)
        value = args[0]
        if isinstance(value, resolved.StrTemplate) and all(isinstance(p, str) for p in value.parts):
            text = "".join(value.parts)
            if text and "/" not in text and "%{" not in text:
                raise self._error(span, f'the content type "{text}"')
        return self._string(value, span)

    def _header_write(self, stmt: resolved.SetOp, target: str) -> None:
        self._check_message(stmt.key, stmt.span, target)
        builtin = f"BI_{_HEADER_VERBS[stmt.variant]}_{_HEADER_MESSAGES[stmt.key]}_HEADER"
        name = self._const_s(stmt.qualifier, stmt.span)
        if stmt.variant is resolved.OpVariant.REMOVE:
            self._effect(builtin, (name,), stmt.span, target)
            return
        self._effect(builtin, (name, self._string(stmt.value, stmt.span)), stmt.span, target)

    def _client_side_outbound(self, key: str, what: str, span: Span) -> Hrw4uSyntaxError:
        inbound = "inbound." + what.removeprefix("outbound.")
        return self._source_map.error_at(
            span, f"'{what}': header_rewrite {_CLIENT_SIDE_OUTBOUND[key]} here whatever the scope; write '{inbound}' "
            "instead")

    def _check_message(
            self,
            scope: str,
            span: Span,
            what: str,
            hook_scopes: dict[SectionType, str] = _HOOK_MESSAGES,
            kind: str = "message") -> None:
        """Refuse a scope naming another message than the hook's, where header_rewrite would work on the hook's."""
        hook_scope = hook_scopes.get(self._hook)
        if hook_scope is None:
            raise self._source_map.error_at(span, f"'{what}' in {self._hook.value}: this hook has no {kind}")
        if hook_scope != scope:
            raise self._source_map.error_at(
                span, f"'{what}' in {self._hook.value}: this hook's {kind} is {hook_scope}, which header_rewrite would "
                "work on instead")

    def _status_scope(self, key: str, span: Span, what: str) -> str:
        """The scope of the status @key names: http.status names none, so it is the hook's."""
        if key == "http.status" and self._hook in _HOOK_STATUSES:
            key = _HOOK_STATUSES[self._hook]
        self._check_message(key, span, what, _HOOK_STATUSES, "status")
        return key

    def _warn_unscoped_status(self, key: str, scope: str, suffix: str, span: Span) -> None:
        if key == "http.status":
            self._warn(
                span, f"http.status{suffix} names no message and works on the hook's response, here {scope}; write "
                f"'{scope}{suffix}' instead")

    def _string(self, value: resolved.RValue, span: Span) -> Reg:
        if isinstance(value, resolved.ExternCall):
            return self._extern(value, span)
        if isinstance(value, resolved.InstanceRef):
            return self._read(value, span)
        if not isinstance(value, resolved.StrTemplate):
            raise self._error(span, "a non-string value")
        lits = [""]
        holes: list[Reg] = []
        for part in value.parts:
            if isinstance(part, str):
                lits[-1] += part
            else:
                holes.append(self._read(part, span))
                lits.append("")
        lits = [decode_conf_escapes(lit) for lit in lits]
        # header_rewrite expands %{...} in a value at run time (value.cc), so a constant would mean something else.
        if any("%{" in lit for lit in lits):
            raise self._error(span, "'%{' in a string")
        if not holes:
            return self._const_s(lits[0], span)
        fmt = self._pools.intern_fmt(Format(value.source, tuple(lits)))
        return self._value(Op.FMT, (Fmt(fmt), *holes), Ty.SVIEW, span)

    def _extern(self, call: resolved.ExternCall, span: Span) -> Reg:
        """Sema has checked the arguments against the declaration, that a call is for its value only where the value
        is of the type its result is, and that a load function is called in an INSTANCE_VARS initializer only."""
        args = tuple(self._extern_arg(arg, param, span) for arg, param in zip(call.args, call.decl.params))
        op = Op.CALL_PURE
        if call.decl.effect == "load":
            op = Op.CALL_LOAD
        return self._value(op, (Extern(call.decl.name), *args), _EXTERN_TYPES[call.decl.result], span)

    def _extern_arg(self, arg: resolved.RValue, param: str, span: Span) -> Reg:
        if isinstance(arg, resolved.ExternCall):
            return self._extern(arg, span)
        if param == "int64":
            return self._const_i(self._int_literal(arg, span), span)
        if param == "bool":
            text = resolved.value_text(arg)
            if text.lower() not in ("true", "false"):
                raise self._error(span, f"the bool operand {text}")
            return self._const_bool(text.lower() == "true", span)
        return self._string(arg, span)

    def _read(self, ref: resolved.Ref | resolved.InstanceRef | resolved.ModifiedRef | resolved.ExternCall, span: Span) -> Reg:
        if isinstance(ref, resolved.ExternCall):
            return self._extern(ref, span)
        if isinstance(ref, resolved.VarRef):
            return self._load_var(ref.symbol, span)
        if isinstance(ref, resolved.InstanceRef):
            return self._value(Op.LOAD_I, (IVar(ref.index),), Ty.SVIEW, span)
        if isinstance(ref, resolved.ModifiedRef):
            if set(ref.mods) != {"NORM"}:
                raise self._error(span, f"the value modifier {', '.join(ref.mods)}")
            value = self._read(ref.ref, span)
            if value.ty is not Ty.SVIEW:
                raise self._error(span, f"the value modifier NORM on a {value.ty} value")
            return self._pure("BI_NORM", (value,), Ty.SVIEW, span, "NORM")
        what = _ref_text(ref)
        if ref.key in _CLIENT_SIDE_OUTBOUND:
            raise self._client_side_outbound(ref.key, what, span)
        if what in _PLAIN_READS:
            builtin, ty = _PLAIN_READS[what]
            return self._pure(builtin, (), ty, span, what)
        match ref.key:
            case "inbound.req.":
                return self._pure("BI_CLIENT_HEADER", (self._const_s(ref.arg, span),), Ty.SVIEW, span, what)
            case "outbound.req.":
                return self._pure("BI_SERVER_HEADER", (self._const_s(ref.arg, span),), Ty.SVIEW, span, what)
            case "inbound.status" | "outbound.status":
                self._check_message(ref.key, span, what, _HOOK_STATUSES, "status")
                return self._pure(f"BI_{_STATUS_MESSAGES[ref.key]}_STATUS", (), Ty.I64, span, what)
            case "inbound.resp." | "outbound.resp.":
                self._check_message(ref.key, span, what)
                builtin = f"BI_{_HEADER_MESSAGES[ref.key]}_HEADER"
                return self._pure(builtin, (self._const_s(ref.arg, span),), Ty.SVIEW, span, what)
            case key if key in _NAMED_READS:
                return self._pure(_NAMED_READS[key], (self._const_s(ref.arg, span),), Ty.SVIEW, span, what)
            case key if key in _NUMBERED_READS:
                builtin, ty, number = _NUMBERED_READS[key]
                return self._pure(builtin, (self._const_i(number(ref.arg), span),), ty, span, what)
            case "now":
                # header_rewrite's %{NOW} with no qualifier reads the seconds since the epoch.
                return self._pure("BI_NOW", (self._const_i(_NOW_EPOCH, span),), Ty.I64, span, what)
            case "http.cntl.":
                return self._pure("BI_HTTP_CNTL", (self._const_i(_HTTP_CNTLS[ref.arg], span),), Ty.BOOL, span, what)
            case "inbound.conn." if ref.arg in _CLIENT_PROTOCOLS:
                prefix = self._const_s(_CLIENT_PROTOCOLS[ref.arg], span)
                return self._pure("BI_CLIENT_PROTOCOL", (prefix,), Ty.SVIEW, span, what)
            case "nexthop." if ref.arg in _NEXT_HOP_FIELDS:
                field = self._const_i(_NEXT_HOP_FIELDS[ref.arg], span)
                return self._pure("BI_NEXT_HOP", (field,), Ty.SVIEW, span, what)
            case "geo." if ref.arg == "COUNTRY-ISO":
                # header_rewrite's MaxMind lookup answers only ASN of its integer fields, and its GeoIP lookup, the one
                # that answers a country number, is not built.
                raise self._source_map.error_at(
                    span, f"'{what}': header_rewrite with MaxMind reads -1 for it whatever the address; read 'geo.COUNTRY' instead")
            case "geo." if ref.arg in _GEO_BINDINGS:
                binding, ty = _GEO_BINDINGS[ref.arg]
                return self._value(Op.CALL_PURE, (Extern(binding),), ty, span)
            case "cidr":
                # Sema has checked there are two prefix lengths, IPv4's then IPv6's.
                v4, v6 = (self._const_i(int(n), span) for n in ref.arg.split(","))
                return self._pure("BI_CIDR", (v4, v6), Ty.SVIEW, span, what)
        raise self._error(span, f"reading '{what}'")

    def _var(self, symbol: Symbol, span: Span) -> Var:
        if symbol.scope is not VarScope.TXN:
            raise self._error(span, f"a {symbol.scope.name.lower()} {symbol.var_type.value[0]} variable")
        # By its kind and hrw4u slot, as the .conf's STATE-FLAG:n and STATE-INT8:n name it. Within one program only:
        # hrw4u.so keeps a transaction's variables per instance.
        var = Var(symbol.slot, _VAR_KINDS[symbol.var_type])
        self._pools.use_var(var)
        return var

    def _load_var(self, symbol: Symbol, span: Span) -> Reg:
        var = self._var(symbol, span)
        ty = Ty.I64
        if var.kind is VarKind.BOOL:
            ty = Ty.BOOL
        return self._value(Op.LOAD_V, (var,), ty, span)

    def _set_var(self, stmt: resolved.SetVar) -> None:
        var = self._var(stmt.symbol, stmt.span)
        if isinstance(stmt.value, resolved.VarRef):
            # The variable's value, as the docs define assignment; the .conf's set-state-flag takes %{STATE-FLAG:n}
            # as text, so there a bool target is always cleared. Sema allows a copy between variables of one type.
            value = self._load_var(stmt.value.symbol, stmt.span)
        elif var.kind is VarKind.BOOL:
            value = self._const_bool(resolved.value_text(stmt.value).lower() in _ON_WORDS, stmt.span)
        else:
            value = self._const_i(self._int_literal(stmt.value, stmt.span), stmt.span)
        self._emit(Op.STORE_V, (var, value), stmt.span)

    def _pure(self, builtin: str, args: tuple[Reg, ...], ty: Ty, span: Span, what: str) -> Reg:
        self._check_builtin_hook(builtin, span, what)
        return self._value(Op.CALL_PURE, (Builtin(builtin), *args), ty, span)

    def _effect(self, builtin: str, args: tuple[Reg, ...], span: Span, what: str) -> None:
        self._check_builtin_hook(builtin, span, what)
        self._emit(Op.CALL_EFF, (Builtin(builtin), *args), span)

    def _check_builtin_hook(self, builtin: str, span: Span, what: str) -> None:
        hooks = _BUILTIN_HOOKS.get(builtin)
        if hooks is not None and self._hook not in hooks:
            names = ", ".join(sorted(h.value for h in hooks))
            raise self._source_map.error_at(span, f"'{what}' in {self._hook.value}: hrw4u.so runs {builtin} only in {names}")

    def _const_s(self, text: str, span: Span) -> Reg:
        return self._value(Op.CONST_S, (Const(self._pools.intern_const(text)),), Ty.SVIEW, span)

    def _const_i(self, value: int, span: Span) -> Reg:
        return self._value(Op.CONST_I, (IntConst(self._pools.intern_int(value)),), Ty.I64, span)

    def _const_bool(self, value: bool, span: Span) -> Reg:
        return self._value(Op.CONST_I, (IntConst(self._pools.intern_int(int(value))),), Ty.BOOL, span)

    def _value(self, op: Op, operands: tuple[Operand, ...], ty: Ty, span: Span) -> Reg:
        reg = Reg(self._next_reg, ty)
        self._next_reg += 1
        self._emit(op, operands, span, reg)
        return reg

    def _place(self, label: Label) -> None:
        label.index = len(self._instructions)

    def _emit(self, op: Op, operands: tuple[Operand, ...], span: Span, dest: Reg | None = None) -> None:
        span = self._call_site or span
        self._instructions.append(Instruction(op, operands, dest, span.line, span.column))

    def _refuse(self, node: resolved.Stmt) -> Hrw4uSyntaxError:
        return self._error(node.span, type(node).__name__)

    def _error(self, span: Span, what: str) -> Hrw4uSyntaxError:
        return self._source_map.error_at(span, f"{what} is not supported by the IR emitter yet")

    def _warn(self, span: Span, message: str) -> None:
        if span in self._warned:
            return
        self._warned.add(span)
        if self._error_collector is not None:
            self._error_collector.add_warning(Warning.from_span(span, message, self._source_map.line_at(span)))


def lower(
        program: resolved.Program,
        source_map: SourceMap,
        filename: str,
        error_collector: ErrorCollector | None = None) -> IRProgram:
    return _Lowerer(source_map, filename, error_collector).lower(program)
