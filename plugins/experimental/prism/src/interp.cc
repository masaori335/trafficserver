/** @file

  Runs a section of an hrw4u-ir program, calling CriptsBridge for what its builtins do.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
  agreements.  See the NOTICE file distributed with this work for additional information regarding
  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with the License.  You may obtain
  a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed under the License
  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
  or implied. See the License for the specific language governing permissions and limitations under
  the License.
*/

#include "interp.h"

#include "registry.h"

#include "swoc/IPEndpoint.h"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <deque>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace hrw4u
{
namespace
{
  // One register: an sview is (pointer, length); a bool, or an integer as int64_t, is w[0]; an addr is a pointer to a
  // swoc::IPAddr the run keeps. Words, so an extension call passes them as they are.
  struct Value {
    uint64_t w[2];
  };

  using Registers = std::array<Value, MAX_REGS>;
  static_assert(sizeof(Registers) == 4096);

  Value
  sview_value(std::string_view s)
  {
    return Value{
      {reinterpret_cast<uint64_t>(s.data()), s.size()}
    };
  }

  // An empty view may hold null, as BI_LAST_CAPTURE's before a match, or an extension's empty result; the ATS header API
  // asserts on a null name even of length 0.
  std::string_view
  as_sview(const Value &v)
  {
    if (v.w[0] == 0) {
      return "";
    }
    return {reinterpret_cast<const char *>(v.w[0]), static_cast<size_t>(v.w[1])};
  }

  // Built only on a fault, so a call that succeeds allocates nothing.
  std::string
  fault_in(const Inst &inst, std::string_view callee, std::string_view what)
  {
    return "fault in " + std::string(callee) + " @" + std::to_string(inst.line) + ":" + std::to_string(inst.col) + ": " +
           std::string(what);
  }

  std::string
  fault_at(const Inst &inst, std::string_view what)
  {
    return fault_in(inst, "EXT\"" + inst.ext_name + "\"", what);
  }

  int64_t
  as_int(const Value &v)
  {
    return static_cast<int64_t>(v.w[0]);
  }

  std::optional<UrlField>
  url_field(const Value &v)
  {
    int64_t field = as_int(v);

    if (field < 0 || field > static_cast<int64_t>(UrlField::Url)) {
      return std::nullopt;
    }
    return static_cast<UrlField>(field);
  }

  // As header_rewrite's Resources::get_query_param(): pairs split at '&' then '=', names and values as written (no
  // decoding), and a name given twice keeps its last value.
  std::string_view
  query_param(std::string_view query, std::string_view name)
  {
    std::string_view found;

    while (!query.empty()) {
      size_t           amp   = query.find('&');
      std::string_view pair  = query.substr(0, amp);
      size_t           eq    = pair.find('=');
      std::string_view key   = pair.substr(0, eq);
      std::string_view value = {};

      if (eq != std::string_view::npos) {
        value = pair.substr(eq + 1);
      }
      if (!key.empty() && key == name) {
        found = value;
      }
      if (amp == std::string_view::npos) {
        break;
      }
      query.remove_prefix(amp + 1);
    }
    return found;
  }

  // Null in a register never written. The reader refuses such a read; one it misses reads no address, not a crash.
  const swoc::IPAddr &
  as_addr(const Value &v)
  {
    if (v.w[0] == 0) {
      return swoc::IPAddr::INVALID;
    }
    return *reinterpret_cast<const swoc::IPAddr *>(v.w[0]);
  }

  // As inet_ntop() writes it; empty when there is no address.
  void
  render_addr(std::string &out, const swoc::IPAddr &addr)
  {
    swoc::IPEndpoint ep;
    char             buf[INET6_ADDRSTRLEN];
    const char      *text = nullptr;

    if (addr.is_ip4()) {
      addr.copy_to(&ep.sa);
      text = inet_ntop(AF_INET, &ep.sa4.sin_addr, buf, sizeof(buf));
    } else if (addr.is_ip6()) {
      addr.copy_to(&ep.sa);
      text = inet_ntop(AF_INET6, &ep.sa6.sin6_addr, buf, sizeof(buf));
    }
    if (text != nullptr) {
      out += text;
    }
  }

  // As header_rewrite renders a value: a bool is TRUE or FALSE, an integer its decimal digits, an address as inet_ntop()
  // writes it (empty when there is none).
  void
  render(std::string &out, const Value &v, Type type)
  {
    switch (type) {
    case Type::Sview:
      out += as_sview(v);
      break;
    case Type::Bool:
      if (v.w[0] != 0) {
        out += "TRUE";
      } else {
        out += "FALSE";
      }
      break;
    case Type::I64: {
      char buf[24];
      auto [end, ec] = std::to_chars(buf, buf + sizeof(buf), as_int(v));

      out.append(buf, end);
      break;
    }
    case Type::Addr:
      render_addr(out, as_addr(v));
      break;
    }
  }

  // Every byte, as header_rewrite compares; ts::iequals stops at a NUL.
  bool
  equal_nocase(std::string_view a, std::string_view b)
  {
    return std::ranges::equal(a, b, [](unsigned char x, unsigned char y) { return std::tolower(x) == std::tolower(y); });
  }

  bool
  equal(std::string_view a, std::string_view b, bool nocase)
  {
    if (nocase) {
      return equal_nocase(a, b);
    }
    return a == b;
  }

  // As header_rewrite's match_with_modifiers() (matcher.cc): an extension is the text after the last '.', and must not
  // be empty.
  bool
  matches(std::string_view s, std::string_view item, Set::Match match, bool nocase)
  {
    switch (match) {
    case Set::Match::Whole:
      break;
    case Set::Match::Prefix:
      return s.size() >= item.size() && equal(s.substr(0, item.size()), item, nocase);
    case Set::Match::Suffix:
      return s.size() >= item.size() && equal(s.substr(s.size() - item.size()), item, nocase);
    case Set::Match::Substring: {
      // As header_rewrite's two searches: find() takes an empty item to match an empty subject, std::search() not.
      if (!nocase) {
        return s.find(item) != std::string_view::npos;
      }
      auto pred = [](unsigned char x, unsigned char y) { return std::tolower(x) == std::tolower(y); };

      return std::ranges::search(s, item, pred).begin() != s.end();
    }
    case Set::Match::Extension: {
      auto dot = s.rfind('.');

      return dot != std::string_view::npos && dot + 1 < s.size() && equal(s.substr(dot + 1), item, nocase);
    }
    }
    return equal(s, item, nocase);
  }

  // A scan, as header_rewrite's: the sets rules use are a handful of items.
  bool
  contains(const Set &set, std::string_view s)
  {
    for (const auto &item : set.items) {
      if (matches(s, item, set.match, set.nocase)) {
        return true;
      }
    }
    return false;
  }

  // Registers view strings a run builds or copies; a deque never moves its elements, so the views stay valid
  // until the run ends. Created on first use: libstdc++ allocates even for an empty deque.
  std::string &
  keep(std::optional<std::deque<std::string>> &strings, std::string s)
  {
    if (!strings) {
      strings.emplace();
    }
    return strings->emplace_back(std::move(s));
  }

  // Addresses registers point to; a deque never moves them. Created on first use, as keep() makes its deque.
  const swoc::IPAddr &
  keep_addr(std::optional<std::deque<swoc::IPAddr>> &addrs, swoc::IPAddr addr)
  {
    if (!addrs) {
      addrs.emplace();
    }
    return addrs->emplace_back(addr);
  }

  bool
  call_ext(const Section &sec, const Inst &inst, hrw4u_rule_ctx *ctx, Registers &regs,
           std::optional<std::deque<std::string>> &strings, std::string &fault)
  {
    if (inst.fn == nullptr) {
      fault = fault_at(inst, "not bound");
      return false;
    }

    std::array<uint64_t, 2 * MAX_EXT_PARAMS> args{};
    std::array<uint64_t, HRW4U_RET_WORDS>    ret{};
    size_t                                   n = 0;

    for (uint32_t reg : inst.args) {
      args[n++] = regs[reg].w[0];
      if (sec.reg_types[reg] == Type::Sview) {
        args[n++] = regs[reg].w[1];
      }
    }
    if (inst.fn(ctx, args.data(), ret.data()) != 0) {
      fault = fault_at(inst, as_sview(Value{
                               {ret[0], ret[1]}
      }));
      return false;
    }
    switch (sec.reg_types[inst.dest]) {
    case Type::Sview: {
      // A copy: the function's next call may reuse what its result views.
      std::string_view result = as_sview(Value{
        {ret[0], ret[1]}
      });

      if (!result.empty()) {
        result = keep(strings, std::string(result));
      }
      regs[inst.dest] = sview_value(result);
      break;
    }
    case Type::Bool:
      regs[inst.dest].w[0] = ret[0] != 0;
      break;
    case Type::I64:
    case Type::Addr: // bind never binds an addr result
      regs[inst.dest].w[0] = ret[0];
      break;
    }
    return true;
  }
} // namespace

// run() and run_instance(): @a ops is null in the Instance section, which calls no builtin, and @a ivars is null in a
// hook, which stores no instance variable.
static bool
execute(const Program &prog, const Section &sec, CriptsBridge *ops, std::string &fault, swoc::MemSpan<uint64_t> vars,
        std::vector<std::string> *ivars)
{
  // A section built without the reader could have more registers than the array.
  if (sec.num_regs > MAX_REGS) {
    fault = "a section of " + std::to_string(sec.num_regs - 1) + " registers, more than " + std::to_string(MAX_REGS - 1);
    return false;
  }

  Registers regs;

  // Only the section's: a read the reader misses gets a null string or address, as an unset one, not the stack's bytes.
  std::fill_n(regs.begin(), sec.num_regs, Value{});

  std::optional<std::deque<std::string>>  strings;
  std::optional<std::deque<swoc::IPAddr>> addrs; // Addresses registers point to; a deque never moves them.
  std::string                             subject;
  std::optional<RegexMatches>             matches; // Created on first use: it allocates the match data.
  size_t                                  pc  = 0;
  hrw4u_rule_ctx                         *ctx = nullptr;

  if (ops != nullptr) {
    ctx = rule_ctx(*ops);
  }

  while (pc < sec.insts.size()) {
    const Inst &inst = sec.insts[pc];

    ++pc;
    switch (inst.op) {
    case Op::ConstI:
      regs[inst.dest].w[0] = static_cast<uint64_t>(prog.ints[inst.operand]);
      break;
    case Op::ConstS:
      regs[inst.dest] = sview_value(prog.consts[inst.operand]);
      break;
    case Op::CallEff:
      switch (inst.builtin) {
      case Builtin::None:
      case Builtin::ClientHeader:
      case Builtin::ClientRespHeader:
      case Builtin::ServerRespHeader:
      case Builtin::ServerRespStatus:
      case Builtin::ClientRespStatus:
      case Builtin::ClientUrl:
      case Builtin::ClientUrlParam:
      case Builtin::ServerHeader:
      case Builtin::ServerUrl:
      case Builtin::IpClient:
      case Builtin::IpInbound:
        break;
      case Builtin::SetClientHeader:
        ops->set_header(Message::ClientRequest, as_sview(regs[inst.args[0]]), as_sview(regs[inst.args[1]]));
        break;
      case Builtin::SetServerHeader:
        ops->set_header(Message::ServerRequest, as_sview(regs[inst.args[0]]), as_sview(regs[inst.args[1]]));
        break;
      case Builtin::SetServerRespHeader:
        ops->set_header(Message::ServerResponse, as_sview(regs[inst.args[0]]), as_sview(regs[inst.args[1]]));
        break;
      case Builtin::SetClientRespHeader:
        ops->set_header(Message::ClientResponse, as_sview(regs[inst.args[0]]), as_sview(regs[inst.args[1]]));
        break;
      case Builtin::AddClientHeader:
        ops->add_header(Message::ClientRequest, as_sview(regs[inst.args[0]]), as_sview(regs[inst.args[1]]));
        break;
      case Builtin::AddServerHeader:
        ops->add_header(Message::ServerRequest, as_sview(regs[inst.args[0]]), as_sview(regs[inst.args[1]]));
        break;
      case Builtin::AddServerRespHeader:
        ops->add_header(Message::ServerResponse, as_sview(regs[inst.args[0]]), as_sview(regs[inst.args[1]]));
        break;
      case Builtin::AddClientRespHeader:
        ops->add_header(Message::ClientResponse, as_sview(regs[inst.args[0]]), as_sview(regs[inst.args[1]]));
        break;
      case Builtin::RmClientHeader:
        ops->rm_header(Message::ClientRequest, as_sview(regs[inst.args[0]]));
        break;
      case Builtin::RmServerHeader:
        ops->rm_header(Message::ServerRequest, as_sview(regs[inst.args[0]]));
        break;
      case Builtin::RmServerRespHeader:
        ops->rm_header(Message::ServerResponse, as_sview(regs[inst.args[0]]));
        break;
      case Builtin::RmClientRespHeader:
        ops->rm_header(Message::ClientResponse, as_sview(regs[inst.args[0]]));
        break;
      }
      break;
    case Op::CallPure:
      switch (inst.builtin) {
      case Builtin::None:
        if (!call_ext(sec, inst, ctx, regs, strings, fault)) {
          return false;
        }
        break;
      case Builtin::ClientRespHeader:
        regs[inst.dest] = sview_value(keep(strings, ops->get_header(Message::ClientResponse, as_sview(regs[inst.args[0]]))));
        break;
      case Builtin::ServerRespHeader:
        regs[inst.dest] = sview_value(keep(strings, ops->get_header(Message::ServerResponse, as_sview(regs[inst.args[0]]))));
        break;
      case Builtin::ClientHeader:
        regs[inst.dest] = sview_value(keep(strings, ops->client_header(as_sview(regs[inst.args[0]]))));
        break;
      case Builtin::ServerRespStatus:
        regs[inst.dest].w[0] = static_cast<uint64_t>(ops->status(Message::ServerResponse));
        break;
      case Builtin::ClientRespStatus:
        regs[inst.dest].w[0] = static_cast<uint64_t>(ops->status(Message::ClientResponse));
        break;
      case Builtin::ClientUrl: {
        auto field = url_field(regs[inst.args[0]]);

        if (!field) {
          fault = fault_in(inst, "BI_CLIENT_URL", "no URL field " + std::to_string(as_int(regs[inst.args[0]])));
          return false;
        }
        regs[inst.dest] = sview_value(keep(strings, ops->client_url_field(*field)));
        break;
      }
      case Builtin::ClientUrlParam: {
        std::string query = ops->client_url_field(UrlField::Query);

        regs[inst.dest] = sview_value(keep(strings, std::string(query_param(query, as_sview(regs[inst.args[0]])))));
        break;
      }
      case Builtin::ServerHeader:
        regs[inst.dest] = sview_value(keep(strings, ops->get_header(Message::ServerRequest, as_sview(regs[inst.args[0]]))));
        break;
      case Builtin::IpClient:
        regs[inst.dest].w[0] = reinterpret_cast<uint64_t>(&keep_addr(addrs, ops->client_addr()));
        break;
      case Builtin::IpInbound:
        regs[inst.dest].w[0] = reinterpret_cast<uint64_t>(&keep_addr(addrs, ops->inbound_addr()));
        break;
      case Builtin::ServerUrl: {
        auto field = url_field(regs[inst.args[0]]);

        if (!field) {
          fault = fault_in(inst, "BI_SERVER_URL", "no URL field " + std::to_string(as_int(regs[inst.args[0]])));
          return false;
        }
        regs[inst.dest] = sview_value(keep(strings, ops->server_url_field(*field)));
        break;
      }
      case Builtin::SetClientHeader:
      case Builtin::SetServerHeader:
      case Builtin::SetServerRespHeader:
      case Builtin::SetClientRespHeader:
      case Builtin::AddClientHeader:
      case Builtin::AddServerHeader:
      case Builtin::AddServerRespHeader:
      case Builtin::AddClientRespHeader:
      case Builtin::RmClientHeader:
      case Builtin::RmServerHeader:
      case Builtin::RmServerRespHeader:
      case Builtin::RmClientRespHeader:
        break;
      }
      break;
    case Op::CallLoad:
      if (!call_ext(sec, inst, ctx, regs, strings, fault)) {
        return false;
      }
      break;
    case Op::Fmt: {
      const Format &fmt  = prog.fmts[inst.operand];
      size_t        size = 0;

      for (const auto &lit : fmt.lits) {
        size += lit.size();
      }
      for (uint32_t reg : inst.args) {
        if (sec.reg_types[reg] == Type::Sview) {
          size += regs[reg].w[1];
        } else {
          size += INET6_ADDRSTRLEN; // the longest address, i64 or FALSE
        }
      }
      std::string &out = keep(strings, {});

      out.reserve(size);
      out += fmt.lits[0];
      for (size_t i = 0; i < inst.args.size(); ++i) {
        render(out, regs[inst.args[i]], sec.reg_types[inst.args[i]]);
        out += fmt.lits[i + 1];
      }
      regs[inst.dest] = sview_value(out);
      break;
    }
    case Op::ReMatch:
      // As header_rewrite, the subject is copied so the captures outlive the register it came from, and a
      // failed match leaves no captures.
      subject.assign(as_sview(regs[inst.args[0]]));
      if (!matches) {
        matches.emplace();
      }
      regs[inst.dest].w[0] = prog.regexes[inst.operand].exec(subject, *matches) > 0;
      break;
    case Op::InSet: {
      const Set &set = prog.sets[inst.operand];

      if (set.kind == Set::Kind::Int) {
        regs[inst.dest].w[0] = std::ranges::find(set.ints, as_int(regs[inst.args[0]])) != set.ints.end();
      } else if (set.kind == Set::Kind::Ip) {
        const swoc::IPAddr &addr = as_addr(regs[inst.args[0]]);

        regs[inst.dest].w[0] = addr.is_valid() && set.ranges->contains(addr);
      } else {
        regs[inst.dest].w[0] = contains(set, as_sview(regs[inst.args[0]]));
      }
      break;
    }
    // The reader keeps every index below the pool's size, which the transaction's memory is sized to; checked anyway, as
    // a write past the variables would land in the memory's other allocations.
    case Op::LoadV:
      regs[inst.dest].w[0] = 0;
      if (inst.operand < vars.size()) {
        regs[inst.dest].w[0] = vars[inst.operand];
      }
      break;
    case Op::StoreV: {
      int64_t value = as_int(regs[inst.args[0]]);
      int64_t max   = 1;

      switch (prog.vars[inst.operand].type) {
      case VarType::Bool:
        value = value != 0;
        break;
      case VarType::U8:
        max = UINT8_MAX;
        break;
      case VarType::U16:
        max = UINT16_MAX;
        break;
      }
      // As set-state-int8 and set-state-int16 mean to: a value out of range leaves the variable as it was.
      if (value >= 0 && value <= max && inst.operand < vars.size()) {
        vars[inst.operand] = static_cast<uint64_t>(value);
      }
      break;
    }
    // The reader keeps every index below the pool's size; checked anyway, as load.v and store.v check theirs.
    case Op::LoadI:
      regs[inst.dest] = Value{};
      if (inst.operand < prog.ivars.size()) {
        regs[inst.dest] = sview_value(prog.ivars[inst.operand]);
      }
      break;
    case Op::StoreI:
      if (ivars != nullptr && inst.operand < ivars->size()) {
        (*ivars)[inst.operand] = as_sview(regs[inst.args[0]]);
      }
      break;
    case Op::CmpIEq:
      regs[inst.dest].w[0] = as_int(regs[inst.args[0]]) == as_int(regs[inst.args[1]]);
      break;
    case Op::CmpINe:
      regs[inst.dest].w[0] = as_int(regs[inst.args[0]]) != as_int(regs[inst.args[1]]);
      break;
    case Op::CmpILt:
      regs[inst.dest].w[0] = as_int(regs[inst.args[0]]) < as_int(regs[inst.args[1]]);
      break;
    case Op::CmpIGt:
      regs[inst.dest].w[0] = as_int(regs[inst.args[0]]) > as_int(regs[inst.args[1]]);
      break;
    case Op::CmpILe:
      regs[inst.dest].w[0] = as_int(regs[inst.args[0]]) <= as_int(regs[inst.args[1]]);
      break;
    case Op::CmpIGe:
      regs[inst.dest].w[0] = as_int(regs[inst.args[0]]) >= as_int(regs[inst.args[1]]);
      break;
    case Op::CmpSEq:
      regs[inst.dest].w[0] = as_sview(regs[inst.args[0]]) == as_sview(regs[inst.args[1]]);
      break;
    case Op::CmpSNe:
      regs[inst.dest].w[0] = as_sview(regs[inst.args[0]]) != as_sview(regs[inst.args[1]]);
      break;
    case Op::BrT:
      if (regs[inst.args[0]].w[0] != 0) {
        pc = inst.target;
      }
      break;
    case Op::BrF:
      if (regs[inst.args[0]].w[0] == 0) {
        pc = inst.target;
      }
      break;
    case Op::Br:
      pc = inst.target;
      break;
    case Op::Break:
    case Op::Ret:
      return true;
    }
  }
  return true;
}
bool
run(const Program &prog, const Section &sec, CriptsBridge &ops, std::string &fault, swoc::MemSpan<uint64_t> vars)
{
  return execute(prog, sec, &ops, fault, vars, nullptr);
}

std::optional<std::string>
run_instance(const Program &prog, std::vector<std::string> &ivars)
{
  ivars.resize(prog.ivars.size());
  if (!prog.instance) {
    return std::nullopt;
  }
  // A section built without the reader could call a builtin, which would need the transaction there is none of.
  for (const Inst &inst : prog.instance->insts) {
    if (inst.builtin != Builtin::None) {
      return fault_in(inst, "a builtin", "the Instance section calls no builtin");
    }
  }

  std::string fault;

  if (!execute(prog, *prog.instance, nullptr, fault, {}, &ivars)) {
    return fault;
  }
  return std::nullopt;
}
} // namespace hrw4u
