/** @file

  Resolves the extension calls in a Program against a Registry.

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

#include "bind.h"

#include <optional>

namespace hrw4u
{
namespace
{
  // No ABI type for addresses yet, so such a register can never match an extension's signature.
  std::optional<hrw4u_type>
  abi_type(Type type)
  {
    switch (type) {
    case Type::Bool:
      return HRW4U_TYPE_BOOL;
    case Type::Sview:
      return HRW4U_TYPE_SVIEW;
    case Type::I64:
      return HRW4U_TYPE_I64;
    case Type::Addr:
      break;
    }
    return std::nullopt;
  }

  std::string
  check(const Section &sec, const Inst &inst, const Registry::Entry *entry)
  {
    if (entry == nullptr) {
      return "neither a Cripts binding of this build nor a loaded extension registers it";
    }
    if (inst.op == Op::CallLoad && entry->effect != HRW4U_EFFECT_LOAD) {
      return "it is not a load function, so call.load cannot call it";
    }
    if (inst.op == Op::CallPure && entry->effect == HRW4U_EFFECT_LOAD) {
      return "runs at load only, so only call.load in the Instance section can call it";
    }
    if (inst.op == Op::CallPure && entry->effect != HRW4U_EFFECT_PURE) {
      return "it is not pure, so call.pure cannot call it";
    }
    if (entry->ret != abi_type(sec.reg_types[inst.dest])) {
      return "its return type differs from the destination register's";
    }
    if (entry->params.size() != inst.args.size()) {
      return "it takes " + std::to_string(entry->params.size()) + " arguments, not " + std::to_string(inst.args.size());
    }
    for (size_t i = 0; i < inst.args.size(); ++i) {
      if (entry->params[i] != abi_type(sec.reg_types[inst.args[i]])) {
        return "argument " + std::to_string(i + 1) + " has the wrong type";
      }
    }
    return {};
  }

  bool
  bind_section(Section &sec, const Registry &reg, std::string &error)
  {
    for (Inst &inst : sec.insts) {
      if ((inst.op != Op::CallPure && inst.op != Op::CallLoad) || inst.builtin != Builtin::None) {
        continue;
      }

      const Registry::Entry *entry = reg.find(inst.ext_name);
      std::string            what  = check(sec, inst, entry);

      if (!what.empty()) {
        error = "EXT\"" + inst.ext_name + "\" @" + std::to_string(inst.line) + ":" + std::to_string(inst.col) + ": " + what;
        return false;
      }
      inst.fn = entry->fn;
    }
    return true;
  }
} // namespace

bool
bind_calls(Program &prog, const Registry &reg, std::string &error)
{
  if (prog.instance && !bind_section(*prog.instance, reg, error)) {
    return false;
  }
  for (Section &sec : prog.sections) {
    if (!bind_section(sec, reg, error)) {
      return false;
    }
  }
  return true;
}
} // namespace hrw4u
