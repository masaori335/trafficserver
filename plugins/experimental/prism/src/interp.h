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

#pragma once

#include "cripts_bridge.h"
#include "ir.h"

#include "swoc/MemSpan.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hrw4u
{
/// @a prog must outlive the call: registers are views into its constants. Returns false when a call faults (an
/// extension's, or a builtin's given an argument it has no meaning for); the section stops there and @a fault says
/// which call and why. @a vars are the transaction's variables, a word for each entry of Program::vars, which keep
/// their values across its hooks; empty for a program that has none.
bool run(const Program &prog, const Section &sec, CriptsBridge &ops, std::string &fault, swoc::MemSpan<uint64_t> vars = {});

/// Runs @a prog's Instance section, with no transaction, storing into @a ivars, which it sizes to Program::ivars.
/// Returns the fault that stopped it, which fails the load, or nothing when it ran or there is no Instance section.
std::optional<std::string> run_instance(const Program &prog, std::vector<std::string> &ivars);

/// The rule context a binding receives is the ops running the call, which live for one hook's run: a binding must not
/// keep them. An extension cannot look through it. The Instance section passes none.
inline hrw4u_rule_ctx *
rule_ctx(CriptsBridge &ops)
{
  return reinterpret_cast<hrw4u_rule_ctx *>(&ops);
}
} // namespace hrw4u
