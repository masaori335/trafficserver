/** @file

  The in-memory form of an hrw4u-ir program.

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

#include "ir.h"

namespace hrw4u
{
const Section *
Program::find(Hook hook) const
{
  for (const auto &sec : sections) {
    if (sec.hook == hook) {
      return &sec;
    }
  }
  return nullptr;
}

bool
Program::runs_in(bool global, std::string &error) const
{
  for (const auto &sec : sections) {
    bool before_remap = sec.hook == Hook::TxnStart || sec.hook == Hook::ReadRequest || sec.hook == Hook::PreRemap;

    if (global && sec.hook == Hook::Remap) {
      error = "a REMAP section runs only from a remap rule";
      return false;
    }
    if (!global && before_remap) {
      error = "a TXN_START, READ_REQUEST or PRE_REMAP section runs only from plugin.config";
      return false;
    }
  }
  return true;
}

const std::string *
Program::const_arg(const Section &sec, uint32_t reg) const
{
  for (const auto &inst : sec.insts) {
    if (inst.dest == reg) {
      if (inst.op != Op::ConstS) {
        return nullptr;
      }
      return &consts[inst.operand];
    }
  }
  return nullptr;
}
} // namespace hrw4u
