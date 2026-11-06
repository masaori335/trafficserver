/** @file

  The bridge between the interpreter and Cripts: what the builtins read from and do to the transaction, each a Cripts
  call.

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

#include "ir.h"

#include "swoc/MemSpan.h"

#include <cstddef>
#include <cstdint>

namespace cripts
{
class Context;
} // namespace cripts

namespace hrw4u
{
class CriptsBridge
{
public:
  /// The Cripts transaction data slot that points at the transaction's memory.
  static constexpr size_t MEMORY_SLOT = 0;

  /// Make the transaction's memory at its first hook, when @a prog keeps anything across hooks.
  static void begin_txn(cripts::Context *ctx, const Program &prog);
  /// Free the transaction's memory, once: at TXN_CLOSE after the section there ran, or, from a remap rule, at REMAP when
  /// the context failed, as Cripts then runs no later hook.
  static void end_txn(cripts::Context *ctx);
  /// The transaction's variables, for run(); empty when its program keeps none.
  static swoc::MemSpan<uint64_t> vars(cripts::Context *ctx);
};
} // namespace hrw4u
