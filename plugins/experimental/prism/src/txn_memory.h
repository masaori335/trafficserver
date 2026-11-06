/** @file

  The memory a transaction keeps from its first hook to TXN_CLOSE.

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

#include "swoc/MemArena.h"
#include "swoc/MemSpan.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace hrw4u
{
/// One arena per transaction, made at its start and destroyed at TXN_CLOSE, which also holds this object and the
/// variables: a single allocation for a transaction that keeps nothing more. What a later store keeps, such as a string
/// variable's bytes, is allocated from arena() and lives until the transaction ends.
class TxnMemory
{
public:
  TxnMemory(const TxnMemory &)            = delete;
  TxnMemory &operator=(const TxnMemory &) = delete;

  /// With @a num_vars variables, each 0 until stored.
  static TxnMemory *create(size_t num_vars);
  /// The bytes create(@a num_vars) allocates from its arena, as its allocated_size() counts them: the arena itself
  /// included, its block header and alignment padding not.
  static size_t size_for(size_t num_vars);
  /// Whether create(@a num_vars) stays within @a limit bytes; false, with @a error, if not.
  static bool fits(size_t num_vars, size_t limit, std::string &error);
  /// Frees everything create() and arena() allocated, @a mem included.
  static void destroy(TxnMemory *mem);

  swoc::MemSpan<uint64_t>
  vars() const
  {
    return _vars;
  }

  swoc::MemArena &
  arena()
  {
    return *_arena;
  }

private:
  explicit TxnMemory(swoc::MemArena *arena) : _arena(arena) {}

  swoc::MemArena         *_arena;
  swoc::MemSpan<uint64_t> _vars;
};
} // namespace hrw4u
