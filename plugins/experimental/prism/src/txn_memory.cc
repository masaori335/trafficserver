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

#include "txn_memory.h"

#include <algorithm>
#include <memory>

namespace hrw4u
{
TxnMemory *
TxnMemory::create(size_t num_vars)
{
  // Room for this object and the variables, so that a transaction with nothing else to keep makes one allocation.
  auto *arena = swoc::MemArena::construct_self_contained(sizeof(TxnMemory) + alignof(uint64_t) + num_vars * sizeof(uint64_t));
  auto *mem   = new (arena->alloc(sizeof(TxnMemory), alignof(TxnMemory)).data()) TxnMemory(arena);

  mem->_vars = arena->alloc_span<uint64_t>(num_vars);
  std::ranges::fill(mem->_vars, 0);
  return mem;
}

size_t
TxnMemory::size_for(size_t num_vars)
{
  return sizeof(swoc::MemArena) + sizeof(TxnMemory) + num_vars * sizeof(uint64_t);
}

bool
TxnMemory::fits(size_t num_vars, size_t limit, std::string &error)
{
  size_t size = size_for(num_vars);

  if (size > limit) {
    error = "the program's variables (" + std::to_string(num_vars) + ") need " + std::to_string(size) +
            " bytes of transaction memory, over prism.txn_memory_limit " + std::to_string(limit);
    return false;
  }
  return true;
}

void
TxnMemory::destroy(TxnMemory *mem)
{
  if (mem == nullptr) {
    return;
  }
  swoc::MemArena *arena = mem->_arena;

  std::destroy_at(mem);
  swoc::MemArena::destroyer(arena);
}
} // namespace hrw4u
