/** @file

  Unit tests for the memory a transaction keeps from its first hook to TXN_CLOSE.

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

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <iterator>
#include <cstdint>
#include <string>
#include <string_view>

using hrw4u::TxnMemory;

TEST_CASE("the variables start at 0 and keep what is stored")
{
  TxnMemory *mem = TxnMemory::create(3);

  REQUIRE(mem->vars().size() == 3);
  CHECK(std::ranges::all_of(mem->vars(), [](uint64_t v) { return v == 0; }));
  mem->vars()[2] = 65535;
  CHECK(mem->vars()[2] == 65535);
  CHECK(reinterpret_cast<uintptr_t>(mem->vars().data()) % alignof(uint64_t) == 0);
  TxnMemory::destroy(mem);
}

TEST_CASE("a transaction that keeps nothing more makes one allocation")
{
  for (size_t n : {0, 1, 120, 500}) {
    TxnMemory *mem = TxnMemory::create(n);

    INFO(n);
    CHECK(std::distance(mem->arena().begin(), mem->arena().end()) == 1);
    TxnMemory::destroy(mem);
  }
}

TEST_CASE("size_for is what create allocates from the arena, the arena itself included")
{
  for (size_t n : {0, 1, 16, 500}) {
    TxnMemory *mem = TxnMemory::create(n);

    INFO(n);
    CHECK(TxnMemory::size_for(n) == mem->arena().allocated_size());
    TxnMemory::destroy(mem);
  }
}

TEST_CASE("a program fits up to its exact size")
{
  auto refusal = [](size_t num_vars, size_t limit) {
    std::string error;

    INFO(num_vars << " in " << limit);
    CHECK_FALSE(TxnMemory::fits(num_vars, limit, error));
    return error;
  };
  std::string error;
  size_t      two = TxnMemory::size_for(2);

  CHECK(TxnMemory::fits(2, two, error));
  CHECK(error.empty());
  CHECK(refusal(2, two - 1) == "the program's variables (2) need " + std::to_string(two) +
                                 " bytes of transaction memory, over prism.txn_memory_limit " + std::to_string(two - 1));
  CHECK(refusal(1, 0) == "the program's variables (1) need " + std::to_string(TxnMemory::size_for(1)) +
                           " bytes of transaction memory, over prism.txn_memory_limit 0");
}

TEST_CASE("a transaction with no variables still gets an arena")
{
  TxnMemory *mem = TxnMemory::create(0);

  CHECK(mem->vars().empty());

  auto copy = mem->arena().localize(std::string_view{"kept until TXN_CLOSE"});

  CHECK(std::string_view(copy.data(), copy.size()) == "kept until TXN_CLOSE");
  TxnMemory::destroy(mem);
}

TEST_CASE("the arena grows past its first block, and the variables stay where they were")
{
  TxnMemory *mem  = TxnMemory::create(2);
  uint64_t  *vars = mem->vars().data();

  mem->vars()[1] = 7;
  for (int i = 0; i < 100; ++i) {
    mem->arena().alloc(1024);
  }
  CHECK(mem->vars().data() == vars);
  CHECK(mem->vars()[1] == 7);
  TxnMemory::destroy(mem);
}

TEST_CASE("destroying no memory does nothing")
{
  TxnMemory::destroy(nullptr);
}
