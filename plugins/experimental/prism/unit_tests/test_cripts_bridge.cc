/** @file

  Unit tests for the prism builtins on Cripts, run against the real plugin API and header heaps.

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

#include "ir_reader.h"
#include "test_txn.h"

#include <string>
#include <string_view>
#include <variant>

using cripts_test::Txn;
using namespace hrw4u;

namespace
{
constexpr std::string_view REQUEST = "GET /a HTTP/1.1\r\nHost: example.com\r\nX-Foo: bar\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\n";

Program
parse(std::string_view ir)
{
  std::string error;
  auto        prog = parse_ir(ir, error);

  INFO(error);
  REQUIRE(prog.has_value());
  return std::move(*prog);
}
} // namespace

TEST_CASE("begin_txn() keeps no memory for a program without variables", "[prism][bridge]")
{
  Txn  txn{REQUEST};
  auto prog = parse(R"(hrw4u-ir 1.0

Section[REMAP]:
  IR:
    ret @1:1
)");

  CriptsBridge::begin_txn(txn.context(), prog);
  CHECK(std::get_if<void *>(&txn.context()->data[CriptsBridge::MEMORY_SLOT]) == nullptr);
  CHECK(CriptsBridge::vars(txn.context()).empty());
  CriptsBridge::end_txn(txn.context());
}
