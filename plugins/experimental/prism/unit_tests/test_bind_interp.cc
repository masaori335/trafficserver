/** @file

  Unit tests for binding extension calls and running them.

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
#include "hrw4u/extension.hpp"
#include "ir_reader.h"
#include "registry.h"
#include "test_txn.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using cripts_test::Txn;
using namespace hrw4u;

namespace
{
constexpr std::string_view REQUEST = "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n";

bool
is_bot(std::string_view ua)
{
  return ua == "Googlebot";
}

bool
takes_bool(bool b)
{
  return b;
}

bool
two_strings(std::string_view a, std::string_view b)
{
  return a == b;
}

std::string
twice(std::string_view s)
{
  return std::string(s) + std::string(s);
}

int64_t
negate(int64_t n)
{
  return -n;
}

int64_t
length_of(std::string_view s)
{
  return static_cast<int64_t>(s.size());
}

bool
always_throws(std::string_view)
{
  throw std::runtime_error("boom");
}

Program
ua_program(std::string_view ua)
{
  std::string text = R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:")" + std::string(ua) +
                     R"(", K1:"X-Bot", K2:"yes", K3:"no"]
  IR:
    %1:sview = const.s K0 @2:7
    %2:bool = call.pure EXT"Example::UA::IsBot", %1 @2:7
    br.f %2, .L7 @2:7
    %3:sview = const.s K1 @2:36
    %4:sview = const.s K2 @2:36
    %5:bool = call.pure EXT"T::SetHeader", %3, %4 @2:36
    br .L10 @2:4
    .L7: %6:sview = const.s K1 @2:72
    %7:sview = const.s K3 @2:72
    %8:bool = call.pure EXT"T::SetHeader", %6, %7 @2:72
    .L10: ret @2:72
)";
  std::string error;
  auto        prog = parse_ir(text, error);

  INFO(error);
  REQUIRE(prog.has_value());
  return std::move(*prog);
}

Calls
run_ua(std::string_view ua)
{
  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&is_bot>("Example::UA::IsBot", HRW4U_EFFECT_PURE);
  m.def<&set_header>("T::SetHeader", HRW4U_EFFECT_PURE);

  Program     prog = ua_program(ua);
  std::string error;

  INFO(error);
  REQUIRE(bind_calls(prog, reg, error));

  Txn         txn{REQUEST};
  std::string fault;

  CHECK(run_on(txn, prog, Hook::SendResponse, fault));
  CHECK(fault.empty());
  return recorded_calls();
}

std::string
bind_error(Registry &reg)
{
  Program     prog = ua_program("Googlebot");
  std::string error;

  CHECK_FALSE(bind_calls(prog, reg, error));
  return error;
}
} // namespace

TEST_CASE("a bot takes the then-branch")
{
  CHECK(run_ua("Googlebot") == Calls{
                                 {"X-Bot", "yes"}
  });
}

TEST_CASE("another client takes the else-branch")
{
  CHECK(run_ua("curl/8.4.0") == Calls{
                                  {"X-Bot", "no"}
  });
}

TEST_CASE("bind rejects")
{
  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&set_header>("T::SetHeader", HRW4U_EFFECT_PURE);

  SECTION("an unregistered name, as a Cripts binding left out of this build is")
  {
    std::string error = bind_error(reg);

    CHECK(error.find("Example::UA::IsBot") != std::string::npos);
    CHECK(error.find("neither a Cripts binding of this build nor a loaded extension registers it") != std::string::npos);
  }
  SECTION("an effectful function in call.pure")
  {
    m.def<&is_bot>("Example::UA::IsBot", HRW4U_EFFECT_EFFECT);
    CHECK(bind_error(reg).find("Example::UA::IsBot") != std::string::npos);
  }
  SECTION("a parameter type mismatch")
  {
    m.def<&takes_bool>("Example::UA::IsBot", HRW4U_EFFECT_PURE);
    CHECK(bind_error(reg).find("Example::UA::IsBot") != std::string::npos);
  }
  SECTION("a return type mismatch")
  {
    m.def<&twice>("Example::UA::IsBot", HRW4U_EFFECT_PURE);
    CHECK(bind_error(reg).find("Example::UA::IsBot") != std::string::npos);
  }
  SECTION("an integer result for a bool register")
  {
    m.def<&length_of>("Example::UA::IsBot", HRW4U_EFFECT_PURE);
    CHECK(bind_error(reg).find("its return type differs from the destination register's") != std::string::npos);
  }
  SECTION("an argument count mismatch")
  {
    m.def<&two_strings>("Example::UA::IsBot", HRW4U_EFFECT_PURE);
    CHECK(bind_error(reg).find("Example::UA::IsBot") != std::string::npos);
  }
}

TEST_CASE("a fault stops the section")
{
  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&always_throws>("Example::UA::IsBot", HRW4U_EFFECT_PURE);
  m.def<&set_header>("T::SetHeader", HRW4U_EFFECT_PURE);

  Program     prog = ua_program("Googlebot");
  std::string error;

  REQUIRE(bind_calls(prog, reg, error));

  Txn         txn{REQUEST};
  std::string fault;

  CHECK_FALSE(run_on(txn, prog, Hook::SendResponse, fault));
  CHECK(fault.find("Example::UA::IsBot") != std::string::npos);
  CHECK(fault.find("boom") != std::string::npos);
  CHECK(recorded_calls().empty());
}

TEST_CASE("a string result outlives the function's next call")
{
  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&twice>("T::Twice", HRW4U_EFFECT_PURE);
  m.def<&set_header>("T::SetHeader", HRW4U_EFFECT_PURE);

  std::string error;
  auto        prog = parse_ir(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"a", K1:"b", K2:"X-A", K3:"X-B"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = call.pure EXT"T::Twice", %1 @1:1
    %3:sview = const.s K1 @2:1
    %4:sview = call.pure EXT"T::Twice", %3 @2:1
    %5:sview = const.s K2 @3:1
    %6:bool = call.pure EXT"T::SetHeader", %5, %2 @3:1
    %7:sview = const.s K3 @4:1
    %8:bool = call.pure EXT"T::SetHeader", %7, %4 @4:1
    ret @4:1
)",
                              error);

  INFO(error);
  REQUIRE(prog.has_value());
  REQUIRE(bind_calls(*prog, reg, error));

  Txn         txn{REQUEST};
  std::string fault;

  CHECK(run_on(txn, *prog, Hook::SendResponse, fault));
  CHECK(recorded_calls() == Calls{
                              {"X-A", "aa"},
                              {"X-B", "bb"},
  });
}

TEST_CASE("an empty string result is an empty value")
{
  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&twice>("T::Twice", HRW4U_EFFECT_PURE);
  m.def<&set_header>("T::SetHeader", HRW4U_EFFECT_PURE);

  std::string error;
  auto        prog = parse_ir(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"", K1:"X-A"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = call.pure EXT"T::Twice", %1 @1:1
    %3:sview = const.s K1 @1:1
    %4:bool = call.pure EXT"T::SetHeader", %3, %2 @1:1
    ret @1:1
)",
                              error);

  INFO(error);
  REQUIRE(prog.has_value());
  REQUIRE(bind_calls(*prog, reg, error));

  Txn         txn{REQUEST};
  std::string fault;

  CHECK(run_on(txn, *prog, Hook::SendResponse, fault));
  CHECK(recorded_calls() == Calls{
                              {"X-A", ""}
  });
}

TEST_CASE("an integer goes into a call and its result comes back as an integer")
{
  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&negate>("T::Negate", HRW4U_EFFECT_PURE);
  m.def<&set_header>("T::SetHeader", HRW4U_EFFECT_PURE);

  std::string error;
  auto        prog = parse_ir(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-N"]
  ints   = [I0:5]
  fmt    = [F0:"{n}" arity=1 lits=["", ""]]
  IR:
    %1:i64 = const.i I0 @1:1
    %2:i64 = call.pure EXT"T::Negate", %1 @1:1
    %3:sview = const.s K0 @1:1
    %4:sview = fmt F0, %2 @1:1
    %5:bool = call.pure EXT"T::SetHeader", %3, %4 @1:1
    ret @1:1
)",
                              error);

  INFO(error);
  REQUIRE(prog.has_value());
  REQUIRE(bind_calls(*prog, reg, error));

  Txn         txn{REQUEST};
  std::string fault;

  CHECK(run_on(txn, *prog, Hook::SendResponse, fault));
  CHECK(recorded_calls() == Calls{
                              {"X-N", "-5"}
  });
}

TEST_CASE("registry rejects a duplicate name")
{
  std::vector<std::string> logs;
  Registry                 reg([&logs](std::string_view msg) { logs.emplace_back(msg); });
  hrw4u::ext::Module       m(reg.host_api(), "test");

  m.def<&is_bot>("Example::UA::IsBot", HRW4U_EFFECT_PURE);
  CHECK_FALSE(m.failed());
  m.def<&is_bot>("Example::UA::IsBot", HRW4U_EFFECT_PURE);
  CHECK(m.failed());
  CHECK_FALSE(logs.empty());
}

TEST_CASE("registry rejects a type it does not know")
{
  Registry         reg([](std::string_view) {});
  std::string      error;
  const auto       unknown  = static_cast<hrw4u_type>(99);
  const hrw4u_type params[] = {unknown};
  hrw4u_fn         fn       = [](hrw4u_rule_ctx *, const uint64_t *, uint64_t *) { return 0; };

  CHECK_FALSE(reg.add({"T::Ret", unknown, 0, nullptr, HRW4U_EFFECT_PURE, fn}, error));
  CHECK(error == "T::Ret: unknown return type");
  CHECK_FALSE(reg.add({"T::Param", HRW4U_TYPE_I64, 1, params, HRW4U_EFFECT_PURE, fn}, error));
  CHECK(error == "T::Param: unknown parameter type");
}

TEST_CASE("bind refuses an integer argument to a string parameter")
{
  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&is_bot>("Example::UA::IsBot", HRW4U_EFFECT_PURE);

  std::string error;
  auto        prog = parse_ir(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  ints   = [I0:1]
  IR:
    %1:i64 = const.i I0 @1:1
    %2:bool = call.pure EXT"Example::UA::IsBot", %1 @1:1
    ret @1:1
)",
                              error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK_FALSE(bind_calls(*prog, reg, error));
  CHECK(error.find("Example::UA::IsBot") != std::string::npos);
}

namespace
{
std::string
load_key(std::string_view name)
{
  return "k:" + std::string(name);
}

std::string
load_fails(std::string_view)
{
  throw std::runtime_error("no such key");
}

// INSTANCE_VARS { key: string = <instance_call>; } SEND_RESPONSE { inbound.resp.X-Key = key; }
Program
instance_program(std::string_view instance_call, std::string_view hook_call = "load.i i0")
{
  std::string text = R"(hrw4u-ir 1.1

Instance:
  ivars  = [i0:sview]
  consts = [K0:"x", K1:"X-Key"]
  IR:
    %1:sview = const.s K0 @2:20
    %2:sview = )" + std::string(instance_call) +
                     R"( @2:20
    store.i i0, %2 @2:5
    ret @2:5

Section[SEND_RESPONSE]:
  IR:
    %1:sview = const.s K1 @4:5
    %2:sview = )" + std::string(hook_call) +
                     R"( @4:20
    %3:bool = call.pure EXT"T::SetHeader", %1, %2 @4:5
    ret @4:5
)";
  std::string error;
  auto        prog = parse_ir(text, error);

  INFO(error);
  REQUIRE(prog.has_value());
  return std::move(*prog);
}
} // namespace

TEST_CASE("the Instance section stores a load function's result, which every hook then loads")
{
  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&load_key>("T::Load", HRW4U_EFFECT_LOAD);
  m.def<&set_header>("T::SetHeader", HRW4U_EFFECT_PURE);

  Program     prog = instance_program(R"(call.load EXT"T::Load", %1)");
  std::string error;

  INFO(error);
  REQUIRE(bind_calls(prog, reg, error));
  CHECK(run_instance(prog, prog.ivars) == std::nullopt);
  CHECK(prog.ivars == std::vector<std::string>{"k:x"});

  for (int i = 0; i < 2; ++i) {
    Txn         txn{REQUEST};
    std::string fault;

    CHECK(run_on(txn, prog, Hook::SendResponse, fault));
    CHECK(recorded_calls() == Calls{
                                {"X-Key", "k:x"}
    });
  }
}

TEST_CASE("a fault in the Instance section is the load's error")
{
  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&load_fails>("T::Load", HRW4U_EFFECT_LOAD);
  m.def<&set_header>("T::SetHeader", HRW4U_EFFECT_PURE);

  Program     prog = instance_program(R"(call.load EXT"T::Load", %1)");
  std::string error;

  INFO(error);
  REQUIRE(bind_calls(prog, reg, error));
  CHECK(run_instance(prog, prog.ivars) == "fault in EXT\"T::Load\" @2:20: no such key");
}

TEST_CASE("bind lets only call.load call a load function, and call.load call only a load function")
{
  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&load_key>("T::Load", HRW4U_EFFECT_LOAD);
  m.def<&twice>("T::Twice", HRW4U_EFFECT_PURE);
  m.def<&set_header>("T::SetHeader", HRW4U_EFFECT_PURE);

  std::string error;

  SECTION("call.pure of a load function in a hook")
  {
    Program prog = instance_program(R"(call.load EXT"T::Load", %1)", R"(call.pure EXT"T::Load", %1)");

    CHECK_FALSE(bind_calls(prog, reg, error));
    CHECK(error == "EXT\"T::Load\" @4:20: runs at load only, so only call.load in the Instance section can call it");
  }
  SECTION("call.pure of a load function in the Instance section")
  {
    Program prog = instance_program(R"(call.pure EXT"T::Load", %1)");

    CHECK_FALSE(bind_calls(prog, reg, error));
    CHECK(error == "EXT\"T::Load\" @2:20: runs at load only, so only call.load in the Instance section can call it");
  }
  SECTION("call.load of a pure function")
  {
    Program prog = instance_program(R"(call.load EXT"T::Twice", %1)");

    CHECK_FALSE(bind_calls(prog, reg, error));
    CHECK(error == "EXT\"T::Twice\" @2:20: it is not a load function, so call.load cannot call it");
  }
  SECTION("a pure function in the Instance section")
  {
    Program prog = instance_program(R"(call.pure EXT"T::Twice", %1)");

    CHECK(bind_calls(prog, reg, error));
    CHECK(run_instance(prog, prog.ivars) == std::nullopt);
    CHECK(prog.ivars == std::vector<std::string>{"xx"});
  }
}

TEST_CASE("a program with no Instance section has nothing to run at load")
{
  Program prog = ua_program("Googlebot");

  CHECK(run_instance(prog, prog.ivars) == std::nullopt);
  CHECK(prog.ivars.empty());
}
