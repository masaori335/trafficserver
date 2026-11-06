/** @file

  Unit tests for the hrw4u interpreter.

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

#include <string>
#include <tuple>
#include <utility>
#include <vector>

using cripts_test::Txn;
using namespace hrw4u;

namespace
{
constexpr std::string_view REQUEST = "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n";

// Binds T::SetHeader, which the programs call to show what they computed.
Program
parse(std::string_view text)
{
  std::string error;
  auto        prog = parse_ir(text, error);

  INFO(error);
  REQUIRE(prog.has_value());

  Registry           reg([](std::string_view) {});
  hrw4u::ext::Module m(reg.host_api(), "test");

  m.def<&set_header>("T::SetHeader", HRW4U_EFFECT_PURE);
  REQUIRE(bind_calls(*prog, reg, error));
  return std::move(*prog);
}

// The transaction's variables as run() takes them, one word for each entry of the program's vars pool.
swoc::MemSpan<uint64_t>
span_of(std::vector<uint64_t> &vars)
{
  return {vars.data(), vars.size()};
}

Calls
run_program(std::string_view text)
{
  Program     prog = parse(text);
  Txn         txn{REQUEST};
  std::string fault;

  CHECK(run_on(txn, prog, Hook::SendResponse, fault));
  return recorded_calls();
}

// Sets X-R: true when `lhs <op> rhs` holds, and nothing otherwise.
Calls
run_cmp(std::string_view op, std::string_view lhs, std::string_view rhs)
{
  return run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:")" + std::string(lhs) +
                     R"(", K1:")" + std::string(rhs) + R"(", K2:"X-R", K3:"true"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = const.s K1 @1:1
    %3:bool = )" + std::string(op) +
                     R"( %1, %2 @1:1
    br.f %3, .L7 @1:1
    %4:sview = const.s K2 @1:1
    %5:sview = const.s K3 @1:1
    %6:bool = call.pure EXT"T::SetHeader", %4, %5 @1:1
    .L7: ret @1:1
)");
}
} // namespace

TEST_CASE("run calls set_header with the program's constants")
{
  CHECK(run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-Foo", K1:"bar"]
  IR:
    %1:sview = const.s K0 @2:4
    %2:sview = const.s K1 @2:4
    %3:bool = call.pure EXT"T::SetHeader", %1, %2 @2:4
    ret @2:4
)") == Calls{
         {"X-Foo", "bar"}
  });
}

TEST_CASE("run makes each call in order")
{
  CHECK(run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-A", K1:"one", K2:"X-B", K3:"two"]
  IR:
    %1:sview = const.s K0 @2:4
    %2:sview = const.s K1 @2:4
    %3:bool = call.pure EXT"T::SetHeader", %1, %2 @2:4
    %4:sview = const.s K2 @3:4
    %5:sview = const.s K3 @3:4
    %6:bool = call.pure EXT"T::SetHeader", %4, %5 @3:4
    ret @3:4
)") == Calls{
         {"X-A", "one"},
         {"X-B", "two"}
  });
}

TEST_CASE("BI_SERVER_RESP_HEADER reads the origin's response header, empty when absent")
{
  Program prog = parse(R"(hrw4u-ir 1.1

Section[READ_RESPONSE]:
  consts = [K0:"Cache-Control"]
  IR:
    %1:sview = const.s K0 @2:8
    %2:sview = call.pure BI_SERVER_RESP_HEADER, %1 @2:8
    %3:bool = call.pure EXT"T::SetHeader", %1, %2 @2:8
    ret @2:8
)");

  auto run_with = [&prog](std::string_view response) {
    Txn         txn{REQUEST};
    std::string fault;

    txn.set_server_response(response);
    CHECK(run_on(txn, prog, Hook::ReadResponse, fault));
    return recorded_calls();
  };

  CHECK(run_with("HTTP/1.1 200 OK\r\n\r\n") == Calls{
                                                 {"Cache-Control", ""}
  });
  CHECK(run_with("HTTP/1.1 200 OK\r\nCache-Control: no-store\r\n\r\n") == Calls{
                                                                            {"Cache-Control", "no-store"}
  });
}

TEST_CASE("BI_CLIENT_HEADER reads the client request, empty when absent")
{
  Program prog = parse(R"(hrw4u-ir 1.1

Section[READ_RESPONSE]:
  consts = [K0:"X-Source", K1:"X-From-Client", K2:"X-None"]
  IR:
    %1:sview = const.s K0 @2:4
    %2:sview = call.pure BI_CLIENT_HEADER, %1 @2:4
    %3:sview = const.s K1 @2:4
    %4:bool = call.pure EXT"T::SetHeader", %3, %2 @2:4
    %5:sview = const.s K2 @3:4
    %6:sview = call.pure BI_CLIENT_HEADER, %5 @3:4
    %7:bool = call.pure EXT"T::SetHeader", %5, %6 @3:4
    ret @3:4
)");

  Txn         txn{"GET /a HTTP/1.1\r\nHost: example.com\r\nX-Source: client\r\n\r\n"};
  std::string fault;

  txn.set_server_response("HTTP/1.1 200 OK\r\nX-Source: origin\r\n\r\n");
  CHECK(run_on(txn, prog, Hook::ReadResponse, fault));
  CHECK(recorded_calls() == Calls{
                              {"X-From-Client", "client"},
                              {"X-None",        ""      }
  });
}

TEST_CASE("cmp.s.eq compares strings for equality")
{
  CHECK(run_cmp("cmp.s.eq", "a", "a") == Calls{
                                           {"X-R", "true"}
  });
  CHECK(run_cmp("cmp.s.eq", "a", "b").empty());
  CHECK(run_cmp("cmp.s.eq", "", "").size() == 1);
  CHECK(run_cmp("cmp.s.eq", "a", "A").empty());
}

TEST_CASE("cmp.s.ne compares strings for inequality")
{
  CHECK(run_cmp("cmp.s.ne", "a", "b") == Calls{
                                           {"X-R", "true"}
  });
  CHECK(run_cmp("cmp.s.ne", "a", "a").empty());
}

TEST_CASE("br.t jumps when the register is true")
{
  // X-R: reached is set only when cmp.s.eq is false, so br.t did not jump.
  auto run_br_t = [](std::string_view lhs, std::string_view rhs) {
    return run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:")" + std::string(lhs) +
                       R"(", K1:")" + std::string(rhs) + R"(", K2:"X-R", K3:"reached"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = const.s K1 @1:1
    %3:bool = cmp.s.eq %1, %2 @1:1
    br.t %3, .L7 @1:1
    %4:sview = const.s K2 @1:1
    %5:sview = const.s K3 @1:1
    %6:bool = call.pure EXT"T::SetHeader", %4, %5 @1:1
    .L7: ret @1:1
)");
  };

  CHECK(run_br_t("a", "a").empty());
  CHECK(run_br_t("a", "b") == Calls{
                                {"X-R", "reached"}
  });
}

TEST_CASE("re.match tests a string against a regex")
{
  auto matches = [](std::string_view subject, std::string_view regex) {
    return !run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:")" + std::string(subject) +
                        R"(", K1:"X-R", K2:"true"]
  regex  = [R0:)" + std::string(regex) +
                        R"(]
  IR:
    %1:sview = const.s K0 @1:1
    %2:bool = re.match %1, R0 @1:1
    br.f %2, .L6 @1:1
    %3:sview = const.s K1 @1:1
    %4:sview = const.s K2 @1:1
    %5:bool = call.pure EXT"T::SetHeader", %3, %4 @1:1
    .L6: ret @1:1
)")
              .empty();
  };

  CHECK(matches("some_path_foo_", "/some_path_(.+)_/"));
  CHECK_FALSE(matches("other", "/some_path_(.+)_/"));
  CHECK(matches("a/b", "/^a\\/b$/"));
  CHECK_FALSE(matches("ABC", "/abc/"));
  CHECK(matches("ABC", "/abc/i"));
}

TEST_CASE("in.set tests membership")
{
  auto member = [](std::string_view subject, std::string_view set) {
    return !run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:")" + std::string(subject) +
                        R"(", K1:"X-R", K2:"true"]
  sets   = [S0:)" + std::string(set) +
                        R"(]
  IR:
    %1:sview = const.s K0 @1:1
    %2:bool = in.set %1, S0 @1:1
    br.f %2, .L6 @1:1
    %3:sview = const.s K1 @1:1
    %4:sview = const.s K2 @1:1
    %5:bool = call.pure EXT"T::SetHeader", %3, %4 @1:1
    .L6: ret @1:1
)")
              .empty();
  };

  CHECK(member("bar", R"(s("foo", "bar"))"));
  CHECK_FALSE(member("ba", R"(s("foo", "bar"))"));
  CHECK_FALSE(member("BAR", R"(s("foo", "bar"))"));
  CHECK(member("BAR", R"(s("foo", "bar") nocase)"));
  CHECK_FALSE(member("", R"(s("foo"))"));
  CHECK_FALSE(member(R"(A\x00c)", R"(s("a\x00b") nocase)"));
  CHECK(member(R"(A\x00B)", R"(s("a\x00b") nocase)"));

  SECTION("match modes, as header_rewrite's [PRE], [SUF], [MID] and [EXT]")
  {
    CHECK(member("Content/TS_ts/a.ts", R"(s("Content/TS_ts/") pre)"));
    CHECK_FALSE(member("x/Content/TS_ts/", R"(s("Content/TS_ts/") pre)"));
    CHECK(member("content/ts_ts/a.ts", R"(s("Content/TS_ts/") pre nocase)"));
    CHECK(member("a/index.m3u8", R"(s("m3u8") suf)"));
    CHECK_FALSE(member("m3u", R"(s("m3u8") suf)"));
    CHECK(member("a/index.m3u8?x", R"(s("/index.m3u8") mid)"));
    CHECK(member("A/INDEX.M3U8", R"(s("/index.m3u8") mid nocase)"));
    CHECK_FALSE(member("a/index.m3u", R"(s("/index.m3u8") mid)"));
    CHECK(member("a/b.M3U8", R"(s("ts", "m3u8") ext nocase)"));
    CHECK_FALSE(member("a/b.m3u8", R"(s("M3U8") ext)"));
    CHECK_FALSE(member("a/b.", R"(s("") ext)"));
    CHECK_FALSE(member("noext", R"(s("noext") ext)"));
    CHECK(member("anything", R"(s("") mid)"));
  }
  SECTION("an empty subject or item, as header_rewrite's matcher takes them")
  {
    CHECK(member("", R"(s("") pre)"));
    CHECK(member("", R"(s("") suf)"));
    CHECK(member("", R"(s("") mid)"));
    CHECK_FALSE(member("", R"(s("") mid nocase)"));
    CHECK(member("x", R"(s("") mid nocase)"));
    CHECK_FALSE(member("", R"(s("a") pre)"));
    CHECK_FALSE(member(".", R"(s("") ext)"));
    CHECK(member(".foo", R"(s("foo") ext)"));
  }
}

TEST_CASE("load.v reads the transaction's variable, false until set")
{
  Program prog = parse(R"(hrw4u-ir 1.1

Section[REMAP]:
  vars   = [v0:bool, v1:bool]
  consts = [K0:"X-foo", K1:"bar"]
  IR:
    %1:bool = load.v v1:bool @6:7
    br.f %1, .L5 @6:7
    %2:sview = const.s K0 @7:8
    %3:sview = const.s K1 @7:8
    %4:bool = call.pure EXT"T::SetHeader", %2, %3 @7:8
    .L5: ret @7:8
)");

  auto run_with = [&prog](std::vector<uint64_t> vars) {
    Txn         txn{REQUEST};
    std::string fault;

    CHECK(run_on(txn, prog, Hook::Remap, fault, span_of(vars)));
    return recorded_calls();
  };

  CHECK(run_with({0, 0}).empty());
  CHECK(run_with({1, 0}).empty());
  CHECK(run_with({
          0, 1
  }) == Calls{{"X-foo", "bar"}});
}

TEST_CASE("store.v sets and clears one variable, and load.v reads it back")
{
  Program prog = parse(R"(hrw4u-ir 1.1

Section[REMAP]:
  vars   = [v0:bool, v1:bool]
  consts = [K0:"X-V1"]
  ints   = [I0:1, I1:0]
  fmt    = [F0:"{v1}" arity=1 lits=["", ""]]
  IR:
    %1:bool = const.i I0 @1:1
    store.v v1:bool, %1 @1:1
    %2:bool = const.i I1 @2:1
    store.v v0:bool, %2 @2:1
    %3:sview = const.s K0 @3:1
    %4:bool = load.v v1:bool @3:1
    %5:sview = fmt F0, %4 @3:1
    %6:bool = call.pure EXT"T::SetHeader", %3, %5 @3:1
    ret @3:1
)");

  Txn                   txn{REQUEST};
  std::string           fault;
  std::vector<uint64_t> vars = {1, 0};

  CHECK(run_on(txn, prog, Hook::Remap, fault, span_of(vars)));
  CHECK(vars == std::vector<uint64_t>{0, 1});
  CHECK(recorded_calls() == Calls{
                              {"X-V1", "TRUE"}
  });
}

TEST_CASE("integer variables keep their range, and load.v reads them as i64")
{
  Program prog = parse(R"(hrw4u-ir 1.1

Section[REMAP]:
  vars   = [v0:bool, v0:u8, v1:u8, v0:u16]
  consts = [K0:"X-V"]
  ints   = [I0:255, I1:256, I2:-1, I3:65535, I4:65536]
  fmt    = [F0:"{a}/{b}/{c}" arity=3 lits=["", "/", "/", ""]]
  IR:
    %1:i64 = const.i I0 @1:1
    store.v v0:u8, %1 @1:1
    %2:i64 = const.i I1 @2:1
    store.v v1:u8, %2 @2:1
    %3:i64 = const.i I2 @3:1
    store.v v1:u8, %3 @3:1
    %4:i64 = const.i I3 @4:1
    store.v v0:u16, %4 @4:1
    %5:i64 = const.i I4 @5:1
    store.v v0:u16, %5 @5:1
    store.v v0:u16, %3 @5:1
    %6:sview = const.s K0 @6:1
    %7:i64 = load.v v0:u8 @6:1
    %8:i64 = load.v v1:u8 @6:1
    %9:i64 = load.v v0:u16 @6:1
    %10:sview = fmt F0, %7, %8, %9 @6:1
    %11:bool = call.pure EXT"T::SetHeader", %6, %10 @6:1
    ret @6:1
)");

  Txn                   txn{REQUEST};
  std::string           fault;
  std::vector<uint64_t> vars = {0, 0, 9, 0};

  CHECK(run_on(txn, prog, Hook::Remap, fault, span_of(vars)));
  // 256 and -1 are out of v1:u8's range, 65536 and -1 out of v0:u16's: each leaves the variable as it was.
  CHECK(recorded_calls() == Calls{
                              {"X-V", "255/9/65535"}
  });
  CHECK(vars == std::vector<uint64_t>{0, 255, 9, 65535});
}

TEST_CASE("variables have no count limit")
{
  std::string vars = "  vars   = [";

  for (int i = 0; i < 100; ++i) {
    if (i > 0) {
      vars += ", ";
    }
    vars += "v" + std::to_string(i) + ":bool";
  }

  Program prog = parse("hrw4u-ir 1.0\n\nSection[REMAP]:\n" + vars +
                       "]\n  ints   = [I0:1]\n  IR:\n"
                       "    %1:bool = const.i I0 @1:1\n    store.v v99:bool, %1 @1:1\n    ret @1:1\n");

  Txn                   txn{REQUEST};
  std::string           fault;
  std::vector<uint64_t> words(100);

  CHECK(run_on(txn, prog, Hook::Remap, fault, span_of(words)));
  CHECK(words[99] == 1);
}

TEST_CASE("load.v and store.v past the transaction's variables read 0 and write nothing")
{
  Program prog = parse(R"(hrw4u-ir 1.1

Section[REMAP]:
  vars   = [v0:bool, v1:bool]
  consts = [K0:"X-V1"]
  ints   = [I0:1]
  fmt    = [F0:"{v1}" arity=1 lits=["", ""]]
  IR:
    %1:bool = const.i I0 @1:1
    store.v v1:bool, %1 @1:1
    %2:sview = const.s K0 @2:1
    %3:bool = load.v v1:bool @2:1
    %4:sview = fmt F0, %3 @2:1
    %5:bool = call.pure EXT"T::SetHeader", %2, %4 @2:1
    ret @2:1
)");

  SECTION("no variables at all")
  {
    Txn         txn{REQUEST};
    std::string fault;

    CHECK(run_on(txn, prog, Hook::Remap, fault));
    CHECK(recorded_calls() == Calls{
                                {"X-V1", "FALSE"}
    });
  }
  SECTION("fewer variables than the program has")
  {
    Txn                   txn{REQUEST};
    std::string           fault;
    std::vector<uint64_t> vars = {7};

    CHECK(run_on(txn, prog, Hook::Remap, fault, span_of(vars)));
    CHECK(vars == std::vector<uint64_t>{7});
    CHECK(recorded_calls() == Calls{
                                {"X-V1", "FALSE"}
    });
  }
}

TEST_CASE("run() refuses a section with more registers than its register file holds")
{
  Program prog = parse(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-Foo", K1:"bar"]
  IR:
    %1:sview = const.s K0 @2:4
    %2:sview = const.s K1 @2:4
    %3:bool = call.pure EXT"T::SetHeader", %1, %2 @2:4
    ret @2:4
)");
  // The reader refuses the 256th register, so the section is changed after it is read.
  prog.sections[0].num_regs = MAX_REGS + 1;

  Txn         txn{REQUEST};
  std::string fault;

  CHECK_FALSE(run_on(txn, prog, Hook::SendResponse, fault));
  CHECK(fault == "a section of 256 registers, more than 255");
  CHECK(recorded_calls().empty());
}

TEST_CASE("in.set tests an integer against an integer set")
{
  auto member = [](int64_t value) {
    return !run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-R", K1:"true"]
  ints   = [I0:)" + std::to_string(value) +
                        R"(]
  sets   = [S0:i(200, 404)]
  IR:
    %1:i64 = const.i I0 @1:1
    %2:bool = in.set %1, S0 @1:1
    br.f %2, .L6 @1:1
    %3:sview = const.s K0 @1:1
    %4:sview = const.s K1 @1:1
    %5:bool = call.pure EXT"T::SetHeader", %3, %4 @1:1
    .L6: ret @1:1
)")
              .empty();
  };

  CHECK(member(200));
  CHECK(member(404));
  CHECK_FALSE(member(201));
  CHECK_FALSE(member(0));
}

TEST_CASE("const.i loads a bool literal")
{
  auto taken = [](int64_t value) {
    return !run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-R", K1:"true"]
  ints   = [I0:)" + std::to_string(value) +
                        R"(]
  IR:
    %1:bool = const.i I0 @1:1
    br.f %1, .L5 @1:1
    %2:sview = const.s K0 @1:1
    %3:sview = const.s K1 @1:1
    %4:bool = call.pure EXT"T::SetHeader", %2, %3 @1:1
    .L5: ret @1:1
)")
              .empty();
  };

  CHECK(taken(1));
  CHECK_FALSE(taken(0));
}

TEST_CASE("break ends the section where it stands")
{
  Calls calls = run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-Before", K1:"yes", K2:"X-After"]
  IR:
    %1:sview = const.s K0 @1:1
    %2:sview = const.s K1 @1:1
    %3:bool = call.pure EXT"T::SetHeader", %1, %2 @1:1
    break @2:1
    %4:sview = const.s K2 @3:1
    %5:bool = call.pure EXT"T::SetHeader", %4, %2 @3:1
    ret @3:1
)");

  CHECK(calls == Calls{
                   {"X-Before", "yes"}
  });
}

TEST_CASE("cmp.i64 compares integers")
{
  // Sets X-R: true when `a <op> b` holds, and nothing otherwise.
  auto holds = [](std::string_view op, int64_t a, int64_t b) {
    return !run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-R", K1:"true"]
  ints   = [I0:)" + std::to_string(a) +
                        ", I1:" + std::to_string(b) + R"(]
  IR:
    %1:i64 = const.i I0 @1:1
    %2:i64 = const.i I1 @1:1
    %3:bool = )" + std::string(op) +
                        R"( %1, %2 @1:1
    br.f %3, .L7 @1:1
    %4:sview = const.s K0 @1:1
    %5:sview = const.s K1 @1:1
    %6:bool = call.pure EXT"T::SetHeader", %4, %5 @1:1
    .L7: ret @1:1
)")
              .empty();
  };

  CHECK(holds("cmp.i64.eq", 404, 404));
  CHECK_FALSE(holds("cmp.i64.eq", 404, 403));
  CHECK(holds("cmp.i64.ne", 404, 403));
  CHECK_FALSE(holds("cmp.i64.ne", 404, 404));
  CHECK(holds("cmp.i64.lt", 399, 400));
  CHECK_FALSE(holds("cmp.i64.lt", 400, 400));
  CHECK(holds("cmp.i64.gt", 401, 400));
  CHECK_FALSE(holds("cmp.i64.gt", 400, 400));
  CHECK(holds("cmp.i64.le", 400, 400));
  CHECK_FALSE(holds("cmp.i64.le", 401, 400));
  CHECK(holds("cmp.i64.ge", 400, 400));
  CHECK_FALSE(holds("cmp.i64.ge", 399, 400));

  // Signed, over the whole i64 range.
  CHECK(holds("cmp.i64.lt", -1, 0));
  CHECK(holds("cmp.i64.lt", -9223372036854775807 - 1, 9223372036854775807));
  CHECK(holds("cmp.i64.gt", 4294967296, 4294967295));
}

TEST_CASE("fmt builds a string from literals and arguments")
{
  // X-R gets fmt's result; %3 is a bool from cmp.s.eq, %4 an integer.
  auto build = [](std::string_view fmt, std::string_view args) {
    Calls calls = run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-R", K1:"abc", K2:"q\"x"]
  ints   = [I0:-42]
  fmt    = [)" + std::string(fmt) +
                              R"(]
  IR:
    %1:sview = const.s K1 @1:1
    %2:sview = const.s K2 @1:1
    %3:bool = cmp.s.eq %1, %1 @1:1
    %4:i64 = const.i I0 @1:1
    %5:sview = fmt F0)" + std::string(args) +
                              R"( @1:1
    %6:sview = const.s K0 @1:1
    %7:bool = call.pure EXT"T::SetHeader", %6, %5 @1:1
    ret @1:1
)");

    REQUIRE(calls.size() == 1);
    return calls[0].second;
  };

  CHECK(build(R"(F0:"lit" arity=0 lits=["lit"])", "") == "lit");
  CHECK(build(R"(F0:"{a}" arity=1 lits=["", ""])", ", %1") == "abc");
  CHECK(build(R"(F0:"<{a}|{b}>" arity=2 lits=["<", "|", ">"])", ", %1, %2") == "<abc|q\"x>");
  CHECK(build(R"(F0:"n={n}" arity=1 lits=["n=", ""])", ", %4") == "n=-42");
  CHECK(build(R"(F0:"{t}" arity=1 lits=["", ""])", ", %3") == "TRUE");
}

TEST_CASE("fmt renders a false bool as FALSE")
{
  Calls calls = run_program(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-R", K1:"a", K2:"b"]
  fmt    = [F0:"{t}" arity=1 lits=["", ""]]
  IR:
    %1:sview = const.s K1 @1:1
    %2:sview = const.s K2 @1:1
    %3:bool = cmp.s.eq %1, %2 @1:1
    %4:sview = fmt F0, %3 @1:1
    %5:sview = const.s K0 @1:1
    %6:bool = call.pure EXT"T::SetHeader", %5, %4 @1:1
    ret @1:1
)");

  CHECK(calls == Calls{
                   {"X-R", "FALSE"}
  });
}

TEST_CASE("BI_CLIENT_URL faults on a field number it has no field for, and stops the section")
{
  for (int64_t field : {-1, 6}) {
    Program prog = parse(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"X-Field"]
  ints   = [I0:)" + std::to_string(field) +
                         R"(]
  IR:
    %1:i64 = const.i I0 @2:7
    %2:sview = call.pure BI_CLIENT_URL, %1 @2:7
    %3:sview = const.s K0 @2:7
    %4:bool = call.pure EXT"T::SetHeader", %3, %2 @2:7
    ret @2:7
)");

    Txn         txn{REQUEST};
    std::string fault;

    INFO(field);
    CHECK_FALSE(run_on(txn, prog, Hook::SendResponse, fault));
    CHECK(fault.find("BI_CLIENT_URL") != std::string::npos);
    CHECK(recorded_calls().empty());
  }
}

TEST_CASE("BI_CLIENT_URL_PARAM finds a query parameter as header_rewrite does")
{
  auto param = [](std::string_view query, std::string_view name) {
    Program prog = parse(R"(hrw4u-ir 1.1

Section[REMAP]:
  consts = [K0:")" + std::string(name) +
                         R"(", K1:"X-P"]
  IR:
    %1:sview = const.s K0 @2:4
    %2:sview = call.pure BI_CLIENT_URL_PARAM, %1 @2:4
    %3:sview = const.s K1 @2:4
    %4:bool = call.pure EXT"T::SetHeader", %3, %2 @2:4
    ret @2:4
)");

    Txn         txn{"GET http://example.com/?" + std::string(query) + " HTTP/1.1\r\nHost: example.com\r\n\r\n"};
    auto       &st = txn.sm().t_state;
    std::string fault;

    // As HttpTransact keeps it once it has read the request.
    st.unmapped_url.create(txn.client_url().m_heap);
    st.unmapped_url.copy(&txn.client_url());
    CHECK(run_on(txn, prog, Hook::Remap, fault));
    REQUIRE(recorded_calls().size() == 1);
    return recorded_calls()[0].second;
  };

  CHECK(param("r=usw2&pbr=true", "pbr") == "true");
  CHECK(param("r=usw2&pbr=true", "r") == "usw2");
  CHECK(param("r=1&r=2", "r") == "2");
  CHECK(param("flag&x=1", "flag").empty());
  CHECK(param("my%20param=1", "my param").empty());
  CHECK(param("R=1", "r").empty());
  CHECK(param("", "r").empty());
}
