/** @file

  Unit tests for the hrw4u IR text reader.

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

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

using namespace hrw4u;

namespace
{
// Two constants and an instruction that reads them both, on line 8.
constexpr std::string_view COMPARE_IR = R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"X-Foo", K1:"bar"]
  IR:
    %1:sview = const.s K0 @2:4
    %2:sview = const.s K1 @2:4
    %3:bool = cmp.s.eq %1, %2 @2:4
    ret @2:4
)";

// The shape the front end would write for:
//   SEND_RESPONSE { if Example::UA::IsBot("Googlebot") { inbound.resp.X-Bot = "yes"; } else { inbound.resp.X-Bot = "no"; } }
// with each arm's header set a compare of the two strings the arm writes.
constexpr std::string_view UA_IR = R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"Googlebot", K1:"X-Bot", K2:"yes", K3:"no"]
  IR:
    %1:sview = const.s K0 @2:7
    %2:bool = call.pure EXT"Example::UA::IsBot", %1 @2:7
    br.f %2, .L7 @2:7
    %3:sview = const.s K1 @2:36
    %4:sview = const.s K2 @2:36
    %5:bool = cmp.s.eq %3, %4 @2:36
    br .L10 @2:4
    .L7: %6:sview = const.s K1 @2:72
    %7:sview = const.s K3 @2:72
    %8:bool = cmp.s.eq %6, %7 @2:72
    .L10: ret @2:72
)";

// The lines of @a ir, without their newlines.
std::vector<std::string>
lines_of(std::string_view ir)
{
  std::vector<std::string> lines;

  while (!ir.empty()) {
    auto end = ir.find('\n');

    lines.emplace_back(ir.substr(0, end));
    if (end == std::string_view::npos) {
      break;
    }
    ir.remove_prefix(end + 1);
  }
  return lines;
}

std::string
text_of(const std::vector<std::string> &lines)
{
  std::string text;

  for (const auto &line : lines) {
    text += line;
    text += '\n';
  }
  return text;
}

// 1-based line numbers, matching the reader's error messages.
std::string
replace_line(size_t line, const std::string &with, std::string_view ir = COMPARE_IR)
{
  auto lines = lines_of(ir);

  lines[line - 1] = with;
  return text_of(lines);
}

std::string
insert_line(size_t line, const std::string &text, std::string_view ir = COMPARE_IR)
{
  auto lines = lines_of(ir);

  lines.insert(lines.begin() + (line - 1), text);
  return text_of(lines);
}

void
require_error_at(const std::string &text, size_t line)
{
  std::string error;
  auto        prog = parse_ir(text, error);

  CHECK_FALSE(prog.has_value());
  CHECK(error.starts_with("line " + std::to_string(line) + ":"));
}

// @a ir, whose first section header is on line 3, with that section in @a hook instead.
std::string
in_hook(std::string_view hook, std::string_view ir)
{
  return replace_line(3, "Section[" + std::string(hook) + "]:", ir);
}

constexpr std::string_view EVERY_HOOK[] = {"TXN_START",    "READ_REQUEST",  "PRE_REMAP",     "REMAP",
                                           "SEND_REQUEST", "READ_RESPONSE", "SEND_RESPONSE", "TXN_CLOSE"};
// Every hook but TXN_START, which comes before the client's request is read.
constexpr std::string_view MESSAGE_HOOKS[] = {"READ_REQUEST",  "PRE_REMAP",     "REMAP",    "SEND_REQUEST",
                                              "READ_RESPONSE", "SEND_RESPONSE", "TXN_CLOSE"};
} // namespace

TEST_CASE("parse_ir reads the compare program")
{
  std::string error;
  auto        prog = parse_ir(std::string(COMPARE_IR), error);

  REQUIRE(prog.has_value());
  CHECK(error.empty());
  CHECK(prog->consts == std::vector<std::string>{"X-Foo", "bar"});
  REQUIRE(prog->sections.size() == 1);

  const Section &sec = prog->sections[0];

  CHECK(sec.hook == Hook::SendResponse);
  CHECK(sec.num_regs == 4);
  REQUIRE(sec.insts.size() == 4);

  CHECK(sec.insts[0].op == Op::ConstS);
  CHECK(sec.insts[0].dest == 1);
  CHECK(sec.insts[0].operand == 0);
  CHECK(sec.insts[0].line == 2);
  CHECK(sec.insts[0].col == 4);

  CHECK(sec.insts[1].op == Op::ConstS);
  CHECK(sec.insts[1].dest == 2);
  CHECK(sec.insts[1].operand == 1);

  CHECK(sec.insts[2].op == Op::CmpSEq);
  CHECK(sec.insts[2].dest == 3);
  CHECK(sec.insts[2].args == std::vector<uint32_t>{1, 2});

  CHECK(sec.insts[3].op == Op::Ret);

  CHECK(prog->find(Hook::SendResponse) == &sec);
}

TEST_CASE("parse_ir reads a section of each supported hook")
{
  struct Case {
    std::string header;
    Hook        hook;
  };
  const Case cases[] = {
    {"Section[TXN_START]:",     Hook::TxnStart    },
    {"Section[READ_REQUEST]:",  Hook::ReadRequest },
    {"Section[PRE_REMAP]:",     Hook::PreRemap    },
    {"Section[REMAP]:",         Hook::Remap       },
    {"Section[SEND_REQUEST]:",  Hook::SendRequest },
    {"Section[READ_RESPONSE]:", Hook::ReadResponse},
    {"Section[SEND_RESPONSE]:", Hook::SendResponse},
    {"Section[TXN_CLOSE]:",     Hook::TxnClose    },
  };

  for (const Case &c : cases) {
    std::string error;
    auto        prog = parse_ir("hrw4u-ir 1.0\n\n" + c.header + "\n  IR:\n    ret @1:1\n", error);

    INFO(c.header << ": " << error);
    REQUIRE(prog.has_value());
    REQUIRE(prog->sections.size() == 1);
    CHECK(prog->sections[0].hook == c.hook);
    CHECK(prog->find(c.hook) == &prog->sections[0]);
  }
}

TEST_CASE("the hooks before remap run only from plugin.config, REMAP only from a remap rule")
{
  auto program = [](std::string_view hook) {
    std::string error;
    auto        prog = parse_ir("hrw4u-ir 1.0\n\nSection[" + std::string(hook) + "]:\n  IR:\n    ret @1:1\n", error);

    INFO(error);
    REQUIRE(prog.has_value());
    return std::move(*prog);
  };
  std::string error;

  for (auto hook : {"TXN_START", "READ_REQUEST", "PRE_REMAP"}) {
    INFO(hook);
    CHECK(program(hook).runs_in(true, error));
    CHECK_FALSE(program(hook).runs_in(false, error));
    CHECK(error == "a TXN_START, READ_REQUEST or PRE_REMAP section runs only from plugin.config");
  }
  CHECK(program("REMAP").runs_in(false, error));
  CHECK_FALSE(program("REMAP").runs_in(true, error));
  CHECK(error == "a REMAP section runs only from a remap rule");
  for (auto hook : {"SEND_REQUEST", "READ_RESPONSE", "SEND_RESPONSE", "TXN_CLOSE"}) {
    INFO(hook);
    CHECK(program(hook).runs_in(true, error));
    CHECK(program(hook).runs_in(false, error));
  }
}

TEST_CASE("parse_ir reads a section per hook, pools under the first")
{
  constexpr std::string_view two = R"(hrw4u-ir 1.0

Section[SEND_REQUEST]:
  consts = [K0:"X-Foo", K1:"bar"]
  IR:
    %1:sview = const.s K0 @2:4
    %2:sview = const.s K1 @2:4
    %3:bool = cmp.s.eq %1, %2 @2:4
    ret @2:4

Section[SEND_RESPONSE]:
  IR:
    %1:sview = const.s K1 @5:4
    %2:bool = cmp.s.eq %1, %1 @5:4
    ret @5:4
)";

  std::string error;
  auto        prog = parse_ir(std::string(two), error);

  INFO(error);
  REQUIRE(prog.has_value());
  REQUIRE(prog->sections.size() == 2);
  CHECK(prog->find(Hook::SendRequest) == &prog->sections[0]);
  CHECK(prog->find(Hook::SendResponse) == &prog->sections[1]);
  CHECK(prog->sections[1].num_regs == 3);
  CHECK(prog->sections[1].insts[0].operand == 1);

  SECTION("the same hook twice is refused")
  {
    require_error_at(replace_line(11, "Section[SEND_REQUEST]:", two), 11);
  }
  SECTION("a pool under a later section is refused")
  {
    require_error_at(insert_line(12, "  ints   = [I0:1]", two), 12);
  }
  SECTION("a section that does not end with ret is refused")
  {
    auto lines = lines_of(two);

    lines.erase(lines.begin() + 8);
    require_error_at(text_of(lines), 10);
  }
  SECTION("labels count from the section's own first instruction")
  {
    auto lines = lines_of(two);

    lines.insert(lines.begin() + 13, "    br .L3 @5:4");
    lines[15] = "    .L3: ret @5:4";

    std::string error;
    auto        labelled = parse_ir(text_of(lines), error);

    INFO(error);
    CHECK(labelled.has_value());
  }
  SECTION("a branch may not leave its section")
  {
    auto lines = lines_of(two);

    lines.insert(lines.begin() + 8, "    br .L5 @2:4");
    require_error_at(text_of(lines), 9);
  }
}

TEST_CASE("escapes")
{
  std::string error;
  auto        prog = parse_ir(replace_line(4, R"(  consts = [K0:"a\"b\\c\x41\t", K1:"bar"])"), error);

  REQUIRE(prog.has_value());
  CHECK(prog->consts[0] == "a\"b\\cA\t");
}

TEST_CASE("trailing newline is optional and trailing blanks are skipped")
{
  std::string error;
  auto        text = std::string(COMPARE_IR);

  SECTION("no trailing newline")
  {
    text.pop_back();
    CHECK(parse_ir(text, error).has_value());
  }
  SECTION("trailing blank lines")
  {
    text += "\n\n";
    CHECK(parse_ir(text, error).has_value());
  }
}

TEST_CASE("rejects what step 1 does not run")
{
  SECTION("another pool")
  {
    require_error_at(insert_line(5, "  tables = [T0:x]"), 5);
  }
  SECTION("another opcode")
  {
    require_error_at(insert_line(9, "    %4:bool = call.v BI_X, %1 @1:1"), 9);
  }
  SECTION("another builtin")
  {
    require_error_at(insert_line(9, "    %4:sview = call.pure BI_NO_SUCH_BUILTIN, %1 @1:1"), 9);
  }
  SECTION("another hook")
  {
    require_error_at(replace_line(3, "Section[POST_REMAP]:"), 3);
  }
  SECTION("a label")
  {
    require_error_at(replace_line(9, "    .L4: ret @1:1"), 9);
  }
}

TEST_CASE("an IR of this version or of this major with no minor loads but another major or a newer minor does not")
{
  auto error_of = [](const std::string &version_line) {
    std::string error;
    auto        prog = parse_ir(replace_line(1, version_line), error);

    CHECK(prog.has_value() == error.empty());
    return error;
  };

  CHECK(error_of("hrw4u-ir 1.0").empty());
  CHECK(error_of("hrw4u-ir 1").empty());
  CHECK(error_of("hrw4u-ir 1.1").empty());
  CHECK(error_of("hrw4u-ir 1.2") == "line 1: IR version 1.2 is newer than 1.1, which this prism.so reads");
  CHECK(error_of("hrw4u-ir 2.0") == "line 1: IR version 2.0 has another major than 1.1, which this prism.so reads");
  CHECK(error_of("hrw4u-ir 0.9") == "line 1: IR version 0.9 has another major than 1.1, which this prism.so reads");
  for (const char *line : {"hrw4u-ir", "hrw4u-ir 1.", "hrw4u-ir .0", "hrw4u-ir 1.-1", "hrw4u-ir  1.0", "hrw4u-ir 1.0.0",
                           "hrw4u-ir 1.0 ", "hrw4u-ir -1.0", "hrw4u-ir v1", "hrw4u-ir 4294967296.0"}) {
    INFO(line);
    CHECK(error_of(line) == "line 1: expected 'hrw4u-ir <major>.<minor>'");
  }
}

namespace
{
// What the compiler would write for:
//   INSTANCE_VARS { g2o_secret: string = prism::Crypto::Hex::Decode(prism::File::Line::Read("g2o_secret.hex")); }
//   SEND_REQUEST { outbound.req.X-Secret = g2o_secret; }
// with the header set a compare of its name and the secret.
constexpr std::string_view INSTANCE_IR = R"(hrw4u-ir 1.1

Instance:
  ivars  = [i0:sview]
  consts = [K0:"g2o_secret.hex", K1:"X-Secret"]
  IR:
    %1:sview = const.s K0 @2:43
    %2:sview = call.load EXT"prism::File::Line::Read", %1 @2:43
    %3:sview = call.pure EXT"prism::Crypto::Hex::Decode", %2 @2:20
    store.i i0, %3 @2:5
    ret @2:5

Section[SEND_REQUEST]:
  IR:
    %1:sview = const.s K1 @9:5
    %2:sview = load.i i0 @9:60
    %3:bool = cmp.s.eq %1, %2 @9:5
    ret @9:5
)";

void
require_error(const std::string &text, const std::string &expected)
{
  std::string error;
  auto        prog = parse_ir(text, error);

  CHECK_FALSE(prog.has_value());
  CHECK(error == expected);
}
} // namespace

TEST_CASE("parse_ir reads an Instance section, which stores what the hooks load")
{
  std::string error;
  auto        prog = parse_ir(std::string(INSTANCE_IR), error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->ivars.size() == 1);
  CHECK(prog->consts == std::vector<std::string>{"g2o_secret.hex", "X-Secret"});
  REQUIRE(prog->instance.has_value());
  REQUIRE(prog->sections.size() == 1);
  CHECK(prog->sections[0].hook == Hook::SendRequest);

  const Section &inst = *prog->instance;

  REQUIRE(inst.insts.size() == 5);
  CHECK(inst.insts[1].op == Op::CallLoad);
  CHECK(inst.insts[1].ext_name == "prism::File::Line::Read");
  CHECK(inst.insts[1].args == std::vector<uint32_t>{1});
  CHECK(inst.insts[2].op == Op::CallPure);
  CHECK(inst.insts[2].ext_name == "prism::Crypto::Hex::Decode");
  CHECK(inst.insts[3].op == Op::StoreI);
  CHECK(inst.insts[3].operand == 0);
  CHECK(inst.insts[3].args == std::vector<uint32_t>{3});

  const Inst &load = prog->sections[0].insts[1];

  CHECK(load.op == Op::LoadI);
  CHECK(load.operand == 0);
  CHECK(prog->sections[0].reg_types[load.dest] == Type::Sview);
}

TEST_CASE("an IR that says 1.0 cannot use what 1.1 adds")
{
  require_error(replace_line(1, "hrw4u-ir 1.0", INSTANCE_IR), "line 3: 'Instance:' needs hrw4u-ir 1.1");
  require_error(insert_line(9, "    %4:sview = load.i i0 @1:1"), "line 9: load.i needs hrw4u-ir 1.1");
  require_error(insert_line(9, "    store.i i0, %1 @1:1"), "line 9: store.i needs hrw4u-ir 1.1");
  require_error(insert_line(9, R"(    %4:sview = call.load EXT"x", %1 @1:1)"), "line 9: call.load needs hrw4u-ir 1.1");
}

TEST_CASE("a call to a binding needs hrw4u-ir 1.1, except the Geo bindings")
{
  SECTION("a non-Geo binding at 1.0")
  {
    require_error(replace_line(1, "hrw4u-ir 1.0", UA_IR), "line 7: 'call.pure EXT\"Example::UA::IsBot\"' needs hrw4u-ir 1.1");
  }
  SECTION("a non-Geo binding at 1.1")
  {
    std::string error;

    CHECK(parse_ir(std::string(UA_IR), error).has_value());
  }
  SECTION("each Geo binding at 1.0")
  {
    struct Geo {
      std::string_view name;
      std::string_view type;
    };

    for (const Geo &geo : {
           Geo{"cripts::Geo::Country", "sview"},
           Geo{"cripts::Geo::ASN",     "i64"  },
           Geo{"cripts::Geo::ASNName", "sview"}
    }) {
      std::string error;
      std::string ir = "hrw4u-ir 1.0\n\nSection[SEND_RESPONSE]:\n  IR:\n    %1:" + std::string(geo.type) + " = call.pure EXT\"" +
                       std::string(geo.name) + "\" @2:4\n    ret @2:4\n";

      INFO(geo.name << ": " << error);
      CHECK(parse_ir(ir, error).has_value());
    }
  }
}

TEST_CASE("the Instance section and the hooks keep to their own instructions")
{
  SECTION("store.i in a hook")
  {
    require_error(replace_line(16, "    store.i i0, %1 @9:60", INSTANCE_IR), "line 16: store.i runs only in the Instance section");
  }
  SECTION("call.load in a hook")
  {
    require_error(replace_line(16, R"(    %2:sview = call.load EXT"x", %1 @9:60)", INSTANCE_IR),
                  "line 16: call.load runs only in the Instance section");
  }
  SECTION("load.i in the Instance section")
  {
    require_error(insert_line(11, "    %4:sview = load.i i0 @2:5", INSTANCE_IR),
                  "line 11: load.i does not run in the Instance section");
  }
  SECTION("a comparison or a branch in the Instance section")
  {
    require_error(insert_line(11, "    %4:bool = cmp.s.eq %1, %3 @2:5", INSTANCE_IR),
                  "line 11: cmp.s.eq does not run in the Instance section");
    require_error(insert_line(11, "    br .L6 @2:5", INSTANCE_IR), "line 11: br does not run in the Instance section");
  }
}

TEST_CASE("each instance variable is declared, then stored once from a string")
{
  SECTION("load.i of an undeclared variable")
  {
    require_error(replace_line(16, "    %2:sview = load.i i1 @9:60", INSTANCE_IR),
                  "line 16: instance variable i1 is not in the pool");
  }
  SECTION("a second store.i")
  {
    require_error(insert_line(11, "    store.i i0, %2 @2:5", INSTANCE_IR), "line 11: i0 is stored twice");
  }
  SECTION("no store.i")
  {
    auto lines = lines_of(INSTANCE_IR);

    lines.erase(lines.begin() + 9);
    require_error(text_of(lines), "line 12: i0 is never stored");
  }
  SECTION("store.i of a register that is not a string")
  {
    auto lines = lines_of(INSTANCE_IR);

    lines.insert(lines.begin() + 5, "  ints   = [I0:1]");
    lines.insert(lines.begin() + 10, "    %4:i64 = const.i I0 @2:5");
    lines[11] = "    store.i i0, %4 @2:5";
    require_error(text_of(lines), "line 12: register %4 is not a string, which an instance variable holds");
  }
  SECTION("an instance variable of another type")
  {
    require_error(replace_line(4, "  ivars  = [i0:i64]", INSTANCE_IR), "line 4: instance variable i0 must be an sview");
  }
  SECTION("instance variables out of order")
  {
    require_error(replace_line(4, "  ivars  = [i1:sview]", INSTANCE_IR), "line 4: instance variable i1 out of order");
  }
  SECTION("an ivars pool under a hook section")
  {
    require_error(insert_line(4, "  ivars  = [i0:sview]"), "line 4: the ivars pool comes under 'Instance:' only");
  }
}

TEST_CASE("the Instance section comes first, once")
{
  constexpr std::string_view hook_first = R"(hrw4u-ir 1.1

Section[SEND_REQUEST]:
  IR:
    ret @1:1

Instance:
  IR:
    ret @1:1
)";

  require_error(std::string(hook_first), "line 7: 'Instance:' comes before every hook's section");
  require_error(insert_line(12, "Instance:\n  IR:\n    ret @1:1\n", INSTANCE_IR), "line 12: a second 'Instance:' section");
}

TEST_CASE("rejects out-of-range and use-before-def")
{
  SECTION("constant index out of range")
  {
    require_error_at(replace_line(7, "    %2:sview = const.s K5 @2:4"), 7);
  }
  SECTION("register read before it is written")
  {
    require_error_at(replace_line(8, "    %3:bool = cmp.s.eq %1, %9 @2:4"), 8);
  }
  SECTION("register written twice")
  {
    require_error_at(replace_line(7, "    %1:sview = const.s K1 @2:4"), 7);
  }
  SECTION("ret not last")
  {
    require_error_at(insert_line(9, "    ret @2:4"), 10);
  }
  SECTION("largest register number")
  {
    require_error_at(replace_line(7, "    %4294967295:sview = const.s K1 @2:4"), 7);
  }
  SECTION("sparse register number")
  {
    require_error_at(replace_line(7, "    %100000000:sview = const.s K1 @2:4"), 7);
  }
}

TEST_CASE("a section has at most 255 registers")
{
  // Line 6 holds %1, so %n is on line 5 + n.
  auto section_of = [](uint32_t regs) {
    std::string text = "hrw4u-ir 1.0\n\nSection[SEND_RESPONSE]:\n  consts = [K0:\"X\"]\n  IR:\n";

    for (uint32_t reg = 1; reg <= regs; ++reg) {
      text += "    %" + std::to_string(reg) + ":sview = const.s K0 @1:1\n";
    }
    return text + "    ret @1:1\n";
  };
  std::string error;

  CHECK(parse_ir(section_of(255), error).has_value());
  CHECK(error.empty());
  CHECK(parse_ir(section_of(256), error) == std::nullopt);
  CHECK(error == "line 261: a section has at most 255 registers");
}

TEST_CASE("a register is read only where every path to the read has written it")
{
  auto lines = lines_of(UA_IR);

  SECTION("on the arm a branch skips to, a register of the other arm")
  {
    require_error_at(replace_line(15, "    %8:bool = cmp.s.eq %3, %7 @2:72", UA_IR), 15);
  }
  SECTION("after the arms join, a register of one arm")
  {
    lines[15] = "    .L10: %9:bool = cmp.s.eq %3, %4 @2:72";
    lines.push_back("    ret @2:72");
    require_error_at(text_of(lines), 16);
  }
  SECTION("on both arms and after the join, a register written before the branch")
  {
    lines[14] = "    %8:bool = cmp.s.eq %1, %7 @2:72";
    lines[15] = "    .L10: %9:bool = cmp.s.eq %1, %1 @2:72";
    lines.push_back("    ret @2:72");

    std::string error;

    CHECK(parse_ir(text_of(lines), error).has_value());
    CHECK(error.empty());
  }
  SECTION("after the join, a register of one arm when the other arm breaks, so its branch to the join never runs")
  {
    lines[10] = "    break @2:36";
    lines[12] = "    .L7: %5:sview = const.s K1 @2:72";
    lines[13] = "    %6:sview = const.s K3 @2:72";
    lines[14] = "    %7:bool = cmp.s.eq %5, %6 @2:72";
    lines[15] = "    .L10: %8:bool = cmp.s.eq %5, %6 @2:72";
    lines.push_back("    ret @2:72");

    std::string error;

    CHECK(parse_ir(text_of(lines), error).has_value());
    CHECK(error.empty());
  }
}

TEST_CASE("where two branches meet, a register is written only if both have written it")
{
  SECTION("the first branch read has written it and the second has not")
  {
    require_error_at(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"Googlebot", K1:"X-Bot"]
  IR:
    %1:sview = const.s K0 @2:7
    %2:bool = call.pure EXT"Example::UA::IsBot", %1 @2:7
    br.f %2, .L5 @2:7
    %3:sview = const.s K1 @2:36
    br.t %2, .L7 @2:36
    .L5: br.f %2, .L7 @2:36
    break @2:36
    .L7: %4:bool = cmp.s.eq %1, %3 @2:72
    ret @2:72
)",
                     13);
  }
  SECTION("both have written it")
  {
    std::string error;

    CHECK(parse_ir(R"(hrw4u-ir 1.1

Section[SEND_RESPONSE]:
  consts = [K0:"Googlebot", K1:"X-Bot"]
  IR:
    %1:sview = const.s K0 @2:7
    %2:bool = call.pure EXT"Example::UA::IsBot", %1 @2:7
    %3:sview = const.s K1 @2:36
    br.f %2, .L5 @2:7
    br.t %2, .L7 @2:36
    .L5: br.f %2, .L7 @2:36
    break @2:36
    .L7: %4:bool = cmp.s.eq %1, %3 @2:72
    ret @2:72
)",
                   error)
            .has_value());
    CHECK(error.empty());
  }
}

TEST_CASE("a register written where no path reaches is not written once a branch reaches the code again")
{
  require_error_at(R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"X-Foo", K1:"bar"]
  IR:
    %1:sview = const.s K0 @2:4
    br .L3 @2:4
    %2:sview = const.s K1 @2:4
    .L3: %3:bool = cmp.s.eq %1, %2 @2:4
    ret @2:4
)",
                   9);
}

TEST_CASE("where no path reaches, a register no instruction has written yet is still refused")
{
  require_error_at(R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"X-Foo", K1:"bar"]
  IR:
    %1:sview = const.s K0 @2:4
    br .L3 @2:4
    %2:bool = cmp.s.eq %1, %3 @2:4
    .L3: ret @2:4
)",
                   8);
}

TEST_CASE("the destination's type must be what the instruction writes")
{
  SECTION("const.s into a bool")
  {
    require_error_at(replace_line(6, "    %1:bool = const.s K0 @2:4"), 6);
  }
  SECTION("const.i into a string")
  {
    auto lines = lines_of(COMPARE_IR);

    lines[5] = "    %1:sview = const.i I0 @2:4";
    lines.insert(lines.begin() + 4, "  ints   = [I0:1]");
    require_error_at(text_of(lines), 7);
  }
  SECTION("cmp into an integer")
  {
    require_error_at(replace_line(7, "    %2:i64 = cmp.s.eq %1, %1 @2:7", UA_IR), 7);
  }
  SECTION("an unknown type")
  {
    require_error_at(replace_line(6, "    %1:str = const.s K0 @2:4"), 6);
  }
}

TEST_CASE("load_ir_file names a missing path")
{
  std::string error;
  auto        prog = load_ir_file("/nonexistent/x.ir", error);

  CHECK_FALSE(prog.has_value());
  CHECK(error.find("/nonexistent/x.ir") != std::string::npos);
}

TEST_CASE("parse_ir reads the User-Agent program")
{
  std::string error;
  auto        prog = parse_ir(std::string(UA_IR), error);

  INFO(error);
  REQUIRE(prog.has_value());

  const Section &sec = prog->sections[0];

  REQUIRE(sec.insts.size() == 11);
  CHECK(sec.num_regs == 9);

  CHECK(sec.insts[1].op == Op::CallPure);
  CHECK(sec.insts[1].dest == 2);
  CHECK(sec.insts[1].ext_name == "Example::UA::IsBot");
  CHECK(sec.insts[1].args == std::vector<uint32_t>{1});

  CHECK(sec.insts[2].op == Op::BrF);
  CHECK(sec.insts[2].args == std::vector<uint32_t>{2});
  CHECK(sec.insts[2].target == 7);

  CHECK(sec.insts[6].op == Op::Br);
  CHECK(sec.insts[6].target == 10);

  CHECK(sec.insts[7].op == Op::ConstS);
  CHECK(sec.insts[10].op == Op::Ret);

  REQUIRE(sec.reg_types.size() == 9);
  CHECK(sec.reg_types[1] == Type::Sview);
  CHECK(sec.reg_types[2] == Type::Bool);
}

TEST_CASE("rejects bad branches")
{
  SECTION("backward target")
  {
    require_error_at(replace_line(12, "    br .L1 @2:4", UA_IR), 12);
  }
  SECTION("target is the branch itself")
  {
    require_error_at(replace_line(12, "    br .L6 @2:4", UA_IR), 12);
  }
  SECTION("target past the last instruction")
  {
    require_error_at(replace_line(12, "    br .L99 @2:4", UA_IR), 12);
  }
  SECTION("label that is not its instruction's index")
  {
    require_error_at(replace_line(13, "    .L8: %6:sview = const.s K1 @2:72", UA_IR), 13);
  }
  SECTION("br.f on a string register")
  {
    require_error_at(replace_line(8, "    br.f %1, .L7 @2:7", UA_IR), 8);
  }
}

TEST_CASE("rejects what milestone 2 does not run")
{
  SECTION("an extension call returning an address")
  {
    require_error_at(replace_line(7, R"(    %2:addr = call.pure EXT"x", %1 @2:7)", UA_IR), 7);
  }
  SECTION("call.pure of an unsupported builtin")
  {
    require_error_at(replace_line(7, "    %2:bool = call.pure BI_CLIENT_RESP_STATUS @2:7", UA_IR), 7);
  }
  SECTION("call.eff of an extension")
  {
    require_error_at(replace_line(7, R"(    call.eff EXT"x", %1 @2:7)", UA_IR), 7);
  }
  SECTION("BI_SET_CLIENT_RESP_HEADER with a non-string argument")
  {
    require_error_at(replace_line(11, "    call.eff BI_SET_CLIENT_RESP_HEADER, %3, %2 @2:36", UA_IR), 11);
  }
}

TEST_CASE("parse_ir reads a header builtin's call")
{
  std::string error;
  auto        prog = parse_ir(replace_line(8, "    call.eff BI_SET_CLIENT_RESP_HEADER, %1, %2 @2:4"), error);

  INFO(error);
  REQUIRE(prog.has_value());

  const Inst &inst = prog->sections[0].insts[2];

  CHECK(inst.op == Op::CallEff);
  CHECK(inst.dest == 0);
  CHECK(inst.builtin == Builtin::SetClientRespHeader);
  CHECK(inst.args == std::vector<uint32_t>{1, 2});
}

TEST_CASE("BI_RM_CLIENT_RESP_HEADER takes one string")
{
  std::string error;
  auto        prog = parse_ir(replace_line(8, "    call.eff BI_RM_CLIENT_RESP_HEADER, %1 @2:4"), error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->sections[0].insts[2].op == Op::CallEff);
  CHECK(prog->sections[0].insts[2].builtin == Builtin::RmClientRespHeader);
  CHECK(prog->sections[0].insts[2].args == std::vector<uint32_t>{1});

  SECTION("no argument is refused")
  {
    require_error_at(replace_line(8, "    call.eff BI_RM_CLIENT_RESP_HEADER @2:4"), 8);
  }
  SECTION("two arguments are refused")
  {
    require_error_at(replace_line(8, "    call.eff BI_RM_CLIENT_RESP_HEADER, %1, %2 @2:4"), 8);
  }
  SECTION("a non-string argument is refused")
  {
    require_error_at(replace_line(11, "    call.eff BI_RM_CLIENT_RESP_HEADER, %2 @2:36", UA_IR), 11);
  }
}

TEST_CASE("BI_SERVER_RESP_HEADER reads a string by name")
{
  const auto resp = in_hook("READ_RESPONSE", COMPARE_IR);
  const auto ua   = in_hook("READ_RESPONSE", UA_IR);

  std::string error;
  auto        prog = parse_ir(replace_line(7, "    %2:sview = call.pure BI_SERVER_RESP_HEADER, %1 @2:4", resp), error);

  INFO(error);
  REQUIRE(prog.has_value());

  const Inst &inst = prog->sections[0].insts[1];

  CHECK(inst.op == Op::CallPure);
  CHECK(inst.builtin == Builtin::ServerRespHeader);
  CHECK(inst.args == std::vector<uint32_t>{1});
  CHECK(inst.ext_name.empty());

  SECTION("into a bool register is refused")
  {
    require_error_at(replace_line(7, "    %2:bool = call.pure BI_SERVER_RESP_HEADER, %1 @2:4", resp), 7);
  }
  SECTION("without a name is refused")
  {
    require_error_at(replace_line(7, "    %2:sview = call.pure BI_SERVER_RESP_HEADER @2:4", resp), 7);
  }
  SECTION("with two names is refused")
  {
    require_error_at(replace_line(7, "    %2:sview = call.pure BI_SERVER_RESP_HEADER, %1, %1 @2:4", resp), 7);
  }
  SECTION("of a non-string is refused")
  {
    require_error_at(replace_line(8, "    %3:sview = call.pure BI_SERVER_RESP_HEADER, %2 @2:7", ua), 8);
  }
  SECTION("by call.eff is refused")
  {
    require_error_at(replace_line(8, "    call.eff BI_SERVER_RESP_HEADER, %1 @2:4", resp), 8);
  }
  SECTION("and call.pure of an effect is refused")
  {
    require_error_at(replace_line(7, "    %2:sview = call.pure BI_RM_SERVER_RESP_HEADER, %1 @2:4", resp), 7);
  }
}

TEST_CASE("a builtin that reads the client's request is refused at TXN_START")
{
  std::string line = "    %3:sview = call.pure BI_CLIENT_HEADER, %1 @2:4";
  std::string error;

  CHECK(parse_ir(replace_line(8, line), error).has_value());
  require_error_at(replace_line(8, line, in_hook("TXN_START", COMPARE_IR)), 8);
  parse_ir(replace_line(8, line, in_hook("TXN_START", COMPARE_IR)), error);
  CHECK(error.ends_with("does not run in this section's hook"));
}

TEST_CASE("BI_CLIENT_HEADER reads the client request in every hook with a message")
{
  for (auto hook : MESSAGE_HOOKS) {
    std::string error;
    auto prog = parse_ir(replace_line(7, "    %2:sview = call.pure BI_CLIENT_HEADER, %1 @2:4", in_hook(hook, COMPARE_IR)), error);

    INFO(hook << ": " << error);
    REQUIRE(prog.has_value());
    CHECK(prog->sections[0].insts[1].builtin == Builtin::ClientHeader);
  }
}

TEST_CASE("a header builtin runs only in the hooks whose message is the one it names")
{
  const std::set<std::string_view> client_request{"READ_REQUEST", "PRE_REMAP", "REMAP"};
  const std::set<std::string_view> server_request{"SEND_REQUEST"};
  const std::set<std::string_view> server_response{"READ_RESPONSE"};
  const std::set<std::string_view> client_response{"SEND_RESPONSE", "TXN_CLOSE"};

  const std::tuple<std::string_view, Builtin, const std::set<std::string_view> &> calls[] = {
    {"call.eff BI_SET_CLIENT_HEADER, %1, %2",          Builtin::SetClientHeader,     client_request },
    {"call.eff BI_ADD_CLIENT_HEADER, %1, %2",          Builtin::AddClientHeader,     client_request },
    {"call.eff BI_RM_CLIENT_HEADER, %1",               Builtin::RmClientHeader,      client_request },
    {"call.eff BI_SET_SERVER_HEADER, %1, %2",          Builtin::SetServerHeader,     server_request },
    {"call.eff BI_ADD_SERVER_HEADER, %1, %2",          Builtin::AddServerHeader,     server_request },
    {"call.eff BI_RM_SERVER_HEADER, %1",               Builtin::RmServerHeader,      server_request },
    {"%3:sview = call.pure BI_SERVER_RESP_HEADER, %1", Builtin::ServerRespHeader,    server_response},
    {"call.eff BI_SET_SERVER_RESP_HEADER, %1, %2",     Builtin::SetServerRespHeader, server_response},
    {"call.eff BI_ADD_SERVER_RESP_HEADER, %1, %2",     Builtin::AddServerRespHeader, server_response},
    {"call.eff BI_RM_SERVER_RESP_HEADER, %1",          Builtin::RmServerRespHeader,  server_response},
    {"%3:sview = call.pure BI_CLIENT_RESP_HEADER, %1", Builtin::ClientRespHeader,    client_response},
    {"call.eff BI_SET_CLIENT_RESP_HEADER, %1, %2",     Builtin::SetClientRespHeader, client_response},
    {"call.eff BI_ADD_CLIENT_RESP_HEADER, %1, %2",     Builtin::AddClientRespHeader, client_response},
    {"call.eff BI_RM_CLIENT_RESP_HEADER, %1",          Builtin::RmClientRespHeader,  client_response},
  };

  for (const auto &[call, builtin, hooks] : calls) {
    std::string line = "    " + std::string(call) + " @2:4";

    for (auto hook :
         {"TXN_START", "READ_REQUEST", "PRE_REMAP", "REMAP", "SEND_REQUEST", "READ_RESPONSE", "SEND_RESPONSE", "TXN_CLOSE"}) {
      std::string error;
      auto        prog = parse_ir(replace_line(8, line, in_hook(hook, COMPARE_IR)), error);

      INFO(call << " in " << hook << ": " << error);
      if (hooks.contains(hook)) {
        REQUIRE(prog.has_value());
        CHECK(prog->sections[0].insts[2].builtin == builtin);
      } else {
        CHECK(error.ends_with("does not run in this section's hook"));
      }
    }
  }
}

TEST_CASE("cmp.s compares two string registers into a bool")
{
  std::string error;
  auto        prog = parse_ir(replace_line(7, "    %2:bool = cmp.s.ne %1, %1 @2:7", UA_IR), error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->sections[0].insts[1].op == Op::CmpSNe);
  CHECK(prog->sections[0].insts[1].args == std::vector<uint32_t>{1, 1});
  CHECK(prog->sections[0].reg_types[2] == Type::Bool);

  SECTION("a bool operand is refused")
  {
    require_error_at(replace_line(8, "    %3:bool = cmp.s.eq %2, %1 @2:7", UA_IR), 8);
  }
}

TEST_CASE("br.t reads like br.f")
{
  std::string error;
  auto        prog = parse_ir(replace_line(8, "    br.t %2, .L7 @2:7", UA_IR), error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->sections[0].insts[2].op == Op::BrT);
  CHECK(prog->sections[0].insts[2].args == std::vector<uint32_t>{2});
  CHECK(prog->sections[0].insts[2].target == 7);

  SECTION("a string register is refused")
  {
    require_error_at(replace_line(8, "    br.t %1, .L7 @2:7", UA_IR), 8);
  }
  SECTION("a backward target is refused")
  {
    require_error_at(replace_line(8, "    br.t %2, .L1 @2:7", UA_IR), 8);
  }
}

TEST_CASE("break may stand anywhere, ret only last")
{
  std::string error;
  auto        prog = parse_ir(insert_line(9, "    break @2:4"), error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->sections[0].insts[3].op == Op::Break);
  CHECK(prog->sections[0].insts[4].op == Op::Ret);

  SECTION("break takes no operands")
  {
    require_error_at(insert_line(9, "    break %1 @2:4"), 9);
  }
  SECTION("the section still has to end with ret")
  {
    require_error_at(replace_line(9, "    break @2:4"), 9);
  }
}

TEST_CASE("const.i loads from the ints pool")
{
  constexpr std::string_view ir = R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"X-Foo"]
  ints   = [I0:399, I1:-5]
  IR:
    %1:i64 = const.i I1 @2:4
    ret @2:4
)";

  std::string error;
  auto        prog = parse_ir(std::string(ir), error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->ints == std::vector<int64_t>{399, -5});
  CHECK(prog->sections[0].insts[0].op == Op::ConstI);
  CHECK(prog->sections[0].insts[0].operand == 1);
  CHECK(prog->sections[0].reg_types[1] == Type::I64);

  SECTION("ints without consts")
  {
    auto lines = lines_of(ir);

    lines.erase(lines.begin() + 3);
    CHECK(parse_ir(text_of(lines), error).has_value());
  }
  SECTION("ints before consts is refused")
  {
    auto lines = lines_of(ir);

    std::swap(lines[3], lines[4]);
    require_error_at(text_of(lines), 5);
  }
  SECTION("an index out of order is refused")
  {
    require_error_at(replace_line(5, "  ints   = [I1:399]", ir), 5);
  }
  SECTION("a value that is not an integer is refused")
  {
    require_error_at(replace_line(5, "  ints   = [I0:abc]", ir), 5);
  }
  SECTION("const.i past the pool is refused")
  {
    require_error_at(replace_line(7, "    %1:i64 = const.i I2 @2:4", ir), 7);
  }
  SECTION("a value beyond i64 is refused")
  {
    require_error_at(replace_line(5, "  ints   = [I0:9223372036854775808]", ir), 5);
  }
  SECTION("the whole i64 range is accepted")
  {
    CHECK(parse_ir(replace_line(5, "  ints   = [I0:-9223372036854775808, I1:9223372036854775807]", ir), error).has_value());
  }
}

TEST_CASE("const.i of 0 or 1 loads a bool")
{
  auto program = [](int64_t value) {
    return replace_line(4, "  ints   = [I0:" + std::to_string(value) + "]", R"(hrw4u-ir 1.0

Section[REMAP]:
  ints   = [I0:0]
  IR:
    %1:bool = const.i I0 @2:4
    ret @2:4
)");
  };

  for (int64_t value : {0, 1}) {
    std::string error;
    auto        prog = parse_ir(program(value), error);

    INFO(value << ": " << error);
    REQUIRE(prog.has_value());
    CHECK(prog->sections[0].reg_types[1] == Type::Bool);
  }
  require_error_at(program(2), 6);
  require_error_at(program(-1), 6);
}

TEST_CASE("cmp.i64 compares two integer registers into a bool")
{
  constexpr std::string_view ir = R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"x"]
  ints   = [I0:1]
  IR:
    %1:i64 = const.i I0 @1:1
    %2:bool = cmp.i64.ge %1, %1 @1:1
    ret @1:1
)";

  std::string error;
  auto        prog = parse_ir(std::string(ir), error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->sections[0].insts[1].op == Op::CmpIGe);
  CHECK(prog->sections[0].reg_types[2] == Type::Bool);

  SECTION("a string operand is refused")
  {
    require_error_at(replace_line(7, "    %1:sview = const.s K0 @1:1", ir), 8);
  }
}

namespace
{
// Two pools and two fmt instructions: one hole, then two holes of different types.
constexpr std::string_view FMT_IR = R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"X-A", K1:"v"]
  ints   = [I0:7]
  fmt    = [F0:"{a}" arity=1 lits=["", ""], F1:"x{a}-{b}y" arity=2 lits=["x", "-", "y"]]
  IR:
    %1:sview = const.s K1 @1:1
    %2:sview = fmt F0, %1 @1:1
    %3:i64 = const.i I0 @1:1
    %4:sview = fmt F1, %1, %3 @1:1
    ret @1:1
)";
} // namespace

TEST_CASE("parse_ir reads the format pool and fmt")
{
  std::string error;
  auto        prog = parse_ir(std::string(FMT_IR), error);

  INFO(error);
  REQUIRE(prog.has_value());
  REQUIRE(prog->fmts.size() == 2);
  CHECK(prog->fmts[0].source == "{a}");
  CHECK(prog->fmts[0].lits == std::vector<std::string>{"", ""});
  CHECK(prog->fmts[1].source == "x{a}-{b}y");
  CHECK(prog->fmts[1].lits == std::vector<std::string>{"x", "-", "y"});

  const Section &sec = prog->sections[0];

  CHECK(sec.insts[1].op == Op::Fmt);
  CHECK(sec.insts[1].operand == 0);
  CHECK(sec.insts[1].args == std::vector<uint32_t>{1});
  CHECK(sec.insts[3].operand == 1);
  CHECK(sec.insts[3].args == std::vector<uint32_t>{1, 3});
  CHECK(sec.reg_types[4] == Type::Sview);
}

TEST_CASE("rejects a bad format pool or fmt")
{
  SECTION("arity that is not lits - 1")
  {
    require_error_at(replace_line(6, R"(  fmt    = [F0:"{a}" arity=2 lits=["", ""]])", FMT_IR), 6);
  }
  SECTION("an index out of order")
  {
    require_error_at(replace_line(6, R"(  fmt    = [F1:"{a}" arity=1 lits=["", ""]])", FMT_IR), 6);
  }
  SECTION("no lits")
  {
    require_error_at(replace_line(6, R"(  fmt    = [F0:"" arity=0 lits=[]])", FMT_IR), 6);
  }
  SECTION("fmt before ints")
  {
    auto lines = lines_of(FMT_IR);

    std::swap(lines[4], lines[5]);
    require_error_at(text_of(lines), 6);
  }
  SECTION("fmt past the pool")
  {
    require_error_at(replace_line(9, "    %2:sview = fmt F2, %1 @1:1", FMT_IR), 9);
  }
  SECTION("fmt with the wrong number of arguments")
  {
    require_error_at(replace_line(9, "    %2:sview = fmt F0, %1, %1 @1:1", FMT_IR), 9);
  }
  SECTION("fmt into a non-string register")
  {
    require_error_at(replace_line(9, "    %2:bool = fmt F0, %1 @1:1", FMT_IR), 9);
  }
}

TEST_CASE("parse_ir reads the regex pool and re.match")
{
  constexpr std::string_view ir = R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"a/b"]
  regex  = [R0:/^a\/(b)$/, R1:/X/i]
  IR:
    %1:sview = const.s K0 @2:7
    %2:bool = re.match %1, R0 @2:7
    %3:bool = re.match %1, R1 @2:7
    ret @2:7
)";

  std::string error;
  auto        prog = parse_ir(std::string(ir), error);

  INFO(error);
  REQUIRE(prog.has_value());
  REQUIRE(prog->regexes.size() == 2);
  CHECK(prog->sections[0].insts[1].op == Op::ReMatch);
  CHECK(prog->sections[0].insts[1].operand == 0);
  CHECK(prog->sections[0].insts[1].args == std::vector<uint32_t>{1});
  CHECK(prog->sections[0].insts[2].operand == 1);

  SECTION("a regex that does not compile is refused")
  {
    require_error_at(replace_line(5, "  regex  = [R0:/(/]", ir), 5);
  }
  SECTION("an unknown flag is refused")
  {
    require_error_at(replace_line(5, "  regex  = [R0:/x/g]", ir), 5);
  }
  SECTION("regex before ints is refused")
  {
    auto bad = lines_of(ir);

    bad.insert(bad.begin() + 5, "  ints   = [I0:1]");
    require_error_at(text_of(bad), 6);
  }
  SECTION("re.match past the pool is refused")
  {
    require_error_at(replace_line(9, "    %3:bool = re.match %1, R2 @2:7", ir), 9);
  }
  SECTION("re.match of a non-string is refused")
  {
    require_error_at(replace_line(9, "    %3:bool = re.match %2, R1 @2:7", ir), 9);
  }
  SECTION("re.match into a string is refused")
  {
    require_error_at(replace_line(9, "    %3:sview = re.match %1, R1 @2:7", ir), 9);
  }
}

TEST_CASE("parse_ir reads the sets pool and in.set")
{
  constexpr std::string_view ir = R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"foo"]
  fmt    = [F0:"x" arity=0 lits=["x"]]
  sets   = [S0:s("foo", "bar"), S1:s("A") nocase]
  IR:
    %1:sview = const.s K0 @2:7
    %2:bool = in.set %1, S0 @2:7
    %3:bool = in.set %1, S1 @2:7
    ret @2:7
)";

  std::string error;
  auto        prog = parse_ir(std::string(ir), error);

  INFO(error);
  REQUIRE(prog.has_value());
  REQUIRE(prog->sets.size() == 2);
  CHECK(prog->sets[0].items == std::vector<std::string>{"foo", "bar"});
  CHECK_FALSE(prog->sets[0].nocase);
  CHECK(prog->sets[1].nocase);
  CHECK(prog->sections[0].insts[1].op == Op::InSet);
  CHECK(prog->sections[0].insts[1].operand == 0);
  CHECK(prog->sections[0].insts[2].operand == 1);

  SECTION("an IP range set")
  {
    auto ip = parse_ir(
      replace_line(6, R"(  sets   = [S0:s("foo"), S1:s("A"), S2:ip("10.0.0.0/8", "127.0.0.1", "2001:db8::/32")])", ir), error);

    INFO(error);
    REQUIRE(ip.has_value());
    CHECK(ip->sets[2].kind == Set::Kind::Ip);
  }
  SECTION("an IP range that does not parse is refused")
  {
    require_error_at(replace_line(6, R"(  sets   = [S0:ip("10.0.0.0/33")])", ir), 6);
    require_error_at(replace_line(6, R"(  sets   = [S0:ip("example.com")])", ir), 6);
  }
  SECTION("an IP range set holds addresses, a string set strings")
  {
    require_error_at(replace_line(6, R"(  sets   = [S0:ip("10.0.0.0/8"), S1:s("A")])", ir), 9);
  }
  SECTION("an IP range set ignoring case is refused")
  {
    require_error_at(replace_line(6, R"(  sets   = [S0:ip("10.0.0.0/8") nocase])", ir), 6);
  }
  SECTION("an integer set, tested with an integer register")
  {
    auto ints = lines_of(ir);

    ints[3] = "  ints   = [I0:200]";
    ints[5] = R"(  sets   = [S0:i(200, -404), S1:s("A")])";
    ints[7] = "    %1:i64 = const.i I0 @2:7";
    ints[9] = "    %3:bool = in.set %1, S1 @2:7";

    auto bad = parse_ir(text_of(ints), error);

    // S1 is a string set, and %1 an integer.
    REQUIRE_FALSE(bad.has_value());
    ints[8]     = "    %2:bool = in.set %1, S0 @2:7";
    ints[9]     = "    %3:bool = in.set %1, S0 @2:7";
    auto parsed = parse_ir(text_of(ints), error);

    INFO(error);
    REQUIRE(parsed.has_value());
    CHECK(parsed->sets[0].kind == Set::Kind::Int);
    CHECK(parsed->sets[0].ints == std::vector<int64_t>{200, -404});
  }
  SECTION("an integer set of quoted or non-numeric items, or with a mode or a case, is refused")
  {
    require_error_at(replace_line(6, R"(  sets   = [S0:i("1")])", ir), 6);
    require_error_at(replace_line(6, "  sets   = [S0:i(x)]", ir), 6);
    require_error_at(replace_line(6, "  sets   = [S0:i(1) pre]", ir), 6);
    require_error_at(replace_line(6, "  sets   = [S0:i(1) nocase]", ir), 6);
  }
  SECTION("match modes, before nocase")
  {
    auto modes = parse_ir(replace_line(6, R"(  sets   = [S0:s("foo") pre, S1:s("A") ext nocase])", ir), error);

    INFO(error);
    REQUIRE(modes.has_value());
    CHECK(modes->sets[0].match == Set::Match::Prefix);
    CHECK_FALSE(modes->sets[0].nocase);
    CHECK(modes->sets[1].match == Set::Match::Extension);
    CHECK(modes->sets[1].nocase);
  }
  SECTION("an unknown match mode, a mode after nocase or a mode on an IP range set is refused")
  {
    require_error_at(replace_line(6, R"(  sets   = [S0:s("foo") prefix])", ir), 6);
    require_error_at(replace_line(6, R"(  sets   = [S0:s("foo") nocase pre])", ir), 6);
    require_error_at(replace_line(6, R"(  sets   = [S0:ip("10.0.0.0/8") pre])", ir), 6);
  }
  SECTION("sets before fmt is refused")
  {
    auto bad = lines_of(ir);

    std::swap(bad[4], bad[5]);
    require_error_at(text_of(bad), 6);
  }
  SECTION("in.set past the pool is refused")
  {
    require_error_at(replace_line(10, "    %3:bool = in.set %1, S2 @2:7", ir), 10);
  }
  SECTION("in.set of a non-string is refused")
  {
    require_error_at(replace_line(10, "    %3:bool = in.set %2, S1 @2:7", ir), 10);
  }
}

TEST_CASE("parse_ir reads the vars pool and load.v")
{
  constexpr std::string_view ir = R"(hrw4u-ir 1.0

Section[REMAP]:
  vars   = [v0:bool, v1:bool]
  consts = [K0:"x"]
  IR:
    %1:bool = load.v v1:bool @6:7
    ret @6:7
)";

  std::string error;
  auto        prog = parse_ir(std::string(ir), error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->vars == std::vector<Var>{
                        {VarType::Bool, 0},
                        {VarType::Bool, 1}
  });
  CHECK(prog->sections[0].insts[0].op == Op::LoadV);
  CHECK(prog->sections[0].insts[0].operand == 1);

  SECTION("integer variables are numbered apart from the bools, and load.v finds them by type and number")
  {
    auto both = lines_of(ir);

    both[3]   = "  vars   = [v0:bool, v0:u8, v1:bool, v1:u8, v0:u16]";
    both[6]   = "    %1:i64 = load.v v1:u8 @6:7";
    auto ints = parse_ir(text_of(both), error);

    INFO(error);
    REQUIRE(ints.has_value());
    CHECK(ints->vars[3] == Var{VarType::U8, 1});
    CHECK(ints->sections[0].insts[0].operand == 3);
  }
  SECTION("a variable named twice is refused")
  {
    require_error_at(replace_line(4, "  vars   = [v0:u8, v0:u8]", ir), 4);
  }
  SECTION("store.v of a bool register into an integer variable is refused")
  {
    auto bad = lines_of(ir);

    bad[3] = "  vars   = [v0:u8]";
    bad[4] = "  ints   = [I0:1]";
    bad[6] = "    %1:bool = const.i I0 @6:7";
    bad.insert(bad.begin() + 7, "    store.v v0:u8, %1 @6:7");
    require_error_at(text_of(bad), 8);
  }
  SECTION("a register type a variable does not keep is refused")
  {
    require_error_at(replace_line(4, "  vars   = [v0:i64]", ir), 4);
    auto bad = lines_of(ir);

    bad[3] = "  vars   = [v0:u8]";
    bad[6] = "    %1:bool = load.v v0:u8 @6:7";
    require_error_at(text_of(bad), 7);
  }
  SECTION("a session variable is refused, not supported yet")
  {
    require_error_at(replace_line(4, "  vars   = [v0:bool@ssn]", ir), 4);
  }
  SECTION("an unknown type is refused")
  {
    require_error_at(replace_line(4, "  vars   = [v0:boolean]", ir), 4);
    require_error_at(replace_line(4, "  vars   = [v0:flag]", ir), 4);
  }
  SECTION("an empty pool, an index out of order or trailing text is refused")
  {
    require_error_at(replace_line(4, "  vars   = []", ir), 4);
    require_error_at(replace_line(4, "  vars   = [v1:bool]", ir), 4);
    require_error_at(replace_line(4, "  vars   = [v0:bool] x", ir), 4);
  }
  SECTION("more than 64 variables are accepted")
  {
    std::string all = "  vars   = [";

    for (int i = 0; i < 100; ++i) {
      if (i > 0) {
        all += ", ";
      }
      all += "v" + std::to_string(i) + ":bool";
    }

    auto full = lines_of(ir);

    full[3] = all + "]";
    full[6] = "    %1:bool = load.v v99:bool @6:7";

    std::string error;
    auto        prog = parse_ir(text_of(full), error);

    INFO(error);
    REQUIRE(prog.has_value());
    CHECK(prog->sections[0].insts[0].operand == 99);
  }
  SECTION("vars after consts is refused")
  {
    auto bad = lines_of(ir);

    std::swap(bad[3], bad[4]);
    require_error_at(text_of(bad), 5);
  }
  SECTION("load.v past the pool is refused")
  {
    require_error_at(replace_line(7, "    %1:bool = load.v v2:bool @6:7", ir), 7);
  }
  SECTION("load.v naming the wrong type is refused")
  {
    require_error_at(replace_line(7, "    %1:i64 = load.v v1:i64 @6:7", ir), 7);
  }
}

TEST_CASE("parse_ir reads store.v")
{
  constexpr std::string_view ir = R"(hrw4u-ir 1.0

Section[REMAP]:
  vars   = [v0:bool, v1:bool]
  ints   = [I0:1]
  IR:
    %1:bool = const.i I0 @6:4
    store.v v1:bool, %1 @6:4
    ret @6:4
)";

  std::string error;
  auto        prog = parse_ir(std::string(ir), error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->sections[0].insts[1].op == Op::StoreV);
  CHECK(prog->sections[0].insts[1].operand == 1);
  CHECK(prog->sections[0].insts[1].args == std::vector<uint32_t>{1});

  SECTION("store.v past the pool is refused")
  {
    require_error_at(replace_line(8, "    store.v v2:bool, %1 @6:4", ir), 8);
  }
  SECTION("store.v naming the wrong type is refused")
  {
    require_error_at(replace_line(8, "    store.v v1:i64, %1 @6:4", ir), 8);
  }
  SECTION("store.v of a register of another type is refused")
  {
    auto bad = replace_line(7, "    %1:i64 = const.i I0 @6:4", ir);

    require_error_at(bad, 8);
  }
  SECTION("store.v of a register not yet written is refused")
  {
    require_error_at(replace_line(8, "    store.v v1:bool, %2 @6:4", ir), 8);
  }
  SECTION("a malformed store.v is refused")
  {
    require_error_at(replace_line(8, "    store.v v1:bool %1 @6:4", ir), 8);
  }
}

TEST_CASE("format literals take the string escapes")
{
  std::string error;
  auto        prog = parse_ir(
    replace_line(6, R"(  fmt    = [F0:"{a}" arity=1 lits=["a\"b", "\n\x41\\"], F1:"x{a}-{b}y" arity=2 lits=["x", "-", "y"]])",
                        FMT_IR),
    error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->fmts[0].lits == std::vector<std::string>{"a\"b", "\nA\\"});
}

TEST_CASE("rejects trailing text after the format pool")
{
  require_error_at(
    replace_line(6, R"(  fmt    = [F0:"{a}" arity=1 lits=["", ""], F1:"x{a}-{b}y" arity=2 lits=["x", "-", "y"]] x)", FMT_IR), 6);
}

TEST_CASE("a status builtin reads its response's status as an integer, in that response's hook only")
{
  auto program = [](std::string_view name, std::string_view hook, std::string_view type) {
    return replace_line(5, "    %1:" + std::string(type) + " = call.pure " + std::string(name) + " @2:7",
                        in_hook(hook, R"(hrw4u-ir 1.0

Section[REMAP]:
  IR:
    %1:i64 = call.pure BI_CLIENT_RESP_STATUS @2:7
    ret @2:7
)"));
  };

  for (auto [name, builtin, hook] : {
         std::tuple{"BI_SERVER_RESP_STATUS", Builtin::ServerRespStatus, "READ_RESPONSE"},
         std::tuple{"BI_CLIENT_RESP_STATUS", Builtin::ClientRespStatus, "SEND_RESPONSE"}
  }) {
    std::string error;
    auto        prog = parse_ir(program(name, hook, "i64"), error);

    INFO(name << " in " << hook << ": " << error);
    REQUIRE(prog.has_value());
    CHECK(prog->sections[0].insts[0].builtin == builtin);
    CHECK(prog->sections[0].insts[0].args.empty());

    for (auto other : EVERY_HOOK) {
      if (other != std::string_view(hook)) {
        INFO(name << " in " << other);
        require_error_at(program(name, other, "i64"), 5);
      }
    }
    require_error_at(program(name, hook, "sview"), 5);
  }
}

TEST_CASE("BI_CLIENT_URL reads a URL field named by an integer")
{
  const std::string text = R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  ints   = [I0:3]
  IR:
    %1:i64 = const.i I0 @2:7
    %2:sview = call.pure BI_CLIENT_URL, %1 @2:7
    ret @2:7
)";

  std::string error;
  auto        prog = parse_ir(text, error);

  INFO(error);
  REQUIRE(prog.has_value());
  CHECK(prog->sections[0].insts[1].builtin == Builtin::ClientUrl);

  SECTION("not at TXN_START")
  {
    require_error_at(in_hook("TXN_START", text), 7);
  }
  SECTION("without a field is refused")
  {
    require_error_at(R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  IR:
    %1:sview = call.pure BI_CLIENT_URL @2:7
    ret @2:7
)",
                     5);
  }
  SECTION("a string field is refused")
  {
    require_error_at(R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"PATH"]
  IR:
    %1:sview = const.s K0 @2:7
    %2:sview = call.pure BI_CLIENT_URL, %1 @2:7
    ret @2:7
)",
                     7);
  }
}

TEST_CASE("BI_CLIENT_URL_PARAM reads a query parameter by name in every hook with a message")
{
  for (auto hook : MESSAGE_HOOKS) {
    std::string error;
    auto        prog =
      parse_ir(replace_line(7, "    %2:sview = call.pure BI_CLIENT_URL_PARAM, %1 @2:4", in_hook(hook, COMPARE_IR)), error);

    INFO(hook << ": " << error);
    REQUIRE(prog.has_value());
    CHECK(prog->sections[0].insts[1].builtin == Builtin::ClientUrlParam);
  }
  require_error_at(replace_line(7, "    %2:sview = call.pure BI_CLIENT_URL_PARAM, %1 @2:4", in_hook("TXN_START", COMPARE_IR)), 7);
}

TEST_CASE("BI_SERVER_HEADER reads a string by name after the request is sent")
{
  const auto req = in_hook("SEND_REQUEST", COMPARE_IR);
  const auto ua  = UA_IR;

  std::string error;
  auto        prog = parse_ir(replace_line(7, "    %2:sview = call.pure BI_SERVER_HEADER, %1 @2:4", req), error);

  INFO(error);
  REQUIRE(prog.has_value());

  const Inst &inst = prog->sections[0].insts[1];

  CHECK(inst.op == Op::CallPure);
  CHECK(inst.builtin == Builtin::ServerHeader);
  CHECK(inst.args == std::vector<uint32_t>{1});

  SECTION("of a non-string is refused")
  {
    require_error_at(replace_line(8, "    %3:sview = call.pure BI_SERVER_HEADER, %2 @2:7", ua), 8);
  }
  SECTION("by call.eff is refused")
  {
    require_error_at(replace_line(8, "    call.eff BI_SERVER_HEADER, %1 @2:4", req), 8);
  }
  SECTION("only in the hooks where hrw4u reads outbound.req.")
  {
    const std::set<std::string_view> sent{"SEND_REQUEST", "READ_RESPONSE", "SEND_RESPONSE"};

    for (auto hook : EVERY_HOOK) {
      const auto text = replace_line(7, "    %2:sview = call.pure BI_SERVER_HEADER, %1 @2:4", in_hook(hook, req));

      INFO(hook);
      if (sent.contains(hook)) {
        std::string hook_error;

        CHECK(parse_ir(text, hook_error).has_value());
      } else {
        require_error_at(text, 7);
      }
    }
  }
}

TEST_CASE("BI_SERVER_URL reads the request to the origin in every hook")
{
  const std::string field = R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  ints   = [I0:3]
  IR:
    %1:i64 = const.i I0 @2:7
    %2:sview = call.pure BI_SERVER_URL, %1 @2:7
    ret @2:7
)";

  for (auto hook : EVERY_HOOK) {
    std::string error;

    INFO(hook);
    CHECK(parse_ir(in_hook(hook, field), error).has_value());
  }
  SECTION("a field by string is refused")
  {
    require_error_at(R"(hrw4u-ir 1.0

Section[SEND_RESPONSE]:
  consts = [K0:"PATH"]
  IR:
    %1:sview = const.s K0 @2:7
    %2:sview = call.pure BI_SERVER_URL, %1 @2:7
    ret @2:7
)",
                     7);
  }
}

TEST_CASE("BI_IP_CLIENT reads an address in every hook")
{
  auto program = [](std::string_view hook, std::string_view type) {
    return replace_line(5, "    %1:" + std::string(type) + " = call.pure BI_IP_CLIENT @2:4", in_hook(hook, R"(hrw4u-ir 1.0

Section[REMAP]:
  IR:
    %1:addr = call.pure BI_IP_CLIENT @2:4
    ret @2:4
)"));
  };

  for (auto hook : EVERY_HOOK) {
    std::string error;
    auto        prog = parse_ir(program(hook, "addr"), error);

    INFO(hook << ": " << error);
    REQUIRE(prog.has_value());
    CHECK(prog->sections[0].insts[0].builtin == Builtin::IpClient);
    CHECK(prog->sections[0].reg_types[1] == Type::Addr);
  }
  require_error_at(program("REMAP", "sview"), 5);
}

TEST_CASE("BI_IP_INBOUND returns an address in every hook")
{
  for (auto hook : EVERY_HOOK) {
    std::string error;
    auto        prog = parse_ir(in_hook(hook, R"(hrw4u-ir 1.0

Section[REMAP]:
  IR:
    %1:addr = call.pure BI_IP_INBOUND @2:4
    ret @2:4
)"),
                                error);

    INFO(hook << ": " << error);
    REQUIRE(prog.has_value());
    CHECK(prog->sections[0].insts[0].builtin == Builtin::IpInbound);
  }
}

TEST_CASE("BI_NOW takes and returns an integer in every hook")
{
  for (auto hook : EVERY_HOOK) {
    std::string error;
    auto        prog = parse_ir(in_hook(hook, R"(hrw4u-ir 1.0

Section[REMAP]:
  ints   = [I0:0]
  IR:
    %1:i64 = const.i I0 @2:4
    %2:i64 = call.pure BI_NOW, %1 @2:4
    ret @2:4
)"),
                                error);

    INFO(hook << ": " << error);
    REQUIRE(prog.has_value());
    CHECK(prog->sections[0].insts[1].builtin == Builtin::Now);
  }
}

TEST_CASE("BI_RANDOM takes and returns an integer in every hook")
{
  for (auto hook : EVERY_HOOK) {
    std::string error;
    auto        prog = parse_ir(in_hook(hook, R"(hrw4u-ir 1.0

Section[REMAP]:
  ints   = [I0:1000]
  IR:
    %1:i64 = const.i I0 @2:4
    %2:i64 = call.pure BI_RANDOM, %1 @2:4
    ret @2:4
)"),
                                error);

    INFO(hook << ": " << error);
    REQUIRE(prog.has_value());
    CHECK(prog->sections[0].insts[1].builtin == Builtin::Random);
  }
}
