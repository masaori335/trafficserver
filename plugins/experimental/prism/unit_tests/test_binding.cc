/** @file

  Unit tests for the extension binding layer: the wrappers it generates, called through the C ABI.

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

#include "hrw4u/extension.hpp"

#include "swoc/TextView.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace
{
bool
is_jp(std::string_view code)
{
  return code == "JP";
}

bool
both(bool a, std::string_view b)
{
  return a && b == "x";
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

// A library's own string type, as cripts::string is.
struct OwnString : std::string {
  using std::string::string;
};

OwnString
exclaim(swoc::TextView s)
{
  OwnString out(s.data(), s.size());

  out += '!';
  return out;
}

bool
has_pointer(std::string_view s)
{
  return s.data() != nullptr;
}

bool
always_throws(std::string_view)
{
  throw std::runtime_error("boom");
}

std::optional<std::string>
non_empty(std::string_view s)
{
  if (s.empty()) {
    return std::nullopt;
  }
  return std::string(s);
}

std::optional<int64_t>
positive(int64_t n)
{
  if (n <= 0) {
    return std::nullopt;
  }
  return n;
}

std::optional<bool>
is_a(std::string_view s)
{
  if (s.empty()) {
    return std::nullopt;
  }
  return s == "a";
}

std::optional<OwnString>
own_non_empty(std::string_view s)
{
  if (s.empty()) {
    return std::nullopt;
  }
  return OwnString(s.data(), s.size());
}

hrw4u_rule_ctx *seen_ctx = nullptr;

std::string
ctx_only(hrw4u_rule_ctx *ctx)
{
  seen_ctx = ctx;
  return "from the transaction";
}

bool
ctx_is_jp(hrw4u_rule_ctx *ctx, std::string_view code)
{
  seen_ctx = ctx;
  return code == "JP";
}

struct Recorded {
  std::string             name;
  hrw4u_type              ret;
  std::vector<hrw4u_type> params;
  hrw4u_effect            effect;
  hrw4u_fn                fn;
};

struct Recorder {
  std::vector<Recorded>    decls;
  std::vector<std::string> logs;
  int                      def_result   = 0;
  size_t                   refuse_after = SIZE_MAX;
  bool                     def_throws   = false;
  hrw4u_host_api           api;

  Recorder() : api{HRW4U_EXT_ABI_VERSION, this, &Recorder::def, &Recorder::log} {}

  static int
  def(void *instance, const hrw4u_fn_decl *decl)
  {
    auto *self = static_cast<Recorder *>(instance);

    if (self->def_throws) {
      throw std::bad_alloc();
    }
    self->decls.push_back({
      decl->name,
      decl->ret,
      {decl->params, decl->params + decl->nparams},
      decl->effect,
      decl->fn
    });
    if (self->decls.size() > self->refuse_after) {
      return 1;
    }
    return self->def_result;
  }

  static void
  log(void *instance, const char *message)
  {
    static_cast<Recorder *>(instance)->logs.emplace_back(message);
  }
};

uint64_t
ptr_word(std::string_view s)
{
  return reinterpret_cast<uint64_t>(s.data());
}
} // namespace

HRW4U_MODULE("test", HRW4U_DEF("T::IsJp", HRW4U_EFFECT_PURE, &is_jp));

HRW4U_MODULE_TABLE(test_table, "table", HRW4U_DEF("T::IsJp", HRW4U_EFFECT_PURE, &is_jp),
                   HRW4U_DEF("T::Both", HRW4U_EFFECT_EFFECT, &both));

HRW4U_MODULE_TABLE(string_table, "strings::table", HRW4U_DEF("T::Twice", HRW4U_EFFECT_PURE, &twice));

HRW4U_MODULE_TABLE(ctx_table, "ctx", HRW4U_DEF("T::CtxIsJp", HRW4U_EFFECT_PURE, &ctx_is_jp));

HRW4U_MODULE_TABLE(int_table, "ints", HRW4U_DEF("T::Negate", HRW4U_EFFECT_PURE, &negate));

HRW4U_MODULE_TABLE(load_table, "load", HRW4U_DEF("T::Load", HRW4U_EFFECT_LOAD, &twice));

HRW4U_MODULE_TABLE(optional_table, "optional", HRW4U_DEF("T::NonEmpty", HRW4U_EFFECT_PURE, &non_empty),
                   HRW4U_DEF("T::IsA", HRW4U_EFFECT_PURE, &is_a));

TEST_CASE("def records the signature")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&is_jp>("T::IsJp", HRW4U_EFFECT_PURE);
  m.def<&both>("T::Both", HRW4U_EFFECT_EFFECT);

  REQUIRE(rec.decls.size() == 2);
  CHECK(rec.decls[0].name == "T::IsJp");
  CHECK(rec.decls[0].ret == HRW4U_TYPE_BOOL);
  CHECK(rec.decls[0].params == std::vector<hrw4u_type>{HRW4U_TYPE_SVIEW});
  CHECK(rec.decls[0].effect == HRW4U_EFFECT_PURE);
  CHECK(rec.decls[1].params == std::vector<hrw4u_type>{HRW4U_TYPE_BOOL, HRW4U_TYPE_SVIEW});
  CHECK(rec.decls[1].effect == HRW4U_EFFECT_EFFECT);
  CHECK_FALSE(m.failed());
}

TEST_CASE("the wrapper converts words")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&is_jp>("T::IsJp", HRW4U_EFFECT_PURE);
  m.def<&both>("T::Both", HRW4U_EFFECT_PURE);

  std::string_view jp = "JP";
  std::string_view us = "US";
  std::string_view x  = "x";
  uint64_t         ret[1]{2};

  uint64_t jp_args[] = {ptr_word(jp), jp.size()};
  CHECK(rec.decls[0].fn(nullptr, jp_args, ret) == 0);
  CHECK(ret[0] == 1);

  uint64_t us_args[] = {ptr_word(us), us.size()};
  CHECK(rec.decls[0].fn(nullptr, us_args, ret) == 0);
  CHECK(ret[0] == 0);

  uint64_t both_args[] = {1, ptr_word(x), x.size()};
  CHECK(rec.decls[1].fn(nullptr, both_args, ret) == 0);
  CHECK(ret[0] == 1);
}

TEST_CASE("a leading rule context is passed through, and is not a parameter")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&ctx_is_jp>("T::CtxIsJp", HRW4U_EFFECT_PURE);
  REQUIRE(rec.decls.size() == 1);
  CHECK(rec.decls[0].params == std::vector<hrw4u_type>{HRW4U_TYPE_SVIEW});

  int              transaction = 0;
  auto            *ctx         = reinterpret_cast<hrw4u_rule_ctx *>(&transaction);
  std::string_view jp          = "JP";
  uint64_t         args[]      = {ptr_word(jp), jp.size()};
  uint64_t         ret[HRW4U_RET_WORDS]{2};

  CHECK(rec.decls[0].fn(ctx, args, ret) == 0);
  CHECK(ret[0] == 1);
  CHECK(seen_ctx == ctx);
}

TEST_CASE("a function with only a rule context takes no arguments")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&ctx_only>("T::CtxOnly", HRW4U_EFFECT_PURE);
  REQUIRE(rec.decls.size() == 1);
  CHECK(rec.decls[0].params.empty());

  int      transaction = 0;
  auto    *ctx         = reinterpret_cast<hrw4u_rule_ctx *>(&transaction);
  uint64_t ret[HRW4U_RET_WORDS]{};

  REQUIRE(rec.decls[0].fn(ctx, nullptr, ret) == 0);
  CHECK(std::string_view(reinterpret_cast<const char *>(ret[0]), ret[1]) == "from the transaction");
  CHECK(seen_ctx == ctx);
}

TEST_CASE("a string result comes back as a view")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&twice>("T::Twice", HRW4U_EFFECT_PURE);
  REQUIRE(rec.decls.size() == 1);
  CHECK(rec.decls[0].ret == HRW4U_TYPE_SVIEW);

  std::string_view ab     = "ab";
  uint64_t         args[] = {ptr_word(ab), ab.size()};
  uint64_t         ret[HRW4U_RET_WORDS]{};

  REQUIRE(rec.decls[0].fn(nullptr, args, ret) == 0);
  CHECK(std::string_view(reinterpret_cast<const char *>(ret[0]), ret[1]) == "abab");
}

TEST_CASE("an integer is one word each way, its sign kept")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&negate>("T::Negate", HRW4U_EFFECT_PURE);
  REQUIRE(rec.decls.size() == 1);
  CHECK(rec.decls[0].ret == HRW4U_TYPE_I64);
  CHECK(rec.decls[0].params == std::vector<hrw4u_type>{HRW4U_TYPE_I64});

  uint64_t args[] = {static_cast<uint64_t>(int64_t{-5})};
  uint64_t ret[HRW4U_RET_WORDS]{};

  REQUIRE(rec.decls[0].fn(nullptr, args, ret) == 0);
  CHECK(static_cast<int64_t>(ret[0]) == 5);

  args[0] = 7;
  REQUIRE(rec.decls[0].fn(nullptr, args, ret) == 0);
  CHECK(static_cast<int64_t>(ret[0]) == -7);
}

TEST_CASE("string types derived from the standard ones bind")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&exclaim>("T::Exclaim", HRW4U_EFFECT_PURE);
  REQUIRE(rec.decls.size() == 1);
  CHECK(rec.decls[0].ret == HRW4U_TYPE_SVIEW);
  CHECK(rec.decls[0].params == std::vector<hrw4u_type>{HRW4U_TYPE_SVIEW});

  std::string_view ab     = "ab";
  uint64_t         args[] = {ptr_word(ab), ab.size()};
  uint64_t         ret[HRW4U_RET_WORDS]{};

  REQUIRE(rec.decls[0].fn(nullptr, args, ret) == 0);
  CHECK(std::string_view(reinterpret_cast<const char *>(ret[0]), ret[1]) == "ab!");
}

TEST_CASE("an empty view given as NULL reaches the function with a pointer")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&has_pointer>("T::HasPointer", HRW4U_EFFECT_PURE);

  uint64_t args[] = {0, 0};
  uint64_t ret[HRW4U_RET_WORDS]{};

  REQUIRE(rec.decls[0].fn(nullptr, args, ret) == 0);
  CHECK(ret[0] == 1);
}

TEST_CASE("an exception is a fault")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&always_throws>("T::Throws", HRW4U_EFFECT_PURE);

  std::string_view jp     = "JP";
  uint64_t         args[] = {ptr_word(jp), jp.size()};
  uint64_t         ret[HRW4U_RET_WORDS]{};

  REQUIRE(rec.decls[0].fn(nullptr, args, ret) != 0);
  CHECK(std::string_view(reinterpret_cast<const char *>(ret[0]), ret[1]) == "boom");
}

TEST_CASE("an optional result binds as its value's type, and an empty one is a fault")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&non_empty>("T::NonEmpty", HRW4U_EFFECT_PURE);
  m.def<&positive>("T::Positive", HRW4U_EFFECT_PURE);
  REQUIRE(rec.decls.size() == 2);
  CHECK(rec.decls[0].ret == HRW4U_TYPE_SVIEW);
  CHECK(rec.decls[1].ret == HRW4U_TYPE_I64);

  std::string_view ab     = "ab";
  uint64_t         args[] = {ptr_word(ab), ab.size()};
  uint64_t         ret[HRW4U_RET_WORDS]{};

  REQUIRE(rec.decls[0].fn(nullptr, args, ret) == 0);
  CHECK(std::string_view(reinterpret_cast<const char *>(ret[0]), ret[1]) == "ab");

  args[0] = 0;
  args[1] = 0;
  REQUIRE(rec.decls[0].fn(nullptr, args, ret) != 0);
  CHECK(std::string_view(reinterpret_cast<const char *>(ret[0]), ret[1]) == "no value");

  uint64_t n[] = {3};

  REQUIRE(rec.decls[1].fn(nullptr, n, ret) == 0);
  CHECK(ret[0] == 3);

  n[0] = 0;
  REQUIRE(rec.decls[1].fn(nullptr, n, ret) != 0);
  CHECK(std::string_view(reinterpret_cast<const char *>(ret[0]), ret[1]) == "no value");
}

TEST_CASE("an optional holding false or a derived string is a value, not a fault")
{
  Recorder           rec;
  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&is_a>("T::IsA", HRW4U_EFFECT_PURE);
  m.def<&own_non_empty>("T::OwnNonEmpty", HRW4U_EFFECT_PURE);
  REQUIRE(rec.decls.size() == 2);
  CHECK(rec.decls[0].ret == HRW4U_TYPE_BOOL);
  CHECK(rec.decls[1].ret == HRW4U_TYPE_SVIEW);

  std::string_view b      = "b";
  uint64_t         args[] = {ptr_word(b), b.size()};
  uint64_t         ret[HRW4U_RET_WORDS]{};

  ret[0] = 1;
  REQUIRE(rec.decls[0].fn(nullptr, args, ret) == 0);
  CHECK(ret[0] == 0);

  REQUIRE(rec.decls[1].fn(nullptr, args, ret) == 0);
  CHECK(std::string_view(reinterpret_cast<const char *>(ret[0]), ret[1]) == "b");
}

TEST_CASE("a refused def marks the module failed")
{
  Recorder rec;

  rec.def_result = 1;

  hrw4u::ext::Module m(&rec.api, "test");

  m.def<&is_jp>("T::IsJp", HRW4U_EFFECT_PURE);
  CHECK(m.failed());
}

TEST_CASE("HRW4U_MODULE exports the entry points")
{
  Recorder rec;

  CHECK(hrw4u_ext_abi_version == HRW4U_EXT_ABI_VERSION);
  CHECK(hrw4u_ext_init(&rec.api) == 0);
  REQUIRE(rec.decls.size() == 1);
  CHECK(rec.decls[0].name == "T::IsJp");
  hrw4u_ext_fini(&rec.api);
}

TEST_CASE("a module table registers each function in order")
{
  Recorder rec;

  CHECK(test_table::define(&rec.api));
  REQUIRE(rec.decls.size() == 2);
  CHECK(rec.decls[0].name == "T::IsJp");
  CHECK(rec.decls[0].params == std::vector<hrw4u_type>{HRW4U_TYPE_SVIEW});
  CHECK(rec.decls[0].effect == HRW4U_EFFECT_PURE);
  CHECK(rec.decls[1].name == "T::Both");
  CHECK(rec.decls[1].params == std::vector<hrw4u_type>{HRW4U_TYPE_BOOL, HRW4U_TYPE_SVIEW});
  CHECK(rec.decls[1].effect == HRW4U_EFFECT_EFFECT);
}

TEST_CASE("a module table registers a load function with its effect")
{
  Recorder rec;

  CHECK(load_table::define(&rec.api));
  REQUIRE(rec.decls.size() == 1);
  CHECK(rec.decls[0].name == "T::Load");
  CHECK(rec.decls[0].effect == HRW4U_EFFECT_LOAD);
}

TEST_CASE("a module table fails when the host refuses a function")
{
  Recorder rec;

  rec.def_result = 1;
  CHECK_FALSE(test_table::define(&rec.api));
}

TEST_CASE("a module table offers every function even after the host refuses one")
{
  Recorder rec;

  rec.refuse_after = 1;
  CHECK_FALSE(test_table::define(&rec.api));
  CHECK(rec.decls.size() == 2);
}

TEST_CASE("HRW4U_MODULE fails init, rather than unwinding into the host, when the host's def throws")
{
  Recorder rec;

  rec.def_throws = true;
  CHECK(hrw4u_ext_init(&rec.api) != 0);
}

TEST_CASE("HRW4U_MODULE refuses a host of another ABI version")
{
  Recorder rec;

  rec.api.abi_version = HRW4U_EXT_ABI_VERSION + 1;
  CHECK(hrw4u_ext_init(&rec.api) != 0);
  CHECK(rec.decls.empty());
}

TEST_CASE("a module table writes its signatures as manifest text")
{
  CHECK(std::string_view(test_table::manifest.data(), test_table::manifest.size()) == "hrw4u-manifest 1\n"
                                                                                      "module table\n"
                                                                                      "fn T::IsJp pure bool sview\n"
                                                                                      "fn T::Both effect bool bool sview\n"
                                                                                      "end\n");
  CHECK(std::string_view(string_table::manifest.data(), string_table::manifest.size()) == "hrw4u-manifest 1\n"
                                                                                          "module strings::table\n"
                                                                                          "fn T::Twice pure sview sview\n"
                                                                                          "end\n");
  CHECK(std::string_view(ctx_table::manifest.data(), ctx_table::manifest.size()) == "hrw4u-manifest 1\n"
                                                                                    "module ctx\n"
                                                                                    "fn T::CtxIsJp pure bool sview\n"
                                                                                    "end\n");
  CHECK(std::string_view(int_table::manifest.data(), int_table::manifest.size()) == "hrw4u-manifest 1\n"
                                                                                    "module ints\n"
                                                                                    "fn T::Negate pure i64 i64\n"
                                                                                    "end\n");
  CHECK(std::string_view(load_table::manifest.data(), load_table::manifest.size()) == "hrw4u-manifest 1\n"
                                                                                      "module load\n"
                                                                                      "fn T::Load load sview sview\n"
                                                                                      "end\n");
  CHECK(std::string_view(optional_table::manifest.data(), optional_table::manifest.size()) == "hrw4u-manifest 1\n"
                                                                                              "module optional\n"
                                                                                              "fn T::NonEmpty pure sview sview\n"
                                                                                              "fn T::IsA pure bool sview\n"
                                                                                              "end\n");
}
