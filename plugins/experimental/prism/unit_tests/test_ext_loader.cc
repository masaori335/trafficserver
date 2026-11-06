/** @file

  Unit tests for loading extension .so files.

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

#include "ext_loader.h"
#include "registry.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <utility>
#include <string>
#include <string_view>

using namespace hrw4u;

namespace
{
void
ignore(std::string_view)
{
}

// Calls a function of one sview argument the extension registered, and gives its two result words.
std::pair<uint64_t, uint64_t>
call(const Registry &reg, std::string_view name, std::string_view ua)
{
  const Registry::Entry *entry  = reg.find(name);
  uint64_t               args[] = {reinterpret_cast<uint64_t>(ua.data()), ua.size()};
  uint64_t               ret[HRW4U_RET_WORDS]{};

  REQUIRE(entry != nullptr);
  REQUIRE(entry->fn(nullptr, args, ret) == 0);
  return {ret[0], ret[1]};
}

bool
is_bot(const Registry &reg, std::string_view ua)
{
  return call(reg, "Example::UA::IsBot", ua).first != 0;
}

std::string
family(const Registry &reg, std::string_view ua)
{
  auto [data, size] = call(reg, "Example::UA::Family", ua);

  return {reinterpret_cast<const char *>(data), size};
}
} // namespace

TEST_CASE("loads the example extension")
{
  Registry    reg(ignore);
  std::string error;
  auto        ext = LoadedExtension::load(EXAMPLE_UA_SO, reg.host_api(), error);

  INFO(error);
  REQUIRE(ext != nullptr);
  CHECK(is_bot(reg, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"));
  CHECK(is_bot(reg, "SomeCrawler/1.0"));
  CHECK(is_bot(reg, "Baiduspider/2.0"));
  CHECK_FALSE(is_bot(reg, "curl/8.4.0"));
  CHECK(family(reg, "curl/8.4.0") == "curl");
  CHECK(family(reg, "Mozilla/5.0 (Macintosh; rv:121.0) Gecko/20100101 Firefox/121.0") == "firefox");
  CHECK(family(reg, "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Edg/120.0") == "edge");
  CHECK(family(reg, "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/120.0 Safari/537.36") == "chrome");
  CHECK(family(reg, "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15") == "safari");
  CHECK(family(reg, "Wget/1.21") == "other");
}

TEST_CASE("a missing .so names its path")
{
  Registry    reg(ignore);
  std::string error;

  CHECK(LoadedExtension::load("/nonexistent/hrw4u_ext.so", reg.host_api(), error) == nullptr);
  CHECK(error.find("/nonexistent/hrw4u_ext.so") != std::string::npos);
}

TEST_CASE("a different ABI version is refused")
{
  Registry    reg(ignore);
  std::string error;

  CHECK(LoadedExtension::load(WRONG_ABI_SO, reg.host_api(), error) == nullptr);
  CHECK(error.find("ABI") != std::string::npos);
  CHECK(error.find(WRONG_ABI_SO) != std::string::npos);
}

TEST_CASE("a .so without hrw4u_ext_init is refused")
{
  Registry    reg(ignore);
  std::string error;

  CHECK(LoadedExtension::load(NO_INIT_SO, reg.host_api(), error) == nullptr);
  CHECK(error.find("hrw4u_ext_init") != std::string::npos);
}

TEST_CASE("an extension can be unloaded and loaded again")
{
  std::string error;

  {
    Registry reg(ignore);
    auto     ext = LoadedExtension::load(EXAMPLE_UA_SO, reg.host_api(), error);

    REQUIRE(ext != nullptr);
  }

  Registry reg(ignore);
  auto     ext = LoadedExtension::load(EXAMPLE_UA_SO, reg.host_api(), error);

  INFO(error);
  REQUIRE(ext != nullptr);
  CHECK(is_bot(reg, "Googlebot/2.1"));
}

TEST_CASE("two instances share one .so, and one can go while the other keeps working")
{
  std::string error;
  Registry    first(ignore);
  Registry    second(ignore);
  auto        first_ext  = LoadedExtension::load(EXAMPLE_UA_SO, first.host_api(), error);
  auto        second_ext = LoadedExtension::load(EXAMPLE_UA_SO, second.host_api(), error);

  INFO(error);
  REQUIRE(first_ext != nullptr);
  REQUIRE(second_ext != nullptr);

  first_ext.reset();
  CHECK(is_bot(second, "Googlebot/2.1"));
  CHECK(family(second, "curl/8.4.0") == "curl");
}
