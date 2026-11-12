/** @file

  Unit tests for the functions prism.so gives the IR, called through the registry as prism.so calls them.

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

#include "cripts_bindings.h"
#include "registry.h"

#include "ts/ts.h"
#include "tsutil/StringConvert.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace hrw4u;

namespace
{
// std::nullopt only for the fault an empty optional gives, so a binding that throws fails the test.
std::optional<std::string>
call(std::string_view name, std::initializer_list<std::string_view> params)
{
  Registry reg([](std::string_view) {});

  REQUIRE(def_cripts_bindings(reg.host_api()));

  const auto *entry = reg.find(name);

  REQUIRE(entry != nullptr);

  std::vector<uint64_t> args;

  for (auto p : params) {
    args.push_back(reinterpret_cast<uint64_t>(p.data()));
    args.push_back(p.size());
  }

  uint64_t          ret[HRW4U_RET_WORDS]{};
  const int         rc = entry->fn(nullptr, args.data(), ret);
  const std::string out(reinterpret_cast<const char *>(ret[0]), ret[1]);

  if (rc != 0) {
    REQUIRE(out == "no value");
    return std::nullopt;
  }
  return out;
}

std::optional<std::string>
hex_decode(std::string_view hex)
{
  return call("prism::Crypto::Hex::Decode", {hex});
}

struct TempDir {
  std::filesystem::path path =
    std::filesystem::temp_directory_path() /
    ("prism_bindings_test_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

  TempDir() { std::filesystem::create_directories(path); }
  ~TempDir()
  {
    std::error_code ec;

    std::filesystem::remove_all(path, ec);
  }
};
} // namespace

TEST_CASE("Hex::Decode: both cases, NUL bytes and the empty string", "[prism][bindings]")
{
  CHECK(hex_decode("00ff7FaB") == std::string("\x00\xff\x7f\xab", 4));
  CHECK(hex_decode("") == std::string{});
}

TEST_CASE("Hex::Decode: every digit", "[prism][bindings]")
{
  CHECK(hex_decode("0123456789abcdefABCDEF") == std::string("\x01\x23\x45\x67\x89\xab\xcd\xef\xab\xcd\xef", 11));
}

TEST_CASE("Hex::Decode rejects an odd length and a non-digit in either place of a pair", "[prism][bindings]")
{
  CHECK_FALSE(hex_decode("abc"));
  CHECK_FALSE(hex_decode("0z00"));
  CHECK_FALSE(hex_decode("z000"));
  CHECK_FALSE(hex_decode("000z"));
  CHECK_FALSE(hex_decode("0x00"));
  CHECK_FALSE(hex_decode(" 000"));
}

TEST_CASE("Hex::Decode rejects the characters next to each digit range, and high-bit bytes", "[prism][bindings]")
{
  for (std::string_view bad : {"/0", ":0", "@0", "G0", "`0", "g0", "0/", "0:", "0@", "0G", "0`", "0g"}) {
    CHECK_FALSE(hex_decode(bad));
  }
  CHECK_FALSE(hex_decode(std::string_view("\x80\x00", 2)));
  CHECK_FALSE(hex_decode("\xff"
                         "0"));
}

TEST_CASE("HMAC::SHA256::Sign takes the key first, as RFC 4231 test case 2", "[prism][bindings]")
{
  auto mac = call("prism::Crypto::HMAC::SHA256::Sign", {"Jefe", "what do ya want for nothing?"});

  REQUIRE(mac);
  CHECK(ts::hex(*mac) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST_CASE("Base64::Encode", "[prism][bindings]")
{
  CHECK(call("prism::Crypto::Base64::Encode", {"foobar"}) == "Zm9vYmFy");
}

TEST_CASE("File::Line::Read: the first line of an absolute path", "[prism][bindings]")
{
  TempDir dir;
  auto    file = dir.path / "key.hex";

  std::ofstream{file} << "00ff\nsecond\n";
  CHECK(call("prism::File::Line::Read", {file.string()}) == "00ff");
}

TEST_CASE("File::Line::Read: a relative path from the config directory", "[prism][bindings]")
{
  std::filesystem::path dir{TSConfigDirGet()};

  std::ofstream{dir / "prism_bindings_test.hex"} << "abcd\n";
  CHECK(call("prism::File::Line::Read", {"prism_bindings_test.hex"}) == "abcd");
  std::filesystem::remove(dir / "prism_bindings_test.hex");
}

TEST_CASE("File::Line::Read: no value for a relative path out of the config directory", "[prism][bindings]")
{
  std::filesystem::path outside = std::filesystem::path{TSConfigDirGet()}.parent_path() / "prism_bindings_outside.hex";

  std::ofstream{outside} << "abcd\n";
  CHECK_FALSE(call("prism::File::Line::Read", {"../prism_bindings_outside.hex"}));
  std::filesystem::remove(outside);
}

TEST_CASE("File::Line::Read: no value for a missing file or an empty first line", "[prism][bindings]")
{
  TempDir dir;
  auto    empty = dir.path / "empty";

  std::ofstream{empty} << "\nsecond\n";
  CHECK_FALSE(call("prism::File::Line::Read", {(dir.path / "missing").string()}));
  CHECK_FALSE(call("prism::File::Line::Read", {empty.string()}));
}
