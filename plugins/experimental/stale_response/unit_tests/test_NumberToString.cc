/** @file

  Unit tests for the base16 helpers used by the stale_response plugin.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "NumberToString.h"

#include <catch2/catch_test_macros.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

TEST_CASE("base16_decode respects the destination length", "[base16]")
{
  SECTION("A source that exactly fills the destination is fully decoded")
  {
    std::array<unsigned char, 4> dst{};
    REQUIRE(base16_decode(dst.data(), dst.size(), "0badc0de", 8) == 4);
    CHECK(dst == std::array<unsigned char, 4>{0x0b, 0xad, 0xc0, 0xde});
  }

  SECTION("A source longer than the destination is truncated, not overflowed")
  {
    // The trailing guard bytes stand in for whatever lives next to a small
    // destination on the stack.
    std::array<unsigned char, 12> buffer;
    buffer.fill(0xcc);

    std::string const oversized(1024, '4');

    REQUIRE(base16_decode(buffer.data(), 4, oversized.c_str(), oversized.length()) == 4);
    CHECK(buffer[0] == 0x44);
    CHECK(buffer[3] == 0x44);
    for (std::size_t i = 4; i < buffer.size(); ++i) {
      CHECK(buffer[i] == 0xcc);
    }
  }

  SECTION("A zero length destination is never written to")
  {
    unsigned char guard = 0xcc;

    REQUIRE(base16_decode(&guard, 0, "0badc0de", 8) == 0);
    CHECK(guard == 0xcc);
  }

  SECTION("A source shorter than the destination decodes only what it holds")
  {
    std::array<unsigned char, 4> dst{};
    dst.fill(0xcc);

    REQUIRE(base16_decode(dst.data(), dst.size(), "0bad", 4) == 2);
    CHECK(dst[0] == 0x0b);
    CHECK(dst[1] == 0xad);
    CHECK(dst[2] == 0xcc);
    CHECK(dst[3] == 0xcc);
  }

  SECTION("A trailing odd digit is ignored")
  {
    std::array<unsigned char, 4> dst{};
    dst.fill(0xcc);

    REQUIRE(base16_decode(dst.data(), dst.size(), "0bad0", 5) == 2);
    CHECK(dst[2] == 0xcc);
  }

  SECTION("Decoding stops at the first non hexadecimal digit")
  {
    std::array<unsigned char, 4> dst{};
    dst.fill(0xcc);

    REQUIRE(base16_decode(dst.data(), dst.size(), "0badzzzz", 8) == 2);
    CHECK(dst[0] == 0x0b);
    CHECK(dst[1] == 0xad);
    CHECK(dst[2] == 0xcc);
  }
}

TEST_CASE("base16_encode and base16_decode round trip", "[base16]")
{
  uint32_t const key = 0xdeadbeef;
  char           encoded[10];

  base16_encode(encoded, reinterpret_cast<unsigned char const *>(&key), sizeof(key));
  REQUIRE(std::strlen(encoded) == 8);

  uint32_t decoded = 0;
  REQUIRE(base16_decode(reinterpret_cast<unsigned char *>(&decoded), sizeof(decoded), encoded, std::strlen(encoded)) ==
          sizeof(decoded));
  CHECK(decoded == key);
}
