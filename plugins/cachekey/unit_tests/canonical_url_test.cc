/*
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

#include <catch2/catch_test_macros.hpp>
#include "common.h"

TEST_CASE("buildCanonicalUrlPrefix encodes host bytes", "[cachekey][canonical]")
{
  SECTION("plain host: scheme://host:port unchanged")
  {
    REQUIRE(buildCanonicalUrlPrefix("https", "example.com", "443", true, true) == "https://example.com:443");
  }

  SECTION("host with %2f is re-encoded under canonical prefix")
  {
    // The cache hashes the resulting key as a URL and decodes percent
    // sequences. Without re-encoding here, '%2f' in the Host header would
    // collapse into a path separator and collide with a different host.
    REQUIRE(buildCanonicalUrlPrefix("http", "example.com%2fevil", "80", true, true) == "http://example.com%252fevil:80");
  }

  SECTION("host with %2f is re-encoded under default key")
  {
    REQUIRE(buildCanonicalUrlPrefix("http", "example.com%2fevil", "80", false, true) == "/example.com%252fevil/80");
  }

  SECTION("host with %2f is re-encoded under canonical capture-prefix")
  {
    // CacheKey::appendPrefix feeds --capture-prefix captures under
    // --canonical-prefix from getCanonicalUrl(canonicalPrefix=true,
    // provideDefaultKey=false) and appends them raw, so the host must be
    // encoded here. This shape is distinct from the (true, true) default
    // prefix: dropping the canonicalPrefix term from encodeHost would reopen
    // the collision only for this config.
    REQUIRE(buildCanonicalUrlPrefix("http", "example.com%2fevil", "80", true, false) == "http://example.com%252fevil:80");
  }

  SECTION("regex-input form leaves host raw for downstream encoding")
  {
    // The regex-input shape (canonicalPrefix=false, provideDefaultKey=false)
    // is appended to the cache key via the encoded path in
    // CacheKey::appendPrefix (--capture-prefix). Encoding here would
    // double-encode. The downstream appendEncoded handles the round-trip.
    REQUIRE(buildCanonicalUrlPrefix("http", "example.com%2fevil", "80", false, false) == "example.com%2fevil:80");
  }

  SECTION("regex-input round-trip through appendEncoded preserves %2f")
  {
    // Simulate what CacheKey::appendPrefix does when --capture-prefix
    // matches the whole host:port and appends the capture verbatim through
    // appendEncoded. The final encoded bytes must contain %252f so the
    // cache's URL parser decodes back to %2f and not '/'.
    String      raw = buildCanonicalUrlPrefix("http", "example.com%2fevil", "80", false, false);
    char        buf[256];
    std::size_t written = 0;
    REQUIRE(cachekey_encode_value(raw.data(), raw.size(), buf, sizeof(buf), &written));
    REQUIRE(String(buf, written) == "example.com%252fevil:80");
  }

  SECTION("a %2f host is encoded while a literal / host is left intact")
  {
    // The encoding must turn %2f into %252f (so the cache's URL parser decodes
    // it back to %2f, not a path separator) while leaving a genuine '/' alone.
    REQUIRE(buildCanonicalUrlPrefix("http", "a%2fb", "80", true, true) == "http://a%252fb:80");
    REQUIRE(buildCanonicalUrlPrefix("http", "a/b", "80", true, true) == "http://a/b:80");
  }

  SECTION("structural delimiters survive while the host is encoded")
  {
    // A host carrying bytes the encoder touches ('%') must not disturb the
    // scheme '://' and ':port' delimiters.
    auto out = buildCanonicalUrlPrefix("https", "h%2fx", "443", true, true);
    REQUIRE(out == "https://h%252fx:443");
    REQUIRE(out.starts_with("https://"));
    REQUIRE(out.ends_with(":443"));
  }
}

TEST_CASE("cachekey_encode_value follows the documented escape policy", "[cachekey][encode]")
{
  auto encode = [](const String &input) {
    char        buf[256];
    std::size_t written = 0;
    REQUIRE(cachekey_encode_value(input.data(), input.size(), buf, sizeof(buf), &written));
    return String(buf, written);
  };

  SECTION("alphanumerics pass through")
  {
    REQUIRE(encode("abcXYZ0123") == "abcXYZ0123");
  }

  SECTION("percent is encoded so existing percent-sequences round-trip")
  {
    REQUIRE(encode("%2f") == "%252f");
  }

  SECTION("space, comma, and other reserved chars are encoded")
  {
    REQUIRE(encode(" ") == "%20");
    REQUIRE(encode(",") == "%2C");
    REQUIRE(encode("<") == "%3C");
  }

  SECTION("non-ASCII is left unmodified per the documented policy")
  {
    String input{static_cast<char>(0x80), static_cast<char>(0xFF)};
    REQUIRE(encode(input) == input);
  }

  SECTION("every byte 0-255 matches the documented policy")
  {
    // Independent description of the policy so a change to the encode bitmap
    // cannot silently pass: control chars (0-31), DEL (127), the reserved set
    // below, and nothing in 128-255.
    static const std::string reserved = " \"#%,<>[\\]^`{|}~";
    auto                     hex      = [](unsigned char c) {
      static const char *d = "0123456789ABCDEF";
      return String("%") + d[c >> 4] + d[c & 0xF];
    };

    for (int i = 0; i < 256; ++i) {
      unsigned char const c          = static_cast<unsigned char>(i);
      bool const          should_enc = (c < 0x20) || (c == 0x7F) || (reserved.find(static_cast<char>(c)) != String::npos);
      String const        input(1, static_cast<char>(c));
      CAPTURE(i);
      REQUIRE(encode(input) == (should_enc ? hex(c) : input));
    }
  }

  SECTION("returns false when destination buffer is too small")
  {
    char        buf[2];
    std::size_t written = 42;
    REQUIRE_FALSE(cachekey_encode_value("%2f", 3, buf, sizeof(buf), &written));
    REQUIRE(written == 0);
  }
}
