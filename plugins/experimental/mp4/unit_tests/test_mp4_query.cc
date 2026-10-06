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

#include <catch2/catch_test_macros.hpp> /* catch unit-test framework */

#include "../mp4_query.h"

#include <cmath>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

TEST_CASE("mp4_query_param finds a value", "[mp4][query]")
{
  SECTION("only parameter")
  {
    CHECK(mp4_query_param("start=12.5", "start") == "12.5");
  }
  SECTION("first of several")
  {
    CHECK(mp4_query_param("start=3&a=1", "start") == "3");
  }
  SECTION("last of several")
  {
    CHECK(mp4_query_param("a=1&start=3", "start") == "3");
  }
  SECTION("middle of several")
  {
    CHECK(mp4_query_param("a=1&start=3&b=2", "start") == "3");
  }
  SECTION("empty value")
  {
    auto v = mp4_query_param("a=1&start=&b=2", "start");
    CHECK(v.data() != nullptr);
    CHECK(v.empty());
  }
  SECTION("first match wins when the parameter repeats")
  {
    CHECK(mp4_query_param("start=0&start=5", "start") == "0");
  }
}

TEST_CASE("mp4_query_param rejects non-parameters", "[mp4][query]")
{
  SECTION("absent")
  {
    CHECK(mp4_query_param("a=1&b=2", "start").data() == nullptr);
  }
  SECTION("empty query")
  {
    CHECK(mp4_query_param("", "start").data() == nullptr);
  }
  SECTION("key is a suffix of another key, not its own parameter")
  {
    CHECK(mp4_query_param("mystart=3", "start").data() == nullptr);
  }
  SECTION("key is a substring of a value")
  {
    CHECK(mp4_query_param("a=start&b=2", "start").data() == nullptr);
  }
  // An empty key names no parameter. Without an explicit answer it would find a
  // zero length match at the front and read a query beginning with '=' as
  // having a nameless parameter.
  SECTION("an empty key never matches")
  {
    CHECK(mp4_query_param("start=5&a=1", "").data() == nullptr);
    CHECK(mp4_query_param("=5&a=1", "").data() == nullptr);
    CHECK(mp4_query_param("", "").data() == nullptr);
    CHECK(mp4_query_without_param("=5&a=1", "") == "=5&a=1");
  }
  // A candidate that fails the parameter test must not end the search. Without
  // this the scan could stop at "starts" and miss the real parameter behind it.
  SECTION("a failing candidate does not hide a later real parameter")
  {
    CHECK(mp4_query_param("starts=1&start=2", "start") == "2");
    CHECK(mp4_query_param("a=startx&start=9", "start") == "9");
    CHECK(mp4_query_param("mystart=1&start=4", "start") == "4");
  }
  // The query handed to the plugin comes from the header heap with an explicit
  // length and no NUL terminator, so a key sitting flush against the end must be
  // rejected without reading the byte that follows it. These views deliberately
  // stop short of a buffer that continues with the very byte a careless bounds
  // check would accept, so passing them requires honouring the length.
  SECTION("key at end of query, with an equals sign just past the end")
  {
    std::string const      buffer = "a=1&start=5";
    std::string_view const query{buffer.data(), 9}; // "a=1&start"
    CHECK(mp4_query_param(query, "start").data() == nullptr);
  }
  // This one cannot fail against the current implementation, because find on a
  // view cannot match past its end. It guards against a future rewrite going
  // back to a raw memory search with the wrong length, which is what the code
  // this replaced did.
  SECTION("key truncated at end of query, with the rest just past the end")
  {
    std::string const      buffer = "a=1&start=5";
    std::string_view const query{buffer.data(), 8}; // "a=1&star"
    CHECK(mp4_query_param(query, "start").data() == nullptr);
  }
  SECTION("value view ends exactly at the end of the query")
  {
    std::string const      buffer = "a=1&start=";
    std::string_view const query{buffer.data(), buffer.size()};
    auto const             v = mp4_query_param(query, "start");
    CHECK(v.data() != nullptr);
    CHECK(v.empty());
  }
}

TEST_CASE("mp4_query_parse_float accepts the documented start forms", "[mp4][query]")
{
  float f = -1;
  SECTION("plain integer")
  {
    REQUIRE(mp4_query_parse_float("12", f));
    CHECK(f == 12.0f);
  }
  SECTION("decimal")
  {
    REQUIRE(mp4_query_parse_float("12.5", f));
    CHECK(f == 12.5f);
  }
  SECTION("negative")
  {
    REQUIRE(mp4_query_parse_float("-3", f));
    CHECK(f == -3.0f);
  }
  SECTION("leading plus")
  {
    REQUIRE(mp4_query_parse_float("+7", f));
    CHECK(f == 7.0f);
  }
  SECTION("leading spaces")
  {
    REQUIRE(mp4_query_parse_float("  7", f));
    CHECK(f == 7.0f);
  }
  SECTION("exponent")
  {
    REQUIRE(mp4_query_parse_float("1e2", f));
    CHECK(f == 100.0f);
  }
  SECTION("valid prefix followed by junk")
  {
    REQUIRE(mp4_query_parse_float("5abc", f));
    CHECK(f == 5.0f);
  }
}

TEST_CASE("mp4_query_parse_float rejects non-numbers", "[mp4][query]")
{
  float f = 99;
  SECTION("empty")
  {
    CHECK_FALSE(mp4_query_parse_float("", f));
    CHECK(f == 99);
  }
  SECTION("letters")
  {
    CHECK_FALSE(mp4_query_parse_float("abc", f));
    CHECK(f == 99);
  }
  SECTION("only a sign")
  {
    CHECK_FALSE(mp4_query_parse_float("+", f));
    CHECK(f == 99);
  }
  // A number the conversion cannot complete, such as an exponent with no digits
  // or the start of a spelled out infinity, is where C libraries genuinely
  // disagree: some report no match, others hand back the digits they had
  // already taken. So assert the property that actually matters and is portable,
  // that this agrees with the platform's own conversion, rather than a specific
  // answer. Reading the longest valid prefix instead, which is what from_chars
  // and strtof do, diverges from the library on every one of these wherever the
  // library reports no match.
  SECTION("an incomplete number agrees with the platform's own conversion")
  {
    for (auto const *text : {"1e", "1E", "1e+", "1e-", "3.4e", "0x1p", "0x", "infi", "INFI", "-infi", "nan(", "nan(1"}) {
      float      expected  = 0;
      bool const reference = std::sscanf(text, "%f", &expected) == 1;
      float      actual    = 0;
      bool const parsed    = mp4_query_parse_float(text, actual);
      CAPTURE(text);
      CHECK(parsed == reference);
      if (reference) {
        CHECK(((actual == expected) || (std::isnan(actual) && std::isnan(expected))));
      }
    }
  }
  // Reading a non-terminated buffer is what let the old parse run past the
  // value. The digits here continue immediately past the view with no separator
  // to stop on, so only respecting the length gives the right answer.
  SECTION("stops at the end of the view with no separator to stop on")
  {
    std::string const      buffer = "12345";
    std::string_view const value{buffer.data(), 2};
    REQUIRE(mp4_query_parse_float(value, f));
    CHECK(f == 12.0f);
  }
  // Every form the parse accepts has to respect the view, not just plain digits.
  // Two of these cross a branch boundary in the caller: a value that reads as 0
  // means no seek at all, and a negative value means a rejected request.
  SECTION("a hexadecimal value is cut by the view")
  {
    std::string const      buffer = "0x10";
    std::string_view const value{buffer.data(), 1};
    REQUIRE(mp4_query_parse_float(value, f));
    CHECK(f == 0.0f);
  }
  SECTION("a sign alone is not a value, even with digits past the view")
  {
    std::string const      buffer = "-5";
    std::string_view const value{buffer.data(), 1};
    CHECK_FALSE(mp4_query_parse_float(value, f));
  }
  SECTION("infinity is not read from past the view")
  {
    std::string const      buffer = "inf";
    std::string_view const value{buffer.data(), 1};
    CHECK_FALSE(mp4_query_parse_float(value, f));
  }
  SECTION("a fraction is cut by the view")
  {
    std::string const      buffer = "1.5";
    std::string_view const value{buffer.data(), 2};
    REQUIRE(mp4_query_parse_float(value, f));
    CHECK(f == 1.0f);
  }
  SECTION("leading spaces do not let the parse reach past the view")
  {
    std::string const      buffer = "  12";
    std::string_view const value{buffer.data(), 2};
    CHECK_FALSE(mp4_query_parse_float(value, f));
  }
  // The digits continue immediately past the view with no separator to stop on,
  // so a parse that ignored the length would read a larger number. Cutting
  // before the exponent leaves a value that is still complete on its own.
  SECTION("stops at the end of the view before an exponent")
  {
    std::string const      buffer = "12e5";
    std::string_view const value{buffer.data(), 2};
    REQUIRE(mp4_query_parse_float(value, f));
    CHECK(f == 12.0f);
  }
  SECTION("stops at the end of the view when a separator follows")
  {
    std::string const      buffer = "12&next=34";
    std::string_view const value{buffer.data(), 2};
    REQUIRE(mp4_query_parse_float(value, f));
    CHECK(f == 12.0f);
  }
}

TEST_CASE("mp4_query_without_param removes the parameter and its separator", "[mp4][query]")
{
  SECTION("only parameter")
  {
    CHECK(mp4_query_without_param("start=3", "start") == "");
  }
  SECTION("first parameter")
  {
    CHECK(mp4_query_without_param("start=3&a=1", "start") == "a=1");
  }
  SECTION("last parameter")
  {
    CHECK(mp4_query_without_param("a=1&start=3", "start") == "a=1");
  }
  SECTION("middle parameter")
  {
    CHECK(mp4_query_without_param("a=1&start=3&b=2", "start") == "a=1&b=2");
  }
  SECTION("middle parameter with several trailing parameters")
  {
    CHECK(mp4_query_without_param("a=1&start=3&b=2&c=3", "start") == "a=1&b=2&c=3");
  }
  SECTION("absent leaves the query alone")
  {
    CHECK(mp4_query_without_param("a=1&b=2", "start") == "a=1&b=2");
  }
  SECTION("empty query")
  {
    CHECK(mp4_query_without_param("", "start") == "");
  }
  // Only one of the two separators around the parameter comes out. A query that
  // ends in '&' keeps it, because dropping it would change the cache key and
  // the request sent upstream for a query that is perfectly legal.
  SECTION("a trailing separator is preserved")
  {
    CHECK(mp4_query_without_param("a=1&start=3&", "start") == "a=1&");
    CHECK(mp4_query_without_param("a=1&b=2&start=3&", "start") == "a=1&b=2&");
    CHECK(mp4_query_without_param("&&start=3&", "start") == "&&");
    CHECK(mp4_query_without_param("a=1&start=3&b=2&", "start") == "a=1&b=2&");
  }
  SECTION("a parameter that is the whole query leaves nothing behind")
  {
    CHECK(mp4_query_without_param("start=3&", "start") == "");
    CHECK(mp4_query_without_param("&start=3", "start") == "");
  }
  // Empty parameters in the original are carried through untouched rather than
  // tidied up, so the result stays a faithful copy of what the client sent.
  SECTION("empty neighbouring parameters are preserved")
  {
    CHECK(mp4_query_without_param("a=1&&start=3", "start") == "a=1&");
    CHECK(mp4_query_without_param("start=3&&a=1", "start") == "&a=1");
    CHECK(mp4_query_without_param("a=1&start=3&&", "start") == "a=1&&");
    CHECK(mp4_query_without_param("&&start=3", "start") == "&");
    CHECK(mp4_query_without_param("b=&start=3", "start") == "b=");
  }
  // Only the first occurrence is the parameter, so a repeat is left in place.
  SECTION("a repeated parameter is left in the result")
  {
    CHECK(mp4_query_without_param("start=1&start=2", "start") == "start=2");
  }
  // Both separator rules apply here, because taking the '&' in front of the
  // parameter leaves nothing before it, so the one behind it goes as well. The
  // empty leading parameter disappears with it.
  SECTION("both separator rules can apply to one query")
  {
    CHECK(mp4_query_without_param("&start=3&b=2", "start") == "b=2");
    CHECK(mp4_query_without_param("&start=3&", "start") == "");
    CHECK(mp4_query_without_param("&start=&a=1", "start") == "a=1");
  }
  // The query is not percent-decoded before the plugin sees it, so an encoded
  // separator is an ordinary character and the value runs to the end of the
  // query. Everything after "start=" is therefore part of the parameter being
  // removed. That is worth stating plainly: this is the one shape where the
  // result is much shorter than the input by design rather than by truncation.
  SECTION("an encoded separator does not split a parameter")
  {
    CHECK(mp4_query_without_param("start=1%26keep=yes", "start") == "");
    CHECK(mp4_query_without_param("a=1&start=1%26keep=yes", "start") == "a=1");
  }
  // A NUL is an ordinary byte to the rewrite, because the length is what bounds
  // it. Only a compliance setting well below the default lets one through, but
  // the rewrite should carry it like anything else.
  SECTION("a NUL byte in the query is carried through")
  {
    std::string const buffer  = std::string("a=1&start=1\0"
                                             "2&b=3",
                                            17);
    std::string const trimmed = mp4_query_without_param(buffer, "start");
    CHECK(trimmed == "a=1&b=3");
  }
  // Rewrites of one and two bytes, which the length sweep cannot express.
  SECTION("a very short remainder")
  {
    CHECK(mp4_query_without_param("start=1&a", "start") == "a");
    CHECK(mp4_query_without_param("start=1&ab", "start") == "ab");
  }
}

// The rewrite used to be built with snprintf into a fixed 1024 byte stack
// buffer, and snprintf's return value, which is what it *would* have written,
// was passed on as the result length. Any query whose rewrite exceeded the
// buffer therefore reported a length longer than the bytes that existed. The
// rewrite only ever removes a parameter, so it must carry the full remainder at
// any size.
//
// The sizes below are driven from the length of the REWRITTEN query rather than
// from the padding, because that is the length the old buffer bounded. The band
// 1020 to 1030 brackets it exactly: at 1023 the old code still fitted, at 1024
// it truncated, and at 1025 it first read past the end. The largest sizes run
// past the biggest query a default configuration accepts, so passing them
// requires sizing the result from the input rather than from any buffer chosen
// ahead of time.
namespace
{
std::vector<size_t>
rewrite_lengths()
{
  std::vector<size_t> lengths;
  for (size_t n = 1020; n <= 1030; ++n) {
    lengths.push_back(n);
  }
  for (size_t n : {size_t{100}, size_t{4096}, size_t{60000}, size_t{65535}, size_t{70000}}) {
    lengths.push_back(n);
  }
  return lengths;
}

// Padding of the length needed to make the whole rewritten query `total` bytes,
// given the fixed characters that surround it in each construction below.
std::string
pad_for(size_t total, size_t fixed)
{
  return std::string(total > fixed ? total - fixed : 0, 'A');
}
} // namespace

TEST_CASE("mp4_query_without_param is exact across and beyond the old buffer size", "[mp4][query]")
{
  for (size_t total : rewrite_lengths()) {
    // "pad=" is 4 characters.
    {
      std::string const pad      = pad_for(total, 4);
      std::string const expected = "pad=" + pad;
      std::string const query    = "start=1&" + expected;
      auto const        result   = mp4_query_without_param(query, "start");
      CHECK(result.size() == expected.size());
      CHECK(result == expected);
    }
    {
      std::string const pad      = pad_for(total, 4);
      std::string const expected = "pad=" + pad;
      std::string const query    = expected + "&start=1";
      auto const        result   = mp4_query_without_param(query, "start");
      CHECK(result.size() == expected.size());
      CHECK(result == expected);
    }
    // "pad=" plus "&tail=2" is 11 characters.
    {
      std::string const pad      = pad_for(total, 11);
      std::string const expected = "pad=" + pad + "&tail=2";
      std::string const query    = "pad=" + pad + "&start=1&tail=2";
      auto const        result   = mp4_query_without_param(query, "start");
      CHECK(result.size() == expected.size());
      CHECK(result == expected);
    }
  }
}

// These record the accepted forms as they have always been, which is the point:
// the bound is what changed, not the grammar. They are not a statement that a
// non-finite start time is meaningful. A caller that goes on to convert such a
// value to an integer has its own problem to solve, and this parse deliberately
// does not paper over it by narrowing what it accepts.
//
// The parse is bounded now, but the forms it accepts are unchanged. These pin
// the ones a rewrite of the parser could quietly drop: a hexadecimal value and
// a magnitude that overflows to infinity both used to be accepted, and a value
// that seeks nowhere must still leave the query alone.
TEST_CASE("mp4_query_parse_float keeps the forms the C library accepts", "[mp4][query]")
{
  float f = -1;
  SECTION("hexadecimal")
  {
    REQUIRE(mp4_query_parse_float("0x10", f));
    CHECK(f == 16.0f);
  }
  SECTION("hexadecimal with an exponent")
  {
    REQUIRE(mp4_query_parse_float("0x1p3", f));
    CHECK(f == 8.0f);
  }
  SECTION("magnitude that overflows to infinity")
  {
    REQUIRE(mp4_query_parse_float("1e40", f));
    CHECK(std::isinf(f));
    CHECK(f > 0);
  }
  // The sign matters to the caller, but neither sign is a seek: the transform
  // cannot represent an infinity either way. A negative one is answered with a
  // 400, while a positive one becomes no start at all and the request is passed
  // through with its query, this spelling included, untouched.
  SECTION("infinity spelled out")
  {
    REQUIRE(mp4_query_parse_float("inf", f));
    CHECK(std::isinf(f));
    CHECK(f > 0);
  }
  SECTION("negative infinity keeps its sign")
  {
    REQUIRE(mp4_query_parse_float("-inf", f));
    CHECK(std::isinf(f));
    CHECK(f < 0);
  }
  SECTION("not a number")
  {
    REQUIRE(mp4_query_parse_float("nan", f));
    CHECK(std::isnan(f));
  }
  // Worth naming because it is the form nobody spells deliberately: an ordinary
  // looking decimal that overflows to infinity, accepted here exactly as the
  // C library has always accepted it.
  SECTION("a decimal that overflows reads as infinity")
  {
    REQUIRE(mp4_query_parse_float("1e40", f));
    CHECK(std::isinf(f));
  }
  // Both answers conform, and they take opposite branches in the caller: a
  // subnormal is a non-zero seek, while a flush to zero reads as no seek at all
  // and leaves the query alone. Pin the pair rather than accept anything.
  SECTION("a value that underflows lands on one of two conforming answers")
  {
    REQUIRE(mp4_query_parse_float("1e-45", f));
    CHECK((f == 0.0f || (f > 0.0f && f < 1e-37f)));
  }
}
