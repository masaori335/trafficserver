/** @file
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

/**
 * @file test_content_range.cc
 * @brief Unit test for slice ContentRange
 */

#include <catch2/catch_test_macros.hpp> /* catch unit-test framework */
#include "../ContentRange.h"

TEST_CASE("content_range invalid state", "[AWS][slice][utility]")
{
  CHECK_FALSE(ContentRange().isValid());                 // null range
  CHECK_FALSE(ContentRange(1024, 1024, 4000).isValid()); // zero range
  CHECK_FALSE(ContentRange(0, 1024, 1023).isValid());    // past end
  CHECK_FALSE(ContentRange(-5, 13, 40).isValid());       // negative start
}

TEST_CASE("content_range to/from string - valid", "[AWS][slice][utility]")
{
  ContentRange const exprange(1023, 1048576, 307232768);

  CHECK(exprange.isValid());

  std::string const expstr("bytes 1023-1048575/307232768");

  char gotbuf[1024];
  int  gotlen = sizeof(gotbuf);

  bool const strstat(exprange.toStringClosed(gotbuf, &gotlen));

  CHECK(strstat);
  CHECK(gotlen == static_cast<int>(expstr.size()));
  CHECK(expstr == std::string(gotbuf));

  ContentRange gotrange;
  bool const   gotstat(gotrange.fromStringClosed(expstr.c_str()));

  CHECK(gotstat);
  CHECK(gotrange.m_beg == exprange.m_beg);
  CHECK(gotrange.m_end == exprange.m_end);
  CHECK(gotrange.m_length == exprange.m_length);
}

TEST_CASE("content_range from string - invalid", "[AWS][slice][utility]")
{
  std::vector<std::string> const badstrings = {
    "bytes=1024-1692",                                                            // malformed, wrong prefix
    "bytes=1023-1048575/307232768",                                               // malformed, wrong prefix
    "bytes 1023-1022/5000",                                                       // first > last
    "bytes -40-12/50",                                                            // negative start
    "bytes 5-13/11",                                                              // last >= length
    "bytes 5-13",                                                                 // missing /length
    "bytes 5-13/",                                                                // empty length
    "bytes -13/50",                                                               // empty first
    "bytes 5-/50",                                                                // empty last
    "bytes 5-1a/50",                                                              // non-digit in last
    "bytes a-13/50",                                                              // non-digit in first
    "bytes 5-13/5a",                                                              // non-digit in length
    "bytes5-13/50",                                                               // no space after prefix
    "byte 5-13/50",                                                               // wrong prefix
    "bytes 0-9223372036854775808/100",                                            // last overflows int64_t by one
    "bytes 0-99999999999999999999999999999999/100000000000000000000000000000000", // far more digits than int64 holds
    "bytes 0-9223372036854775807/9223372036854775807", // last == INT64_MAX: the m_end += 1 overflow trigger
    "bytes 1023-1048575/307232768x",                   // trailing garbage
    "",                                                // empty string
    "bytes ",                                          // prefix only
  };

  ContentRange cr;

  for (std::string const &badstr : badstrings) {
    INFO(badstr.c_str());
    CHECK_FALSE(cr.fromStringClosed(badstr.c_str()));
    CHECK_FALSE(cr.isValid());
    CHECK(cr.m_beg == -1);
    CHECK(cr.m_end == -1);
    CHECK(cr.m_length == -1);
  }
}

TEST_CASE("content_range from string - overflow at length position", "[AWS][slice][utility]")
{
  ContentRange cr;

  CHECK_FALSE(cr.fromStringClosed("bytes 0-9/9223372036854775808"));
  CHECK_FALSE(cr.isValid());
  CHECK(cr.m_beg == -1);
  CHECK(cr.m_end == -1);
  CHECK(cr.m_length == -1);
}

TEST_CASE("content_range to/from string - additional valid forms round trip", "[AWS][slice][utility]")
{
  std::vector<ContentRange> const goodranges = {
    ContentRange(0, 1, 1),
    ContentRange(0, 500, 1000),
    ContentRange(5, 6, 10),
  };

  for (ContentRange const &exprange : goodranges) {
    CHECK(exprange.isValid());

    char gotbuf[1024];
    int  gotlen = sizeof(gotbuf);

    CHECK(exprange.toStringClosed(gotbuf, &gotlen));

    ContentRange gotrange;
    CHECK(gotrange.fromStringClosed(gotbuf));
    CHECK(gotrange.m_beg == exprange.m_beg);
    CHECK(gotrange.m_end == exprange.m_end);
    CHECK(gotrange.m_length == exprange.m_length);
  }
}

TEST_CASE("content range from string - trailing whitespace tolerated", "[AWS][slice][utility]")
{
  // Origin supplied headers are not under our control, so trailing blanks
  // are stripped rather than treated as garbage.
  ContentRange cr;
  REQUIRE(cr.fromStringClosed("bytes 0-17/18  "));
  CHECK(cr.m_beg == 0);
  CHECK(cr.m_end == 18);
  CHECK(cr.m_length == 18);

  ContentRange cr2;
  REQUIRE(cr2.fromStringClosed("bytes 1023-1048575/307232768\t"));
  CHECK(cr2.m_beg == 1023);
  CHECK(cr2.m_end == 1048576);

  // Non blank trailing content still rejects.
  ContentRange cr3;
  CHECK_FALSE(cr3.fromStringClosed("bytes 0-17/18 x"));
  CHECK_FALSE(cr3.isValid());
}

TEST_CASE("content range from string - length bounded by Range::maxval", "[AWS][slice][utility]")
{
  // m_length becomes Data::m_contentlen, which a last-N-bytes request is
  // resolved against in server.cc. An unbounded length would push the
  // resolved range past Range::maxval and overflow the block offset
  // arithmetic in util.cc and prefetch.cc, so it carries the same bound.
  std::string const atmax = "bytes 0-100/" + std::to_string(Range::maxval);
  ContentRange      cr;
  CHECK(cr.fromStringClosed(atmax.c_str()));
  CHECK(cr.m_length == Range::maxval);

  std::string const abovemax = "bytes 0-100/" + std::to_string(Range::maxval + 1);
  ContentRange      cr2;
  CHECK_FALSE(cr2.fromStringClosed(abovemax.c_str()));
  CHECK_FALSE(cr2.isValid());
  CHECK(cr2.m_length == -1);

  // The historical shape that reached the overflow: a huge origin length
  // with a normal looking first block.
  ContentRange cr3;
  CHECK_FALSE(cr3.fromStringClosed("bytes 0-1048575/9223372036854775807"));
  CHECK_FALSE(cr3.isValid());

  // A realistic large object is still accepted.
  ContentRange cr4;
  REQUIRE(cr4.fromStringClosed("bytes 0-1048575/1099511627776"));
  CHECK(cr4.m_beg == 0);
  CHECK(cr4.m_end == 1048576);
  CHECK(cr4.m_length == 1099511627776);
}
