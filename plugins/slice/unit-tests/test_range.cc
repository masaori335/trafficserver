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
 * @file test_range.cc
 * @brief Unit tests for slice Range
 */

#include <catch2/catch_test_macros.hpp> /* catch unit-test framework */
#include <cstdint>
#include <string>
#include <vector>
#include "../Range.h"

TEST_CASE("range invalid state", "[AWS][slice][utility]")
{
  CHECK_FALSE(Range().isValid());           // null range
  CHECK_FALSE(Range(1024, 1024).isValid()); // zero range
  CHECK_FALSE(Range(-5, 13).isValid());     // negative start
}

TEST_CASE("range to/from string - valid", "[AWS][slice][utility]")
{
  std::vector<std::string> const teststrings = {
    "bytes=0-1023", // start at zero
    "bytes=1-1024", // start from non zero
    "bytes=11-11",  // single byte
    "bytes=1-",     // 2nd byte to end
    "bytes=3-17",   // closed range
    "bytes=0-0",    // first byte only
    "bytes=-20",    // last 20 bytes of file
  };

  std::vector<Range> const exps = {
    Range{0,   1023 + 1     },
    Range{1,   1024 + 1     },
    Range{11,  11 + 1       },
    Range{1,   Range::maxval},
    Range{3,   17 + 1       },
    Range{0,   1            },
    Range{-20, 0            }  //
  };

  for (size_t index = 0; index < teststrings.size(); ++index) {
    std::string const &str = teststrings[index];

    Range got;
    CHECK(got.fromStringClosed(str.c_str()));
    CHECK(got.isValid());

    if (!got.isValid()) {
      INFO(str.c_str());
    }

    Range const &exp = exps[index];
    CHECK(got.m_beg == exp.m_beg);
    CHECK(got.m_end == exp.m_end);
  }
}

TEST_CASE("blockIsInside - normal cases", "[AWS][slice][utility]")
{
  // Block 0 of size 1024: [0, 1024)
  Range r(0, 2048);
  CHECK(r.blockIsInside(1024, 0));
  CHECK(r.blockIsInside(1024, 1));
  CHECK_FALSE(r.blockIsInside(1024, 2));

  // Single byte range at start of block 1
  Range r2(1024, 1025);
  CHECK_FALSE(r2.blockIsInside(1024, 0));
  CHECK(r2.blockIsInside(1024, 1));
  CHECK_FALSE(r2.blockIsInside(1024, 2));

  // Range spanning partial blocks
  Range r3(500, 1500);
  CHECK(r3.blockIsInside(1024, 0));
  CHECK(r3.blockIsInside(1024, 1));
  CHECK_FALSE(r3.blockIsInside(1024, 2));
}

TEST_CASE("blockIsInside - zero and negative blocksize", "[AWS][slice][utility]")
{
  Range r(0, 4096);
  CHECK_FALSE(r.blockIsInside(0, 0));
  CHECK_FALSE(r.blockIsInside(-1, 0));
  CHECK_FALSE(r.blockIsInside(-1024, 0));
  CHECK_FALSE(r.blockIsInside(INT64_MIN, 0));
}

TEST_CASE("blockIsInside - negative blocknum", "[AWS][slice][utility]")
{
  Range r(0, 4096);
  CHECK_FALSE(r.blockIsInside(1024, -1));
  CHECK_FALSE(r.blockIsInside(1024, -100));
  CHECK_FALSE(r.blockIsInside(1024, INT64_MIN));
}

TEST_CASE("blockIsInside - overflow protection", "[AWS][slice][utility]")
{
  Range r(0, INT64_MAX);

  // blocknum at overflow boundary: blocksize * (blocknum + 1) would overflow,
  // but blockmax itself is now handled via clamped block end.
  // blockmax block has range [blocksize*blockmax, INT64_MAX) which intersects r.
  CHECK(r.blockIsInside(1024, INT64_MAX / 1024));
  CHECK_FALSE(r.blockIsInside(1024, INT64_MAX)); // far beyond blockmax
  CHECK(r.blockIsInside(2, INT64_MAX / 2));
  CHECK_FALSE(r.blockIsInside(2, INT64_MAX)); // far beyond blockmax

  // Largest safe blocknum: blockmax - 1 where blockmax = INT64_MAX / blocksize
  int64_t const blocksize = 1024;
  int64_t const blockmax  = INT64_MAX / blocksize;
  // blockmax - 1 should be safe
  CHECK(r.blockIsInside(blocksize, blockmax - 1));
  // blockmax itself is valid (clamped end prevents overflow)
  CHECK(r.blockIsInside(blocksize, blockmax));

  // Large blocksize with blocknum = 1
  CHECK_FALSE(r.blockIsInside(INT64_MAX, 1));
  // blocknum = 0 with large blocksize should work
  CHECK(r.blockIsInside(INT64_MAX, 0));

  // blocksize = 1, very large blocknum
  CHECK(r.blockIsInside(1, INT64_MAX - 1));
  CHECK_FALSE(r.blockIsInside(1, INT64_MAX));
}

TEST_CASE("skipBytesForBlock - normal cases", "[AWS][slice][utility]")
{
  // Range starts at byte 500, block 0 is [0,1024)
  Range r(500, 2048);
  CHECK(r.skipBytesForBlock(1024, 0) == 500);
  // Block 1 starts at 1024, range starts at 500 which is before block 1
  CHECK(r.skipBytesForBlock(1024, 1) == 0);

  // Range starts exactly at block boundary
  Range r2(1024, 2048);
  CHECK(r2.skipBytesForBlock(1024, 1) == 0);
  CHECK(r2.skipBytesForBlock(1024, 0) == 1024);
}

TEST_CASE("skipBytesForBlock - invalid inputs", "[AWS][slice][utility]")
{
  Range r(0, 4096);
  // Zero/negative blocksize
  CHECK(r.skipBytesForBlock(0, 0) == 0);
  CHECK(r.skipBytesForBlock(-1, 0) == 0);
  CHECK(r.skipBytesForBlock(INT64_MIN, 0) == 0);

  // Negative blocknum
  CHECK(r.skipBytesForBlock(1024, -1) == 0);
  CHECK(r.skipBytesForBlock(1024, INT64_MIN) == 0);
}

TEST_CASE("skipBytesForBlock - overflow protection", "[AWS][slice][utility]")
{
  Range r(0, INT64_MAX);

  // blocknum at/over the blockmax boundary
  // (protects blocksize * blocknum from overflow)
  CHECK(r.skipBytesForBlock(1024, INT64_MAX / 1024) == 0);
  CHECK(r.skipBytesForBlock(1024, INT64_MAX) == 0);
  CHECK(r.skipBytesForBlock(2, INT64_MAX / 2) == 0);
  CHECK(r.skipBytesForBlock(INT64_MAX, 1) == 0);

  // Largest safe blocknum
  int64_t const blocksize = 1024;
  int64_t const blockmax  = INT64_MAX / blocksize;
  CHECK(r.skipBytesForBlock(blocksize, blockmax - 1) == 0); // m_beg=0 < blockstart

  // Range starting mid-block with large blocknum
  int64_t const bigstart = blocksize * (blockmax - 1) + 100;
  Range         r2(bigstart, bigstart + 500);
  CHECK(r2.skipBytesForBlock(blocksize, blockmax - 1) == 100);
}

TEST_CASE("range from string - invalid")
{
  std::vector<std::string> const badstrings = {
    "Range: bytes=-13",    // malformed
    "bytes=-60-50",        // first negative, second nonzero
    "bytes=17-13",         // degenerate
    "bytes 0-1023/146515", // malformed
    "bytes=3 -17",         // whitespace is not part of range syntax
    "bytes=3- 17",
    "bytes=3- 17 ",
    "bytes=3  -17",
    "bytes=--13", // repeated separator
    "bytes=+-13", // signed suffix
    "bytes=+1-2", // signed first position
    "bytes=1-+2", // signed last position
    "bytes=-+13", // signed suffix value
    "bytes=1--2", // repeated separator
    "bytes=1-2x", // trailing data
    "bytes=-0",
    "bytes=9223372036854775808-", // first-pos is unsatisfiable, not clamped
  };

  Range range;
  for (std::string const &badstr : badstrings) {
    CHECK_FALSE(range.fromStringClosed(badstr.c_str()));
    CHECK_FALSE(range.isValid());
    if (range.isValid()) {
      INFO(badstr.c_str());
    }
  }

  CHECK_FALSE(range.fromStringClosed(nullptr));
  CHECK_FALSE(range.isValid());
}

TEST_CASE("range from string - oversized input rejected", "[AWS][slice][utility]")
{
  // The parser accepts at most 1023 bytes before the NUL terminator.
  std::string valid = "bytes=0-1023";
  Range       r;
  CHECK(r.fromStringClosed(valid.c_str()));

  // Whitespace inside the range expression is not valid RFC 9110 syntax.
  std::string padded = "bytes=0 - 1023";
  Range       r2;
  CHECK_FALSE(r2.fromStringClosed(padded.c_str()));

  // Create input that exceeds the parser's bounded input length.
  std::string oversized = "bytes=0-";
  oversized.append(1022, '1'); // 2 + 1022 payload bytes exceeds the total limit
  Range r3;
  CHECK_FALSE(r3.fromStringClosed(oversized.c_str()));

  // An input within the buffer limit still fails safely when its first-pos
  // overflows int64.
  std::string atLimit = "bytes=";
  atLimit.append(1015, '9');
  atLimit += "-";
  atLimit.append(6, '9');
  Range r4;
  CHECK_FALSE(r4.fromStringClosed(atLimit.c_str()));

  // Interleaved whitespace is rejected rather than normalized.
  std::string spacey = "bytes=  0  -  1023  ";
  Range       r4b;
  CHECK_FALSE(r4b.fromStringClosed(spacey.c_str()));

  // Non-blank char after buffer full triggers rejection
  std::string truncated = "bytes=0-";
  truncated.append(1021, '1'); // fills buffer
  truncated += "x";            // non-blank leftover
  Range r5;
  CHECK_FALSE(r5.fromStringClosed(truncated.c_str()));
}

TEST_CASE("range from string - oversized last-pos and suffix clamped", "[AWS][slice][utility]")
{
  // RFC 9110 section 14.1.2: a last-pos at or past the representation
  // selects through its end, the same as the open-ended form.
  Range open;
  REQUIRE(open.fromStringClosed("bytes=0-"));

  std::vector<std::string> const lastposes = {
    "bytes=0-" + std::to_string(Range::maxval),
    "bytes=0-" + std::to_string(INT64_MAX),
    "bytes=0-9223372036854775808",
    "bytes=0-99999999999999999999999999",
  };
  for (std::string const &str : lastposes) {
    INFO(str);
    Range r;
    REQUIRE(r.fromStringClosed(str.c_str()));
    CHECK(r.m_beg == open.m_beg);
    CHECK(r.m_end == open.m_end);
    CHECK(r.isValid());
  }

  // Range::maxval - 1 is the largest last-pos that round trips unchanged.
  std::string justunder = "bytes=0-" + std::to_string(Range::maxval - 1);
  Range       r2;
  CHECK(r2.fromStringClosed(justunder.c_str()));
  CHECK(r2.m_beg == 0);
  CHECK(r2.m_end == Range::maxval);

  char buf[64];
  int  buflen = sizeof(buf);
  CHECK(r2.toStringClosed(buf, &buflen));
  CHECK(std::string(buf) == justunder);

  // A suffix-length past the representation selects all of it.
  std::vector<std::string> const suffixes = {
    "bytes=-" + std::to_string(Range::maxval),
    "bytes=-" + std::to_string(INT64_MAX),
    "bytes=-9223372036854775808",
    "bytes=-99999999999999999999999999",
  };
  for (std::string const &str : suffixes) {
    INFO(str);
    Range r;
    REQUIRE(r.fromStringClosed(str.c_str()));
    CHECK(r.m_beg == -Range::maxval);
    CHECK(r.m_end == 0);
    CHECK(r.isEndBytes());
    CHECK(r.isValid());
  }

  std::string justunder_suffix = "bytes=-" + std::to_string(Range::maxval - 1);
  Range       r4;
  CHECK(r4.fromStringClosed(justunder_suffix.c_str()));
  CHECK(r4.m_beg == -(Range::maxval - 1));
  CHECK(r4.m_end == 0);

  // Clamping must not rescue a malformed or inverted range.
  Range r5;
  CHECK_FALSE(r5.fromStringClosed("bytes=0-99999999999999999999x"));
  Range r6;
  CHECK_FALSE(r6.fromStringClosed("bytes=-99999999999999999999x"));
  Range r7;
  CHECK_FALSE(r7.fromStringClosed("bytes=99999999999999999999-99999999999999999999"));
}

TEST_CASE("range from string - end-bytes negation overflow rejected", "[AWS][slice][utility]")
{
  // A repeated separator must not be interpreted as a signed value or
  // trigger negation of INT64_MIN.
  std::string dblneg = "bytes=--" + std::to_string(INT64_MIN);
  Range       r;
  CHECK_FALSE(r.fromStringClosed(dblneg.c_str()));

  // The magnitude of INT64_MIN cannot be represented as a positive int64_t.
  std::string minmag = "bytes=--9223372036854775808";
  Range       r2;
  CHECK_FALSE(r2.fromStringClosed(minmag.c_str()));

  // Zero last-bytes is not a useful range; rejected.
  Range r3;
  CHECK_FALSE(r3.fromStringClosed("bytes=-0"));

  // Normal last-N-bytes still parses.
  Range r4;
  CHECK(r4.fromStringClosed("bytes=-20"));
  CHECK(r4.m_beg == -20);
  CHECK(r4.m_end == 0);
}

TEST_CASE("range size", "[AWS][slice][utility]")
{
  CHECK(Range(0, 1024).size() == 1024);
  CHECK(Range(100, 200).size() == 100);
  CHECK(Range(0, 1).size() == 1);
  // End-byte range: size is 0 - (-20) = 20
  CHECK(Range(-20, 0).size() == 20);
}

TEST_CASE("range toStringClosed", "[AWS][slice][utility]")
{
  char buf[64];
  int  buflen;

  // Normal range (half-open [0,1024) -> closed "bytes=0-1023")
  buflen = sizeof(buf);
  Range r(0, 1024);
  CHECK(r.toStringClosed(buf, &buflen));
  CHECK(std::string(buf) == "bytes=0-1023");

  // Open-ended range (m_end > maxval)
  buflen = sizeof(buf);
  Range r2(100, Range::maxval + 1);
  CHECK(r2.toStringClosed(buf, &buflen));
  CHECK(std::string(buf) == "bytes=100-");

  // Invalid range returns false
  buflen = sizeof(buf);
  Range invalid;
  CHECK_FALSE(invalid.toStringClosed(buf, &buflen));
  CHECK(buflen == 0);

  // Buffer too small: truncates, returns false
  buflen = 5;
  CHECK_FALSE(r.toStringClosed(buf, &buflen));
}

TEST_CASE("firstBlockFor", "[AWS][slice][utility]")
{
  Range r(2000, 5000);
  CHECK(r.firstBlockFor(1024) == 1); // 2000 / 1024 = 1
  CHECK(r.firstBlockFor(512) == 3);  // 2000 / 512 = 3
  CHECK(r.firstBlockFor(2048) == 0); // 2000 / 2048 = 0

  // Range starting at 0
  Range r2(0, 4096);
  CHECK(r2.firstBlockFor(1024) == 0);

  // Invalid blocksize
  CHECK(r.firstBlockFor(0) == -1);
  CHECK(r.firstBlockFor(-1) == -1);

  // Invalid range
  Range invalid;
  CHECK(invalid.firstBlockFor(1024) == -1);
}

TEST_CASE("lastBlockFor", "[AWS][slice][utility]")
{
  Range r(2000, 5000);
  CHECK(r.lastBlockFor(1024) == 4); // (5000-1) / 1024 = 4
  CHECK(r.lastBlockFor(512) == 9);  // (5000-1) / 512 = 9

  // Single byte range
  Range r2(1024, 1025);
  CHECK(r2.lastBlockFor(1024) == 1); // (1025-1) / 1024 = 1

  // Range ending exactly at block boundary
  Range r3(0, 1024);
  CHECK(r3.lastBlockFor(1024) == 0); // (1024-1) / 1024 = 0

  // Invalid blocksize
  CHECK(r.lastBlockFor(0) == -1);
  CHECK(r.lastBlockFor(-1) == -1);

  // Invalid range
  Range invalid;
  CHECK(invalid.lastBlockFor(1024) == -1);
}

TEST_CASE("intersectedWith", "[AWS][slice][utility]")
{
  // Overlapping ranges
  Range a(100, 500);
  Range b(300, 700);
  Range isec = a.intersectedWith(b);
  CHECK(isec.m_beg == 300);
  CHECK(isec.m_end == 500);
  CHECK(isec.isValid());

  // Non-overlapping: result is invalid
  Range c(0, 100);
  Range d(200, 300);
  Range no_isec = c.intersectedWith(d);
  CHECK_FALSE(no_isec.isValid());

  // Adjacent ranges (no overlap in half-open)
  Range e(0, 100);
  Range f(100, 200);
  Range adj = e.intersectedWith(f);
  CHECK_FALSE(adj.isValid()); // [100,100) is empty

  // One contains the other
  Range outer(0, 1000);
  Range inner(200, 400);
  Range contained = outer.intersectedWith(inner);
  CHECK(contained.m_beg == 200);
  CHECK(contained.m_end == 400);
}

TEST_CASE("isEndBytes", "[AWS][slice][utility]")
{
  CHECK(Range(-20, 0).isEndBytes());
  CHECK(Range(-1, 0).isEndBytes());
  CHECK_FALSE(Range(0, 100).isEndBytes());
  CHECK_FALSE(Range(-5, 5).isEndBytes());
  CHECK_FALSE(Range(-5, -1).isEndBytes());
  CHECK_FALSE(Range().isEndBytes()); // m_beg=-1, m_end=-1: m_end != 0
}

TEST_CASE("range from string - input length boundary", "[AWS][slice][utility]")
{
  // strnlen(rangestr, 1024) returning 1024 means no terminator was seen in
  // the first 1024 bytes, which rejects. The longest accepted string is
  // therefore 1023 characters, occupying 1024 bytes with its terminator.
  std::string atlimit = "bytes=0-";
  atlimit.append(1015, '0');
  REQUIRE(atlimit.size() == 1023);

  Range r;
  CHECK(r.fromStringClosed(atlimit.c_str()));
  CHECK(r.m_beg == 0);
  CHECK(r.m_end == 1);

  // One character longer is rejected purely on length: the payload is still
  // well formed and would otherwise parse to the same range.
  std::string overlimit = "bytes=0-";
  overlimit.append(1016, '0');
  REQUIRE(overlimit.size() == 1024);

  Range r2;
  CHECK_FALSE(r2.fromStringClosed(overlimit.c_str()));
  CHECK_FALSE(r2.isValid());
}

TEST_CASE("range from string - first-byte-pos at Range::maxval rejected", "[AWS][slice][utility]")
{
  // The open ended form is the only shape that isolates the first position
  // bound: a closed form trips the last-pos bound too and so cannot tell
  // whether this guard is present. Without it the parse reports success
  // while leaving the range invalid, which is the state this guard exists
  // to prevent.
  std::string const atmax = "bytes=" + std::to_string(Range::maxval) + "-";
  Range             r;
  CHECK_FALSE(r.fromStringClosed(atmax.c_str()));
  CHECK_FALSE(r.isValid());

  std::string const abovemax = "bytes=" + std::to_string(Range::maxval + 1) + "-";
  Range             r2;
  CHECK_FALSE(r2.fromStringClosed(abovemax.c_str()));
  CHECK_FALSE(r2.isValid());

  // Range::maxval - 1 is the largest accepted first-byte-pos.
  std::string const justunder = "bytes=" + std::to_string(Range::maxval - 1) + "-";
  Range             r3;
  REQUIRE(r3.fromStringClosed(justunder.c_str()));
  CHECK(r3.m_beg == Range::maxval - 1);
  CHECK(r3.m_end == Range::maxval);
  CHECK(r3.isValid());
}

TEST_CASE("range from string - success implies a valid range", "[AWS][slice][utility]")
{
  // Any input fromStringClosed accepts must leave the object usable; a true
  // return with isValid() false is the failure mode the bounds guard against.
  std::vector<std::string> const inputs = {
    "bytes=0-1023",
    "bytes=0-",
    "bytes=-20",
    "bytes=" + std::to_string(Range::maxval - 1) + "-",
    "bytes=" + std::to_string(Range::maxval) + "-",
    "bytes=0-" + std::to_string(Range::maxval),
    "bytes=-" + std::to_string(Range::maxval),
    "bytes=0-99999999999999999999999999",
    "bytes=-99999999999999999999999999",
    "bytes=17-13",
    "bytes=--13",
  };

  for (std::string const &str : inputs) {
    INFO(str);
    Range r;
    if (r.fromStringClosed(str.c_str())) {
      CHECK(r.isValid());
      CHECK(r.m_end <= Range::maxval);
    }
  }
}
