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

#include "ContentRange.h"

#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <limits>

static char const *const format = "bytes %" PRId64 "-%" PRId64 "/%" PRId64;

namespace
{
// Parses the run of decimal digits starting at p, advancing p past them.
// Rejects (returning false, p left unmoved) on no digits or on a value that
// does not fit in int64_t. Unlike Range::fromStringClosed, which clamps an
// oversized request position, this parses a response header, and a length
// or offset we cannot represent exactly is not one we can slice against.
bool
parse_uint(char const *&p, char const *const end, int64_t &value)
{
  if (p == end || !isdigit(static_cast<unsigned char>(*p))) {
    return false;
  }

  int64_t constexpr max = std::numeric_limits<int64_t>::max();
  int64_t parsed{0};

  char const *cur = p;

  while (cur != end && isdigit(static_cast<unsigned char>(*cur))) {
    int64_t const digit = *cur - '0';

    if (parsed > (max - digit) / 10) {
      return false;
    }

    parsed = parsed * 10 + digit;
    ++cur;
  }

  value = parsed;
  p     = cur;

  return true;
}

} // namespace

bool
ContentRange::fromStringClosed(char const *const valstr)
{
  static char const *const PREFIX    = "bytes";
  static size_t const      PREFIXLEN = strlen(PREFIX);
  // valstr must be NUL-terminated within BUFCAP bytes, or else have BUFCAP
  // readable bytes: strnlen() stops at the terminator but will read BUFCAP
  // bytes without one. strnlen returning BUFCAP means no terminator was seen,
  // so the longest accepted value is BUFCAP - 1 characters plus its
  // terminator (callers pass a char[BUFCAP], see server.cc).
  static size_t constexpr BUFCAP = 1024;

  m_beg = m_end = m_length = -1; // initialize invalid

  if (nullptr == valstr) {
    return false;
  }

  size_t const inputlen = strnlen(valstr, BUFCAP);
  if (inputlen < PREFIXLEN || BUFCAP <= inputlen) {
    return false;
  }

  if (0 != strncmp(PREFIX, valstr, PREFIXLEN)) {
    return false;
  }

  char const *p   = valstr + PREFIXLEN;
  char const *end = valstr + inputlen;

  if (p == end || !isblank(static_cast<unsigned char>(*p))) {
    return false;
  }

  while (p != end && isblank(static_cast<unsigned char>(*p))) {
    ++p;
  }

  int64_t first{0};
  int64_t last{0};
  int64_t length{0};

  if (!parse_uint(p, end, first) || p == end || '-' != *p) {
    return false;
  }
  ++p;

  if (!parse_uint(p, end, last) || p == end || '/' != *p) {
    return false;
  }
  ++p;

  if (!parse_uint(p, end, length)) {
    return false;
  }

  // Trailing blanks are tolerated as field whitespace, unlike a request
  // Range, which rejects any whitespace; anything else after the length
  // rejects.
  while (p != end && isblank(static_cast<unsigned char>(*p))) {
    ++p;
  }
  if (p != end) {
    return false;
  }

  // last must be well below INT64_MAX so that the closed-to-half-open
  // "+ 1" below cannot overflow, and last must fall strictly inside the
  // representation for the Content-Range to make sense. length carries the
  // same bound because it becomes the content length a last-N-bytes request
  // is resolved against, and that result feeds the block offset arithmetic.
  if (last < first || Range::maxval <= last || length <= last || Range::maxval < length) {
    return false;
  }

  m_beg    = first;
  m_end    = last + 1;
  m_length = length;

  return isValid();
}

bool
ContentRange::toStringClosed(char *const rangestr, int *const rangelen) const
{
  if (!isValid()) {
    if (0 < *rangelen) {
      rangestr[0] = '\0';
    }
    *rangelen = 0;
    return false;
  }

  int const lenin = *rangelen;
  *rangelen       = snprintf(rangestr, lenin, format, m_beg, (m_end - 1), m_length);

  return (0 < *rangelen && *rangelen < lenin);
}
