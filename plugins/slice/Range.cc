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

#include "Range.h"

#include <algorithm>
#include <cinttypes>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>

bool
Range::isValid() const
{
  return m_beg < m_end && (0 <= m_beg || 0 == m_end);
}

int64_t
Range::size() const
{
  return m_end - m_beg;
}

bool
Range::fromStringClosed(char const *const rangestr)
{
  static char const *const BYTESTR    = "bytes=";
  static size_t const      BYTESTRLEN = strlen(BYTESTR);
  // rangestr must be NUL-terminated within BUFCAP bytes, or else have BUFCAP
  // readable bytes: strnlen() stops at the terminator but will read BUFCAP
  // bytes without one. strnlen returning BUFCAP means no terminator was seen,
  // so the longest accepted value is BUFCAP - 1 characters plus its
  // terminator.
  static size_t const BUFCAP = 1024;

  m_beg = m_end = -1; // initialize invalid

  if (nullptr == rangestr) {
    return false;
  }

  size_t const inputlen = strnlen(rangestr, BUFCAP);
  if (inputlen < BYTESTRLEN || BUFCAP <= inputlen) {
    return false;
  }

  // Range syntax does not allow whitespace within the expression.
  if (0 != strncmp(BYTESTR, rangestr, BYTESTRLEN)) {
    return false;
  }

  char const *pstr = rangestr + BYTESTRLEN;
  char const *end  = rangestr + inputlen;
  char const *dash = std::find(pstr, end, '-');
  if (dash == end || std::find(dash + 1, end, '-') != end) {
    return false;
  }

  // Saturates at Range::maxval rather than failing, so an oversized
  // last-pos or suffix-length clamps as RFC 9110 section 14.1.2 requires.
  auto parse_number = [](char const *begin, char const *end, int64_t &value) {
    if (begin == end) {
      return false;
    }
    int64_t parsed = 0;
    for (char const *p = begin; p != end; ++p) {
      if (!isdigit(static_cast<unsigned char>(*p))) {
        return false;
      }
      int64_t const digit = *p - '0';
      parsed              = (parsed > (Range::maxval - digit) / 10) ? Range::maxval : parsed * 10 + digit;
    }
    value = parsed;
    return true;
  };

  int64_t first  = 0;
  int64_t second = 0;
  if (dash == pstr) {
    // A suffix-length past the representation selects all of it; only zero is unsatisfiable.
    if (!parse_number(dash + 1, end, second) || second == 0) {
      return false;
    }
    m_beg = -second;
    m_end = 0;
    return true;
  }
  // A first-pos at or past the representation is unsatisfiable.
  if (!parse_number(pstr, dash, first) || Range::maxval <= first) {
    return false;
  }
  if (dash + 1 == end) {
    m_beg = first;
    m_end = Range::maxval;
    return true;
  }
  // A last-pos at or past the representation clamps to the representation end.
  if (!parse_number(dash + 1, end, second) || second < first) {
    return false;
  }
  m_beg = first;
  m_end = std::min(second + 1, Range::maxval);
  return true;
}

bool
Range::toStringClosed(char *const bufstr,
                      int *const  buflen // returns actual bytes used
) const
{
  if (!isValid()) {
    if (0 < *buflen) {
      bufstr[0] = '\0';
    }
    *buflen = 0;
    return false;
  }

  int const lenin = *buflen;

  if (m_end <= Range::maxval) {
    *buflen = snprintf(bufstr, lenin, "bytes=%" PRId64 "-%" PRId64, m_beg, m_end - 1);
  } else {
    *buflen = snprintf(bufstr, lenin, "bytes=%" PRId64 "-", m_beg);
  }

  return (0 < *buflen && *buflen < lenin);
}

int64_t
Range::firstBlockFor(int64_t const blocksize) const
{
  if (0 < blocksize && isValid()) {
    return std::max(static_cast<int64_t>(0), m_beg / blocksize);
  } else {
    return -1;
  }
}

int64_t
Range::lastBlockFor(int64_t const blocksize) const
{
  if (0 < blocksize && isValid()) {
    return std::max(static_cast<int64_t>(0), (m_end - 1) / blocksize);
  } else {
    return -1;
  }
}

Range
Range::intersectedWith(Range const &other) const
{
  return Range(std::max(m_beg, other.m_beg), std::min(m_end, other.m_end));
}

bool
Range::blockIsInside(int64_t const blocksize, int64_t const blocknum) const
{
  if (blocksize <= 0) {
    return false;
  }

  int64_t const blockmax = INT64_MAX / blocksize;

  if (blocknum < 0 || blockmax < blocknum) {
    return false;
  }

  int64_t const blockstart = blocksize * blocknum;
  int64_t const blockend   = (blocknum < blockmax) ? blocksize * (blocknum + 1) : INT64_MAX;
  Range const   blockrange(blockstart, blockend);
  Range const   isec(blockrange.intersectedWith(*this));

  return isec.isValid();
}

int64_t
Range::skipBytesForBlock(int64_t const blocksize, int64_t const blocknum) const
{
  if (blocksize <= 0 || blocknum < 0) {
    return 0;
  }

  int64_t const blockmax = INT64_MAX / blocksize;

  if (blockmax < blocknum) {
    return 0;
  }

  int64_t const blockstart = blocksize * blocknum;

  if (m_beg < blockstart) {
    return 0;
  } else {
    return m_beg - blockstart;
  }
}

bool
Range::isEndBytes() const
{
  return m_beg < 0 && 0 == m_end;
}
