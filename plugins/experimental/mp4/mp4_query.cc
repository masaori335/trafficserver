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

#include "mp4_query.h"

#include <cstdio>

namespace
{
/** Offset of the '=' that introduces @a key's value, or npos.
 *
 * A match must begin the query or follow a '&', and must be followed by '='.
 * The '=' is required to be inside @a query rather than assumed to be present,
 * because the query arrives from the header heap with an explicit length and no
 * NUL terminator, so the byte after the last one does not belong to us.
 */
size_t
find_key_equals(std::string_view query, std::string_view key)
{
  // An empty key has no parameter to name. Searching for one finds a zero
  // length match at the front, which would read a query that happens to begin
  // with '=' as having a nameless parameter. Say no instead of leaving that to
  // fall out of the loop.
  if (key.empty()) {
    return std::string_view::npos;
  }

  for (size_t pos = 0; (pos = query.find(key, pos)) != std::string_view::npos; ++pos) {
    bool const   at_param_start = (pos == 0) || (query[pos - 1] == '&');
    size_t const eq             = pos + key.size();
    if (at_param_start && eq < query.size() && query[eq] == '=') {
      return eq;
    }
  }
  return std::string_view::npos;
}
} // namespace

std::string_view
mp4_query_param(std::string_view query, std::string_view key)
{
  size_t const eq = find_key_equals(query, key);
  if (eq == std::string_view::npos) {
    return {nullptr, 0};
  }

  size_t const value_start = eq + 1;
  size_t const amp         = query.find('&', value_start);
  size_t const value_end   = (amp == std::string_view::npos) ? query.size() : amp;

  return query.substr(value_start, value_end - value_start);
}

bool
mp4_query_parse_float(std::string_view value, float &out)
{
  // The defect was never the conversion, it was running it on a string that had
  // no terminator: the value points into the header heap, which stores an
  // explicit length and writes no NUL. So keep the same conversion and give it a
  // terminated copy sized from the value. The read is then bounded by the copy,
  // and the grammar is untouched, which matters because the C library's scan
  // conversion and its strtof do not accept the same inputs everywhere.
  //
  // Where they differ is a number the conversion cannot complete, such as "1e",
  // and that answer belongs to the platform, not to us. glibc does not back up:
  // it consumes the exponent it cannot finish and reports no match, so the start
  // is dropped. Darwin does back up: sscanf("1e", "%f") there returns 1 with a
  // value of 1, so ?start=1e is a one second seek. Measured, not assumed, and
  // "1e+", "0x1p" and "infi" go the same way. strtof and from_chars give the
  // backing-up answer everywhere, so swapping one in would change what glibc
  // builds do. Keeping the same conversion keeps whatever each platform already
  // did, which is the claim this change rests on.
  std::string const text{value};

  float parsed = 0;
  if (std::sscanf(text.c_str(), "%f", &parsed) != 1) {
    return false;
  }

  out = parsed;
  return true;
}

std::string
mp4_query_without_param(std::string_view query, std::string_view key)
{
  size_t const eq = find_key_equals(query, key);
  if (eq == std::string_view::npos) {
    return std::string{query};
  }

  size_t const key_start = eq - key.size();
  size_t const amp       = query.find('&', eq + 1);
  size_t const value_end = (amp == std::string_view::npos) ? query.size() : amp;

  std::string_view head = query.substr(0, key_start);
  std::string_view tail = query.substr(value_end);

  // Remove exactly one of the two separators that bracketed the parameter, so
  // the parts rejoin without a doubled '&'. Which one depends on whether the
  // parameter had anything before it, and both apply when it was preceded by a
  // single leading '&', which leaves nothing in front of it.
  if (!head.empty() && head.back() == '&') {
    head.remove_suffix(1);
  }
  if (head.empty() && !tail.empty() && tail.front() == '&') {
    tail.remove_prefix(1);
  }

  std::string result;
  result.reserve(head.size() + tail.size());
  result.append(head);
  result.append(tail);
  return result;
}
