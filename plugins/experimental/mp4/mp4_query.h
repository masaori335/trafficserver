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

#pragma once

#include <string>
#include <string_view>

/** Find the value of @a key in a URL query string.
 *
 * @param query The query string, without the leading '?'.
 * @param key   The parameter name to look for.
 * @return The parameter's value, or a view whose @c data() is @c nullptr when
 *         @a key is not present as a parameter of its own.
 *
 * @a query is not required to be NUL terminated and is never read outside its
 * own bounds. A key that appears as a substring of another key, of a value, or
 * without a following '=' is not a match, and an empty @a key never matches.
 *
 * The result aliases @a query rather than owning anything, so it lives exactly
 * as long as the bytes behind @a query do. When those bytes are in a header
 * heap, the view does not survive a write to that heap: allocating a string
 * there can coalesce the heaps and relocate what is already in them. Read the
 * value, or copy it, before writing the header it came from.
 */
std::string_view mp4_query_param(std::string_view query, std::string_view key);

/** Prefix-parse @a value as a float.
 *
 * @param value The text to parse. Not required to be NUL terminated, and never
 *              read outside its own bounds.
 * @param out   Set to the parsed value on success, untouched on failure.
 * @return @c true when a float was read.
 *
 * The accepted forms are exactly those of the C library's scan conversion for a
 * float, unchanged: leading spaces, a leading sign, hexadecimal forms, and
 * trailing text after a valid number all behave as they always have for the
 * start time. Only the bound is new.
 *
 * What a value whose number cannot be completed does, such as an exponent with
 * no digits, is platform defined, and is deliberately left that way rather than
 * pinned: glibc reports no value at all, while Darwin hands back the digits it
 * had already taken, so "1e" parses as 1 there. Keeping the same conversion
 * keeps whichever answer the platform already gave; strtof and @c from_chars
 * would give the second answer everywhere and change the first set of platforms.
 */
bool mp4_query_parse_float(std::string_view value, float &out);

/** Return @a query with the @a key parameter and its joining separator removed.
 *
 * @param query The query string, without the leading '?'.
 * @param key   The parameter name to remove.
 * @return The rewritten query, which is never longer than @a query. When @a key
 *         is absent the result equals @a query.
 *
 * The result is sized from @a query, so no query length causes it to be
 * truncated. That matters beyond memory safety: a truncated query would change
 * the cache key and the request forwarded to origin.
 */
std::string mp4_query_without_param(std::string_view query, std::string_view key);
