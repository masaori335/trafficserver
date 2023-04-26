/** @file

  Collection of utility functions for converting between different chars.

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

#pragma once

#include "MemSpan.h"

#include <string_view>

namespace ts
{
/** Copy @a src to @a dst, transforming to lower case.
 *
 * @param src Input string.
 * @param dst Output buffer.
 */
inline void
transform_lower(std::string_view src, ts::MemSpan<char> dst)
{
  if (src.size() > dst.size() - 1) { // clip @a src, reserving space for the terminal nul.
    src = std::string_view{src.data(), dst.size() - 1};
  }
  auto final = std::transform(src.begin(), src.end(), dst.data(), [](char c) -> char { return std::tolower(c); });
  *final++   = '\0';
}
} // namespace ts
