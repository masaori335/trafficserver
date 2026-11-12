/** @file

  An example hrw4u extension: two functions that classify a User-Agent, registered through the binding layer.

  It needs only the ABI headers, no TSAPI and no Cripts. The classification is deliberately small; a real one would
  read its rules from a file the instance loads.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
  agreements.  See the NOTICE file distributed with this work for additional information regarding
  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with the License.  You may obtain
  a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed under the License
  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
  or implied. See the License for the specific language governing permissions and limitations under
  the License.
*/

#include "hrw4u/extension.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

namespace example_ua
{
namespace
{
  bool
  contains_nocase(std::string_view text, std::string_view word)
  {
    auto same = [](char a, char b) {
      return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    };

    return std::ranges::search(text, word, same).begin() != text.end();
  }
} // namespace

// Whether the User-Agent names a crawler, by the words crawlers put in it.
bool
is_bot(std::string_view ua)
{
  return contains_nocase(ua, "bot") || contains_nocase(ua, "crawler") || contains_nocase(ua, "spider");
}

// The client's family, by the first product token that tells it: Edge's User-Agent also names Chrome and Safari, and
// Chrome's also names Safari, so they are tested first.
std::string
family(std::string_view ua)
{
  if (ua.starts_with("curl/")) {
    return "curl";
  }
  if (ua.find("Firefox/") != std::string_view::npos) {
    return "firefox";
  }
  if (ua.find("Edg/") != std::string_view::npos) {
    return "edge";
  }
  if (ua.find("Chrome/") != std::string_view::npos) {
    return "chrome";
  }
  if (ua.find("Safari/") != std::string_view::npos) {
    return "safari";
  }
  return "other";
}
} // namespace example_ua

HRW4U_MODULE("example::ua", HRW4U_DEF("Example::UA::IsBot", HRW4U_EFFECT_PURE, &example_ua::is_bot),
             HRW4U_DEF("Example::UA::Family", HRW4U_EFFECT_PURE, &example_ua::family));
