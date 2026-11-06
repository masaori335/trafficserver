/** @file

  The Cripts functions the IR calls by names under cripts::.

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

#include "cripts_bindings.h"

#include "hrw4u/extension.hpp"

#include "swoc/TextView.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "cripts/Crypto.hpp"
#include "cripts/Files.hpp"

namespace hrw4u
{
namespace
{
  // Runs only at load, so it can afford to log why: the key's own path, never its bytes, as the file holds a secret.
  std::optional<std::string>
  file_line_read(std::string_view path)
  {
    cripts::File::Path resolved{path};

    // Rebase() can throw; the extension thunk turns that into a load error until Cripts stops throwing.
    resolved.Rebase();

    cripts::string line = cripts::File::Line::Reader(resolved.string());

    // Reader gives an empty line for a file it cannot open, too. Rebase() clears a path it refuses, so log the given one.
    if (line.empty()) {
      TSError("[prism] cannot read '%.*s', or its first line is empty", static_cast<int>(path.size()), path.data());
      return std::nullopt;
    }
    return std::string(line.data(), line.size());
  }

  // Exposed as Sign, as an HMAC is not encryption; Cripts is to gain that name and deprecate Encrypt.
  cripts::string
  hmac_sha256_sign(std::string_view key, std::string_view message)
  {
    return cripts::Crypto::HMAC::SHA256::Encrypt(message, cripts::string{key}).String();
  }

  // svtoi_convert has digits up to base 36.
  int
  hex_digit(char c)
  {
    const int v = swoc::svtoi_convert[static_cast<uint8_t>(c)];

    if (v >= 16) {
      return -1;
    }
    return v;
  }

  // Not cripts::UnHex(): it decodes a last pair whose second character is not a digit ("..0z") as its first digit
  // alone, so a key with a typo at the end loads as another key.
  std::optional<std::string>
  hex_decode(std::string_view str)
  {
    if (str.size() % 2 != 0) {
      return std::nullopt;
    }

    std::string ret;

    ret.reserve(str.size() / 2);
    for (size_t i = 0; i < str.size(); i += 2) {
      const int hi = hex_digit(str[i]);
      const int lo = hex_digit(str[i + 1]);

      if (hi < 0 || lo < 0) {
        return std::nullopt;
      }
      ret.push_back(static_cast<char>((hi << 4) | lo));
    }
    return ret;
  }

  HRW4U_MODULE_TABLE(cripts_module, "cripts",
                     HRW4U_DEF(&cripts::Crypto::Base64::Encode, "cripts::Crypto::Base64::Encode", HRW4U_EFFECT_PURE),
                     HRW4U_DEF(&file_line_read, "cripts::File::Line::Read", HRW4U_EFFECT_LOAD),
                     HRW4U_DEF(&hex_decode, "cripts::Crypto::Hex::Decode", HRW4U_EFFECT_PURE),
                     HRW4U_DEF(&hmac_sha256_sign, "cripts::Crypto::HMAC::SHA256::Sign", HRW4U_EFFECT_PURE));
} // namespace

bool
def_cripts_bindings(const hrw4u_host_api *api)
{
  return cripts_module::define(api);
}
} // namespace hrw4u
