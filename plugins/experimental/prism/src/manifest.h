/** @file

  Reads the manifest section HRW4U_MODULE writes into a .so, from the file, without loading it.

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

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace hrw4u::manifest
{
struct Function {
  std::string              name;
  std::string              effect; ///< "pure", "effect" or "load"
  std::string              result; ///< "bool", "i64" or "sview"
  std::vector<std::string> params; ///< "bool", "i64" or "sview" each
};

struct Module {
  std::string           name;
  std::vector<Function> functions;
};

/// The manifest section's bytes in @a image, a 64-bit little-endian ELF or Mach-O file. On failure, @a error says why.
std::optional<std::string_view> find_section(std::string_view image, std::string &error);

/// On failure, @a error reads "line N: <what>".
std::optional<std::vector<Module>> parse(std::string_view section, std::string &error);

/// @a modules as hrw4u extern declarations, with @a source named as the file they came from.
std::string render(const std::vector<Module> &modules, std::string_view source);
} // namespace hrw4u::manifest
