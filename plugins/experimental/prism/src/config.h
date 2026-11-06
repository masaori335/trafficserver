/** @file

  A prism.so instance's settings, from the YAML file its --config= argument names.

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

#include <cstddef>
#include <string>
#include <string_view>

namespace hrw4u
{
/// A prism.so instance's settings.
struct Settings {
  /// The most bytes a transaction's memory may allocate from its arena, the arena's own included.
  size_t txn_memory_limit = 64 * 1024;
};

/// Read the settings in @a yaml, a `prism:` map: `txn_memory_limit` (decimal digits) caps each transaction's memory;
/// a key left out takes its default. Returns false, with @a error and @a settings as they were, for YAML that does not
/// parse, a missing `prism` map, a key given twice, or a key or value it does not know.
bool read_config(std::string_view yaml, Settings &settings, std::string &error);

/// read_config() on the file at @a path.
bool read_config_file(const std::string &path, Settings &settings, std::string &error);
} // namespace hrw4u
