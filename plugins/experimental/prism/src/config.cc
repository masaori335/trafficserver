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

#include "config.h"

#include <yaml-cpp/yaml.h>

#include <charconv>
#include <fstream>
#include <set>
#include <sstream>

namespace hrw4u
{
namespace
{
  bool
  read_bytes(const std::string &key, const std::string &value, size_t &bytes, std::string &error)
  {
    const char *end    = value.data() + value.size();
    auto        result = std::from_chars(value.data(), end, bytes);

    if (result.ec != std::errc{} || result.ptr != end) {
      error = "prism." + key + ": not a byte count: " + value;
      return false;
    }
    return true;
  }

  bool
  read_setting(const std::string &key, const std::string &value, Settings &settings, std::string &error)
  {
    if (key == "txn_memory_limit") {
      return read_bytes(key, value, settings.txn_memory_limit, error);
    }
    error = "unknown setting prism." + key;
    return false;
  }
} // namespace

bool
read_config(std::string_view yaml, Settings &settings, std::string &error)
{
  Settings read;

  // yaml-cpp throws on input that does not parse.
  try {
    YAML::Node            root = YAML::Load(std::string(yaml));
    YAML::Node            map;
    std::set<std::string> seen;

    if (root.IsMap()) {
      map = root["prism"];
    }
    if (!map.IsMap()) {
      error = "the configuration has no prism map";
      return false;
    }
    for (const auto &entry : map) {
      if (!entry.first.IsScalar()) {
        error = "a key of prism is not a name";
        return false;
      }

      auto key = entry.first.as<std::string>();

      // YAML forbids a key twice in a map, which yaml-cpp lets through.
      if (!seen.insert(key).second) {
        error = "prism." + key + " is set twice";
        return false;
      }
      if (!entry.second.IsScalar()) {
        error = "prism." + key + " is not a value";
        return false;
      }
      if (!read_setting(key, entry.second.as<std::string>(), read, error)) {
        return false;
      }
    }
  } catch (const std::exception &ex) {
    error = std::string("the configuration does not parse: ") + ex.what();
    return false;
  }
  settings = read;
  return true;
}

bool
read_config_file(const std::string &path, Settings &settings, std::string &error)
{
  std::ifstream file(path);

  if (!file) {
    error = "cannot read " + path;
    return false;
  }

  std::stringstream text;

  text << file.rdbuf();
  if (!read_config(text.str(), settings, error)) {
    error = path + ": " + error;
    return false;
  }
  return true;
}
} // namespace hrw4u
