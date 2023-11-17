/** @file

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

#include "iocore/cache/YamlCacheConfig.h"

#include "P_Cache.h"

#include "tscore/Diags.h"

#include <yaml-cpp/yaml.h>

#include <set>
#include <string>

namespace
{

/// Additional configuration key values.
std::set<std::string> valid_storage_config_keys = {"path", "id", "size", "volume_num"};

bool
validate_map(const YAML::Node &node, const std::set<std::string> &keys)
{
  if (!node.IsMap()) {
    throw YAML::ParserException(node.Mark(), "malformed entry");
  }

  for (const auto &item : node) {
    if (std::none_of(keys.begin(), keys.end(), [&item](const std::string &s) { return s == item.first.as<std::string>(); })) {
      throw YAML::ParserException(item.first.Mark(), "format: unsupported key '" + item.first.as<std::string>() + "'");
    }
  }

  return true;
}
} // namespace

namespace YAML
{
template <> struct convert<StorageConfigParams> {
  static bool
  decode(const Node &node, StorageConfigParams &storage)
  {
    validate_map(node, valid_storage_config_keys);

    if (!node["path"]) {
      throw ParserException(node.Mark(), "missing 'path' argument");
    }
    storage.path = node["path"].as<std::string>();

    if (!node["size"]) {
      throw ParserException(node.Mark(), "missing 'size' argument");
    }
    std::string size = node["size"].as<std::string>();
    storage.size     = ink_atoi64(size.c_str());

    // optional configs
    if (node["volume"]) {
      storage.volume_num = node["volume"].as<int>();
    };

    if (node["id"]) {
      storage.id = node["id"].as<std::string>();
    };

    return true;
  };
};
} // namespace YAML

bool
YamlStorageConfig::load(StorageConfig &storage_config, std::string_view filename)
{
  try {
    YAML::Node config = YAML::LoadFile(filename.data());

    if (config.IsNull()) {
      return false;
    }

    if (!config.IsMap()) {
      Error("malformed %s file; expected map", filename.data());
      return false;
    }

    YAML::Node node = config["storage"];
    if (!node) {
      Error("malformed %s file; expected a toplevel 'storage' node", filename.data());
      return false;
    }

    if (!node.IsSequence()) {
      Error("malformed %s file; expected sequence", filename.data());
      return false;
    }

    for (const auto &it : node) {
      storage_config.push_back(it.as<StorageConfigParams>());
    }
  } catch (std::exception &ex) {
    Error("%s", ex.what());
    return false;
  }

  return true;
}
