/** @file

  YAML based cache configs

  TODO: Add YamlCacheConfig, YamlHostingConfig and YamlStorageConfig

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

#include <string>

struct StorageConfigParams {
  std::string path;
  std::string id;
  int64_t size   = 0;
  int volume_num = 0;
};

using StorageConfig = std::vector<StorageConfigParams>;

class YamlStorageConfig
{
public:
  static bool load(StorageConfig &config, std::string_view filename);
  static bool save();
  
private:
  YamlStorageConfig(const YamlStorageConfig &)            = delete;
  YamlStorageConfig &operator=(const YamlStorageConfig &) = delete;
};
