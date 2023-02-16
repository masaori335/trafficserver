/** @file

  A brief file description

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

#include "Resource.h"
#include "ResourceStats.h"

/**
   Global Singlton

   Manage id, config and stats
 */
class ResourceManager
{
public:
  ResourceManager()  = default;
  ~ResourceManager() = default;

  // No copying or moving
  ResourceManager(const ResourceManager &) = delete;
  ResourceManager &operator=(const ResourceManager &) = delete;
  ResourceManager(ResourceManager &&)                 = delete;
  ResourceManager &operator=(ResourceManager &&) = delete;

  void start();
  void stop();
  void reconfigure();

  void set_sum(ResourceType stats_type, uint64_t tag_id, ResourceStatsType index, uint64_t value);
  void set_sum(ResourceType stats_type, ResourceStatsType index, uint64_t value);
  void clear(ResourceType stats_type);

  std::string_view name(uint64_t tid) const;

  Ptr<ProxyMutex> mutex;

private:
  void _add(std::string_view name);

  ResourceStats _sni_stats;
  ResourceStats _active_q_stats;
  ResourceStats _disk_read_stats;
  ResourceStats _disk_write_stats;
};

extern ResourceManager resourceManager;
