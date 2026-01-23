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

#include <unordered_map>
#include <array>

#include "tsutil/Metrics.h"
#include "Resource.h"
#include "iocore/eventsystem/Lock.h"
#include "tsutil/Bravo.h"

class ResourceStats
{
public:
  void init(Ptr<ProxyMutex> mutex, std::string_view stats_name, int32_t stats_size);
  void add(std::string_view name);
  void add(uint32_t tid, std::string_view name);
  void increment(uint64_t tag_id, ResourceStatsType index, uint64_t value);
  void increment(ResourceStatsType s, uint64_t value);
  void enable_queue();
  bool queue();

  ////
  // Variables
  //
  Ptr<ProxyMutex> mutex; ///< guard for creating new stats

private:
  using CounterList = std::array<ts::Metrics::Counter::AtomicType *, static_cast<size_t>(ResourceStatsType::LAST_ENTRY)>;

  ////
  // Functions
  //
  void _register_property_stat(CounterList &list, std::string_view name, ResourceStatsType s);
  void _register_global_stat(ResourceStatsType s);

  ////
  // Variables
  //
  std::string_view _name;
  bool             _queue = false;

  CounterList                               _global_stats;
  std::unordered_map<uint64_t, CounterList> _property_stats; ///< { property id: array of resource stats }
  std::unordered_map<uint64_t, std::string> _name_map;       ///< { property id: name }
  mutable ts::bravo::shared_mutex           _map_mutex;
};
