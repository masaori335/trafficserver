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

#include "iocore/resource/ResourceStats.h"

#include <utility>

#include "swoc/BufferWriter.h"
#include "tsutil/Metrics.h"

#include "../net/P_UnixNet.h"

namespace
{
using namespace std::literals;

constexpr std::string_view STATS_PREFIX = "proxy.process.resource"sv;

/**
   String of ResourceStatsType. The order must be the same.
 */
constexpr std::string_view STAT_ENTRIES[] = {"observed"sv,   "token"sv,   "tmp_limit", "denied"sv,
                                             "overflowed"sv, "enqueue"sv, "dequeue"sv};

DbgCtl dbg_ctl_rm{"resource"};
} // namespace

////
// ResourceStats
//
void
ResourceStats::init(Ptr<ProxyMutex> m, std::string_view stats_name, int32_t /* stats_size */)
{
  mutex = m;
  _name = stats_name;

  // register global stats here and (partially) fill the global array
  _register_global_stat(ResourceStatsType::OBSERVED);
  _register_global_stat(ResourceStatsType::TOKEN);
}

void
ResourceStats::enable_queue()
{
  _queue = true;
}

bool
ResourceStats::queue()
{
  return _queue;
}

/**
   Store {tid, name} map
 */
void
ResourceStats::add(std::string_view name)
{
  if (mutex == nullptr) {
    return;
  }

  uint64_t tag_id = ResourceConstraints::hash(name);

  auto r = _name_map.find(tag_id);
  if (r != _name_map.end()) {
    // Do nothing if the tag already exists
    return;
  }

  _name_map.insert_or_assign(tag_id, name);
}

void
ResourceStats::add(uint32_t tid, std::string_view name)
{
  if (mutex == nullptr) {
    return;
  }

  auto r = _name_map.find(tid);
  if (r != _name_map.end()) {
    // Do nothing if the tag already exists
    return;
  }

  _name_map.insert_or_assign(tid, name);
}

void
ResourceStats::increment(uint64_t tid, ResourceStatsType index, uint64_t value)
{
  if (mutex == nullptr || value == 0) {
    // Do NOT create new stats entry if value is 0
    return;
  }

  // Read path: shared lock for concurrent reads
  {
    ts::bravo::shared_lock<ts::bravo::shared_mutex> read_lock(_map_mutex);
    auto                                            it = _property_stats.find(tid);
    if (it != _property_stats.end()) {
      CounterList stats = it->second;
      int         id    = static_cast<int>(index);
      auto        stat  = stats.at(id);
      if (stat == nullptr) {
        Error("metric index: %d is nullptr for tag id %" PRIu64, id, tid);
        return;
      }
      ts::Metrics::Counter::increment(stat, value);
      return;
    }
  }

  // Write path: modifying shared _property_stats
  {
    std::unique_lock<ts::bravo::shared_mutex> write_lock(_map_mutex);
    auto                                      it = _property_stats.find(tid);
    if (it == _property_stats.end()) {
      auto name_map_result = _name_map.find(tid);
      if (name_map_result == _name_map.end()) {
        // unknown property
        return;
      }

      std::string_view name = name_map_result->second;

      CounterList list;
      for (int i = 0; i <= static_cast<int>(ResourceStatsType::OVERFLOWED); i++) {
        _register_property_stat(list, name, static_cast<ResourceStatsType>(i));
      }

      if (_queue) {
        _register_property_stat(list, name, ResourceStatsType::ENQUEUE);
        _register_property_stat(list, name, ResourceStatsType::DEQUEUE);
      }

      auto result = _property_stats.insert({tid, list});
      it          = result.first;
    }

    CounterList stats = it->second;
    int         id    = static_cast<int>(index);
    auto        stat  = stats.at(id);
    if (stat == nullptr) {
      Error("metric index: %d is nullptr for tag id %" PRIu64, id, tid);
      return;
    }
    ts::Metrics::Counter::increment(stat, value);
  }
}

void
ResourceStats::increment(ResourceStatsType index, uint64_t value)
{
  if (mutex == nullptr) {
    return;
  }

  int  id   = static_cast<int>(index);
  auto stat = _global_stats.at(id);
  if (stat == nullptr) {
    Error("global stat not incrementable, index: %d", id);
    return;
  }
  ts::Metrics::Counter::increment(stat, value);
}

void
ResourceStats::_register_property_stat(CounterList &list, std::string_view name, ResourceStatsType s)
{
  int id = static_cast<int>(s);

  swoc::LocalBufferWriter<1024> bw;
  bw.print("{0}.{1}.{2}.{3}\0", STATS_PREFIX, _name, name, STAT_ENTRIES[id]);
  auto metric = ts::Metrics::Counter::createPtr(bw.data());
  if (metric == nullptr) {
    Error("couldn't register property stat: %s", bw.data());
  }
  list[id] = metric;
  Dbg(dbg_ctl_rm, "added %s", bw.data());
}

void
ResourceStats::_register_global_stat(ResourceStatsType s)
{
  int id = static_cast<int>(s);

  swoc::LocalBufferWriter<1024> bw;
  bw.print("{0}.global.{1}.{2}\0", STATS_PREFIX, _name, STAT_ENTRIES[id]);
  auto metric = ts::Metrics::Counter::createPtr(bw.data());
  if (metric == nullptr) {
    Error("couldn't register global stat: %s", bw.data());
  }
  _global_stats[id] = metric;
}
