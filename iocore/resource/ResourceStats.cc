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

#include "ResourceStats.h"

#include "tscore/BufferWriter.h"

namespace
{
using namespace std::literals;

constexpr std::string_view STATS_PREFIX = "proxy.process.resource"sv;

struct StatEntry {
  std::string_view name;
  RecRawStatSyncCb cb;
};

/**
   String of ResourceStatsType. The order must be the same.
 */
constexpr StatEntry STAT_ENTRIES[] = {{"observed"sv, RecRawStatSyncSum},
                                      {"token"sv, RecRawStatSyncSum},
                                      {"tmp_limit"sv, RecRawStatSyncSum},
                                      {"denied"sv, RecRawStatSyncSum},
                                      {"overflowed"sv, RecRawStatSyncSum}};

} // namespace

////
// ResourceStats
//
void
ResourceStats::init(Ptr<ProxyMutex> m, std::string_view stats_name, int32_t stats_size)
{
  mutex = m;
  _name = stats_name;

  _property_buckets.init(stats_size);

  _global_buckets = RecAllocateRawStatBlock(static_cast<int>(ResourceStatsType::LAST_ENTRY));

  _register_global_stat(ResourceStatsType::OBSERVED);
  _register_global_stat(ResourceStatsType::TOKEN);
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
ResourceStats::set_sum(uint64_t tid, ResourceStatsType index, uint64_t value)
{
  if (mutex == nullptr) {
    return;
  }

  int offset = _find_register(tid, value);
  if (offset < 0) {
    return;
  }

  int sid = offset + static_cast<int>(index);

  _property_buckets.set_sum_thread(sid, value);
}

void
ResourceStats::set_sum(ResourceStatsType index, uint64_t value)
{
  if (mutex == nullptr) {
    return;
  }

  RecRawStat *tlp = raw_stat_get_tlp(_global_buckets, static_cast<int>(index), nullptr);
  tlp->sum        = value;
}

void
ResourceStats::increment(uint64_t tid, ResourceStatsType index, uint64_t value)
{
  if (mutex == nullptr) {
    return;
  }

  int offset = _find_register(tid, value);
  if (offset < 0) {
    return;
  }

  int sid = offset + static_cast<int>(index);

  _property_buckets.increment(sid, value);
}

void
ResourceStats::increment(ResourceStatsType index, uint64_t value)
{
  if (mutex == nullptr) {
    return;
  }
  RecIncrRawStat(_global_buckets, nullptr, static_cast<int>(index), value);
}

int
ResourceStats::_find_register(uint64_t tid, uint64_t value)
{
  // Race of creating new stats if _stats_id_map doesn't have it
  SCOPED_MUTEX_LOCK(lock, mutex, this_ethread());

  auto stats_id_result = _stats_id_map.find(tid);
  if (stats_id_result == _stats_id_map.end()) {
    if (value == 0) {
      // Do NOT create new stats entry if value is 0
      return -1;
    }

    auto name_map_result = _name_map.find(tid);
    if (name_map_result == _name_map.end()) {
      // unknown property
      return -1;
    }

    std::string_view name = name_map_result->second;

    // remember only the first stat_id
    int stat_id = _register_property_stat(name, ResourceStatsType::OBSERVED);
    if (stat_id < 0) {
      Warning("error with adding %.*s", static_cast<int>(name.size()), name.data());
      return -1;
    }
    _stats_id_map.insert_or_assign(tid, stat_id);

    _register_property_stat(name, ResourceStatsType::TOKEN);
    _register_property_stat(name, ResourceStatsType::TMP_LIMIT);
    _register_property_stat(name, ResourceStatsType::DENIED);
    _register_property_stat(name, ResourceStatsType::OVERFLOWED);
    return 0;
  }
  return stats_id_result->second;
}

void
ResourceStats::clear()
{
  if (mutex == nullptr) {
    return;
  }

  for (auto entry : _stats_id_map) {
    int sid = entry.second;
    _property_buckets.set_sum_thread(sid + static_cast<int>(ResourceStatsType::OBSERVED), 0);
    _property_buckets.set_sum_thread(sid + static_cast<int>(ResourceStatsType::TOKEN), 0);
    _property_buckets.set_sum_thread(sid + static_cast<int>(ResourceStatsType::TMP_LIMIT), 0);
    _property_buckets.set_sum_thread(sid + static_cast<int>(ResourceStatsType::DENIED), 0);
    _property_buckets.set_sum_thread(sid + static_cast<int>(ResourceStatsType::OVERFLOWED), 0);
  }
}

int
ResourceStats::_register_property_stat(std::string_view name, ResourceStatsType s)
{
  int id = static_cast<int>(s);

  ts::LocalBufferWriter<1024> bw;
  bw.print("{0}.{1}.{2}.{3}\0", STATS_PREFIX, _name, name, STAT_ENTRIES[id].name);

  Debug("resource", "add %s", bw.data());

  return _property_buckets.create(RECT_PROCESS, bw.data(), RECD_INT, STAT_ENTRIES[id].cb);
}

void
ResourceStats::_register_global_stat(ResourceStatsType s)
{
  int id = static_cast<int>(s);

  // Q: is there any function to make the string null terminated?
  ts::LocalBufferWriter<1024> bw;
  bw.print("{0}.global.{1}.{2}\0", STATS_PREFIX, _name, STAT_ENTRIES[id].name);

  RecRegisterRawStat(_global_buckets, RECT_PROCESS, bw.data(), RECD_INT, RECP_NON_PERSISTENT, id, STAT_ENTRIES[id].cb);
}
