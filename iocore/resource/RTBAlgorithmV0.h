/** @file

  Reactive Token Bucket v0

  No limit. Recording Stats Only.

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

#include "RTBStatsType.h"

#include "tscore/Diags.h"
#include "tscore/BufferWriter.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <map>
#include <unordered_map>

namespace RTB
{
template <class StatsType> class AlgorithmV0
{
public:
  struct Conf {
    uint64_t top_n = 10;
  };

  struct Bucket {
    uint64_t observed = 0;
  };

  using BucketMap    = std::unordered_map<uint64_t, Bucket>; ///< key = tid, value = bucket
  using SortedTidMap = std::multimap<uint64_t, uint64_t>;    ///< key = observed, value = tid

  struct GlobalBucket {
    uint64_t observed = 0;
  };

  AlgorithmV0() {}
  AlgorithmV0(Conf c) : _conf(c) {}

  void add(uint64_t tid);
  bool is_full(uint64_t tid);
  void inc(uint64_t tid);
  void dec(uint64_t tid);
  void filter();
  void reserve();
  void reconfigure(const Conf &c);

  // Accessor for reporter
  const auto &bucket_map() const;
  const auto &sorted_tid_map() const;
  const auto &global_bucket() const;
  const auto &conf() const;

private:
  Conf _conf;
  BucketMap _bucket_map;
  SortedTidMap _sorted_tid_map;
  GlobalBucket _global_bucket;
};

////
// Inline Functions
//
template <class StatsType>
inline void
AlgorithmV0<StatsType>::add(uint64_t tid)
{
  Bucket b{};
  _bucket_map.insert(std::pair(tid, b));
}

template <class StatsType>
inline bool
AlgorithmV0<StatsType>::is_full(uint64_t tid)
{
  return false;
}

template <class StatsType>
inline void
AlgorithmV0<StatsType>::inc(uint64_t tid)
{
  auto e = _bucket_map.find(tid);
  if (e == _bucket_map.end()) {
    return;
  }

  Bucket &b = e->second;
  ++b.observed;
  ++_global_bucket.observed;
}

template <class StatsType>
inline void
AlgorithmV0<StatsType>::dec(uint64_t tid)
{
  ink_assert(StatsType::is_decrementable);

  auto e = _bucket_map.find(tid);
  if (e == _bucket_map.end()) {
    return;
  }

  Bucket &b = e->second;
  ink_assert(b.observed > 0);
  --(b.observed);

  ink_assert(_global_bucket.observed > 0);
  --_global_bucket.observed;

  return;
}

template <class StatsType>
inline void
AlgorithmV0<StatsType>::filter()
{
  // sort by observed
  _sorted_tid_map.clear();

  // Sort tid by observed
  for (auto &[tid, bucket] : _bucket_map) {
    _sorted_tid_map.insert(std::make_pair(bucket.observed, tid));
  }
}

template <class StatsType>
inline void
AlgorithmV0<StatsType>::reserve()
{
  StatsType::clear(_global_bucket.observed);

  for (auto &[tid, s] : _bucket_map) {
    StatsType::clear(s.observed);
  }

  return;
}

template <class StatsType>
inline void
AlgorithmV0<StatsType>::reconfigure(const Conf &c)
{
  _conf = c;
}

template <class StatsType>
inline const auto &
AlgorithmV0<StatsType>::bucket_map() const
{
  return _bucket_map;
}

template <class StatsType>
inline const auto &
AlgorithmV0<StatsType>::sorted_tid_map() const
{
  return _sorted_tid_map;
}

template <class StatsType>
inline const auto &
AlgorithmV0<StatsType>::global_bucket() const
{
  return _global_bucket;
}

template <class StatsType>
inline const auto &
AlgorithmV0<StatsType>::conf() const
{
  return _conf;
}

} // namespace RTB
