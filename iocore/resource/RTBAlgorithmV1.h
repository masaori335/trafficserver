/** @file

  Reactive Token Bucket v1

  This algorithm is based on regular Token Bucket. Main ideas are

  1). Token size is dynamically adjusted by demands
  2). Add Overflow Bucket

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
/**
   - Set Red zone (_global_bucket bucket size) by config
   - Divide blue zone by top N properties

    ┌───────────────┬───────┐
    │     BLUE      │  RED  │
    ├─┬─┬─┬─┬─┬───┬─┼───────┤
    │A│B│C│D│E│...│N│       │
    └─┴─┴─┴─┴─┴───┴─┴───────┘
 */
template <class StatsType> class AlgorithmV1
{
public:
  struct Conf {
    uint64_t top_n            = 10;
    uint64_t limit            = 0;
    uint64_t penalty_duration = 0;
    float red_zone            = 0.1;
    bool queue                = 0;
  };

  struct Bucket {
    uint64_t observed          = 0;
    uint64_t overflowed        = 0;
    uint64_t token             = 0;
    uint64_t tmp_limit         = 0;
    uint64_t tmp_limit_counter = 0;
    uint64_t denied            = 0;
    uint64_t enqueue           = 0;
    uint64_t dequeue           = 0;
    uint64_t queue_delta       = 0;
  };

  using BucketMap    = std::unordered_map<uint64_t, Bucket>; ///< key = tid, value = bucket
  using SortedTidMap = std::multimap<uint64_t, uint64_t>;    ///< key = observed, value = tid

  struct GlobalBucket {
    uint64_t observed = 0;
    uint64_t token    = 0;
  };

  AlgorithmV1() {}
  AlgorithmV1(Conf c) : _conf(c) {}

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
  void _reserve_with_tmp_limit();
  void _reserve_without_tmp_limit();

  Conf _conf;
  BucketMap _bucket_map;
  SortedTidMap _sorted_tid_map;
  GlobalBucket _global_bucket;
};

////
// Inline Functions
//
////
// Algorithm v1
//
template <class StatsType>
inline void
AlgorithmV1<StatsType>::add(uint64_t tid)
{
  Bucket b{};
  _bucket_map.insert(std::pair(tid, b));
}

template <class StatsType>
inline bool
AlgorithmV1<StatsType>::is_full(uint64_t tid)
{
  if (_conf.limit == 0) {
    return false;
  }

  auto e = _bucket_map.find(tid);
  if (e == _bucket_map.end()) {
    return false;
  }

  Bucket &b = e->second;

  if (b.token == 0) {
    return false;
  }

  // even if the bucket has temporal limit, allow them to use global bucket.
  // if (b.tmp_limit > 0 && b.observed >= b.tmp_limit) {
  //   ++b.denied;
  //   return true;
  // }

  if (b.observed > b.token && _global_bucket.observed > _global_bucket.token) {
    ++b.denied;
    return true;
  }

  return false;
}

template <class StatsType>
inline void
AlgorithmV1<StatsType>::inc(uint64_t tid)
{
  auto e = _bucket_map.find(tid);
  if (e == _bucket_map.end()) {
    return;
  }

  Bucket &b = e->second;
  ++b.observed;
  ++b.enqueue;

  if (b.token > 0 && b.observed <= b.token) {
    return;
  }

  ++b.overflowed;
  ++_global_bucket.observed;
}

template <class StatsType>
inline void
AlgorithmV1<StatsType>::dec(uint64_t tid)
{
  auto e = _bucket_map.find(tid);
  if (e == _bucket_map.end()) {
    return;
  }

  Bucket &b = e->second;
  --b.observed;
  ++b.dequeue;
  if (b.overflowed == 0) {
    return;
  }

  --b.overflowed;
  --_global_bucket.observed;
}

template <class StatsType>
inline void
AlgorithmV1<StatsType>::filter()
{
  // sort by observed
  _sorted_tid_map.clear();

  // Sort tid by observed
  for (auto &[tid, bucket] : _bucket_map) {
    if (_conf.queue) {
      bucket.queue_delta += bucket.enqueue - bucket.dequeue;
      bucket.observed = bucket.queue_delta + bucket.enqueue;
    }
    _sorted_tid_map.insert(std::make_pair(bucket.observed, tid));
  }
}

/**
   This traverses the BucketMap 2 times (+1 at sort) ...any better idea?
 */
template <class StatsType>
inline void
AlgorithmV1<StatsType>::reserve()
{
  // _reserve_without_tmp_limit();
  _reserve_with_tmp_limit();
}

template <class StatsType>
inline void
AlgorithmV1<StatsType>::_reserve_without_tmp_limit()
{
  ////
  // Dedicated Buckets
  //

  // Calcurate total observed of top N properties
  uint64_t total = 0;
  uint64_t i     = 0;
  for (auto iter = _sorted_tid_map.crbegin(); iter != _sorted_tid_map.crend() && i < _conf.top_n; ++iter, ++i) {
    const uint64_t tid = iter->second;
    Bucket &bucket     = _bucket_map[tid];
    if (_conf.queue) {
      bucket.queue_delta += bucket.enqueue - bucket.dequeue;
      bucket.observed = bucket.queue_delta + bucket.enqueue;
    }
    total += bucket.observed;
  }

  // Reserve tokens for each properties
  uint64_t assigned_token = 0;
  if (total > 0) {
    float unit = _conf.limit * (1 - _conf.red_zone) / total;

    i = 0;
    for (auto iter = _sorted_tid_map.crbegin(); iter != _sorted_tid_map.crend(); ++iter, ++i) {
      const uint64_t tid = iter->second;
      Bucket &bucket     = _bucket_map[tid];

      if (i < _conf.top_n) {
        // Top N properties
        bucket.token = std::max(static_cast<int>(bucket.observed * unit), 1);
        assigned_token += bucket.token;
      } else {
        // Small properties - no dedicated buckets
        bucket.token = 0;
      }

      // Clear Stats
      StatsType::clear(bucket.observed);
      StatsType::clear(bucket.overflowed);
      StatsType::clear(bucket.enqueue);
      StatsType::clear(bucket.dequeue);
      StatsType::clear(bucket.denied);
    }
  }

  ////
  // Global Bucket
  //
  ink_assert(_conf.limit > assigned_token);

  _global_bucket.token = _conf.limit - assigned_token;
  StatsType::clear(_global_bucket.observed);
}

/**
   This traverses the BucketMap 2 times (+1 at sort) ...any better idea?
 */
template <class StatsType>
inline void
AlgorithmV1<StatsType>::_reserve_with_tmp_limit()
{
  ////
  // Dedicated Buckets
  //

  // Calcurate total observed of top N properties
  // Process tmp_limit
  uint64_t total = 0;
  uint64_t i     = 0;
  for (auto iter = _sorted_tid_map.crbegin(); iter != _sorted_tid_map.crend() && i < _conf.top_n; ++iter, ++i) {
    const uint64_t tid = iter->second;
    Bucket &bucket     = _bucket_map[tid];

    if (bucket.tmp_limit > 0) {
      if (++bucket.tmp_limit_counter >= _conf.penalty_duration) {
        bucket.tmp_limit         = 0;
        bucket.tmp_limit_counter = 0;
      }
    } else {
      if (_global_bucket.observed > _global_bucket.token && bucket.observed > bucket.token && bucket.denied > 0) {
        bucket.tmp_limit = bucket.token;
      }
    }

    total += (bucket.tmp_limit > 0) ? bucket.tmp_limit : bucket.observed;
  }

  // Reserve tokens for each properties
  float unit = 0.0;
  if (total > 0) {
    unit = _conf.limit * (1 - _conf.red_zone) / total;
  }

  uint64_t assigned_token = 0;
  uint64_t j              = 0;
  for (auto iter = _sorted_tid_map.crbegin(); iter != _sorted_tid_map.crend(); ++iter, ++j) {
    const uint64_t tid = iter->second;
    Bucket &bucket     = _bucket_map[tid];

    if (j < _conf.top_n) {
      // Top N properties
      uint64_t observed = (bucket.tmp_limit > 0) ? bucket.tmp_limit : bucket.observed;

      bucket.token = static_cast<int>(observed * unit);
      assigned_token += bucket.token;
    } else {
      // Small properties - no dedicated buckets
      bucket.token = 0;
    }

    // Clear Stats
    StatsType::clear(bucket.observed);
    StatsType::clear(bucket.overflowed);
    StatsType::clear(bucket.enqueue);
    StatsType::clear(bucket.dequeue);
    StatsType::clear(bucket.denied);
  }

  ////
  // Global Bucket
  //
  ink_assert(_conf.limit >= assigned_token);

  _global_bucket.token = _conf.limit - assigned_token;
  StatsType::clear(_global_bucket.observed);
}

template <class StatsType>
inline void
AlgorithmV1<StatsType>::reconfigure(const Conf &c)
{
  _conf = c;
}

template <class StatsType>
inline const auto &
AlgorithmV1<StatsType>::bucket_map() const
{
  return _bucket_map;
}

template <class StatsType>
inline const auto &
AlgorithmV1<StatsType>::sorted_tid_map() const
{
  return _sorted_tid_map;
}

template <class StatsType>
inline const auto &
AlgorithmV1<StatsType>::global_bucket() const
{
  return _global_bucket;
}

template <class StatsType>
inline const auto &
AlgorithmV1<StatsType>::conf() const
{
  return _conf;
}
} // namespace RTB
