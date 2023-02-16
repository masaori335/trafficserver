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

#include "ResourceConstraints.h"
#include "ResourceManager.h"

#include "P_SSLSNI.h"
#include "P_UnixNet.h"

namespace
{
// for ATS v10+, `swoc::meta::vary` is the equivalent
// helper type for the visitor
// explicit deduction guide (not needed as of C++20)
template <class... Ts> struct overloaded : Ts... {
  using Ts::operator()...;
};
template <class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

// TODO: figure out gettting ResourceType from the limiter
template <class T>
void
report_v0(const T &limiter, ResourceType resource_type)
{
  SCOPED_MUTEX_LOCK(lock, resourceManager.mutex, this_ethread());

  auto &global_bucket = limiter.global_bucket();

  resourceManager.set_sum(resource_type, ResourceStatsType::OBSERVED, global_bucket.observed);

  resourceManager.clear(resource_type);

  auto &map            = limiter.bucket_map();
  auto &sorted_tid_map = limiter.sorted_tid_map();
  auto &conf           = limiter.conf();

  uint64_t i = 0;
  for (auto iter = sorted_tid_map.crbegin(); iter != sorted_tid_map.crend() && i < conf.top_n; ++iter, ++i) {
    const uint64_t tid = iter->second;
    const auto &bucket = map.at(tid);

    resourceManager.set_sum(resource_type, tid, ResourceStatsType::OBSERVED, bucket.observed);
  }
}

template <class T>
void
report_v1(const T &limiter, ResourceType resource_type)
{
  auto &global_bucket = limiter.global_bucket();

  resourceManager.set_sum(resource_type, ResourceStatsType::OBSERVED, global_bucket.observed);
  resourceManager.set_sum(resource_type, ResourceStatsType::TOKEN, global_bucket.token);

  resourceManager.clear(resource_type);

  auto &map            = limiter.bucket_map();
  auto &sorted_tid_map = limiter.sorted_tid_map();
  auto &conf           = limiter.conf();

  uint64_t i = 0;
  for (auto iter = sorted_tid_map.crbegin(); iter != sorted_tid_map.crend() && i < conf.top_n; ++iter, ++i) {
    const uint64_t tid = iter->second;
    const auto &bucket = map.at(tid);

    resourceManager.set_sum(resource_type, tid, ResourceStatsType::OBSERVED, bucket.observed);
    resourceManager.set_sum(resource_type, tid, ResourceStatsType::TOKEN, bucket.token);
    resourceManager.set_sum(resource_type, tid, ResourceStatsType::DENIED, bucket.denied);
    resourceManager.set_sum(resource_type, tid, ResourceStatsType::TMP_LIMIT, bucket.tmp_limit);
    resourceManager.set_sum(resource_type, tid, ResourceStatsType::OVERFLOWED, bucket.overflowed);
  }
}

} // namespace

////
// ResourceReport
//
void
ResourceReport::operator()(const TLSHandshakeLimiterV0 &limiter)
{
  report_v0<TLSHandshakeLimiterV0>(limiter, ResourceType::SNI);
}

void
ResourceReport::operator()(const TLSHandshakeLimiterV1 &limiter)
{
  report_v1<TLSHandshakeLimiterV1>(limiter, ResourceType::SNI);
}

void
ResourceReport::operator()(const ActiveQLimiterV0 &limiter)
{
  report_v0<ActiveQLimiterV0>(limiter, ResourceType::ACTIVE_Q);
}

void
ResourceReport::operator()(const ActiveQLimiterV1 &limiter)
{
  report_v1<ActiveQLimiterV1>(limiter, ResourceType::ACTIVE_Q);
}

void
ResourceReport::operator()(const DiskReadLimiterV1 &limiter)
{
  report_v1<DiskReadLimiterV1>(limiter, ResourceType::DISK_READ);
}

void
ResourceReport::operator()(const DiskWriteLimiterV1 &limiter)
{
  report_v1<DiskWriteLimiterV1>(limiter, ResourceType::DISK_WRITE);
}

////
// ResourceLocalManager
//
void
ResourceLocalManager::start()
{
  mutex = new_ProxyMutex();

  _limiters.emplace_back(TLSHandshakeLimiterV1{});
  _limiters.emplace_back(ActiveQLimiterV1{});
  _limiters.emplace_back(DiskReadLimiterV1{});
  _limiters.emplace_back(DiskWriteLimiterV1{});

  for (auto &limiter : _limiters) {
    std::visit(overloaded{
                 [&](TLSHandshakeLimiterV0 &l) {},
                 [&](TLSHandshakeLimiterV1 &l) { _sni_limiter = &l; },
                 [&](ActiveQLimiterV0 &l) {},
                 [&](ActiveQLimiterV1 &l) { _active_q_limiter = &l; },
                 [&](DiskReadLimiterV1 &l) { _disk_read_limiter = &l; },
                 [&](DiskWriteLimiterV1 &l) { _disk_write_limiter = &l; },
               },
               limiter);
  }

  // setup for "unknown"
  _tid_map.insert_or_assign(UNKNOWN_TID, UNKNOWN_TAG);

  for (auto &limiter : _limiters) {
    std::visit([&](auto &l) { l.add(UNKNOWN_TID); }, limiter);
  }

  reconfigure();
}

void
ResourceLocalManager::stop()
{
  mutex->free();
}

/**
   Requires SNIConfig is loaded
 */
void
ResourceLocalManager::reconfigure()
{
  ink_assert(_limiters.size() == static_cast<size_t>(ResourceType::LAST_ENTRY));

  {
    ResourceConfig::scoped_config resource_conf;

    _mode_sni        = resource_conf->sni.mode;
    _mode_active_q   = resource_conf->active_q.mode;
    _mode_disk_read  = resource_conf->disk_read.mode;
    _mode_disk_write = resource_conf->disk_write.mode;

    for (auto &limiter : _limiters) {
      std::visit(overloaded{
                   [&](TLSHandshakeLimiterV0 &l) { l.reconfigure({resource_conf->top_n}); },
                   [&](TLSHandshakeLimiterV1 &l) {
                     l.reconfigure({
                       resource_conf->top_n,
                       resource_conf->sni.limit,
                       resource_conf->sni.penalty_duration,
                       resource_conf->sni.red_zone,
                     });
                   },
                   [&](ActiveQLimiterV0 &l) { l.reconfigure({resource_conf->top_n}); },
                   [&](ActiveQLimiterV1 &l) {
                     l.reconfigure({
                       resource_conf->top_n,
                       resource_conf->active_q.limit,
                       resource_conf->active_q.penalty_duration,
                       resource_conf->active_q.red_zone,
                     });
                   },
                   [&](DiskReadLimiterV1 &l) {
                     l.reconfigure({
                       resource_conf->top_n,
                       resource_conf->disk_read.limit,
                       resource_conf->disk_read.penalty_duration,
                       resource_conf->disk_read.red_zone,
                     });
                   },
                   [&](DiskWriteLimiterV1 &l) {
                     l.reconfigure({
                       resource_conf->top_n,
                       resource_conf->disk_write.limit,
                       resource_conf->disk_write.penalty_duration,
                       resource_conf->disk_write.red_zone,
                     });
                   },
                 },
                 limiter);
    }
  }

  {
    SNIConfig::scoped_config sni_conf;
    for (const auto &item : sni_conf->yaml_sni.items) {
      if (item.tag.empty()) {
        continue;
      }

      uint32_t tid = ResourceConstraints::hash(item.tag);
      if (tid == UNKNOWN_TID) {
        Warning("tid for %s got conflict with tid for unknown", item.tag.c_str());
        continue;
      }

      auto r = _tid_map.find(tid);
      if (r != _tid_map.end()) {
        // skip tid already registered
        continue;
      }

      _tid_map.insert_or_assign(tid, item.tag);

      for (auto &limiter : _limiters) {
        std::visit([&](auto &l) { l.add(tid); }, limiter);
      }
    }
  }
}

/**
   TODO: check all stats type on SNI hook
 */
bool
ResourceLocalManager::is_full(uint64_t tid)
{
  return false;
}

bool
ResourceLocalManager::is_full(uint64_t tid, ResourceType type)
{
  bool result;

  switch (type) {
  case ResourceType::SNI: {
    result = _sni_limiter->is_full(tid);

    if (_mode_sni == ResourceConfigMode::RESTRICTION) {
      return result;
    }

    break;
  }
  case ResourceType::ACTIVE_Q: {
    result = _active_q_limiter->is_full(tid);

    if (_mode_disk_write == ResourceConfigMode::RESTRICTION) {
      return result;
    }

    break;
  }
  case ResourceType::DISK_READ: {
    result = _disk_read_limiter->is_full(tid);

    if (_mode_disk_read == ResourceConfigMode::RESTRICTION) {
      return result;
    }

    break;
  }
  case ResourceType::DISK_WRITE: {
    result = _disk_write_limiter->is_full(tid);

    if (_mode_disk_write == ResourceConfigMode::RESTRICTION) {
      return result;
    }

    break;
  }
  default:
    ink_abort("unsupported yet");
    break;
  }

  return false;
}

void
ResourceLocalManager::inc(uint64_t tid, ResourceType type)
{
  switch (type) {
  case ResourceType::SNI: {
    if (_mode_sni == ResourceConfigMode::DISABLED) {
      // nothing to do
      return;
    }

    return _sni_limiter->inc(tid);
  }
  case ResourceType::ACTIVE_Q: {
    if (_mode_active_q == ResourceConfigMode::DISABLED) {
      // nothing to do
      return;
    }

    return _active_q_limiter->inc(tid);
  }
  case ResourceType::DISK_READ: {
    if (_mode_sni == ResourceConfigMode::DISABLED) {
      // nothing to do
      return;
    }

    return _disk_read_limiter->inc(tid);
  }
  case ResourceType::DISK_WRITE: {
    if (_mode_disk_write == ResourceConfigMode::DISABLED) {
      // nothing to do
      return;
    }

    return _disk_write_limiter->inc(tid);
  }

  default:
    ink_abort("unsupported yet");
    break;
  }
}

void
ResourceLocalManager::dec(uint64_t tid, ResourceType type)
{
  switch (type) {
  case ResourceType::ACTIVE_Q:
  case ResourceType::SNI:
  default:
    ink_abort("unsupported yet");
    break;
  }
}

/**
   Travarse all entry is pretty naive...we need to figure out good data structure.
 */
void
ResourceLocalManager::reserve()
{
  if (resourceManager.mutex == nullptr) {
    // Do nothing until ResourceManager is ready
    return;
  }

  // NOTE: can we reduce glue code like this?
  // for (auto &limiter : _limiters) {
  //   std::visit([&](auto &l) { l.filter(); }, limiter);
  //   std::visit(ResourceReport{}, limiter);
  //   std::visit([&](auto &l) { l.reserve(); }, limiter);
  // }

  if (_mode_sni != ResourceConfigMode::DISABLED) {
    _sni_limiter->filter();
    report_v1<TLSHandshakeLimiterV1>(*_sni_limiter, ResourceType::SNI);
    _sni_limiter->reserve();
  }

  if (_mode_active_q != ResourceConfigMode::DISABLED) {
    _active_q_limiter->filter();
    report_v1<ActiveQLimiterV1>(*_active_q_limiter, ResourceType::ACTIVE_Q);
    _active_q_limiter->reserve();
  }

  if (_mode_disk_read != ResourceConfigMode::DISABLED) {
    _disk_read_limiter->filter();
    report_v1<DiskReadLimiterV1>(*_disk_read_limiter, ResourceType::DISK_READ);
    _disk_read_limiter->reserve();
  }

  if (_mode_disk_write != ResourceConfigMode::DISABLED) {
    _disk_write_limiter->filter();
    report_v1<DiskWriteLimiterV1>(*_disk_write_limiter, ResourceType::DISK_WRITE);
    _disk_write_limiter->reserve();
  }
}
