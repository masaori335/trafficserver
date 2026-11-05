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

#include "iocore/resource/ResourceConstraints.h"
#include "iocore/eventsystem/Continuation.h"
#include "iocore/resource/ResourceConfig.h"
#include "iocore/resource/ResourceManager.h"

#include "iocore/net/SSLSNIConfig.h"
#include "iocore/eventsystem/VConnection.h"

namespace
{
// TODO: figure out gettting ResourceType from the limiter

// Remove report_v0, as that used gauges to keep track of stats. We now use counters as that
// captures a fuller picture of what happens between ATS exporter measurments
template <class T>
void
report_v0(const T & /* limiter */, ResourceType /* resource_type */)
{
  // do nothing
  // Remove report_v0, as that used gauges to keep track of stats. We now use counters as that
  // captures a fuller picture of what happens between ATS exporter measurments
}

template <class T>
void
report_v1(const T &limiter, ResourceType resource_type)
{
  auto &global_bucket = limiter.global_bucket();

  resourceManager.increment(resource_type, ResourceStatsType::OBSERVED, global_bucket.observed);
  resourceManager.increment(resource_type, ResourceStatsType::TOKEN, global_bucket.token);

  auto &map            = limiter.bucket_map();
  auto &sorted_tid_map = limiter.sorted_tid_map();
  auto &conf           = limiter.conf();

  uint64_t i = 0;

  for (auto iter = sorted_tid_map.crbegin(); iter != sorted_tid_map.crend(); ++iter, ++i) {
    const uint64_t tid    = iter->second;
    const auto    &bucket = map.at(tid);

    resourceManager.increment(resource_type, tid, ResourceStatsType::OBSERVED, bucket.observed);
    resourceManager.increment(resource_type, tid, ResourceStatsType::TOKEN, bucket.token);
    resourceManager.increment(resource_type, tid, ResourceStatsType::DENIED, bucket.denied);
    resourceManager.increment(resource_type, tid, ResourceStatsType::TMP_LIMIT, bucket.tmp_limit);
    resourceManager.increment(resource_type, tid, ResourceStatsType::OVERFLOWED, bucket.overflowed);
    if (conf.queue) {
      resourceManager.increment(resource_type, tid, ResourceStatsType::ENQUEUE, bucket.enqueue);
      resourceManager.increment(resource_type, tid, ResourceStatsType::DEQUEUE, bucket.dequeue);
    }
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
ResourceLocalManager::ResourceLocalManager() : Continuation(new_ProxyMutex())
{
  SET_HANDLER(&ResourceLocalManager::state_init);
}

ResourceLocalManager::~ResourceLocalManager()
{
  this->mutex = nullptr;
}

int
ResourceLocalManager::state_init(int /* event */, void * /* data */)
{
  return EVENT_DONE;
}

int
ResourceLocalManager::state_running(int event, void * /* data */)
{
  switch (event) {
  case EVENT_IMMEDIATE: {
    reconfigure();
    break;
  }
  case EVENT_INTERVAL: {
    reserve();
    break;
  }
  default:
    ink_abort("unsupported event=%s (%d)", get_vc_event_name(event), event);
    break;
  }
  return EVENT_DONE;
}

void
ResourceLocalManager::start(EThread *ethread)
{
  _limiters.emplace_back(TLSHandshakeLimiterV1{});

  for (auto &limiter : _limiters) {
    std::visit(swoc::meta::vary{
                 [&](TLSHandshakeLimiterV0 & /* l */) {},
                 [&](TLSHandshakeLimiterV1 &l) { _sni_limiter = &l; },
                 [&](auto & /* l */) {},
               },
               limiter);
  }

  // setup for "unknown"
  for (auto &limiter : _limiters) {
    std::visit([&](auto &l) { l.add(UNKNOWN_TID); }, limiter);
  }

  // schedule self periodical event
  ResourceConfig::scoped_config config;
  ethread->schedule_every(this, HRTIME_SECONDS(config->freq));
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

    _mode_sni = resource_conf->sni.mode;

    for (auto &limiter : _limiters) {
      std::visit(swoc::meta::vary{[&](TLSHandshakeLimiterV0 &l) { l.reconfigure({resource_conf->top_n}); },
                                  [&](TLSHandshakeLimiterV1 &l) {
                                    l.reconfigure({
                                      resource_conf->top_n,
                                      resource_conf->sni.limit,
                                      resource_conf->sni.penalty_duration,
                                      resource_conf->sni.red_zone,
                                    });
                                  },
                                  [&](auto & /* l */) {}},
                 limiter);
    }
  }

  {
    // clear disabled property list to be reloadable
    _tid_disable_set.clear();
    SNIConfig::scoped_config sni_conf;
    for (const auto &item : sni_conf->yaml_sni.items) {
      if (item.tag.empty()) {
        continue;
      }

      uint64_t tid = ResourceConstraints::hash(item.tag);
      if (tid == UNKNOWN_TID) {
        Warning("tid for %s got conflict with tid for unknown", item.tag.c_str());
        continue;
      }

      for (auto &limiter : _limiters) {
        std::visit([&](auto &l) { l.add(tid); }, limiter);
      }

      if (item.disable_harmony) {
        _tid_disable_set.insert(tid);
      }
    }
  }

  SET_HANDLER(&ResourceLocalManager::state_running);
}

bool
ResourceLocalManager::running()
{
  return (this->handler == &ResourceLocalManager::state_running);
}

/**
   TODO: check all stats type on SNI hook
 */
bool
ResourceLocalManager::is_full(uint64_t /* tid */)
{
  return false;
}

bool
ResourceLocalManager::is_full(uint64_t tid, ResourceType type)
{
  bool result;
  bool disabled = (_tid_disable_set.find(tid) != _tid_disable_set.end());
  if (disabled) {
    return false;
  }

  switch (type) {
  case ResourceType::SNI: {
    if (_mode_sni == ResourceConfigMode::DISABLED) {
      return false;
    }
    result = _sni_limiter->is_full(tid);

    if (_mode_sni == ResourceConfigMode::RESTRICTION) {
      return result;
    }

    break;
  }
  case ResourceType::ACTIVE_Q: {
    if (_mode_active_q == ResourceConfigMode::DISABLED) {
      return false;
    }
    result = _active_q_limiter->is_full(tid);

    if (_mode_active_q == ResourceConfigMode::RESTRICTION) {
      return result;
    }

    break;
  }
  case ResourceType::DISK_READ: {
    if (_mode_disk_read == ResourceConfigMode::DISABLED) {
      return false;
    }
    result = _disk_read_limiter->is_full(tid);

    if (_mode_disk_read == ResourceConfigMode::RESTRICTION) {
      return result;
    }

    break;
  }
  case ResourceType::DISK_WRITE: {
    if (_mode_disk_write == ResourceConfigMode::DISABLED) {
      return false;
    }
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
    if (_mode_disk_read == ResourceConfigMode::DISABLED) {
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
  case ResourceType::ACTIVE_Q: {
    if (_mode_active_q == ResourceConfigMode::DISABLED) {
      // nothing to do
      return;
    }

    return _active_q_limiter->dec(tid);
  }
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

  ink_assert(this->mutex->thread_holding == this_ethread());

  for (auto &limiter : _limiters) {
    std::visit([&](auto &l) { l.filter(); }, limiter);
    std::visit(ResourceReport{}, limiter);
    std::visit([&](auto &l) { l.reserve(); }, limiter);
  }
}
