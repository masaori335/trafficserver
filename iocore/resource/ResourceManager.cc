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

#include "ResourceManager.h"

#include "P_SSLSNI.h"
#include "P_UnixNet.h"

ResourceManager resourceManager;

////
// ResourceManager
//
/**
   TODO: add config to turn on/off resource constraints feature
 */
void
ResourceManager::start()
{
  ResourceConfig::startup();

  mutex = new_ProxyMutex();

  // start ResourceLocalManager on each ET_NET thread
  EventProcessor::ThreadGroupDescriptor *tg = &(eventProcessor.thread_group[0]);
  ink_release_assert(memcmp(tg->_name.data(), "ET_NET", 6) == 0);

  for (int i = 0; i < tg->_count; ++i) {
    EThread *ethread = tg->_thread[i];
    NetHandler *nh   = get_NetHandler(ethread);
    new (&nh->resource_local_manager) ResourceLocalManager();
    nh->resource_local_manager.start();
  }

  this->reconfigure(true);
}

void
ResourceManager::stop()
{
  // stop ResourceLocalManager on each ET_NET thread
  EventProcessor::ThreadGroupDescriptor *tg = &(eventProcessor.thread_group[0]);
  ink_release_assert(memcmp(tg->_name.data(), "ET_NET", 6) == 0);

  for (int i = 0; i < tg->_count; ++i) {
    EThread *ethread = tg->_thread[i];
    NetHandler *nh   = get_NetHandler(ethread);
    nh->resource_local_manager.stop();
  }

  mutex->free();
}

/**
   Called on startup or task thread
 */
void
ResourceManager::reconfigure(bool startup)
{
  Note("reconfigure Resource Manager");

  if (mutex == nullptr) {
    // don't reconfigure before start
    return;
  }

  SCOPED_MUTEX_LOCK(lock, mutex, this_ethread());

  Debug("resource", "manager=%p", this);

  {
    ResourceConfig::scoped_config resource_conf;

    if (resource_conf->sni.mode != ResourceConfigMode::DISABLED && _sni_stats.mutex == nullptr) {
      _sni_stats.init(mutex, TLSHandshakeResource::prefix, resource_conf->stats_size);
    }

    if (resource_conf->active_q.mode != ResourceConfigMode::DISABLED && _active_q_stats.mutex == nullptr) {
      _active_q_stats.init(mutex, ActiveQResource::prefix, resource_conf->stats_size);
    }

    if (resource_conf->disk_read.mode != ResourceConfigMode::DISABLED && _disk_read_stats.mutex == nullptr) {
      _disk_read_stats.init(mutex, DiskReadResource::prefix, resource_conf->stats_size);
    }

    if (resource_conf->disk_write.mode != ResourceConfigMode::DISABLED && _disk_write_stats.mutex == nullptr) {
      _disk_write_stats.init(mutex, DiskWriteResource::prefix, resource_conf->stats_size);
    }
  }

  // setup stats for "unknown"
  _sni_stats.add(UNKNOWN_TID, UNKNOWN_TAG);
  _active_q_stats.add(UNKNOWN_TID, UNKNOWN_TAG);
  _disk_read_stats.add(UNKNOWN_TID, UNKNOWN_TAG);
  _disk_write_stats.add(UNKNOWN_TID, UNKNOWN_TAG);

  // setup stats from sni.yaml
  {
    SNIConfig::scoped_config sni_conf;
    for (const auto &item : sni_conf->yaml_sni.items) {
      if (!item.tag.empty()) {
        _add(item.tag);
      }
    }
  }

  // reconfigure ResourceLocalManager on each ET_NET thread
  EventProcessor::ThreadGroupDescriptor *tg = &(eventProcessor.thread_group[0]);
  ink_release_assert(memcmp(tg->_name.data(), "ET_NET", 6) == 0);

  for (int i = 0; i < tg->_count; ++i) {
    EThread *ethread = tg->_thread[i];
    NetHandler *nh   = get_NetHandler(ethread);
    if (startup) {
      SCOPED_MUTEX_LOCK(lock, nh->resource_local_manager.mutex, this_ethread());
      nh->resource_local_manager.reconfigure();
    } else {
      if (nh->resource_local_manager.handler == &ResourceLocalManager::state_running) {
        ethread->schedule_imm_local(&nh->resource_local_manager);
      } else {
        Warning("Resource Local Manager is not running yet. Retry later");
      }
    }
  }
}

void
ResourceManager::_add(std::string_view name)
{
  _sni_stats.add(name);
  _active_q_stats.add(name);
  _disk_read_stats.add(name);
  _disk_write_stats.add(name);
}

void
ResourceManager::set_sum(ResourceType stats_type, uint64_t tag_id, ResourceStatsType index, uint64_t value)
{
  switch (static_cast<int>(stats_type)) {
  case static_cast<int>(ResourceType::SNI): {
    _sni_stats.set_sum(tag_id, index, value);
    break;
  }
  case static_cast<int>(ResourceType::ACTIVE_Q): {
    _active_q_stats.set_sum(tag_id, index, value);
    break;
  }
  case static_cast<int>(ResourceType::DISK_READ): {
    _disk_read_stats.set_sum(tag_id, index, value);
    break;
  }
  case static_cast<int>(ResourceType::DISK_WRITE): {
    _disk_write_stats.set_sum(tag_id, index, value);
    break;
  }
  default:
    ink_abort("unsupported stats type");
  }
}

void
ResourceManager::set_sum(ResourceType stats_type, ResourceStatsType index, uint64_t value)
{
  switch (static_cast<int>(stats_type)) {
  case static_cast<int>(ResourceType::SNI): {
    _sni_stats.set_sum(index, value);
    break;
  }
  case static_cast<int>(ResourceType::ACTIVE_Q): {
    _active_q_stats.set_sum(index, value);
    break;
  }
  case static_cast<int>(ResourceType::DISK_READ): {
    _disk_read_stats.set_sum(index, value);
    break;
  }
  case static_cast<int>(ResourceType::DISK_WRITE): {
    _disk_write_stats.set_sum(index, value);
    break;
  }
  default:
    ink_abort("unsupported stats type");
  }
}

void
ResourceManager::increment(ResourceType stats_type, uint64_t tag_id, ResourceStatsType index, uint64_t value)
{
  switch (static_cast<int>(stats_type)) {
  case static_cast<int>(ResourceType::SNI): {
    _sni_stats.increment(tag_id, index, value);
    break;
  }
  case static_cast<int>(ResourceType::ACTIVE_Q): {
    _active_q_stats.increment(tag_id, index, value);
    break;
  }
  case static_cast<int>(ResourceType::DISK_READ): {
    _disk_read_stats.increment(tag_id, index, value);
    break;
  }
  case static_cast<int>(ResourceType::DISK_WRITE): {
    _disk_write_stats.increment(tag_id, index, value);
    break;
  }
  default:
    ink_abort("unsupported stats type");
  }
}

void
ResourceManager::increment(ResourceType stats_type, ResourceStatsType index, uint64_t value)
{
  switch (static_cast<int>(stats_type)) {
  case static_cast<int>(ResourceType::SNI): {
    _sni_stats.increment(index, value);
    break;
  }
  case static_cast<int>(ResourceType::ACTIVE_Q): {
    _active_q_stats.increment(index, value);
    break;
  }
  case static_cast<int>(ResourceType::DISK_READ): {
    _disk_read_stats.increment(index, value);
    break;
  }
  case static_cast<int>(ResourceType::DISK_WRITE): {
    _disk_write_stats.increment(index, value);
    break;
  }
  default:
    ink_abort("unsupported stats type");
  }
}

void
ResourceManager::clear(ResourceType stats_type)
{
  switch (static_cast<int>(stats_type)) {
  case static_cast<int>(ResourceType::SNI): {
    _sni_stats.clear();
    break;
  }
  case static_cast<int>(ResourceType::ACTIVE_Q): {
    _active_q_stats.clear();
    break;
  }
  case static_cast<int>(ResourceType::DISK_READ): {
    _disk_read_stats.clear();
    break;
  }
  case static_cast<int>(ResourceType::DISK_WRITE): {
    _disk_write_stats.clear();
    break;
  }
  default:
    ink_abort("unsupported stats type");
  }
}
