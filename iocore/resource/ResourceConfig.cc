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

#include "ResourceConfig.h"
#include "ResourceConstraints.h"
#include "ResourceManager.h"

////
// ResourceConfigParams
//
ResourceConfigParams::ResourceConfigParams()
{
  // RECU_RESTART_TS
  REC_ReadConfigInteger(this->stats_size, "proxy.config.resource.max_stats_size");

  // RECU_DYNAMIC
  // TODO: check the naming convention
  REC_ReadConfigInteger(this->top_n, "proxy.config.resource.top_n");

  // sni
  int32_t sni_mode;
  REC_ReadConfigInteger(sni_mode, "proxy.config.resource.sni.mode");
  this->sni.mode = static_cast<ResourceConfigMode>(sni_mode);
  REC_ReadConfigInteger(this->sni.limit, "proxy.config.resource.sni.limit");
  REC_ReadConfigInteger(this->sni.penalty_duration, "proxy.config.resource.sni.penalty_duration");
  REC_ReadConfigFloat(this->sni.red_zone, "proxy.config.resource.sni.red_zone");

  // active_q
  int32_t active_q_mode;
  REC_ReadConfigInteger(active_q_mode, "proxy.config.resource.active_q.mode");
  this->active_q.mode = static_cast<ResourceConfigMode>(active_q_mode);
  REC_ReadConfigInteger(this->active_q.limit, "proxy.config.resource.active_q.limit");
  REC_ReadConfigInteger(this->active_q.penalty_duration, "proxy.config.resource.active_q.penalty_duration");
  REC_ReadConfigFloat(this->active_q.red_zone, "proxy.config.resource.active_q.red_zone");
  this->active_q.queue = true;

  // disk_read
  int32_t disk_read_mode;
  REC_ReadConfigInteger(disk_read_mode, "proxy.config.resource.disk_read.mode");
  this->disk_read.mode = static_cast<ResourceConfigMode>(disk_read_mode);
  REC_ReadConfigInteger(this->disk_read.limit, "proxy.config.resource.disk_read.limit");
  REC_ReadConfigInteger(this->disk_read.penalty_duration, "proxy.config.resource.disk_read.penalty_duration");
  REC_ReadConfigFloat(this->disk_read.red_zone, "proxy.config.resource.disk_read.red_zone");

  // disk_write
  int32_t disk_write_mode;
  REC_ReadConfigInteger(disk_write_mode, "proxy.config.resource.disk_write.mode");
  this->disk_write.mode = static_cast<ResourceConfigMode>(disk_write_mode);
  REC_ReadConfigInteger(this->disk_write.limit, "proxy.config.resource.disk_write.limit");
  REC_ReadConfigInteger(this->disk_write.penalty_duration, "proxy.config.resource.disk_write.penalty_duration");
  REC_ReadConfigFloat(this->disk_write.red_zone, "proxy.config.resource.disk_write.red_zone");
}

////
// ResourceConfig
//
void
ResourceConfig::startup()
{
  _config_update_handler = std::make_unique<ConfigUpdateHandler<ResourceConfig>>();

  // RECU_DYNAMIC
  _config_update_handler->attach("proxy.config.resource.top_n");

  _config_update_handler->attach("proxy.config.resource.sni.limit");
  _config_update_handler->attach("proxy.config.resource.sni.mode");
  _config_update_handler->attach("proxy.config.resource.sni.penalty_duration");
  _config_update_handler->attach("proxy.config.resource.sni.red_zone");

  _config_update_handler->attach("proxy.config.resource.active_q.limit");
  _config_update_handler->attach("proxy.config.resource.active_q.mode");
  _config_update_handler->attach("proxy.config.resource.active_q.penalty_duration");
  _config_update_handler->attach("proxy.config.resource.active_q.red_zone");

  _config_update_handler->attach("proxy.config.resource.disk_read.limit");
  _config_update_handler->attach("proxy.config.resource.disk_read.mode");
  _config_update_handler->attach("proxy.config.resource.disk_read.penalty_duration");
  _config_update_handler->attach("proxy.config.resource.disk_read.red_zone");

  _config_update_handler->attach("proxy.config.resource.disk_write.limit");
  _config_update_handler->attach("proxy.config.resource.disk_write.mode");
  _config_update_handler->attach("proxy.config.resource.disk_write.penalty_duration");
  _config_update_handler->attach("proxy.config.resource.disk_write.red_zone");

  reconfigure();
}

void
ResourceConfig::reconfigure()
{
  ResourceConfigParams *params = new ResourceConfigParams();
  _config_id                   = configProcessor.set(_config_id, params);
}

ResourceConfigParams *
ResourceConfig::acquire()
{
  return static_cast<ResourceConfigParams *>(configProcessor.get(_config_id));
}

void
ResourceConfig::release(ResourceConfigParams *params)
{
  configProcessor.release(_config_id, params);
}
