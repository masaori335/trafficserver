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

#include "iocore/resource/ResourceConfig.h"
#include "iocore/resource/ResourceConstraints.h"
#include "iocore/resource/ResourceManager.h"
#include "records/RecCore.h"

////
// ResourceConfigParams
//
ResourceConfigParams::ResourceConfigParams()
{
  // RECU_RESTART_TS
  this->stats_size = RecGetRecordInt("proxy.config.resource.max_stats_size").value_or(0);

  // RECU_DYNAMIC
  this->top_n = RecGetRecordInt("proxy.config.resource.top_n").value_or(0);

  // sni
  int32_t sni_mode           = RecGetRecordInt("proxy.config.resource.sni.mode").value_or(0);
  this->sni.mode             = static_cast<ResourceConfigMode>(sni_mode);
  this->sni.limit            = RecGetRecordInt("proxy.config.resource.sni.limit").value_or(0);
  this->sni.penalty_duration = RecGetRecordInt("proxy.config.resource.sni.penalty_duration").value_or(0);
  this->sni.red_zone         = RecGetRecordFloat("proxy.config.resource.sni.red_zone").value_or(0.0);

  // NOTE: add other resources here
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
