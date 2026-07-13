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
#include "mgmt/config/ConfigRegistry.h"

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
  // RECU_DYNAMIC
  config::ConfigRegistry::Get_Instance().register_record_config(
    "resource", [](ConfigContext ctx) { ResourceConfig::reconfigure(ctx); },
    {"proxy.config.resource.top_n", "proxy.config.resource.sni.limit", "proxy.config.resource.sni.mode",
     "proxy.config.resource.sni.penalty_duration", "proxy.config.resource.sni.red_zone"});

  reconfigure();
}

void
ResourceConfig::reconfigure(ConfigContext ctx)
{
  ResourceConfigParams *params = new ResourceConfigParams();
  _config_id                   = configProcessor.set(_config_id, params);

  ctx.complete("Resource config published");
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
