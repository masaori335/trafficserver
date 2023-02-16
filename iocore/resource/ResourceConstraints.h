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

#pragma once

#include "Resource.h"
#include "ResourceConfig.h"
#include "ResourceStats.h"

#include "ReactiveTokenBucket.h"

#include "tscore/BufferWriter.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

#include <variant>
#include <vector>

// Special tid for untracked property
static constexpr uint64_t UNKNOWN_TID         = 0;
static constexpr std::string_view UNKNOWN_TAG = "unknown";

// TLS Handshake
struct TLSHandshakeResource : public RTB::Counter {
  static const std::string_view prefix;
  static const ResourceType resource_type;
};

constexpr std::string_view TLSHandshakeResource::prefix    = "sni";
constexpr ResourceType TLSHandshakeResource::resource_type = ResourceType::SNI;

// Active Queue
struct ActiveQResource : public RTB::Counter {
  static const std::string_view prefix;
  static const ResourceType resource_type;
};

constexpr std::string_view ActiveQResource::prefix    = "active_q";
constexpr ResourceType ActiveQResource::resource_type = ResourceType::ACTIVE_Q;

// Disk Read
struct DiskReadResource : public RTB::Counter {
  static const std::string_view prefix;
  static const ResourceType resource_type;
};

constexpr std::string_view DiskReadResource::prefix    = "disk_read";
constexpr ResourceType DiskReadResource::resource_type = ResourceType::DISK_READ;

// Disk write
struct DiskWriteResource : public RTB::Counter {
  static const std::string_view prefix;
  static const ResourceType resource_type;
};

constexpr std::string_view DiskWriteResource::prefix    = "disk_write";
constexpr ResourceType DiskWriteResource::resource_type = ResourceType::DISK_WRITE;

//
// Limiter
//
using TLSHandshakeLimiterV0 = RTB::AlgorithmV0<TLSHandshakeResource>;
using TLSHandshakeLimiterV1 = RTB::AlgorithmV1<TLSHandshakeResource>;
using ActiveQLimiterV0      = RTB::AlgorithmV0<ActiveQResource>;
using ActiveQLimiterV1      = RTB::AlgorithmV1<ActiveQResource>;
using DiskReadLimiterV1     = RTB::AlgorithmV1<DiskReadResource>;
using DiskWriteLimiterV1    = RTB::AlgorithmV1<DiskWriteResource>;

using ResourceLimiter  = std::variant<TLSHandshakeLimiterV0, TLSHandshakeLimiterV1, ActiveQLimiterV0, ActiveQLimiterV1,
                                     DiskReadLimiterV1, DiskWriteLimiterV1>;
using ResourceLimiters = std::vector<ResourceLimiter>;

struct ResourceReport {
  void operator()(const TLSHandshakeLimiterV0 &limiter);
  void operator()(const TLSHandshakeLimiterV1 &limiter);
  void operator()(const ActiveQLimiterV0 &limiter);
  void operator()(const ActiveQLimiterV1 &limiter);
  void operator()(const DiskReadLimiterV1 &limiter);
  void operator()(const DiskWriteLimiterV1 &limiter);
};

/**
   Thread Local Resource Manager
 */
class ResourceLocalManager
{
public:
  ResourceLocalManager()  = default;
  ~ResourceLocalManager() = default;

  // No copying or moving
  ResourceLocalManager(const ResourceLocalManager &) = delete;
  ResourceLocalManager &operator=(const ResourceLocalManager &) = delete;
  ResourceLocalManager(ResourceLocalManager &&)                 = delete;
  ResourceLocalManager &operator=(ResourceLocalManager &&) = delete;

  void start();
  void stop();
  void reconfigure();

  bool is_full(uint64_t tid);
  bool is_full(uint64_t tid, ResourceType type);
  void inc(uint64_t tid, ResourceType type);
  void dec(uint64_t tid, ResourceType type);
  void reserve();

  ////
  // Variables
  //

  // For race of Task Thread (config reload) vs ET Thread
  Ptr<ProxyMutex> mutex;

private:
  void _reserve(ResourceLimiter *limiter);

  //
  // Variables
  //
  ResourceConfigMode _mode_sni        = ResourceConfigMode::DISABLED;
  ResourceConfigMode _mode_active_q   = ResourceConfigMode::DISABLED;
  ResourceConfigMode _mode_disk_read  = ResourceConfigMode::DISABLED;
  ResourceConfigMode _mode_disk_write = ResourceConfigMode::DISABLED;

  TLSHandshakeLimiterV1 *_sni_limiter     = nullptr;
  ActiveQLimiterV1 *_active_q_limiter     = nullptr;
  DiskReadLimiterV1 *_disk_read_limiter   = nullptr;
  DiskWriteLimiterV1 *_disk_write_limiter = nullptr;

  ResourceLimiters _limiters;

  std::unordered_map<uint64_t, std::string> _tid_map;
};
