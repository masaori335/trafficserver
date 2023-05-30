/** @file

  Stub file for linking libinknet.a from unit tests

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

class EThread;
class Continuation;
void
initialize_thread_for_http_sessions(EThread *, int)
{
}

#include "P_UnixNet.h"
#include "P_DNSConnection.h"
int
DNSConnection::close()
{
  ink_assert(false);
  return 0;
}

void
DNSConnection::trigger()
{
  ink_assert(false);
}

#include "StatPages.h"
void
StatPagesManager::register_http(char const *, Action *(*)(Continuation *, HTTPHdr *))
{
  ink_assert(false);
}

#include "ParentSelection.h"
void
SocksServerConfig::startup()
{
  ink_assert(false);
}

int SocksServerConfig::m_id = 0;

void
ParentConfigParams::findParent(HttpRequestData *, ParentResult *, unsigned int, unsigned int)
{
  ink_assert(false);
}

void
ParentConfigParams::nextParent(HttpRequestData *, ParentResult *, unsigned int, unsigned int)
{
  ink_assert(false);
}

#include "Log.h"
void
Log::trace_in(sockaddr const *, unsigned short, char const *, ...)
{
  ink_assert(false);
}

void
Log::trace_out(sockaddr const *, unsigned short, char const *, ...)
{
  ink_assert(false);
}

#include "InkAPIInternal.h"
int
APIHook::invoke(int, void *) const
{
  ink_assert(false);
  return 0;
}

int
APIHook::blocking_invoke(int, void *) const
{
  ink_assert(false);
  return 0;
}

APIHook *
APIHook::next() const
{
  ink_assert(false);
  return nullptr;
}

APIHook *
APIHook::prev() const
{
  ink_assert(false);
  return nullptr;
}

APIHook *
APIHooks::head() const
{
  ink_assert(false);
  return nullptr;
}

void
ConfigUpdateCbTable::invoke(const char * /* name ATS_UNUSED */)
{
  ink_release_assert(false);
}

#include "ControlMatcher.h"
char *
HttpRequestData::get_string()
{
  ink_assert(false);
  return nullptr;
}

const char *
HttpRequestData::get_host()
{
  ink_assert(false);
  return nullptr;
}

sockaddr const *
HttpRequestData::get_ip()
{
  ink_assert(false);
  return nullptr;
}

sockaddr const *
HttpRequestData::get_client_ip()
{
  ink_assert(false);
  return nullptr;
}

SslAPIHooks *ssl_hooks             = nullptr;
LifecycleAPIHooks *lifecycle_hooks = nullptr;
StatPagesManager statPagesManager;

#include "ProcessManager.h"
ProcessManager *pmgmt = nullptr;

int
BaseManager::registerMgmtCallback(int, MgmtCallback const &)
{
  ink_assert(false);
  return 0;
}

void
ProcessManager::signalManager(int, char const *, int)
{
  ink_assert(false);
  return;
}

void
ProcessManager::signalManager(int, char const *)
{
  ink_assert(false);
  return;
}

#include "PreWarmManager.h"
void
PreWarmManager::reconfigure()
{
  ink_assert(false);
  return;
}

PreWarmManager prewarmManager;

#include "ResourceManager.h"
void
ResourceManager::reconfigure(bool startup)
{
  ink_assert(false);
  return;
}

ResourceManager resourceManager;

#include "ResourceConstraints.h"
ResourceLocalManager::ResourceLocalManager() : Continuation(nullptr)
{
  ink_assert(false);
  return;
}

ResourceLocalManager::~ResourceLocalManager()
{
  ink_assert(false);
  return;
}

void
ResourceLocalManager::inc(uint64_t tid, ResourceType type)
{
  ink_assert(false);
  return;
}

void
ResourceLocalManager::dec(uint64_t tid, ResourceType type)
{
  ink_assert(false);
  return;
}

bool
ResourceLocalManager::is_full(uint64_t tid, ResourceType type)
{
  ink_assert(false);
  return false;
}

void
ResourceLocalManager::reserve()
{
  ink_assert(false);
  return;
}

#include "Resource.h"

uint32_t
ResourceConstraints::hash(std::string_view name)
{
  ink_assert(false);
  return 0;
}

#include "../src/traffic_server/FetchSM.h"
ClassAllocator<FetchSM> FetchSMAllocator("unusedFetchSMAllocator");
void
FetchSM::ext_launch()
{
}
void
FetchSM::ext_destroy()
{
}
ssize_t
FetchSM::ext_read_data(char *, unsigned long)
{
  return 0;
}
void
FetchSM::ext_add_header(char const *, int, char const *, int)
{
}
void
FetchSM::ext_write_data(void const *, unsigned long)
{
}
void *
FetchSM::ext_get_user_data()
{
  return nullptr;
}
void
FetchSM::ext_set_user_data(void *)
{
}
void
FetchSM::ext_init(Continuation *, char const *, char const *, char const *, sockaddr const *, int)
{
}

ChunkedHandler::ChunkedHandler() {}
