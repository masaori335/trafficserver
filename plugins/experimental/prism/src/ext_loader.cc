/** @file

  Loads an extension .so and keeps it loaded for as long as the instance that loaded it.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
  agreements.  See the NOTICE file distributed with this work for additional information regarding
  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with the License.  You may obtain
  a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed under the License
  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
  or implied. See the License for the specific language governing permissions and limitations under
  the License.
*/

#include "ext_loader.h"

#include <dlfcn.h>

namespace hrw4u
{
namespace
{
  using InitFn = int (*)(const hrw4u_host_api *);
  using FiniFn = void (*)(const hrw4u_host_api *);

  std::unique_ptr<LoadedExtension>
  refuse(void *handle, std::string &error, std::string what)
  {
    error = std::move(what);
    dlclose(handle);
    return nullptr;
  }
} // namespace

std::unique_ptr<LoadedExtension>
LoadedExtension::load(const std::string &path, const hrw4u_host_api *api, std::string &error)
{
  // RTLD_LOCAL: two extensions may define the same symbol names without seeing each other's.
  void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);

  if (handle == nullptr) {
    error = path + ": " + dlerror();
    return nullptr;
  }

  auto *version = static_cast<const uint32_t *>(dlsym(handle, HRW4U_EXT_ABI_SYMBOL));

  if (version == nullptr) {
    return refuse(handle, error, path + ": no " HRW4U_EXT_ABI_SYMBOL);
  }
  if (*version != HRW4U_EXT_ABI_VERSION) {
    return refuse(handle, error,
                  path + ": ABI version " + std::to_string(*version) + ", prism.so expects " +
                    std::to_string(HRW4U_EXT_ABI_VERSION));
  }

  auto init = reinterpret_cast<InitFn>(dlsym(handle, HRW4U_EXT_INIT_SYMBOL));

  if (init == nullptr) {
    return refuse(handle, error, path + ": no " HRW4U_EXT_INIT_SYMBOL);
  }
  if (init(api) != 0) {
    return refuse(handle, error, path + ": " HRW4U_EXT_INIT_SYMBOL " failed");
  }
  return std::unique_ptr<LoadedExtension>(new LoadedExtension(handle, api));
}

LoadedExtension::~LoadedExtension()
{
  auto fini = reinterpret_cast<FiniFn>(dlsym(_handle, HRW4U_EXT_FINI_SYMBOL));

  if (fini != nullptr) {
    fini(_api);
  }
  dlclose(_handle);
}
} // namespace hrw4u
