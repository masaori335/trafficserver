/** @file

  The functions a prism instance can call by name, and the host API extensions register through.

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

#pragma once

#include "hrw4u/extension.h"

#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace hrw4u
{
/// Bounds the argument words a call packs on the stack.
constexpr size_t MAX_EXT_PARAMS = 8;

/// One per instance, so two remap rules never see each other's extensions.
class Registry
{
public:
  struct Entry {
    std::string             name;
    hrw4u_type              ret;
    std::vector<hrw4u_type> params;
    hrw4u_effect            effect;
    hrw4u_fn                fn;
  };

  explicit Registry(std::function<void(std::string_view)> log);
  Registry(const Registry &)            = delete;
  Registry &operator=(const Registry &) = delete;

  bool         add(const hrw4u_fn_decl &decl, std::string &error);
  const Entry *find(std::string_view name) const;

  /// Refuse every later name under @a prefix, so a name there tells its provider.
  void reserve(std::string_view prefix);

  /// Valid while this registry lives: it points back at it.
  const hrw4u_host_api *
  host_api() const
  {
    return &_api;
  }

private:
  static int  def(void *instance, const hrw4u_fn_decl *decl);
  static void log(void *instance, const char *message);

  std::function<void(std::string_view)>     _log;
  std::map<std::string, Entry, std::less<>> _entries;
  std::string                               _reserved;
  hrw4u_host_api                            _api;
};
} // namespace hrw4u
