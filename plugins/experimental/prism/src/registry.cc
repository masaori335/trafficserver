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

#include "registry.h"

#include <utility>

namespace hrw4u
{
namespace
{
  bool
  known_type(hrw4u_type type)
  {
    return type == HRW4U_TYPE_BOOL || type == HRW4U_TYPE_SVIEW || type == HRW4U_TYPE_I64;
  }
} // namespace

Registry::Registry(std::function<void(std::string_view)> log)
  : _log(std::move(log)), _api{HRW4U_EXT_ABI_VERSION, this, &Registry::def, &Registry::log}
{
}

bool
Registry::add(const hrw4u_fn_decl &decl, std::string &error)
{
  if (decl.name == nullptr || decl.fn == nullptr) {
    error = "a declaration without a name or a function";
    return false;
  }

  std::string name = decl.name;

  if (_entries.contains(name)) {
    error = name + ": already registered";
    return false;
  }
  if (decl.nparams > MAX_EXT_PARAMS || (decl.nparams > 0 && decl.params == nullptr)) {
    error = name + ": bad parameter list";
    return false;
  }

  Entry entry{
    name,
    decl.ret,
    {decl.params, decl.params + decl.nparams},
    decl.effect,
    decl.fn
  };

  if (!known_type(entry.ret)) {
    error = name + ": unknown return type";
    return false;
  }
  for (hrw4u_type type : entry.params) {
    if (!known_type(type)) {
      error = name + ": unknown parameter type";
      return false;
    }
  }
  _entries.emplace(name, std::move(entry));
  return true;
}

const Registry::Entry *
Registry::find(std::string_view name) const
{
  auto it = _entries.find(name);

  if (it == _entries.end()) {
    return nullptr;
  }
  return &it->second;
}

int
Registry::def(void *instance, const hrw4u_fn_decl *decl)
{
  auto       *self = static_cast<Registry *>(instance);
  std::string error;

  if (decl == nullptr || !self->add(*decl, error)) {
    self->_log(error);
    return 1;
  }
  return 0;
}

void
Registry::log(void *instance, const char *message)
{
  static_cast<Registry *>(instance)->_log(message);
}
} // namespace hrw4u
