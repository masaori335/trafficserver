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

#pragma once

#include "hrw4u/extension.h"

#include <memory>
#include <string>

namespace hrw4u
{
class LoadedExtension
{
public:
  /// On failure, @a error names @a path. @a api must outlive the returned object: fini is called with it.
  static std::unique_ptr<LoadedExtension> load(const std::string &path, const hrw4u_host_api *api, std::string &error);

  ~LoadedExtension();
  LoadedExtension(const LoadedExtension &)            = delete;
  LoadedExtension &operator=(const LoadedExtension &) = delete;

private:
  LoadedExtension(void *handle, const hrw4u_host_api *api) : _handle(handle), _api(api) {}

  void                 *_handle;
  const hrw4u_host_api *_api;
};
} // namespace hrw4u
