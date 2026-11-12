/** @file

  The functions prism.so gives the IR by names under prism::, whether each calls Cripts or is prism's own.

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

namespace hrw4u
{
/// Registered before any extension loads, so an extension cannot take one of these names. False when one is refused.
bool def_cripts_bindings(const hrw4u_host_api *api);
} // namespace hrw4u
