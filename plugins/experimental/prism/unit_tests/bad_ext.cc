/** @file

  A broken extension for the loader tests: built twice, once exporting the wrong ABI version
  (BAD_EXT_WRONG_ABI) and once without hrw4u_ext_init (BAD_EXT_NO_INIT).

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

#include "hrw4u/extension.h"

#define EXPORT __attribute__((visibility("default")))

#ifdef BAD_EXT_WRONG_ABI
extern "C" EXPORT const uint32_t hrw4u_ext_abi_version = HRW4U_EXT_ABI_VERSION + 1;
#else
extern "C" EXPORT const uint32_t hrw4u_ext_abi_version = HRW4U_EXT_ABI_VERSION;
#endif

#ifndef BAD_EXT_NO_INIT
extern "C" EXPORT int
hrw4u_ext_init(const hrw4u_host_api *)
{
  return 0;
}
#endif
