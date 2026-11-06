/** @file

  Runs the prism tests' programs on a Cripts test transaction.

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

// Before the Cripts headers, which define instance as a macro.
#include "cripts_bridge.h"
#include "interp.h"

#include "CriptsTestTxn.h"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

using Calls = std::vector<std::pair<std::string, std::string>>;

inline Calls &
recorded_calls()
{
  static Calls calls;

  return calls;
}

/// T::SetHeader: unlike a header builtin, it runs in any hook and records an empty value too.
inline bool
set_header(hrw4u_rule_ctx *, std::string_view name, std::string_view value)
{
  recorded_calls().emplace_back(name, value);
  return true;
}

// The hook the Epilogue enters before it runs a cript's code for @a hook; do_remap() runs in READ_REQUEST's.
inline TSHttpHookID
cripts_hook(hrw4u::Hook hook)
{
  using hrw4u::Hook;

  switch (hook) {
  case Hook::TxnStart:
    return TS_HTTP_TXN_START_HOOK;
  case Hook::PreRemap:
    return TS_HTTP_PRE_REMAP_HOOK;
  case Hook::SendRequest:
    return TS_HTTP_SEND_REQUEST_HDR_HOOK;
  case Hook::ReadResponse:
    return TS_HTTP_READ_RESPONSE_HDR_HOOK;
  case Hook::SendResponse:
    return TS_HTTP_SEND_RESPONSE_HDR_HOOK;
  case Hook::TxnClose:
    return TS_HTTP_TXN_CLOSE_HOOK;
  case Hook::ReadRequest:
  case Hook::Remap:
    break;
  }
  return TS_HTTP_READ_REQUEST_HDR_HOOK;
}

/// Does not leave the hook, which would reenable a transaction that is not running.
inline bool
run_on(cripts_test::Txn &txn, const hrw4u::Program &prog, hrw4u::Hook hook, std::string &fault, swoc::MemSpan<uint64_t> vars = {})
{
  cripts::Context      *ctx = txn.context();
  const hrw4u::Section *sec = prog.find(hook);

  REQUIRE(sec != nullptr);
  recorded_calls().clear();
  ctx->reset();
  ctx->state.hook = cripts_hook(hook);

  hrw4u::CriptsBridge ops;

  return hrw4u::run(prog, *sec, ops, fault, vars);
}
