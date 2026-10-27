/** @file

  Exercise TSHttpSchedule() and TSActionCancel() on the resulting action.

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

/*
 * At TS_HTTP_READ_REQUEST_HDR_HOOK the plugin fills every transaction user
 * argument slot it can reserve with a sentinel and then, depending on the
 * request path:
 *
 *   /cancel/...  TSHttpSchedule() with a long timeout, TSActionCancel() the
 *                returned action, TSContDestroy() the continuation, and
 *                reenable the transaction.
 *   /fire/...    TSHttpSchedule() with no timeout and reenable the transaction
 *                from the scheduled callback.
 *
 * Afterwards it checks that the sentinels survived and reports the outcome to
 * the origin in the X-Http-Schedule request header. The transaction user
 * arguments live inside the HttpSM, so they detect any stray write into it.
 */

#include <ts/ts.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace
{
constexpr char PLUGIN_NAME[]   = "test_TSHttpSchedule";
constexpr char RESULT_HEADER[] = "X-Http-Schedule";

DbgCtl dbg_ctl{PLUGIN_NAME};

constexpr TSHRTime  CANCEL_TIMEOUT_MS = 60 * 1000;
constexpr uintptr_t SENTINEL_BASE     = 0x5eed0000;

std::array<int, 16> arg_indices;
int                 arg_count = 0;

void *
sentinel(int slot)
{
  return reinterpret_cast<void *>(SENTINEL_BASE + slot);
}

void
fill_user_args(TSHttpTxn txnp)
{
  for (int slot = 0; slot < arg_count; ++slot) {
    TSUserArgSet(txnp, arg_indices[slot], sentinel(slot));
  }
}

bool
user_args_intact(TSHttpTxn txnp)
{
  bool intact = true;

  for (int slot = 0; slot < arg_count; ++slot) {
    void *value = TSUserArgGet(txnp, arg_indices[slot]);
    if (value != sentinel(slot)) {
      TSError("[%s] transaction user arg %d corrupted: expected %p, got %p", PLUGIN_NAME, arg_indices[slot], sentinel(slot), value);
      intact = false;
    }
  }
  return intact;
}

void
set_result_header(TSHttpTxn txnp, std::string_view result)
{
  TSMBuffer bufp;
  TSMLoc    hdr_loc;

  if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    TSError("[%s] could not get the client request", PLUGIN_NAME);
    return;
  }

  TSMLoc field_loc;
  if (TSMimeHdrFieldCreateNamed(bufp, hdr_loc, RESULT_HEADER, sizeof(RESULT_HEADER) - 1, &field_loc) == TS_SUCCESS) {
    TSMimeHdrFieldValueStringSet(bufp, hdr_loc, field_loc, -1, result.data(), static_cast<int>(result.size()));
    TSMimeHdrFieldAppend(bufp, hdr_loc, field_loc);
    TSHandleMLocRelease(bufp, hdr_loc, field_loc);
  }
  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
}

void
report_and_reenable(TSHttpTxn txnp, std::string_view scenario)
{
  std::string result{scenario};

  result += user_args_intact(txnp) ? "-intact" : "-corrupted";
  Dbg(dbg_ctl, "%s", result.c_str());
  set_result_header(txnp, result);
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
}

int
handle_scheduled(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(TSContDataGet(contp));

  Dbg(dbg_ctl, "scheduled callback with event %d", event);
  if (edata != txnp) {
    TSError("[%s] scheduled callback edata %p is not the transaction %p", PLUGIN_NAME, edata, txnp);
  }
  TSContDestroy(contp);
  report_and_reenable(txnp, "fire");
  return 0;
}

std::string
request_path(TSHttpTxn txnp)
{
  TSMBuffer bufp;
  TSMLoc    hdr_loc;
  TSMLoc    url_loc;
  int       path_len = 0;

  std::string path;
  if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    return path;
  }
  if (TSHttpHdrUrlGet(bufp, hdr_loc, &url_loc) == TS_SUCCESS) {
    if (char const *p = TSUrlPathGet(bufp, url_loc, &path_len); p != nullptr) {
      path.assign(p, path_len);
    }
    TSHandleMLocRelease(bufp, hdr_loc, url_loc);
  }
  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
  return path;
}

int
handle_read_request(TSCont /* contp ATS_UNUSED */, TSEvent /* event ATS_UNUSED */, void *edata)
{
  TSHttpTxn   txnp = static_cast<TSHttpTxn>(edata);
  std::string path = request_path(txnp);

  fill_user_args(txnp);

  TSCont contp = TSContCreate(handle_scheduled, TSMutexCreate());
  TSContDataSet(contp, txnp);

  if (path.starts_with("cancel")) {
    TSAction action = TSHttpSchedule(contp, txnp, CANCEL_TIMEOUT_MS);
    TSActionCancel(action);
    TSContDestroy(contp);
    report_and_reenable(txnp, "cancel");
  } else if (path.starts_with("fire")) {
    TSHttpSchedule(contp, txnp, 0);
  } else {
    TSContDestroy(contp);
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  }
  return 0;
}

} // namespace

void
TSPluginInit(int /* argc ATS_UNUSED */, char const ** /* argv ATS_UNUSED */)
{
  TSPluginRegistrationInfo info;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] plugin registration failed", PLUGIN_NAME);
    return;
  }

  // Claim every transaction user argument slot so a stray write anywhere in
  // the HttpSM's user argument array is noticed.
  for (auto &index : arg_indices) {
    std::string name = std::string{PLUGIN_NAME} + "." + std::to_string(arg_count);
    if (TSUserArgIndexReserve(TS_USER_ARGS_TXN, name.c_str(), "sentinel", &index) != TS_SUCCESS) {
      break;
    }
    ++arg_count;
  }
  Dbg(dbg_ctl, "reserved %d transaction user args", arg_count);

  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, TSContCreate(handle_read_request, nullptr));
}
