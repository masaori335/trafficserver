/** @file

  A Plugin to trigger HTTP/2 Server Push by 103 Early Hints

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

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "ts/ts.h"
#include "ts/experimental.h"

const char *PLUGIN_NAME = "early-hints";
const char *LINK = "LINK";

bool
is_early_hints(TSHttpTxn txnp)
{
  TSMBuffer mbuf;
  TSMLoc hdr;
  if (TSHttpTxnServerRespGet(txnp, &mbuf, &hdr) != TS_SUCCESS) {
    return false;
  }

  /* NOTE: Should TSHttpHdrStatusGet return TSReturnCode ? */
  return TSHttpHdrStatusGet(mbuf, hdr) == TS_HTTP_STATUS_EARLY_HINTS;
}

bool
parse_link_header(uri)
{
  return true;
}

bool
get_link_headers(TSHttpTxn txnp)
{
  TSMBuffer mbuf;
  TSMLoc hdr_loc;
  if (TSHttpTxnServerRespGet(txnp, &mbuf, &hdr_loc) != TS_SUCCESS) {
    return false;
  }

  // Find LINK Headers
  TSMLoc field_loc;
  field_loc = TSMimeHdrFieldFind(mbuf, hdr_loc, LINK, strlen(LINK));
  if (TS_NULL_MLOC == field_loc) {
    TSError("[%s] Can't find LINK Header", PLUGIN_NAME);

    /* TSHandleMLocRelease(mbuf, TS_NULL_MLOC, resp_loc); */
    /* TSHandleMLocRelease(cached_bufp, TS_NULL_MLOC, cached_loc); */
    return false;
  }

  // Get Value of LINK Header
  TSMBuffer value_buf;
  ptr;
  ptr = TSMimeHdrFieldValueStringGet(value_buf, hdr_loc, field_loc, -1, &length);
  if (NULL == ptr) {
    TSError("[%s] Can't get LINK Header value", PLUGIN_NAME);
    return false;
  }

  return true;
}


static int
early_hints_plugin(TSCont contp, TSEvent event, void *edata)
{
  /* TSHttpSsn ssnp; */
  TSHttpTxn txnp;

  switch (event) {
  /* case TS_EVENT_HTTP_SSN_START: */
  /*   ssnp = (TSHttpSsn)edata; */
  /*   TSHttpSsnHookAdd(ssnp, TS_HTTP_TXN_START_HOOK, contp); */
  /*   TSHttpSsnReenable(ssnp, TS_EVENT_HTTP_CONTINUE); */
  /*   break; */
  /* case TS_EVENT_HTTP_TXN_START: */
  /*   txnp = (TSHttpTxn)edata; */
  /*   TSHttpTxnHookAdd(txnp, TS_HTTP_READ_REQUEST_HDR_HOOK, contp); */
  /*   TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE); */
  /*   break; */
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    txnp = (TSHttpTxn)edata;

    if (is_early_hints(txnp)) {
      // parse & support multiple LINK headerso
      char *url = "https://mkoshiba02.img.ssk.ynwm.yahoo.co.jp:4443/http2rulez/public/assets/css/bootstrap.css";
      TSHttpTxnServerPush(txnp, url, strlen(url));
      TSHttpTxnReenable(txnp, TS_EVENT_HTTP_READ_REQUEST_HDR);
    } else {
      TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    }
    break;
  default:
    break;
  }

  return 0;
}

void
TSPluginInit(int argc /* ATS_UNUSED */, const char *argv[] /* ATS_UNUSED */)
{
  TSPluginRegistrationInfo info;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "MyCompany";
  info.support_email = "ts-api-support@MyCompany.com";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] Plugin registration failed", PLUGIN_NAME);
  }

  TSCont handler = TSContCreate(early_hints_plugin, NULL);
  if (handler) {
    TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, handler);
  } else {
    TSError("[%s] Could not create continuation", PLUGIN_NAME);
  }
}
