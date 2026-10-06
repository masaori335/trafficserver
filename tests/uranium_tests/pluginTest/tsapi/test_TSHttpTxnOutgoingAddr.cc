/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Test plugin for the per-transaction outbound address override lifetime.
 *
 * On a request carrying the trigger header, it pins the outbound (source)
 * port for that transaction via TSHttpTxnOutgoingAddrSet.  On every request it
 * logs the effective bound outbound port (read back from the established
 * upstream connection via TSHttpTxnOutgoingAddrGet).  A keep-alive client that
 * sends one triggering request followed by a plain request can then observe
 * whether the override incorrectly persists onto the later transaction that
 * shares the same client session.
 *
 * Every log line also carries the client session's transaction count, which is
 * what proves the two requests really did share one session.  Without it the
 * port comparison is unanchored: two separate client sessions cannot leak, so
 * the ports would differ and the test would pass having demonstrated nothing.
 */

#include <ts/ts.h>

#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdlib>
#include <string_view>

namespace
{

constexpr std::string_view PNAME = "test_outbound_addr";

DbgCtl dbg_ctl{PNAME.data()};

// Request header that asks the plugin to pin the outbound source port for that
// single transaction.
constexpr std::string_view UUID_HEADER    = "uuid";
constexpr std::string_view TRIGGER_HEADER = "X-Set-Outbound";

// Distinctive source port pinned on the triggering request.  If it leaks onto a
// later request on the same session it is trivially recognizable in the log.
int g_pinned_port = 0;

bool
request_has_trigger(TSHttpTxn txnp)
{
  TSMBuffer bufp;
  TSMLoc    hdr_loc;
  if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    return false;
  }
  bool   found     = false;
  TSMLoc field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, TRIGGER_HEADER.data(), static_cast<int>(TRIGGER_HEADER.size()));
  if (field_loc != TS_NULL_MLOC) {
    found = true;
    TSHandleMLocRelease(bufp, hdr_loc, field_loc);
  }
  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
  return found;
}

/** Copy the request's uuid header into @a buf, returning false when absent.

    The replay tags each transaction (first-request, second-request). Without it the
    checker can only index log lines by position, and a retried upstream connect emits
    a second line for the SAME transaction, so position stops meaning transaction.
 */
bool
request_uuid(TSHttpTxn txnp, char *buf, size_t cap)
{
  TSMBuffer bufp;
  TSMLoc    hdr_loc;
  if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    return false;
  }
  bool   found     = false;
  TSMLoc field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, UUID_HEADER.data(), static_cast<int>(UUID_HEADER.size()));
  if (field_loc != TS_NULL_MLOC) {
    int         len   = 0;
    char const *value = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, 0, &len);
    if (value != nullptr && len > 0 && static_cast<size_t>(len) < cap) {
      memcpy(buf, value, len);
      buf[len] = '\0';
      found    = true;
    }
    TSHandleMLocRelease(bufp, hdr_loc, field_loc);
  }
  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
  return found;
}

int
handle_read_request(TSHttpTxn txnp)
{
  if (request_has_trigger(txnp)) {
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(g_pinned_port);
    if (TSHttpTxnOutgoingAddrSet(txnp, reinterpret_cast<sockaddr const *>(&addr)) == TS_SUCCESS) {
      Dbg(dbg_ctl, "pinned outbound source port to %d for this transaction", g_pinned_port);
    } else {
      TSError("[%.*s] TSHttpTxnOutgoingAddrSet failed", static_cast<int>(PNAME.size()), PNAME.data());
    }
  }
  return 0;
}

int
handle_send_request(TSHttpTxn txnp)
{
  int             port = -1;
  sockaddr const *addr = TSHttpTxnOutgoingAddrGet(txnp);
  if (addr != nullptr && addr->sa_family == AF_INET) {
    port = ntohs(reinterpret_cast<sockaddr_in const *>(addr)->sin_port);
  }
  // Identify the transaction rather than relying on log order. A session id cannot
  // do this job: it is per connection, not per transaction, so a retried connect
  // yields two lines with the same id.
  char uuid[64];
  if (!request_uuid(txnp, uuid, sizeof(uuid))) {
    TSstrlcpy(uuid, "unknown", sizeof(uuid));
  }

  // The client session's transaction count is the runtime discriminator for the
  // premise the port comparison rests on: both requests must travel over ONE client
  // session. On a reused session the two lines report 1 then 2; if ATS closed the
  // session in between, each transaction is the first on its own session and both
  // lines report 1. Proxy Verifier's own "(reuse 2)" summary cannot do this job: it
  // reports the replay file's session structure and prints the same text even when
  // the client is forced to reconnect between the two transactions. A session id
  // cannot do it either: it is not comparable across branches, where
  // next_connection_id() is an atomic counter whose first session is 0 on some and a
  // Snowflake id on others, and con_id itself defaults to 0.
  int       ssn_txn = -1;
  TSHttpSsn ssnp    = TSHttpTxnSsnGet(txnp);

  if (ssnp != nullptr) {
    ssn_txn = TSHttpSsnTransactionCount(ssnp);
  }

  // Greppable tag consumed by the autest, emitted through the debug log so it does
  // not trip the diags.log error scan. A failed read-back prints "unavailable"
  // rather than a number, so the checker's pattern simply fails to match instead of
  // handing it a value that compares unequal to the pinned port and reads as a pass.
  if (port > 0) {
    Dbg(dbg_ctl, "OUTBOUND_PORT uuid=%s effective=%d ssn_txn=%d", uuid, port, ssn_txn);
  } else {
    Dbg(dbg_ctl, "OUTBOUND_PORT uuid=%s effective=unavailable ssn_txn=%d", uuid, ssn_txn);
  }
  return 0;
}

int
txn_handler(TSCont /* contp ATS_UNUSED */, TSEvent event, void *edata)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);
  switch (event) {
  case TS_EVENT_HTTP_READ_REQUEST_HDR:
    handle_read_request(txnp);
    break;
  case TS_EVENT_HTTP_SEND_REQUEST_HDR:
    handle_send_request(txnp);
    break;
  default:
    break;
  }
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 0;
}

} // anonymous namespace

void
TSPluginInit(int argc, char const *argv[])
{
  TSPluginRegistrationInfo info;
  info.plugin_name   = PNAME.data();
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";
  TSReleaseAssert(TSPluginRegister(&info) == TS_SUCCESS);

  if (argc != 2) {
    TSError("[%.*s] usage: %s <pinned-source-port>", static_cast<int>(PNAME.size()), PNAME.data(), argv[0]);
    return;
  }
  g_pinned_port = atoi(argv[1]);
  if (g_pinned_port <= 0 || g_pinned_port >= 65536) {
    TSError("[%.*s] invalid pinned port %s", static_cast<int>(PNAME.size()), PNAME.data(), argv[1]);
    return;
  }

  TSCont contp = TSContCreate(txn_handler, nullptr);
  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, contp);
  TSHttpHookAdd(TS_HTTP_SEND_REQUEST_HDR_HOOK, contp);
  Dbg(dbg_ctl, "initialized; pinned source port %d", g_pinned_port);
}
