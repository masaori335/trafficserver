/*
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

#include "CriptsTestTxn.h"

using cripts_test::Txn;

TEST_CASE("Transaction: DisableCallback clears only that callback", "[cripts][Transaction]")
{
  Txn  txn{"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"};
  auto context = txn.context();

  transaction.enabled_hooks = cripts::Callbacks::DO_READ_RESPONSE | cripts::Callbacks::DO_SEND_RESPONSE;

  // The documented spelling, which a function-like DisableCallback macro would break.
  transaction.DisableCallback(cripts::Callbacks::DO_READ_RESPONSE);
  CHECK(transaction.enabled_hooks == cripts::Callbacks::DO_SEND_RESPONSE);
}
