/** @file

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

#include <array>
#include <cstdint>
#include <vector>

#include <pthread.h>

#include <catch2/catch_test_macros.hpp>

#include <libnuraft/buffer.hxx>
#include <libnuraft/buffer_serializer.hxx>
#include <libnuraft/cluster_config.hxx>
#include <libnuraft/snapshot.hxx>

#include "state_machine.h"

namespace
{
/// Make a NuRaft payload with a byte-array length prefix that is not the
/// required fixed STEK size. The payload is otherwise well-formed so the state
/// machine can reject the malformed length without depending on buffer errors.
nuraft::ptr<nuraft::buffer>
make_stek_log_entry(size_t stek_len)
{
  std::vector<unsigned char>  stek(stek_len, 0xa5);
  nuraft::ptr<nuraft::buffer> data = nuraft::buffer::alloc(sizeof(int) + stek_len);
  nuraft::buffer_serializer   bs(data);

  bs.put_bytes(stek.data(), stek_len);
  return data;
}
} // namespace

TEST_CASE("STEKShareSM rejects malformed commit payload lengths", "[stek_share]")
{
  constexpr std::array<size_t, 2> invalid_lengths{SSL_TICKET_KEY_SIZE - 1, SSL_TICKET_KEY_SIZE + 1};
  for (auto stek_len : invalid_lengths) {
    INFO("STEK payload length: " << stek_len);
    STEKShareSM                 sm;
    ssl_ticket_key_t            curr_stek{};
    nuraft::ptr<nuraft::buffer> malformed = make_stek_log_entry(stek_len);

    nuraft::ptr<nuraft::buffer> result = sm.commit(1, *malformed);

    REQUIRE(result == nullptr);
    CHECK(sm.last_commit_index() == 1);
    CHECK_FALSE(sm.received_stek(&curr_stek));
  }
}

TEST_CASE("STEKShareSM rejects malformed snapshot payload lengths", "[stek_share]")
{
  constexpr std::array<size_t, 2> invalid_lengths{SSL_TICKET_KEY_SIZE - 1, SSL_TICKET_KEY_SIZE + 1};
  for (auto stek_len : invalid_lengths) {
    INFO("STEK payload length: " << stek_len);
    STEKShareSM                         sm;
    nuraft::ptr<nuraft::cluster_config> config = nuraft::cs_new<nuraft::cluster_config>();
    nuraft::snapshot                    snapshot(1, 1, config);
    uint64_t                            obj_id    = 0;
    nuraft::ptr<nuraft::buffer>         malformed = make_stek_log_entry(stek_len);

    sm.save_logical_snp_obj(snapshot, obj_id, *malformed, true, true);

    CHECK(obj_id == 1);
    CHECK(sm.last_snapshot() == nullptr);
  }
}
