/** @file

  A brief file description

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

#include "tscore/BufferWriter.h"

template <typename T>
uint64_t
report_v1(const T &limiter, int t)
{
  ts::LocalBufferWriter<4096> buf;

  buf << "----t=" << t << "----\n";

  auto &map            = limiter.bucket_map();
  auto &sorted_tid_map = limiter.sorted_tid_map();
  auto &conf           = limiter.conf();

  uint64_t i              = 0;
  uint64_t total_token    = 0;
  uint64_t total_observed = 0;

  for (auto iter = limiter.sorted_tid_map().crbegin(); iter != sorted_tid_map.crend(); ++iter, ++i) {
    const uint64_t tid = iter->second;
    const auto &bucket = map.at(tid);

    total_token += bucket.token;

    if (i < conf.top_n) {
      buf.print("tid={:>3}:", tid);
      buf.print(" token={:>4}", bucket.token);
      buf.print(" observed={:>4}", bucket.observed);

      if (bucket.denied > 0) {
        buf.print(" denied=\033[31m{:>4}\033[0m ", bucket.denied);
      } else {
        buf.print(" denied={:>4} ", bucket.denied);
      }

      buf.print(" tmp_limit={:>4}", bucket.tmp_limit);
      buf << "\n";
    }

    if (bucket.observed <= bucket.token) {
      total_observed += bucket.observed;
    } else {
      total_observed += bucket.token;
    }
  }

  const auto &global_bucket = limiter.global_bucket();
  buf << "global bucket:";
  buf << " token=" << global_bucket.token;
  buf << " observed=" << global_bucket.observed;
  buf << "\n";

  total_token += global_bucket.token;
  total_observed += global_bucket.observed;

  buf.print("total: token={:>4} observed={:>4}", total_token, total_observed);
  buf << "\n";

  std::cout << buf;

  return total_token;
}
