/** @file

  Catch based unit tests of Reactive Token Bucket

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

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "ReactiveTokenBucket.h"
#include "test_Reporter.h"

using namespace RTB;

TEST_CASE("ReactiveTokenBucket v1", "")
{
  SECTION("Counter")
  {
    using TestLimiter = RTB::AlgorithmV1<RTB::Counter>;

    TestLimiter::Conf c;
    c.top_n            = 10;
    c.limit            = 10;
    c.penalty_duration = 300;
    c.red_zone         = 0.2;

    TestLimiter limiter(c);

    int t = 0;

    SECTION("Scenario 1")
    {
      const uint64_t tid_1 = 1;
      limiter.add(tid_1);

      // ---- t=0 ----
      CHECK(limiter.is_full(tid_1) == false);

      for (int i = 0; i < 3; ++i) {
        limiter.inc(tid_1);
      }

      limiter.filter();
      report_v1<TestLimiter>(limiter, t++);
      limiter.reserve();

      // ---- t=1 ----
      CHECK(limiter.is_full(tid_1) == false);

      for (int i = 0; i < 11; ++i) {
        limiter.inc(tid_1);
      }

      CHECK(limiter.is_full(tid_1) == true);

      limiter.filter();
      CHECK(report_v1<TestLimiter>(limiter, t++) == c.limit);
      limiter.reserve();
    }

    SECTION("Scenario 2")
    {
      const uint64_t tid_1 = 1;
      limiter.add(tid_1);

      const uint64_t tid_2 = 2;
      limiter.add(tid_2);

      // ---- t=0 ----
      CHECK(limiter.is_full(tid_1) == false);
      CHECK(limiter.is_full(tid_2) == false);

      for (int i = 0; i < 3; ++i) {
        limiter.inc(tid_1);
      }

      for (int i = 0; i < 4; ++i) {
        limiter.inc(tid_2);
      }

      CHECK(limiter.is_full(tid_1) == false);
      CHECK(limiter.is_full(tid_2) == false);

      limiter.filter();
      report_v1<TestLimiter>(limiter, t++);
      limiter.reserve();

      // ---- t=1 ----
      CHECK(limiter.is_full(tid_1) == false);
      CHECK(limiter.is_full(tid_2) == false);

      for (int i = 0; i < 11; ++i) {
        limiter.inc(tid_1);
      }

      for (int i = 0; i < 4; ++i) {
        limiter.inc(tid_2);
      }

      CHECK(limiter.is_full(tid_1) == true);
      CHECK(limiter.is_full(tid_2) == false);

      limiter.filter();
      CHECK(report_v1<TestLimiter>(limiter, t++) == c.limit);
      limiter.reserve();

      // ---- t=2 ----
      CHECK(limiter.is_full(tid_1) == false);
      CHECK(limiter.is_full(tid_2) == false);

      for (int i = 0; i < 5; ++i) {
        limiter.inc(tid_2);
      }

      for (int i = 0; i < 12; ++i) {
        limiter.inc(tid_1);
      }

      CHECK(limiter.is_full(tid_1) == true);
      CHECK(limiter.is_full(tid_2) == true);

      limiter.filter();
      CHECK(report_v1<TestLimiter>(limiter, t++) == c.limit);
      limiter.reserve();
    }
  }

  SECTION("Gauge")
  {
    using TestLimiter = RTB::AlgorithmV1<RTB::Gauge>;

    TestLimiter::Conf c;
    c.top_n            = 10;
    c.limit            = 10;
    c.penalty_duration = 300;
    c.red_zone         = 0.2;

    TestLimiter limiter(c);

    int t = 0;

    SECTION("Scenario 1")
    {
      const uint64_t tid_1 = 1;
      limiter.add(tid_1);

      // ---- t=0 ----
      CHECK(limiter.is_full(tid_1) == false);

      for (int i = 0; i < 3; ++i) {
        limiter.inc(tid_1);
      }

      CHECK(limiter.is_full(tid_1) == false);

      limiter.filter();
      report_v1<TestLimiter>(limiter, t++);
      limiter.reserve();

      // ---- t=1 ----
      CHECK(limiter.is_full(tid_1) == false);

      for (int i = 0; i < 11; ++i) {
        limiter.inc(tid_1);
      }

      for (int i = 0; i < 9; ++i) {
        limiter.dec(tid_1);
      }

      CHECK(limiter.is_full(tid_1) == false);

      limiter.filter();
      CHECK(report_v1<TestLimiter>(limiter, t++) == c.limit);
      limiter.reserve();

      // ---- t=2 ----
      CHECK(limiter.is_full(tid_1) == false);

      for (int i = 0; i < 11; ++i) {
        limiter.inc(tid_1);
      }

      CHECK(limiter.is_full(tid_1) == true);

      limiter.filter();
      CHECK(report_v1<TestLimiter>(limiter, t++) == c.limit);
      limiter.reserve();

      // ---- t=3 ----
      CHECK(limiter.is_full(tid_1) == true);

      // Makge the gauge 0
      for (int i = 0; i < 16; ++i) {
        limiter.dec(tid_1);
      }

      CHECK(limiter.is_full(tid_1) == false);

      CHECK(limiter.global_bucket().observed == 0);

      limiter.filter();
      CHECK(report_v1<TestLimiter>(limiter, t++) == c.limit);
      limiter.reserve();
    }
  }
}
