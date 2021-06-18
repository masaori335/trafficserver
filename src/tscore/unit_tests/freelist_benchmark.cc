/** @file

  Micro Benchmark tool for freelist - requires Catch2 v2.9.0+

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

#define CATCH_CONFIG_ENABLE_BENCHMARKING
#define CATCH_CONFIG_MAIN

#include "v2.13.6/catch.hpp"

#include "tscore/ink_thread.h"
#include "tscore/ink_queue.h"

InkFreeList *flist  = nullptr;
constexpr int nloop = 1000000;

void *
test_case_1(void *d)
{
  int id;
  void *m1;

  id = (intptr_t)d;

  const InkFreeListOps *ops = ink_freelist_freelist_ops();

  for (int i = 0; i < nloop; ++i) {
    m1 = ink_freelist_new(flist, ops);

    memset(m1, id, 64);

    ink_freelist_free(flist, m1, ops);
  }

  return nullptr;
}

void
setup_test_case_1(int64_t nthreads)
{
  for (int i = 0; i < nthreads; i++) {
    ink_thread_create(nullptr, test_case_1, (void *)((intptr_t)i), 0, 0, nullptr);
  }

  // go 100 times in default (--benchmark-samples)
  BENCHMARK("case 1") { return test_case_1((void *)nthreads); };
}

TEST_CASE("case 1 - simple new and free", "")
{
  flist = ink_freelist_create("woof", 64, 256, 8);

  SECTION("nthread = 1") { setup_test_case_1(1); }
  SECTION("nthread = 4") { setup_test_case_1(4); }
  SECTION("nthread = 8") { setup_test_case_1(8); }
  SECTION("nthread = 12") { setup_test_case_1(12); }
  SECTION("nthread = 16") { setup_test_case_1(16); }
  SECTION("nthread = 20") { setup_test_case_1(20); }
  SECTION("nthread = 24") { setup_test_case_1(24); }
  SECTION("nthread = 28") { setup_test_case_1(28); }
  SECTION("nthread = 32") { setup_test_case_1(32); }
  SECTION("nthread = 36") { setup_test_case_1(36); }
  SECTION("nthread = 40") { setup_test_case_1(40); }
  SECTION("nthread = 44") { setup_test_case_1(44); }
  SECTION("nthread = 48") { setup_test_case_1(48); }
  SECTION("nthread = 52") { setup_test_case_1(52); }
  SECTION("nthread = 56") { setup_test_case_1(56); }
  SECTION("nthread = 60") { setup_test_case_1(60); }
  SECTION("nthread = 64") { setup_test_case_1(64); }
}
