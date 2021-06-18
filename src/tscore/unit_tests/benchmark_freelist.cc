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

#define NTHREADS 16

InkFreeList *flist = nullptr;
int nloop = 1000000;

void *
test(void *d)
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

TEST_CASE("freelist", "")
{
  flist = ink_freelist_create("woof", 64, 256, 8);

  for (int i = 0; i < NTHREADS; i++) {
    fprintf(stderr, "Create thread %d\n", i);
    ink_thread_create(nullptr, test, (void *)((intptr_t)i), 0, 0, nullptr);
  }

  BENCHMARK("simple new and free") { return test((void *)NTHREADS); };
}
