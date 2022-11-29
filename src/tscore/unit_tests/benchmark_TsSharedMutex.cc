/** @file

  Micro Benchmark tool for TsSharedMutex - requires Catch2 v2.9.0+

  ```
  $ taskset -c 2-65 benchmark_TsSharedMutex
  ```

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
#define CATCH_CONFIG_RUNNER

#include "catch.hpp"

#include "tscore/ink_thread.h"
#include "tscpp/util/TsSharedMutex.h"

#include <shared_mutex>

namespace
{
// Args
int nloop    = 1;
int nthreads = 1;

ts::shared_mutex mutex;

void *
test_case_0(void *d)
{
  thread_local int counter = 0;

  for (int i = 0; i < nloop; ++i) {
    ++counter;
  }

  return nullptr;
}

void *
test_case_1(void *d)
{
  thread_local int counter = 0;

  for (int i = 0; i < nloop; ++i) {
    std::shared_lock lock(mutex);
    ++counter;
  }

  return nullptr;
}

void *
test_case_2(void *d)
{
  thread_local int counter = 0;

  for (int i = 0; i < nloop; ++i) {
    std::unique_lock lock(mutex);
    ++counter;
  }

  return nullptr;
}

void
spawn_n_thread(void *(*func)(void *))
{
  ink_thread list[nthreads];

  for (int i = 0; i < nthreads; i++) {
    ink_thread_create(&list[i], func, (void *)((intptr_t)i), 0, 0, nullptr);
  }

  for (int i = 0; i < nthreads; i++) {
    ink_thread_join(list[i]);
  }
}

TEST_CASE("TsSharedLock Benchmark", "")
{
  BENCHMARK("no lock") { return spawn_n_thread(test_case_0); };
  BENCHMARK("shared lock") { return spawn_n_thread(test_case_1); };
  BENCHMARK("unique lock") { return spawn_n_thread(test_case_2); };
}
} // namespace

int
main(int argc, char *argv[])
{
  Catch::Session session;

  using namespace Catch::clara;

  auto cli = session.cli() | Opt(nloop, "n")["--ts-nloop"]("number of loop (default: 1000000)") |
             Opt(nthreads, "n")["--ts-nthreads"]("number of threads (default: 1)");

  session.cli(cli);

  int returnCode = session.applyCommandLine(argc, argv);
  if (returnCode != 0) {
    return returnCode;
  }

  return session.run();
}
