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
#define CATCH_CONFIG_RUNNER

#include "v2.13.6/catch.hpp"

#include "tscore/ink_thread.h"
#include "tscore/ink_queue.h"

#include <hwloc.h>

#include <iostream>

namespace
{
InkFreeList *flist = nullptr;

// Args
int nloop    = 1000000;
int affinity = 0;
int nthread  = 0;

hwloc_obj_type_t
thread_affinity()
{
  hwloc_obj_type_t obj_type = HWLOC_OBJ_MACHINE;
  char const *obj_name      = nullptr;

  switch (affinity) {
  case 3: {
    // assign threads to real cores
    obj_type = HWLOC_OBJ_CORE;
    obj_name = "Core";
    break;
  }
  case 1: {
    // assign threads to NUMA nodes (often 1:1 with sockets)
    obj_type = HWLOC_OBJ_NODE;
    obj_name = "NUMA Node";
    if (hwloc_get_nbobjs_by_type(ink_get_topology(), obj_type) > 0) {
      break;
    }
    [[fallthrough]];
  }
  case 2: {
    // assign threads to sockets
    obj_type = HWLOC_OBJ_SOCKET;
    obj_name = "Socket";
    break;
  }
  case 4: {
    // assign threads to logical processing units
#if HAVE_HWLOC_OBJ_PU
    // Older versions of libhwloc (eg. Ubuntu 10.04) don't have HWLOC_OBJ_PU.
    obj_type = HWLOC_OBJ_PU;
    obj_name = "Logical Processor";
    break;
#endif
    [[fallthrough]];
  }
  default: // assign threads to the machine as a whole (a level below SYSTEM)
    obj_type = HWLOC_OBJ_MACHINE;
    obj_name = "Machine";
  }

  std::cout << "thread affinity type = " << obj_name << " (" << affinity << ")" << std::endl;

  return obj_type;
}

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
  // ThreadAffinityInitializer::set_affinity mimics
  const hwloc_obj_type_t obj_type = thread_affinity();
  const int obj_count             = hwloc_get_nbobjs_by_type(ink_get_topology(), obj_type);

  for (int i = 0; i < nthreads; i++) {
    pthread_t tid;

    ink_thread_create(&tid, test_case_1, (void *)((intptr_t)i), 0, 0, nullptr);

    int dst = i * 2;
    if (dst >= obj_count) {
      dst = (i * 2 - obj_count) + 1;
    }

    hwloc_obj_t obj = hwloc_get_obj_by_type(ink_get_topology(), obj_type, dst % obj_count);

    int cpu_mask_len = hwloc_bitmap_snprintf(nullptr, 0, obj->cpuset) + 1;
    char *cpu_mask   = (char *)alloca(cpu_mask_len);
    hwloc_bitmap_snprintf(cpu_mask, cpu_mask_len, obj->cpuset);

    std::cout << "tid=" << tid << " obj->logical_index=" << obj->logical_index << " cpu_mask=" << cpu_mask << std::endl;

    hwloc_set_thread_cpubind(ink_get_topology(), tid, obj->cpuset, HWLOC_CPUBIND_STRICT);
  }

  // go 100 times in default (--benchmark-samples)
  char name[128];
  snprintf(name, sizeof(name), "nthread = %d", nthread);
  BENCHMARK(name) { return test_case_1((void *)nthreads); };
}

TEST_CASE("case 1 - simple new and free", "")
{
  flist = ink_freelist_create("woof", 64, 256, 8);

  if (nthread > 0) {
    SECTION("benchmark specific thread number") { setup_test_case_1(nthread); }
  } else {
    // default
    SECTION("benchmark nthread = 1") { setup_test_case_1(1); }
    SECTION("benchmark nthread = 4") { setup_test_case_1(4); }
    SECTION("benchmark nthread = 8") { setup_test_case_1(8); }
    SECTION("benchmark nthread = 12") { setup_test_case_1(12); }
    SECTION("benchmark nthread = 16") { setup_test_case_1(16); }
    SECTION("benchmark nthread = 20") { setup_test_case_1(20); }
    SECTION("benchmark nthread = 24") { setup_test_case_1(24); }
    SECTION("benchmark nthread = 28") { setup_test_case_1(28); }
    SECTION("benchmark nthread = 32") { setup_test_case_1(32); }
    SECTION("benchmark nthread = 36") { setup_test_case_1(36); }
    SECTION("benchmark nthread = 40") { setup_test_case_1(40); }
    SECTION("benchmark nthread = 44") { setup_test_case_1(44); }
    SECTION("benchmark nthread = 48") { setup_test_case_1(48); }
    SECTION("benchmark nthread = 52") { setup_test_case_1(52); }
    SECTION("benchmark nthread = 56") { setup_test_case_1(56); }
    SECTION("benchmark nthread = 60") { setup_test_case_1(60); }
    SECTION("benchmark nthread = 64") { setup_test_case_1(64); }
    SECTION("benchmark nthread = 68") { setup_test_case_1(68); }
    SECTION("benchmark nthread = 72") { setup_test_case_1(72); }
  }
}
} // namespace

int
main(int argc, char *argv[])
{
  Catch::Session session;

  using namespace Catch::clara;

  auto cli = session.cli() |
             Opt(affinity, "affinity")["--ts-affinity"]("thread affinity type [0 - 4]\n"
                                                        "0 = HWLOC_OBJ_MACHINE (default)\n"
                                                        "1 = HWLOC_OBJ_NODE\n"
                                                        "2 = HWLOC_OBJ_SOCKET\n"
                                                        "3 = HWLOC_OBJ_CORE\n"
                                                        "4 = HWLOC_OBJ_PU") |
             Opt(nloop, "nloop")["--ts-nloop"]("number of loop\n"
                                               "(default: 1000000)") |
             Opt(nthread, "nthread")["--ts-nthread"]("number of threads");

  session.cli(cli);

  int returnCode = session.applyCommandLine(argc, argv);
  if (returnCode != 0) {
    return returnCode;
  }

  if (nthread > 0) {
    std::cout << "nthread = " << nthread << std::endl;
  }

  std::cout << "nloop = " << nloop << std::endl;

  return session.run();
}
