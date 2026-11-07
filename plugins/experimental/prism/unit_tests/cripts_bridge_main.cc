/** @file

  Runs the prism test cases on Cripts, against the real plugin API, without a traffic_server.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
  agreements.  See the NOTICE file distributed with this work for additional information regarding
  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with the License.  You may obtain
  a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed under the License
  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
  or implied. See the License for the specific language governing permissions and limitations under
  the License.
*/

// Stands in for traffic_server: the cases are a module loaded the way prism.so is, after the core is set up, because
// libcripts' static initializers read the core's state. src/cripts/unit_tests/README.md explains the layout.

#include "api/InkAPIInternal.h"
#include "iocore/eventsystem/EThread.h"
#include "proxy/hdrs/HTTP.h"
#include "tscore/BaseLogFile.h"
#include "tscore/Diags.h"
#include "tscore/ink_queue.h"
#include "tscore/Layout.h"

#include <catch2/catch_session.hpp>

#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <unistd.h>

extern int cmd_disable_pfreelist;

int
main(int argc, char *argv[])
{
  // No event threads, so keep the allocators off the thread local free lists. THREAD_ALLOC() and TSContCreate() still
  // need a current thread.
  cmd_disable_pfreelist = true;
  ink_freelist_init_ops(0, cmd_disable_pfreelist);
  Thread *main_thread = new EThread();
  main_thread->set_specific();
  DiagsPtr::set(new Diags("test_prism_cripts_bridge", "" /* tags */, "" /* actions */, new BaseLogFile("stderr")));

  // An empty prefix of its own, for the config directory File::Line::Read resolves a relative path against. The cases
  // write there, so an exported config directory must not take its place.
  unsetenv("PROXY_CONFIG_CONFIG_DIR");
  std::error_code ec;
  std::string     prefix = (std::filesystem::temp_directory_path(ec) / "test_prism_cripts_bridge.XXXXXX").string();

  if (mkdtemp(prefix.data()) == nullptr) {
    std::perror("mkdtemp");
    return 1;
  }
  Layout::create(prefix);
  // File::Path::Rebase() throws without a config directory, as traffic_server never runs.
  std::filesystem::create_directories(Layout::get()->sysconfdir, ec);
  http_init();
  api_init();

  int result = 1;

  if (dlopen(PRISM_TEST_CASES_PATH, RTLD_NOW | RTLD_GLOBAL) == nullptr) {
    std::fprintf(stderr, "dlopen(%s): %s\n", PRISM_TEST_CASES_PATH, dlerror());
  } else {
    result = Catch::Session().run(argc, argv);
  }
  std::filesystem::remove_all(prefix, ec);
  return result;
}
