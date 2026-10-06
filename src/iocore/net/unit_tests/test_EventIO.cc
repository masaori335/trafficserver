/** @file

  Catch based unit tests for EventIO

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

#include <catch2/catch_test_macros.hpp>

#include <unistd.h>

#include "swoc/swoc_file.h"

#include <atomic>
#include <thread>

#include "iocore/net/EventIO.h"
#include "../P_UnixPollDescriptor.h"

namespace
{
// Minimal concrete EventIO so we can drive start_common()/stop()/modify()/refresh()
// in isolation. process_event() is never invoked by these tests.
struct TestEventIO : public EventIO {
  void
  process_event(int /* flags */) override
  {
  }

  int
  test_start(EventLoop l, int afd, int e)
  {
    return start_common(l, afd, e);
  }
};
} // namespace

// Platform note: modify() dereferences event_loop on no supported platform: both of its
// blocks require !defined(USE_EDGE_TRIGGER), which EventIO.h always defines.  refresh()
// dereferences it only under TS_USE_KQUEUE, so on macOS and FreeBSD this test exercises a
// real null dereference in a release build, and on Linux it pins the guard against
// regression if either block is ever re-enabled.
//
// A descriptor that has been stopped (or migrated) has its event_loop cleared to
// nullptr by stop(). A concurrent modify()/refresh() on the same EventIO must not
// dereference that null pointer; it has nothing registered, so it must be a no-op
// returning 0.
TEST_CASE("EventIO modify/refresh after stop is a no-op", "[EventIO]")
{
  PollDescriptor pd;

  int pipefd[2];
  REQUIRE(pipe(pipefd) == 0);
  // Take ownership of the pipe fds so they are closed on scope exit even if a REQUIRE
  // below aborts the test.
  swoc::file::unique_fd read_fd{pipefd[0]};
  swoc::file::unique_fd write_fd{pipefd[1]};

  TestEventIO eio;
  REQUIRE(eio.test_start(&pd, read_fd, EVENTIO_READ) == 0);

  // stop() removes the descriptor and clears event_loop.
  REQUIRE(eio.stop() == 0);
  REQUIRE(eio.event_loop.load() == nullptr);

  // These would dereference the now-null event_loop without the guard.
  CHECK(eio.modify(EVENTIO_READ) == 0);
  CHECK(eio.refresh(EVENTIO_READ) == 0);
}

// The guard above makes a cleared event_loop safe to observe.  This case is about the
// observation itself: stop() writes the member from one thread while modify() and
// refresh() read it from another, which on a plain pointer is a data race and therefore
// undefined, however indivisible a pointer store happens to be on the target.  event_loop is
// a std::atomic, which makes every access well defined.
//
// What this case can and cannot show.  Under ThreadSanitizer (cmake --preset tsan) it is a
// real oracle: with event_loop turned back into a plain pointer it reports a write/read data
// race on EventIO::event_loop, and with the atomic it is clean.  Without TSan it cannot fail on
// the race at all, so treat it as a smoke test on those builds and run the tsan preset to
// actually exercise the claim.
TEST_CASE("EventIO stop racing modify does not race on event_loop", "[EventIO]")
{
  // Short rounds with a fresh registration each time, released together, so the two
  // threads genuinely overlap instead of one always finishing before the other starts.
  constexpr int ROUNDS = 200;

  for (int round = 0; round < ROUNDS; ++round) {
    PollDescriptor pd;

    int pipefd[2];
    REQUIRE(pipe(pipefd) == 0);
    swoc::file::unique_fd read_fd{pipefd[0]};
    swoc::file::unique_fd write_fd{pipefd[1]};

    TestEventIO eio;
    REQUIRE(eio.test_start(&pd, read_fd, EVENTIO_READ) == 0);

    std::atomic<bool> go{false};

    std::thread stopper([&]() {
      while (!go.load(std::memory_order_acquire)) {}
      eio.stop();
    });

    std::thread toucher([&]() {
      while (!go.load(std::memory_order_acquire)) {}
      eio.modify(EVENTIO_READ);
      eio.refresh(EVENTIO_READ);
    });

    go.store(true, std::memory_order_release);
    stopper.join();
    toucher.join();

    // Whichever order they ran in, stop() is the last writer and the descriptor is gone.
    CHECK(eio.event_loop.load() == nullptr);
  }
}
