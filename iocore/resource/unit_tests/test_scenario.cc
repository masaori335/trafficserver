/** @file

  Test Algorithms with CSV data

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

#define CATCH_CONFIG_RUNNER

#include "catch.hpp"

#include "ReactiveTokenBucket.h"
#include "test_Reporter.h"

#include "tscore/BufferWriter.h"
#include "tscpp/util/TextView.h"

#include <fstream>
#include <iostream>
#include <string>

using namespace RTB;

struct Scenario {
  using Header = std::vector<std::string>;
  using Record = std::vector<uint64_t>;
  using Data   = std::vector<Record>;

  Header header;
  Data data;
};

using TestLimiterV1 = RTB::AlgorithmV1<RTB::Counter>;
using Limiter       = std::variant<TestLimiterV1>;

namespace
{
std::string in    = "./unit_tests/data/scenario0.csv";
uint64_t top_n    = 10;
uint64_t limit    = 6000;
uint64_t duration = 10;
float red_zone    = 0.2;

void
load_scenario(Scenario &scenario)
{
  std::fstream ifs;
  ifs.open(in, std::ios::in);
  REQUIRE(ifs.is_open());

  std::string buf;

  // Header
  {
    std::getline(ifs, buf);

    ts::TextView header(buf);
    ts::TextView token = header.split_prefix_at(',');
    token.trim('"');

    REQUIRE_THAT((std::string)token, Catch::Matchers::Equals("Time"));

    token = header.split_prefix_at(',');
    while (token.size() > 0) {
      token.trim('"');
      scenario.header.push_back(std::string(token));
      token = header.split_prefix_at(',');
    }
  }

  // Records
  while (std::getline(ifs, buf)) {
    ts::TextView record(buf);
    // skip Time column
    ts::TextView token = record.split_prefix_at(',');

    Scenario::Record r;
    token = record.split_prefix_at(',');
    for (int i = 0; i < (int)scenario.header.size(); ++i) {
      if (token.size() > 0) {
        r.push_back(std::atoi(token.data()));
      } else {
        r.push_back(0);
      }
      token = record.split_prefix_at(',');
    }
    scenario.data.push_back(r);
  }
}

void
runner(Limiter &limiter)
{
  Scenario s;
  load_scenario(s);

  // setup
  for (size_t i = 0; i < s.header.size(); ++i) {
    std::visit([&](auto &l) { l.add(i); }, limiter);
  }
  std::visit([&](auto &l) { l.reserve(); }, limiter);

  // run scenario records
  int t = 0;
  for (auto record : s.data) {
    // Round Robin
    while (true) {
      bool stop = true;
      for (size_t i = 0; i < s.header.size(); ++i) {
        if (record[i] == 0) {
          continue;
        } else {
          --record[i];
          stop = false;

          std::visit([&](auto &l) -> bool { return l.is_full(i); }, limiter);
          std::visit([&](auto &l) { l.inc(i); }, limiter);
        }
      }
      if (stop) {
        break;
      }
    }

    std::visit([&](auto &l) { l.filter(); }, limiter);
    std::visit([&](TestLimiterV1 &l) { CHECK(limit == report_v1(l, t++)); }, limiter);
    std::visit([&](auto &l) { l.reserve(); }, limiter);
  }

  // check
  for (size_t i = 0; i < s.header.size(); ++i) {
    CHECK(std::visit([&](auto &l) { return l.is_full(i); }, limiter) == false);
  }
}
} // namespace

TEST_CASE("ReactiveTokenBucket v1", "")
{
  std::cout << "AlgorithmV1<Counter>" << std::endl;

  TestLimiterV1::Conf c;
  c.top_n            = top_n;
  c.limit            = limit;
  c.penalty_duration = duration;
  c.red_zone         = red_zone;

  Limiter limiter = TestLimiterV1{c};
  std::cout << "limit=" << limit << " overflow token=" << limit * red_zone << std::endl;

  runner(limiter);
}

int
main(int argc, char *argv[])
{
  Catch::Session session;

  using namespace Catch::clara;

  // clang-format off
  auto cli = session.cli()
    | Opt(in, "in")["--r-in"]("input file")
    | Opt(top_n, "top_n")["--r-top"]("top N filter")
    | Opt(limit, "limit")["--r-limit"]("limit")
    | Opt(duration, "duration")["--r-duration"]("tmp limit duration")
    | Opt(red_zone, "red_zone")["--r-red-zone"]("red zone");
  // clang-format on

  session.cli(cli);

  int returnCode = session.applyCommandLine(argc, argv);
  if (returnCode != 0) {
    return returnCode;
  }

  return session.run();
}
