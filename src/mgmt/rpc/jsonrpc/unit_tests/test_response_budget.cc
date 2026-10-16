/** @file

   Catch-based tests for rpc::ResponseBudget and the record budget inside lookup_records.

   These cover the boundaries the cases in test_basic_protocol.cc do not reach: a budget that lands
   exactly on zero without ever being refused, a take() of more than one record, accumulation across
   the elements of a single message, and the early stop that keeps a truncated lookup from walking
   the store again for every element behind it.

   @section license License

   Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements.
   See the NOTICE file distributed with this work for additional information regarding copyright
   ownership.  The ASF licenses this file to you under the Apache License, Version 2.0 (the
   "License"); you may not use this file except in compliance with the License.  You may obtain a
   copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software distributed under the License
   is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
   or implied. See the License for the specific language governing permissions and limitations under
   the License.
 */

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "mgmt/rpc/jsonrpc/JsonRPCManager.h"
#include "mgmt/rpc/handlers/records/Records.h"
#include "tsutil/Metrics.h"

namespace
{
// Three is enough to put a budget boundary on either side of the matched set and exactly on it.
// Metrics rather than config records because this binary has no main() of its own and so never
// calls RecProcessInit(). A by-name element naming a metric is answered here, since RecLookupRecord
// consults ts::Metrics before librecords, but one naming a config record reaches the librecords
// half and aborts on the uninitialised lock, and the regex arm's config walk finds an empty store.
constexpr size_t       EXACT_COUNT = 3;
std::string_view const EXACT_PREFIX{"proxy.process.test.auditor.exact."};
std::string const      EXACT_REGEX{R"(^proxy\.process\.test\.auditor\.exact\.)"};

// The metric store is process global and re-creating a name relists the same slot, so register once.
void
register_auditor_metrics()
{
  static bool once = []() -> bool {
    for (size_t i = 0; i < EXACT_COUNT; ++i) {
      ts::Metrics::Counter::createPtr(std::string{EXACT_PREFIX} + std::to_string(i));
    }
    return true;
  }();
  (void)once;
}

YAML::Node
regex_element(std::string const &regex)
{
  YAML::Node e{YAML::NodeType::Map};
  e["record_name_regex"] = regex;
  return e;
}

/// An element that names neither a record nor a regex, so its conversion throws and lookup_records
/// answers it with INVALID_INCOMING_DATA. Used as a marker for "this element was reached".
YAML::Node
undecodable_element()
{
  YAML::Node e{YAML::NodeType::Map};
  e["not_a_record_key"] = "x";
  return e;
}

YAML::Node
params_of(std::vector<YAML::Node> const &elements)
{
  YAML::Node params{YAML::NodeType::Sequence};
  for (auto const &e : elements) {
    params.push_back(e);
  }
  return params;
}

// The wire-visible code, spelled out rather than taken from the enum, so a renumbering of
// RecordError fails here the way it would fail a client.
constexpr int RESPONSE_TRUNCATED = 2012;

struct Answer {
  size_t records{0};
  size_t truncated{0}; ///< errorList entries whose code is RESPONSE_TRUNCATED
  size_t others{0};    ///< every other errorList entry
};

Answer
read_answer(YAML::Node const &result)
{
  REQUIRE(result["recordList"]);
  REQUIRE(result["errorList"]);

  Answer a;
  a.records = result["recordList"].size();
  for (auto &&e : result["errorList"]) {
    REQUIRE(e["code"]);
    if (e["code"].as<int>() == RESPONSE_TRUNCATED) {
      ++a.truncated;
    } else {
      ++a.others;
    }
  }
  return a;
}
} // namespace

// test_basic_protocol.cc crosses the budget only by overshooting it, so it never distinguishes "the
// allowance ran out exactly" from "the allowance was refused". Marking a budget spent the moment the
// remainder reaches zero satisfies every case there, and reports a response that dropped nothing as
// truncated.
TEST_CASE("ResponseBudget: a budget that lands exactly on zero is not spent", "[limits][records]")
{
  SECTION("one record at a time")
  {
    rpc::ResponseBudget budget{3};

    CHECK(budget.take());
    CHECK(budget.take());
    CHECK(budget.take());
    CHECK_FALSE(budget.spent());

    CHECK_FALSE(budget.take());
    CHECK(budget.spent());
  }

  SECTION("a single take of the whole allowance")
  {
    rpc::ResponseBudget budget{10};

    CHECK(budget.take(10));
    CHECK_FALSE(budget.spent());
  }

  SECTION("an empty allowance refuses the first record")
  {
    rpc::ResponseBudget budget{0};

    CHECK_FALSE(budget.take());
    CHECK(budget.spent());
  }
}

// take(n) for n > 1 has no caller in the tree yet and no coverage, so its boundary is pinned here
// rather than left to the first caller to discover.
TEST_CASE("ResponseBudget: take(n) fits at the remainder and not one past it", "[limits][records]")
{
  SECTION("n equal to the remainder fits")
  {
    rpc::ResponseBudget budget{5};

    CHECK(budget.take(5));
    CHECK_FALSE(budget.spent());
  }

  SECTION("n one past the remainder does not")
  {
    rpc::ResponseBudget budget{5};

    CHECK_FALSE(budget.take(6));
    CHECK(budget.spent());
  }

  SECTION("a partial spend leaves the rest")
  {
    rpc::ResponseBudget budget{5};

    CHECK(budget.take(2));
    CHECK(budget.take(3));
    CHECK_FALSE(budget.spent());
    CHECK_FALSE(budget.take(1));
    CHECK(budget.spent());
  }

  // Without the latch a refused take leaves the remainder untouched, so a smaller take after it
  // would succeed and a response already reported short would carry on growing.
  SECTION("a take refused for being too large refuses every later take")
  {
    rpc::ResponseBudget budget{5};

    CHECK_FALSE(budget.take(6));
    CHECK(budget.spent());
    CHECK_FALSE(budget.take(1));
    CHECK_FALSE(budget.take(4));
    CHECK(budget.spent());
  }
}

// The cases in test_basic_protocol.cc put one element in each message, so nothing there pins that a
// second element of the same message spends what the first one left.
TEST_CASE("lookup_records: the budget accumulates across the elements of one message", "[limits][records]")
{
  register_auditor_metrics();

  SECTION("two elements whose matches add up to exactly the budget are answered in full")
  {
    rpc::ResponseBudget budget{2 * EXACT_COUNT};

    auto const rv =
      rpc::handlers::records::lookup_records("1", params_of({regex_element(EXACT_REGEX), regex_element(EXACT_REGEX)}), budget);
    auto const answer = read_answer(rv.result());

    CHECK(answer.records == 2 * EXACT_COUNT);
    CHECK(answer.truncated == 0);
    CHECK(answer.others == 0);
    CHECK_FALSE(budget.spent());
  }

  SECTION("one record short, the second element is cut off and the response says so")
  {
    rpc::ResponseBudget budget{2 * EXACT_COUNT - 1};

    auto const rv =
      rpc::handlers::records::lookup_records("1", params_of({regex_element(EXACT_REGEX), regex_element(EXACT_REGEX)}), budget);
    auto const answer = read_answer(rv.result());

    CHECK(answer.records == 2 * EXACT_COUNT - 1);
    CHECK(answer.truncated == 1);
    CHECK(answer.others == 0);
    CHECK(budget.spent());
  }
}

// Once the allowance is gone the remaining elements must not be walked at all. Nothing in the
// change's tests observes that: the record count and the RESPONSE_TRUNCATED entry are the same with
// the early stop and without it, and the only other difference is how long the request takes --
// measured at 8s for tests/gold_tests/jsonrpc/jsonrpc_request_limits.test.py with the stop and
// 2m29s without. An element behind the truncation that cannot be decoded gives the same difference
// as a verdict instead of a duration: reaching it adds its own error to the list.
TEST_CASE("lookup_records: a truncated lookup does not process the elements behind it", "[limits][records]")
{
  register_auditor_metrics();

  rpc::ResponseBudget budget{1};

  auto const rv =
    rpc::handlers::records::lookup_records("1", params_of({regex_element(EXACT_REGEX), undecodable_element()}), budget);
  auto const answer = read_answer(rv.result());

  CHECK(answer.records == 1);
  CHECK(answer.truncated == 1);
  // Would be 1 (INVALID_INCOMING_DATA) if the second element had been reached.
  CHECK(answer.others == 0);
  CHECK(budget.spent());
}

// The budget is one per request and lookup_records is called once per message, so the message that
// spends it is usually not the last one to run. A check placed only after a record is refused
// catches the elements behind the truncation inside one message and misses every message after it,
// which then pays a whole store walk for records no element can receive. The undecodable element
// is the marker again: reaching it would add its own error.
TEST_CASE("lookup_records: a message that inherits a spent budget looks at nothing", "[limits][records]")
{
  register_auditor_metrics();

  rpc::ResponseBudget budget{1};

  auto const first =
    read_answer(rpc::handlers::records::lookup_records("1", params_of({regex_element(EXACT_REGEX)}), budget).result());

  CHECK(first.records == 1);
  CHECK(first.truncated == 1);
  REQUIRE(budget.spent());

  auto const second = read_answer(rpc::handlers::records::lookup_records("2", params_of({undecodable_element()}), budget).result());

  CHECK(second.records == 0);
  CHECK(second.truncated == 1);
  CHECK(second.others == 0);
}

// A message with nothing to ask for has lost nothing, whoever spent the budget, so it must not be
// reported short. Reading the answer back from budget.spent() alone would report it.
TEST_CASE("lookup_records: an empty message is not reported truncated", "[limits][records]")
{
  register_auditor_metrics();

  rpc::ResponseBudget budget{1};

  CHECK(
    read_answer(rpc::handlers::records::lookup_records("1", params_of({regex_element(EXACT_REGEX)}), budget).result()).truncated ==
    1);
  REQUIRE(budget.spent());

  auto const empty = read_answer(rpc::handlers::records::lookup_records("2", params_of({}), budget).result());

  CHECK(empty.records == 0);
  CHECK(empty.truncated == 0);
  CHECK(empty.others == 0);
}

// The same element on its own, so the marker above is known to be a marker: an undecodable element
// that is reached does report INVALID_INCOMING_DATA.
TEST_CASE("lookup_records: an undecodable element that is reached is reported", "[limits][records]")
{
  rpc::ResponseBudget budget{rpc::JsonRPCManager::MAX_RECORDS_PER_REQUEST};

  auto const rv     = rpc::handlers::records::lookup_records("1", params_of({undecodable_element()}), budget);
  auto const answer = read_answer(rv.result());

  CHECK(answer.records == 0);
  CHECK(answer.truncated == 0);
  CHECK(answer.others == 1);
  CHECK_FALSE(budget.spent());
}
