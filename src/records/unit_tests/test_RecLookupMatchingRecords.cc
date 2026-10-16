/** @file

   Catch-based tests for RecLookupMatchingRecords regex handling.

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

#include "records/RecCore.h"
#include "tsutil/Metrics.h"
#include "tsutil/Regex.h"
#include "test_Diags.h"

namespace
{
void
count_callback(const RecRecord * /* record ATS_UNUSED */, void *data)
{
  ++*static_cast<int *>(data);
}

// A long 'a' run followed by a character that cannot satisfy the anchor is what drives "(a+)+$" into
// exponential backtracking.
std::string const REDOS_SUFFIX = std::string(40, 'a') + "z";

// Every pattern below anchors on the prefix its own case registers. The record and metric stores are
// process-global and shared with the other test files in this binary, so an unanchored pattern would
// make each case's count depend on what its neighbours happened to register and on the order Catch2
// chose to run them in. Anchoring keeps every other name in the store a couple of steps from a
// verdict, so a case measures only the names it created.
std::string const CONFIG_REDOS_PATTERN = R"(^proxy\.config\.test\.redos\.[0-9]+\.(a+)+$)";
std::string const METRIC_REDOS_PATTERN = R"(^proxy\.process\.test\.redos\.(counter|string)\.(a+)+$)";
std::string const HIDDEN_REDOS_PATTERN = R"(^proxy\.process\.test\.redos\.hidden\.(a+)+$)";

CatchDiags *
clear_diags()
{
  CatchDiags *cdiag = static_cast<CatchDiags *>(diags());
  cdiag->messages.clear();
  return cdiag;
}

} // namespace

// The cap is what stops one admin_lookup_records pattern from backtracking without limit, and the
// report is what stops an abandoned lookup from answering short in silence. Both are asserted here
// on the record table, the exec() site RECT_CONFIG reaches.
//
// Deliberately no wall-clock assertion: it is the one kind of check here whose result depends on
// the machine, and it fails under valgrind or on a loaded CI host. What pins the cap instead is
// "installs the cap it reports" below, whose fixture lands between this cap and PCRE2's own much
// larger default so that removing the cap changes the observed outcome. This case does not pin it;
// its fixture exceeds both.
TEST_CASE("RecLookupMatchingRecords bounds regex backtracking", "[librecords][RecCore][redos]")
{
  constexpr int RECORD_COUNT = 2;

  for (int i = 0; i < RECORD_COUNT; ++i) {
    std::string const name = "proxy.config.test.redos." + std::to_string(i) + "." + REDOS_SUFFIX;
    REQUIRE(RecRegisterConfigInt(RECT_CONFIG, name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) == REC_ERR_OKAY);
  }

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, CONFIG_REDOS_PATTERN.c_str(), count_callback, &match_count, true, &indeterminate) ==
          REC_ERR_OKAY);

  CHECK(match_count == 0);
  CHECK(indeterminate == RECORD_COUNT);

  REQUIRE(cdiag->messages.size() == 1);
  CHECK(cdiag->messages[0].find("left 2 record name(s)") != std::string::npos);
  CHECK(cdiag->messages[0].find("results are incomplete") != std::string::npos);
  // Names the first undecided name's own cap, 67^2 for these 67 character names, and the ceiling it
  // is held under. The cases that fail when the cap stops being installed or scaled are "installs
  // the cap it reports" and "scales the step cap to the name" below; this only checks the message
  // reports it.
  CHECK(cdiag->messages[0].find("step cap 4489 for the first of them, scaled to name length up to 50000,") != std::string::npos);
}

// Metrics are two more exec() sites, reached only for RECT_PROCESS, RECT_NODE and RECT_PLUGIN. The
// RECT_CONFIG case above walks the record table instead, so it never enters them.
TEST_CASE("RecLookupMatchingRecords bounds regex backtracking for metrics", "[librecords][RecCore][redos]")
{
  REQUIRE(ts::Metrics::Counter::createPtr("proxy.process.test.redos.counter." + REDOS_SUFFIX) != nullptr);
  // createString returns void, so registration is confirmed by the lookup below reaching it.
  ts::Metrics::StaticString::createString("proxy.process.test.redos.string." + REDOS_SUFFIX, "value");

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_PROCESS, METRIC_REDOS_PATTERN.c_str(), count_callback, &match_count, true,
                                   &indeterminate) == REC_ERR_OKAY);

  // One name from each of the two loops, so the count is what shows both ran rather than just one.
  CHECK(indeterminate == 2);
  REQUIRE(cdiag->messages.size() == 1);
  CHECK(cdiag->messages[0].find("left 2 record name(s)") != std::string::npos);
}

// The fourth exec() site, reached only when RECT_HIDDEN_METRIC is requested, since hidden metrics
// are excluded even from RECT_ALL, see RecDefs.h. No case above sets that bit.
TEST_CASE("RecLookupMatchingRecords bounds regex backtracking for hidden metrics", "[librecords][RecCore][redos]")
{
  auto *m = ts::Metrics::Gauge::createHiddenPtr("proxy.process.test.redos.hidden." + REDOS_SUFFIX);

  REQUIRE(m != nullptr);

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_HIDDEN_METRIC, HIDDEN_REDOS_PATTERN.c_str(), count_callback, &match_count, true,
                                   &indeterminate) == REC_ERR_OKAY);

  // The hidden store is shared with the other test files in this binary, notably
  // test_RecHiddenMetricLookup.cc, so the anchored pattern rather than the store's contents is what
  // makes this count exact.
  CHECK(indeterminate == 1);
  REQUIRE(cdiag->messages.size() == 1);
  CHECK(cdiag->messages[0].find("left 1 record name(s)") != std::string::npos);
}

// Pins the cap itself, which no other case in this file can do.
//
// Every other fixture here uses a shape needing on the order of 2^40 steps, which exceeds both the
// cap installed by RecLookupMatchingRecords and PCRE2's own compiled-in default of 10,000,000. A
// private match context is created with pcre2_match_context_create(nullptr), and that does not mean
// unbounded: it means that default. So deleting the set_match_limit call swaps one cap for a much
// larger one, and to those fixtures the two are indistinguishable -- the suite would stay green
// with the guard gone.
//
// This fixture lands between them. Measured against PCRE2 10.47, two sequential ".*" proving no
// match over a 400 character name costs 70,499 steps with JIT and 70,126 without: past the 50,000
// cap, so the lookup is abandoned and counted, and far short of 10,000,000, so with no cap
// installed the same name resolves to an ordinary NOMATCH and nothing is counted. The assertion on
// the count therefore fails if the cap stops being installed, which is the security property this
// file is here to hold.
TEST_CASE("RecLookupMatchingRecords installs the cap it reports", "[librecords][RecCore][redos]")
{
  std::string const prefix = "proxy.config.test.midbound.";
  std::string const name   = prefix + std::string(400 - prefix.size(), 'x');

  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) == REC_ERR_OKAY);

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(^proxy\.config\.test\.midbound\..*.*[~=])", count_callback, &match_count, true,
                                   &indeterminate) == REC_ERR_OKAY);

  CHECK(match_count == 0);
  CHECK(indeterminate == 1);
  REQUIRE(cdiag->messages.size() == 1);
  // A 400 character name is past the 224 characters at which the scaled cap reaches the ceiling, so
  // it runs under the full 50,000. No case in this file separates a number read back from the match
  // context from the same number recomputed, because for every fixture here the two agree; what the
  // cases below pin is that the number tracks the name rather than any constant.
  CHECK(cdiag->messages[0].find("step cap 50000 for the first of them,") != std::string::npos);
}

// Regression for a pattern that exhausts a resource other than the step count.
//
// A recursive pattern recurses deeper than any practical JIT stack, so under JIT it reports
// PCRE2_ERROR_JIT_STACKLIMIT (-46) and without JIT it reports PCRE2_ERROR_RECURSELOOP (-52).
// Neither is PCRE2_ERROR_MATCHLIMIT (-47), so counting only -47 dropped every record while leaving
// the counter at zero: no warning, no error to the caller, and an empty result indistinguishable
// from "nothing matched".
//
// Which code appears is a property of the pattern here, not of the missing JIT stack: this one
// reports -46 even against the 1MB stack the thread-global context assigns, and even with no match
// limit set at all. The RPC-level counterpart is the left-recursive shape in
// tests/gold_tests/traffic_ctl/traffic_ctl_config_match_redos.test.py, which recurses before
// consuming anything: measured against PCRE2 10.47 it reaches the stack in 683 steps, under the
// 1,024 floor, so every name reports -46 whatever its length. A shape that consumes first, such as
// a bare "^(?:[a-z.]|(?R))*[~=]", exhausts the scaled cap of a short name before the stack and
// reports -47 instead.
//
// Recursion is confined to a named subroutine behind a literal prefix, rather than applied to the
// whole pattern with (?R). A bare recursive pattern is expensive against every all-lowercase dotted
// name, and some of those, including the long names the cases below register, exhaust the step count
// and so report MATCHLIMIT. That would let the pre-fix code count those names instead and satisfy
// this case for the wrong reason. Confining recursion keeps every name but this one a couple of
// steps from a clean verdict, so the count is exactly one and it is reached only through the code
// path this case exists to test.
TEST_CASE("RecLookupMatchingRecords reports resource failures other than the match limit", "[librecords][RecCore][redos]")
{
  static constexpr char RECURSIVE_PATTERN[] = R"(^proxy\.config\.test\.recursive\.(?<r>(?:[a-z.]|(?&r))*)[~=])";
  static constexpr char PROBE_NAME[]        = "proxy.config.test.recursive.probe";

  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, PROBE_NAME, 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) == REC_ERR_OKAY);

  // Ask this PCRE2 build which resource the pattern actually exhausts, rather than hardcoding a
  // code. The answer differs between a JIT and a non-JIT build, and ATS supports both: nothing in
  // the build system requires JIT and Regex::compile discards the result of pcre2_jit_compile.
  int expected_rc = 0;
  {
    Regex regex;

    REQUIRE(regex.compile(RECURSIVE_PATTERN, RE_CASE_INSENSITIVE | RE_UNANCHORED));

    RegexMatchContext match_context;

    // The cap the lookup installs for this 33 character name, 33^2, so the probe asks PCRE2 the
    // same question the lookup will.
    match_context.set_match_limit(1089);

    RegexMatches matches;

    expected_rc = regex.exec(PROBE_NAME, matches, 0, &match_context);

    // The premise of the case: this pattern yields no verdict for this name, and does so by
    // exhausting something other than the step count. Excluding MATCHLIMIT as well as NOMATCH
    // matters, because a PCRE2 that reported MATCHLIMIT here would leave the case passing against
    // the one code the pre-fix enumeration already handled, proving nothing. If a future PCRE2
    // resolves this pattern, or bounds it by step count, the case should be rewritten rather than
    // silently pass.
    REQUIRE(expected_rc < 0);
    REQUIRE(expected_rc != RE_ERROR_NOMATCH);
    REQUIRE(expected_rc != RE_ERROR_MATCHLIMIT);
  }

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, RECURSIVE_PATTERN, count_callback, &match_count, true, &indeterminate) ==
          REC_ERR_OKAY);

  CHECK(match_count == 0);
  CHECK(indeterminate == 1);
  REQUIRE(cdiag->messages.size() == 1);
  CHECK(cdiag->messages[0].find("results are incomplete") != std::string::npos);
  // Asserting the resource, not just the count, is what separates this fix from an enumeration
  // widened to include one more code: whichever code PCRE2 returns has to reach the operator.
  CHECK(cdiag->messages[0].find(Regex::get_error_string(expected_rc)) != std::string::npos);
}

// Counting rather than bailing out exists so that one undecided name does not cost the caller the
// records that were resolved. Nothing else in this file would notice a "stop the walk on the first
// resource failure" refactor: every other redos case expects zero matches, and every matching case
// expects no warning, so both would still pass.
TEST_CASE("RecLookupMatchingRecords returns matches alongside an undecided sibling", "[librecords][RecCore][redos]")
{
  std::string const redos_name = "proxy.config.test.mixed.redos." + REDOS_SUFFIX;

  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, redos_name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) ==
          REC_ERR_OKAY);
  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, "proxy.config.test.mixed.hit", 1, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) ==
          REC_ERR_OKAY);

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(^proxy\.config\.test\.mixed\.redos\.(a+)+$|^proxy\.config\.test\.mixed\.hit$)",
                                   count_callback, &match_count, true, &indeterminate) == REC_ERR_OKAY);

  CHECK(match_count == 1);
  CHECK(indeterminate == 1);
  REQUIRE(cdiag->messages.size() == 1);
  CHECK(cdiag->messages[0].find("left 1 record name(s)") != std::string::npos);
}

// The limit must also be loose enough for real lookups, or it silently drops records. Two sequential
// ".*" proving no match is the most expensive shape a legitimate caller is likely to write, at about
// N^2/2 steps for a backtracking run of length N.
//
// Here N is the 223 character run the two ".*" divide, not the 250 character name: the anchored
// prefix is consumed once and costs nothing further. That run needs about 24,900 steps, half of the
// 50,000 limit, so the case is insensitive to step-accounting differences between PCRE2 versions,
// yet 2.5x above 10,000, so reverting the limit to that or to 1750 fails here rather than quietly
// truncating in production. Measured against PCRE2 10.47, this shape resolves names up to 340
// characters, and is bounded by the step limit rather than the JIT stack at every length.
TEST_CASE("RecLookupMatchingRecords does not truncate legitimate lookups", "[librecords][RecCore]")
{
  std::string const prefix = "proxy.config.test.longname.";
  std::string const name   = prefix + std::string(250 - prefix.size(), 'x');

  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) == REC_ERR_OKAY);

  CatchDiags *cdiag = clear_diags();

  // Anchoring on the prefix keeps every other registered name to a couple of steps, so this
  // measures the long name and nothing else.
  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(^proxy\.config\.test\.longname\..*.*[~=])", count_callback, &match_count, true,
                                   &indeterminate) == REC_ERR_OKAY);

  CHECK(match_count == 0);
  CHECK(indeterminate == 0);
  CHECK(cdiag->messages.empty());
}

TEST_CASE("RecLookupMatchingRecords still matches ordinary patterns", "[librecords][RecCore]")
{
  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, "proxy.config.test.lookup.plain", 7, RECU_DYNAMIC, RECC_NULL, nullptr,
                               REC_SOURCE_NULL) == REC_ERR_OKAY);

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(proxy\.config\.test\.lookup\.plain)", count_callback, &match_count, true,
                                   &indeterminate) == REC_ERR_OKAY);

  CHECK(match_count == 1);
  CHECK(indeterminate == 0);
}

TEST_CASE("RecLookupMatchingRecords refuses a pattern that switches on UTF mode", "[librecords][RecCore][redos]")
{
  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, "proxy.config.test.lookup.utf", 7, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) ==
          REC_ERR_OKAY);

  CatchDiags *cdiag = clear_diags();

  // In UTF mode pcre2 validates each subject as UTF-8 before matching it, so a record name holding
  // a byte that is not valid UTF-8 comes back as PCRE2_ERROR_UTF8_ERR* -- a negative code that is
  // not NOMATCH, which the lookup counts as undecided. One verb from the caller would therefore
  // report the whole lookup incomplete over names the pattern does not match. The verb is refused
  // only here; operator-written patterns elsewhere are documented to be allowed to use it, which
  // src/tsutil/unit_tests/test_Regex.cc pins from the other side.
  //
  // It is not a backtracking bound: measured against PCRE2 10.47 a (*UTF) pattern JIT-compiles and
  // stays on the JIT, hitting the same limits as the same pattern without it.
  int match_count = 0;

  // Poisoned rather than zeroed, so this also pins that the lookup zeroes the out parameter before
  // it can fail. Every caller in the tree happens to pre-zero its own variable, which would hide a
  // regression here until one did not.
  unsigned indeterminate = 0xDEADBEEF;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"((*UTF)proxy\.config\.test\.lookup\.utf)", count_callback, &match_count, true,
                                   &indeterminate) == REC_ERR_FAIL);

  // Refused at compile, so nothing was walked: no matches, and no name left undecided either.
  CHECK(match_count == 0);
  CHECK(indeterminate == 0);

  // REQUIRE, not CHECK, because the index below is only safe once the size is known. Asserting
  // PCRE2's own wording as well as our prefix is what distinguishes this refusal from the several
  // other ways a pattern can fail to compile, which all reach the same log line.
  REQUIRE(cdiag->messages.size() == 1);
  CHECK(cdiag->messages[0].find("failed to compile") != std::string::npos);
  CHECK(cdiag->messages[0].find("using UTF is disabled by the application") != std::string::npos);

  // Same pattern without the verb still matches, so the refusal is the verb and not the name.
  match_count   = 0;
  indeterminate = 0;
  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(proxy\.config\.test\.lookup\.utf)", count_callback, &match_count, true,
                                   &indeterminate) == REC_ERR_OKAY);
  CHECK(match_count == 1);
  CHECK(indeterminate == 0);
}

TEST_CASE("RecLookupMatchingRecords counts a match whose captures overflow the ovector", "[librecords][RecCore][redos]")
{
  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, "proxy.config.test.lookup.groups", 7, RECU_DYNAMIC, RECC_NULL, nullptr,
                               REC_SOURCE_NULL) == REC_ERR_OKAY);

  CatchDiags *cdiag = clear_diags();

  // pcre2_match has three kinds of return, not two, and the third is easy to lose. A pattern with
  // more capture groups than the match data has slots -- RegexMatches defaults to 10, so eleven
  // groups is enough -- matches and returns 0, meaning "matched, but the ovector was too small to
  // report every group". Measured against PCRE2 10.47: capture count 11, ovector slots 10, rc 0.
  //
  // 0 is not negative, so the classification must treat it as the match it is. Narrowing the test
  // to `rc > 0` would silently reclassify every such match as an undecided name: the record would
  // vanish from the results and the caller would be told the list is incomplete, for a pattern that
  // matched perfectly well. No other fixture in this file uses more than a handful of groups, so
  // this is the only one that holds that line.
  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(^((p)(r)(o)(x)(y)(\.)(c)(o)(n)(f))ig\.test\.lookup\.groups$)", count_callback,
                                   &match_count, true, &indeterminate) == REC_ERR_OKAY);

  CHECK(match_count == 1);
  CHECK(indeterminate == 0);
  CHECK(cdiag->messages.empty());
}

TEST_CASE("RecLookupMatchingRecords sums both stores into one report under RECT_ALL", "[librecords][RecCore][redos]")
{
  // RECT_ALL is what an admin_lookup_records element asks for when it names no rec_types
  // (src/mgmt/rpc/handlers/records/Records.cc), so it is the lookup an unauthenticated caller gets
  // by default, and it is the default walk that crosses both stores, the metric loops and the
  // config record table. Any mask mixing a config bit with a metric bit crosses them too. Every case
  // above reaches one store at a time, which leaves untested the property that only appears when
  // both are involved: undecided names from the two are summed into one count and reported in one
  // warning, rather than one store's report replacing the other's or the lookup reporting once per
  // store.
  std::string const config_name = "proxy.config.test.rectall." + REDOS_SUFFIX;
  std::string const metric_name = "proxy.process.test.rectall." + REDOS_SUFFIX;

  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, config_name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) ==
          REC_ERR_OKAY);
  REQUIRE(ts::Metrics::Counter::createPtr(metric_name) != nullptr);

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  // The literal prefix confines the backtracking to these two names: every other name this binary
  // registers fails it within a few steps.
  REQUIRE(RecLookupMatchingRecords(RECT_ALL, R"(^proxy\.(config|process)\.test\.rectall\.(a+)+$)", count_callback, &match_count,
                                   true, &indeterminate) == REC_ERR_OKAY);

  CHECK(match_count == 0);
  CHECK(indeterminate == 2);
  REQUIRE(cdiag->messages.size() == 1);
  CHECK(cdiag->messages[0].find("left 2 record name(s)") != std::string::npos);
}

// Pins the scaling, which no case above can do: each name they register gets the same verdict
// under the scaled cap as under a flat 50,000.
//
// This name sits between the two bounds. Measured against PCRE2 10.47, "(a+)+$" over a 12 'a' run
// that ends in 'z' needs 8,190 steps to prove no match with JIT and 10,240 without. The name is 38
// characters, so its cap is 38^2 = 1,444: the lookup gives up on it and counts it. Under a flat
// 50,000 the same name resolves to an ordinary NOMATCH and nothing is counted, so this fails if the
// cap stops being scaled.
TEST_CASE("RecLookupMatchingRecords scales the step cap to the name", "[librecords][RecCore][redos]")
{
  std::string const name = "proxy.config.test.scaled." + std::string(12, 'a') + "z";

  REQUIRE(name.size() == 38);
  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) == REC_ERR_OKAY);

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(^proxy\.config\.test\.scaled\.(a+)+$)", count_callback, &match_count, true,
                                   &indeterminate) == REC_ERR_OKAY);

  CHECK(match_count == 0);
  CHECK(indeterminate == 1);
  REQUIRE(cdiag->messages.size() == 1);
  CHECK(cdiag->messages[0].find("step cap 1444 for the first of them,") != std::string::npos);
}

// Pins the floor. Scaling alone would give a short name almost no room: L^2 is 121 steps for this
// 11 character name, less than the "(a+)+$" over its 7 'a' run needs to prove no match, which is 254
// steps with JIT and 320 without (PCRE2 10.47). The 1,024 floor lets it resolve, so this fails if
// the floor is dropped and the lookup starts truncating ordinary patterns on short names.
TEST_CASE("RecLookupMatchingRecords keeps a floor under the step cap for short names", "[librecords][RecCore][redos]")
{
  std::string const name = "fl." + std::string(7, 'a') + "z";

  REQUIRE(name.size() == 11);
  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) == REC_ERR_OKAY);

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(^fl\.(a+)+$)", count_callback, &match_count, true, &indeterminate) ==
          REC_ERR_OKAY);

  CHECK(match_count == 0);
  CHECK(indeterminate == 0);
  CHECK(cdiag->messages.empty());
}

// The warning names the cap of the FIRST undecided name. Every case above that leaves several names
// undecided gives them the same length, and the name walked last is always one of the case's own, so
// reporting the last undecided name's cap -- or reading the context after the loop, as the code did
// when the cap was flat -- satisfies them all. Here the two undecided names differ in length, and a
// third name of a third length is registered after them.
TEST_CASE("RecLookupMatchingRecords reports the first undecided name's cap", "[librecords][RecCore][redos]")
{
  std::string const first  = "proxy.config.test.capfirst." + REDOS_SUFFIX;      // 27 + 41 = 68 -> 4624
  std::string const second = "proxy.config.test.capfirst.bbbb." + REDOS_SUFFIX; // 32 + 41 = 73 -> 5329
  std::string const last   = "proxy.config.test.capfirst.c";                    // decided, registered last

  REQUIRE(first.size() == 68);
  REQUIRE(second.size() == 73);
  for (auto const &name : {first, second, last}) {
    REQUIRE(RecRegisterConfigInt(RECT_CONFIG, name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) == REC_ERR_OKAY);
  }

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(^proxy\.config\.test\.capfirst\.(bbbb\.)?(a+)+$)", count_callback, &match_count,
                                   true, &indeterminate) == REC_ERR_OKAY);

  CHECK(indeterminate == 2);
  REQUIRE(cdiag->messages.size() == 1);
  INFO(cdiag->messages[0]);
  CHECK(cdiag->messages[0].find("step cap 4624 for the first of them,") != std::string::npos);
}

// Pins the floor's value, which the case above it does not: that fixture needs about 320 steps, so a
// floor of 512 would satisfy it too. 24 characters squared is 576, below the floor, so the cap this
// name runs under can only be the floor itself.
TEST_CASE("RecLookupMatchingRecords installs the floor itself on a short name", "[librecords][RecCore][redos]")
{
  std::string const name = "afl." + std::string(19, 'a') + "z";

  REQUIRE(name.size() == 24);
  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) == REC_ERR_OKAY);

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(^afl\.(a+)+$)", count_callback, &match_count, true, &indeterminate) ==
          REC_ERR_OKAY);

  CHECK(indeterminate == 1);
  REQUIRE(cdiag->messages.size() == 1);
  INFO(cdiag->messages[0]);
  CHECK(cdiag->messages[0].find("step cap 1024 for the first of them,") != std::string::npos);
}

// Between the floor and the ceiling the cap is the square. The other cases use names of 11, 24, 33,
// 38, 67, 68, 73, 250 and 400 characters, so nothing between 74 and 223 is pinned, and a ceiling
// shortcut taken from any length in that range would satisfy all of them. 150 squared is 22,500.
TEST_CASE("RecLookupMatchingRecords squares a mid-range name rather than taking the ceiling", "[librecords][RecCore][redos]")
{
  std::string const prefix = "proxy.config.test.midrange.";
  std::string const name   = prefix + std::string(150 - prefix.size() - 1, 'a') + "z";

  REQUIRE(name.size() == 150);
  REQUIRE(RecRegisterConfigInt(RECT_CONFIG, name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) == REC_ERR_OKAY);

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(^proxy\.config\.test\.midrange\.(a+)+$)", count_callback, &match_count, true,
                                   &indeterminate) == REC_ERR_OKAY);

  CHECK(indeterminate == 1);
  REQUIRE(cdiag->messages.size() == 1);
  INFO(cdiag->messages[0]);
  CHECK(cdiag->messages[0].find("step cap 22500 for the first of them,") != std::string::npos);
}

// "does not truncate legitimate lookups" above uses a 250 character name, which sits at the ceiling
// and so says nothing about the range every real name is in. This asks the two-".*" shape of every
// name shorter than 224 characters, which is where the scaled cap actually applies, so halving the
// scaling is caught by a truncated lookup rather than only by the number in the message.
TEST_CASE("RecLookupMatchingRecords does not truncate two wildcards in the scaled range", "[librecords][RecCore]")
{
  for (size_t len : {12, 24, 32, 40, 64, 100, 150, 200, 223}) {
    std::string const prefix = "sr." + std::to_string(len) + ".";
    std::string const name   = prefix + std::string(len - prefix.size(), 'x');

    REQUIRE(name.size() == len);
    REQUIRE(RecRegisterConfigInt(RECT_CONFIG, name.c_str(), 0, RECU_DYNAMIC, RECC_NULL, nullptr, REC_SOURCE_NULL) == REC_ERR_OKAY);
  }

  CatchDiags *cdiag = clear_diags();

  int      match_count   = 0;
  unsigned indeterminate = 0;

  // The lookahead refuses a longer subject outright, so the names other cases register at the
  // ceiling are not what this measures.
  REQUIRE(RecLookupMatchingRecords(RECT_CONFIG, R"(^(?=.{0,223}$).*.*[~=])", count_callback, &match_count, true, &indeterminate) ==
          REC_ERR_OKAY);

  CHECK(match_count == 0);
  CHECK(indeterminate == 0);
  if (!cdiag->messages.empty()) {
    INFO(cdiag->messages[0]);
  }
  CHECK(cdiag->messages.empty());
}
