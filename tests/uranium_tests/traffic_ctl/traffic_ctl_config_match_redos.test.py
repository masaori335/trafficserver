#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import sys

# To include util classes
sys.path.insert(0, f'{Test.TestDirectory}')

from jsonrpc import Request, Response
from traffic_ctl_test_utils import Make_traffic_ctl

Test.Summary = '''
Test that the backtracking cap applies to traffic_ctl config match and metric match, and that a
lookup the regex engine abandoned is reported to the caller rather than returned as a short answer.

This does not establish that the RPC server cannot be stalled. The cap counts backtracking steps,
not work, and the reporting is keyed on the engine's own resource errors, so an expensive pattern
that still reaches a verdict on every name is neither capped nor reported here.
'''

Test.ContinueOnFail = True

# "([a-z.]+)+" can partition a run of letters and dots a great many ways, and the trailing class
# holds characters no name contains, so the match can never complete. Lookups are case insensitive,
# so the run is ended only by a digit or an underscore, not by capitals.
#
# No crafted records are needed, but the margin is narrower than it looks. Measured against PCRE2
# 10.47, a run of 15 characters is the shortest that exceeds the limit, and the shortest leading run
# among the 582 names records.yaml registers is exactly 15 -- "proxy.config.io_uring", ended by its
# underscore. Nothing that ships is below that, so every config record is undecided under this
# pattern, which is what the reported count reflects. Against a stock server's names this costs
# roughly 20s of CPU unbounded, against about 120ms once the match limit applies.
#
# Two details are load bearing. The tail must be a character class rather than a literal, because
# for an absent literal PCRE2's required-code-unit check rejects each name up front and no
# backtracking happens, leaving the test to pass with or without the fix. And it must be
# unsatisfiable rather than merely unlikely; an earlier "[0-9]\z" tail matched
# proxy.config.ssl.TLSv1, as lookups are case insensitive. The "(a+)+$" from the original report is
# useless here, no real name holds two consecutive 'a' characters to backtrack over.
REDOS_PATTERN = '^([a-z.]+)+[~=]'

# This shape exhausts the JIT stack before the step count, so PCRE2 reports
# PCRE2_ERROR_JIT_STACKLIMIT (-46) rather than PCRE2_ERROR_MATCHLIMIT (-47). That depends on the
# headroom, not on the pattern alone: measured against PCRE2 10.47 it reports -46 on the default
# 32KB block these lookups run with, and -47 once given a 32769 byte stack. Classifying only the
# step count as "no verdict" let this shape drop every record while reporting nothing at all: empty
# output, no diags entry and a zero exit status, indistinguishable from a pattern that legitimately
# matched nothing. It is covered here as well as in the unit tests because the RPC path is where an
# unauthenticated caller reaches it.
#
# The stdout and exit status below are what this case pins. Its diags.log line is not asserted,
# because the warning is throttled per call site and the lookup above has already emitted one within
# the interval, so this one is suppressed by design. Coverage of the -46 error text reaching the log
# lives in src/records/unit_tests/test_RecLookupMatchingRecords.cc, where no throttle is active.
RECURSIVE_PATTERN = '^(?:[a-z.]|(?R))*[~=]'

# A truncated lookup is a partial answer, not a failed one, so traffic_ctl reports it through the
# error list, which sets exit status CTRL_EX_ERROR.
CTRL_EX_ERROR = 2

records_yaml = '''
    diags:
      debug:
        enabled: 0
    '''

traffic_ctl = Make_traffic_ctl(Test, records_yaml)

# The bound holds, and the truncation is reported to the caller rather than presented as an empty
# result. Returning promptly is half the point; saying the answer is short is the other half.
traffic_ctl.config().match(f"'{REDOS_PATTERN}'") \
    .validate_contains_all("Errors", "the returned list is incomplete") \
    .validate_with_exit_code(CTRL_EX_ERROR)

# Same, for the resource failure that is not the step limit. Before the classification fix this
# command printed nothing, logged nothing and exited 0.
traffic_ctl.config().match(f"'{RECURSIVE_PATTERN}'") \
    .validate_contains_all("Errors", "the returned list is incomplete") \
    .validate_with_exit_code(CTRL_EX_ERROR)

# The metric lookup reaches the same bounded regex walk through a different printer, which formats
# the error list separately from the config one.
traffic_ctl.metric().match(f"'{REDOS_PATTERN}'") \
    .validate_contains_all("Errors", "the returned list is incomplete") \
    .validate_with_exit_code(CTRL_EX_ERROR)

# The JSON format takes a different path out of BasePrinter, which returns as soon as it has
# emitted the response. A truncated lookup there used to exit zero while the text form exited 2, so
# a script asking for JSON -- the callers most likely to ask -- received a partial answer and read
# it as complete. The record errors travel inside the JSON result either way, so it is only the
# status that had to be fixed.
traffic_ctl.config().match(f"'{REDOS_PATTERN}'").as_json() \
    .validate_contains_all("errorList", "the returned list is incomplete") \
    .validate_with_exit_code(CTRL_EX_ERROR)

# Same again for the metric printer, which is a separate class reaching the JSON exit-status hook
# by its own route. Covering only the config half would leave the two printers' JSON paths pinned
# unequally, and an unpinned printer is exactly how the describe printer shipped still exiting 0.
traffic_ctl.metric().match(f"'{REDOS_PATTERN}'").as_json() \
    .validate_contains_all("errorList", "the returned list is incomplete") \
    .validate_with_exit_code(CTRL_EX_ERROR)

# Teaching MetricRecordPrinter to print the error list is what makes "metric match" report
# truncation, but that printer also backs "metric get", so a failing metric get now reports the
# error and exits non-zero where it used to print nothing and exit 0. That matches what "config get"
# has always done for an unknown record. Pinned here because it is a visible change to a scripted
# command rather than a side effect worth discovering later.
traffic_ctl.metric().get("proxy.process.test.no.such.metric") \
    .validate_contains_all("Errors", "Record not found") \
    .validate_with_exit_code(CTRL_EX_ERROR)

# config reset sends the path it is given as a regex too, so it reaches the same bounded lookup, but
# it is a write: it resets whatever the lookup returned. A truncated lookup there would write an
# arbitrary subset of what the operator named, so it has to refuse rather than proceed.
traffic_ctl.config().reset(f"'{REDOS_PATTERN}'") \
    .validate_contains_all("Not resetting any record", "the returned list is incomplete") \
    .validate_with_exit_code(CTRL_EX_ERROR)

# A leading (*UTF) puts the engine in UTF mode, where pcre2 validates each subject as UTF-8 before
# matching it. A record name is a byte string, so a name that is not valid UTF-8 comes back as an
# error rather than a verdict and is counted undecided -- one verb from the caller reporting the
# whole lookup incomplete over names the pattern does not match. The lookup asks Regex to refuse
# the verb; operator-written patterns elsewhere may still use it, which
# src/tsutil/unit_tests/test_Regex.cc pins from the other side.
#
# The stdout assertion alone is weak: a compile failure surfaces as a general read error, the same
# answer "proxy.config.(" has always produced. The diags.log assertion further down carries PCRE2's
# own wording for this refusal, which is what tells the two apart.
traffic_ctl.config().match(r"'(*UTF)proxy\.config\..*'") \
    .validate_contains_all("Errors", "Error reading the record") \
    .validate_with_exit_code(CTRL_EX_ERROR)

# RecordDescribePrinter reports the error list too, so "config describe" of a record the lookup
# cannot return exits non-zero on the JSON path as well as the text one. Pinned because the JSON
# path used to exit 0 here while the text path exited 2, which is the divergence that made a script
# asking for JSON read a failure as a success.
traffic_ctl.config().describe("proxy.config.test.no.such.record").as_json() \
    .validate_with_exit_code(CTRL_EX_ERROR)

# One element can both leave names undecided and refuse a record, and ctx.ec in
# get_record_regex_impl (src/mgmt/rpc/handlers/common/RecordsUtils.cc) holds one code, so the two
# compete for it. The truncation has to win, or the caller is told the list is complete.
# traffic_ctl's config and metric commands cannot reach that branch, because their type sets are
# fixed. A raw request naming RECT_NODE alone does: the metric loops run for RECT_NODE but tag
# every metric they find RECT_PROCESS, so a metric the pattern matches is then refused as the wrong
# type, while the second alternative leaves other names undecided.
#
# The first alternative matches a metric every server registers. The caller must see
# LOOKUP_INCOMPLETE and not REQUESTED_TYPE_MISMATCH, and the displaced cause goes to diags.log
# instead (asserted below). Restoring the early return that preceded this hands the caller the type
# mismatch alone and drops the truncation, which fails both.
RECT_NODE = 4
REQUESTED_TYPE_MISMATCH = 2007
LOOKUP_INCOMPLETE = 2011
PRECEDENCE_PATTERN = r'^proxy\.process\.http\.completed_requests$|' + REDOS_PATTERN


def check_truncation_wins(resp: Response):
    if resp.is_error():
        return (False, resp.error_as_str())
    codes = [int(e['code']) for e in resp.result.get('errorList', [])]
    if LOOKUP_INCOMPLETE not in codes:
        return (False, f"the truncation should win the element's error code, got {codes}")
    if REQUESTED_TYPE_MISMATCH in codes:
        return (False, f"the displaced type mismatch should reach the log, not the caller, got {codes}")
    return (True, "truncation reported to the caller, displaced cause kept off it")


tr = Test.AddTestRun("a lookup that both truncates and refuses a record reports the truncation")
tr.AddJsonRPCClientRequest(
    traffic_ctl.ts, Request.admin_lookup_records([{
        "record_name_regex": PRECEDENCE_PATTERN,
        "rec_types": [str(RECT_NODE)]
    }]))
tr.Processes.Default.Streams.stdout = Testers.CustomJSONRPCResponse(check_truncation_wins)
tr.StillRunningAfter = traffic_ctl.ts

# An ordinary lookup afterwards shows the RPC server was left responsive rather than wedged, and
# that an untruncated lookup still reports no error and exits zero.
traffic_ctl.config().match("proxy.config.diags.debug.enabled") \
    .validate_with_text("proxy.config.diags.debug.enabled: 0")

# The operator-facing half of the report. Unlike a timing check, this assertion does not depend on
# machine speed.
traffic_ctl.ts.Disk.diags_log.Content += Testers.IncludesExpression(
    "results are incomplete", "the truncated lookup should be reported, not silently returned as a short answer")

# Pins the value of the bound itself. Every other assertion here passes just as well on a build
# whose limit has been raised back to PCRE2's 10,000,000 default, which is the vulnerability. Matched
# with the words before it so a stray "50000" elsewhere in the log cannot satisfy it, and with the
# comma after it so a cap of 500000 or 5000000 cannot either.
traffic_ctl.ts.Disk.diags_log.Content += Testers.IncludesExpression(
    "step cap in effect 50000,", "the log should name the cap installed on the match context, not a compile-time constant")

# Identifies the (*UTF) refusal above as that refusal, rather than as any of the other ways a
# pattern can fail to compile. The wording is PCRE2's own, so it cannot be produced by a pattern
# that was mangled before it reached pcre2_compile.
traffic_ctl.ts.Disk.diags_log.Content += Testers.IncludesExpression(
    "failed to compile at offset 6: using UTF is disabled by the application",
    "the (*UTF) pattern should be refused by the never-UTF flag, naming the verb's offset")

# The cause the truncation displaced in the RECT_NODE case above is logged rather than dropped, so
# the operator still learns why a record was refused.
traffic_ctl.ts.Disk.diags_log.Content += Testers.IncludesExpression(
    "and also refused a record", "the error the truncation displaced should be logged rather than dropped")
