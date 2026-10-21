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

import json
import re
import time

from tools.uranium.services import ATS, CommandResult, wait_for_file_lines
from uranium_tests.lib.jsonrpc import Request

# "([a-z.]+)+" can partition a run of letters and dots a great many ways, and the trailing class
# holds characters no name contains, so the match can never complete. Lookups are case insensitive,
# so the run is ended only by a digit or an underscore, not by capitals.
#
# No crafted records are needed, but the margin is narrower than it looks. Measured against PCRE2
# 10.47, proving no match over a leading run of k characters costs 2^(k+1)-2 steps under the JIT and
# 3*2^k on the interpreter, so a run of 10 characters already exceeds the 1,024 smallest cap a name
# gets either way, and the shortest leading run among the names records.yaml registers is 15
# ("proxy.config.io_uring", ended by its underscore). Nothing that ships is below that, so every
# config record is undecided under this pattern, which is what the reported count reflects.
#
# Two details are load bearing. The tail must be a character class rather than a literal, because
# for an absent literal PCRE2's required-code-unit check rejects each name up front and no
# backtracking happens, leaving the test to pass with or without the cap. And it must be
# unsatisfiable rather than merely unlikely; an earlier "[0-9]\z" tail matched
# proxy.config.ssl.TLSv1, as lookups are case insensitive.
BACKTRACKING_PATTERN = '^([a-z.]+)+[~=]'

# This shape exhausts a resource other than the step count, so PCRE2 reports something other than
# PCRE2_ERROR_MATCHLIMIT (-47). The recursion comes first in the group, so each name recurses at the
# same position without consuming anything: the JIT runs out of stack and reports
# PCRE2_ERROR_JIT_STACKLIMIT (-46), and the interpreter detects the loop and reports
# PCRE2_ERROR_RECURSELOOP (-52). Every name gets that code under both the scaled step cap and a flat
# 50,000, so the case does not depend on how small a name's cap is.
#
# Classifying only the step count as "no verdict" let this shape drop every record while reporting
# nothing at all: empty output, no diags entry and a zero exit status, indistinguishable from a
# pattern that legitimately matched nothing.
#
# The stdout and exit status are what this case pins. Its diags.log line is not asserted, because
# the warning is throttled per call site and the lookup above has already emitted one within the
# interval, so this one is suppressed by design. Coverage of the -46 error text reaching the log
# lives in src/records/unit_tests/test_RecLookupMatchingRecords.cc, where no throttle is active.
RECURSIVE_PATTERN = '^(?:(?R)|[a-z.])*[~=]'

# A truncated lookup is a partial answer, not a failed one, so traffic_ctl reports it through the
# error list, which sets exit status CTRL_EX_ERROR.
CTRL_EX_ERROR = 2

# One lookup under the cap takes about 10ms including the traffic_ctl start, and the same lookup
# without the cap takes several seconds, so the bound sits well clear of both.
LOOKUP_SECONDS = 1.0

RECT_NODE = 4
REQUESTED_TYPE_MISMATCH = 2007
LOOKUP_INCOMPLETE = 2011


def match(*arguments: str, ats: ATS) -> CommandResult:
    """Run a traffic_ctl lookup, require exit status 2 and a bounded run time.

    :param arguments: traffic_ctl arguments.
    :param ats: Running Traffic Server instance.
    """

    began = time.monotonic()
    result = ats.traffic_ctl(*arguments)
    elapsed = time.monotonic() - began
    assert elapsed < LOOKUP_SECONDS, f"the lookup took {elapsed:.1f}s\n{result.output}"
    assert result.returncode == CTRL_EX_ERROR, result.output
    return result


INCOMPLETE = "the returned list is incomplete"


def start(ats: ATS) -> None:
    """Start Traffic Server with debug output off, so only the warnings under test reach diags.log.

    :param ats: Fresh Traffic Server instance.
    """

    ats.records.update({"proxy.config.diags.debug.enabled": 0})
    ats.start()


def test_traffic_ctl_config_match_limit_text(ats: ATS) -> None:
    """Backtracking is capped for config and metric lookups, and an abandoned lookup is reported to the caller.

    The cap counts backtracking steps, not work, and the reporting is keyed on the engine's own resource errors, so an
    expensive pattern that still reaches a verdict on every name is neither capped nor reported here.

    :param ats: Fresh Traffic Server instance.
    """

    start(ats)

    # The bound holds, and the truncation is reported to the caller rather than presented as an empty
    # result. Returning promptly is half the point; saying the answer is short is the other half.
    result = match("config", "match", BACKTRACKING_PATTERN, ats=ats)
    assert "Errors" in result.stdout and INCOMPLETE in result.stdout, result.output

    # Same, for the resource failure that is not the step limit. Before the classification fix this
    # command printed nothing, logged nothing and exited 0.
    result = match("config", "match", RECURSIVE_PATTERN, ats=ats)
    assert "Errors" in result.stdout and INCOMPLETE in result.stdout, result.output

    # The metric lookup reaches the same bounded walk through a different printer, which formats the
    # error list separately from the config one.
    result = match("metric", "match", BACKTRACKING_PATTERN, ats=ats)
    assert "Errors" in result.stdout and INCOMPLETE in result.stdout, result.output

    # An ordinary lookup afterwards shows the RPC server was left responsive, and that an
    # untruncated lookup still reports no error and exits zero.
    result = ats.traffic_ctl("config", "match", "proxy.config.diags.debug.enabled")
    assert result.returncode == 0, result.output
    assert "proxy.config.diags.debug.enabled: 0" in result.stdout, result.output

    # The operator-facing half of the report. Unlike a timing check, this does not depend on
    # machine speed.
    log = wait_for_file_lines(ats.diags_log, "results are incomplete", 1)

    # Pins the value of the bound itself. Every other assertion here passes just as well on a build
    # whose limit has been raised back to PCRE2's 10,000,000 default. The first warning comes from
    # the config lookup above, and names the cap of the first config record it left undecided. Every
    # config name is 21 to 62 characters, so its cap is that length squared held at 1,024 or more:
    # four digits. A flat 50,000 has five, so this also fails if the cap stops being scaled. The
    # ceiling is matched with the comma after it so a ceiling of 500000 or 5000000 cannot satisfy it.
    assert re.search("step cap [0-9]{4} for the first of them, scaled to name length up to 50000,", log), log


def test_traffic_ctl_config_match_limit_json(ats: ATS) -> None:
    """A truncated lookup exits non-zero in JSON format as well as text.

    The JSON format takes a different path out of BasePrinter, which returns as soon as it has emitted the response. A
    truncated lookup there used to exit zero while the text form exited 2, so a script asking for JSON received a
    partial answer and read it as complete. The metric printer is a separate class reaching the exit-status hook by its
    own route, and the describe printer a third, so each is pinned.

    :param ats: Fresh Traffic Server instance.
    """

    start(ats)
    for noun in ("config", "metric"):
        result = match(noun, "match", BACKTRACKING_PATTERN, "-f", "json", ats=ats)
        assert "errorList" in result.stdout and INCOMPLETE in result.stdout, result.output

    # "config describe" of a record the lookup cannot return exits non-zero on the JSON path as well
    # as the text one. The JSON path used to exit 0 here while the text path exited 2.
    match("config", "describe", "proxy.config.test.no.such.record", "-f", "json", ats=ats)


def test_traffic_ctl_metric_get_unknown(ats: ATS) -> None:
    """A failing metric get reports the error and exits non-zero.

    Teaching the metric printer to print the error list is what makes "metric match" report truncation, but that
    printer also backs "metric get", so a failing metric get used to print nothing and exit 0. That matches what
    "config get" has always done for an unknown record.

    :param ats: Fresh Traffic Server instance.
    """

    start(ats)
    result = ats.traffic_ctl("metric", "get", "proxy.process.test.no.such.metric")
    assert result.returncode == CTRL_EX_ERROR, result.output
    assert "Errors" in result.stdout and "Record not found" in result.stdout, result.output


def test_traffic_ctl_config_reset_truncated(ats: ATS) -> None:
    """A reset whose lookup was cut short refuses rather than resetting a subset.

    config reset sends the path it is given as a regex too, so it reaches the same bounded lookup, but it is a write: it
    resets whatever the lookup returned. A truncated lookup there would write an arbitrary subset of what the operator
    named.

    :param ats: Fresh Traffic Server instance.
    """

    start(ats)
    result = match("config", "reset", BACKTRACKING_PATTERN, ats=ats)
    assert "Not resetting any record" in result.stdout and INCOMPLETE in result.stdout, result.output


def test_traffic_ctl_config_match_utf_verb(ats: ATS) -> None:
    """A pattern opening with (*UTF) is refused by the lookup.

    The verb puts the engine in UTF mode, where pcre2 validates each subject as UTF-8 before matching it. A record name
    is a byte string, so a name that is not valid UTF-8 comes back as an error rather than a verdict and is counted
    undecided: one verb from the caller reporting the whole lookup incomplete over names the pattern does not match. The
    lookup asks Regex to refuse the verb; operator-written patterns elsewhere may still use it, which
    src/tsutil/unit_tests/test_Regex.cc pins from the other side.

    :param ats: Fresh Traffic Server instance.
    """

    start(ats)
    result = match("config", "match", r"(*UTF)proxy\.config\..*", ats=ats)
    assert "Errors" in result.stdout and "Error reading the record" in result.stdout, result.output

    # The stdout assertion alone is weak: any compile failure surfaces as the same read error. The
    # wording is PCRE2's own, so it cannot be produced by a pattern that was mangled before it reached
    # pcre2_compile, and it identifies the refusal of the verb at its offset.
    log = wait_for_file_lines(ats.diags_log, "failed to compile", 1)
    assert "failed to compile at offset 6: using UTF is disabled by the application" in log, log


def test_traffic_ctl_config_match_limit_error_precedence(ats: ATS) -> None:
    """A lookup that both leaves names undecided and refuses a record reports the truncation.

    One element can do both, and ctx.ec in get_record_regex_impl (src/mgmt/rpc/handlers/common/RecordsUtils.cc) holds
    one code, so the two compete for it. The truncation has to win, or the caller is told the list is complete.
    traffic_ctl's config and metric commands cannot reach that branch, because their type sets are fixed. A raw request
    naming RECT_NODE alone does: the metric loops run for RECT_NODE but tag every metric they find RECT_PROCESS, so a
    metric the pattern matches is then refused as the wrong type, while the second alternative leaves other names
    undecided.

    The first alternative matches a metric every server registers. The caller must see LOOKUP_INCOMPLETE and not
    REQUESTED_TYPE_MISMATCH, and the displaced cause goes to diags.log instead.

    :param ats: Fresh Traffic Server instance.
    """

    start(ats)
    pattern = r'^proxy\.process\.http\.completed_requests$|' + BACKTRACKING_PATTERN
    began = time.monotonic()
    result = ats.rpc(Request.admin_lookup_records([{"record_name_regex": pattern, "rec_types": [str(RECT_NODE)]}]))
    elapsed = time.monotonic() - began
    assert result.returncode == 0, result.output
    assert elapsed < LOOKUP_SECONDS, f"the lookup took {elapsed:.1f}s\n{result.output}"
    response = json.loads(result.stdout)
    assert "error" not in response, response
    codes = [int(error["code"]) for error in response["result"].get("errorList", [])]
    assert LOOKUP_INCOMPLETE in codes, f"the truncation should win the element's error code, got {codes}"
    assert REQUESTED_TYPE_MISMATCH not in codes, f"the displaced type mismatch should reach the log, not the caller, got {codes}"

    # The cause the truncation displaced is logged rather than dropped, so the operator still learns
    # why a record was refused.
    wait_for_file_lines(ats.diags_log, "and also refused a record", 1)
