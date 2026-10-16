'''
Verify that the JSONRPC server refuses a batch of more than 64 messages and a request carrying more than
1024 params elements, answering for the whole request, and runs requests at those limits as before.
'''
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

from jsonrpc import Request, BatchRequest

Test.Summary = __doc__
# Each run below checks one limit on its own, so a failure in one should not hide the others.
Test.ContinueOnFail = True

ts = Test.MakeATSProcess("ts")

MAX_BATCH_SIZE = 64
MAX_PARAMS_ELEMENTS = 1024

INVALID_REQUEST = -32600
INVALID_PARAMS = -32602

# Matches no record, so each element costs one walk of the store and adds nothing to the response.
NO_MATCH = {"record_name_regex": r"^proxy\.config\.test\.request_limits\.none$"}

# Matches every record, so each element answers with a whole store walk.
MATCH_ALL = {"record_name_regex": "."}

MAX_RECORDS_PER_REQUEST = 10000
RESPONSE_TRUNCATED = "2012"
# The message is the whole reason this code is not LOOKUP_INCOMPLETE, whose text says a pattern was abandoned. Nothing else
# asserts it, so losing the switch arm that produces it would report "Record error error 2012" with the suite still green.
RESPONSE_TRUNCATED_TEXT = "number of records one response may carry"


def lookups(n: int) -> list[dict[str, str]]:
    return [dict(NO_MATCH) for _ in range(n)]


def expect(tr, condition: str) -> None:
    """Pipe the response to a check that exits zero only if the condition holds for the parsed JSON, bound to r.

    CustomJSONRPCResponse cannot be used here: it parses a single response object and raises on the array a batch is answered
    with, which is exactly the answer a request over the batch limit gets when the limit is not enforced.

    The condition is python source run under single quotes, so it names its JSON keys through the ID, ERROR and CODE variables
    the preamble defines rather than quoting them inline. It runs under the interpreter running this test, not whatever
    `python3` resolves to, so a virtualenv or a differently named interpreter still gets used.
    """
    preamble = 'import json, sys; ID, ERROR, CODE, MSG, RESULT, RECS, ERRS = "id", "error", "code", "message", "result", "recordList", "errorList"; r = json.load(sys.stdin)'
    tr.Processes.Default.Command += f" | {sys.executable} -c '{preamble}; sys.exit(0 if {condition} else 1)'"


def batch_ran(n: int) -> str:
    return f'isinstance(r, list) and len(r) == {n} and all(RESULT in x for x in r)'


def single_ran() -> str:
    return 'isinstance(r, dict) and RESULT in r'


# Refused whole: one error object, not a batch of per-message answers. A single request is answered with its own id, so that a
# client matching answers by id still finds it; a batch has no one id to answer with. The id is compared to the one that was
# sent rather than merely checked for being present, since any id at all would satisfy a client that matches on it.
def refused(code: int, sent_id: str | None) -> str:
    id_check = f'r.get(ID) == "{sent_id}"' if sent_id is not None else 'ID not in r'
    return f'isinstance(r, dict) and r.get(ERROR, {{}}).get(CODE) == {code} and {id_check}'


tr = Test.AddTestRun("a batch at the limit runs every message")
tr.Processes.Default.StartBefore(ts)
tr.AddJsonRPCClientRequest(ts, BatchRequest(*[Request.admin_lookup_records(lookups(1)) for _ in range(MAX_BATCH_SIZE)]))
expect(tr, batch_ran(MAX_BATCH_SIZE))
tr.StillRunningAfter = ts

tr = Test.AddTestRun("a batch over the limit is refused whole")
tr.AddJsonRPCClientRequest(ts, BatchRequest(*[Request.admin_lookup_records(lookups(1)) for _ in range(MAX_BATCH_SIZE + 1)]))
expect(tr, refused(INVALID_REQUEST, None))
tr.StillRunningAfter = ts

tr = Test.AddTestRun("a request at the params limit runs")
tr.AddJsonRPCClientRequest(ts, Request.admin_lookup_records(lookups(MAX_PARAMS_ELEMENTS)))
expect(tr, single_ran())
tr.StillRunningAfter = ts

tr = Test.AddTestRun("a request over the params limit is refused whole")
OVER_PARAMS_ID = "over-the-params-limit"
tr.AddJsonRPCClientRequest(ts, Request.admin_lookup_records(lookups(MAX_PARAMS_ELEMENTS + 1), id=OVER_PARAMS_ID))
expect(tr, refused(INVALID_PARAMS, OVER_PARAMS_ID))
tr.StillRunningAfter = ts

# Two messages each well inside the limit, whose params add up to one past it.
tr = Test.AddTestRun("params elements are summed across a batch")
half = MAX_PARAMS_ELEMENTS // 2
tr.AddJsonRPCClientRequest(
    ts, BatchRequest(Request.admin_lookup_records(lookups(half)), Request.admin_lookup_records(lookups(half + 1))))
expect(tr, refused(INVALID_PARAMS, None))
tr.StillRunningAfter = ts

# The refusals left the server answering.
# The element limit bounds how many lookups one request may ask for; it does not bound how much each one answers with. Before the
# record budget existed this same request produced a 501MB response and 9.8GB of peak RSS, measured on a build without a
# sanitizer. A default store is about 1,339 records, so 1024 broad elements reach the budget without needing a bigger store.
tr = Test.AddTestRun("a request whose lookups match more than the record budget is capped and reports it")
tr.AddJsonRPCClientRequest(ts, Request.admin_lookup_records([dict(MATCH_ALL) for _ in range(MAX_PARAMS_ELEMENTS)]))
expect(
    tr, f'len(r[RESULT][RECS]) == {MAX_RECORDS_PER_REQUEST} '
    f'and any(e[CODE] == "{RESPONSE_TRUNCATED}" and "{RESPONSE_TRUNCATED_TEXT}" in e[MSG] for e in r[RESULT][ERRS])')
tr.StillRunningAfter = ts

# The budget must not touch what an operator actually types. One broad element is a whole store and well inside it.
tr = Test.AddTestRun("an ordinary full lookup is answered in full and reports nothing")
tr.AddJsonRPCClientRequest(ts, Request.admin_lookup_records([{"record_name_regex": ".*"}]))
expect(tr, f'0 < len(r[RESULT][RECS]) < {MAX_RECORDS_PER_REQUEST} and not r[RESULT][ERRS]')
tr.StillRunningAfter = ts

# A refused request must read as a failure in both output formats. The JSON path returns as soon as it has printed the response,
# so before this it set no exit status from a top-level error and a script asking for JSON saw a refusal as success. 1025 names is
# one element each, so the request is refused with -32602 having run nothing.
TOO_MANY_NAMES = " ".join(f"proxy.config.test.exit_status.{i}" for i in range(MAX_PARAMS_ELEMENTS + 1))

# The code is pinned as well as the status: an unknown record name has always exited 2 through the per-record error list, so
# 1025 names would exit 2 even with the limit removed and the request run. Only -32602 in the output says it was refused.
tr = Test.AddTestRun("a refused request exits non-zero in text format")
tr.Processes.Default.Command = f"traffic_ctl config get {TOO_MANY_NAMES}"
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.ReturnCode = 2
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("-32602", "the refusal should be reported in the text output")
tr.StillRunningAfter = ts

tr = Test.AddTestRun("a refused request exits non-zero in json format too")
tr.Processes.Default.Command = f"traffic_ctl config get {TOO_MANY_NAMES} --format json"
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.ReturnCode = 2
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "-32602", "the refusal should still be reported in the json output")
tr.StillRunningAfter = ts

tr = Test.AddTestRun("an ordinary lookup still runs after the refusals")
tr.Processes.Default.Command = 'traffic_ctl config get proxy.config.diags.debug.enabled'
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    r'proxy\.config\.diags\.debug\.enabled: 0', 'the server should still answer an ordinary request')
tr.StillRunningAfter = ts
