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
from typing import Any

from tools.uranium.services import ATS
from uranium_tests.lib.jsonrpc import BatchRequest, Request

MAX_BATCH_SIZE = 64
MAX_PARAMS_ELEMENTS = 1024
MAX_RECORDS_PER_REQUEST = 10000

INVALID_REQUEST = -32600
INVALID_PARAMS = -32602

# Matches no record, so each element costs one walk of the store and adds nothing to the response.
NO_MATCH = {"record_name_regex": r"^proxy\.config\.test\.request_limits\.none$"}

# Matches every record, so each element answers with a whole store walk.
MATCH_ALL = {"record_name_regex": "."}

RESPONSE_TRUNCATED = "2012"
# The message is what tells this code apart from LOOKUP_INCOMPLETE, whose text says a pattern was abandoned.
RESPONSE_TRUNCATED_TEXT = "number of records one response may carry"


def lookups(count: int) -> list[dict[str, str]]:
    """Build lookup elements that each walk the record store and match nothing.

    :param count: Number of params elements.
    """

    return [dict(NO_MATCH) for _ in range(count)]


def send(request: object, *, _ats: ATS) -> Any:
    """Send one request and decode the answer, which is an array for a batch.

    :param request: Single request or batch.
    :param _ats: Test-local ats configured by the test.
    """

    result = _ats.rpc(request)
    assert result.returncode == 0, result.output
    return json.loads(result.stdout)


def assert_batch_ran(response: Any, count: int) -> None:
    """Require one successful answer per message of a batch.

    :param response: Decoded answer.
    :param count: Number of messages sent.
    """

    assert isinstance(response, list) and len(response) == count, response
    assert all("result" in message for message in response), response


def assert_refused(response: Any, code: int, sent_id: str | None) -> None:
    """Require one error object for the whole request, not a batch of per-message answers.

    A single request is answered with its own id so that a client matching answers by id still finds it. A batch has no
    one id to answer with.

    :param response: Decoded answer.
    :param code: Expected JSON-RPC error code.
    :param sent_id: Id the request was sent with, or None for a batch.
    """

    assert isinstance(response, dict), response
    assert response.get("error", {}).get("code") == code, response
    if sent_id is None:
        assert "id" not in response, response
    else:
        assert response.get("id") == sent_id, response


def test_jsonrpc_request_limits_batch_and_params(ats: ATS) -> None:
    """The JSON-RPC server refuses a batch over 64 messages and params over 1024 elements, answering for the whole request.

    :param ats: Fresh Traffic Server instance.
    """

    ats.start()

    # A batch at the limit runs every message, and one over it is refused whole.
    response = send(BatchRequest(*[Request.admin_lookup_records(lookups(1)) for _ in range(MAX_BATCH_SIZE)]), _ats=ats)
    assert_batch_ran(response, MAX_BATCH_SIZE)
    response = send(BatchRequest(*[Request.admin_lookup_records(lookups(1)) for _ in range(MAX_BATCH_SIZE + 1)]), _ats=ats)
    assert_refused(response, INVALID_REQUEST, None)

    # A request at the params limit runs, and one over it is refused whole under its own id.
    response = send(Request.admin_lookup_records(lookups(MAX_PARAMS_ELEMENTS)), _ats=ats)
    assert isinstance(response, dict) and "result" in response, response
    over_params_id = "over-the-params-limit"
    response = send(Request.admin_lookup_records(lookups(MAX_PARAMS_ELEMENTS + 1), id=over_params_id), _ats=ats)
    assert_refused(response, INVALID_PARAMS, over_params_id)

    # Two messages each well inside the limit, whose params add up to one past it.
    half = MAX_PARAMS_ELEMENTS // 2
    response = send(
        BatchRequest(Request.admin_lookup_records(lookups(half)), Request.admin_lookup_records(lookups(half + 1))), _ats=ats)
    assert_refused(response, INVALID_PARAMS, None)

    # The refusals left the server answering.
    assert_batch_ran(send(BatchRequest(Request.admin_lookup_records(lookups(1))), _ats=ats), 1)


def test_jsonrpc_request_limits_record_budget(ats: ATS) -> None:
    """One response carries at most 10,000 records and reports when a lookup was cut short.

    The element limit bounds how many lookups one request may ask for, not how much each one answers with. A default
    store holds well over a thousand records, so a few broad elements reach the budget.

    :param ats: Fresh Traffic Server instance.
    """

    ats.start()
    response = send(Request.admin_lookup_records([dict(MATCH_ALL) for _ in range(16)]), _ats=ats)
    assert "error" not in response, response
    assert len(response["result"]["recordList"]) == MAX_RECORDS_PER_REQUEST, len(response["result"]["recordList"])
    assert any(
        error["code"] == RESPONSE_TRUNCATED and RESPONSE_TRUNCATED_TEXT in error["message"]
        for error in response["result"]["errorList"]), response["result"]["errorList"]

    # The budget does not touch what an operator actually types: one broad element is a whole store and well inside it.
    response = send(Request.admin_lookup_records([{"record_name_regex": ".*"}]), _ats=ats)
    assert 0 < len(response["result"]["recordList"]) < MAX_RECORDS_PER_REQUEST, len(response["result"]["recordList"])
    assert not response["result"]["errorList"], response["result"]["errorList"]


def test_jsonrpc_request_limits_refusal_exit_status(ats: ATS) -> None:
    """A refused request makes traffic_ctl exit non-zero in both text and json format.

    The request is refused with -32602 having run nothing. The code is pinned as well as the status, since an unknown
    record name exits 2 through the per-record error list even when the request runs.

    :param ats: Fresh Traffic Server instance.
    """

    ats.start()
    too_many_names = [f"proxy.config.test.exit_status.{i}" for i in range(MAX_PARAMS_ELEMENTS + 1)]
    for output_format in ("text", "json"):
        result = ats.traffic_ctl("config", "get", *too_many_names, "--format", output_format)
        assert result.returncode == 2, result.output
        assert "-32602" in result.stdout, result.output

    # The refusals left the server answering.
    result = ats.traffic_ctl("config", "get", "proxy.config.diags.debug.enabled")
    assert result.returncode == 0, result.output
    assert "proxy.config.diags.debug.enabled: 0" in result.stdout, result.output
