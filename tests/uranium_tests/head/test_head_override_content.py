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
"""Verify reject_head_with_content governs whether a HEAD request body is rejected or forwarded.

replay/head-reject-content.test.yaml covers this configuration everywhere Proxy
Verifier can reach, but it cannot cover the opt-out: Proxy Verifier zeroes the
content length of any HEAD request, so it never sends a body for one and ATS is
left waiting for the bytes its Content-Length promised. An ad-hoc client and
origin write and parse the framing directly instead.
"""

from pathlib import Path
import sys

import pytest

from tools.uranium.services import ATS, ATSFactory, Curl, ProcessService, ServiceFactory

TEST_DIRECTORY = Path(__file__).parent


def configure_origin(services: ServiceFactory, *, _case: str) -> tuple[ProcessService, int]:
    """Create the origin that records the HEAD request body it receives.

    :param services: Factory owning support services and their cleanup.
    :param _case: Test-local case configured by the test.
    """

    port = services.allocate_port()
    origin = services.process(
        f"origin-{_case}",
        (sys.executable, TEST_DIRECTORY / "head_override_content_server.py", "127.0.0.1", str(port)),
        ready_port=port,
    )
    return origin, port


def configure_ats(ats_factory: ATSFactory, *, _case: str, _origin_port: int) -> ATS:
    """Map the case's host to the origin, turning the check off for the forward case.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param _case: Test-local case configured by the test.
    :param _origin_port: Test-local origin port configured by the test.
    """

    ats = ats_factory.create(f"ts-{_case}", enable_cache=False)
    origin = f"http://127.0.0.1:{_origin_port}/"
    if _case == "reject":
        ats.remap_config.add_line(f"map http://reject-body.example.com/ {origin}")
    else:
        if not ats.plugin_exists("conf_remap.so"):
            pytest.skip("conf_remap.so is required")
        ats.remap_config.add_line(
            f"map http://allow-body.example.com/ {origin} "
            "@plugin=conf_remap.so @pparam=proxy.config.http.reject_head_with_content=0")
    ats.records.update({
        "proxy.config.diags.debug.enabled": 1,
        "proxy.config.diags.debug.tags": "http|http_trans",
    })
    return ats


@pytest.mark.parametrize("case", ("reject", "forward"))
def test_head_override_content(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, case: str) -> None:
    """A HEAD body is rejected with 400 by default and forwarded when the rule turns the check off.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param case: Case used by this test step.
    """
    if curl.uses_uds:
        pytest.skip("the raw HEAD client requires a TCP listener")
    _origin, _origin_port = configure_origin(services, _case=case)
    _ats = configure_ats(ats_factory, _case=case, _origin_port=_origin_port)

    _origin.start()
    _ats.start()
    host = "reject-body.example.com" if case == "reject" else "allow-body.example.com"
    client = services.process(
        f"client-{case}",
        (
            sys.executable,
            TEST_DIRECTORY / "head_override_content_client.py",
            "127.0.0.1",
            str(_ats.http_port),
            host,
            "/override/content-length",
        ),
    )
    result = client.run(timeout=30)
    assert result.returncode == 0, result.output
    # Waiting on the request body would show up as a client-side timeout.
    assert "READ_TIMED_OUT: yes" not in result.stdout, result.output

    if case == "reject":
        assert "STATUS_LINE: HTTP/1.1 400" in result.stdout, result.output
        # ATS must reject before the request ever reaches the origin.
        _origin.stop()
        assert "REQUEST_LINE:" not in _origin.stdout_text, _origin.output
        return

    assert "STATUS_LINE: HTTP/1.1 200" in result.stdout, result.output
    assert "X-Origin-Response: head-override" in result.stdout, result.output
    assert "Content-Length: 14" in result.stdout, result.output
    # A HEAD response carries no body regardless of Content-Length. If ATS
    # forwarded one, the client would report a non-zero length here.
    assert "RESPONSE_BODY_LEN: 0" in result.stdout, result.output

    # The whole point of the opt-out: the request and its body are forwarded
    # unchanged.
    output = _origin.wait_for_output(r"---- END ORIGIN REQUEST ----")
    assert "REQUEST_LINE: HEAD /override/content-length HTTP/1.1" in output, output
    assert "DECLARED_CONTENT_LENGTH: 5" in output, output
    assert "BODY_LEN: 5" in output, output
    assert "BODY: b'hello'" in output, output
    # A declared body that never arrives is the failure this test exists to
    # catch, and it is distinct from a body that arrives truncated.
    assert "BODY_TIMED_OUT: yes" not in output, output
