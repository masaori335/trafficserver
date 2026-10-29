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

from pathlib import Path
import sys

import pytest

from tools.uranium.services import ATSFactory, ServiceFactory

PROXY_PROTOCOL_CLIENT = Path(__file__).parent.parent / "tls" / "proxy_protocol_client.py"
HOST = "acl.proxy.protocol.test"


@pytest.mark.parametrize("subjects", ["PROXY", "PLUGIN,PROXY"])
@pytest.mark.parametrize("protocol_version", [1, 2])
@pytest.mark.parametrize(("addressless", "expected_status"), [(False, "200 OK"), (True, "403")], ids=["address", "addressless"])
def test_remap_acl_proxy_subject(
    subjects: str,
    protocol_version: int,
    addressless: bool,
    expected_status: str,
    ats_factory: ATSFactory,
    services: ServiceFactory,
) -> None:
    """A remap ACL uses the PROXY address only when the PROXY header carries one.

    A v1 UNKNOWN or v2 LOCAL header has no address, so the ACL is evaluated
    against the peer address, which the rule does not allow.

    :param subjects: Value of proxy.config.acl.subjects.
    :param protocol_version: PROXY protocol version sent by the client.
    :param addressless: Whether the PROXY header omits the addresses.
    :param expected_status: Status line text expected in the client response.
    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    """

    origin = services.origin("origin")
    origin.add_response(
        {
            "headers": f"GET /proxy_protocol HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n",
            "body": ""
        },
        {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            "body": "ok"
        },
    )

    ats = ats_factory.create("ts", enable_cache=False, enable_proxy_protocol=True)
    ats.records.update({
        "proxy.config.acl.subjects": subjects,
        "proxy.config.http.proxy_protocol_allowlist": "127.0.0.1",
    })
    ats.remap_config.add_line(f"map http://{HOST}/ http://127.0.0.1:{origin.port}/ @action=allow @src_ip=10.0.0.0/8")

    arguments: list[str | Path] = [
        sys.executable,
        PROXY_PROTOCOL_CLIENT,
        "127.0.0.1",
        str(ats.proxy_protocol_port),
        HOST,
        "10.1.2.3",
        "127.0.0.1",
        "1111",
        "2222",
        str(protocol_version),
    ]
    if addressless:
        arguments.append("--addressless")
    client = services.process("client", arguments)

    origin.start()
    ats.start()
    result = client.run(timeout=10)
    assert result.returncode == 0, result.output
    assert f"HTTP/1.1 {expected_status}" in result.output, result.output
