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
"""Verify authproxy --forward-header-prefix cannot be spoofed by the client."""

from pathlib import Path

import pytest

from tools.uranium.services import ATS, ATSFactory, ServiceFactory

TEST_DIRECTORY = Path(__file__).parent
AUTH_REPLAY = TEST_DIRECTORY / "forward_prefix_auth.replay.yaml"
ORIGIN_REPLAY = TEST_DIRECTORY / "forward_prefix.replay.yaml"


def test_forward_prefix(ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """Client-supplied headers matching the forward prefix are replaced or stripped before reaching the origin.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    """

    ats = ats_factory.create("ts")
    if not ats.plugin_exists("authproxy.so"):
        pytest.skip("authproxy.so is required")

    auth_server = services.verifier_server("auth-server", AUTH_REPLAY, https_ports=[])
    origin_server = services.verifier_server("origin-server", ORIGIN_REPLAY, https_ports=[])

    ats.records.update({"proxy.config.diags.debug.enabled": 0})
    auth_port = auth_server.http_port
    ats.remap_config.add_line(
        f"map http://www.example.com/ http://127.0.0.1:{origin_server.http_port}/ "
        f"@plugin=authproxy.so @pparam=--auth-transform=redirect @pparam=--auth-host=127.0.0.1 "
        f"@pparam=--auth-port={auth_port} @pparam=--forward-header-prefix=X-Auth-")
    ats.remap_config.add_line(f"map http://127.0.0.1:{auth_port}/ http://127.0.0.1:{auth_port}/")

    client = services.verifier_client("client", ORIGIN_REPLAY, http_ports=[ats.http_port])

    auth_server.start()
    origin_server.start()
    ats.start()
    result = client.run()
    assert result.returncode == 0, result.output
