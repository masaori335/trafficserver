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

import pytest

from tools.uranium.services import ATSFactory, Curl, ServiceFactory


def test_lua_fetch_host_inference(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """ts.fetch infers the Host header from the URL authority alone.

    The sub-request re-enters remap, where the Lua script answers 204 if the
    Host the plugin inferred is exactly the authority and 400 otherwise.
    Asserting on that keeps the check on the parsing rather than on how the
    origin matches a query string.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    origin = services.origin("origin")
    origin.add_response(
        {
            "headers": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        },
        {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            "body": "outer"
        },
    )

    authority = f"127.0.0.1:{origin.port}"
    ats = ats_factory.create("ts")
    if not ats.plugin_exists("tslua.so"):
        pytest.skip("tslua.so is required")
    ats.copy_to_config("fetch_host_inference.lua")
    ats.remap_config.add_line(
        f"map / http://{authority}/ @plugin=tslua.so @pparam={ats.config_directory}/fetch_host_inference.lua @pparam={authority}")
    ats.records.update({"proxy.config.diags.debug.enabled": 1, "proxy.config.diags.debug.tags": "ts_lua"})

    origin.start()
    ats.start()
    response = curl.get(ats, options="-s -D -")
    assert response.returncode == 0, response.output
    assert "Sub-Status: 204" in response.stdout, response.output
    assert "Sub-Status: 400" not in response.stdout, response.output
