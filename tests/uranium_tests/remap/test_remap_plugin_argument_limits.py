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

from tools.uranium.services import ATS, ATSFactory, Curl, ServiceFactory

# BUILD_TABLE_MAX_ARGS in src/proxy/http/remap/RemapConfig.h.
BUILD_TABLE_MAX_ARGS = 2048

PARAMETER = "@pparam=proxy.config.diags.debug.enabled=0"


def test_remap_plugin_argument_limits_near_limit(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """A rule with just under the maximum number of chained-plugin parameters loads and serves.

    The count sits just under BUILD_TABLE_MAX_ARGS so that the copy buffers in remap_load_plugin are
    pinned to that size. The total argument count, these parameters plus the plugin and pparam
    keywords, must stay under the maximum. The repeated override is harmless: only the count matters.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    ats = ats_factory.create("ts-ok")
    if not ats.plugin_exists("conf_remap.so"):
        pytest.skip("conf_remap.so is required")
    server = services.origin("server")
    server.add_response(
        {
            "headers": "GET / HTTP/1.1\r\nHost: overflow.example.com\r\n\r\n",
            "body": ""
        }, {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            "body": ""
        })
    ats.records.update({"proxy.config.diags.debug.enabled": 0})
    parameters = " ".join([PARAMETER] * 2040)
    ats.remap_config.add_line(
        f"map http://overflow.example.com http://127.0.0.1:{server.port} "
        f"@plugin=conf_remap.so {PARAMETER} @plugin=conf_remap.so {parameters}")

    server.start()
    ats.start()
    result = curl.get(ats, "/", headers={"Host": "overflow.example.com"}, options="--verbose")
    assert result.returncode == 0, result.output
    assert "200 OK" in result.stderr, result.output
    assert ats.is_running, ats.process_output
    for text in ("failed assertion", "received signal"):
        assert text not in ats.traffic_out.read_text(errors="replace"), ats.process_output


def test_remap_plugin_argument_limits_over_limit(ats_factory: ATSFactory) -> None:
    """A rule with more arguments than the maximum is rejected without a crash.

    A malformed line aborts the whole remap load, so Traffic Server is expected to fail to start
    rather than write past the parser's argument arrays.

    :param ats_factory: Factory for isolated Traffic Server instances.
    """

    ats = ats_factory.create("ts-bad")
    parameters = " ".join([PARAMETER] * (BUILD_TABLE_MAX_ARGS + 52))
    ats.remap_config.add_line(f"map http://overflow.example.com http://127.0.0.1:80 {parameters}")
    ats.expect_start_failure(r"too many arguments")

    ats.start()
    assert not ats.is_running
    log = ats.diags_log.read_text(errors="replace")
    assert "too many arguments" in log, log
    assert "received signal" not in log, log
    assert "failed assertion" not in ats.traffic_out.read_text(errors="replace")
