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

from tools.uranium.services import ATS, ATSFactory, Curl, OriginServer, ServiceFactory
from tools.uranium.services.service_utils import wait_for_file_lines


def configure_ats(ats_factory: ATSFactory, services: ServiceFactory, script: str) -> tuple[ATS, OriginServer]:
    """Load @a script as a remap plugin with a single Lua state.

    ts.log.object_creat() assigns to one file-static TSTextLogObject and
    __init__ runs once per Lua state, so the default 256 states turn one
    object_creat() call into 256 TSTextLogObjectCreate() calls for the same
    filename and log-file conflict resolution fails the plugin load.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param script: Name of the Lua script, relative to this directory.
    """

    origin = services.origin("origin")
    origin.add_response(
        {
            "headers": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
            "body": ""
        },
        {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            "body": "ok"
        },
    )
    ats = ats_factory.create("ts")
    if not ats.plugin_exists("tslua.so"):
        pytest.skip("tslua.so is required")
    ats.copy_to_config(script)
    ats.remap_config.add_line(
        f"map http://www.example.com/ http://127.0.0.1:{origin.port}/ "
        f"@plugin=tslua.so @pparam=--states=1 @pparam={ats.config_directory}/{script}")
    ats.records.update({
        "proxy.config.diags.debug.enabled": 1,
        "proxy.config.diags.debug.tags": "ts_lua",
    })
    return ats, origin


def test_lua_log_object_destroy_twice(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """Destroying the log object twice and then writing to it is rejected.

    The second object_destroy() and the object_write() after it must be
    refused with an error rather than reaching the log APIs with a stale
    handle, and Traffic Server must keep running.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    ats, origin = configure_ats(ats_factory, services, "log_object_destroy.lua")
    origin.start()
    ats.start()
    response = curl.get(ats, headers={"Host": "www.example.com"}, options="-s -D - -o /dev/null")
    assert response.returncode == 0, response.output
    assert "200 OK" in response.stdout, response.output
    wait_for_file_lines(ats.diags_log, r"log object does not exist for destroy", 1)
    wait_for_file_lines(ats.diags_log, r"log object does not exist for write", 1)
    assert ats.is_running


def test_lua_log_object_destroy_without_create(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """Destroying a log object that was never created is rejected.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    ats, origin = configure_ats(ats_factory, services, "log_object_destroy_no_creat.lua")
    origin.start()
    ats.start()
    response = curl.get(ats, headers={"Host": "www.example.com"}, options="-s -D - -o /dev/null")
    assert response.returncode == 0, response.output
    assert "200 OK" in response.stdout, response.output
    wait_for_file_lines(ats.diags_log, r"log object does not exist for destroy", 1)
    assert ats.is_running
