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


def test_lua_log_object_write(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """ts.log.object_write() writes its argument literally.

    A string full of conversion specifiers must reach the custom log verbatim
    and Traffic Server must stay up.

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
            "body": "ok"
        },
    )

    ats = ats_factory.create("ts")
    if not ats.plugin_exists("tslua.so"):
        pytest.skip("tslua.so is required")
    # ts.log.object_creat() assigns to a single file-static TSTextLogObject and
    # __init__ runs once per Lua state, so with the default 256 states one
    # object_creat() call becomes 256 TSTextLogObjectCreate() calls for the same
    # filename and log-file conflict resolution fails the plugin load. One state
    # keeps the API usable.
    ats.copy_to_config("log_object_write.lua")
    ats.remap_config.add_line(
        f"map http://www.example.com/ http://127.0.0.1:{origin.port}/ "
        f"@plugin=tslua.so @pparam=--states=1 @pparam={ats.config_directory}/log_object_write.lua")
    ats.records.update({
        "proxy.config.diags.debug.enabled": 1,
        "proxy.config.diags.debug.tags": "ts_lua",
    })

    origin.start()
    ats.start()
    response = curl.get(ats, headers={"Host": "www.example.com"}, options="-s -D - -o /dev/null")
    assert response.returncode == 0, response.output
    assert "200 OK" in response.stdout, response.output
    assert ats.is_running
    # The custom log is buffered, so read it once shutdown has flushed it.
    ats.stop()
    custom_log = ats.log_directory / "lua_object_write.log"
    assert "literal %s and %d and %n and %p tokens" in custom_log.read_text(errors="replace")
