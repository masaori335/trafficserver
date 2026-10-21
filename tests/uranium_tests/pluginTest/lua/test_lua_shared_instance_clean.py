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

import time

import pytest

from tools.uranium.services import ATSFactory, Curl, ServiceFactory
from tools.uranium.services.service_utils import wait_for_file_lines


def test_lua_shared_instance_clean(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """__clean__ runs only when the last remap instance sharing a script is freed.

    Two remap rules naming the same Lua script share one instance
    configuration. Tearing that configuration down on a remap.config reload
    must run the script's __clean__ exactly once, not once per referencing
    rule.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    origin = services.origin("origin")
    origin.add_response(
        {
            "headers": "GET / HTTP/1.1\r\nHost: one.example.com\r\n\r\n",
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

    # __clean__ appends one line per invocation so the test can count them.
    clean_log = ats.run_directory / "clean_calls.txt"
    ats.write_config_file(
        "shared_instance_clean.lua", f"""
function __clean__()
  local f = io.open('{clean_log}', 'a')
  if f then
    f:write('CLEAN\\n')
    f:close()
  end
end

function do_remap()
  return 0
end
""")

    # Both rules name the same script with no extra parameters, which is the
    # condition under which TSRemapNewInstance shares one ts_lua_instance_conf.
    # One state keeps the __clean__ invocation count independent of the host's
    # thread count: ts_lua_del_module runs __clean__ once per Lua state.
    shared_rules = [
        f"map http://one.example.com/ http://127.0.0.1:{origin.port}/ "
        f"@plugin=tslua.so @pparam=--states=1 @pparam={ats.config_directory}/shared_instance_clean.lua",
        f"map http://two.example.com/ http://127.0.0.1:{origin.port}/ "
        f"@plugin=tslua.so @pparam=--states=1 @pparam={ats.config_directory}/shared_instance_clean.lua",
    ]
    ats.remap_config.add_lines(shared_rules)
    ats.records.update({
        "proxy.config.diags.debug.enabled": 1,
        "proxy.config.diags.debug.tags": "ts_lua",
    })

    origin.start()
    ats.start()
    response = curl.get(ats, headers={"Host": "one.example.com"}, options="-s -D - -o /dev/null")
    assert response.returncode == 0, response.output
    assert "200 OK" in response.stdout, response.output

    # Rewrite remap.config with the same two rules plus a third so the reload
    # has a change to act on; an unchanged remap.config is skipped. Wait for a
    # later proxy.process.proxy.reconfigure_time second than the initial load,
    # otherwise the new configuration adopts the existing instance instead of
    # replacing it and nothing is torn down.
    time.sleep(2)
    ats.remap_config.path.write_text(
        "\n".join(shared_rules + [f"map http://three.example.com/ http://127.0.0.1:{origin.port}/"]) + "\n")
    result = ats.traffic_ctl("config", "reload", "--token", "shared-instance-clean")
    assert result.returncode == 0, result.output
    deadline = time.monotonic() + 15
    status = ""
    while "success" not in status:
        assert time.monotonic() < deadline, f"The reload did not succeed:\n{status}"
        assert "failed" not in status, status
        time.sleep(0.1)
        status = ats.traffic_ctl("config", "status", "--token", "shared-instance-clean").output.lower()

    response = curl.get(ats, headers={"Host": "one.example.com"}, options="-s -D - -o /dev/null")
    assert response.returncode == 0, response.output
    assert "200 OK" in response.stdout, response.output

    # The old UrlRewrite is destroyed on ET_TASK once the last transaction using
    # it is gone, so the teardown is not synchronous with the reload. Wait for
    # the first call, then give a second call time to show up.
    wait_for_file_lines(clean_log, "^CLEAN$", 1)
    time.sleep(3)
    assert clean_log.read_text().count("CLEAN") == 1, clean_log.read_text()
