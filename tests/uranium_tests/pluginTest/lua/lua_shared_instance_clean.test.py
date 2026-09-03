'''
Verify __clean__ runs only when the last remap instance sharing a script is freed.
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

import os
import re


def update_remap_config(path: str, lines: list) -> None:
    """Rewrite remap.config so a reload actually picks the file up.

    ATS skips the remap.config reload task when the file is unchanged.

    :param path: The path to the remap.config file.
    :param lines: The list of lines to write to the file.
    """
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')


Test.Summary = '''
Two remap rules referencing the same Lua script share one instance
configuration. Verify that tearing that configuration down on a
remap.config reload runs the script's __clean__ exactly once, rather than
once per referencing rule.
'''

Test.SkipUnless(Condition.PluginExists('tslua.so'),)

Test.ContinueOnFail = True

ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")

req = {"headers": "GET / HTTP/1.1\r\nHost: one.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
resp = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "ok"}
server.addResponse("sessionfile.log", req, resp)

# __clean__ appends one line per invocation so the test can count them.
clean_log = os.path.join(Test.RunDirectory, "clean_calls.txt")

ts.Disk.File(os.path.join(ts.Variables.CONFIGDIR, "shared_instance_clean.lua"), id="lua_script")
ts.Disk.lua_script.WriteOn(
    f'''
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
''')

# Both rules name the same script with no extra parameters, which is the
# condition under which TSRemapNewInstance shares one ts_lua_instance_conf.
shared_rules = [
    f'map http://one.example.com/ http://127.0.0.1:{server.Variables.Port}/'
    ' @plugin=tslua.so @pparam=shared_instance_clean.lua',
    f'map http://two.example.com/ http://127.0.0.1:{server.Variables.Port}/'
    ' @plugin=tslua.so @pparam=shared_instance_clean.lua',
]
ts.Disk.remap_config.AddLines(shared_rules)

remap_cfg_path = os.path.join(ts.Variables.CONFIGDIR, 'remap.config')

ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'ts_lua',
        # One VM keeps the __clean__ invocation count independent of the host's
        # thread count: ts_lua_del_module runs __clean__ once per Lua state.
        'proxy.config.plugin.lua.max_states': 1,
    })

tr = Test.AddTestRun("Serve a request through the shared Lua instance")
tr.MakeCurlCommand("-s -D - -o /dev/null -H 'Host: one.example.com' http://127.0.0.1:{0}/".format(ts.Variables.port), ts=ts)
tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200 OK", "the shared instance should serve traffic")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Rewrite the file with the same two rules plus a third so the reload has a
# change to act on; an unchanged remap.config is skipped by the reload.
tr = Test.AddTestRun("Touch remap.config so the reload has work to do")
p = tr.Processes.Default
p.Env = ts.Env
p.Command = 'echo "rewriting remap.config"'
p.Setup.Lambda(
    lambda: update_remap_config(
        remap_cfg_path, shared_rules + [f'map http://three.example.com/ http://127.0.0.1:{server.Variables.Port}/']))
tr.StillRunningAfter = ts

# delay_start puts the reload in a later proxy.process.proxy.reconfigure_time
# second than the initial load. Without that the new configuration adopts the
# existing instance instead of replacing it, and nothing is torn down.
tr = Test.AddConfigReload(ts, expect="success", expect_tasks=["remap.config"], delay_start=2, description="Reload remap.config")
tr.StillRunningAfter = ts

tr = Test.AddTestRun("Serve a request through the reloaded configuration")
tr.MakeCurlCommand("-s -D - -o /dev/null -H 'Host: one.example.com' http://127.0.0.1:{0}/".format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200 OK", "the reloaded instance should serve traffic")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# The old UrlRewrite is destroyed on ET_TASK once the last transaction using
# it is gone, so the teardown is not synchronous with the reload.
tr = Test.AddTestRun("__clean__ runs once, not once per referencing remap rule")
tr.DelayStart = 3
tr.Command = f"grep -c CLEAN {clean_log}"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "^1$", "__clean__ should run exactly once for the shared instance", reflags=re.MULTILINE)
tr.StillRunningAfter = ts
