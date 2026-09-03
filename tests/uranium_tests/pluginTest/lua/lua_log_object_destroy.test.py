'''
Verify ts.log.object_destroy() does not leave the log handle dangling.
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

Test.Summary = '''
TSTextLogObjectDestroy() and TSTextLogObjectWrite() both sdk_assert on their
handle, which aborts traffic_server in release builds. Verify that destroying
the Lua log object twice, and writing to it afterwards, are both rejected
with an error rather than reaching those APIs with a stale handle.
'''

Test.SkipUnless(Condition.PluginExists('tslua.so'),)

Test.ContinueOnFail = True

ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")

req = {"headers": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
resp = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "ok"}
server.addResponse("sessionfile.log", req, resp)

ts.Disk.remap_config.AddLine(
    f'map http://www.example.com/ http://127.0.0.1:{server.Variables.Port}/'
    ' @plugin=tslua.so @pparam=log_object_destroy.lua')

ts.Setup.Copy("log_object_destroy.lua", ts.Variables.CONFIGDIR)

ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'ts_lua',
        # ts.log.object_creat() assigns to a single file-static TSTextLogObject and
        # __init__ runs once per Lua state, so the default 256 states turn one
        # object_creat() call into 256 TSTextLogObjectCreate() calls for the same
        # filename and log-file conflict resolution fails the plugin load.
        'proxy.config.plugin.lua.max_states': 1,
    })

# The script deliberately provokes both guards, so the default "no ERROR in
# diags.log" assertion has to be replaced with the errors we expect.
ts.Disk.diags_log.Content = Testers.ContainsExpression(
    r'log object does not exist for destroy', "the second object_destroy() should be rejected")
ts.Disk.diags_log.Content += Testers.ContainsExpression(
    r'log object does not exist for write', "object_write() after a destroy should be rejected")

# A second instance whose script never calls object_creat, so the handle is
# still null. This is the path that actually aborts without the guard:
# TSTextLogObjectDestroy(nullptr) fails a release sdk_assert.
ts_no_creat = Test.MakeATSProcess("ts_no_creat")

ts_no_creat.Disk.remap_config.AddLine(
    f'map http://www.example.com/ http://127.0.0.1:{server.Variables.Port}/'
    ' @plugin=tslua.so @pparam=log_object_destroy_no_creat.lua')

ts_no_creat.Setup.Copy("log_object_destroy_no_creat.lua", ts_no_creat.Variables.CONFIGDIR)

ts_no_creat.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'ts_lua',
        'proxy.config.plugin.lua.max_states': 1,
    })

ts_no_creat.Disk.diags_log.Content = Testers.ContainsExpression(
    r'log object does not exist for destroy', "object_destroy() without a prior object_creat() should be rejected")

tr = Test.AddTestRun("Double object_destroy() followed by object_write()")
tr.MakeCurlCommand("-s -D - -o /dev/null -H 'Host: www.example.com' http://127.0.0.1:{0}/".format(ts.Variables.port), ts=ts)
tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200 OK", "the request should still succeed")
# The real assertion: traffic_server must not have aborted.
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

tr = Test.AddTestRun("object_destroy() with no prior object_creat()")
tr.MakeCurlCommand(
    "-s -D - -o /dev/null -H 'Host: www.example.com' http://127.0.0.1:{0}/".format(ts_no_creat.Variables.port), ts=ts_no_creat)
tr.Processes.Default.StartBefore(ts_no_creat)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200 OK", "the request should still succeed")
tr.StillRunningAfter = ts_no_creat
tr.StillRunningAfter = server
