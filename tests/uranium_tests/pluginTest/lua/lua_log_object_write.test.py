'''
Verify ts.log.object_write() writes its argument literally.
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

Test.Summary = '''
TSTextLogObjectWrite() is TS_PRINTFLIKE, so passing script-supplied text as
its format argument lets that text act as a format string. Verify that a
string full of conversion specifiers reaches the custom log verbatim and
that ATS stays up.
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
    ' @plugin=tslua.so @pparam=log_object_write.lua')

ts.Setup.Copy("log_object_write.lua", ts.Variables.CONFIGDIR)

ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'ts_lua',
        # ts.log.object_creat() assigns to a single file-static TSTextLogObject and
        # __init__ runs once per Lua state, so with the default 256 states one
        # object_creat() call becomes 256 TSTextLogObjectCreate() calls for the
        # same filename and log-file conflict resolution fails the plugin load.
        # One state keeps the API usable.
        'proxy.config.plugin.lua.max_states': 1,
    })

custom_log = os.path.join(ts.Variables.LOGDIR, 'lua_object_write.log')
ts.Disk.File(custom_log, id="lua_log", exists=True)
ts.Disk.lua_log.Content = Testers.ContainsExpression(
    r'literal %s and %d and %n and %p tokens', "object_write() must not interpret its argument as a format string")

tr = Test.AddTestRun("ts.log.object_write() with conversion specifiers")
tr.MakeCurlCommand("-s -D - -o /dev/null -H 'Host: www.example.com' http://127.0.0.1:{0}/".format(ts.Variables.port), ts=ts)
tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression("200 OK", "the request should succeed")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server
