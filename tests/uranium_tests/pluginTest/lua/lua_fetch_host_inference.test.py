'''
Verify ts.fetch infers the Host header from the URL authority only.
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
Verify ts.fetch derives the Host header from the URL authority, excluding any query.
'''

Test.SkipUnless(Condition.PluginExists('tslua.so'),)

Test.ContinueOnFail = True

ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")

origin = f'127.0.0.1:{server.Variables.Port}'

outer_req = {"headers": f"GET / HTTP/1.1\r\nHost: {origin}\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
outer_resp = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "outer"}
server.addResponse("sessionfile.log", outer_req, outer_resp)

ts.Disk.remap_config.AddLine(f'map / http://{origin}/ @plugin=tslua.so @pparam=fetch_host_inference.lua @pparam={origin}')

ts.Setup.Copy("fetch_host_inference.lua", ts.Variables.CONFIGDIR)

ts.Disk.records_config.update({'proxy.config.diags.debug.enabled': 1, 'proxy.config.diags.debug.tags': 'ts_lua'})

tr = Test.AddTestRun("ts.fetch infers Host from the authority, not the query")
tr.MakeCurlCommand(f"-s -D - http://127.0.0.1:{ts.Variables.port}/", ts=ts)
tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
# The sub-request re-enters remap, where the Lua script answers 204 if the Host
# the plugin inferred is exactly the authority and 400 otherwise. Asserting on
# that keeps the check on the parsing rather than on how the origin stub matches
# a query string.
tr.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
    "Sub-Status: 204", "ts.fetch must infer the authority alone as the Host")
tr.Processes.Default.Streams.stdout.Content += Testers.ExcludesExpression(
    "Sub-Status: 400", "The query string must not be folded into the inferred Host")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts
