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
'''
Verify that ATS surfaces origin-side failures as 5xx and marks a repeatedly
failing origin down, using Toxiproxy to impair the ATS->origin leg of a Proxy
Verifier topology:

  verifier-client --> ATS --> toxiproxy --> verifier-server

Toxiproxy is a TCP fault-injection proxy. Each replay file under replay/ declares
its topology plus the DNS and ATS config in the `autest` node, and the client
traffic with expected responses in `sessions`; Test.ToxiproxyReplayTest builds
the whole topology from that file.

Scenarios:
  - timeout: the origin never sends a response, so ATS hits its no-activity
             timeout. With connect.down.policy=3 a single inactive timeout marks
             the origin down: the first request gets 504, the next 500.
  - down:    same timeout toxic, but ATS retries the origin first; the failures
             accumulate across the retries to mark the origin down, so the first
             request 504s (after several retries) and the next 500s.
  - latency: the origin responds well past ATS's timeout; ATS times out, retries,
             marks the origin down, and returns 504 then 500.
'''

Test.Summary = 'Toxiproxy: origin server'

# Skip the whole test unless the Toxiproxy binaries are available.
Test.SkipUnless(
    Condition.HasProgram("toxiproxy-server", "toxiproxy-server must be installed (e.g. brew install toxiproxy)."),
    Condition.HasProgram("toxiproxy-cli", "toxiproxy-cli must be installed (e.g. brew install toxiproxy)."))

Test.ToxiproxyReplayTest(replay_file="replay/origin_down.replay.yaml")
Test.ToxiproxyReplayTest(replay_file="replay/origin_timeout.replay.yaml")
Test.ToxiproxyReplayTest(replay_file="replay/origin_latency.replay.yaml")
