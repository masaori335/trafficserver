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
Verify ATS parent-selection behavior when the child->parent leg is impaired,
using Toxiproxy to inject transport faults into a Proxy Verifier topology with
two ATS instances:

  verifier-client --> ATS (child) --> toxiproxy --> ATS (parent) --> verifier-server

The child forwards to the parent via parent.config; Toxiproxy impairs the leg in
between. Each replay file under replay/ declares its topology plus the ATS config
for both instances in the `autest` node, and the client traffic with expected
responses in `sessions`; Test.ToxiproxyParentReplayTest builds the whole topology
from that file. This exercises the parent-proxy code path (parent markdown and
failover) that the origin-leg tests (toxiproxy_origin.test.py) cannot reach.

Scenarios:
  - partition: the parent leg is refused (proxy disabled). With go_direct=false
               and a single parent, the child returns 502 and marks the parent
               down; the second request is refused parent selection (502).
  - markdown:  the parent leg accepts the connection but never responds (timeout
               toxic). The child times out (504) and, with timeout markdowns
               enabled, marks the parent down; the second request returns 502.
  - failover:  the primary parent is refused but a healthy secondary parent lets
               the child fail over and return 200.
'''

Test.Summary = 'Toxiproxy: parent proxy'

# The three scenarios are independent; keep going so one failure does not mask
# the others.
Test.ContinueOnFail = True

# Skip the whole test unless the Toxiproxy binaries are available.
Test.SkipUnless(
    Condition.HasProgram("toxiproxy-server", "toxiproxy-server must be installed (e.g. brew install toxiproxy)."),
    Condition.HasProgram("toxiproxy-cli", "toxiproxy-cli must be installed (e.g. brew install toxiproxy)."))

Test.ToxiproxyParentReplayTest(replay_file="replay/parent_partition.replay.yaml")
Test.ToxiproxyParentReplayTest(replay_file="replay/parent_markdown.replay.yaml")
Test.ToxiproxyParentReplayTest(replay_file="replay/parent_failover.replay.yaml")
