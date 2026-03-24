'''
Verify regex_map performs anchored matching on hostnames.

This test ensures that regex_map rules only match exact hostnames,
not substrings within longer hostnames. For example, a rule for
"cdn.example.com" should NOT match "prefix.cdn.example.com.evil.com".
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
Verify regex_map performs anchored matching on hostnames.
'''

Test.ATSReplayTest(replay_file="replay/regex_map_anchor.replay.yaml")
