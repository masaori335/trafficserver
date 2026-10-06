'''
Test mp4.so query rewriting for queries larger than a fixed buffer.
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
Test that mp4.so removes the start parameter from a query and reproduces the
rest of it exactly, including queries larger than one kilobyte, and that a
start value it cannot use is refused with a 400 when it is negative and
otherwise leaves the request alone.
'''

Test.SkipUnless(Condition.PluginExists('mp4.so'))

Test.ATSReplayTest(replay_file="mp4_query_rewrite.replay.yaml")
