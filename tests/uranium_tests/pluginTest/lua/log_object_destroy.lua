--  Licensed to the Apache Software Foundation (ASF) under one
--  or more contributor license agreements.  See the NOTICE file
--  distributed with this work for additional information
--  regarding copyright ownership.  The ASF licenses this file
--  to you under the Apache License, Version 2.0 (the
--  "License"); you may not use this file except in compliance
--  with the License.  You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
--  Unless required by applicable law or agreed to in writing, software
--  distributed under the License is distributed on an "AS IS" BASIS,
--  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--  See the License for the specific language governing permissions and
--  limitations under the License.

-- object_creat reads the log mode from stack index 3, so it needs method
-- syntax. 2 is TS_LOG_MODE_DO_NOT_RENAME; the plugin injects no named
-- constant for it.
function __init__(argtb)
  ts.log:object_creat('lua_object_destroy', 2)
end

function do_remap()
  ts.log.object_write('before destroy')

  ts.log:object_destroy()

  -- The second destroy reaches TSTextLogObjectDestroy() with a stale handle
  -- unless object_destroy() clears it and guards on null. That function
  -- sdk_asserts on a null handle, which aborts traffic_server.
  ts.log:object_destroy()

  -- object_write() only guards on the handle being non-null, so a handle left
  -- dangling by destroy would be passed to TSTextLogObjectWrite().
  ts.log.object_write('after destroy')

  return 0
end
