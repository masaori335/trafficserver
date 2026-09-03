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

-- object_creat reads the log mode from stack index 3, so it must be called
-- with method syntax: self, name, mode. 2 is TS_LOG_MODE_DO_NOT_RENAME; the
-- plugin injects no named constant for it.
function __init__(argtb)
  ts.log:object_creat('lua_object_write', 2)
end

function do_remap()
  -- The conversion specifiers here must reach the log verbatim. Before the
  -- fix this string was passed as TSTextLogObjectWrite()'s format argument,
  -- so %s and %d consumed nonexistent varargs.
  ts.log.object_write('literal %s and %d and %n and %p tokens')
  return 0
end
