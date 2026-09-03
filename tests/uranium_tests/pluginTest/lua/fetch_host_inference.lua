--  Licensed to the Apache Software Foundation (ASF) under one
--  or more contributor license agreements.  See the NOTICE file
--  distributed with this work for additional information
--  regarding copyright ownership.  The ASF licenses this file
--  to you under the Apache License, Version 2.0 (the
--  "License"); you may not use this file except in compliance
--  with the License.  You may obtain a copy of the License at
--
--  http://www.apache.org/licenses/LICENSE-2.0
--
--  Unless required by applicable law or agreed to in writing, software
--  distributed under the License is distributed on an "AS IS" BASIS,
--  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--  See the License for the specific language governing permissions and
--  limitations under the License.

local origin

function __init__(argtb)
    origin = argtb[1]
end

function send_response()
    if ts.ctx['status'] ~= nil then
        ts.client_response.header['Sub-Status'] = ts.ctx['status']
    end
    if ts.ctx['body_len'] ~= nil then
        ts.client_response.header['Sub-Body-Len'] = ts.ctx['body_len']
    end
end

function post_remap()
    if ts.http.is_internal_request() ~= 0 then
        return 0
    end

    -- No Host header is supplied, so the plugin has to infer it from the URL.
    -- The authority is followed directly by the query with no path in between,
    -- so a scan that stops only at '/' runs past the end of the authority.
    local url = string.format('http://%s?x=1', origin)
    local res = ts.fetch(url, {method = 'GET'})
    if res then
        ts.ctx['status'] = res.status
        ts.ctx['body_len'] = string.len(res.body or '')
    end

    -- A colon that is not followed by "//" is not a scheme delimiter, so no
    -- Host may be inferred from it. This must not crash or read past the URL.
    ts.fetch('http:/inner.txt', {method = 'GET'})
end

function do_remap()
    if ts.http.is_internal_request() ~= 0 then
        -- The sub-request re-enters remap, so the Host the plugin inferred can
        -- be inspected here. Answering 400 on a mismatch surfaces the actual
        -- value in the outer response rather than relying on the origin to
        -- reject it.
        local host = ts.client_request.header['Host']
        if host == origin then
            ts.http.set_resp(204, '')
        else
            ts.http.set_resp(400, 'inferred host: ' .. tostring(host))
        end
        return 0
    end
    ts.hook(TS_LUA_HOOK_POST_REMAP, post_remap)
    ts.hook(TS_LUA_HOOK_SEND_RESPONSE_HDR, send_response)
end
