'''
Verify proxy.config.http.reject_head_with_content governs whether a HEAD request
carrying a body is rejected or forwarded.
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

from ports import get_port
import sys

Test.Summary = '''
Verify proxy.config.http.reject_head_with_content governs whether a HEAD request
carrying a body is rejected or forwarded to the origin.
'''

Test.ContinueOnFail = True


class HeadOverrideContentTest:
    '''Drive a HEAD request that actually puts a body on the wire.

    head-reject-content.test.py covers this configuration everywhere Proxy
    Verifier can reach, but it cannot cover the opt-out: Proxy Verifier zeroes the
    content length of any HEAD request, so it never sends a body for one and ATS
    is left waiting for the bytes its Content-Length promised. An ad-hoc client
    writes the framing directly instead.
    '''

    _client_script: str = 'head_override_content_client.py'
    _server_script: str = 'head_override_content_server.py'
    _counter: int = 0

    def __init__(self, reject: bool) -> None:
        '''Configure a test run.

        :param reject: True to leave proxy.config.http.reject_head_with_content
            at its default of 1, False to turn it off for the mapped rule.
        '''
        self._reject = reject
        self._name = f'head_override_{"reject" if reject else "forward"}_{HeadOverrideContentTest._counter}'
        HeadOverrideContentTest._counter += 1

        description = (
            'Verify a HEAD request with a body is rejected with 400 by default.'
            if reject else 'Verify reject_head_with_content=0 forwards a HEAD request body to the origin.')
        tr = Test.AddTestRun(description)
        tr.TimeOut = 30
        self._configure_server(tr)
        self._configure_traffic_server(tr)
        self._configure_client(tr)

    def _configure_server(self, tr: 'TestRun') -> 'Process':
        '''Configure the recording origin server.

        :param tr: The test run to add the server to.
        :return: The origin server process.
        '''
        server = tr.Processes.Process(f'origin_{self._name}')
        tr.Setup.Copy(self._server_script)
        http_port = get_port(server, "http_port")
        server.Command = f'{sys.executable} {self._server_script} 127.0.0.1 {http_port} '
        server.ReturnCode = 0
        server.Ready = When.PortOpenv4(http_port)

        if self._reject:
            # ATS must reject before the request ever reaches the origin.
            server.Streams.All += Testers.ExcludesExpression(
                r'REQUEST_LINE:', 'The origin must not receive a HEAD request carrying content.')
        else:
            # The whole point of the opt-out: the request and its body are
            # forwarded unchanged.
            server.Streams.All += Testers.ContainsExpression(
                r'REQUEST_LINE: HEAD /override/content-length HTTP/1\.1', 'The origin should receive the HEAD request.')
            server.Streams.All += Testers.ContainsExpression(
                r'DECLARED_CONTENT_LENGTH: 5', 'The origin should see the Content-Length ATS forwarded.')
            server.Streams.All += Testers.ContainsExpression(r'BODY_LEN: 5', 'The origin should receive all five body bytes.')
            server.Streams.All += Testers.ContainsExpression(
                r"BODY: b'hello'", 'The origin should receive the body content unchanged.')
            # A declared body that never arrives is the failure this test exists
            # to catch, and it is distinct from a body that arrives truncated.
            server.Streams.All += Testers.ExcludesExpression(
                r'BODY_TIMED_OUT: yes', 'The origin should not have to wait out a body that never arrives.')
        self._server = server
        return server

    def _configure_traffic_server(self, tr: 'TestRun') -> 'Process':
        '''Configure ATS as a reverse proxy in front of the origin.

        :param tr: The test run to add the ATS process to.
        :return: The ATS process.
        '''
        ts = tr.MakeATSProcess(f'ts_{self._name}', enable_cache=False)
        origin = f'http://127.0.0.1:{self._server.Variables.http_port}/'
        if self._reject:
            ts.Disk.remap_config.AddLine(f'map http://reject-body.example.com/ {origin}')
        else:
            ts.Disk.remap_config.AddLine(
                f'map http://allow-body.example.com/ {origin} '
                f'@plugin=conf_remap.so @pparam=proxy.config.http.reject_head_with_content=0')
        ts.Disk.records_config.update({
            'proxy.config.diags.debug.enabled': 1,
            'proxy.config.diags.debug.tags': 'http|http_trans',
        })
        self._ts = ts
        return ts

    def _configure_client(self, tr: 'TestRun') -> 'Process':
        '''Configure the client that sends the HEAD request with a body.

        :param tr: The test run to add the client to.
        :return: The client process.
        '''
        client = tr.Processes.Default
        tr.Setup.Copy(self._client_script)
        host = 'reject-body.example.com' if self._reject else 'allow-body.example.com'
        client.Command = (
            f'{sys.executable} {self._client_script} 127.0.0.1 {self._ts.Variables.port} '
            f'{host} /override/content-length')
        client.ReturnCode = 0

        if self._reject:
            client.Streams.All += Testers.ContainsExpression(
                r'STATUS_LINE: HTTP/1\.1 400', 'ATS should reject a HEAD request carrying content with a 400.')
        else:
            client.Streams.All += Testers.ContainsExpression(
                r'STATUS_LINE: HTTP/1\.1 200', 'ATS should relay the origin 200 back to the client.')
            client.Streams.All += Testers.ContainsExpression(
                r'X-Origin-Response: head-override', 'The response should come from the origin, not ATS.')
            client.Streams.All += Testers.ContainsExpression(
                r'Content-Length: 14', 'ATS should relay the origin Content-Length header.')
            # A HEAD response carries no body regardless of Content-Length. If
            # ATS forwarded one, the client would report a non-zero length here.
            client.Streams.All += Testers.ContainsExpression(
                r'RESPONSE_BODY_LEN: 0', 'A HEAD response must not carry a message body.')
        # Waiting on the request body would show up as a client-side timeout.
        client.Streams.All += Testers.ExcludesExpression(r'READ_TIMED_OUT: yes', 'ATS should respond without stalling.')

        client.StartBefore(self._server)
        client.StartBefore(self._ts)
        return client


HeadOverrideContentTest(reject=True)
HeadOverrideContentTest(reject=False)
