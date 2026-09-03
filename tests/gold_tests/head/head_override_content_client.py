#!/usr/bin/env python3
"""A client that sends a HEAD request carrying a declared message body.

Proxy Verifier zeroes the content length of any HEAD request, so it cannot put a
body on the wire for one. This client writes the framing itself, which is what
exercises proxy.config.http.reject_head_with_content: with the check enabled the
proxy must answer 400, and with it disabled the proxy must forward the request
and its body to the origin.
"""

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

import argparse
import socket
import sys

BODY = b'hello'


def parse_args() -> argparse.Namespace:
    """Parse the command line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proxy_address", help="Address of the proxy to connect to.")
    parser.add_argument("proxy_port", type=int, help="The port of the proxy to connect to.")
    parser.add_argument("host", help="The Host header field value to use.")
    parser.add_argument("path", help="The request target to use.")
    return parser.parse_args()


def build_request(host: str, path: str) -> bytes:
    """Build a HEAD request that declares and then sends a body.

    :param host: The Host header field value.
    :param path: The request target.
    :returns: The raw request bytes.
    """
    head = (f'HEAD {path} HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            f'Content-Length: {len(BODY)}\r\n'
            f'Connection: close\r\n'
            f'\r\n').encode()
    return head + BODY


def main() -> int:
    """Send the request and print the response that came back."""
    args = parse_args()

    request = build_request(args.host, args.path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((args.proxy_address, args.proxy_port))
        print(f'Connected to {args.proxy_address}:{args.proxy_port}')
        print(f'Sending request ({len(request)} bytes):')
        print(request)
        sys.stdout.flush()
        sock.sendall(request)

        # A HEAD response has no message body, so the response ends at the blank
        # line after the header block. Keep reading until then so a proxy that
        # stalls waiting on the request body is caught by the timeout rather than
        # looking like a short response.
        sock.settimeout(10.0)
        response = b""
        try:
            while b'\r\n\r\n' not in response:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
        except socket.timeout:
            print('READ_TIMED_OUT: yes')

    print('==== RESPONSE RECEIVED ====')
    print(response.decode(errors='replace'))
    print('==== END RESPONSE ====')

    status = response.split(b'\r\n', 1)[0].decode(errors='replace') if response else ''
    print(f'STATUS_LINE: {status}')
    # A HEAD response must not carry a body, whatever Content-Length says.
    _, _, after_headers = response.partition(b'\r\n\r\n')
    print(f'RESPONSE_BODY_LEN: {len(after_headers)}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
