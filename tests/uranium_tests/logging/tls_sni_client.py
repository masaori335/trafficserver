#!/usr/bin/env python3
'''Complete a TLS handshake with the given SNI, then send an HTTP request.'''
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
import ssl


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('address', help='The ATS address.')
    parser.add_argument('port', type=int, help='The ATS TLS port.')
    parser.add_argument('sni', help='The SNI value. Python escapes such as \\r and \\n are interpreted.')
    parser.add_argument('path', help='The request target.')
    args = parser.parse_args()

    sni = args.sni.encode('latin-1').decode('unicode_escape')
    request = f'GET {args.path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'.encode()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((args.address, args.port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as s:
            s.sendall(request)
            while s.recv(4096):
                pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
