#!/usr/bin/env python3
'''Send a PROXY protocol v2 header with an AUTHORITY TLV, then an HTTP request.'''
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
import struct

VERSION_2_SIGNATURE = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
PP2_TYPE_AUTHORITY = 0x02


def construct_header(authority: bytes) -> bytes:
    addresses = socket.inet_pton(socket.AF_INET, '1.2.3.4') + socket.inet_pton(socket.AF_INET, '5.6.7.8') + struct.pack(
        '!HH', 1234, 80)
    tlv = struct.pack('!BH', PP2_TYPE_AUTHORITY, len(authority)) + authority
    # Protocol version 2 + PROXY command, TCP over IPv4
    return VERSION_2_SIGNATURE + b'\x21\x11' + struct.pack('!H', len(addresses) + len(tlv)) + addresses + tlv


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('address', help='The ATS address.')
    parser.add_argument('port', type=int, help='The ATS PROXY protocol port.')
    parser.add_argument('authority', help='The AUTHORITY TLV value. Python escapes such as \\r and \\n are interpreted.')
    parser.add_argument('path', help='The request target.')
    args = parser.parse_args()

    authority = args.authority.encode('latin-1').decode('unicode_escape').encode('latin-1')
    request = f'GET {args.path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'.encode()

    with socket.create_connection((args.address, args.port), timeout=10) as s:
        s.sendall(construct_header(authority) + request)
        while s.recv(4096):
            pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
