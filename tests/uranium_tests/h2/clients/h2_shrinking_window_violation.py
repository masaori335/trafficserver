#!/usr/bin/env python3
'''
HTTP/2 client that exceeds ATS's receive connection window while it shrinks.
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

import argparse
import socket
import ssl
from typing import Tuple

CONNECTION_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

FRAME_TYPE_DATA = 0
FRAME_TYPE_HEADERS = 1
FRAME_TYPE_SETTINGS = 4
FRAME_TYPE_GOAWAY = 7

FLAG_END_STREAM = 0x01
FLAG_END_HEADERS = 0x04
FLAG_SETTINGS_ACK = 0x01

ERROR_FLOW_CONTROL = 3

BODY_SIZE = 32768
DATA_CHUNK_SIZE = 16384


def make_socket(port: int) -> ssl.SSLSocket:
    """Create a TLS-wrapped HTTP/2 socket."""

    socket.setdefaulttimeout(10)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2'])

    raw_socket = socket.create_connection(('localhost', port))
    tls_socket = ctx.wrap_socket(raw_socket, server_hostname='localhost')
    negotiated = tls_socket.selected_alpn_protocol()
    if negotiated != 'h2':
        raise RuntimeError(f'Expected h2 ALPN, negotiated {negotiated!r}')
    return tls_socket


def make_frame(frame_type: int, flags: int = 0, stream_id: int = 0, payload: bytes = b'') -> bytes:
    """Serialize a minimal HTTP/2 frame."""

    return (len(payload).to_bytes(3, 'big') + bytes([frame_type, flags]) + (stream_id & 0x7fffffff).to_bytes(4, 'big') + payload)


def read_exact(sock: ssl.SSLSocket, size: int) -> bytes:
    """Read exactly @a size bytes or raise EOFError."""

    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError('socket closed')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def read_frame(sock: ssl.SSLSocket) -> Tuple[int, int, int, bytes]:
    """Read and parse one HTTP/2 frame."""

    header = read_exact(sock, 9)
    length = int.from_bytes(header[0:3], 'big')
    frame_type = header[3]
    flags = header[4]
    stream_id = int.from_bytes(header[5:9], 'big') & 0x7fffffff
    payload = read_exact(sock, length)
    return frame_type, flags, stream_id, payload


def hpack_string(value: str) -> bytes:
    """Encode a short, non-Huffman HPACK string literal."""

    encoded = value.encode('utf-8')
    if len(encoded) >= 128:
        raise ValueError('test header value is too long for this helper')
    return bytes([len(encoded)]) + encoded


def hpack_literal_header(name: str, value: str) -> bytes:
    """Encode a non-indexed HPACK literal header with a new name."""

    return b'\x00' + hpack_string(name) + hpack_string(value)


def request_header_block(stream_id: int) -> bytes:
    """Build a tiny HPACK request block."""

    block = bytearray()
    block.append(0x83)  # :method: POST
    block.append(0x87)  # :scheme: https
    block.append(0x01)  # :authority literal without indexing, indexed name 1
    block.extend(hpack_string('localhost'))
    block.append(0x04)  # :path literal without indexing, indexed name 4
    block.extend(hpack_string(f'/window-{stream_id}'))
    block.extend(hpack_literal_header('content-length', str(BODY_SIZE)))
    block.extend(hpack_literal_header('uuid', f'shrinking-window-{stream_id}'))
    return bytes(block)


def read_server_settings(sock: ssl.SSLSocket) -> None:
    """Read frames through ATS's initial SETTINGS frame."""

    while True:
        frame_type, flags, _stream_id, _payload = read_frame(sock)
        if frame_type == FRAME_TYPE_SETTINGS and not (flags & FLAG_SETTINGS_ACK):
            return


def send_request(sock: ssl.SSLSocket, stream_id: int) -> None:
    """Send one POST request whose body consumes half the default connection window."""

    sock.sendall(make_frame(FRAME_TYPE_HEADERS, FLAG_END_HEADERS, stream_id, request_header_block(stream_id)))
    bytes_left = BODY_SIZE
    while bytes_left > 0:
        chunk_size = min(DATA_CHUNK_SIZE, bytes_left)
        bytes_left -= chunk_size
        flags = FLAG_END_STREAM if bytes_left == 0 else 0
        sock.sendall(make_frame(FRAME_TYPE_DATA, flags, stream_id, b'x' * chunk_size))


def run(port: int) -> int:
    """Return zero only if ATS sends the expected FLOW_CONTROL_ERROR GOAWAY."""

    with make_socket(port) as sock:
        sock.sendall(CONNECTION_PREFACE)
        sock.sendall(make_frame(FRAME_TYPE_SETTINGS))
        read_server_settings(sock)
        sock.sendall(make_frame(FRAME_TYPE_SETTINGS, FLAG_SETTINGS_ACK))

        send_request(sock, 1)
        send_request(sock, 3)

        try:
            while True:
                frame_type, _flags, _stream_id, payload = read_frame(sock)
                if frame_type == FRAME_TYPE_GOAWAY:
                    error_code = int.from_bytes(payload[4:8], 'big')
                    print(f'GOAWAY error_code={error_code}')
                    return 0 if error_code == ERROR_FLOW_CONTROL else 1
        except (EOFError, socket.timeout) as exc:
            print(f'Expected FLOW_CONTROL_ERROR GOAWAY, got {exc!r}')
            return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('port', type=int, help='ATS TLS port')
    args = parser.parse_args()
    return run(args.port)


if __name__ == '__main__':
    raise SystemExit(main())
