#!/usr/bin/env python3
"""An origin server that records the request body it received for a HEAD request.

Proxy Verifier zeroes the content length of any HEAD request, so it cannot put a
body on the wire for one. This server parses the framing itself and prints the
body it read, so a test can verify that the proxy forwarded a HEAD request body
rather than swallowing it or stalling on it.

The response deliberately advertises a non-zero Content-Length with no message
body, which is what a HEAD response looks like.
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
import signal
import socket
import sys

# Advertised on the response without a body, as a HEAD response must.
RESPONSE_CONTENT_LENGTH = 14


def parse_args() -> argparse.Namespace:
    """Parse the command line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", help="Address to listen on.")
    parser.add_argument("port", type=int, help="The port to listen on.")
    return parser.parse_args()


def get_listening_socket(address: str, port: int) -> socket.socket:
    """Create a listening socket.

    :param address: The address to bind to.
    :param port: The port to bind to.
    :returns: The listening socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(1)
    return sock


def recv_until(sock: socket.socket, buffer: bytes, delimiter: bytes) -> bytes:
    """Read from the socket until the buffer contains the delimiter.

    :param sock: The socket to read from.
    :param buffer: Bytes already read from the socket.
    :param delimiter: The delimiter to read until.
    :returns: The buffer, guaranteed to contain the delimiter, or all bytes read
        before the socket closed.
    """
    while delimiter not in buffer:
        data = sock.recv(4096)
        if not data:
            break
        buffer += data
    return buffer


def content_length_of(header_lines: list) -> int:
    """Extract the Content-Length value from the request header lines.

    :param header_lines: The request header field lines, without the request line.
    :returns: The declared Content-Length, or 0 if absent or malformed.
    """
    for line in header_lines:
        name, _, value = line.partition(':')
        if name.strip().lower() == 'content-length':
            try:
                return int(value.strip())
            except ValueError:
                return 0
    return 0


def handle_connection(sock: socket.socket) -> None:
    """Read one request, report the body that arrived with it, and respond.

    :param sock: The accepted client socket.
    """
    sock.settimeout(10.0)
    try:
        buffer = recv_until(sock, b"", b'\r\n\r\n')
    except socket.timeout:
        print("Timed out waiting for the request header.")
        sys.stdout.flush()
        return
    if b'\r\n\r\n' not in buffer:
        print("Connection closed before a complete request header arrived.")
        sys.stdout.flush()
        return

    header_bytes, _, body = buffer.partition(b'\r\n\r\n')
    lines = header_bytes.decode(errors='replace').split('\r\n')
    request_line = lines[0]
    content_length = content_length_of(lines[1:])

    # Read exactly the advertised body. A proxy that declared Content-Length but
    # never forwarded the body shows up here as a short read, not as a hang,
    # because the timeout bounds the wait.
    timed_out = False
    try:
        while len(body) < content_length:
            data = sock.recv(4096)
            if not data:
                break
            body += data
    except socket.timeout:
        timed_out = True
    body = body[:content_length]

    print('---- ORIGIN REQUEST ----')
    print(f'REQUEST_LINE: {request_line}')
    for line in lines[1:]:
        print(f'HEADER: {line}')
    print(f'DECLARED_CONTENT_LENGTH: {content_length}')
    print(f'BODY_LEN: {len(body)}')
    print(f'BODY: {body!r}')
    if timed_out:
        print('BODY_TIMED_OUT: yes')
    print('---- END ORIGIN REQUEST ----')
    sys.stdout.flush()

    # A HEAD response carries no message body even though Content-Length is set.
    sock.sendall(
        b'HTTP/1.1 200 OK\r\n'
        b'X-Origin-Response: head-override\r\n'
        b'Content-Type: text/plain\r\n'
        b'Content-Length: ' + str(RESPONSE_CONTENT_LENGTH).encode() + b'\r\n'
        b'\r\n')


def main() -> int:
    """Run the recording origin server until terminated by the test harness."""
    # The test harness stops long-running processes with SIGTERM. Register
    # SIGINT too, explicitly, because it may be inherited as ignored from the
    # launcher.
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    args = parse_args()
    try:
        with get_listening_socket(args.address, args.port) as listening_sock:
            print(f"Listening on {args.address}:{args.port}")
            sys.stdout.flush()
            while True:
                conn, _ = listening_sock.accept()
                with conn:
                    handle_connection(conn)
    except (KeyboardInterrupt, SystemExit):
        # SIGTERM from the test harness or a Ctrl-C is a clean shutdown.
        pass
    except OSError as e:
        # An unexpected socket error (e.g. bind or accept failure) should be
        # surfaced with a non-zero exit rather than masked as success.
        print(f"Origin server error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
