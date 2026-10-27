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

import socket
import ssl
import struct
import threading

import pytest

from tools.uranium.services import ATS, ATSFactory

COMPRESS_CERTIFICATE = 27
ALGORITHM_IDS = {"zlib": 1, "brotli": 2, "zstd": 3}
HANDSHAKE = 22
CLIENT_HELLO = 1
CERTIFICATE_REQUEST = 13


def parse_extensions(data: bytes) -> dict[int, bytes]:
    """Split a TLS extension block into type and body.

    :param data: Extension block, starting with its two-byte length.
    """

    (length,) = struct.unpack_from("!H", data, 0)
    extensions = {}
    offset = 2
    while offset < 2 + length:
        ext_type, ext_length = struct.unpack_from("!HH", data, offset)
        extensions[ext_type] = data[offset + 4:offset + 4 + ext_length]
        offset += 4 + ext_length
    return extensions


def compression_algorithms(extensions: dict[int, bytes]) -> list[int]:
    """Return the algorithms offered in a compress_certificate extension.

    :param extensions: Parsed extensions of one handshake message.
    """

    body = extensions.get(COMPRESS_CERTIFICATE)
    if body is None:
        return []
    return [struct.unpack_from("!H", body, 1 + i)[0] for i in range(0, body[0], 2)]


def client_hello_extensions(record: bytes) -> dict[int, bytes]:
    """Parse the extensions of a plaintext ClientHello record.

    :param record: The first TLS record a client sent.
    """

    assert record[0] == HANDSHAKE and record[5] == CLIENT_HELLO, record[:8].hex()
    offset = 5 + 4 + 2 + 32
    offset += 1 + record[offset]
    offset += 2 + struct.unpack_from("!H", record, offset)[0]
    offset += 1 + record[offset]
    return parse_extensions(record[offset:])


def outbound_client_hello(ats: ATS, origin: socket.socket) -> dict[int, bytes]:
    """Send one request through ATS and capture the ClientHello it sends the origin.

    :param ats: Traffic Server remapping to the origin socket.
    :param origin: Listening socket standing in for a TLS origin.
    """

    def request() -> None:
        with socket.create_connection(("127.0.0.1", ats.http_port), timeout=10) as client:
            client.sendall(b"GET / HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
            try:
                while client.recv(4096):
                    pass
            except OSError:
                pass

    sender = threading.Thread(target=request, daemon=True)
    sender.start()
    origin.settimeout(10)
    conn, _ = origin.accept()
    with conn:
        conn.settimeout(10)
        record = b""
        while len(record) < 5 or len(record) < 5 + struct.unpack_from("!H", record, 3)[0]:
            chunk = conn.recv(65536)
            assert chunk, f"origin connection closed after {len(record)} bytes"
            record += chunk
    sender.join(10)
    return client_hello_extensions(record)


def inbound_certificate_request(ats: ATS) -> dict[int, bytes]:
    """Handshake with ATS and capture the CertificateRequest it sends.

    :param ats: Traffic Server that asks clients for a certificate.
    """

    messages = []

    def observe(_conn, direction, _version, content_type, msg_type, data) -> None:
        if direction == "read" and content_type == HANDSHAKE and msg_type == CERTIFICATE_REQUEST:
            messages.append(bytes(data))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context._msg_callback = observe
    with socket.create_connection(("127.0.0.1", ats.https_port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname="ats.test"):
            pass
    assert len(messages) == 1, f"saw {len(messages)} CertificateRequest messages"
    body = messages[0][4:]
    return parse_extensions(body[1 + body[0]:])


def start_ats(ats_factory: ATSFactory, name: str, origin_port: int, algorithms: str | None) -> ATS:
    """Start ATS with TLS both ways and the given compression setting.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param name: Unique Traffic Server name within this test.
    :param origin_port: Port of the TLS origin stand-in.
    :param algorithms: Value for both cert_compression.algorithms records, or None to leave them unset.
    """

    ats = ats_factory.create(name, enable_tls=True, enable_cache=False)
    ats.add_default_ssl_files()
    ats.remap_config.add_line(f"map / https://127.0.0.1:{origin_port}/")
    records = {
        "proxy.config.ssl.client.certification_level": 1,
        "proxy.config.ssl.CA.cert.filename": str(ats.ssl_directory / "server.pem"),
        "proxy.config.ssl.client.verify.server.policy": "DISABLED",
    }
    if algorithms is not None:
        records["proxy.config.ssl.server.cert_compression.algorithms"] = algorithms
        records["proxy.config.ssl.client.cert_compression.algorithms"] = algorithms
    ats.records.update(records)
    ats.start()
    return ats


def require_openssl_cert_compression(ats_factory: ATSFactory) -> None:
    """Skip unless OpenSSL itself negotiates certificate compression by default.

    :param ats_factory: Factory for isolated Traffic Server instances.
    """

    if ats_factory.has_feature("TS_HAS_CERT_COMPRESSION_CALLBACKS") or not ats_factory.has_feature("TS_HAS_CERT_COMPRESSION"):
        pytest.skip("only OpenSSL 3.2+ built with a compression algorithm negotiates certificate compression on its own")
    if not hasattr(ssl.SSLContext, "_msg_callback"):
        pytest.skip("Python's ssl module has no message callback")


@pytest.mark.parametrize("algorithms", [None, ""], ids=["unset", "empty"])
def test_tls_cert_comp_unset(ats_factory: ATSFactory, algorithms: str | None) -> None:
    """With no algorithms configured, ATS offers certificate compression in neither direction.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param algorithms: Records value under test, None meaning the records are absent.
    """
    require_openssl_cert_compression(ats_factory)

    with socket.create_server(("127.0.0.1", 0)) as origin:
        ats = start_ats(ats_factory, "ts", origin.getsockname()[1], algorithms)
        outbound = compression_algorithms(outbound_client_hello(ats, origin))
    inbound = compression_algorithms(inbound_certificate_request(ats))

    assert (outbound, inbound) == ([], []), f"ClientHello to the origin offered {outbound}, CertificateRequest offered {inbound}"


def test_tls_cert_comp_configured(ats_factory: ATSFactory) -> None:
    """A configured algorithm is offered in both directions, so the observers can see the extension.

    :param ats_factory: Factory for isolated Traffic Server instances.
    """
    require_openssl_cert_compression(ats_factory)

    algorithm = next(
        name for name in ("zlib", "brotli", "zstd") if ats_factory.has_feature(f"TS_HAS_CERT_COMPRESSION_{name.upper()}"))
    with socket.create_server(("127.0.0.1", 0)) as origin:
        ats = start_ats(ats_factory, "ts", origin.getsockname()[1], algorithm)
        outbound = compression_algorithms(outbound_client_hello(ats, origin))
    inbound = compression_algorithms(inbound_certificate_request(ats))

    expected = [ALGORITHM_IDS[algorithm]]
    assert (outbound, inbound) == (expected, expected), \
        f"ClientHello to the origin offered {outbound}, CertificateRequest offered {inbound}"
