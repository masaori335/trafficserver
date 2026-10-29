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

from pathlib import Path
import re
import sys

from tools.uranium.services import ATS, ATSFactory, OriginServer, ProcessService, ServiceFactory, wait_for_file_lines

TEST_DIRECTORY = Path(__file__).parent

# Python escapes in this value are interpreted by the client.
SNI = r'a"b\\c\r\nX-Forwarded-User: admin\x7f'

ESCAPES = ("default", "none")


def configure_origin(services: ServiceFactory) -> OriginServer:
    """Serve the request sent after the TLS handshake.

    :param services: Factory owning support services and their cleanup.
    """

    origin = services.origin("origin")
    origin.add_response(
        {
            "headers": "GET /test HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            "body": ""
        },
        {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            "body": "ok"
        },
    )
    return origin


def configure_ats(ats_factory: ATSFactory, *, _origin: OriginServer) -> ATS:
    """Log the client SNI with and without an explicit escape.

    :param _origin: Test-local origin configured by the test.
    :param ats_factory: Factory for isolated Traffic Server instances.
    """

    ats = ats_factory.create("ts", enable_cache=False, enable_tls=True)
    ats.remap_config.add_line(f"map / http://127.0.0.1:{_origin.port}/")

    formats = []
    for escape in ESCAPES:
        log_format = {"name": f"cssn_{escape}", "format": f"{escape}:%<cssn>"}
        if escape != "default":
            log_format["escape"] = escape
        formats.append(log_format)

    ats.set_logging_yaml(
        {
            "logging":
                {
                    "formats": formats,
                    "logs": [{
                        "filename": f"cssn-{escape}",
                        "format": f"cssn_{escape}"
                    } for escape in ESCAPES],
                }
        })
    return ats


def configure_client(services: ServiceFactory, *, _ats: ATS) -> ProcessService:
    """Complete a TLS handshake with control bytes in the SNI.

    :param _ats: Test-local ats configured by the test.
    :param services: Factory owning support services and their cleanup.
    """

    return services.process(
        "client", [
            sys.executable,
            TEST_DIRECTORY / "tls_sni_client.py",
            "127.0.0.1",
            str(_ats.https_port),
            SNI,
            "/test",
        ])


def test_log_field_sni_escape(ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """The client SNI log field is escaped unless the format chooses otherwise.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    """
    _origin = configure_origin(services)
    _ats = configure_ats(ats_factory, _origin=_origin)
    _client = configure_client(services, _ats=_ats)

    _origin.start()
    _ats.start()
    result = _client.run(timeout=10)
    assert result.returncode == 0, result.output

    logs = {
        escape: wait_for_file_lines(_ats.log_directory / f"cssn-{escape}.log", rf"^{escape}:", 1, timeout=30) for escape in ESCAPES
    }

    expected = r'a\\x22b\\x5cc\\x0d\\x0aX-Forwarded-User: admin\\x7f$'
    assert re.search(rf"(?m)^default:{expected}", logs["default"]), "The SNI is escaped by default."
    assert not re.search(r"(?m)^X-Forwarded-User:", logs["default"]), "The SNI does not start a new log line."

    # An explicit none writes the bytes as they are, which also shows the client sent them.
    assert re.search(r"(?m)^X-Forwarded-User: admin", logs["none"]), "An explicit none keeps the bytes as they are."
