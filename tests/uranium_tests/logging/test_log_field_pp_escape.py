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

import pytest

from tools.uranium.services import ATS, ATSFactory, OriginServer, ProcessService, ServiceFactory, wait_for_file_lines

TEST_DIRECTORY = Path(__file__).parent

# Python escapes in this value are interpreted by the client.
AUTHORITY = r'a"b\\c\r\nX-Forwarded-User: admin\x7f'
# AUTHORITY values containing a NUL, and how each is logged.
NUL_AUTHORITIES = (
    (r'a\x00XXXXXX\r\nFORGED', 'a'),
    (r'\x00XXXXXXX\r\nFORGED', '-'),
)

ESCAPES = ("default", "none", "hex", "json")


def configure_origin(services: ServiceFactory) -> OriginServer:
    """Serve the request sent after the PROXY protocol header.

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
    """Log the AUTHORITY TLV with each escape setting, plus one format with no escape setting.

    :param _origin: Test-local origin configured by the test.
    :param ats_factory: Factory for isolated Traffic Server instances.
    """

    ats = ats_factory.create("ts", enable_cache=False, enable_proxy_protocol=True)
    ats.records.update({"proxy.config.http.proxy_protocol_allowlist": "127.0.0.1"})
    ats.remap_config.add_line(f"map / http://127.0.0.1:{_origin.port}/")

    formats = []
    for escape in ESCAPES:
        log_format = {"name": f"ppa_{escape}", "format": f"{escape}:%<ppa>"}
        if escape != "default":
            log_format["escape"] = escape
        formats.append(log_format)

    ats.set_logging_yaml(
        {
            "logging":
                {
                    "formats": formats,
                    "logs": [{
                        "filename": f"ppa-{escape}",
                        "format": f"ppa_{escape}"
                    } for escape in ESCAPES],
                }
        })
    return ats


def configure_nul_ats(ats_factory: ATSFactory, *, _origin: OriginServer) -> ATS:
    """Log the AUTHORITY TLV followed by another string field, with no escape setting.

    :param _origin: Test-local origin configured by the test.
    :param ats_factory: Factory for isolated Traffic Server instances.
    """

    ats = ats_factory.create("ts", enable_cache=False, enable_proxy_protocol=True)
    ats.records.update({"proxy.config.http.proxy_protocol_allowlist": "127.0.0.1"})
    ats.remap_config.add_line(f"map / http://127.0.0.1:{_origin.port}/")
    ats.set_logging_yaml(
        {
            "logging":
                {
                    "formats": [{
                        "name": "ppa_nul",
                        "format": "nul:%<ppa> %<cqup>"
                    }],
                    "logs": [{
                        "filename": "ppa-nul",
                        "format": "ppa_nul"
                    }],
                }
        })
    return ats


def configure_client(services: ServiceFactory, *, _ats: ATS, _authority: str = AUTHORITY) -> ProcessService:
    """Send a PROXY protocol v2 header with control bytes in the AUTHORITY TLV.

    :param _ats: Test-local ats configured by the test.
    :param _authority: AUTHORITY TLV value, with Python escapes.
    :param services: Factory owning support services and their cleanup.
    """

    return services.process(
        "client", [
            sys.executable,
            TEST_DIRECTORY / "pp2_tlv_client.py",
            "127.0.0.1",
            str(_ats.proxy_protocol_port),
            _authority,
            "/test",
        ])


def test_log_field_pp_escape(ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """PROXY protocol TLV log fields are escaped unless the format chooses otherwise.

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
        escape: wait_for_file_lines(_ats.log_directory / f"ppa-{escape}.log", rf"^{escape}:", 1, timeout=30) for escape in ESCAPES
    }

    # Escaped by default, and with an explicit hex.
    expected = r'a\\x22b\\x5cc\\x0d\\x0aX-Forwarded-User: admin\\x7f$'
    for escape in ("default", "hex"):
        assert re.search(rf"(?m)^{escape}:{expected}", logs[escape]), f"The AUTHORITY TLV is escaped in the {escape} log."
        assert not re.search(r"(?m)^X-Forwarded-User:", logs[escape]), "The TLV does not start a new log line."

    # An explicit none writes the bytes as they are.
    assert re.search(r"(?m)^X-Forwarded-User: admin", logs["none"]), "An explicit none keeps the bytes as they are."

    # JSON escape still applies when specified.
    assert re.search(r'(?m)^json:a\\"b\\\\c\\r\\nX-Forwarded-User: admin', logs["json"]), "The JSON escape still applies."


@pytest.mark.parametrize("authority,expected", NUL_AUTHORITIES, ids=["embedded", "leading"])
def test_log_field_pp_nul(authority: str, expected: str, ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """A NUL in a PROXY protocol TLV ends the logged value without shifting the next field.

    :param authority: AUTHORITY TLV value, with Python escapes.
    :param expected: The logged AUTHORITY value.
    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    """
    _origin = configure_origin(services)
    _ats = configure_nul_ats(ats_factory, _origin=_origin)
    _client = configure_client(services, _ats=_ats, _authority=authority)

    _origin.start()
    _ats.start()
    result = _client.run(timeout=10)
    assert result.returncode == 0, result.output

    log = wait_for_file_lines(_ats.log_directory / "ppa-nul.log", r"^nul:", 1, timeout=30)

    assert re.search(
        rf"(?m)^nul:{re.escape(expected)} test$", log), "The AUTHORITY TLV ends at the NUL and the next field is read correctly."
    assert not re.search(r"(?m)^FORGED", log), "The bytes after the NUL do not reach the log."
