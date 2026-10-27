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

import pytest

from tools.uranium.services import ATS, ATSFactory, CommandResult, Curl, OriginServer, ServiceFactory


def configure_origin(services: ServiceFactory) -> OriginServer:
    """Serve the request used to increment the reputation buckets.

    :param services: Factory owning support services and their cleanup.
    """

    origin = services.origin("origin")
    origin.add_response(
        {
            "headers": "GET /test HTTP/1.1\r\nHost: iprep.example.com\r\n\r\n",
            "body": ""
        },
        {
            "headers": "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n",
            "body": "OK"
        },
    )
    return origin


def configure_ats(ats_factory: ATSFactory, *, _origin: OriginServer, size: int | None = 10, buckets: int = 5) -> ATS:
    """Configure an IP-reputation table and the SNI selector.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param _origin: Test-local origin configured by the test.
    :param size: The ip-rep ``size``, or None to leave it unset.
    :param buckets: The ip-rep ``buckets``.
    """

    size_line = "" if size is None else f"    size: {size}\n"
    ats = ats_factory.create("ts", enable_tls=True)
    if not ats.plugin_exists("rate_limit.so"):
        pytest.skip("rate_limit.so is required")
    ats.write_config_file(
        "rate_limit.yaml",
        "ip-rep:\n"
        "  - name: test-iprep\n"
        f"    buckets: {buckets}\n"
        f"{size_line}"
        "    percentage: 90\n"
        "    max_age: 300\n"
        "selector:\n"
        "  - sni: iprep.example.com\n"
        "    limit: 100\n"
        "    ip-rep: test-iprep\n",
    )
    ats.plugin_config.add_line(f"rate_limit.so {ats.config_directory}/rate_limit.yaml")
    ats.records.update(
        {
            "proxy.config.diags.debug.enabled": 1,
            "proxy.config.diags.debug.tags": "rate_limit",
            "proxy.config.http.insert_response_via_str": 0,
            "proxy.config.url_remap.remap_required": 0,
        })
    ats.remap_config.add_line(f"map / http://127.0.0.1:{_origin.port}/")
    return ats


def request(*, _ats: ATS, _curl: Curl) -> CommandResult:
    """Open a fresh TLS connection with the selector's SNI.

    :param _ats: Test-local ats configured by the test.
    :param _curl: Test-local curl configured by the test.
    """

    return _curl.run(
        (
            f"--silent --insecure --output /dev/null --write-out '%{{http_code}}' --resolve "
            f"'iprep.example.com:{_ats.https_port}:127.0.0.1' "
            f"'https://iprep.example.com:{_ats.https_port}/test'"),)


# Size 4 with 5 buckets is the smallest accepted size, leaving a single-entry last bucket.
@pytest.mark.parametrize("size", [10, 4])
def test_rate_limit_iprep(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, size: int) -> None:
    """IP-reputation buckets are sized before indexed initialization and updates.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param size: The ip-rep ``size``.
    """
    _origin = configure_origin(services)
    _ats = configure_ats(ats_factory, _origin=_origin, size=size)

    _origin.start()
    _ats.start()
    for _ in range(6):
        result = request(_ats=_ats, _curl=curl)
        assert result.returncode == 0, result.output
        assert result.stdout == "200", result.output
    assert "FATAL" not in _ats.diags_log.read_text(errors="replace")


def test_rate_limit_iprep_default_size_disabled(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """An ip-rep node without ``size`` is disabled rather than creating unbounded buckets.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """
    _origin = configure_origin(services)
    _ats = configure_ats(ats_factory, _origin=_origin, size=None)

    _origin.start()
    _ats.start()
    result = request(_ats=_ats, _curl=curl)
    assert result.returncode == 0, result.output
    assert result.stdout == "200", result.output
    assert "has no size, IP reputation is disabled" in _ats.diags_log.read_text(errors="replace")
    assert "no IP reputation" in _ats.traffic_out.read_text(errors="replace")


# One case per clause of the sizing guard in SieveLru::parseYaml().
@pytest.mark.parametrize(("size", "buckets"), [(3, 5), (31, 5), (10, 0)])
def test_rate_limit_iprep_invalid_size(ats_factory: ATSFactory, services: ServiceFactory, size: int, buckets: int) -> None:
    """An ip-rep size the buckets cannot be derived from fails the configuration load.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param size: The ip-rep ``size``.
    :param buckets: The ip-rep ``buckets``.
    """
    _origin = configure_origin(services)
    _ats = configure_ats(ats_factory, _origin=_origin, size=size, buckets=buckets)
    _ats.expect_start_failure(r"Invalid ip-rep test-iprep", return_code=70)

    _ats.start()
    assert not _ats.is_running
    assert "Invalid ip-rep test-iprep" in _ats.diags_log.read_text(errors="replace")
