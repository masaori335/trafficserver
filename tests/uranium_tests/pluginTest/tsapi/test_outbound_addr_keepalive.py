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

import re

from tools.uranium.services import ATS, ATSFactory, ProcessService, ServiceFactory, VerifierServer, wait_for_file_lines

OUTBOUND_ADDR__replay = "outbound_addr_keepalive.replay.yaml"


def configure_server(services: ServiceFactory) -> VerifierServer:
    """Create the origin that closes every upstream connection.

    :param services: Factory owning support services and their cleanup.
    """

    return services.verifier_server("server", OUTBOUND_ADDR__replay, https_ports=[])


def configure_ats(ats_factory: ATSFactory, *, _server: VerifierServer, _pinned_port: int) -> ATS:
    """Load the plugin that pins the outbound source port on the first request only.

    :param _server: Test-local server configured by the test.
    :param _pinned_port: Test-local pinned source port configured by the test.
    :param ats_factory: Factory for isolated Traffic Server instances.
    """

    ats = ats_factory.create("ts", enable_cache=False)
    ats.copy_custom_plugin("{AtsBuildUraniumTestsDir}/pluginTest/tsapi/.libs/test_TSHttpTxnOutgoingAddr.so")
    ats.plugin_config.add_line(f"test_TSHttpTxnOutgoingAddr.so {_pinned_port}")
    ats.records.update(
        {
            "proxy.config.diags.debug.enabled": 1,
            "proxy.config.diags.debug.tags": "test_outbound_addr",
            # Keep the client session alive between the two transactions.
            "proxy.config.http.keep_alive_enabled_in": 1,
        })
    ats.remap_config.add_line(f"map / http://127.0.0.1:{_server.http_port}/")
    return ats


def configure_client(services: ServiceFactory, *, _ats: ATS) -> ProcessService:
    """Create the single client session carrying both transactions.

    :param _ats: Test-local ats configured by the test.
    :param services: Factory owning support services and their cleanup.
    """

    return services.verifier_client("client", OUTBOUND_ADDR__replay, http_ports=[_ats.http_port])


def check_outbound_ports(traffic_out: str, pinned_port: int) -> str:
    """Return a failure description, or an empty string when the override did not leak.

    :param traffic_out: Contents of traffic.out holding the plugin's debug lines.
    :param pinned_port: Source port the plugin pins on the first request.
    """

    # Select by transaction, never by position. A retried upstream connect emits a
    # second line for the same transaction, so first-and-last can silently compare
    # one transaction against itself.
    by_uuid: dict[str, list[tuple[str, int]]] = {}
    pattern = r"OUTBOUND_PORT uuid=(\S+) effective=(\d{1,5}|unavailable) ssn_txn=(-?\d+)"
    for uuid, port, ssn_txn in re.findall(pattern, traffic_out):
        by_uuid.setdefault(uuid, []).append((port, int(ssn_txn)))

    # A missing first-request line means the harness never got off the ground. A
    # missing second line is different: it is one of the two shapes the leak takes,
    # so it must not be reported as an inconclusive run.
    if "first-request" not in by_uuid:
        return (
            f"No upstream connect was logged for first-request (saw {sorted(by_uuid)}). "
            "Either the plugin never loaded, or that transaction never reached "
            "SEND_REQUEST_HDR. Nothing about the override was verified.")

    if "second-request" not in by_uuid:
        first_seen = by_uuid["first-request"][0][0]
        if first_seen != "unavailable" and int(first_seen) == pinned_port:
            return (
                f"The first request bound the pinned port {pinned_port} and the second "
                "request never reached SEND_REQUEST_HDR, so no second port was logged. "
                "The likely cause is that the override persisted onto the second "
                f"transaction and its bind() to {pinned_port} failed while that port was "
                "still held by the first upstream connection. Any upstream connect "
                "failure looks the same from here: the client should show 502 connect "
                "failed for second-request, and diags.log should show the bind failure. "
                f"A second request that binds {pinned_port} outright is the other shape "
                "of the same problem.")
        return (
            f"No upstream connect was logged for second-request (saw {sorted(by_uuid)}), and "
            f"the first request did not bind the pinned port {pinned_port} either, so this "
            "run is inconclusive.")

    # Both transactions must have travelled over one client session. Two separate
    # client sessions cannot leak outbound options at all, so the ports would differ
    # and the test would pass having demonstrated nothing. The session transaction
    # count settles it, and unlike a session id it is comparable on every branch.
    # Use the first line per transaction; a retried connect repeats the same count.
    first_ssn_txn = by_uuid["first-request"][0][1]
    second_ssn_txn = by_uuid["second-request"][0][1]
    if first_ssn_txn < 1 or second_ssn_txn < 1:
        return (
            f"The client session transaction count was unreadable "
            f"(first-request={first_ssn_txn}, second-request={second_ssn_txn}), so it is "
            "unknown whether the two requests shared a session.")
    if second_ssn_txn != first_ssn_txn + 1:
        return (
            f"The two requests did not travel over one reused client session: the client "
            f"session transaction count was {first_ssn_txn} for first-request and "
            f"{second_ssn_txn} for second-request, where a reused session must count "
            f"{first_ssn_txn} then {first_ssn_txn + 1}.")

    # "unavailable" means TSHttpTxnOutgoingAddrGet gave no AF_INET address, so there
    # is no bound port to compare.
    for want in ("first-request", "second-request"):
        if any(port == "unavailable" for port, _ in by_uuid[want]):
            return f"The outbound address read-back failed for {want}; there is no bound port to compare."

    first = int(by_uuid["first-request"][0][0])
    if first != pinned_port:
        return f"First request should bind the pinned source port {pinned_port}, got {first}"

    # Every connect after the first transaction must be free of the override.
    # Checking only the last one lets a failed rebind fall back to an ephemeral
    # port and hide the leak that caused it.
    for port, _ in by_uuid["second-request"]:
        if int(port) == pinned_port:
            return (
                f"Second request inherited the first request's pinned source port {pinned_port}; "
                "the outbound override leaked across the keep-alive session")
    return ""


def test_outbound_addr_keepalive(ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """A plugin's outbound address override does not persist onto a later keep-alive transaction.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    """
    # A recognizable, free source port the plugin pins on the first request only.
    _pinned_port = services.allocate_port()
    _server = configure_server(services)
    _ats = configure_ats(ats_factory, _server=_server, _pinned_port=_pinned_port)
    _client = configure_client(services, _ats=_ats)

    _server.start()
    _ats.start()
    client = _client.run()
    assert client.returncode == 0, client.output
    # The premise, that both transactions travel over one client session, is checked
    # from the client session transaction count the plugin logs. It is deliberately
    # not checked against Proxy Verifier's "N transactions in 1 session" summary:
    # that line reports the replay file's own session structure and is printed
    # unchanged even when ATS answers "Connection: close" and the client reconnects.
    wait_for_file_lines(_ats.traffic_out, r"OUTBOUND_PORT uuid=first-request", 1)
    traffic_out = wait_for_file_lines(_ats.traffic_out, r"OUTBOUND_PORT uuid=second-request", 1)
    failure = check_outbound_ports(traffic_out, _pinned_port)
    assert not failure, failure
