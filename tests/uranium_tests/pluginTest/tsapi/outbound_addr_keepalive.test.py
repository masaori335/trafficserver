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

import os
import re
from ports import get_port

Test.Summary = '''
Verify a plugin's per-transaction outbound address override does not persist
onto a later transaction that reuses the same keep-alive client session.
'''

plugin_name = "test_TSHttpTxnOutgoingAddr"


class TestOutboundAddrKeepAlive:
    """Verify the outbound address override is scoped to a single transaction."""
    _replay_file = "outbound_addr_keepalive.replay.yaml"

    def _configure_server(self, tr: 'TestRun') -> 'Process':
        self._server = tr.AddVerifierServerProcess("server", self._replay_file)
        return self._server

    def _configure_traffic_server(self, tr: 'TestRun') -> 'Process':
        self._ts = tr.MakeATSProcess("ts", enable_cache=False)
        ts = self._ts

        # A recognizable, guaranteed-free source port the plugin pins on the
        # first (triggering) request only.
        self._pinned_port = get_port(ts, "pinned_port")

        plugin_path = os.path.join(Test.Variables.AtsBuildGoldTestsDir, 'pluginTest', 'tsapi', '.libs', f'{plugin_name}.so')
        ts.Setup.Copy(plugin_path, ts.Env['PROXY_CONFIG_PLUGIN_PLUGIN_DIR'])
        ts.Disk.plugin_config.AddLine(f"{plugin_path} {self._pinned_port}")

        ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'test_outbound_addr',
                # Keep the client session alive between the two transactions.
                'proxy.config.http.keep_alive_enabled_in': 1,
            })

        ts.Disk.remap_config.AddLine(f'map / http://127.0.0.1:{self._server.Variables.http_port}/')
        return ts

    def _add_content_check(self):
        pinned_port = self._pinned_port

        def verify_outbound_ports(output):
            # Select by transaction, never by position. A retried upstream connect
            # emits a second line for the SAME transaction, so first-and-last can
            # silently compare one transaction against itself.
            by_uuid = {}
            pattern = r'OUTBOUND_PORT uuid=(\S+) effective=(\d{1,5}|unavailable) ssn_txn=(-?\d+)'
            for uuid, port, ssn_txn in re.findall(pattern, str(output)):
                by_uuid.setdefault(uuid, []).append((port, int(ssn_txn)))

            # A missing first-request line means the harness never got off the ground.
            # A missing SECOND line is a different thing entirely: it is one of the two
            # shapes the leak takes, so it must not be reported as an inconclusive run.
            if 'first-request' not in by_uuid:
                return (
                    f"No upstream connect was logged for first-request (saw {sorted(by_uuid)}). "
                    f"Either the plugin never loaded, or that transaction never reached "
                    f"SEND_REQUEST_HDR. Nothing about the override was verified.")

            if 'second-request' not in by_uuid:
                first_seen = by_uuid['first-request'][0][0]
                if first_seen != 'unavailable' and int(first_seen) == pinned_port:
                    return (
                        f"The first request bound the pinned port {pinned_port} and the second "
                        f"request never reached SEND_REQUEST_HDR, so no second port was logged. "
                        f"The likely cause is the leak: the override persisted onto the second "
                        f"transaction and its bind() to {pinned_port} failed while that port was "
                        f"still held by the first upstream connection. Confirm before believing "
                        f"it, because any upstream connect failure looks the same from here: the "
                        f"client should show 502 connect failed for second-request, and "
                        f"diags.log should show the bind failure. A second request that binds "
                        f"{pinned_port} outright is the other shape of the same bug.")
                return (
                    f"No upstream connect was logged for second-request (saw {sorted(by_uuid)}), and "
                    f"the first request did not bind the pinned port {pinned_port} either, so this "
                    f"run is inconclusive rather than a detection.")

            # Pin the premise the port comparison rests on: both transactions must have
            # travelled over ONE client session. Two separate client sessions cannot leak
            # outbound options at all, so the ports would differ and the test would pass
            # having demonstrated nothing. The session transaction count is the runtime
            # observation that settles it, and unlike a session id it is comparable on
            # every branch. Use the first line per transaction; a retried connect repeats
            # the same count.
            first_ssn_txn = by_uuid['first-request'][0][1]
            second_ssn_txn = by_uuid['second-request'][0][1]
            if first_ssn_txn < 1 or second_ssn_txn < 1:
                return (
                    f"The client session transaction count was unreadable "
                    f"(first-request={first_ssn_txn}, second-request={second_ssn_txn}), so it is "
                    f"unknown whether the two requests shared a session and the port comparison "
                    f"proves nothing.")
            if second_ssn_txn != first_ssn_txn + 1:
                return (
                    f"The two requests did not travel over one reused client session: the client "
                    f"session transaction count was {first_ssn_txn} for first-request and "
                    f"{second_ssn_txn} for second-request, where a reused session must count "
                    f"{first_ssn_txn} then {first_ssn_txn + 1}. Equal counts mean ATS closed the "
                    f"client session and each request started a session of its own, in which case "
                    f"no override can leak and the port comparison below demonstrates nothing.")

            # "unavailable" means TSHttpTxnOutgoingAddrGet gave us no AF_INET address,
            # so there is no bound port to compare and a pass would prove nothing.
            for want in ('first-request', 'second-request'):
                if any(port == 'unavailable' for port, _ in by_uuid[want]):
                    return (
                        f"The outbound address read-back failed for {want}; there is no "
                        f"bound port to compare, so this run proves nothing.")

            first = int(by_uuid['first-request'][0][0])
            if first != pinned_port:
                return f"First request should bind the pinned source port {pinned_port}, got {first}"

            # Every connect after the first transaction must be free of the override.
            # Checking only the last one lets a failed rebind fall back to an ephemeral
            # port and hide the leak that caused it.
            for port, _ in by_uuid['second-request']:
                if int(port) == pinned_port:
                    return (
                        f"Second request inherited the first request's pinned source "
                        f"port {pinned_port}; the outbound override leaked across the "
                        f"keep-alive session")
            return ""

        self._ts.Disk.traffic_out.Content += Testers.FileContentCallback(verify_outbound_ports, 'verify_outbound_ports')

    def run(self):
        tr = Test.AddTestRun("Outbound address override must not persist across keep-alive requests.")
        self._configure_server(tr)
        self._configure_traffic_server(tr)
        tr.AddVerifierClientProcess("client", self._replay_file, http_ports=[self._ts.Variables.port])

        tr.Processes.Default.StartBefore(self._server)
        tr.Processes.Default.StartBefore(self._ts)

        # The premise these port assertions rest on, that both transactions travel over
        # one client session, is checked inside the traffic.out callback via the client
        # session transaction count the plugin logs. It is deliberately NOT checked
        # against Proxy Verifier's "N transactions in 1 session (reuse N)" summary: that
        # line reports the replay file's own session structure and is printed unchanged
        # even when ATS answers "Connection: close" and the client visibly reconnects
        # between the two requests, which is exactly the condition that has to be caught.
        self._add_content_check()


test = TestOutboundAddrKeepAlive()
test.run()
