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
"""Verify that per-SNI client CA certificates still apply when a cert hook pauses the handshake."""
import json
import re
import subprocess
from pathlib import Path

import pytest
from tools.uranium import runtime
from tools.uranium.services import ATSFactory, Curl, ServiceFactory
from tools.uranium.utils import version_tuple

SSL = Path(__file__).parent / "ssl"

# A paused hook holds the handshake for two seconds.
CURL_MAX_TIME = 15

TLS_VERSIONS = {"TLSv1.2": "--tls-max 1.2", "TLSv1.3": "--tlsv1.3"}

# Server names and the context each one selects:
#   bbb-signed: the bbb-signed.pem entry, which is not the "*" entry, so it has no handshake callbacks.
#   bbb.com:    no certificate entry matches, so the handshake stays on the "*" context.
SERVER_NAMES = {
    "bbb-signed": "a named context",
    "bbb.com": "the default context",
}

# Client certificates: name -> whether the bbb-ca.pem client CA set for the SNI trusts it.
#   bbb-signed: signed by bbb-ca, the SNI's verify_client_ca_certs.
#   aaa-signed: signed by aaa-ca, the global proxy.config.ssl.CA.cert.filename only.
#   ccc-signed: signed by ccc-ca, trusted nowhere.
CLIENT_CERTS = {
    "bbb-signed": True,
    "aaa-signed": False,
    "ccc-signed": False,
    None: False,
}


@pytest.mark.parametrize("hook_args", ("-i=1", "-cert=1"), ids=("immediate", "paused"))
def test_tls_sni_ca_paused_cert_hook(
        ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, uranium_test_runtime: runtime.TestRuntime,
        hook_args: str) -> None:
    """The SNI client CA must apply whether or not the cert hook pauses.

    :param ats_factory: Proxy factory.
    :param services: Origin factory.
    :param curl: TLS client.
    :param uranium_test_runtime: Installed-tool paths, used to read the OpenSSL version ATS links.
    :param hook_args: The ssl_hook_test plugin arguments: an immediate or a paused cert hook.
    """
    versions = json.loads(
        subprocess.check_output([uranium_test_runtime.ats_bin / "traffic_layout", "info", "--versions", "--json"], text=True))
    if version_tuple(versions["openssl_str"]) < (1, 1, 1):
        pytest.skip("OpenSSL 1.1.1 or newer is required")
    if curl.uses_uds:
        pytest.skip("client certificate verification requires a TCP TLS listener")

    origin = services.origin("server")
    origin.add_response(
        {
            "headers": "GET / HTTP/1.1\r\nuuid: basic\r\n\r\n",
            "body": ""
        }, {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n",
            "body": "ok"
        })
    ats = ats_factory.create("ts", enable_tls=True)
    ats.copy_to_ssl(
        *(SSL / f for f in ("server.pem", "server.key", "bbb-signed.pem", "bbb-signed.key", "aaa-ca.pem", "bbb-ca.pem")))
    ats.records.update(
        {
            "proxy.config.diags.debug.enabled": 1,
            "proxy.config.diags.debug.tags": "ssl_hook_test|ssl_load|ssl_verify",
            "proxy.config.ssl.CA.cert.filename": str(ats.ssl_directory / "aaa-ca.pem"),
        })
    # The nonmatching dest_ip keeps bbb-signed.pem out of the "*" slot, so only server.pem's
    # context gets the handshake callbacks.
    ats.set_ssl_multicert_yaml(
        {
            "ssl_multicert":
                [
                    {
                        "dest_ip": "192.0.2.1",
                        "ssl_cert_name": "bbb-signed.pem",
                        "ssl_key_name": "bbb-signed.key"
                    }, {
                        "dest_ip": "*",
                        "ssl_cert_name": "server.pem",
                        "ssl_key_name": "server.key"
                    }
                ]
        })
    sni_lines = ["sni:"]
    for sni in SERVER_NAMES:
        sni_lines += [
            f"- fqdn: {sni}",
            "  verify_client: STRICT",
            f"  verify_client_ca_certs: {ats.ssl_directory}/bbb-ca.pem",
        ]
    ats.write_config_file("sni.yaml", "\n".join(sni_lines) + "\n")
    ats.remap_config.add_line(f"map / http://127.0.0.1:{origin.port}")
    ats.copy_custom_plugin("{ATS_TEST_PLUGINS_DIR}/ssl_hook_test.so")
    ats.plugin_config.add_line(f"ssl_hook_test.so {hook_args}")
    origin.start()
    ats.start()

    port = ats.https_port
    failures = []
    for version, version_args in TLS_VERSIONS.items():
        for sni, context in SERVER_NAMES.items():
            for client, trusted in CLIENT_CERTS.items():
                cert_args = f"--cert {SSL / client}.pem --key {SSL / client}.key" if client else ""
                result = curl.run_for(
                    ats, f"-v -k --max-time {CURL_MAX_TIME} -o /dev/null -w 'status=%{{http_code}}\\n' {version_args} "
                    f"{cert_args} -H uuid:basic --resolve '{sni}:{port}:127.0.0.1' https://{sni}:{port}/",
                    timeout=CURL_MAX_TIME + 5)
                if trusted:
                    passed = result.returncode == 0 and "status=200" in result.stdout
                else:
                    # A TLS 1.3 client learns of the rejection after its Finished, so its next write can fail first (55).
                    passed = result.returncode in (35, 55, 56) and "status=000" in result.stdout
                if not passed:
                    cert_desc = f"{client} certificate" if client else "no certificate"
                    outcome = "accepted" if trusted else "rejected"
                    failures.append(
                        f"{version}, {sni} ({context}): {cert_desc} should be {outcome}, "
                        f"curl exit {result.returncode}:\n{result.output}")
    assert not failures, "\n\n".join(failures)
    assert origin.is_running and ats.is_running

    ats.stop()
    assert re.search(r"Cert callback 0 ", ats.traffic_out.read_text(errors="replace")), "the cert hook ran"
    diags = ats.diags_log.read_text(errors="replace")
    assert not re.search("ERROR:|Unrecognized configuration value", diags), diags
