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
"""Verify URI signing token extraction and validation."""

from dataclasses import dataclass
import shlex

import pytest

from tools.uranium.services import ATS, ATSFactory, Curl, OriginServer, ServiceFactory, wait_for_file_lines

GOOD_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE5MjMwNTYwODR9."
    "zw_wFQ-wvrWmfPLGj3hAUWn-GOHkiJZi2but4KV0paY")
EXPIRED_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjF9."
    "GkdlOPHQc6BqS4Q6x79GeYuVFO2zuGbaPZZsJfD6ir8")
SECOND_KEY_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjE5MjMwNTYwODR9."
    "ozH4sNwgcOlTZT0l4RQlVCH_osxz9yI1HCBesEv-jYg")
MISSING_ISS_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAifQ."
    "eyJleHAiOjcyODQxODg0OTl9."
    "wQOWi2nZEWVdFobE6hldi79rUgbPeyuJ4ZUDaD7_JEE")
# A token with alg "none" must be rejected before any key lookup.
ALG_NONE_TOKEN = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjcyODQxODg0OTl9."
# A token with no alg header at all.
MISSING_ALG_TOKEN = (
    "eyJraWQiOiIwIn0."
    "eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjcyODQxODg0OTl9."
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
# RS256 against the oct (HMAC) key: the algorithm does not fit the key type.
KEY_TYPE_MISMATCH_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjAifQ."
    "eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjcyODQxODg0OTl9."
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
# HS512 against a key pinned to HS256: rejected even though the HMAC verifies.
ALG_MISMATCH_TOKEN = (
    "eyJhbGciOiJIUzUxMiIsImtpZCI6IjAifQ."
    "eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjcyODQxODg0OTl9."
    "vPIaTGbrn0WuZ1Tyd9K8TVjL71MWG9kT6M3mjqYvht_jNIZ7KRcIRfioQgpXgJP44bVfV73J3fAOi0iNtQ2XnQ")

# The diagnostic each rejected token must leave in traffic.out.
REJECTION_LOGS = (
    "Missing issuer in verified JWT",
    "Rejecting JWS with 'none' algorithm",
    "Unable to read JWS: URISigningPackage, invalid argument",
    "No valid configured key for alg RS256 kid 0 found",
    "No valid configured key for alg HS512 kid 0 found",
)


@dataclass(frozen=True)
class RequestCase:
    """Describe one URI-signing request and its expected status."""

    name: str
    url: str
    status: str
    cookie: str | None = None


def configure_server(*, _services: ServiceFactory) -> OriginServer:
    """Create the three origin resources used by the request matrix.

    :param _services: Test-local services configured by the test.
    """

    origin = _services.origin("origin")
    origin.add_response(
        {"headers": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"},
        {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"},
    )
    origin.add_response(
        {"headers": "GET /someasset.ts HTTP/1.1\r\nHost: somehost\r\n\r\n"},
        {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            "body": "somebody"
        },
    )
    origin.add_response(
        {"headers": "GET /crossdomain.xml HTTP/1.1\r\nHost: somehost\r\n\r\n"},
        {
            "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            "body": "<crossdomain></crossdomain>",
        },
    )
    return origin


def configure_ats(*, _ats_factory: ATSFactory, _origin: OriginServer) -> ATS:
    """Configure ATS with URI signing on the somehost mapping.

    :param _ats_factory: Test-local ats factory configured by the test.
    :param _origin: Test-local origin configured by the test.
    """

    ats = _ats_factory.create("ats", enable_cache=False)
    if not ats.plugin_exists("uri_signing.so"):
        pytest.skip("uri_signing.so is not installed")
    ats.records.update({
        "proxy.config.diags.debug.enabled": 1,
        "proxy.config.diags.debug.tags": "uri_signing|http",
    })
    ats.copy_to_config("config.json", "run_sign.sh", "signer.json")
    ats.remap_config.add_line(
        f"map http://somehost/ http://127.0.0.1:{_origin.port}/ "
        f"@plugin=uri_signing.so @pparam={ats.config_directory}/config.json")
    return ats


def request_cases() -> tuple[RequestCase, ...]:
    """Return the URL and cookie token extraction matrix."""

    return (
        RequestCase("unsigned", "/someasset.ts", "403 Forbidden"),
        RequestCase("passthrough", "/crossdomain.xml", "200 OK"),
        RequestCase("query token", f"/someasset.ts?URISigningPackage={GOOD_TOKEN}", "200 OK"),
        RequestCase("expired query token", f"/someasset.ts?URISigningPackage={EXPIRED_TOKEN}", "403 Forbidden"),
        RequestCase("second key", f"/someasset.ts?URISigningPackage={SECOND_KEY_TOKEN}", "200 OK"),
        RequestCase("inline token", f"/URISigningPackage={GOOD_TOKEN}/someasset.ts", "200 OK"),
        RequestCase("expired inline token", f"/URISigningPackage={EXPIRED_TOKEN}/someasset.ts", "403 Forbidden"),
        RequestCase("parameter token", f"/someasset.ts;URISigningPackage={GOOD_TOKEN}", "200 OK"),
        RequestCase(
            "expired parameter token",
            f"/someasset.ts;URISigningPackage={EXPIRED_TOKEN}",
            "403 Forbidden",
        ),
        RequestCase("cookie token", "/someasset.ts", "200 OK", f"URISigningPackage={GOOD_TOKEN}"),
        RequestCase("expired cookie token", "/someasset.ts", "403 Forbidden", f"URISigningPackage={EXPIRED_TOKEN}"),
        RequestCase(
            "multiple cookies",
            "/someasset.ts",
            "200 OK",
            f"URISigningPackage={EXPIRED_TOKEN};URISigningPackage={GOOD_TOKEN}",
        ),
        RequestCase("missing issuer", f"/someasset.ts?URISigningPackage={MISSING_ISS_TOKEN}", "403 Forbidden"),
        RequestCase("alg none", f"/someasset.ts?URISigningPackage={ALG_NONE_TOKEN}", "403 Forbidden"),
        RequestCase("missing alg", f"/someasset.ts?URISigningPackage={MISSING_ALG_TOKEN}", "403 Forbidden"),
        RequestCase(
            "key type mismatch",
            f"/someasset.ts?URISigningPackage={KEY_TYPE_MISMATCH_TOKEN}",
            "403 Forbidden",
        ),
        RequestCase("alg mismatch", f"/someasset.ts?URISigningPackage={ALG_MISMATCH_TOKEN}", "403 Forbidden"),
    )


def run_client(*, _ats: ATS, _curl: Curl) -> None:
    """Issue every curl request and verify the plugin response status.

    :param _ats: Test-local ats configured by the test.
    :param _curl: Test-local curl configured by the test.
    """

    proxy = f"http://127.0.0.1:{_ats.http_port}"
    for case in request_cases():
        arguments = ["--silent", "--show-error", "--verbose", "--proxy", proxy]
        if case.cookie is not None:
            arguments.extend(["--header", f"Cookie: {case.cookie}"])
        arguments.append(f"http://somehost{case.url}")
        result = _curl.run_for(
            _ats,
            shlex.join(arguments),
        )
        assert result.returncode == 0, f"{case.name}: {result.output}"
        assert f"< HTTP/1.1 {case.status}" in result.stderr, f"{case.name}: {result.output}"


def test_uri_signing(ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """Exercise URI-signing validation through curl-specific request forms.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    """
    _origin = configure_server(_services=services)
    _ats = configure_ats(_ats_factory=ats_factory, _origin=_origin)
    _curl = Curl(ats_factory.run_directory)

    _origin.start()
    _ats.start()
    run_client(_ats=_ats, _curl=_curl)
    for message in REJECTION_LOGS:
        wait_for_file_lines(_ats.traffic_out, message, 1)
