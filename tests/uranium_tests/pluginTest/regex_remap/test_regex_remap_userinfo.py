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
"""regex_remap must not let a capture inject userinfo into the authority.

A rule whose substitution places ``$n`` immediately after the host (no slash)
used to let a client-controlled capture that begins with ``@`` re-parse as URL
userinfo, turning the operator's origin into userinfo and the client's text
into the origin host.
"""

import pytest

from tools.uranium.services import ATS, ATSFactory, Curl, DNSServer, OriginServer, ServiceFactory, wait_for_file_lines, wait_for_metric


def configure_origins(services: ServiceFactory) -> tuple[OriginServer, OriginServer]:
    """Create the operator's intended origin and a second one it must not reach.

    :param services: Factory owning support services and their cleanup.
    """

    primary = services.origin("primary")
    secondary = services.origin("secondary")

    for path in ("/foo", "/thing@safe", "/@attacker/x"):
        primary.add_response(
            {"headers": f"GET {path} HTTP/1.1\r\nHost: primary\r\n\r\n"},
            {
                "headers": "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n",
                "body": "PRIMARY"
            },
        )
    secondary.add_response(
        {"headers": "GET /x HTTP/1.1\r\nHost: secondary\r\n\r\n"},
        {
            "headers": "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n",
            "body": "SECONDARY"
        },
    )
    return primary, secondary


def configure_ats(ats_factory: ATSFactory, *, _dns: DNSServer, _primary: OriginServer) -> ATS:
    """Load the prefix-strip rule shape named in the report, plus the safe form.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param _dns: Test-local dns configured by the test.
    :param _primary: The operator's intended origin.
    """

    ats = ats_factory.create("ats", enable_cache=False)
    if not ats.plugin_exists("regex_remap.so"):
        pytest.skip("regex_remap.so is not installed")
    if not ats.plugin_exists("header_rewrite.so"):
        pytest.skip("header_rewrite.so is not installed")

    origin = f"127.0.0.1:{_primary.port}"
    ats.write_config_file("rr_noslash.conf", f"^/api(.*)$ http://{origin}$1\n")
    ats.write_config_file("rr_slash.conf", f"^/(.*)$ http://{origin}/$1\n")
    ats.write_config_file("rr_noscheme.conf", f"^/api(.*)$ {origin}$1\n")
    ats.write_config_file("rr_userinfo.conf", f"^/api(.*)$ http://ops:pass@{origin}$1\n")
    ats.write_config_file("rr_emptyuser.conf", f"^/api(.*)$ http://@{origin}$1\n")
    ats.write_config_file("rr_pwonly.conf", f"^/api(.*)$ http://:pw@{origin}$1\n")
    ats.write_config_file("rr_userpos.conf", f"^/api(.*)$ http://ops$1@{origin}/\n^/api(.*)$ http://{origin}$1\n")
    ats.write_config_file("rr_empty.conf", "^/e(.*)$ http://$1/\n")
    ats.write_config_file("hr_redirect.conf", "set-redirect 302 http://%{URL:HOST}:%{URL:PORT}/chained\n")
    ats.write_config_file("rr_redirect.conf", f"^/go(.*)$ http://{origin}$1 @status=302\n^/ns(.*)$ {origin}$1 @status=302\n")
    ats.remap_config.add_lines(
        (
            f"map http://primary.test/ http://{origin}/ @plugin=regex_remap.so @pparam=rr_noslash.conf",
            f"map http://slash.test/ http://{origin}/ @plugin=regex_remap.so @pparam=rr_slash.conf",
            f"map http://noscheme.test/ http://{origin}/ @plugin=regex_remap.so @pparam=rr_noscheme.conf",
            f"map http://redirect.test/ http://{origin}/ @plugin=regex_remap.so @pparam=rr_redirect.conf",
            f"map http://empty.test/ http://{origin}/ @plugin=regex_remap.so @pparam=rr_empty.conf",
            f"map http://userinfo.test/ http://{origin}/ @plugin=regex_remap.so @pparam=rr_userinfo.conf",
            f"map http://emptyuser.test/ http://{origin}/ @plugin=regex_remap.so @pparam=rr_emptyuser.conf",
            f"map http://userpos.test/ http://{origin}/ @plugin=regex_remap.so @pparam=rr_userpos.conf",
            f"map http://pwonly.test/ http://{origin}/ @plugin=regex_remap.so @pparam=rr_pwonly.conf",
            f"map http://chain.test/ http://{origin}/ @plugin=regex_remap.so @pparam=rr_noslash.conf "
            "@plugin=header_rewrite.so @pparam=hr_redirect.conf",
        ))
    ats.records.update(
        {
            "proxy.config.diags.debug.enabled": 1,
            "proxy.config.diags.debug.tags": "regex_remap",
            "proxy.config.dns.nameservers": f"127.0.0.1:{_dns.port}",
            "proxy.config.dns.resolv_conf": "NULL",
            "proxy.config.url_remap.remap_required": 1,
        })
    return ats


def _get(ats: ATS, curl: Curl, host: str, path: str) -> str:
    """Issue one request through ATS and return status line plus body.

    :param ats: Test-local ats configured by the test.
    :param curl: Test-local curl configured by the test.
    :param host: Host header selecting the remap rule.
    :param path: Raw request target.
    """

    result = curl.get(ats, path, headers={"Host": host}, options="-s -i")
    assert result.returncode == 0, result.output
    return result.stdout


def test_regex_remap_userinfo_injection(ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """The authority of a substituted target may not gain an injected ``@``.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    """

    _primary, _secondary = configure_origins(services)
    _dns = services.dns("dns", default="127.0.0.1")
    _ats = configure_ats(ats_factory, _dns=_dns, _primary=_primary)
    _curl = Curl(ats_factory.run_directory)

    _primary.start()
    _secondary.start()
    _dns.start()
    _ats.start()

    normal = _get(_ats, _curl, "primary.test", "/api/foo")
    assert "HTTP/1.1 200 OK" in normal and "PRIMARY" in normal

    safe_at = _get(_ats, _curl, "primary.test", "/api/thing@safe")
    assert "HTTP/1.1 200 OK" in safe_at and "PRIMARY" in safe_at

    injection = _get(_ats, _curl, "primary.test", f"/api@127.0.0.1:{_secondary.port}/x")
    assert "HTTP/1.1 403" in injection, injection
    assert "SECONDARY" not in injection, injection

    noscheme = _get(_ats, _curl, "noscheme.test", f"/api@127.0.0.1:{_secondary.port}/x")
    assert "HTTP/1.1 403" in noscheme, noscheme
    assert "SECONDARY" not in noscheme, noscheme

    redirect = _get(_ats, _curl, "redirect.test", f"/go@127.0.0.1:{_secondary.port}/x")
    assert "HTTP/1.1 403" in redirect, redirect
    assert f"127.0.0.1:{_secondary.port}" not in redirect, redirect

    noscheme_redirect = _get(_ats, _curl, "redirect.test", f"/ns@127.0.0.1:{_secondary.port}/x")
    assert "HTTP/1.1 403" in noscheme_redirect, noscheme_redirect
    assert f"127.0.0.1:{_secondary.port}" not in noscheme_redirect, noscheme_redirect

    empty_userinfo = _get(_ats, _curl, "empty.test", f"/e@127.0.0.1:{_secondary.port}")
    assert "HTTP/1.1 403" in empty_userinfo, empty_userinfo

    with_userinfo = _get(_ats, _curl, "userinfo.test", "/api/foo")
    assert "HTTP/1.1 200 OK" in with_userinfo and "PRIMARY" in with_userinfo, with_userinfo
    second_user = _get(_ats, _curl, "userinfo.test", f"/api@127.0.0.1:{_secondary.port}/x")
    assert "HTTP/1.1 500" in second_user, second_user
    assert "SECONDARY" not in second_user, second_user

    for host in ("emptyuser.test", "pwonly.test"):
        own_userinfo = _get(_ats, _curl, host, "/api/foo")
        assert "HTTP/1.1 200 OK" in own_userinfo and "PRIMARY" in own_userinfo, own_userinfo
        extra_at = _get(_ats, _curl, host, f"/api@127.0.0.1:{_secondary.port}/x")
        assert "HTTP/1.1 403" in extra_at, extra_at
        assert "SECONDARY" not in extra_at, extra_at

    skipped_rule = _get(_ats, _curl, "userpos.test", f"/api@127.0.0.1:{_secondary.port}/x?y")
    assert "HTTP/1.1 403" in skipped_rule, skipped_rule
    assert "SECONDARY" not in skipped_rule, skipped_rule
    fallback = _get(_ats, _curl, "userpos.test", "/api/foo")
    assert "HTTP/1.1 200 OK" in fallback and "PRIMARY" in fallback, fallback

    chained = _get(_ats, _curl, "chain.test", f"/api@127.0.0.1:{_secondary.port}/x")
    assert "HTTP/1.1 403" in chained, chained
    assert "Location:" not in chained, chained
    assert f"127.0.0.1:{_secondary.port}" not in chained, chained

    slash_form = _get(_ats, _curl, "slash.test", "/@attacker/x")
    assert "HTTP/1.1 200 OK" in slash_form and "PRIMARY" in slash_form

    wait_for_file_lines(_ats.diags_log, "capture injected userinfo into the authority", 1)
    wait_for_file_lines(_ats.diags_log, "can't parse substituted URL string", 1)
    wait_for_file_lines(_ats.diags_log, "substitution before '@' in the authority", 1)
    wait_for_metric(_ats, "plugin.regex_remap.userinfo_refused", 9)
