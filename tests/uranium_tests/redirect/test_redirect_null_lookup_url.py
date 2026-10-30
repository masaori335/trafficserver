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
"""Redirects whose original request never established a cache lookup URL.

Each scenario sends a request to a dynamic looking URL with caching of such URLs
disabled, so the original request establishes no cache lookup URL, and then has
ATS follow a redirect into a code path that needs one. The first redirect hop then
records a lookup URL; the two hop scenarios check that it names the URL each later
hop looks up.
"""

from pathlib import Path
from string import Template
import re
import time

import pytest

from tools.uranium.services import (
    ATS, ATSFactory, CommandResult, Curl, DNSServer, ProceduralContext, ServiceFactory, VerifierServer, wait_for_file_lines)

TEST_DIRECTORY = Path(__file__).parent
# Large enough that the request body arrives in more than one read.
POST_BODY_SIZE = 200000


def render_replay(context: ProceduralContext, name: str, **values: object) -> Path:
    """Substitute listener ports into a replay template.

    :param context: Procedural context owning the run directory.
    :param name: Replay file name under the replay directory.
    :param values: Template values substituted into the replay.
    """

    template = Template((TEST_DIRECTORY / "replay" / name).read_text())
    replay = context.run_directory / name
    replay.write_text(template.substitute(values))
    return replay


def configure_dns(services: ServiceFactory) -> DNSServer:
    """Resolve both origin hostnames to loopback.

    :param services: Factory owning support services and their cleanup.
    """

    dns = services.dns("dns")
    dns.add_records({"a.test": ["127.0.0.1"], "b.test": ["127.0.0.1"]})
    return dns


def configure_ats(ats_factory: ATSFactory, *, _dns: DNSServer, _orig_cache_key: int, _compat_key_read: int = 0) -> ATS:
    """Follow self redirects without cache lookups for dynamic looking URLs.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param _dns: Test-local dns configured by the test.
    :param _orig_cache_key: Value for redirect_use_orig_cache_key.
    :param _compat_key_read: Value for cache.try_compat_key_read.
    """

    ats = ats_factory.create("ts", enable_cache=True)
    ats.records.update(
        {
            "proxy.config.diags.debug.enabled": 1,
            "proxy.config.diags.debug.tags": "http|cache|redirect|dns",
            "proxy.config.http.number_of_redirections": 2,
            "proxy.config.http.redirect_use_orig_cache_key": _orig_cache_key,
            "proxy.config.http.redirect.actions": "self:follow",
            # Do not cache-lookup dynamic looking (query string) URLs so the first
            # request does not establish a cache lookup URL.
            "proxy.config.http.cache.cache_urls_that_look_dynamic": 0,
            # Redirect targets are absolute URLs with an explicit port, resolved
            # straight through DNS without another remap.
            "proxy.config.url_remap.remap_required": 0,
            "proxy.config.dns.nameservers": f"127.0.0.1:{_dns.port}",
            "proxy.config.dns.resolv_conf": "NULL",
            # Buffer request bodies so a redirected POST can be replayed.
            "proxy.config.http.post_copy_size": 1048576,
            "proxy.config.http.cache.try_compat_key_read": _compat_key_read,
            "proxy.config.log.max_secs_per_buffer": 1,
        })
    ats.set_logging_yaml(
        {
            "logging":
                {
                    "formats": [{
                        "name": "lookup_url",
                        "format": "uuid=%<{uuid}cqh> cluc=%<cluc>",
                    }],
                    "logs": [{
                        "filename": "lookup_url",
                        "format": "lookup_url",
                        "mode": "ascii"
                    }],
                }
        })
    return ats


def assert_no_crash(ats: ATS) -> str:
    """Assert Traffic Server is still up and reported no fatal signal or memory error.

    :param ats: Traffic Server instance under test.
    """

    output = ats.traffic_out.read_text(errors="replace")
    assert ats.is_running, ats.process_output
    assert "AddressSanitizer" not in output, output
    assert "received signal" not in output, output
    return output


def configure_cache_delete_origins(context: ProceduralContext, services: ServiceFactory, *, _entry: str,
                                   _target: str) -> tuple[VerifierServer, VerifierServer]:
    """Create a target origin and an entry origin that redirects at it.

    :param context: Procedural context owning the run directory.
    :param services: Factory owning support services and their cleanup.
    :param _entry: Entry origin replay template name.
    :param _target: Target origin replay name.
    """

    target = services.verifier_server("target_srv", f"replay/{_target}")
    entry = services.verifier_server("entry_srv", render_replay(context, _entry, target_http_port=target.http_port))
    return entry, target


def test_redirect_orig_cache_key_without_lookup_url(
        procedural_context: ProceduralContext, ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """A redirect that reuses the original cache key falls back to the request URL.

    The redirected cache lookup must use the current request URL instead of the
    lookup URL the original request never established.

    :param procedural_context: Procedural context used by this test step.
    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    """

    srv2 = services.verifier_server("srv2", "replay/redirect_orig_cache_key_null_srv2.replay.yaml")
    # The first origin answers with a 302 whose Location points at srv2 on an
    # explicit port so the redirected request resolves through DNS.
    srv1 = services.verifier_server(
        "srv1", render_replay(procedural_context, "redirect_orig_cache_key_null_srv1.replay.yaml", vs_http_port=srv2.http_port))
    dns = configure_dns(services)
    ats = configure_ats(ats_factory, _dns=dns, _orig_cache_key=1)
    ats.remap_config.add_line(f"map http://a.test/ http://a.test:{srv1.http_port}/")
    client = services.verifier_client(
        "client", "replay/redirect_orig_cache_key_null_client.replay.yaml", http_ports=[ats.http_port])

    dns.start()
    srv1.start()
    srv2.start()
    ats.start()
    client.run()
    assert_no_crash(ats)


def test_redirect_cache_delete_without_lookup_url(
        procedural_context: ProceduralContext, ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """A redirect hop that reaches the cache delete path deletes under the request URL.

    Warm a target into the cache, let it go stale, then send a conditional GET to
    a dynamic looking URL that redirects at the warmed target. The revalidation
    is answered with a 304 that forbids storing, which drives the transaction to
    the cache delete on a redirect hop that started with no cache lookup URL.
    redirect_use_orig_cache_key is enabled because it is what makes the redirect
    hop ask for the original lookup URL, both for the lookup that finds the stale
    target and for the delete. At the default the hop addresses the current
    request URL and never consults the missing one.

    :param procedural_context: Procedural context used by this test step.
    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    """

    entry, target = configure_cache_delete_origins(
        procedural_context,
        services,
        _entry="lookupnull_entry_srv.replay.yaml",
        _target="lookupnull_target_srv.replay.yaml",
    )
    dns = configure_dns(services)
    ats = configure_ats(ats_factory, _dns=dns, _orig_cache_key=1)
    ats.remap_config.add_lines(
        [
            f"map http://a.test/ http://a.test:{entry.http_port}/",
            f"map http://b.test/ http://a.test:{target.http_port}/",
        ])
    warm = services.verifier_client("warm_client", "replay/lookupnull_warm_client.replay.yaml", http_ports=[ats.http_port])
    probe = services.verifier_client("probe_client", "replay/lookupnull_probe_client.replay.yaml", http_ports=[ats.http_port])

    dns.start()
    target.start()
    entry.start()
    ats.start()
    warm.run()
    # Let the cached copy go stale.
    time.sleep(3)
    probe.run()
    output = assert_no_crash(ats)

    # The replay's 304 can be produced by routes that never reach the cache delete,
    # so require that the delete ran for the warmed target, the object the redirect
    # hop looked up, and was not skipped.
    assert f"Issuing cache delete for http://a.test:{target.http_port}/target" in output, output
    assert "Skipping cache delete" not in output, output


def test_redirect_purge_without_lookup_url(
        procedural_context: ProceduralContext, ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """A redirected PURGE that hits a cached target deletes under the request URL.

    Warm a target into the cache, then send a PURGE to a dynamic looking URL that
    redirects at the warmed target. The PURGE hits the cached target, which drives
    the transaction to the cache delete on a redirect hop that started with no
    cache lookup URL. redirect_use_orig_cache_key is enabled to exercise its
    fallback as well. A GET for the target before the PURGE must be served from
    the cache, and one after it must go back to the origin.

    :param procedural_context: Procedural context used by this test step.
    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    entry, target = configure_cache_delete_origins(
        procedural_context,
        services,
        _entry="lookupnull_purge_entry_srv.replay.yaml",
        _target="lookupnull_purge_target_srv.replay.yaml",
    )
    dns = configure_dns(services)
    ats = configure_ats(ats_factory, _dns=dns, _orig_cache_key=1)
    ats.remap_config.add_lines(
        [
            f"map http://a.test/ http://a.test:{entry.http_port}/",
            f"map http://b.test/ http://a.test:{target.http_port}/",
        ])
    warm = services.verifier_client("warm_client", "replay/lookupnull_purge_warm_client.replay.yaml", http_ports=[ats.http_port])
    probe = services.verifier_client("probe_client", "replay/lookupnull_purge_client.replay.yaml", http_ports=[ats.http_port])

    dns.start()
    target.start()
    entry.start()
    ats.start()
    warm.run()
    # The origin has no answer for this uuid, so only a cache hit returns the warm copy.
    before = fetch(curl, ats, "http://b.test/target", "lookupnull-purge-before")
    assert before.headers.get("x-src") == "warm", before.raw
    probe.run()
    after = fetch(curl, ats, "http://b.test/target", "lookupnull-purge-after")
    assert_no_crash(ats)
    assert after.headers.get("x-src") == "refetch", after.raw


class Response:
    """Status line and headers of one curl response."""

    def __init__(self, result: CommandResult) -> None:
        self.raw = result.output
        head = result.stdout.replace("\r\n", "\n").split("\n\n", 1)[0]
        lines = head.split("\n")
        self.status = lines[0]
        self.headers: dict[str, str] = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep:
                self.headers[name.strip().lower()] = value.strip()


def fetch(curl: Curl, ats: ATS, url: str, uuid: str, method: str = "GET") -> Response:
    """Send one request through Traffic Server as a forward proxy.

    :param curl: Transport-aware curl command runner.
    :param ats: Traffic Server instance under test.
    :param url: Absolute request URL.
    :param uuid: Value of the uuid header the origins key their replies on.
    :param method: Request method; a POST carries a POST_BODY_SIZE byte body.
    """

    body = ""
    if method == "POST":
        upload = ats.run_directory / "post.bin"
        upload.write_bytes(b"p" * POST_BODY_SIZE)
        body = f"--data-binary @{upload} -H 'Content-Type: application/octet-stream' -H 'Expect:'"
    result = curl.run_for(
        ats, f"-s -i -X {method} {body} -x http://127.0.0.1:{ats.http_port} -H 'uuid: {uuid}' '{url}'", timeout=15)
    assert result.returncode == 0, result.output
    return Response(result)


class TwoHops:
    """A running two hop chain and the URL of each hop."""

    def __init__(self, ats: ATS, entry: VerifierServer, mid: VerifierServer, target: VerifierServer) -> None:
        self.ats = ats
        self.entry_url = f"http://a.test:{entry.http_port}/entry?x=1"
        self.mid_url = f"http://a.test:{mid.http_port}/m1"
        self.target_url = f"http://a.test:{target.http_port}/t2"


def warm(curl: Curl, ats: ATS, url: str, uuid: str) -> None:
    """Store an object in the cache and confirm the next request is served from it.

    :param curl: Transport-aware curl command runner.
    :param ats: Traffic Server instance under test.
    :param url: URL of the object to store.
    :param uuid: uuid the origin answers with its cacheable copy.
    """

    fetch(curl, ats, url, uuid)
    # The origin has no answer for this uuid, so only a cache hit returns the warm copy.
    control = fetch(curl, ats, url, f"{uuid}-control")
    assert control.headers.get("x-src") == "warm", control.raw


def start_two_hops(
        context: ProceduralContext,
        ats_factory: ATSFactory,
        services: ServiceFactory,
        curl: Curl,
        *,
        method: str,
        orig_cache_key: int,
        compat_key_read: int = 0) -> TwoHops:
    """Start entry -> 302 -> mid /m1 -> 302 -> target /t2 and warm the target into the cache.

    :param context: Procedural context owning the run directory.
    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param method: Method of the redirected request.
    :param orig_cache_key: Value for redirect_use_orig_cache_key.
    :param compat_key_read: Value for cache.try_compat_key_read.
    """

    target = services.verifier_server("target_srv", render_replay(context, "lookup_hops_target_srv.replay.yaml", method=method))
    mid = services.verifier_server(
        "mid_srv", render_replay(context, "lookup_hops_mid_srv.replay.yaml", method=method, next_http_port=target.http_port))
    entry = services.verifier_server(
        "entry_srv", render_replay(context, "lookup_hops_entry_srv.replay.yaml", method=method, next_http_port=mid.http_port))
    dns = configure_dns(services)
    ats = configure_ats(ats_factory, _dns=dns, _orig_cache_key=orig_cache_key, _compat_key_read=compat_key_read)
    ats.remap_config.add_line(f"map http://a.test/ http://a.test:{entry.http_port}/")
    dns.start()
    for origin in (target, mid, entry):
        origin.start()
    ats.start()

    hops = TwoHops(ats, entry, mid, target)
    warm(curl, ats, hops.target_url, "lookup-hops-warm")
    return hops


@pytest.mark.parametrize("orig_cache_key", [0, 1])
def test_two_hop_get_hits_warmed_target(
        procedural_context: ProceduralContext, ats_factory: ATSFactory, services: ServiceFactory, curl: Curl,
        orig_cache_key: int) -> None:
    """A GET redirected twice is served from the cached target.

    The second hop must look up the target it is requesting, not the first hop's
    URL, so the warmed copy is a hit. This path never sets lookup_url_storage, so
    the %<cluc> log field falls back to the request URL and must name each hop's URL.

    :param procedural_context: Procedural context used by this test step.
    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param orig_cache_key: Value for redirect_use_orig_cache_key.
    """

    hops = start_two_hops(procedural_context, ats_factory, services, curl, method="GET", orig_cache_key=orig_cache_key)

    probe = fetch(curl, hops.ats, "http://a.test/entry?x=1", "lookup-hops-probe")
    assert_no_crash(hops.ats)
    assert "200" in probe.status, probe.raw
    assert probe.headers.get("x-src") == "warm", probe.raw

    # Each redirect hop is logged before it is followed, then the final response.
    log = wait_for_file_lines(hops.ats.log_directory / "lookup_url.log", r"^uuid=lookup-hops-probe ", 3)
    logged = re.findall(r"^uuid=lookup-hops-probe cluc=(\S+)$", log, re.MULTILINE)
    assert logged == [hops.entry_url, hops.mid_url, hops.target_url], log


@pytest.mark.parametrize("orig_cache_key", [0, 1])
def test_two_hop_post_invalidates_warmed_target(
        procedural_context: ProceduralContext, ats_factory: ATSFactory, services: ServiceFactory, curl: Curl,
        orig_cache_key: int) -> None:
    """A POST redirected twice invalidates the cached target.

    With redirect_use_orig_cache_key=1 the second hop looks up cache_info.lookup_url,
    so it must name the target for the invalidation to reach it. The [0] arm is a
    control that does not discriminate: at the default setting the second hop looks
    up the request URL whatever lookup_url holds, so it only shows that the x-src
    observer sees an invalidation when the lookup is right.

    :param procedural_context: Procedural context used by this test step.
    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param orig_cache_key: Value for redirect_use_orig_cache_key.
    """

    hops = start_two_hops(procedural_context, ats_factory, services, curl, method="POST", orig_cache_key=orig_cache_key)

    probe = fetch(curl, hops.ats, "http://a.test/entry?x=1", "lookup-hops-probe", method="POST")
    assert probe.headers.get("x-src") == "probe", probe.raw
    after = fetch(curl, hops.ats, hops.target_url, "lookup-hops-after")
    assert_no_crash(hops.ats)
    assert after.headers.get("x-src") == "after", after.raw


@pytest.mark.parametrize("orig_cache_key", [0, 1])
def test_two_hop_post_compat_delete_names_target(
        procedural_context: ProceduralContext, ats_factory: ATSFactory, services: ServiceFactory, curl: Curl,
        orig_cache_key: int) -> None:
    """With the compatibility key read on, a POST redirected twice also deletes the target's legacy key.

    The buffered body is replayed through tunnel_handler_for_partial_post, which
    clears redirect_in_process before the response arrives. The compatibility delete
    then addresses cache_info.lookup_url directly, even at the default orig cache key
    setting. No object exists under the legacy key in this test, so the debug log is
    the observer: the compatibility delete must name the target, not the first hop.

    :param procedural_context: Procedural context used by this test step.
    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param orig_cache_key: Value for redirect_use_orig_cache_key.
    """

    hops = start_two_hops(
        procedural_context, ats_factory, services, curl, method="POST", orig_cache_key=orig_cache_key, compat_key_read=1)

    fetch(curl, hops.ats, "http://a.test/entry?x=1", "lookup-hops-probe", method="POST")
    output = assert_no_crash(hops.ats)
    # Each hop replays the body, and it is the second hop's replay that clears
    # redirect_in_process before the response that leads to the delete.
    assert output.count("[tunnel_handler_for_partial_post, HTTP_TUNNEL_EVENT_DONE]") == 2, output
    deletes = re.findall(r"Issuing compatibility cache delete for (\S+)", output)
    assert deletes == [hops.target_url], output
