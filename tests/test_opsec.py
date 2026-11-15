"""Investigator safety: egress routes (Tor, VPN, proxy), anonymous cases, route tests, a neutral identity."""

from __future__ import annotations

import base64
import json
import select
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import aiohttp
import pytest

from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.models import EntityType, ScanConfig
from argus.core.settings import EgressRoute, Settings
from argus.evidence import capture as cap
from argus.evidence import guard_proxy
from argus.evidence.guard_proxy import ROUTE_FAILED_HEADER, GuardProxy
from argus.modules.base import BaseModule
from argus.security.network import BlockedDestinationError

PAGE = "<html><head><title>Their site</title></head><body><p>What they said.</p></body></html>"


# ---------------------------------------------------------------------------- fakes
class Site(ThreadingHTTPServer):
    """A web server that records who visited (User-Agent) and answers an IP-echo request."""

    daemon_threads = True

    def __init__(self, ip: str):
        self.ip, self.seen = ip, []
        super().__init__(("127.0.0.1", 0), SiteHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self) -> int:
        return self.server_address[1]


class SiteHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append({"path": self.path, "ua": self.headers.get("User-Agent", "")})
        if self.path.startswith("/ip"):
            body, kind = json.dumps({"IsTor": True, "IP": self.server.ip}).encode(), "application/json"
        else:
            body, kind = PAGE.encode(), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Upstream(socketserver.ThreadingTCPServer):
    """A fake Tor HTTPTunnelPort / VPN proxy: records each CONNECT, tunnels to ``site`` whatever the host."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, site: Site, refuse: bool = False):
        self.site, self.refuse, self.connects, self.auth = site, refuse, [], []
        super().__init__(("127.0.0.1", 0), UpstreamHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class UpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self):
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            head += chunk
        lines = head.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        self.server.connects.append(lines[0].split(" ")[1])
        self.server.auth += [
            h.split(":", 1)[1].strip() for h in lines[1:] if h.lower().startswith("proxy-authorization")
        ]
        if self.server.refuse:
            self.request.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            return
        upstream = socket.create_connection(("127.0.0.1", self.server.site.port))
        self.request.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        pair = [self.request, upstream]
        try:
            while True:
                ready, _, _ = select.select(pair, [], [], 10)
                if not ready:
                    return
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        return
                    (upstream if s is self.request else self.request).sendall(data)
        except OSError:
            return
        finally:
            upstream.close()


@pytest.fixture
def sites():
    target, exit_site = Site("203.0.113.9"), Site("185.220.101.7")  # this server as seen directly; the Tor exit
    yield target, exit_site
    for s in (target, exit_site):
        s.shutdown()


def tor(upstream: Upstream) -> EgressRoute:
    return EgressRoute(name="tor", kind="tor", url=upstream.url, description="Tor on this server")


async def get_via(proxy: GuardProxy, url: str) -> tuple[int, dict[str, str], str]:
    async with aiohttp.ClientSession() as http, http.get(url, proxy=proxy.url) as resp:
        return resp.status, dict(resp.headers), await resp.text()


# ---------------------------------------------------------------------------- the routed guard proxy
def test_routes_are_validated():
    assert EgressRoute(name="tor", kind="tor", url="http://127.0.0.1:9080").is_anonymous
    assert not EgressRoute(name="office-vpn", url="http://10.0.0.5:3128").is_anonymous
    assert EgressRoute(name="vpn", url="http://10.0.0.5:3128", anonymous=True).is_anonymous
    for bad in ({"name": "Tor!", "url": "http://127.0.0.1:9080"}, {"name": "tor", "url": "socks5://127.0.0.1:9050"},
                {"name": "tor", "url": "http://127.0.0.1"}):  # fmt: skip
        with pytest.raises(ValueError, match="validation error"):
            EgressRoute(**bad)


async def test_tor_routes_never_resolve_names_here(sites, monkeypatch):
    _, exit_site = sites
    upstream = Upstream(exit_site)

    async def no_dns(host, port):  # a local lookup would tell the resolver which sites are visited
        raise AssertionError(f"resolved {host} locally")

    monkeypatch.setattr(guard_proxy, "resolve_public", no_dns)
    try:
        async with GuardProxy(allow_private=False, upstream=tor(upstream)) as proxy:
            status, _, body = await get_via(proxy, "http://their-site.example/")
            assert status == 200 and "What they said" in body
            assert upstream.connects == ["their-site.example:80"]  # the name, unresolved
            for internal in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22/", "http://10.1.2.3/"):
                status, headers, _ = await get_via(proxy, internal)
                assert status == 403 and headers.get(guard_proxy.REFUSED_HEADER), internal
            assert upstream.connects == ["their-site.example:80"]  # internal addresses never reached the route
    finally:
        upstream.shutdown()


async def test_proxy_routes_check_here_and_authenticate(sites, monkeypatch):
    _, exit_site = sites
    upstream = Upstream(exit_site)

    async def fake_resolve(host, port):
        if host == "their-site.example":
            return ["93.184.216.34"]
        raise BlockedDestinationError(host)

    monkeypatch.setattr(guard_proxy, "resolve_public", fake_resolve)
    route = EgressRoute(name="vpn", url=upstream.url.replace("http://", "http://jo:p%40ss@"))
    try:
        async with GuardProxy(allow_private=False, upstream=route) as proxy:
            assert (await get_via(proxy, "http://their-site.example/"))[0] == 200
            assert (await get_via(proxy, "http://intranet.corp/"))[0] == 403  # a proxy may sit inside the network
        assert upstream.connects == ["their-site.example:80"]
        assert upstream.auth == ["Basic " + base64.b64encode(b"jo:p@ss").decode()]
    finally:
        upstream.shutdown()


async def test_a_failing_route_is_reported_not_bypassed(sites):
    _, exit_site = sites
    upstream = Upstream(exit_site, refuse=True)
    try:
        async with GuardProxy(allow_private=True, upstream=tor(upstream)) as proxy:
            status, headers, _ = await get_via(proxy, "http://their-site.example/")
        assert status == 502 and headers.get(ROUTE_FAILED_HEADER) and proxy.log.failed
        assert exit_site.seen == []  # nothing went out another way
    finally:
        upstream.shutdown()


# ---------------------------------------------------------------------------- captures
async def test_captures_go_through_the_route_with_a_neutral_identity(sites):
    target, exit_site = sites
    upstream = Upstream(exit_site)
    settings = Settings(allow_private_targets=True, capture_browser="off", evidence_timestamp_url="")
    try:
        c = await cap.capture_url("http://their-site.example/", settings, tor(upstream))
        assert c.manifest["route"] == {"name": "tor", "kind": "tor", "anonymous": True}
        assert "What they said" in c.files["text.txt"][1].decode()
        assert upstream.connects == ["their-site.example:80"] and target.seen == []
        visit = exit_site.seen[0]
        assert "Argus" not in visit["ua"] and visit["ua"].startswith("Mozilla/5.0") and "Chrome/" in visit["ua"]

        direct = await cap.capture_url(f"http://127.0.0.1:{target.port}/", settings)
        assert direct.manifest["route"]["kind"] == "direct" and "Argus" not in target.seen[0]["ua"]
    finally:
        upstream.shutdown()


async def test_a_capture_route_that_is_down_is_explained(sites):
    _, exit_site = sites
    upstream = Upstream(exit_site, refuse=True)
    settings = Settings(allow_private_targets=True, capture_browser="off", evidence_timestamp_url="")
    try:
        for url in ("http://their-site.example/", "https://their-site.example/"):
            with pytest.raises(cap.CaptureError, match="route could not reach"):
                await cap.capture_url(url, settings, tor(upstream))
    finally:
        upstream.shutdown()


# ---------------------------------------------------------------------------- scans
class Probe(BaseModule):
    name = "probe"
    supported_entity_types = [EntityType.DOMAIN]

    def __init__(self):
        self.status = None

    async def run(self, entity, session, config):
        async with session.get(f"http://{entity.value}/", headers={"User-Agent": "Argus-OSINT/1.0"}) as resp:
            self.status = resp.status
        return
        yield  # pragma: no cover


class RawSocket(Probe):
    name = "raw_socket"
    direct_connections = True


async def test_scans_go_through_the_route(sites):
    _, exit_site = sites
    upstream = Upstream(exit_site)
    probe, raw = Probe(), RawSocket()
    config = ScanConfig(target="their-site.example", target_type=EntityType.DOMAIN, max_depth=0)
    try:
        engine = ArgusEngine(config, bus=EventBus(), modules={"probe": probe, "raw_socket": raw}, egress=tor(upstream))
        await engine.start()
        assert probe.status == 200 and raw.status is None  # the raw-socket module could not hide: skipped
        assert engine.skipped_for_route == ["raw_socket"] and any(
            "raw_socket" in w for w in engine.investigation.warnings
        )
        assert upstream.connects == ["their-site.example:80"]
        assert "Argus" not in exit_site.seen[0]["ua"]  # even a module's own User-Agent is replaced
        assert "egress" not in config.model_dump_json()  # the route (and its credentials) is never stored
    finally:
        upstream.shutdown()


# ---------------------------------------------------------------------------- the API
@pytest.fixture
def routed(make_client, sites):
    target, exit_site = sites
    upstream = Upstream(exit_site)
    leaky = Upstream(target)  # "anonymous", but leaves from this server's own address
    routes = [
        {"name": "tor", "kind": "tor", "url": upstream.url, "description": "Tor on this server"},
        {"name": "leaky-vpn", "url": leaky.url.replace("http://", "http://jo:secret@"), "anonymous": True},
        {"name": "office", "url": upstream.url},
    ]
    client = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false",
                         allow_private_targets="true", capture_browser="off", evidence_timestamp_url="",
                         egress_routes=json.dumps(routes), egress_check_url=f"http://127.0.0.1:{target.port}/ip")  # fmt: skip
    client.post("/api/demo")
    yield client, upstream, target, exit_site
    upstream.shutdown()
    leaky.shutdown()


def new_case(client, **extra):
    return client.post("/api/cases", json={"title": "Fake charity", "confirmed": True,
                                           "purpose": "Investigating a fake charity fundraising online", **extra})  # fmt: skip


def test_investigators_see_route_names_never_addresses(routed):
    client, upstream, *_ = routed
    r = client.get("/api/opsec/routes")
    assert r.status_code == 200
    names = {x["name"]: x for x in r.json()["routes"]}
    assert names["tor"] == {"name": "tor", "kind": "tor", "anonymous": True, "description": "Tor on this server"}
    assert not names["office"]["anonymous"]
    text = r.text
    assert (
        "secret" not in text
        and str(upstream.server_address[1]) not in text
        and "127.0.0.1" not in text.split("check_url")[0]
    )


def test_a_route_check_shows_the_exit_and_catches_leaks(routed):
    client, *_ = routed
    good = client.post("/api/opsec/routes/tor/check").json()
    assert good["working"] and good["exit_ip"] == "185.220.101.7" and good["direct_ip"] == "203.0.113.9"
    assert good["hides_address"] is True and good["is_tor"] is True and good["error"] is None
    leak = client.post("/api/opsec/routes/leaky-vpn/check").json()
    assert leak["working"] and leak["hides_address"] is False and "leaks" in leak["error"]
    assert client.post("/api/opsec/routes/nope/check").status_code == 422
    assert any(e["action"] == "opsec.route_check" for e in client.get("/api/audit").json())


def test_anonymous_cases_never_touch_their_subjects_directly(routed):
    client, upstream, target, _ = routed
    assert new_case(client, opsec_mode="anonymous").status_code == 422  # needs an anonymous route
    assert new_case(client, opsec_mode="anonymous", egress="office").status_code == 422  # not anonymous
    assert new_case(client, egress="nope").status_code == 422
    case = new_case(client, opsec_mode="anonymous", egress="tor").json()
    assert case["egress"] == "tor" and case["opsec_mode"] == "anonymous"

    url = f"http://127.0.0.1:{target.port}/"
    for route in ("direct", "office"):
        r = client.post(f"/api/cases/{case['id']}/captures", json={"url": url, "egress": route})
        assert r.status_code == 409 and "anonymous" in r.json()["detail"]
    assert target.seen == []  # refused before anything went out

    r = client.post(f"/api/cases/{case['id']}/captures", json={"url": "http://their-site.example/"})
    assert r.status_code == 201, r.text
    assert r.json()["route"]["name"] == "tor" and upstream.connects[-1] == "their-site.example:80"

    # Scans for the case: routed, and passive whatever was asked.
    r = client.post("/api/scan", json={"target": "their-site.example", "purpose": "Story research",
                                       "authorized": True, "case_id": case["id"], "egress": "direct"})  # fmt: skip
    assert r.status_code == 409
    r = client.post("/api/scan", json={"target": "their-site.example", "purpose": "Story research", "max_depth": 0,
                                       "authorized": True, "case_id": case["id"], "passive_only": False})  # fmt: skip
    assert r.status_code == 200, r.text
    assert r.json()["route"] == "tor" and r.json()["passive_only"] is True
    items = client.get(f"/api/cases/{case['id']}").json()["items"]
    assert any(i["kind"] == "scan" and i["data"]["investigation_id"] == r.json()["investigation_id"] for i in items)

    # Back to standard: direct work is allowed again, and it is the owner's recorded choice.
    assert (
        client.patch(f"/api/cases/{case['id']}", json={"opsec_mode": "standard", "egress": ""}).json()["egress"] == ""
    )
    r = client.post(f"/api/cases/{case['id']}/captures", json={"url": url})
    assert r.status_code == 201 and r.json()["route"]["kind"] == "direct"
    assert client.patch(f"/api/cases/{case['id']}", json={"opsec_mode": "anonymous"}).status_code == 422


# ---------------------------------------------------------------------------- the real browser
REVEAL = ("<html><body><p id=o>?</p><script>document.getElementById('o').textContent = "
          "Intl.DateTimeFormat().resolvedOptions().timeZone + '|' + navigator.language + '|' + navigator.userAgent;"
          "</script></body></html>")  # fmt: skip


@pytest.mark.skipif(cap.find_browser(Settings()) is None, reason="no headless browser installed")
async def test_the_browser_goes_through_the_route_and_gives_nothing_away(sites, monkeypatch):
    _, exit_site = sites
    upstream = Upstream(exit_site)
    monkeypatch.setattr(SiteHandler, "do_GET", _reveal)
    settings = Settings(capture_browser_sandbox=False, allow_private_targets=False)
    monkeypatch.setattr(guard_proxy, "resolve_public", _no_local_dns)
    try:
        async with GuardProxy(allow_private=False, upstream=tor(upstream)) as proxy:
            rendered = await cap.render("http://their-site.example/", cap.find_browser(settings), settings, proxy)
    finally:
        upstream.shutdown()
    assert rendered["screenshot"], rendered["notes"]
    assert "their-site.example:80" in upstream.connects
    zone, language, agent = rendered["dom"].decode().split('id="o">')[1].split("<")[0].split("|")
    assert zone == "UTC" and language == "en-US" and "Argus" not in agent and "Headless" not in agent


async def _no_local_dns(host, port):
    raise AssertionError(f"resolved {host} locally")


def _reveal(self):
    body = REVEAL.encode()
    self.send_response(200)
    self.send_header("Content-Type", "text/html")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)


def test_the_python_client_covers_routes(routed):
    import sys
    from pathlib import Path

    client, *_ = routed
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    argus = ArgusClient(http=client)
    assert [r["name"] for r in argus.routes()] == ["tor", "leaky-vpn", "office"]
    assert argus.check_route("tor")["hides_address"] is True
    case = argus.create_case("Shell companies", purpose="Following money through shell companies", egress="tor",
                             anonymous=True)  # fmt: skip
    assert case["opsec_mode"] == "anonymous"
    assert argus.capture(case["id"], "http://their-site.example/")["route"]["name"] == "tor"
    r = argus.scan("their-site.example", purpose="Story research", depth=0, case_id=case["id"])
    assert r["route"] == "tor" and r["passive_only"] is True
