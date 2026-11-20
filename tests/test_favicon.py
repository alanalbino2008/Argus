"""Phase 60: favicon fingerprints and pivoting."""

from __future__ import annotations

import base64
import re
from typing import Any

import aiohttp
import pytest
from multidict import CIMultiDict

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, RelationType, ScanConfig
from argus.intel.favicon import fingerprint, icon_links, murmur3_32, shodan_hash, sniff_image
from argus.intel.query import run_query
from argus.modules import get_module_catalog
from argus.modules.infrastructure.favicon import FaviconPivotModule
from argus.security.network import BlockedDestinationError

CONFIG = ScanConfig(target="x", target_type=EntityType.DOMAIN)
PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(200))
ICO = b"\x00\x00\x01\x00" + b"\x01" * 300


# ----------------------------------------------------------------------------- hashing
@pytest.mark.parametrize(
    "data, seed, expected",
    [  # the published MurmurHash3_x86_32 reference vectors (unsigned)
        (b"", 0, 0x00000000),
        (b"", 1, 0x514E28B7),
        (b"", 0xFFFFFFFF, 0x81F16F39),
        (b"\x00\x00\x00\x00", 0, 0x2362F9DE),
        (b"abc", 0, 0xB3DD93FA),
        (b"aaaa", 0x9747B28C, 0x5A97808A),
        (b"Hello, world!", 0x9747B28C, 0x24884CBA),
        (b"The quick brown fox jumps over the lazy dog", 0x9747B28C, 0x2FA826CD),
    ],
)
def test_murmur3_reference_vectors(data, seed, expected):
    assert murmur3_32(data, seed) & 0xFFFFFFFF == expected


def test_murmur3_is_signed_like_mmh3():
    value = murmur3_32(b"abc")  # 0xB3DD93FA has the top bit set
    assert value < 0 and value == 0xB3DD93FA - (1 << 32)


def test_shodan_hash_uses_mime_base64():
    icon = bytes(range(256)) * 3  # long enough for several 76-character lines
    encoded = base64.encodebytes(icon)
    assert encoded.count(b"\n") > 1
    assert shodan_hash(icon) == murmur3_32(encoded)
    assert shodan_hash(icon) != murmur3_32(base64.b64encode(icon))  # the line breaks matter


@pytest.mark.parametrize(
    "data, kind",
    [
        (ICO, "image/x-icon"),
        (PNG, "image/png"),
        (b"GIF89a....", "image/gif"),
        (b"\xff\xd8\xff\xe0JFIF", "image/jpeg"),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp"),
        (b'  <svg xmlns="http://www.w3.org/2000/svg"></svg>', "image/svg+xml"),
        (b'<?xml version="1.0"?>\n<svg></svg>', "image/svg+xml"),
        (b"<!doctype html><html>Not found</html>", None),  # a "soft 404"
        (b"", None),
    ],
)
def test_sniff_image(data, kind):
    assert sniff_image(data) == kind


def test_fingerprint_and_search_queries():
    fp = fingerprint(PNG)
    assert fp is not None and fp.content_type == "image/png" and fp.size == len(PNG)
    queries = fp.queries()
    assert queries["shodan"] == f"http.favicon.hash:{fp.mmh3}"
    assert queries["fofa"] == f'icon_hash="{fp.mmh3}"'
    assert queries["censys"] == f'host.services.endpoints.http.favicons.hash_sha256 = "{fp.sha256}"'
    assert fingerprint(b"<html></html>") is None
    assert fingerprint(b"\x89PNG\r\n\x1a\n" + b"x" * (300 * 1024)) is None  # too big to be an icon


def test_icon_links():
    html = """<head>
      <link rel="stylesheet" href="/a.css">
      <LINK REL='shortcut icon' HREF='/static/fav.ico'>
      <link href=/touch.png rel="apple-touch-icon">
      <link rel="icon" href="data:image/png;base64,AAAA">
      <link rel="icon" type="image/svg+xml" href="https://cdn.example/icon.svg">
    </head>"""
    assert icon_links(html) == ["/static/fav.ico", "/touch.png", "https://cdn.example/icon.svg"]


# ----------------------------------------------------------------------------- module
class FakeContent:
    def __init__(self, data: bytes):
        self.data = data

    async def read(self, n: int = -1) -> bytes:
        return self.data if n < 0 else self.data[:n]


class FakeResponse:
    def __init__(self, url: str, status: int = 200, body: bytes = b"", content_type: str = ""):
        self.url = url
        self.status = status
        self.content = FakeContent(body)
        self.headers = CIMultiDict({"Content-Type": content_type} if content_type else {})

    async def read(self) -> bytes:
        return self.content.data


class FakeSession:
    """Regex routes to responses or exceptions; anything else is a 404."""

    def __init__(self, routes: dict[str, Any]):
        self.routes = routes
        self.requested: list[str] = []

    def get(self, url: str, **_: Any):
        self.requested.append(url)
        outcome: Any = FakeResponse(url, status=404)
        for pattern, value in self.routes.items():
            if re.search(pattern, url):
                outcome = value
                break
        return _Ctx(outcome, url)


class _Ctx:
    def __init__(self, outcome: Any, url: str):
        self.outcome, self.url = outcome, url

    async def __aenter__(self):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        if isinstance(self.outcome, FakeResponse):
            self.outcome.url = self.outcome.url or self.url
        return self.outcome

    async def __aexit__(self, *exc):
        return False


async def collect(session: FakeSession, value: str = "shop.example.com", **metadata):
    entity = Entity.create(EntityType.SUBDOMAIN, value, metadata=metadata, depth=1)
    return entity, [item async for item in FaviconPivotModule().run(entity, session, CONFIG)]


async def test_favicon_ico_becomes_a_shared_node():
    session = FakeSession({r"/favicon\.ico$": FakeResponse("", body=PNG)})
    entity, items = await collect(session)
    icon, relation = items
    fp = fingerprint(PNG)
    assert icon.type == EntityType.GENERIC and icon.value == f"favicon:{fp.mmh3}"
    assert icon.metadata["category"] == "favicon" and icon.metadata["pivot_hub"] is True
    assert icon.metadata["search_queries"]["shodan"] == f"http.favicon.hash:{fp.mmh3}"
    assert (relation.source_id, relation.target_id, relation.type) == (entity.id, icon.id, RelationType.USES_TECH)
    assert relation.confidence < 1  # a lead, not proof
    assert session.requested == ["https://shop.example.com/favicon.ico"]
    # A second host with the same icon points at the very same node.
    _, again = await collect(FakeSession({r"/favicon\.ico$": FakeResponse("", body=PNG)}), "www.example.com")
    assert again[0].id == icon.id


async def test_soft_404_falls_back_to_the_declared_icon():
    page = '<html><head><link rel="icon" href="/assets/brand.ico"></head></html>'
    session = FakeSession(
        {
            r"/favicon\.ico$": FakeResponse("", body=b"<html>Page not found</html>", content_type="text/html"),
            r"/assets/brand\.ico$": FakeResponse("", body=ICO),
            r"example\.com/$": FakeResponse("https://shop.example.com/", body=page.encode(), content_type="text/html"),
        }
    )
    _, items = await collect(session)
    assert items[0].metadata["content_type"] == "image/x-icon"
    assert items[1].metadata["url"] == "https://shop.example.com/assets/brand.ico"


async def test_plain_http_is_tried_only_when_https_is_unreachable():
    down = aiohttp.ClientConnectionError("refused")
    session = FakeSession({r"^https://": down, r"^http://.*/favicon\.ico$": FakeResponse("", body=ICO)})
    _, items = await collect(session)
    assert len(items) == 2
    answered = FakeSession({})  # HTTPS answers with 404s: nothing more to try
    _, none = await collect(answered)
    assert none == [] and not any(u.startswith("http://") for u in answered.requested)


async def test_private_icon_links_are_refused_without_failing():
    page = '<link rel="icon" href="http://10.0.0.5/icon.png">'
    session = FakeSession(
        {
            r"10\.0\.0\.5": BlockedDestinationError("private address"),
            r"example\.com/$": FakeResponse("https://shop.example.com/", body=page.encode(), content_type="text/html"),
        }
    )
    _, items = await collect(session)
    assert items == []


async def test_third_party_assets_are_left_alone():
    session = FakeSession({r"favicon": FakeResponse("", body=PNG)})
    _, items = await collect(session, out_of_scope=True)
    assert items == [] and session.requested == []


def test_registered_as_an_active_module():
    module = get_module_catalog()["favicon_pivot"]
    assert module.active and not module.third_party_safe
    assert module.can_handle(Entity.create(EntityType.DOMAIN, "example.com"))
    assert not module.can_handle(Entity.create(EntityType.IP_ADDRESS, "192.0.2.1"))


async def test_shared_icons_are_queryable():
    graph = IntelligenceGraph("inv_fav")
    hosts = [Entity.create(EntityType.SUBDOMAIN, h) for h in ("a.example.com", "b.example.org", "c.example.net")]
    for host in hosts:
        graph.add_entity(host)
    shared = FakeSession({r"/favicon\.ico$": FakeResponse("", body=PNG)})
    for host in hosts[:2]:
        async for item in FaviconPivotModule().run(host, shared, CONFIG):
            if isinstance(item, Entity):
                graph.add_entity(item)
            else:
                graph.add_relation(item)
    result = run_query(graph, "category:favicon degree>=2 <-[USES_TECH]- *")
    assert sorted(r["label"] for r in result["rows"]) == ["a.example.com", "b.example.org"]
