"""Dark-web index and paste/leak-forum sources, and the findings they produce.

Argus reads only the clearnet index/provider; it never fetches an onion service. These tests check the
provider client (auth, caps, the SSRF guard, tolerant JSON parsing) and the conservative severity rules
(a bare mention is low; leak-looking or recent raises it)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from aiohttp import web

from argus.core.settings import Settings
from argus.intel.breach_sources import SourceError, SourceUnavailable
from argus.intel.darkweb import DarkWebSources
from argus.intel.exposure import darkweb_findings, paste_findings

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)
RECENT = (NOW - timedelta(days=5)).isoformat()
OLD = "2019-01-01"


# ---------------------------------------------------------------------------- findings / severity
def test_mention_severity_is_conservative():
    # a bare, old mention is low
    [low] = darkweb_findings("Acme", [{"title": "acme fan page", "onion": "http://a.onion", "date": OLD}], NOW)
    assert low.severity == "low" and low.details["leak_signal"] is False and low.kind == "darkweb_mention"
    # leak words OR recency -> medium
    [kw] = darkweb_findings("Acme", [{"title": "acme database dump", "onion": "http://a.onion", "date": OLD}], NOW)
    assert kw.severity == "medium" and kw.details["leak_signal"] is True
    [fresh] = darkweb_findings("Acme", [{"title": "acme fan page", "onion": "http://a.onion", "date": RECENT}], NOW)
    assert fresh.severity == "medium"
    # leak words AND recent -> high
    [hi] = paste_findings("Acme", [{"title": "acme combolist", "url": "https://p.ex/1", "date": RECENT}], NOW)
    assert hi.severity == "high" and hi.kind == "paste_leak" and hi.subject == "Acme"


def test_findings_dedupe_and_keep_the_reference():
    hit = {"title": "dump", "onion": "http://x.onion/t", "snippet": "leak", "date": RECENT}
    found = darkweb_findings("Acme", [hit, dict(hit)], NOW)  # same onion+date twice
    assert len(found) == 1 and found[0].details["onion"] == "http://x.onion/t"
    assert found[0].occurred_at == RECENT[:10]


# ---------------------------------------------------------------------------- the provider client
@pytest.fixture
async def provider():
    seen: list[dict] = []

    async def index(request):
        seen.append({"auth": request.headers.get("Authorization"), "q": request.query.get("q")})
        return web.json_response({"results": [
            {"title": "Falcon dump", "onion": "http://abc.onion/9", "snippet": "credentials", "last_seen": RECENT},
            {"url": "http://def.onion", "description": "mention"},  # minimal/alternate keys
            "garbage",
        ]})  # fmt: skip

    async def pastes(request):
        return web.json_response([{"title": "leak", "url": "https://paste.ex/a", "text": "combo", "created": RECENT}])

    app = web.Application()
    app.router.add_get("/index", index)
    app.router.add_get("/pastes", pastes)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    yield {"base": base, "seen": seen}
    await runner.cleanup()


async def test_the_provider_client_reads_index_and_pastes(provider):
    settings = Settings(
        allow_private_targets=True,
        darkweb_index_url=f"{provider['base']}/index", darkweb_index_api_key="idx-key",
        paste_monitor_url=f"{provider['base']}/pastes",
    )  # fmt: skip
    dw = DarkWebSources(settings)
    try:
        assert dw.capabilities() == {"darkweb_index": True, "paste_monitor": True}
        hits = await dw.index("Project Falcon")
        assert [h["title"] for h in hits] == ["Falcon dump", "http://def.onion"]
        assert hits[0]["onion"] == "http://abc.onion/9" and hits[0]["is_onion"] is True
        assert provider["seen"][0] == {"auth": "Bearer idx-key", "q": "Project Falcon"}
        pastes = await dw.pastes("Project Falcon")
        assert pastes[0]["url"] == "https://paste.ex/a" and pastes[0]["snippet"] == "combo"
    finally:
        await dw.close()


async def test_a_provider_that_is_off_or_private_is_handled():
    off = DarkWebSources(Settings())
    assert off.capabilities() == {"darkweb_index": False, "paste_monitor": False}
    with pytest.raises(SourceUnavailable, match="ARGUS_DARKWEB_INDEX_URL"):
        await off.index("x")
    with pytest.raises(SourceUnavailable, match="ARGUS_PASTE_MONITOR_URL"):
        await off.pastes("x")
    await off.close()
    # the SSRF guard refuses a private index host by default
    guarded = DarkWebSources(Settings(darkweb_index_url="http://127.0.0.1:9/index"))
    try:
        with pytest.raises(SourceError):
            await guarded.index("x")
    finally:
        await guarded.close()


async def test_the_cap_limits_results():
    settings = Settings(allow_private_targets=True, darkweb_index_url="http://x/index", darkweb_lookups_max=1)
    dw = DarkWebSources(settings)

    async def fake_search(which, url, selector):
        return [{"title": f"t{i}", "onion": f"http://{i}.onion"} for i in range(5)]

    dw._search = fake_search  # type: ignore[method-assign]
    assert len(await dw.index("x")) == 1
    await dw.close()
