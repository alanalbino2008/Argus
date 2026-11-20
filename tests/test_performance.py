"""Phase 58: compressed responses and a quieter live stream."""

import asyncio

from argus.api import server
from argus.core.events import Event, EventType
from argus.demo import DEMO_ID


def test_large_responses_are_gzipped(client):
    client.post("/api/demo")
    resp = client.get(f"/api/investigation/{DEMO_ID}/graph", headers={"Accept-Encoding": "gzip"})
    assert resp.status_code == 200
    assert resp.headers.get("content-encoding") == "gzip"
    assert resp.json()["elements"]  # httpx decompresses transparently
    # Security headers survive compression (gzip sits inside them).
    assert resp.headers["cache-control"] == "no-store"
    assert "content-security-policy" in resp.headers


def test_small_responses_are_not_compressed(client):
    resp = client.get("/api/health", headers={"Accept-Encoding": "gzip"})
    assert "content-encoding" not in resp.headers


def test_compression_setting(monkeypatch):
    from argus.core.settings import Settings

    assert Settings().compress_responses is True
    monkeypatch.setenv("ARGUS_COMPRESS_RESPONSES", "false")
    assert Settings().compress_responses is False
    assert any(m.cls.__name__ == "GZipMiddleware" for m in server.app.user_middleware)


class _Conn:
    def __init__(self):
        self.messages = []

    def offer(self, message):
        self.messages.append(message)


def test_module_chatter_is_not_streamed():
    conn = _Conn()
    server.CONNECTIONS["inv_perf"] = {conn}
    try:
        for kind in (EventType.MODULE_STARTED, EventType.MODULE_FINISHED, EventType.ENTITY_DISCOVERED):
            asyncio.run(server.ws_dispatcher(Event(type=kind, investigation_id="inv_perf", data={})))
    finally:
        server.CONNECTIONS.pop("inv_perf", None)
    assert len(conn.messages) == 1
    assert '"entity_discovered"' in conn.messages[0]
