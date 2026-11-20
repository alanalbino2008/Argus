"""Phase 64: finished investigations' graphs are cached for read-only views, and stay read-only."""

from __future__ import annotations

import json

from starlette.routing import Route

from argus.demo import DEMO_ID
from argus.observability import metrics


def _dump(graph) -> str:
    return json.dumps(
        {"nodes": [e.model_dump(mode="json") for e in graph.get_all_entities()],
         "edges": [r.model_dump(mode="json") for r in graph.get_all_relations()]},
        sort_keys=True, default=str,
    )  # fmt: skip


def _count(result: str) -> float:
    return metrics.REGISTRY.get_sample_value("argus_graph_cache_total", {"result": result}) or 0.0


def test_no_view_modifies_the_shared_graph(make_client):
    client = make_client(monitors_enabled="false")
    client.post("/api/demo")
    repo = client.app.state.repo
    shared = client.portal.call(lambda: repo.load_graph(DEMO_ID, shared=True))
    before = _dump(shared)

    hit = 0
    for route in client.app.routes:
        if isinstance(route, Route) and "{inv_id}" in route.path and "GET" in route.methods:
            assert client.get(route.path.replace("{inv_id}", DEMO_ID)).status_code < 500, route.path
            hit += 1
    for body in ({"query": "* | sort key_score"}, {"query": "path from type:email to ip"}):
        assert client.post(f"/api/investigation/{DEMO_ID}/query", json=body).status_code == 200
    client.post("/api/hunt", json={"query": "*"})
    assert hit >= 12

    again = client.portal.call(lambda: repo.load_graph(DEMO_ID, shared=True))
    assert again is shared  # still the cached object...
    assert _dump(again) == before  # ...and nothing changed it


def test_hits_misses_and_private_copies(make_client):
    client = make_client(monitors_enabled="false")
    client.post("/api/demo")
    repo = client.app.state.repo
    hits, misses = _count("hit"), _count("miss")
    first = client.portal.call(lambda: repo.load_graph(DEMO_ID, shared=True))
    second = client.portal.call(lambda: repo.load_graph(DEMO_ID, shared=True))
    private = client.portal.call(lambda: repo.load_graph(DEMO_ID))
    assert second is first and private is not first  # callers that may edit get their own copy
    assert _count("hit") >= hits + 1 and _count("miss") >= misses + 1


def test_changed_or_deleted_investigations_are_never_served_stale(make_client):
    from sqlalchemy import update

    from argus.storage.db import InvestigationRow

    client = make_client(monitors_enabled="false")
    client.post("/api/demo")
    repo = client.app.state.repo
    first = client.portal.call(lambda: repo.load_graph(DEMO_ID, shared=True))

    async def touch():
        async with client.app.state.db.session() as s, s.begin():
            await s.execute(update(InvestigationRow).where(InvestigationRow.id == DEMO_ID).values(edge_count=999))

    client.portal.call(touch)  # e.g. another replica rewrote it
    assert client.portal.call(lambda: repo.load_graph(DEMO_ID, shared=True)) is not first
    assert client.delete(f"/api/investigation/{DEMO_ID}").status_code in (200, 204)
    assert client.portal.call(lambda: repo.load_graph(DEMO_ID, shared=True)) is None
    assert DEMO_ID not in repo._graph_cache


def test_running_scans_and_size_limit(make_client):
    client = make_client(monitors_enabled="false", graph_cache_size=1)
    ids = client.post("/api/demo").json()["investigation_id"], "inv_demo_acme_prev"
    repo = client.app.state.repo
    for inv_id in ids:
        client.portal.call(lambda inv_id=inv_id: repo.load_graph(inv_id, shared=True))
    assert list(repo._graph_cache) == [ids[1]]  # the least recently used was dropped


def test_cache_can_be_turned_off(make_client):
    client = make_client(monitors_enabled="false", graph_cache_size=0)
    client.post("/api/demo")
    repo = client.app.state.repo
    a = client.portal.call(lambda: repo.load_graph(DEMO_ID, shared=True))
    b = client.portal.call(lambda: repo.load_graph(DEMO_ID, shared=True))
    assert a is not b and not repo._graph_cache
