"""Persistence layer: repository, write-behind recorder, crash recovery, API history & replay."""

import asyncio

import pytest

from argus.api import server
from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.models import EntityType, InvestigationStatus, ScanConfig
from argus.storage import Database, InvestigationRecorder, InvestigationRepository
from tests.test_engine import FanOutModule


@pytest.fixture
async def repo(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    await db.create_all()
    yield InvestigationRepository(db)
    await db.dispose()


def make_engine(fan=3, depth=1, delay=0.0, target="example.com"):
    config = ScanConfig(target=target, target_type=EntityType.DOMAIN, max_depth=depth)
    return ArgusEngine(config, bus=EventBus(), modules={"fan_out": FanOutModule(fan=fan, delay=delay)})


async def run_recorded(repo, engine, interval=0.05):
    recorder = InvestigationRecorder(repo, engine, flush_interval=interval)
    await recorder.start()
    try:
        await engine.start()
    finally:
        await recorder.finish()
    return recorder


async def test_completed_scan_round_trips_through_database(repo):
    engine = make_engine(fan=3, depth=2)
    await run_recorded(repo, engine)

    inv = await repo.get_investigation(engine.investigation_id)
    assert inv.status == InvestigationStatus.COMPLETED
    assert inv.node_count == engine.graph.node_count == 13
    assert inv.analytics and inv.module_stats["fan_out"]["succeeded"] == 4

    graph = await repo.load_graph(engine.investigation_id)
    assert graph.node_count == 13 and graph.edge_count == 12
    assert sorted(graph.to_maltego_csv().splitlines()) == sorted(engine.graph.to_maltego_csv().splitlines())


async def test_findings_are_checkpointed_while_scan_runs(repo):
    engine = make_engine(fan=3, depth=3, delay=0.15)
    recorder = InvestigationRecorder(repo, engine, flush_interval=0.05)
    await recorder.start()
    task = asyncio.create_task(engine.start())
    await asyncio.sleep(0.4)  # mid-scan

    mid = await repo.load_graph(engine.investigation_id)
    assert 1 < mid.node_count < 40  # partial results already durable
    assert (await repo.get_investigation(engine.investigation_id)).status == InvestigationStatus.RUNNING

    engine.cancel()
    await task
    await recorder.finish()
    assert (await repo.get_investigation(engine.investigation_id)).status == InvestigationStatus.CANCELLED
    assert recorder.flushes >= 2


async def test_interrupted_scans_are_marked_failed_on_startup(repo):
    engine = make_engine()
    engine.investigation.status = InvestigationStatus.RUNNING
    await repo.save_investigation(engine.investigation)

    assert await repo.mark_interrupted() == 1
    inv = await repo.get_investigation(engine.investigation_id)
    assert inv.status == InvestigationStatus.FAILED
    assert "Interrupted" in inv.errors[-1]
    assert await repo.mark_interrupted() == 0  # idempotent


async def test_history_listing_search_and_delete(repo):
    a, b = make_engine(target="alpha.com"), make_engine(target="beta.com")
    await run_recorded(repo, a)
    await run_recorded(repo, b)

    listed = await repo.list_investigations()
    assert [r["target"] for r in listed] == ["beta.com", "alpha.com"]  # newest first
    assert listed[0]["threat_exposure_score"] is not None
    assert [r["target"] for r in await repo.list_investigations(target="ALPHA")] == ["alpha.com"]

    hits = await repo.search_entities("n1.alpha")
    assert len(hits) == 1 and hits[0]["investigation_target"] == "alpha.com"
    assert len(await repo.search_entities("n0.", entity_type="subdomain")) == 2

    assert await repo.delete_investigation(a.investigation_id) is True
    assert await repo.get_investigation(a.investigation_id) is None
    assert await repo.load_graph(a.investigation_id) is None
    assert await repo.search_entities("alpha") == []
    assert await repo.delete_investigation(a.investigation_id) is False


async def test_upsert_merges_rather_than_duplicates(repo):
    engine = make_engine()
    await run_recorded(repo, engine)
    await repo.save_graph(engine.graph)  # second full save must be idempotent
    assert (await repo.load_graph(engine.investigation_id)).node_count == 4


# ----------------------------------------------------------------------------- API level


def _seed_finished_investigation(client) -> str:
    """Run a fake scan and persist it through the app's own repository."""
    repo = client.app.state.repo
    engine = make_engine(fan=2, depth=1)
    client.portal.call(run_recorded, repo, engine)
    return engine.investigation_id


def test_health(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok" and body["database"]["reachable"] is True


def test_history_survives_and_serves_finished_investigations(client):
    inv_id = _seed_finished_investigation(client)

    listing = client.get("/api/investigations").json()
    assert listing[0]["id"] == inv_id and listing[0]["status"] == "completed"
    assert client.get("/api/investigations", params={"status": "failed"}).json() == []

    detail = client.get(f"/api/investigation/{inv_id}").json()
    assert detail["node_count"] == 3 and detail["module_stats"]["fan_out"]["runs"] == 1

    graph = client.get(f"/api/investigation/{inv_id}/graph").json()
    assert len(graph["elements"]) == 5
    assert client.get(f"/api/investigation/{inv_id}/export/csv").status_code == 200
    assert client.post(f"/api/investigation/{inv_id}/cancel").status_code == 409


def test_websocket_replays_snapshot_for_finished_scan(client):
    inv_id = _seed_finished_investigation(client)
    ticket = client.post("/api/ws-ticket").json()["ticket"]
    with client.websocket_connect(f"/ws/stream/{inv_id}?ticket={ticket}") as ws:
        msg = ws.receive_json()
    assert msg["type"] == "snapshot"
    assert msg["data"]["investigation"]["status"] == "completed"
    assert len(msg["data"]["entities"]) == 3 and len(msg["data"]["relations"]) == 2


def test_websocket_rejects_unknown_investigation(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        ticket = client.post("/api/ws-ticket").json()["ticket"]
        with client.websocket_connect(f"/ws/stream/inv_missing?ticket={ticket}") as ws:
            ws.receive_json()


def test_entity_search_and_delete_endpoints(client):
    inv_id = _seed_finished_investigation(client)
    hits = client.get("/api/entities/search", params={"q": "n0.example"}).json()
    assert hits and hits[0]["investigation_id"] == inv_id
    assert client.get("/api/entities/search", params={"q": "x"}).status_code == 422

    assert client.delete(f"/api/investigation/{inv_id}").status_code == 204
    assert client.get(f"/api/investigation/{inv_id}").status_code == 404
    assert client.delete(f"/api/investigation/{inv_id}").status_code == 404


async def test_slow_websocket_client_is_cut_off_not_buffered_forever():
    """Backpressure: a client that stops reading is disconnected once its queue is full."""
    conn = server.ClientConnection(ws=None, maxsize=3)
    for i in range(3):
        conn.offer(f"msg{i}")
    assert not conn.dead.is_set()
    conn.offer("one too many")
    assert conn.dead.is_set() and conn.queue.qsize() == 3
