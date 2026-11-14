"""Several replicas sharing one database (Kubernetes): every coordination path.

Each "replica" here is a separate Database engine (its own connection pool) on the same
database - exactly the situation of two pods - so these tests run unchanged on SQLite and,
with ARGUS_TEST_DATABASE_URL, on PostgreSQL.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import update

from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.models import Entity, EntityType, Investigation, InvestigationStatus, ScanConfig
from argus.security.auth import Principal, Role
from argus.storage import Database, InvestigationRecorder, InvestigationRepository
from argus.storage.db import InvestigationRow
from argus.storage.migrate import upgrade_database
from argus.storage.monitor_repo import MonitorRepository
from argus.storage.security_repo import AuditLog, TicketStore
from tests.conftest import PG_URL, database_url
from tests.test_engine import FanOutModule

ALICE = Principal(key_id="k1", name="alice", role=Role.ANALYST)


@pytest.fixture
async def pods(tmp_path):
    """Two independent connections ("pods") to one migrated database."""
    url = database_url(tmp_path, "cluster.db")
    a, b = Database(url), Database(url)
    await upgrade_database(a)
    yield a, b
    await a.dispose()
    await b.dispose()


def running(inv_id: str) -> Investigation:
    return Investigation(
        id=inv_id,
        name=inv_id,
        config=ScanConfig(target="acme.example", target_type=EntityType.DOMAIN),
        status=InvestigationStatus.RUNNING,
    )


async def age_heartbeat(db: Database, inv_id: str, seconds: float) -> None:
    async with db.session() as s, s.begin():
        await s.execute(
            update(InvestigationRow)
            .where(InvestigationRow.id == inv_id)
            .values(heartbeat_at=datetime.now(timezone.utc) - timedelta(seconds=seconds))
        )


# ------------------------------------------------------------------ tickets
async def test_ticket_issued_on_one_pod_is_redeemable_once_on_another(pods):
    a, b = pods
    ticket = await TicketStore(a, ttl=30).issue(ALICE)
    redeemed = await TicketStore(b, ttl=30).redeem(ticket)
    assert redeemed == ALICE
    assert await TicketStore(a, ttl=30).redeem(ticket) is None  # single use, cluster-wide
    assert await TicketStore(b, ttl=30).redeem("forged") is None


async def test_expired_tickets_are_rejected(pods):
    a, _ = pods
    store = TicketStore(a, ttl=-1)
    assert await store.redeem(await store.issue(ALICE)) is None


# ------------------------------------------------------------------ scheduler
async def test_a_due_monitor_is_claimed_by_exactly_one_pod(pods):
    a, b = pods
    mon = await MonitorRepository(a).create(
        target="acme.example", target_type="domain", max_depth=1, interval_hours=24, purpose="cluster", created_by="t"
    )
    results = []
    for _ in range(3):  # several rounds of both pods racing for the same monitor
        results += await asyncio.gather(MonitorRepository(a).claim(mon["id"]), MonitorRepository(b).claim(mon["id"]))
    assert results.count(True) == 1
    await MonitorRepository(b).release(mon["id"])  # a failed launch makes it due again
    assert await MonitorRepository(a).claim(mon["id"]) is True


# ------------------------------------------------------------------ audit chain
@pytest.mark.skipif(not PG_URL, reason="SQLite is a single-writer, single-node backend")
async def test_concurrent_audit_appends_from_two_pods_keep_the_chain_valid(pods):
    a, b = pods
    logs = [AuditLog(a), AuditLog(b)]
    await asyncio.gather(*(logs[i % 2].record(ALICE, "test.concurrent", f"r{i}") for i in range(40)))
    assert await AuditLog(a).verify() == {"valid": True, "checked": 40, "first_invalid_id": None}


# ------------------------------------------------------------------ ownership, heartbeat, cancel
async def test_cancel_requested_on_one_pod_reaches_the_owner_via_heartbeat(pods):
    a, b = pods
    owner, other = InvestigationRepository(a), InvestigationRepository(b)
    await owner.save_investigation(running("inv_x"))
    await owner.claim("inv_x", "pod-a")
    assert await owner.heartbeat("inv_x") is False
    assert await other.request_cancel("inv_x") is True
    assert await owner.heartbeat("inv_x") is True
    assert await other.request_cancel("inv_missing") is False


async def test_crash_detection_spares_live_scans_on_other_pods(pods):
    a, b = pods
    repo = InvestigationRepository(a)
    for inv_id, owner in [("inv_live", "pod-b"), ("inv_dead", "pod-c"), ("inv_mine", "pod-a"), ("inv_legacy", None)]:
        await repo.save_investigation(running(inv_id))
        if owner:
            await repo.claim(inv_id, owner)
    await age_heartbeat(a, "inv_dead", 600)

    # pod-a restarts: its own old scans, ownerless legacy rows and stale scans are failed...
    assert await InvestigationRepository(b).mark_interrupted(owned_by="pod-a", stale_seconds=120) == 3
    status = {
        i: (await repo.get_investigation(i)).status.value for i in ("inv_live", "inv_dead", "inv_mine", "inv_legacy")
    }
    assert status == {"inv_live": "running", "inv_dead": "failed", "inv_mine": "failed", "inv_legacy": "failed"}
    # ...and the live scan on pod-b counts towards the cluster-wide concurrency cap.
    assert [s["id"] for s in await repo.active_scans(120)] == ["inv_live"]
    await age_heartbeat(a, "inv_live", 600)
    assert await repo.mark_interrupted(stale_seconds=120, exclude=["inv_live"]) == 0  # still running here
    # A frozen owner that wakes up is fenced: its next heartbeat tells it to stop.
    assert await repo.heartbeat("inv_dead") is True


async def test_recorder_cancels_its_scan_when_another_pod_asks(pods):
    a, b = pods
    config = ScanConfig(target="example.com", target_type=EntityType.DOMAIN, max_depth=4)
    engine = ArgusEngine(config, bus=EventBus(), modules={"fan_out": FanOutModule(fan=3, delay=0.2)})
    recorder = InvestigationRecorder(InvestigationRepository(a), engine, flush_interval=0.05, owner="pod-a")
    await recorder.start()
    scan = asyncio.create_task(engine.start())
    await asyncio.sleep(0.3)
    assert await InvestigationRepository(b).request_cancel(engine.investigation_id) is True
    await asyncio.wait_for(scan, timeout=10)
    await recorder.finish()
    stored = await InvestigationRepository(b).get_investigation(engine.investigation_id)
    assert stored.status == InvestigationStatus.CANCELLED


# ------------------------------------------------------------------ API on a pod that is not the owner
def _remote_scan(client, inv_id: str, owner: str = "pod-elsewhere") -> InvestigationRepository:
    repo: InvestigationRepository = client.app.state.repo

    async def setup():
        await repo.save_investigation(running(inv_id))
        await repo.claim(inv_id, owner)
        await repo.upsert_entities(inv_id, [Entity.create(EntityType.DOMAIN, "acme.example").model_dump(mode="json")])
        inv = running(inv_id)
        inv.node_count = 1
        await repo.save_investigation(inv)

    client.portal.call(setup)
    return repo


def test_cancel_and_delete_work_for_scans_running_on_another_pod(make_client):
    client = make_client(monitors_enabled="false")
    repo = _remote_scan(client, "inv_remote")
    assert client.delete("/api/investigation/inv_remote").status_code == 409  # still running elsewhere
    r = client.post("/api/investigation/inv_remote/cancel")
    assert r.status_code == 200 and r.json()["status"] == "cancelling"
    assert client.portal.call(repo.heartbeat, "inv_remote") is True  # the owner will see it
    assert client.get("/api/audit", params={"action": "scan.cancel"}).json()[0]["details"] == {"via": "cluster"}


def test_concurrency_cap_counts_scans_on_every_pod(make_client):
    client = make_client(monitors_enabled="false", max_concurrent_scans=1)
    _remote_scan(client, "inv_remote")
    r = client.post("/api/scan", json={"target": "example.com", "purpose": "cluster cap test", "authorized": True})
    assert r.status_code == 429 and "concurrent scans" in r.json()["detail"]


def test_websocket_streams_a_scan_running_on_another_pod(make_client):
    client = make_client(monitors_enabled="false", persist_flush_interval="0.1")
    repo = _remote_scan(client, "inv_remote")
    ticket = client.post("/api/ws-ticket").json()["ticket"]
    with client.websocket_connect(f"/ws/stream/inv_remote?ticket={ticket}") as ws:
        snapshot = ws.receive_json()
        assert snapshot["type"] == "snapshot" and len(snapshot["data"]["entities"]) == 1

        async def owner_finds_more_then_finishes():
            new = Entity.create(EntityType.SUBDOMAIN, "vpn.acme.example")
            await repo.upsert_entities("inv_remote", [new.model_dump(mode="json")])
            inv = running("inv_remote")
            inv.node_count = 2
            await repo.save_investigation(inv)
            await asyncio.sleep(0.8)
            inv.status = InvestigationStatus.COMPLETED
            await repo.save_investigation(inv)

        client.portal.call(owner_finds_more_then_finishes)
        found = ws.receive_json()
        assert found["type"] == "entity_discovered" and found["data"]["entity"]["value"] == "vpn.acme.example"
        done = ws.receive_json()
        assert done["type"] == "scan_completed" and done["data"]["analytics"]["node_count"] == 2


def test_startup_fails_only_scans_whose_owner_is_gone(make_client, tmp_path):
    client = make_client(monitors_enabled="false", instance_id="pod-a")
    db = client.app.state.db
    _remote_scan(client, "inv_live", owner="pod-b")
    _remote_scan(client, "inv_dead", owner="pod-c")
    client.portal.call(age_heartbeat, db, "inv_dead", 600)
    restarted = make_client(monitors_enabled="false", instance_id="pod-a")  # pod-a restarts
    fresh = restarted.app.state.repo
    status = {i: restarted.portal.call(fresh.get_investigation, i).status.value for i in ("inv_live", "inv_dead")}
    assert status == {"inv_live": "running", "inv_dead": "failed"}


def test_liveness_ignores_the_database_but_health_reports_the_instance(make_client):
    client = make_client(monitors_enabled="false", instance_id="argus-7d9f-abcde")
    assert client.get("/api/live").json() == {"status": "alive"}
    assert client.get("/api/health").json()["instance"] == "argus-7d9f-abcde"


async def test_status_changes_reach_other_pods_even_without_new_findings(pods):
    a, b = pods
    engine = ArgusEngine(ScanConfig(target="example.com", target_type=EntityType.DOMAIN), bus=EventBus(), modules={})
    recorder = InvestigationRecorder(InvestigationRepository(a), engine, flush_interval=60, owner="pod-a")
    await recorder.start()
    engine.investigation.status = InvestigationStatus.RUNNING  # nothing found yet
    await recorder.flush()
    seen = await InvestigationRepository(b).get_investigation(engine.investigation_id)
    assert seen.status == InvestigationStatus.RUNNING
    await recorder.finish()


@pytest.mark.skipif(not PG_URL, reason="advisory locks are PostgreSQL-only; SQLite is single-node")
async def test_cluster_lock_serialises_check_then_act_across_pods(pods):
    """Two pods bootstrapping at once must create exactly one admin key."""
    from argus.security.auth import Role as R
    from argus.storage.security_repo import ApiKeyRepository

    async def bootstrap(db):
        async with db.cluster_lock(0x1234):
            repo = ApiKeyRepository(db)
            if await repo.count_active(R.ADMIN) == 0:
                await asyncio.sleep(0.05)  # widen the race window
                await repo.create("bootstrap-admin", R.ADMIN, created_by="system")

    await asyncio.gather(*(bootstrap(db) for db in pods * 3))
    assert await ApiKeyRepository(pods[0]).count_active(R.ADMIN) == 1
