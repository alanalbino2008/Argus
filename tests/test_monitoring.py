"""Drift detection, diff API, monitors and the scheduler (end-to-end, offline)."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import update

from argus.api import server
from argus.core import engine as engine_module
from argus.demo import DEMO_ID, DEMO_PREVIOUS_ID, build_demo
from argus.intel.diff import compare, headline
from argus.storage.db import MonitorRow
from tests.test_engine import FanOutModule

MON = {
    "target": "example.com",
    "interval_hours": 24,
    "max_depth": 1,
    "purpose": "Continuous monitoring of own estate",
    "authorized": True,
}


# ------------------------------------------------------------------- diff logic
def test_demo_drift_is_detected_precisely():
    _, old = build_demo(previous=True)
    _, new = build_demo()
    d = compare(old, new)
    s = d["summary"]
    assert (s["added"], s["removed"], s["changed"]) == (4, 1, 2)
    assert {p["title"] for p in d["new_paths"]} >= {"Redis exposed to the internet on 203.0.113.30"}
    assert [p["title"] for p in d["resolved_paths"]] == ["FTP exposed to the internet on 203.0.113.30"]
    # same scenario, worse: identity is rule + subject, so it escalates rather than "new + resolved"
    assert [(p["score_before"], p["score"]) for p in d["escalated_paths"]] == [(40, 80)]
    assert s["trend"] == "worse" and s["risk_delta"] > 0 and s["material"]
    changes = {c["value"]: c["changes"] for c in d["changed"]}
    assert changes["legacy.acme-corp.example"]["virustotal_malicious"] == {"before": 0, "after": 4}
    assert "1 path(s) escalated" in headline(d, "acme-corp.example")


def test_identical_scans_are_not_material():
    _, g = build_demo()
    d = compare(g, g)
    assert d["summary"]["material"] is False and d["summary"]["trend"] == "unchanged"
    assert headline(d, "x").startswith("x: no changes")


# --------------------------------------------------------------------- diff API
def test_diff_api_defaults_to_previous_scan(client):
    client.post("/api/demo")
    body = client.get(f"/api/investigation/{DEMO_ID}/diff").json()
    assert body["previous_investigation_id"] == DEMO_PREVIOUS_ID and body["summary"]["trend"] == "worse"
    explicit = client.get(f"/api/investigation/{DEMO_ID}/diff", params={"against": DEMO_PREVIOUS_ID}).json()
    assert explicit["summary"] == body["summary"]
    assert client.get(f"/api/investigation/{DEMO_PREVIOUS_ID}/diff").status_code == 404  # nothing earlier


# ------------------------------------------------------------------ monitor API
def test_monitor_crud_and_rules_of_engagement(make_client):
    client = make_client(monitors_enabled="false")
    assert client.post("/api/monitors", json={**MON, "authorized": False}).status_code == 422
    assert client.post("/api/monitors", json={**MON, "target": "10.0.0.5"}).status_code == 422  # scope
    created = client.post("/api/monitors", json=MON)
    assert created.status_code == 201
    mon = created.json()
    assert client.get("/api/monitors").json()[0]["id"] == mon["id"]
    assert client.patch(f"/api/monitors/{mon['id']}", json={"enabled": False}).json()["enabled"] is False
    assert client.delete(f"/api/monitors/{mon['id']}").status_code == 204
    assert client.delete(f"/api/monitors/{mon['id']}").status_code == 404
    actions = {e["action"] for e in client.get("/api/audit").json()}
    assert {"monitor.create", "monitor.update", "monitor.delete"} <= actions


def test_viewers_cannot_create_monitors(make_client):
    client = make_client(monitors_enabled="false")
    viewer = client.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    client.headers["Authorization"] = f"Bearer {viewer}"
    assert client.post("/api/monitors", json=MON).status_code == 403


# ------------------------------------------------------------ scheduler end-to-end
def _wait_for_background(client):
    async def idle():
        for _ in range(200):
            if not server.SCAN_TASKS and not server.BACKGROUND_TASKS:
                return
            await asyncio.sleep(0.05)
        raise AssertionError("background work did not finish")

    client.portal.call(idle)


def _make_due(client, monitor_id):
    async def due():
        async with client.app.state.db.session() as s, s.begin():
            await s.execute(
                update(MonitorRow)
                .where(MonitorRow.id == monitor_id)
                .values(next_run_at=datetime.now(timezone.utc) - timedelta(minutes=1))
            )

    client.portal.call(due)


def test_scheduler_rescans_and_raises_alert_on_drift(make_client, monkeypatch):
    fan = {"n": 2}
    monkeypatch.setattr(engine_module, "get_default_modules", lambda: {"fan_out": FanOutModule(fan=fan["n"])})
    client = make_client(monitors_enabled="false")  # drive the scheduler manually
    scheduler = client.app.state.scheduler

    mon = client.post("/api/monitors", json=MON).json()
    assert len(client.portal.call(scheduler.tick)) == 1  # baseline scan
    _wait_for_background(client)
    assert client.get("/api/alerts").json() == []  # a baseline never alerts

    assert client.portal.call(scheduler.tick) == []  # not due yet
    fan["n"] = 4  # the attack surface drifts: two new subdomains appear
    _make_due(client, mon["id"])
    assert len(client.portal.call(scheduler.tick)) == 1
    _wait_for_background(client)

    alerts = client.get("/api/alerts").json()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["monitor_id"] == mon["id"] and alert["summary"]["summary"]["added"] == 2
    assert "2 new asset(s)" in alert["headline"]
    assert client.get("/api/monitors").json()[0]["last_investigation_id"] == alert["investigation_id"]

    assert client.post(f"/api/alerts/{alert['id']}/acknowledge").status_code == 200
    assert client.get("/api/alerts", params={"unacknowledged": True}).json() == []
    assert client.post(f"/api/alerts/{alert['id']}/acknowledge").status_code == 404
    actions = {e["action"] for e in client.get("/api/audit").json()}
    assert {"monitor.run", "alert.raised", "alert.acknowledge"} <= actions


def test_scheduler_respects_the_concurrency_cap(make_client, monkeypatch):
    client = make_client(monitors_enabled="false", max_concurrent_scans=1)
    monkeypatch.setattr(server, "_running_scans", lambda: 1)  # server already at capacity
    client.app.state.scheduler.running_scans = server._running_scans
    client.post("/api/monitors", json=MON)
    assert client.portal.call(client.app.state.scheduler.tick) == []


def test_scheduler_disables_monitors_that_fall_out_of_scope(make_client):
    client = make_client(monitors_enabled="false")
    repo = client.app.state.monitors
    client.portal.call(
        lambda: repo.create(
            target="intranet.corp",
            target_type="domain",
            max_depth=1,
            interval_hours=1,
            purpose="legacy monitor",
            created_by="x",
        )
    )
    assert client.portal.call(client.app.state.scheduler.tick) == []
    assert client.get("/api/monitors").json()[0]["enabled"] is False
    assert any(e["action"] == "monitor.disabled" for e in client.get("/api/audit").json())


@pytest.fixture(autouse=True)
def _clean_background():
    yield
    server.BACKGROUND_TASKS.clear()
