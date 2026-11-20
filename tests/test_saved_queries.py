"""Phase 61: saved queries, hunts across investigations, and query alerts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from argus.api import server
from argus.core.models import Entity, EntityType, InvestigationStatus, Relation, RelationType
from argus.demo import DEMO_ID, DEMO_PREVIOUS_ID
from argus.intel.hunt import alert_headline
from argus.intel.query import run_query
from argus.notify.render import alert_event

RED = {"X-Argus-Workspace": "red-team"}
KEV = {"name": "Exploited CVEs", "query": "type:vulnerability intel.kev:*", "severity": "high"}


@pytest.fixture
def demo_client(make_client):
    client = make_client(monitors_enabled="false")
    client.post("/api/demo")
    return client


def test_crud_and_validation(demo_client):
    c = demo_client
    created = c.post("/api/saved-queries", json={**KEV, "description": "KEV", "alert": True})
    assert created.status_code == 201
    sq = created.json()
    assert sq["id"].startswith("sq_") and sq["alert"] is True and sq["severity"] == "high"
    assert [q["id"] for q in c.get("/api/saved-queries").json()] == [sq["id"]]

    bad = c.post("/api/saved-queries", json={"name": "broken", "query": "type:dom"})
    assert bad.status_code == 400 and bad.json()["detail"]["position"] == 5
    assert c.post("/api/saved-queries", json={"name": "x", "query": "*", "severity": "urgent"}).status_code == 422

    updated = c.patch(f"/api/saved-queries/{sq['id']}", json={"alert": False, "name": "  KEV  "}).json()
    assert updated["alert"] is False and updated["name"] == "KEV" and updated["query"] == KEV["query"]
    assert c.patch(f"/api/saved-queries/{sq['id']}", json={"query": "path from"}).status_code == 400
    assert c.delete(f"/api/saved-queries/{sq['id']}").status_code == 204
    assert c.delete(f"/api/saved-queries/{sq['id']}").status_code == 404
    assert c.get("/api/saved-queries").json() == []
    actions = {e["action"] for e in c.get("/api/audit").json()}
    assert {"saved_query.create", "saved_query.update", "saved_query.delete"} <= actions


def test_saved_queries_belong_to_their_workspace(demo_client):
    c = demo_client
    c.post("/api/workspaces", json={"name": "Red Team"})
    sq = c.post("/api/saved-queries", json=KEV).json()
    assert c.get("/api/saved-queries", headers=RED).json() == []
    assert c.patch(f"/api/saved-queries/{sq['id']}", json={"alert": True}, headers=RED).status_code == 404
    assert c.delete(f"/api/saved-queries/{sq['id']}", headers=RED).status_code == 404
    assert c.post(f"/api/saved-queries/{sq['id']}/hunt", headers=RED).status_code == 404
    # A Red Team hunt never sees Default's investigations.
    assert c.post("/api/hunt", json={"query": "*"}, headers=RED).json()["investigations_searched"] == 0


def test_hunt_across_investigations(demo_client):
    c = demo_client
    result = c.post("/api/hunt", json={"query": "type:vulnerability intel.kev:*"}).json()
    assert result["investigations_searched"] == 2  # the demo scan and the one a month earlier
    by_id = {r["investigation_id"]: r for r in result["results"]}
    assert by_id[DEMO_ID]["count"] == 2 and len(by_id[DEMO_ID]["rows"]) == 2
    assert result["total_matches"] == sum(r["count"] for r in result["results"])
    assert set(by_id) <= {DEMO_ID, DEMO_PREVIOUS_ID}
    newest_only = c.post("/api/hunt", json={"query": "*", "investigations": 1}).json()
    assert newest_only["investigations_searched"] == 1
    nothing = c.post("/api/hunt", json={"query": "type:crypto_wallet"}).json()
    assert nothing["investigations_matched"] == 0 and nothing["results"] == []
    assert c.post("/api/hunt", json={"query": "type:dom"}).status_code == 400
    sq = c.post("/api/saved-queries", json=KEV).json()
    assert c.post(f"/api/saved-queries/{sq['id']}/hunt").json()["total_matches"] == result["total_matches"]
    assert "hunt.run" in {e["action"] for e in c.get("/api/audit").json()}


def test_collect_ids_ignores_shaping():
    from argus.demo import build_demo

    _, graph = build_demo()
    full = run_query(graph, "type:domain", collect_ids=True)
    shaped = run_query(graph, "type:domain | limit 1 | count", collect_ids=True)
    assert shaped["rows"] == [] and shaped["match_ids"] == full["match_ids"] and len(full["match_ids"]) > 1
    assert "match_ids" not in run_query(graph, "type:domain")


class _Engine:
    def __init__(self, investigation, graph):
        self.investigation, self.graph = investigation, graph


def _rescan(client, graph, status=InvestigationStatus.COMPLETED):
    """A later scan of the demo target (not stored: only the previous one needs to be)."""
    inv = client.portal.call(client.app.state.repo.get_investigation, DEMO_ID).model_copy(deep=True)
    inv.id, inv.status = "inv_rescan", status
    inv.created_at = datetime.now(timezone.utc) + timedelta(minutes=1)
    return _Engine(inv, graph)


def _alerts(client):
    return [a for a in client.get("/api/alerts").json() if (a.get("summary") or {}).get("saved_query")]


def test_alerts_only_on_new_matches(demo_client):
    c = demo_client
    c.post("/api/saved-queries", json={**KEV, "alert": True})
    c.post("/api/saved-queries", json={"name": "Not alerting", "query": "type:domain", "alert": False})
    graph = c.portal.call(c.app.state.repo.load_graph, DEMO_ID)

    c.portal.call(server._evaluate_saved_queries, c.app, _rescan(c, graph))
    assert _alerts(c) == []  # same CVEs as last time: nothing new

    ip = next(e for e in graph.get_all_entities() if e.type == EntityType.IP_ADDRESS)
    cve = Entity.create(EntityType.VULNERABILITY, "CVE-2099-0001", metadata={"intel": {"kev": {"name": "test"}}})
    graph.add_entity(cve)
    graph.add_relation(Relation.create(ip.id, cve.id, RelationType.EXPOSES))
    c.portal.call(server._evaluate_saved_queries, c.app, _rescan(c, graph))
    (alert,) = _alerts(c)
    assert alert["severity"] == "high"
    assert alert["headline"] == alert_headline({"name": "Exploited CVEs"}, 1, "acme-corp.example")
    sq = alert["summary"]["saved_query"]
    assert sq["new_count"] == 1 and sq["total_count"] == 3 and sq["new_matches"] == ["CVE-2099-0001"]
    assert alert["previous_investigation_id"] == DEMO_ID
    saved = c.get("/api/saved-queries").json()
    kev = next(q for q in saved if q["name"] == "Exploited CVEs")
    assert kev["alerts_raised"] == 1 and kev["last_alert_at"] and kev["last_checked_at"]
    assert next(q for q in saved if q["name"] == "Not alerting")["last_checked_at"] is None

    event = alert_event(alert, {"id": "ws_default", "name": "Default"}, None)
    assert event["alert"]["saved_query"]["new_matches"] == ["CVE-2099-0001"]
    assert "new_ids" not in event["alert"]["saved_query"]


def test_unfinished_scans_and_empty_workspaces_are_skipped(demo_client):
    c = demo_client
    graph = c.portal.call(c.app.state.repo.load_graph, DEMO_ID)
    c.portal.call(server._evaluate_saved_queries, c.app, _rescan(c, graph))  # no saved queries: no-op
    c.post("/api/saved-queries", json={"name": "Any", "query": "*", "alert": True})
    c.portal.call(server._evaluate_saved_queries, c.app, _rescan(c, graph, InvestigationStatus.FAILED))
    assert _alerts(c) == []
    assert c.get("/api/saved-queries").json()[0]["last_checked_at"] is None


def test_real_scans_trigger_query_alerts(make_client, monkeypatch):
    """End to end: finished scans run the alerting queries; only what is new raises an alert."""
    from argus.core import engine as engine_module
    from tests.test_engine import FanOutModule
    from tests.test_monitoring import _wait_for_background

    fan = {"n": 2}
    monkeypatch.setattr(engine_module, "get_default_modules", lambda: {"fan_out": FanOutModule(fan=fan["n"])})
    client = make_client(monitors_enabled="false")
    client.post("/api/saved-queries", json={"name": "Subdomains", "query": "type:subdomain | count", "alert": True})
    scan = {
        "target": "example.com",
        "target_type": "domain",
        "max_depth": 1,
        "purpose": "Unit test",
        "authorized": True,
    }

    assert client.post("/api/scan", json=scan).status_code == 200
    _wait_for_background(client)
    first = _alerts(client)
    assert len(first) == 1 and first[0]["summary"]["saved_query"]["new_count"] == 2  # first scan: all are new

    fan["n"] = 4
    assert client.post("/api/scan", json=scan).status_code == 200
    _wait_for_background(client)
    newest = _alerts(client)
    assert len(newest) == 2
    latest = max(newest, key=lambda a: a["created_at"])["summary"]["saved_query"]
    assert latest["new_count"] == 2 and latest["total_count"] == 4  # "| count" does not hide the matches


def test_python_client(demo_client):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    argus = ArgusClient(http=demo_client)
    assert argus.query(DEMO_ID, "type:vulnerability intel.kev:*")["count"] == 2
    assert argus.links(DEMO_ID)["key_entities"]
    saved = argus.save_query("KEV", "type:vulnerability intel.kev:*", alert=True, severity="high")
    assert [q["id"] for q in argus.saved_queries()] == [saved["id"]]
    assert argus.hunt("type:vulnerability intel.kev:*")["investigations_matched"] >= 1
