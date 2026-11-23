"""Phase 81: alert workflow — status, assignee, comments, activity and response times."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import update

from argus.storage.db import AlertRow

RED = {"X-Argus-Workspace": "red-team"}


@pytest.fixture
def c(make_client):
    return make_client(monitors_enabled="false", notifications_enabled="false")


def _raise(c, severity="high", workspace_id="ws_default", headline="New attack path on acme.example"):
    return c.portal.call(lambda: c.app.state.monitors.create_alert(
        monitor_id=None, investigation_id="", previous_investigation_id="", target="acme.example", severity=severity,
        headline=headline, summary={}, workspace_id=workspace_id, notify=False))  # fmt: skip


def test_the_life_of_an_alert(c):
    alert = _raise(c)
    assert alert["status"] == "open" and alert["assignee"] is None
    assert c.post(f"/api/alerts/{alert['id']}/acknowledge").status_code == 200
    seen = c.get(f"/api/alerts/{alert['id']}").json()
    assert seen["status"] == "investigating" and seen["activity"][0]["event"] == "acknowledged"

    me = c.get("/api/alerts/assignees").json()["me"]
    mine = c.patch(f"/api/alerts/{alert['id']}", json={"assignee": "me", "note": "Taking this one"}).json()
    assert mine["assignee"] == me and mine["activity"][-1] == {**mine["activity"][-1], "event": "assigned", "to": me,
                                                               "note": "Taking this one"}  # fmt: skip
    assert c.patch(f"/api/alerts/{alert['id']}", json={"assignee": "stranger@elsewhere.example"}).status_code == 422
    entry = c.post(f"/api/alerts/{alert['id']}/comments", json={"body": "Port 3389 closed by IT; verifying."}).json()
    assert entry["event"] == "comment" and entry["by"] == me
    listed = c.get("/api/alerts?status=open,investigating&assignee=me").json()
    assert [a["id"] for a in listed] == [alert["id"]] and listed[0]["comments"] == 1
    assert c.get("/api/alerts?assignee=none&status=open,investigating").json() == []

    done = c.patch(f"/api/alerts/{alert['id']}", json={"status": "resolved", "note": "Closed and verified"}).json()
    assert done["status"] == "resolved" and done["resolved_by"] == me and done["resolved_at"]
    assert c.get("/api/alerts?status=open,investigating").json() == []
    assert [a["id"] for a in c.get("/api/alerts?status=resolved,false_positive").json()] == [alert["id"]]
    reopened = c.patch(f"/api/alerts/{alert['id']}", json={"status": "open"}).json()
    assert reopened["resolved_at"] is None and reopened["status"] == "open"
    events = [e["event"] for e in c.get(f"/api/alerts/{alert['id']}").json()["activity"]]
    assert events == ["acknowledged", "assigned", "comment", "status", "status"]
    unassigned = c.patch(f"/api/alerts/{alert['id']}", json={"assignee": ""}).json()
    assert unassigned["assignee"] is None
    assert c.get("/api/alerts?status=nonsense").status_code == 422
    actions = {e["action"] for e in c.get("/api/audit?limit=50").json()}
    assert {"alert.update", "alert.comment", "alert.acknowledge"} <= actions


def test_response_times(c):
    now = datetime.now(timezone.utc)
    quick, slow, noise, waiting = (_raise(c, s) for s in ("critical", "high", "low", "medium"))

    async def backdate():
        async with c.app.state.db.session() as s, s.begin():
            for alert, created in ((quick, 10), (slow, 50), (noise, 5), (waiting, 3)):
                await s.execute(
                    update(AlertRow).where(AlertRow.id == alert["id"]).values(created_at=now - timedelta(hours=created))
                )

    c.portal.call(backdate)
    c.post(f"/api/alerts/{quick['id']}/acknowledge")
    c.patch(f"/api/alerts/{quick['id']}", json={"status": "resolved"})
    c.patch(f"/api/alerts/{slow['id']}", json={"status": "resolved"})
    c.patch(f"/api/alerts/{noise['id']}", json={"status": "false_positive"})
    c.patch(f"/api/alerts/{waiting['id']}", json={"assignee": "me"})
    stats = c.get("/api/alerts/stats?days=30").json()
    assert stats["open"] == 1 and stats["open_by_severity"] == {"medium": 1} and stats["unassigned"] == 0
    assert stats["raised"] == 4 and stats["resolved"] == 3 and stats["false_positive_rate"] == round(1 / 3, 3)
    assert 9.5 < stats["median_hours_to_resolve"] < 10.5  # 10, 50 and 5 hours -> median 10


def test_roles_and_teams(c):
    alert = _raise(c)
    viewer = c.post("/api/keys", json={"name": "reader", "role": "viewer"}).json()["key"]
    as_viewer = {"Authorization": f"Bearer {viewer}"}
    assert c.get(f"/api/alerts/{alert['id']}", headers=as_viewer).status_code == 200
    assert c.patch(f"/api/alerts/{alert['id']}", json={"status": "resolved"}, headers=as_viewer).status_code == 403
    assert c.post(f"/api/alerts/{alert['id']}/comments", json={"body": "x"}, headers=as_viewer).status_code == 403
    c.post("/api/workspaces", json={"id": "red-team", "name": "Red team"})
    assert c.get(f"/api/alerts/{alert['id']}", headers=RED).status_code == 404
    assert c.patch(f"/api/alerts/{alert['id']}", json={"status": "resolved"}, headers=RED).status_code == 404
    assert c.get("/api/alerts/stats", headers=RED).json()["open"] == 0


def test_the_python_client(c):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    argus = ArgusClient(http=c)
    alert = _raise(c)
    assert argus.update_alert(alert["id"], status="investigating", assignee="me")["status"] == "investigating"
    assert argus.comment_alert(alert["id"], "Looking")["event"] == "comment"
    assert argus.alert_stats(days=7)["period_days"] == 7  # the parameter really reaches the server
    assert argus.brand_protection(days=14)["period_days"] == 14
