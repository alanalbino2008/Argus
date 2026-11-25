"""Phase 91: retention periods per workspace, with legal hold, that never break the audit chain."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import partial

from sqlalchemy import select, update

from argus.storage.db import AlertRow, CaseRow, InvestigationRow

NOW = datetime.now(timezone.utc)
DEMO = "inv_demo_acme"


def _ago(days):
    return NOW - timedelta(days=days)


async def _scan(db, inv_id, target, days, status="completed"):
    async with db.session() as s, s.begin():
        s.add(InvestigationRow(id=inv_id, workspace_id="ws_default", target=target, target_type="domain", status=status,
                               created_at=_ago(days), completed_at=_ago(days), data={}))  # fmt: skip


async def _set(db, model, row_id, **values):
    async with db.session() as s, s.begin():
        await s.execute(update(model).where(model.id == row_id).values(**values))


async def _exists(db, model, row_id):
    async with db.session() as s:
        return await s.scalar(select(model.id).where(model.id == row_id)) is not None


def _case(c, title, status="open"):
    r = c.post("/api/cases", json={"title": title, "purpose": "Retention test case for the audit", "confirmed": True})
    case = r.json()["id"]
    if status != "open":
        assert c.patch(f"/api/cases/{case}", json={"status": status}).status_code == 200
    return case


def test_periods_are_validated_and_nothing_goes_by_default(client):
    assert client.get("/api/retention").json()["would_delete"] == {"investigations": 0, "alerts": 0, "cases": 0}
    assert client.put("/api/retention", json={"alerts_days": 3}).status_code == 422  # under a week
    assert client.put("/api/retention", json={"alerts_days": 0, "cases_days": 365}).status_code == 200


def test_old_investigations_go_but_those_in_use_stay(client):
    c, db = client, client.app.state.db
    c.post("/api/demo")
    target = c.get(f"/api/investigation/{DEMO}").json()["target"]
    c.portal.call(partial(_set, db, InvestigationRow, DEMO, completed_at=_ago(200), created_at=_ago(200)))
    c.portal.call(partial(_scan, db, "inv_newer_same", target, 1))  # so the demo is no longer the latest
    c.portal.call(partial(_scan, db, "inv_stale", "old.example", 300))
    c.portal.call(partial(_scan, db, "inv_old_other", "old.example", 200))
    c.portal.call(partial(_scan, db, "inv_latest_other", "old.example", 120))  # old, but the latest of its target
    c.portal.call(partial(_scan, db, "inv_running", "old.example", 400, status="running"))
    case = _case(c, "Keeps its scan")
    assert (
        c.post(f"/api/cases/{case}/items", json={"kind": "scan", "data": {"investigation_id": DEMO}}).status_code == 201
    )

    c.put("/api/retention", json={"investigations_days": 90})
    preview = c.get("/api/retention").json()
    assert preview["would_delete"]["investigations"] == 2 and preview["kept"]["investigations_in_use"] == 2
    result = c.post("/api/retention/run").json()
    assert result["investigations"] == 2
    gone = {i: c.portal.call(partial(_exists, db, InvestigationRow, i)) for i in
            ("inv_stale", "inv_old_other", "inv_latest_other", "inv_running", DEMO, "inv_newer_same")}  # fmt: skip
    assert gone == {"inv_stale": False, "inv_old_other": False, "inv_latest_other": True, "inv_running": True,
                    DEMO: True, "inv_newer_same": True}  # fmt: skip
    assert c.get("/api/retention").json()["last_result"]["investigations"] == 2


def test_closed_alerts_and_cases_go_unless_held(client):
    c, db = client, client.app.state.db

    async def alert(headline):
        return (await c.app.state.monitors.create_alert(
            monitor_id=None, investigation_id="", previous_investigation_id="", target="x", severity="low",
            headline=headline, summary={}, workspace_id="ws_default", notify=False))["id"]  # fmt: skip

    resolved, still_open = c.portal.call(alert, "old and resolved"), c.portal.call(alert, "old and open")
    assert c.patch(f"/api/alerts/{resolved}", json={"status": "resolved", "reason": "fixed"}).status_code == 200
    c.portal.call(partial(_set, db, AlertRow, resolved, resolved_at=_ago(60), created_at=_ago(60)))
    c.portal.call(partial(_set, db, AlertRow, still_open, created_at=_ago(60)))

    closed, held, open_case = (
        _case(c, "Closed long ago", "closed"),
        _case(c, "Under hold", "closed"),
        _case(c, "Still open"),
    )
    hold = c.put(f"/api/cases/{held}/legal-hold", json={"hold": True, "note": "Matter 2026-114, counsel J. Doe"}).json()
    assert hold["legal_hold"] and hold["legal_hold_note"].startswith("Matter")
    for case in (closed, held, open_case):
        c.portal.call(partial(_set, db, CaseRow, case, updated_at=_ago(400)))

    c.put("/api/retention", json={"alerts_days": 30, "cases_days": 365})
    result = c.post("/api/retention/run").json()
    assert (result["alerts"], result["cases"], result["kept"]["cases_on_legal_hold"]) == (1, 1, 1)
    assert not c.portal.call(partial(_exists, db, AlertRow, resolved)) and c.portal.call(
        partial(_exists, db, AlertRow, still_open)
    )
    assert c.get(f"/api/cases/{closed}").status_code == 404
    assert c.get(f"/api/cases/{held}").status_code == 200 and c.get(f"/api/cases/{open_case}").status_code == 200

    # A held case cannot be deleted by hand either; releasing the hold allows it.
    refused = c.delete(f"/api/cases/{held}")
    assert refused.status_code == 409 and "legal hold" in refused.json()["detail"]
    assert not c.put(f"/api/cases/{held}/legal-hold", json={"hold": False}).json()["legal_hold"]
    assert c.delete(f"/api/cases/{held}").status_code == 204

    audit = c.get("/api/audit?limit=200").json()
    purge = next(e for e in audit if e["action"] == "retention.purge")
    assert purge["details"]["alerts"] == 1 and purge["details"]["cases"] == 1
    assert {"case.legal_hold", "case.legal_hold_release", "retention.policy"} <= {e["action"] for e in audit}
    assert c.get("/api/audit/verify").json()["valid"]  # the audit chain is never purged


def test_with_two_person_approval_deleting_sooner_needs_approval(client):
    c = client
    bob = c.post("/api/keys", json={"name": "bob", "role": "admin"}).json()["key"]
    c.put("/api/approval-policy", json={"actions": ["case.delete"]})
    asked = c.put("/api/retention", json={"cases_days": 30})
    assert asked.status_code == 202
    assert c.get("/api/retention").json()["cases_days"] == 0
    assert c.put("/api/retention", json={"alerts_days": 30}).status_code == 200  # alerts are not cases

    held = _case(c, "Held")
    c.put(f"/api/cases/{held}/legal-hold", json={"hold": True})
    release = c.put(f"/api/cases/{held}/legal-hold", json={"hold": False})
    assert release.status_code == 202
    approval = release.json()["approval"]["id"]
    c.post(f"/api/approvals/{approval}/approve", json={}, headers={"Authorization": f"Bearer {bob}"})
    done = c.put(f"/api/cases/{held}/legal-hold", json={"hold": False}, headers={"X-Argus-Approval": approval})
    assert done.status_code == 200 and not done.json()["legal_hold"]
