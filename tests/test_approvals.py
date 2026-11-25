"""Phase 90: sensitive actions need a second administrator's approval when the workspace asks for it."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import partial

import pytest
from sqlalchemy import update

from argus.storage.db import ApprovalRow

PROTECT = ["case.delete", "case.export", "exposure.reveal", "key.create_admin"]


@pytest.fixture
def team(client):
    def key(name, role):
        r = client.post("/api/keys", json={"name": name, "role": role})
        assert r.status_code == 201, r.text
        return {"Authorization": f"Bearer {r.json()['key']}"}

    people = {"alice": key("alice", "admin"), "bob": key("bob", "admin"), "carol": key("carol", "analyst")}
    assert client.put("/api/approval-policy", json={"actions": PROTECT}, headers=people["alice"]).json()[
        "actions"
    ] == sorted(PROTECT)
    return client, people


def _case(c, who):
    r = c.post("/api/cases", json={"title": "Fraud ring", "purpose": "Internal fraud investigation, ticket SEC-9", "confirmed": True},
               headers=who)  # fmt: skip
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_without_a_policy_nothing_changes(client):
    assert client.get("/api/approval-policy").json()["actions"] == []
    case = _case(client, {})
    assert client.delete(f"/api/cases/{case}").status_code == 204


def test_delete_needs_someone_elses_approval(team):
    c, p = team
    case = _case(c, p["carol"])
    asked = c.delete(f"/api/cases/{case}", headers={**p["carol"], "X-Argus-Reason": "Duplicate of case 12"})
    assert asked.status_code == 202 and asked.json()["approval_required"]
    approval = asked.json()["approval"]
    assert (
        approval["status"] == "pending"
        and approval["action"] == "case.delete"
        and approval["reason"] == "Duplicate of case 12"
    )
    assert asked.headers["X-Argus-Approval-Request"] == approval["id"]
    again = c.delete(f"/api/cases/{case}", headers=p["carol"])
    assert again.json()["approval"]["id"] == approval["id"]  # the open request is reused, not duplicated
    assert c.get(f"/api/cases/{case}").status_code == 200  # nothing happened yet

    url = f"/api/approvals/{approval['id']}"
    assert c.post(f"{url}/approve", json={}, headers=p["carol"]).status_code == 403  # analysts cannot approve
    assert [a["id"] for a in c.get("/api/approvals", headers=p["bob"]).json()] == [approval["id"]]
    decided = c.post(f"{url}/approve", json={"note": "Checked with legal"}, headers=p["alice"]).json()
    assert decided["status"] == "approved" and decided["decided_by"] == "alice"
    assert c.post(f"{url}/approve", json={}, headers=p["bob"]).status_code == 409  # already decided

    wrong = c.delete(f"/api/cases/{case}", headers={**p["bob"], "X-Argus-Approval": approval["id"]})
    assert wrong.status_code == 403 and "Only the person who asked" in wrong.json()["detail"]
    done = c.delete(f"/api/cases/{case}", headers={**p["carol"], "X-Argus-Approval": approval["id"]})
    assert done.status_code == 204 and c.get(f"/api/cases/{case}").status_code == 404
    assert c.get(url).json()["status"] == "used"
    actions = [e["action"] for e in c.get("/api/audit?limit=200").json()]
    assert {"approval.request", "approval.approve", "approval.used", "approval.refused", "case.delete"} <= set(actions)
    (alert,) = [a for a in c.get("/api/alerts").json() if (a.get("summary") or {}).get("approval_request")]
    assert alert["headline"] == "Approval needed: carol asks to delete a case"


def test_no_self_approval_single_use_and_bound_to_the_action(team):
    c, p = team
    case = _case(c, p["alice"])
    export = c.get(f"/api/cases/{case}/export", headers=p["alice"]).json()["approval"]
    refused = c.post(f"/api/approvals/{export['id']}/approve", json={}, headers=p["alice"])
    assert refused.status_code == 403 and "someone else" in refused.json()["detail"]
    c.post(f"/api/approvals/{export['id']}/approve", json={}, headers=p["bob"])
    # An approval to export does not allow deleting.
    other = c.delete(f"/api/cases/{case}", headers={**p["alice"], "X-Argus-Approval": export["id"]})
    assert other.status_code == 403 and "another action" in other.json()["detail"]
    bundle = c.get(f"/api/cases/{case}/export", headers={**p["alice"], "X-Argus-Approval": export["id"]})
    assert bundle.status_code == 200 and bundle.headers["content-type"] == "application/zip"
    spent = c.get(f"/api/cases/{case}/export", headers={**p["alice"], "X-Argus-Approval": export["id"]})
    assert spent.status_code == 403 and "used" in spent.json()["detail"]


async def _expire(db, approval_id):
    async with db.session() as s, s.begin():
        await s.execute(update(ApprovalRow).where(ApprovalRow.id == approval_id)
                        .values(expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)))  # fmt: skip


def test_approvals_expire_and_can_be_rejected(team):
    c, p = team
    reveal = c.get("/api/exposure?reveal=true", headers=p["carol"]).json()["approval"]
    c.post(f"/api/approvals/{reveal['id']}/approve", json={}, headers=p["alice"])
    c.portal.call(partial(_expire, c.app.state.db, reveal["id"]))
    late = c.get("/api/exposure?reveal=true", headers={**p["carol"], "X-Argus-Approval": reveal["id"]})
    assert late.status_code == 403 and "expired" in late.json()["detail"]
    assert c.get("/api/exposure", headers=p["carol"]).status_code == 200  # masked view needs no approval

    fresh = c.get("/api/exposure?reveal=true", headers=p["carol"]).json()["approval"]
    assert fresh["id"] != reveal["id"]  # the expired one is not reused
    rejected = c.post(f"/api/approvals/{fresh['id']}/reject", json={"note": "Not needed"}, headers=p["bob"]).json()
    assert rejected["status"] == "rejected"
    no = c.get("/api/exposure?reveal=true", headers={**p["carol"], "X-Argus-Approval": fresh["id"]})
    assert no.status_code == 403


def test_admin_keys_and_loosening_the_policy_need_approval(team):
    c, p = team
    assert c.post("/api/keys", json={"name": "ci", "role": "analyst"}, headers=p["alice"]).status_code == 201
    asked = c.post("/api/keys", json={"name": "root2", "role": "admin"}, headers=p["alice"])
    assert asked.status_code == 202
    approval = asked.json()["approval"]
    c.post(f"/api/approvals/{approval['id']}/approve", json={}, headers=p["bob"])
    made = c.post("/api/keys", json={"name": "root2", "role": "admin"},
                  headers={**p["alice"], "X-Argus-Approval": approval["id"]})  # fmt: skip
    assert made.status_code == 201 and made.json()["role"] == "admin"

    # Adding protection is immediate; removing it needs an approval.
    loosen = c.put("/api/approval-policy", json={"actions": ["case.delete"]}, headers=p["alice"])
    assert loosen.status_code == 202 and loosen.json()["approval"]["action"] == "approval.policy"
    assert len(c.get("/api/approval-policy").json()["actions"]) == 4
    c.post(f"/api/approvals/{loosen.json()['approval']['id']}/approve", json={}, headers=p["bob"])
    done = c.put("/api/approval-policy", json={"actions": ["case.delete"]},
                 headers={**p["alice"], "X-Argus-Approval": loosen.json()["approval"]["id"]})  # fmt: skip
    assert done.status_code == 200 and done.json()["actions"] == ["case.delete"]
    assert c.put("/api/approval-policy", json={"actions": ["nope"]}, headers=p["alice"]).status_code == 422
