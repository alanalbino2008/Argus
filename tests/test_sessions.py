"""Phase 93: idle sessions end, people manage their sessions, workspaces can be limited to networks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import partial

from sqlalchemy import update

from argus.api import deps
from argus.storage.db import SessionRow
from tests.test_workspaces import _user, as_user

WS = "ws_default"


def _second_session(c, user):
    async def make():
        return await c.app.state.users.create_session(
            user["id"], timedelta(hours=1), "198.51.100.4", "Firefox on Linux"
        )

    return {**user, "token": c.portal.call(make)}


async def _idle(db, user_id, minutes):
    async with db.session() as s, s.begin():
        await s.execute(update(SessionRow).where(SessionRow.user_id == user_id)
                        .values(last_seen_at=datetime.now(timezone.utc) - timedelta(minutes=minutes)))  # fmt: skip


def test_an_idle_session_ends(make_client):
    c = make_client(session_idle_minutes=30)
    alice = _user(c, "alice@example.com", WS)
    assert c.get("/api/me", headers=as_user(alice)).status_code == 200
    c.portal.call(partial(_idle, c.app.state.db, alice["id"], 20))
    assert c.get("/api/me", headers=as_user(alice)).status_code == 200  # 20 minutes: still fine (and refreshed)
    c.portal.call(partial(_idle, c.app.state.db, alice["id"], 31))
    ended = c.get("/api/me", headers=as_user(alice))
    assert ended.status_code == 401 and "session has ended" in ended.json()["detail"]
    assert c.get("/api/me", headers=as_user(alice)).status_code == 401  # and it is gone, not just refused once


def test_people_see_and_end_their_sessions(client):
    alice = _user(client, "alice@example.com", WS)
    laptop = _second_session(client, alice)
    listed = client.get("/api/auth/sessions", headers=as_user(alice)).json()
    assert len(listed) == 2 and sum(s["current"] for s in listed) == 1
    other = next(s for s in listed if not s["current"])
    assert other["user_agent"] == "Firefox on Linux" and other["ip"] == "198.51.100.4" and len(other["id"]) == 16
    assert laptop["token"] not in str(listed)  # ids are hash prefixes, never the cookie

    assert client.delete(f"/api/auth/sessions/{other['id']}", headers=as_user(alice)).status_code == 204
    assert client.get("/api/me", headers=as_user(laptop)).status_code == 401
    assert client.get("/api/me", headers=as_user(alice)).status_code == 200
    assert client.delete("/api/auth/sessions/0000000000000000", headers=as_user(alice)).status_code == 404

    phone, tablet = _second_session(client, alice), _second_session(client, alice)
    assert client.post("/api/auth/sessions/end-others", headers=as_user(alice)).json() == {"ended": 2}
    assert client.get("/api/me", headers=as_user(phone)).status_code == 401
    assert client.get("/api/me", headers=as_user(tablet)).status_code == 401
    assert client.get("/api/me", headers=as_user(alice)).status_code == 200
    assert client.get("/api/auth/sessions").status_code == 400  # an API key has no sessions

    # A platform administrator signs a person out everywhere.
    assert client.post(f"/api/users/{alice['id']}/sign-out").json() == {"ended": 1}
    assert client.get("/api/me", headers=as_user(alice)).status_code == 401
    actions = {e["action"] for e in client.get("/api/audit?limit=200").json()}
    assert {"session.end", "session.end_others", "session.sign_out_user"} <= actions


def test_a_workspace_limited_to_its_networks(client, monkeypatch):
    analyst = client.post("/api/keys", json={"name": "soc", "role": "admin"}).json()["key"]
    as_soc = {"Authorization": f"Bearer {analyst}"}
    alice = _user(client, "alice@example.com", WS)
    where = {"ip": "10.20.30.40"}
    monkeypatch.setattr(deps, "client_ip", lambda request: where["ip"])
    import argus.api.session_routes as routes

    monkeypatch.setattr(routes, "client_ip", lambda request: where["ip"])

    locked_out = client.put("/api/access-policy", json={"allowed_networks": ["192.0.2.0/24"]}, headers=as_soc)
    assert locked_out.status_code == 422 and "lock you out" in locked_out.json()["detail"]
    assert client.put("/api/access-policy", json={"allowed_networks": ["nope"]}, headers=as_soc).status_code == 422
    policy = client.put("/api/access-policy", json={"allowed_networks": ["10.0.0.0/8"]}, headers=as_soc).json()
    assert policy["allowed_networks"] == ["10.0.0.0/8"]

    assert client.get("/api/cases", headers=as_soc).status_code == 200
    assert client.get("/api/cases", headers=as_user(alice)).status_code == 200
    where["ip"] = "203.0.113.50"  # the same people from a café
    assert client.get("/api/cases", headers=as_soc).status_code == 404  # looks like there is no workspace
    assert client.get("/api/cases", headers=as_user(alice)).status_code == 404
    assert client.get("/api/cases").status_code == 200  # platform administrators can always fix the policy
    refused = [e for e in client.get("/api/audit?limit=200").json() if e["action"] == "auth.forbidden"]
    assert any("outside its networks (203.0.113.50)" in (e["details"] or {}).get("reason", "") for e in refused)
    assert client.put("/api/access-policy", json={"allowed_networks": []}).json()["allowed_networks"] == []
    assert client.get("/api/cases", headers=as_soc).status_code == 200
