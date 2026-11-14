"""Team workspaces: hard isolation between tenants, proven route by route."""

from __future__ import annotations

from datetime import timedelta

import pytest
from starlette.routing import Route
from starlette.websockets import WebSocketDisconnect

from argus.demo import DEMO_ID

RED = {"X-Argus-Workspace": "red-team"}


@pytest.fixture
def tenants(make_client):
    """Default workspace holds the demo; 'Red Team' is a second tenant with its own admin key."""
    client = make_client(monitors_enabled="false")
    assert client.post("/api/workspaces", json={"name": "Red Team"}).json()["slug"] == "red-team"
    client.post("/api/demo")  # into Default (no header)
    red_key = client.post("/api/keys", json={"name": "red-admin", "role": "admin"}, headers=RED).json()["key"]
    return client, {"Authorization": f"Bearer {red_key}"}


def _investigation_routes(app):
    for route in app.routes:
        if isinstance(route, Route) and "{inv_id}" in route.path:
            for method in route.methods - {"HEAD"}:
                yield method, route.path.replace("{inv_id}", DEMO_ID)


def test_every_investigation_route_is_invisible_from_another_workspace(tenants):
    client, red = tenants
    routes = list(_investigation_routes(client.app))
    assert len(routes) >= 12  # the sweep really covers the API surface (the WebSocket is tested separately)
    for method, path in routes:
        if method == "GET":  # control: it really exists, at home
            assert client.request(method, path).status_code == 200, (method, path)
        for headers in (red, RED):  # a Red Team key, and a platform admin who switched to Red Team
            response = client.request(method, path, headers=headers)
            assert response.status_code == 404, (method, path, headers, response.status_code)
    assert client.get(f"/api/investigation/{DEMO_ID}").status_code == 200  # still fine at home


def test_lists_and_pivot_search_only_show_your_workspace(tenants):
    client, red = tenants
    assert {r["id"] for r in client.get("/api/investigations").json()} >= {DEMO_ID}
    assert client.get("/api/investigations", headers=red).json() == []
    assert client.get("/api/entities/search", params={"q": "acme-corp"}).json()
    assert client.get("/api/entities/search", params={"q": "acme-corp"}, headers=red).json() == []


def test_a_bound_key_cannot_switch_workspace(tenants):
    client, red = tenants
    assert client.get("/api/investigations", headers={**red, "X-Argus-Workspace": "default"}).status_code == 404
    assert client.get("/api/investigations", headers={"X-Argus-Workspace": "nope"}).status_code == 404


def test_monitors_and_alerts_are_scoped(tenants):
    client, red = tenants
    body = {"target": "example.com", "purpose": "tenant isolation test", "authorized": True}
    mon = client.post("/api/monitors", json=body).json()
    assert client.get("/api/monitors", headers=red).json() == []
    assert client.patch(f"/api/monitors/{mon['id']}", json={"enabled": False}, headers=red).status_code == 404
    assert client.delete(f"/api/monitors/{mon['id']}", headers=red).status_code == 404
    assert client.get("/api/monitors").json()[0]["enabled"] is True  # untouched
    alert = client.portal.call(
        lambda: client.app.state.monitors.create_alert(
            monitor_id=mon["id"], investigation_id=DEMO_ID, previous_investigation_id="x", target="example.com",
            severity="high", headline="drift", summary={}, workspace_id="ws_default",
        )
    )  # fmt: skip
    assert client.get("/api/alerts", headers=red).json() == []
    assert client.post(f"/api/alerts/{alert['id']}/acknowledge", headers=red).status_code == 404
    assert client.post(f"/api/alerts/{alert['id']}/acknowledge").status_code == 200


def test_keys_and_audit_are_scoped(tenants):
    client, red = tenants
    red_keys = client.get("/api/keys", headers=red).json()
    assert [k["name"] for k in red_keys] == ["red-admin"]
    default_key = next(k for k in client.get("/api/keys", params={"scope": "all"}).json() if k["workspace_id"] is None)
    assert client.delete(f"/api/keys/{default_key['id']}", headers=red).status_code == 404
    platform = {"name": "x", "role": "admin", "platform": True}
    assert client.post("/api/keys", json=platform, headers=red).status_code == 403  # no escalation
    red_audit = client.get("/api/audit", headers=red).json()
    assert {e["action"] for e in red_audit} == {"workspace.create", "key.create"}  # its own events only
    assert {e["workspace_id"] for e in red_audit} == {red_audit[0]["workspace_id"]}
    assert "demo.load" in {e["action"] for e in client.get("/api/audit").json()}  # platform view: everything
    assert client.get("/api/audit/verify", headers=red).status_code == 403  # chain is platform-wide
    assert client.get("/api/audit/verify").json()["valid"] is True


def test_live_stream_tickets_are_bound_to_their_workspace(tenants):
    client, red = tenants
    ticket = client.post("/api/ws-ticket", headers=red).json()["ticket"]
    with (
        pytest.raises(WebSocketDisconnect) as exc,
        client.websocket_connect(f"/ws/stream/{DEMO_ID}?ticket={ticket}") as ws,
    ):
        ws.receive_json()
    assert exc.value.code == 4404
    home = client.post("/api/ws-ticket").json()["ticket"]
    with client.websocket_connect(f"/ws/stream/{DEMO_ID}?ticket={home}") as ws:
        assert ws.receive_json()["type"] == "snapshot"


def test_each_workspace_gets_its_own_demo(tenants):
    client, red = tenants
    red_demo = client.post("/api/demo", headers=red).json()["investigation_id"]
    assert red_demo != DEMO_ID and red_demo.startswith(DEMO_ID)
    assert {r["id"] for r in client.get("/api/investigations", headers=red).json()} == {red_demo, f"{red_demo}_prev"}
    assert client.get(f"/api/investigation/{red_demo}").status_code == 404  # Default can't see it either
    assert (
        client.get(f"/api/investigation/{red_demo}/diff", headers=red).json()["previous_investigation_id"]
        == f"{red_demo}_prev"
    )


def test_scans_land_in_the_callers_workspace(tenants, monkeypatch):
    from argus.core import engine as engine_module
    from tests.test_engine import FanOutModule

    monkeypatch.setattr(engine_module, "get_default_modules", lambda: {"fan_out": FanOutModule(fan=1)})
    client, red = tenants
    body = {"target": "example.com", "max_depth": 1, "purpose": "tenant isolation test", "authorized": True}
    inv_id = client.post("/api/scan", json=body, headers=red).json()["investigation_id"]
    assert client.get(f"/api/investigation/{inv_id}", headers=red).status_code == 200
    assert client.get(f"/api/investigation/{inv_id}").status_code == 404


# ---------------------------------------------------------------------------- people & roles
def _user(client, email: str, workspace: str | None, role: str = "analyst") -> dict:
    """A signed-in SSO user (created directly) with a session cookie value."""
    users, workspaces = client.app.state.users, client.app.state.workspaces

    async def make():
        user = await users.upsert_from_login(issuer="https://idp.example", subject=email, email=email, name=email,
                                             role="viewer", role_from_idp=False)  # fmt: skip
        if workspace:
            ws = await workspaces.get(workspace)
            await workspaces.set_member(ws["id"], user["id"], role, "test")
        token = await users.create_session(user["id"], timedelta(hours=1), None, None)
        return {**user, "token": token}

    return client.portal.call(make)


def as_user(user: dict, **headers: str) -> dict:
    return {"Authorization": "", "Cookie": f"argus_session={user['token']}", "Origin": "http://testserver", **headers}


def test_members_see_only_their_workspaces_with_their_role(tenants):
    client, _ = tenants
    alice = _user(client, "alice@acme.example", "red-team", "viewer")
    me = client.get("/api/me", headers=as_user(alice)).json()
    assert me["platform_admin"] is False and [(w["slug"], w["role"]) for w in me["workspaces"]] == [
        ("red-team", "viewer")
    ]
    assert client.get("/api/investigations", headers=as_user(alice)).json() == []  # lands in Red Team
    assert (
        client.get("/api/investigations", headers=as_user(alice, **{"X-Argus-Workspace": "default"})).status_code == 404
    )
    scan = {"target": "example.com", "purpose": "tenant isolation test", "authorized": True}
    assert client.post("/api/scan", json=scan, headers=as_user(alice)).status_code == 403  # viewer
    loner = _user(client, "loner@acme.example", None)
    assert client.get("/api/investigations", headers=as_user(loner)).status_code == 403


def test_workspace_admins_manage_members_but_not_the_platform(tenants):
    client, _ = tenants
    lead = _user(client, "lead@acme.example", "red-team", "admin")
    bob = _user(client, "bob@acme.example", None)
    h = as_user(lead)
    assert (
        client.post(
            "/api/workspaces/red-team/members", json={"email": "bob@acme.example", "role": "analyst"}, headers=h
        ).status_code
        == 201
    )
    roles = {m["email"]: m["role"] for m in client.get("/api/workspaces/red-team/members", headers=h).json()}
    assert roles == {"lead@acme.example": "admin", "bob@acme.example": "analyst"}
    assert (
        client.put(f"/api/workspaces/red-team/members/{lead['id']}", json={"role": "viewer"}, headers=h).status_code
        == 409
    )
    assert client.delete(f"/api/workspaces/red-team/members/{lead['id']}", headers=h).status_code == 409
    assert client.get("/api/workspaces/default/members", headers=h).status_code == 404  # not their workspace
    assert client.post("/api/workspaces", json={"name": "Shadow IT"}, headers=h).status_code == 403
    assert client.get("/api/users", headers=h).status_code == 403
    assert client.delete(f"/api/workspaces/red-team/members/{bob['id']}", headers=h).status_code == 204


def test_workspace_lifecycle_protects_data(tenants):
    client, red = tenants
    assert client.delete("/api/workspaces/default").status_code == 409
    client.post("/api/demo", headers=red)
    assert client.delete("/api/workspaces/red-team").status_code == 409  # not empty
    empty = client.post("/api/workspaces", json={"name": "Temp"}).json()
    assert client.patch(f"/api/workspaces/{empty['id']}", json={"name": "Temporary"}).json()["name"] == "Temporary"
    assert client.delete(f"/api/workspaces/{empty['id']}").status_code == 204
    assert client.get(f"/api/workspaces/{empty['id']}/members").status_code == 404
