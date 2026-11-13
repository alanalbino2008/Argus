"""Platform security: authentication, RBAC, audit chain, headers, rate limits, scope."""

import pytest
from sqlalchemy import update
from starlette.websockets import WebSocketDisconnect

from argus.api import server
from argus.storage.db import AuditEventRow
from tests.conftest import ADMIN_KEY

SCAN = {"target": "example.com", "purpose": "Authorised test engagement", "authorized": True}


def make_key(client, role, name=None):
    r = client.post("/api/keys", json={"name": name or f"{role}-user", "role": role})
    assert r.status_code == 201
    return r.json()


def as_key(client, key):
    """Same app, different credentials."""
    client.headers["Authorization"] = f"Bearer {key}"
    return client


# ------------------------------------------------------------------ authentication
@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer argus_wrong"}, {"X-API-Key": "nope"}])
def test_requests_without_valid_key_are_rejected(client, headers):
    client.headers.pop("Authorization")
    r = client.get("/api/investigations", headers=headers)
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"


def test_health_and_ui_stay_public(client):
    client.headers.pop("Authorization")
    assert client.get("/api/health").status_code == 200
    assert client.get("/").status_code == 200


def test_x_api_key_header_also_works(client):
    client.headers.pop("Authorization")
    assert client.get("/api/me", headers={"X-API-Key": ADMIN_KEY}).json()["role"] == "admin"


def test_plaintext_keys_are_never_stored_or_listed(client):
    created = make_key(client, "viewer")
    assert created["key"].startswith("argus_")
    listed = client.get("/api/keys").json()
    assert all("key" not in k and "hash" not in k for k in listed)
    assert created["key"] not in str(listed)


def test_revoked_key_stops_working(client):
    created = make_key(client, "analyst")
    assert client.delete(f"/api/keys/{created['id']}").status_code == 204
    as_key(client, created["key"])
    assert client.get("/api/me").status_code == 401


def test_cannot_revoke_last_admin(client):
    admin_id = client.get("/api/me").json()["key_id"]
    assert client.delete(f"/api/keys/{admin_id}").status_code == 409


# --------------------------------------------------------------------------- RBAC
@pytest.mark.parametrize("role,method,path,body,allowed", [
    ("viewer", "get", "/api/investigations", None, True),
    ("viewer", "post", "/api/scan", SCAN, False),
    ("viewer", "get", "/api/keys", None, False),
    ("analyst", "get", "/api/audit", None, False),
    ("analyst", "delete", "/api/investigation/inv_x", None, False),
    ("analyst", "post", "/api/keys", {"name": "escalate", "role": "admin"}, False),
])
def test_role_permissions(client, role, method, path, body, allowed):
    key = make_key(client, role)["key"]
    as_key(client, key)
    r = getattr(client, method)(path, **({"json": body} if body else {}))
    assert (r.status_code != 403) is allowed


def test_forbidden_attempts_are_audited(client):
    viewer = make_key(client, "viewer", name="nosy")
    as_key(client, viewer["key"]).get("/api/keys")
    as_key(client, ADMIN_KEY)
    events = client.get("/api/audit", params={"action": "auth.forbidden"}).json()
    assert events and events[0]["actor_name"] == "nosy" and events[0]["outcome"] == "denied"


# ------------------------------------------------------------------- audit chain
def test_audit_chain_detects_tampering(client):
    make_key(client, "viewer", name="alice")
    make_key(client, "viewer", name="bob")
    assert client.get("/api/audit/verify").json()["valid"] is True

    # An insider edits history directly in the database...
    async def tamper():
        async with client.app.state.db.session() as s, s.begin():
            await s.execute(update(AuditEventRow).where(AuditEventRow.id == 2).values(actor_name="mallory"))
    client.portal.call(tamper)

    result = client.get("/api/audit/verify").json()
    assert result == {"valid": False, "checked": 1, "first_invalid_id": 2}


def test_bootstrap_is_audited(client):
    events = client.get("/api/audit", params={"action": "key.bootstrap"}).json()
    assert len(events) == 1 and events[0]["actor_id"] == "system"


# ------------------------------------------------------------- scope & abuse limits
@pytest.mark.parametrize("target,ttype", [
    ("127.0.0.1", None), ("169.254.169.254", None), ("10.0.0.8", None),
    ("localhost", "domain"), ("intranet.corp", None),
])
def test_internal_targets_rejected_and_audited(client, target, ttype):
    r = client.post("/api/scan", json={**SCAN, "target": target, **({"target_type": ttype} if ttype else {})})
    assert r.status_code == 422
    denied = client.get("/api/audit", params={"action": "scan.start"}).json()
    assert denied[0]["outcome"] == "denied" and denied[0]["resource"] == target


def test_scan_rate_limit_per_key(make_client, monkeypatch):
    client = make_client(scans_per_minute=2, max_concurrent_scans=50)
    launched = []
    monkeypatch.setattr(server, "_run_scan", _noop_scan(launched))
    codes = [client.post("/api/scan", json=SCAN).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_concurrent_scan_cap(make_client, monkeypatch):
    client = make_client(max_concurrent_scans=1)
    monkeypatch.setattr(server, "_run_scan", _noop_scan([]))
    assert client.post("/api/scan", json=SCAN).status_code == 200
    assert client.post("/api/scan", json=SCAN).status_code == 429


def test_scan_records_purpose_and_operator(client, monkeypatch):
    monkeypatch.setattr(server, "_run_scan", _noop_scan([]))
    inv_id = client.post("/api/scan", json=SCAN).json()["investigation_id"]
    detail = client.get(f"/api/investigation/{inv_id}").json()
    assert detail["purpose"] == SCAN["purpose"] and detail["created_by"] == "bootstrap-admin"
    event = client.get("/api/audit", params={"action": "scan.start"}).json()[0]
    assert event["details"]["authorized_confirmed"] is True


def _noop_scan(record):
    """Replace the real scan runner: keep the engine registered as 'running' without network I/O."""
    async def runner(engine, recorder):
        record.append(engine.investigation_id)
    return runner


# ------------------------------------------------------------------ websockets
def test_websocket_requires_single_use_ticket(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/stream/inv_x") as ws:
            ws.receive_json()
    assert exc.value.code == 4401

    ticket = client.post("/api/ws-ticket").json()["ticket"]
    assert client.app.state.ws_tickets.redeem(ticket) is not None
    assert client.app.state.ws_tickets.redeem(ticket) is None  # replay fails


# ---------------------------------------------------------------- headers & CORS
def test_security_headers(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-eval" not in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/api/me").headers["cache-control"] == "no-store"


def test_cors_not_open_to_arbitrary_origins(client):
    r = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_auth_can_be_disabled_for_local_dev(make_client):
    client = make_client(auth_enabled="false")
    client.headers.pop("Authorization")
    assert client.get("/api/me").json()["role"] == "admin"


def test_only_invalid_keys_are_audited_not_anonymous_visits(client):
    client.headers.pop("Authorization")
    client.get("/api/me")                                              # not signed in yet
    client.get("/api/me", headers={"Authorization": "Bearer argus_guess"})  # wrong key
    client.headers["Authorization"] = f"Bearer {ADMIN_KEY}"
    events = client.get("/api/audit", params={"action": "auth.failed"}).json()
    assert len(events) == 1 and events[0]["details"]["key_prefix"] == "argus_gues"


def test_weak_bootstrap_key_refused(make_client):
    with pytest.raises(RuntimeError, match="at least 32"):
        make_client(bootstrap_admin_key="admin123")


def test_empty_bootstrap_key_generates_one(make_client, caplog):
    client = make_client(bootstrap_admin_key="")
    keys = client.app.state.keys
    assert client.portal.call(keys.count_active) == 1
    assert "will NOT be shown again" in caplog.text
