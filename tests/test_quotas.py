"""Phase 100: per-workspace quotas on scans, evidence, watches and API keys."""

from __future__ import annotations

from argus.observability import metrics


def _refusals(resource):
    return metrics.REGISTRY.get_sample_value("argus_quota_refusals_total", {"resource": resource}) or 0


def test_no_limits_by_default(client):
    usage = client.get("/api/quota").json()["resources"]
    assert all(r["limit"] is None and r["share"] is None and not r["warning"] for r in usage.values())
    assert client.post("/api/keys", json={"name": "a", "role": "viewer"}).status_code == 201


def test_api_keys_are_held_to_the_limit(make_client):
    c = make_client(quota_api_keys=2)
    assert c.post("/api/keys", json={"name": "a", "role": "viewer"}).status_code == 201
    second = c.post("/api/keys", json={"name": "b", "role": "viewer"}).json()
    usage = c.get("/api/quota").json()["resources"]["api_keys"]
    assert usage == {"label": "active API keys", "used": 2.0, "limit": 2, "share": 1.0, "warning": True}
    before = _refusals("api_keys")
    refused = c.post("/api/keys", json={"name": "c", "role": "viewer"})
    assert (
        refused.status_code == 403
        and refused.json()["quota"] == "api_keys"
        and "limit of 2" in refused.json()["detail"]
    )
    assert _refusals("api_keys") == before + 1
    c.delete(f"/api/keys/{second['id']}")  # revoking frees the place
    assert c.post("/api/keys", json={"name": "c", "role": "viewer"}).status_code == 201


def test_scans_per_day_answer_429_with_retry_after(make_client):
    c = make_client(quota_scans_per_day=1, monitors_enabled="false")
    c.post("/api/demo")  # the demo investigation counts as today's scan
    refused = c.post(
        "/api/scan", json={"target": "example.com", "purpose": "Quota test, ticket Q-1", "authorized": True}
    )
    assert refused.status_code == 429 and refused.json()["quota"] == "scans_per_day"
    assert 60 <= int(refused.headers["retry-after"]) <= 86_401


def test_evidence_storage_is_held_to_the_limit(make_client):
    c = make_client(quota_evidence_mb=1)
    case = c.post("/api/cases", json={"title": "Q", "purpose": "Quota evidence test", "confirmed": True}).json()["id"]
    small = c.post(f"/api/cases/{case}/uploads", files={"file": ("a.txt", b"x" * 400_000, "text/plain")})
    assert small.status_code == 201
    big = c.post(f"/api/cases/{case}/uploads", files={"file": ("b.txt", b"y" * 700_000, "text/plain")})
    assert big.status_code == 403 and big.json()["quota"] == "evidence_mb"
    assert c.get("/api/quota").json()["resources"]["evidence_mb"]["used"] < 1


def test_a_platform_administrator_sets_a_workspaces_own_limits(client):
    usage = client.put("/api/quota", json={"watches": 1, "api_keys": 0}).json()["resources"]
    assert usage["watches"]["limit"] == 1 and usage["api_keys"]["limit"] is None  # 0: no limit
    assert client.post("/api/brand-watches", json={"domain": "acmebank.com"}).status_code == 201
    refused = client.post("/api/brand-watches", json={"domain": "acme-pay.com"})
    assert refused.status_code == 403 and refused.json()["quota"] == "watches"
    admin = client.post("/api/keys", json={"name": "ws-admin", "role": "admin"}).json()["key"]
    as_ws_admin = {"Authorization": f"Bearer {admin}"}
    assert client.put("/api/quota", json={"watches": 50}, headers=as_ws_admin).status_code == 403
    assert client.get("/api/quota", headers=as_ws_admin).json()["resources"]["watches"]["limit"] == 1
    assert client.put("/api/quota", json={"watches": None}).json()["resources"]["watches"]["limit"] is None  # default
    assert "quota.set" in {e["action"] for e in client.get("/api/audit?limit=50").json()}
