"""Phase 89: API keys with an expiry, allowed networks and rotation without downtime."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import partial

import pytest
from sqlalchemy import update

from argus.api import deps
from argus.security import key_expiry
from argus.storage.db import ApiKeyRow
from argus.storage.security_repo import allowed_from, clean_networks


def _key(c, **body):
    r = c.post("/api/keys", json={"name": "siem", "role": "viewer", **body})
    assert r.status_code == 201, r.text
    return r.json()


def _as(c, key):
    return {"Authorization": f"Bearer {key}"}


async def _set(db, key_id, **values):
    async with db.session() as s, s.begin():
        await s.execute(update(ApiKeyRow).where(ApiKeyRow.id == key_id).values(**values))


def _failures(c):
    return [e for e in c.get("/api/audit?limit=200").json() if e["action"] == "auth.failed"]


def test_networks_are_validated_and_matched():
    assert clean_networks(["203.0.113.7", " 10.0.0.0/8 ", "10.0.0.0/8", "2001:db8::/32", ""]) == [
        "203.0.113.7/32", "10.0.0.0/8", "2001:db8::/32"]  # fmt: skip
    with pytest.raises(ValueError, match="does not appear"):
        clean_networks(["not-a-network"])
    assert allowed_from(None, "198.51.100.1") and allowed_from([], None)
    assert allowed_from(["10.0.0.0/8"], "10.20.30.40") and not allowed_from(["10.0.0.0/8"], "11.0.0.1")
    assert allowed_from(["10.0.0.0/8"], "::ffff:10.1.1.1")  # an IPv4 client seen through a dual-stack socket
    assert not allowed_from(["10.0.0.0/8"], None) and not allowed_from(["10.0.0.0/8"], "testclient")


def test_an_expired_key_is_refused_like_a_wrong_one(client):
    key = _key(client, expires_in_days=30)
    assert 29.9 < key["expires_in_days"] <= 30 and not key["expired"]
    assert client.get("/api/me", headers=_as(client, key["key"])).status_code == 200
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    client.portal.call(partial(_set, client.app.state.db, key["id"], expires_at=past))
    refused = client.get("/api/me", headers=_as(client, key["key"]))
    assert refused.status_code == 401 and "expired" not in refused.text.lower()  # the caller learns nothing
    assert _failures(client)[0]["details"]["reason"] == "expired key"
    listed = next(k for k in client.get("/api/keys").json() if k["id"] == key["id"])
    assert listed["expired"] and listed["expires_in_days"] is None


def test_a_key_works_only_from_its_networks(client, monkeypatch):
    assert client.post("/api/keys", json={"name": "x", "allowed_networks": ["nope"]}).status_code == 422
    key = _key(client, allowed_networks=["10.0.0.0/8", "203.0.113.9"])
    assert key["allowed_networks"] == ["10.0.0.0/8", "203.0.113.9/32"]
    monkeypatch.setattr(deps, "client_ip", lambda request: "198.51.100.1")
    assert client.get("/api/me", headers=_as(client, key["key"])).status_code == 401
    assert "outside its networks (198.51.100.1)" in _failures(client)[0]["details"]["reason"]
    monkeypatch.setattr(deps, "client_ip", lambda request: "10.9.8.7")
    assert client.get("/api/me", headers=_as(client, key["key"])).status_code == 200
    # Widen it to anywhere: takes effect on the next request.
    changed = client.patch(f"/api/keys/{key['id']}", json={"allowed_networks": []}).json()
    assert changed["allowed_networks"] == []
    monkeypatch.setattr(deps, "client_ip", lambda request: "198.51.100.1")
    assert client.get("/api/me", headers=_as(client, key["key"])).status_code == 200
    actions = {e["action"] for e in client.get("/api/audit?limit=200").json()}
    assert "key.networks" in actions


def test_rotation_overlaps_then_the_old_key_stops(client, monkeypatch):
    monkeypatch.setattr(deps, "client_ip", lambda request: "10.1.1.1")
    old = _key(client, expires_in_days=90, allowed_networks=["10.0.0.0/8"])
    rotated = client.post(f"/api/keys/{old['id']}/rotate", json={"overlap_hours": 24})
    assert rotated.status_code == 201, rotated.text
    new = rotated.json()
    assert new["key"] != old["key"] and new["name"] == "siem" and new["role"] == "viewer"
    assert new["allowed_networks"] == ["10.0.0.0/8"] and 89.9 < new["expires_in_days"] <= 90  # same lifetime
    for key in (old["key"], new["key"]):  # both work during the overlap
        assert client.get("/api/me", headers=_as(client, key)).status_code == 200
    listed = {k["id"]: k for k in client.get("/api/keys").json()}
    assert listed[old["id"]]["replaced_by"] == new["id"] and listed[old["id"]]["expires_in_days"] <= 1.0
    assert client.post(f"/api/keys/{old['id']}/rotate", json={}).status_code == 409  # already rotated
    once_more = client.post(f"/api/keys/{new['id']}/rotate", json={"overlap_hours": 0}).json()
    assert client.get("/api/me", headers=_as(client, new["key"])).status_code == 401  # no overlap: gone at once
    assert client.get("/api/me", headers=_as(client, once_more["key"])).status_code == 200
    assert client.post("/api/keys/key_nope/rotate", json={}).status_code == 404
    rotations = [e for e in client.get("/api/audit?limit=200").json() if e["action"] == "key.rotate"]
    assert len(rotations) == 2 and rotations[-1]["details"]["new_key"] == new["id"]


def test_a_maximum_lifetime_policy(make_client):
    c = make_client(api_key_max_lifetime_days=30)
    assert 29.9 < _key(c)["expires_in_days"] <= 30  # no expiry asked for: the maximum
    refused = c.post("/api/keys", json={"name": "x", "expires_in_days": 365})
    assert refused.status_code == 422 and "30 days" in refused.json()["detail"]


def test_the_report_and_the_expiry_warning(client):
    soon = _key(client, expires_in_days=3)
    forever = _key(client)
    long_ago = datetime.now(timezone.utc) - timedelta(days=120)
    client.portal.call(partial(_set, client.app.state.db, forever["id"], last_used_at=long_ago))
    report = client.get("/api/keys/report").json()
    assert [k["id"] for k in report["expiring"]] == [soon["id"]]
    assert forever["id"] in [k["id"] for k in report["stale"]]
    assert forever["id"] in [k["id"] for k in report["never_expire"]]
    assert {soon["id"], forever["id"]} <= {k["id"] for k in report["unrestricted"]}

    assert client.portal.call(key_expiry.warn_expiring, client.app) == [soon["id"]]
    assert client.portal.call(key_expiry.warn_expiring, client.app) == []  # warned once
    (alert,) = [a for a in client.get("/api/alerts").json() if (a.get("summary") or {}).get("api_key_expiry")]
    assert (
        alert["headline"].startswith("API key siem expires in")
        and "rotate" in alert["summary"]["api_key_expiry"]["advice"]
    )
    assert "key.expiry_warning" in {e["action"] for e in client.get("/api/audit?limit=200").json()}
