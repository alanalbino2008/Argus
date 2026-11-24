"""Phase 83: limits on the endpoints added in phases 68-82 (credits, look-ups, renders, memory)."""

from __future__ import annotations

import base64

import pytest

from argus.api import annotation_routes, brand_watch_routes, case_report_routes, taxii_routes
from argus.core.models import EntityType, generate_entity_id
from argus.storage import annotation_repo
from tests.test_brand_watch import _cert, _tick, bw  # noqa: F401  (fixture used by name)
from tests.test_fingerprint_watches import _watch as watch_fingerprint
from tests.test_fingerprint_watches import watch_client  # noqa: F401


def _retry(r):
    assert r.status_code == 429, r.text
    assert int(r.headers["Retry-After"]) >= 1
    return r


def test_run_now_has_a_cooldown(make_client, bw, monkeypatch):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert("acmebank-login.com")]
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com"}).json()
    _tick(c)  # it has just run
    c.app.state.settings.watch_run_cooldown_seconds = 600
    r = _retry(c.post(f"/api/brand-watches/{watch['id']}/run"))
    assert "run it again in" in r.json()["detail"] and int(r.headers["Retry-After"]) > 500
    c.app.state.settings.watch_run_cooldown_seconds = 0
    assert c.post(f"/api/brand-watches/{watch['id']}/run").status_code == 202


def test_fingerprint_run_now_has_a_cooldown(watch_client):  # noqa: F811
    c, _ = watch_client
    watch = watch_fingerprint(c).json()
    c.portal.call(c.app.state.fingerprint_watcher.tick)
    c.app.state.settings.watch_run_cooldown_seconds = 600
    _retry(c.post(f"/api/fingerprint-watches/{watch['id']}/run"))
    assert c.post("/api/fingerprint-watches/fpw_nope/run").status_code == 404  # unknown: still 404, not 429


def test_takedown_lookups_and_lookalike_captures_are_limited(bw, monkeypatch):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert(f"acmebank-x{i}.com") for i in range(12)]
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com"}).json()
    _tick(c)

    async def contacts(domain, ips):
        return {"registrar": {}, "hosts": []}

    c.app.state.brand_watcher.takedown_contacts = contacts
    url = f"/api/brand-watches/{watch['id']}/takedowns"
    codes = [c.post(url, json={"domain": f"acmebank-x{i}.com"}).status_code for i in range(11)]
    assert codes[:10] == [201] * 10
    _retry(c.post(url, json={"domain": "acmebank-x11.com"}))

    monkeypatch.setattr(brand_watch_routes, "_rdap_limiter", brand_watch_routes.SlidingWindowLimiter(100, 60))
    from argus.api import case_routes

    monkeypatch.setattr(case_routes, "_capture_limiter", case_routes.SlidingWindowLimiter(0, 60))  # used up
    r = c.post(f"/api/brand-watches/{watch['id']}/lookalikes/acmebank-x0.com/case", json={"confirmed": True})
    assert r.status_code == 429 and c.get("/api/cases").json() == []  # refused before anything was created


def test_taxii_is_limited_per_key(bw, monkeypatch):  # noqa: F811
    c, _ = bw
    monkeypatch.setattr(taxii_routes, "_limiter", taxii_routes.SlidingWindowLimiter(3, 60))
    key = c.post("/api/keys", json={"name": "siem", "role": "viewer"}).json()["key"]
    auth = {"Authorization": "Basic " + base64.b64encode(f"x:{key}".encode()).decode()}
    for _ in range(3):
        assert c.get("/taxii2/ws_default/collections/", headers=auth).status_code == 200
    _retry(c.get("/taxii2/ws_default/collections/", headers=auth))
    other = c.post("/api/keys", json={"name": "siem2", "role": "viewer"}).json()["key"]
    assert c.get("/taxii2/ws_default/collections/", headers={"Authorization": f"Bearer {other}"}).status_code == 200


def test_annotations_are_capped(bw, monkeypatch):  # noqa: F811
    c, _ = bw
    monkeypatch.setattr(annotation_repo, "MAX_ANNOTATIONS", 2)

    def tag(value):
        eid = generate_entity_id(EntityType.DOMAIN, value)
        return c.put(f"/api/annotations/{eid}", json={"entity_type": "domain", "value": value, "tags": ["x"]})

    assert tag("a.example").status_code == 200 and tag("b.example").status_code == 200
    r = tag("c.example")
    assert r.status_code == 422 and "up to 2" in r.json()["detail"]
    assert tag("a.example").status_code == 200  # changing an existing one is always allowed
    assert annotation_routes.AnnotationLimit is annotation_repo.AnnotationLimit


def test_report_verification_is_bounded(bw, monkeypatch):  # noqa: F811
    c, _ = bw
    monkeypatch.setattr(case_report_routes, "MAX_VERIFY_BYTES", 100)
    assert c.post("/api/reports/verify", files={"file": ("r.html", b"x" * 101, "text/html")}).status_code == 413
    monkeypatch.setattr(case_report_routes, "_verify_limiter", case_report_routes.SlidingWindowLimiter(1, 60))
    assert c.post("/api/reports/verify", files={"file": ("r.html", b"<html></html>", "text/html")}).status_code == 200
    _retry(c.post("/api/reports/verify", files={"file": ("r.html", b"<html></html>", "text/html")}))


@pytest.mark.parametrize("path", ["/api/campaigns", "/api/brand-protection/summary"])
def test_workspace_wide_reads_are_limited(bw, monkeypatch, path):  # noqa: F811
    from argus.api import campaign_routes

    c, _ = bw
    monkeypatch.setattr(campaign_routes, "_read_limiter", campaign_routes.SlidingWindowLimiter(2, 60))
    assert c.get(path).status_code == 200 and c.get(path).status_code == 200
    _retry(c.get(path))
