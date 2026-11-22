"""Phase 71: brand watch — lookalike domains in Certificate Transparency."""

from __future__ import annotations

import contextlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from argus.intel import brand_watch
from argus.intel.brand_watch import Certificate, SourceFailed, candidate_map, classify, findings_from, own_domains
from argus.notify.render import alert_event

RED = {"X-Argus-Workspace": "red-team"}
NOW = datetime.now(timezone.utc)


def _cert(*names, days_ago=1, source="crt.sh"):
    issued = (NOW - timedelta(days=days_ago)).isoformat()
    return Certificate(tuple(names), "Let's Encrypt", issued, "https://crt.sh/?id=1", source)


@pytest.fixture
def bw(make_client, monkeypatch):
    state = {"keyword": [], "exact": {}, "keyword_fail": None, "exact_fail": None, "looked": []}

    async def fake_crtsh(http, brand):
        if state["keyword_fail"]:
            raise SourceFailed(state["keyword_fail"])
        return list(state["keyword"])

    async def fake_certspotter(http, name, key):
        if state["exact_fail"]:
            raise SourceFailed(state["exact_fail"])
        state["looked"].append(name)
        return list(state["exact"].get(name, []))

    monkeypatch.setattr(brand_watch, "crtsh", fake_crtsh)
    monkeypatch.setattr(brand_watch, "certspotter", fake_certspotter)
    client = make_client(monitors_enabled="false")
    watcher = client.app.state.brand_watcher
    watcher.kick = lambda: None
    watcher.http_factory = contextlib.nullcontext
    return client, state


def _tick(client):
    return client.portal.call(client.app.state.brand_watcher.tick)


def _alerts(client):
    return [a for a in client.get("/api/alerts").json() if (a.get("summary") or {}).get("brand_watch")]


def _due(client, watch_id):
    assert client.post(f"/api/brand-watches/{watch_id}/run").status_code == 202


def test_classification():
    candidates = candidate_map("acmebank.com")
    own = own_domains("acmebank.com", ["acmebank.de"])

    def c(name):
        hit = classify(name, "acmebank", own, candidates)
        return hit and (hit[1], hit[3])

    assert c("www.acmebank.com") is None and c("acmebank.de") is None and c("unrelated.example") is None
    assert c("acrnebank.com") == ("homoglyph", "high")
    assert c("acmebank-login.com") == ("combosquat", "high")
    assert c("acmebank-careers.com") == ("combosquat", "medium")
    assert c("acmebank.co") == ("tld", "medium")
    assert c("secure.acmebank.com.evil.example") == ("subdomain", "high")
    assert c("not a host") is None and c("*.acmebank-secure.com") == ("combosquat", "high")
    idn = next(n for n in candidates if n.startswith("xn--"))
    (found,) = findings_from([_cert(idn)], "acmebank.com", [], candidates)
    assert found.technique == "homoglyph" and found.display != found.name  # shown as it looks, in Unicode


def test_baseline_then_new_lookalikes_alert(bw):
    c, state = bw
    state["keyword"] = [_cert("acmebank-login.com", days_ago=200), _cert("acmebank-secure.net", days_ago=3),
                        _cert("www.acmebank.com", "acmebank.de")]  # fmt: skip
    watch = c.post("/api/brand-watches", json={"domain": "https://www.AcmeBank.com/", "allow": ["acmebank.de"]}).json()
    assert watch["domain"] == "acmebank.com" and watch["allow"] == ["acmebank.de"]

    (first,) = _tick(c)
    assert first["baseline"] and first["recorded"] == 2 and first["new"] == 1  # only the recent one is news
    (alert,) = _alerts(c)
    assert alert["severity"] == "high" and "acmebank-secure.net" in alert["headline"]
    assert alert["summary"]["brand_watch"]["baseline"] is True
    assert len(state["looked"]) == brand_watch.EXACT_PER_RUN and not any("acmebank" in n for n in state["looked"])

    # Nothing new: no alert. A new homoglyph found by name: alert.
    _due(c, watch["id"])
    assert _tick(c)[0]["new"] == 0 and len(_alerts(c)) == 1
    target = "acrnebank.com"
    state["exact"][target] = [_cert(target, source="Cert Spotter")]
    state["looked"].clear()
    listed = c.get("/api/brand-watches").json()[0]
    names = brand_watch.exact_candidates("acmebank.com", candidate_map("acmebank.com"), True)
    assert target in names
    for _ in range(len(names) // brand_watch.EXACT_PER_RUN + 1):  # the cursor reaches it within a cycle
        _due(c, watch["id"])
        _tick(c)
        if len(_alerts(c)) == 2:
            break
    latest = _alerts(c)[0]
    assert latest["summary"]["brand_watch"]["findings"][0]["technique"] == "homoglyph"
    listed = c.get("/api/brand-watches").json()[0]
    assert listed["known"] == 3 and listed["alerts_raised"] == 2 and listed["recent"][0]["name"] == target
    event = alert_event(latest, {"id": "default", "name": "Default"}, "https://argus.example")
    assert event["alert"]["brand_watch"]["lookalikes"][0]["name"] == target
    assert event["alert"]["url"].endswith("#/monitoring")
    actions = {e["action"] for e in c.get("/api/audit").json()}
    assert {"brand_watch.create", "brand_watch.run", "brand_watch.alert"} <= actions


def test_outages_are_partial_or_retried(bw):
    c, state = bw
    state["keyword_fail"] = "crt.sh answered 502"
    state["exact_fail"] = "Cert Spotter answered 503"
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com"}).json()
    (out,) = _tick(c)
    assert out["status"] == "error"
    listed = c.get("/api/brand-watches").json()[0]
    assert listed["last_status"] == "error" and "502" in listed["last_message"] and not listed["baselined"]
    next_run = datetime.fromisoformat(listed["next_run_at"])
    assert next_run - datetime.now(timezone.utc) <= timedelta(hours=1, minutes=1)  # retried soon, not tomorrow
    # Only crt.sh down: partial, Cert Spotter still checked, it becomes the baseline.
    state["exact_fail"] = None
    _due(c, watch["id"])
    (out,) = _tick(c)
    listed = c.get("/api/brand-watches").json()[0]
    assert out["status"] == "partial" and listed["baselined"] and listed["sources"]["crt.sh"]["status"] == "error"
    # Without the keyword search, names containing the brand are looked up by name instead.
    assert any("acmebank" in n for n in state["looked"])


def test_short_brands_skip_the_keyword_search(bw):
    c, _ = bw
    c.post("/api/brand-watches", json={"domain": "hp.com"})
    (out,) = _tick(c)
    listed = c.get("/api/brand-watches").json()[0]
    assert out["status"] == "ok" and listed["sources"]["crt.sh"]["status"] == "skipped"


def test_validation_roles_and_teams(bw):
    c, _ = bw
    assert c.post("/api/brand-watches", json={"domain": "not a domain"}).status_code == 422
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com"}).json()
    assert c.post("/api/brand-watches", json={"domain": "www.acmebank.com"}).status_code == 409
    updated = c.patch(f"/api/brand-watches/{watch['id']}", json={"allow": ["acmebank.de", "acmebank.com", " "]}).json()
    assert updated["allow"] == ["acmebank.de"]
    viewer = c.post("/api/keys", json={"name": "reader", "role": "viewer"}).json()["key"]
    as_viewer = {"Authorization": f"Bearer {viewer}"}
    assert len(c.get("/api/brand-watches", headers=as_viewer).json()) == 1
    assert c.post("/api/brand-watches", json={"domain": "x-corp.com"}, headers=as_viewer).status_code == 403
    c.post("/api/workspaces", json={"id": "red-team", "name": "Red team"})
    assert c.get("/api/brand-watches", headers=RED).json() == []
    assert c.delete(f"/api/brand-watches/{watch['id']}", headers=RED).status_code == 404
    assert c.post(f"/api/brand-watches/{watch['id']}/run", headers=RED).status_code == 404
    assert c.delete(f"/api/brand-watches/{watch['id']}").status_code == 204
    assert json.dumps(c.get("/api/brand-watches").json()) == "[]"


def test_claim_is_exclusive(bw):
    c, _ = bw
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com"}).json()
    repo = c.app.state.brand_watches
    moment = datetime.now(timezone.utc) + timedelta(seconds=1)
    assert c.portal.call(repo.claim, watch["id"], moment) is True
    assert c.portal.call(repo.claim, watch["id"], moment) is False


class _Resp:
    def __init__(self, status, body):
        self.status, self.body = status, body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def json(self, content_type=None):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


class _Http:
    def __init__(self, status, body):
        self.status, self.body, self.calls = status, body, []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Resp(self.status, self.body)


async def test_the_sources_are_read():
    rows = [{"id": 42, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "acmebank-login.com",
             "name_value": "acmebank-login.com\nwww.acmebank-login.com", "not_before": "2026-11-20T10:00:00"}, "junk"]  # fmt: skip
    http = _Http(200, rows)
    (cert,) = await brand_watch.crtsh(http, "acmebank")
    assert set(cert.names) == {"acmebank-login.com", "www.acmebank-login.com"} and cert.link.endswith("id=42")
    assert http.calls[0][1]["params"]["q"] == "%acmebank%" and http.calls[0][1]["params"]["exclude"] == "expired"
    for status, body, message in (
        (502, None, "502"),
        (200, {"x": 1}, "unexpected"),
        (200, ValueError("bad"), "reached"),
    ):
        with pytest.raises(SourceFailed, match=message):
            await brand_watch.crtsh(_Http(status, body), "acmebank")

    spotted = [{"dns_names": ["acrnebank.com"], "issuer": {"friendly_name": "Sectigo"}, "not_before": "2026-11-19T00:00:00Z",
                "cert_sha256": "ab" * 32}]  # fmt: skip
    http = _Http(200, spotted)
    (cert,) = await brand_watch.certspotter(http, "acrnebank.com", "key-123")
    assert cert.names == ("acrnebank.com",) and cert.issuer == "Sectigo" and cert.source == "Cert Spotter"
    assert ("domain", "acrnebank.com") in http.calls[0][1]["params"]
    assert http.calls[0][1]["headers"] == {"Authorization": "Bearer key-123"}
    with pytest.raises(SourceFailed, match="free limit"):
        await brand_watch.certspotter(_Http(429, None), "acrnebank.com", "")


def test_one_finding_per_registered_lookalike():
    candidates = candidate_map("acmebank.com")
    certs = [_cert("api.secure-acmebank.com", "www.secure-acmebank.com", days_ago=30),
             _cert("login.secure-acmebank.com", days_ago=2), _cert("acmebank-careers.com")]  # fmt: skip
    found = findings_from(certs, "acmebank.com", [], candidates)
    assert [f.name for f in found] == ["secure-acmebank.com", "acmebank-careers.com"]
    first = found[0]
    assert first.severity == "high" and first.host_count == 3 and "login.secure-acmebank.com" in first.hosts
    assert first.not_before == certs[0].not_before  # its first certificate: when it went live
