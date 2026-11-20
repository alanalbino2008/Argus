"""Phase 69: fingerprint watches — a fingerprint's Shodan/Censys search on a schedule, alerting on new servers."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from argus.demo import DEMO_ID
from argus.intel import fingerprint_watch, internet_search
from argus.intel.fingerprint_watch import server_key
from argus.notify.render import alert_event
from tests.test_internet_search import KEY, _entity_id

RED = {"X-Argus-Workspace": "red-team"}


def _match(ip, port=443, org="Bad Hosting"):
    return {"ip_str": ip, "port": port, "transport": "tcp", "org": org, "location": {"country_name": "Netherlands"}}


@pytest.fixture
def watch_client(make_client, monkeypatch):
    state = {"matches": [_match("198.51.100.7")], "calls": 0, "fail": None}

    async def fake_get(http, path, params):
        state["calls"] += 1
        if state["fail"]:
            raise state["fail"]
        return {"total": 40 + len(state["matches"]), "matches": state["matches"]}

    monkeypatch.setattr(internet_search, "_get", fake_get)
    client = make_client(shodan_api_key=KEY, monitors_enabled="false")
    client.post("/api/demo")
    client.app.state.fingerprint_watcher.kick = lambda: None  # the tests run ticks themselves
    return client, state


def _watch(client, prefix="favicon:", **extra):
    body = {"investigation_id": DEMO_ID, "entity_id": _entity_id(client, prefix), **extra}
    return client.post("/api/fingerprint-watches", json=body, headers=extra.pop("headers", None) or {})


def _tick(client):
    return client.portal.call(client.app.state.fingerprint_watcher.tick)


def _fp_alerts(client):
    return [a for a in client.get("/api/alerts").json() if (a.get("summary") or {}).get("fingerprint_watch")]


def test_baseline_then_alert_on_new_servers(watch_client):
    c, state = watch_client
    watch = _watch(c).json()
    assert watch["engine"] == "shodan" and watch["query"].startswith("http.favicon.hash:")
    assert (
        watch["label"].lower().startswith("favicon")
        and "favicon" not in watch["label"][8:].lower()
        and watch["interval_hours"] == 24
        and watch["last_status"] is None
    )

    (first,) = _tick(c)
    assert first["baseline"] and first["new"] == 0 and first["alert"] is None
    assert _fp_alerts(c) == []
    assert _tick(c) == []  # not due again for a day
    (listed,) = c.get("/api/fingerprint-watches").json()
    assert listed["known"] == 1 and listed["last_status"] == "ok" and listed["last_total"] == 41

    # Same servers: no alert.
    c.post(f"/api/fingerprint-watches/{watch['id']}/run")
    (same,) = _tick(c)
    assert same["new"] == 0 and _fp_alerts(c) == []

    # A new server, and a known host on a new port: both are news.
    state["matches"] = [_match("198.51.100.7"), _match("203.0.113.9", org="Other Ltd"), _match("198.51.100.7", 8443)]
    c.post(f"/api/fingerprint-watches/{watch['id']}/run")
    (news,) = _tick(c)
    assert news["new"] == 2 and news["alert"]
    (alert,) = _fp_alerts(c)
    assert alert["severity"] == "high" and alert["investigation_id"] == DEMO_ID
    assert alert["headline"].startswith("2 new servers share Favicon")
    fw = alert["summary"]["fingerprint_watch"]
    assert [s["ip"] for s in fw["new_servers"]] == ["203.0.113.9", "198.51.100.7"] and fw["total_count"] == 43
    listed = c.get("/api/fingerprint-watches").json()[0]
    assert listed["alerts_raised"] == 1 and listed["last_new"] == ["203.0.113.9:443", "198.51.100.7:8443"]

    event = alert_event(alert, {"id": "default", "name": "Default"}, None)
    assert event["alert"]["fingerprint_watch"]["new_count"] == 2 and KEY not in json.dumps(event)
    actions = {e["action"] for e in c.get("/api/audit").json()}
    assert {"fingerprint_watch.create", "fingerprint_watch.run", "fingerprint_watch.alert"} <= actions


def test_errors_are_recorded_and_retried_on_schedule(watch_client):
    c, state = watch_client
    _watch(c)
    state["fail"] = internet_search.SearchError(429, "Shodan is rate-limiting this key")
    (out,) = _tick(c)
    assert out["status"] == "error"
    (listed,) = c.get("/api/fingerprint-watches").json()
    assert listed["last_status"] == "error" and "rate-limiting" in listed["last_message"]
    assert listed["known"] == 0
    # The next successful run is still the baseline: nothing was recorded before.
    state["fail"] = None
    c.post(f"/api/fingerprint-watches/{listed['id']}/run")
    (out,) = _tick(c)
    assert out["baseline"] and _fp_alerts(c) == []


def test_refusals(watch_client, make_client):
    c, _ = watch_client
    assert _watch(c).status_code == 201
    assert _watch(c).status_code == 409  # already watched
    seed = {"investigation_id": DEMO_ID, "entity_id": _entity_id(c, "acme-corp.example")}
    assert c.post("/api/fingerprint-watches", json=seed).status_code == 422  # nothing to search for
    missing = {"investigation_id": DEMO_ID, "entity_id": "favicon_000000000000"}
    assert c.post("/api/fingerprint-watches", json=missing).status_code == 404
    assert _watch(c, "jarm:", engine="censys").status_code == 409  # no Censys token
    assert _watch(c, "jarm:", interval_hours=5).status_code == 422
    assert c.post("/api/fingerprint-watches/fpw_nope/run").status_code == 404
    assert c.delete("/api/fingerprint-watches/fpw_nope").status_code == 404


def test_roles_teams_and_delete(watch_client):
    c, _ = watch_client
    watch = _watch(c).json()
    viewer = c.post("/api/keys", json={"name": "reader", "role": "viewer"}).json()["key"]
    as_viewer = {"Authorization": f"Bearer {viewer}"}
    assert len(c.get("/api/fingerprint-watches", headers=as_viewer).json()) == 1
    assert c.post(f"/api/fingerprint-watches/{watch['id']}/run", headers=as_viewer).status_code == 403
    c.post("/api/workspaces", json={"id": "red-team", "name": "Red team"})
    assert c.get("/api/fingerprint-watches", headers=RED).json() == []
    assert c.delete(f"/api/fingerprint-watches/{watch['id']}", headers=RED).status_code == 404
    other = {"investigation_id": DEMO_ID, "entity_id": _entity_id(c, "jarm:")}
    assert c.post("/api/fingerprint-watches", json=other, headers=RED).status_code == 404  # not their scan
    assert c.delete(f"/api/fingerprint-watches/{watch['id']}").status_code == 204
    assert c.get("/api/fingerprint-watches").json() == []


def test_claim_is_exclusive(watch_client):
    c, _ = watch_client
    watch = _watch(c).json()
    repo = c.app.state.fingerprint_watches
    now = datetime.now(timezone.utc) + timedelta(seconds=1)
    assert [w["id"] for w in c.portal.call(repo.due, now)] == [watch["id"]]
    assert c.portal.call(repo.claim, watch["id"], now) is True
    assert c.portal.call(repo.claim, watch["id"], now) is False  # a second replica gets nothing
    assert c.portal.call(repo.due, now) == []


def test_known_servers_are_capped(watch_client, monkeypatch):
    c, state = watch_client
    monkeypatch.setattr("argus.storage.fingerprint_watch_repo.MAX_KNOWN", 3)
    watch = _watch(c).json()
    state["matches"] = [_match(f"198.51.100.{i}") for i in range(5)]
    _tick(c)
    assert c.portal.call(c.app.state.fingerprint_watches.known, watch["id"]) == [
        "198.51.100.2:443", "198.51.100.3:443", "198.51.100.4:443"]  # fmt: skip


def test_server_key_and_headline():
    assert server_key({"ip": "192.0.2.1", "port": 22}) == "192.0.2.1:22"
    assert server_key({"ip": "192.0.2.1", "port": None}) == "192.0.2.1"
    assert server_key({"ip": None}) is None
    watch = {"label": "JARM 2ad2ad", "engine": "censys"}
    assert fingerprint_watch.alert_headline(watch, 1) == "1 new server share JARM 2ad2ad (Censys)"
