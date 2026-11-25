"""Phase 87: a watch that keeps failing alerts its workspace, pauses after a week, and Run now resumes it."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from argus.intel import internet_search, watch_health
from argus.storage.db import FingerprintWatchRow
from tests.test_brand_watch import _due, bw  # noqa: F401  (fixture used by name)
from tests.test_brand_watch import _tick as _brand_tick
from tests.test_fingerprint_watches import _tick, _watch, watch_client  # noqa: F401

NOW = datetime(2026, 11, 25, 12, tzinfo=timezone.utc)


def test_the_health_state_machine():
    data, events = {"label": "x"}, []
    for i in range(4):
        data, event = watch_health.after_run(data, "error", NOW + timedelta(hours=i))
        events.append(event)
    assert events == [None, None, "failing", None] and data["failures"] == 4 and data["label"] == "x"
    data, event = watch_health.after_run(data, "partial", NOW)  # one source failed, the other worked: a success
    assert event == "recovered" and "failures" not in data and data["label"] == "x"
    assert watch_health.after_run(data, "ok", NOW) == (data, None)  # no second "working again"

    week_ago = {
        "failures": 9,
        "failing_since": (NOW - timedelta(days=7, minutes=1)).isoformat(),
        "health_alerted": True,
    }
    data, event = watch_health.after_run(week_ago, "error", NOW)
    assert event == "paused" and data["paused_reason"].startswith("Paused by Argus after 10 failed runs")
    data = watch_health.resumed(data)
    assert data["failures"] == 0 and "failing_since" not in data and "paused_reason" not in data


def test_advice():
    assert "Integrations" in watch_health.advice("No Shodan key is configured")
    assert "revoked" in watch_health.advice("Shodan answered 401: Invalid API key")
    assert "quota" in watch_health.advice("Shodan is rate-limiting this key (429)")
    assert "route" in watch_health.advice("The route 'tor' is not configured any more")
    assert "outbound network" in watch_health.advice("crt.sh could not be reached (ClientConnectorError)")
    assert "Run now" in watch_health.advice("something unusual")


def _health_alerts(c):
    return [a for a in c.get("/api/alerts").json() if (a.get("summary") or {}).get("watch_health")]


async def _age(db, watch_id):
    async with db.session() as s, s.begin():
        row = await s.get(FingerprintWatchRow, watch_id)
        row.data = {**row.data, "failing_since": (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()}


def test_fail_alert_pause_resume_recover(watch_client):  # noqa: F811
    c, state = watch_client
    watch = _watch(c).json()
    run = lambda: (c.post(f"/api/fingerprint-watches/{watch['id']}/run"), _tick(c))  # noqa: E731
    state["fail"] = internet_search.SearchError(429, "Shodan is rate-limiting this key")
    _tick(c)
    run()
    assert _health_alerts(c) == []  # two failures: not yet
    run()
    (alert,) = _health_alerts(c)
    health = alert["summary"]["watch_health"]
    assert alert["severity"] == "medium" and "has failed 3 runs in a row" in alert["headline"]
    assert health["event"] == "failing" and "quota" in health["advice"] and "rate-limiting" in health["error"]
    (listed,) = c.get("/api/fingerprint-watches").json()
    assert listed["failures"] == 3 and listed["enabled"] and listed["failing_since"]

    c.portal.call(_age, c.app.state.db, watch["id"])  # a week of failures later
    run()
    (listed,) = c.get("/api/fingerprint-watches").json()
    assert not listed["enabled"] and listed["paused_reason"].startswith("Paused by Argus")
    paused = _health_alerts(c)[0]
    assert paused["severity"] == "high" and paused["headline"].endswith("paused after failing for a week")
    assert c.portal.call(c.app.state.fingerprint_watches.due) == []  # it no longer runs, or spends credits

    state["fail"] = None
    run()  # Run now resumes it, and this time it works
    (listed,) = c.get("/api/fingerprint-watches").json()
    assert listed["enabled"] and listed["failures"] == 0 and listed["paused_reason"] is None
    recovered = _health_alerts(c)[0]
    assert recovered["severity"] == "low" and recovered["headline"].endswith("is working again")
    assert len(_health_alerts(c)) == 3
    actions = [e["action"] for e in c.get("/api/audit?limit=200").json()]
    assert actions.count("fingerprint_watch.health") == 3


def test_brand_watch_failures_alert_but_partial_runs_do_not(bw):  # noqa: F811
    c, state = bw
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com"}).json()
    state["keyword_fail"] = "crt.sh answered 502"
    for _ in range(3):  # Cert Spotter still works: partial, never "failing"
        _due(c, watch["id"])
        _brand_tick(c)
    assert _health_alerts(c) == []
    state["exact_fail"] = "Cert Spotter could not be reached (ClientConnectorError)"
    for _ in range(3):
        _due(c, watch["id"])
        _brand_tick(c)
    (alert,) = _health_alerts(c)
    assert alert["summary"]["watch_health"]["kind"] == "brand" and alert["target"] == "acmebank.com"
    assert "outbound network" in alert["summary"]["watch_health"]["advice"]
    assert c.get("/api/brand-watches").json()[0]["failures"] == 3
