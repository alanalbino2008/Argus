"""Phase 84: watcher observability — runs, source failures, lookalikes, takedowns and refusals are counted."""

from __future__ import annotations

import pytest

from argus.intel import internet_search
from argus.intel.lookalike_triage import WebProfile
from argus.observability import metrics
from argus.security.ratelimit import SlidingWindowLimiter
from tests.test_brand_watch import _cert, _due, _tick, bw  # noqa: F401  (fixture used by name)
from tests.test_fingerprint_watches import _tick as _fp_tick
from tests.test_fingerprint_watches import _watch, watch_client  # noqa: F401


def _value(name: str, **labels: str) -> float:
    return metrics.REGISTRY.get_sample_value(name, labels) or 0.0


def test_brand_watch_runs_sources_and_lookalikes_are_counted(bw):  # noqa: F811
    c, state = bw
    before = {
        "ok": _value("argus_watch_runs_total", kind="brand", status="ok"),
        "partial": _value("argus_watch_runs_total", kind="brand", status="partial"),
        "error": _value("argus_watch_runs_total", kind="brand", status="error"),
        "crt": _value("argus_watch_source_errors_total", source="crt.sh"),
        "spotter": _value("argus_watch_source_errors_total", source="Cert Spotter"),
        "high": _value("argus_lookalikes_found_total", severity="high"),
        "runs": _value("argus_watch_run_duration_seconds_count", kind="brand"),
    }
    state["keyword"] = [_cert("acmebank-secure.net", days_ago=3)]
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com"}).json()
    (out,) = _tick(c)
    assert out["status"] == "ok"
    assert _value("argus_watch_runs_total", kind="brand", status="ok") == before["ok"] + 1
    assert _value("argus_lookalikes_found_total", severity="high") == before["high"] + 1
    assert _value("argus_watch_last_success_timestamp_seconds", kind="brand") > 0

    state["keyword_fail"] = "crt.sh answered 502"
    _due(c, watch["id"])
    assert _tick(c)[0]["status"] == "partial"
    state["exact_fail"] = "Cert Spotter answered 503"
    _due(c, watch["id"])
    assert _tick(c)[0]["status"] == "error"
    assert _value("argus_watch_runs_total", kind="brand", status="partial") == before["partial"] + 1
    assert _value("argus_watch_runs_total", kind="brand", status="error") == before["error"] + 1
    assert _value("argus_watch_source_errors_total", source="crt.sh") == before["crt"] + 2
    assert _value("argus_watch_source_errors_total", source="Cert Spotter") == before["spotter"] + 1
    assert _value("argus_watch_run_duration_seconds_count", kind="brand") == before["runs"] + 3


def test_fingerprint_watch_runs_and_failures_are_counted(watch_client):  # noqa: F811
    c, state = watch_client
    ok = _value("argus_watch_runs_total", kind="fingerprint", status="ok")
    error = _value("argus_watch_runs_total", kind="fingerprint", status="error")
    shodan = _value("argus_watch_source_errors_total", source="Shodan")
    watch = _watch(c).json()
    _fp_tick(c)
    assert _value("argus_watch_runs_total", kind="fingerprint", status="ok") == ok + 1
    state["fail"] = internet_search.SearchError(429, "Shodan is rate-limiting this key")
    c.post(f"/api/fingerprint-watches/{watch['id']}/run")
    assert _fp_tick(c)[0]["status"] == "error"
    assert _value("argus_watch_runs_total", kind="fingerprint", status="error") == error + 1
    assert _value("argus_watch_source_errors_total", source="Shodan") == shodan + 1


def test_takedown_steps_are_counted(bw):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert("acmebank-login.com", days_ago=1)]
    state["web"]["acmebank-login.com"] = WebProfile(True, 200, "acmebank-login.com", "Sign in", True, "f" * 64)

    async def fake_contacts(domain, ips):
        return {"registrar": {"registrar": "Registrar Inc", "abuse_email": "abuse@registrar.example"}, "hosts": []}

    c.app.state.brand_watcher.takedown_contacts = fake_contacts
    counts = {e: _value("argus_takedown_events_total", event=e) for e in metrics.TAKEDOWN_STEPS}
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com", "web_check": "direct"}).json()
    _tick(c)
    url = f"/api/brand-watches/{watch['id']}/takedowns"
    assert c.post(url, json={"domain": "acmebank-login.com"}).status_code in (200, 201)
    assert c.post(f"{url}/acmebank-login.com/reported").status_code == 200
    state["web"]["acmebank-login.com"] = WebProfile(False, error="ClientConnectorError")
    for _ in range(2):
        _due(c, watch["id"])
        _tick(c)
    assert {e: _value("argus_takedown_events_total", event=e) - counts[e] for e in metrics.TAKEDOWN_STEPS} == {
        "drafted": 1,
        "reported": 1,
        "down": 1,
        "closed": 0,
    }


def test_refusals_are_counted_by_limit():
    from fastapi import HTTPException

    from argus.api.deps import cooldown, throttle

    limiter = SlidingWindowLimiter(limit=1, window=60, name="test_limit")
    before = _value("argus_rate_limited_total", limit="test_limit")
    throttle(limiter, "k", "slow down")
    with pytest.raises(HTTPException) as refused:
        throttle(limiter, "k", "slow down")
    assert refused.value.status_code == 429
    assert _value("argus_rate_limited_total", limit="test_limit") == before + 1

    from datetime import datetime, timezone

    cooled = _value("argus_rate_limited_total", limit="brand_watch_cooldown")
    with pytest.raises(HTTPException):
        cooldown(datetime.now(timezone.utc).isoformat(), 600, "brand watch")
    assert _value("argus_rate_limited_total", limit="brand_watch_cooldown") == cooled + 1
