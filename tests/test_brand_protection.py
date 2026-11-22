"""Phase 79: brand-protection metrics, the PDF report, and scheduling it."""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

from pypdf import PdfReader

from argus.intel.brand_metrics import summarise
from argus.notify import render
from argus.storage.notification_repo import _summary
from tests.test_brand_watch import _cert, _tick, bw  # noqa: F401  (fixture used by name)
from tests.test_lookalike_triage import WebProfile

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def test_the_numbers():
    watch = {
        "domain": "acmebank.com", "last_run_at": _iso(0.1), "last_status": "ok",
        "triage": {"phish.example": {"verdict": "phishing", "severity": "critical", "label": "Active phishing page"},
                   "clone.example": {"verdict": "clone", "severity": "high", "label": "Copies your site"},
                   "gone.example": {"verdict": "dormant", "severity": "medium"},
                   "mine.example": {"verdict": "yours", "severity": "low"},
                   "parked.example": {"verdict": "parked", "severity": "low"}},
        "takedowns": {
            "gone.example": {"status": "down", "reported_at": _iso(10), "down_at": _iso(6)},
            "old.example": {"status": "down", "reported_at": _iso(200), "down_at": _iso(190)},
            "clone.example": {"status": "reported", "reported_at": _iso(3), "draft": {"to": ["a@x", "b@y"]}},
        },
    }  # fmt: skip
    first_seen = {"phish.example": _iso(2), "clone.example": _iso(20), "gone.example": _iso(15), "mine.example": _iso(1),
                  "parked.example": _iso(120)}  # fmt: skip
    details = {"phish.example": {"technique": "combosquat"}, "clone.example": {"technique": "homoglyph"}}
    campaigns = [{"name": "IP address: 45.77.10.5", "size": 3, "severity": "critical"}]
    summary = summarise([(watch, first_seen, details)], campaigns, days=30, now=NOW)
    assert summary["found"] == {"known": 4, "new": 3}  # "yours" is not counted; parked is older than the period
    assert summary["open_threats"]["count"] == 2
    assert [t["domain"] for t in summary["open_threats"]["top"]] == ["phish.example", "clone.example"]
    take = summary["takedowns"]
    assert take["by_status"] == {"down": 2, "reported": 1}
    assert take["down_in_period"] == 1 and take["reported_in_period"] == 2
    assert take["median_days_to_down"] == 7.0  # (4 + 10) / 2
    assert take["open"] == [{"domain": "clone.example", "brand": "acmebank.com", "status": "reported",
                             "waiting_days": 3.0, "recipients": 2}]  # fmt: skip
    assert summary["campaigns"]["count"] == 1 and summary["brands"][0]["threats"] == 2
    assert len(summary["trend"]["week_starts"]) == 5 and sum(summary["trend"]["new_lookalikes"]) == 3
    assert sum(summary["trend"]["taken_down"]) == 1


def test_summary_pdf_and_schedule(bw):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert("acmebank-login.com", days_ago=1)]
    state["web"]["acmebank-login.com"] = WebProfile(True, 200, "acmebank-login.com", "Sign in", True, "f" * 64)
    c.post("/api/brand-watches", json={"domain": "acmebank.com", "web_check": "direct"})
    _tick(c)
    summary = c.get("/api/brand-protection/summary?days=30").json()
    assert summary["open_threats"]["count"] == 1 and summary["found"]["new"] == 1 and summary["period_days"] == 30

    r = c.post("/api/brand-protection/report", json={"days": 30, "prepared_for": "Board <b>"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    text = "".join(page.extract_text() for page in PdfReader(io.BytesIO(r.content)).pages)
    assert "acmebank-login.com" in text and "Active phishing page" in text and "Board <b>" in text
    verified = c.get(f"/api/reports/verify/{r.headers['X-Report-SHA256']}").json()
    assert verified["genuine"] and verified["target"] == "Brand protection"
    viewer = c.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    assert (
        c.post("/api/brand-protection/report", json={}, headers={"Authorization": f"Bearer {viewer}"}).status_code
        == 403
    )

    channel = c.post("/api/notifications/channels", json={
        "name": "Brand hook", "type": "webhook", "destination": {"url": "https://hooks.example.com/brand"}}).json()  # fmt: skip
    created = c.post("/api/reports/schedules", json={"name": "Monthly brand", "frequency": "monthly", "day_of_month": 1,
                                                     "hour": 7, "channel_ids": [channel["id"]],
                                                     "options": {"kind": "brand", "period_days": 30}})  # fmt: skip
    assert created.status_code == 201, created.text
    schedule = created.json()
    assert schedule["target"] == "Brand protection"
    assert c.portal.call(c.app.state.report_scheduler.run, schedule) == "sent"
    (delivery,) = c.get("/api/notifications/deliveries").json()
    assert delivery["summary"].startswith("Brand-protection report ARG-") and "(1 open threats)" in delivery["summary"]


def test_brand_notifications_read_well():
    record = {"id": "ARG-9", "target": "Brand protection", "tlp": "AMBER", "sha256": "cd" * 32, "prepared_for": None}
    summary = {"period_days": 30, "open_threats": {"count": 2}, "found": {"new": 5}, "campaigns": {"count": 1},
               "takedowns": {"down_in_period": 3, "median_days_to_down": 4.5}}  # fmt: skip
    event = render.brand_event(record, summary, {"id": "s", "name": "Monthly"}, {"id": "ws_default", "name": "D"},
                               "https://argus.example")  # fmt: skip
    assert render._title(event) == "Monthly: brand protection (2 open threats)"
    text = render.slack(event)["blocks"][0]["text"]["text"]
    assert "5 new lookalike domain(s) in 30 days" in text and "median 4.5 days" in text
    assert _summary(event) == "Brand-protection report ARG-9 (2 open threats)"
    assert "The PDF is attached." in render.email(event, "a@x.example", ["b@x.example"], attachment=("b.pdf", b"%PDF")
                                                  ).get_body(("plain",)).get_content()  # fmt: skip
