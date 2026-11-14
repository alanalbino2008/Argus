"""Guided first scan: scope guidance, pre-flight checks and getting-started progress."""

from __future__ import annotations

import pytest

from argus.core.models import EntityType as E
from argus.demo import DEMO_TARGET
from argus.security.scope import assess


def codes(target, kind=E.DOMAIN, passive=True, active=4):
    return {w.code: w.level for w in assess(target, kind, passive_only=passive, active_checks=active)}


@pytest.mark.parametrize(
    "target, expected",
    [
        ("hmrc.gov.uk", {"public_sector": "danger"}),
        ("www.nhs.uk", {"public_sector": "danger"}),
        ("nhs.uk", {"public_sector": "danger"}),  # the zone itself, not only names inside it
        ("police.uk", {"public_sector": "danger"}),
        ("gp-surgery.nhs.uk", {"public_sector": "danger"}),
        ("defense.gov", {"public_sector": "danger"}),
        ("mail.google.com", {"third_party": "danger"}),
        ("github.com", {"third_party": "danger"}),
        ("notgithub.com", {}),  # suffix matching respects label boundaries
        ("abertay.ac.uk", {"academic": "warning"}),
        ("example.com", {"reserved": "info"}),
        ("shop.test", {"reserved": "info"}),
        ("my-portfolio.dev", {}),
    ],
)
def test_domain_scope_guidance(target, expected):
    assert codes(target) == expected


def test_people_ips_and_active_checks():
    assert codes("jane@my-portfolio.dev", E.EMAIL) == {"personal_data": "warning"}
    assert codes("jane@gmail.com", E.EMAIL) == {"third_party": "danger", "personal_data": "warning"}
    assert codes("janedoe", E.USERNAME) == {"personal_data": "warning"}
    assert codes("203.0.113.7", E.IP_ADDRESS) == {"shared_ip": "info"}
    assert codes("my-portfolio.dev", passive=False) == {"active_contact": "info"}
    assert codes("my-portfolio.dev", passive=False, active=0) == {}


@pytest.fixture
def client(make_client):
    return make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false")


def test_preflight_explains_what_would_happen_without_scanning(client):
    response = client.post("/api/scan/preflight", json={"target": "mail.google.com", "passive_only": False})
    assert response.status_code == 200
    p = response.json()
    assert p["target_type"] == "domain" and p["type_label"] == "a domain" and p["allowed"]
    assert {w["code"] for w in p["warnings"]} == {"third_party", "active_contact"}
    assert p["sources"]["passive"] and p["sources"]["active"] and p["contacts_target"]
    assert all({"name", "description", "handles_target"} <= set(m) for m in p["sources"]["passive"])
    passive = client.post("/api/scan/preflight", json={"target": "mail.google.com"}).json()
    assert passive["sources"]["active"] == [] and not passive["contacts_target"]
    assert client.get("/api/investigations").json() == []  # nothing was scanned


def test_preflight_reports_blocked_targets_and_recent_scans(client):
    blocked = client.post("/api/scan/preflight", json={"target": "169.254.169.254"}).json()
    assert not blocked["allowed"] and "private" in blocked["blocked_reason"]
    client.post("/api/demo")
    demo = client.post("/api/scan/preflight", json={"target": DEMO_TARGET}).json()
    assert demo["recent"] and demo["recent"]["status"] == "completed"


def test_preflight_needs_an_analyst(client):
    viewer = client.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    response = client.post(
        "/api/scan/preflight", json={"target": "my-portfolio.dev"}, headers={"Authorization": f"Bearer {viewer}"}
    )
    assert response.status_code == 403


def test_the_audit_log_records_what_the_person_was_warned_about(client, monkeypatch):
    from argus.api import server

    async def no_scan(app, config, **kwargs):  # don't touch the network
        class Engine:
            investigation_id = "inv_test"

        return Engine()

    monkeypatch.setattr(server, "launch_scan", no_scan)
    body = {"target": "hmrc.gov.uk", "purpose": "HMRC vulnerability disclosure programme", "authorized": True,
            "passive_only": True}  # fmt: skip
    assert client.post("/api/scan", json=body).status_code == 200
    event = next(e for e in client.get("/api/audit?limit=5").json() if e["action"] == "scan.start")
    assert event["details"]["scope_warnings"] == ["public_sector"]


def test_onboarding_progress_follows_what_was_done(client):
    def steps(headers=None):
        return {s["id"]: s for s in client.get("/api/onboarding", headers=headers or {}).json()["steps"]}

    start = steps()
    assert not any(s["done"] for s in start.values()) and all(s["available"] for s in start.values())
    client.post("/api/demo")
    after = client.get("/api/onboarding").json()
    assert {k: v["done"] for k, v in steps().items()}["demo"] is True
    assert steps()["first_scan"]["done"] is False  # the demo is not your own scan
    assert after["latest_id"] and after["first_scan_id"] is None
    client.post(f"/api/investigation/{after['latest_id']}/report")
    assert steps()["report"]["done"] is True

    viewer = client.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    as_viewer = steps({"Authorization": f"Bearer {viewer}"})
    assert not as_viewer["first_scan"]["available"] and not as_viewer["destination"]["available"]
