"""The one-box ``/api/investigate``: type a single identifier, and Argus opens a case, adds the person
with that detail, and starts a full search — the fast path to parity with one-box OSINT tools, without
losing the case, the legal purpose or the audit trail."""

from __future__ import annotations

from argus.api.subject_routes import _known_field
from tests.test_subjects import Scans, wait


def test_known_field_detects_what_was_typed():
    assert _known_field("jane@example.org") == ("emails", "jane@example.org")
    assert _known_field("+44 7700 900123")[0] == "phones"
    assert _known_field("https://github.com/jdoe")[0] == "profiles"
    assert _known_field("github.com/jdoe")[0] == "profiles"  # a bare profile link
    assert _known_field("Jane Doe") == ("names", "Jane Doe")  # a space → a name
    assert _known_field("jdoe") == ("usernames", "jdoe")  # one token → a username
    assert _known_field("example.com")[0] == "websites"


def test_investigate_opens_a_case_and_searches_from_one_identifier(make_client):
    c = make_client(monitors_enabled="false")
    scans = Scans()
    c.app.state.playbook_scan = scans
    r = c.post("/api/investigate", json={"identifier": "jdoe", "purpose": "Fraud report R-99", "confirmed": True})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["field"] == "usernames" and body["name"] == "jdoe"
    case = c.get(f"/api/cases/{body['case_id']}").json()
    assert case["title"] == "Investigation: jdoe" and case["purpose"] == "Fraud report R-99"
    subject = wait(c, body["case_id"], body["subject_id"])
    assert subject["status"] != "running" and scans.targets  # a search was started
    # the typed identifier is the person's known detail
    assert subject["known"]["usernames"] == ["jdoe"]
    # audited as reached through the one box
    assert any(e["action"] == "case.create" and e["details"].get("via") == "investigate"
               for e in c.get("/api/audit?limit=50").json())  # fmt: skip


def test_investigate_names_the_person_from_a_typed_name(make_client):
    c = make_client(monitors_enabled="false")
    c.app.state.playbook_scan = Scans()
    r = c.post("/api/investigate", json={"identifier": "Jane Doe", "name": "The seller",
                                         "purpose": "Marketplace fraud R-100", "confirmed": True})  # fmt: skip
    assert r.status_code == 201
    assert r.json()["field"] == "names" and r.json()["name"] == "The seller"


def test_investigate_needs_the_confirmation(make_client):
    c = make_client(monitors_enabled="false")
    c.app.state.playbook_scan = Scans()
    r = c.post("/api/investigate", json={"identifier": "jdoe", "purpose": "A legitimate purpose", "confirmed": False})
    assert r.status_code == 422


def test_investigate_requires_authorization_when_the_instance_demands_it(make_client):
    c = make_client(monitors_enabled="false", require_case_authorization="true")
    c.app.state.playbook_scan = Scans()
    body = {"identifier": "jdoe", "purpose": "A legitimate purpose", "confirmed": True}
    assert c.post("/api/investigate", json=body).status_code == 422
    ok = c.post("/api/investigate", json={**body, "authorization": "Warrant 2024/55"})
    assert ok.status_code == 201
    case = c.get(f"/api/cases/{ok.json()['case_id']}").json()
    assert case["authorization"] == "Warrant 2024/55"


def test_investigate_is_rate_limited(make_client):
    c = make_client(monitors_enabled="false")
    c.app.state.playbook_scan = Scans()
    body = {"identifier": "jdoe", "purpose": "Fraud report R-101", "confirmed": True}
    codes = [c.post("/api/investigate", json=body).status_code for _ in range(12)]
    assert codes.count(201) == 10 and codes[-1] == 429


def test_a_search_that_cannot_start_still_returns_the_case_without_duplicates(make_client, monkeypatch):
    from fastapi import HTTPException

    from argus.api import subject_routes

    c = make_client(monitors_enabled="false")
    c.app.state.playbook_scan = Scans()

    async def refuse(*_a, **_k):
        raise HTTPException(status_code=429, detail="Scan rate limit exceeded")

    monkeypatch.setattr(subject_routes, "start", refuse)
    r = c.post("/api/investigate", json={"identifier": "jdoe", "purpose": "Fraud report R-102", "confirmed": True})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["started"] is False and body["problem"] == "Scan rate limit exceeded"
    assert c.get(f"/api/cases/{body['case_id']}").status_code == 200  # the case is usable, not orphaned
    assert [x["title"] for x in c.get("/api/cases").json()].count("Investigation: jdoe") == 1
