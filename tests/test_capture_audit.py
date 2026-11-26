"""Capture and audit: confirmed accounts preserved at once, a legal authorisation on every case, views audited."""

from __future__ import annotations

import time

from argus.api import subject_routes
from argus.evidence.capture import Capture
from tests.test_learning import INSTA, LearningScans
from tests.test_subjects import run, wait


def _case(c, **extra):
    return c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-40", "confirmed": True, **extra})


def test_a_case_records_its_legal_authorisation(make_client):
    c = make_client()
    case = _case(c, authorization="Production order 2026/0412").json()
    assert case["authorization"] == "Production order 2026/0412"
    assert (
        c.patch(f"/api/cases/{case['id']}", json={"authorization": "Warrant W-77"}).json()["authorization"]
        == "Warrant W-77"
    )
    entry = next(e for e in c.get("/api/audit?limit=50").json() if e["action"] == "case.create")
    assert entry["details"]["authorization"] == "Production order 2026/0412"
    report = c.get(f"/api/cases/{case['id']}/report.html").text
    assert "Authorisation" in report and "Warrant W-77" in report
    strict = make_client(require_case_authorization="true")
    refused = _case(strict)
    assert refused.status_code == 422 and "legal authorisation" in refused.json()["detail"]
    assert _case(strict, authorization="Ticket LEGAL-118").status_code == 201


def test_confirming_an_account_captures_it_and_views_are_audited(make_client, monkeypatch):
    captured = []

    async def fake_capture(url, settings, route=None):
        captured.append(url)
        files = {
            "page.html": ("text/html", f"<title>{url}</title>".encode()),
            "page.warc": ("application/warc", b"WARC/1.1"),
        }
        return Capture(
            {"kind": "web_capture", "url": url, "title": url, "files": list(files)}, "e" * 64, files, None, []
        )

    monkeypatch.setattr(subject_routes, "capture_url", fake_capture)
    c = make_client(monitors_enabled="false")
    c.app.state.playbook_scan = LearningScans()
    case_id = _case(c, authorization="Ticket LEGAL-118").json()["id"]
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane Doe", "confirmed": True,
                 "known": {"names": ["Jane Doe"], "usernames": ["janedoe84"]}}).json()["id"]  # fmt: skip
    run(c, case_id, sid, rounds=1)
    insta = next(x for x in wait(c, case_id, sid)["candidates"] if x["value"] == INSTA)
    c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{insta['id']}/confirm", json={})
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        cand = next(
            x for x in c.get(f"/api/cases/{case_id}/subjects/{sid}").json()["candidates"] if x["id"] == insta["id"]
        )
        if cand.get("capture", {}).get("status") != "capturing":
            break
        time.sleep(0.05)
    assert captured == [INSTA] and cand["capture"]["status"] == "done", cand.get("capture")
    evidence = c.get(f"/api/cases/{case_id}").json()["captures"]
    assert (
        evidence[0]["id"] == cand["capture"]["evidence_id"]
        and "confirmed as belonging to Jane Doe" in evidence[0]["note"]
    )
    events = c.get("/api/audit?limit=200").json()
    capture = next(e for e in events if e["action"] == "evidence.capture")
    assert capture["details"]["authorization"] == "Ticket LEGAL-118" and capture["details"]["subject"] == sid
    assert next(e for e in events if e["action"] == "subject.confirm")["details"]["authorization"] == "Ticket LEGAL-118"
    assert any(e["action"] == "subject.view" and e["resource"] == sid for e in events)
    assert next(e for e in events if e["action"] == "subject.run")["details"]["authorization"] == "Ticket LEGAL-118"


def test_a_failed_capture_never_breaks_the_confirmation(make_client):
    c = make_client(monitors_enabled="false")  # the test-wide stub refuses every capture
    c.app.state.playbook_scan = LearningScans()
    case_id = _case(c).json()["id"]
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane", "confirmed": True,
                 "known": {"usernames": ["janedoe84"]}}).json()["id"]  # fmt: skip
    run(c, case_id, sid, rounds=1)
    insta = next(x for x in wait(c, case_id, sid)["candidates"] if x["value"] == INSTA)
    ok = c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{insta['id']}/confirm", json={})
    assert ok.status_code == 200
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        cand = next(
            x for x in c.get(f"/api/cases/{case_id}/subjects/{sid}").json()["candidates"] if x["id"] == insta["id"]
        )
        if cand["capture"]["status"] != "capturing":
            break
        time.sleep(0.05)
    assert cand["status"] == "confirmed" and cand["capture"] == {**cand["capture"], "status": "failed"}
    assert "switched off" in cand["capture"]["detail"]
    skipped = c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{insta['id']}/confirm", json={"capture": False})
    assert skipped.status_code == 200
