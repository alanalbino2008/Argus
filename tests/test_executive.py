"""The executive view and board report: area rules, messages, privacy, the PDF and scheduled delivery."""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

import pytest
from pypdf import PdfReader

from argus.intel.executive import assess, redact, remediation_area, score_change, supplier_area
from argus.notify import render

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)


def raw(**over):
    base = {
        "organisations": [], "suppliers": [], "exposure_summary": None, "exposure_own": {}, "exposure_watched": 0,
        "remediation": None, "active_tasks": [], "untracked_critical": 0, "untracked_paths": [], "alerts": [],
    }  # fmt: skip
    return {**base, **over}


def org(target, grade, score, history=None, critical=0):
    return {"target": target, "grade": grade, "score": score, "critical_issues": critical,
            "history": history or [], "trend": [h["score"] for h in history or []], "change": None}  # fmt: skip


def rem(**over):
    base = {"active": 4, "overdue": 0, "overdue_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "sla_compliance": 95, "closed_in_window": 10, "mttr_days": {"critical": 4.5}, "regressions": 0}  # fmt: skip
    return {**base, **over}


# ---------------------------------------------------------------------------- rules
def test_nothing_measured_is_grey_and_says_what_to_do():
    summary = assess(raw(), NOW, 90)
    assert summary["overall"] == "grey" and {a["status"] for a in summary["areas"]} == {"grey"}
    assert summary["verdict"].startswith("Not enough data yet")
    threats = next(a for a in summary["areas"] if a["key"] == "threats")
    assert threats["reason"] == "Nothing is monitored, so no alerts can be raised."


def test_a_healthy_workspace_is_green_with_good_news():
    history = [{"score": 78, "grade": "B", "assessed_at": (NOW - timedelta(days=80)).isoformat()},
               {"score": 86, "grade": "B", "assessed_at": NOW.isoformat()}]  # fmt: skip
    summary = assess(raw(organisations=[org("acme.com", "B", 86, history)], remediation=rem(), watched=2,
                         exposure_watched=1, exposure_summary={"accounts": 0}), NOW, 90)  # fmt: skip
    assert summary["overall"] == "green" and summary["verdict"] == "Within tolerance in every measured area."
    assert "acme.com is rated B, up 8 points in the period." in summary["messages"]
    assert "No remediation work is overdue." in summary["messages"]
    assert "95% of fixes were verified within their deadline (target 90%)." in summary["messages"]


def test_red_areas_explain_themselves_worst_first():
    history = [{"score": 72, "grade": "C", "assessed_at": (NOW - timedelta(days=60)).isoformat()},
               {"score": 55, "grade": "F", "assessed_at": NOW.isoformat()}]  # fmt: skip
    suppliers = [{"name": "Payroll Co", "tier": "critical", "status": "below_minimum", "risk": {"level": "critical"},
                  "exposure": {"ransomware_post": 1}}]  # fmt: skip
    summary = assess(raw(
        organisations=[org("acme.com", "F", 55, history, critical=2)],
        remediation=rem(overdue=3, overdue_by_severity={"critical": 1, "high": 2, "medium": 0, "low": 0}, sla_compliance=60),
        exposure_watched=1, exposure_summary={"accounts": 4}, exposure_own={"stealer_log": 2}, suppliers=suppliers,
        untracked_critical=2, alerts=[{"severity": "critical"}], watched=1,
    ), NOW, 90)  # fmt: skip
    assert summary["overall"] == "red"
    assert summary["verdict"] == ("Action needed: Attack surface, Remediation, Breach & dark-web exposure, "
                                  "Supplier risk, Threat activity.")  # fmt: skip
    assert summary["messages"][:3] == [
        "Supplier Payroll Co was named on a ransomware leak site: check what data of yours it holds.",
        "2 employees' credentials were stolen by infostealer malware.",
        "1 critical fix is past its deadline.",
    ]
    assert "acme.com's security rating fell from C to F (-17 points)." in summary["messages"]
    areas = {a["key"]: a for a in summary["areas"]}
    assert areas["remediation"]["reason"] == "3 tasks overdue; 60% fixed on time; 2 critical path(s) untracked"
    assert areas["suppliers"]["figures"]["ransomware"] == 1 and len(summary["messages"]) == 7


def test_thresholds():
    assert remediation_area(rem(sla_compliance=85), 0)[0]["status"] == "amber"  # below the 90% target
    assert remediation_area(rem(sla_compliance=65), 0)[0]["status"] == "red"  # below the 70% floor
    assert remediation_area(rem(overdue=1, overdue_by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0}), 0)[0][
        "status"] == "amber"  # fmt: skip
    assert remediation_area(None, 3)[0]["status"] == "red"  # critical paths nobody owns
    assert supplier_area([{"name": "x", "tier": "low", "status": "below_minimum", "risk": {"level": "low"}}])[0][
        "status"] == "amber"  # fmt: skip
    assert score_change([{"score": 70, "grade": "C", "assessed_at": NOW.isoformat()}], NOW) == (None, None)


def test_people_in_findings_are_never_named_but_owners_are():
    summary = assess(raw(untracked_critical=1, untracked_paths=[{
        "id": "path_1", "title": "Leaked credentials for dana.whitfield@acme.com", "severity": "critical",
        "target": "acme.com", "investigation_id": "inv_1"}], active_tasks=[{
        "id": "rem_1", "title": "Reset bob@acme.com", "severity": "high", "target": "acme.com",
        "assignee": "alice@acme.com", "due_at": NOW.isoformat(), "overdue": True, "status": "open"}]), NOW, 90)  # fmt: skip
    titles = [r["title"] for r in summary["top_risks"]]
    assert titles == ["Leaked credentials for d•••d@acme.com", "Reset b•••b@acme.com"]
    assert summary["top_risks"][1]["owner"] == "alice@acme.com"  # accountability is named
    assert redact("no addresses here") == "no addresses here"


# ---------------------------------------------------------------------------- the API and the PDF
@pytest.fixture
def client(make_client):
    c = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false",
                    encryption_key="k" * 40, public_url="https://argus.example")  # fmt: skip
    c.post("/api/demo")
    return c


def test_the_overview_on_the_demo(client):
    d = client.get("/api/executive?days=90").json()
    assert d["overall"] == "red" and d["period_days"] == 90
    areas = {a["key"]: a["status"] for a in d["areas"]}
    assert areas == {"surface": "red", "remediation": "red", "exposure": "red", "suppliers": "grey", "threats": "green"}
    assert next(a for a in d["areas"] if a["key"] == "threats")["reason"] == "0 alerts in 90 days"
    assert d["messages"][0] == "Your organisation was named on a ransomware group's leak site."
    assert d["organisations"][0]["target"] == "acme-corp.example" and d["organisations"][0]["grade"] == "F"
    assert all(r["status"] == "untracked" for r in d["top_risks"])
    assert "dana.whitfield" not in str(d["top_risks"])
    assert client.get("/api/executive?days=45").status_code == 422
    # Tracking a path takes it off the "nobody owns it" list.
    first = d["top_risks"][0]
    client.post("/api/remediation", json={"source": {"type": "attack_path", "investigation_id": first["investigation_id"],
                                                     "path_id": first["path_id"]}, "assignee": "alice"})  # fmt: skip
    again = client.get("/api/executive").json()
    tracked = next(r for r in again["top_risks"] if r["title"] == first["title"])
    assert tracked["status"] == "open" and tracked["owner"] == "alice"
    client.post("/api/workspaces", json={"name": "Board"})
    assert client.get("/api/executive", headers={"X-Argus-Workspace": "board"}).json()["overall"] == "grey"


def test_the_board_report_pdf(client):
    r = client.post("/api/executive/report", json={"days": 90, "prepared_for": "Board of Directors", "tlp": "AMBER"})
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    text = "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(r.content)).pages)
    assert "Overall: RED" in text and "Key messages" in text and "Risks to act on" in text
    assert "prepared for Board of Directors" in text and "TLP:AMBER" in text
    assert "dana.whitfield" not in text and "@acme-corp.example" in text  # masked, not removed
    assert "/api/reports/verify/<sha256>" in text
    verified = client.get(f"/api/reports/verify/{r.headers['X-Report-SHA256']}").json()
    assert (
        verified["genuine"]
        and verified["target"] == "Board report"
        and verified["report_id"] == r.headers["X-Report-Id"]
    )
    event = next(e for e in client.get("/api/audit?limit=10").json() if e["action"] == "report.board")
    assert event["details"]["overall"] == "red"
    viewer = client.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    as_viewer = {"Authorization": f"Bearer {viewer}"}
    assert client.get("/api/executive", headers=as_viewer).status_code == 200  # directors can read the overview
    assert client.post("/api/executive/report", json={}, headers=as_viewer).status_code == 403


def test_board_reports_can_be_scheduled(client):
    channel = client.post("/api/notifications/channels", json={
        "name": "Board inbox hook", "type": "webhook", "destination": {"url": "https://hooks.example.com/board"}}).json()  # fmt: skip
    body = {"name": "Monthly board report", "frequency": "monthly", "day_of_month": 1, "hour": 7,
            "channel_ids": [channel["id"]], "options": {"kind": "board", "period_days": 30, "tlp": "GREEN"}}  # fmt: skip
    created = client.post("/api/reports/schedules", json=body)
    assert created.status_code == 201, created.text
    schedule = created.json()
    assert schedule["target"] == "Board report" and schedule["has_scan"]
    assert client.post("/api/reports/schedules", json={**body, "options": {"kind": "assessment"}}).status_code == 422
    assert client.portal.call(client.app.state.report_scheduler.run, schedule) == "sent"
    [delivery] = client.get("/api/notifications/deliveries").json()
    assert delivery["summary"].startswith("Board report ARG-") and delivery["summary"].endswith("(RED)")
    saved = client.get("/api/reports/schedules").json()[0]
    assert saved["last_status"] == "sent" and saved["last_report_id"]


def test_board_notifications_read_well():
    record = {"id": "ARG-1", "target": "Board report", "tlp": "GREEN", "sha256": "ab" * 32, "prepared_for": None}
    summary = {"overall": "amber", "verdict": "No emergencies, but some areas are below target.",
               "messages": ["3 remediation tasks are overdue."], "areas": [{"key": "remediation", "status": "amber"}],
               "period_days": 30}  # fmt: skip
    event = render.board_event(record, summary, {"id": "sch_1", "name": "Monthly"}, {"id": "ws_default", "name": "Default"},
                               "https://argus.example")  # fmt: skip
    assert event["report"]["url"] == "https://argus.example/?ws=ws_default#/executive"
    text = render.slack(event)["blocks"][0]["text"]["text"]
    assert "Monthly: board report (AMBER)" in text and "3 remediation tasks are overdue." in text
    mail = render.email(event, "argus@example.com", ["ciso@example.com"], attachment=("board.pdf", b"%PDF-1.4"))
    assert (
        mail["Subject"] == "[Argus] Monthly: board report (AMBER)"
        and "The PDF is attached." in mail.get_body(("plain",)).get_content()
    )


def test_the_python_client_covers_the_executive_view(client):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    argus = ArgusClient(http=client)
    assert argus.executive(days=30)["period_days"] == 30
    assert argus.board_report(prepared_for="Audit committee").startswith(b"%PDF")
