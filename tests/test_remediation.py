"""Remediation: deadlines, transitions, verification by scans, regressions, alerts, automation and the API."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from functools import partial

import pytest

from argus.api import remediation_hooks
from argus.demo import DEMO_TARGET, build_demo
from argus.intel.exposure import Finding
from argus.intel.paths import find_attack_paths
from argus.intel.remediation import comparable, due_date, metrics, transition_error, verification
from argus.notify import render

NOW = datetime(2026, 11, 15, 12, tzinfo=timezone.utc)
SCOPE = {"max_depth": 3, "passive_only": False, "modules": None}


# ---------------------------------------------------------------------------- rules
def test_deadlines_follow_severity_and_policy():
    assert due_date("critical", NOW) == NOW + timedelta(days=7)
    assert due_date("low", NOW) == NOW + timedelta(days=180)
    assert due_date("high", NOW, {"high": 14}) == NOW + timedelta(days=14)


def test_people_cannot_skip_the_evidence():
    path_task = {"status": "fixed", "source_type": "attack_path"}
    assert "verified by a scan" in transition_error(path_task, "verified")
    assert transition_error({"status": "fixed", "source_type": "exposure"}, "verified") is None
    assert "cannot be moved" in transition_error({"status": "open", "source_type": "manual"}, "verified")
    assert transition_error({"status": "verified", "source_type": "manual"}, "open") is None
    assert "minimum grade" in transition_error({"status": "fixed", "source_type": "supplier"}, "verified")


def test_only_a_comparable_scan_proves_a_fix():
    full = {"max_depth": 3, "passive_only": False, "modules": None}
    assert comparable(SCOPE, full)
    assert not comparable(SCOPE, {**full, "max_depth": 2})  # looked less deeply
    assert not comparable(SCOPE, {**full, "passive_only": True})  # did not touch the target
    assert not comparable(SCOPE, {**full, "truncated": True})  # stopped early
    assert not comparable(SCOPE, {**full, "modules": ["dns"]})  # skipped modules
    assert comparable({**SCOPE, "modules": ["dns"]}, {**full, "modules": ["dns", "ports"]})
    assert comparable({**SCOPE, "passive_only": True}, {**full, "passive_only": True})


def test_what_a_scan_means_for_a_task():
    def task(status):
        return {"status": status, "details": {"scope": SCOPE}}

    scan = {**SCOPE, "truncated": False}
    light = {**scan, "max_depth": 1}
    assert verification(task("fixed"), present=False, scan=scan) == "verified"
    assert verification(task("open"), present=False, scan=scan) == "verified"  # fixed without telling us
    assert verification(task("fixed"), present=False, scan=light) is None  # absence in a light scan proves nothing
    assert verification(task("fixed"), present=True, scan=light) == "reopened"  # presence in any scan does
    assert verification(task("verified"), present=True, scan=scan) == "reopened"  # a regression
    assert verification(task("open"), present=True, scan=scan) is None
    assert verification(task("accepted"), present=False, scan=scan) is None  # a person's decision stands


def test_metrics():
    def t(severity, status, created_days_ago, closed_days_ago=None, due_in=7, assignee=None, reopen=0):
        return {
            "severity": severity, "status": status, "assignee": assignee, "reopen_count": reopen,
            "created_at": (NOW - timedelta(days=created_days_ago)).isoformat(),
            "closed_at": (NOW - timedelta(days=closed_days_ago)).isoformat() if closed_days_ago is not None else None,
            "due_at": (NOW - timedelta(days=created_days_ago) + timedelta(days=due_in)).isoformat(),
        }  # fmt: skip

    tasks = [
        t("critical", "verified", 20, 16),  # 4 days, on time
        t("critical", "verified", 30, 20),  # 10 days, late
        t("critical", "verified", 12, 6, reopen=1),  # 6 days, on time
        t("high", "open", 40, due_in=30, assignee="alice"),  # overdue
        t("high", "in_progress", 1, due_in=30, assignee="alice"),
        t("medium", "fixed", 3, due_in=5),  # due in 2 days
        t("low", "accepted", 50, 40),
    ]
    m = metrics(tasks, NOW)
    assert (m["active"], m["overdue"], m["due_within_7_days"], m["awaiting_verification"]) == (3, 1, 1, 1)
    assert m["mttr_days"]["critical"] == 6.0 and m["mttr_days"]["high"] is None
    assert m["sla_compliance"] == 67 and m["closed_in_window"] == 3
    assert m["by_assignee"] == {"alice": {"open": 2, "overdue": 1}, "Unassigned": {"open": 1, "overdue": 0}}
    assert m["regressions"] == 1 and len(m["trend"]) == 12 and sum(w["opened"] for w in m["trend"]) == 7


# ---------------------------------------------------------------------------- the API
@pytest.fixture
def client(make_client):
    c = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false")
    c.post("/api/demo")
    return c


def demo_paths():
    latest, latest_graph = build_demo(previous=False)
    earlier, earlier_graph = build_demo(previous=True)
    now_ids = {p["id"]: p for p in find_attack_paths(latest_graph)["paths"]}
    then_ids = {p["id"]: p for p in find_attack_paths(earlier_graph)["paths"]}
    return (latest, latest_graph, now_ids), (earlier, earlier_graph, then_ids)


def track(client, inv_id, path_id, **extra):
    return client.post("/api/remediation", json={"source": {"type": "attack_path", "investigation_id": inv_id,
                                                            "path_id": path_id}, **extra})  # fmt: skip


def test_tracking_an_attack_path_snapshots_it_with_a_deadline(client):
    (latest, _, now_paths), _ = demo_paths()
    path = next(iter(now_paths.values()))
    created = track(client, latest.id, path["id"], assignee="alice@acme.example", external_ref="SEC-1")
    assert created.status_code == 201, created.text
    task = created.json()
    assert task["created"] and task["title"] == path["title"] and task["severity"] == path["severity"]
    assert task["target"] == DEMO_TARGET and task["details"]["remediation"] == path["remediation"]
    assert task["details"]["scope"]["max_depth"] == 3
    due = datetime.fromisoformat(task["due_at"]) - datetime.fromisoformat(task["created_at"])
    assert round(due.total_seconds() / 86400) == {"critical": 7, "high": 30, "medium": 90, "low": 180}[path["severity"]]
    again = track(client, latest.id, path["id"])
    assert again.status_code == 200 and again.json()["id"] == task["id"] and not again.json()["created"]
    assert track(client, latest.id, "path_nope").status_code == 404
    assert client.post("/api/remediation", json={"source": {"type": "manual", "title": "x"}}).status_code == 422


def test_scans_verify_fixes_and_catch_regressions(client):
    (latest, latest_graph, now_paths), (earlier, earlier_graph, then_paths) = demo_paths()
    gone = next(pid for pid in then_paths if pid not in now_paths)  # fixed between the two demo scans
    task = track(client, earlier.id, gone).json()
    client.patch(f"/api/remediation/{task['id']}", json={"status": "fixed", "note": "Closed the port"})

    async def scan(inv, graph, **config):
        inv = inv.model_copy(update={"config": inv.config.model_copy(update=config)}) if config else inv
        return await remediation_hooks.after_scan(client.app, inv, graph, truncated=False)

    assert (
        client.portal.call(partial(scan, latest, latest_graph, max_depth=1))["verified"] == []
    )  # too light to prove it
    assert client.portal.call(scan, latest, latest_graph)["verified"] == [task["id"]]
    verified = client.get(f"/api/remediation/{task['id']}").json()
    assert verified["status"] == "verified" and verified["verified_by"] == latest.id and verified["closed_at"]
    assert verified["events"][-1]["kind"] == "verified" and verified["events"][-1]["by"] == f"scan {latest.id}"

    assert client.portal.call(scan, earlier, earlier_graph)["reopened"] == [task["id"]]  # it came back
    regressed = client.get(f"/api/remediation/{task['id']}").json()
    assert regressed["status"] == "open" and regressed["reopen_count"] == 1
    assert regressed["events"][-1]["text"] == "Regression: the attack path is back"


def test_accepting_a_risk_needs_a_reason_and_an_end_date_and_expires(client):
    (latest, _, now_paths), _ = demo_paths()
    task = track(client, latest.id, next(iter(now_paths))).json()
    until = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    url = f"/api/remediation/{task['id']}"
    assert client.patch(url, json={"status": "accepted", "note": "Legacy box, decommissioned in Q1"}).status_code == 422
    assert client.patch(url, json={"status": "accepted", "accepted_until": until}).status_code == 422
    too_long = (datetime.now(timezone.utc) + timedelta(days=500)).isoformat()
    assert (
        client.patch(url, json={"status": "accepted", "accepted_until": too_long, "note": "Legacy box"}).status_code
        == 422
    )
    accepted = client.patch(url, json={"status": "accepted", "accepted_until": until, "note": "Legacy box, gone in Q1"})
    assert accepted.json()["status"] == "accepted" and accepted.json()["closed_at"]
    later = datetime.now(timezone.utc) + timedelta(days=31)
    assert client.portal.call(client.app.state.remediation.expire_acceptances, later) == 1
    reopened = client.get(url).json()
    assert reopened["status"] == "open" and reopened["events"][-1]["text"] == "Risk acceptance expired: decide again"


def test_overdue_tasks_are_announced_once(client):
    (latest, _, now_paths), _ = demo_paths()
    ids = list(now_paths)[:2]
    for pid in ids:
        task = track(client, latest.id, pid).json()
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        client.patch(f"/api/remediation/{task['id']}", json={"due_at": past})
    clock = client.app.state.remediation_clock
    assert client.portal.call(clock.tick)["alerts"] == 1
    [alert] = client.get("/api/alerts").json()
    assert alert["headline"].startswith("2 remediation tasks are now overdue")
    assert alert["summary"]["remediation"]["overdue"] == 2
    assert client.portal.call(clock.tick)["alerts"] == 0  # already announced
    event = render.alert_event(alert, {"id": "ws_default", "name": "Default"}, "https://argus.example")
    assert event["alert"]["url"] == "https://argus.example/?ws=ws_default#/remediation"
    data = client.get("/api/remediation?overdue=true").json()
    assert len(data["tasks"]) == 2 and data["metrics"]["overdue"] == 2


def test_the_policy_opens_tasks_automatically(client):
    assert (
        client.put("/api/remediation/policy", json={"sla_days": {"critical": 3}, "auto_create": "high"}).status_code
        == 200
    )
    assert client.put("/api/remediation/policy", json={"sla_days": {"critical": 0}}).status_code == 422
    assert client.put("/api/remediation/policy", json={"sla_days": {"urgent": 3}}).status_code == 422
    (latest, latest_graph, now_paths), _ = demo_paths()
    watched = latest.model_copy(update={"monitor_id": "mon_1"})
    outcome = client.portal.call(
        partial(remediation_hooks.after_scan, client.app, watched, latest_graph, truncated=False)
    )
    qualifying = [p for p in now_paths.values() if p["severity"] in ("critical", "high")]
    assert len(outcome["opened"]) == len(qualifying) > 0
    tasks = client.get("/api/remediation").json()["tasks"]
    critical = next(t for t in tasks if t["severity"] == "critical")
    assert critical["created_by"] == "Argus automation"
    assert (datetime.fromisoformat(critical["due_at"]) - datetime.fromisoformat(critical["created_at"])).days == 3
    # A second scan does not duplicate them.
    again = client.portal.call(
        partial(remediation_hooks.after_scan, client.app, watched, latest_graph, truncated=False)
    )
    assert len(client.get("/api/remediation").json()["tasks"]) == len(qualifying) and len(again["opened"]) == len(
        qualifying
    )


def test_exposure_and_remediation_stay_in_step(client):
    findings = client.get("/api/exposure").json()["findings"]
    stealer, other = findings[0], findings[2]
    task = client.post("/api/remediation", json={"source": {"type": "exposure", "finding_id": stealer["id"]}}).json()
    assert task["severity"] == "critical" and "r•••n@acme-corp.example" in task["title"] and "r.chen" not in str(task)
    client.patch(f"/api/remediation/{task['id']}", json={"status": "fixed", "note": "Laptop re-imaged"})
    resolved = client.get("/api/exposure?status=resolved").json()["findings"]
    assert [f["id"] for f in resolved] == [stealer["id"]]
    # The other direction: resolving a finding on the Exposure page verifies its task.
    second = client.post("/api/remediation", json={"source": {"type": "exposure", "finding_id": other["id"]}}).json()
    client.post("/api/exposure/findings/status", json={"ids": [other["id"]], "status": "resolved", "note": "Reset"})
    assert client.get(f"/api/remediation/{second['id']}").json()["status"] == "verified"


def test_supplier_tasks_close_when_the_grade_recovers(client):
    supplier = client.post("/api/suppliers", json={"name": "Acme", "domain": DEMO_TARGET, "tier": "critical",
                                                   "basis": "Contracted payroll provider", "authorized": True}).json()  # fmt: skip
    task = client.post("/api/remediation", json={"source": {"type": "supplier", "supplier_id": supplier["id"]}}).json()
    assert task["severity"] == "critical" and "up to grade B" in task["title"]
    assert client.patch(f"/api/remediation/{task['id']}", json={"status": "fixed"}).status_code == 200
    assert client.patch(f"/api/remediation/{task['id']}", json={"status": "verified"}).status_code == 409
    client.portal.call(partial(remediation_hooks.after_supplier_assessment, client.app, "ws_default", supplier,
                               grade="B", floor="B", below=False))  # fmt: skip
    assert client.get(f"/api/remediation/{task['id']}").json()["status"] == "verified"


def test_rescan_reuses_the_original_scope(client):
    (latest, _, now_paths), _ = demo_paths()
    task = track(client, latest.id, next(iter(now_paths))).json()
    launched = []

    async def fake_rescan(config, principal, purpose, workspace_id):
        launched.append((config.target, config.max_depth, purpose, workspace_id))
        return "inv_verify"

    client.app.state.rescan = fake_rescan
    r = client.post(f"/api/remediation/{task['id']}/rescan")
    assert r.status_code == 202 and r.json()["investigation_id"] == "inv_verify"
    assert launched[0][:2] == (DEMO_TARGET, 3) and launched[0][2].startswith(
        f"Remediation verification of {task['id']}"
    )
    assert (
        client.get(f"/api/remediation/{task['id']}").json()["events"][-1]["text"]
        == "Verification scan started: inv_verify"
    )
    manual = client.post("/api/remediation", json={"source": {"type": "manual", "title": "Enforce MFA",
                                                              "severity": "high"}}).json()  # fmt: skip
    assert client.post(f"/api/remediation/{manual['id']}/rescan").status_code == 409


def test_roles_isolation_export_and_timeline(client):
    manual = client.post("/api/remediation", json={"source": {"type": "manual", "title": "Enforce MFA on the VPN",
                         "severity": "high", "target": "vpn.acme.example"}, "assignee": "bob"}).json()  # fmt: skip
    url = f"/api/remediation/{manual['id']}"
    client.patch(url, json={"assignee": "alice", "status": "in_progress", "note": "Rolling out to IT first"})
    client.post(f"{url}/comments", json={"text": "Half the staff enrolled"})
    events = client.get(url).json()["events"]
    assert [e["kind"] for e in events] == ["created", "assigned", "status", "comment"]
    assert events[1]["text"] == "Assigned to alice" and events[2]["text"] == "In progress: Rolling out to IT first"

    viewer = client.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    analyst = client.post("/api/keys", json={"name": "a", "role": "analyst"}).json()["key"]
    as_viewer, as_analyst = {"Authorization": f"Bearer {viewer}"}, {"Authorization": f"Bearer {analyst}"}
    assert client.get("/api/remediation", headers=as_viewer).status_code == 200
    assert client.patch(url, json={"status": "fixed"}, headers=as_viewer).status_code == 403
    assert client.get("/api/remediation?assignee=me", headers=as_analyst).json()["tasks"] == []
    assert len(client.get("/api/remediation?assignee=alice").json()["tasks"]) == 1
    assert client.delete(url, headers=as_analyst).status_code == 403

    client.post("/api/workspaces", json={"name": "Red Team"})
    red = {"X-Argus-Workspace": "red-team"}
    assert client.get("/api/remediation", headers=red).json()["tasks"] == []
    assert (
        client.get(url, headers=red).status_code == 404
        and client.patch(url, json={"status": "fixed"}, headers=red).status_code == 404
    )

    rows = list(csv.reader(io.StringIO(client.get("/api/remediation/export.csv").text)))
    assert rows[0][:5] == ["ID", "Title", "Severity", "Status", "Assignee"] and rows[1][4] == "alice"
    assert client.delete(url).status_code == 204 and client.get(url).status_code == 404


def test_purging_keeps_two_years_of_closed_tasks(client):
    repo = client.app.state.remediation
    task, _ = client.portal.call(lambda: repo.create(workspace_id="ws_default", by="t", fields={
        "source_type": "manual", "title": "Old", "severity": "low", "target": "", "description": ""}))  # fmt: skip
    client.patch(f"/api/remediation/{task['id']}", json={"status": "fixed"})
    client.patch(f"/api/remediation/{task['id']}", json={"status": "verified"})
    assert client.portal.call(lambda: repo.purge_closed(older_than_days=730)) == 0
    assert client.portal.call(lambda: repo.purge_closed(older_than_days=-1)) == 1


def test_finding_helpers_do_not_leak_addresses():
    from argus.intel.remediation import from_exposure

    finding = {"id": "exf_1", "kind": "breach_account", "severity": "high", "title": "Staff account exposed",
               "subject": "acme.com", "account": "alice@acme.com", "account_masked": "a•••e@acme.com"}  # fmt: skip
    fields = from_exposure(finding)
    assert "alice" not in str(fields) and fields["title"] == "Staff account exposed (a•••e@acme.com)"
    assert Finding  # the exposure module stays importable alongside


def test_the_python_client_covers_remediation(client):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    argus = ArgusClient(http=client)
    task = argus.track({"type": "manual", "title": "Rotate the shared admin password", "severity": "high"},
                       assignee="alice", external_ref="SEC-9")  # fmt: skip
    assert task["created"] and task["assignee"] == "alice"
    assert argus.update_task(task["id"], status="fixed", note="Rotated")["status"] == "fixed"
    data = argus.tasks(assignee="alice")
    assert [t["id"] for t in data["tasks"]] == [task["id"]] and data["metrics"]["awaiting_verification"] == 1
