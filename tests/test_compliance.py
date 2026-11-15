"""Compliance mapping: catalogue integrity, control evaluation, honesty about coverage, and the API."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from argus.intel.compliance import BY_ID, CHECKS, FRAMEWORKS, assess_framework, evaluate
from argus.intel.exposure import KINDS

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)
PATH_RULES = set(re.findall(r'rule="([a-z_]+)"', (Path(__file__).parents[1] / "argus/intel/paths.py").read_text()))


def test_the_catalogue_only_refers_to_things_that_exist():
    # A typo in a rule name would make a control look "met" forever, so every reference is checked.
    assert len(PATH_RULES) >= 17
    for fw in FRAMEWORKS:
        refs = [c.ref for c in fw.controls]
        assert len(refs) == len(set(refs)), fw.id
        for c in fw.controls:
            assert set(c.rules) <= PATH_RULES, (fw.id, c.ref, set(c.rules) - PATH_RULES)
            assert set(c.exposure) <= set(KINDS), (fw.id, c.ref)
            assert set(c.checks) <= set(CHECKS), (fw.id, c.ref)
            assert c.coverage in ("direct", "partial", "process")
            assert c.rules or c.exposure or c.checks, (fw.id, c.ref)  # every control has some evidence
    assert set(BY_ID) == {"cyber_essentials", "iso27001", "nist_csf", "dora"}
    mapped = {r for fw in FRAMEWORKS for c in fw.controls for r in c.rules}
    # Lookalike domains are registered by someone else: threat intelligence, not a failed control of yours.
    assert PATH_RULES - mapped == {"lookalike_domain", "lookalike_domain_watchlist"}
    assert {"exposed_sensitive_service", "exploitable_public_service", "end_of_life_software"} <= mapped


def ctx(**over):
    base = {
        "own_scans": [{"target": "acme.com", "investigation_id": "inv_1", "completed_at": (NOW - timedelta(days=3)).isoformat()}],
        "paths": [], "exposure_findings": [], "exposure_watches": 1, "suppliers": [],
        "monitors": [{"target": "acme.com", "enabled": True, "interval_hours": 24}],
        "channels": [{"name": "SOC", "type": "slack", "enabled": True}],
        "remediation": {"active": 2, "closed_in_window": 10, "sla_compliance": 95, "overdue": 0,
                        "overdue_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "mttr_days": {"critical": 3}},
        "policy": {"sla_days": {"critical": 7, "high": 14, "medium": 90, "low": 180}},
    }  # fmt: skip
    return {**base, **over}


def path(rule, severity="high", task=None):
    return {"rule": rule, "severity": severity, "title": f"{rule} on acme.com", "target": "acme.com",
            "path_id": f"path_{rule}", "investigation_id": "inv_1", "task": task}  # fmt: skip


def control(fw, ref):
    return next(c for c in BY_ID[fw].controls if c.ref == ref)


# ---------------------------------------------------------------------------- evaluation
def test_a_well_run_clean_estate_meets_cyber_essentials():
    result = assess_framework(BY_ID["cyber_essentials"], ctx(), NOW)
    assert result["counts"] == {"met": 5, "partial": 0, "gap": 0, "not_assessed": 0} and result["met_pct"] == 100
    ce3 = next(c for c in result["controls"] if c["ref"] == "CE-3")
    assert "Your deadlines for critical and high issues are within 14 days" in ce3["reasons"]


def test_no_evidence_is_never_a_pass():
    empty = ctx(own_scans=[], monitors=[], channels=[], remediation=None, exposure_watches=0)
    ce = assess_framework(BY_ID["cyber_essentials"], empty, NOW)
    assert ce["counts"]["met"] == 0
    statuses = {c["ref"]: c["status"] for c in ce["controls"]}
    assert statuses["CE-1"] == "not_assessed" and statuses["CE-5"] == "not_assessed"
    # A policy that allows 30 days for high-severity updates is itself a finding.
    weak_policy = {"sla_days": {"critical": 7, "high": 30, "medium": 90, "low": 180}}
    ce3 = evaluate(control("cyber_essentials", "CE-3"), {**empty, "policy": weak_policy}, NOW)
    assert ce3["status"] == "partial" and any("your policy allows 30 days for high" in r for r in ce3["reasons"])
    monitoring = evaluate(control("iso27001", "A.8.16"), empty, NOW)
    assert monitoring["status"] == "gap"  # absence of monitoring is evidence, not a blank


def test_findings_owners_and_severity_decide_the_status():
    firewall = control("cyber_essentials", "CE-1")
    untracked = evaluate(firewall, ctx(paths=[path("exposed_sensitive_service")]), NOW)
    assert (
        untracked["status"] == "gap"
        and untracked["reasons"][0] == "1 finding(s) against this control, 1 without an owner"
    )
    owned = evaluate(
        firewall, ctx(paths=[path("exposed_sensitive_service", task={"id": "rem_1", "status": "open"})]), NOW
    )
    assert (
        owned["status"] == "partial"
        and owned["reasons"][0] == "1 finding(s) against this control, all being remediated"
    )
    minor = evaluate(firewall, ctx(paths=[path("exposed_sensitive_service", severity="medium")]), NOW)
    assert minor["status"] == "partial"
    unrelated = evaluate(firewall, ctx(paths=[path("tls_interception")]), NOW)
    assert unrelated["status"] == "met" and unrelated["gaps"] == []


def test_stale_evidence_and_exposure():
    old = ctx(own_scans=[{"target": "acme.com", "investigation_id": "inv_1",
                          "completed_at": (NOW - timedelta(days=200)).isoformat()}])  # fmt: skip
    assert evaluate(control("cyber_essentials", "CE-1"), old, NOW)["status"] == "partial"
    stealer = {"kind": "stealer_log", "severity": "critical", "title": "Staff credentials captured", "target": "acme.com",
               "finding_id": "exf_1", "account_masked": "r•••n@acme.com", "task": None}  # fmt: skip
    access = evaluate(control("cyber_essentials", "CE-4"), ctx(exposure_findings=[stealer]), NOW)
    assert access["status"] == "gap" and access["gaps"][0]["kind"] == "exposure"
    malware = evaluate(control("cyber_essentials", "CE-5"), ctx(exposure_findings=[stealer]), NOW)
    assert malware["status"] == "gap"


def test_supplier_controls():
    def supplier(status, task=None, exposure=None):
        return {"name": "Payroll Co", "tier": "critical", "status": status, "grade": "D", "min_grade": "B",
                "task": task, "exposure": exposure or {}}  # fmt: skip

    iso = control("iso27001", "A.5.19")
    assert evaluate(iso, ctx(), NOW)["status"] == "gap"  # no register at all
    assert evaluate(iso, ctx(suppliers=[supplier("within_tolerance")]), NOW)["status"] == "met"
    assert evaluate(iso, ctx(suppliers=[supplier("below_minimum")]), NOW)["status"] == "gap"
    tracked = evaluate(
        iso, ctx(suppliers=[supplier("below_minimum", task={"id": "rem_2", "status": "in_progress"})]), NOW
    )
    assert tracked["status"] == "partial"
    hit = evaluate(
        control("dora", "Art. 28"), ctx(suppliers=[supplier("within_tolerance", exposure={"ransomware_post": 1})]), NOW
    )
    assert hit["status"] == "gap" and "ransomware" in hit["reasons"][-1]


# ---------------------------------------------------------------------------- the API
@pytest.fixture
def client(make_client):
    c = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false")
    c.post("/api/demo")
    return c


def test_the_demo_against_every_framework(client):
    data = client.get("/api/compliance").json()
    assert "does not replace" in data["disclaimer"]
    frameworks = {f["id"]: f for f in data["frameworks"]}
    ce = frameworks["cyber_essentials"]
    assert ce["counts"]["gap"] == 5 and ce["assessed_pct"] == 100  # the fictional demo company is in poor shape
    firewall = next(c for c in ce["controls"] if c["ref"] == "CE-1")
    assert firewall["gaps"] and all(g["target"] == "acme-corp.example" for g in firewall["gaps"])
    assert "dana.whitfield" not in json.dumps(data)  # people in findings are masked

    # Owning every gap turns the control from "gap" into "partially met".
    for g in firewall["gaps"]:
        client.post("/api/remediation", json={"source": {"type": "attack_path", "investigation_id": g["investigation_id"],
                                                         "path_id": g["path_id"]}})  # fmt: skip
    again = client.get("/api/compliance").json()["frameworks"][0]
    assert next(c for c in again["controls"] if c["ref"] == "CE-1")["status"] == "partial"


def test_exports_are_audited_and_isolated(client):
    r = client.get("/api/compliance/iso27001/export.csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:4] == ["Control", "Title", "Status", "Coverage"]
    assert {row[0] for row in rows[1:14]} >= {"A.5.7", "A.8.8", "A.8.24"}
    assert "does not replace" in rows[-1][0]
    assert client.get("/api/compliance/sox/export.csv").status_code == 404
    pack = client.get("/api/compliance/evidence.json")
    body = json.loads(pack.content)
    assert [f["id"] for f in body["frameworks"]] == ["cyber_essentials", "iso27001", "nist_csf", "dora"]
    assert body["workspace"]["id"] == "ws_default" and "attachment" in pack.headers["content-disposition"]
    exports = [e for e in client.get("/api/audit?limit=10").json() if e["action"] == "compliance.export"]
    assert len(exports) == 2
    viewer = client.post("/api/keys", json={"name": "auditor", "role": "viewer"}).json()["key"]
    assert client.get("/api/compliance", headers={"Authorization": f"Bearer {viewer}"}).status_code == 200
    client.post("/api/workspaces", json={"name": "Empty"})
    empty = client.get("/api/compliance", headers={"X-Argus-Workspace": "empty"}).json()["frameworks"][0]
    assert empty["counts"]["met"] == 0 and empty["counts"]["not_assessed"] >= 4


def test_the_python_client_covers_compliance(client):
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    data = ArgusClient(http=client).compliance()
    assert [f["name"] for f in data["frameworks"]] == [
        "Cyber Essentials",
        "ISO/IEC 27001",
        "NIST Cybersecurity Framework",
        "DORA",
    ]
