"""Supplier risk: register import, policy and risk matrix, passive monitoring, alerts and isolation."""

from __future__ import annotations

import csv
import io
from functools import partial

import pytest

from argus.api import server
from argus.demo import DEMO_TARGET, build_demo
from argus.intel.suppliers import impact, normalise_domain, parse_register, risk, status


# ---------------------------------------------------------------------------- policy and parsing
def test_domains_are_normalised():
    assert normalise_domain("https://www.Payroll-Co.com/login?x=1") == "payroll-co.com"
    assert normalise_domain("cloudhost.io") == "cloudhost.io"
    for bad in ("not a domain", "", "localhost", "http://"):
        assert normalise_domain(bad) is None


def test_registers_from_spreadsheets_are_parsed_forgivingly():
    text = (
        "Vendor Name\tWebsite\tCriticality\tData handled\tOwner\n"
        "Payroll Co\thttps://www.payroll-co.com/\tcritical\tpersonal data\tHR\n"
        "Cloud Host\tcloudhost.io\tHigh\tconfidential\tIT\n"
        "Canteen\tcanteen.co.uk\t\t\t\n"
        "Broken\tnot a domain\tlow\t\t\n"
        "Again\tPAYROLL-CO.COM\tlow\t\t\n"
        "Odd\todd.com\tmega\t\t\n"
    )
    result = parse_register(text)
    assert [(r["domain"], r["tier"], r["data_access"]) for r in result.rows] == [
        ("payroll-co.com", "critical", "personal"), ("cloudhost.io", "high", "sensitive"),
        ("canteen.co.uk", "medium", "none"),
    ]  # fmt: skip
    assert [e["line"] for e in result.errors] == [5, 6, 7]
    assert parse_register("name,email\nx,y@z.com\n").errors[0]["error"] == "No domain/website column found"


def test_risk_combines_rating_with_criticality():
    assert impact("critical", "sensitive") == 5 and impact("low", "personal") == 2
    assert risk("critical", "personal", "D") == {"likelihood": 4, "impact": 5, "score": 20, "level": "critical"}
    assert risk("low", "none", "D")["level"] == "low"  # a D-rated canteen is not a payroll provider
    assert risk("medium", "none", None)["level"] == "unknown"
    assert status("critical", "C") == "below_minimum" and status("high", "C") == "within_tolerance"
    assert status("low", "F") == "within_tolerance" and status("critical", None) == "not_assessed"
    assert status("low", "D", override="C") == "below_minimum"


# ---------------------------------------------------------------------------- the API
@pytest.fixture
def client(make_client):
    c = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false")
    c.post("/api/demo")  # gives acme-corp.example completed assessments (D, then F)
    return c


BASIS = "Contracted payroll provider; processes staff personal data"


def add(client, **extra):
    body = {"name": "Acme Corp", "domain": DEMO_TARGET, "tier": "critical", "data_access": "personal",
            "owner": "HR", "basis": BASIS, "authorized": True, **extra}  # fmt: skip
    return client.post("/api/suppliers", json=body)


def test_adding_a_supplier_creates_a_passive_monitor_and_rates_it(client):
    response = add(client)
    assert response.status_code == 201, response.text
    s = response.json()
    assert (s["grade"], s["min_grade"], s["status"]) == ("F", "B", "below_minimum")
    assert s["risk"] == {"likelihood": 5, "impact": 5, "score": 25, "level": "critical"}
    assert s["trend"] == [69.0, 59.0] and s["reassessed_every_days"] == 7
    [monitor] = client.get("/api/monitors").json()
    assert monitor["passive_only"] is True and monitor["interval_hours"] == 168  # never contacts the supplier
    assert "Supplier risk assessment (passive)" in monitor["purpose"]
    event = next(e for e in client.get("/api/audit?limit=10").json() if e["action"] == "supplier.create")
    assert event["details"]["basis"] == BASIS


def test_supplier_validation(client):
    assert add(client, authorized=False).status_code == 422
    assert add(client, domain="not a domain").status_code == 422
    assert add(client, domain="intranet.local").status_code == 422  # internal names are never scanned
    assert add(client).status_code == 201
    assert add(client, domain=f"https://www.{DEMO_TARGET}/about").status_code == 409  # same supplier


def test_import_creates_skips_and_reports(client):
    add(client)
    text = f"Supplier,Domain,Tier\nAcme,{DEMO_TARGET},critical\nCloud Host,cloudhost.example,high\nBad,nope,low\n"
    result = client.post("/api/suppliers/import", json={"csv": text, "basis": BASIS, "authorized": True}).json()
    assert result["created"] == ["cloudhost.example"] and result["skipped"] == [DEMO_TARGET]
    assert result["errors"][0]["line"] == 4
    data = client.get("/api/suppliers").json()
    assert [s["status"] for s in data["suppliers"]] == ["below_minimum", "not_assessed"]
    assert data["summary"] == {"total": 2, "below_minimum": 1, "not_assessed": 1,
                               "by_risk": {"critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 1}}  # fmt: skip
    assert data["matrix"]["5"]["F"] == 1 and data["policy"]["critical"]["min_grade"] == "B"
    assert (
        client.post("/api/suppliers/import", json={"csv": text, "basis": BASIS, "authorized": False}).status_code == 422
    )


def test_editing_tier_reschedules_and_override_changes_tolerance(client):
    s = add(client, tier="low").json()
    assert s["status"] == "within_tolerance"
    s = client.patch(f"/api/suppliers/{s['id']}", json={"min_grade_override": "C"}).json()
    assert s["status"] == "below_minimum" and s["min_grade"] == "C"
    client.patch(f"/api/suppliers/{s['id']}", json={"tier": "high"})
    assert client.get("/api/monitors").json()[0]["interval_hours"] == 24 * 14
    assert client.post(f"/api/suppliers/{s['id']}/assess").status_code == 202


def test_roles_export_and_delete(client):
    s = add(client).json()
    viewer = client.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    analyst = client.post("/api/keys", json={"name": "a", "role": "analyst"}).json()["key"]
    as_viewer, as_analyst = {"Authorization": f"Bearer {viewer}"}, {"Authorization": f"Bearer {analyst}"}
    assert client.get("/api/suppliers", headers=as_viewer).status_code == 200
    assert add(client, domain="other.example").status_code == 201
    assert client.post("/api/suppliers", json={"name": "x", "domain": "x.example", "basis": BASIS, "authorized": True},
                       headers=as_viewer).status_code == 403  # fmt: skip
    assert client.delete(f"/api/suppliers/{s['id']}", headers=as_analyst).status_code == 403
    export = client.get("/api/suppliers/export.csv")
    rows = list(csv.reader(io.StringIO(export.text)))
    assert rows[0][:5] == ["Supplier", "Domain", "Tier", "Data handled", "Owner"]
    assert [r[1] for r in rows[1:]] == [DEMO_TARGET, "other.example"] and rows[1][5] == "F"
    assert client.delete(f"/api/suppliers/{s['id']}").status_code == 204
    assert [m["target"] for m in client.get("/api/monitors").json()] == ["other.example"]  # its monitor went too


def test_suppliers_are_workspace_scoped(client):
    s = add(client).json()
    client.post("/api/workspaces", json={"name": "Red Team"})
    red = {"X-Argus-Workspace": "red-team"}
    assert client.get("/api/suppliers", headers=red).json()["suppliers"] == []
    for method, path in [("PATCH", f"/api/suppliers/{s['id']}"), ("POST", f"/api/suppliers/{s['id']}/assess"),
                         ("DELETE", f"/api/suppliers/{s['id']}")]:  # fmt: skip
        kwargs = {"json": {"name": "x"}} if method == "PATCH" else {}
        assert client.request(method, path, headers=red, **kwargs).status_code == 404, path


# ---------------------------------------------------------------------------- alerts
def test_grade_drops_and_policy_breaches_raise_alerts(client):
    s = add(client).json()
    app = client.app
    # Start from a supplier that has never been assessed, then replay its two scans in order.
    reset = partial(app.state.suppliers.update, s["id"], workspace_id="ws_default", last_grade=None,
                    last_investigation_id=None)  # fmt: skip
    client.portal.call(reset)

    def finish(previous: bool):
        inv, graph = build_demo(previous=previous)
        inv = inv.model_copy(update={"monitor_id": s["monitor_id"]})
        return client.portal.call(server._evaluate_supplier, app, inv, graph)

    assert finish(previous=True) is True  # first assessment: D, below the B required
    assert finish(previous=False) is True  # D -> F: dropped
    assert finish(previous=False) is True  # still F: nothing new
    alerts = client.get("/api/alerts").json()
    headlines = [a["headline"] for a in alerts]
    assert headlines == [
        f"Supplier Acme Corp ({DEMO_TARGET}) dropped from D to F, below the B required for critical suppliers",
        f"Supplier Acme Corp ({DEMO_TARGET}) was rated D, below the B required for critical suppliers",
    ]
    assert {a["severity"] for a in alerts} == {"critical"}
    assert alerts[0]["summary"]["supplier"]["previous_grade"] == "D"
