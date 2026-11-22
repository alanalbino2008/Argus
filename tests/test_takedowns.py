"""Phase 75: takedown requests — abuse reports to the registrar and host, followed until the domain is down."""

from __future__ import annotations

import json
from pathlib import Path

from argus.intel import takedown
from argus.intel.lookalike_triage import WebProfile
from tests.test_brand_watch import _alerts, _cert, _due, _tick, bw  # noqa: F401  (fixture used by name)

RDAP_DOMAIN = json.loads((Path(__file__).parent / "data" / "rdap_domain_lookalike.json").read_text())


def test_a_real_rdap_record_is_read():
    found = takedown.parse_domain_rdap(RDAP_DOMAIN)
    assert found["registrar"] == "PDR Ltd. d/b/a PublicDomainRegistry.com" and found["registrar_iana_id"] == "303"
    assert found["abuse_email"] == "abuse-contact@publicdomainregistry.com" and found["registered"].startswith("2013")


def test_the_letter():
    found = {"registrar": {"registrar": "Registrar Inc", "abuse_email": "Abuse@Registrar.example", "registrar_iana_id": "9"},
             "hosts": [{"ip": "203.0.113.5", "network": "Bullet Hosting", "abuse_email": "abuse@host.example"},
                       {"ip": "203.0.113.6", "network": "Bullet Hosting", "abuse_email": "abuse@host.example"}]}  # fmt: skip
    finding = {"technique": "combosquat", "detail": "brand + 'login'", "not_before": "2026-11-20T00:00:00",
               "issuer": "R11", "link": "https://crt.sh/?id=1", "hosts": ["acmebank-login.com", "www.acmebank-login.com"]}  # fmt: skip
    triage = {"verdict": "phishing", "reasons": ["Serves your favicon", "Shows a password field"],
              "web": {"title": "Sign in", "final_host": "acmebank-login.com"}, "dns": {"ips": ["203.0.113.5"], "mx": []}}  # fmt: skip
    letter = takedown.draft(domain="acmebank-login.com", display="acmebank-login.com", brand="acmebank.com",
                            finding=finding, triage=triage, found=found, organisation="AcmeBank plc")  # fmt: skip
    assert letter["to"] == ["abuse@registrar.example", "abuse@host.example"]  # de-duplicated, lower-cased
    assert letter["subject"] == "Abuse report: acmebank-login.com impersonates acmebank.com (phishing)"
    body = letter["body"]
    assert "a phishing page impersonating AcmeBank plc, whose official domain is acmebank.com" in body
    assert "suspend the domain and remove the content it hosts" in body
    for line in (
        "- Serves your favicon.",
        "- Shows a password field.",
        "First certificate: issued 2026-11-20 by R11",
        "Registrar: Registrar Inc (IANA 9)",
        "Hosting network for 203.0.113.5: Bullet Hosting",
    ):
        assert line in body


def test_down_detection():
    assert takedown.went_down({"verdict": "dormant"}, False, 0) == (True, 1)
    assert takedown.went_down({"verdict": "live", "web": {"reachable": False}}, True, 0) == (False, 1)
    assert takedown.went_down({"verdict": "live", "web": {"reachable": False}}, True, 1) == (True, 2)
    assert takedown.went_down({"verdict": "live", "web": {"reachable": True, "status": 200}}, True, 1) == (False, 0)
    assert takedown.went_down({"verdict": "live", "web": {"reachable": True, "status": 404}}, True, 1) == (True, 2)
    assert takedown.went_down({"verdict": "live"}, False, 0) == (False, 0)  # no web check: only DNS can tell


def test_draft_report_and_follow_until_down(bw):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert("acmebank-login.com", days_ago=1)]
    state["web"]["acmebank-login.com"] = WebProfile(True, 200, "acmebank-login.com", "Sign in", True, "f" * 64)
    lookups = []

    async def fake_contacts(domain, ips):
        lookups.append((domain, ips))
        return {"registrar": {"registrar": "Registrar Inc", "abuse_email": "abuse@registrar.example"},
                "hosts": [{"ip": ips[0], "network": "Bullet Hosting", "abuse_email": "abuse@host.example"}]}  # fmt: skip

    c.app.state.brand_watcher.takedown_contacts = fake_contacts
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com", "web_check": "direct"}).json()
    _tick(c)
    url = f"/api/brand-watches/{watch['id']}/takedowns"
    assert c.post(url, json={"domain": "nope.example"}).status_code == 404
    record = c.post(url, json={"domain": "acmebank-login.com", "organisation": "AcmeBank plc"}).json()
    assert record["status"] == "drafted" and lookups == [("acmebank-login.com", ["203.0.113.5"])]
    assert record["draft"]["to"] == ["abuse@registrar.example", "abuse@host.example"]
    assert "Shows a password field" in record["draft"]["body"] and "AcmeBank plc" in record["draft"]["body"]
    assert c.post(url, json={"domain": "acmebank-login.com"}).status_code == 409  # one open takedown per domain
    reported = c.post(f"{url}/acmebank-login.com/reported").json()
    assert reported["status"] == "reported" and reported["reported_at"]

    # Still up: nothing changes. Then the site disappears: one miss, a second miss -> down.
    _due(c, watch["id"])
    _tick(c)
    assert c.get("/api/brand-watches").json()[0]["takedowns"]["acmebank-login.com"]["status"] == "reported"
    state["web"]["acmebank-login.com"] = WebProfile(False, error="ClientConnectorError")
    for _ in range(2):
        _due(c, watch["id"])
        _tick(c)
    record = c.get("/api/brand-watches").json()[0]["takedowns"]["acmebank-login.com"]
    assert record["status"] == "down" and record["down_at"]
    assert [h["event"] for h in record["history"]][:2] == ["drafted", "reported"] and record["history"][-1][
        "event"
    ] == "down"
    latest = _alerts(c)[0]
    assert latest["severity"] == "low" and latest["headline"].startswith("Taken down: acmebank-login.com")
    assert c.post(f"{url}/acmebank-login.com/reported").status_code == 409
    actions = {e["action"] for e in c.get("/api/audit?limit=100").json()}
    assert {"takedown.draft", "takedown.reported"} <= actions


def test_close_and_access(bw):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert("acmebank-login.com", days_ago=1)]

    async def fake_contacts(domain, ips):
        return {"registrar": {}, "hosts": []}

    c.app.state.brand_watcher.takedown_contacts = fake_contacts
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com"}).json()
    _tick(c)
    url = f"/api/brand-watches/{watch['id']}/takedowns"
    record = c.post(url, json={"domain": "acmebank-login.com"}).json()
    assert record["draft"]["to"] == [] and "suspend the domain." in record["draft"]["body"]
    assert "a domain impersonating acmebank.com. It is not ours" in record["draft"]["body"]
    assert record["draft"]["body"].endswith("[Your name, organisation and how to reach you]")
    viewer = c.post("/api/keys", json={"name": "reader", "role": "viewer"}).json()["key"]
    assert (
        c.post(f"{url}/acmebank-login.com/close", json={}, headers={"Authorization": f"Bearer {viewer}"}).status_code
        == 403
    )
    closed = c.post(f"{url}/acmebank-login.com/close", json={"reason": "Handled by our legal team"}).json()
    assert closed["status"] == "closed" and closed["close_reason"] == "Handled by our legal team"
    assert c.post(f"{url}/other.example/reported").status_code == 404
    c.post("/api/workspaces", json={"id": "red-team", "name": "Red team"})
    assert (
        c.post(url, json={"domain": "acmebank-login.com"}, headers={"X-Argus-Workspace": "red-team"}).status_code == 404
    )
