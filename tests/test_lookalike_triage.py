"""Phase 74: lookalike triage — which lookalikes are a threat now."""

from __future__ import annotations

from argus.intel.lookalike_triage import WebProfile, dns_verdict, judge
from tests.test_brand_watch import _alerts, _cert, _due, _tick, bw  # noqa: F401  (fixture used by name)

OWN = {"ns": {"acmebank.com"}, "ips": {"192.0.2.10"}, "title": "AcmeBank | Online banking", "favicon_sha256": "f" * 64}
LIVE = {"ips": ["203.0.113.5"], "ns": ["ns1.cheap-host.example"], "mx": []}


def test_judgement():
    def j(dns, web=None, base="medium", sensitive=False):
        return judge(base, "acmebank", dns, OWN, web, sensitive=sensitive)

    assert j(None).verdict == "dormant" and j(None, base="high").severity == "medium"
    assert j({"ips": ["192.0.2.10"], "ns": [], "mx": []}).verdict == "yours"
    assert j({"ips": [], "ns": ["ns1.acmebank.com"], "mx": []}).verdict == "yours"
    parked = j({"ips": ["198.51.100.1"], "ns": ["ns1.sedoparking.com"], "mx": []}, base="high")
    assert (parked.verdict, parked.severity) == ("parked", "low")
    mail = j({**LIVE, "mx": ["mx.evil.example"]}, sensitive=True)
    assert (mail.verdict, mail.severity) == ("mail", "high") and "MX" in mail.reasons[0]
    phishing = j(LIVE, WebProfile(True, 200, "acmebank-login.com", "Sign in", True, "f" * 64))
    assert (phishing.verdict, phishing.severity) == ("phishing", "critical")
    assert "Serves your favicon" in phishing.reasons and "Shows a password field" in phishing.reasons
    clone = j(LIVE, WebProfile(True, 200, "x", "AcmeBank | Online banking", False, ""))
    assert (clone.verdict, clone.severity) == ("clone", "high")
    by_title = j(LIVE, WebProfile(True, 200, "x", "Acme Bank - secure login", True, ""))
    assert by_title.verdict == "phishing"  # the brand in the title, with a password field
    plain = j(LIVE, WebProfile(True, 200, "x", "Welcome to nginx", False, ""))
    assert plain.verdict == "live" and plain.severity == "medium"
    down = j(LIVE, WebProfile(False, error="ClientConnectorError"))
    assert down.verdict == "suspicious" and down.reasons == ["Website did not answer (ClientConnectorError)"]
    assert dns_verdict({"ns": ["ns2.parkingcrew.net"]}, set(), set()) == "parked"


def test_shared_providers_are_not_proof_of_ownership():
    # The brand on Cloudflare; a phishing site on Cloudflare shares its name servers and an anycast address.
    on_cloudflare = {"cloudflare.com"}
    phish = {"ips": ["104.16.1.1"], "ns": ["kim.ns.cloudflare.com"], "mx": []}
    assert dns_verdict(phish, on_cloudflare, {"104.16.1.1"}) == "suspicious"
    assert dns_verdict({"ips": [], "ns": ["ns-12.awsdns-01.com"], "mx": []}, {"awsdns-01.com"}, set()) == "suspicious"
    # The brand's own name servers, or an address behind its own name servers: yours.
    assert dns_verdict({"ips": [], "ns": ["ns1.acmebank.com"], "mx": []}, {"acmebank.com"}, set()) == "yours"
    assert dns_verdict({"ips": ["192.0.2.10"], "ns": [], "mx": []}, {"acmebank.com"}, {"192.0.2.10"}) == "yours"


def test_web_check_is_off_unless_chosen(bw):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert("acmebank-login.com", days_ago=1)]
    c.post("/api/brand-watches", json={"domain": "acmebank.com"})
    _tick(c)
    assert state["web_calls"] == []  # nobody visited the lookalike
    (watch,) = c.get("/api/brand-watches").json()
    assert (watch["web_check"] == "off" and watch["recent"][0]["triage"]["verdict"] == "live") or watch["recent"][0][
        "triage"
    ]["verdict"] == "suspicious"
    assert c.post("/api/brand-watches", json={"domain": "other.com", "web_check": "tor-nonexistent"}).status_code == 422
    assert c.patch(f"/api/brand-watches/{watch['id']}", json={"web_check": "direct"}).json()["web_check"] == "direct"


def test_phishing_is_critical_and_escalations_alert(bw):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert("acmebank-login.com", days_ago=2), _cert("acmebank-pay.net", days_ago=400),
                        _cert("acmebank-mine.org", days_ago=1)]  # fmt: skip
    state["web"]["acmebank-login.com"] = WebProfile(True, 200, "acmebank-login.com", "Sign in", True, "f" * 64)
    state["dns"]["acmebank-pay.net"] = {"ips": ["198.51.100.1"], "ns": ["ns1.sedoparking.com"], "mx": []}
    state["dns"]["acmebank-mine.org"] = {"ips": ["192.0.2.10"], "ns": ["ns1.acmebank.com"], "mx": []}
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com", "web_check": "direct"}).json()
    _tick(c)
    (alert,) = _alerts(c)
    assert alert["severity"] == "critical" and alert["headline"].startswith(
        "Active phishing page imitating acmebank.com"
    )
    found = alert["summary"]["brand_watch"]["findings"]
    assert [f["name"] for f in found] == ["acmebank-login.com"]  # parked is old news; "yours" is never reported
    assert found[0]["verdict"] == "phishing" and "Shows a password field" in found[0]["reasons"]
    listed = {f["name"]: f for f in c.get("/api/brand-watches").json()[0]["recent"]}
    assert listed["acmebank-mine.org"]["triage"]["verdict"] == "yours"
    assert listed["acmebank-pay.net"]["triage"]["verdict"] == "parked"

    # The parked domain goes live with a copy of the bank's site: an escalation alert, though not new.
    state["dns"]["acmebank-pay.net"] = {"ips": ["203.0.113.9"], "ns": ["ns1.bullet-host.example"], "mx": ["mx.x"]}
    state["web"]["acmebank-pay.net"] = WebProfile(True, 200, "acmebank-pay.net", "AcmeBank | Online banking", True, "")
    _due(c, watch["id"])
    _tick(c)
    latest = _alerts(c)[0]
    escalated = latest["summary"]["brand_watch"]["findings"]
    assert [f["name"] for f in escalated] == ["acmebank-pay.net"]
    assert escalated[0]["escalated_from"] == "parked" and escalated[0]["verdict"] == "phishing"
    assert "Active phishing page" in latest["headline"]
    # The same state again: no further alert.
    _due(c, watch["id"])
    _tick(c)
    assert len(_alerts(c)) == 2
