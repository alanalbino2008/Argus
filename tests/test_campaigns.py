"""Phase 76: campaigns — lookalikes, watched servers and tagged indicators sharing infrastructure."""

from __future__ import annotations

from argus.core.models import EntityType, generate_entity_id
from argus.intel.campaigns import cluster, distinctive_ip, distinctive_title
from argus.intel.lookalike_triage import WebProfile
from tests.test_brand_watch import _cert, _tick, bw  # noqa: F401  (fixture used by name)


def _look(name, ips=(), ns=(), mx=(), favicon="", title="", severity="high", verdict="live"):
    return {"name": name, "display": name, "brand": "acmebank.com", "severity": severity, "verdict": verdict,
            "first_seen": "2026-11-20T00:00:00+00:00",
            "triage": {"dns": {"ips": list(ips), "ns": list(ns), "mx": list(mx)},
                       "web": {"favicon_sha256": favicon, "title": title}}}  # fmt: skip


def test_shared_infrastructure_makes_a_campaign():
    lookalikes = [
        _look(
            "acmebank-login.com",
            ips=["45.77.10.5"],
            ns=["ns1.bulletdns.example"],
            severity="critical",
            verdict="phishing",
        ),
        _look("acmebank-secure.net", ips=["45.77.10.5"]),  # same server
        _look("acrnebank.com", ns=["ns2.bulletdns.example"]),  # same private name servers
        _look("acmebank-pay.org", favicon="a" * 64),  # same favicon as a fingerprint-watch server? no: as below
        _look("acmebank-help.co", favicon="a" * 64),
        _look("lonely-acmebank.com", ips=["198.51.100.77"]),  # shares nothing
    ]
    servers = [{"server": "45.77.10.5:443", "watch_id": "fpw_1", "label": "favicon Favicon -1", "first_seen": "2026-11-21"},
               {"server": "[2001:db8::5]:22", "watch_id": "fpw_1", "label": "favicon Favicon -1", "first_seen": "2026-11-21"}]  # fmt: skip
    tagged = [{"value": "45.77.10.5", "entity_type": "ip_address", "tags": ["c2"], "updated_at": "2026-11-19"}]
    campaigns = cluster(lookalikes, servers, tagged)
    assert len(campaigns) == 2
    big, small = campaigns
    assert big["severity"] == "critical" and big["size"] == 5
    assert {m["value"] for m in big["members"]} == {"acmebank-login.com", "acmebank-secure.net", "acrnebank.com",
                                                     "45.77.10.5", "2001:db8::5"}  # fmt: skip
    kinds = {(link["type"], link["value"]) for link in big["links"]}
    assert ("ip", "45.77.10.5") in kinds and ("ns", "bulletdns.example") in kinds
    assert ("fingerprint", "favicon Favicon -1") in kinds  # the watch is named, not its id
    server = next(m for m in big["members"] if m["value"] == "45.77.10.5")
    assert server["tags"] == ["c2"] and server["kind"] == "server"
    assert big["links"][0]["type"] == "fingerprint"  # strongest evidence first
    assert {m["value"] for m in small["members"]} == {"acmebank-pay.org", "acmebank-help.co"}
    assert small["links"][0]["type"] == "favicon" and big["id"] != small["id"]
    assert small["name"] == f"Favicon: sha256 {'a' * 12}…"  # hashes shortened
    assert big["name"] == "IP address: 45.77.10.5"  # named after the most readable evidence
    assert cluster(lookalikes, servers, tagged)[0]["id"] == big["id"]  # stable ids


def test_shared_providers_never_link():
    lookalikes = [
        _look("a-acmebank.com", ips=["104.16.1.1"], ns=["kim.ns.cloudflare.com"], mx=["aspmx.l.google.com"], title="Just a moment..."),
        _look("b-acmebank.com", ips=["104.16.1.1"], ns=["bob.ns.cloudflare.com"], mx=["alt1.aspmx.l.google.com"], title="Just a moment..."),
        _look("c-acmebank.com", ns=["ns-1.awsdns-01.com"], title="Welcome to nginx!"),
        _look("d-acmebank.com", ns=["ns-2.awsdns-01.com"], title="Welcome to nginx!"),
    ]  # fmt: skip
    assert cluster(lookalikes, [], []) == []
    assert not distinctive_ip("151.101.3.1") and not distinctive_ip("10.1.2.3") and distinctive_ip("208.91.196.152")
    assert distinctive_title("Index of /") is None and distinctive_title("AcmeBank | Online banking")


def test_campaigns_from_the_watches(bw):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert("acmebank-login.com"), _cert("acmebank-verify.net"), _cert("acmebank-other.org")]
    for name in ("acmebank-login.com", "acmebank-verify.net"):
        state["dns"][name] = {"ips": ["45.77.10.50"], "ns": ["ns1.evil-dns.example"], "mx": []}
    state["dns"]["acmebank-other.org"] = {"ips": ["198.51.100.9"], "ns": ["ns1.elsewhere.example"], "mx": []}
    state["web"]["acmebank-login.com"] = WebProfile(True, 200, "acmebank-login.com", "Sign in", True, "f" * 64)
    c.post("/api/brand-watches", json={"domain": "acmebank.com", "web_check": "direct"})
    _tick(c)
    tag = generate_entity_id(EntityType.IP_ADDRESS, "45.77.10.50")
    c.put(f"/api/annotations/{tag}", json={"entity_type": "ip_address", "value": "45.77.10.50", "tags": ["c2"]})
    result = c.get("/api/campaigns").json()
    (campaign,) = result["campaigns"]
    assert campaign["severity"] == "critical" and campaign["brands"] == ["acmebank.com"]
    assert {m["value"] for m in campaign["members"]} == {"acmebank-login.com", "acmebank-verify.net", "45.77.10.50"}
    assert campaign["name"].startswith(("IP address", "Name servers"))
    viewer = c.post("/api/keys", json={"name": "reader", "role": "viewer"}).json()["key"]
    assert c.get("/api/campaigns", headers={"Authorization": f"Bearer {viewer}"}).status_code == 200
    c.post("/api/workspaces", json={"id": "red-team", "name": "Red team"})
    assert c.get("/api/campaigns", headers={"X-Argus-Workspace": "red-team"}).json()["campaigns"] == []
