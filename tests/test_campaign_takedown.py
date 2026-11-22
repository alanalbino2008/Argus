"""Phase 77: taking down a whole campaign, and campaigns in the TAXII feed."""

from __future__ import annotations

import stix2

from argus.core.models import EntityType, generate_entity_id
from argus.intel import takedown
from argus.intel.lookalike_triage import WebProfile
from tests.test_brand_watch import _cert, _tick, bw  # noqa: F401  (fixture used by name)
from tests.test_taxii import _basic


def _campaign_world(c, state):
    names = ("acmebank-login.com", "acmebank-verify.net", "acrnebank.com")
    state["keyword"] = [_cert("acmebank-login.com"), _cert("acmebank-verify.net")]
    state["exact"]["acrnebank.com"] = [_cert("acrnebank.com", source="Cert Spotter")]
    for name in names:
        state["dns"][name] = {"ips": ["45.77.10.50"], "ns": ["ns1.evil-dns.example"], "mx": []}
    state["web"]["acmebank-login.com"] = WebProfile(True, 200, "acmebank-login.com", "Sign in", True, "f" * 64)

    async def contacts(domain, ips):
        registrar = {"registrar": "Cheap Names", "abuse_email": "abuse@cheapnames.example"} if domain != "acrnebank.com" \
            else {"registrar": "Other Reg", "abuse_email": "abuse@otherreg.example"}  # fmt: skip
        return {
            "registrar": registrar,
            "hosts": [{"ip": ips[0], "network": "Bullet Host", "abuse_email": "abuse@bullet.example"}],
        }

    c.app.state.brand_watcher.takedown_contacts = contacts
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com", "web_check": "direct"}).json()
    for _ in range(40):  # Cert Spotter finds the homoglyph within a cycle
        c.post(f"/api/brand-watches/{watch['id']}/run")
        _tick(c)
        if c.get("/api/brand-watches").json()[0]["known"] == 3:
            break
    (campaign,) = c.get("/api/campaigns").json()["campaigns"]
    return watch, campaign


def test_one_report_per_registrar_and_host(bw):  # noqa: F811
    c, state = bw
    watch, campaign = _campaign_world(c, state)
    assert campaign["size"] == 3
    result = c.post(f"/api/campaigns/{campaign['id']}/takedown", json={"organisation": "AcmeBank plc"}).json()
    by_to = {letter["to"][0]: letter for letter in result["letters"]}
    assert set(by_to) == {"abuse@bullet.example", "abuse@cheapnames.example", "abuse@otherreg.example"}
    host = by_to["abuse@bullet.example"]
    assert sorted(host["domains"]) == ["acmebank-login.com", "acmebank-verify.net", "acrnebank.com"]
    assert host["subject"] == "Abuse report: 3 domains impersonating acmebank.com (phishing)"
    assert "IP address: 45.77.10.50 (3 of them)" in host["body"] and "host (Bullet Host)" in host["body"]
    assert "AcmeBank plc" in host["body"] and "- acmebank-login.com: combosquat; active phishing page" in host["body"]
    assert sorted(by_to["abuse@cheapnames.example"]["domains"]) == ["acmebank-login.com", "acmebank-verify.net"]
    single = by_to["abuse@otherreg.example"]
    assert (
        single["domains"] == ["acrnebank.com"]
        and single["subject"] == "Abuse report: acrnebank.com impersonates acmebank.com"
    )
    assert (
        "It is not ours" in single["body"] and "a group of 3 lookalike domains sharing infrastructure" in single["body"]
    )
    takedowns = c.get("/api/brand-watches").json()[0]["takedowns"]
    assert {n: t["status"] for n, t in takedowns.items()} == dict.fromkeys(host["domains"], "drafted")
    assert all(t["campaign_id"] == campaign["id"] for t in takedowns.values())

    # Again: nothing new is drafted, the same reports come back.
    again = c.post(f"/api/campaigns/{campaign['id']}/takedown", json={}).json()
    assert again["drafted"] == [] and sorted(again["already_open"]) == sorted(host["domains"])
    assert {letter["to"][0] for letter in again["letters"]} == set(by_to)
    # Each domain is then reported (and followed) on its own.
    for domain in host["domains"]:
        assert c.post(f"/api/brand-watches/{watch['id']}/takedowns/{domain}/reported").status_code == 200
    assert {e["action"] for e in c.get("/api/audit?limit=100").json()} >= {"takedown.campaign"}


def test_access_and_missing(bw):  # noqa: F811
    c, state = bw
    _watch, campaign = _campaign_world(c, state)
    viewer = c.post("/api/keys", json={"name": "reader", "role": "viewer"}).json()["key"]
    assert c.post(f"/api/campaigns/{campaign['id']}/takedown", json={},
                  headers={"Authorization": f"Bearer {viewer}"}).status_code == 403  # fmt: skip
    assert c.post("/api/campaigns/cmp_nope/takedown", json={}).status_code == 404
    c.post("/api/workspaces", json={"id": "red-team", "name": "Red team"})
    assert c.post(f"/api/campaigns/{campaign['id']}/takedown", json={},
                  headers={"X-Argus-Workspace": "red-team"}).status_code == 404  # fmt: skip


def test_campaigns_in_taxii(bw):  # noqa: F811
    c, state = bw
    _campaign_world(c, state)
    tag = generate_entity_id(EntityType.IP_ADDRESS, "45.77.10.50")
    c.put(f"/api/annotations/{tag}", json={"entity_type": "ip_address", "value": "45.77.10.50", "tags": ["c2"]})
    viewer = c.post("/api/keys", json={"name": "siem", "role": "viewer"}).json()["key"]
    objects = c.get("/taxii2/ws_default/collections/campaigns/objects/", headers=_basic(viewer)).json()["objects"]
    for o in objects:
        stix2.parse(o)
    (camp,) = [o for o in objects if o["type"] == "campaign"]
    rels = [o for o in objects if o["type"] == "relationship"]
    indicators = {o["id"] for o in objects if o["type"] == "indicator"}
    assert len(rels) == 4 and all(r["target_ref"] == camp["id"] and r["relationship_type"] == "indicates" for r in rels)
    assert {r["source_ref"] for r in rels} == indicators  # every relationship points at an included indicator
    lookalike_ids = {o["id"] for o in c.get("/taxii2/ws_default/collections/lookalikes/objects/",
                                             headers=_basic(viewer)).json()["objects"]}  # fmt: skip
    tagged_ids = {
        o["id"]
        for o in c.get("/taxii2/ws_default/collections/tagged/objects/", headers=_basic(viewer)).json()["objects"]
    }
    assert indicators <= lookalike_ids | tagged_ids  # the same ids as the other collections
    assert "brand:acmebank.com" in camp["labels"] and "45.77.10.50" in camp["description"]


def test_letters_without_contacts():
    assert (
        takedown.campaign_letters(
            campaign={"links": []}, domains=[{"domain": "x.example", "found": {}}], organisation=""
        )
        == []
    )
