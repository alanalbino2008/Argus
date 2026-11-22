"""Phase 73: a read-only TAXII 2.1 server — tagged entities, lookalikes and watched servers as STIX."""

from __future__ import annotations

import base64
import contextlib

import pytest
import stix2

from argus.core.models import EntityType, generate_entity_id
from argus.intel import brand_watch, fingerprint_watch, internet_search, taxii
from argus.intel.brand_watch import Certificate
from tests.test_internet_search import KEY, _entity_id

TAXII = "application/taxii+json;version=2.1"
RED = {"X-Argus-Workspace": "red-team"}
C2 = generate_entity_id(EntityType.DOMAIN, "evil-c2.example")


@pytest.fixture
def tc(make_client, monkeypatch):
    async def fake_get(http, path, params):
        return {"total": 2, "matches": [{"ip_str": "198.51.100.7", "port": 443}, {"ip_str": "2001:db8::5", "port": 22}]}

    async def fake_crtsh(http, brand):
        return [
            Certificate(("acme-corp-login.com", "www.acme-corp-login.com"), "R11", "2026-11-20T00:00:00", "x", "crt.sh")
        ]

    async def fake_certspotter(http, name, key):
        return []

    monkeypatch.setattr(internet_search, "_get", fake_get)
    monkeypatch.setattr(brand_watch, "crtsh", fake_crtsh)
    monkeypatch.setattr(brand_watch, "certspotter", fake_certspotter)
    c = make_client(shodan_api_key=KEY, monitors_enabled="false")
    c.post("/api/demo")
    for watcher in (c.app.state.fingerprint_watcher, c.app.state.brand_watcher):
        watcher.kick = lambda: None
    c.app.state.brand_watcher.http_factory = contextlib.nullcontext

    async def fake_dns(name):  # no real DNS in tests: the brand on its own servers, lookalikes elsewhere
        if name == "acme-corp.com":
            return {"ips": ["192.0.2.10"], "ns": ["ns1.acme-corp.com"], "mx": []}
        return {"ips": ["203.0.113.5"], "ns": ["ns1.cheap-host.example"], "mx": []}

    c.app.state.brand_watcher.dns_lookup = fake_dns
    viewer = c.post("/api/keys", json={"name": "siem", "role": "viewer"}).json()["key"]
    return c, viewer


def _basic(key):
    return {"Authorization": "Basic " + base64.b64encode(f"opencti:{key}".encode()).decode()}


def _fill(c):
    put = lambda eid, kind, value, tags, note="": c.put(f"/api/annotations/{eid}", json={  # noqa: E731
        "entity_type": kind, "value": value, "tags": tags, "note": note})  # fmt: skip
    put(C2, "domain", "evil-c2.example", ["c2", "apt-x"], "Beacon seen on the VPN")
    put(generate_entity_id(EntityType.IP_ADDRESS, "203.0.113.66"), "ip_address", "203.0.113.66", ["c2"])
    put(generate_entity_id(EntityType.PERSON, "Jane Roe"), "person", "Jane Roe", ["suspect"])  # not an observable
    put(generate_entity_id(EntityType.EMAIL, "odd'name@x.example"), "email", "odd'name@x.example", ["phish"])
    c.post(
        "/api/fingerprint-watches", json={"investigation_id": "inv_demo_acme", "entity_id": _entity_id(c, "favicon:")}
    )
    c.portal.call(c.app.state.fingerprint_watcher.tick)
    c.post("/api/brand-watches", json={"domain": "acme-corp.com"})
    c.portal.call(c.app.state.brand_watcher.tick)


def test_discovery_collections_and_objects(tc):
    c, viewer = tc
    _fill(c)
    headers = {**_basic(viewer), "Accept": TAXII}
    found = c.get("/taxii2/", headers=headers)
    assert found.status_code == 200 and found.headers["content-type"].startswith("application/taxii+json")
    root = found.json()["default"]
    assert root.endswith("/taxii2/ws_default/") and c.get("/taxii2/ws_default/", headers=headers).json()[
        "versions"
    ] == [TAXII]
    cols = c.get("/taxii2/ws_default/collections/", headers=headers).json()["collections"]
    assert {x["alias"] for x in cols} == {"tagged", "lookalikes", "fingerprint-servers", "campaigns"}
    assert all(x["can_read"] and not x["can_write"] for x in cols)
    by_alias = {x["alias"]: x["id"] for x in cols}
    assert (
        c.get(f"/taxii2/ws_default/collections/{by_alias['tagged']}/", headers=headers).json()["title"]
        == "Tagged entities"
    )

    def objects(alias, **params):
        r = c.get(f"/taxii2/ws_default/collections/{by_alias[alias]}/objects/", headers=headers, params=params)
        assert r.status_code == 200, r.text
        return r

    tagged = objects("tagged").json()
    indicators = [o for o in tagged["objects"] if o["type"] == "indicator"]
    for o in tagged["objects"]:
        stix2.parse(o, allow_custom=False)  # valid STIX 2.1, patterns included
    by_name = {o["name"]: o for o in indicators}
    assert set(by_name) == {"evil-c2.example", "203.0.113.66", "odd'name@x.example"}  # people are not indicators
    c2 = by_name["evil-c2.example"]
    assert c2["pattern"] == "[domain-name:value = 'evil-c2.example']" and c2["labels"] == ["c2", "apt-x"]
    assert c2["description"] == "Beacon seen on the VPN" and c2["object_marking_refs"]
    assert by_name["odd'name@x.example"]["pattern"] == "[email-addr:value = 'odd\\'name@x.example']"

    servers = [o for o in objects("fingerprint-servers").json()["objects"] if o["type"] == "indicator"]
    assert {o["name"] for o in servers} == {"198.51.100.7:443", "[2001:db8::5]:22"}
    for o in servers:
        stix2.parse(o)
        assert "network-traffic:dst_port" in o["pattern"] and "fingerprint-watch" in o["labels"]
    lookalikes = [o for o in objects("lookalikes").json()["objects"] if o["type"] == "indicator"]
    (lookalike,) = lookalikes
    stix2.parse(lookalike)
    assert lookalike["pattern"] == "[domain-name:value = 'acme-corp-login.com']"
    assert "brand:acme-corp.com" in lookalike["labels"] and lookalike["indicator_types"] == ["malicious-activity"]

    # Stable ids, a single object, and the manifest.
    assert [o["id"] for o in objects("tagged").json()["objects"]] == [o["id"] for o in tagged["objects"]]
    one = c.get(f"/taxii2/ws_default/collections/tagged/objects/{c2['id']}/", headers=headers).json()
    assert one["objects"][0]["id"] == c2["id"]
    manifest = c.get(f"/taxii2/ws_default/collections/{by_alias['tagged']}/manifest/", headers=headers).json()
    assert {m["id"] for m in manifest["objects"]} == {o["id"] for o in tagged["objects"]}
    assert {e["action"] for e in c.get("/api/audit?limit=100").json()} >= {"taxii.read"}


def test_paging_and_incremental_pulls(tc):
    c, viewer = tc
    _fill(c)
    url = "/taxii2/ws_default/collections/tagged/objects/"
    first = c.get(url, headers=_basic(viewer), params={"limit": 2})
    body = first.json()
    assert body["more"] and len(body["objects"]) == 2  # the limit counts every object
    assert body["objects"][0]["type"] == "identity"  # the oldest: who made the indicators
    rest = c.get(url, headers=_basic(viewer), params={"limit": 2, "next": body["next"]}).json()
    assert not rest["more"] and len(rest["objects"]) == 2
    last = first.headers["X-TAXII-Date-Added-Last"]
    later = c.get(url, headers=_basic(viewer), params={"added_after": last}).json()
    assert len(later["objects"]) == 2  # only what came after the first page
    newest = c.get(url, headers=_basic(viewer), params={"added_after": "2999-01-01T00:00:00Z"}).json()
    assert len(c.get(url, headers=_basic(viewer)).json()["objects"]) == 4  # 3 indicators and the identity
    assert newest == {"more": False, "objects": []}
    assert c.get(url, headers=_basic(viewer), params={"next": "!!"}).status_code == 400
    typed = c.get(url, headers=_basic(viewer), params={"match[type]": "identity"}).json()
    assert [o["type"] for o in typed["objects"]] == ["identity"]


def test_access(tc):
    c, viewer = tc
    _fill(c)
    assert c.get("/taxii2/ws_default/collections/", headers={"Authorization": "Basic Zm9vOmJhcg=="}).status_code == 401
    assert c.get("/taxii2/ws_default/collections/", headers={"Authorization": "Basic !!"}).status_code == 401
    assert c.get("/taxii2/ws_default/", headers={**_basic(viewer), "Accept": "text/html"}).status_code == 406
    assert c.get("/taxii2/ws_default/collections/nope/objects/", headers=_basic(viewer)).json()["http_status"] == "404"
    # Another team: its own empty root; it cannot read ours.
    c.post("/api/workspaces", json={"id": "red-team", "name": "Red team"})
    red = c.post("/api/keys", json={"name": "red-siem", "role": "viewer"}, headers=RED).json()["key"]
    roots = c.get("/taxii2/", headers=_basic(red)).json()["api_roots"]
    assert [r.rsplit("/taxii2/", 1)[1] for r in roots] == [roots[0].rsplit("/taxii2/", 1)[1]]
    assert "ws_default" not in roots[0]
    assert c.get("/taxii2/ws_default/collections/", headers=_basic(red)).status_code == 404
    red_root = roots[0].rsplit("/taxii2/", 1)[1]
    red_objects = c.get(f"/taxii2/{red_root}collections/tagged/objects/", headers=_basic(red)).json()
    assert red_objects == {"more": False, "objects": []}


def test_patterns():
    assert taxii.pattern_for("ip_address", "10.0.0.1") == "[ipv4-addr:value = '10.0.0.1']"
    assert taxii.pattern_for("ip_address", "2001:db8::1") == "[ipv6-addr:value = '2001:db8::1']"
    assert taxii.pattern_for("ip_address", "nope") is None
    assert taxii.pattern_for("url", "ftp://x") is None and taxii.pattern_for("person", "x") is None
    assert taxii.pattern_for("domain", "Evil\\.Example") == "[domain-name:value = 'evil\\\\.example']"
    assert fingerprint_watch.server_key({"ip": "2001:db8::5", "port": 22}) == "[2001:db8::5]:22"
    assert taxii.split_server("[2001:db8::5]:22") == ("2001:db8::5", "22")
    assert taxii.split_server("198.51.100.7:443") == ("198.51.100.7", "443")
    assert taxii.split_server("2001:db8::5") == ("2001:db8::5", "")


def test_the_workspace_slug_works_too(tc):
    c, viewer = tc
    slug = c.get("/api/workspaces").json()[0]["slug"]
    assert c.get(f"/taxii2/{slug}/collections/", headers=_basic(viewer)).status_code == 200
