"""Phase 63: on-demand Shodan pivots for fingerprints."""

from __future__ import annotations

import json
from typing import Any

import pytest

from argus.demo import DEMO_ID
from argus.intel import internet_search
from argus.intel.internet_search import SearchError, rarity

KEY = "shodan-test-key-0123456789abcdef"
COUNT = {"total": 12, "facets": {"org": [{"value": "Bad Hosting Ltd", "count": 9}],
                                 "country": [{"value": "NL", "count": 7}]}}  # fmt: skip
SEARCH = {
    "total": 12,
    "matches": [
        {"ip_str": "198.51.100.7", "port": 443, "transport": "tcp", "hostnames": ["c2.bad.example"], "org": "Bad Hosting",
         "asn": "AS64500", "location": {"country_name": "Netherlands", "city": "Amsterdam"}, "product": "nginx",
         "version": "1.25.3", "timestamp": "2026-11-01T10:00:00.000000"},
    ],
}  # fmt: skip


@pytest.fixture
def shodan_client(make_client, monkeypatch):
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake_get(http, path, params):
        calls.append((path, params))
        return COUNT if path.endswith("/count") else SEARCH

    monkeypatch.setattr(internet_search, "_get", fake_get)
    client = make_client(shodan_api_key=KEY, monitors_enabled="false")
    client.post("/api/demo")
    return client, calls


def _entity_id(client, prefix):
    graph = client.get(f"/api/investigation/{DEMO_ID}/graph").json()["elements"]
    return next(e["data"]["id"] for e in graph if e["group"] == "nodes" and e["data"]["value"].startswith(prefix))


def test_status(make_client, shodan_client):
    client, _ = shodan_client
    assert client.get("/api/internet-search").json() == {"shodan": True, "censys": False}


def test_count_is_free_and_rates_the_fingerprint(shodan_client):
    client, calls = shodan_client
    jarm_id = _entity_id(client, "jarm:")
    result = client.post(f"/api/investigation/{DEMO_ID}/internet-search", json={"entity_id": jarm_id}).json()
    assert result["mode"] == "count" and result["total"] == 12 and result["hosts"] == []
    assert result["rarity"]["level"] == "rare"
    assert result["top_orgs"] == [{"value": "Bad Hosting Ltd", "count": 9}]
    path, params = calls[-1]
    assert path == "/shodan/host/count" and params["query"].startswith("ssl.jarm:") and params["key"] == KEY
    audit = [e for e in client.get("/api/audit").json() if e["action"] == "investigation.internet_search"]
    assert audit and audit[0]["details"]["mode"] == "count" and KEY not in json.dumps(audit)


def test_search_lists_hosts(shodan_client):
    client, calls = shodan_client
    favicon_id = _entity_id(client, "favicon:")
    result = client.post(f"/api/investigation/{DEMO_ID}/internet-search",
                         json={"entity_id": favicon_id, "mode": "search"}).json()  # fmt: skip
    assert calls[-1][0] == "/shodan/host/search" and calls[-1][1]["query"].startswith("http.favicon.hash:")
    (host,) = result["hosts"]
    assert host == {"ip": "198.51.100.7", "port": 443, "transport": "tcp", "hostnames": ["c2.bad.example"],
                    "domains": [], "org": "Bad Hosting", "asn": "AS64500", "country": "Netherlands",
                    "city": "Amsterdam", "product": "nginx 1.25.3", "seen": "2026-11-01"}  # fmt: skip


def test_refusals(shodan_client, make_client):
    client, _ = shodan_client
    url = f"/api/investigation/{DEMO_ID}/internet-search"
    seed = _entity_id(client, "acme-corp.example")
    assert client.post(url, json={"entity_id": seed}).status_code == 422  # nothing to search for
    assert client.post(url, json={"entity_id": "generic_nope"}).status_code == 404
    assert client.post(url, json={"entity_id": seed, "mode": "everything"}).status_code == 422
    assert client.post("/api/investigation/inv_missing/internet-search", json={"entity_id": seed}).status_code == 404


def test_without_a_key(make_client):
    client = make_client(monitors_enabled="false")
    client.post("/api/demo")
    assert client.get("/api/internet-search").json() == {"shodan": False, "censys": False}
    jarm_id = _entity_id(client, "jarm:")
    response = client.post(f"/api/investigation/{DEMO_ID}/internet-search", json={"entity_id": jarm_id})
    assert response.status_code == 409 and "ARGUS_SHODAN_API_KEY" in response.json()["detail"]


@pytest.mark.parametrize(
    "total, level", [(0, "unique"), (1, "unique"), (12, "rare"), (50, "rare"), (51, "uncommon"), (5001, "common")]
)
def test_rarity(total, level):
    assert rarity(total)["level"] == level


class _Response:
    def __init__(self, status, body):
        self.status, self._body = status, body

    async def json(self, content_type=None):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Http:
    def __init__(self, status, body):
        self.response = _Response(status, body)
        self.seen: list[str] = []

    def get(self, url, params=None):
        self.seen.append(url)
        return self.response


@pytest.mark.parametrize(
    "status, body, expected",
    [(401, {}, 409), (402, {}, 402), (403, {}, 402), (429, {}, 429), (500, {}, 502), (200, {"error": "bad"}, 502),
     (200, ["not", "a", "dict"], 502)],
)  # fmt: skip
async def test_errors_are_explained_without_the_key(status, body, expected):
    with pytest.raises(SearchError) as info:
        await internet_search.shodan(_Http(status, body), KEY, "ssl.jarm:x", mode="count")
    assert info.value.status == expected and KEY not in info.value.detail


async def test_real_request_shape():
    http = _Http(200, COUNT)
    result = await internet_search.shodan(http, KEY, "ssh.hassh:abc", mode="count")
    assert http.seen == ["https://api.shodan.io/shodan/host/count"] and result["total"] == 12


# ----------------------------------------------------------------------------- Censys Platform
TOKEN = "censys-test-token-0123456789abcdef"
AGG_ORGS = {"result": {"total_count": 3, "other_count": 0, "query_duration_millis": 5, "is_more_than_total_hits": False,
                       "buckets": [{"key": "Bad Hosting Ltd", "count": 3}]}}  # fmt: skip
AGG_COUNTRIES = {
    "result": {"total_count": 3, "buckets": [{"key": "Netherlands", "count": 2}, {"key": "Germany", "count": 1}]}
}
QUERY = {
    "result": {
        "total_hits": 2.0, "next_page_token": "", "previous_page_token": "", "query_duration_millis": 9,
        "hits": [
            {"host_v1": {"resource": {"ip": "198.51.100.9", "dns": {"names": ["c2.bad.example"]},
                                      "autonomous_system": {"asn": 64500, "name": "Bad Hosting Ltd"},
                                      "location": {"country": "Netherlands", "city": "Amsterdam"}},
                         "matched_services": [{"port": 8443, "protocol": "HTTP", "transport_protocol": "tcp"}]}},
            {"certificate_v1": {"resource": {"fingerprint_sha256": "ab"}}},  # not a server: skipped
        ],
    }
}  # fmt: skip


class _Post:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls: list[dict] = []

    def post(self, url, params=None, json=None, headers=None):
        self.calls.append({"url": url, "params": params, "json": json, "headers": headers})
        status, body = self.answers.pop(0)
        return _Response(status, body)


async def test_censys_count_uses_aggregates():
    http = _Post([(200, AGG_ORGS), (200, AGG_COUNTRIES)])
    query = 'host.services.jarm.fingerprint = "abc"'
    result = await internet_search.censys(http, TOKEN, query, mode="count", organization="org-uuid")
    assert [c["url"] for c in http.calls] == ["https://api.platform.censys.io/v3/global/search/aggregate"] * 2
    first = http.calls[0]
    assert first["headers"]["Authorization"] == f"Bearer {TOKEN}" and first["params"] == {"organization_id": "org-uuid"}
    assert first["json"] == {"query": query, "field": "host.autonomous_system.name", "number_of_buckets": 5}
    assert http.calls[1]["json"]["field"] == "host.location.country"
    assert result["engine"] == "censys" and result["total"] == 3 and result["rarity"]["level"] == "rare"
    assert result["top_orgs"] == [{"value": "Bad Hosting Ltd", "count": 3}]
    assert result["top_countries"][0] == {"value": "Netherlands", "count": 2}


async def test_censys_search_lists_hosts():
    http = _Post([(200, QUERY)])
    result = await internet_search.censys(http, TOKEN, "q", mode="search")
    call = http.calls[0]
    assert call["url"] == "https://api.platform.censys.io/v3/global/search/query" and call["params"] is None
    assert call["json"]["page_size"] == 100 and "host.services.port" in call["json"]["fields"]
    assert result["total"] == 2
    assert result["hosts"] == [{"ip": "198.51.100.9", "port": 8443, "transport": "tcp", "hostnames": ["c2.bad.example"],
                                "domains": [], "org": "Bad Hosting Ltd", "asn": "AS64500", "country": "Netherlands",
                                "city": "Amsterdam", "product": "HTTP", "seen": None}]  # fmt: skip


@pytest.mark.parametrize(
    "status, body, expected",
    [
        (401, {}, 409),
        (403, {}, 402),
        (422, {}, 502),
        (400, {}, 502),
        (429, {}, 429),
        (500, {}, 502),
        (200, {"x": 1}, 502),
    ],
)
async def test_censys_errors_are_explained_without_the_token(status, body, expected):
    with pytest.raises(SearchError) as info:
        await internet_search.censys(_Post([(status, body)]), TOKEN, "q", mode="search")
    assert info.value.status == expected and TOKEN not in info.value.detail


def test_censys_through_the_api(make_client, monkeypatch):
    sent = []

    async def fake_post(http, token, organization, path, body):
        sent.append((token, organization, path, body))
        return AGG_ORGS["result"] if path.endswith("aggregate") else QUERY["result"]

    monkeypatch.setattr(internet_search, "_censys_post", fake_post)
    client = make_client(censys_api_token=TOKEN, censys_organization_id="org-uuid", monitors_enabled="false")
    client.post("/api/demo")
    assert client.get("/api/internet-search").json() == {"shodan": False, "censys": True}
    jarm_id = _entity_id(client, "jarm:")
    url = f"/api/investigation/{DEMO_ID}/internet-search"
    counted = client.post(url, json={"entity_id": jarm_id, "engine": "censys"}).json()
    assert counted["engine"] == "censys" and counted["total"] == 3
    token, organization, _, body = sent[0]
    assert (
        token == TOKEN and organization == "org-uuid" and body["query"].startswith("host.services.jarm.fingerprint = ")
    )
    listed = client.post(url, json={"entity_id": jarm_id, "engine": "censys", "mode": "search"}).json()
    assert listed["hosts"][0]["ip"] == "198.51.100.9"
    favicon_id = _entity_id(client, "favicon:")
    assert client.post(url, json={"entity_id": favicon_id, "engine": "censys"}).status_code == 200
    shodan = client.post(url, json={"entity_id": jarm_id, "engine": "shodan"})
    assert shodan.status_code == 409 and "ARGUS_SHODAN_API_KEY" in shodan.json()["detail"]
    audit = [e for e in client.get("/api/audit").json() if e["action"] == "investigation.internet_search"]
    assert {e["details"]["engine"] for e in audit} == {"censys"} and TOKEN not in json.dumps(audit)
