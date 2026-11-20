"""Internet-wide pivots on demand: who else serves this fingerprint, according to Shodan or Censys.

A fingerprint node (favicon, JARM, HASSH, certificate) carries the Shodan search that finds
every other server with the same fingerprint. With an API key configured, an analyst can run it
from Argus instead of pasting it into Shodan:

* **count** (free: Shodan's ``/count`` endpoint spends no query credits): how many servers share
  the fingerprint, with the top organisations and countries. This is the single most useful fact
  about a shared fingerprint: 12 hosts is a cluster, 1.2 million is a default configuration.
* **search** (spends a Shodan query credit): up to 100 of those servers, with IP, port, host
  names, organisation, country and product.

Always analyst-initiated, never automatic: each search costs money and reaches a third party.
The query is the node's own (not free text), the key never leaves the server or reaches logs,
and every lookup is audited. Results are shown and can each start a new, separately authorised
investigation. They are not written into the scan's record, which stays what the scan saw.
"""

from __future__ import annotations

from typing import Any

from argus.core.http import HttpClient
from argus.security.secrets import register_secret

SHODAN_API = "https://api.shodan.io"
CENSYS_API = "https://api.platform.censys.io"  # the Censys Platform API (v3)
CENSYS_FIELDS = [  # only what Argus shows; the port and protocol fields keep "matched_services" in the answer
    "host.ip", "host.services.port", "host.services.protocol", "host.services.transport_protocol",
    "host.autonomous_system.name", "host.autonomous_system.asn", "host.location.country", "host.location.city",
    "host.dns.names",
]  # fmt: skip
FACETS = "org:5,country:5"
MAX_HOSTS = 100


class SearchError(Exception):
    """A lookup that could not be done, with the HTTP status the API should answer."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def rarity(total: int) -> dict[str, str]:
    """How much a fingerprint shared by ``total`` servers says about who runs them."""
    if total <= 1:
        return {"level": "unique", "meaning": "Only this server: the fingerprint identifies it."}
    if total <= 50:
        return {"level": "rare", "meaning": "A small cluster: a strong lead to the same operator or kit."}
    if total <= 5000:
        return {"level": "uncommon", "meaning": "Shared by a few thousand servers: a lead worth narrowing down."}
    return {"level": "common", "meaning": "A widespread default configuration: says little about who runs it."}


async def _get(http: HttpClient, path: str, params: dict[str, Any]) -> dict[str, Any]:
    async with http.get(f"{SHODAN_API}{path}", params=params) as resp:
        if resp.status == 401:
            raise SearchError(409, "Shodan refused the API key: check ARGUS_SHODAN_API_KEY")
        if resp.status in (402, 403):
            raise SearchError(402, "This Shodan plan cannot run this search (it needs query credits or a paid filter)")
        if resp.status == 429:
            raise SearchError(429, "Shodan is rate-limiting this key: try again in a minute")
        if resp.status != 200:
            raise SearchError(502, f"Shodan answered {resp.status}: try again later")
        data = await resp.json(content_type=None)
    if not isinstance(data, dict):
        raise SearchError(502, "Shodan sent an unexpected answer")
    if data.get("error"):
        raise SearchError(502, f"Shodan: {str(data['error'])[:200]}")
    return data


def _facet(data: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [{"value": f.get("value"), "count": f.get("count")} for f in ((data.get("facets") or {}).get(name) or [])]


def _host(match: dict[str, Any]) -> dict[str, Any]:
    location = match.get("location") or {}
    return {
        "ip": match.get("ip_str"),
        "port": match.get("port"),
        "transport": match.get("transport"),
        "hostnames": (match.get("hostnames") or [])[:5],
        "domains": (match.get("domains") or [])[:5],
        "org": match.get("org"),
        "asn": match.get("asn"),
        "country": location.get("country_name"),
        "city": location.get("city"),
        "product": " ".join(str(p) for p in (match.get("product"), match.get("version")) if p) or None,
        "seen": str(match.get("timestamp") or "")[:10] or None,
    }


async def shodan(http: HttpClient, key: str, query: str, *, mode: str) -> dict[str, Any]:
    """Run ``query`` on Shodan: ``mode`` "count" (free, with facets) or "search" (one query credit)."""
    register_secret(key)  # never in an error message or a log line
    if mode == "count":
        data = await _get(http, "/shodan/host/count", {"key": key, "query": query, "facets": FACETS})
    else:
        data = await _get(http, "/shodan/host/search", {"key": key, "query": query, "facets": FACETS, "minify": "true"})
    total = int(data.get("total") or 0)
    result: dict[str, Any] = {
        "engine": "shodan",
        "mode": mode,
        "query": query,
        "total": total,
        "rarity": rarity(total),
        "top_orgs": _facet(data, "org"),
        "top_countries": _facet(data, "country"),
        "hosts": [_host(m) for m in (data.get("matches") or [])[:MAX_HOSTS]] if mode == "search" else [],
    }
    return result


# ----------------------------------------------------------------------------- Censys Platform
async def _censys_post(http: HttpClient, token: str, organization: str | None, path: str, body: dict[str, Any]) -> Any:
    params = {"organization_id": organization} if organization else None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    async with http.post(f"{CENSYS_API}{path}", params=params, json=body, headers=headers) as resp:
        if resp.status == 401:
            raise SearchError(409, "Censys refused the token: check ARGUS_CENSYS_API_TOKEN")
        if resp.status in (402, 403):
            raise SearchError(402, "This Censys account cannot run this search (API access role, plan or credits)")
        if resp.status in (400, 422):
            raise SearchError(502, "Censys did not accept the search: its query syntax may have changed")
        if resp.status == 429:
            raise SearchError(429, "Censys is rate-limiting this token: try again in a minute")
        if resp.status != 200:
            raise SearchError(502, f"Censys answered {resp.status}: try again later")
        data = await resp.json(content_type=None)
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, dict):
        raise SearchError(502, "Censys sent an unexpected answer")
    return result


def _buckets(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"value": b.get("key"), "count": b.get("count")} for b in (result.get("buckets") or [])[:5]]


def _censys_host(hit: dict[str, Any]) -> dict[str, Any] | None:
    asset = hit.get("host_v1") or {}
    host = asset.get("resource") or {}
    if not host.get("ip"):
        return None  # a certificate or web property hit: not a server to list
    matched = (asset.get("matched_services") or [{}])[0]
    routing = host.get("autonomous_system") or {}
    location = host.get("location") or {}
    return {
        "ip": host.get("ip"),
        "port": matched.get("port"),
        "transport": matched.get("transport_protocol") or None,
        "hostnames": ((host.get("dns") or {}).get("names") or [])[:5],
        "domains": [],
        "org": routing.get("name"),
        "asn": f"AS{routing['asn']}" if routing.get("asn") else None,
        "country": location.get("country"),
        "city": location.get("city"),
        "product": matched.get("protocol") or None,
        "seen": None,
    }


async def censys(
    http: HttpClient, token: str, query: str, *, mode: str, organization: str | None = None
) -> dict[str, Any]:
    """Run a CenQL ``query`` on the Censys Platform: "count" (aggregates) or "search" (up to 100 hosts)."""
    register_secret(token)
    if mode == "count":
        orgs = await _censys_post(http, token, organization, "/v3/global/search/aggregate",
                                  {"query": query, "field": "host.autonomous_system.name", "number_of_buckets": 5})  # fmt: skip
        countries = await _censys_post(http, token, organization, "/v3/global/search/aggregate",
                                       {"query": query, "field": "host.location.country", "number_of_buckets": 5})  # fmt: skip
        total, hosts = int(orgs.get("total_count") or 0), []
        top_orgs, top_countries = _buckets(orgs), _buckets(countries)
    else:
        found = await _censys_post(http, token, organization, "/v3/global/search/query",
                                   {"query": query, "page_size": MAX_HOSTS, "fields": CENSYS_FIELDS})  # fmt: skip
        total = int(found.get("total_hits") or 0)
        hosts = [h for h in (_censys_host(hit) for hit in (found.get("hits") or [])[:MAX_HOSTS]) if h]
        top_orgs, top_countries = [], []
    return {
        "engine": "censys",
        "mode": mode,
        "query": query,
        "total": total,
        "rarity": rarity(total),
        "top_orgs": top_orgs,
        "top_countries": top_countries,
        "hosts": hosts,
    }
