"""Internet-wide pivots on demand: who else serves this fingerprint, according to Shodan.

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
