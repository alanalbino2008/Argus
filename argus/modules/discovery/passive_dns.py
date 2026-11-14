"""Sub-domains from five independent passive sources, with per-host provenance.

Certificate Transparency (``subdomain_finder``) only sees hosts that got a public TLS
certificate. Passive DNS and web-crawl datasets see hosts that were *resolved* or
*visited* - internal-looking names, staging servers, old infrastructure.

Sources (all free, no key): HackerTarget, AlienVault OTX passive DNS, Anubis-DB,
CertSpotter and urlscan.io. Each host records which sources reported it, and
confidence grows with independent confirmations. A failing source is reported in
the run report and never fails the module.
"""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import ClassVar
from urllib.parse import quote

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

MAX_HOSTS = 500
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


async def _hackertarget(session: HttpClient, domain: str) -> set[str]:
    async with session.get(f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}") as resp:
        text = await resp.text() if resp.status == 200 else ""
    if "API count exceeded" in text or text.startswith("error"):
        raise RuntimeError("quota exceeded")
    return {line.split(",", 1)[0] for line in text.splitlines() if "," in line}


async def _otx(session: HttpClient, domain: str) -> set[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/passive_dns"
    async with session.get(url) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        data = await resp.json(content_type=None)
    return {row.get("hostname", "") for row in data.get("passive_dns", [])}


async def _anubis(session: HttpClient, domain: str) -> set[str]:
    async with session.get(f"https://jldc.me/anubis/subdomains/{quote(domain)}") as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        data = await resp.json(content_type=None)
    return {h for h in data if isinstance(h, str)}


async def _certspotter(session: HttpClient, domain: str) -> set[str]:
    url = f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}&include_subdomains=true&expand=dns_names"
    async with session.get(url) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        data = await resp.json(content_type=None)
    return {name for item in data for name in item.get("dns_names", [])}


async def _urlscan(session: HttpClient, domain: str) -> set[str]:
    async with session.get(f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=500") as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        data = await resp.json(content_type=None)
    return {
        host
        for result in data.get("results", [])
        for host in (result.get("page", {}).get("domain"), result.get("task", {}).get("domain"))
        if host
    }


SOURCES: dict[str, Callable[[HttpClient, str], Awaitable[set[str]]]] = {
    "hackertarget": _hackertarget,
    "alienvault-otx": _otx,
    "anubis": _anubis,
    "certspotter": _certspotter,
    "urlscan": _urlscan,
}


def normalise(host: str, domain: str) -> str | None:
    h = host.strip().lower().rstrip(".").removeprefix("*.")
    if h == domain or not h.endswith("." + domain) or not HOST_RE.match(h):
        return None
    return h


class PassiveDnsModule(BaseModule):
    name = "passive_dns"
    description = "Sub-domains from passive DNS and crawl datasets (HackerTarget, OTX, Anubis, CertSpotter, urlscan)"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.DOMAIN]
    attack_techniques = ("T1596.001", "T1590.002")
    rate_limits: ClassVar[dict[str, float]] = {"api.hackertarget.com": 2.0, "urlscan.io": 2.0}

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth <= 1

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        domain = entity.value.strip().lower()
        results = await asyncio.gather(*(fn(session, domain) for fn in SOURCES.values()), return_exceptions=True)
        seen: dict[str, set[str]] = defaultdict(set)
        answered = []
        for source, result in zip(SOURCES, results, strict=True):
            if isinstance(result, BaseException):
                if isinstance(result, asyncio.CancelledError):
                    raise result
                self.report_error(source, result)
                continue
            answered.append(source)
            for raw in result:
                host = normalise(raw, domain)
                if host:
                    seen[host].add(source)
        entity.metadata["passive_dns"] = {"sources_answered": answered, "hosts": len(seen)}

        ranked = sorted(seen.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:MAX_HOSTS]
        for host, sources in ranked:
            sub = Entity.create(
                EntityType.SUBDOMAIN,
                host,
                label=host,
                metadata={"passive_sources": sorted(sources)},
                source_module=self.name,
                confidence=round(min(0.95, 0.55 + 0.1 * len(sources)), 2),
                depth=entity.depth + 1,
            )
            yield sub
            yield Relation.create(sub.id, entity.id, RelationType.SUBDOMAIN_OF, label="Passive DNS")
