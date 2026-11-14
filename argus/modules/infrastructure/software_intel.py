"""Software & vulnerability intelligence: is this software supported, and is this CVE dangerous?

Knowing "PHP/7.4.3" or "CVE-2024-21762" is only half the story. This module adds
the context security teams use to prioritise:

* **Lifecycle** (endoflife.date): has this version reached *end of life* - meaning
  the vendor no longer ships security fixes - and how far is it behind the latest
  patch release of its line?
* **Exploitation in the wild** (CISA Known Exploited Vulnerabilities catalog): is
  the CVE being used in real attacks right now, and by ransomware groups?
* **Exploit likelihood** (FIRST EPSS): probability of exploitation in the next 30 days.
* **Severity** (NIST NVD): CVSS score and the official description.

All sources are free public APIs. Results enrich existing entities (no new nodes);
the attack-path engine and risk analyzer turn them into prioritised findings.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from datetime import date
from typing import Any, ClassVar

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, ScanConfig
from argus.modules.base import BaseModule

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
EOL_URL = "https://endoflife.date/api/{}.json"

# Product names as they appear in banners -> endoflife.date product slugs.
PRODUCTS = {
    "nginx": "nginx",
    "php": "php",
    "apache": "apache-http-server",
    "openssl": "openssl",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "python": "python",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "django": "django",
    "tomcat": "tomcat",
    "jquery": "jquery",
}
SOFTWARE_RE = re.compile(
    r"(?i)\b("
    + "|".join(re.escape(p) for p in sorted(PRODUCTS, key=len, reverse=True))
    + r")[\s/_-]*v?(\d+(?:\.\d+){1,3})"
)


def parse_software(text: str) -> tuple[str, str] | None:
    """'PHP/7.4.3' -> ('php', '7.4.3'); 'Apache/2.4.49 (Ubuntu)' -> ('apache-http-server', '2.4.49')."""
    m = SOFTWARE_RE.search(text or "")
    return (PRODUCTS[m.group(1).lower()], m.group(2)) if m else None


def _vtuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version))


def match_cycle(cycles: list[dict[str, Any]], version: str, today: date | None = None) -> dict[str, Any] | None:
    """Find the release line a version belongs to and summarise its support status."""
    candidates = [c for c in cycles if version == str(c.get("cycle")) or version.startswith(f"{c.get('cycle')}.")]
    if not candidates:
        return None
    cycle = max(candidates, key=lambda c: len(str(c["cycle"])))
    eol = cycle.get("eol")
    today = today or date.today()
    if isinstance(eol, bool):
        reached, eol_date = eol, None
    else:
        eol_date = str(eol) if eol else None
        reached = eol_date is not None and date.fromisoformat(eol_date) <= today
    latest = str(cycle.get("latest") or "")
    return {
        "version": version,
        "cycle": str(cycle["cycle"]),
        "eol": reached,
        "eol_date": eol_date,
        "latest": latest or None,
        "outdated": bool(latest) and _vtuple(version) < _vtuple(latest),
    }


class SoftwareIntelModule(BaseModule):
    name = "software_intel"
    description = "Software end-of-life status and CVE intelligence (CISA KEV, EPSS, NVD CVSS)"
    supported_entity_types: ClassVar[list[EntityType]] = [
        EntityType.TECHNOLOGY,
        EntityType.PORT,
        EntityType.VULNERABILITY,
    ]
    enrichment = True
    attack_techniques = ("T1592.002", "T1596.005")
    rate_limits: ClassVar[dict[str, float]] = {"services.nvd.nist.gov": 6.5}  # NVD: 5 requests / 30 s without a key

    def __init__(self) -> None:
        self._kev: dict[str, dict[str, Any]] | None = None
        self._kev_lock = asyncio.Lock()
        self._eol: dict[str, list[dict[str, Any]] | None] = {}

    def can_handle(self, entity: Entity) -> bool:
        if not super().can_handle(entity):
            return False
        if entity.type == EntityType.VULNERABILITY:
            return entity.value.upper().startswith("CVE-")
        return parse_software(self._software_text(entity)) is not None

    @staticmethod
    def _software_text(entity: Entity) -> str:
        if entity.type == EntityType.PORT:
            md = entity.metadata
            return f"{md.get('product', '')} {md.get('version', '')}".strip()
        return entity.value

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        if entity.type == EntityType.VULNERABILITY:
            await self._vulnerability(entity, session)
        else:
            await self._lifecycle(entity, session)
        return
        yield  # pragma: no cover - enrichment only

    # ------------------------------------------------------------------ lifecycle
    async def _lifecycle(self, entity: Entity, session: HttpClient) -> None:
        parsed = parse_software(self._software_text(entity))
        if not parsed:
            return
        product, version = parsed
        if product not in self._eol:
            async with session.get(EOL_URL.format(product)) as resp:
                self._eol[product] = await resp.json() if resp.status == 200 else None
        cycles = self._eol[product]
        if not cycles:
            return
        info = match_cycle(cycles, version)
        if info:
            entity.metadata["lifecycle"] = {"product": product, **info}

    # ------------------------------------------------------------------ vulnerabilities
    async def _kev_catalog(self, session: HttpClient) -> dict[str, dict[str, Any]]:
        async with self._kev_lock:  # one download per scan, shared by every CVE
            if self._kev is None:
                self._kev = {}
                async with session.get(KEV_URL) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._kev = {v["cveID"].upper(): v for v in data.get("vulnerabilities", []) if v.get("cveID")}
                    else:
                        self.report_error("cisa-kev", f"HTTP {resp.status}")
        return self._kev

    async def _vulnerability(self, entity: Entity, session: HttpClient) -> None:
        cve = entity.value.upper()
        intel: dict[str, Any] = {}

        kev = (await self._kev_catalog(session)).get(cve)
        intel["kev"] = (
            {
                "date_added": kev.get("dateAdded"),
                "due_date": kev.get("dueDate"),
                "ransomware": str(kev.get("knownRansomwareCampaignUse", "")).lower() == "known",
                "product": f"{kev.get('vendorProject', '')} {kev.get('product', '')}".strip(),
                "name": kev.get("vulnerabilityName"),
                "action": kev.get("requiredAction"),
            }
            if kev
            else None
        )

        async with session.get(EPSS_URL.format(cve)) as resp:
            if resp.status == 200:
                rows = (await resp.json()).get("data") or []
                if rows:
                    intel["epss"] = round(float(rows[0].get("epss", 0)), 4)
                    intel["epss_percentile"] = round(float(rows[0].get("percentile", 0)), 4)

        async with session.get(NVD_URL.format(cve)) as resp:
            if resp.status == 200:
                vulns = (await resp.json()).get("vulnerabilities") or []
                if vulns:
                    item = vulns[0].get("cve", {})
                    metrics = item.get("metrics", {})
                    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if metrics.get(key):
                            data = metrics[key][0].get("cvssData", {})
                            intel["cvss_score"] = data.get("baseScore")
                            intel["cvss_severity"] = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                            break
                    descriptions = [d.get("value") for d in item.get("descriptions", []) if d.get("lang") == "en"]
                    if descriptions:
                        intel["description"] = descriptions[0][:500]
        entity.metadata["intel"] = intel
