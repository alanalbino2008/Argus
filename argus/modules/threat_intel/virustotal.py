"""VirusTotal reputation for domains and IP addresses (requires ARGUS_VIRUSTOTAL_API_KEY)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import ClassVar

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, ScanConfig
from argus.modules.base import BaseModule

API = "https://www.virustotal.com/api/v3"


class VirusTotalModule(BaseModule):
    name = "virustotal"
    description = "VirusTotal reputation: how many security vendors flag a domain or IP as malicious"
    supported_entity_types: ClassVar[list[EntityType]] = [
        EntityType.DOMAIN,
        EntityType.SUBDOMAIN,
        EntityType.IP_ADDRESS,
    ]
    attack_techniques = ("T1597.001",)
    requires_settings = ("virustotal_api_key",)
    rate_limits: ClassVar[dict[str, float]] = {"www.virustotal.com": 15.0}  # free tier: 4 requests/minute

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        kind = "ip_addresses" if entity.type == EntityType.IP_ADDRESS else "domains"
        headers = {"x-apikey": self.secret("virustotal_api_key"), "Accept": "application/json"}
        async with session.get(f"{API}/{kind}/{entity.value.strip().lower()}", headers=headers) as resp:
            if resp.status == 404:
                return  # unknown to VirusTotal: a valid (empty) answer
            if resp.status != 200:
                self.report_error("virustotal", f"HTTP {resp.status}")
                return
            attributes = (await resp.json()).get("data", {}).get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})
        entity.metadata["virustotal"] = {
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "reputation": attributes.get("reputation"),
            "categories": sorted(set((attributes.get("categories") or {}).values()))[:10],
        }
        return
        yield  # pragma: no cover - enrichment only; makes this an async generator
