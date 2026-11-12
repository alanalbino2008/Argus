"""Passive subdomain discovery leveraging Certificate Transparency logs and public feeds."""

from __future__ import annotations

import logging
import re
from typing import AsyncIterator, Set, Union
import aiohttp

from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.subdomain_finder")


class SubdomainFinderModule(BaseModule):
    """Discovers subdomains passively via Certificate Transparency logs (crt.sh)."""

    name = "subdomain_finder"
    description = "Passive subdomain enumeration via Certificate Transparency and public telemetry"
    supported_entity_types = [EntityType.DOMAIN]

    async def run(
        self,
        entity: Entity,
        session: aiohttp.ClientSession,
        config: ScanConfig,
    ) -> AsyncIterator[Union[Entity, Relation]]:
        domain = entity.value.strip().lower()
        subdomains: Set[str] = set()

        # 1. Certificate Transparency via crt.sh
        crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ArgusOSINT/1.0"}

        try:
            timeout = aiohttp.ClientTimeout(total=config.timeout_seconds * 1.5)
            async with session.get(crt_url, headers=headers, timeout=timeout) as resp:
                if resp.status == 200:
                    entries = await resp.json(content_type=None)
                    if isinstance(entries, list):
                        for item in entries:
                            name_val = item.get("name_value", "")
                            # May contain multiline entries
                            for sub in name_val.split("\n"):
                                clean_sub = sub.strip().lower().lstrip("*.")
                                if clean_sub.endswith(f".{domain}") and clean_sub != domain:
                                    # Simple regex validation
                                    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", clean_sub):
                                        subdomains.add(clean_sub)
        except Exception as e:
            logger.debug("crt.sh passive lookup failed for %s: %s", domain, e)

        # 2. HackerTarget free passive DNS lookup
        try:
            ht_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
            async with session.get(ht_url, headers=headers, timeout=timeout) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    if "error" not in text.lower():
                        for line in text.splitlines():
                            parts = line.split(",")
                            if len(parts) >= 1:
                                host = parts[0].strip().lower()
                                if host.endswith(f".{domain}") and host != domain:
                                    subdomains.add(host)
        except Exception as e:
            logger.debug("HackerTarget lookup failed for %s: %s", domain, e)

        # Yield discovered subdomains (limit to top 40 to prevent node explosion on wild domains)
        for sub in list(subdomains)[:40]:
            sub_entity = Entity.create(
                entity_type=EntityType.SUBDOMAIN,
                value=sub,
                label=sub,
                metadata={"parent_domain": domain, "discovery_method": "certificate_transparency"},
                source_module=self.name,
                confidence=0.95,
                depth=entity.depth + 1,
            )
            yield sub_entity

            yield Relation.create(
                source_id=sub_entity.id,
                target_id=entity.id,
                rel_type=RelationType.SUBDOMAIN_OF,
                label="Subdomain of",
            )
