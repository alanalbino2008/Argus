"""Have I Been Pwned: data breaches containing an email address (requires ARGUS_HIBP_API_KEY).

Breach exposure is strong evidence for credential-stuffing and phishing risk
(ATT&CK T1589.001). Only breach *metadata* is collected - never credentials.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import ClassVar
from urllib.parse import quote

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

API = "https://haveibeenpwned.com/api/v3"
MAX_BREACHES = 25


class HibpModule(BaseModule):
    name = "hibp"
    description = "Have I Been Pwned: public data breaches that included an email address"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.EMAIL]
    attack_techniques = ("T1589.001",)
    requires_settings = ("hibp_api_key",)
    rate_limits: ClassVar[dict[str, float]] = {"haveibeenpwned.com": 6.5}  # entry-level plan: 10 requests/minute

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        email = entity.value.strip().lower()
        headers = {"hibp-api-key": self.secret("hibp_api_key")}
        url = f"{API}/breachedaccount/{quote(email, safe='')}?truncateResponse=false"
        async with session.get(url, headers=headers) as resp:
            if resp.status == 404:
                entity.metadata["breach_count"] = 0  # HIBP's documented "not pwned" answer
                return
            if resp.status != 200:
                self.report_error("hibp", f"HTTP {resp.status}")
                return
            breaches = await resp.json()

        entity.metadata["breach_count"] = len(breaches)
        for breach in sorted(breaches, key=lambda b: b.get("BreachDate", ""), reverse=True)[:MAX_BREACHES]:
            name = breach.get("Name") or breach.get("Title")
            if not name:
                continue
            breach_entity = Entity.create(
                entity_type=EntityType.BREACH,
                value=name,
                label=f"Breach: {breach.get('Title', name)} ({breach.get('BreachDate', '?')[:4]})",
                metadata={
                    "breach_date": breach.get("BreachDate"),
                    "domain": breach.get("Domain"),
                    "pwn_count": breach.get("PwnCount"),
                    "data_classes": breach.get("DataClasses", []),
                    "is_verified": breach.get("IsVerified"),
                    "is_sensitive": breach.get("IsSensitive"),
                },
                source_module=self.name,
                confidence=0.99 if breach.get("IsVerified") else 0.7,
                depth=entity.depth + 1,
            )
            yield breach_entity
            yield Relation.create(
                source_id=entity.id,
                target_id=breach_entity.id,
                rel_type=RelationType.EXPOSES,
                label="Exposed in breach",
            )
