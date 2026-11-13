"""International phone number reconnaissance, country dial-code mapping, and carrier analysis."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator

import aiohttp

from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.phone_recon")

COUNTRY_DIAL_CODES = {
    "+1": {"country": "United States / Canada", "code": "US/CA"},
    "+44": {"country": "United Kingdom", "code": "GB"},
    "+33": {"country": "France", "code": "FR"},
    "+49": {"country": "Germany", "code": "DE"},
    "+61": {"country": "Australia", "code": "AU"},
    "+81": {"country": "Japan", "code": "JP"},
    "+91": {"country": "India", "code": "IN"},
    "+353": {"country": "Ireland", "code": "IE"},
    "+34": {"country": "Spain", "code": "ES"},
    "+39": {"country": "Italy", "code": "IT"},
    "+55": {"country": "Brazil", "code": "BR"},
    "+86": {"country": "China", "code": "CN"},
    "+7": {"country": "Russia / Kazakhstan", "code": "RU/KZ"},
}


class PhoneReconModule(BaseModule):
    """Enriches international telephone numbers with country of origin, format checks, and dorks."""

    name = "phone_recon"
    description = "International phone number parsing, country origin identification, and OSINT footprinting"
    supported_entity_types = [EntityType.PHONE]

    async def run(
        self,
        entity: Entity,
        session: aiohttp.ClientSession,
        config: ScanConfig,
    ) -> AsyncIterator[Entity | Relation]:
        raw_phone = entity.value.strip()
        # Normalize: keep plus and digits
        digits_only = re.sub(r"[^\d+]", "", raw_phone)
        if not digits_only.startswith("+"):
            digits_only = "+" + digits_only

        matched_country = None
        matched_prefix = None

        # Prefix matching
        for prefix in sorted(COUNTRY_DIAL_CODES.keys(), key=len, reverse=True):
            if digits_only.startswith(prefix):
                matched_country = COUNTRY_DIAL_CODES[prefix]
                matched_prefix = prefix
                break

        if matched_country:
            national_part = digits_only[len(matched_prefix) :]
            entity.metadata.update(
                {
                    "country": matched_country["country"],
                    "country_code": matched_country["code"],
                    "dial_code": matched_prefix,
                    "national_number": national_part,
                    "e164_formatted": digits_only,
                }
            )

            # Create country/operator entity
            country_entity = Entity.create(
                entity_type=EntityType.ORGANIZATION,
                value=f"Telecom Region: {matched_country['country']}",
                label=f"Telecom: {matched_country['country']}",
                metadata={"country": matched_country["country"], "dial_code": matched_prefix},
                source_module=self.name,
                confidence=1.0,
                depth=entity.depth + 1,
            )
            yield country_entity

            yield Relation.create(
                source_id=entity.id,
                target_id=country_entity.id,
                rel_type=RelationType.LOCATED_IN,
                label=f"Registered in {matched_country['country']}",
            )
