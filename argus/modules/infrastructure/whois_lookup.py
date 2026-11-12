"""Registration Data Access Protocol (RDAP/WHOIS) domain and organization profiling."""

from __future__ import annotations

import logging
from typing import AsyncIterator, Union
import aiohttp

from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.whois_lookup")


class WhoisLookupModule(BaseModule):
    """Interrogates domain registration data using standardized RDAP protocol."""

    name = "whois_lookup"
    description = "RDAP domain registration metadata, registrar identification, and ownership tracking"
    supported_entity_types = [EntityType.DOMAIN]

    async def run(
        self,
        entity: Entity,
        session: aiohttp.ClientSession,
        config: ScanConfig,
    ) -> AsyncIterator[Union[Entity, Relation]]:
        domain = entity.value.strip().lower()
        rdap_url = f"https://rdap.org/domain/{domain}"
        headers = {"Accept": "application/rdap+json, application/json", "User-Agent": "Argus-OSINT/1.0"}

        try:
            timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
            async with session.get(rdap_url, headers=headers, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    # Extract events (creation, expiration)
                    events = {ev.get("eventAction"): ev.get("eventDate") for ev in data.get("events", [])}
                    entity.metadata["registration_date"] = events.get("registration")
                    entity.metadata["expiration_date"] = events.get("expiration")
                    entity.metadata["last_changed"] = events.get("last changed")

                    # Extract entities (Registrar, Registrant, Abuse)
                    for item in data.get("entities", []):
                        roles = item.get("roles", [])
                        vcard_array = item.get("vcardArray", [])

                        # Parse vcard fn (full name / organization)
                        fn = None
                        email_addr = None
                        if len(vcard_array) > 1 and isinstance(vcard_array[1], list):
                            for prop in vcard_array[1]:
                                if len(prop) > 3:
                                    if prop[0] == "fn":
                                        fn = prop[3]
                                    elif prop[0] == "email":
                                        email_addr = prop[3]

                        if "registrar" in roles and fn:
                            reg_entity = Entity.create(
                                entity_type=EntityType.ORGANIZATION,
                                value=fn,
                                label=f"Registrar: {fn}",
                                metadata={"role": "registrar", "domain": domain},
                                source_module=self.name,
                                confidence=1.0,
                                depth=entity.depth + 1,
                            )
                            yield reg_entity
                            yield Relation.create(
                                source_id=reg_entity.id,
                                target_id=entity.id,
                                rel_type=RelationType.OPERATES,
                                label="Domain Registrar",
                            )

                        elif "registrant" in roles and fn:
                            registrant_entity = Entity.create(
                                entity_type=EntityType.ORGANIZATION,
                                value=fn,
                                label=fn,
                                metadata={"role": "registrant", "domain": domain},
                                source_module=self.name,
                                confidence=0.9,
                                depth=entity.depth + 1,
                            )
                            yield registrant_entity
                            yield Relation.create(
                                source_id=entity.id,
                                target_id=registrant_entity.id,
                                rel_type=RelationType.BELONGS_TO,
                                label="Registrant Organization",
                            )

                        if email_addr and ("abuse" in roles or "technical" in roles):
                            email_entity = Entity.create(
                                entity_type=EntityType.EMAIL,
                                value=email_addr,
                                label=email_addr,
                                metadata={"contact_role": ", ".join(roles)},
                                source_module=self.name,
                                confidence=1.0,
                                depth=entity.depth + 1,
                            )
                            yield email_entity
                            yield Relation.create(
                                source_id=email_entity.id,
                                target_id=entity.id,
                                rel_type=RelationType.ASSOCIATED_WITH,
                                label=f"Contact ({', '.join(roles)})",
                            )

        except Exception as e:
            logger.debug("RDAP lookup failed for %s: %s", domain, e)
