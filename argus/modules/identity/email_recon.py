"""Email intelligence, MX validation, disposable domain detection, and Gravatar profiling."""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import AsyncIterator

import aiohttp
import dns.asyncresolver
import dns.resolver

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.email_recon")

DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "tempmail.com",
    "trashmail.com",
    "yopmail.com",
    "sharklasers.com",
    "throwawaymail.com",
    "dispostable.com",
    "getairmail.com",
    "fakemailgenerator.com",
}


class EmailReconModule(BaseModule):
    """Enriches email targets into linked Domains, Usernames, and Gravatar profiles."""

    name = "email_recon"
    description = "Email syntax validation, domain extraction, MX verification, and Gravatar profiling"
    supported_entity_types = [EntityType.EMAIL]
    attack_techniques = ("T1589.002", "T1590.002")

    async def run(
        self,
        entity: Entity,
        session: HttpClient,
        config: ScanConfig,
    ) -> AsyncIterator[Entity | Relation]:
        email = entity.value.strip().lower()
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            return

        username_part, domain_part = email.split("@", 1)

        # 1. Extract and yield Username entity
        username_entity = Entity.create(
            entity_type=EntityType.USERNAME,
            value=username_part,
            label=username_part,
            metadata={"origin": "email_prefix", "email": email},
            source_module=self.name,
            confidence=0.85,
            depth=entity.depth + 1,
        )
        yield username_entity
        yield Relation.create(
            source_id=entity.id,
            target_id=username_entity.id,
            rel_type=RelationType.BELONGS_TO,
            label="Username Prefix",
        )

        # 2. Extract and yield Domain entity
        is_disposable = domain_part in DISPOSABLE_DOMAINS
        domain_entity = Entity.create(
            entity_type=EntityType.DOMAIN,
            value=domain_part,
            label=domain_part,
            metadata={"is_disposable_provider": is_disposable},
            source_module=self.name,
            confidence=0.95,
            depth=entity.depth + 1,
        )
        yield domain_entity
        yield Relation.create(
            source_id=entity.id,
            target_id=domain_entity.id,
            rel_type=RelationType.ASSOCIATED_WITH,
            label="Email Hosted Domain",
        )

        # 3. Check MX records via DNS
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = config.timeout_seconds
            mx_answers = await resolver.resolve(domain_part, "MX")
            mx_records = [str(r.exchange).rstrip(".") for r in mx_answers]

            domain_entity.metadata["mx_records"] = mx_records
            domain_entity.metadata["has_valid_mx"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            domain_entity.metadata["has_valid_mx"] = False
        except Exception as e:
            # A timeout tells us nothing about the domain: record "unknown", not "invalid".
            domain_entity.metadata["has_valid_mx"] = None
            self.report_error("dns:MX", e)

        # 4. Check Gravatar Profile via MD5 hash
        # Gravatar's public API is keyed by MD5; this is an identifier, not a security control.
        email_hash = hashlib.md5(email.encode("utf-8"), usedforsecurity=False).hexdigest()
        gravatar_profile_url = f"https://en.gravatar.com/{email_hash}.json"

        try:
            timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
            async with session.get(gravatar_profile_url, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    entry = data.get("entry", [{}])[0]
                    display_name = entry.get("displayName") or entry.get("preferredUsername") or username_part
                    profile_url = entry.get("profileUrl", f"https://gravatar.com/{email_hash}")

                    grav_entity = Entity.create(
                        entity_type=EntityType.SOCIAL_PROFILE,
                        value=profile_url,
                        label=f"Gravatar: {display_name}",
                        metadata={
                            "displayName": display_name,
                            "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}",
                            "aboutMe": entry.get("aboutMe", ""),
                            "currentLocation": entry.get("currentLocation", ""),
                        },
                        source_module=self.name,
                        confidence=0.98,
                        depth=entity.depth + 1,
                    )
                    yield grav_entity
                    yield Relation.create(
                        source_id=entity.id,
                        target_id=grav_entity.id,
                        rel_type=RelationType.HAS_ACCOUNT,
                        label="Gravatar Profile",
                    )
        except Exception as e:
            logger.debug("Gravatar lookup error: %s", e)
