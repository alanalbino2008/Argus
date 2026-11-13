"""Sherlock-style high-speed asynchronous username reconnaissance."""

from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator, Union
import aiohttp

from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.signatures import PLATFORM_SIGNATURES
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.username_hunter")


class UsernameHunterModule(BaseModule):
    """Searches for username accounts across 60+ platforms concurrently."""

    name = "username_hunter"
    description = "Sherlock-style cross-platform social profile & account discovery"
    supported_entity_types = [EntityType.USERNAME]

    async def run(
        self,
        entity: Entity,
        session: aiohttp.ClientSession,
        config: ScanConfig,
    ) -> AsyncIterator[Union[Entity, Relation]]:
        username = entity.value.strip()
        sem = asyncio.Semaphore(config.concurrency_limit)

        async def check_platform(plat: dict):
            async with sem:
                check_url = plat["check_url"].format(username)
                profile_url = plat["url_template"].format(username)
                headers = plat.get("headers", {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "Accept-Language": "en-US,en;q=0.9",
                })

                try:
                    timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
                    async with session.get(check_url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                        status = resp.status
                        check_type = plat.get("check_type", "status_code")

                        is_found = False
                        extra_meta = {
                            "platform": plat["name"],
                            "category": plat.get("category", "General"),
                            "profile_url": profile_url,
                            "http_status": status,
                        }

                        if check_type == "status_code":
                            if status == plat.get("exists_code", 200):
                                is_found = True
                        elif check_type == "body_not_contains":
                            if status == 200:
                                text = await resp.text(errors="ignore")
                                if plat.get("missing_text", "") not in text:
                                    is_found = True
                        elif check_type == "body_not_null":
                            if status == 200:
                                text = (await resp.text(errors="ignore")).strip()
                                if text and text != "null":
                                    is_found = True
                        elif check_type == "message_json":
                            if status == 200:
                                data = await resp.json()
                                if plat.get("check_key") in data and data[plat["check_key"]]:
                                    is_found = True

                        if is_found:
                            return plat["name"], profile_url, extra_meta

                except asyncio.CancelledError:
                    raise
                except Exception as ex:
                    logger.debug("Failed probe for %s on %s: %s", username, plat['name'], ex)
                return None

        # Execute all platform probes concurrently
        tasks = [check_platform(plat) for plat in PLATFORM_SIGNATURES]
        for future in asyncio.as_completed(tasks):
            res = await future
            if res:
                platform_name, profile_url, meta = res
                profile_entity = Entity.create(
                    entity_type=EntityType.SOCIAL_PROFILE,
                    value=profile_url,
                    label=f"{platform_name}: {username}",
                    metadata=meta,
                    source_module=self.name,
                    confidence=0.95,
                    depth=entity.depth + 1,
                )
                yield profile_entity

                rel = Relation.create(
                    source_id=entity.id,
                    target_id=profile_entity.id,
                    rel_type=RelationType.HAS_ACCOUNT,
                    label=f"Registered on {platform_name}",
                    metadata={"platform": platform_name},
                )
                yield rel
