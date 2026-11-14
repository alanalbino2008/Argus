"""Sherlock-style username reconnaissance across 100+ platforms, with self-calibration.

Site signatures are data (``argus/data/platforms.json``). Every hit is double-checked
against a random, certainly-unregistered *canary* handle on the same site: if the
site claims the canary exists too, it answers "yes" to everything (rate-limit pages,
login walls, soft-404s) and its results are discarded for this scan. That keeps a
large site list from turning into a large list of false positives.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import string
from collections.abc import AsyncIterator
from typing import Any

import aiohttp

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.modules.base import BaseModule
from argus.modules.identity.platforms import Platform, detect, load_platforms, needs_body

logger = logging.getLogger("argus.module.username_hunter")

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}
MAX_BODY = 2_000_000


def canary_username() -> str:
    """Letters only, so every site's username rules accept it; 14 random letters will not be registered."""
    return "zq" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(14))


def get_platforms() -> list[Platform]:
    return load_platforms(get_settings().extra_platforms_file)


class UsernameHunterModule(BaseModule):
    """Searches for a username across 100+ platforms concurrently."""

    name = "username_hunter"
    description = "Sherlock-style cross-platform account discovery (100+ sites, self-calibrating)"
    supported_entity_types = [EntityType.USERNAME]
    attack_techniques = ("T1593.001",)

    def __init__(self) -> None:
        self._canary = canary_username()
        self._calibration: dict[str, asyncio.Task[bool]] = {}

    async def _exists(self, platform: Platform, username: str, session: HttpClient, config: ScanConfig) -> bool:
        timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
        headers = {**BROWSER_HEADERS, **platform.headers}
        async with session.get(
            platform.probe_url(username), headers=headers, timeout=timeout, allow_redirects=platform.redirects
        ) as resp:
            body = (
                (await resp.text(errors="ignore"))[:MAX_BODY] if needs_body(platform) and resp.status == 200 else None
            )
            return detect(platform, resp.status, body)

    async def _reliable(self, platform: Platform, session: HttpClient, config: ScanConfig) -> bool:
        """True when the site correctly says the canary does NOT exist (computed once per site per scan)."""
        if platform.name not in self._calibration:
            self._calibration[platform.name] = asyncio.ensure_future(
                self._exists(platform, self._canary, session, config)
            )
        try:
            return not await self._calibration[platform.name]
        except asyncio.CancelledError:
            raise
        except Exception:
            return False  # can't calibrate -> don't trust it

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        username = entity.value.strip()
        platforms = [p for p in get_platforms() if p.accepts(username)]
        sem = asyncio.Semaphore(config.concurrency_limit)
        unreliable: list[str] = []
        failed = 0

        async def check(platform: Platform) -> tuple[Platform, dict[str, Any]] | None:
            nonlocal failed
            async with sem:
                try:
                    if not await self._exists(platform, username, session, config):
                        return None
                    if not await self._reliable(platform, session, config):
                        unreliable.append(platform.name)
                        return None
                except asyncio.CancelledError:
                    raise
                except Exception as ex:
                    failed += 1
                    logger.debug("Probe failed for %s on %s: %s", username, platform.name, ex)
                    return None
            return platform, {
                "platform": platform.name,
                "username": username,
                "category": platform.category,
                "profile_url": platform.profile_url(username),
                "detection": platform.detect,
                "calibrated": True,
            }

        for future in asyncio.as_completed([check(p) for p in platforms]):
            found = await future
            if not found:
                continue
            platform, meta = found
            profile = Entity.create(
                entity_type=EntityType.SOCIAL_PROFILE,
                value=meta["profile_url"],
                label=f"{platform.name}: {username}",
                metadata=meta,
                source_module=self.name,
                confidence=0.8 if platform.detect == "status" else 0.85,
                depth=entity.depth + 1,
            )
            yield profile
            yield Relation.create(
                source_id=entity.id,
                target_id=profile.id,
                rel_type=RelationType.HAS_ACCOUNT,
                label=f"Registered on {platform.name}",
                metadata={"platform": platform.name},
            )

        entity.metadata["platforms_checked"] = len(platforms)
        if unreliable:
            entity.metadata["platforms_unreliable"] = sorted(unreliable)
        if failed:
            entity.metadata["platforms_unreachable"] = failed


async def verify_platforms(
    platforms: list[Platform], session: HttpClient, config: ScanConfig, concurrency: int = 10
) -> list[dict[str, Any]]:
    """Health-check signatures: a known account must be found and a random one must not.

    ``ok`` - both right; ``false_positive`` - the random handle "exists" (signature useless:
    the canary check already discards it during scans); ``false_negative`` - the known
    account was not found (site changed or blocks automated requests); ``error`` - unreachable.
    """
    hunter = UsernameHunterModule()
    sem = asyncio.Semaphore(concurrency)

    async def one(platform: Platform) -> dict[str, Any]:
        row: dict[str, Any] = {"name": platform.name, "category": platform.category, "known": platform.known}
        if not platform.known:
            return {**row, "status": "untested"}
        async with sem:
            try:
                found = await hunter._exists(platform, platform.known, session, config)
                canary = await hunter._exists(platform, hunter._canary, session, config)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                return {**row, "status": "error", "detail": type(exc).__name__}
        status = "false_positive" if canary else "ok" if found else "false_negative"
        return {**row, "status": status}

    return sorted(await asyncio.gather(*(one(p) for p in platforms)), key=lambda r: (r["status"] == "ok", r["name"]))
