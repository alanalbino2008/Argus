"""Sherlock-style username reconnaissance across hundreds of platforms, with self-calibration.

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
from urllib.parse import urlsplit

import aiohttp

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.intel.handles import variants
from argus.modules.base import BaseModule
from argus.modules.identity.catalog import community_platforms
from argus.modules.identity.maigret_catalog import extra_platforms
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


def _site_key(platform: Platform) -> str:
    """The site a platform checks, so the same site from two catalogs is only checked once."""
    host = urlsplit(platform.url.replace("{}", "x")).hostname or ""
    return host.removeprefix("www.").removeprefix("x.")


async def all_platforms(session: HttpClient) -> list[Platform]:
    """Hand-checked signatures, then WhatsMyName, then Maigret: each site once, the better source first."""
    chosen: list[Platform] = []
    names: set[str] = set()
    sites: set[str] = set()
    for source in (get_platforms(), await community_platforms(session), await extra_platforms(session)):
        for platform in source:
            key = _site_key(platform)
            if platform.name.lower() in names or (key and key in sites):
                continue
            chosen.append(platform)
            names.add(platform.name.lower())
            if key:
                sites.add(key)
    return chosen


class UsernameHunterModule(BaseModule):
    """Searches for a username across hundreds of platforms concurrently."""

    name = "username_hunter"
    description = "Sherlock-style cross-platform account discovery (hundreds of sites, self-calibrating)"
    supported_entity_types = [EntityType.USERNAME]
    attack_techniques = ("T1593.001",)
    timeout_factor = 4.0  # hundreds of sites (and variants): more than the default per-module limit

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
        catalog = await all_platforms(session)
        # Variants only for the handle the investigator asked about, never for ones found along the way.
        handles = [username] + (variants(username) if config.handle_variants and entity.depth == 0 else [])
        sem = asyncio.Semaphore(max(config.concurrency_limit * 3, 40))  # one request per site: different hosts
        unreliable: set[str] = set()
        failed = 0
        checked = 0

        async def check(platform: Platform, handle: str) -> tuple[Platform, str] | None:
            nonlocal failed
            async with sem:
                try:
                    if not await self._exists(platform, handle, session, config):
                        return None
                    if not await self._reliable(platform, session, config):
                        unreliable.add(platform.name)
                        return None
                except asyncio.CancelledError:
                    raise
                except Exception as ex:
                    failed += 1
                    logger.debug("Probe failed for %s on %s: %s", handle, platform.name, ex)
                    return None
            return platform, handle

        jobs = []
        for handle in handles:
            usable = [p for p in catalog if p.accepts(handle)]
            checked = max(checked, len(usable)) if handle == username else checked
            jobs += [check(p, handle) for p in usable]
        for future in asyncio.as_completed(jobs):
            found = await future
            if not found:
                continue
            platform, handle = found
            variant = handle != username
            meta: dict[str, Any] = {
                "platform": platform.name,
                "username": handle,
                "category": platform.category,
                "profile_url": platform.profile_url(handle),
                "detection": platform.detect,
                "calibrated": True,
                "signature": platform.source,
            }
            if variant:
                meta["variant_of"] = username
            confidence = (0.8 if platform.detect == "status" else 0.85) - (0.1 if platform.source == "community" else 0)
            profile = Entity.create(
                entity_type=EntityType.SOCIAL_PROFILE,
                value=platform.profile_url(handle),
                label=f"{platform.name}: {handle}",
                metadata=meta,
                source_module=self.name,
                confidence=round(confidence - (0.3 if variant else 0), 2),
                depth=entity.depth + 1,
            )
            yield profile
            yield Relation.create(
                source_id=entity.id,
                target_id=profile.id,
                rel_type=RelationType.HAS_ACCOUNT,
                label=f"Possibly the same person: variant {handle} on {platform.name}"
                if variant
                else f"Registered on {platform.name}",
                metadata={"platform": platform.name, **({"variant": handle} if variant else {})},
            )

        entity.metadata["platforms_checked"] = checked
        if len(handles) > 1:
            entity.metadata["variants_checked"] = handles[1:]
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
