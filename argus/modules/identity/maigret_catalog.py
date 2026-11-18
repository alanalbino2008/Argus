"""A second community username catalog: Maigret's, with a couple of thousand more sites.

`Maigret <https://github.com/soxoj/maigret>`_ (MIT licence) keeps one of the largest lists of
sites where a username can be looked up, with how each site shows a real profile and a missing
one. Argus reads it at run time, like the WhatsMyName catalog (``argus.modules.identity.catalog``):

* from ``ARGUS_USERNAME_CATALOG_EXTRA_FILE`` (offline installs), else
* from ``ARGUS_USERNAME_CATALOG_EXTRA_URL``, through the scan's own HTTP client, cached in memory.

It lists several thousand sites, many of them small forums. The most visited come first, and at
most ``ARGUS_USERNAME_CATALOG_EXTRA_LIMIT`` (3,000) are checked, so a search stays a few minutes
long at most.

Only entries Argus can check safely are used: HTTPS, a clear sign of a real or a missing profile
(a status code, or text that appears on one and not the other), not marked disabled by the
maintainers. Site "engines" (shared templates for forums running the same software) are applied.
Sites already in the hand-checked list or WhatsMyName, by name or by address, are not repeated.

As with every catalog, each hit is checked against a random, certainly-unregistered username, so
a site that claims every name exists is ignored, and community hits get a lower confidence.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from argus.core.settings import get_settings
from argus.modules.identity.catalog import MAX_CATALOG
from argus.modules.identity.platforms import Platform, _parse

logger = logging.getLogger("argus.module.catalog")
TAGS = {"social": "Social", "photo": "Creative", "art": "Creative", "music": "Music", "video": "Video",
        "gaming": "Gaming", "coding": "Developer", "tech": "Developer", "forum": "Community", "news": "Community",
        "blog": "Blogging", "dating": "Dating", "shopping": "Shopping", "finance": "Finance", "crypto": "Finance",
        "business": "Professional", "career": "Professional", "education": "Community", "porn": "Adult"}  # fmt: skip


class _State:
    platforms: list[Platform] = []
    loaded_at = 0.0
    skipped = 0
    source = ""
    error: str | None = None


_state = _State()
_lock: asyncio.Lock | None = None


def _category(tags: Any) -> str:
    for tag in tags if isinstance(tags, list) else []:
        if str(tag).lower() in TAGS:
            return TAGS[str(tag).lower()]
    return "Other"


def _template(site: dict[str, Any], value: str) -> str:
    return (value.replace("{urlMain}", str(site.get("urlMain") or "").rstrip("/"))
            .replace("{urlSubpath}", str(site.get("urlSubpath") or "")).replace("{username}", "{}"))  # fmt: skip


def _site(name: str, site: dict[str, Any], engines: dict[str, Any]) -> Platform:
    engine = engines.get(str(site.get("engine") or "")) or {}
    site = {**(engine.get("site") or {}), **site}
    if site.get("disabled") or not site.get("url"):
        raise ValueError("not usable")
    url = _template(site, str(site["url"]))
    probe = _template(site, str(site["urlProbe"])) if site.get("urlProbe") else None
    kind = site.get("checkType")
    present = [str(s) for s in site.get("presenseStrs") or [] if str(s).strip()]
    absent = [str(s) for s in site.get("absenceStrs") or [] if str(s).strip()]
    fields: dict[str, Any]
    if kind == "status_code":
        fields = {"detect": "status"}
    elif kind == "message" and present:
        fields = {"detect": "present", "text": present[0], "missing_text": absent[0] if absent else None}
    elif kind == "message" and absent:
        fields = {"detect": "absent", "text": absent[0]}
    else:
        raise ValueError("no safe way to tell profiles apart")  # e.g. redirect-based checks
    valid = None
    if site.get("regexCheck"):
        try:
            re.compile(str(site["regexCheck"]))
            valid = str(site["regexCheck"])
        except re.error:
            valid = None
    headers = {str(k): str(v) for k, v in (site.get("headers") or {}).items()}
    return _parse({
        "name": str(name)[:80], "category": _category(site.get("tags")), "url": url,
        "probe": probe if probe and probe != url else None, "valid": valid, "headers": headers,
        "known": str(site["usernameClaimed"]) if site.get("usernameClaimed") else None, "source": "community",
        **fields,
    })  # fmt: skip


def _popularity(entry: tuple[str, Any]) -> int:
    rank = entry[1].get("alexaRank") if isinstance(entry[1], dict) else None
    return int(rank) if isinstance(rank, int) and rank > 0 else 10**9


def _usable(name: str, site: Any, engines: dict[str, Any]) -> Platform | None:
    try:
        return _site(name, site, engines)
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def convert(document: dict[str, Any]) -> tuple[list[Platform], int]:
    """Maigret ``sites`` -> Argus platforms. Returns (platforms, number skipped)."""
    sites = document.get("sites") if isinstance(document, dict) else None
    raw_engines = document.get("engines") if isinstance(document, dict) else None
    engines: dict[str, Any] = raw_engines if isinstance(raw_engines, dict) else {}
    entries = sorted(sites.items() if isinstance(sites, dict) else [], key=_popularity)  # most visited first
    found = [_usable(name, site, engines) for name, site in entries]
    platforms = [p for p in found if p is not None]
    return platforms, len(found) - len(platforms)


async def extra_platforms(http: Any) -> list[Platform]:
    """The extra catalog (cached). Never raises: on failure the other lists still run."""
    global _lock
    settings = get_settings()
    if not settings.username_catalog_extra_file and not settings.username_catalog_extra_url:
        return []
    ttl = settings.username_catalog_ttl_hours * 3600
    _lock = _lock or asyncio.Lock()
    async with _lock:
        if _state.loaded_at and time.monotonic() - _state.loaded_at < ttl:
            return _state.platforms[: settings.username_catalog_extra_limit]
        try:
            document, source = await _fetch(http)
            platforms, skipped = convert(document)
            if not platforms:
                raise ValueError("the catalog has no usable sites")
            _state.platforms, _state.skipped, _state.source, _state.error = platforms, skipped, source, None
            logger.info("Extra username catalog: %d sites (%d skipped) from %s", len(platforms), skipped, source)
        except Exception as exc:
            _state.error = f"{type(exc).__name__}: {str(exc)[:160]}"
            logger.warning("Extra username catalog unavailable (%s)", _state.error)
        _state.loaded_at = time.monotonic() - (ttl - 600 if _state.error and not _state.platforms else 0)
        return _state.platforms[: settings.username_catalog_extra_limit]


async def _fetch(http: Any) -> tuple[dict[str, Any], str]:
    settings = get_settings()
    if settings.username_catalog_extra_file:
        path = Path(settings.username_catalog_extra_file)
        return json.loads(await asyncio.to_thread(path.read_text, encoding="utf-8")), path.name
    url = settings.username_catalog_extra_url
    async with http.get(url, headers={"Accept": "application/json"}) as resp:
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        body = await resp.content.read(MAX_CATALOG + 1)
    if len(body) > MAX_CATALOG:
        raise ValueError("the catalog is too large")
    return json.loads(body), url


def status() -> dict[str, Any]:
    return {"extra_sites": len(_state.platforms), "skipped": _state.skipped, "source": _state.source,
            "error": _state.error}  # fmt: skip


def reset() -> None:
    global _state, _lock
    _state, _lock = _State(), None
