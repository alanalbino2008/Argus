"""The community username catalog: hundreds more sites, in the WhatsMyName format.

Argus ships ~130 hand-checked signatures (``argus/data/platforms.json``). The OSINT community
maintains a much larger list, `WhatsMyName <https://github.com/WebBreacher/WhatsMyName>`_
(CC BY-SA 4.0), kept current as sites change. Argus reads it at run time instead of copying it:

* from ``ARGUS_USERNAME_CATALOG_FILE`` (offline and air-gapped installs), else
* from ``ARGUS_USERNAME_CATALOG_URL``, through the scan's own HTTP client (so through the scan's
  egress route), cached in memory for ``ARGUS_USERNAME_CATALOG_TTL_HOURS``.

Each WhatsMyName entry says what a real profile shows (``e_code`` / ``e_string``) **and** what a
missing one shows (``m_code`` / ``m_string``); both are checked. Entries Argus cannot use safely are
skipped: POST probes, plain-HTTP sites, and entries the maintainers marked invalid. Hand-checked
signatures win over community ones of the same name.

A larger list must not mean more false positives. Every hit is still checked against a random,
certainly-unregistered handle (see ``username_hunter``): a site that says that one exists too is
ignored for the scan, and community hits get a lower confidence than hand-checked ones.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from argus.core.settings import get_settings
from argus.modules.identity.platforms import Platform, _parse

logger = logging.getLogger("argus.module.catalog")
MAX_CATALOG = 10 * 1024 * 1024
CATEGORIES = {"social": "Social", "tech": "Developer", "coding": "Developer", "gaming": "Gaming", "music": "Music",
              "art": "Creative", "images": "Creative", "video": "Video", "blog": "Blogging", "news": "Community",
              "business": "Professional", "finance": "Finance", "shopping": "Shopping", "dating": "Dating",
              "hobby": "Lifestyle", "health": "Lifestyle", "political": "Community", "xx NSFW xx": "Adult",
              "misc": "Other", "archived": "Other"}  # fmt: skip


@dataclass
class CatalogState:
    platforms: list[Platform] = field(default_factory=list)
    loaded_at: float = 0.0
    source: str = ""
    skipped: int = 0
    error: str | None = None


_state = CatalogState()
_locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = weakref.WeakKeyDictionary()


def _lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    if loop not in _locks:
        _locks[loop] = asyncio.Lock()
    return _locks[loop]


def convert(document: dict[str, Any]) -> tuple[list[Platform], int]:
    """WhatsMyName ``sites`` -> Argus platforms. Returns (platforms, number skipped)."""
    platforms: list[Platform] = []
    skipped = 0
    sites = document.get("sites") if isinstance(document, dict) else None
    for site in sites if isinstance(sites, list) else []:
        platform = _usable(site)
        if platform is None:
            skipped += 1
        else:
            platforms.append(platform)
    return platforms, skipped


def _usable(site: Any) -> Platform | None:
    try:
        return _site(site)
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def _site(site: dict[str, Any]) -> Platform:
    if site.get("valid") is False or site.get("post_body"):
        raise ValueError("not usable")
    probe = str(site["uri_check"]).replace("{account}", "{}")
    pretty = str(site.get("uri_pretty") or site["uri_check"]).replace("{account}", "{}")
    e_string, m_string = str(site.get("e_string") or ""), str(site.get("m_string") or "")
    if not e_string and not m_string:
        raise ValueError("no way to tell profiles apart")
    headers = {str(k): str(v) for k, v in (site.get("headers") or {}).items()}
    known = site.get("known") or []
    return _parse({
        "name": str(site["name"])[:80], "category": CATEGORIES.get(str(site.get("cat")), "Other"),
        "url": pretty, "probe": probe if probe != pretty else None,
        "detect": "present" if e_string else "status", "text": e_string or None,
        "exists": int(site.get("e_code") or 200),
        "missing_text": m_string or None, "missing_status": int(site["m_code"]) if site.get("m_code") else None,
        "strip": str(site["strip_bad_char"]) if site.get("strip_bad_char") else None,
        "known": str(known[0]) if known else None, "headers": headers, "source": "community",
    })  # fmt: skip


async def community_platforms(http: Any) -> list[Platform]:
    """The community catalog (cached). Never raises: on failure the hand-checked list still runs."""
    settings = get_settings()
    if not settings.username_catalog_file and not settings.username_catalog_url:
        return []
    ttl = settings.username_catalog_ttl_hours * 3600
    async with _lock():
        if _state.loaded_at and time.monotonic() - _state.loaded_at < ttl:
            return _state.platforms
        try:
            document, source = await _fetch(http)
            platforms, skipped = convert(document)
            if not platforms:
                raise ValueError("the catalog has no usable sites")
            _state.platforms, _state.skipped, _state.source, _state.error = platforms, skipped, source, None
            logger.info("Username catalog: %d community sites (%d skipped) from %s", len(platforms), skipped, source)
        except (OSError, ValueError, asyncio.TimeoutError) as exc:  # network, JSON, file and HTTP errors
            _state.error = f"{type(exc).__name__}: {str(exc)[:160]}"
            logger.warning("Username catalog unavailable (%s); using the built-in sites only", _state.error)
        except Exception as exc:  # aiohttp and anything else a hostile server provokes
            _state.error = type(exc).__name__
            logger.warning("Username catalog unavailable (%s); using the built-in sites only", _state.error)
        # Retry a failed load after 10 minutes rather than on every scan.
        _state.loaded_at = time.monotonic() - (ttl - 600 if _state.error and not _state.platforms else 0)
        return _state.platforms


async def _fetch(http: Any) -> tuple[dict[str, Any], str]:
    settings = get_settings()
    if settings.username_catalog_file:
        path = Path(settings.username_catalog_file)
        text = await asyncio.to_thread(path.read_text, encoding="utf-8")
        return json.loads(text), path.name
    url = settings.username_catalog_url or ""
    async with http.get(url, headers={"Accept": "application/json"}) as resp:
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        body = await resp.content.read(MAX_CATALOG + 1)
    if len(body) > MAX_CATALOG:
        raise ValueError("the catalog is too large")
    return json.loads(body), url


def status() -> dict[str, Any]:
    return {"community_sites": len(_state.platforms), "skipped": _state.skipped, "source": _state.source,
            "error": _state.error}  # fmt: skip


def reset() -> None:
    """Forget the cached catalog (tests, and after a settings change)."""
    global _state
    _state = CatalogState()
