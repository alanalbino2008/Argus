"""Dark-web and paste/leak-forum sources for a watched selector.

A **selector** is anything an investigator wants to watch for on the dark web and the leak ecosystem:
a brand, a product codename, an executive's address, a username, a card BIN. Unlike the domain
watches in :mod:`argus.intel.exposure`, a selector is not a domain you have to own — so these sources
are read-only lookups of **indexes**, never of the criminal services themselves.

Two provider-backed sources, each off until an admin points Argus at a provider (just like the custom
breach provider). Both are plain JSON search APIs that take the selector as the ``q`` parameter:

* **dark-web index** (``darkweb_index_url``) — an index of onion-site titles and snippets (a self-hosted
  Ahmia/Elasticsearch, or a licensed index). Argus reads only this **clearnet** index; it never fetches
  an ``.onion`` service, so no criminal content is downloaded and no Tor route is needed.
* **paste / leak-forum monitor** (``paste_monitor_url``) — an index of paste sites and leak-forum posts.

Both go out through the same SSRF guard as every other Argus fetcher (private, loopback and link-local
hosts are refused, including on redirects), and results are capped (``darkweb_lookups_max``). Only
metadata is kept — where the selector appears, the title/snippet, the date — never leaked files or
credentials.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from argus.core.settings import Settings
from argus.intel.breach_sources import SourceError, SourceUnavailable
from argus.security.network import GuardedResolver, configured_proxy_hosts

USER_AGENT = "Argus-DarkWeb-Monitor/1 (+https://github.com/alanalbino2008/Argus)"
MAX_BODY = 16 * 1024 * 1024
SPACING = 1.0  # polite spacing between provider calls
SNIPPET = 500


def _text(value: Any, limit: int = 200) -> str:
    return str(value or "").strip()[:limit]


def _first(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if record.get(key):
            return record[key]
    return None


def _is_onion(value: str) -> bool:
    host = urlsplit(value if "://" in value else f"//{value}").hostname or ""
    return host.endswith(".onion")


class DarkWebSources:
    """Provider-backed dark-web index and paste/leak-forum search, both off unless configured."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._session: aiohttp.ClientSession | None = None
        self._last_call: dict[str, float] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ configuration
    @property
    def index_url(self) -> str | None:
        return (self.settings.darkweb_index_url or "").strip().rstrip("/") or None

    @property
    def paste_url(self) -> str | None:
        return (self.settings.paste_monitor_url or "").strip().rstrip("/") or None

    def _key(self, which: str) -> str | None:
        secret = self.settings.darkweb_index_api_key if which == "index" else self.settings.paste_monitor_api_key
        return secret.get_secret_value() if secret else None

    def capabilities(self) -> dict[str, bool]:
        return {"darkweb_index": bool(self.index_url), "paste_monitor": bool(self.paste_url)}

    @property
    def _cap(self) -> int:
        return max(0, int(self.settings.darkweb_lookups_max))

    # ------------------------------------------------------------------ http
    def _http(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            resolver = None if self.settings.allow_private_targets else GuardedResolver(
                trusted_hosts=configured_proxy_hosts())  # fmt: skip
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=4, resolver=resolver),
                timeout=aiohttp.ClientTimeout(total=30),
                trust_env=True,
                headers={"User-Agent": USER_AGENT},
            )
        return self._session

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()

    async def _space(self, bucket: str) -> None:
        async with self._lock:
            wait = self._last_call.get(bucket, 0.0) + SPACING - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call[bucket] = time.monotonic()

    async def _search(self, which: str, url: str, selector: str) -> list[dict[str, Any]]:
        await self._space(which)
        headers = {}
        key = self._key(which)
        if key:
            headers["Authorization"] = f"Bearer {key}"
        try:
            async with self._http().get(url, params={"q": selector}, headers=headers, allow_redirects=False) as resp:
                raw = await resp.content.read(MAX_BODY + 1)
                if len(raw) > MAX_BODY:
                    raise SourceError("The answer was too large")
                if resp.status == 404:
                    return []
                if resp.status == 401 or resp.status == 403:
                    raise SourceUnavailable(f"The dark-web provider rejected the request (HTTP {resp.status})")
                if resp.status == 429:
                    raise SourceError("The dark-web provider rate limit was reached")
                if resp.status != 200:
                    raise SourceError(f"The dark-web provider answered HTTP {resp.status}")
                try:
                    data = await asyncio.to_thread(json.loads, raw)
                except ValueError as exc:
                    raise SourceError("The dark-web provider did not return JSON") from exc
        except asyncio.TimeoutError as exc:
            raise SourceError("Timed out") from exc
        except aiohttp.ClientError as exc:
            raise SourceError(f"Could not connect ({type(exc).__name__})") from exc
        if isinstance(data, dict):
            data = data.get("results") or data.get("items") or data.get("data") or data.get("hits") or []
        return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []

    # ------------------------------------------------------------------ sources
    async def index(self, selector: str) -> list[dict[str, Any]]:
        """Onion-site listings whose title or body mentions ``selector`` (clearnet index only)."""
        url = self.index_url
        if not url:
            raise SourceUnavailable("The dark-web index is off (ARGUS_DARKWEB_INDEX_URL)")
        hits = []
        for record in await self._search("index", url, selector):
            onion = _text(_first(record, "onion", "url", "address", "link"), 300)
            title = _text(_first(record, "title", "name", "heading")) or (onion or "untitled")
            hits.append({
                "title": title,
                "onion": onion,
                "is_onion": _is_onion(onion),
                "snippet": _text(_first(record, "snippet", "description", "excerpt", "content"), SNIPPET),
                "date": _text(_first(record, "last_seen", "date", "seen", "crawled"), 32) or None,
                "source": _text(_first(record, "source", "index"), 60) or "dark-web index",
            })  # fmt: skip
            if len(hits) >= self._cap:
                break
        return hits

    async def pastes(self, selector: str) -> list[dict[str, Any]]:
        """Paste-site and leak-forum posts mentioning ``selector``."""
        url = self.paste_url
        if not url:
            raise SourceUnavailable("The paste/leak-forum monitor is off (ARGUS_PASTE_MONITOR_URL)")
        hits = []
        for record in await self._search("paste", url, selector):
            link = _text(_first(record, "url", "link", "paste_url", "href"), 300)
            hits.append({
                "title": _text(_first(record, "title", "name", "key", "id")) or (link or "paste"),
                "url": link,
                "snippet": _text(_first(record, "snippet", "excerpt", "preview", "text"), SNIPPET),
                "date": _text(_first(record, "date", "created", "published", "added"), 32) or None,
                "source": _text(_first(record, "source", "site", "forum"), 60) or "paste site",
            })  # fmt: skip
            if len(hits) >= self._cap:
                break
        return hits
