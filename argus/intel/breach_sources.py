"""Where exposure comes from: Have I Been Pwned and a ransomware leak-site research feed.

* **HIBP breach catalogue** (``/breaches``, free, no key): every public breach with its data
  classes and dates. Used to describe breaches and to find breaches *of* an organisation.
* **HIBP domain search** (``/breacheddomain/{domain}``, API key): every address at a domain seen
  in a breach. HIBP only answers for domains the key's owner has **verified they control**, which
  is exactly the authorisation this kind of search needs.
* **HIBP stealer logs** (``/stealerlogsbyemaildomain/{domain}``, API key on plans that include
  it): addresses at the domain whose credentials were captured by infostealer malware.
* **Ransomware leak sites**, through ransomware.live's public API, which indexes the posts groups
  publish about their victims. Argus never visits the leak sites (Tor hidden services run by
  criminals) itself.

Every source can fail on its own. A check records which sources ran, and a missing key or plan
is reported as "not available" rather than as an error.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import aiohttp

from argus.core.settings import Settings
from argus.security.network import GuardedResolver, configured_proxy_hosts

HIBP = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "Argus-Exposure-Monitor/1 (+https://github.com/alanalbino2008/Argus)"
MAX_BODY = 16 * 1024 * 1024
CATALOGUE_TTL = 6 * 3600.0
HIBP_SPACING = 6.5  # the entry-level HIBP plan allows 10 keyed requests a minute
FEED_SPACING = 1.0


class SourceUnavailable(Exception):
    """This source cannot be used here (no key, not on the plan, domain not verified)."""


class SourceError(Exception):
    """The source failed this time (network, rate limit, server error); try again next check."""


@dataclass
class _Answer:
    status: int
    data: Any
    retry_after: str | None = None


class BreachSources:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._session: aiohttp.ClientSession | None = None
        self._catalogue: tuple[float, dict[str, dict[str, Any]]] | None = None
        self._last_call: dict[str, float] = {}
        self._lock = asyncio.Lock()

    @property
    def hibp_key(self) -> str | None:
        key = self.settings.hibp_api_key
        return key.get_secret_value() if key else None

    @property
    def ransomware_feed(self) -> str | None:
        return (self.settings.ransomware_feed_url or "").rstrip("/") or None

    def capabilities(self) -> dict[str, bool]:
        return {
            "breach_catalogue": True,
            "domain_search": bool(self.hibp_key),
            "stealer_logs": bool(self.hibp_key),
            "ransomware": bool(self.ransomware_feed),
        }

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

    async def _space(self, bucket: str, seconds: float) -> None:
        async with self._lock:
            wait = self._last_call.get(bucket, 0.0) + seconds - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call[bucket] = time.monotonic()

    async def _get(self, url: str, *, headers: dict[str, str] | None = None) -> _Answer:
        try:
            async with self._http().get(url, headers=headers or {}, allow_redirects=False) as resp:
                raw = await resp.content.read(MAX_BODY + 1)
                if len(raw) > MAX_BODY:
                    raise SourceError("The answer was too large")
                data = None
                if raw and "json" in (resp.headers.get("Content-Type") or ""):
                    try:
                        data = await asyncio.to_thread(json.loads, raw)
                    except ValueError:
                        data = None
                return _Answer(resp.status, data, resp.headers.get("Retry-After"))
        except asyncio.TimeoutError as exc:
            raise SourceError("Timed out") from exc
        except aiohttp.ClientError as exc:
            raise SourceError(f"Could not connect ({type(exc).__name__})") from exc

    # ------------------------------------------------------------------ HIBP
    async def catalogue(self) -> dict[str, dict[str, Any]]:
        """Every breach HIBP knows, by name (cached for six hours)."""
        if self._catalogue and time.monotonic() - self._catalogue[0] < CATALOGUE_TTL:
            return self._catalogue[1]
        answer = await self._get(f"{HIBP}/breaches")
        if answer.status != 200 or not isinstance(answer.data, list):
            raise SourceError(f"Breach catalogue answered HTTP {answer.status}")
        breaches = {str(b["Name"]): b for b in answer.data if isinstance(b, dict) and b.get("Name")}
        self._catalogue = (time.monotonic(), breaches)
        return breaches

    async def _hibp_keyed(self, path: str, what: str) -> Any:
        if not self.hibp_key:
            raise SourceUnavailable("Needs a Have I Been Pwned API key (ARGUS_HIBP_API_KEY)")
        await self._space("hibp", HIBP_SPACING)
        answer = await self._get(f"{HIBP}{path}", headers={"hibp-api-key": self.hibp_key})
        if answer.status == 200:
            return answer.data
        if answer.status == 404:
            return {}  # nothing found: HIBP's documented "not pwned" answer
        if answer.status == 401:
            raise SourceUnavailable("The Have I Been Pwned API key was rejected")
        if answer.status == 403:
            raise SourceUnavailable(
                f"Have I Been Pwned will not show {what} for this domain: verify it in your HIBP domain search "
                "dashboard (and check your plan includes it)"
            )
        if answer.status == 429:
            raise SourceError(f"Have I Been Pwned rate limit reached (retry after {answer.retry_after or '?'}s)")
        raise SourceError(f"Have I Been Pwned answered HTTP {answer.status}")

    async def domain_accounts(self, domain: str) -> dict[str, list[str]]:
        """``{"alias": ["BreachName", ...]}`` for every breached address at the (verified) domain."""
        data = await self._hibp_keyed(f"/breacheddomain/{quote(domain)}", "breached addresses")
        if not isinstance(data, dict):
            return {}
        return {str(k): [str(b) for b in v] for k, v in data.items() if isinstance(v, list)}

    async def stealer_accounts(self, domain: str) -> dict[str, list[str]]:
        """``{"alias": ["website", ...]}``: addresses at the domain found in infostealer logs."""
        data = await self._hibp_keyed(f"/stealerlogsbyemaildomain/{quote(domain)}", "stealer logs")
        if isinstance(data, dict):
            return {str(k): [str(w) for w in v] if isinstance(v, list) else [] for k, v in data.items()}
        if isinstance(data, list):  # a bare list of addresses
            return {str(e).split("@", 1)[0]: [] for e in data}
        return {}

    # ------------------------------------------------------------------ ransomware leak sites
    async def ransomware_posts(self, keyword: str) -> list[dict[str, Any]]:
        """Leak-site posts whose victim matches ``keyword`` (the feed's own search)."""
        feed = self.ransomware_feed
        if not feed:
            raise SourceUnavailable("The ransomware feed is turned off (ARGUS_RANSOMWARE_FEED_URL)")
        await self._space("ransomware", FEED_SPACING)
        answer = await self._get(f"{feed}/searchvictims/{quote(keyword)}")
        if answer.status == 404:
            return []
        if answer.status != 200:
            raise SourceError(f"The ransomware feed answered HTTP {answer.status}")
        data = answer.data
        if isinstance(data, dict):  # some versions wrap the list
            data = data.get("victims") or data.get("data") or []
        return [p for p in data if isinstance(p, dict)] if isinstance(data, list) else []
