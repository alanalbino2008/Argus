"""Resilient HTTP client used by every Argus reconnaissance module.

Wraps a single shared ``aiohttp.ClientSession`` and adds the behaviour that
real-world OSINT collection needs but raw aiohttp does not provide:

* **Automatic retries** with exponential backoff + jitter on transient
  failures (connection resets, timeouts, HTTP 429/5xx).
* **Retry-After awareness** - when a server says "slow down", we listen.
* **Per-host rate limiting** - a minimum interval between requests to the same
  host, so we never hammer a single data source (crt.sh, GitHub, ...).
* **Per-host and global concurrency caps** - bounded parallelism.
* **Telemetry** - counters for requests, retries, throttles and failures.

The public surface mirrors aiohttp (``client.get(...)`` used as an async
context manager), so modules can switch between the two without changes.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
import logging
import random
import time
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import aiohttp

from argus.core.runctx import report_error, report_ok
from argus.security.network import BlockedDestinationError, assert_public_host

logger = logging.getLogger("argus.http")

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
RETRYABLE_EXCEPTIONS = (
    aiohttp.ClientConnectionError,
    aiohttp.ClientPayloadError,
    asyncio.TimeoutError,
)
DEFAULT_USER_AGENT = "Argus-OSINT/1.1 (+https://github.com/alanalbino2008/Argus)"


@dataclass
class HttpStats:
    """Aggregate request telemetry for a single investigation."""

    requests: int = 0
    retries: int = 0
    throttled: int = 0
    failures: int = 0
    blocked: int = 0
    status_counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "requests": self.requests,
            "retries": self.retries,
            "throttled": self.throttled,
            "failures": self.failures,
            "blocked": self.blocked,
            "status_counts": dict(self.status_counts),
        }


class HostRateLimiter:
    """Enforces a minimum spacing between requests and a concurrency cap per host."""

    def __init__(self, min_interval: float, per_host_concurrency: int):
        self.min_interval = max(0.0, min_interval)
        self.per_host_concurrency = max(1, per_host_concurrency)
        self._locks: Dict[str, asyncio.Lock] = {}
        self._semaphores: Dict[str, asyncio.Semaphore] = {}
        self._next_slot: Dict[str, float] = {}
        self._penalty_until: Dict[str, float] = {}

    def semaphore(self, host: str) -> asyncio.Semaphore:
        if host not in self._semaphores:
            self._semaphores[host] = asyncio.Semaphore(self.per_host_concurrency)
        return self._semaphores[host]

    async def wait_turn(self, host: str) -> None:
        """Sleep until this host may receive another request."""
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            start = max(now, self._next_slot.get(host, 0.0), self._penalty_until.get(host, 0.0))
            self._next_slot[host] = start + self.min_interval
        delay = start - now
        if delay > 0:
            await asyncio.sleep(delay)

    def penalize(self, host: str, seconds: float) -> None:
        """Back off an entire host (e.g. after a 429) for every caller."""
        until = time.monotonic() + seconds
        if until > self._penalty_until.get(host, 0.0):
            self._penalty_until[host] = until


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError):
        return None


class _RetryingRequest:
    """Async context manager returned by ``HttpClient.request``."""

    def __init__(self, client: "HttpClient", method: str, url: str, kwargs: Dict[str, Any]):
        self._client = client
        self._method = method
        self._url = url
        self._kwargs = kwargs
        self._response: Optional[aiohttp.ClientResponse] = None

    async def __aenter__(self) -> aiohttp.ClientResponse:
        self._response = await self._client._send(self._method, self._url, self._kwargs)
        return self._response

    async def __aexit__(self, *exc: Any) -> None:
        if self._response is not None:
            self._response.release()

    def __await__(self):
        return self._client._send(self._method, self._url, self._kwargs).__await__()


class HttpClient:
    """Retrying, rate-limited facade over an ``aiohttp.ClientSession``."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        backoff_cap: float = 20.0,
        min_host_interval: float = 0.05,
        per_host_concurrency: int = 6,
        global_concurrency: int = 50,
        max_retry_after: float = 30.0,
        allow_private: bool = False,
    ):
        self.session = session
        self.allow_private = allow_private
        self.max_retries = max(0, max_retries)
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self.max_retry_after = max_retry_after
        self.limiter = HostRateLimiter(min_host_interval, per_host_concurrency)
        self._global = asyncio.Semaphore(max(1, global_concurrency))
        self.stats = HttpStats()

    # aiohttp-compatible verbs ------------------------------------------------
    def request(self, method: str, url: str, **kwargs: Any) -> _RetryingRequest:
        return _RetryingRequest(self, method.upper(), str(url), kwargs)

    def get(self, url: str, **kwargs: Any) -> _RetryingRequest:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> _RetryingRequest:
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> _RetryingRequest:
        return self.request("POST", url, **kwargs)

    # internals ---------------------------------------------------------------
    def _backoff(self, attempt: int) -> float:
        exp = min(self.backoff_cap, self.backoff_base * (2 ** attempt))
        return random.uniform(0, exp)  # "full jitter" (AWS architecture blog)

    async def _send(self, method: str, url: str, kwargs: Dict[str, Any]) -> aiohttp.ClientResponse:
        host = urlsplit(url).hostname or "unknown"
        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault("User-Agent", DEFAULT_USER_AGENT)
        kwargs["headers"] = headers

        if not self.allow_private:
            try:
                assert_public_host(host)
            except BlockedDestinationError as exc:
                self.stats.blocked += 1
                report_error(host, exc)
                raise

        attempt = 0
        while True:
            async with self.limiter.semaphore(host):
                await self.limiter.wait_turn(host)
                self.stats.requests += 1
                try:
                    async with self._global:
                        resp = await self.session.request(method, url, **kwargs)
                except RETRYABLE_EXCEPTIONS as exc:
                    if isinstance(getattr(exc, "os_error", None), BlockedDestinationError):
                        # Egress guard refused the resolved address: retrying cannot help.
                        self.stats.blocked += 1
                        report_error(host, exc.os_error)
                        raise
                    if attempt >= self.max_retries:
                        self.stats.failures += 1
                        report_error(host, exc)
                        raise
                    error: Optional[BaseException] = exc
                    resp = None
                except Exception as exc:
                    # Non-transient (TLS failure, proxy refusal, bad URL...): count and surface.
                    self.stats.failures += 1
                    report_error(host, exc)
                    raise
                else:
                    error = None

            if resp is not None:
                self.stats.status_counts[resp.status] += 1
                if resp.status not in RETRYABLE_STATUS:
                    report_ok()
                    return resp
                if attempt >= self.max_retries:
                    report_error(host, f"HTTP {resp.status} after {attempt} retries")
                    return resp
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                if resp.status == 429:
                    self.stats.throttled += 1
                resp.release()
                delay = min(retry_after, self.max_retry_after) if retry_after is not None else self._backoff(attempt)
                if resp.status == 429:
                    self.limiter.penalize(host, delay)
                logger.debug("HTTP %s from %s, retrying in %.2fs", resp.status, host, delay)
            else:
                delay = self._backoff(attempt)
                logger.debug("%s on %s, retrying in %.2fs", type(error).__name__, host, delay)

            attempt += 1
            self.stats.retries += 1
            await asyncio.sleep(delay)
